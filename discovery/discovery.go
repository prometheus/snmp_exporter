// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"maps"
	"net"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/discovery"
	"github.com/prometheus/prometheus/discovery/targetgroup"
	"golang.org/x/sync/errgroup"

	"github.com/prometheus/snmp_exporter/collector"
	"github.com/prometheus/snmp_exporter/config"
	"github.com/prometheus/snmp_exporter/scraper"
)

var DefaultInterval = 5 * time.Minute

type D struct {
	fp       *collector.Fingerprint
	auth     *config.Auth
	authName string
	target   *net.IPNet

	Timeout  time.Duration
	Interval time.Duration

	knownHosts    map[string][]string
	fingerprintFn func(context.Context, net.IP, *config.Auth) ([]string, error)

	logger  *slog.Logger
	metrics collector.Metrics
}

var _ discovery.Discoverer = (*D)(nil)

func New(fp *collector.Fingerprint, auth *config.Auth, authName string, target *net.IPNet, metrics collector.Metrics, logger *slog.Logger) *D {
	d := &D{
		fp:       fp,
		metrics:  metrics,
		logger:   logger,
		auth:     auth,
		authName: authName,
		target:   target,

		Interval: DefaultInterval,
		Timeout:  time.Second * 5,

		knownHosts: make(map[string][]string),
	}
	d.fingerprintFn = d.snmpFingerprint
	return d
}

// Run implements [discovery.Discoverer].
func (d *D) Run(ctx context.Context, up chan<- []*targetgroup.Group) {
	interval := d.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	ticker := time.NewTicker(interval)
	d.logger.DebugContext(ctx, "starting discovery timer", "interval", interval)
	scan := func() {
		d.logger.DebugContext(ctx, "starting scheduled scan")
		err := d.ScanNetwork(ctx, up)
		if err != nil {
			d.logger.ErrorContext(ctx, "failed to scan network", "err", err)
			return
		}
	}

	// perform immediate scan to avoid waiting a long time for first results
	scan()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			scan()
		}
	}
}

func (d *D) ScanNetwork(ctx context.Context, up chan<- []*targetgroup.Group) error {
	workers, ctx := errgroup.WithContext(ctx)
	nWorkers := max(*concurrency, 1)
	workers.SetLimit(nWorkers)
	startT := time.Now()

	d.logger.InfoContext(ctx, "starting full network scan, this might take a while", "network", d.target.String(), "workers", nWorkers)
	discoveredHosts := sync.Map{}
	for iterIP := net.IP(bytes.Clone(d.target.IP)); d.target.Contains(iterIP); incIP(iterIP) {
		wip := net.IP(bytes.Clone(iterIP))
		workers.Go(func() error {
			modules, err := d.fingerprintFn(ctx, wip, d.auth)
			if err != nil {
				return err
			}
			if len(modules) > 0 {
				slices.Sort(modules)
				up <- []*targetgroup.Group{
					{
						Targets: []model.LabelSet{
							{
								model.AddressLabel: model.LabelValue(wip.String()),
							},
						},
						Labels: model.LabelSet{
							"__param_module": model.LabelValue(strings.Join(modules, ",")),
							"__param_auth":   model.LabelValue(d.authName),
						},
						Source: wip.String(),
					},
				}
				discoveredHosts.Store(wip.String(), modules)
				if prev, ok := d.knownHosts[wip.String()]; !ok || !slices.Equal(prev, modules) {
					d.logger.InfoContext(ctx, "found new modules for target", "target", wip.String(), "modules", modules)
				}
			}
			return nil
		})
	}
	if err := workers.Wait(); err != nil {
		return err
	}
	for k := range d.knownHosts {
		// send empty update from this source if a previously known host no longer responds
		if _, ok := discoveredHosts.Load(k); !ok {
			d.logger.InfoContext(ctx, "previously discovered target no longer found, removing it from target list", "target", k)
			up <- []*targetgroup.Group{
				{
					Source: k,
				},
			}
		}
	}
	d.knownHosts = make(map[string][]string)

	discoveredHosts.Range(func(k, v any) bool {
		d.knownHosts[k.(string)] = v.([]string)
		return true
	})

	d.logger.InfoContext(ctx, "finished network scan", "network", d.target.String(), "elapsed", time.Since(startT))
	return nil
}

func (d *D) snmpFingerprint(ctx context.Context, ip net.IP, auth *config.Auth) ([]string, error) {
	log := d.logger.With("target", ip.String())
	client, err := scraper.NewGoSNMP(log, ip.String(), "", true)
	if err != nil {
		return nil, err
	}
	client.SetOptions(func(g *gosnmp.GoSNMP) {
		g.Context = ctx
		auth.ConfigureSNMP(g, "")
	})

	if err := client.Connect(); err != nil {
		log.WarnContext(ctx, "failed to connect to snmp target for fingerprinting", "err", err)
		return nil, nil
	}
	defer client.Close()

	matched := make(map[string]struct{})
	for _, m := range d.fp.DiscoveryModules() {
		client.SetOptions(
			// Set the metrics options.
			func(g *gosnmp.GoSNMP) {
				var sent time.Time
				g.OnSent = func(_ *gosnmp.GoSNMP) {
					sent = time.Now()
					d.metrics.SNMPPackets.Inc()
				}
				g.OnRecv = func(_ *gosnmp.GoSNMP) {
					d.metrics.SNMPDuration.Observe(time.Since(sent).Seconds())
				}
				g.OnRetry = func(_ *gosnmp.GoSNMP) {
					d.metrics.SNMPRetries.Inc()
				}
			},
			// Set the Walk options.
			func(g *gosnmp.GoSNMP) {
				g.Retries = 0
				g.Timeout = d.Timeout
				if g.Timeout == 0 {
					g.Timeout = time.Second * 5
				}
				g.MaxRepetitions = m.WalkParams.MaxRepetitions
				g.UseUnconnectedUDPSocket = m.WalkParams.UseUnconnectedUDPSocket
				if m.WalkParams.AllowNonIncreasingOIDs {
					g.AppOpts = map[string]any{
						"c": true,
					}
				}
			},
		)
		result, err := collector.ScrapeTarget(client, ip.String(), auth, m.Module, d.logger, d.metrics)
		if err != nil {
			if !errors.Is(err, gosnmp.ErrMaxRetriesExceeded) && !errors.Is(err, syscall.ECONNREFUSED) {
				log.WarnContext(ctx, "failed to get response for discovery", "module", m.Name, "err", err)
			}
			continue
		}

		// The fingerprinter does _not_ return the discovery module used in its list
		// of matches. Since we want _all_ applicable modules for discovery, add it
		// when any results have been returned
		if len(result.PDUs) > 0 {
			matched[m.Name] = struct{}{}
		}

		modules := d.fp.Match(result.PDUs, d.metrics)
		for _, disco := range modules {
			matched[disco.Name] = struct{}{}
		}
	}
	return slices.Collect(maps.Keys(matched)), nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
