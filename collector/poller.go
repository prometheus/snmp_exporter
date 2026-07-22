// Copyright 2026 The Prometheus Authors
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

package collector

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/prometheus/snmp_exporter/config"
	"github.com/prometheus/snmp_exporter/sample"
	"github.com/prometheus/snmp_exporter/scraper"
)

// TargetSnapshot contains immutable device data used for one poll.
type TargetSnapshot struct {
	Address      string
	DeviceID     string
	SNMPContext  string
	SNMPEngineID string
	Labels       map[string]string
}

// ProfileSnapshot contains one compiled SNMP polling module.
type ProfileSnapshot struct {
	Name   string
	Module *config.Module
}

// Credentials wraps an SNMP authentication profile. A
// SecretStore-backed implementation can construct this value without changing
// the polling API.
type Credentials struct {
	Name string
	Auth *config.Auth
}

// PollResult is the output-independent result of one device poll.
type PollResult struct {
	Samples   []sample.Sample
	StartedAt time.Time
	EndedAt   time.Time
	Packets   uint64
	Retries   uint64
}

// upMetricName is the per-device health gauge emitted on every poll attempt
// (1 on success, 0 on failure), independent of the MIB modules being polled.
// Remote-write mode has no HTTP scrape and therefore no Prometheus `up`
// metric of its own, so dashboards rely on this sample for health panels.
const (
	upMetricName  = "snmp_up"
	deviceIPLabel = "device_ip"
)

// Poller polls a device without relying on an HTTP scrape request.
type Poller interface {
	Poll(context.Context, TargetSnapshot, ProfileSnapshot, Credentials) (PollResult, error)
}

type scraperFactory func(*slog.Logger, string, string, bool) (scraper.SNMPScraper, error)

// ActivePoller reuses the shared SNMP scraper and PDU parsing core.
type ActivePoller struct {
	logger        *slog.Logger
	metrics       Metrics
	debugSNMP     bool
	sourceAddress string
	newScraper    scraperFactory
	newPollID     func() (string, error)
	now           func() time.Time
}

// NewPoller constructs the polling core used by the active scheduler.
func NewPoller(logger *slog.Logger, metrics Metrics, debugSNMP bool) *ActivePoller {
	return &ActivePoller{
		logger:        logger,
		metrics:       metrics,
		debugSNMP:     debugSNMP,
		sourceAddress: *srcAddress,
		newScraper: func(logger *slog.Logger, target, sourceAddress string, debug bool) (scraper.SNMPScraper, error) {
			return scraper.NewGoSNMP(logger, target, sourceAddress, debug)
		},
		newPollID: randomPollID,
		now:       time.Now,
	}
}

// Poll performs a single profile poll and returns internal samples. It does
// not register a Prometheus collector and does not interact with an output.
func (p *ActivePoller) Poll(ctx context.Context, target TargetSnapshot, profile ProfileSnapshot, credentials Credentials) (result PollResult, err error) {
	result.StartedAt = p.now()
	defer func() {
		result.EndedAt = p.now()
	}()

	if err := validatePollInput(target, profile, credentials); err != nil {
		return result, err
	}
	target, err = withAutomaticTargetLabels(target)
	if err != nil {
		return result, err
	}
	pollID, err := p.newPollID()
	if err != nil {
		return result, fmt.Errorf("create poll ID: %w", err)
	}

	down := func(pollErr error) (PollResult, error) {
		result.Samples = []sample.Sample{healthSample(0, target, pollID, result.StartedAt.UnixMilli())}
		return result, pollErr
	}

	logger := p.logger.With("device_id", target.DeviceID, "profile", profile.Name, "poll_id", pollID)
	client, err := p.newScraper(logger, target.Address, p.sourceAddress, p.debugSNMP)
	if err != nil {
		return down(fmt.Errorf("create SNMP client: %w", err))
	}

	if err := p.configureClient(ctx, client, target, profile, credentials, &result); err != nil {
		return down(err)
	}
	if err := client.Connect(); err != nil {
		return down(err)
	}
	defer client.Close()

	if p.metrics.SNMPInflight != nil {
		p.metrics.SNMPInflight.Inc()
		defer p.metrics.SNMPInflight.Dec()
	}

	scrapeStarted := p.now()
	scrapeResult, err := ScrapeTarget(client, target.Address, credentials.Auth, profile.Module, logger, p.metrics)
	if p.metrics.SNMPCollectionDuration != nil {
		p.metrics.SNMPCollectionDuration.WithLabelValues(profile.Name).Observe(p.now().Sub(scrapeStarted).Seconds())
	}
	if err != nil {
		return down(err)
	}

	result.Samples, err = buildInternalSamples(scrapeResult, target, profile, pollID, result.StartedAt.UnixMilli(), logger, p.metrics)
	if err != nil {
		return down(err)
	}
	result.Samples = append(result.Samples, healthSample(1, target, pollID, result.StartedAt.UnixMilli()))
	return result, nil
}

// healthSample builds the per-poll snmp_up gauge described on PollResult.
func healthSample(value float64, target TargetSnapshot, pollID string, timestamp int64) sample.Sample {
	return sample.Sample{
		Name:      upMetricName,
		Value:     value,
		Timestamp: timestamp,
		Labels:    sample.CloneLabels(target.Labels),
		Type:      sample.MetricGauge,
		DeviceID:  target.DeviceID,
		PollID:    pollID,
	}
}

func validatePollInput(target TargetSnapshot, profile ProfileSnapshot, credentials Credentials) error {
	if target.Address == "" {
		return fmt.Errorf("target address is required")
	}
	if target.DeviceID == "" {
		return fmt.Errorf("target device ID is required")
	}
	if profile.Name == "" {
		return fmt.Errorf("profile name is required")
	}
	if profile.Module == nil {
		return fmt.Errorf("profile module is required")
	}
	if credentials.Auth == nil {
		return fmt.Errorf("credentials auth is required")
	}
	return nil
}

// withAutomaticTargetLabels adds stable identity labels derived from the
// inventory target. Hostname() deliberately strips the transport, brackets,
// and port without performing DNS resolution, which could make time-series
// identity change while the collector is running.
func withAutomaticTargetLabels(target TargetSnapshot) (TargetSnapshot, error) {
	parsed, err := url.Parse(target.Address)
	if err != nil || parsed.Hostname() == "" {
		return TargetSnapshot{}, fmt.Errorf("extract device IP from target address %q", target.Address)
	}

	deviceIP := parsed.Hostname()
	labels := sample.CloneLabels(target.Labels)
	if labels == nil {
		labels = make(map[string]string, 1)
	}
	if configured, exists := labels[deviceIPLabel]; exists && configured != deviceIP {
		return TargetSnapshot{}, fmt.Errorf("label %q conflicts with target address", deviceIPLabel)
	}
	labels[deviceIPLabel] = deviceIP
	target.Labels = labels
	return target, nil
}

func (p *ActivePoller) configureClient(ctx context.Context, client scraper.SNMPScraper, target TargetSnapshot, profile ProfileSnapshot, credentials Credentials, result *PollResult) error {
	if target.SNMPEngineID != "" && credentials.Auth.Version == 3 {
		engineID, err := hex.DecodeString(target.SNMPEngineID)
		if err != nil {
			return fmt.Errorf("decode SNMP engine ID: %w", err)
		}
		client.SetOptions(func(g *gosnmp.GoSNMP) {
			g.ContextEngineID = string(engineID)
		})
	}

	client.SetOptions(
		func(g *gosnmp.GoSNMP) {
			var sent time.Time
			g.OnSent = func(*gosnmp.GoSNMP) {
				sent = p.now()
				result.Packets++
				if p.metrics.SNMPPackets != nil {
					p.metrics.SNMPPackets.Inc()
				}
			}
			g.OnRecv = func(*gosnmp.GoSNMP) {
				if p.metrics.SNMPDuration != nil && !sent.IsZero() {
					p.metrics.SNMPDuration.Observe(p.now().Sub(sent).Seconds())
				}
			}
			g.OnRetry = func(*gosnmp.GoSNMP) {
				result.Retries++
				if p.metrics.SNMPRetries != nil {
					p.metrics.SNMPRetries.Inc()
				}
			}
		},
		func(g *gosnmp.GoSNMP) {
			g.Context = ctx
			g.UseUnconnectedUDPSocket = profile.Module.WalkParams.UseUnconnectedUDPSocket
			g.Timeout = profile.Module.WalkParams.Timeout
			g.MaxRepetitions = profile.Module.WalkParams.MaxRepetitions
			if profile.Module.WalkParams.Retries != nil {
				g.Retries = *profile.Module.WalkParams.Retries
			}
			if profile.Module.WalkParams.AllowNonIncreasingOIDs {
				g.AppOpts = map[string]any{"c": true}
			}
			credentials.Auth.ConfigureSNMP(g, target.SNMPContext)
		},
	)
	return nil
}

func buildInternalSamples(results ScrapeResults, target TargetSnapshot, profile ProfileSnapshot, pollID string, timestamp int64, logger *slog.Logger, metrics Metrics) ([]sample.Sample, error) {
	oidToPDU := make(map[string]gosnmp.SnmpPDU, len(results.pdus))
	for _, pdu := range results.pdus {
		oidToPDU[trimLeadingDot(pdu.Name)] = pdu
	}

	metricTree := buildMetricTree(profile.Module.Metrics)
	samples := make([]sample.Sample, 0, len(results.pdus))
	for oid, pdu := range oidToPDU {
		head := metricTree
		oidList := oidToList(oid)
		for i, part := range oidList {
			var ok bool
			head, ok = head.children[part]
			if !ok {
				break
			}
			if head.metric == nil {
				continue
			}
			for _, raw := range pduToMetricSamples(oidList[i+1:], &pdu, head.metric, oidToPDU, logger, metrics) {
				converted, err := internalSample(raw, target, pollID, timestamp)
				if err != nil {
					return nil, err
				}
				samples = append(samples, converted)
			}
			break
		}
	}
	return samples, nil
}

func internalSample(raw metricSample, target TargetSnapshot, pollID string, timestamp int64) (sample.Sample, error) {
	if raw.err != nil {
		return sample.Sample{}, raw.err
	}
	if len(raw.labelnames) != len(raw.labelvalues) {
		return sample.Sample{}, fmt.Errorf("metric %q has mismatched label names and values", raw.name)
	}

	labels := sample.CloneLabels(target.Labels)
	if labels == nil {
		labels = make(map[string]string, len(raw.labelnames))
	}
	for i, name := range raw.labelnames {
		if _, exists := labels[name]; exists {
			return sample.Sample{}, fmt.Errorf("metric %q label %q conflicts with a target label", raw.name, name)
		}
		labels[name] = raw.labelvalues[i]
	}

	metricType := sample.MetricGauge
	if raw.valueType == prometheus.CounterValue {
		metricType = sample.MetricCounter
	} else if raw.info {
		metricType = sample.MetricInfo
	}
	converted := sample.Sample{
		Name:      raw.name,
		Value:     raw.value,
		Timestamp: timestamp,
		Labels:    labels,
		Type:      metricType,
		OID:       raw.oid,
		DeviceID:  target.DeviceID,
		PollID:    pollID,
	}
	if err := converted.Validate(); err != nil {
		return sample.Sample{}, fmt.Errorf("validate metric %q: %w", raw.name, err)
	}
	return converted, nil
}

func trimLeadingDot(oid string) string {
	if len(oid) > 0 && oid[0] == '.' {
		return oid[1:]
	}
	return oid
}

func randomPollID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(id[:]), nil
}
