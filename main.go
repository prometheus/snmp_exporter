// Copyright 2018 The Prometheus Authors
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
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/alecthomas/kingpin/v2"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
	yaml "gopkg.in/yaml.v2"

	"github.com/prometheus/snmp_exporter/collector"
	"github.com/prometheus/snmp_exporter/config"
)

const (
	namespace = "snmp"
)

var (
	configFile    = kingpin.Flag("config.file", "Path to configuration file.").Default("snmp.yml").Strings()
	dryRun        = kingpin.Flag("dry-run", "Only verify configuration is valid and exit.").Default("false").Bool()
	concurrency   = kingpin.Flag("snmp.module-concurrency", "The number of modules to fetch concurrently per scrape").Default("1").Int()
	expandEnvVars = kingpin.Flag("config.expand-environment-variables", "Expand environment variables to source secrets").Default("false").Bool()
	metricsPath   = kingpin.Flag(
		"web.telemetry-path",
		"Path under which to expose metrics.",
	).Default("/metrics").String()
	toolkitFlags = webflag.AddFlags(kingpin.CommandLine, ":9116")

	// Metrics about the SNMP exporter itself.
	snmpRequestErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "request_errors_total",
			Help:      "Errors in requests to the SNMP exporter",
		},
	)
	snmpCollectionDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "collection_duration_seconds",
			Help:      "Duration of collections by the SNMP exporter",
		},
		[]string{"module"},
	)
	sc = &SafeConfig{
		C: &config.Config{},
	}
	reloadCh chan chan error
)

const (
	proberPath = "/snmp"
	configPath = "/config"
)

func handler(w http.ResponseWriter, r *http.Request, logger log.Logger, exporterMetrics collector.Metrics) {
	query := r.URL.Query()

	target := query.Get("target")
	if len(query["target"]) != 1 || target == "" {
		http.Error(w, "'target' parameter must be specified once", http.StatusBadRequest)
		snmpRequestErrors.Inc()
		return
	}

	authName := query.Get("auth")
	if len(query["auth"]) > 1 {
		http.Error(w, "'auth' parameter must only be specified once", http.StatusBadRequest)
		snmpRequestErrors.Inc()
		return
	}
	if authName == "" {
		authName = "public_v2"
	}

	queryModule := query["module"]
	if len(queryModule) == 0 {
		queryModule = append(queryModule, "if_mib")
	}
	uniqueM := make(map[string]bool)
	var modules []string
	for _, qm := range queryModule {
		for _, m := range strings.Split(qm, ",") {
			if m == "" {
				continue
			}
			if _, ok := uniqueM[m]; !ok {
				uniqueM[m] = true
				modules = append(modules, m)
			}
		}
	}
	sc.RLock()
	auth, authOk := sc.C.Auths[authName]
	if !authOk {
		sc.RUnlock()
		http.Error(w, fmt.Sprintf("Unknown auth '%s'", authName), http.StatusBadRequest)
		snmpRequestErrors.Inc()
		return
	}
	var nmodules []*collector.NamedModule
	for _, m := range modules {
		module, moduleOk := sc.C.Modules[m]
		if !moduleOk {
			sc.RUnlock()
			http.Error(w, fmt.Sprintf("Unknown module '%s'", m), http.StatusBadRequest)
			snmpRequestErrors.Inc()
			return
		}
		nmodules = append(nmodules, collector.NewNamedModule(m, module))
	}
	sc.RUnlock()
	logger = log.With(logger, "auth", authName, "target", target)
	registry := prometheus.NewRegistry()
	c := collector.New(r.Context(), target, authName, auth, nmodules, logger, exporterMetrics, *concurrency)
	registry.MustRegister(c)
	// Delegate http serving to Prometheus client library, which will call collector.Collect.
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func updateConfiguration(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		rc := make(chan error)
		reloadCh <- rc
		if err := <-rc; err != nil {
			http.Error(w, fmt.Sprintf("failed to reload config: %s", err), http.StatusInternalServerError)
		}
	default:
		http.Error(w, "POST method expected", http.StatusBadRequest)
	}
}

type SafeConfig struct {
	sync.RWMutex
	C *config.Config
}

func (sc *SafeConfig) ReloadConfig(configFile []string, expandEnvVars bool) (err error) {
	conf, err := config.LoadFile(configFile, expandEnvVars)
	if err != nil {
		return err
	}
	sc.Lock()
	sc.C = conf
	// Initialize metrics.
	for module := range sc.C.Modules {
		snmpCollectionDuration.WithLabelValues(module)
	}
	sc.Unlock()
	return nil
}

func main() {
	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("snmp_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)
	if *concurrency < 1 {
		*concurrency = 1
	}

	level.Info(logger).Log("msg", "Starting snmp_exporter", "version", version.Info(), "concurrency", concurrency)
	level.Info(logger).Log("build_context", version.BuildContext())

	prometheus.MustRegister(version.NewCollector("snmp_exporter"))

	// Bail early if the config is bad.
	err := sc.ReloadConfig(*configFile, *expandEnvVars)
	if err != nil {
		level.Error(logger).Log("msg", "Error parsing config file", "err", err)
		level.Error(logger).Log("msg", "Possible old config file, see https://github.com/prometheus/snmp_exporter/blob/main/auth-split-migration.md")
		os.Exit(1)
	}

	// Exit if in dry-run mode.
	if *dryRun {
		level.Info(logger).Log("msg", "Configuration parsed successfully")
		return
	}

	hup := make(chan os.Signal, 1)
	reloadCh = make(chan chan error)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-hup:
				if err := sc.ReloadConfig(*configFile, *expandEnvVars); err != nil {
					level.Error(logger).Log("msg", "Error reloading config", "err", err)
				} else {
					level.Info(logger).Log("msg", "Loaded config file")
				}
			case rc := <-reloadCh:
				if err := sc.ReloadConfig(*configFile, *expandEnvVars); err != nil {
					level.Error(logger).Log("msg", "Error reloading config", "err", err)
					rc <- err
				} else {
					level.Info(logger).Log("msg", "Loaded config file")
					rc <- nil
				}
			}
		}
	}()

	buckets := prometheus.ExponentialBuckets(0.0001, 2, 15)
	exporterMetrics := collector.Metrics{
		SNMPCollectionDuration: snmpCollectionDuration,
		SNMPUnexpectedPduType: promauto.NewCounter(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "unexpected_pdu_type_total",
				Help:      "Unexpected Go types in a PDU.",
			},
		),
		SNMPDuration: promauto.NewHistogram(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "packet_duration_seconds",
				Help:      "A histogram of latencies for SNMP packets.",
				Buckets:   buckets,
			},
		),
		SNMPPackets: promauto.NewCounter(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "packets_total",
				Help:      "Number of SNMP packet sent, including retries.",
			},
		),
		SNMPRetries: promauto.NewCounter(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "packet_retries_total",
				Help:      "Number of SNMP packet retries.",
			},
		),
		SNMPInflight: promauto.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "request_in_flight",
				Help:      "Current number of SNMP scrapes being requested.",
			},
		),
	}

	http.Handle(*metricsPath, promhttp.Handler()) // Normal metrics endpoint for SNMP exporter itself.
	// Endpoint to do SNMP scrapes.
	http.HandleFunc(proberPath, func(w http.ResponseWriter, r *http.Request) {
		handler(w, r, logger, exporterMetrics)
	})
	http.HandleFunc("/-/reload", updateConfiguration) // Endpoint to reload configuration.

	if *metricsPath != "/" && *metricsPath != "" {
		landingConfig := web.LandingConfig{
			Name:        "SNMP Exporter",
			Description: "Prometheus Exporter for SNMP targets",
			Version:     version.Info(),
			Form: web.LandingForm{
				Action: proberPath,
				Inputs: []web.LandingFormInput{
					{
						Label:       "Target",
						Type:        "text",
						Name:        "target",
						Placeholder: "X.X.X.X/[::X]",
						Value:       "::1",
					},
					{
						Label:       "Auth",
						Type:        "text",
						Name:        "auth",
						Placeholder: "auth",
						Value:       "public_v2",
					},
					{
						Label:       "Module",
						Type:        "text",
						Name:        "module",
						Placeholder: "module",
						Value:       "if_mib",
					},
				},
			},
			Links: []web.LandingLinks{
				{
					Address: configPath,
					Text:    "Config",
				},
				{
					Address: *metricsPath,
					Text:    "Metrics",
				},
			},
		}
		landingPage, err := web.NewLandingPage(landingConfig)
		if err != nil {
			level.Error(logger).Log("err", err)
			os.Exit(1)
		}
		http.Handle("/", landingPage)
	}

	http.HandleFunc(configPath, func(w http.ResponseWriter, r *http.Request) {
		sc.RLock()
		c, err := yaml.Marshal(sc.C)
		sc.RUnlock()
		if err != nil {
			level.Error(logger).Log("msg", "Error marshaling configuration", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(c)
	})

	srv := &http.Server{}
	if err := web.ListenAndServe(srv, toolkitFlags, logger); err != nil {
		level.Error(logger).Log("msg", "Error starting HTTP server", "err", err)
		os.Exit(1)
	}
}
