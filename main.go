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
	"sync"
	"syscall"
	"time"

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

var (
	configFile  = kingpin.Flag("config.file", "Path to configuration file.").Default("snmp.yml").String()
	dryRun      = kingpin.Flag("dry-run", "Only verify configuration is valid and exit.").Default("false").Bool()
	metricsPath = kingpin.Flag(
		"web.telemetry-path",
		"Path under which to expose metrics.",
	).Default("/metrics").String()
	toolkitFlags = webflag.AddFlags(kingpin.CommandLine, ":9116")

	// Metrics about the SNMP exporter itself.
	snmpDuration = promauto.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "snmp_collection_duration_seconds",
			Help: "Duration of collections by the SNMP exporter",
		},
		[]string{"module"},
	)
	snmpRequestErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "snmp_request_errors_total",
			Help: "Errors in requests to the SNMP exporter",
		},
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

func handler(w http.ResponseWriter, r *http.Request, logger log.Logger) {
	query := r.URL.Query()

	target := query.Get("target")
	if len(query["target"]) != 1 || target == "" {
		http.Error(w, "'target' parameter must be specified once", 400)
		snmpRequestErrors.Inc()
		return
	}

	moduleName := query.Get("module")
	if len(query["module"]) > 1 {
		http.Error(w, "'module' parameter must only be specified once", 400)
		snmpRequestErrors.Inc()
		return
	}
	if moduleName == "" {
		moduleName = "if_mib"
	}
	sc.RLock()
	module, ok := (*(sc.C))[moduleName]
	sc.RUnlock()
	if !ok {
		http.Error(w, fmt.Sprintf("Unknown module '%s'", moduleName), 400)
		snmpRequestErrors.Inc()
		return
	}

	logger = log.With(logger, "module", moduleName, "target", target)
	level.Debug(logger).Log("msg", "Starting scrape")

	start := time.Now()
	registry := prometheus.NewRegistry()
	c := collector.New(r.Context(), target, module, logger)
	registry.MustRegister(c)
	// Delegate http serving to Prometheus client library, which will call collector.Collect.
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
	duration := time.Since(start).Seconds()
	snmpDuration.WithLabelValues(moduleName).Observe(duration)
	level.Debug(logger).Log("msg", "Finished scrape", "duration_seconds", duration)
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
		http.Error(w, "POST method expected", 400)
	}
}

type SafeConfig struct {
	sync.RWMutex
	C *config.Config
}

func (sc *SafeConfig) ReloadConfig(configFile string) (err error) {
	conf, err := config.LoadFile(configFile)
	if err != nil {
		return err
	}
	sc.Lock()
	sc.C = conf
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

	level.Info(logger).Log("msg", "Starting snmp_exporter", "version", version.Info())
	level.Info(logger).Log("build_context", version.BuildContext())

	prometheus.MustRegister(version.NewCollector("snmp_exporter"))

	// Bail early if the config is bad.
	var err error
	sc.C, err = config.LoadFile(*configFile)
	if err != nil {
		level.Error(logger).Log("msg", "Error parsing config file", "err", err)
		os.Exit(1)
	}

	// Exit if in dry-run mode.
	if *dryRun {
		level.Info(logger).Log("msg", "Configuration parsed successfully")
		return
	}

	// Initialize metrics.
	for module := range *sc.C {
		snmpDuration.WithLabelValues(module)
	}

	hup := make(chan os.Signal, 1)
	reloadCh = make(chan chan error)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-hup:
				if err := sc.ReloadConfig(*configFile); err != nil {
					level.Error(logger).Log("msg", "Error reloading config", "err", err)
				} else {
					level.Info(logger).Log("msg", "Loaded config file")
				}
			case rc := <-reloadCh:
				if err := sc.ReloadConfig(*configFile); err != nil {
					level.Error(logger).Log("msg", "Error reloading config", "err", err)
					rc <- err
				} else {
					level.Info(logger).Log("msg", "Loaded config file")
					rc <- nil
				}
			}
		}
	}()

	http.Handle("/metrics", promhttp.Handler()) // Normal metrics endpoint for SNMP exporter itself.
	// Endpoint to do SNMP scrapes.
	http.HandleFunc(proberPath, func(w http.ResponseWriter, r *http.Request) {
		handler(w, r, logger)
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
			http.Error(w, err.Error(), 500)
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
