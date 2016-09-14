package main

import (
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
)

var (
	configFile = flag.String(
		"config.file", "snmp.yml",
		"Path to configuration file.",
	)
	listenAddress = flag.String(
		"web.listen-address", ":9116",
		"Address to listen on for web interface and telemetry.",
	)

	// Mertrics about the SNMP exporter itself.
	snmpDuration = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "snmp_collection_duration_seconds",
			Help: "Duration of collections by the SNMP exporter",
		},
		[]string{"module"},
	)
	snmpRequestErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "snmp_request_errors_total",
			Help: "Errors in requests to the SNMP exporter",
		},
	)
)

func handler(w http.ResponseWriter, r *http.Request) {
	cfg, err := LoadFile(*configFile)
	if err != nil {
		msg := fmt.Sprintf("Error parsing config file: %s", err)
		http.Error(w, msg, 400)
		log.Errorf(msg)
		return
	}

	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "'target' parameter must be specified", 400)
		snmpRequestErrors.Inc()
		return
	}
	moduleName := r.URL.Query().Get("module")
	if moduleName == "" {
		moduleName = "default"
	}
	module, ok := (*cfg)[moduleName]
	if !ok {
		http.Error(w, fmt.Sprintf("Unkown module '%s'", module), 400)
		snmpRequestErrors.Inc()
		return
	}
	log.Debugf("Scraping target '%s' with module '%s'", target, moduleName)

	start := time.Now()
	registry := prometheus.NewRegistry()
	collector := collector{target: target, module: module}
	registry.MustRegister(collector)
	// Delegate http serving to Promethues client library, which will call collector.Collect.
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
	duration := float64(time.Since(start).Seconds())
	snmpDuration.WithLabelValues(moduleName).Observe(duration)
	log.Debugf("Scrape of target '%s' with module '%s' took %f seconds", target, moduleName, duration)
}

func main() {
	flag.Parse()

	// Bail early if the config is bad.
	_, err := LoadFile(*configFile)
	if err != nil {
		log.Fatalf("Error parsing config file: %s", err)
	}

	http.Handle("/metrics", promhttp.Handler()) // Normal metrics endpoint for SNMP exporter itself.
	http.HandleFunc("/snmp", handler)           // Endpoint to do SNMP scrapes.
	log.Infof("Listening on %s", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
