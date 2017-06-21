package main

import (
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"

	"github.com/prometheus/snmp_exporter/config"
)

var (
	showVersion = flag.Bool("version", false, "Print version information.")
	configFile  = flag.String(
		"config.file", "snmp.yml",
		"Path to configuration file.",
	)
	configDirectory = flag.String(
		"config.directory", "",
		"Path to directory with configuration files. It will be preferred if specified.",
	)
	listenAddress = flag.String(
		"web.listen-address", ":9116",
		"Address to listen on for web interface and telemetry.",
	)

	// Metrics about the SNMP exporter itself.
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

func init() {
	prometheus.MustRegister(snmpDuration)
	prometheus.MustRegister(snmpRequestErrors)
	prometheus.MustRegister(version.NewCollector("snmp_exporter"))
}

func handler(w http.ResponseWriter, r *http.Request) {
	var cfg *config.Config
	var err error
	// Prefer config directory in case it is specified
	if *configDirectory != "" {
		cfg, err = config.LoadFiles(*configDirectory)
	} else {
		cfg, err = config.LoadFile(*configFile)
	}
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
		http.Error(w, fmt.Sprintf("Unkown module '%s'", moduleName), 400)
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

	if *showVersion {
		fmt.Fprintln(os.Stdout, version.Print("snmp_exporter"))
		os.Exit(0)
	}

	log.Infoln("Starting snmp exporter", version.Info())
	log.Infoln("Build context", version.BuildContext())

	// Bail early if the config is bad.
	var cfg *config.Config
	var err error
	if *configDirectory != "" {
		log.Infoln("Read configurations from", *configDirectory)
		cfg, err = config.LoadFiles(*configDirectory)
	} else {
		log.Infoln("Read configuration from", *configFile)
		cfg, err = config.LoadFile(*configFile)
	}
	if err != nil {
		log.Fatalf("Error parsing configuration: %s", err)
	}
	// Initilise metrics.
	for module, _ := range *cfg {
		snmpDuration.WithLabelValues(module)
	}

	http.Handle("/metrics", promhttp.Handler()) // Normal metrics endpoint for SNMP exporter itself.
	http.HandleFunc("/snmp", handler)           // Endpoint to do SNMP scrapes.

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
            <head>
            <title>SNMP Exporter</title>
            <style>
            label{
            display:inline-block;
            width:75px;
            }
            form label {
            margin: 10px;
            }
            form input {
            margin: 10px;
            }
            </style>
            </head>
            <body>
            <h1>SNMP Exporter</h1>
            <form action="/snmp">
            <label>Target:</label> <input type="text" name="target" placeholder="X.X.X.X" value="1.2.3.4"><br>
            <label>Module:</label> <input type="text" name="module" placeholder="module" value="default"><br>
            <input type="submit" value="Submit">
            </form>
            </body>
            </html>`))
	})

	log.Infof("Listening on %s", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
