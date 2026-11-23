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
	"context"
	"errors"
	"net"
	"net/http"
	"os"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/common/promslog/flag"
	"github.com/prometheus/common/version"

	"github.com/prometheus/snmp_exporter/collector"
	"github.com/prometheus/snmp_exporter/config"
)

var (
	configFile    = kingpin.Flag("config.file", "Path to configuration file.").Default("snmp.yml").Strings()
	expandEnvVars = kingpin.Flag("config.expand-environment-variables", "Expand environment variables to source secrets").Default("false").Bool()
	listenAddr    = kingpin.Flag("http.listen-addr", "Address to listen on for http_sd request").Default("0.0.0.0:9117").String()
	concurrency   = kingpin.Flag("discovery.concurrency", "The number of workers to use for scanning the network").Default("1").Int()
	authName      = kingpin.Flag("discovery.auth", "Authentication context to use").Default("public_v2").String()
	network       = kingpin.Flag("discovery.network", "Network containing SNMP targets, CIDR notation").Required().String()
	fpName        = kingpin.Flag("discovery.fingerprinter", "Name of the fingerprinter to use for module discovery").Default("default").String()
	interval      = kingpin.Flag("discovery.interval", "Interval between full scans of the network").Default("10m").Duration()
	timeout       = kingpin.Flag("discovery.timeout", "Duration to wait for receiving SNMP packets").Default("5s").Duration()
)

const (
	discoveryPath = "/discovery"
)

func main() {
	promslogConfig := &promslog.Config{}
	flag.AddFlags(kingpin.CommandLine, promslogConfig)
	kingpin.Version(version.Print("snmp_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promslog.New(promslogConfig)
	if *concurrency < 1 {
		*concurrency = 1
	}
	logger.Info("Starting snmp_exporter/discovery", "version", version.Info(), "concurrency", *concurrency)
	logger.Info("operational information", "build_context", version.BuildContext())

	cfg, err := config.LoadFile(logger, *configFile, *expandEnvVars)
	if err != nil {
		logger.Error("invalid config", "err", err)
		os.Exit(1)
	}

	auth, ok := cfg.Auths[*authName]
	if !ok {
		logger.Error("auth not found in config", "auth", *authName)
		os.Exit(1)
	}

	_, targetNet, err := net.ParseCIDR(*network)
	if err != nil {
		logger.Error("failed to parse target network", "err", err)
		os.Exit(1)
	}

	fpConfig, ok := cfg.Fingerprinters[*fpName]
	if !ok {
		logger.Error("fingerprinter not found in config", "fingerprinter", *fpName)
		os.Exit(1)
	}

	fp, err := collector.NewFingerprint(*fpName, fpConfig, cfg.Modules)
	if err != nil {
		logger.Error("failed to build fingerprinter", "err", err)
		os.Exit(1)
	}

	disco := New(fp, auth, *authName, targetNet, buildMetrics(), logger)
	disco.Timeout = *timeout
	disco.Interval = *interval
	manager := NewManaged(disco)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go manager.Run(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc(discoveryPath, manager.Handle)
	if err := http.ListenAndServe(*listenAddr, mux); err != nil && errors.Is(err, net.ErrClosed) {
		logger.Error("failed to server requests", "err", err)
	}
}

func buildMetrics() collector.Metrics {
	namespace := "snmp"
	buckets := prometheus.ExponentialBuckets(0.0001, 2, 15)
	return collector.Metrics{
		SNMPCollectionDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "collection_duration_seconds",
				Help:      "Duration of collections by the SNMP exporter",
			},
			[]string{"module"},
		),
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
}
