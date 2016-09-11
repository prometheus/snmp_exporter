package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"github.com/soniah/gosnmp"
	"gopkg.in/yaml.v2"
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
)

func LoadFile(filename string) (*Config, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	err = yaml.Unmarshal(content, cfg)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

type Config map[string]*Module

type Module struct {
	// A list of OIDs.
	Walk    []string  `yaml:"walk"`
	Metrics []*Metric `yaml:"metrics"`
	// TODO: Security

	// TODO: Use these.
	XXX map[string]interface{} `yaml:",inline"`
}

type Metric struct {
	Name    string    `yaml:"name"`
	Oid     string    `yaml:"oid"`
	Indexes []*Index  `yaml:"indexes,omitempty"`
	Lookups []*Lookup `yaml:"lookups,omitempty"`

	XXX map[string]interface{} `yaml:",inline"`
}

type Index struct {
	Labelname string `yaml:"labelname"`
	Type      string `yaml:"type"`

	XXX map[string]interface{} `yaml:",inline"`
}

type Lookup struct {
	Labels    []string `yaml:"labels"`
	Labelname string   `yaml:"labelname"`
	Oid       string   `yaml:"oid"`

	XXX map[string]interface{} `yaml:",inline"`
}

func OidToList(oid string) []int {
	result := []int{}
	for _, x := range strings.Split(oid, ".") {
		o, _ := strconv.Atoi(x)
		result = append(result, o)
	}
	return result
}

func ScrapeTarget(target string, config *Module) ([]gosnmp.SnmpPDU, error) {
	// Set the options.
	snmp := gosnmp.GoSNMP{}
	snmp.Retries = 3
	snmp.MaxRepetitions = 25

	snmp.Target = target
	snmp.Port = 161
	if host, port, err := net.SplitHostPort(target); err == nil {
		snmp.Target = host
		p, err := strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("Error converting port number to int for target %s: %s", target, err)
		}
		snmp.Port = uint16(p)
	}

	snmp.Version = gosnmp.Version2c
	snmp.Community = "public"
	snmp.Timeout = time.Second * 60

	// Do the actual walk.
	err := snmp.Connect()
	if err != nil {
		return nil, fmt.Errorf("Error connecting to target %s: %s", target, err)
	}
	defer snmp.Conn.Close()

	result := []gosnmp.SnmpPDU{}
	for _, subtree := range config.Walk {
		var pdus []gosnmp.SnmpPDU
		if snmp.Version == gosnmp.Version1 {
			pdus, err = snmp.WalkAll(subtree)
		} else {
			pdus, err = snmp.BulkWalkAll(subtree)
		}
		if err != nil {
			return nil, fmt.Errorf("Error walking target %s: %s", snmp.Target, err)
		}
		result = append(result, pdus...)
	}
	return result, nil
}

type MetricNode struct {
	metric  *Metric
	oidList []int

	children map[int]*MetricNode
}

// Build a tree of metrics from the config, for fast lookup when there's lots of them.
func buildMetricTree(metrics []*Metric) *MetricNode {
	metricTree := &MetricNode{children: map[int]*MetricNode{}}
	for _, metric := range metrics {
		head := metricTree
		for _, o := range OidToList(metric.Oid) {
			_, ok := head.children[o]
			if !ok {
				head.children[o] = &MetricNode{children: map[int]*MetricNode{}}
			}
			head = head.children[o]
		}
		head.metric = metric
		head.oidList = OidToList(metric.Oid)
	}
	return metricTree
}

type collector struct {
	target string
	module *Module
}

// Describe implements Prometheus.Collector.
func (c collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- prometheus.NewDesc("dummy", "dummy", nil, nil)
}

func PduToSample(metric *Metric, pdu *gosnmp.SnmpPDU) prometheus.Metric {
	return prometheus.MustNewConstMetric(prometheus.NewDesc(metric.Name, "", []string{"label"}, nil),
		prometheus.UntypedValue,
		float64(gosnmp.ToBigInt(pdu.Value).Int64()),
		pdu.Name,
	)
}

// Collect implements Prometheus.Collector.
func (c collector) Collect(ch chan<- prometheus.Metric) {
	start := time.Now()
	pdus, err := ScrapeTarget(c.target, c.module)
	if err != nil {
		log.Errorf("Error scraping target %s: %s", c.target, err)
		return
	}
	ch <- prometheus.MustNewConstMetric(
		prometheus.NewDesc("snmp_scrape_walk_duration_seconds", "Time SNMP walk/bulkwalk took.", nil, nil),
		prometheus.GaugeValue,
		float64(time.Since(start).Seconds()))
	ch <- prometheus.MustNewConstMetric(
		prometheus.NewDesc("snmp_scrape_pdus_returned", "PDUs returned from walk.", nil, nil),
		prometheus.GaugeValue,
		float64(len(pdus)))
	oidToPdu := make(map[string]gosnmp.SnmpPDU, len(pdus))
	for _, pdu := range pdus {
		oidToPdu[pdu.Name[1:]] = pdu
	}

	metricTree := buildMetricTree(c.module.Metrics)
	// Look for metrics that match each pdu.
PduLoop:
	for oid, pdu := range oidToPdu {
		head := metricTree
		oidList := OidToList(oid)
		for _, o := range oidList {
			var ok bool
			head, ok = head.children[o]
			if !ok {
				continue PduLoop
			}
			if head.metric != nil {
				// Found a match.
				ch <- PduToSample(head.metric, &pdu)
				break
			}
		}
	}
	ch <- prometheus.MustNewConstMetric(
		prometheus.NewDesc("snmp_scrape_duration_seconds", "Total SNMP time scrape took (walk and processing).", nil, nil),
		prometheus.GaugeValue,
		float64(time.Since(start).Seconds()))
}

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
		return
	}
	moduleName := r.URL.Query().Get("module")
	if moduleName == "" {
		moduleName = "default"
	}
	module, ok := (*cfg)[moduleName]
	if !ok {
		http.Error(w, fmt.Sprintf("Unkown module '%s'", module), 400)
		return
	}

	registry := prometheus.NewRegistry()
	collector := collector{target: target, module: module}
	registry.MustRegister(collector)
	// Delegate http serving to Promethues client library, which will call collector.Collect.
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func main() {
	flag.Parse()

	http.Handle("/metrics", promhttp.Handler()) // Normal metrics endpoint for SNMP exporter itself.
	http.HandleFunc("/snmp", handler)           // Endpoint to do SNMP scrapes.
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
