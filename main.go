package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"time"

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
		"web.listen-address", ":9104",
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

func main() {
	flag.Parse()

	cfg, err := LoadFile(*configFile)
	if err != nil {
		log.Errorf("Error parsing config file: %s", err)
		return
	}
	_ = cfg

	module := (*cfg)["default"]
	metricTree := buildMetricTree(module.Metrics)

	pdus, err := ScrapeTarget("192.168.1.2", module)
	oidToPdu := make(map[string]*gosnmp.SnmpPDU, len(pdus))
	for _, pdu := range pdus {
		oidToPdu[pdu.Name[1:]] = &pdu
	}

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
				fmt.Printf("Metric: %s Value: %s Remaining Oid: %s\n", head.metric.Name, pdu.Value, oidList[len(head.oidList):])
				break
			}
		}
	}
}
