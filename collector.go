package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"github.com/soniah/gosnmp"

	"github.com/prometheus/snmp_exporter/config"
)

var (
	snmpUnexpectedPduType = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "snmp_unexpected_pdu_type_total",
			Help: "Unexpected Go types in a PDU.",
		},
	)
)

func init() {
	prometheus.MustRegister(snmpUnexpectedPduType)
}

func oidToList(oid string) []int {
	result := []int{}
	for _, x := range strings.Split(oid, ".") {
		o, _ := strconv.Atoi(x)
		result = append(result, o)
	}
	return result
}

func ScrapeTarget(target string, config *config.Module) ([]gosnmp.SnmpPDU, error) {
	// Set the options.
	snmp := gosnmp.GoSNMP{}
	snmp.MaxRepetitions = config.MaxRepetitions
	// User specifies timeout of each retry attempt but GoSNMP expects total timeout for all attemtps.
	snmp.Retries = config.Retries
	snmp.Timeout = config.Timeout * time.Duration(snmp.Retries)

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

	// Configure auth.
	config.ConfigureSNMP(&snmp)

	// Do the actual walk.
	err := snmp.Connect()
	if err != nil {
		return nil, fmt.Errorf("Error connecting to target %s: %s", target, err)
	}
	defer snmp.Conn.Close()

	result := []gosnmp.SnmpPDU{}
	for _, subtree := range config.Walk {
		var pdus []gosnmp.SnmpPDU
		log.Debugf("Walking target %q subtree %q", snmp.Target, subtree)
		walkStart := time.Now()
		if snmp.Version == gosnmp.Version1 {
			pdus, err = snmp.WalkAll(subtree)
		} else {
			pdus, err = snmp.BulkWalkAll(subtree)
		}
		if err != nil {
			return nil, fmt.Errorf("Error walking target %s: %s", snmp.Target, err)
		} else {
			log.Debugf("Walk of target %q subtree %q completed in %s", snmp.Target, subtree, time.Since(walkStart))
		}
		result = append(result, pdus...)
	}
	return result, nil
}

type MetricNode struct {
	metric *config.Metric

	children map[int]*MetricNode
}

// Build a tree of metrics from the config, for fast lookup when there's lots of them.
func buildMetricTree(metrics []*config.Metric) *MetricNode {
	metricTree := &MetricNode{children: map[int]*MetricNode{}}
	for _, metric := range metrics {
		head := metricTree
		for _, o := range oidToList(metric.Oid) {
			_, ok := head.children[o]
			if !ok {
				head.children[o] = &MetricNode{children: map[int]*MetricNode{}}
			}
			head = head.children[o]
		}
		head.metric = metric
	}
	return metricTree
}

type collector struct {
	target string
	module *config.Module
}

// Describe implements Prometheus.Collector.
func (c collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- prometheus.NewDesc("dummy", "dummy", nil, nil)
}

// Collect implements Prometheus.Collector.
func (c collector) Collect(ch chan<- prometheus.Metric) {
	start := time.Now()
	pdus, err := ScrapeTarget(c.target, c.module)
	if err != nil {
		log.Infof("Error scraping target %s: %s", c.target, err)
		ch <- prometheus.NewInvalidMetric(prometheus.NewDesc("snmp_error", "Error scraping target", nil, nil), err)
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
		oidList := oidToList(oid)
		for i, o := range oidList {
			var ok bool
			head, ok = head.children[o]
			if !ok {
				continue PduLoop
			}
			if head.metric != nil {
				// Found a match.
				ch <- pduToSample(oidList[i+1:], &pdu, head.metric, oidToPdu)
				break
			}
		}
	}
	ch <- prometheus.MustNewConstMetric(
		prometheus.NewDesc("snmp_scrape_duration_seconds", "Total SNMP time scrape took (walk and processing).", nil, nil),
		prometheus.GaugeValue,
		float64(time.Since(start).Seconds()))
}

func pduToSample(indexOids []int, pdu *gosnmp.SnmpPDU, metric *config.Metric, oidToPdu map[string]gosnmp.SnmpPDU) prometheus.Metric {
	// The part of the OID that is the indexes.
	labels := indexesToLabels(indexOids, metric, oidToPdu)

	value := float64(gosnmp.ToBigInt(pdu.Value).Int64())
	t := prometheus.UntypedValue
	stringType := false

	switch metric.Type {
	case "counter":
		t = prometheus.CounterValue
	case "gauge":
		t = prometheus.GaugeValue
	default:
		// It's some form of string.
		t = prometheus.GaugeValue
		value = 1.0
		stringType = true
	}

	labelnames := make([]string, 0, len(labels)+1)
	labelvalues := make([]string, 0, len(labels)+1)
	for k, v := range labels {
		labelnames = append(labelnames, k)
		labelvalues = append(labelvalues, v)
	}
	// For strings we put the value as a label with the same name as the metric.
	// If the name is already an index, we do not need to set it again.
	if stringType {
		if _, ok := labels[metric.Name]; !ok {
			labelnames = append(labelnames, metric.Name)
			labelvalues = append(labelvalues, pduValueAsString(pdu, metric.Type))
		}
	}

	return prometheus.MustNewConstMetric(prometheus.NewDesc(metric.Name, metric.Help, labelnames, nil),
		t, value, labelvalues...)
}

// Right pad oid with zeros, and split at the given point.
// Some routers exclude trailing 0s in responses.
func splitOid(oid []int, count int) ([]int, []int) {
	head := make([]int, count)
	tail := []int{}
	for i, v := range oid {
		if i < count {
			head[i] = v
		} else {
			tail = append(tail, v)
		}
	}
	return head, tail
}

// This mirrors decodeValue in gosnmp's helper.go.
func pduValueAsString(pdu *gosnmp.SnmpPDU, typ string) string {
	switch pdu.Value.(type) {
	case int:
		return strconv.Itoa(pdu.Value.(int))
	case uint:
		return strconv.FormatUint(uint64(pdu.Value.(uint)), 10)
	case uint64:
		return strconv.FormatUint(pdu.Value.(uint64), 10)
	case string:
		if pdu.Type == gosnmp.ObjectIdentifier {
			// Trim leading period.
			return pdu.Value.(string)[1:]
		}
		// DisplayString
		return pdu.Value.(string)
	case []byte:
		if typ == "" {
			typ = "OctetString"
		}
		// Reuse the OID index parsing code.
		parts := make([]int, len(pdu.Value.([]byte)))
		for i, o := range pdu.Value.([]byte) {
			parts[i] = int(o)
		}
		if typ == "OctetString" || typ == "DisplayString" {
			// Prepend the length, as it is explicit in an index.
			parts = append([]int{len(pdu.Value.([]byte))}, parts...)
		}
		str, _, _ := indexOidsAsString(parts, typ)
		return str
	case nil:
		return ""
	default:
		// This shouldn't happen.
		log.Infof("Got PDU with unexpected type: Name: %s Value: '%s', Go Type: %T SNMP Type: %s", pdu.Name, pdu.Value, pdu.Value, pdu.Type)
		snmpUnexpectedPduType.Inc()
		return fmt.Sprintf("%s", pdu.Value)
	}
}

// Convert oids to a string index value.
//
// Returns the string, the oids that were used and the oids left over.
func indexOidsAsString(indexOids []int, typ string) (string, []int, []int) {
	switch typ {
	case "Integer32", "Integer", "gauge", "counter":
		// Extract the oid for this index, and keep the remainder for the next index.
		subOid, indexOids := splitOid(indexOids, 1)
		return fmt.Sprintf("%d", subOid[0]), subOid, indexOids
	case "PhysAddress48":
		subOid, indexOids := splitOid(indexOids, 6)
		parts := make([]string, 6)
		for i, o := range subOid {
			parts[i] = fmt.Sprintf("%02X", o)
		}
		return strings.Join(parts, ":"), subOid, indexOids
	case "OctetString":
		subOid, indexOids := splitOid(indexOids, 1)
		length := subOid[0]
		content, indexOids := splitOid(indexOids, length)
		subOid = append(subOid, content...)
		parts := make([]byte, length)
		for i, o := range content {
			parts[i] = byte(o)
		}
		if len(parts) == 0 {
			return "", subOid, indexOids
		} else {
			return fmt.Sprintf("0x%X", string(parts)), subOid, indexOids
		}
	case "DisplayString":
		subOid, indexOids := splitOid(indexOids, 1)
		length := subOid[0]
		content, indexOids := splitOid(indexOids, length)
		subOid = append(subOid, content...)
		parts := make([]byte, length)
		for i, o := range content {
			parts[i] = byte(o)
		}
		// ASCII, so can convert staight to utf-8.
		return string(parts), subOid, indexOids
	case "InetAddress":
		addressType, indexOids := splitOid(indexOids, 1)
		octets, indexOids := splitOid(indexOids, 1)
		address, indexOids := splitOid(indexOids, octets[0])
		subOid := append(addressType, octets...)
		subOid = append(subOid, address...)
		if addressType[0] == 1 { // IPv4.
			parts := make([]string, 4)
			for i, o := range address {
				parts[i] = strconv.Itoa(o)
			}
			return strings.Join(parts, "."), subOid, indexOids
		} else if addressType[0] == 2 { // IPv6.
			parts := make([]string, 8)
			for i := 0; i < 8; i++ {
				parts[i] = fmt.Sprintf("%02X%02X", address[i*2], address[i*2+1])
			}
			return strings.Join(parts, ":"), subOid, indexOids
		} else { // Unknown, treat as OctetString.
			parts := make([]byte, octets[0])
			for i, o := range address {
				parts[i] = byte(o)
			}
			return fmt.Sprintf("0x%X", string(parts)), subOid, indexOids
		}
	case "IpAddr":
		subOid, indexOids := splitOid(indexOids, 4)
		parts := make([]string, 4)
		for i, o := range subOid {
			parts[i] = strconv.Itoa(o)
		}
		return strings.Join(parts, "."), subOid, indexOids
	case "InetAddressType":
		subOid, indexOids := splitOid(indexOids, 1)
		switch subOid[0] {
		case 0:
			return "unknown", subOid, indexOids
		case 1:
			return "ipv4", subOid, indexOids
		case 2:
			return "ipv6", subOid, indexOids
		case 3:
			return "ipv4z", subOid, indexOids
		case 4:
			return "ipv6z", subOid, indexOids
		case 16:
			return "dns", subOid, indexOids
		default:
			return strconv.Itoa(subOid[0]), subOid, indexOids
		}
	default:
		log.Fatalf("Unknown index type %s", typ)
		return "", nil, nil
	}
}

func indexesToLabels(indexOids []int, metric *config.Metric, oidToPdu map[string]gosnmp.SnmpPDU) map[string]string {
	labels := map[string]string{}
	labelOids := map[string][]int{}

	// Covert indexes to useful strings.
	for _, index := range metric.Indexes {
		str, subOid, remainingOids := indexOidsAsString(indexOids, index.Type)
		// The labelvalue is the text form of the index oids.
		labels[index.Labelname] = str
		// Save its oid in case we need it for lookups.
		labelOids[index.Labelname] = subOid
		// For the next iteration.
		indexOids = remainingOids
	}

	// Perform lookups.
	for _, lookup := range metric.Lookups {
		oid := lookup.Oid
		for _, label := range lookup.Labels {
			for _, o := range labelOids[label] {
				oid = fmt.Sprintf("%s.%d", oid, o)
			}
		}
		if pdu, ok := oidToPdu[oid]; ok {
			labels[lookup.Labelname] = pduValueAsString(&pdu, lookup.Type)
		} else {
			labels[lookup.Labelname] = ""
		}
	}

	return labels
}
