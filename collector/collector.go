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

package collector

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/gosnmp/gosnmp"
	"github.com/itchyny/timefmt-go"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/prometheus/snmp_exporter/config"
	"github.com/prometheus/snmp_exporter/scraper"
)

var (
	// 64-bit float mantissa: https://en.wikipedia.org/wiki/Double-precision_floating-point_format
	float64Mantissa uint64 = 9007199254740992
	wrapCounters           = kingpin.Flag("snmp.wrap-large-counters", "Wrap 64-bit counters to avoid floating point rounding.").Default("true").Bool()
	srcAddress             = kingpin.Flag("snmp.source-address", "Source address to send snmp from in the format 'address:port' to use when connecting targets. If the port parameter is empty or '0', as in '127.0.0.1:' or '[::1]:0', a source port number is automatically (random) chosen.").Default("").String()
)

// Types preceded by an enum with their actual type.
var combinedTypeMapping = map[string]map[int]string{
	"InetAddress": {
		1: "InetAddressIPv4",
		2: "InetAddressIPv6",
	},
	"InetAddressMissingSize": {
		1: "InetAddressIPv4",
		2: "InetAddressIPv6",
	},
	"LldpPortId": {
		1: "DisplayString",
		2: "DisplayString",
		3: "PhysAddress48",
		5: "DisplayString",
		7: "DisplayString",
	},
}

func oidToList(oid string) []int {
	result := make([]int, 0, strings.Count(oid, ".")+1)
	for x := range strings.SplitSeq(oid, ".") {
		o, _ := strconv.Atoi(x)
		result = append(result, o)
	}
	return result
}

func listToOid(l []int) string {
	if len(l) == 0 {
		return ""
	}
	var result strings.Builder
	result.Grow(len(l) * 4) // Estimate 3 digits + dot per number
	for i, o := range l {
		if i > 0 {
			result.WriteByte('.')
		}
		result.WriteString(strconv.Itoa(o))
	}
	return result.String()
}

type ScrapeResults struct {
	pdus []gosnmp.SnmpPDU
}

func ScrapeTarget(snmp scraper.SNMPScraper, target string, auth *config.Auth, module *config.Module, logger *slog.Logger, metrics Metrics) (ScrapeResults, error) {
	results := ScrapeResults{}
	// Evaluate rules.
	newGet := module.Get
	newWalk := module.Walk

	// allowedIndicesByTarget accumulates, for each target OID, the
	// intersection of the indices allowed by every filter targeting it.
	// This makes multiple filters that target the same OID act as an AND,
	// rather than the later filter discarding the earlier one's results.
	allowedIndicesByTarget := map[string][]string{}
	var filteredTargets []string

	for _, filter := range module.Filters {
		allowedList := []string{}
		pdus, err := snmp.WalkAll(filter.Oid)
		// Do not try to filter anything if we had errors.
		if err != nil {
			logger.Info("Error getting OID, won't do any filter on this oid", "oid", filter.Oid)
			continue
		}

		allowedList = filterAllowedIndices(logger, filter, pdus, allowedList, metrics)

		// Update config to get only index and not walk them.
		newWalk = updateWalkConfig(newWalk, filter, logger)

		for _, targetOid := range filter.Targets {
			if existing, ok := allowedIndicesByTarget[targetOid]; ok {
				allowedIndicesByTarget[targetOid] = intersectIndices(existing, allowedList)
			} else {
				filteredTargets = append(filteredTargets, targetOid)
				allowedIndicesByTarget[targetOid] = allowedList
			}
		}
	}

	// Apply the combined filters: remove each filtered target OID from the
	// get config once, then add back only the indices allowed by every
	// filter targeting that OID.
	for _, targetOid := range filteredTargets {
		singleTarget := config.DynamicFilter{Targets: []string{targetOid}}
		newGet = updateGetConfig(newGet, singleTarget, logger)
		newGet = addAllowedIndices(singleTarget, allowedIndicesByTarget[targetOid], logger, newGet)
	}

	version := auth.Version
	getOids := newGet
	maxOids := int(module.WalkParams.MaxRepetitions)
	// Max Repetition can be 0, maxOids cannot. SNMPv1 can only report one OID error per call.
	if maxOids == 0 || version == 1 {
		maxOids = 1
	}
	for len(getOids) > 0 {
		oids := min(len(getOids), maxOids)

		packet, err := snmp.Get(getOids[:oids])
		if err != nil {
			return results, err
		}
		// SNMPv1 will return packet error for unsupported OIDs.
		if packet.Error == gosnmp.NoSuchName && version == 1 {
			logger.Debug("OID not supported by target", "oids", getOids[0])
			getOids = getOids[oids:]
			continue
		}
		// Response received with errors.
		// TODO: "stringify" gosnmp errors instead of showing error code.
		if packet.Error != gosnmp.NoError {
			return results, fmt.Errorf("error reported by target %s: Error Status %d", target, packet.Error)
		}
		for _, v := range packet.Variables {
			if v.Type == gosnmp.NoSuchObject || v.Type == gosnmp.NoSuchInstance || v.Type == gosnmp.EndOfMibView {
				logger.Debug("OID not supported by target", "oids", v.Name)
				continue
			}
			results.pdus = append(results.pdus, v)
		}
		getOids = getOids[oids:]
	}

	for _, subtree := range newWalk {
		pdus, err := snmp.WalkAll(subtree)
		if err != nil {
			return results, err
		}
		results.pdus = append(results.pdus, pdus...)
	}
	return results, nil
}

// intersectIndices returns the indices present in both a and b, preserving
// the order of a.
func intersectIndices(a, b []string) []string {
	bSet := make(map[string]bool, len(b))
	for _, idx := range b {
		bSet[idx] = true
	}
	result := make([]string, 0, len(a))
	for _, idx := range a {
		if bSet[idx] {
			result = append(result, idx)
		}
	}
	return result
}

func filterAllowedIndices(logger *slog.Logger, filter config.DynamicFilter, pdus []gosnmp.SnmpPDU, allowedList []string, metrics Metrics) []string {
	logger.Debug("Evaluating rule for oid", "oid", filter.Oid)
	for _, pdu := range pdus {
		found := false
		for _, val := range filter.Values {
			snmpval := pduValueAsString(&pdu, "DisplayString", "", metrics)
			logger.Debug("evaluating filters", "config value", val, "snmp value", snmpval)

			if regexp.MustCompile(val).MatchString(snmpval) {
				found = true
				break
			}
		}
		if found {
			pduArray := strings.Split(pdu.Name, ".")
			index := pduArray[len(pduArray)-1]
			logger.Debug("Caching index", "index", index)
			allowedList = append(allowedList, index)
		}
	}
	return allowedList
}

func updateWalkConfig(walkConfig []string, filter config.DynamicFilter, logger *slog.Logger) []string {
	newCfg := []string{}
	for _, elem := range walkConfig {
		found := false
		for _, targetOid := range filter.Targets {
			if elem == targetOid {
				logger.Debug("Deleting for walk configuration", "oid", targetOid)
				found = true
				break
			}
		}
		// Oid not found in target,  we walk it.
		if !found {
			newCfg = append(newCfg, elem)
		}
	}
	return newCfg
}

func updateGetConfig(getConfig []string, filter config.DynamicFilter, logger *slog.Logger) []string {
	newCfg := []string{}
	for _, elem := range getConfig {
		found := false
		for _, targetOid := range filter.Targets {
			if strings.HasPrefix(elem, targetOid) {
				found = true
				break
			}
		}
		// Oid not found in targets, we keep it.
		if !found {
			logger.Debug("Keeping get configuration", "oid", elem)
			newCfg = append(newCfg, elem)
		}
	}
	return newCfg
}

func addAllowedIndices(filter config.DynamicFilter, allowedList []string, logger *slog.Logger, newCfg []string) []string {
	for _, targetOid := range filter.Targets {
		for _, index := range allowedList {
			logger.Debug("Adding get configuration", "oid", targetOid+"."+index)
			newCfg = append(newCfg, targetOid+"."+index)
		}
	}
	return newCfg
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

type Metrics struct {
	SNMPCollectionDuration *prometheus.HistogramVec
	SNMPUnexpectedPduType  prometheus.Counter
	SNMPDuration           prometheus.Histogram
	SNMPPackets            prometheus.Counter
	SNMPRetries            prometheus.Counter
	SNMPInflight           prometheus.Gauge
}

func getPduValue(pdu *gosnmp.SnmpPDU) float64 {
	switch pdu.Type {
	case gosnmp.Counter64:
		if *wrapCounters {
			// Wrap by 2^53.
			return float64(gosnmp.ToBigInt(pdu.Value).Uint64() % float64Mantissa)
		}
		return float64(gosnmp.ToBigInt(pdu.Value).Uint64())
	case gosnmp.OpaqueFloat:
		return float64(pdu.Value.(float32))
	case gosnmp.OpaqueDouble:
		return pdu.Value.(float64)
	default:
		return float64(gosnmp.ToBigInt(pdu.Value).Int64())
	}
}

// parseDateAndTime extracts a UNIX timestamp from an RFC 2579 DateAndTime.
func parseDateAndTime(pdu *gosnmp.SnmpPDU) (float64, error) {
	var (
		v   []byte
		tz  *time.Location
		err error
	)
	// DateAndTime should be a slice of bytes.
	switch pduType := pdu.Value.(type) {
	case []byte:
		v = pdu.Value.([]byte)
	default:
		return 0, fmt.Errorf("invalid DateAndTime type %v", pduType)
	}
	pduLength := len(v)
	// DateAndTime can be 8 or 11 bytes depending if the time zone is included.
	switch pduLength {
	case 8:
		// No time zone included, assume UTC.
		tz = time.UTC
	case 11:
		// Extract the timezone from the last 3 bytes.
		locString := fmt.Sprintf("%s%02d%02d", string(v[8]), v[9], v[10])
		loc, err := time.Parse("-0700", locString)
		if err != nil {
			return 0, fmt.Errorf("error parsing location string: %q, error: %w", locString, err)
		}
		tz = loc.Location()
	default:
		return 0, fmt.Errorf("invalid DateAndTime length %v", pduLength)
	}
	if err != nil {
		return 0, fmt.Errorf("unable to parse DateAndTime %q, error: %w", v, err)
	}
	// Build the date from the various fields and time zone.
	t := time.Date(
		int(binary.BigEndian.Uint16(v[0:2])),
		time.Month(v[2]),
		int(v[3]),
		int(v[4]),
		int(v[5]),
		int(v[6]),
		int(v[7])*1e+8,
		tz)
	return float64(t.Unix()), nil
}

func parseDateAndTimeWithPattern(metric *config.Metric, pdu *gosnmp.SnmpPDU, metrics Metrics) (float64, error) {
	pduValue := pduValueAsString(pdu, "DisplayString", "", metrics)
	t, err := timefmt.Parse(pduValue, metric.DateTimePattern)
	if err != nil {
		return 0, fmt.Errorf("error parsing date and time %w", err)
	}
	return float64(t.Unix()), nil
}

func parseNtpTimestamp(pdu *gosnmp.SnmpPDU) (float64, error) {
	data, ok := pdu.Value.([]byte)
	if !ok {
		return 0, fmt.Errorf("invalid NTPTimeStamp type %T", pdu.Value)
	}
	if len(data) < 8 {
		return 0, fmt.Errorf("invalid NTPTimeStamp length %d, expected at least 8", len(data))
	}

	// Prometheus uses the Unix time epoch (seconds since 1970).
	// NTP seconds are counted since 1900 and must be corrected
	// by removing 70 yrs of seconds (1970-1900) or 2208988800
	// seconds.
	secs := int64(binary.BigEndian.Uint32(data[:4])) - 2208988800
	nanos := (int64(binary.BigEndian.Uint32(data[4:])) * 1e9) >> 32

	t := time.Unix(secs, nanos)
	return float64(t.Unix()), nil
}

type metricSample struct {
	name        string
	help        string
	labelnames  []string
	labelvalues []string
	valueType   prometheus.ValueType
	value       float64
	oid         string
	info        bool
	err         error
	errorHelp   string
}

func pduToMetricSamples(indexOids []int, pdu *gosnmp.SnmpPDU, metric *config.Metric, oidToPdu map[string]gosnmp.SnmpPDU, logger *slog.Logger, metrics Metrics) []metricSample {
	var err error
	// The part of the OID that is the indexes.
	labels := indexesToLabels(indexOids, metric, oidToPdu, metrics)

	value := getPduValue(pdu)

	labelnames := make([]string, 0, len(labels)+1)
	labelvalues := make([]string, 0, len(labels)+1)
	for k, v := range labels {
		labelnames = append(labelnames, k)
		labelvalues = append(labelvalues, v)
	}

	var t prometheus.ValueType
	switch metric.Type {
	case "counter":
		t = prometheus.CounterValue
	case "gauge":
		t = prometheus.GaugeValue
	case "Float", "Double":
		t = prometheus.GaugeValue
	case "DateAndTime":
		t = prometheus.GaugeValue
		value, err = parseDateAndTime(pdu)
		if err != nil {
			logger.Debug("Error parsing DateAndTime", "err", err)
			return []metricSample{}
		}
	case "ParseDateAndTime":
		t = prometheus.GaugeValue
		value, err = parseDateAndTimeWithPattern(metric, pdu, metrics)
		if err != nil {
			logger.Debug("Error parsing ParseDateAndTime", "err", err)
			return []metricSample{}
		}
	case "NTPTimeStamp":
		t = prometheus.GaugeValue
		value, err = parseNtpTimestamp(pdu)
		if err != nil {
			logger.Debug("Error parsing NTPTimeStamp", "err", err)
			return []metricSample{}
		}
	case "EnumAsInfo":
		return enumAsInfo(metric, int(value), labelnames, labelvalues, pdu.Name)
	case "EnumAsStateSet":
		return enumAsStateSet(metric, int(value), labelnames, labelvalues, pdu.Name)
	case "Bits":
		return bits(metric, pdu.Value, labelnames, labelvalues, pdu.Name)
	default:
		// It's some form of string.
		t = prometheus.GaugeValue
		value = 1.0
		metricType := metric.Type

		if typeMapping, ok := combinedTypeMapping[metricType]; ok {
			// Lookup associated sub type in previous object.
			prevOid := fmt.Sprintf("%s.%s", getPrevOid(metric.Oid), listToOid(indexOids))
			if prevPdu, ok := oidToPdu[prevOid]; ok {
				val := int(getPduValue(&prevPdu))
				if t, ok := typeMapping[val]; ok {
					metricType = t
				} else {
					metricType = "OctetString"
					logger.Debug("Unable to handle type value", "value", val, "oid", prevOid, "metric", metric.Name)
				}
			} else {
				metricType = "OctetString"
				logger.Debug("Unable to find type at oid for metric", "oid", prevOid, "metric", metric.Name)
			}
		}

		if len(metric.RegexpExtracts) > 0 {
			return applyRegexExtracts(metric, pduValueAsString(pdu, metricType, metric.DisplayHint, metrics), labelnames, labelvalues, pdu.Name, logger)
		}
		// For strings we put the value as a label with the same name as the metric.
		// If the name is already an index, we do not need to set it again.
		if _, ok := labels[metric.Name]; !ok {
			labelnames = append(labelnames, metric.Name)
			labelvalues = append(labelvalues, pduValueAsString(pdu, metricType, metric.DisplayHint, metrics))
		}
	}

	if metric.Scale != 0.0 {
		value *= metric.Scale
	}
	value += metric.Offset

	return []metricSample{{
		name:        metric.Name,
		help:        metric.Help,
		labelnames:  labelnames,
		labelvalues: labelvalues,
		valueType:   t,
		value:       value,
		oid:         strings.TrimPrefix(pdu.Name, "."),
	}}
}

func applyRegexExtracts(metric *config.Metric, pduValue string, labelnames, labelvalues []string, oid string, logger *slog.Logger) []metricSample {
	results := []metricSample{}
	for name, strMetricSlice := range metric.RegexpExtracts {
		for _, strMetric := range strMetricSlice {
			indexes := strMetric.Regex.FindStringSubmatchIndex(pduValue)
			if indexes == nil {
				logger.Debug("No match found for regexp", "metric", metric.Name, "value", pduValue, "regex", strMetric.Regex.String())
				continue
			}
			res := strMetric.Regex.ExpandString([]byte{}, strMetric.Value, pduValue, indexes)
			v, err := strconv.ParseFloat(string(res), 64)
			if err != nil {
				logger.Debug("Error parsing float64 from value", "metric", metric.Name, "value", pduValue, "regex", strMetric.Regex.String(), "extracted_value", res)
				continue
			}
			if metric.Scale != 0.0 {
				v *= metric.Scale
			}
			v += metric.Offset
			results = append(results, metricSample{
				name:        metric.Name + name,
				help:        metric.Help + " (regex extracted)",
				labelnames:  labelnames,
				labelvalues: labelvalues,
				valueType:   prometheus.GaugeValue,
				value:       v,
				oid:         strings.TrimPrefix(oid, "."),
			})
			break
		}
	}
	return results
}

func enumAsInfo(metric *config.Metric, value int, labelnames, labelvalues []string, oid string) []metricSample {
	// Lookup enum, default to the value.
	state, ok := metric.EnumValues[int(value)]
	if !ok {
		state = strconv.Itoa(int(value))
	}
	// If the metric name is already a label (e.g. it is also a table index with
	// type EnumAsInfo), the enum string is already captured there and we must not
	// add it again or Prometheus will reject the duplicate label.
	for _, ln := range labelnames {
		if ln == metric.Name {
			return []metricSample{}
		}
	}
	labelnames = append(labelnames, metric.Name)
	labelvalues = append(labelvalues, state)

	return []metricSample{{
		name:        metric.Name + "_info",
		help:        metric.Help + " (EnumAsInfo)",
		labelnames:  labelnames,
		labelvalues: labelvalues,
		valueType:   prometheus.GaugeValue,
		value:       1,
		oid:         strings.TrimPrefix(oid, "."),
		info:        true,
	}}
}

func enumAsStateSet(metric *config.Metric, value int, labelnames, labelvalues []string, oid string) []metricSample {
	labelnames = append(labelnames, metric.Name)
	results := []metricSample{}

	state, ok := metric.EnumValues[value]
	if !ok {
		// Fallback to using the value.
		state = strconv.Itoa(value)
	}
	results = append(results, metricSample{
		name:        metric.Name,
		help:        metric.Help + " (EnumAsStateSet)",
		labelnames:  labelnames,
		labelvalues: append(append([]string(nil), labelvalues...), state),
		valueType:   prometheus.GaugeValue,
		value:       1,
		oid:         strings.TrimPrefix(oid, "."),
	})

	for k, v := range metric.EnumValues {
		if k == value {
			continue
		}
		results = append(results, metricSample{
			name:        metric.Name,
			help:        metric.Help + " (EnumAsStateSet)",
			labelnames:  labelnames,
			labelvalues: append(append([]string(nil), labelvalues...), v),
			valueType:   prometheus.GaugeValue,
			value:       0,
			oid:         strings.TrimPrefix(oid, "."),
		})
	}
	return results
}

func bits(metric *config.Metric, value any, labelnames, labelvalues []string, oid string) []metricSample {
	bytes, ok := value.([]byte)
	if !ok {
		return []metricSample{{
			err:       fmt.Errorf("error for metric %s with labels %v: %T", metric.Name, labelvalues, value),
			errorHelp: "BITS type was not a BISTRING on the wire.",
		}}
	}
	labelnames = append(labelnames, metric.Name)
	results := []metricSample{}

	for k, v := range metric.EnumValues {
		bit := 0.0
		// Most significant byte most significant bit, then most significant byte 2nd most significant bit etc.
		if k < len(bytes)*8 {
			if (bytes[k/8] & (128 >> (k % 8))) != 0 {
				bit = 1.0
			}
		}
		results = append(results, metricSample{
			name:        metric.Name,
			help:        metric.Help + " (Bits)",
			labelnames:  labelnames,
			labelvalues: append(append([]string(nil), labelvalues...), v),
			valueType:   prometheus.GaugeValue,
			value:       bit,
			oid:         strings.TrimPrefix(oid, "."),
		})
	}
	return results
}

// Right pad oid with zeros, and split at the given point.
// Some routers exclude trailing 0s in responses.
func splitOid(oid []int, count int) ([]int, []int) {
	head := make([]int, count)
	tailCapacity := len(oid) - count
	if tailCapacity < 0 {
		tailCapacity = 0
	}
	tail := make([]int, 0, tailCapacity)
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
func pduValueAsString(pdu *gosnmp.SnmpPDU, typ, displayHint string, metrics Metrics) string {
	switch v := pdu.Value.(type) {
	case int:
		return strconv.Itoa(v)
	case uint:
		return strconv.FormatUint(uint64(v), 10)
	case uint32:
		return strconv.FormatUint(uint64(v), 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	case float32:
		return strconv.FormatFloat(float64(v), 'f', -1, 32)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case string:
		if pdu.Type == gosnmp.ObjectIdentifier {
			// Trim leading period.
			return v[1:]
		}
		// DisplayString.
		return strings.ToValidUTF8(v, "�")
	case []byte:
		// Apply DISPLAY-HINT if provided and type is OctetString
		if displayHint != "" && (typ == "" || typ == "OctetString") {
			if result, ok := applyDisplayHint(displayHint, v); ok {
				return strings.ToValidUTF8(result, "�")
			}
			// Fall through to default formatting on parse error
		}
		if typ == "" || typ == "Bits" {
			typ = "OctetString"
		}
		// Reuse the OID index parsing code.
		parts := make([]int, len(v))
		for i, o := range v {
			parts[i] = int(o)
		}
		if typ == "OctetString" || typ == "DisplayString" {
			// Prepend the length, as it is explicit in an index.
			parts = append([]int{len(v)}, parts...)
		}
		str, _, _ := indexOidsAsString(parts, typ, 0, false, nil)
		return strings.ToValidUTF8(str, "�")
	case nil:
		return ""
	default:
		// This shouldn't happen.
		metrics.SNMPUnexpectedPduType.Inc()
		return fmt.Sprintf("%s", pdu.Value)
	}
}

// Convert oids to a string index value.
//
// Returns the string, the oids that were used and the oids left over.
func indexOidsAsString(indexOids []int, typ string, fixedSize int, implied bool, enumValues map[int]string) (string, []int, []int) {
	if typeMapping, ok := combinedTypeMapping[typ]; ok {
		subOid, valueOids := splitOid(indexOids, 2)
		if typ == "InetAddressMissingSize" {
			// The size of the main index value is missing.
			subOid, valueOids = splitOid(indexOids, 1)
		}
		var str string
		var used, remaining []int
		if t, ok := typeMapping[subOid[0]]; ok {
			str, used, remaining = indexOidsAsString(valueOids, t, 0, false, enumValues)
			return str, append(subOid, used...), remaining
		}
		if typ == "InetAddressMissingSize" {
			// We don't know the size, so pass everything remaining.
			return indexOidsAsString(indexOids, "OctetString", 0, true, enumValues)
		}
		// The 2nd oid is the length.
		return indexOidsAsString(indexOids, "OctetString", subOid[1]+2, false, enumValues)
	}

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
		var subOid []int
		// The length of fixed size indexes come from the MIB.
		// For varying size, we read it from the first oid.
		length := fixedSize
		if implied {
			length = len(indexOids)
		}
		if length == 0 {
			subOid, indexOids = splitOid(indexOids, 1)
			length = subOid[0]
		}
		content, indexOids := splitOid(indexOids, length)
		subOid = append(subOid, content...)
		parts := make([]byte, length)
		for i, o := range content {
			parts[i] = byte(o)
		}
		if len(parts) == 0 {
			return "", subOid, indexOids
		}
		return fmt.Sprintf("0x%X", string(parts)), subOid, indexOids
	case "DisplayString":
		var subOid []int
		length := fixedSize
		if implied {
			length = len(indexOids)
		}
		if length == 0 {
			subOid, indexOids = splitOid(indexOids, 1)
			length = subOid[0]
		}
		content, indexOids := splitOid(indexOids, length)
		subOid = append(subOid, content...)
		parts := make([]byte, length)
		for i, o := range content {
			parts[i] = byte(o)
		}
		// ASCII, so can convert staight to utf-8.
		return string(parts), subOid, indexOids
	case "InetAddressIPv4":
		subOid, indexOids := splitOid(indexOids, 4)
		parts := make([]string, 4)
		for i, o := range subOid {
			parts[i] = strconv.Itoa(o)
		}
		return strings.Join(parts, "."), subOid, indexOids
	case "InetAddressIPv6":
		subOid, indexOids := splitOid(indexOids, 16)
		parts := make([]any, 16)
		for i, o := range subOid {
			parts[i] = o
		}
		return fmt.Sprintf("%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X", parts...), subOid, indexOids
	case "EnumAsInfo":
		subOid, indexOids := splitOid(indexOids, 1)
		value, ok := enumValues[subOid[0]]
		if ok {
			return value, subOid, indexOids
		}
		return fmt.Sprintf("%d", subOid[0]), subOid, indexOids
	default:
		panic(fmt.Sprintf("Unknown index type %s", typ))
	}
}

func getPrevOid(oid string) string {
	oids := strings.Split(oid, ".")
	i, _ := strconv.Atoi(oids[len(oids)-1])
	oids[len(oids)-1] = strconv.Itoa(i - 1)
	return strings.Join(oids, ".")
}

func indexesToLabels(indexOids []int, metric *config.Metric, oidToPdu map[string]gosnmp.SnmpPDU, metrics Metrics) map[string]string {
	labels := map[string]string{}
	labelOids := map[string][]int{}

	// Covert indexes to useful strings.
	for _, index := range metric.Indexes {
		str, subOid, remainingOids := indexOidsAsString(indexOids, index.Type, index.FixedSize, index.Implied, index.EnumValues)
		// The labelvalue is the text form of the index oids. Ensure it is valid UTF-8,
		// as required for Prometheus label values.
		labels[index.Labelname] = strings.ToValidUTF8(str, "�")
		// Save its oid in case we need it for lookups.
		labelOids[index.Labelname] = subOid
		// For the next iteration.
		indexOids = remainingOids
	}

	// Perform lookups.
	for _, lookup := range metric.Lookups {
		if len(lookup.Labels) == 0 {
			delete(labels, lookup.Labelname)
			continue
		}
		oid := lookup.Oid
		for _, label := range lookup.Labels {
			oid = fmt.Sprintf("%s.%s", oid, listToOid(labelOids[label]))
		}
		if pdu, ok := oidToPdu[oid]; ok {
			t := lookup.Type
			if typeMapping, ok := combinedTypeMapping[lookup.Type]; ok {
				// Lookup associated sub type in previous object.
				prevOid := getPrevOid(lookup.Oid)
				for _, label := range lookup.Labels {
					prevOid = fmt.Sprintf("%s.%s", prevOid, listToOid(labelOids[label]))
				}
				if prevPdu, ok := oidToPdu[prevOid]; ok {
					val := int(getPduValue(&prevPdu))
					if ty, ok := typeMapping[val]; ok {
						t = ty
					}
				}
			}
			if t == "EnumAsInfo" && len(lookup.EnumValues) > 0 {
				intVal := int(gosnmp.ToBigInt(pdu.Value).Int64())
				if str, ok := lookup.EnumValues[intVal]; ok {
					labels[lookup.Labelname] = str
				} else {
					labels[lookup.Labelname] = strconv.Itoa(intVal)
				}
			} else {
				labels[lookup.Labelname] = pduValueAsString(&pdu, t, lookup.DisplayHint, metrics)
			}
			labelOids[lookup.Labelname] = []int{int(gosnmp.ToBigInt(pdu.Value).Int64())}
		} else {
			labels[lookup.Labelname] = ""
		}
	}

	return labels
}
