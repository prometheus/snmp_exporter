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
	"errors"
	"reflect"
	"regexp"
	"testing"

	"github.com/go-kit/log"
	"github.com/gosnmp/gosnmp"
	"github.com/prometheus/client_model/go"
	kingpin "gopkg.in/alecthomas/kingpin.v2"

	"github.com/prometheus/snmp_exporter/config"
)

func TestPduToSample(t *testing.T) {

	cases := []struct {
		pdu             *gosnmp.SnmpPDU
		indexOids       []int
		metric          *config.Metric
		oidToPdu        map[string]gosnmp.SnmpPDU
		expectedMetrics []string
		shouldErr       bool
	}{
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.1.1.1.1",
				Value: "SomeStringValue",
			},
			indexOids: []int{},
			metric: &config.Metric{
				Name: "TestMetricName",
				Oid:  "1.1.1.1.1",
				Help: "HelpText",
				RegexpExtracts: map[string][]config.RegexpExtract{
					"Extension": []config.RegexpExtract{
						{
							Regex: config.Regexp{
								regexp.MustCompile(".*"),
							},
							Value: "5",
						},
					},
				},
			},
			oidToPdu: make(map[string]gosnmp.SnmpPDU),
			expectedMetrics: []string{
				`Desc{fqName: "TestMetricNameExtension", help: "HelpText (regex extracted)", constLabels: {}, variableLabels: []} gauge:<value:5 > `,
			},
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.1.1.1.1",
				Value: "SomeStringValue",
			},
			indexOids: []int{},
			metric: &config.Metric{
				Name: "TestMetricName",
				Oid:  "1.1.1.1.1",
				Help: "HelpText",
				RegexpExtracts: map[string][]config.RegexpExtract{
					"Extension": []config.RegexpExtract{
						{
							Regex: config.Regexp{
								regexp.MustCompile(".*"),
							},
							Value: "",
						},
					},
				},
			},
			expectedMetrics: []string{},
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.1.1.1.1",
				Value: "SomeStringValue",
			},
			indexOids: []int{},
			metric: &config.Metric{
				Name: "TestMetricName",
				Oid:  "1.1.1.1.1",
				Help: "HelpText",
				RegexpExtracts: map[string][]config.RegexpExtract{
					"Extension": []config.RegexpExtract{
						{
							Regex: config.Regexp{
								regexp.MustCompile("(will_not_match)"),
							},
							Value: "",
						},
					},
				},
			},
			expectedMetrics: []string{},
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.1.1.1.1",
				Value: 2,
			},
			indexOids: []int{},
			metric: &config.Metric{
				Name: "TestMetricName",
				Oid:  "1.1.1.1.1",
				Help: "HelpText",
				RegexpExtracts: map[string][]config.RegexpExtract{
					"Status": []config.RegexpExtract{
						{
							Regex: config.Regexp{
								regexp.MustCompile(".*"),
							},
							Value: "5",
						},
					},
				},
			},
			expectedMetrics: []string{
				`Desc{fqName: "TestMetricNameStatus", help: "HelpText (regex extracted)", constLabels: {}, variableLabels: []} gauge:<value:5 > `,
			},
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.1.1.1.1",
				Value: "Test value 4.42 123 999",
			},
			indexOids: []int{},
			metric: &config.Metric{
				Name: "TestMetricName",
				Oid:  "1.1.1.1.1",
				Help: "HelpText",
				RegexpExtracts: map[string][]config.RegexpExtract{
					"Blank": []config.RegexpExtract{
						{
							Regex: config.Regexp{
								regexp.MustCompile("^XXXX$"),
							},
							Value: "4",
						},
					},
					"Extension": []config.RegexpExtract{
						{
							Regex: config.Regexp{
								regexp.MustCompile(".*"),
							},
							Value: "5",
						},
					},
					"MultipleRegexes": []config.RegexpExtract{
						{
							Regex: config.Regexp{
								regexp.MustCompile("^XXXX$"),
							},
							Value: "123",
						},
						{
							Regex: config.Regexp{
								regexp.MustCompile("123.*"),
							},
							Value: "999",
						},
						{
							Regex: config.Regexp{
								regexp.MustCompile(".*"),
							},
							Value: "777",
						},
					},
					"Template": []config.RegexpExtract{
						{
							Regex: config.Regexp{
								regexp.MustCompile("([0-9].[0-9]+)"),
							},
							Value: "$1",
						},
					},
				},
			},
			oidToPdu: make(map[string]gosnmp.SnmpPDU),
			expectedMetrics: []string{
				`Desc{fqName: "TestMetricNameExtension", help: "HelpText (regex extracted)", constLabels: {}, variableLabels: []} gauge:<value:5 > `,
				`Desc{fqName: "TestMetricNameMultipleRegexes", help: "HelpText (regex extracted)", constLabels: {}, variableLabels: []} gauge:<value:999 > `,
				`Desc{fqName: "TestMetricNameTemplate", help: "HelpText (regex extracted)", constLabels: {}, variableLabels: []} gauge:<value:4.42 > `,
			},
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.1.1.1.1",
				Type:  gosnmp.Integer,
				Value: 2,
			},
			indexOids: []int{},
			metric: &config.Metric{
				Name: "test_metric",
				Oid:  "1.1.1.1.1",
				Type: "counter",
				Help: "Help string",
			},
			oidToPdu:        make(map[string]gosnmp.SnmpPDU),
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: []} counter:<value:2 > `},
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.1.1.1.1",
				Type:  gosnmp.Integer,
				Value: 2,
			},
			indexOids: []int{},
			metric: &config.Metric{
				Name: "test_metric",
				Oid:  "1.1.1.1.1",
				Type: "gauge",
				Help: "Help string",
			},
			oidToPdu:        make(map[string]gosnmp.SnmpPDU),
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: []} gauge:<value:2 > `},
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.1.1.1.1",
				Type:  gosnmp.Integer,
				Value: -2,
			},
			indexOids: []int{},
			metric: &config.Metric{
				Name: "test_metric",
				Oid:  "1.1.1.1.1",
				Help: "Help string",
			},
			oidToPdu:        make(map[string]gosnmp.SnmpPDU),
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: [test_metric]} label:<name:"test_metric" value:"-2" > gauge:<value:1 > `},
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.1.1.1.1",
				Type:  gosnmp.OpaqueFloat,
				Value: float32(3.0),
			},
			indexOids: []int{},
			metric: &config.Metric{
				Name: "test_metric",
				Oid:  "1.1.1.1.1",
				Type: "gauge",
				Help: "Help string",
			},
			oidToPdu:        make(map[string]gosnmp.SnmpPDU),
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: []} gauge:<value:3 > `},
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.1.1.1.1",
				Type:  gosnmp.OpaqueDouble,
				Value: float64(3.0),
			},
			indexOids: []int{},
			metric: &config.Metric{
				Name: "test_metric",
				Oid:  "1.1.1.1.1",
				Type: "gauge",
				Help: "Help string",
			},
			oidToPdu:        make(map[string]gosnmp.SnmpPDU),
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: []} gauge:<value:3 > `},
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.1.1.1.1",
				Type:  gosnmp.Integer,
				Value: 3,
			},
			indexOids: []int{2, 65, 65},
			metric: &config.Metric{
				Name:    "test_metric",
				Oid:     "1.1.1.1.1",
				Type:    "gauge",
				Help:    "Help string",
				Indexes: []*config.Index{{Labelname: "foo", Type: "DisplayString"}},
			},
			oidToPdu:        make(map[string]gosnmp.SnmpPDU),
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: [foo]} label:<name:"foo" value:"AA" > gauge:<value:3 > `},
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.1.1.1.1",
				Type:  gosnmp.Integer,
				Value: 3,
			},
			indexOids: []int{2, 65, 255},
			metric: &config.Metric{
				Name:    "test_metric",
				Oid:     "1.1.1.1.1",
				Type:    "gauge",
				Help:    "Help string",
				Indexes: []*config.Index{{Labelname: "foo", Type: "DisplayString"}},
			},
			oidToPdu:  make(map[string]gosnmp.SnmpPDU),
			shouldErr: true, // Invalid ASCII/UTF-8 string.
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.1.1.1.1",
				Type:  gosnmp.Integer,
				Value: 3,
			},
			indexOids: []int{2, 65, 255},
			metric: &config.Metric{
				Name:    "test_metric",
				Oid:     "1.1.1.1.1",
				Type:    "gauge",
				Help:    "Help string",
				Indexes: []*config.Index{{Labelname: "foo", Type: "DisplayString"}},
				RegexpExtracts: map[string][]config.RegexpExtract{
					"": []config.RegexpExtract{{Value: "1", Regex: config.Regexp{regexp.MustCompile(".*")}}},
				},
			},
			oidToPdu:  make(map[string]gosnmp.SnmpPDU),
			shouldErr: true, // Invalid ASCII/UTF-8 string.
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.42.2",
				Value: []byte{4, 5, 6, 7},
			},
			indexOids: []int{2},
			metric: &config.Metric{
				Name: "test_metric",
				Oid:  "1.42",
				Type: "InetAddress",
				Help: "Help string",
			},
			oidToPdu:        map[string]gosnmp.SnmpPDU{"1.41.2": gosnmp.SnmpPDU{Value: 1}},
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: [test_metric]} label:<name:"test_metric" value:"4.5.6.7" > gauge:<value:1 > `},
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.42.2",
				Value: []byte{4, 5, 6, 7},
			},
			indexOids: []int{2},
			metric: &config.Metric{
				Name: "test_metric",
				Oid:  "1.42",
				Type: "InetAddressMissingSize",
				Help: "Help string",
			},
			oidToPdu:        map[string]gosnmp.SnmpPDU{"1.41.2": gosnmp.SnmpPDU{Value: 1}},
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: [test_metric]} label:<name:"test_metric" value:"4.5.6.7" > gauge:<value:1 > `},
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.42.2",
				Value: []byte{4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
			},
			indexOids: []int{2},
			metric: &config.Metric{
				Name: "test_metric",
				Oid:  "1.42",
				Type: "InetAddress",
				Help: "Help string",
			},
			oidToPdu:        map[string]gosnmp.SnmpPDU{"1.41.2": gosnmp.SnmpPDU{Value: 2}},
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: [test_metric]} label:<name:"test_metric" value:"0405:0607:0809:0A0B:0C0D:0E0F:1011:1213" > gauge:<value:1 > `},
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.42.2",
				Value: []byte{4, 5, 6, 7, 8},
			},
			indexOids: []int{2},
			metric: &config.Metric{
				Name: "test_metric",
				Oid:  "1.42",
				Type: "InetAddress",
				Help: "Help string",
			},
			oidToPdu:        map[string]gosnmp.SnmpPDU{"1.41.2": gosnmp.SnmpPDU{Value: 3}},
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: [test_metric]} label:<name:"test_metric" value:"0x0405060708" > gauge:<value:1 > `},
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.42.2",
				Value: []byte{4, 5, 6, 7},
			},
			indexOids: []int{2},
			metric: &config.Metric{
				Name: "test_metric",
				Oid:  "1.42",
				Type: "InetAddress",
				Help: "Help string",
			},
			oidToPdu:        make(map[string]gosnmp.SnmpPDU),
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: [test_metric]} label:<name:"test_metric" value:"0x04050607" > gauge:<value:1 > `},
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.42.2",
				Value: []byte{4, 5, 6, 7, 8, 9},
			},
			indexOids: []int{2},
			metric: &config.Metric{
				Name: "test_metric",
				Oid:  "1.42",
				Type: "LldpPortId",
				Help: "Help string",
			},
			oidToPdu:        map[string]gosnmp.SnmpPDU{"1.41.2": gosnmp.SnmpPDU{Value: 3}},
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: [test_metric]} label:<name:"test_metric" value:"04:05:06:07:08:09" > gauge:<value:1 > `},
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.1",
				Type:  gosnmp.Integer,
				Value: 2,
			},
			metric: &config.Metric{
				Name:       "test_metric",
				Oid:        "1.1",
				Type:       "EnumAsInfo",
				Help:       "Help string",
				EnumValues: map[int]string{0: "foo", 1: "bar", 2: "baz"},
			},
			expectedMetrics: []string{`Desc{fqName: "test_metric_info", help: "Help string (EnumAsInfo)", constLabels: {}, variableLabels: [test_metric]} label:<name:"test_metric" value:"baz" > gauge:<value:1 > `},
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.1",
				Type:  gosnmp.Integer,
				Value: 3,
			},
			metric: &config.Metric{
				Name:       "test_metric",
				Oid:        "1.1",
				Type:       "EnumAsInfo",
				Help:       "Help string",
				EnumValues: map[int]string{0: "foo", 1: "bar", 2: "baz"},
			},
			expectedMetrics: []string{`Desc{fqName: "test_metric_info", help: "Help string (EnumAsInfo)", constLabels: {}, variableLabels: [test_metric]} label:<name:"test_metric" value:"3" > gauge:<value:1 > `},
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.1",
				Type:  gosnmp.Integer,
				Value: 2,
			},
			metric: &config.Metric{
				Name:       "test_metric",
				Oid:        "1.1",
				Type:       "EnumAsStateSet",
				Help:       "Help string",
				EnumValues: map[int]string{0: "foo", 1: "bar", 2: "baz"},
			},
			expectedMetrics: []string{
				`Desc{fqName: "test_metric", help: "Help string (EnumAsStateSet)", constLabels: {}, variableLabels: [test_metric]} label:<name:"test_metric" value:"foo" > gauge:<value:0 > `,
				`Desc{fqName: "test_metric", help: "Help string (EnumAsStateSet)", constLabels: {}, variableLabels: [test_metric]} label:<name:"test_metric" value:"bar" > gauge:<value:0 > `,
				`Desc{fqName: "test_metric", help: "Help string (EnumAsStateSet)", constLabels: {}, variableLabels: [test_metric]} label:<name:"test_metric" value:"baz" > gauge:<value:1 > `,
			},
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.1",
				Type:  gosnmp.Integer,
				Value: 3,
			},
			metric: &config.Metric{
				Name:       "test_metric",
				Oid:        "1.1",
				Type:       "EnumAsStateSet",
				Help:       "Help string",
				EnumValues: map[int]string{0: "foo", 1: "bar", 2: "baz"},
			},
			expectedMetrics: []string{
				`Desc{fqName: "test_metric", help: "Help string (EnumAsStateSet)", constLabels: {}, variableLabels: [test_metric]} label:<name:"test_metric" value:"foo" > gauge:<value:0 > `,
				`Desc{fqName: "test_metric", help: "Help string (EnumAsStateSet)", constLabels: {}, variableLabels: [test_metric]} label:<name:"test_metric" value:"bar" > gauge:<value:0 > `,
				`Desc{fqName: "test_metric", help: "Help string (EnumAsStateSet)", constLabels: {}, variableLabels: [test_metric]} label:<name:"test_metric" value:"baz" > gauge:<value:0 > `,
				`Desc{fqName: "test_metric", help: "Help string (EnumAsStateSet)", constLabels: {}, variableLabels: [test_metric]} label:<name:"test_metric" value:"3" > gauge:<value:1 > `,
			},
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.1",
				Type:  gosnmp.Integer,
				Value: []byte{1<<7 + 1<<6, 1 << 7, 1 << 0},
			},
			metric: &config.Metric{
				Name:       "test_metric",
				Oid:        "1.1",
				Type:       "Bits",
				Help:       "Help string",
				EnumValues: map[int]string{0: "foo", 1: "bar", 2: "baz", 8: "byte2msb", 15: "byte2lsb", 16: "byte3msb", 23: "byte3lsb", 24: "missing"},
			},
			expectedMetrics: []string{
				`Desc{fqName: "test_metric", help: "Help string (Bits)", constLabels: {}, variableLabels: [test_metric]} label:<name:"test_metric" value:"foo" > gauge:<value:1 > `,
				`Desc{fqName: "test_metric", help: "Help string (Bits)", constLabels: {}, variableLabels: [test_metric]} label:<name:"test_metric" value:"bar" > gauge:<value:1 > `,
				`Desc{fqName: "test_metric", help: "Help string (Bits)", constLabels: {}, variableLabels: [test_metric]} label:<name:"test_metric" value:"baz" > gauge:<value:0 > `,
				`Desc{fqName: "test_metric", help: "Help string (Bits)", constLabels: {}, variableLabels: [test_metric]} label:<name:"test_metric" value:"byte2msb" > gauge:<value:1 > `,
				`Desc{fqName: "test_metric", help: "Help string (Bits)", constLabels: {}, variableLabels: [test_metric]} label:<name:"test_metric" value:"byte2lsb" > gauge:<value:0 > `,
				`Desc{fqName: "test_metric", help: "Help string (Bits)", constLabels: {}, variableLabels: [test_metric]} label:<name:"test_metric" value:"byte3msb" > gauge:<value:0 > `,
				`Desc{fqName: "test_metric", help: "Help string (Bits)", constLabels: {}, variableLabels: [test_metric]} label:<name:"test_metric" value:"byte3lsb" > gauge:<value:1 > `,
				`Desc{fqName: "test_metric", help: "Help string (Bits)", constLabels: {}, variableLabels: [test_metric]} label:<name:"test_metric" value:"missing" > gauge:<value:0 > `,
			},
		},
	}

	for _, c := range cases {
		metrics := pduToSamples(c.indexOids, c.pdu, c.metric, c.oidToPdu, log.NewNopLogger())
		metric := &io_prometheus_client.Metric{}
		expected := map[string]struct{}{}
		for _, e := range c.expectedMetrics {
			expected[e] = struct{}{}
		}
		errHappened := false
		for _, m := range metrics {
			err := m.Write(metric)
			if err != nil {
				if c.shouldErr {
					errHappened = true
					continue
				} else {
					t.Fatalf("Error writing metric: %v", err)
				}
			}
			got := m.Desc().String() + " " + metric.String()
			if _, ok := expected[got]; !ok {
				t.Errorf("Unexpected metric: got %v", got)
			} else {
				delete(expected, got)
			}
		}
		for e := range expected {
			t.Errorf("Expected metric %v, but was not returned.", e)
		}
		if !errHappened && c.shouldErr {
			t.Fatalf("Was expecting error, but none returned.")
		}
	}
}

func TestGetPduValue(t *testing.T) {
	pdu := &gosnmp.SnmpPDU{
		Value: uint64(1 << 63),
		Type:  gosnmp.Counter64,
	}
	value := getPduValue(pdu)
	if value <= 0 {
		t.Fatalf("Got negative value for PDU value type Counter64: %v", value)
	}
}

func TestGetPduLargeValue(t *testing.T) {
	_, err := kingpin.CommandLine.Parse([]string{})
	if err != nil {
		t.Fatal(err)
	}

	pdu := &gosnmp.SnmpPDU{
		Value: uint64(19007199254740992),
		Type:  gosnmp.Counter64,
	}
	value := getPduValue(pdu)
	if value != 992800745259008.0 {
		t.Fatalf("Got incorrect counter wrapping for Counter64: %v", value)
	}

	_, err = kingpin.CommandLine.Parse([]string{"--no-snmp.wrap-large-counters"})
	if err != nil {
		t.Fatal(err)
	}

	pdu = &gosnmp.SnmpPDU{
		Value: uint64(19007199254740992),
		Type:  gosnmp.Counter64,
	}
	value = getPduValue(pdu)
	if value != 19007199254740990.0 {
		t.Fatalf("Got incorrect rounded float for Counter64: %v", value)
	}
}

func TestOidToList(t *testing.T) {
	cases := []struct {
		oid    string
		result []int
	}{
		{
			oid:    "1",
			result: []int{1},
		},
		{
			oid:    "1.2.3.4",
			result: []int{1, 2, 3, 4},
		},
	}
	for _, c := range cases {
		got := oidToList(c.oid)
		if !reflect.DeepEqual(got, c.result) {
			t.Errorf("oidToList(%v): got %v, want %v", c.oid, got, c.result)
		}
	}
}

func TestSplitOid(t *testing.T) {
	cases := []struct {
		oid        []int
		count      int
		resultHead []int
		resultTail []int
	}{
		{
			oid:        []int{1, 2, 3, 4},
			count:      2,
			resultHead: []int{1, 2},
			resultTail: []int{3, 4},
		},
		{
			oid:        []int{1, 2},
			count:      4,
			resultHead: []int{1, 2, 0, 0},
			resultTail: []int{},
		},
		{
			oid:        []int{},
			count:      2,
			resultHead: []int{0, 0},
			resultTail: []int{},
		},
	}
	for _, c := range cases {
		head, tail := splitOid(c.oid, c.count)
		if !reflect.DeepEqual(head, c.resultHead) || !reflect.DeepEqual(tail, c.resultTail) {
			t.Errorf("splitOid(%v, %d): got [%v, %v], want [%v, %v]", c.oid, c.count, head, tail, c.resultHead, c.resultTail)
		}
	}
}

func TestPduValueAsString(t *testing.T) {
	cases := []struct {
		pdu    *gosnmp.SnmpPDU
		typ    string
		result string
	}{
		{
			pdu:    &gosnmp.SnmpPDU{Value: int(-1)},
			result: "-1",
		},
		{
			pdu:    &gosnmp.SnmpPDU{Value: uint(1)},
			result: "1",
		},
		{
			pdu:    &gosnmp.SnmpPDU{Value: uint64(1)},
			result: "1",
		},
		{
			pdu:    &gosnmp.SnmpPDU{Value: ".1.2.3.4", Type: gosnmp.ObjectIdentifier},
			result: "1.2.3.4",
		},
		{
			pdu:    &gosnmp.SnmpPDU{Value: "1.2.3.4", Type: gosnmp.IPAddress},
			result: "1.2.3.4",
		},
		{
			pdu:    &gosnmp.SnmpPDU{Value: []byte{}},
			result: "",
		},
		{
			pdu:    &gosnmp.SnmpPDU{Value: []byte{65, 66}},
			typ:    "DisplayString",
			result: "AB",
		},
		{
			pdu:    &gosnmp.SnmpPDU{Value: []byte{127, 128, 255, 0}},
			result: "0x7F80FF00",
		},
		{
			pdu:    &gosnmp.SnmpPDU{Value: []byte{127, 128, 255, 0}},
			typ:    "OctetString",
			result: "0x7F80FF00",
		},
		{
			pdu:    &gosnmp.SnmpPDU{Value: []byte{1, 2, 3, 4}},
			typ:    "InetAddressIPv4",
			result: "1.2.3.4",
		},
		{
			pdu:    &gosnmp.SnmpPDU{Value: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}},
			typ:    "InetAddressIPv6",
			result: "0102:0304:0506:0708:090A:0B0C:0D0E:0F10",
		},
		{
			pdu:    &gosnmp.SnmpPDU{Value: nil},
			result: "",
		},
		{
			pdu:    &gosnmp.SnmpPDU{Value: float32(10.1), Type: gosnmp.OpaqueFloat},
			result: "10.1",
		},
		{
			pdu:    &gosnmp.SnmpPDU{Value: 10.1, Type: gosnmp.OpaqueDouble},
			result: "10.1",
		},
	}
	for _, c := range cases {
		got := pduValueAsString(c.pdu, c.typ)
		if !reflect.DeepEqual(got, c.result) {
			t.Errorf("pduValueAsString(%v, %q): got %q, want %q", c.pdu, c.typ, got, c.result)
		}
	}
}

func TestParseDateAndTime(t *testing.T) {
	cases := []struct {
		pdu    *gosnmp.SnmpPDU
		result float64
		err    error
	}{
		// No timezone, use UTC
		{
			pdu:    &gosnmp.SnmpPDU{Value: []byte{7, 226, 8, 15, 8, 1, 15, 0}},
			result: 1534320075,
			err:    nil,
		},
		// +0200
		{
			pdu:    &gosnmp.SnmpPDU{Value: []byte{7, 226, 8, 15, 8, 1, 15, 0, 43, 2, 0}},
			result: 1534312875,
			err:    nil,
		},
		{
			pdu:    &gosnmp.SnmpPDU{Value: []byte{0}},
			result: 0,
			err:    errors.New("invalid DateAndTime length 1"),
		},
	}
	for _, c := range cases {
		got, err := parseDateAndTime(c.pdu)
		if !reflect.DeepEqual(err, c.err) {
			t.Errorf("parseDateAndTime(%v) error: got %v, want %v", c.pdu, err, c.err)
		}
		if !reflect.DeepEqual(got, c.result) {
			t.Errorf("parseDateAndTime(%v) result: got %v, want %v", c.pdu, got, c.result)
		}
	}
}

func TestIndexesToLabels(t *testing.T) {
	cases := []struct {
		oid      []int
		metric   config.Metric
		oidToPdu map[string]gosnmp.SnmpPDU
		result   map[string]string
	}{
		{
			oid:      []int{},
			metric:   config.Metric{},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{},
		},
		{
			oid:      []int{4},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "gauge"}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "4"},
		},
		{
			oid: []int{3, 4},
			metric: config.Metric{
				Indexes: []*config.Index{{Labelname: "a", Type: "gauge"}, {Labelname: "b", Type: "gauge"}},
				Lookups: []*config.Lookup{{Labels: []string{"a", "b"}, Labelname: "l", Oid: "1.2"}},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{"1.2.3.4": gosnmp.SnmpPDU{Value: "eth0"}},
			result:   map[string]string{"a": "3", "b": "4", "l": "eth0"},
		},
		{
			oid: []int{4},
			metric: config.Metric{
				Indexes: []*config.Index{{Labelname: "l", Type: "gauge"}},
				Lookups: []*config.Lookup{{Labels: []string{"l"}, Labelname: "l", Oid: "1.2.3"}},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{"1.2.3.4": gosnmp.SnmpPDU{Value: "eth0"}},
			result:   map[string]string{"l": "eth0"},
		},
		{
			oid: []int{4},
			metric: config.Metric{
				Indexes: []*config.Index{{Labelname: "l", Type: "gauge"}},
				Lookups: []*config.Lookup{{Labels: []string{"l"}, Labelname: "l", Oid: "1.2.3", Type: "InetAddressIPv4"}},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{"1.2.3.4": gosnmp.SnmpPDU{Value: []byte{5, 6, 7, 8}}},
			result:   map[string]string{"l": "5.6.7.8"},
		},
		{
			oid: []int{4},
			metric: config.Metric{
				Indexes: []*config.Index{{Labelname: "l", Type: "gauge"}},
				Lookups: []*config.Lookup{{Labels: []string{"l"}, Labelname: "l", Oid: "1.2.3", Type: "InetAddressIPv6"}},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{"1.2.3.4": gosnmp.SnmpPDU{Value: []byte{5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}}},
			result:   map[string]string{"l": "0506:0708:090A:0B0C:0D0E:0F10:1112:1314"},
		},
		{
			oid: []int{4},
			metric: config.Metric{
				Indexes: []*config.Index{{Labelname: "l", Type: "gauge"}},
				Lookups: []*config.Lookup{{Labels: []string{"l"}, Labelname: "l", Oid: "1.2.3"}},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{"1.2.3.4": gosnmp.SnmpPDU{Value: []byte{5, 6, 7, 8}}},
			result:   map[string]string{"l": "0x05060708"},
		},
		{
			oid: []int{4},
			metric: config.Metric{
				Indexes: []*config.Index{{Labelname: "l", Type: "gauge"}},
				Lookups: []*config.Lookup{{Labelname: "l"}},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{},
		},
		{
			oid: []int{4},
			metric: config.Metric{
				Indexes: []*config.Index{{Labelname: "l", Type: "gauge"}},
				Lookups: []*config.Lookup{{Labels: []string{"l"}, Labelname: "l", Oid: "1.2.3"}},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": ""},
		},
		{
			oid:      []int{},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "gauge"}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "0"},
		},
		{
			oid:      []int{1, 255, 0, 0, 0, 16},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "PhysAddress48"}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "01:FF:00:00:00:10"},
		},
		{
			oid:      []int{3, 65, 32, 255},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "OctetString"}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "0x4120FF"},
		},
		{
			oid:      []int{65, 32, 255},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "OctetString", FixedSize: 3}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "0x4120FF"},
		},
		{
			oid:      []int{65, 32, 255},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "OctetString", Implied: true}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "0x4120FF"},
		},
		{
			oid:      []int{2, 65, 32},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "DisplayString"}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "A "},
		},
		{
			oid:      []int{65, 32},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "DisplayString", FixedSize: 2}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "A "},
		},
		{
			oid:      []int{65, 32},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "DisplayString", Implied: true}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "A "},
		},
		{
			oid:      []int{0},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "EnumAsInfo", EnumValues: map[int]string{0: "foo", 1: "bar", 2: "baz"}}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "foo"},
		},
		{
			oid:      []int{3},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "EnumAsInfo", EnumValues: map[int]string{0: "foo", 1: "bar", 2: "baz"}}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "3"},
		},
		{
			oid: []int{3, 65, 32, 255},
			metric: config.Metric{
				Indexes: []*config.Index{{Labelname: "l", Type: "OctetString"}},
				Lookups: []*config.Lookup{{Labels: []string{"l"}, Labelname: "l", Oid: "1"}},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{"1.3.65.32.255": gosnmp.SnmpPDU{Value: "octet"}},
			result:   map[string]string{"l": "octet"},
		},
		{
			oid:      []int{192, 168, 1, 2},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "InetAddressIPv4"}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "192.168.1.2"},
		},
		{
			oid:      []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "InetAddressIPv6"}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "0102:0304:0506:0708:090A:0B0C:0D0E:0F10"},
		},
		{
			oid:      []int{1, 4, 192, 168, 1, 2},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "InetAddress"}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "192.168.1.2"},
		},
		{
			oid:      []int{2, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "InetAddress"}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "0102:0304:0506:0708:090A:0B0C:0D0E:0F10"},
		},
		{
			oid:      []int{1, 4, 192, 168, 1, 2, 2, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "a", Type: "InetAddress"}, {Labelname: "b", Type: "InetAddress"}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"a": "192.168.1.2", "b": "0102:0304:0506:0708:090A:0B0C:0D0E:0F10"},
		},
		{
			oid:      []int{3, 5, 192, 168, 1, 2, 5},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "InetAddress"}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "0x0305C0A8010205"},
		},
		{
			oid:      []int{1, 192, 168, 1, 2},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "InetAddressMissingSize"}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "192.168.1.2"},
		},
		{
			oid:      []int{2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "InetAddressMissingSize"}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "0102:0304:0506:0708:090A:0B0C:0D0E:0F10"},
		},
		{
			oid:      []int{1, 192, 168, 1, 2, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "a", Type: "InetAddressMissingSize"}, {Labelname: "b", Type: "InetAddressMissingSize"}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"a": "192.168.1.2", "b": "0102:0304:0506:0708:090A:0B0C:0D0E:0F10"},
		},
		{
			oid:      []int{3, 192, 168, 1, 2, 5},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "InetAddressMissingSize"}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "0x03C0A8010205"},
		},
		{
			oid: []int{1, 1, 1, 1},
			metric: config.Metric{
				Indexes: []*config.Index{{Labelname: "a", Type: "gauge"}},
				Lookups: []*config.Lookup{
					{Labels: []string{"a"}, Labelname: "chainable_id", Oid: "1.1.1.2"},
					{Labels: []string{"chainable_id"}, Labelname: "targetlabel", Oid: "2.2.2"},
				},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{
				"1.1.1.1.1": gosnmp.SnmpPDU{Value: "source_obj0"},
				"1.1.1.2.1": gosnmp.SnmpPDU{Value: 42},
				"2.2.2.42":  gosnmp.SnmpPDU{Value: "targetvalue"},
			},
			result: map[string]string{"a": "1", "chainable_id": "42", "targetlabel": "targetvalue"},
		},
		{
			oid: []int{1, 1, 1, 1},
			metric: config.Metric{
				Indexes: []*config.Index{{Labelname: "a", Type: "gauge"}},
				Lookups: []*config.Lookup{
					{Labels: []string{"a"}, Labelname: "chainable_id", Oid: "1.1.1.2"},
					{Labels: []string{"chainable_id"}, Labelname: "targetlabel", Oid: "2.2.2"},
				},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{
				"1.1.1.1.1": gosnmp.SnmpPDU{Value: "source_obj0"},
				"1.1.1.2.1": gosnmp.SnmpPDU{Value: uint(42)},
				"2.2.2.42":  gosnmp.SnmpPDU{Value: "targetvalue"},
			},
			result: map[string]string{"a": "1", "chainable_id": "42", "targetlabel": "targetvalue"},
		},
	}
	for _, c := range cases {
		got := indexesToLabels(c.oid, &c.metric, c.oidToPdu)
		if !reflect.DeepEqual(got, c.result) {
			t.Errorf("indexesToLabels(%v, %v, %v): got %v, want %v", c.oid, c.metric, c.oidToPdu, got, c.result)
		}
	}
}
