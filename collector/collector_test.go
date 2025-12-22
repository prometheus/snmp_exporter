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
	"strings"
	"testing"

	kingpin "github.com/alecthomas/kingpin/v2"
	"github.com/gosnmp/gosnmp"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"

	"github.com/prometheus/snmp_exporter/config"
	"github.com/prometheus/snmp_exporter/scraper"
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
					"Extension": {
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
				`Desc{fqName: "TestMetricNameExtension", help: "HelpText (regex extracted)", constLabels: {}, variableLabels: {}} gauge:{value:5}`,
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
					"Extension": {
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
					"Extension": {
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
					"Status": {
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
				`Desc{fqName: "TestMetricNameStatus", help: "HelpText (regex extracted)", constLabels: {}, variableLabels: {}} gauge:{value:5}`,
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
					"Blank": {
						{
							Regex: config.Regexp{
								regexp.MustCompile("^XXXX$"),
							},
							Value: "4",
						},
					},
					"Extension": {
						{
							Regex: config.Regexp{
								regexp.MustCompile(".*"),
							},
							Value: "5",
						},
					},
					"MultipleRegexes": {
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
					"Template": {
						{
							Regex: config.Regexp{
								regexp.MustCompile(`(\d.\d+)`),
							},
							Value: "$1",
						},
					},
				},
			},
			oidToPdu: make(map[string]gosnmp.SnmpPDU),
			expectedMetrics: []string{
				`Desc{fqName: "TestMetricNameExtension", help: "HelpText (regex extracted)", constLabels: {}, variableLabels: {}} gauge:{value:5}`,
				`Desc{fqName: "TestMetricNameMultipleRegexes", help: "HelpText (regex extracted)", constLabels: {}, variableLabels: {}} gauge:{value:999}`,
				`Desc{fqName: "TestMetricNameTemplate", help: "HelpText (regex extracted)", constLabels: {}, variableLabels: {}} gauge:{value:4.42}`,
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
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: {}} counter:{value:2}`},
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
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: {}} gauge:{value:2}`},
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.1.1.1.1",
				Type:  gosnmp.Integer,
				Value: 420,
			},
			indexOids: []int{},
			metric: &config.Metric{
				Name:  "test_metric",
				Oid:   "1.1.1.1.1",
				Type:  "gauge",
				Help:  "Help string",
				Scale: 0.1,
			},
			oidToPdu:        make(map[string]gosnmp.SnmpPDU),
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: {}} gauge:{value:42}`},
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.1.1.1.1",
				Type:  gosnmp.Integer,
				Value: 70,
			},
			indexOids: []int{},
			metric: &config.Metric{
				Name:   "test_metric",
				Oid:    "1.1.1.1.1",
				Type:   "gauge",
				Help:   "Help string",
				Offset: -1.0,
			},
			oidToPdu:        make(map[string]gosnmp.SnmpPDU),
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: {}} gauge:{value:69}`},
		},
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.1.1.1.1",
				Type:  gosnmp.Integer,
				Value: 2,
			},
			indexOids: []int{},
			metric: &config.Metric{
				Name:   "test_metric",
				Oid:    "1.1.1.1.1",
				Type:   "gauge",
				Help:   "Help string",
				Offset: 2.0,
				Scale:  -1.0,
			},
			oidToPdu:        make(map[string]gosnmp.SnmpPDU),
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: {}} gauge:{value:0}`},
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
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: {test_metric}} label:{name:"test_metric" value:"-2"} gauge:{value:1}`},
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
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: {}} gauge:{value:3}`},
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
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: {}} gauge:{value:3}`},
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
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: {foo}} label:{name:"foo" value:"AA"} gauge:{value:3}`},
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
					"": {{Value: "1", Regex: config.Regexp{regexp.MustCompile(".*")}}},
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
			oidToPdu:        map[string]gosnmp.SnmpPDU{"1.41.2": {Value: 1}},
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: {test_metric}} label:{name:"test_metric" value:"4.5.6.7"} gauge:{value:1}`},
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
			oidToPdu:        map[string]gosnmp.SnmpPDU{"1.41.2": {Value: 1}},
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: {test_metric}} label:{name:"test_metric" value:"4.5.6.7"} gauge:{value:1}`},
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
			oidToPdu:        map[string]gosnmp.SnmpPDU{"1.41.2": {Value: 2}},
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: {test_metric}} label:{name:"test_metric" value:"0405:0607:0809:0A0B:0C0D:0E0F:1011:1213"} gauge:{value:1}`},
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
			oidToPdu:        map[string]gosnmp.SnmpPDU{"1.41.2": {Value: 3}},
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: {test_metric}} label:{name:"test_metric" value:"0x0405060708"} gauge:{value:1}`},
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
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: {test_metric}} label:{name:"test_metric" value:"0x04050607"} gauge:{value:1}`},
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
			oidToPdu:        map[string]gosnmp.SnmpPDU{"1.41.2": {Value: 3}},
			expectedMetrics: []string{`Desc{fqName: "test_metric", help: "Help string", constLabels: {}, variableLabels: {test_metric}} label:{name:"test_metric" value:"04:05:06:07:08:09"} gauge:{value:1}`},
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
			expectedMetrics: []string{`Desc{fqName: "test_metric_info", help: "Help string (EnumAsInfo)", constLabels: {}, variableLabels: {test_metric}} label:{name:"test_metric" value:"baz"} gauge:{value:1}`},
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
			expectedMetrics: []string{`Desc{fqName: "test_metric_info", help: "Help string (EnumAsInfo)", constLabels: {}, variableLabels: {test_metric}} label:{name:"test_metric" value:"3"} gauge:{value:1}`},
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
				`Desc{fqName: "test_metric", help: "Help string (EnumAsStateSet)", constLabels: {}, variableLabels: {test_metric}} label:{name:"test_metric" value:"foo"} gauge:{value:0}`,
				`Desc{fqName: "test_metric", help: "Help string (EnumAsStateSet)", constLabels: {}, variableLabels: {test_metric}} label:{name:"test_metric" value:"bar"} gauge:{value:0}`,
				`Desc{fqName: "test_metric", help: "Help string (EnumAsStateSet)", constLabels: {}, variableLabels: {test_metric}} label:{name:"test_metric" value:"baz"} gauge:{value:1}`,
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
				`Desc{fqName: "test_metric", help: "Help string (EnumAsStateSet)", constLabels: {}, variableLabels: {test_metric}} label:{name:"test_metric" value:"foo"} gauge:{value:0}`,
				`Desc{fqName: "test_metric", help: "Help string (EnumAsStateSet)", constLabels: {}, variableLabels: {test_metric}} label:{name:"test_metric" value:"bar"} gauge:{value:0}`,
				`Desc{fqName: "test_metric", help: "Help string (EnumAsStateSet)", constLabels: {}, variableLabels: {test_metric}} label:{name:"test_metric" value:"baz"} gauge:{value:0}`,
				`Desc{fqName: "test_metric", help: "Help string (EnumAsStateSet)", constLabels: {}, variableLabels: {test_metric}} label:{name:"test_metric" value:"3"} gauge:{value:1}`,
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
				`Desc{fqName: "test_metric", help: "Help string (Bits)", constLabels: {}, variableLabels: {test_metric}} label:{name:"test_metric" value:"foo"} gauge:{value:1}`,
				`Desc{fqName: "test_metric", help: "Help string (Bits)", constLabels: {}, variableLabels: {test_metric}} label:{name:"test_metric" value:"bar"} gauge:{value:1}`,
				`Desc{fqName: "test_metric", help: "Help string (Bits)", constLabels: {}, variableLabels: {test_metric}} label:{name:"test_metric" value:"baz"} gauge:{value:0}`,
				`Desc{fqName: "test_metric", help: "Help string (Bits)", constLabels: {}, variableLabels: {test_metric}} label:{name:"test_metric" value:"byte2msb"} gauge:{value:1}`,
				`Desc{fqName: "test_metric", help: "Help string (Bits)", constLabels: {}, variableLabels: {test_metric}} label:{name:"test_metric" value:"byte2lsb"} gauge:{value:0}`,
				`Desc{fqName: "test_metric", help: "Help string (Bits)", constLabels: {}, variableLabels: {test_metric}} label:{name:"test_metric" value:"byte3msb"} gauge:{value:0}`,
				`Desc{fqName: "test_metric", help: "Help string (Bits)", constLabels: {}, variableLabels: {test_metric}} label:{name:"test_metric" value:"byte3lsb"} gauge:{value:1}`,
				`Desc{fqName: "test_metric", help: "Help string (Bits)", constLabels: {}, variableLabels: {test_metric}} label:{name:"test_metric" value:"missing"} gauge:{value:0}`,
			},
		},
		// DisplayHint with regex_extracts - verifies FormatSpec is applied before regex matching.
		{
			pdu: &gosnmp.SnmpPDU{
				Name:  "1.1.1.1.1",
				Value: []byte{192, 168, 1, 100}, // IP address bytes
			},
			indexOids: []int{},
			metric: &config.Metric{
				Name: "test_metric",
				Oid:  "1.1.1.1.1",
				Type: "DisplayHint",
				Help: "Help string",
				FormatSpec: []config.FormatOp{
					{Take: 1, Fmt: "d", Sep: "."},
					{Take: 1, Fmt: "d", Sep: "."},
					{Take: 1, Fmt: "d", Sep: "."},
					{Take: 1, Fmt: "d"},
				},
				RegexpExtracts: map[string][]config.RegexpExtract{
					"_last_octet": {
						{
							Regex: config.Regexp{
								regexp.MustCompile(`192\.168\.1\.(\d+)`),
							},
							Value: "$1",
						},
					},
				},
			},
			oidToPdu: make(map[string]gosnmp.SnmpPDU),
			expectedMetrics: []string{
				`Desc{fqName: "test_metric_last_octet", help: "Help string (regex extracted)", constLabels: {}, variableLabels: {}} gauge:{value:100}`,
			},
		},
	}

	for _, c := range cases {
		metrics := pduToSamples(c.indexOids, c.pdu, c.metric, c.oidToPdu, promslog.NewNopLogger(), Metrics{})
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
				}
				t.Fatalf("Error writing metric: %v", err)
			}
			got := strings.ReplaceAll(m.Desc().String()+" "+metric.String(), "  ", " ")
			if _, ok := expected[got]; !ok {
				t.Errorf("Got metric:      %v", got)
			} else {
				delete(expected, got)
			}
		}
		for e := range expected {
			t.Errorf("Expected metric: %v, but was not returned.", e)
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

func TestNtpTimestamp(t *testing.T) {
	cases := []struct {
		pdu    *gosnmp.SnmpPDU
		result float64
		err    error
	}{
		{
			pdu:    &gosnmp.SnmpPDU{Value: []byte{235, 6, 119, 246, 48, 209, 11, 59}},
			result: 1.734080886e+09,
			err:    nil,
		},
	}
	for _, c := range cases {
		got, err := parseNtpTimestamp(c.pdu)
		if !reflect.DeepEqual(err, c.err) {
			t.Errorf("parseNtpTimestamp(%v) error: got %v, want %v", c.pdu, err, c.err)
		}
		if !reflect.DeepEqual(got, c.result) {
			t.Errorf("parseNtpTimestamp(%v) result: got %v, want %v", c.pdu, got, c.result)
		}
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
			pdu:    &gosnmp.SnmpPDU{Value: []byte{2, 0}},
			typ:    "Bits",
			result: "0x0200",
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
		{
			pdu:    &gosnmp.SnmpPDU{Value: []byte{115, 97, 110, 101, 253, 190, 214}},
			typ:    "DisplayString",
			result: "sane�",
		},
	}
	for _, c := range cases {
		got := pduValueAsString(c.pdu, c.typ, Metrics{})
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

func TestParseDateAndTimeWithPattern(t *testing.T) {
	cases := []struct {
		pdu       *gosnmp.SnmpPDU
		metric    config.Metric
		result    float64
		shouldErr bool
	}{
		{
			pdu:       &gosnmp.SnmpPDU{Value: "Apr 01 2025"},
			metric:    config.Metric{DateTimePattern: "%b %d %Y"},
			result:    1.7434656e+09,
			shouldErr: false,
		},
		{
			pdu:       &gosnmp.SnmpPDU{Value: "ABC"},
			metric:    config.Metric{DateTimePattern: "%b %d %Y"},
			result:    0,
			shouldErr: true,
		},
	}
	for _, c := range cases {
		got, err := parseDateAndTimeWithPattern(&c.metric, c.pdu, Metrics{})
		if c.shouldErr && err == nil {
			t.Fatalf("Was expecting error, but none returned.")
		}
		if !c.shouldErr && err != nil {
			t.Fatalf("Was expecting no error, but one returned.")
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
			oidToPdu: map[string]gosnmp.SnmpPDU{"1.2.3.4": {Value: "eth0"}},
			result:   map[string]string{"a": "3", "b": "4", "l": "eth0"},
		},
		{
			oid: []int{4},
			metric: config.Metric{
				Indexes: []*config.Index{{Labelname: "l", Type: "gauge"}},
				Lookups: []*config.Lookup{{Labels: []string{"l"}, Labelname: "l", Oid: "1.2.3"}},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{"1.2.3.4": {Value: "eth0"}},
			result:   map[string]string{"l": "eth0"},
		},
		{
			oid: []int{4},
			metric: config.Metric{
				Indexes: []*config.Index{{Labelname: "l", Type: "gauge"}},
				Lookups: []*config.Lookup{{Labels: []string{"l"}, Labelname: "l", Oid: "1.2.3", Type: "InetAddressIPv4"}},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{"1.2.3.4": {Value: []byte{5, 6, 7, 8}}},
			result:   map[string]string{"l": "5.6.7.8"},
		},
		{
			oid: []int{4},
			metric: config.Metric{
				Indexes: []*config.Index{{Labelname: "l", Type: "gauge"}},
				Lookups: []*config.Lookup{{Labels: []string{"l"}, Labelname: "l", Oid: "1.2.3", Type: "InetAddressIPv6"}},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{"1.2.3.4": {Value: []byte{5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}}},
			result:   map[string]string{"l": "0506:0708:090A:0B0C:0D0E:0F10:1112:1314"},
		},
		{
			oid: []int{4},
			metric: config.Metric{
				Indexes: []*config.Index{{Labelname: "l", Type: "gauge"}},
				Lookups: []*config.Lookup{{Labels: []string{"l"}, Labelname: "l", Oid: "1.2.3"}},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{"1.2.3.4": {Value: []byte{5, 6, 7, 8}}},
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
		// DisplayHint type with FormatSpec applies RFC 2579 formatting.
		{
			oid: []int{4, 192, 168, 1, 1},
			metric: config.Metric{Indexes: []*config.Index{{
				Labelname: "l",
				Type:      "DisplayHint",
				FormatSpec: []config.FormatOp{
					{Take: 1, Fmt: "d", Sep: "."},
					{Take: 1, Fmt: "d", Sep: "."},
					{Take: 1, Fmt: "d", Sep: "."},
					{Take: 1, Fmt: "d"},
				},
			}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "192.168.1.1"},
		},
		// DisplayHint with FixedSize.
		{
			oid: []int{192, 168, 1, 1},
			metric: config.Metric{Indexes: []*config.Index{{
				Labelname: "l",
				Type:      "DisplayHint",
				FixedSize: 4,
				FormatSpec: []config.FormatOp{
					{Take: 1, Fmt: "d", Sep: "."},
					{Take: 1, Fmt: "d", Sep: "."},
					{Take: 1, Fmt: "d", Sep: "."},
					{Take: 1, Fmt: "d"},
				},
			}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "192.168.1.1"},
		},
		// DisplayHint with Implied.
		{
			oid: []int{192, 168, 1, 1},
			metric: config.Metric{Indexes: []*config.Index{{
				Labelname: "l",
				Type:      "DisplayHint",
				Implied:   true,
				FormatSpec: []config.FormatOp{
					{Take: 1, Fmt: "d", Sep: "."},
					{Take: 1, Fmt: "d", Sep: "."},
					{Take: 1, Fmt: "d", Sep: "."},
					{Take: 1, Fmt: "d"},
				},
			}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "192.168.1.1"},
		},
		// DisplayHint with MAC-style hint (1x: implicit repetition).
		{
			oid: []int{6, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
			metric: config.Metric{Indexes: []*config.Index{{
				Labelname:  "l",
				Type:       "DisplayHint",
				FormatSpec: []config.FormatOp{{Take: 1, Fmt: "x", Sep: ":"}},
			}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "aa:bb:cc:dd:ee:ff"},
		},
		// DisplayHint without FormatSpec falls back to hex (edge case).
		{
			oid:      []int{3, 65, 32, 255},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "DisplayHint"}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "0x4120FF"},
		},
		// OctetString always renders as raw hex, even if FormatSpec is present.
		{
			oid: []int{4, 192, 168, 1, 1},
			metric: config.Metric{Indexes: []*config.Index{{
				Labelname: "l",
				Type:      "OctetString",
				FormatSpec: []config.FormatOp{
					{Take: 1, Fmt: "d", Sep: "."},
					{Take: 1, Fmt: "d", Sep: "."},
					{Take: 1, Fmt: "d", Sep: "."},
					{Take: 1, Fmt: "d"},
				},
			}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "0xC0A80101"},
		},
		{
			oid: []int{3, 65, 32, 255},
			metric: config.Metric{
				Indexes: []*config.Index{{Labelname: "l", Type: "OctetString"}},
				Lookups: []*config.Lookup{{Labels: []string{"l"}, Labelname: "l", Oid: "1"}},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{"1.3.65.32.255": {Value: "octet"}},
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
				"1.1.1.1.1": {Value: "source_obj0"},
				"1.1.1.2.1": {Value: 42},
				"2.2.2.42":  {Value: "targetvalue"},
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
				"1.1.1.1.1": {Value: "source_obj0"},
				"1.1.1.2.1": {Value: uint(42)},
				"2.2.2.42":  {Value: "targetvalue"},
			},
			result: map[string]string{"a": "1", "chainable_id": "42", "targetlabel": "targetvalue"},
		},
		{
			oid: []int{1, 8, 1},
			metric: config.Metric{
				Indexes: []*config.Index{
					{Labelname: "lldpRemTimeMark", Type: "gauge"},
					{Labelname: "lldpRemLocalPortNum", Type: "gauge"},
					{Labelname: "lldpRemIndex", Type: "gauge"},
				},
				Lookups: []*config.Lookup{
					{Labels: []string{"lldpRemLocalPortNum"}, Labelname: "lldpLocPortId", Oid: "1.1.3", Type: "LldpPortId"},
				},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{
				"1.1.9.1.8.1": {Value: "hostname"},
				"1.1.2.8":     {Value: 3},
				"1.1.3.8":     {Value: []byte{4, 5, 6, 7, 8, 9}},
			},
			result: map[string]string{"lldpRemTimeMark": "1", "lldpRemLocalPortNum": "8", "lldpRemIndex": "1", "lldpLocPortId": "04:05:06:07:08:09"},
		},
		// Lookup with DisplayHint + FormatSpec applies RFC 2579 formatting.
		{
			oid: []int{1},
			metric: config.Metric{
				Indexes: []*config.Index{{Labelname: "idx", Type: "gauge"}},
				Lookups: []*config.Lookup{{
					Labels:    []string{"idx"},
					Labelname: "ip_addr",
					Oid:       "1.2.3",
					Type:      "DisplayHint",
					FormatSpec: []config.FormatOp{
						{Take: 1, Fmt: "d", Sep: "."},
						{Take: 1, Fmt: "d", Sep: "."},
						{Take: 1, Fmt: "d", Sep: "."},
						{Take: 1, Fmt: "d"},
					},
				}},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{
				"1.2.3.1": {Value: []byte{10, 0, 0, 1}},
			},
			result: map[string]string{"idx": "1", "ip_addr": "10.0.0.1"},
		},
		// Lookup with DisplayHint but no FormatSpec falls back to hex.
		{
			oid: []int{1},
			metric: config.Metric{
				Indexes: []*config.Index{{Labelname: "idx", Type: "gauge"}},
				Lookups: []*config.Lookup{{
					Labels:    []string{"idx"},
					Labelname: "raw_data",
					Oid:       "1.2.3",
					Type:      "DisplayHint",
				}},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{
				"1.2.3.1": {Value: []byte{0xAB, 0xCD}},
			},
			result: map[string]string{"idx": "1", "raw_data": "0xABCD"},
		},
	}
	for _, c := range cases {
		got := indexesToLabels(c.oid, &c.metric, c.oidToPdu, Metrics{})
		if !reflect.DeepEqual(got, c.result) {
			t.Errorf("indexesToLabels(%v, %v, %v): got %v, want %v", c.oid, c.metric, c.oidToPdu, got, c.result)
		}
	}
}

func TestConfigureTarget(t *testing.T) {
	cases := []struct {
		target     string
		gTransport string
		gTarget    string
		gPort      uint16
		shouldErr  bool
	}{
		{
			target:     "localhost",
			gTransport: "",
			gTarget:    "localhost",
			gPort:      161,
			shouldErr:  false,
		},
		{
			target:     "localhost:1161",
			gTransport: "",
			gTarget:    "localhost",
			gPort:      1161,
			shouldErr:  false,
		},
		{
			target:     "udp://localhost",
			gTransport: "udp",
			gTarget:    "localhost",
			gPort:      161,
			shouldErr:  false,
		},
		{
			target:     "udp://localhost:1161",
			gTransport: "udp",
			gTarget:    "localhost",
			gPort:      1161,
			shouldErr:  false,
		},
		{
			target:     "tcp://localhost",
			gTransport: "tcp",
			gTarget:    "localhost",
			gPort:      161,
			shouldErr:  false,
		},
		{
			target:     "tcp://localhost:1161",
			gTransport: "tcp",
			gTarget:    "localhost",
			gPort:      1161,
			shouldErr:  false,
		},
		{
			target:     "[::1]",
			gTransport: "",
			gTarget:    "[::1]",
			gPort:      161,
			shouldErr:  false,
		},
		{
			target:     "[::1]:1161",
			gTransport: "",
			gTarget:    "::1",
			gPort:      1161,
			shouldErr:  false,
		},
		{
			target:     "udp://[::1]",
			gTransport: "udp",
			gTarget:    "[::1]",
			gPort:      161,
			shouldErr:  false,
		},
		{
			target:     "udp://[::1]:1161",
			gTransport: "udp",
			gTarget:    "::1",
			gPort:      1161,
			shouldErr:  false,
		},
		{
			target:     "tcp://[::1]",
			gTransport: "tcp",
			gTarget:    "[::1]",
			gPort:      161,
			shouldErr:  false,
		},
		{
			target:     "tcp://[::1]:1161",
			gTransport: "tcp",
			gTarget:    "::1",
			gPort:      1161,
			shouldErr:  false,
		},
		{ // this case is valid during parse but invalid during connect
			target:     "tcp://udp://localhost:1161",
			gTransport: "tcp",
			gTarget:    "udp://localhost:1161",
			gPort:      161,
			shouldErr:  false,
		},
		{
			target:     "localhost:badport",
			gTransport: "",
			gTarget:    "",
			gPort:      0,
			shouldErr:  true,
		},
		{
			target:     "udp://localhost:badport",
			gTransport: "",
			gTarget:    "",
			gPort:      0,
			shouldErr:  true,
		},
		{
			target:     "tcp://localhost:badport",
			gTransport: "",
			gTarget:    "",
			gPort:      0,
			shouldErr:  true,
		},
		{
			target:     "[::1]:badport",
			gTransport: "",
			gTarget:    "",
			gPort:      0,
			shouldErr:  true,
		},
		{
			target:     "udp://[::1]:badport",
			gTransport: "",
			gTarget:    "",
			gPort:      0,
			shouldErr:  true,
		},
		{
			target:     "tcp://[::1]:badport",
			gTransport: "",
			gTarget:    "",
			gPort:      0,
			shouldErr:  true,
		},
	}

	for _, c := range cases {
		var g gosnmp.GoSNMP
		err := configureTarget(&g, c.target)
		if c.shouldErr {
			if err == nil {
				t.Fatalf("Was expecting error, but none returned for %q", c.target)
			}
			continue
		}
		if err != nil {
			t.Fatalf("Error configuring target %q: %v", c.target, err)
		}
		if g.Transport != c.gTransport {
			t.Fatalf("Bad SNMP transport for %q, got=%q, expected=%q", c.target, g.Transport, c.gTransport)
		}
		if g.Target != c.gTarget {
			t.Fatalf("Bad SNMP target for %q, got=%q, expected=%q", c.target, g.Target, c.gTarget)
		}
		if g.Port != c.gPort {
			t.Fatalf("Bad SNMP port for %q, got=%d, expected=%d", c.target, g.Port, c.gPort)
		}
	}
}

func TestFilterAllowedIndices(t *testing.T) {
	pdus := []gosnmp.SnmpPDU{
		{
			Name:  "1.3.6.1.2.1.2.2.1.8.1",
			Value: "2",
		},
		{
			Name:  "1.3.6.1.2.1.2.2.1.8.2",
			Value: "1",
		},
		{
			Name:  "1.3.6.1.2.1.2.2.1.8.3",
			Value: "1",
		},
		{
			Name:  "1.3.6.1.2.1.2.2.1.8.4",
			Value: "5",
		},
	}

	cases := []struct {
		filter      config.DynamicFilter
		allowedList []string
		result      []string
	}{
		{
			filter: config.DynamicFilter{
				Oid:     "1.3.6.1.2.1.2.2.1.8",
				Targets: []string{"1.3.6.1.2.1.2.2.1.3", "1.3.6.1.2.1.2.2.1.5"},
				Values:  []string{"1"},
			},
			result: []string{"2", "3"},
		},
		{
			filter: config.DynamicFilter{
				Oid:     "1.3.6.1.2.1.2.2.1.8",
				Targets: []string{"1.3.6.1.2.1.2.2.1.3", "1.3.6.1.2.1.2.2.1.5"},
				Values:  []string{"5"},
			},
			result: []string{"4"},
		},
	}
	for _, c := range cases {
		got := filterAllowedIndices(promslog.NewNopLogger(), c.filter, pdus, c.allowedList, Metrics{})
		if !reflect.DeepEqual(got, c.result) {
			t.Errorf("filterAllowedIndices(%v): got %v, want %v", c.filter, got, c.result)
		}
	}
}

func TestUpdateWalkConfig(t *testing.T) {
	cases := []struct {
		filter config.DynamicFilter
		result []string
	}{
		{
			filter: config.DynamicFilter{
				Oid:     "1.3.6.1.2.1.2.2.1.8",
				Targets: []string{"1.3.6.1.2.1.2.2.1.3", "1.3.6.1.2.1.2.2.1.5", "1.3.6.1.2.1.2.2.1.7"},
				Values:  []string{"1"},
			},
			result: []string{},
		},
		{
			filter: config.DynamicFilter{
				Oid:     "1.3.6.1.2.1.2.2.1.8",
				Targets: []string{"1.3.6.1.2.1.2.2.1.3", "1.3.6.1.2.1.2.2.1.21"},
				Values:  []string{"1"},
			},
			result: []string{"1.3.6.1.2.1.2.2.1.5", "1.3.6.1.2.1.2.2.1.7"},
		},
	}
	walkConfig := []string{"1.3.6.1.2.1.2.2.1.3", "1.3.6.1.2.1.2.2.1.5", "1.3.6.1.2.1.2.2.1.7"}
	for _, c := range cases {
		got := updateWalkConfig(walkConfig, c.filter, promslog.NewNopLogger())
		if !reflect.DeepEqual(got, c.result) {
			t.Errorf("updateWalkConfig(%v): got %v, want %v", c.filter, got, c.result)
		}
	}
}

func TestUpdateGetConfig(t *testing.T) {
	cases := []struct {
		filter config.DynamicFilter
		result []string
	}{
		{
			filter: config.DynamicFilter{
				Oid:     "1.3.6.1.2.1.2.2.1.8",
				Targets: []string{"1.3.6.1.2.1.2.2.1"},
				Values:  []string{"1"},
			},
			result: []string{},
		},
		{
			filter: config.DynamicFilter{
				Oid:     "1.3.6.1.2.1.2.2.1.8",
				Targets: []string{"1.3.6.1.2.1.2.2.1.3", "1.3.6.1.2.1.2.2.1.21"},
				Values:  []string{"1"},
			},
			result: []string{"1.3.6.1.2.1.2.2.1.5", "1.3.6.1.2.1.2.2.1.7"},
		},
	}
	getConfig := []string{"1.3.6.1.2.1.2.2.1.3", "1.3.6.1.2.1.2.2.1.5", "1.3.6.1.2.1.2.2.1.7"}
	for _, c := range cases {
		got := updateGetConfig(getConfig, c.filter, promslog.NewNopLogger())
		if !reflect.DeepEqual(got, c.result) {
			t.Errorf("updateGetConfig(%v): got %v, want %v", c.filter, got, c.result)
		}
	}
}

func TestAddAllowedIndices(t *testing.T) {
	cases := []struct {
		filter config.DynamicFilter
		result []string
	}{
		{
			filter: config.DynamicFilter{
				Oid:     "1.3.6.1.2.1.2.2.1.8",
				Targets: []string{"1.3.6.1.2.1.2.2.1"},
				Values:  []string{"1"},
			},
			result: []string{"1.3.6.1.2.1.31.1.1.1.10", "1.3.6.1.2.1.31.1.1.1.11", "1.3.6.1.2.1.2.2.1.2", "1.3.6.1.2.1.2.2.1.3"},
		},
		{
			filter: config.DynamicFilter{
				Oid:     "1.3.6.1.2.1.2.2.1.8",
				Targets: []string{"1.3.6.1.2.1.2.2.1.3", "1.3.6.1.2.1.2.2.1.21"},
				Values:  []string{"1"},
			},
			result: []string{"1.3.6.1.2.1.31.1.1.1.10", "1.3.6.1.2.1.31.1.1.1.11", "1.3.6.1.2.1.2.2.1.3.2", "1.3.6.1.2.1.2.2.1.3.3", "1.3.6.1.2.1.2.2.1.21.2", "1.3.6.1.2.1.2.2.1.21.3"},
		},
	}
	allowedList := []string{"2", "3"}
	newCfg := []string{"1.3.6.1.2.1.31.1.1.1.10", "1.3.6.1.2.1.31.1.1.1.11"}
	for _, c := range cases {
		got := addAllowedIndices(c.filter, allowedList, promslog.NewNopLogger(), newCfg)
		if !reflect.DeepEqual(got, c.result) {
			t.Errorf("addAllowedIndices(%v): got %v, want %v", c.filter, got, c.result)
		}
	}
}

func TestApplyFormatSpec(t *testing.T) {
	cases := []struct {
		name   string
		spec   []config.FormatOp
		data   []byte
		result string
	}{
		{
			name:   "Empty spec returns hex",
			spec:   []config.FormatOp{},
			data:   []byte{0x01, 0x02, 0x03},
			result: "010203",
		},
		{
			name:   "Empty data returns empty hex",
			spec:   []config.FormatOp{{Take: 1, Fmt: "d"}},
			data:   []byte{},
			result: "",
		},
		{
			name: "InetAddressIPv4 - 1d.1d.1d.1d",
			spec: []config.FormatOp{
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d"},
			},
			data:   []byte{192, 168, 1, 1},
			result: "192.168.1.1",
		},
		{
			name: "InetAddressIPv4z - 1d.1d.1d.1d%4d (zone ID)",
			spec: []config.FormatOp{
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "%"},
				{Take: 4, Fmt: "d"},
			},
			data:   []byte{192, 168, 1, 1, 0, 0, 0, 3},
			result: "192.168.1.1%3",
		},
		{
			name: "PhysAddress (MAC) - 1x: with implicit repetition",
			spec: []config.FormatOp{
				{Take: 1, Fmt: "x", Sep: ":"},
			},
			data:   []byte{0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e},
			result: "00:1a:2b:3c:4d:5e",
		},
		{
			name: "InetAddressIPv6 - 2x:...:2x",
			spec: []config.FormatOp{
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x"},
			},
			data:   []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			result: "2001:0db8:0000:0000:0000:0000:0000:0001",
		},
		{
			name: "InetAddressIPv6z - IPv6 with zone ID",
			spec: []config.FormatOp{
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: "%"},
				{Take: 4, Fmt: "d"},
			},
			data:   []byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05},
			result: "fe80:0000:0000:0000:0000:0000:0000:0001%5",
		},
		{
			name: "DisplayString - 255a",
			spec: []config.FormatOp{
				{Take: 255, Fmt: "a"},
			},
			data:   []byte("Hello, World!"),
			result: "Hello, World!",
		},
		{
			name: "Simple decimal - 1d",
			spec: []config.FormatOp{
				{Take: 1, Fmt: "d"},
			},
			data:   []byte{42},
			result: "42",
		},
		{
			name: "Multi-byte decimal - 4d (DNS-SERVER-MIB)",
			spec: []config.FormatOp{
				{Take: 4, Fmt: "d"},
			},
			data:   []byte{0x00, 0x01, 0x00, 0x00},
			result: "65536",
		},
		{
			name: "Octal format - 1o",
			spec: []config.FormatOp{
				{Take: 1, Fmt: "o"},
			},
			data:   []byte{8},
			result: "10",
		},
		{
			name: "Hex with dash separator - 1x- (ALCATEL-IND1-ISIS-SPB-MIB)",
			spec: []config.FormatOp{
				{Take: 1, Fmt: "x", Sep: "-"},
			},
			data:   []byte{0xaa, 0xbb, 0xcc},
			result: "aa-bb-cc",
		},
		{
			name: "Star prefix repeat",
			spec: []config.FormatOp{
				{Take: 1, StarPrefix: true, Fmt: "x", Sep: ":"},
			},
			data:   []byte{3, 0xaa, 0xbb, 0xcc},
			result: "aa:bb:cc",
		},
		{
			name: "Star prefix with terminator",
			spec: []config.FormatOp{
				{Take: 1, StarPrefix: true, Fmt: "d", Sep: ".", Term: "/"},
				{Take: 1, Fmt: "d"},
			},
			data:   []byte{3, 10, 20, 30, 40},
			result: "10.20.30/40",
		},
		{
			name: "Trailing separator suppressed",
			spec: []config.FormatOp{
				{Take: 1, Fmt: "d", Sep: "."},
			},
			data:   []byte{1, 2, 3},
			result: "1.2.3",
		},
		{
			name: "DateAndTime-like format - 2d-1d-1d,1d:1d:1d.1d",
			spec: []config.FormatOp{
				{Take: 2, Fmt: "d", Sep: "-"},
				{Take: 1, Fmt: "d", Sep: "-"},
				{Take: 1, Fmt: "d", Sep: ","},
				{Take: 1, Fmt: "d", Sep: ":"},
				{Take: 1, Fmt: "d", Sep: ":"},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d"},
			},
			data:   []byte{0x07, 0xE6, 8, 15, 8, 1, 15, 0},
			result: "2022-8-15,8:1:15.0",
		},
		{
			name: "Data shorter than spec",
			spec: []config.FormatOp{
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d"},
			},
			data:   []byte{10, 20},
			result: "10.20",
		},
		{
			name: "UTF-8 format - 1t (F5-PLATFORM-STATS-MIB)",
			spec: []config.FormatOp{
				{Take: 10, Fmt: "t"},
			},
			data:   []byte("hello"),
			result: "hello",
		},
		{
			name: "UUID format (UUID-TC-MIB) - 4x-2x-2x-1x1x-6x",
			spec: []config.FormatOp{
				{Take: 4, Fmt: "x", Sep: "-"},
				{Take: 2, Fmt: "x", Sep: "-"},
				{Take: 2, Fmt: "x", Sep: "-"},
				{Take: 1, Fmt: "x"},
				{Take: 1, Fmt: "x", Sep: "-"},
				{Take: 6, Fmt: "x"},
			},
			data:   []byte{0x12, 0x34, 0x56, 0x78, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			result: "12345678-abcd-ef01-2345-001122334455",
		},
		{
			name: "IPv4 with prefix (VIPTELA-OPER-BGP) - 1d.1d.1d.1d/1d",
			spec: []config.FormatOp{
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "/"},
				{Take: 1, Fmt: "d"},
			},
			data:   []byte{192, 168, 1, 0, 24},
			result: "192.168.1.0/24",
		},
		{
			name: "IPv4 with port (MPLS-TC-STD-MIB) - 1d.1d.1d.1d:2d",
			spec: []config.FormatOp{
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: ":"},
				{Take: 2, Fmt: "d"},
			},
			data:   []byte{192, 168, 1, 1, 0x1f, 0x90}, // port 8080
			result: "192.168.1.1:8080",
		},
		{
			name: "Version number (RAISECOM-SYSTEM-MIB) - 4d.4d.4d.4d",
			spec: []config.FormatOp{
				{Take: 4, Fmt: "d", Sep: "."},
				{Take: 4, Fmt: "d", Sep: "."},
				{Take: 4, Fmt: "d", Sep: "."},
				{Take: 4, Fmt: "d"},
			},
			data:   []byte{0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4},
			result: "1.2.3.4",
		},
		{
			name: "VPN RD (JUNIPER-VPN-MIB) - 2x-1d.1d.1d.1d:2d",
			spec: []config.FormatOp{
				{Take: 2, Fmt: "x", Sep: "-"},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: ":"},
				{Take: 2, Fmt: "d"},
			},
			data:   []byte{0x00, 0x01, 192, 168, 1, 1, 0x00, 0x64}, // type 1, 192.168.1.1:100
			result: "0001-192.168.1.1:100",
		},
		{
			name: "Simple date (ADVA-MIB) - 2d-1d-1d",
			spec: []config.FormatOp{
				{Take: 2, Fmt: "d", Sep: "-"},
				{Take: 1, Fmt: "d", Sep: "-"},
				{Take: 1, Fmt: "d"},
			},
			data:   []byte{0x07, 0xe9, 12, 25}, // 2025-12-25
			result: "2025-12-25",
		},
		{
			name: "MAC with dash (TPLINK-TC-MIB) - 1x-1x-1x-1x-1x-1x",
			spec: []config.FormatOp{
				{Take: 1, Fmt: "x", Sep: "-"},
				{Take: 1, Fmt: "x", Sep: "-"},
				{Take: 1, Fmt: "x", Sep: "-"},
				{Take: 1, Fmt: "x", Sep: "-"},
				{Take: 1, Fmt: "x", Sep: "-"},
				{Take: 1, Fmt: "x"},
			},
			data:   []byte{0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e},
			result: "00-1a-2b-3c-4d-5e",
		},
		{
			name: "Bridge ID (PRVT-SPANNING-TREE-MIB) - 2d.1x:1x:1x:1x:1x:1x",
			spec: []config.FormatOp{
				{Take: 2, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "x", Sep: ":"},
				{Take: 1, Fmt: "x", Sep: ":"},
				{Take: 1, Fmt: "x", Sep: ":"},
				{Take: 1, Fmt: "x", Sep: ":"},
				{Take: 1, Fmt: "x", Sep: ":"},
				{Take: 1, Fmt: "x"},
			},
			data:   []byte{0x80, 0x00, 0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e}, // priority 32768
			result: "32768.00:1a:2b:3c:4d:5e",
		},
		{
			name: "IPv6-mapped IPv4 (WATCHGUARD-IPSEC-SA-MON-MIB-EXT)",
			spec: []config.FormatOp{
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d"},
			},
			data:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 192, 168, 1, 1},
			result: "0000:0000:0000:0000:0000:ffff:192.168.1.1",
		},
		{
			name: "Timezone offset (SNMPv2-TC DateAndTime suffix) - 1a1d:1d",
			spec: []config.FormatOp{
				{Take: 1, Fmt: "a"},
				{Take: 1, Fmt: "d", Sep: ":"},
				{Take: 1, Fmt: "d"},
			},
			data:   []byte{'+', 5, 30}, // +05:30
			result: "+5:30",
		},
		{
			name: "Zero octet length produces empty output",
			spec: []config.FormatOp{
				{Take: 0, Fmt: "a"},
				{Take: 1, Fmt: "d"},
			},
			data:   []byte{42},
			result: "42",
		},
		// Note: applyFormatSpec produces raw bytes for 'a' and 't' formats.
		// Invalid UTF-8 is sanitized at call sites via strings.ToValidUTF8().
		// The following tests document the raw output behavior.
		{
			name: "ASCII format with high bytes (raw output)",
			spec: []config.FormatOp{
				{Take: 10, Fmt: "a"},
			},
			data:   []byte{'H', 'i', 0x80, 0xFF}, // 0x80 and 0xFF are invalid UTF-8
			result: "Hi\x80\xff",                 // Raw bytes preserved
		},
		{
			name: "UTF-8 format with incomplete sequence (raw output)",
			spec: []config.FormatOp{
				{Take: 10, Fmt: "t"},
			},
			data:   []byte{'O', 'K', 0xC2}, // 0xC2 starts a 2-byte sequence but is incomplete
			result: "OK\xc2",               // Raw bytes preserved
		},
		{
			name: "Star prefix with repeat count zero",
			spec: []config.FormatOp{
				{Take: 1, StarPrefix: true, Fmt: "x", Sep: ":"},
			},
			// repeat=0 means skip, then read next byte (0x02) as count, apply 2 times
			data:   []byte{0, 2, 0xaa, 0xbb},
			result: "aa:bb",
		},
		{
			name: "Star prefix with repeat count zero followed by another spec",
			spec: []config.FormatOp{
				{Take: 1, StarPrefix: true, Fmt: "x", Sep: ":"},
				{Take: 1, Fmt: "d", Sep: "."},
			},
			data:   []byte{0, 10, 20, 30}, // repeat=0 for first spec, second spec applies with implicit repetition
			result: "10.20.30",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := applyFormatSpec(c.spec, c.data)
			if got != c.result {
				t.Errorf("applyFormatSpec(%v, %v): got %q, want %q", c.spec, c.data, got, c.result)
			}
		})
	}
}

// TestApplyFormatSpecUTF8Sanitization verifies that invalid UTF-8 is sanitized
// when applyFormatSpec results are wrapped with strings.ToValidUTF8 (as done at call sites).
func TestApplyFormatSpecUTF8Sanitization(t *testing.T) {
	cases := []struct {
		name   string
		spec   []config.FormatOp
		data   []byte
		result string
	}{
		{
			name: "ASCII format with invalid UTF-8 bytes sanitized",
			spec: []config.FormatOp{
				{Take: 10, Fmt: "a"},
			},
			data:   []byte{'H', 'i', 0x80, 0xFF, '!'},
			result: "Hi�!", // Consecutive invalid bytes replaced with single replacement char
		},
		{
			name: "UTF-8 format with incomplete sequence sanitized",
			spec: []config.FormatOp{
				{Take: 10, Fmt: "t"},
			},
			data:   []byte{'O', 'K', 0xC2}, // 0xC2 starts 2-byte sequence, incomplete
			result: "OK�",
		},
		{
			name: "UTF-8 format with overlong encoding sanitized",
			spec: []config.FormatOp{
				{Take: 10, Fmt: "t"},
			},
			data:   []byte{0xC0, 0x80}, // Overlong encoding of NUL - treated as single invalid sequence
			result: "�",
		},
		{
			name: "UTF-8 format with invalid continuation byte sanitized",
			spec: []config.FormatOp{
				{Take: 10, Fmt: "t"},
			},
			data:   []byte{'A', 0xE2, 0x28, 0xA1}, // 0xE2 expects valid continuation, 0x28 is not
			result: "A�(�",
		},
		{
			name: "Valid UTF-8 preserved",
			spec: []config.FormatOp{
				{Take: 20, Fmt: "t"},
			},
			data:   []byte("Hello, 世界!"),
			result: "Hello, 世界!",
		},
		{
			name: "Mixed valid and invalid UTF-8",
			spec: []config.FormatOp{
				{Take: 20, Fmt: "t"},
			},
			data:   []byte{'H', 'i', 0xFF, 0xFE, ' ', 0xE4, 0xB8, 0x96}, // "Hi" + invalid + " " + "世"
			result: "Hi� 世",                                             // Consecutive invalid bytes replaced with single replacement char
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// This mirrors the call site behavior: applyFormatSpec wrapped with ToValidUTF8
			raw := applyFormatSpec(c.spec, c.data)
			got := strings.ToValidUTF8(raw, "�")
			if got != c.result {
				t.Errorf("ToValidUTF8(applyFormatSpec(%v, %v)): got %q, want %q", c.spec, c.data, got, c.result)
			}
		})
	}
}

func TestScrapeTarget(t *testing.T) {
	cases := []struct {
		name          string
		module        *config.Module
		getResponse   map[string]gosnmp.SnmpPDU
		walkResponses map[string][]gosnmp.SnmpPDU
		expectPdus    []gosnmp.SnmpPDU
		getCall       []string
		walkCall      []string
	}{
		{
			name: "basic",
			module: &config.Module{
				Get:  []string{"1.3.6.1.2.1.1.1.0"},
				Walk: []string{"1.3.6.1.2.1.2.2.1.2", "1.3.6.1.2.1.31.1.1.1.18"},
			},
			getResponse: map[string]gosnmp.SnmpPDU{
				"1.3.6.1.2.1.1.1.0": {Type: gosnmp.OctetString, Name: "1.3.6.1.2.1.1.1.0", Value: "Test Device"}, // sysDescr
			},
			walkResponses: map[string][]gosnmp.SnmpPDU{
				"1.3.6.1.2.1.2.2.1.2": {
					{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.2.2.1.2.1", Value: "lo"},
					{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.2.2.1.2.2", Value: "Intel Corporation 82540EM Gigabit Ethernet Controller"},
					{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.2.2.1.2.3", Value: "Intel Corporation 82540EM Gigabit Ethernet Controller"},
				},
				"1.3.6.1.2.1.31.1.1.1.18": {
					{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.31.1.1.1.18.1", Value: "lo"},
					{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.31.1.1.1.18.2", Value: "eth0"},
					{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.31.1.1.1.18.3", Value: "swp1"},
				},
			},
			expectPdus: []gosnmp.SnmpPDU{
				{Type: gosnmp.OctetString, Name: "1.3.6.1.2.1.1.1.0", Value: "Test Device"},
				{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.2.2.1.2.1", Value: "lo"},
				{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.2.2.1.2.2", Value: "Intel Corporation 82540EM Gigabit Ethernet Controller"},
				{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.2.2.1.2.3", Value: "Intel Corporation 82540EM Gigabit Ethernet Controller"},
				{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.31.1.1.1.18.1", Value: "lo"},
				{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.31.1.1.1.18.2", Value: "eth0"},
				{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.31.1.1.1.18.3", Value: "swp1"},
			},
			getCall:  []string{"1.3.6.1.2.1.1.1.0"},
			walkCall: []string{"1.3.6.1.2.1.2.2.1.2", "1.3.6.1.2.1.31.1.1.1.18"},
		},
		{
			name: "dynamic filter",
			module: &config.Module{
				Get:  []string{},
				Walk: []string{"1.3.6.1.2.1.31.1.1.1.18"},
				Filters: []config.DynamicFilter{
					{
						Oid: "1.3.6.1.2.1.2.2.1.2",
						Targets: []string{
							"1.3.6.1.2.1.31.1.1.1.18",
						},
						Values: []string{"Intel Corporation 82540EM Gigabit Ethernet Controller"},
					},
				},
			},
			getResponse: map[string]gosnmp.SnmpPDU{
				"1.3.6.1.2.1.31.1.1.1.18.2": {Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.31.1.1.1.18.2", Value: "eth0"},
				"1.3.6.1.2.1.31.1.1.1.18.3": {Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.31.1.1.1.18.3", Value: "swp1"},
			},
			walkResponses: map[string][]gosnmp.SnmpPDU{
				"1.3.6.1.2.1.2.2.1.2": {
					{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.2.2.1.2.1", Value: "lo"},
					{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.2.2.1.2.2", Value: "Intel Corporation 82540EM Gigabit Ethernet Controller"},
					{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.2.2.1.2.3", Value: "Intel Corporation 82540EM Gigabit Ethernet Controller"},
				},
			},
			expectPdus: []gosnmp.SnmpPDU{
				{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.31.1.1.1.18.2", Value: "eth0"},
				{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.31.1.1.1.18.3", Value: "swp1"},
			},
			getCall:  []string{"1.3.6.1.2.1.31.1.1.1.18.2", "1.3.6.1.2.1.31.1.1.1.18.3"},
			walkCall: []string{"1.3.6.1.2.1.2.2.1.2"},
		},
	}

	auth := &config.Auth{Version: 2}
	for _, c := range cases {
		tt := c
		t.Run(tt.name, func(t *testing.T) {
			mock := scraper.NewMockSNMPScraper(tt.getResponse, tt.walkResponses)
			results, err := ScrapeTarget(mock, "someTarget", auth, tt.module, promslog.NewNopLogger(), Metrics{})
			if err != nil {
				t.Errorf("ScrapeTarget returned an error: %v", err)
			}
			if !reflect.DeepEqual(mock.CallGet(), tt.getCall) {
				t.Errorf("Expected get call %v, got %v", tt.getCall, mock.CallGet())
			}
			if !reflect.DeepEqual(mock.CallWalk(), tt.walkCall) {
				t.Errorf("Expected walk call %v, got %v", tt.walkCall, mock.CallWalk())
			}
			expectedPdusLen := len(tt.expectPdus)
			if len(results.pdus) != expectedPdusLen {
				t.Fatalf("Expected %d PDUs, got %d", expectedPdusLen, len(results.pdus))
			}

			for i, pdu := range tt.expectPdus {
				if !reflect.DeepEqual(pdu, results.pdus[i]) {
					t.Errorf("Expected %v, got %v", pdu, results.pdus[i])
				}
			}
		})
	}
}
