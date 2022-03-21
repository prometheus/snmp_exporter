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
	"reflect"
	"regexp"
	"testing"

	"github.com/go-kit/log"
	"github.com/prometheus/snmp_exporter/config"
	yaml "gopkg.in/yaml.v2"
)

func TestTreePrepare(t *testing.T) {
	cases := []struct {
		in  *Node
		out *Node
	}{
		// Descriptions trimmed.
		{
			in:  &Node{Oid: "1", Description: "A long   sentence.      Even more detail!"},
			out: &Node{Oid: "1", Description: "A long sentence"},
		},
		// Indexes copied down.
		{
			in: &Node{Oid: "1", Label: "labelEntry", Indexes: []string{"myIndex"},
				Children: []*Node{
					{Oid: "1.1", Label: "labelA"}},
			},
			out: &Node{Oid: "1", Label: "labelEntry", Indexes: []string{"myIndex"},
				Children: []*Node{
					{Oid: "1.1", Label: "labelA", Indexes: []string{"myIndex"}}},
			},
		},
		// Augemnts copied over.
		{
			in: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "table",
						Children: []*Node{
							{Oid: "1.1.1", Label: "tableEntry", Indexes: []string{"tableDesc"},
								Children: []*Node{
									{Oid: "1.1.1.1", Label: "tableDesc"}}}}},
					{Oid: "1.2", Label: "augmentingTable",
						Children: []*Node{
							{Oid: "1.2.1", Label: "augmentingTableEntry", Augments: "tableEntry",
								Children: []*Node{
									{Oid: "1.2.1.1", Label: "augmentingA"}}}}},
				},
			},
			out: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "table",
						Children: []*Node{
							{Oid: "1.1.1", Label: "tableEntry", Indexes: []string{"tableDesc"},
								Children: []*Node{
									{Oid: "1.1.1.1", Label: "tableDesc", Indexes: []string{"tableDesc"}}}}}},
					{Oid: "1.2", Label: "augmentingTable",
						Children: []*Node{
							{Oid: "1.2.1", Label: "augmentingTableEntry", Augments: "tableEntry", Indexes: []string{"tableDesc"},
								Children: []*Node{
									{Oid: "1.2.1.1", Label: "augmentingA", Indexes: []string{"tableDesc"}}}}}},
				},
			},
		},
		// INTEGER indexes fixed.
		{
			in: &Node{Oid: "1", Label: "snSlotsEntry", Indexes: []string{"INTEGER"},
				Children: []*Node{
					{Oid: "1.1", Label: "snSlotsA"}},
			},
			out: &Node{Oid: "1", Label: "snSlotsEntry", Indexes: []string{"snSlotsEntry"},
				Children: []*Node{
					{Oid: "1.1", Label: "snSlotsA", Indexes: []string{"snSlotsEntry"}}},
			},
		},
		// MAC Address type set.
		{
			in:  &Node{Oid: "1", Label: "mac", Hint: "1x:"},
			out: &Node{Oid: "1", Label: "mac", Hint: "1x:", Type: "PhysAddress48"},
		},
		// Short ASCII string.
		{
			in:  &Node{Oid: "1", Label: "ascii", Hint: "32a"},
			out: &Node{Oid: "1", Label: "ascii", Hint: "32a", Type: "DisplayString"},
		},
		// DisplayString referencing RFC1213.
		{
			in:  &Node{Oid: "1", Label: "ascii", TextualConvention: "DisplayString"},
			out: &Node{Oid: "1", Label: "ascii", TextualConvention: "DisplayString", Type: "DisplayString"},
		},
		// PhysAddress referencing RFC1213.
		{
			in:  &Node{Oid: "1", Label: "mac", TextualConvention: "PhysAddress"},
			out: &Node{Oid: "1", Label: "mac", TextualConvention: "PhysAddress", Type: "PhysAddress48"},
		},
		// UTF-8 string.
		{
			in:  &Node{Oid: "1", Label: "utf8", Hint: "255t"},
			out: &Node{Oid: "1", Label: "utf8", Hint: "255t", Type: "DisplayString"},
		},
		// Mix of number and ASCII string.
		{
			in:  &Node{Oid: "1", Label: "notascii", Hint: "2d32a", Type: "OCTETSTR"},
			out: &Node{Oid: "1", Label: "notascii", Hint: "2d32a", Type: "OCTETSTR"},
		},
		// Opaques converted.
		{
			in:  &Node{Oid: "1", Type: "OPAQUE", TextualConvention: "Float"},
			out: &Node{Oid: "1", Type: "Float", TextualConvention: "Float"},
		},
		{
			in:  &Node{Oid: "1", Type: "OPAQUE", TextualConvention: "Double"},
			out: &Node{Oid: "1", Type: "Double", TextualConvention: "Double"},
		},
		// RFC 2579 DateAndTime.
		{
			in:  &Node{Oid: "1", Type: "DisplayString", TextualConvention: "DateAndTime"},
			out: &Node{Oid: "1", Type: "DateAndTime", TextualConvention: "DateAndTime"},
		},
		// RFC 4100 InetAddress conventions.
		{
			in:  &Node{Oid: "1", Type: "OctectString", TextualConvention: "InetAddressIPv4"},
			out: &Node{Oid: "1", Type: "InetAddressIPv4", TextualConvention: "InetAddressIPv4"},
		},
		{
			in:  &Node{Oid: "1", Type: "OctectString", TextualConvention: "InetAddressIPv6"},
			out: &Node{Oid: "1", Type: "InetAddressIPv6", TextualConvention: "InetAddressIPv6"},
		},
		{
			in:  &Node{Oid: "1", Type: "OctectString", TextualConvention: "InetAddress"},
			out: &Node{Oid: "1", Type: "InetAddress", TextualConvention: "InetAddress"},
		},
	}
	for i, c := range cases {
		// Indexes always end up initialized.
		walkNode(c.out, func(n *Node) {
			if n.Indexes == nil {
				n.Indexes = []string{}
			}
		})

		prepareTree(c.in, log.NewNopLogger())

		if !reflect.DeepEqual(c.in, c.out) {
			t.Errorf("prepareTree: difference in case %d", i)
			walkNode(c.in, func(n *Node) {
				t.Errorf("Got: %+v", n)
			})
			walkNode(c.out, func(n *Node) {
				t.Errorf("Wanted: %+v\n\n", n)
			})

		}
	}
}

func TestGenerateConfigModule(t *testing.T) {
	var regexpFooBar config.Regexp
	regexpFooBar.Regexp, _ = regexp.Compile(".*")

	strMetrics := make(map[string][]config.RegexpExtract)
	strMetrics["Status"] = []config.RegexpExtract{
		{
			Regex: regexpFooBar,
			Value: "5",
		},
	}

	overrides := make(map[string]MetricOverrides)
	overrides["root"] = MetricOverrides{
		RegexpExtracts: strMetrics,
	}

	cases := []struct {
		node *Node
		cfg  *ModuleConfig  // SNMP generator config.
		out  *config.Module // SNMP exporter config.
	}{
		// Simple metric with Regexp override.
		{
			node: &Node{Oid: "1", Access: "ACCESS_READONLY", Type: "INTEGER", Label: "root"},
			cfg: &ModuleConfig{
				Walk:      []string{"root"},
				Overrides: overrides,
			},
			out: &config.Module{
				Get: []string{"1.0"},
				Metrics: []*config.Metric{
					{
						Name:           "root",
						Oid:            "1",
						Type:           "gauge",
						Help:           " - 1",
						RegexpExtracts: strMetrics,
					},
				},
			},
		},
		// Simple metric.
		{
			node: &Node{Oid: "1", Access: "ACCESS_READONLY", Type: "INTEGER", Label: "root"},
			cfg: &ModuleConfig{
				Walk: []string{"root"},
			},
			out: &config.Module{
				Get: []string{"1.0"},
				Metrics: []*config.Metric{
					{
						Name: "root",
						Oid:  "1",
						Type: "gauge",
						Help: " - 1",
					},
				},
			},
		},
		// Simple walk.
		{
			node: &Node{Oid: "1", Type: "OTHER", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Access: "ACCESS_READONLY", Type: "INTEGER", Label: "node"},
				}},
			cfg: &ModuleConfig{
				Walk: []string{"root"},
			},
			out: &config.Module{
				Walk: []string{"1"},
				Metrics: []*config.Metric{
					{
						Name: "node",
						Oid:  "1.1",
						Type: "gauge",
						Help: " - 1.1",
					},
				},
			},
		},
		// Can also provide OIDs to get.
		{
			node: &Node{Oid: "1", Access: "ACCESS_READONLY", Type: "INTEGER", Label: "root"},
			cfg: &ModuleConfig{
				Walk: []string{"1"},
			},
			out: &config.Module{
				Get: []string{"1.0"},
				Metrics: []*config.Metric{
					{
						Name: "root",
						Oid:  "1",
						Type: "gauge",
						Help: " - 1",
					},
				},
			},
		},
		// Duplicate walks handled gracefully.
		{
			node: &Node{Oid: "1", Access: "ACCESS_READONLY", Type: "INTEGER", Label: "root"},
			cfg: &ModuleConfig{
				Walk: []string{"1", "root"},
			},
			out: &config.Module{
				Get: []string{"1.0"},
				Metrics: []*config.Metric{
					{
						Name: "root",
						Oid:  "1",
						Type: "gauge",
						Help: " - 1",
					},
				},
			},
		},
		// Scalar root with instance child.
		{
			node: &Node{Oid: "1", Access: "ACCESS_READONLY", Type: "INTEGER", Label: "root",
				Children: []*Node{
					{Oid: "1.0", Type: "OTHER", Label: "rootInstance"},
				}},
			cfg: &ModuleConfig{
				Walk: []string{"root"},
			},
			out: &config.Module{
				Get: []string{"1.0"},
				Metrics: []*config.Metric{
					{
						Name: "root",
						Oid:  "1",
						Type: "gauge",
						Help: " - 1",
					},
				},
			},
		},
		// Metric types.
		{
			node: &Node{Oid: "1", Type: "OTHER", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Access: "ACCESS_READONLY", Label: "OBJID", Type: "OCTETSTR"},
					{Oid: "1.2", Access: "ACCESS_READONLY", Label: "OCTETSTR", Type: "OCTETSTR"},
					{Oid: "1.3", Access: "ACCESS_READONLY", Label: "INTEGER", Type: "INTEGER"},
					{Oid: "1.4", Access: "ACCESS_READONLY", Label: "NETADDR", Type: "NETADDR"},
					{Oid: "1.5", Access: "ACCESS_READONLY", Label: "IPADDR", Type: "IPADDR"},
					{Oid: "1.6", Access: "ACCESS_READONLY", Label: "COUNTER", Type: "COUNTER"},
					{Oid: "1.7", Access: "ACCESS_READONLY", Label: "GAUGE", Type: "GAUGE"},
					{Oid: "1.8", Access: "ACCESS_READONLY", Label: "TIMETICKS", Type: "TIMETICKS"},
					{Oid: "1.9", Access: "ACCESS_READONLY", Label: "OPAQUE", Type: "OPAQUE"},
					{Oid: "1.10", Access: "ACCESS_READONLY", Label: "NULL", Type: "NULL"},
					{Oid: "1.11", Access: "ACCESS_READONLY", Label: "COUNTER64", Type: "COUNTER64"},
					{Oid: "1.12", Access: "ACCESS_READONLY", Label: "BITSTRING", Type: "BITSTRING"},
					{Oid: "1.13", Access: "ACCESS_READONLY", Label: "NSAPADDRESS", Type: "NSAPADDRESS"},
					{Oid: "1.14", Access: "ACCESS_READONLY", Label: "UINTEGER", Type: "UINTEGER"},
					{Oid: "1.15", Access: "ACCESS_READONLY", Label: "UNSIGNED32", Type: "UNSIGNED32"},
					{Oid: "1.16", Access: "ACCESS_READONLY", Label: "INTEGER32", Type: "INTEGER32"},
					{Oid: "1.20", Access: "ACCESS_READONLY", Label: "TRAPTYPE", Type: "TRAPTYPE"},
					{Oid: "1.21", Access: "ACCESS_READONLY", Label: "NOTIFTYPE", Type: "NOTIFTYPE"},
					{Oid: "1.22", Access: "ACCESS_READONLY", Label: "OBJGROUP", Type: "OBJGROUP"},
					{Oid: "1.23", Access: "ACCESS_READONLY", Label: "NOTIFGROUP", Type: "NOTIFGROUP"},
					{Oid: "1.24", Access: "ACCESS_READONLY", Label: "MODID", Type: "MODID"},
					{Oid: "1.25", Access: "ACCESS_READONLY", Label: "AGENTCAP", Type: "AGENTCAP"},
					{Oid: "1.26", Access: "ACCESS_READONLY", Label: "MODCOMP", Type: "MODCOMP"},
					{Oid: "1.27", Access: "ACCESS_READONLY", Label: "OBJIDENTITY", Type: "OBJIDENTITY"},
					{Oid: "1.100", Access: "ACCESS_READONLY", Label: "MacAddress", Type: "OCTETSTR", Hint: "1x:"},
					{Oid: "1.200", Access: "ACCESS_READONLY", Label: "Float", Type: "OPAQUE", TextualConvention: "Float"},
					{Oid: "1.201", Access: "ACCESS_READONLY", Label: "Double", Type: "OPAQUE", TextualConvention: "Double"},
					{Oid: "1.202", Access: "ACCESS_READONLY", Label: "DateAndTime", Type: "DisplayString", TextualConvention: "DateAndTime"},
					{Oid: "1.203", Access: "ACCESS_READONLY", Label: "InetAddressIPv4", Type: "OCTETSTR", TextualConvention: "InetAddressIPv4"},
					{Oid: "1.204", Access: "ACCESS_READONLY", Label: "InetAddressIPv6", Type: "OCTETSTR", TextualConvention: "InetAddressIPv6"},
				}},
			cfg: &ModuleConfig{
				Walk: []string{"root", "1.3"},
			},
			out: &config.Module{
				Walk: []string{"1"},
				Metrics: []*config.Metric{
					{
						Name: "OBJID",
						Oid:  "1.1",
						Type: "OctetString",
						Help: " - 1.1",
					},
					{
						Name: "OCTETSTR",
						Oid:  "1.2",
						Type: "OctetString",
						Help: " - 1.2",
					},
					{
						Name: "INTEGER",
						Oid:  "1.3",
						Type: "gauge",
						Help: " - 1.3",
					},
					{
						Name: "NETADDR",
						Oid:  "1.4",
						Type: "InetAddressIPv4",
						Help: " - 1.4",
					},
					{
						Name: "IPADDR",
						Oid:  "1.5",
						Type: "InetAddressIPv4",
						Help: " - 1.5",
					},
					{
						Name: "COUNTER",
						Oid:  "1.6",
						Type: "counter",
						Help: " - 1.6",
					},
					{
						Name: "GAUGE",
						Oid:  "1.7",
						Type: "gauge",
						Help: " - 1.7",
					},
					{
						Name: "TIMETICKS",
						Oid:  "1.8",
						Type: "gauge",
						Help: " - 1.8",
					},
					{
						Name: "COUNTER64",
						Oid:  "1.11",
						Type: "counter",
						Help: " - 1.11",
					},
					{
						Name: "BITSTRING",
						Oid:  "1.12",
						Type: "Bits",
						Help: " - 1.12",
					},
					{
						Name: "UINTEGER",
						Oid:  "1.14",
						Type: "gauge",
						Help: " - 1.14",
					},
					{
						Name: "UNSIGNED32",
						Oid:  "1.15",
						Type: "gauge",
						Help: " - 1.15",
					},
					{
						Name: "INTEGER32",
						Oid:  "1.16",
						Type: "gauge",
						Help: " - 1.16",
					},
					{
						Name: "MacAddress",
						Oid:  "1.100",
						Type: "PhysAddress48",
						Help: " - 1.100",
					},
					{
						Name: "Float",
						Oid:  "1.200",
						Type: "Float",
						Help: " - 1.200",
					},
					{
						Name: "Double",
						Oid:  "1.201",
						Type: "Double",
						Help: " - 1.201",
					},
					{
						Name: "DateAndTime",
						Oid:  "1.202",
						Type: "DateAndTime",
						Help: " - 1.202",
					},
					{
						Name: "InetAddressIPv4",
						Oid:  "1.203",
						Type: "InetAddressIPv4",
						Help: " - 1.203",
					},
					{
						Name: "InetAddressIPv6",
						Oid:  "1.204",
						Type: "InetAddressIPv6",
						Help: " - 1.204",
					},
				},
			},
		},
		// Simple metric with ignore override.
		{
			node: &Node{Oid: "1", Type: "OTHER", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Access: "ACCESS_READONLY", Type: "INTEGER", Label: "node1"},
					{Oid: "1.2", Access: "ACCESS_READONLY", Type: "OCTETSTR", Label: "node2"},
				}},
			cfg: &ModuleConfig{
				Walk: []string{"root"},
				Overrides: map[string]MetricOverrides{
					"node2": MetricOverrides{Ignore: true},
				},
			},
			out: &config.Module{
				Walk: []string{"1"},
				Metrics: []*config.Metric{
					{
						Name: "node1",
						Oid:  "1.1",
						Type: "gauge",
						Help: " - 1.1",
					},
				},
			},
		},
		// Simple metric with type override.
		{
			node: &Node{Oid: "1", Type: "OTHER", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Access: "ACCESS_READONLY", Type: "INTEGER", Label: "node1"},
					{Oid: "1.2", Access: "ACCESS_READONLY", Type: "OCTETSTR", Label: "node2"},
				}},
			cfg: &ModuleConfig{
				Walk: []string{"root"},
				Overrides: map[string]MetricOverrides{
					"node2": MetricOverrides{Type: "DisplayString"},
				},
			},
			out: &config.Module{
				Walk: []string{"1"},
				Metrics: []*config.Metric{
					{
						Name: "node1",
						Oid:  "1.1",
						Type: "gauge",
						Help: " - 1.1",
					},
					{
						Name: "node2",
						Oid:  "1.2",
						Type: "DisplayString",
						Help: " - 1.2",
					},
				},
			},
		},
		// Enums
		{
			node: &Node{Oid: "1", Type: "OTHER", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Access: "ACCESS_READONLY", Type: "INTEGER", Label: "node1", EnumValues: map[int]string{0: "a"}},
					{Oid: "1.2", Access: "ACCESS_READONLY", Type: "INTEGER", Label: "node2", EnumValues: map[int]string{0: "b"}},
				}},
			cfg: &ModuleConfig{
				Walk: []string{"root"},
				Overrides: map[string]MetricOverrides{
					"node1": MetricOverrides{Type: "EnumAsInfo"},
					"node2": MetricOverrides{Type: "EnumAsStateSet"},
				},
			},
			out: &config.Module{
				Walk: []string{"1"},
				Metrics: []*config.Metric{
					{
						Name:       "node1",
						Oid:        "1.1",
						Type:       "EnumAsInfo",
						Help:       " - 1.1",
						EnumValues: map[int]string{0: "a"},
					},
					{
						Name:       "node2",
						Oid:        "1.2",
						Type:       "EnumAsStateSet",
						Help:       " - 1.2",
						EnumValues: map[int]string{0: "b"},
					},
				},
			},
		},
		// Table with type override.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "table",
						Children: []*Node{
							{Oid: "1.1.1", Label: "tableEntry", Indexes: []string{"node1"},
								Children: []*Node{
									{Oid: "1.1.1.1", Access: "ACCESS_READONLY", Label: "node1", Type: "INTEGER"},
									{Oid: "1.1.1.2", Access: "ACCESS_READONLY", Label: "node2", Type: "OCTETSTR"},
								}}}}}},
			cfg: &ModuleConfig{
				Walk: []string{"1"},
				Overrides: map[string]MetricOverrides{
					"node1": MetricOverrides{Type: "counter"},
					"node2": MetricOverrides{Type: "DisplayString"},
				},
			},
			out: &config.Module{
				Walk: []string{"1"},
				Metrics: []*config.Metric{
					{
						Name: "node1",
						Oid:  "1.1.1.1",
						Type: "counter",
						Help: " - 1.1.1.1",
						Indexes: []*config.Index{
							{
								Labelname: "node1",
								Type:      "counter",
							},
						},
					},
					{
						Name: "node2",
						Oid:  "1.1.1.2",
						Type: "DisplayString",
						Help: " - 1.1.1.2",
						Indexes: []*config.Index{
							{
								Labelname: "node1",
								Type:      "counter",
							},
						},
					},
				},
			},
		},
		// Tables with accessible & inaccessible.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "table",
						Children: []*Node{
							{Oid: "1.1.1", Label: "tableEntry",
								Children: []*Node{
									{Oid: "1.1.1.1", Access: "ACCESS_NOACCESS", Label: "tableNoAccess", Type: "INTEGER"},
									{Oid: "1.1.1.2", Access: "ACCESS_CREATE", Label: "tableCreate", Type: "INTEGER"},
									{Oid: "1.1.1.3", Access: "ACCESS_WRITEONLY", Label: "tableWriteOnly", Type: "INTEGER"},
									{Oid: "1.1.1.4", Access: "ACCESS_READONLY", Label: "tableReadOnly", Type: "INTEGER"},
									{Oid: "1.1.1.5", Access: "ACCESS_READWRITE", Label: "tableReadWrite", Type: "INTEGER"},
									{Oid: "1.1.1.6", Access: "ACCESS_NOTIFY", Label: "tableNotify", Type: "INTEGER"},
								}}}}}},
			cfg: &ModuleConfig{
				Walk: []string{"1"},
			},
			out: &config.Module{
				Walk: []string{"1"},
				Metrics: []*config.Metric{
					{
						Name: "tableNoAccess",
						Oid:  "1.1.1.1",
						Type: "gauge",
						Help: " - 1.1.1.1",
					},
					{
						Name: "tableCreate",
						Oid:  "1.1.1.2",
						Type: "gauge",
						Help: " - 1.1.1.2",
					},
					{
						Name: "tableReadOnly",
						Oid:  "1.1.1.4",
						Type: "gauge",
						Help: " - 1.1.1.4",
					},
					{
						Name: "tableReadWrite",
						Oid:  "1.1.1.5",
						Type: "gauge",
						Help: " - 1.1.1.5",
					},
				},
			},
		},
		// Basic table with integer index.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "table",
						Children: []*Node{
							{Oid: "1.1.1", Label: "tableEntry", Indexes: []string{"tableIndex"},
								Children: []*Node{
									{Oid: "1.1.1.1", Access: "ACCESS_READONLY", Label: "tableIndex", Type: "INTEGER"},
									{Oid: "1.1.1.2", Access: "ACCESS_READONLY", Label: "tableFoo", Type: "INTEGER"},
								}}}}}},
			cfg: &ModuleConfig{
				Walk: []string{"1"},
			},
			out: &config.Module{
				Walk: []string{"1"},
				Metrics: []*config.Metric{
					{
						Name: "tableIndex",
						Oid:  "1.1.1.1",
						Type: "gauge",
						Help: " - 1.1.1.1",
						Indexes: []*config.Index{
							{
								Labelname: "tableIndex",
								Type:      "gauge",
							},
						},
					},
					{
						Name: "tableFoo",
						Oid:  "1.1.1.2",
						Type: "gauge",
						Help: " - 1.1.1.2",
						Indexes: []*config.Index{
							{
								Labelname: "tableIndex",
								Type:      "gauge",
							},
						},
					},
				},
			},
		},
		// Tables with non-integer indexes.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "octet",
						Children: []*Node{
							{Oid: "1.1.1", Label: "octetEntry", Indexes: []string{"octetIndex"},
								Children: []*Node{
									{Oid: "1.1.1.1", Access: "ACCESS_READONLY", Label: "octetIndex", Type: "OCTETSTR"},
									{Oid: "1.1.1.2", Access: "ACCESS_READONLY", Label: "octetFoo", Type: "INTEGER"}}}}},
					{Oid: "1.2", Label: "bitstring",
						Children: []*Node{
							{Oid: "1.2.1", Label: "bitstringEntry", Indexes: []string{"bitstringIndex"},
								Children: []*Node{
									{Oid: "1.2.1.1", Access: "ACCESS_READONLY", Label: "bitstringIndex", Type: "BITSTRING"},
									{Oid: "1.2.1.2", Access: "ACCESS_READONLY", Label: "bitstringFoo", Type: "INTEGER"}}}}},
					{Oid: "1.3", Label: "ipaddr",
						Children: []*Node{
							{Oid: "1.3.1", Label: "ipaddrEntry", Indexes: []string{"ipaddrIndex"},
								Children: []*Node{
									{Oid: "1.3.1.1", Access: "ACCESS_READONLY", Label: "ipaddrIndex", Type: "IPADDR"},
									{Oid: "1.3.1.2", Access: "ACCESS_READONLY", Label: "ipaddrFoo", Type: "INTEGER"}}}}},
					{Oid: "1.4", Label: "netaddr",
						Children: []*Node{
							{Oid: "1.4.1", Label: "netaddrEntry", Indexes: []string{"netaddrIndex"},
								Children: []*Node{
									{Oid: "1.4.1.1", Access: "ACCESS_READONLY", Label: "netaddrIndex", Type: "NETADDR"},
									{Oid: "1.4.1.2", Access: "ACCESS_READONLY", Label: "netaddrFoo", Type: "INTEGER"}}}}},
					{Oid: "1.5", Label: "physaddress48",
						Children: []*Node{
							{Oid: "1.5.1", Label: "physaddress48Entry", Indexes: []string{"physaddress48Index"},
								Children: []*Node{
									{Oid: "1.5.1.1", Access: "ACCESS_READONLY", Label: "physaddress48Index", Type: "OCTETSTR", Hint: "1x:"},
									{Oid: "1.5.1.2", Access: "ACCESS_READONLY", Label: "physaddress48Foo", Type: "INTEGER"}}}}},
					{Oid: "1.6", Label: "fixedSize",
						Children: []*Node{
							{Oid: "1.6.1", Label: "fixedSizeEntry", Indexes: []string{"fixedSizeIndex"},
								Children: []*Node{
									{Oid: "1.6.1.1", Access: "ACCESS_READONLY", Label: "fixedSizeIndex", Type: "OCTETSTR", FixedSize: 8},
									{Oid: "1.6.1.2", Access: "ACCESS_READONLY", Label: "fixedSizeFoo", Type: "INTEGER"}}}}},
					{Oid: "1.7", Label: "impliedSize",
						Children: []*Node{
							{Oid: "1.7.1", Label: "impliedSizeEntry", Indexes: []string{"impliedSizeIndex"}, ImpliedIndex: true,
								Children: []*Node{
									{Oid: "1.7.1.1", Access: "ACCESS_READONLY", Label: "impliedSizeIndex", Type: "OCTETSTR"},
									{Oid: "1.7.1.2", Access: "ACCESS_READONLY", Label: "impliedSizeFoo", Type: "INTEGER"}}}}},
					{Oid: "1.8", Label: "ipv4",
						Children: []*Node{
							{Oid: "1.8.1", Label: "ipv4Entry", Indexes: []string{"ipv4Index"},
								Children: []*Node{
									{Oid: "1.8.1.1", Access: "ACCESS_READONLY", Label: "ipv4Index", Type: "OCTETSTR", TextualConvention: "InetAddressIPv4"},
									{Oid: "1.8.1.2", Access: "ACCESS_READONLY", Label: "ipv4Foo", Type: "INTEGER"}}}}},
					{Oid: "1.9", Label: "ipv6",
						Children: []*Node{
							{Oid: "1.9.1", Label: "ipv6Entry", Indexes: []string{"ipv6Index"},
								Children: []*Node{
									{Oid: "1.9.1.1", Access: "ACCESS_READONLY", Label: "ipv6Index", Type: "OCTETSTR", TextualConvention: "InetAddressIPv6"},
									{Oid: "1.9.1.2", Access: "ACCESS_READONLY", Label: "ipv6Foo", Type: "INTEGER"}}}}},
				}},
			cfg: &ModuleConfig{
				Walk: []string{"1"},
			},
			out: &config.Module{
				Walk: []string{"1"},
				Metrics: []*config.Metric{
					{
						Name: "octetIndex",
						Oid:  "1.1.1.1",
						Help: " - 1.1.1.1",
						Type: "OctetString",
						Indexes: []*config.Index{
							{
								Labelname: "octetIndex",
								Type:      "OctetString",
							},
						},
					},
					{
						Name: "octetFoo",
						Oid:  "1.1.1.2",
						Help: " - 1.1.1.2",
						Type: "gauge",
						Indexes: []*config.Index{
							{
								Labelname: "octetIndex",
								Type:      "OctetString",
							},
						},
					},
					{
						Name: "bitstringIndex",
						Oid:  "1.2.1.1",
						Help: " - 1.2.1.1",
						Type: "Bits",
						Indexes: []*config.Index{
							{
								Labelname: "bitstringIndex",
								Type:      "Bits",
							},
						},
					},
					{
						Name: "bitstringFoo",
						Oid:  "1.2.1.2",
						Help: " - 1.2.1.2",
						Type: "gauge",
						Indexes: []*config.Index{
							{
								Labelname: "bitstringIndex",
								Type:      "Bits",
							},
						},
					},
					{
						Name: "ipaddrIndex",
						Oid:  "1.3.1.1",
						Help: " - 1.3.1.1",
						Type: "InetAddressIPv4",
						Indexes: []*config.Index{
							{
								Labelname: "ipaddrIndex",
								Type:      "InetAddressIPv4",
							},
						},
					},
					{
						Name: "ipaddrFoo",
						Oid:  "1.3.1.2",
						Help: " - 1.3.1.2",
						Type: "gauge",
						Indexes: []*config.Index{
							{
								Labelname: "ipaddrIndex",
								Type:      "InetAddressIPv4",
							},
						},
					},
					{
						Name: "netaddrIndex",
						Oid:  "1.4.1.1",
						Help: " - 1.4.1.1",
						Type: "InetAddressIPv4",
						Indexes: []*config.Index{
							{
								Labelname: "netaddrIndex",
								Type:      "InetAddressIPv4",
							},
						},
					},
					{
						Name: "netaddrFoo",
						Oid:  "1.4.1.2",
						Help: " - 1.4.1.2",
						Type: "gauge",
						Indexes: []*config.Index{
							{
								Labelname: "netaddrIndex",
								Type:      "InetAddressIPv4",
							},
						},
					},
					{
						Name: "physaddress48Index",
						Oid:  "1.5.1.1",
						Help: " - 1.5.1.1",
						Type: "PhysAddress48",
						Indexes: []*config.Index{
							{
								Labelname: "physaddress48Index",
								Type:      "PhysAddress48",
							},
						},
					},
					{
						Name: "physaddress48Foo",
						Oid:  "1.5.1.2",
						Help: " - 1.5.1.2",
						Type: "gauge",
						Indexes: []*config.Index{
							{
								Labelname: "physaddress48Index",
								Type:      "PhysAddress48",
							},
						},
					},
					{
						Name: "fixedSizeIndex",
						Oid:  "1.6.1.1",
						Help: " - 1.6.1.1",
						Type: "OctetString",
						Indexes: []*config.Index{
							{
								Labelname: "fixedSizeIndex",
								Type:      "OctetString",
								FixedSize: 8,
							},
						},
					},
					{
						Name: "fixedSizeFoo",
						Oid:  "1.6.1.2",
						Help: " - 1.6.1.2",
						Type: "gauge",
						Indexes: []*config.Index{
							{
								Labelname: "fixedSizeIndex",
								Type:      "OctetString",
								FixedSize: 8,
							},
						},
					},
					{
						Name: "impliedSizeIndex",
						Oid:  "1.7.1.1",
						Help: " - 1.7.1.1",
						Type: "OctetString",
						Indexes: []*config.Index{
							{
								Labelname: "impliedSizeIndex",
								Type:      "OctetString",
								Implied:   true,
							},
						},
					},
					{
						Name: "impliedSizeFoo",
						Oid:  "1.7.1.2",
						Help: " - 1.7.1.2",
						Type: "gauge",
						Indexes: []*config.Index{
							{
								Labelname: "impliedSizeIndex",
								Type:      "OctetString",
								Implied:   true,
							},
						},
					},
					{
						Name: "ipv4Index",
						Oid:  "1.8.1.1",
						Help: " - 1.8.1.1",
						Type: "InetAddressIPv4",
						Indexes: []*config.Index{
							{
								Labelname: "ipv4Index",
								Type:      "InetAddressIPv4",
							},
						},
					},
					{
						Name: "ipv4Foo",
						Oid:  "1.8.1.2",
						Help: " - 1.8.1.2",
						Type: "gauge",
						Indexes: []*config.Index{
							{
								Labelname: "ipv4Index",
								Type:      "InetAddressIPv4",
							},
						},
					},
					{
						Name: "ipv6Index",
						Oid:  "1.9.1.1",
						Help: " - 1.9.1.1",
						Type: "InetAddressIPv6",
						Indexes: []*config.Index{
							{
								Labelname: "ipv6Index",
								Type:      "InetAddressIPv6",
							},
						},
					},
					{
						Name: "ipv6Foo",
						Oid:  "1.9.1.2",
						Help: " - 1.9.1.2",
						Type: "gauge",
						Indexes: []*config.Index{
							{
								Labelname: "ipv6Index",
								Type:      "InetAddressIPv6",
							},
						},
					},
				},
			},
		},
		// Basic table with integer index and enum_values, overridden as EnumAsInfo.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "table",
						Children: []*Node{
							{Oid: "1.1.1", Label: "tableEntry", Indexes: []string{"tableIndex"},
								Children: []*Node{
									{Oid: "1.1.1.1", Access: "ACCESS_READONLY", Label: "tableIndex", Type: "INTEGER", EnumValues: map[int]string{0: "a"}},
									{Oid: "1.1.1.2", Access: "ACCESS_READONLY", Label: "tableFoo", Type: "INTEGER"},
								}}}}}},
			cfg: &ModuleConfig{
				Walk: []string{"1"},
				Overrides: map[string]MetricOverrides{
					"tableIndex": MetricOverrides{Type: "EnumAsInfo"},
				},
			},
			out: &config.Module{
				Walk: []string{"1"},
				Metrics: []*config.Metric{
					{
						Name: "tableIndex",
						Oid:  "1.1.1.1",
						Type: "EnumAsInfo",
						Help: " - 1.1.1.1",
						Indexes: []*config.Index{
							{
								Labelname:  "tableIndex",
								Type:       "EnumAsInfo",
								EnumValues: map[int]string{0: "a"},
							},
						},
						EnumValues: map[int]string{0: "a"},
					},
					{
						Name: "tableFoo",
						Oid:  "1.1.1.2",
						Type: "gauge",
						Help: " - 1.1.1.2",
						Indexes: []*config.Index{
							{
								Labelname:  "tableIndex",
								Type:       "EnumAsInfo",
								EnumValues: map[int]string{0: "a"},
							},
						},
					},
				},
			},
		},

		// One table lookup, lookup not walked, labels kept.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "octet",
						Children: []*Node{
							{Oid: "1.1.1", Label: "octetEntry", Indexes: []string{"octetIndex"},
								Children: []*Node{
									{Oid: "1.1.1.1", Access: "ACCESS_READONLY", Label: "octetIndex", Type: "INTEGER"},
									{Oid: "1.1.1.2", Access: "ACCESS_READONLY", Label: "octetDesc", Type: "OCTETSTR"},
									{Oid: "1.1.1.3", Access: "ACCESS_READONLY", Label: "octetFoo", Type: "INTEGER"}}}}}}},
			cfg: &ModuleConfig{
				Walk: []string{"octetFoo"},
				Lookups: []*Lookup{
					{
						SourceIndexes: []string{"octetIndex"},
						Lookup:        "octetDesc",
					},
				},
			},
			out: &config.Module{
				// Walk is expanded to include the lookup OID.
				Walk: []string{"1.1.1.2", "1.1.1.3"},
				Metrics: []*config.Metric{
					{
						Name: "octetFoo",
						Oid:  "1.1.1.3",
						Help: " - 1.1.1.3",
						Type: "gauge",
						Indexes: []*config.Index{
							{
								Labelname: "octetIndex",
								Type:      "gauge",
							},
						},
						Lookups: []*config.Lookup{
							{
								Labels:    []string{"octetIndex"},
								Labelname: "octetDesc",
								Type:      "OctetString",
								Oid:       "1.1.1.2",
							},
						},
					},
				},
			},
		},
		// One table lookup, lookup not walked.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "octet",
						Children: []*Node{
							{Oid: "1.1.1", Label: "octetEntry", Indexes: []string{"octetIndex"},
								Children: []*Node{
									{Oid: "1.1.1.1", Access: "ACCESS_READONLY", Label: "octetIndex", Type: "INTEGER"},
									{Oid: "1.1.1.2", Access: "ACCESS_READONLY", Label: "octetDesc", Type: "OCTETSTR"},
									{Oid: "1.1.1.3", Access: "ACCESS_READONLY", Label: "octetFoo", Type: "INTEGER"}}}}}}},
			cfg: &ModuleConfig{
				Walk: []string{"octetFoo"},
				Lookups: []*Lookup{
					{
						SourceIndexes:     []string{"octetIndex"},
						Lookup:            "octetDesc",
						DropSourceIndexes: true,
					},
				},
			},
			out: &config.Module{
				// Walk is expanded to include the lookup OID.
				Walk: []string{"1.1.1.2", "1.1.1.3"},
				Metrics: []*config.Metric{
					{
						Name: "octetFoo",
						Oid:  "1.1.1.3",
						Help: " - 1.1.1.3",
						Type: "gauge",
						Indexes: []*config.Index{
							{
								Labelname: "octetIndex",
								Type:      "gauge",
							},
						},
						Lookups: []*config.Lookup{
							{
								Labels:    []string{"octetIndex"},
								Labelname: "octetDesc",
								Type:      "OctetString",
								Oid:       "1.1.1.2",
							},
							{
								Labelname: "octetIndex",
							},
						},
					},
				},
			},
		},
		// Lookup via OID.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "octet",
						Children: []*Node{
							{Oid: "1.1.1", Label: "octetEntry", Indexes: []string{"octetIndex"},
								Children: []*Node{
									{Oid: "1.1.1.1", Access: "ACCESS_READONLY", Label: "octetIndex", Type: "INTEGER"},
									{Oid: "1.1.1.2", Access: "ACCESS_READONLY", Label: "octetDesc", Type: "OCTETSTR"},
									{Oid: "1.1.1.3", Access: "ACCESS_READONLY", Label: "octetFoo", Type: "INTEGER"}}}}}}},
			cfg: &ModuleConfig{
				Walk: []string{"octetFoo"},
				Lookups: []*Lookup{
					{
						SourceIndexes:     []string{"octetIndex"},
						Lookup:            "1.1.1.2",
						DropSourceIndexes: true,
					},
				},
			},
			out: &config.Module{
				// Walk is expanded to include the lookup OID.
				Walk: []string{"1.1.1.2", "1.1.1.3"},
				Metrics: []*config.Metric{
					{
						Name: "octetFoo",
						Oid:  "1.1.1.3",
						Help: " - 1.1.1.3",
						Type: "gauge",
						Indexes: []*config.Index{
							{
								Labelname: "octetIndex",
								Type:      "gauge",
							},
						},
						Lookups: []*config.Lookup{
							{
								Labels:    []string{"octetIndex"},
								Labelname: "octetDesc",
								Type:      "OctetString",
								Oid:       "1.1.1.2",
							},
							{
								Labelname: "octetIndex",
							},
						},
					},
				},
			},
		},
		// Multi-index table lookup, lookup not walked.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "octet",
						Children: []*Node{
							{Oid: "1.1.1", Label: "octetEntry", Indexes: []string{"octetIndex", "octetIndex2"},
								Children: []*Node{
									{Oid: "1.1.1.1", Access: "ACCESS_READONLY", Label: "octetIndex", Type: "INTEGER"},
									{Oid: "1.1.1.2", Access: "ACCESS_READONLY", Label: "octetIndex2", Type: "INTEGER"},
									{Oid: "1.1.1.3", Access: "ACCESS_READONLY", Label: "octetDesc", Type: "OCTETSTR"},
									{Oid: "1.1.1.4", Access: "ACCESS_READONLY", Label: "octetFoo", Type: "INTEGER"}}}}}}},
			cfg: &ModuleConfig{
				Walk: []string{"octetFoo"},
				Lookups: []*Lookup{
					{
						SourceIndexes:     []string{"octetIndex", "octetIndex2"},
						Lookup:            "octetDesc",
						DropSourceIndexes: true,
					},
				},
			},
			out: &config.Module{
				// Walk is expanded to include the lookup OID.
				Walk: []string{"1.1.1.3", "1.1.1.4"},
				Metrics: []*config.Metric{
					{
						Name: "octetFoo",
						Oid:  "1.1.1.4",
						Help: " - 1.1.1.4",
						Type: "gauge",
						Indexes: []*config.Index{
							{
								Labelname: "octetIndex",
								Type:      "gauge",
							},
							{
								Labelname: "octetIndex2",
								Type:      "gauge",
							},
						},
						Lookups: []*config.Lookup{
							{
								Labels:    []string{"octetIndex", "octetIndex2"},
								Labelname: "octetDesc",
								Type:      "OctetString",
								Oid:       "1.1.1.3",
							},
							{
								Labelname: "octetIndex",
							},
							{
								Labelname: "octetIndex2",
							},
						},
					},
				},
			},
		},
		// Validate metric names.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Access: "ACCESS_READONLY", Label: "digital-sen1-1", Hint: "1x:"},
				}},
			cfg: &ModuleConfig{
				Walk: []string{"root"},
			},
			out: &config.Module{
				Walk: []string{"1"},
				Metrics: []*config.Metric{
					{
						Name:    "digital_sen1_1",
						Oid:     "1.1",
						Type:    "PhysAddress48",
						Help:    " - 1.1",
						Indexes: []*config.Index{},
						Lookups: []*config.Lookup{},
					},
				},
			},
		},
		// Validate label names.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "octet",
						Children: []*Node{
							{Oid: "1.1.1", Label: "octet-Entry", Indexes: []string{"octet&Index"},
								Children: []*Node{
									{Oid: "1.1.1.1", Access: "ACCESS_READONLY", Label: "octet&Index", Type: "INTEGER"},
									{Oid: "1.1.1.2", Access: "ACCESS_READONLY", Label: "octet*Desc", Type: "OCTETSTR"},
									{Oid: "1.1.1.3", Access: "ACCESS_READONLY", Label: "octet^Foo", Type: "INTEGER"}}}}}}},
			cfg: &ModuleConfig{
				Walk: []string{"octet^Foo"},
				Lookups: []*Lookup{
					{
						SourceIndexes:     []string{"octet&Index"},
						Lookup:            "1.1.1.2",
						DropSourceIndexes: true,
					},
				},
			},
			out: &config.Module{
				// Walk is expanded to include the lookup OID.
				Walk: []string{"1.1.1.2", "1.1.1.3"},
				Metrics: []*config.Metric{
					{
						Name: "octet_Foo",
						Oid:  "1.1.1.3",
						Type: "gauge",
						Help: " - 1.1.1.3",
						Indexes: []*config.Index{
							{
								Labelname: "octet_Index",
								Type:      "gauge",
							},
						},
						Lookups: []*config.Lookup{
							{
								Labels:    []string{"octet_Index"},
								Labelname: "octet_Desc",
								Type:      "OctetString",
								Oid:       "1.1.1.2",
							},
							{
								Labelname: "octet_Index",
							},
						},
					},
				},
			},
		},
		// Validate table and instance conflict.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "table",
						Children: []*Node{
							{Oid: "1.1.1", Label: "tableEntry", Indexes: []string{"tableIndex"},
								Children: []*Node{
									{Oid: "1.1.1.1", Access: "ACCESS_READONLY", Label: "tableIndex", Type: "INTEGER"},
									{Oid: "1.1.1.2", Access: "ACCESS_READONLY", Label: "tableFoo", Type: "INTEGER"},
								}}}}}},
			cfg: &ModuleConfig{
				Walk: []string{"1.1.1.2.100", "1.1.1.2"},
			},
			out: &config.Module{
				Walk: []string{"1.1.1.2"},
				Metrics: []*config.Metric{
					{
						Name: "tableFoo",
						Oid:  "1.1.1.2",
						Type: "gauge",
						Help: " - 1.1.1.2",
						Indexes: []*config.Index{
							{
								Labelname: "tableIndex",
								Type:      "gauge",
							},
						},
					},
				},
			},
		},
		// Validate table instances.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "table",
						Children: []*Node{
							{Oid: "1.1.1", Label: "tableEntry", Indexes: []string{"tableIndex"},
								Children: []*Node{
									{Oid: "1.1.1.1", Access: "ACCESS_READONLY", Label: "tableIndex", Type: "INTEGER"},
									{Oid: "1.1.1.2", Access: "ACCESS_READONLY", Label: "tableFoo", Type: "INTEGER"},
								}}}}}},
			cfg: &ModuleConfig{
				Walk: []string{"1.1.1.2.100", "1.1.1.2.200"},
			},
			out: &config.Module{
				Get: []string{"1.1.1.2.100", "1.1.1.2.200"},
				// Single metric.
				Metrics: []*config.Metric{
					{
						Name: "tableFoo",
						Oid:  "1.1.1.2",
						Type: "gauge",
						Help: " - 1.1.1.2",
						Indexes: []*config.Index{
							{
								Labelname: "tableIndex",
								Type:      "gauge",
							},
						},
					},
				},
			},
		},
		// Validate multiple rows of table instances.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "table",
						Children: []*Node{
							{Oid: "1.1.1", Label: "tableEntry", Indexes: []string{"tableIndex"},
								Children: []*Node{
									{Oid: "1.1.1.1", Access: "ACCESS_READONLY", Label: "tableIndex", Type: "INTEGER"},
									{Oid: "1.1.1.2", Access: "ACCESS_READONLY", Label: "tableFoo", Type: "INTEGER"},
									{Oid: "1.1.1.3", Access: "ACCESS_READONLY", Label: "tableDesc", Type: "OCTETSTR"},
								}}}}}},
			cfg: &ModuleConfig{
				Walk: []string{"1.1.1.2.100", "1.1.1.3.200"},
			},
			out: &config.Module{
				Get: []string{"1.1.1.2.100", "1.1.1.3.200"},
				Metrics: []*config.Metric{
					{
						Name: "tableFoo",
						Oid:  "1.1.1.2",
						Type: "gauge",
						Help: " - 1.1.1.2",
						Indexes: []*config.Index{
							{
								Labelname: "tableIndex",
								Type:      "gauge",
							},
						},
					},
					{
						Name: "tableDesc",
						Oid:  "1.1.1.3",
						Type: "OctetString",
						Help: " - 1.1.1.3",
						Indexes: []*config.Index{
							{
								Labelname: "tableIndex",
								Type:      "gauge",
							},
						},
					},
				},
			},
		},
		// Validate table instances with lookup not walked.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "table",
						Children: []*Node{
							{Oid: "1.1.1", Label: "tableEntry", Indexes: []string{"tableIndex"},
								Children: []*Node{
									{Oid: "1.1.1.1", Access: "ACCESS_READONLY", Label: "tableIndex", Type: "INTEGER"},
									{Oid: "1.1.1.2", Access: "ACCESS_READONLY", Label: "tableFoo", Type: "INTEGER"},
									{Oid: "1.1.1.3", Access: "ACCESS_READONLY", Label: "tableDesc", Type: "OCTETSTR"},
									{Oid: "1.1.1.4", Access: "ACCESS_READONLY", Label: "tableBar", Type: "INTEGER"},
								}}}}}},
			cfg: &ModuleConfig{
				Walk: []string{"1.1.1.2.100", "1.1.1.4.100", "1.1.1.2.200"},
				Lookups: []*Lookup{
					{
						SourceIndexes:     []string{"tableIndex"},
						Lookup:            "tableDesc",
						DropSourceIndexes: true,
					},
				},
			},
			out: &config.Module{
				Get: []string{"1.1.1.2.100", "1.1.1.2.200", "1.1.1.3.100", "1.1.1.3.200", "1.1.1.4.100"},
				Metrics: []*config.Metric{
					{
						Name: "tableFoo",
						Oid:  "1.1.1.2",
						Type: "gauge",
						Help: " - 1.1.1.2",
						Indexes: []*config.Index{
							{
								Labelname: "tableIndex",
								Type:      "gauge",
							},
						},
						Lookups: []*config.Lookup{
							{
								Labels:    []string{"tableIndex"},
								Labelname: "tableDesc",
								Type:      "OctetString",
								Oid:       "1.1.1.3",
							},
							{
								Labelname: "tableIndex",
							},
						},
					},
					{
						Name: "tableBar",
						Oid:  "1.1.1.4",
						Type: "gauge",
						Help: " - 1.1.1.4",
						Indexes: []*config.Index{
							{
								Labelname: "tableIndex",
								Type:      "gauge",
							},
						},
						Lookups: []*config.Lookup{
							{
								Labels:    []string{"tableIndex"},
								Labelname: "tableDesc",
								Type:      "OctetString",
								Oid:       "1.1.1.3",
							},
							{
								Labelname: "tableIndex",
							},
						},
					},
				},
			},
		},
		// Validate specific table instances with lookup walked.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "table",
						Children: []*Node{
							{Oid: "1.1.1", Label: "tableEntry", Indexes: []string{"tableIndex"},
								Children: []*Node{
									{Oid: "1.1.1.1", Access: "ACCESS_READONLY", Label: "tableIndex", Type: "INTEGER"},
									{Oid: "1.1.1.2", Access: "ACCESS_READONLY", Label: "tableFoo", Type: "INTEGER"},
									{Oid: "1.1.1.3", Access: "ACCESS_READONLY", Label: "tableDesc", Type: "OCTETSTR"},
								}}}}}},
			cfg: &ModuleConfig{
				Walk: []string{"1.1.1.2.100", "1.1.1.3"},
				Lookups: []*Lookup{
					{
						SourceIndexes:     []string{"tableIndex"},
						Lookup:            "tableDesc",
						DropSourceIndexes: true,
					},
				},
			},
			out: &config.Module{
				Get:  []string{"1.1.1.2.100"},
				Walk: []string{"1.1.1.3"},
				Metrics: []*config.Metric{
					{
						Name: "tableFoo",
						Oid:  "1.1.1.2",
						Type: "gauge",
						Help: " - 1.1.1.2",
						Indexes: []*config.Index{
							{
								Labelname: "tableIndex",
								Type:      "gauge",
							},
						},
						Lookups: []*config.Lookup{
							{
								Labels:    []string{"tableIndex"},
								Labelname: "tableDesc",
								Type:      "OctetString",
								Oid:       "1.1.1.3",
							},
							{
								Labelname: "tableIndex",
							},
						},
					},
					{
						Name: "tableDesc",
						Oid:  "1.1.1.3",
						Type: "OctetString",
						Help: " - 1.1.1.3",
						Indexes: []*config.Index{
							{
								Labelname: "tableIndex",
								Type:      "gauge",
							},
						},
						Lookups: []*config.Lookup{
							{
								Labels:    []string{"tableIndex"},
								Labelname: "tableDesc",
								Type:      "OctetString",
								Oid:       "1.1.1.3",
							},
							{
								Labelname: "tableIndex",
							},
						},
					},
				},
			},
		},
		// Table with InetAddressType and valid InetAddress.
		// InetAddressType is added to walk.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "table",
						Children: []*Node{
							{Oid: "1.1.1", Label: "tableEntry", Indexes: []string{"tableIndex"},
								Children: []*Node{
									{Oid: "1.1.1.1", Access: "ACCESS_READONLY", Label: "tableIndex", Type: "INTEGER"},
									{Oid: "1.1.1.2", Access: "ACCESS_READONLY", Label: "tableAddrType", Type: "INTEGER", TextualConvention: "InetAddressType"},
									{Oid: "1.1.1.3", Access: "ACCESS_READONLY", Label: "tableAddr", Type: "OCTETSTR", TextualConvention: "InetAddress"},
								}}}}}},
			cfg: &ModuleConfig{
				Walk: []string{"1.1.1.3"},
			},
			out: &config.Module{
				Walk: []string{"1.1.1.2", "1.1.1.3"},
				Metrics: []*config.Metric{
					{
						Name: "tableAddr",
						Oid:  "1.1.1.3",
						Type: "InetAddress",
						Help: " - 1.1.1.3",
						Indexes: []*config.Index{
							{
								Labelname: "tableIndex",
								Type:      "gauge",
							},
						},
					},
				},
			},
		},
		// Table with InetAddressType and valid InetAddress instance.
		// InetAddressType is added to walk.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "table",
						Children: []*Node{
							{Oid: "1.1.1", Label: "tableEntry", Indexes: []string{"tableIndex"},
								Children: []*Node{
									{Oid: "1.1.1.1", Access: "ACCESS_READONLY", Label: "tableIndex", Type: "INTEGER"},
									{Oid: "1.1.1.2", Access: "ACCESS_READONLY", Label: "tableAddrType", Type: "INTEGER", TextualConvention: "InetAddressType"},
									{Oid: "1.1.1.3", Access: "ACCESS_READONLY", Label: "tableAddr", Type: "OCTETSTR", TextualConvention: "InetAddress"},
								}}}}}},
			cfg: &ModuleConfig{
				Walk: []string{"1.1.1.3.42"},
			},
			out: &config.Module{
				Get: []string{"1.1.1.2.42", "1.1.1.3.42"},
				Metrics: []*config.Metric{
					{
						Name: "tableAddr",
						Oid:  "1.1.1.3",
						Type: "InetAddress",
						Help: " - 1.1.1.3",
						Indexes: []*config.Index{
							{
								Labelname: "tableIndex",
								Type:      "gauge",
							},
						},
					},
				},
			},
		},
		// Table with InetAddressType and InetAddress in the wrong order.
		// InetAddress becomes OctetString.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "table",
						Children: []*Node{
							{Oid: "1.1.1", Label: "tableEntry", Indexes: []string{"tableIndex"},
								Children: []*Node{
									{Oid: "1.1.1.1", Access: "ACCESS_READONLY", Label: "tableIndex", Type: "INTEGER"},
									{Oid: "1.1.1.2", Access: "ACCESS_READONLY", Label: "tableAddr", Type: "OCTETSTR", TextualConvention: "InetAddress"},
									{Oid: "1.1.1.3", Access: "ACCESS_READONLY", Label: "tableAddrType", Type: "INTEGER", TextualConvention: "InetAddressType"},
								}}}}}},
			cfg: &ModuleConfig{
				Walk: []string{"1.1.1.2"},
			},
			out: &config.Module{
				Walk: []string{"1.1.1.2"},
				Metrics: []*config.Metric{
					{
						Name: "tableAddr",
						Oid:  "1.1.1.2",
						Type: "OctetString",
						Help: " - 1.1.1.2",
						Indexes: []*config.Index{
							{
								Labelname: "tableIndex",
								Type:      "gauge",
							},
						},
					},
				},
			},
		},
		// Table with InetAddressType and InetAddress index.
		// Index becomes just InetAddress.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "table",
						Children: []*Node{
							{Oid: "1.1.1", Label: "tableEntry", Indexes: []string{"tableAddrType", "tableAddr"},
								Children: []*Node{
									{Oid: "1.1.1.1", Access: "ACCESS_READONLY", Label: "tableAddrType", Type: "INTEGER", TextualConvention: "InetAddressType"},
									{Oid: "1.1.1.2", Access: "ACCESS_READONLY", Label: "tableAddr", Type: "OCTETSTR", TextualConvention: "InetAddress"},
								}}}}}},
			cfg: &ModuleConfig{
				Walk: []string{"1"},
			},
			out: &config.Module{
				Walk: []string{"1"},
				Metrics: []*config.Metric{
					{
						Name: "tableAddrType",
						Oid:  "1.1.1.1",
						Type: "gauge",
						Help: " - 1.1.1.1",
						Indexes: []*config.Index{
							{
								Labelname: "tableAddr",
								Type:      "InetAddress",
							},
						},
					},
					{
						Name: "tableAddr",
						Oid:  "1.1.1.2",
						Type: "InetAddress",
						Help: " - 1.1.1.2",
						Indexes: []*config.Index{
							{
								Labelname: "tableAddr",
								Type:      "InetAddress",
							},
						},
					},
				},
			},
		},
		// Table with InetAddressType and InetAddress index in wrong order gets dropped.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "table",
						Children: []*Node{
							{Oid: "1.1.1", Label: "tableEntry", Indexes: []string{"tableAddr", "tableAddrType"},
								Children: []*Node{
									{Oid: "1.1.1.1", Access: "ACCESS_READONLY", Label: "tableAddrType", Type: "INTEGER", TextualConvention: "InetAddressType"},
									{Oid: "1.1.1.2", Access: "ACCESS_READONLY", Label: "tableAddr", Type: "OCTETSTR", TextualConvention: "InetAddress"},
								}}}}}},
			cfg: &ModuleConfig{
				Walk: []string{"1"},
			},
			out: &config.Module{
				Walk: []string{"1"},
			},
		},
		// Table with InetAddressType and valid InetAddressMissingSize.
		// InetAddressType is added to walk.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "table",
						Children: []*Node{
							{Oid: "1.1.1", Label: "tableEntry", Indexes: []string{"tableIndex"},
								Children: []*Node{
									{Oid: "1.1.1.1", Access: "ACCESS_READONLY", Label: "tableIndex", Type: "INTEGER"},
									{Oid: "1.1.1.2", Access: "ACCESS_READONLY", Label: "tableAddrType", Type: "INTEGER", TextualConvention: "InetAddressType"},
									{Oid: "1.1.1.3", Access: "ACCESS_READONLY", Label: "tableAddr", Type: "OCTETSTR", TextualConvention: "InetAddress"},
								}}}}}},
			cfg: &ModuleConfig{
				Walk: []string{"1.1.1.3"},
				Overrides: map[string]MetricOverrides{
					"tableAddr": MetricOverrides{Type: "InetAddressMissingSize"},
				},
			},
			out: &config.Module{
				Walk: []string{"1.1.1.2", "1.1.1.3"},
				Metrics: []*config.Metric{
					{
						Name: "tableAddr",
						Oid:  "1.1.1.3",
						Type: "InetAddressMissingSize",
						Help: " - 1.1.1.3",
						Indexes: []*config.Index{
							{
								Labelname: "tableIndex",
								Type:      "gauge",
							},
						},
					},
				},
			},
		},
		// Table with InetAddressType and InetAddressMissingSize in the wrong order.
		// InetAddressMissingSize becomes OctetString.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "table",
						Children: []*Node{
							{Oid: "1.1.1", Label: "tableEntry", Indexes: []string{"tableIndex"},
								Children: []*Node{
									{Oid: "1.1.1.1", Access: "ACCESS_READONLY", Label: "tableIndex", Type: "INTEGER"},
									{Oid: "1.1.1.2", Access: "ACCESS_READONLY", Label: "tableAddr", Type: "OCTETSTR", TextualConvention: "InetAddress"},
									{Oid: "1.1.1.3", Access: "ACCESS_READONLY", Label: "tableAddrType", Type: "INTEGER", TextualConvention: "InetAddressType"},
								}}}}}},
			cfg: &ModuleConfig{
				Walk: []string{"1.1.1.2"},
				Overrides: map[string]MetricOverrides{
					"tableAddr": MetricOverrides{Type: "InetAddressMissingSize"},
				},
			},
			out: &config.Module{
				Walk: []string{"1.1.1.2"},
				Metrics: []*config.Metric{
					{
						Name: "tableAddr",
						Oid:  "1.1.1.2",
						Type: "OctetString",
						Help: " - 1.1.1.2",
						Indexes: []*config.Index{
							{
								Labelname: "tableIndex",
								Type:      "gauge",
							},
						},
					},
				},
			},
		},
		// Table with InetAddressType and InetAddressMissingSize index.
		// Index becomes just InetAddressMissingSize.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "table",
						Children: []*Node{
							{Oid: "1.1.1", Label: "tableEntry", Indexes: []string{"tableAddrType", "tableAddr"},
								Children: []*Node{
									{Oid: "1.1.1.1", Access: "ACCESS_READONLY", Label: "tableAddrType", Type: "INTEGER", TextualConvention: "InetAddressType"},
									{Oid: "1.1.1.2", Access: "ACCESS_READONLY", Label: "tableAddr", Type: "OCTETSTR", TextualConvention: "InetAddress"},
								}}}}}},
			cfg: &ModuleConfig{
				Walk: []string{"1"},
				Overrides: map[string]MetricOverrides{
					"tableAddr": MetricOverrides{Type: "InetAddressMissingSize"},
				},
			},
			out: &config.Module{
				Walk: []string{"1"},
				Metrics: []*config.Metric{
					{
						Name: "tableAddrType",
						Oid:  "1.1.1.1",
						Type: "gauge",
						Help: " - 1.1.1.1",
						Indexes: []*config.Index{
							{
								Labelname: "tableAddr",
								Type:      "InetAddressMissingSize",
							},
						},
					},
					{
						Name: "tableAddr",
						Oid:  "1.1.1.2",
						Type: "InetAddressMissingSize",
						Help: " - 1.1.1.2",
						Indexes: []*config.Index{
							{
								Labelname: "tableAddr",
								Type:      "InetAddressMissingSize",
							},
						},
					},
				},
			},
		},
		// Table with InetAddressType and InetAddressMissingSize index in wrong order gets dropped.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "table",
						Children: []*Node{
							{Oid: "1.1.1", Label: "tableEntry", Indexes: []string{"tableAddr", "tableAddrType"},
								Children: []*Node{
									{Oid: "1.1.1.1", Access: "ACCESS_READONLY", Label: "tableAddrType", Type: "INTEGER", TextualConvention: "InetAddressType"},
									{Oid: "1.1.1.2", Access: "ACCESS_READONLY", Label: "tableAddr", Type: "OCTETSTR", TextualConvention: "InetAddress"},
								}}}}}},
			cfg: &ModuleConfig{
				Walk: []string{"1"},
				Overrides: map[string]MetricOverrides{
					"tableAddr": MetricOverrides{Type: "InetAddressMissingSize"},
				},
			},
			out: &config.Module{
				Walk: []string{"1"},
			},
		},
		// Table with LldpPortIdSubtype and LldpPortId index.
		// Index becomes just LldpPortId.
		{
			node: &Node{Oid: "1", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "table",
						Children: []*Node{
							{Oid: "1.1.1", Label: "tableEntry", Indexes: []string{"tableAddrType", "tableAddr"},
								Children: []*Node{
									{Oid: "1.1.1.1", Access: "ACCESS_READONLY", Label: "tableAddrType", Type: "INTEGER", TextualConvention: "LldpPortIdSubtype"},
									{Oid: "1.1.1.2", Access: "ACCESS_READONLY", Label: "tableAddr", Type: "OCTETSTR", TextualConvention: "LldpPortId"},
								}}}}}},
			cfg: &ModuleConfig{
				Walk: []string{"1"},
			},
			out: &config.Module{
				Walk: []string{"1"},
				Metrics: []*config.Metric{
					{
						Name: "tableAddrType",
						Oid:  "1.1.1.1",
						Type: "gauge",
						Help: " - 1.1.1.1",
						Indexes: []*config.Index{
							{
								Labelname: "tableAddr",
								Type:      "LldpPortId",
							},
						},
					},
					{
						Name: "tableAddr",
						Oid:  "1.1.1.2",
						Type: "LldpPortId",
						Help: " - 1.1.1.2",
						Indexes: []*config.Index{
							{
								Labelname: "tableAddr",
								Type:      "LldpPortId",
							},
						},
					},
				},
			},
		},
	}
	for i, c := range cases {
		// Indexes and lookups always end up initialized.
		for _, m := range c.out.Metrics {
			if m.Indexes == nil {
				m.Indexes = []*config.Index{}
			}
			if m.Lookups == nil {
				m.Lookups = []*config.Lookup{}
			}
		}

		nameToNode := prepareTree(c.node, log.NewNopLogger())
		got, err := generateConfigModule(c.cfg, c.node, nameToNode, log.NewNopLogger())
		if err != nil {
			t.Errorf("Error generating config in case %d: %s", i, err)
		}
		if !reflect.DeepEqual(got, c.out) {
			t.Errorf("GenerateConfigModule: difference in case %d", i)
			out, _ := yaml.Marshal(got)
			t.Errorf("Got: %s", out)
			out, _ = yaml.Marshal(c.out)
			t.Errorf("Wanted: %s", out)
		}
	}
}
