package main

import (
	"reflect"
	"testing"

	"gopkg.in/yaml.v2"

	"github.com/prometheus/snmp_exporter/config"
)

func TestTreePrepate(t *testing.T) {
	cases := []struct {
		in  *Node
		out *Node
	}{
		// Descriptions trimmed.
		{
			in:  &Node{Oid: "1", Description: "A long   sentance.      Even more detail!"},
			out: &Node{Oid: "1", Description: "A long sentance"},
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
	}
	for i, c := range cases {
		// Indexes always end up initilized.
		walkNode(c.out, func(n *Node) {
			if n.Indexes == nil {
				n.Indexes = []string{}
			}
		})

		_ = prepareTree(c.in)

		if !reflect.DeepEqual(c.in, c.out) {
			t.Errorf("prepareTree: difference in case %d", i)
			walkNode(c.in, func(n *Node) {
				t.Errorf("Got: %+v", n)
			})
			walkNode(c.out, func(n *Node) {
				t.Errorf("Wanted: %+v", n)
			})

		}
	}
}

func TestGenerateConfigModule(t *testing.T) {
	cases := []struct {
		node *Node
		cfg  *ModuleConfig  // SNMP generator config.
		out  *config.Module // SNMP exporter config.
	}{
		// Simple metric.
		{
			node: &Node{Oid: "1", Type: "INTEGER", Label: "root"},
			cfg: &ModuleConfig{
				Walk: []string{"root"},
			},
			out: &config.Module{
				Walk: []string{"1"},
				Metrics: []*config.Metric{
					{
						Name: "root",
						Oid:  "1",
					},
				},
			},
		},
		// Can also provide OIDs to walk.
		{
			node: &Node{Oid: "1", Type: "INTEGER", Label: "root"},
			cfg: &ModuleConfig{
				Walk: []string{"1"},
			},
			out: &config.Module{
				Walk: []string{"1"},
				Metrics: []*config.Metric{
					{
						Name: "root",
						Oid:  "1",
					},
				},
			},
		},
		// Duplicate walks handled gracefully.
		{
			node: &Node{Oid: "1", Type: "INTEGER", Label: "root"},
			cfg: &ModuleConfig{
				Walk: []string{"1", "root"},
			},
			out: &config.Module{
				Walk: []string{"1"},
				Metrics: []*config.Metric{
					{
						Name: "root",
						Oid:  "1",
					},
				},
			},
		},
		// Metric types.
		{
			node: &Node{Oid: "1", Type: "OTHER", Label: "root",
				Children: []*Node{
					{Oid: "1.1", Label: "OBJID", Type: "OBJID"},
					{Oid: "1.2", Label: "OCTETSTR", Type: "OCTETSTR"},
					{Oid: "1.3", Label: "INTEGER", Type: "INTEGER"},
					{Oid: "1.4", Label: "NETADDR", Type: "NETADDR"},
					{Oid: "1.5", Label: "IPADDR", Type: "IPADDR"},
					{Oid: "1.6", Label: "COUNTER", Type: "COUNTER"},
					{Oid: "1.7", Label: "GAUGE", Type: "GAUGE"},
					{Oid: "1.8", Label: "TIMETICKS", Type: "TIMETICKS"},
					{Oid: "1.9", Label: "OPAQUE", Type: "OPAQUE"},
					{Oid: "1.10", Label: "NULL", Type: "NULL"},
					{Oid: "1.11", Label: "COUNTER64", Type: "COUNTER64"},
					{Oid: "1.12", Label: "BITSTRING", Type: "BITSTRING"},
					{Oid: "1.13", Label: "NSAPADDRESS", Type: "NSAPADDRESS"},
					{Oid: "1.14", Label: "UINTEGER", Type: "UINTEGER"},
					{Oid: "1.15", Label: "UNSIGNED32", Type: "UNSIGNED32"},
					{Oid: "1.16", Label: "INTEGER32", Type: "INTEGER32"},
					{Oid: "1.20", Label: "TRAPTYPE", Type: "TRAPTYPE"},
					{Oid: "1.21", Label: "NOTIFTYPE", Type: "NOTIFTYPE"},
					{Oid: "1.22", Label: "OBJGROUP", Type: "OBJGROUP"},
					{Oid: "1.23", Label: "NOTIFGROUP", Type: "NOTIFGROUP"},
					{Oid: "1.24", Label: "MODID", Type: "MODID"},
					{Oid: "1.25", Label: "AGENTCAP", Type: "AGENTCAP"},
					{Oid: "1.26", Label: "MODCOMP", Type: "MODCOMP"},
					{Oid: "1.27", Label: "OBJIDENTITY", Type: "OBJIDENTITY"},
					{Oid: "1.100", Label: "MacAddress", Type: "OCTETSTR", Hint: "1x:"},
				}},
			cfg: &ModuleConfig{
				Walk: []string{"root", "1.3"},
			},
			out: &config.Module{
				Walk: []string{"1"},
				Metrics: []*config.Metric{
					{
						Name: "INTEGER",
						Oid:  "1.3",
					},
					{
						Name: "COUNTER",
						Oid:  "1.6",
					},
					{
						Name: "GAUGE",
						Oid:  "1.7",
					},
					{
						Name: "TIMETICKS",
						Oid:  "1.8",
					},
					{
						Name: "COUNTER64",
						Oid:  "1.11",
					},
					{
						Name: "UINTEGER",
						Oid:  "1.14",
					},
					{
						Name: "UNSIGNED32",
						Oid:  "1.15",
					},
					{
						Name: "INTEGER32",
						Oid:  "1.16",
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
									{Oid: "1.1.1.1", Label: "tableIndex", Type: "INTEGER"},
									{Oid: "1.1.1.2", Label: "tableFoo", Type: "INTEGER"},
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
						Indexes: []*config.Index{
							{
								Labelname: "tableIndex",
								Type:      "Integer",
							},
						},
					},
					{
						Name: "tableFoo",
						Oid:  "1.1.1.2",
						Indexes: []*config.Index{
							{
								Labelname: "tableIndex",
								Type:      "Integer",
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
									{Oid: "1.1.1.1", Label: "octetIndex", Type: "OCTETSTR"},
									{Oid: "1.1.1.2", Label: "octetFoo", Type: "INTEGER"}}}}},
					{Oid: "1.2", Label: "bitstring",
						Children: []*Node{
							{Oid: "1.2.1", Label: "bitstringEntry", Indexes: []string{"bitstringIndex"},
								Children: []*Node{
									{Oid: "1.2.1.1", Label: "bitstringIndex", Type: "BITSTRING"},
									{Oid: "1.2.1.2", Label: "bitstringFoo", Type: "INTEGER"}}}}},
					{Oid: "1.3", Label: "ipaddr",
						Children: []*Node{
							{Oid: "1.3.1", Label: "ipaddrEntry", Indexes: []string{"ipaddrIndex"},
								Children: []*Node{
									{Oid: "1.3.1.1", Label: "ipaddrIndex", Type: "IPADDR"},
									{Oid: "1.3.1.2", Label: "ipaddrFoo", Type: "INTEGER"}}}}},
					{Oid: "1.4", Label: "netaddr",
						Children: []*Node{
							{Oid: "1.4.1", Label: "netaddrEntry", Indexes: []string{"netaddrIndex"},
								Children: []*Node{
									{Oid: "1.4.1.1", Label: "netaddrIndex", Type: "NETADDR"},
									{Oid: "1.4.1.2", Label: "netaddrFoo", Type: "INTEGER"}}}}},
					{Oid: "1.5", Label: "physaddress48",
						Children: []*Node{
							{Oid: "1.5.1", Label: "physaddress48Entry", Indexes: []string{"physaddress48Index"},
								Children: []*Node{
									{Oid: "1.5.1.1", Label: "physaddress48Index", Type: "OCTETSTRING", Hint: "1x:"},
									{Oid: "1.5.1.2", Label: "physaddress48Foo", Type: "INTEGER"}}}}},
				}},
			cfg: &ModuleConfig{
				Walk: []string{"1"},
			},
			out: &config.Module{
				Walk: []string{"1"},
				Metrics: []*config.Metric{
					{
						Name: "octetFoo",
						Oid:  "1.1.1.2",
						Indexes: []*config.Index{
							{
								Labelname: "octetIndex",
								Type:      "OctetString",
							},
						},
					},
					{
						Name: "bitstringFoo",
						Oid:  "1.2.1.2",
						Indexes: []*config.Index{
							{
								Labelname: "bitstringIndex",
								Type:      "OctetString",
							},
						},
					},
					{
						Name: "ipaddrFoo",
						Oid:  "1.3.1.2",
						Indexes: []*config.Index{
							{
								Labelname: "ipaddrIndex",
								Type:      "IpAddr",
							},
						},
					},
					{
						Name: "netaddrFoo",
						Oid:  "1.4.1.2",
						Indexes: []*config.Index{
							{
								Labelname: "netaddrIndex",
								Type:      "InetAddress",
							},
						},
					},
					{
						Name: "physaddress48Foo",
						Oid:  "1.5.1.2",
						Indexes: []*config.Index{
							{
								Labelname: "physaddress48Index",
								Type:      "PhysAddress48",
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
									{Oid: "1.1.1.1", Label: "octetIndex", Type: "INTEGER"},
									{Oid: "1.1.1.2", Label: "octetDesc", Type: "OCTETSTRING"},
									{Oid: "1.1.1.3", Label: "octetFoo", Type: "INTEGER"}}}}}}},
			cfg: &ModuleConfig{
				Walk: []string{"octetFoo"},
				Lookups: []*Lookup{
					{
						OldIndex: "octetIndex",
						NewIndex: "octetDesc",
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
						Indexes: []*config.Index{
							{
								Labelname: "octetDesc",
								Type:      "Integer",
							},
						},
						Lookups: []*config.Lookup{
							{
								Labels:    []string{"octetDesc"},
								Labelname: "octetDesc",
								Oid:       "1.1.1.2",
							},
						},
					},
				},
			},
		},
	}
	for i, c := range cases {
		// Indexes and lookups always end up initilized.
		for _, m := range c.out.Metrics {
			if m.Indexes == nil {
				m.Indexes = []*config.Index{}
			}
			if m.Lookups == nil {
				m.Lookups = []*config.Lookup{}
			}
		}

		nameToNode := prepareTree(c.node)
		got := generateConfigModule(c.cfg, c.node, nameToNode)

		if !reflect.DeepEqual(got, c.out) {
			t.Errorf("GenerateConfigModule: difference in case %d", i)
			out, _ := yaml.Marshal(got)
			t.Errorf("Got: %s", out)
			out, _ = yaml.Marshal(c.out)
			t.Errorf("Wanted: %s", out)
		}
	}
}
