package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/prometheus/snmp_exporter/config"
	"gopkg.in/yaml.v2"
)

// Helper to walk MIB nodes.
func walkNode(n *Node, f func(n *Node)) {
	f(n)
	for _, c := range n.Children {
		walkNode(c, f)
	}
}

// Transform the tree
func prepareTree(nodes *Node) map[string]*Node {
	// Build a map from names and oids to nodes.
	nameToNode := map[string]*Node{}
	walkNode(nodes, func(n *Node) {
		nameToNode[n.Oid] = n
		nameToNode[n.Label] = n
	})

	// Trim down description to first sentance, removing extra whitespace.
	walkNode(nodes, func(n *Node) {
		s := strings.Join(strings.Fields(n.Description), " ")
		n.Description = strings.Split(s, ". ")[0]
	})

	// Fix indexes to "INTEGER" rather than an object name.
	// Example: snSlotsEntry in LANOPTICS-HUB-MIB
	walkNode(nodes, func(n *Node) {
		indexes := []string{}
		for _, i := range n.Indexes {
			if i == "INTEGER" {
				// Use the TableEntry name.
				indexes = append(indexes, n.Label)
			} else {
				indexes = append(indexes, i)
			}
		}
		n.Indexes = indexes
	})

	// Copy over indexes based on augments.
	walkNode(nodes, func(n *Node) {
		if n.Augments == "" {
			return
		}
		augmented, ok := nameToNode[n.Augments]
		if !ok {
			println("Error, can't find augmenting oid " + n.Augments + " for " + n.Label)
			return
		}
		for _, c := range n.Children {
			c.Indexes = augmented.Indexes
		}
		n.Indexes = augmented.Indexes
	})

	// Copy indexes from table entries down to the entries.
	walkNode(nodes, func(n *Node) {
		if len(n.Indexes) != 0 {
			for _, c := range n.Children {
				c.Indexes = n.Indexes
			}
		}
	})

	// Set type on MAC addresses.
	walkNode(nodes, func(n *Node) {
		// RFC 2579
		if n.Hint == "1x:" {
			n.Type = "PhysAddress48"
		}
	})

	return nameToNode
}

type Lookup struct {
	OldIndex string
	NewIndex string
}

var cfg = struct {
	Walk    []string
	Lookups []Lookup
}{
	Walk: []string{"sysUpTime", "interfaces", "ifXTable"},
	Lookups: []Lookup{
		Lookup{
			OldIndex: "ifIndex",
			NewIndex: "ifDescr",
		},
	},
}

func isNumericType(t string) bool {
	switch t {
	case "INTEGER", "COUNTER", "GAUGE", "TIMETICKS", "COUNTER64", "UINTEGER", "UNSIGNED32", "INTEGER32":
		return true
	default:
		return false
	}
}

func main() {
	initSNMP()
	nodes := getMIBTree()
	nameToNode := prepareTree(nodes)

	_ = nameToNode

	out := &config.Module{}
	needToWalk := map[string]struct{}{}

	// Find all the usable metrics.
	for _, oid := range cfg.Walk {
		node := nameToNode[oid]
		needToWalk[node.Oid] = struct{}{}
		walkNode(node, func(n *Node) {
			if !isNumericType(n.Type) {
				return
			}
			metric := &config.Metric{
				Name:    n.Label,
				Oid:     n.Oid,
				Indexes: []*config.Index{},
				Lookups: []*config.Lookup{},
			}
			for _, i := range n.Indexes {
				index := &config.Index{Labelname: i}
				indexNode, ok := nameToNode[i]
				if !ok {
					println("Error, can't find index " + i + " for node " + n.Label)
					return
				}
				indexType := indexNode.Type
				switch {
				case isNumericType(indexType):
					index.Type = "Integer"
				case indexType == "OCTETSTR" || indexType == "BITSTRING":
					index.Type = "OctetString"
				case indexType == "IPADDR":
					index.Type = "IpAddr"
				case indexType == "NETADDR":
					// TODO: Not sure about this one.
					index.Type = "InetAddress"
				case indexType == "PhysAddress48":
					index.Type = "PhysAddress48"
				}
				metric.Indexes = append(metric.Indexes, index)
			}
			out.Metrics = append(out.Metrics, metric)
		})
	}

	// Apply lookups.
	for _, lookup := range cfg.Lookups {
		for _, metric := range out.Metrics {
			for _, index := range metric.Indexes {
				if index.Labelname == lookup.OldIndex {
					oid := nameToNode[lookup.NewIndex].Oid
					// Avoid leaving the old labelname around.
					index.Labelname = lookup.NewIndex
					metric.Lookups = append(metric.Lookups, &config.Lookup{
						Labels:    []string{lookup.NewIndex},
						Labelname: lookup.NewIndex,
						Oid:       oid,
					})
					// Make sure we walk the lookup OID
					needToWalk[oid] = struct{}{}
				}
			}
		}
	}

	// Remove redundant OIDs to be walked.
	oids := []string{}
	for k, _ := range needToWalk {
		oids = append(oids, k)
	}
	sort.Strings(oids)
	prevOid := ""
	neededOids := []string{}
	for _, oid := range oids {
		if !strings.HasPrefix(oid+".", prevOid) || prevOid == "" {
			neededOids = append(neededOids, oid)
			prevOid = oid + "."
		}
	}
	out.Walk = neededOids

	m, _ := yaml.Marshal(out)
	fmt.Println(string(m))

	//walkNode(nodes, func(n *Node) {
	//	fmt.Printf("%s %s %s %s %s %+v\n", n.Oid, n.Label, n.Type, n.Indexes, n.Description)
	//})
}
