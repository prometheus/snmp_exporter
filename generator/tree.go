package main

import (
	"sort"
	"strings"

	"github.com/prometheus/common/log"

	"github.com/prometheus/snmp_exporter/config"
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
			log.Warnf("Can't find augmenting oid %s for %s", n.Augments, n.Label)
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

func isNumericType(t string) bool {
	switch t {
	case "INTEGER", "COUNTER", "GAUGE", "TIMETICKS", "COUNTER64", "UINTEGER", "UNSIGNED32", "INTEGER32":
		return true
	default:
		return false
	}
}

// Reduce a set of overlapping OID subtrees.
func minimizeOids(oids []string) []string {
	sort.Strings(oids)
	prevOid := ""
	minimized := []string{}
	for _, oid := range oids {
		if !strings.HasPrefix(oid+".", prevOid) || prevOid == "" {
			minimized = append(minimized, oid)
			prevOid = oid + "."
		}
	}
	return minimized
}

func generateConfigModule(cfg *ModuleConfig, node *Node, nameToNode map[string]*Node) *config.Module {
	out := &config.Module{}
	needToWalk := map[string]struct{}{}

	// Remove redundant OIDs to be walked.
	toWalk := []string{}
	for _, oid := range cfg.Walk {
		node, ok := nameToNode[oid]
		if !ok {
			log.Fatalf("Cannot find oid '%s' to walk", oid)
		}
		toWalk = append(toWalk, node.Oid)
	}
	toWalk = minimizeOids(toWalk)

	// Find all the usable metrics.
	for _, oid := range toWalk {
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
					log.Warnf("Error, can't find index %s for node %s", i, n.Label)
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
					if _, ok := nameToNode[lookup.NewIndex]; !ok {
						log.Fatalf("Unknown index '%s'", lookup.NewIndex)
					}
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

	oids := []string{}
	for k, _ := range needToWalk {
		oids = append(oids, k)
	}
	// Remove redundant OIDs to be walked.
	out.Walk = minimizeOids(oids)
	return out
}
