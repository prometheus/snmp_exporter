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

	// Set type on MAC addresses and ASCII strings.
	walkNode(nodes, func(n *Node) {
		// For some odd reason ifPhysAddress's MIB isn't being parsed correctly
		// so set this by hand.
		switch n.Label {
		case "ifPhysAddress":
			n.Hint = "1x:"
		case "ifDescr", "ifName", "ifAlias":
			n.Hint = "255a"
		}
		// RFC 2579
		switch n.Hint {
		case "1x:":
			n.Type = "PhysAddress48"
		case "255a":
			n.Type = "DisplayString"
		}
	})

	return nameToNode
}

func metricType(t string) (string, bool) {
	switch t {
	case "INTEGER", "GAUGE", "TIMETICKS", "UINTEGER", "UNSIGNED32", "INTEGER32":
		return "gauge", true
	case "COUNTER", "COUNTER64":
		return "counter", true
	case "OCTETSTR", "BITSTRING":
		return "OctetString", true
	case "IPADDR":
		return "IpAddr", true
	case "NETADDR":
		// TODO: Not sure about this one.
		return "InetAddress", true
	case "PhysAddress48", "DisplayString":
		return t, true
	default:
		// Unsupported type.
		return "", false
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
			t, ok := metricType(n.Type)
			if !ok {
				return // Unsupported type.
			}
			metric := &config.Metric{
				Name:    n.Label,
				Oid:     n.Oid,
				Type:    t,
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
				index.Type, ok = metricType(indexNode.Type)
				if !ok {
					log.Warnf("Error, can't handle index type %s for node %s", indexNode.Type, n.Label)
					return
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
					indexNode := nameToNode[lookup.NewIndex]
					// Avoid leaving the old labelname around.
					index.Labelname = lookup.NewIndex
					typ, ok := metricType(indexNode.Type)
					if !ok {
						log.Fatalf("Unknown index type %s for %s", indexNode.Type, lookup.NewIndex)
					}
					metric.Lookups = append(metric.Lookups, &config.Lookup{
						Labels:    []string{lookup.NewIndex},
						Labelname: lookup.NewIndex,
						Type:      typ,
						Oid:       indexNode.Oid,
					})
					// Make sure we walk the lookup OID
					needToWalk[indexNode.Oid] = struct{}{}
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
