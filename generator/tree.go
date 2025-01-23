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
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/prometheus/snmp_exporter/config"
)

// These types have one following the other.
// We need to check indexes and sequences have them
// in the right order, so the exporter can handle them.
var combinedTypes = map[string]string{
	"InetAddress":            "InetAddressType",
	"InetAddressMissingSize": "InetAddressType",
	"LldpPortId":             "LldpPortIdSubtype",
}

// Helper to walk MIB nodes.
func walkNode(n *Node, f func(n *Node)) {
	f(n)
	for _, c := range n.Children {
		walkNode(c, f)
	}
}

// Transform the tree.
func prepareTree(nodes *Node, logger *slog.Logger) map[string]*Node {
	// Build a map from names and oids to nodes.
	nameToNode := map[string]*Node{}
	walkNode(nodes, func(n *Node) {
		nameToNode[n.Oid] = n
		nameToNode[n.Label] = n
	})

	// Trim down description to first sentence, removing extra whitespace.
	walkNode(nodes, func(n *Node) {
		s := strings.Join(strings.Fields(n.Description), " ")
		n.Description = strings.Split(s, ". ")[0]
	})

	// Fix indexes to "INTEGER" rather than an object name.
	// Example: snSlotsEntry in LANOPTICS-HUB-MIB.
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
			logger.Warn("Can't find augmenting node", "augments", n.Augments, "node", n.Label)
			return
		}
		for _, c := range n.Children {
			c.Indexes = augmented.Indexes
			c.ImpliedIndex = augmented.ImpliedIndex
		}
		n.Indexes = augmented.Indexes
		n.ImpliedIndex = augmented.ImpliedIndex
	})

	// Copy indexes from table entries down to the entries.
	walkNode(nodes, func(n *Node) {
		if len(n.Indexes) != 0 {
			for _, c := range n.Children {
				c.Indexes = n.Indexes
				c.ImpliedIndex = n.ImpliedIndex
			}
		}
	})

	// Include both ASCII and UTF-8 in DisplayString, even though DisplayString
	// is technically only ASCII.
	displayStringRe := regexp.MustCompile(`^\d+[at]$`)

	// Apply various tweaks to the types.
	walkNode(nodes, func(n *Node) {
		// Set type on MAC addresses and strings.
		// RFC 2579
		switch n.Hint {
		case "1x:":
			n.Type = "PhysAddress48"
		}
		if displayStringRe.MatchString(n.Hint) {
			n.Type = "DisplayString"
		}

		// Some MIBs refer to RFC1213 for this, which is too
		// old to have the right hint set.
		if n.TextualConvention == "DisplayString" {
			n.Type = "DisplayString"
		}
		if n.TextualConvention == "PhysAddress" {
			n.Type = "PhysAddress48"
		}

		// Promote Opaque Float/Double textual convention to type.
		if n.TextualConvention == "Float" || n.TextualConvention == "Double" {
			n.Type = n.TextualConvention
		}

		// Convert RFC 2579 DateAndTime textual convention to type.
		if n.TextualConvention == "DateAndTime" {
			n.Type = "DateAndTime"
		}
		if n.TextualConvention == "ParseDateAndTime" {
			n.Type = "ParseDateAndTime"
		}
		if n.TextualConvention == "NTPTimeStamp" {
			n.Type = "NTPTimeStamp"
		}
		// Convert RFC 4001 InetAddress types textual convention to type.
		if n.TextualConvention == "InetAddressIPv4" || n.TextualConvention == "InetAddressIPv6" || n.TextualConvention == "InetAddress" {
			n.Type = n.TextualConvention
		}
		// Convert LLDP-MIB LldpPortId type textual convention to type.
		if n.TextualConvention == "LldpPortId" {
			n.Type = n.TextualConvention
		}
	})

	return nameToNode
}

func metricType(t string) (string, bool) {
	if _, ok := combinedTypes[t]; ok {
		return t, true
	}
	switch t {
	case "gauge", "INTEGER", "GAUGE", "TIMETICKS", "UINTEGER", "UNSIGNED32", "INTEGER32":
		return "gauge", true
	case "counter", "COUNTER", "COUNTER64":
		return "counter", true
	case "OctetString", "OCTETSTR", "OBJID":
		return "OctetString", true
	case "BITSTRING":
		return "Bits", true
	case "InetAddressIPv4", "IpAddr", "IPADDR", "NETADDR":
		return "InetAddressIPv4", true
	case "PhysAddress48", "DisplayString", "Float", "Double", "InetAddressIPv6":
		return t, true
	case "DateAndTime":
		return t, true
	case "ParseDateAndTime":
		return t, true
	case "NTPTimeStamp":
		return t, true
	case "EnumAsInfo", "EnumAsStateSet":
		return t, true
	default:
		// Unsupported type.
		return "", false
	}
}

func metricAccess(a string) bool {
	switch a {
	case "ACCESS_READONLY", "ACCESS_READWRITE", "ACCESS_CREATE", "ACCESS_NOACCESS":
		return true
	default:
		// The others are inaccessible metrics.
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

// Search node tree for the longest OID match.
func searchNodeTree(oid string, node *Node) *Node {
	if node == nil || !strings.HasPrefix(oid+".", node.Oid+".") {
		return nil
	}

	for _, child := range node.Children {
		match := searchNodeTree(oid, child)
		if match != nil {
			return match
		}
	}
	return node
}

type oidMetricType uint8

const (
	oidNotFound oidMetricType = iota
	oidScalar
	oidInstance
	oidSubtree
)

// Find node in SNMP MIB tree that represents the metric.
func getMetricNode(oid string, node *Node, nameToNode map[string]*Node) (*Node, oidMetricType) {
	// Check if is a known OID/name.
	n, ok := nameToNode[oid]
	if ok {
		// Known node, check if OID is a valid metric or a subtree.
		_, ok = metricType(n.Type)
		if ok && metricAccess(n.Access) && len(n.Indexes) == 0 {
			return n, oidScalar
		}
		return n, oidSubtree
	}

	// Unknown OID/name, search Node tree for longest match.
	n = searchNodeTree(oid, node)
	if n == nil {
		return nil, oidNotFound
	}

	// Table instances must be a valid metric node and have an index.
	_, ok = metricType(n.Type)
	ok = ok && metricAccess(n.Access)
	if !ok || len(n.Indexes) == 0 {
		return nil, oidNotFound
	}
	return n, oidInstance
}

// In the case of multiple nodes with the same label try to return the node
// where the OID matches in every branch apart from the last one.
func getIndexNode(lookup string, nameToNode map[string]*Node, metricOid string) *Node {
	for _, node := range nameToNode {
		if node.Label != lookup {
			continue
		}

		oid := strings.Split(metricOid, ".")
		oidPrefix := strings.Join(oid[:len(oid)-1], ".")

		if strings.HasPrefix(node.Oid, oidPrefix) {
			return node
		}
	}

	// If no node matches, revert to previous behavior.
	return nameToNode[lookup]
}

func generateConfigModule(cfg *ModuleConfig, node *Node, nameToNode map[string]*Node, logger *slog.Logger) (*config.Module, error) {
	out := &config.Module{}
	needToWalk := map[string]struct{}{}
	tableInstances := map[string][]string{}

	// Apply type overrides for the current module.
	for name, params := range cfg.Overrides {
		if params.Type == "" {
			continue
		}
		// Find node to override.
		n, ok := nameToNode[name]
		if !ok {
			logger.Warn("Could not find node to override type", "node", name)
			continue
		}
		// params.Type validated at generator configuration.
		n.Type = params.Type
	}

	// Remove redundant OIDs to be walked.
	toWalk := []string{}
	for _, oid := range cfg.Walk {
		// Resolve name to OID if possible.
		n, ok := nameToNode[oid]
		if ok {
			toWalk = append(toWalk, n.Oid)
		} else {
			toWalk = append(toWalk, oid)
		}
	}
	toWalk = minimizeOids(toWalk)

	// Find all top-level nodes.
	metricNodes := map[*Node]struct{}{}
	for _, oid := range toWalk {
		metricNode, oidType := getMetricNode(oid, node, nameToNode)
		switch oidType {
		case oidNotFound:
			return nil, fmt.Errorf("cannot find oid '%s' to walk", oid)
		case oidSubtree:
			needToWalk[oid] = struct{}{}
		case oidInstance:
			// Add a trailing period to the OID to indicate a "Get" instead of a "Walk".
			needToWalk[oid+"."] = struct{}{}
			// Save instance index for lookup.
			index := strings.Replace(oid, metricNode.Oid, "", 1)
			tableInstances[metricNode.Oid] = append(tableInstances[metricNode.Oid], index)
		case oidScalar:
			// Scalar OIDs must be accessed using index 0.
			needToWalk[oid+".0."] = struct{}{}
		}
		metricNodes[metricNode] = struct{}{}
	}
	// Sort the metrics by OID to make the output deterministic.
	metrics := make([]*Node, 0, len(metricNodes))
	for key := range metricNodes {
		metrics = append(metrics, key)
	}
	sort.Slice(metrics, func(i, j int) bool {
		return metrics[i].Oid < metrics[j].Oid
	})

	// Find all the usable metrics.
	for _, metricNode := range metrics {
		walkNode(metricNode, func(n *Node) {
			t, ok := metricType(n.Type)
			if !ok {
				return // Unsupported type.
			}

			if !metricAccess(n.Access) {
				return // Inaccessible metrics.
			}

			metric := &config.Metric{
				Name:       sanitizeLabelName(n.Label),
				Oid:        n.Oid,
				Type:       t,
				Help:       n.Description + " - " + n.Oid,
				Indexes:    []*config.Index{},
				Lookups:    []*config.Lookup{},
				EnumValues: n.EnumValues,
			}

			if cfg.Overrides[metric.Name].Ignore {
				return // Ignored metric.
			}

			// Afi (Address family)
			prevType := ""
			// Safi (Subsequent address family, e.g. Multicast/Unicast)
			prev2Type := ""
			for count, i := range n.Indexes {
				index := &config.Index{Labelname: i}
				indexNode, ok := nameToNode[i]
				if !ok {
					logger.Warn("Could not find index for node", "node", n.Label, "index", i)
					return
				}
				index.Type, ok = metricType(indexNode.Type)
				if !ok {
					logger.Warn("Can't handle index type on node", "node", n.Label, "index", i, "type", indexNode.Type)
					return
				}
				index.FixedSize = indexNode.FixedSize
				if n.ImpliedIndex && count+1 == len(n.Indexes) {
					index.Implied = true
				}
				index.EnumValues = indexNode.EnumValues

				// Convert (InetAddressType,InetAddress) to (InetAddress)
				if subtype, ok := combinedTypes[index.Type]; ok {
					if prevType == subtype {
						metric.Indexes = metric.Indexes[:len(metric.Indexes)-1]
					} else if prev2Type == subtype {
						metric.Indexes = metric.Indexes[:len(metric.Indexes)-2]
					} else {
						logger.Warn("Can't handle index type on node, missing preceding", "node", n.Label, "type", index.Type, "missing", subtype)
						return
					}
				}
				prev2Type = prevType
				prevType = indexNode.TextualConvention
				metric.Indexes = append(metric.Indexes, index)
			}
			out.Metrics = append(out.Metrics, metric)
		})
	}

	// Build an map of all oid targeted by a filter to access it easily later.
	filterMap := map[string][]string{}

	for _, filter := range cfg.Filters.Static {
		for _, oid := range filter.Targets {
			n, ok := nameToNode[oid]
			if ok {
				oid = n.Oid
			}
			filterMap[oid] = filter.Indices
		}
	}

	// Apply lookups.
	for _, metric := range out.Metrics {
		toDelete := []string{}

		// Build a list of lookup labels which are required as index.
		requiredAsIndex := []string{}
		for _, lookup := range cfg.Lookups {
			requiredAsIndex = append(requiredAsIndex, lookup.SourceIndexes...)
		}

		for _, lookup := range cfg.Lookups {
			foundIndexes := 0
			// See if all lookup indexes are present.
			for _, index := range metric.Indexes {
				for _, lookupIndex := range lookup.SourceIndexes {
					if index.Labelname == lookupIndex {
						foundIndexes++
					}
				}
			}
			if foundIndexes == len(lookup.SourceIndexes) {
				if _, ok := nameToNode[lookup.Lookup]; !ok {
					return nil, fmt.Errorf("unknown index '%s'", lookup.Lookup)
				}
				indexNode := getIndexNode(lookup.Lookup, nameToNode, metric.Oid)
				typ, ok := metricType(indexNode.Type)
				if !ok {
					return nil, fmt.Errorf("unknown index type %s for %s", indexNode.Type, lookup.Lookup)
				}
				l := &config.Lookup{
					Labelname: sanitizeLabelName(indexNode.Label),
					Type:      typ,
					Oid:       indexNode.Oid,
				}
				for _, oldIndex := range lookup.SourceIndexes {
					l.Labels = append(l.Labels, sanitizeLabelName(oldIndex))
				}
				metric.Lookups = append(metric.Lookups, l)

				// If lookup label is used as source index in another lookup,
				// we need to add this new label as another index.
				for _, sourceIndex := range requiredAsIndex {
					if sourceIndex == l.Labelname {
						idx := &config.Index{Labelname: l.Labelname, Type: l.Type}
						metric.Indexes = append(metric.Indexes, idx)
						break
					}
				}

				// Make sure we walk the lookup OID(s).
				if len(tableInstances[metric.Oid]) > 0 {
					for _, index := range tableInstances[metric.Oid] {
						needToWalk[indexNode.Oid+index+"."] = struct{}{}
					}
				} else {
					needToWalk[indexNode.Oid] = struct{}{}
				}
				// We apply the same filter to metric.Oid if the lookup oid is filtered.
				indices, found := filterMap[indexNode.Oid]
				if found {
					delete(needToWalk, metric.Oid)
					for _, index := range indices {
						needToWalk[metric.Oid+"."+index+"."] = struct{}{}
					}
				}
				if lookup.DropSourceIndexes {
					// Avoid leaving the old labelname around.
					toDelete = append(toDelete, lookup.SourceIndexes...)
				}
			}
		}
		for _, l := range toDelete {
			metric.Lookups = append(metric.Lookups, &config.Lookup{
				Labelname: sanitizeLabelName(l),
			})
		}
	}

	// Ensure index label names are sane.
	for _, metric := range out.Metrics {
		for _, index := range metric.Indexes {
			index.Labelname = sanitizeLabelName(index.Labelname)
		}
	}

	// Check that the object before an InetAddress is an InetAddressType.
	// If not, change it to an OctetString.
	for _, metric := range out.Metrics {
		if metric.Type == "InetAddress" || metric.Type == "InetAddressMissingSize" {
			// Get previous oid.
			oids := strings.Split(metric.Oid, ".")
			i, _ := strconv.Atoi(oids[len(oids)-1])
			oids[len(oids)-1] = strconv.Itoa(i - 1)
			prevOid := strings.Join(oids, ".")
			if prevObj, ok := nameToNode[prevOid]; !ok || prevObj.TextualConvention != "InetAddressType" {
				metric.Type = "OctetString"
			} else {
				// Make sure the InetAddressType is included.
				if len(tableInstances[metric.Oid]) > 0 {
					for _, index := range tableInstances[metric.Oid] {
						needToWalk[prevOid+index+"."] = struct{}{}
					}
				} else {
					needToWalk[prevOid] = struct{}{}
				}
			}
		}
	}

	// Apply module config overrides to their corresponding metrics.
	for name, params := range cfg.Overrides {
		for _, metric := range out.Metrics {
			if name == metric.Name || name == metric.Oid {
				metric.RegexpExtracts = params.RegexpExtracts
				metric.DateTimePattern = params.DateTimePattern
				metric.Offset = params.Offset
				metric.Scale = params.Scale
				if params.Help != "" {
					metric.Help = params.Help
				}
				if params.Name != "" {
					metric.Name = params.Name
				}
			}
		}
	}

	// Apply filters.
	for _, filter := range cfg.Filters.Static {
		// Delete the oid targeted by the filter, as we won't walk the whole table.
		for _, oid := range filter.Targets {
			n, ok := nameToNode[oid]
			if ok {
				oid = n.Oid
			}
			delete(needToWalk, oid)
			for _, index := range filter.Indices {
				needToWalk[oid+"."+index+"."] = struct{}{}
			}
		}
	}

	out.Filters = cfg.Filters.Dynamic

	oids := []string{}
	for k := range needToWalk {
		oids = append(oids, k)
	}
	// Remove redundant OIDs and separate Walk and Get OIDs.
	for _, k := range minimizeOids(oids) {
		if k[len(k)-1:] == "." {
			out.Get = append(out.Get, k[:len(k)-1])
		} else {
			out.Walk = append(out.Walk, k)
		}
	}
	return out, nil
}

var (
	invalidLabelCharRE = regexp.MustCompile(`[^a-zA-Z0-9_]`)
)

func sanitizeLabelName(name string) string {
	return invalidLabelCharRE.ReplaceAllString(name, "_")
}
