package main

/*
#cgo LDFLAGS: -lsnmp
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/mib_api.h>
*/
import "C"

import (
	"fmt"
	"os"
)

// One entry in the tree of the MIB.
type Node struct {
	Oid         string
	Label       string
	Augments    string
	Children    []*Node
	Description string
	Type        string

	Indexes []string
}

// Adapted from parse.h
var netSnmptypeMap = map[int]string{
	0:  "OTHER",
	1:  "OBJID",
	2:  "OCTETSTR",
	3:  "INTEGER",
	4:  "NETADDR",
	5:  "IPADDR",
	6:  "COUNTER",
	7:  "GAUGE",
	8:  "TIMETICKS",
	9:  "OPAQUE",
	10: "NULL",
	11: "COUNTER64",
	12: "BITSTRING",
	13: "NSAPADDRESS",
	14: "UINTEGER",
	15: "UNSIGNED32",
	16: "INTEGER32",
	20: "TRAPTYPE",
	21: "NOTIFTYPE",
	22: "OBJGROUP",
	23: "NOTIFGROUP",
	24: "MODID",
	25: "AGENTCAP",
	26: "MODCOMP",
	27: "OBJIDENTITY",
}

func init() {
  // Load all the MIBs.
	os.Setenv("MIBS", "ALL")
  // We want the descriptions.
	C.snmp_set_save_descriptions(1)
	C.netsnmp_init_mib()
}

// Walk NetSNMP MIB tree, building a Go tree from it.
func buildMIBTree(t *C.struct_tree, n *Node, oid string) {
	if oid != "" {
		n.Oid = fmt.Sprintf("%s.%d", oid, t.subid)
	} else {
		n.Oid = fmt.Sprintf("%d", t.subid)
	}
	n.Label = C.GoString(t.label)
	if typ, ok := netSnmptypeMap[int(t._type)]; ok {
		n.Type = typ
	} else {
		n.Type = "unknown"
	}
	n.Augments = C.GoString(t.augments)
	n.Description = C.GoString(t.description)

	if t.child_list == nil {
		return
	}

	head := t.child_list
	n.Children = []*Node{}
	for head != nil {
		child := &Node{}
		// Prepend, as nodes are backwards.
		n.Children = append([]*Node{child}, n.Children...)
		buildMIBTree(head, child, n.Oid)
		head = head.next_peer
	}

	// Set names of indexes on each child.
	// This avoids having to walk back up the tree to get
	// the index from the table entry.
	index := t.indexes
	indexes := []string{}
	for index != nil {
		indexes = append(indexes, C.GoString(index.ilabel))
		index = index.next
	}
	if len(indexes) != 0 {
		for _, c := range n.Children {
			c.Indexes = indexes
		}
		// Set it on the table entry too.
		n.Indexes = indexes
	}

}

// Convert the NetSNMP MIB tree to a Go data structure.
func getMIBTree() *Node {

	tree := C.get_tree_head()
	head := &Node{}
	buildMIBTree(tree, head, "")
	return head
}
