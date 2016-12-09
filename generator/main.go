package main

/*
#cgo LDFLAGS: -lsnmp
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/mib_api.h>
*/
import "C"
import "fmt"

// One entry in the tree of the MIB.
type Node struct {
	Oid         string
	Label       string
	Children    []*Node
	Description string
	Type        string

	Indexes []string
}

// Adapted from parse.h
const typeMap = map[int]string{
	0:  "OTHER ",
	1:  "OBJID ",
	2:  "OCTETSTR ",
	3:  "INTEGER ",
	4:  "NETADDR ",
	5:  "IPADDR ",
	6:  "COUNTER ",
	7:  "GAUGE ",
	8:  "TIMETICKS ",
	9:  "OPAQUE ",
	10: "NULL ",
	11: "COUNTER64 ",
	12: "BITSTRING ",
	13: "NSAPADDRESS ",
	14: "UINTEGER ",
	15: "UNSIGNED32 ",
	16: "INTEGER32 ",
	20: "TRAPTYPE ",
	21: "NOTIFTYPE ",
	22: "OBJGROUP ",
	23: "NOTIFGROUP ",
	24: "MODID ",
	25: "AGENTCAP ",
	26: "MODCOMP ",
	27: "OBJIDENTITY ",
}

func buildTree(t *C.struct_tree, n *Node, oid string) {
	n.Oid = fmt.Sprintf("%s.%d", oid, t.subid)
	n.Label = C.GoString(t.label)

	if t.child_list == nil {
		return
	}

	head := t.child_list
	n.Children = []*Node{}
	for head != nil {
		child := &Node{}
		n.Children = append(n.Children, child)
		buildTree(head, child, n.Oid)
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
	for _, c := range n.Children {
		c.Indexes = indexes
	}

}

func main() {
	C.netsnmp_init_mib()
	tree := C.get_tree_head()

	nodes := &Node{}

	buildTree(tree, nodes, "")

	fmt.Printf("%+v", nodes)
}
