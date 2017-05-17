package main

/*
#cgo LDFLAGS: -lnetsnmp -L/usr/local/lib
#cgo CFLAGS: -I/usr/local/include
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/mib_api.h>
#include <unistd.h>
*/
import "C"

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/prometheus/common/log"
)

// One entry in the tree of the MIB.
type Node struct {
	Oid         string
	Label       string
	Augments    string
	Children    []*Node
	Description string
	Type        string
	Hint        string
	Units       string
	Access      string

	Indexes []string
}

// Adapted from parse.h.
var (
	netSnmptypeMap = map[int]string{
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
	netSnmpaccessMap = map[int]string{
		18: "ACCESS_READONLY",
		19: "ACCESS_READWRITE",
		20: "ACCESS_WRITEONLY",
		21: "ACCESS_NOACCESS",
		67: "ACCESS_NOTIFY",
		48: "ACCESS_CREATE",
	}
)

// Initilise NetSNMP. Returns MIB parse errors.
//
// Warning: This function plays with the stderr file descriptor.
func initSNMP() string {
	// Load all the MIBs.
	// RFC1213-MIB is lacking type hints and has many common tables,
	// so prefer MIBs with hints.
	os.Setenv("MIBS", "SNMPv2-MIB:IF-MIB:IP-MIB:ALL")
	// Help the user find their MIB directories.
	log.Infof("Loading MIBs from %s", C.GoString(C.netsnmp_get_mib_directory()))
	// We want the descriptions.
	C.snmp_set_save_descriptions(1)

	// Make stderr go to a pipe, as netsnmp tends to spew a
	// lot of errors on startup that there's no apparent
	// way to disable or redirect.
	r, w, err := os.Pipe()
	if err != nil {
		log.Fatalf("Error creating pipe: %s", err)
	}
	defer r.Close()
	defer w.Close()
	savedStderrFd := C.dup(2)
	C.close(2)
	C.dup2(C.int(w.Fd()), 2)
	ch := make(chan string)
	go func() {
		data, err := ioutil.ReadAll(r)
		if err != nil {
			log.Fatalf("Error reading from pipe: %s", err)
		}
		ch <- string(data)
	}()

	// Do the initilization.
	C.netsnmp_init_mib()

	// Restore stderr to normal.
	w.Close()
	C.close(2)
	C.dup2(savedStderrFd, 2)
	C.close(savedStderrFd)
	return <-ch
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

	if access, ok := netSnmpaccessMap[int(t.access)]; ok {
		n.Access = access
	} else {
		n.Access = "unknown"
	}

	n.Augments = C.GoString(t.augments)
	n.Description = C.GoString(t.description)
	n.Hint = C.GoString(t.hint)
	n.Units = C.GoString(t.units)

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
	// In practice this means only the entry will have it.
	index := t.indexes
	indexes := []string{}
	for index != nil {
		indexes = append(indexes, C.GoString(index.ilabel))
		index = index.next
	}
	n.Indexes = indexes
}

// Convert the NetSNMP MIB tree to a Go data structure.
func getMIBTree() *Node {

	tree := C.get_tree_head()
	head := &Node{}
	buildMIBTree(tree, head, "")
	return head
}
