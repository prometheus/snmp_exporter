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

/*
#cgo LDFLAGS: -lnetsnmp -L/usr/local/lib
#cgo CFLAGS: -I/usr/local/include
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/mib_api.h>
#include <net-snmp/agent/agent_callbacks.h>
#include <net-snmp/library/default_store.h>
#include <net-snmp/library/parse.h>
#include <unistd.h>
// From parse.c
// Hacky workarounds to detect which version of net-snmp this
// based on various headers that appear in 5.8 and 5.9.
#if !defined(NETSNMP_DS_LIB_ADD_FORWARDER_INFO)
#if defined(SNMPD_CALLBACK_UNREGISTER_NOTIFICATIONS)
#define MAXTC   16384
#else
#define MAXTC   4096
#endif
#endif

struct tc {
  int             type;
  int             modid;
  char           *descriptor;
  char           *hint;
  struct enum_list *enums;
  struct range_list *ranges;
  char           *description;
#if !defined(NETSNMP_DS_LIB_ADD_FORWARDER_INFO)
} tclist[MAXTC];
int tc_alloc = MAXTC;
#else
} *tclist;
int tc_alloc;
#endif

// Return the size of a fixed, or 0 if it is not fixed.
int get_tc_fixed_size(int tc_index) {
  if (tc_index < 0 || tc_index >= tc_alloc) {
    return 0;
  }
  struct range_list *ranges;
  ranges = tclist[tc_index].ranges;
  // Look for one range with only one possible value.
  if (ranges == NULL || ranges->low != ranges->high || ranges->next != NULL) {
    return 0;
  }
  return ranges->low;
}

*/
import "C"

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
)

// One entry in the tree of the MIB.
type Node struct {
	Oid               string
	subid             int64
	Module            string
	Label             string
	Augments          string
	Children          []*Node
	Description       string
	Type              string
	Hint              string
	TextualConvention string
	FixedSize         int
	Units             string
	Access            string
	EnumValues        map[int]string

	Indexes      []string
	ImpliedIndex bool
}

// Copy returns a deep copy of the tree underneath the current Node.
func (n *Node) Copy() *Node {
	newNode := *n
	newNode.Children = make([]*Node, 0, len(n.Children))
	newNode.EnumValues = make(map[int]string, len(n.EnumValues))
	newNode.Indexes = make([]string, len(n.Indexes))
	copy(newNode.Indexes, n.Indexes)
	// Deep copy children and enums.
	for _, child := range n.Children {
		newNode.Children = append(newNode.Children, child.Copy())
	}
	for k, v := range n.EnumValues {
		newNode.EnumValues[k] = v
	}
	return &newNode
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

// getMibsDir joins the user-specified MIB directories into a single string; if the user didn't pass any,
// the default netsnmp mibs directory is returned.
func getMibsDir(paths []string) string {
	if len(paths) == 1 && paths[0] == "" {
		return C.GoString(C.netsnmp_get_mib_directory())
	}
	return strings.Join(paths, ":")
}

// Initialize NetSNMP. Returns MIB parse errors.
//
// Warning: This function plays with the stderr file descriptor.
func initSNMP(logger *slog.Logger) (string, error) {
	// Load all the MIBs.
	err := os.Setenv("MIBS", "ALL")
	if err != nil {
		return "", err
	}
	mibsDir := getMibsDir(*userMibsDir)
	logger.Info("Loading MIBs", "from", mibsDir)
	C.netsnmp_set_mib_directory(C.CString(mibsDir))
	if *snmpMIBOpts != "" {
		C.snmp_mib_toggle_options(C.CString(*snmpMIBOpts))
	}
	// We want the descriptions.
	C.snmp_set_save_descriptions(1)
	// Make stderr go to a pipe, as netsnmp tends to spew a
	// lot of errors on startup that there's no apparent
	// way to disable or redirect.
	r, w, err := os.Pipe()
	if err != nil {
		return "", fmt.Errorf("error creating pipe: %s", err)
	}
	defer r.Close()
	defer w.Close()
	savedStderrFd := C.dup(2)
	C.close(2)
	C.dup2(C.int(w.Fd()), 2)
	ch := make(chan string)
	errch := make(chan error)
	go func() {
		data, err := io.ReadAll(r)
		if err != nil {
			errch <- fmt.Errorf("error reading from pipe: %s", err)
			return
		}
		errch <- nil
		ch <- string(data)
	}()

	// Do the initialization.
	C.netsnmp_init_mib()

	// Restore stderr to normal.
	w.Close()
	C.close(2)
	C.dup2(savedStderrFd, 2)
	C.close(savedStderrFd)
	if err := <-errch; err != nil {
		return "", err
	}
	return <-ch, nil
}

// Walk NetSNMP MIB tree, building a Go tree from it.
func buildMIBTree(t *C.struct_tree, n *Node, oid string) {
	n.subid = int64(t.subid)
	if oid != "" {
		n.Oid = fmt.Sprintf("%s.%d", oid, t.subid)
	} else {
		n.Oid = fmt.Sprintf("%d", t.subid)
	}
	if m := C.find_module(t.modid); m != nil {
		n.Module = C.GoString(m.name)
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
	n.TextualConvention = C.GoString(C.get_tc_descriptor(t.tc_index))
	n.FixedSize = int(C.get_tc_fixed_size(t.tc_index))
	n.Units = C.GoString(t.units)

	n.EnumValues = map[int]string{}
	enum := t.enums
	for enum != nil {
		n.EnumValues[int(enum.value)] = C.GoString(enum.label)
		enum = enum.next
	}

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

	// Ensure things are consistently ordered.
	sort.Slice(n.Children, func(i, j int) bool {
		return n.Children[i].subid < n.Children[j].subid
	})

	// Set names of indexes on each child.
	// In practice this means only the entry will have it.
	index := t.indexes
	indexes := []string{}
	for index != nil {
		indexes = append(indexes, C.GoString(index.ilabel))
		if index.isimplied != 0 {
			n.ImpliedIndex = true
		}
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
