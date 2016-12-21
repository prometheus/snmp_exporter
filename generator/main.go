package main

import (
	"fmt"
	"strings"

	"github.com/prometheus/common/log"
	"gopkg.in/yaml.v2"
)

type Lookup struct {
	OldIndex string
	NewIndex string
}

type ModuleConfig struct {
	Walk    []string
	Lookups []Lookup
}

var cfg = &ModuleConfig{
	Walk: []string{"sysUpTime", "interfaces", "ifXTable"},
	Lookups: []Lookup{
		Lookup{
			OldIndex: "ifIndex",
			NewIndex: "ifDescr",
		},
	},
}

func main() {
	parseErrors := initSNMP()
	log.Warnf("NetSNMP reported %d parse errors", len(strings.Split(parseErrors, "\n")))

	nodes := getMIBTree()
	nameToNode := prepareTree(nodes)

	_ = nameToNode

	out := generateConfigModule(cfg, nodes, nameToNode)

	m, _ := yaml.Marshal(out)
	fmt.Println(string(m))

	//walkNode(nodes, func(n *Node) {
	//	fmt.Printf("%s %s %s %s %s %+v\n", n.Oid, n.Label, n.Type, n.Indexes, n.Description)
	//})
}
