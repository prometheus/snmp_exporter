package main

import (
	"fmt"

	//"github.com/prometheus/snmp_exporter/config"
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
	initSNMP()
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
