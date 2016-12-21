package main

import (
	"io/ioutil"
	"os"
	"strings"

	"github.com/prometheus/common/log"
	"gopkg.in/yaml.v2"

	"github.com/prometheus/snmp_exporter/config"
)

type Config struct {
	Modules map[string]*ModuleConfig `yaml:"modules"`
}

type ModuleConfig struct {
	Walk    []string  `yaml:"walk"`
	Lookups []*Lookup `yaml:"lookups"`
}

type Lookup struct {
	OldIndex string `yaml:"old_index"`
	NewIndex string `yaml:"new_index"`
}

func main() {
	parseErrors := initSNMP()
	log.Warnf("NetSNMP reported %d parse errors", len(strings.Split(parseErrors, "\n")))

	nodes := getMIBTree()
	nameToNode := prepareTree(nodes)

	content, err := ioutil.ReadFile("generator.yml")
	if err != nil {
		log.Fatalf("Error reading yml config: %s", err)
	}
	cfg := &Config{}
	err = yaml.Unmarshal(content, cfg)
	if err != nil {
		log.Fatalf("Error parsing yml config: %s", err)
	}

	outputConfig := config.Config{}
	for name, m := range cfg.Modules {
		log.Infof("Generating config for module %s", name)
		outputConfig[name] = generateConfigModule(m, nodes, nameToNode)
		log.Infof("Generated %d metrics for module %s", len(outputConfig[name].Metrics), name)
	}

	out, err := yaml.Marshal(outputConfig)
	if err != nil {
		log.Fatalf("Error marshalling yml: %s", err)
	}
	f, err := os.Create("snmp.yml")
	if err != nil {
		log.Fatalf("Error opening output file: %s", err)
	}
	_, err = f.Write(out)
	if err != nil {
		log.Fatalf("Error writing to output file: %s", err)
	}
	log.Infof("Config written to snmp.yml")

	//walkNode(nodes, func(n *Node) {
	//	fmt.Printf("%s %s %s %s %s %+v\n", n.Oid, n.Label, n.Type, n.Indexes, n.Description)
	//})
}
