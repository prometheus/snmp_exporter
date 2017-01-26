package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/prometheus/common/log"
	"gopkg.in/yaml.v2"

	"github.com/prometheus/snmp_exporter/config"
)

// Generate a snmp_exporter config and write it out.
func generateConfig(nodes *Node, nameToNode map[string]*Node) {
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
		outputConfig[name].Version = m.Version
		outputConfig[name].Retries = m.Retries
		outputConfig[name].MaxRepititions = m.MaxRepititions
		outputConfig[name].Timeout = m.Timeout
		outputConfig[name].Auth = m.Auth
		log.Infof("Generated %d metrics for module %s", len(outputConfig[name].Metrics), name)
	}

	out, err := yaml.Marshal(outputConfig)
	if err != nil {
		log.Fatalf("Error marshalling yml: %s", err)
	}

	// Check the generated config to catch auth/version issues.
	err = yaml.Unmarshal(out, &config.Config{})
	if err != nil {
		log.Fatalf("Error parsing generated config: %s", err)
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
}

func help() {
	fmt.Println(`
Commands:
  generate     Generate snmp.yml from generator.yml
  parse_errors Debug: Print the parse errors output by NetSNMP
  dump         Debug: Dump the parsed and prepared MIBs
  help         Print this help`)
}

func main() {
	if len(os.Args) < 2 {
		help()
		log.Errorf("A command must be provided as an argument.")
		os.Exit(1)
	}

	parseErrors := initSNMP()
	log.Warnf("NetSNMP reported %d parse errors", len(strings.Split(parseErrors, "\n")))

	nodes := getMIBTree()
	nameToNode := prepareTree(nodes)

	switch os.Args[1] {
	case "generate":
		generateConfig(nodes, nameToNode)
	case "parse_errors":
		fmt.Println(parseErrors)
	case "dump":
		walkNode(nodes, func(n *Node) {
			fmt.Printf("%s %s %s %s %s\n", n.Oid, n.Label, n.Type, n.Indexes, n.Description)
		})
	case "help":
		help()
	default:
		help()
		log.Errorf("Unknown command '%s'", os.Args[1])
		os.Exit(1)
	}

}
