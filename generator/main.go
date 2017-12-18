package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/prometheus/common/log"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/yaml.v2"

	"github.com/prometheus/snmp_exporter/config"
)

// Generate a snmp_exporter config and write it out.
func generateConfig(nodes *Node, nameToNode map[string]*Node) {
	outputPath, err := filepath.Abs(*outputPath)
	if err != nil {
		log.Fatal("Unable to determine absolute path for output")
	}

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
		outputConfig[name].WalkParams = m.WalkParams
		log.Infof("Generated %d metrics for module %s", len(outputConfig[name].Metrics), name)
	}

	config.DoNotHideSecrets = true
	out, err := yaml.Marshal(outputConfig)
	config.DoNotHideSecrets = false
	if err != nil {
		log.Fatalf("Error marshalling yml: %s", err)
	}

	// Check the generated config to catch auth/version issues.
	err = yaml.Unmarshal(out, &config.Config{})
	if err != nil {
		log.Fatalf("Error parsing generated config: %s", err)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		log.Fatalf("Error opening output file: %s", err)
	}
	_, err = f.Write(out)
	if err != nil {
		log.Fatalf("Error writing to output file: %s", err)
	}
	log.Infof("Config written to %s", outputPath)
}

var (
	generateCommand    = kingpin.Command("generate", "Generate snmp.yml from generator.yml")
	outputPath         = generateCommand.Flag("output-path", "Path to to write resulting config file").Default("snmp.yml").Short('o').String()
	parseErrorsCommand = kingpin.Command("parse_errors", "Debug: Print the parse errors output by NetSNMP")
	dumpCommand        = kingpin.Command("dump", "Debug: Dump the parsed and prepared MIBs")
)

func main() {
	log.AddFlags(kingpin.CommandLine)
	kingpin.HelpFlag.Short('h')
	command := kingpin.Parse()

	parseErrors := initSNMP()
	log.Warnf("NetSNMP reported %d parse errors", len(strings.Split(parseErrors, "\n")))

	nodes := getMIBTree()
	nameToNode := prepareTree(nodes)

	switch command {
	case generateCommand.FullCommand():
		generateConfig(nodes, nameToNode)
	case parseErrorsCommand.FullCommand():
		fmt.Println(parseErrors)
	case dumpCommand.FullCommand():
		walkNode(nodes, func(n *Node) {
			t := n.Type
			if n.FixedSize != 0 {
				t = fmt.Sprintf("%s(%d)", n.Type, n.FixedSize)
			}
			fmt.Printf("%s %s %s %q %q %s %s\n", n.Oid, n.Label, t, n.TextualConvention, n.Hint, n.Indexes, n.Description)
		})
	}
}
