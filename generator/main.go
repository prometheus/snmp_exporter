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
	err = yaml.UnmarshalStrict(content, cfg)
	if err != nil {
		log.Fatalf("Error parsing yml config: %s", err)
	}

	outputConfig := config.Config{}
	for name, m := range cfg.Modules {
		log.Infof("Generating config for module %s", name)
		// Give each module a copy of the tree so that it can be modified.
		mNodes := nodes.Copy()
		// Build the map with new pointers.
		mNameToNode := map[string]*Node{}
		walkNode(mNodes, func(n *Node) {
			mNameToNode[n.Oid] = n
			mNameToNode[n.Label] = n
		})
		outputConfig[name] = generateConfigModule(m, mNodes, mNameToNode)
		outputConfig[name].WalkParams = m.WalkParams
		log.Infof("Generated %d metrics for module %s", len(outputConfig[name].Metrics), name)
	}

	config.DoNotHideSecrets = true
	out, err := yaml.Marshal(outputConfig)
	config.DoNotHideSecrets = false
	if err != nil {
		log.Fatalf("Error marshaling yml: %s", err)
	}

	// Check the generated config to catch auth/version issues.
	err = yaml.UnmarshalStrict(out, &config.Config{})
	if err != nil {
		log.Fatalf("Error parsing generated config: %s", err)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		log.Fatalf("Error opening output file: %s", err)
	}
	out = append([]byte("# WARNING: This file was auto-generated using snmp_exporter generator, manual changes will be lost.\n"), out...)
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

	if len(parseErrors) != 0 {
		log.Warnf("NetSNMP reported %d parse errors", len(strings.Split(parseErrors, "\n")))
	}
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
			implied := ""
			if n.ImpliedIndex {
				implied = "(implied)"
			}
			fmt.Printf("%s %s %s %q %q %s%s %v %s\n",
				n.Oid, n.Label, t, n.TextualConvention, n.Hint, n.Indexes, implied, n.EnumValues, n.Description)
		})
	}
}
