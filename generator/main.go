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

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/yaml.v2"

	"github.com/prometheus/snmp_exporter/config"
)

// Generate a snmp_exporter config and write it out.
func generateConfig(nodes *Node, nameToNode map[string]*Node, logger log.Logger) error {
	outputPath, err := filepath.Abs(*outputPath)
	if err != nil {
		return fmt.Errorf("unable to determine absolute path for output")
	}

	content, err := ioutil.ReadFile("generator.yml")
	if err != nil {
		return fmt.Errorf("error reading yml config: %s", err)
	}
	cfg := &Config{}
	err = yaml.UnmarshalStrict(content, cfg)
	if err != nil {
		return fmt.Errorf("error parsing yml config: %s", err)
	}

	outputConfig := config.Config{}
	for name, m := range cfg.Modules {
		level.Info(logger).Log("msg", "Generating config for module", "module", name)
		// Give each module a copy of the tree so that it can be modified.
		mNodes := nodes.Copy()
		// Build the map with new pointers.
		mNameToNode := map[string]*Node{}
		walkNode(mNodes, func(n *Node) {
			mNameToNode[n.Oid] = n
			mNameToNode[n.Label] = n
		})
		out, err := generateConfigModule(m, mNodes, mNameToNode, logger)
		if err != nil {
			return err
		}
		outputConfig[name] = out
		outputConfig[name].WalkParams = m.WalkParams
		level.Info(logger).Log("msg", "Generated metrics", "module", name, "metrics", len(outputConfig[name].Metrics))
	}

	config.DoNotHideSecrets = true
	out, err := yaml.Marshal(outputConfig)
	config.DoNotHideSecrets = false
	if err != nil {
		return fmt.Errorf("error marshaling yml: %s", err)
	}

	// Check the generated config to catch auth/version issues.
	err = yaml.UnmarshalStrict(out, &config.Config{})
	if err != nil {
		return fmt.Errorf("error parsing generated config: %s", err)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("error opening output file: %s", err)
	}
	out = append([]byte("# WARNING: This file was auto-generated using snmp_exporter generator, manual changes will be lost.\n"), out...)
	_, err = f.Write(out)
	if err != nil {
		return fmt.Errorf("error writing to output file: %s", err)
	}
	level.Info(logger).Log("msg", "Config written", "file", outputPath)
	return nil
}

var (
	failOnParseErrors  = kingpin.Flag("fail-on-parse-errors", "Exit with a non-zero status if there are MIB parsing errors").Default("false").Bool()
	generateCommand    = kingpin.Command("generate", "Generate snmp.yml from generator.yml")
	outputPath         = generateCommand.Flag("output-path", "Path to to write resulting config file").Default("snmp.yml").Short('o').String()
	parseErrorsCommand = kingpin.Command("parse_errors", "Debug: Print the parse errors output by NetSNMP")
	dumpCommand        = kingpin.Command("dump", "Debug: Dump the parsed and prepared MIBs")
)

func main() {
	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.HelpFlag.Short('h')
	command := kingpin.Parse()
	logger := promlog.New(promlogConfig)

	parseOutput, err := initSNMP(logger)
	if err != nil {
		level.Error(logger).Log("msg", "Error initializing netsnmp", "err", err)
		os.Exit(1)
	}

	parseOutput = strings.TrimSpace(parseOutput)
	parseErrors := len(parseOutput) != 0
	if parseErrors {
		level.Warn(logger).Log("msg", "NetSNMP reported parse error(s)", "errors", len(strings.Split(parseOutput, "\n")))
	}

	nodes := getMIBTree()
	nameToNode := prepareTree(nodes, logger)

	switch command {
	case generateCommand.FullCommand():
		err := generateConfig(nodes, nameToNode, logger)
		if err != nil {
			level.Error(logger).Log("msg", "Error generating config netsnmp", "err", err)
			os.Exit(1)
		}
	case parseErrorsCommand.FullCommand():
		fmt.Println(parseOutput)
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
	if *failOnParseErrors && parseErrors {
		os.Exit(1)
	}
}
