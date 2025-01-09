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
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/common/promslog/flag"
	"gopkg.in/yaml.v2"

	"github.com/prometheus/snmp_exporter/config"
)

var (
	cannotFindModuleRE = regexp.MustCompile(`Cannot find module \((.+)\): (.+)`)
)

// Generate a snmp_exporter config and write it out.
func generateConfig(nodes *Node, nameToNode map[string]*Node, logger *slog.Logger) error {
	outputPath, err := filepath.Abs(*outputPath)
	if err != nil {
		return fmt.Errorf("unable to determine absolute path for output")
	}

	content, err := os.ReadFile(*generatorYmlPath)
	if err != nil {
		return fmt.Errorf("error reading yml config: %s", err)
	}
	cfg := &Config{}
	err = yaml.UnmarshalStrict(content, cfg)
	if err != nil {
		return fmt.Errorf("error parsing yml config: %s", err)
	}

	outputConfig := config.Config{}
	outputConfig.Auths = cfg.Auths
	outputConfig.Modules = make(map[string]*config.Module, len(cfg.Modules))
	for name, m := range cfg.Modules {
		logger.Info("Generating config for module", "module", name)
		// Give each module a copy of the tree so that it can be modified.
		mNodes := nodes.Copy()
		// Build the map with new pointers.
		mNameToNode := map[string]*Node{}
		walkNode(mNodes, func(n *Node) {
			mNameToNode[n.Oid] = n
			mNameToNode[n.Label] = n
			if n.Module != "" {
				mNameToNode[n.Module+"::"+n.Label] = n
			}
		})
		out, err := generateConfigModule(m, mNodes, mNameToNode, logger)
		if err != nil {
			return err
		}
		outputConfig.Modules[name] = out
		outputConfig.Modules[name].WalkParams = m.WalkParams
		logger.Info("Generated metrics", "module", name, "metrics", len(outputConfig.Modules[name].Metrics))
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
	logger.Info("Config written", "file", outputPath)
	return nil
}

var (
	failOnParseErrors  = kingpin.Flag("fail-on-parse-errors", "Exit with a non-zero status if there are MIB parsing errors").Default("true").Bool()
	snmpMIBOpts        = kingpin.Flag("snmp.mibopts", "Toggle various defaults controlling MIB parsing, see snmpwalk --help").Default("eu").String()
	generateCommand    = kingpin.Command("generate", "Generate snmp.yml from generator.yml")
	userMibsDir        = kingpin.Flag("mibs-dir", "Paths to mibs directory").Default("").Short('m').Strings()
	generatorYmlPath   = generateCommand.Flag("generator-path", "Path to the input generator.yml file").Default("generator.yml").Short('g').String()
	outputPath         = generateCommand.Flag("output-path", "Path to write the snmp_exporter's config file").Default("snmp.yml").Short('o').String()
	parseErrorsCommand = kingpin.Command("parse_errors", "Debug: Print the parse errors output by NetSNMP")
	dumpCommand        = kingpin.Command("dump", "Debug: Dump the parsed and prepared MIBs")
)

func main() {
	promslogConfig := &promslog.Config{}
	flag.AddFlags(kingpin.CommandLine, promslogConfig)
	kingpin.HelpFlag.Short('h')
	command := kingpin.Parse()
	logger := promslog.New(promslogConfig)

	output, err := initSNMP(logger)
	if err != nil {
		logger.Error("Error initializing netsnmp", "err", err)
		os.Exit(1)
	}

	parseOutput := scanParseOutput(logger, output)
	parseErrors := len(parseOutput)

	nodes := getMIBTree()
	nameToNode := prepareTree(nodes, logger)

	switch command {
	case generateCommand.FullCommand():
		if *failOnParseErrors && parseErrors > 0 {
			logger.Error("Failing on reported parse error(s)", "help", "Use 'generator parse_errors' command to see errors, --no-fail-on-parse-errors to ignore")
		} else {
			err := generateConfig(nodes, nameToNode, logger)
			if err != nil {
				logger.Error("Error generating config netsnmp", "err", err)
				os.Exit(1)
			}
		}
	case parseErrorsCommand.FullCommand():
		if parseErrors > 0 {
			fmt.Printf("%s\n", strings.Join(parseOutput, "\n"))
		} else {
			logger.Info("No parse errors")
		}
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
	if *failOnParseErrors && parseErrors > 0 {
		os.Exit(1)
	}
}

func scanParseOutput(logger *slog.Logger, output string) []string {
	var parseOutput []string
	output = strings.TrimSpace(strings.ToValidUTF8(output, "�"))
	if len(output) > 0 {
		parseOutput = strings.Split(output, "\n")
	}
	parseErrors := len(parseOutput)

	if parseErrors > 0 {
		logger.Warn("NetSNMP reported parse error(s)", "errors", parseErrors)
	}

	for _, line := range parseOutput {
		if strings.HasPrefix(line, "Cannot find module") {
			missing := cannotFindModuleRE.FindStringSubmatch(line)
			logger.Error("Missing MIB", "mib", missing[1], "from", missing[2])
		}
	}
	return parseOutput
}
