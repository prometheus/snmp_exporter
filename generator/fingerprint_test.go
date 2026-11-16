// Copyright 2026 The Prometheus Authors
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
	"strings"
	"testing"

	"go.yaml.in/yaml/v2"

	"github.com/prometheus/snmp_exporter/config"
)

func fingerprintTestTree() map[string]*Node {
	root := &Node{Oid: "1.3.6.1.2.1.1", Label: "system", Module: "SNMPv2-MIB", Children: []*Node{
		{Oid: "1.3.6.1.2.1.1.1", Label: "sysDescr", Module: "SNMPv2-MIB"},
		{Oid: "1.3.6.1.2.1.1.2", Label: "sysObjectID", Module: "SNMPv2-MIB"},
	}}
	nameToNode := map[string]*Node{}
	walkNode(root, func(n *Node) {
		nameToNode[n.Oid] = n
		nameToNode[n.Label] = n
		if n.Module != "" {
			nameToNode[n.Module+"::"+n.Label] = n
		}
	})
	return nameToNode
}

func TestGenerateFingerprinters(t *testing.T) {
	in := `
fingerprinters:
  system:
    discovery_modules: [system]
    default_modules: [if_mib]
    matchers:
      - oid: SNMPv2-MIB::sysObjectID
        regex: '1\.3\.6\.1\.4\.1\.41112(\..*)?'
        modules: [ubiquiti_unifi]
      - oid: sysDescr
        regex: 'Linux .*'
        modules: [linux]
      - oid: 1.3.6.1.2.1.1.2.0
        exists: true
        modules: [if_mib]
`
	cfg := &Config{}
	if err := yaml.UnmarshalStrict([]byte(in), cfg); err != nil {
		t.Fatalf("Error unmarshaling generator config: %v", err)
	}

	out, err := generateFingerprinters(cfg.Fingerprinters, fingerprintTestTree())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	fp := out["system"]
	want := []string{"1.3.6.1.2.1.1.2", "1.3.6.1.2.1.1.1", "1.3.6.1.2.1.1.2.0"}
	for i, m := range fp.Matchers {
		if m.Oid != want[i] {
			t.Errorf("matcher %d: want oid %s, got %s", i, want[i], m.Oid)
		}
	}
	// The input must not be modified.
	if cfg.Fingerprinters["system"].Matchers[0].Oid != "SNMPv2-MIB::sysObjectID" {
		t.Error("input fingerprinter was modified")
	}

	// The output must round trip through the exporter config.
	b, err := yaml.Marshal(config.Config{Fingerprinters: out})
	if err != nil {
		t.Fatalf("Error marshaling: %v", err)
	}
	parsed := &config.Config{}
	if err := yaml.UnmarshalStrict(b, parsed); err != nil {
		t.Fatalf("Error unmarshaling generated config: %v", err)
	}
	if !parsed.Fingerprinters["system"].Matchers[0].Regex.MatchString("1.3.6.1.4.1.41112.1.6") {
		t.Error("regex did not survive round trip")
	}
	if parsed.Fingerprinters["system"].Matchers[0].Regex.MatchString("1.3.6.1.4.1.411120") {
		t.Error("regex lost anchoring in round trip")
	}
}

func TestGenerateFingerprintersUnknownOid(t *testing.T) {
	fps := map[string]*config.Fingerprinter{
		"system": {
			DiscoveryModules: []string{"system"},
			Matchers: []*config.FingerprintMatcher{
				{Oid: "SNMPv2-MIB::sysNope", Exists: true, Modules: []string{"if_mib"}},
			},
		},
	}
	_, err := generateFingerprinters(fps, fingerprintTestTree())
	if err == nil || !strings.Contains(err.Error(), "sysNope") {
		t.Fatalf("expected unknown oid error, got %v", err)
	}
}
