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

package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
	"go.yaml.in/yaml/v2"
)

const fingerprintBaseModules = `
modules:
  system:
    get:
      - 1.3.6.1.2.1.1.1.0
      - 1.3.6.1.2.1.1.2.0
  lldp:
    walk:
      - 1.0.8802.1.1.2.1.4
  if_mib:
    walk:
      - 1.3.6.1.2.1.2
  ubiquiti_unifi:
    walk:
      - 1.3.6.1.4.1.41112.1.6
`

func TestFingerprinterUnmarshal(t *testing.T) {
	content := fingerprintBaseModules + `
fingerprinters:
  system:
    discovery_modules: [system, lldp]
    default_modules: [if_mib]
    matchers:
      - oid: 1.3.6.1.2.1.1.2
        regex: '1\.3\.6\.1\.4\.1\.41112(\..*)?'
        modules: [if_mib, ubiquiti_unifi]
      - oid: 1.0.8802.1.1.2.1.4
        exists: true
        modules: [lldp]
`
	cfg := &Config{}
	if err := yaml.UnmarshalStrict([]byte(content), cfg); err != nil {
		t.Fatalf("Error unmarshaling config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Unexpected validation error: %v", err)
	}

	fp, ok := cfg.Fingerprinters["system"]
	if !ok {
		t.Fatal("fingerprinter 'system' missing")
	}
	if !reflect.DeepEqual(fp.DiscoveryModules, []string{"system", "lldp"}) {
		t.Errorf("unexpected discovery modules: %v", fp.DiscoveryModules)
	}
	if !reflect.DeepEqual(fp.DefaultModules, []string{"if_mib"}) {
		t.Errorf("unexpected default modules: %v", fp.DefaultModules)
	}
	if len(fp.Matchers) != 2 {
		t.Fatalf("expected 2 matchers, got %d", len(fp.Matchers))
	}
	if fp.Matchers[0].Regex.Regexp == nil {
		t.Fatal("regex of first matcher not compiled")
	}
	// Regexes are anchored.
	if !fp.Matchers[0].Regex.MatchString("1.3.6.1.4.1.41112.1.6.3.3") {
		t.Error("regex should match ubnt sysObjectID")
	}
	if fp.Matchers[0].Regex.MatchString("1.3.6.1.4.1.411120") {
		t.Error("regex must be anchored")
	}
	if !fp.Matchers[1].Exists {
		t.Error("second matcher should be an exists matcher")
	}
}

func TestFingerprinterValidation(t *testing.T) {
	cases := []struct {
		name          string
		fingerprinter string
		errContains   string
	}{
		{
			name: "no discovery modules",
			fingerprinter: `
  fp:
    default_modules: [if_mib]
`,
			errContains: "no discovery_modules",
		},
		{
			name: "unknown discovery module",
			fingerprinter: `
  fp:
    discovery_modules: [nope]
`,
			errContains: `unknown discovery module "nope"`,
		},
		{
			name: "unknown default module",
			fingerprinter: `
  fp:
    discovery_modules: [system]
    default_modules: [nope]
`,
			errContains: `unknown default module "nope"`,
		},
		{
			name: "unknown matcher module",
			fingerprinter: `
  fp:
    discovery_modules: [system]
    matchers:
      - oid: 1.3.6.1.2.1.1.2
        exists: true
        modules: [nope]
`,
			errContains: `unknown module "nope"`,
		},
		{
			name: "matcher without oid",
			fingerprinter: `
  fp:
    discovery_modules: [system]
    matchers:
      - exists: true
        modules: [if_mib]
`,
			errContains: "oid must be set",
		},
		{
			name: "matcher with non numeric oid",
			fingerprinter: `
  fp:
    discovery_modules: [system]
    matchers:
      - oid: SNMPv2-MIB::sysObjectID
        exists: true
        modules: [if_mib]
`,
			errContains: "numeric",
		},
		{
			name: "matcher without regex and exists",
			fingerprinter: `
  fp:
    discovery_modules: [system]
    matchers:
      - oid: 1.3.6.1.2.1.1.2
        modules: [if_mib]
`,
			errContains: "exactly one of regex or exists",
		},
		{
			name: "matcher with regex and exists",
			fingerprinter: `
  fp:
    discovery_modules: [system]
    matchers:
      - oid: 1.3.6.1.2.1.1.2
        regex: foo
        exists: true
        modules: [if_mib]
`,
			errContains: "exactly one of regex or exists",
		},
		{
			name: "matcher without modules",
			fingerprinter: `
  fp:
    discovery_modules: [system]
    matchers:
      - oid: 1.3.6.1.2.1.1.2
        exists: true
`,
			errContains: "no modules",
		},
		{
			name: "matcher oid not covered by discovery modules",
			fingerprinter: `
  fp:
    discovery_modules: [system]
    matchers:
      - oid: 1.3.6.1.2.1.1.5
        exists: true
        modules: [if_mib]
`,
			errContains: "not collected by any discovery module",
		},
		{
			name: "matcher oid on non-dotted boundary is not covered",
			fingerprinter: `
  fp:
    discovery_modules: [lldp]
    matchers:
      - oid: 1.0.8802.1.1.2.1.41
        exists: true
        modules: [if_mib]
`,
			errContains: "not collected by any discovery module",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &Config{}
			content := fingerprintBaseModules + "\nfingerprinters:" + c.fingerprinter
			if err := yaml.UnmarshalStrict([]byte(content), cfg); err != nil {
				t.Fatalf("Error unmarshaling config: %v", err)
			}
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.errContains)
			}
			if !strings.Contains(err.Error(), c.errContains) {
				t.Fatalf("expected error containing %q, got %v", c.errContains, err)
			}
		})
	}
}

func TestFingerprinterInvalidRegex(t *testing.T) {
	content := fingerprintBaseModules + `
fingerprinters:
  fp:
    discovery_modules: [system]
    matchers:
      - oid: 1.3.6.1.2.1.1.2
        regex: '('
        modules: [if_mib]
`
	cfg := &Config{}
	if err := yaml.UnmarshalStrict([]byte(content), cfg); err == nil {
		t.Fatal("expected invalid regex to fail config parsing")
	}
}

func TestFingerprinterCoverage(t *testing.T) {
	// Matcher OIDs that are covered by a walk or get of a discovery module,
	// either as ancestor or descendant on a dotted boundary.
	content := fingerprintBaseModules + `
fingerprinters:
  fp:
    discovery_modules: [system, lldp]
    matchers:
      # Get entry is a descendant of the matcher oid (scalar .0 instance).
      - oid: 1.3.6.1.2.1.1.2
        exists: true
        modules: [if_mib]
      # Exact get entry.
      - oid: 1.3.6.1.2.1.1.1.0
        exists: true
        modules: [if_mib]
      # Matcher is a descendant of the walk entry.
      - oid: 1.0.8802.1.1.2.1.4.1.1.5
        exists: true
        modules: [if_mib]
      # Matcher is an ancestor of the walk entry.
      - oid: 1.0.8802.1.1.2
        exists: true
        modules: [if_mib]
`
	cfg := &Config{}
	if err := yaml.UnmarshalStrict([]byte(content), cfg); err != nil {
		t.Fatalf("Error unmarshaling config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Unexpected validation error: %v", err)
	}
}

func TestLoadFileValidatesFingerprintersAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	modules := filepath.Join(dir, "modules.yml")
	fingerprinters := filepath.Join(dir, "fingerprinters.yml")
	if err := os.WriteFile(modules, []byte(fingerprintBaseModules), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fingerprinters, []byte(`
fingerprinters:
  fp:
    discovery_modules: [system]
    default_modules: [if_mib]
`), 0o600); err != nil {
		t.Fatal(err)
	}

	logger := promslog.NewNopLogger()
	// Fingerprinters may reference modules defined in another file.
	cfg, err := LoadFile(logger, []string{fingerprinters, modules}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := cfg.Fingerprinters["fp"]; !ok {
		t.Fatal("fingerprinter not loaded")
	}

	// Without the modules file the reference is dangling.
	if _, err := LoadFile(logger, []string{fingerprinters}, false); err == nil {
		t.Fatal("expected dangling module reference to fail loading")
	}
}
