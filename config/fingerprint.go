// Copyright The Prometheus Authors
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
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Fingerprinter selects the modules to scrape for a target based on the
// values returned by a set of discovery modules.
type Fingerprinter struct {
	// Modules that are scraped first. Their results are exported as usual
	// and are used to evaluate the matchers.
	DiscoveryModules []string `yaml:"discovery_modules"`
	// Modules that are scraped when no matcher matches.
	DefaultModules []string `yaml:"default_modules,omitempty"`
	// All matching matchers contribute their modules (union).
	Matchers []*FingerprintMatcher `yaml:"matchers,omitempty"`
}

// FingerprintMatcher matches against the PDUs returned for an OID subtree by
// the discovery modules.
type FingerprintMatcher struct {
	// Numeric OID. Matches all PDUs equal to or below this OID.
	Oid string `yaml:"oid"`
	// Anchored regular expression matched against the value of the PDUs.
	// Matches if any PDU value matches.
	Regex Regexp `yaml:"regex,omitempty"`
	// Matches if any PDU is returned for the OID.
	Exists bool `yaml:"exists,omitempty"`
	// Modules to scrape when the matcher matches.
	Modules []string `yaml:"modules"`
}

var numericOidRE = regexp.MustCompile(`^\d+(\.\d+)*$`)

// IsNumericOid reports whether oid is a numeric OID without a leading dot.
func IsNumericOid(oid string) bool {
	return numericOidRE.MatchString(oid)
}

// Validate checks cross references in the config. It must be called after
// all config files have been loaded, as fingerprinters may reference modules
// defined in other files.
func (c *Config) Validate() error {
	names := make([]string, 0, len(c.Fingerprinters))
	for name := range c.Fingerprinters {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := c.validateFingerprinter(c.Fingerprinters[name]); err != nil {
			return fmt.Errorf("fingerprinter %q: %w", name, err)
		}
	}
	return nil
}

func (c *Config) validateFingerprinter(fp *Fingerprinter) error {
	if fp == nil || len(fp.DiscoveryModules) == 0 {
		return fmt.Errorf("no discovery_modules defined")
	}
	var discoveryOids []string
	for _, m := range fp.DiscoveryModules {
		module, ok := c.Modules[m]
		if !ok {
			return fmt.Errorf("unknown discovery module %q", m)
		}
		discoveryOids = append(discoveryOids, module.Walk...)
		discoveryOids = append(discoveryOids, module.Get...)
	}
	for _, m := range fp.DefaultModules {
		if _, ok := c.Modules[m]; !ok {
			return fmt.Errorf("unknown default module %q", m)
		}
	}
	for i, matcher := range fp.Matchers {
		if err := c.validateMatcher(matcher, discoveryOids); err != nil {
			return fmt.Errorf("matcher %d: %w", i, err)
		}
	}
	return nil
}

func (c *Config) validateMatcher(m *FingerprintMatcher, discoveryOids []string) error {
	if m == nil {
		return fmt.Errorf("empty matcher")
	}
	if m.Oid == "" {
		return fmt.Errorf("oid must be set")
	}
	if !IsNumericOid(m.Oid) {
		return fmt.Errorf("oid %q must be numeric", m.Oid)
	}
	if (m.Regex.Regexp != nil) == m.Exists {
		return fmt.Errorf("exactly one of regex or exists must be set")
	}
	if len(m.Modules) == 0 {
		return fmt.Errorf("no modules defined")
	}
	for _, mod := range m.Modules {
		if _, ok := c.Modules[mod]; !ok {
			return fmt.Errorf("unknown module %q", mod)
		}
	}
	covered := false
	for _, oid := range discoveryOids {
		if OidContains(oid, m.Oid) || OidContains(m.Oid, oid) {
			covered = true
			break
		}
	}
	if !covered {
		return fmt.Errorf("oid %s is not collected by any discovery module", m.Oid)
	}
	return nil
}

// OidContains reports whether oid equals parent or lies below it in the OID
// tree. Both OIDs are numeric without a leading dot.
func OidContains(parent, oid string) bool {
	return oid == parent || strings.HasPrefix(oid, parent+".")
}
