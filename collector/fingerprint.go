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

package collector

import (
	"fmt"
	"strings"

	"github.com/gosnmp/gosnmp"

	"github.com/prometheus/snmp_exporter/config"
)

// Fingerprint is a fingerprinter with all referenced modules resolved, so it
// can be used without holding the config lock.
type Fingerprint struct {
	name      string
	fp        *config.Fingerprinter
	discovery []*NamedModule
	modules   map[string]*NamedModule
}

// NewFingerprint resolves all modules referenced by fp.
func NewFingerprint(name string, fp *config.Fingerprinter, modules map[string]*config.Module) (*Fingerprint, error) {
	if fp == nil {
		return nil, fmt.Errorf("fingerprinter %q is nil", name)
	}
	f := &Fingerprint{
		name:    name,
		fp:      fp,
		modules: map[string]*NamedModule{},
	}
	resolve := func(m string) (*NamedModule, error) {
		if nm, ok := f.modules[m]; ok {
			return nm, nil
		}
		module, ok := modules[m]
		if !ok {
			return nil, fmt.Errorf("fingerprinter %q references unknown module %q", name, m)
		}
		nm := NewNamedModule(m, module)
		f.modules[m] = nm
		return nm, nil
	}
	for _, m := range fp.DiscoveryModules {
		nm, err := resolve(m)
		if err != nil {
			return nil, err
		}
		f.discovery = append(f.discovery, nm)
	}
	for _, m := range fp.DefaultModules {
		if _, err := resolve(m); err != nil {
			return nil, err
		}
	}
	for _, matcher := range fp.Matchers {
		for _, m := range matcher.Modules {
			if _, err := resolve(m); err != nil {
				return nil, err
			}
		}
	}
	return f, nil
}

// Name returns the name of the fingerprinter.
func (f *Fingerprint) Name() string {
	return f.name
}

// DiscoveryModules returns the modules to scrape before matching.
func (f *Fingerprint) DiscoveryModules() []*NamedModule {
	return f.discovery
}

// Match evaluates all matchers against the PDUs returned by the discovery
// modules. It returns the union of the modules of all matching matchers in
// configuration order, or the default modules when nothing matched.
func (f *Fingerprint) Match(pdus []gosnmp.SnmpPDU, metrics Metrics) []*NamedModule {
	var (
		result []*NamedModule
		seen   = map[string]bool{}
	)
	for _, matcher := range f.fp.Matchers {
		if !matcherMatches(matcher, pdus, metrics) {
			continue
		}
		for _, m := range matcher.Modules {
			if seen[m] {
				continue
			}
			seen[m] = true
			result = append(result, f.modules[m])
		}
	}
	if len(result) > 0 {
		return result
	}
	for _, m := range f.fp.DefaultModules {
		if seen[m] {
			continue
		}
		seen[m] = true
		result = append(result, f.modules[m])
	}
	return result
}

func matcherMatches(m *config.FingerprintMatcher, pdus []gosnmp.SnmpPDU, metrics Metrics) bool {
	for i := range pdus {
		pdu := &pdus[i]
		if pdu.Type == gosnmp.NoSuchObject || pdu.Type == gosnmp.NoSuchInstance || pdu.Type == gosnmp.EndOfMibView {
			continue
		}
		if !config.OidContains(m.Oid, strings.TrimPrefix(pdu.Name, ".")) {
			continue
		}
		if m.Exists {
			return true
		}
		if m.Regex.MatchString(pduValueAsString(pdu, "DisplayString", "", metrics)) {
			return true
		}
	}
	return false
}
