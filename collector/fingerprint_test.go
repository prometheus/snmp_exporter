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
	"context"
	"errors"
	"log/slog"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"
	"go.yaml.in/yaml/v2"

	"github.com/prometheus/snmp_exporter/config"
	"github.com/prometheus/snmp_exporter/scraper"
)

const fingerprintTestConfig = `
modules:
  system:
    get:
      - 1.3.6.1.2.1.1.1.0
      - 1.3.6.1.2.1.1.2.0
    metrics: []
  lldp_probe:
    walk:
      - 1.0.8802.1.1.2.1.3
    metrics: []
  if_mib:
    walk: [1.3.6.1.2.1.2]
    metrics: []
  ubiquiti_unifi:
    walk: [1.3.6.1.4.1.41112.1.6]
    metrics: []
  cisco:
    walk: [1.3.6.1.4.1.9.9]
    metrics: []
  linux:
    walk: [1.3.6.1.4.1.2021]
    metrics: []
  lldp_mib:
    walk: [1.0.8802.1.1.2.1.4]
    metrics: []
fingerprinters:
  system:
    discovery_modules: [system, lldp_probe]
    default_modules: [if_mib]
    matchers:
      - oid: 1.3.6.1.2.1.1.2
        regex: '1\.3\.6\.1\.4\.1\.41112(\..*)?'
        modules: [if_mib, ubiquiti_unifi]
      - oid: 1.3.6.1.2.1.1.2
        regex: '1\.3\.6\.1\.4\.1\.9(\..*)?'
        modules: [if_mib, cisco]
      - oid: 1.3.6.1.2.1.1.1
        regex: 'Linux .*'
        modules: [linux, if_mib]
      - oid: 1.0.8802.1.1.2.1.3
        exists: true
        modules: [lldp_mib]
`

func loadFingerprintTestConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	if err := yaml.UnmarshalStrict([]byte(fingerprintTestConfig), cfg); err != nil {
		t.Fatalf("Error unmarshaling config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Error validating config: %v", err)
	}
	return cfg
}

func sysObjectID(v string) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.1.2.0", Type: gosnmp.ObjectIdentifier, Value: v}
}

func sysDescr(v string) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.1.1.0", Type: gosnmp.OctetString, Value: []byte(v)}
}

func TestNewFingerprint(t *testing.T) {
	cfg := loadFingerprintTestConfig(t)

	fp, err := NewFingerprint("system", cfg.Fingerprinters["system"], cfg.Modules)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var discovery []string
	for _, m := range fp.DiscoveryModules() {
		discovery = append(discovery, m.Name)
	}
	if !reflect.DeepEqual(discovery, []string{"system", "lldp_probe"}) {
		t.Errorf("unexpected discovery modules %v", discovery)
	}

	if _, err := NewFingerprint("system", cfg.Fingerprinters["system"], map[string]*config.Module{}); err == nil {
		t.Error("expected error for missing modules")
	}
	if _, err := NewFingerprint("nil", nil, cfg.Modules); err == nil {
		t.Error("expected error for nil fingerprinter")
	}
}

func TestFingerprintMatch(t *testing.T) {
	cfg := loadFingerprintTestConfig(t)
	fp, err := NewFingerprint("system", cfg.Fingerprinters["system"], cfg.Modules)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cases := []struct {
		name   string
		pdus   []gosnmp.SnmpPDU
		expect []string
	}{
		{
			name:   "no pdus uses default modules",
			pdus:   nil,
			expect: []string{"if_mib"},
		},
		{
			name:   "no matcher hit uses default modules",
			pdus:   []gosnmp.SnmpPDU{sysObjectID(".1.3.6.1.4.1.8072.3.2.10"), sysDescr("FreeBSD")},
			expect: []string{"if_mib"},
		},
		{
			name:   "ubiquiti sysObjectID",
			pdus:   []gosnmp.SnmpPDU{sysObjectID(".1.3.6.1.4.1.41112.1.6.3.3")},
			expect: []string{"if_mib", "ubiquiti_unifi"},
		},
		{
			name:   "regex is anchored",
			pdus:   []gosnmp.SnmpPDU{sysObjectID(".1.3.6.1.4.1.411120")},
			expect: []string{"if_mib"},
		},
		{
			name:   "cisco does not match ubiquiti prefix with 9",
			pdus:   []gosnmp.SnmpPDU{sysObjectID(".1.3.6.1.4.1.9.1.1208")},
			expect: []string{"if_mib", "cisco"},
		},
		{
			name: "union of all matching matchers without duplicates",
			pdus: []gosnmp.SnmpPDU{
				sysObjectID(".1.3.6.1.4.1.41112.1.6.3.3"),
				sysDescr("Linux unifi 4.14.0"),
				{Name: ".1.0.8802.1.1.2.1.3.2.0", Type: gosnmp.OctetString, Value: []byte{0x00, 0x11}},
			},
			expect: []string{"if_mib", "ubiquiti_unifi", "linux", "lldp_mib"},
		},
		{
			name:   "exists matcher only",
			pdus:   []gosnmp.SnmpPDU{{Name: ".1.0.8802.1.1.2.1.3.1.0", Type: gosnmp.Integer, Value: 4}},
			expect: []string{"lldp_mib"},
		},
		{
			name:   "exists ignores NoSuchObject",
			pdus:   []gosnmp.SnmpPDU{{Name: ".1.0.8802.1.1.2.1.3.1.0", Type: gosnmp.NoSuchObject}},
			expect: []string{"if_mib"},
		},
		{
			name:   "pdu names without leading dot",
			pdus:   []gosnmp.SnmpPDU{{Name: "1.3.6.1.2.1.1.2.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.41112.1"}},
			expect: []string{"if_mib", "ubiquiti_unifi"},
		},
		{
			name:   "oid boundary respected",
			pdus:   []gosnmp.SnmpPDU{{Name: ".1.3.6.1.2.1.1.20.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.41112.1"}},
			expect: []string{"if_mib"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := fp.Match(c.pdus, Metrics{})
			var names []string
			for _, m := range got {
				names = append(names, m.Name)
			}
			if !reflect.DeepEqual(names, c.expect) {
				t.Errorf("expected %v, got %v", c.expect, names)
			}
		})
	}
}

func newTestMetrics() Metrics {
	return Metrics{
		SNMPCollectionDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "collection_duration_seconds"}, []string{"module"}),
		SNMPUnexpectedPduType:  prometheus.NewCounter(prometheus.CounterOpts{Name: "unexpected_pdu_type"}),
		SNMPDuration:           prometheus.NewHistogram(prometheus.HistogramOpts{Name: "duration"}),
		SNMPPackets:            prometheus.NewCounter(prometheus.CounterOpts{Name: "packets"}),
		SNMPRetries:            prometheus.NewCounter(prometheus.CounterOpts{Name: "retries"}),
		SNMPInflight:           prometheus.NewGauge(prometheus.GaugeOpts{Name: "inflight"}),
	}
}

// collectResult summarizes the output of a Collect call.
type collectResult struct {
	// Modules for which snmp_scrape_duration_seconds was emitted.
	scraped []string
	// Modules reported by snmp_fingerprint_module_info.
	fingerprinted []string
	errors        int
}

func runCollect(t *testing.T, c *Collector) collectResult {
	t.Helper()
	ch := make(chan prometheus.Metric)
	go func() {
		c.Collect(ch)
		close(ch)
	}()
	res := collectResult{}
	for m := range ch {
		pb := &dto.Metric{}
		if err := m.Write(pb); err != nil {
			res.errors++
			continue
		}
		desc := m.Desc().String()
		labels := map[string]string{}
		for _, l := range pb.GetLabel() {
			labels[l.GetName()] = l.GetValue()
		}
		switch {
		case strings.Contains(desc, `"snmp_scrape_duration_seconds"`):
			res.scraped = append(res.scraped, labels["module"])
		case strings.Contains(desc, `"snmp_fingerprint_module_info"`):
			if labels["fingerprint"] != "system" {
				t.Errorf("unexpected fingerprint label %q", labels["fingerprint"])
			}
			res.fingerprinted = append(res.fingerprinted, labels["module"])
		}
	}
	sort.Strings(res.scraped)
	sort.Strings(res.fingerprinted)
	return res
}

func newFingerprintTestCollector(t *testing.T, explicit []string, conc int, newMock func() *scraper.MockSNMPScraper) *Collector {
	t.Helper()
	cfg := loadFingerprintTestConfig(t)
	fp, err := NewFingerprint("system", cfg.Fingerprinters["system"], cfg.Modules)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var modules []*NamedModule
	for _, m := range explicit {
		modules = append(modules, NewNamedModule(m, cfg.Modules[m]))
	}
	auth := config.DefaultAuth
	c := New(context.Background(), "target", "public_v2", "", "", &auth, modules, promslog.NewNopLogger(), newTestMetrics(), conc, false).
		WithFingerprint(fp)
	c.newScraper = func(*slog.Logger, string, string, bool) (scraper.SNMPScraper, error) {
		return newMock(), nil
	}
	return c
}

func ubiquitiMock() *scraper.MockSNMPScraper {
	return scraper.NewMockSNMPScraper(
		map[string]gosnmp.SnmpPDU{
			"1.3.6.1.2.1.1.2.0": sysObjectID(".1.3.6.1.4.1.41112.1.6.3.3"),
		},
		nil,
	)
}

func TestCollectWithFingerprint(t *testing.T) {
	mock := ubiquitiMock()
	c := newFingerprintTestCollector(t, nil, 1, func() *scraper.MockSNMPScraper { return mock })

	res := runCollect(t, c)
	if res.errors != 0 {
		t.Fatalf("unexpected %d error metrics", res.errors)
	}
	if want := []string{"if_mib", "lldp_probe", "system", "ubiquiti_unifi"}; !reflect.DeepEqual(res.scraped, want) {
		t.Errorf("scraped modules: want %v, got %v", want, res.scraped)
	}
	if want := []string{"if_mib", "ubiquiti_unifi"}; !reflect.DeepEqual(res.fingerprinted, want) {
		t.Errorf("fingerprinted modules: want %v, got %v", want, res.fingerprinted)
	}
	// Discovery modules must have been walked before the matched modules.
	walks := mock.CallWalk()
	if want := []string{"1.0.8802.1.1.2.1.3"}; !reflect.DeepEqual(walks[:1], want) {
		t.Errorf("expected discovery walk first, got %v", walks)
	}
	for _, w := range walks {
		if w == "1.3.6.1.4.1.9.9" {
			t.Error("cisco module must not be scraped")
		}
	}
}

func TestCollectWithFingerprintAndExplicitModules(t *testing.T) {
	c := newFingerprintTestCollector(t, []string{"if_mib", "cisco"}, 1, ubiquitiMock)

	res := runCollect(t, c)
	// if_mib is requested explicitly and via fingerprint, scraped only once.
	if want := []string{"cisco", "if_mib", "lldp_probe", "system", "ubiquiti_unifi"}; !reflect.DeepEqual(res.scraped, want) {
		t.Errorf("scraped modules: want %v, got %v", want, res.scraped)
	}
}

func TestCollectWithFingerprintConcurrent(t *testing.T) {
	c := newFingerprintTestCollector(t, nil, 4, ubiquitiMock)

	res := runCollect(t, c)
	if want := []string{"if_mib", "lldp_probe", "system", "ubiquiti_unifi"}; !reflect.DeepEqual(res.scraped, want) {
		t.Errorf("scraped modules: want %v, got %v", want, res.scraped)
	}
}

func TestCollectWithFingerprintDiscoveryError(t *testing.T) {
	newMock := func() *scraper.MockSNMPScraper {
		m := ubiquitiMock()
		m.GetError = errors.New("timeout")
		return m
	}
	c := newFingerprintTestCollector(t, nil, 1, newMock)

	res := runCollect(t, c)
	if res.errors == 0 {
		t.Error("expected error metric for failed discovery module")
	}
	// Default modules must not be used when discovery failed, otherwise a
	// transient error would change the set of exported metrics.
	if len(res.fingerprinted) != 0 {
		t.Errorf("expected no fingerprinted modules, got %v", res.fingerprinted)
	}
	for _, m := range res.scraped {
		if m == "if_mib" || m == "ubiquiti_unifi" {
			t.Errorf("module %s must not be scraped after failed discovery", m)
		}
	}
}

func TestCollectWithoutFingerprint(t *testing.T) {
	cfg := loadFingerprintTestConfig(t)
	auth := config.DefaultAuth
	modules := []*NamedModule{NewNamedModule("if_mib", cfg.Modules["if_mib"])}
	c := New(context.Background(), "target", "public_v2", "", "", &auth, modules, promslog.NewNopLogger(), newTestMetrics(), 1, false)
	c.newScraper = func(*slog.Logger, string, string, bool) (scraper.SNMPScraper, error) {
		return ubiquitiMock(), nil
	}

	res := runCollect(t, c)
	if want := []string{"if_mib"}; !reflect.DeepEqual(res.scraped, want) {
		t.Errorf("scraped modules: want %v, got %v", want, res.scraped)
	}
	if len(res.fingerprinted) != 0 {
		t.Errorf("expected no fingerprint metrics, got %v", res.fingerprinted)
	}
}

func TestFingerprintMatchWithoutDefaultModules(t *testing.T) {
	cfg := loadFingerprintTestConfig(t)
	fp := *cfg.Fingerprinters["system"]
	fp.DefaultModules = nil
	cfg.Fingerprinters["system"] = &fp
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default_modules must be optional: %v", err)
	}
	f, err := NewFingerprint("system", &fp, cfg.Modules)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := f.Match([]gosnmp.SnmpPDU{sysObjectID(".1.3.6.1.4.1.8072.3.2.10")}, Metrics{}); len(got) != 0 {
		t.Errorf("expected no modules, got %d", len(got))
	}

	// Only the discovery modules are scraped and no fingerprint metric is
	// emitted.
	c := newFingerprintTestCollector(t, nil, 1, func() *scraper.MockSNMPScraper {
		return scraper.NewMockSNMPScraper(map[string]gosnmp.SnmpPDU{
			"1.3.6.1.2.1.1.2.0": sysObjectID(".1.3.6.1.4.1.8072.3.2.10"),
		}, nil)
	})
	c.fingerprint = f
	res := runCollect(t, c)
	if want := []string{"lldp_probe", "system"}; !reflect.DeepEqual(res.scraped, want) {
		t.Errorf("scraped modules: want %v, got %v", want, res.scraped)
	}
	if len(res.fingerprinted) != 0 {
		t.Errorf("expected no fingerprint metrics, got %v", res.fingerprinted)
	}
}
