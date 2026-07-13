// Copyright 2024 The Prometheus Authors
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

package scraper

import (
	"slices"
	"sync"

	"github.com/gosnmp/gosnmp"
)

// mockCalls records Get/Walk invocations. One instance is shared between a
// mock and all its clones (guarded by mu) so tests can assert aggregate
// behavior such as "each subtree walked exactly once".
type mockCalls struct {
	mu   sync.Mutex
	get  []string
	walk []string
}

func NewMockSNMPScraper(get map[string]gosnmp.SnmpPDU, walk map[string][]gosnmp.SnmpPDU) *mockSNMPScraper {
	return &mockSNMPScraper{
		GetResponses:  get,
		WalkResponses: walk,
		calls: &mockCalls{
			get:  make([]string, 0),
			walk: make([]string, 0),
		},
	}
}

type mockSNMPScraper struct {
	GetResponses  map[string]gosnmp.SnmpPDU
	WalkResponses map[string][]gosnmp.SnmpPDU
	ConnectError  error
	CloseError    error

	calls *mockCalls
}

func (m *mockSNMPScraper) CallGet() []string {
	m.calls.mu.Lock()
	defer m.calls.mu.Unlock()
	return slices.Clone(m.calls.get)
}

func (m *mockSNMPScraper) CallWalk() []string {
	m.calls.mu.Lock()
	defer m.calls.mu.Unlock()
	return slices.Clone(m.calls.walk)
}

func (m *mockSNMPScraper) Get(oids []string) (*gosnmp.SnmpPacket, error) {
	pdus := make([]gosnmp.SnmpPDU, 0, len(oids))
	for _, oid := range oids {
		if response, exists := m.GetResponses[oid]; exists {
			pdus = append(pdus, response)
		} else {
			pdus = append(pdus, gosnmp.SnmpPDU{
				Name:  oid,
				Type:  gosnmp.NoSuchObject,
				Value: nil,
			})
		}
	}
	m.calls.mu.Lock()
	m.calls.get = append(m.calls.get, oids...)
	m.calls.mu.Unlock()
	return &gosnmp.SnmpPacket{
		Variables: pdus,
		Error:     gosnmp.NoError,
	}, nil
}

func (m *mockSNMPScraper) WalkAll(baseOID string) ([]gosnmp.SnmpPDU, error) {
	m.calls.mu.Lock()
	m.calls.walk = append(m.calls.walk, baseOID)
	m.calls.mu.Unlock()
	if pdus, exists := m.WalkResponses[baseOID]; exists {
		return pdus, nil
	}
	return nil, nil
}

func (m *mockSNMPScraper) Connect() error {
	return m.ConnectError
}

func (m *mockSNMPScraper) Close() error {
	return m.CloseError
}

func (m *mockSNMPScraper) SetOptions(...func(*gosnmp.GoSNMP)) {
}

// Clone returns a new mock sharing the same response maps (safe for parallel reads)
// and the same call record, so CallGet/CallWalk on the parent report calls made
// through clones too.
func (m *mockSNMPScraper) Clone() SNMPScraper {
	return &mockSNMPScraper{
		GetResponses:  m.GetResponses,
		WalkResponses: m.WalkResponses,
		ConnectError:  m.ConnectError,
		CloseError:    m.CloseError,
		calls:         m.calls,
	}
}
