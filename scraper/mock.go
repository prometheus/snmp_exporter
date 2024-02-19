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
	"github.com/gosnmp/gosnmp"
)

func NewMockSNMPScraper(get map[string]gosnmp.SnmpPDU, walk map[string][]gosnmp.SnmpPDU) *mockSNMPScraper {
	return &mockSNMPScraper{
		GetResponses:  get,
		WalkResponses: walk,
		callGet:       make([]string, 0),
		callWalk:      make([]string, 0),
	}
}

type mockSNMPScraper struct {
	GetResponses  map[string]gosnmp.SnmpPDU
	WalkResponses map[string][]gosnmp.SnmpPDU
	ConnectError  error
	CloseError    error

	callGet  []string
	callWalk []string
}

func (m *mockSNMPScraper) CallGet() []string {
	return m.callGet
}

func (m *mockSNMPScraper) CallWalk() []string {
	return m.callWalk
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
		m.callGet = append(m.callGet, oid)
	}
	return &gosnmp.SnmpPacket{
		Variables: pdus,
		Error:     gosnmp.NoError,
	}, nil
}

func (m *mockSNMPScraper) WalkAll(baseOID string) ([]gosnmp.SnmpPDU, error) {
	m.callWalk = append(m.callWalk, baseOID)
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
