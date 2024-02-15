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
	"strings"

	"github.com/gosnmp/gosnmp"
)

type MockSNMPScraper struct {
	GetResponses     map[string]*gosnmp.SnmpPDU
	WalkAllResponses map[string]gosnmp.SnmpPDU
	ConnectError     error
	CloseError       error
}

func (m *MockSNMPScraper) Get(oids []string) (*gosnmp.SnmpPacket, error) {
	pdus := make([]gosnmp.SnmpPDU, 0, len(oids))
	for _, oid := range oids {
		if response, exists := m.GetResponses[oid]; exists {
			pdus = append(pdus, *response)
		} else {
			pdus = append(pdus, gosnmp.SnmpPDU{
				Name:  oid,
				Type:  gosnmp.NoSuchObject,
				Value: nil,
			})
		}
	}
	return &gosnmp.SnmpPacket{
		Variables: pdus,
		Error:     gosnmp.NoError,
	}, nil
}

func (m *MockSNMPScraper) WalkAll(baseOID string) ([]gosnmp.SnmpPDU, error) {
	var pdus []gosnmp.SnmpPDU
	for k, v := range m.WalkAllResponses {
		if strings.HasPrefix(k, baseOID) {
			pdus = append(pdus, v)
		}
	}
	return pdus, nil

}

func (m *MockSNMPScraper) Connect() error {
	return m.ConnectError
}

func (m *MockSNMPScraper) Close() error {
	return m.CloseError
}

func (m *MockSNMPScraper) SetOptions(...func(*gosnmp.GoSNMP)) {
}
