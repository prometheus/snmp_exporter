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
	"reflect"
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestCacheClient(t *testing.T) {
	cases := []struct {
		name          string
		getResponse   map[string]gosnmp.SnmpPDU
		walkResponses map[string][]gosnmp.SnmpPDU
		getRequest    [][]string
		walkRequest   []string
		getCall       []string
		walkCall      []string
	}{
		{
			name: "basic",
			getResponse: map[string]gosnmp.SnmpPDU{
				"1.3.6.1.2.1.1.1.0": {Type: gosnmp.OctetString, Name: "1.3.6.1.2.1.1.1.0", Value: "Test Device"},
			},
			walkResponses: map[string][]gosnmp.SnmpPDU{
				"1.3.6.1.2.1.2.2.1.2": {
					{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.2.2.1.2.1", Value: "lo"},
					{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.2.2.1.2.2", Value: "Intel Corporation 82540EM Gigabit Ethernet Controller"},
					{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.2.2.1.2.3", Value: "Intel Corporation 82540EM Gigabit Ethernet Controller"},
				},
				"1.3.6.1.2.1.31.1.1.1.18": {
					{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.31.1.1.1.18.1", Value: "lo"},
					{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.31.1.1.1.18.2", Value: "eth0"},
					{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.31.1.1.1.18.3", Value: "swp1"},
				},
			},
			getRequest:  [][]string{{"1.3.6.1.2.1.1.1.0"}},
			walkRequest: []string{"1.3.6.1.2.1.2.2.1.2", "1.3.6.1.2.1.31.1.1.1.18"},
			getCall:     []string{"1.3.6.1.2.1.1.1.0"},
			walkCall:    []string{"1.3.6.1.2.1.2.2.1.2", "1.3.6.1.2.1.31.1.1.1.18"},
		},
		{
			name: "de-duplicate in walk",
			walkResponses: map[string][]gosnmp.SnmpPDU{
				"1.3.6.1.2.1.2.2.1.2": {
					{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.2.2.1.2.1", Value: "lo"},
					{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.2.2.1.2.2", Value: "Intel Corporation 82540EM Gigabit Ethernet Controller"},
					{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.2.2.1.2.3", Value: "Intel Corporation 82540EM Gigabit Ethernet Controller"},
				},
				"1.3.6.1.2.1.31.1.1.1.18": {
					{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.31.1.1.1.18.1", Value: "lo"},
					{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.31.1.1.1.18.2", Value: "eth0"},
					{Type: gosnmp.OctetString, Name: ".1.3.6.1.2.1.31.1.1.1.18.3", Value: "swp1"},
				},
			},
			walkRequest: []string{"1.3.6.1.2.1.2.2.1.2", "1.3.6.1.2.1.31.1.1.1.18", "1.3.6.1.2.1.2.2.1.2", "1.3.6.1.2.1.31.1.1.1.18"},
			getCall:     []string{},
			walkCall:    []string{"1.3.6.1.2.1.2.2.1.2", "1.3.6.1.2.1.31.1.1.1.18"},
		},
	}

	for _, c := range cases {
		tt := c
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockSNMPScraper(tt.getResponse, tt.walkResponses)
			client := NewCacheClient(mock)
			for _, oids := range tt.getRequest {
				res, err := client.Get(oids)
				if err != nil {
					t.Errorf("Get returned an error: %v", err)
				}
				pdus := res.Variables
				if len(pdus) != len(oids) {
					t.Errorf("Expected %d PDUs, got %d", len(oids), len(pdus))
				}
			}
			for _, oid := range tt.walkRequest {
				res, err := client.WalkAll(oid)
				if err != nil {
					t.Errorf("WalkAll returned an error: %v", err)
				}
				if len(res) != len(tt.walkResponses[oid]) {
					t.Errorf("Expected %d PDUs, got %d", len(tt.walkResponses[oid]), len(res))
				}
			}
			if !reflect.DeepEqual(mock.CallGet(), tt.getCall) {
				t.Errorf("Expected get call %v, got %v", tt.getCall, mock.CallGet())
			}
			if !reflect.DeepEqual(mock.CallWalk(), tt.walkCall) {
				t.Errorf("Expected walk call %v, got %v", tt.walkCall, mock.CallWalk())
			}
		})
	}
}
