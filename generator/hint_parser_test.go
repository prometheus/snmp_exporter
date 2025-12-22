// Copyright 2025 The Prometheus Authors
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
	"reflect"
	"testing"

	"github.com/prometheus/snmp_exporter/config"
)

func TestParseDisplayHint(t *testing.T) {
	tests := []struct {
		name    string
		hint    string
		want    []config.FormatOp
		wantErr bool
	}{
		{
			name: "InetAddressIPv4 - 1d.1d.1d.1d",
			hint: "1d.1d.1d.1d",
			want: []config.FormatOp{
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d"},
			},
		},
		{
			name: "InetAddressIPv4z - 1d.1d.1d.1d%4d",
			hint: "1d.1d.1d.1d%4d",
			want: []config.FormatOp{
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "%"},
				{Take: 4, Fmt: "d"},
			},
		},
		{
			name: "InetAddressIPv6 - 2x:2x:2x:2x:2x:2x:2x:2x",
			hint: "2x:2x:2x:2x:2x:2x:2x:2x",
			want: []config.FormatOp{
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x"},
			},
		},
		{
			name: "InetAddressIPv6z - 2x:2x:2x:2x:2x:2x:2x:2x%4d",
			hint: "2x:2x:2x:2x:2x:2x:2x:2x%4d",
			want: []config.FormatOp{
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: "%"},
				{Take: 4, Fmt: "d"},
			},
		},
		{
			name: "PhysAddress - 1x:",
			hint: "1x:",
			want: []config.FormatOp{
				{Take: 1, Fmt: "x", Sep: ":"},
			},
		},
		{
			name: "DisplayString - 255a",
			hint: "255a",
			want: []config.FormatOp{
				{Take: 255, Fmt: "a"},
			},
		},
		{
			name: "UTF8 string - 255t (SNMP-TARGET-MIB, VMWARE-VRNI-MIB)",
			hint: "255t",
			want: []config.FormatOp{
				{Take: 255, Fmt: "t"},
			},
		},
		{
			name: "Simple decimal - 1d",
			hint: "1d",
			want: []config.FormatOp{
				{Take: 1, Fmt: "d"},
			},
		},
		{
			name: "Simple hex - 2x (TN-TC)",
			hint: "2x",
			want: []config.FormatOp{
				{Take: 2, Fmt: "x"},
			},
		},
		{
			name: "Octal format - 1o",
			hint: "1o",
			want: []config.FormatOp{
				{Take: 1, Fmt: "o"},
			},
		},
		{
			name: "Hex with dash separator - 1x- (ALCATEL-IND1-ISIS-SPB-MIB)",
			hint: "1x-",
			want: []config.FormatOp{
				{Take: 1, Fmt: "x", Sep: "-"},
			},
		},
		{
			name: "Star prefix with separator and terminator (SNMPv2-TM SnmpOSIAddress variant)",
			hint: "*1x:/",
			want: []config.FormatOp{
				{Take: 1, StarPrefix: true, Fmt: "x", Sep: ":", Term: "/"},
			},
		},
		{
			name: "Star prefix without terminator",
			hint: "*1x:",
			want: []config.FormatOp{
				{Take: 1, StarPrefix: true, Fmt: "x", Sep: ":"},
			},
		},
		{
			name: "Multi-digit octet length - 128a (CIENA-WS-TYPEDEFS-MIB)",
			hint: "128a",
			want: []config.FormatOp{
				{Take: 128, Fmt: "a"},
			},
		},
		{
			name: "DateAndTime-like complex hint",
			hint: "2d-1d-1d,1d:1d:1d.1d",
			want: []config.FormatOp{
				{Take: 2, Fmt: "d", Sep: "-"},
				{Take: 1, Fmt: "d", Sep: "-"},
				{Take: 1, Fmt: "d", Sep: ","},
				{Take: 1, Fmt: "d", Sep: ":"},
				{Take: 1, Fmt: "d", Sep: ":"},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d"},
			},
		},
		{
			name: "UUID format - 4x-2x-2x-1x1x-6x (UUID-TC-MIB)",
			hint: "4x-2x-2x-1x1x-6x",
			want: []config.FormatOp{
				{Take: 4, Fmt: "x", Sep: "-"},
				{Take: 2, Fmt: "x", Sep: "-"},
				{Take: 2, Fmt: "x", Sep: "-"},
				{Take: 1, Fmt: "x"},
				{Take: 1, Fmt: "x", Sep: "-"},
				{Take: 6, Fmt: "x"},
			},
		},
		{
			name: "UUID variant - 4x-2x-2x-2x-6x (TIMETRA-TC-MIB, RUCKUS-TC-MIB)",
			hint: "4x-2x-2x-2x-6x",
			want: []config.FormatOp{
				{Take: 4, Fmt: "x", Sep: "-"},
				{Take: 2, Fmt: "x", Sep: "-"},
				{Take: 2, Fmt: "x", Sep: "-"},
				{Take: 2, Fmt: "x", Sep: "-"},
				{Take: 6, Fmt: "x"},
			},
		},
		{
			name: "IPv4 with prefix - 1d.1d.1d.1d/1d (VIPTELA-OPER-BGP, SNMPv2-TM)",
			hint: "1d.1d.1d.1d/1d",
			want: []config.FormatOp{
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "/"},
				{Take: 1, Fmt: "d"},
			},
		},
		{
			name: "IPv4 with port - 1d.1d.1d.1d:2d (MPLS-TC-STD-MIB, TRANSPORT-ADDRESS-MIB)",
			hint: "1d.1d.1d.1d:2d",
			want: []config.FormatOp{
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: ":"},
				{Take: 2, Fmt: "d"},
			},
		},
		{
			name: "Version number - 4d.4d.4d.4d (RAISECOM-SYSTEM-MIB)",
			hint: "4d.4d.4d.4d",
			want: []config.FormatOp{
				{Take: 4, Fmt: "d", Sep: "."},
				{Take: 4, Fmt: "d", Sep: "."},
				{Take: 4, Fmt: "d", Sep: "."},
				{Take: 4, Fmt: "d"},
			},
		},
		{
			name: "VPN RD - 2x-1d.1d.1d.1d:2d (JUNIPER-VPN-MIB)",
			hint: "2x-1d.1d.1d.1d:2d",
			want: []config.FormatOp{
				{Take: 2, Fmt: "x", Sep: "-"},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: ":"},
				{Take: 2, Fmt: "d"},
			},
		},
		{
			name: "Simple date - 2d-1d-1d (ADVA-MIB)",
			hint: "2d-1d-1d",
			want: []config.FormatOp{
				{Take: 2, Fmt: "d", Sep: "-"},
				{Take: 1, Fmt: "d", Sep: "-"},
				{Take: 1, Fmt: "d"},
			},
		},
		{
			name: "MAC with dash - 1x-1x-1x-1x-1x-1x (TPLINK-TC-MIB)",
			hint: "1x-1x-1x-1x-1x-1x",
			want: []config.FormatOp{
				{Take: 1, Fmt: "x", Sep: "-"},
				{Take: 1, Fmt: "x", Sep: "-"},
				{Take: 1, Fmt: "x", Sep: "-"},
				{Take: 1, Fmt: "x", Sep: "-"},
				{Take: 1, Fmt: "x", Sep: "-"},
				{Take: 1, Fmt: "x"},
			},
		},
		{
			name: "Bridge ID - 2d.1x:1x:1x:1x:1x:1x (PRVT-SPANNING-TREE-MIB)",
			hint: "2d.1x:1x:1x:1x:1x:1x",
			want: []config.FormatOp{
				{Take: 2, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "x", Sep: ":"},
				{Take: 1, Fmt: "x", Sep: ":"},
				{Take: 1, Fmt: "x", Sep: ":"},
				{Take: 1, Fmt: "x", Sep: ":"},
				{Take: 1, Fmt: "x", Sep: ":"},
				{Take: 1, Fmt: "x"},
			},
		},
		{
			name: "DHCP format - 1d,1d,1x:1x:1x:1x:1x:1x (CISCO-IETF-DHCP-SERVER-MIB)",
			hint: "1d,1d,1x:1x:1x:1x:1x:1x",
			want: []config.FormatOp{
				{Take: 1, Fmt: "d", Sep: ","},
				{Take: 1, Fmt: "d", Sep: ","},
				{Take: 1, Fmt: "x", Sep: ":"},
				{Take: 1, Fmt: "x", Sep: ":"},
				{Take: 1, Fmt: "x", Sep: ":"},
				{Take: 1, Fmt: "x", Sep: ":"},
				{Take: 1, Fmt: "x", Sep: ":"},
				{Take: 1, Fmt: "x"},
			},
		},
		{
			name: "IPv6-mapped IPv4 - 2x:2x:2x:2x:2x:2x:1d.1d.1d.1d (WATCHGUARD-IPSEC-SA-MON-MIB-EXT)",
			hint: "2x:2x:2x:2x:2x:2x:1d.1d.1d.1d",
			want: []config.FormatOp{
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 2, Fmt: "x", Sep: ":"},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d", Sep: "."},
				{Take: 1, Fmt: "d"},
			},
		},
		{
			name: "Timezone offset - 1a1d:1d (SNMPv2-TC DateAndTime suffix)",
			hint: "1a1d:1d",
			want: []config.FormatOp{
				{Take: 1, Fmt: "a"},
				{Take: 1, Fmt: "d", Sep: ":"},
				{Take: 1, Fmt: "d"},
			},
		},
		{
			name: "Leading zero in octet length - 02x (IMM-MIB)",
			hint: "02x",
			want: []config.FormatOp{
				{Take: 2, Fmt: "x"},
			},
		},
		{
			name: "Zero octet length - 0a (TRANSPORT-ADDRESS-MIB bracket literal)",
			hint: "0a",
			want: []config.FormatOp{
				{Take: 0, Fmt: "a"},
			},
		},
		{
			name:    "Empty hint",
			hint:    "",
			wantErr: true,
		},
		{
			name:    "Missing octet length",
			hint:    "d",
			wantErr: true,
		},
		{
			name:    "Invalid format character",
			hint:    "1z",
			wantErr: true,
		},
		{
			name:    "Missing format character",
			hint:    "1",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDisplayHint(tt.hint)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDisplayHint(%q) error = %v, wantErr %v", tt.hint, err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseDisplayHint(%q) = %+v, want %+v", tt.hint, got, tt.want)
			}
		})
	}
}
