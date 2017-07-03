package main

import (
	"reflect"
	"testing"

	"github.com/soniah/gosnmp"

	"github.com/prometheus/snmp_exporter/config"
)

func TestOidToList(t *testing.T) {
	cases := []struct {
		oid    string
		result []int
	}{
		{
			oid:    "1",
			result: []int{1},
		},
		{
			oid:    "1.2.3.4",
			result: []int{1, 2, 3, 4},
		},
	}
	for _, c := range cases {
		got := oidToList(c.oid)
		if !reflect.DeepEqual(got, c.result) {
			t.Errorf("oidToList(%v): got %v, want %v", c.oid, got, c.result)
		}
	}
}

func TestSplitOid(t *testing.T) {
	cases := []struct {
		oid        []int
		count      int
		resultHead []int
		resultTail []int
	}{
		{
			oid:        []int{1, 2, 3, 4},
			count:      2,
			resultHead: []int{1, 2},
			resultTail: []int{3, 4},
		},
		{
			oid:        []int{1, 2},
			count:      4,
			resultHead: []int{1, 2, 0, 0},
			resultTail: []int{},
		},
		{
			oid:        []int{},
			count:      2,
			resultHead: []int{0, 0},
			resultTail: []int{},
		},
	}
	for _, c := range cases {
		head, tail := splitOid(c.oid, c.count)
		if !reflect.DeepEqual(head, c.resultHead) || !reflect.DeepEqual(tail, c.resultTail) {
			t.Errorf("splitOid(%v, %d): got [%v, %v], want [%v, %v]", c.oid, c.count, head, tail, c.resultHead, c.resultTail)
		}
	}
}

func TestPduValueAsString(t *testing.T) {
	cases := []struct {
		pdu    *gosnmp.SnmpPDU
		typ    string
		result string
	}{
		{
			pdu:    &gosnmp.SnmpPDU{Value: int(-1)},
			result: "-1",
		},
		{
			pdu:    &gosnmp.SnmpPDU{Value: uint(1)},
			result: "1",
		},
		{
			pdu:    &gosnmp.SnmpPDU{Value: uint64(1)},
			result: "1",
		},
		{
			pdu:    &gosnmp.SnmpPDU{Value: int64(-1000000000000)},
			result: "-1000000000000",
		},
		{
			pdu:    &gosnmp.SnmpPDU{Value: ".1.2.3.4", Type: gosnmp.ObjectIdentifier},
			result: "1.2.3.4",
		},
		{
			pdu:    &gosnmp.SnmpPDU{Value: "1.2.3.4", Type: gosnmp.IPAddress},
			result: "1.2.3.4",
		},
		{
			pdu:    &gosnmp.SnmpPDU{Value: []byte{}},
			result: "",
		},
		{
			pdu:    &gosnmp.SnmpPDU{Value: []byte{65, 66}},
			typ:    "DisplayString",
			result: "AB",
		},
		{
			pdu:    &gosnmp.SnmpPDU{Value: []byte{127, 128, 255, 0}},
			result: "0x7F80FF00",
		},
		{
			pdu:    &gosnmp.SnmpPDU{Value: []byte{127, 128, 255, 0}},
			typ:    "OctetString",
			result: "0x7F80FF00",
		},
		{
			pdu:    &gosnmp.SnmpPDU{Value: []byte{1, 2, 3, 4}},
			typ:    "IpAddr",
			result: "1.2.3.4",
		},
		{
			pdu:    &gosnmp.SnmpPDU{Value: nil},
			result: "",
		},
	}
	for _, c := range cases {
		got := pduValueAsString(c.pdu, c.typ)
		if !reflect.DeepEqual(got, c.result) {
			t.Errorf("pduValueAsString(%v, %q): got %q, want %q", c.pdu, c.typ, got, c.result)
		}
	}
}

func TestIndexesToLabels(t *testing.T) {
	cases := []struct {
		oid      []int
		metric   config.Metric
		oidToPdu map[string]gosnmp.SnmpPDU
		result   map[string]string
	}{
		{
			oid:      []int{},
			metric:   config.Metric{},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{},
		},
		{
			oid:      []int{4},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "gauge"}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "4"},
		},
		{
			oid: []int{3, 4},
			metric: config.Metric{
				Indexes: []*config.Index{{Labelname: "a", Type: "gauge"}, {Labelname: "b", Type: "gauge"}},
				Lookups: []*config.Lookup{{Labels: []string{"a", "b"}, Labelname: "l", Oid: "1.2"}},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{"1.2.3.4": gosnmp.SnmpPDU{Value: "eth0"}},
			result:   map[string]string{"a": "3", "b": "4", "l": "eth0"},
		},
		{
			oid: []int{4},
			metric: config.Metric{
				Indexes: []*config.Index{{Labelname: "l", Type: "gauge"}},
				Lookups: []*config.Lookup{{Labels: []string{"l"}, Labelname: "l", Oid: "1.2.3"}},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{"1.2.3.4": gosnmp.SnmpPDU{Value: "eth0"}},
			result:   map[string]string{"l": "eth0"},
		},
		{
			oid: []int{4},
			metric: config.Metric{
				Indexes: []*config.Index{{Labelname: "l", Type: "gauge"}},
				Lookups: []*config.Lookup{{Labels: []string{"l"}, Labelname: "l", Oid: "1.2.3", Type: "IpAddr"}},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{"1.2.3.4": gosnmp.SnmpPDU{Value: []byte{5, 6, 7, 8}}},
			result:   map[string]string{"l": "5.6.7.8"},
		},
		{
			oid: []int{4},
			metric: config.Metric{
				Indexes: []*config.Index{{Labelname: "l", Type: "gauge"}},
				Lookups: []*config.Lookup{{Labels: []string{"l"}, Labelname: "l", Oid: "1.2.3"}},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{"1.2.3.4": gosnmp.SnmpPDU{Value: []byte{5, 6, 7, 8}}},
			result:   map[string]string{"l": "0x05060708"},
		},
		{
			oid: []int{4},
			metric: config.Metric{
				Indexes: []*config.Index{{Labelname: "l", Type: "gauge"}},
				Lookups: []*config.Lookup{{Labels: []string{"l"}, Labelname: "l", Oid: "1.2.3"}},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": ""},
		},
		{
			oid:      []int{},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "gauge"}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "0"},
		},
		{
			oid:      []int{1, 255, 0, 0, 0, 16},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "PhysAddress48"}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "01:FF:00:00:00:10"},
		},
		{
			oid:      []int{3, 65, 32, 255},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "OctetString"}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "0x4120FF"},
		},
		{
			oid: []int{3, 65, 32, 255},
			metric: config.Metric{
				Indexes: []*config.Index{{Labelname: "l", Type: "OctetString"}},
				Lookups: []*config.Lookup{{Labels: []string{"l"}, Labelname: "l", Oid: "1"}},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{"1.3.65.32.255": gosnmp.SnmpPDU{Value: "octet"}},
			result:   map[string]string{"l": "octet"},
		},
		{
			oid:      []int{1, 4, 192, 168, 1, 2},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "InetAddress"}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "192.168.1.2"},
		},
		{
			oid: []int{1, 4, 192, 168, 1, 2, 7},
			metric: config.Metric{
				Indexes: []*config.Index{{Labelname: "l", Type: "InetAddress"}, {Labelname: "b", Type: "gauge"}},
				Lookups: []*config.Lookup{{Labels: []string{"l"}, Labelname: "l", Oid: "3"}},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{"3.1.4.192.168.1.2": gosnmp.SnmpPDU{Value: "ipv4"}},
			result:   map[string]string{"l": "ipv4", "b": "7"},
		},
		{
			oid:      []int{2, 16, 42, 6, 29, 128, 0, 1, 0, 3, 0, 0, 0, 0, 0, 1, 1, 52},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "InetAddress"}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "2A06:1D80:0001:0003:0000:0000:0001:0134"},
		},
		{
			oid:      []int{3, 1, 9},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "InetAddress"}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "0x09"},
		},
		{
			oid: []int{2, 16, 42, 6, 29, 128, 0, 1, 0, 3, 0, 0, 0, 0, 0, 1, 1, 52, 7},
			metric: config.Metric{
				Indexes: []*config.Index{{Labelname: "l", Type: "InetAddress"}, {Labelname: "b", Type: "gauge"}},
				Lookups: []*config.Lookup{{Labels: []string{"l"}, Labelname: "l", Oid: "3"}},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{"3.2.16.42.6.29.128.0.1.0.3.0.0.0.0.0.1.1.52": gosnmp.SnmpPDU{Value: "ipv6"}},
			result:   map[string]string{"l": "ipv6", "b": "7"},
		},
		{
			oid:      []int{192, 168, 1, 2},
			metric:   config.Metric{Indexes: []*config.Index{{Labelname: "l", Type: "IpAddr"}}},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result:   map[string]string{"l": "192.168.1.2"},
		},
		{
			oid: []int{0, 1, 2, 3, 4, 16, 42},
			metric: config.Metric{
				Indexes: []*config.Index{
					{Labelname: "a", Type: "InetAddressType"},
					{Labelname: "b", Type: "InetAddressType"},
					{Labelname: "c", Type: "InetAddressType"},
					{Labelname: "d", Type: "InetAddressType"},
					{Labelname: "e", Type: "InetAddressType"},
					{Labelname: "f", Type: "InetAddressType"},
					{Labelname: "g", Type: "InetAddressType"},
				},
			},
			oidToPdu: map[string]gosnmp.SnmpPDU{},
			result: map[string]string{
				"a": "unknown",
				"b": "ipv4",
				"c": "ipv6",
				"d": "ipv4z",
				"e": "ipv6z",
				"f": "dns",
				"g": "42",
			},
		},
	}
	for _, c := range cases {
		got := indexesToLabels(c.oid, &c.metric, c.oidToPdu)
		if !reflect.DeepEqual(got, c.result) {
			t.Errorf("oidToList(%v, %v, %v): got %v, want %v", c.oid, c.metric, c.oidToPdu, got, c.result)
		}
	}
}
