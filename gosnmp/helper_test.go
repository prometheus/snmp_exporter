// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build all || helper
// +build all helper

package gosnmp

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// https://www.scadacore.com/tools/programming-calculators/online-hex-converter/ is useful

func TestParseObjectIdentifier(t *testing.T) {
	oid := []byte{43, 6, 1, 2, 1, 31, 1, 1, 1, 10, 143, 255, 255, 255, 127}
	expected := ".1.3.6.1.2.1.31.1.1.1.10.4294967295"

	buf, err := parseObjectIdentifier(oid)
	if err != nil {
		t.Errorf("parseObjectIdentifier(%v) want %s, error: %v", oid, expected, err)
	}
	result := string(buf)

	if string(result) != expected {
		t.Errorf("parseObjectIdentifier(%v) = %s, want %s", oid, result, expected)
	}
}

func TestParseObjectIdentifierWithOtherOid(t *testing.T) {
	oid := []byte{43, 6, 3, 30, 11, 1, 10}
	expected := ".1.3.6.3.30.11.1.10"
	buf, err := parseObjectIdentifier(oid)
	if err != nil {
		t.Errorf("parseObjectIdentifier(%v) want %s, error: %v", oid, expected, err)
	}
	result := string(buf)
	if string(result) != expected {
		t.Errorf("parseObjectIdentifier(%v) = %s, want %s", oid, result, expected)
	}
}

func BenchmarkParseObjectIdentifier(b *testing.B) {
	oid := []byte{43, 6, 3, 30, 11, 1, 10}
	for i := 0; i < b.N; i++ {
		parseObjectIdentifier(oid)
	}
}

func BenchmarkMarshalObjectIdentifier(b *testing.B) {
	oid := ".1.3.6.3.30.11.1.10"
	for i := 0; i < b.N; i++ {
		marshalObjectIdentifier(oid)
	}
}

type testsMarshalUint32T struct {
	value     uint32
	goodBytes []byte
}

var testsMarshalUint32 = []testsMarshalUint32T{
	{0, []byte{0x00}},
	{2, []byte{0x02}}, // 2
	{128, []byte{0x00, 0x80}},
	{257, []byte{0x01, 0x01}},                  // FF + 2
	{65537, []byte{0x01, 0x00, 0x01}},          // FFFF + 2
	{16777217, []byte{0x01, 0x00, 0x00, 0x01}}, // FFFFFF + 2
	{18542501, []byte{0x01, 0x1a, 0xef, 0xa5}},
	{2147483647, []byte{0x7f, 0xff, 0xff, 0xff}},
	{2147483648, []byte{0x00, 0x80, 0x00, 0x0, 0x0}},
}

func TestMarshalUint32(t *testing.T) {
	for i, test := range testsMarshalUint32 {
		result, err := marshalUint32(test.value)
		if err != nil {
			t.Errorf("%d: expected %0x got err %v", i, test.goodBytes, err)
		}
		if !checkByteEquality2(test.goodBytes, result) {
			t.Errorf("%d: expected %0x got %0x", i, test.goodBytes, result)
		}
	}
}

var testsMarshalInt32 = []struct {
	value     int
	goodBytes []byte
}{
	{0, []byte{0x00}},
	{2, []byte{0x02}}, // 2
	{128, []byte{0x00, 0x80}},
	{257, []byte{0x01, 0x01}},                  // FF + 2
	{65537, []byte{0x01, 0x00, 0x01}},          // FFFF + 2
	{16777217, []byte{0x01, 0x00, 0x00, 0x01}}, // FFFFFF + 2
	{2147483647, []byte{0x7f, 0xff, 0xff, 0xff}},
	{-2147483648, []byte{0x80, 0x00, 0x00, 0x00}},
	{-16777217, []byte{0xfe, 0xff, 0xff, 0xff}},
	{-16777216, []byte{0xff, 0x00, 0x00, 0x00}},
	{-65537, []byte{0xfe, 0xff, 0xff}},
	{-65536, []byte{0xff, 0x00, 0x00}},
	{-257, []byte{0xfe, 0xff}},
	{-256, []byte{0xff, 0x00}},
	{-2, []byte{0xfe}},
	{-1, []byte{0xff}},
}

func TestMarshalInt32(t *testing.T) {
	for _, aTest := range testsMarshalInt32 {
		result, err := marshalInt32(aTest.value)
		assert.NoErrorf(t, err, "value %d", aTest.value)
		assert.EqualValues(t, aTest.goodBytes, result, "bad marshalInt32()")
	}
}

func TestParseUint64(t *testing.T) {
	tests := []struct {
		data []byte
		n    uint64
	}{
		{[]byte{}, 0},
		{[]byte{0x00}, 0},
		{[]byte{0x01}, 1},
		{[]byte{0x01, 0x01}, 257},
		{[]byte{0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1e, 0xb3, 0xbf}, 18446744073694786495},
	}
	for _, test := range tests {
		if ret, err := parseUint64(test.data); err != nil || ret != test.n {
			t.Errorf("parseUint64(%v) = %d, %v want %d, <nil>", test.data, ret, err, test.n)
		}
	}
}

var testsInvalidSNMPResponses = []string{
	"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",
	"MBoCAQEEB3ByaXZhdGWiDAIESESkywIBBQIBAA==",
	"MEo=",
}

func TestInvalidSNMPResponses(t *testing.T) {

	g := &GoSNMP{
		Target:    "127.0.0.1",
		Port:      161,
		Community: "public",
		Version:   Version2c,
	}

	for i, test := range testsInvalidSNMPResponses {
		testBytes, _ := base64.StdEncoding.DecodeString(test)
		result, err := g.SnmpDecodePacket(testBytes)
		if err == nil {
			t.Errorf("#%d, failed to error %v", i, result)
		}
	}
}

func TestParseOpaque(t *testing.T) {
	var testCases = []struct {
		Input  []byte
		Output uint64
	}{
		{
			[]byte{0x9f, 0x7b, 0x1, 0x6},
			6,
		},
		{
			[]byte{0x9f, 0x7b, 0x1, 0x0},
			0,
		},
	}

	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("Parse %v to %v", testCase.Input, testCase.Output), func(t *testing.T) {
			input := testCase.Input
			v := variable{}

			err := parseOpaque(NewLogger(log.New(os.Stdout, "", 0)), input, &v)

			if assert.NoError(t, err) {
				assert.Equal(t, OpaqueUinteger64, v.Type)
				assert.Equal(t, testCase.Output, v.Value)
			}
		})
	}

}

func checkByteEquality2(a, b []byte) bool {

	if a == nil && b == nil {
		return true
	}

	if a == nil || b == nil {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
