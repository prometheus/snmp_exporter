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

package collector

import (
	"strings"
	"testing"
)

func TestApplyDisplayHint(t *testing.T) {
	cases := []struct {
		name   string
		hint   string
		data   []byte
		result string
	}{
		{
			name:   "InetAddressIPv4 - 1d.1d.1d.1d",
			hint:   "1d.1d.1d.1d",
			data:   []byte{192, 168, 1, 1},
			result: "192.168.1.1",
		},
		{
			name:   "InetAddressIPv4z - 1d.1d.1d.1d%4d (zone ID)",
			hint:   "1d.1d.1d.1d%4d",
			data:   []byte{192, 168, 1, 1, 0, 0, 0, 3},
			result: "192.168.1.1%3",
		},
		{
			name:   "PhysAddress (MAC) - 1x: with implicit repetition",
			hint:   "1x:",
			data:   []byte{0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e},
			result: "00:1A:2B:3C:4D:5E",
		},
		{
			name:   "InetAddressIPv6 - 2x:2x:2x:2x:2x:2x:2x:2x",
			hint:   "2x:2x:2x:2x:2x:2x:2x:2x",
			data:   []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			result: "2001:0DB8:0000:0000:0000:0000:0000:0001",
		},
		{
			name:   "InetAddressIPv6z - IPv6 with zone ID",
			hint:   "2x:2x:2x:2x:2x:2x:2x:2x%4d",
			data:   []byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05},
			result: "FE80:0000:0000:0000:0000:0000:0000:0001%5",
		},
		{
			name:   "DisplayString - 255a",
			hint:   "255a",
			data:   []byte("Hello, World!"),
			result: "Hello, World!",
		},
		{
			name:   "Simple decimal - 1d",
			hint:   "1d",
			data:   []byte{42},
			result: "42",
		},
		{
			name:   "Multi-byte decimal - 4d (DNS-SERVER-MIB)",
			hint:   "4d",
			data:   []byte{0x00, 0x01, 0x00, 0x00},
			result: "65536",
		},
		{
			name:   "Octal format - 1o",
			hint:   "1o",
			data:   []byte{8},
			result: "10",
		},
		{
			name:   "Hex with dash separator - 1x-",
			hint:   "1x-",
			data:   []byte{0xaa, 0xbb, 0xcc},
			result: "AA-BB-CC",
		},
		{
			name:   "Star prefix repeat",
			hint:   "*1x:",
			data:   []byte{3, 0xaa, 0xbb, 0xcc},
			result: "AA:BB:CC",
		},
		{
			name:   "Star prefix with terminator",
			hint:   "*1d./1d",
			data:   []byte{3, 10, 20, 30, 40},
			result: "10.20.30/40",
		},
		{
			name:   "Trailing separator suppressed",
			hint:   "1d.",
			data:   []byte{1, 2, 3},
			result: "1.2.3",
		},
		{
			name:   "DateAndTime-like format - 2d-1d-1d,1d:1d:1d.1d",
			hint:   "2d-1d-1d,1d:1d:1d.1d",
			data:   []byte{0x07, 0xE6, 8, 15, 8, 1, 15, 0},
			result: "2022-8-15,8:1:15.0",
		},
		{
			name:   "Data shorter than spec",
			hint:   "1d.1d.1d.1d",
			data:   []byte{10, 20},
			result: "10.20",
		},
		{
			name:   "UTF-8 format - 10t",
			hint:   "10t",
			data:   []byte("hello"),
			result: "hello",
		},
		{
			name:   "UUID format - 4x-2x-2x-1x1x-6x",
			hint:   "4x-2x-2x-1x1x-6x",
			data:   []byte{0x12, 0x34, 0x56, 0x78, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			result: "12345678-ABCD-EF01-2345-001122334455",
		},
		{
			name:   "IPv4 with prefix - 1d.1d.1d.1d/1d",
			hint:   "1d.1d.1d.1d/1d",
			data:   []byte{10, 0, 0, 0, 24},
			result: "10.0.0.0/24",
		},
		{
			name:   "2-digit take value - 10d",
			hint:   "10d",
			data:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			result: "1",
		},
		{
			name:   "Zero-padded hex output",
			hint:   "1x",
			data:   []byte{0x0f},
			result: "0F",
		},
		{
			name:   "Single byte with trailing separator suppressed",
			hint:   "1d.",
			data:   []byte{42},
			result: "42",
		},
		{
			name:   "Implicit repetition with longer data",
			hint:   "1d.",
			data:   []byte{1, 2, 3, 4, 5},
			result: "1.2.3.4.5",
		},
		{
			name:   "Last spec repeats after fixed prefix",
			hint:   "1d-1d.",
			data:   []byte{1, 2, 3, 4, 5, 6},
			result: "1-2.3.4.5.6",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result, ok := applyDisplayHint(c.hint, c.data)
			if !ok {
				t.Errorf("applyDisplayHint(%q, %v) returned ok=false, want ok=true", c.hint, c.data)
				return
			}
			if result != c.result {
				t.Errorf("applyDisplayHint(%q, %v) = %q, want %q", c.hint, c.data, result, c.result)
			}
		})
	}
}

func TestApplyDisplayHintErrors(t *testing.T) {
	// All invalid hints or edge cases should return ok=false
	cases := []struct {
		name string
		hint string
		data []byte
	}{
		{
			name: "Empty hint",
			hint: "",
			data: []byte{1, 2, 3},
		},
		{
			name: "Empty data",
			hint: "1d",
			data: []byte{},
		},
		{
			name: "Invalid format character",
			hint: "1z",
			data: []byte{1, 2, 3},
		},
		{
			name: "Missing format character",
			hint: "1",
			data: []byte{1, 2, 3},
		},
		{
			name: "Missing take value",
			hint: "d",
			data: []byte{1, 2, 3},
		},
		{
			name: "Zero take value",
			hint: "0d",
			data: []byte{1, 2, 3},
		},
		{
			name: "Decimal take too large for uint64",
			hint: "9d",
			data: []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "Octal take too large for uint64",
			hint: "9o",
			data: []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, ok := applyDisplayHint(c.hint, c.data)
			if ok {
				t.Errorf("applyDisplayHint(%q, %v) returned ok=true, want ok=false for invalid hint", c.hint, c.data)
			}
		})
	}
}

func TestApplyDisplayHintUTF8(t *testing.T) {
	// Test that when wrapped with strings.ToValidUTF8, invalid bytes are sanitized
	cases := []struct {
		name   string
		hint   string
		data   []byte
		result string
	}{
		{
			name:   "ASCII format with invalid UTF-8 bytes sanitized",
			hint:   "10a",
			data:   []byte{'H', 'i', 0x80, 0xFF, '!'},
			result: "Hi\ufffd!", // Consecutive invalid bytes coalesced into single replacement
		},
		{
			name:   "Valid UTF-8 preserved",
			hint:   "20t",
			data:   []byte("Hello, 世界!"),
			result: "Hello, 世界!",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw, ok := applyDisplayHint(c.hint, c.data)
			if !ok {
				t.Errorf("applyDisplayHint(%q, %v) returned ok=false, want ok=true", c.hint, c.data)
				return
			}
			result := strings.ToValidUTF8(raw, "\ufffd")
			if result != c.result {
				t.Errorf("ToValidUTF8(applyDisplayHint(%q, %v)) = %q, want %q", c.hint, c.data, result, c.result)
			}
		})
	}
}

func TestApplyDisplayHintOverflowPanic(t *testing.T) {
	// Test that integer overflow in take value doesn't cause panic
	// A hint with a huge take value should gracefully return ok=false, not panic
	cases := []struct {
		name string
		hint string
		data []byte
	}{
		{
			name: "Overflow in second spec",
			hint: "1d9223372036854775807d",
			data: []byte{1, 2, 3},
		},
		{
			name: "Large take after consuming some data",
			hint: "2d9999999999999999999d",
			data: []byte{0, 1, 2, 3, 4},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("applyDisplayHint(%q, %v) panicked: %v", c.hint, c.data, r)
				}
			}()
			// Should not panic - ok=false is acceptable
			_, _ = applyDisplayHint(c.hint, c.data)
		})
	}
}

func TestApplyDisplayHintZeroWidthValid(t *testing.T) {
	// RFC 3419 uses zero-width specs to emit literal characters without consuming data.
	// These are valid patterns where zero-width specs are followed by data-consuming specs.
	cases := []struct {
		name   string
		hint   string
		data   []byte
		result string
	}{
		{
			name:   "Zero-width bracket prefix with trailing content",
			hint:   "0a[1a]1a",
			data:   []byte{0x41, 0x42},
			result: "[A]B",
		},
		{
			name:   "Zero-width prefix trailing suppressed",
			hint:   "0a[1a",
			data:   []byte{0x41},
			result: "[A",
		},
		{
			name:   "TransportAddressIPv6 style simplified",
			hint:   "0a[2x]0a:2d",
			data:   []byte{0x20, 0x01, 0x00, 0x50},
			result: "[2001]:80",
		},
		{
			name:   "Zero-width prefix only",
			hint:   "0a<1d-1d-1d",
			data:   []byte{1, 2, 3},
			result: "<1-2-3",
		},
		{
			name:   "Zero-width mid-hint",
			hint:   "1d-0a.1d",
			data:   []byte{10, 20},
			result: "10-.20",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result, ok := applyDisplayHint(c.hint, c.data)
			if !ok {
				t.Errorf("applyDisplayHint(%q, %v) returned ok=false, want ok=true", c.hint, c.data)
				return
			}
			if result != c.result {
				t.Errorf("applyDisplayHint(%q, %v) = %q, want %q", c.hint, c.data, result, c.result)
			}
		})
	}
}

func TestApplyDisplayHintZeroWidthInvalid(t *testing.T) {
	// Zero-width trailing specs that don't consume data return ok=false to prevent loops.
	cases := []struct {
		name string
		hint string
		data []byte
	}{
		{
			name: "Zero-width hex trailing",
			hint: "0x",
			data: []byte{0x41, 0x42},
		},
		{
			name: "Zero-width decimal trailing",
			hint: "0d",
			data: []byte{1, 2, 3},
		},
		{
			name: "Zero-width octal trailing",
			hint: "0o",
			data: []byte{8, 9},
		},
		{
			name: "Zero-width ascii trailing",
			hint: "0a.",
			data: []byte{1, 2, 3},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, ok := applyDisplayHint(c.hint, c.data)
			if ok {
				t.Errorf("applyDisplayHint(%q, %v) returned ok=true, want ok=false for zero-width trailing", c.hint, c.data)
			}
		})
	}
}
