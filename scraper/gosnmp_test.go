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

package scraper

import (
	"errors"
	"net"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestCloneLocalAddr(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"", ""},
		// No port component: returned unchanged (gosnmp rejects it at
		// Connect() for parent and clone alike; not this function's problem).
		{"192.168.1.1", "192.168.1.1"},
		{"::1", "::1"},
		{"somehost", "somehost"},
		// Fixed port: normalized to 0 so clones bind fresh source ports.
		{"192.168.1.1:12345", "192.168.1.1:0"},
		{"0.0.0.0:9161", "0.0.0.0:0"},
		{"somehost:161", "somehost:0"},
		{"[::1]:12345", "[::1]:0"},
		// Auto-port forms stay auto.
		{"192.168.1.1:", "192.168.1.1:0"},
		{"192.168.1.1:0", "192.168.1.1:0"},
	}
	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			got := cloneLocalAddr(c.input)
			if got != c.want {
				t.Errorf("cloneLocalAddr(%q) = %q, want %q", c.input, got, c.want)
			}
		})
	}
}

func TestCloneConnectsWithSourceAddress(t *testing.T) {
	// Reserve a local UDP port to stand in for the parent's fixed source
	// port, and keep it bound: the clone must neither reuse it (bind
	// conflict) nor fail to parse its own LocalAddr.
	reserved, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("reserving local UDP port: %v", err)
	}
	defer reserved.Close()

	w, err := NewGoSNMP(promslog.NewNopLogger(), "127.0.0.1:1161", reserved.LocalAddr().String(), false)
	if err != nil {
		t.Fatalf("NewGoSNMP: %v", err)
	}
	clone := w.Clone()
	// UDP "connect" only binds and sets the peer; no listener is needed.
	if err := clone.Connect(); err != nil {
		t.Fatalf("clone Connect() with source address set: %v", err)
	}
	clone.Close()
}

func TestMockCloneCopiesConnectError(t *testing.T) {
	wantErr := errors.New("simulated connect failure")
	m := NewMockSNMPScraper(nil, nil)
	m.ConnectError = wantErr

	clone := m.Clone()
	if err := clone.Connect(); !errors.Is(err, wantErr) {
		t.Errorf("Clone().Connect() = %v, want %v", err, wantErr)
	}
}

func TestNewGoSNMPTargetParsing(t *testing.T) {
	cases := []struct {
		target    string
		transport string
		host      string
		port      uint16
		shouldErr bool
	}{
		{
			target:    "localhost",
			transport: "udp",
			host:      "localhost",
			port:      161,
		},
		{
			target:    "localhost:1161",
			transport: "udp",
			host:      "localhost",
			port:      1161,
		},
		{
			target:    "udp://localhost",
			transport: "udp",
			host:      "localhost",
			port:      161,
		},
		{
			target:    "udp://localhost:1161",
			transport: "udp",
			host:      "localhost",
			port:      1161,
		},
		{
			target:    "tcp://localhost",
			transport: "tcp",
			host:      "localhost",
			port:      161,
		},
		{
			target:    "tcp://localhost:1161",
			transport: "tcp",
			host:      "localhost",
			port:      1161,
		},
		{
			target:    "::1",
			transport: "udp",
			host:      "::1",
			port:      161,
		},
		{
			target:    "[::1]",
			transport: "udp",
			host:      "::1",
			port:      161,
		},
		{
			target:    "[::1]:1161",
			transport: "udp",
			host:      "::1",
			port:      1161,
		},
		{
			target:    "udp://[::1]",
			transport: "udp",
			host:      "::1",
			port:      161,
		},
		{
			target:    "udp://[::1]:1161",
			transport: "udp",
			host:      "::1",
			port:      1161,
		},
		{
			target:    "tcp://[::1]",
			transport: "tcp",
			host:      "::1",
			port:      161,
		},
		{
			target:    "tcp://[::1]:1161",
			transport: "tcp",
			host:      "::1",
			port:      1161,
		},
		{
			target:    "192.168.1.1",
			transport: "udp",
			host:      "192.168.1.1",
			port:      161,
		},
		{
			target:    "192.168.1.1:1161",
			transport: "udp",
			host:      "192.168.1.1",
			port:      1161,
		},
		{
			target:    "udp://192.168.1.1:1161",
			transport: "udp",
			host:      "192.168.1.1",
			port:      1161,
		},
		{
			target:    "udp://::1",
			transport: "udp",
			host:      "::1",
			port:      161,
		},
		{
			target:    "tcp://::1",
			transport: "tcp",
			host:      "::1",
			port:      161,
		},
		{ // valid during parse but invalid during connect
			target:    "tcp://udp://localhost:1161",
			transport: "tcp",
			host:      "udp://localhost:1161",
			port:      161,
		},
		// Bracketed non-IPv6 targets. Not valid per RFC 3986 Section 3.2.2
		// (brackets are defined for IPv6 literals only), but accepted by
		// Go's net.SplitHostPort. Consistent with the with-port case which
		// has always stripped brackets via the same codepath.
		{
			target:    "[localhost]",
			transport: "udp",
			host:      "localhost",
			port:      161,
		},
		{
			target:    "[localhost]:1161",
			transport: "udp",
			host:      "localhost",
			port:      1161,
		},
		{
			target:    "[192.168.1.1]",
			transport: "udp",
			host:      "192.168.1.1",
			port:      161,
		},
		{
			target:    "[192.168.1.1]:1161",
			transport: "udp",
			host:      "192.168.1.1",
			port:      1161,
		},
		{
			target:    "localhost:0",
			transport: "udp",
			host:      "localhost",
			port:      0,
		},
		{
			target:    "localhost:65535",
			transport: "udp",
			host:      "localhost",
			port:      65535,
		},
		{
			target:    "localhost:65536",
			shouldErr: true,
		},
		{
			target:    "localhost:-1",
			shouldErr: true,
		},
		{
			target:    "localhost:badport",
			shouldErr: true,
		},
		{
			target:    "udp://localhost:badport",
			shouldErr: true,
		},
		{
			target:    "tcp://localhost:badport",
			shouldErr: true,
		},
		{
			target:    "[::1]:badport",
			shouldErr: true,
		},
		{
			target:    "udp://[::1]:badport",
			shouldErr: true,
		},
		{
			target:    "tcp://[::1]:badport",
			shouldErr: true,
		},
	}

	logger := promslog.NewNopLogger()
	for _, c := range cases {
		t.Run(c.target, func(t *testing.T) {
			w, err := NewGoSNMP(logger, c.target, "", false)
			if c.shouldErr {
				if err == nil {
					t.Fatalf("expected error for target %q, got nil", c.target)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for target %q: %v", c.target, err)
			}
			if w.c.Transport != c.transport {
				t.Errorf("transport for %q: got %q, want %q", c.target, w.c.Transport, c.transport)
			}
			if w.c.Target != c.host {
				t.Errorf("host for %q: got %q, want %q", c.target, w.c.Target, c.host)
			}
			if w.c.Port != c.port {
				t.Errorf("port for %q: got %d, want %d", c.target, w.c.Port, c.port)
			}
		})
	}
}
