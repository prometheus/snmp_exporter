// Copyright 2026 The Prometheus Authors
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
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/prometheus/common/promslog"

	"github.com/prometheus/snmp_exporter/config"
	"github.com/prometheus/snmp_exporter/sample"
	"github.com/prometheus/snmp_exporter/scraper"
)

type callbackScraper struct {
	inner   scraper.SNMPScraper
	options gosnmp.GoSNMP
}

func (s *callbackScraper) Get(oids []string) (*gosnmp.SnmpPacket, error) {
	if s.options.OnSent != nil {
		s.options.OnSent(&s.options)
	}
	if s.options.OnRetry != nil {
		s.options.OnRetry(&s.options)
	}
	packet, err := s.inner.Get(oids)
	if s.options.OnRecv != nil {
		s.options.OnRecv(&s.options)
	}
	return packet, err
}

func (s *callbackScraper) WalkAll(oid string) ([]gosnmp.SnmpPDU, error) {
	return s.inner.WalkAll(oid)
}

func (s *callbackScraper) Connect() error { return s.inner.Connect() }
func (s *callbackScraper) Close() error   { return s.inner.Close() }

func (s *callbackScraper) SetOptions(options ...func(*gosnmp.GoSNMP)) {
	for _, option := range options {
		option(&s.options)
	}
}

func TestActivePollerPoll(t *testing.T) {
	const (
		uptimeOID = "1.3.6.1.2.1.1.3.0"
		statusOID = "1.3.6.1.2.1.1.7.0"
	)
	mock := &callbackScraper{inner: scraper.NewMockSNMPScraper(
		map[string]gosnmp.SnmpPDU{
			uptimeOID: {Name: "." + uptimeOID, Type: gosnmp.Counter64, Value: uint64(42)},
			statusOID: {Name: "." + statusOID, Type: gosnmp.Integer, Value: 1},
		},
		nil,
	)}

	poller := NewPoller(promslog.NewNopLogger(), Metrics{}, false)
	poller.newScraper = func(*slog.Logger, string, string, bool) (scraper.SNMPScraper, error) {
		return mock, nil
	}
	poller.newPollID = func() (string, error) { return "poll-01", nil }
	fixedTime := time.Date(2026, 7, 21, 10, 0, 0, 0, time.UTC)
	poller.now = func() time.Time { return fixedTime }

	targetLabels := map[string]string{"site": "dc01"}
	ctx := context.Background()
	result, err := poller.Poll(
		ctx,
		TargetSnapshot{Address: "udp://192.0.2.1:161", DeviceID: "switch-01", Labels: targetLabels},
		ProfileSnapshot{
			Name: "system",
			Module: &config.Module{
				Get: []string{uptimeOID, statusOID},
				Metrics: []*config.Metric{
					{Name: "sysUpTime", Oid: "1.3.6.1.2.1.1.3", Type: "counter", Help: "System uptime"},
					{Name: "sysStatus", Oid: "1.3.6.1.2.1.1.7", Type: "EnumAsInfo", Help: "System status", EnumValues: map[int]string{1: "up"}},
				},
			},
		},
		Credentials{Name: "public_v2", Auth: &config.Auth{Version: 2, Community: "test-community"}},
	)
	if err != nil {
		t.Fatalf("Poll() returned unexpected error: %v", err)
	}
	if len(result.Samples) != 3 {
		t.Fatalf("Poll() returned %d samples, want 3: %#v", len(result.Samples), result.Samples)
	}
	if result.Packets != 2 || result.Retries != 2 {
		t.Fatalf("Poll() packets/retries = %d/%d, want 2/2", result.Packets, result.Retries)
	}
	if !result.StartedAt.Equal(fixedTime) || !result.EndedAt.Equal(fixedTime) {
		t.Fatalf("Poll() timestamps = %v/%v, want %v", result.StartedAt, result.EndedAt, fixedTime)
	}
	if mock.options.Context != ctx {
		t.Fatal("Poll() did not configure the provided context on the SNMP client")
	}
	if mock.options.Version != gosnmp.Version2c {
		t.Fatalf("SNMP version = %v, want v2c", mock.options.Version)
	}

	byName := make(map[string]sample.Sample, len(result.Samples))
	for _, got := range result.Samples {
		byName[got.Name] = got
		if got.DeviceID != "switch-01" || got.PollID != "poll-01" {
			t.Errorf("sample identity = %q/%q, want switch-01/poll-01", got.DeviceID, got.PollID)
		}
		if got.Timestamp != fixedTime.UnixMilli() {
			t.Errorf("sample timestamp = %d, want %d", got.Timestamp, fixedTime.UnixMilli())
		}
		if got.Labels["site"] != "dc01" {
			t.Errorf("sample site label = %q, want dc01", got.Labels["site"])
		}
		if got.Labels["device_ip"] != "192.0.2.1" {
			t.Errorf("sample device_ip label = %q, want 192.0.2.1", got.Labels["device_ip"])
		}
	}
	if got := byName["sysUpTime"]; got.Type != sample.MetricCounter || got.OID != uptimeOID {
		t.Errorf("sysUpTime type/OID = %q/%q, want counter/%s", got.Type, got.OID, uptimeOID)
	}
	if got := byName["sysStatus_info"]; got.Type != sample.MetricInfo || got.Labels["sysStatus"] != "up" {
		t.Errorf("sysStatus_info = %#v, want info sample with sysStatus=up", got)
	}
	if got := byName["snmp_up"]; got.Type != sample.MetricGauge || got.Value != 1 {
		t.Errorf("snmp_up = %#v, want gauge value 1", got)
	}

	targetLabels["site"] = "dc02"
	if got := result.Samples[0].Labels["site"]; got != "dc01" {
		t.Fatalf("mutating target labels changed result label to %q", got)
	}
}

func TestActivePollerValidatesInput(t *testing.T) {
	poller := NewPoller(promslog.NewNopLogger(), Metrics{}, false)
	validTarget := TargetSnapshot{Address: "udp://192.0.2.1:161", DeviceID: "switch-01"}
	validProfile := ProfileSnapshot{Name: "system", Module: &config.Module{}}
	validCredentials := Credentials{Name: "public_v2", Auth: &config.Auth{Version: 2}}

	tests := []struct {
		name        string
		target      TargetSnapshot
		profile     ProfileSnapshot
		credentials Credentials
		wantErr     string
	}{
		{name: "missing address", target: TargetSnapshot{DeviceID: "switch-01"}, profile: validProfile, credentials: validCredentials, wantErr: "target address is required"},
		{name: "missing device ID", target: TargetSnapshot{Address: "udp://192.0.2.1:161"}, profile: validProfile, credentials: validCredentials, wantErr: "target device ID is required"},
		{name: "missing profile name", target: validTarget, profile: ProfileSnapshot{Module: &config.Module{}}, credentials: validCredentials, wantErr: "profile name is required"},
		{name: "missing module", target: validTarget, profile: ProfileSnapshot{Name: "system"}, credentials: validCredentials, wantErr: "profile module is required"},
		{name: "missing auth", target: validTarget, profile: validProfile, credentials: Credentials{Name: "public_v2"}, wantErr: "credentials auth is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := poller.Poll(context.Background(), tt.target, tt.profile, tt.credentials)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Poll() error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestWithAutomaticTargetLabels(t *testing.T) {
	tests := []struct {
		name    string
		target  TargetSnapshot
		wantIP  string
		wantErr string
	}{
		{
			name:   "IPv4 strips transport and port",
			target: TargetSnapshot{Address: "udp://192.0.2.1:161"},
			wantIP: "192.0.2.1",
		},
		{
			name:   "IPv6 strips brackets and port",
			target: TargetSnapshot{Address: "tcp://[2001:db8::1]:1161"},
			wantIP: "2001:db8::1",
		},
		{
			name:   "hostname remains stable without DNS lookup",
			target: TargetSnapshot{Address: "udp://switch.example.com:161"},
			wantIP: "switch.example.com",
		},
		{
			name: "matching configured label is accepted",
			target: TargetSnapshot{
				Address: "udp://192.0.2.1:161",
				Labels:  map[string]string{"device_ip": "192.0.2.1"},
			},
			wantIP: "192.0.2.1",
		},
		{
			name: "conflicting configured label is rejected",
			target: TargetSnapshot{
				Address: "udp://192.0.2.1:161",
				Labels:  map[string]string{"device_ip": "192.0.2.2"},
			},
			wantErr: "conflicts with target address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := withAutomaticTargetLabels(tt.target)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("withAutomaticTargetLabels() error = %v, want error containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("withAutomaticTargetLabels() returned unexpected error: %v", err)
			}
			if got.Labels["device_ip"] != tt.wantIP {
				t.Fatalf("device_ip = %q, want %q", got.Labels["device_ip"], tt.wantIP)
			}
		})
	}
}
