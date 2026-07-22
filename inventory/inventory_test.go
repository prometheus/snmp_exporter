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

package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/snmp_exporter/config"
)

func TestLoaderLoad(t *testing.T) {
	directory := t.TempDir()
	content := strings.Join([]string{
		"apiVersion: snmpcollector.io/v1alpha1",
		"kind: DeviceList",
		"devices:",
		"  - id: core-switch-01",
		"    address: udp://192.0.2.1:161",
		"    profile: if_mib",
		"    auth: public_v2",
		"    interval: 1m",
		"    timeout: 45s",
		"    labels:",
		"      site: dc01",
		"  - id: disabled-switch",
		"    address: tcp://switch.example.com:161",
		"    profile: if_mib",
		"    auth: public_v2",
		"    enabled: false",
		"",
	}, "\n")
	writeFile(t, filepath.Join(directory, "core.yml"), content)

	loader := NewLoader(time.Minute, 45*time.Second)
	snapshot, err := loader.Load([]string{filepath.Join(directory, "*.yml")}, testProfiles())
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if snapshot.Len() != 2 {
		t.Fatalf("snapshot.Len() = %d, want 2", snapshot.Len())
	}
	if len(snapshot.Revision()) != 64 {
		t.Fatalf("revision length = %d, want 64", len(snapshot.Revision()))
	}

	core, ok := snapshot.Device("core-switch-01")
	if !ok {
		t.Fatal("core-switch-01 was not loaded")
	}
	if !core.Enabled || core.Interval != time.Minute || core.Timeout != 45*time.Second {
		t.Fatalf("core-switch-01 scheduling config = enabled:%v interval:%s timeout:%s", core.Enabled, core.Interval, core.Timeout)
	}
	if core.Labels["site"] != "dc01" {
		t.Fatalf("core-switch-01 site label = %q, want dc01", core.Labels["site"])
	}
	disabled, ok := snapshot.Device("disabled-switch")
	if !ok || disabled.Enabled {
		t.Fatalf("disabled-switch = %#v, want a disabled device", disabled)
	}
	if disabled.Interval != time.Minute || disabled.Timeout != 45*time.Second {
		t.Fatalf("default scheduling config = %s/%s, want 1m/45s", disabled.Interval, disabled.Timeout)
	}

	core.Labels["site"] = "mutated"
	all := snapshot.Devices()
	all["core-switch-01"] = DeviceSnapshot{}
	stored, _ := snapshot.Device("core-switch-01")
	if stored.Labels["site"] != "dc01" || stored.ID != "core-switch-01" {
		t.Fatalf("callers mutated the stored snapshot: %#v", stored)
	}

	second, err := loader.Load([]string{filepath.Join(directory, "*.yml")}, testProfiles())
	if err != nil {
		t.Fatalf("second Load() returned unexpected error: %v", err)
	}
	if second.Revision() != snapshot.Revision() {
		t.Fatalf("unchanged inventory revision changed from %q to %q", snapshot.Revision(), second.Revision())
	}
}

func TestLoaderValidation(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantErr    string
		notInError string
	}{
		{name: "unknown field", body: validDeviceYAML("    unknown: true\n"), wantErr: "field unknown not found"},
		{name: "unsupported API", body: strings.Replace(validDeviceYAML(""), APIVersion, "snmpcollector.io/v9", 1), wantErr: "unsupported apiVersion"},
		{
			name: "duplicate ID",
			body: validDeviceYAML("") + strings.Join([]string{
				"  - id: core-switch-01",
				"    address: udp://192.0.2.2:161",
				"    profile: if_mib",
				"    auth: public_v2",
				"    interval: 1m",
				"    timeout: 30s",
				"",
			}, "\n"),
			wantErr: "duplicate device ID",
		},
		{name: "missing ID", body: strings.Replace(validDeviceYAML(""), "core-switch-01", "", 1), wantErr: "device ID is required"},
		{
			name:       "credentials in address",
			body:       strings.Replace(validDeviceYAML(""), "udp://192.0.2.1:161", "udp://secret-user:secret-password@192.0.2.1:161", 1),
			wantErr:    "must not contain credentials",
			notInError: "secret-password",
		},
		{name: "invalid transport", body: strings.Replace(validDeviceYAML(""), "udp://", "http://", 1), wantErr: "must use udp or tcp"},
		{name: "unknown profile", body: strings.Replace(validDeviceYAML(""), "profile: if_mib", "profile: missing", 1), wantErr: "profile \"missing\" does not exist"},
		{name: "unknown auth", body: strings.Replace(validDeviceYAML(""), "auth: public_v2", "auth: missing", 1), wantErr: "auth \"missing\" does not exist"},
		{name: "interval below timeout", body: strings.Replace(validDeviceYAML(""), "interval: 1m", "interval: 10s", 1), wantErr: "must be greater than or equal to timeout"},
		{name: "reserved label", body: validDeviceYAML("    labels:\n      __name__: forbidden\n"), wantErr: "is reserved"},
	}

	loader := NewLoader(time.Minute, 45*time.Second)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "devices.yml")
			writeFile(t, path, tt.body)
			_, err := loader.Load([]string{path}, testProfiles())
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load() error = %v, want error containing %q", err, tt.wantErr)
			}
			if tt.notInError != "" && strings.Contains(err.Error(), tt.notInError) {
				t.Fatalf("Load() error leaked %q: %v", tt.notInError, err)
			}
		})
	}
}

func TestStoreKeepsLastKnownGoodSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.yml")
	writeFile(t, path, validDeviceYAML(""))
	loader := NewLoader(time.Minute, 45*time.Second)
	store := &Store{}

	if err := store.Reload(loader, []string{path}, testProfiles()); err != nil {
		t.Fatalf("initial Reload() returned unexpected error: %v", err)
	}
	initial := store.Current()
	if initial == nil {
		t.Fatal("initial Reload() did not publish a snapshot")
	}

	writeFile(t, path, strings.Replace(validDeviceYAML(""), "profile: if_mib", "profile: missing", 1))
	if err := store.Reload(loader, []string{path}, testProfiles()); err == nil {
		t.Fatal("invalid Reload() returned nil error")
	}
	if store.Current() != initial {
		t.Fatal("invalid Reload() replaced the last-known-good snapshot")
	}
}

func testProfiles() *config.Config {
	return &config.Config{
		Modules: map[string]*config.Module{"if_mib": {}},
		Auths:   map[string]*config.Auth{"public_v2": {Version: 2}},
	}
}

func validDeviceYAML(extra string) string {
	return strings.Join([]string{
		"apiVersion: snmpcollector.io/v1alpha1",
		"kind: DeviceList",
		"devices:",
		"  - id: core-switch-01",
		"    address: udp://192.0.2.1:161",
		"    profile: if_mib",
		"    auth: public_v2",
		"    interval: 1m",
		"    timeout: 45s",
		extra,
	}, "\n")
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write test inventory: %v", err)
	}
}
