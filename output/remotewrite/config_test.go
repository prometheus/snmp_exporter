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

package remotewrite

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/snmp_exporter/output"
)

func TestLoadConfigFileAppliesDefaultsAndIgnoresInactiveBlock(t *testing.T) {
	path := writeOutputConfig(t,
		"apiVersion: snmpcollector.io/v1alpha1",
		"kind: OutputConfig",
		"output:",
		"  type: remote_write",
		"  remoteWrite:",
		"    endpoint: https://mimir.example.com/api/v1/push",
		"    headerEnv:",
		"      Authorization: MIMIR_AUTHORIZATION",
		"      X-Scope-OrgID: MIMIR_TENANT_ID",
		"    queue: {}",
		"  clickhouse:",
		"    fields:",
		"      unknownToRemoteWrite: true",
	)

	config, err := LoadConfigFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFile() returned unexpected error: %v", err)
	}
	if len(config.Revision) != 64 {
		t.Fatalf("revision length = %d, want 64", len(config.Revision))
	}
	if config.Sender.Endpoint != "https://mimir.example.com/api/v1/push" {
		t.Fatalf("endpoint = %q", config.Sender.Endpoint)
	}
	if config.Sender.MaxInFlight != 4 {
		t.Fatalf("max in-flight = %d, want 4", config.Sender.MaxInFlight)
	}
	wantQueue := output.QueueConfig{
		Capacity:        10000,
		MaxBatchSamples: 2000,
		FlushInterval:   2 * time.Second,
		OverflowPolicy:  output.DropOldest,
		RetryMinBackoff: time.Second,
		RetryMaxBackoff: 30 * time.Second,
		RequestTimeout:  30 * time.Second,
	}
	if config.Queue != wantQueue {
		t.Fatalf("queue = %#v, want %#v", config.Queue, wantQueue)
	}
	if got := config.HeaderEnv["Authorization"]; got != "MIMIR_AUTHORIZATION" {
		t.Fatalf("Authorization environment = %q", got)
	}
}

func TestLoadConfigFileParsesExplicitValues(t *testing.T) {
	path := writeOutputConfig(t,
		"output:",
		"  type: remote_write",
		"  remoteWrite:",
		"    endpoint: http://mimir:9009/api/v1/push",
		"    maxInFlight: 8",
		"    userAgent: collector-test",
		"    credentialRef: vault://monitoring/data/mimir/snmp-collector",
		"    queue:",
		"      capacity: 123",
		"      maxBatchSamples: 45",
		"      flushInterval: 3s",
		"      overflowPolicy: drop_oldest",
		"      retryMinBackoff: 250ms",
		"      retryMaxBackoff: 10s",
		"      requestTimeout: 12s",
	)

	config, err := LoadConfigFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFile() returned unexpected error: %v", err)
	}
	if config.Sender.MaxInFlight != 8 || config.Sender.UserAgent != "collector-test" {
		t.Fatalf("sender config = %#v", config.Sender)
	}
	if config.Queue.Capacity != 123 ||
		config.Queue.MaxBatchSamples != 45 ||
		config.Queue.FlushInterval != 3*time.Second ||
		config.Queue.RetryMinBackoff != 250*time.Millisecond ||
		config.Queue.RetryMaxBackoff != 10*time.Second ||
		config.Queue.RequestTimeout != 12*time.Second {
		t.Fatalf("queue config = %#v", config.Queue)
	}
	if config.CredentialRef != "vault://monitoring/data/mimir/snmp-collector" {
		t.Fatalf("credentialRef = %q", config.CredentialRef)
	}
}

func TestLoadConfigFileRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		want  string
	}{
		{
			name: "unknown remote write field",
			lines: []string{
				"output:", "  type: remote_write", "  remoteWrite:",
				"    endpoint: https://mimir.example.com/api/v1/push",
				"    typo: true", "    queue: {}",
			},
			want: "field typo not found",
		},
		{
			name: "unsupported active type",
			lines: []string{
				"output:", "  type: clickhouse", "  clickhouse:",
				"    dsnRef: env://CLICKHOUSE_DSN",
			},
			want: "unsupported active output type",
		},
		{
			name:  "missing active block",
			lines: []string{"output:", "  type: remote_write"},
			want:  "missing the active remoteWrite block",
		},
		{
			name: "invalid header name",
			lines: []string{
				"output:", "  type: remote_write", "  remoteWrite:",
				"    endpoint: https://mimir.example.com/api/v1/push",
				"    headerEnv:", "      \"Bad Header\": MIMIR_TOKEN", "    queue: {}",
			},
			want: "invalid header name",
		},
		{
			name: "invalid environment name",
			lines: []string{
				"output:", "  type: remote_write", "  remoteWrite:",
				"    endpoint: https://mimir.example.com/api/v1/push",
				"    headerEnv:", "      Authorization: bad-name", "    queue: {}",
			},
			want: "invalid environment variable name",
		},
		{
			name: "two credential sources",
			lines: []string{
				"output:", "  type: remote_write", "  remoteWrite:",
				"    endpoint: https://mimir.example.com/api/v1/push",
				"    credentialRef: env://MIMIR_TOKEN", "    headerEnv:",
				"      Authorization: MIMIR_TOKEN", "    queue: {}",
			},
			want: "only one of credentialRef or headerEnv",
		},
	}

	for _, current := range tests {
		t.Run(current.name, func(t *testing.T) {
			_, err := LoadConfigFile(writeOutputConfig(t, current.lines...))
			if err == nil || !strings.Contains(err.Error(), current.want) {
				t.Fatalf("LoadConfigFile() error = %v, want substring %q", err, current.want)
			}
		})
	}
}

func TestEnvHeaderProviderReadsCurrentValuesAndCopiesConfig(t *testing.T) {
	values := map[string]string{"MIMIR_TOKEN": "Bearer first"}
	source := map[string]string{"Authorization": "MIMIR_TOKEN"}
	provider, err := newEnvHeaderProvider(source, func(name string) (string, bool) {
		value, exists := values[name]
		return value, exists
	})
	if err != nil {
		t.Fatalf("newEnvHeaderProvider() returned unexpected error: %v", err)
	}
	source["Authorization"] = "CHANGED_SOURCE"

	headers, err := provider.Headers(context.Background())
	if err != nil {
		t.Fatalf("Headers() returned unexpected error: %v", err)
	}
	if got := headers.Get("Authorization"); got != "Bearer first" {
		t.Fatalf("first header = %q", got)
	}

	values["MIMIR_TOKEN"] = "Bearer rotated"
	headers, err = provider.Headers(context.Background())
	if err != nil {
		t.Fatalf("Headers() after rotation returned unexpected error: %v", err)
	}
	if got := headers.Get("Authorization"); got != "Bearer rotated" {
		t.Fatalf("rotated header = %q", got)
	}
}

func TestEnvHeaderProviderRejectsMissingOrUnsafeValuesWithoutLeakingThem(t *testing.T) {
	const secret = "Bearer secret-value\r\nInjected: true"
	values := map[string]string{"MIMIR_TOKEN": secret}
	provider, err := newEnvHeaderProvider(
		map[string]string{"Authorization": "MIMIR_TOKEN"},
		func(name string) (string, bool) {
			value, exists := values[name]
			return value, exists
		},
	)
	if err != nil {
		t.Fatalf("newEnvHeaderProvider() returned unexpected error: %v", err)
	}

	_, err = provider.Headers(context.Background())
	if err == nil {
		t.Fatal("Headers() accepted a value containing a newline")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "secret-value") {
		t.Fatalf("Headers() leaked secret in error: %v", err)
	}

	delete(values, "MIMIR_TOKEN")
	_, err = provider.Headers(context.Background())
	if err == nil || !strings.Contains(err.Error(), "is not set") {
		t.Fatalf("Headers() missing environment error = %v", err)
	}
}

func writeOutputConfig(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "outputs.yml")
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write output config: %v", err)
	}
	return path
}
