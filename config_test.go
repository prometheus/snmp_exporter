// Copyright 2018 The Prometheus Authors
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
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
	"go.yaml.in/yaml/v2"

	"github.com/prometheus/snmp_exporter/collector"
	"github.com/prometheus/snmp_exporter/config"
)

var nopLogger = promslog.NewNopLogger()

func TestHideConfigSecrets(t *testing.T) {
	sc := &SafeConfig{}
	err := sc.ReloadConfig(nopLogger, []string{"testdata/snmp-auth.yml"}, false)
	if err != nil {
		t.Errorf("Error loading config %v: %v", "testdata/snmp-auth.yml", err)
	}

	// String method must not reveal authentication credentials.
	sc.mu.RLock()
	c, err := yaml.Marshal(sc.C)
	sc.mu.RUnlock()
	if err != nil {
		t.Errorf("Error marshaling config: %v", err)
	}
	if strings.Contains(string(c), "mysecret") {
		t.Fatal("config's String method reveals authentication credentials.")
	}
}

func TestLoadConfigWithOverrides(t *testing.T) {
	sc := &SafeConfig{}
	err := sc.ReloadConfig(nopLogger, []string{"testdata/snmp-with-overrides.yml"}, false)
	if err != nil {
		t.Errorf("Error loading config %v: %v", "testdata/snmp-with-overrides.yml", err)
	}
	sc.mu.RLock()
	_, err = yaml.Marshal(sc.C)
	sc.mu.RUnlock()
	if err != nil {
		t.Errorf("Error marshaling config: %v", err)
	}
}

func TestLoadMultipleConfigs(t *testing.T) {
	sc := &SafeConfig{}
	configs := []string{"testdata/snmp-auth.yml", "testdata/snmp-with-overrides.yml"}
	err := sc.ReloadConfig(nopLogger, configs, false)
	if err != nil {
		t.Errorf("Error loading configs %v: %v", configs, err)
	}
	sc.mu.RLock()
	_, err = yaml.Marshal(sc.C)
	sc.mu.RUnlock()
	if err != nil {
		t.Errorf("Error marshaling config: %v", err)
	}
}

// When all environment variables are present
func TestEnvSecrets(t *testing.T) {
	t.Setenv("ENV_USERNAME", "username") // snmp_ prefix is set in config file
	t.Setenv("ENV_PASSWORD", "snmp_password")
	t.Setenv("ENV_PRIV_PASSWORD", "snmp_priv_password")

	sc := &SafeConfig{}
	err := sc.ReloadConfig(nopLogger, []string{"testdata/snmp-auth-envvars.yml"}, true)
	if err != nil {
		t.Errorf("Error loading config %v: %v", "testdata/snmp-auth-envvars.yml", err)
	}

	// String method must not reveal authentication credentials.
	sc.mu.RLock()
	c, err := yaml.Marshal(sc.C)
	sc.mu.RUnlock()
	if err != nil {
		t.Errorf("Error marshaling config: %v", err)
	}

	if strings.Contains(string(c), "mysecret") {
		t.Fatal("config's String method reveals authentication credentials.")
	}

	// we check whether vars we set are resolved correctly in config
	for i := range sc.C.Auths {
		if sc.C.Auths[i].Username != "snmp_username" || sc.C.Auths[i].Password != "snmp_password" || sc.C.Auths[i].PrivPassword != "snmp_priv_password" {
			t.Fatal("failed to resolve secrets from env vars")
		}
	}
}

// When environment variable(s) are absent
func TestEnvSecretsMissing(t *testing.T) {
	t.Setenv("ENV_PASSWORD", "snmp_password")
	t.Setenv("ENV_PRIV_PASSWORD", "snmp_priv_password")

	sc := &SafeConfig{}
	err := sc.ReloadConfig(nopLogger, []string{"testdata/snmp-auth-envvars.yml"}, true)
	if err == nil {
		t.Fatal("no error despite missing env var")
	}
	if err != nil {
		// we check the error message pattern to determine the error
		if strings.Contains(err.Error(), "environment variable not found") {
			t.Logf("Error loading config as env var is not set/missing %v: %v", "testdata/snmp-auth-envvars.yml", err)
		} else {
			t.Errorf("Error loading config %v: %v", "testdata/snmp-auth-envvars.yml", err)
		}
	}
}

// When environment variables are present but set to empty values.
func TestEnvSecretsEmpty(t *testing.T) {
	t.Setenv("ENV_USERNAME", "")
	t.Setenv("ENV_PASSWORD", "")
	t.Setenv("ENV_PRIV_PASSWORD", "")

	sc := &SafeConfig{}
	err := sc.ReloadConfig(nopLogger, []string{"testdata/snmp-auth-envvars.yml"}, true)
	if err != nil {
		t.Fatalf("Error loading config with empty env vars: %v", err)
	}

	for i := range sc.C.Auths {
		if sc.C.Auths[i].Username != "snmp_" || sc.C.Auths[i].Password != "" || sc.C.Auths[i].PrivPassword != "" {
			t.Fatal("failed to resolve empty env vars")
		}
	}
}

// When SNMPv2 was specified without credentials
func TestEnvSecretsNotSpecified(t *testing.T) {
	sc := &SafeConfig{}
	err := sc.ReloadConfig(nopLogger, []string{"testdata/snmp-auth-v2nocreds.yml"}, true)
	if err != nil {
		t.Errorf("Error loading config %v: %v", "testdata/snmp-auth-v2nocreds.yml", err)
	}
}

func TestParseModules(t *testing.T) {
	cases := []struct {
		name    string
		query   url.Values
		want    []string
		wantErr string
	}{
		{
			name:  "defaults to if_mib when omitted",
			query: url.Values{},
			want:  []string{"if_mib"},
		},
		{
			name:    "rejects explicit empty module",
			query:   url.Values{"module": {""}},
			wantErr: "'module' parameter must contain at least one module name",
		},
		{
			name:  "deduplicates modules across repeated params and csv values",
			query: url.Values{"module": {"if_mib,system", "system", "if_mib"}},
			want:  []string{"if_mib", "system"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseModules(tc.query)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tc.wantErr)
				}
				if err.Error() != tc.wantErr {
					t.Fatalf("expected error %q, got %q", tc.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("expected modules %v, got %v", tc.want, got)
			}
		})
	}
}

func TestHandlerRejectsEmptyModuleParameter(t *testing.T) {
	sc = &SafeConfig{
		C: &config.Config{
			Auths: map[string]*config.Auth{
				"public_v2": {
					Community:     "public",
					SecurityLevel: "noAuthNoPriv",
					AuthProtocol:  "MD5",
					PrivProtocol:  "DES",
					Version:       2,
				},
			},
			Modules: map[string]*config.Module{
				"if_mib": {},
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/snmp?target=127.0.0.1&module=", http.NoBody)
	resp := httptest.NewRecorder()

	handler(resp, req, nopLogger, collector.Metrics{})

	if resp.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, resp.Code)
	}
	if !strings.Contains(resp.Body.String(), "'module' parameter must contain at least one module name") {
		t.Fatalf("unexpected response body: %q", resp.Body.String())
	}
}
