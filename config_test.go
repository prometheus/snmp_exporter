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
	"strings"
	"testing"

	yaml "gopkg.in/yaml.v2"
)

func TestHideConfigSecrets(t *testing.T) {
	sc := &SafeConfig{}
	err := sc.ReloadConfig([]string{"testdata/snmp-auth.yml"}, false)
	if err != nil {
		t.Errorf("Error loading config %v: %v", "testdata/snmp-auth.yml", err)
	}

	// String method must not reveal authentication credentials.
	sc.RLock()
	c, err := yaml.Marshal(sc.C)
	sc.RUnlock()
	if err != nil {
		t.Errorf("Error marshaling config: %v", err)
	}
	if strings.Contains(string(c), "mysecret") {
		t.Fatal("config's String method reveals authentication credentials.")
	}
}

func TestLoadConfigWithOverrides(t *testing.T) {
	sc := &SafeConfig{}
	err := sc.ReloadConfig([]string{"testdata/snmp-with-overrides.yml"}, false)
	if err != nil {
		t.Errorf("Error loading config %v: %v", "testdata/snmp-with-overrides.yml", err)
	}
	sc.RLock()
	_, err = yaml.Marshal(sc.C)
	sc.RUnlock()
	if err != nil {
		t.Errorf("Error marshaling config: %v", err)
	}
}

func TestLoadMultipleConfigs(t *testing.T) {
	sc := &SafeConfig{}
	configs := []string{"testdata/snmp-auth.yml", "testdata/snmp-with-overrides.yml"}
	err := sc.ReloadConfig(configs, false)
	if err != nil {
		t.Errorf("Error loading configs %v: %v", configs, err)
	}
	sc.RLock()
	_, err = yaml.Marshal(sc.C)
	sc.RUnlock()
	if err != nil {
		t.Errorf("Error marshaling config: %v", err)
	}
}

// When all environment variables are present
func TestEnvSecrets(t *testing.T) {
	t.Setenv("ENV_USERNAME", "snmp_username")
	t.Setenv("ENV_PASSWORD", "snmp_password")
	t.Setenv("ENV_PRIV_PASSWORD", "snmp_priv_password")

	sc := &SafeConfig{}
	err := sc.ReloadConfig([]string{"testdata/snmp-auth-envvars.yml"}, true)
	if err != nil {
		t.Errorf("Error loading config %v: %v", "testdata/snmp-auth-envvars.yml", err)
	}

	// String method must not reveal authentication credentials.
	sc.RLock()
	c, err := yaml.Marshal(sc.C)
	sc.RUnlock()
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
	err := sc.ReloadConfig([]string{"testdata/snmp-auth-envvars.yml"}, true)
	if err != nil {
		// we check the error message pattern to determine the error
		if strings.Contains(err.Error(), "environment variable not found") {
			t.Logf("Error loading config as env var is not set/missing %v: %v", "testdata/snmp-auth-envvars.yml", err)
		} else {
			t.Errorf("Error loading config %v: %v", "testdata/snmp-auth-envvars.yml", err)
		}
	}
}

// When SNMPv2 was specified without credentials
func TestEnvSecretsNotSpecified(t *testing.T) {
	sc := &SafeConfig{}
	err := sc.ReloadConfig([]string{"testdata/snmp-auth-v2nocreds.yml"}, true)
	if err != nil {
		t.Errorf("Error loading config %v: %v", "testdata/snmp-auth-v2nocreds.yml", err)
	}
}
