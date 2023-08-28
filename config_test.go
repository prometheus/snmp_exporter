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
	err := sc.ReloadConfig([]string{"testdata/snmp-auth.yml"})
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
	err := sc.ReloadConfig([]string{"testdata/snmp-with-overrides.yml"})
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
	err := sc.ReloadConfig(configs)
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
