package main

import (
	"strings"
	"testing"

	yaml "gopkg.in/yaml.v2"
)

func TestHideConfigSecrets(t *testing.T) {
	sc := &SafeConfig{}
	err := sc.ReloadConfig("testdata/snmp-auth.yml")
	if err != nil {
		t.Errorf("Error loading config %v: %v", "testdata/snmp-auth.yml", err)
	}

	// String method must not reveal authentication credentials.
	sc.RLock()
	c, err := yaml.Marshal(sc.C)
	sc.RUnlock()
	if err != nil {
		t.Errorf("Error marshalling config: %v", err)
	}
	if strings.Contains(string(c), "mysecret") {
		t.Fatal("config's String method reveals authentication credentials.")
	}
}

func TestLoadConfigWithOverrides(t *testing.T) {
	sc := &SafeConfig{}
	err := sc.ReloadConfig("testdata/snmp-with-overrides.yml")
	if err != nil {
		t.Errorf("Error loading config %v: %v", "testdata/snmp-with-overrides.yml", err)
	}
	sc.RLock()
	_, err = yaml.Marshal(sc.C)
	sc.RUnlock()
	if err != nil {
		t.Errorf("Error marshalling config: %v", err)
	}
}
