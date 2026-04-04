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

package config

import (
	"testing"

	"go.yaml.in/yaml/v2"
)

func TestWalkParamsRetriesIsolation(t *testing.T) {
	content := `
modules:
  module1:
    retries: 5
  module2: {}
`
	cfg := &Config{}
	if err := yaml.UnmarshalStrict([]byte(content), cfg); err != nil {
		t.Fatalf("Error unmarshaling content: %v", err)
	}

	m1, ok := cfg.Modules["module1"]
	if !ok || m1 == nil {
		t.Fatal("module1 missing or nil")
	}
	m2, ok := cfg.Modules["module2"]
	if !ok || m2 == nil {
		t.Fatal("module2 missing or nil")
	}

	if m1.WalkParams.Retries == nil {
		t.Fatal("module1 retries is nil")
	}
	if m2.WalkParams.Retries == nil {
		t.Fatal("module2 retries is nil")
	}

	if *m1.WalkParams.Retries != 5 {
		t.Errorf("module1 retries: expected 5, got %d", *m1.WalkParams.Retries)
	}

	// This is the core check for the fix to ensure pointers are isolated
	if m1.WalkParams.Retries == m2.WalkParams.Retries {
		t.Error("BUG: module1 and module2 share the same Retries pointer!")
	}
}
