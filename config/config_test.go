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

package config

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v2"
)

func TestInvalidIndexType(t *testing.T) {
	content := `
modules:
  module1:
    metrics:
      - name: metric1
        oid: 1.2.3
        type: gauge
        help: A metric
        indexes:
          - labelname: index1
            type: DateAndTime
`
	cfg := &Config{}
	err := yaml.UnmarshalStrict([]byte(content), cfg)
	if err == nil {
		t.Fatal("Expected invalid index type to fail config parsing")
	}
	if !strings.Contains(err.Error(), `invalid index type "DateAndTime"`) {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestBitValues(t *testing.T) {
	cases := []struct {
		name    string
		typ     string
		values  string
		wantErr string
	}{
		{name: "valid", typ: "BitsAsStateSet", values: `{0: foo, 63: bar}`},
		{name: "not set on other types", typ: "gauge"},
		{name: "missing", typ: "BitsAsStateSet", wantErr: `metric "metric1": type BitsAsStateSet requires bit_values`},
		{name: "wrong type", typ: "gauge", values: `{0: foo}`, wantErr: `metric "metric1": bit_values requires type BitsAsStateSet, got "gauge"`},
		{name: "negative bit", typ: "BitsAsStateSet", values: `{-1: foo}`, wantErr: `metric "metric1": bit_values position -1 is out of range 0-63`},
		{name: "bit too high", typ: "BitsAsStateSet", values: `{64: foo}`, wantErr: `metric "metric1": bit_values position 64 is out of range 0-63`},
		{name: "empty name", typ: "BitsAsStateSet", values: `{3: ""}`, wantErr: `metric "metric1": bit_values position 3 has an empty name`},
		{name: "duplicate name", typ: "BitsAsStateSet", values: `{1: foo, 2: foo}`, wantErr: `metric "metric1": bit_values name "foo" is used more than once`},
		{name: "position not a number", typ: "BitsAsStateSet", values: `{a: foo}`, wantErr: `cannot unmarshal !!str`},
		{name: "invalid metric", typ: "[]", wantErr: `cannot unmarshal !!seq`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			content := "modules:\n  module1:\n    metrics:\n      - name: metric1\n        oid: 1.2.3\n        help: A metric\n        type: " + c.typ + "\n"
			if c.values != "" {
				content += "        bit_values: " + c.values + "\n"
			}
			err := yaml.UnmarshalStrict([]byte(content), &Config{})
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Expected config parsing to fail")
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("Unexpected error: %v", err)
			}
		})
	}
}

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
