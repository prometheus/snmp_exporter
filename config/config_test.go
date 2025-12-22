// Copyright 2025 The Prometheus Authors
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

func TestFormatOpValidation(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string // empty = expect success
	}{
		{
			name:    "valid FormatOp",
			yaml:    `{take: 1, fmt: "d", sep: "."}`,
			wantErr: "",
		},
		{
			name:    "take zero causes infinite loop",
			yaml:    `{take: 0, fmt: "x"}`,
			wantErr: "take must be positive",
		},
		{
			name:    "invalid fmt rejected",
			yaml:    `{take: 1, fmt: "z"}`,
			wantErr: "fmt must be one of",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var op FormatOp
			err := yaml.Unmarshal([]byte(tt.yaml), &op)

			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got %v", tt.wantErr, err)
				}
			}
		})
	}
}
