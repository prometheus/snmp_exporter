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

package sample

import (
	"strings"
	"testing"
)

func TestSampleValidate(t *testing.T) {
	valid := Sample{
		Name:      "ifHCInOctets",
		Value:     42,
		Timestamp: 1_721_558_400_000,
		Labels: map[string]string{
			"ifIndex": "1",
			"site":    "dc01",
		},
		Type:     MetricCounter,
		OID:      "1.3.6.1.2.1.31.1.1.1.6.1",
		DeviceID: "core-switch-01",
		PollID:   "poll-01",
	}

	tests := []struct {
		name    string
		mutate  func(*Sample)
		wantErr string
	}{
		{name: "valid"},
		{name: "missing name", mutate: func(s *Sample) { s.Name = "" }, wantErr: "name is required"},
		{name: "invalid name", mutate: func(s *Sample) { s.Name = "invalid-name" }, wantErr: "invalid sample name"},
		{name: "missing timestamp", mutate: func(s *Sample) { s.Timestamp = 0 }, wantErr: "timestamp is required"},
		{name: "missing device ID", mutate: func(s *Sample) { s.DeviceID = "" }, wantErr: "device ID is required"},
		{name: "missing poll ID", mutate: func(s *Sample) { s.PollID = "" }, wantErr: "poll ID is required"},
		{name: "invalid metric type", mutate: func(s *Sample) { s.Type = "histogram" }, wantErr: "invalid sample metric type"},
		{name: "reserved label", mutate: func(s *Sample) { s.Labels = map[string]string{"__name__": "other"} }, wantErr: "is reserved"},
		{name: "invalid label name", mutate: func(s *Sample) { s.Labels = map[string]string{"site-name": "dc01"} }, wantErr: "invalid label name"},
		{name: "invalid label value", mutate: func(s *Sample) { s.Labels = map[string]string{"site": string([]byte{0xff})} }, wantErr: "invalid UTF-8 value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := valid.Clone()
			if tt.mutate != nil {
				tt.mutate(&got)
			}

			err := got.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() returned unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestSampleCloneCopiesLabels(t *testing.T) {
	original := Sample{Labels: map[string]string{"site": "dc01"}}
	cloned := original.Clone()

	cloned.Labels["site"] = "dc02"
	cloned.Labels["vendor"] = "cisco"

	if got := original.Labels["site"]; got != "dc01" {
		t.Fatalf("original site label = %q, want dc01", got)
	}
	if _, ok := original.Labels["vendor"]; ok {
		t.Fatal("mutating cloned labels added a label to the original")
	}
}

func TestCloneLabelsPreservesNil(t *testing.T) {
	if got := CloneLabels(nil); got != nil {
		t.Fatalf("CloneLabels(nil) = %#v, want nil", got)
	}
}
