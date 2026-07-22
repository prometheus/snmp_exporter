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

// Package sample defines the collector's output-independent metric model.
package sample

import (
	"fmt"
	"regexp"
	"unicode/utf8"
)

// MetricType describes the semantic type of a sample.
type MetricType string

const (
	MetricGauge   MetricType = "gauge"
	MetricCounter MetricType = "counter"
	MetricInfo    MetricType = "info"
)

var (
	metricNameRE = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)
	labelNameRE  = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
)

// Sample is a single metric value produced by one device poll. Timestamp is
// expressed as Unix milliseconds.
//
// Labels must not be mutated once the sample has been handed to an output.
// Clone creates an independent copy for asynchronous ownership transfer.
type Sample struct {
	Name      string
	Value     float64
	Timestamp int64
	Labels    map[string]string
	Type      MetricType
	OID       string
	DeviceID  string
	PollID    string
}

// Validate checks invariants shared by every output implementation.
func (s Sample) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("sample name is required")
	}
	if !metricNameRE.MatchString(s.Name) {
		return fmt.Errorf("invalid sample name %q", s.Name)
	}
	if s.Timestamp == 0 {
		return fmt.Errorf("sample timestamp is required")
	}
	if s.DeviceID == "" {
		return fmt.Errorf("sample device ID is required")
	}
	if s.PollID == "" {
		return fmt.Errorf("sample poll ID is required")
	}
	if !s.Type.valid() {
		return fmt.Errorf("invalid sample metric type %q", s.Type)
	}
	for name, value := range s.Labels {
		if name == "__name__" {
			return fmt.Errorf("label %q is reserved", name)
		}
		if !labelNameRE.MatchString(name) {
			return fmt.Errorf("invalid label name %q", name)
		}
		if !utf8.ValidString(value) {
			return fmt.Errorf("label %q has an invalid UTF-8 value", name)
		}
	}
	return nil
}

func (t MetricType) valid() bool {
	switch t {
	case MetricGauge, MetricCounter, MetricInfo:
		return true
	default:
		return false
	}
}

// Clone returns a sample whose Labels map can be mutated independently from
// the source sample. A nil Labels map remains nil.
func (s Sample) Clone() Sample {
	s.Labels = CloneLabels(s.Labels)
	return s
}

// CloneLabels returns an independent copy of labels.
func CloneLabels(labels map[string]string) map[string]string {
	if labels == nil {
		return nil
	}
	cloned := make(map[string]string, len(labels))
	for name, value := range labels {
		cloned[name] = value
	}
	return cloned
}
