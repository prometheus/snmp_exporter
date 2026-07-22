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
	"strings"
	"testing"

	"github.com/prometheus/prometheus/prompb"

	"github.com/prometheus/snmp_exporter/sample"
)

func TestBuildWriteRequestSortsGroupsAndDeduplicates(t *testing.T) {
	batch := []sample.Sample{
		remoteSample("ifInOctets", 2, 20, map[string]string{"z": "last", "a": "first"}),
		remoteSample("ifInOctets", 1, 10, map[string]string{"a": "first", "z": "last"}),
		remoteSample("ifInOctets", 2, 21, map[string]string{"z": "last", "a": "first"}),
		remoteSample("ifOutOctets", 1, 30, nil),
	}
	request, err := buildWriteRequest(batch)
	if err != nil {
		t.Fatalf("buildWriteRequest() returned unexpected error: %v", err)
	}
	if len(request.Timeseries) != 2 {
		t.Fatalf("timeseries count = %d, want 2", len(request.Timeseries))
	}

	byName := make(map[string]prompb.TimeSeries)
	for _, series := range request.Timeseries {
		for _, label := range series.Labels {
			if label.Name == "__name__" {
				byName[label.Value] = series
			}
		}
	}
	in := byName["ifInOctets"]
	wantLabels := []prompb.Label{
		{Name: "__name__", Value: "ifInOctets"},
		{Name: "a", Value: "first"},
		{Name: "device_id", Value: "switch-01"},
		{Name: "z", Value: "last"},
	}
	if len(in.Labels) != len(wantLabels) {
		t.Fatalf("ifInOctets labels = %#v, want %#v", in.Labels, wantLabels)
	}
	for index := range wantLabels {
		if in.Labels[index].Name != wantLabels[index].Name || in.Labels[index].Value != wantLabels[index].Value {
			t.Fatalf("ifInOctets labels = %#v, want sorted %#v", in.Labels, wantLabels)
		}
	}
	if len(in.Samples) != 2 {
		t.Fatalf("ifInOctets samples = %#v, want two deduplicated timestamps", in.Samples)
	}
	if in.Samples[0].Timestamp != 1 || in.Samples[0].Value != 10 ||
		in.Samples[1].Timestamp != 2 || in.Samples[1].Value != 21 {
		t.Fatalf("ifInOctets samples = %#v, want ordered timestamps with last duplicate winning", in.Samples)
	}
}

func TestBuildWriteRequestRejectsDeviceLabelConflict(t *testing.T) {
	current := remoteSample("sysUpTime", 1, 1, map[string]string{"device_id": "different-device"})
	_, err := buildWriteRequest([]sample.Sample{current})
	if err == nil || !strings.Contains(err.Error(), "conflicts with sample device ID") {
		t.Fatalf("buildWriteRequest() error = %v, want device label conflict", err)
	}
}

func remoteSample(name string, timestamp int64, value float64, labels map[string]string) sample.Sample {
	return sample.Sample{
		Name:      name,
		Value:     value,
		Timestamp: timestamp,
		Labels:    labels,
		Type:      sample.MetricCounter,
		DeviceID:  "switch-01",
		PollID:    "poll-01",
	}
}
