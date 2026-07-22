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
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/golang/snappy"
	"github.com/prometheus/prometheus/prompb"

	"github.com/prometheus/snmp_exporter/sample"
)

const deviceIDLabel = "device_id"

type seriesBuilder struct {
	labels  []prompb.Label
	samples map[int64]float64
}

func encode(batch []sample.Sample) ([]byte, error) {
	request, err := buildWriteRequest(batch)
	if err != nil {
		return nil, err
	}
	protobuf, err := request.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal Prometheus remote write request: %w", err)
	}
	return snappy.Encode(nil, protobuf), nil
}

func buildWriteRequest(batch []sample.Sample) (*prompb.WriteRequest, error) {
	seriesByKey := make(map[string]*seriesBuilder)
	for index, current := range batch {
		if err := current.Validate(); err != nil {
			return nil, fmt.Errorf("sample %d is invalid: %w", index, err)
		}
		labels, key, err := remoteWriteLabels(current)
		if err != nil {
			return nil, fmt.Errorf("sample %d: %w", index, err)
		}
		series, exists := seriesByKey[key]
		if !exists {
			series = &seriesBuilder{
				labels:  labels,
				samples: make(map[int64]float64),
			}
			seriesByKey[key] = series
		}
		// Last value wins when a batch contains the same series and timestamp.
		series.samples[current.Timestamp] = current.Value
	}

	keys := make([]string, 0, len(seriesByKey))
	for key := range seriesByKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	request := &prompb.WriteRequest{Timeseries: make([]prompb.TimeSeries, 0, len(keys))}
	for _, key := range keys {
		built := seriesByKey[key]
		timestamps := make([]int64, 0, len(built.samples))
		for timestamp := range built.samples {
			timestamps = append(timestamps, timestamp)
		}
		sort.Slice(timestamps, func(i, j int) bool { return timestamps[i] < timestamps[j] })

		timeseries := prompb.TimeSeries{
			Labels:  built.labels,
			Samples: make([]prompb.Sample, 0, len(timestamps)),
		}
		for _, timestamp := range timestamps {
			timeseries.Samples = append(timeseries.Samples, prompb.Sample{
				Value:     built.samples[timestamp],
				Timestamp: timestamp,
			})
		}
		request.Timeseries = append(request.Timeseries, timeseries)
	}
	return request, nil
}

func remoteWriteLabels(current sample.Sample) ([]prompb.Label, string, error) {
	values := make(map[string]string, len(current.Labels)+2)
	for name, value := range current.Labels {
		values[name] = value
	}
	if configured, exists := values[deviceIDLabel]; exists && configured != current.DeviceID {
		return nil, "", fmt.Errorf("label %q conflicts with sample device ID", deviceIDLabel)
	}
	values[deviceIDLabel] = current.DeviceID
	values["__name__"] = current.Name

	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)

	labels := make([]prompb.Label, 0, len(names))
	var key strings.Builder
	for _, name := range names {
		value := values[name]
		labels = append(labels, prompb.Label{Name: name, Value: value})
		key.WriteString(strconv.Itoa(len(name)))
		key.WriteByte(':')
		key.WriteString(name)
		key.WriteString(strconv.Itoa(len(value)))
		key.WriteByte(':')
		key.WriteString(value)
	}
	return labels, key.String(), nil
}
