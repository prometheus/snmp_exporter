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

package output

import "github.com/prometheus/client_golang/prometheus"

// Metrics contains output instrumentation. Its zero value disables metrics.
type Metrics struct {
	SamplesTotal       *prometheus.CounterVec
	QueueDepth         *prometheus.GaugeVec
	RetriesTotal       *prometheus.CounterVec
	DroppedTotal       *prometheus.CounterVec
	LastSuccessSeconds *prometheus.GaugeVec
}

// NewMetrics registers output metrics against registerer.
func NewMetrics(registerer prometheus.Registerer) Metrics {
	metrics := Metrics{
		SamplesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "snmpcollector_output_samples_total",
			Help: "Number of samples handled by an output.",
		}, []string{"output", "status"}),
		QueueDepth: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "snmpcollector_output_queue_depth",
			Help: "Number of samples waiting in an output queue.",
		}, []string{"output"}),
		RetriesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "snmpcollector_output_retries_total",
			Help: "Number of retried output requests.",
		}, []string{"output"}),
		DroppedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "snmpcollector_output_dropped_total",
			Help: "Number of samples dropped by an output.",
		}, []string{"output", "reason"}),
		LastSuccessSeconds: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "snmpcollector_output_last_success_timestamp_seconds",
			Help: "Unix timestamp of the last successful output request.",
		}, []string{"output"}),
	}
	if registerer != nil {
		registerer.MustRegister(
			metrics.SamplesTotal,
			metrics.QueueDepth,
			metrics.RetriesTotal,
			metrics.DroppedTotal,
			metrics.LastSuccessSeconds,
		)
	}
	return metrics
}
