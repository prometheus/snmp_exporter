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

package scheduler

import "github.com/prometheus/client_golang/prometheus"

// Metrics contains scheduler collectors. A zero value disables instrumentation
// and is useful for tests and embedding.
type Metrics struct {
	QueueDepth   prometheus.Gauge
	PollSkipped  *prometheus.CounterVec
	WorkerActive prometheus.Gauge
	PollDuration *prometheus.HistogramVec
	PollTotal    *prometheus.CounterVec
	SNMPPackets  prometheus.Counter
	SNMPRetries  prometheus.Counter
}

// NewMetrics registers the scheduler metrics required by the collector spec.
func NewMetrics(registerer prometheus.Registerer) Metrics {
	metrics := Metrics{
		QueueDepth: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "snmpcollector_scheduler_queue_depth",
			Help: "Number of device polls waiting in the scheduler worker queue.",
		}),
		PollSkipped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "snmpcollector_scheduler_poll_skipped_total",
			Help: "Number of scheduled polls skipped or deferred.",
		}, []string{"reason"}),
		WorkerActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "snmpcollector_worker_active",
			Help: "Number of workers currently polling a device.",
		}),
		PollDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "snmpcollector_poll_duration_seconds",
			Help: "Duration of active SNMP polls.",
		}, []string{"profile"}),
		PollTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "snmpcollector_poll_total",
			Help: "Number of completed active SNMP polls.",
		}, []string{"status", "profile"}),
		SNMPPackets: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "snmpcollector_snmp_packets_total",
			Help: "Number of SNMP packets sent by active polls.",
		}),
		SNMPRetries: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "snmpcollector_snmp_retries_total",
			Help: "Number of SNMP packet retries by active polls.",
		}),
	}
	if registerer != nil {
		registerer.MustRegister(
			metrics.QueueDepth,
			metrics.PollSkipped,
			metrics.WorkerActive,
			metrics.PollDuration,
			metrics.PollTotal,
			metrics.SNMPPackets,
			metrics.SNMPRetries,
		)
	}
	return metrics
}
