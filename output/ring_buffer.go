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

import "github.com/prometheus/snmp_exporter/sample"

// ringBuffer is the fixed-size in-memory storage used by AsyncOutput.
type ringBuffer struct {
	values []sample.Sample
	head   int
	size   int
}

func newRingBuffer(capacity int) ringBuffer {
	return ringBuffer{values: make([]sample.Sample, capacity)}
}

// push appends a sample and overwrites the oldest queued sample when full.
func (q *ringBuffer) push(value sample.Sample) bool {
	if q.size < len(q.values) {
		index := (q.head + q.size) % len(q.values)
		q.values[index] = value
		q.size++
		return false
	}
	q.values[q.head] = value
	q.head = (q.head + 1) % len(q.values)
	return true
}

func (q *ringBuffer) pop(maximum int) []sample.Sample {
	count := min(maximum, q.size)
	if count == 0 {
		return nil
	}
	result := make([]sample.Sample, count)
	for index := range count {
		position := (q.head + index) % len(q.values)
		result[index] = q.values[position]
		q.values[position] = sample.Sample{}
	}
	q.head = (q.head + count) % len(q.values)
	q.size -= count
	return result
}

func (q *ringBuffer) discard() int {
	count := q.size
	for q.size > 0 {
		q.pop(q.size)
	}
	return count
}
