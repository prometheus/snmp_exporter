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

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/prometheus/snmp_exporter/sample"
)

type recordingSender struct {
	mu        sync.Mutex
	started   bool
	closed    bool
	sendCount int
	sendFn    func(context.Context, []sample.Sample) error
	batches   chan []sample.Sample
	readyErr  error
}

func (s *recordingSender) Start(context.Context) error {
	s.mu.Lock()
	s.started = true
	s.mu.Unlock()
	return nil
}

func (s *recordingSender) Send(ctx context.Context, batch []sample.Sample) error {
	s.mu.Lock()
	s.sendCount++
	sendFn := s.sendFn
	s.mu.Unlock()
	if sendFn != nil {
		if err := sendFn(ctx, batch); err != nil {
			return err
		}
	}
	if s.batches != nil {
		frozen := make([]sample.Sample, len(batch))
		for index := range batch {
			frozen[index] = batch[index].Clone()
		}
		select {
		case s.batches <- frozen:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (s *recordingSender) Ready() error { return s.readyErr }

func (s *recordingSender) Close(context.Context) error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

func (s *recordingSender) sends() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sendCount
}

func TestAsyncOutputDropsOldestAndFreezesSamples(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)
	sender := &recordingSender{batches: make(chan []sample.Sample, 1)}
	queued := newTestAsync(t, QueueConfig{
		Capacity:        3,
		MaxBatchSamples: 10,
		FlushInterval:   time.Hour,
		OverflowPolicy:  DropOldest,
		RetryMinBackoff: time.Millisecond,
		RetryMaxBackoff: time.Second,
		RequestTimeout:  time.Second,
	}, sender, func(error) bool { return false }, metrics)
	startOutput(t, queued)

	batch := []sample.Sample{
		testSample(1),
		testSample(2),
		testSample(3),
		testSample(4),
	}
	if err := queued.Write(context.Background(), batch); err != nil {
		t.Fatalf("Write() returned unexpected error: %v", err)
	}
	batch[1].Labels["site"] = "mutated"
	if err := queued.Flush(context.Background()); err != nil {
		t.Fatalf("Flush() returned unexpected error: %v", err)
	}

	got := waitBatch(t, sender.batches)
	if len(got) != 3 {
		t.Fatalf("sent batch length = %d, want 3", len(got))
	}
	for index, want := range []float64{2, 3, 4} {
		if got[index].Value != want {
			t.Errorf("sent sample %d value = %v, want %v", index, got[index].Value, want)
		}
	}
	if got[0].Labels["site"] != "dc01" {
		t.Fatalf("queued sample label = %q, want immutable dc01", got[0].Labels["site"])
	}
	if value := counterValue(t, metrics.DroppedTotal.WithLabelValues("remote_write", "queue_full")); value != 1 {
		t.Fatalf("queue_full dropped counter = %v, want 1", value)
	}
	closeOutput(t, queued)
}

func TestAsyncOutputRetriesSameBatch(t *testing.T) {
	transient := errors.New("transient")
	sender := &recordingSender{batches: make(chan []sample.Sample, 1)}
	sender.sendFn = func(context.Context, []sample.Sample) error {
		if sender.sends() <= 2 {
			return transient
		}
		return nil
	}
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)
	queued := newTestAsync(t, testQueueConfig(), sender, func(err error) bool {
		return errors.Is(err, transient)
	}, metrics)
	queued.waitRetry = func(context.Context, time.Duration) bool { return true }
	startOutput(t, queued)

	if err := queued.Write(context.Background(), []sample.Sample{testSample(1)}); err != nil {
		t.Fatalf("Write() returned unexpected error: %v", err)
	}
	got := waitBatch(t, sender.batches)
	if len(got) != 1 || got[0].Value != 1 {
		t.Fatalf("retried batch = %#v, want the original sample", got)
	}
	if sender.sends() != 3 {
		t.Fatalf("sender attempts = %d, want 3", sender.sends())
	}
	if value := counterValue(t, metrics.RetriesTotal.WithLabelValues("remote_write")); value != 2 {
		t.Fatalf("retry counter = %v, want 2", value)
	}
	closeOutput(t, queued)
}

func TestAsyncOutputBatchesBySampleLimit(t *testing.T) {
	sender := &recordingSender{batches: make(chan []sample.Sample, 3)}
	config := testQueueConfig()
	config.MaxBatchSamples = 2
	queued := newTestAsync(t, config, sender, func(error) bool { return false }, Metrics{})
	startOutput(t, queued)

	batch := []sample.Sample{
		testSample(1),
		testSample(2),
		testSample(3),
		testSample(4),
		testSample(5),
	}
	if err := queued.Write(context.Background(), batch); err != nil {
		t.Fatalf("Write() returned unexpected error: %v", err)
	}
	if err := queued.Flush(context.Background()); err != nil {
		t.Fatalf("Flush() returned unexpected error: %v", err)
	}

	var values []float64
	for len(values) < len(batch) {
		sent := waitBatch(t, sender.batches)
		if len(sent) > config.MaxBatchSamples {
			t.Fatalf("sent batch length = %d, limit %d", len(sent), config.MaxBatchSamples)
		}
		for _, current := range sent {
			values = append(values, current.Value)
		}
	}
	for index, want := range []float64{1, 2, 3, 4, 5} {
		if values[index] != want {
			t.Fatalf("sent values = %v, want ordered values 1..5", values)
		}
	}
	closeOutput(t, queued)
}

func TestAsyncOutputBlockedSenderDoesNotBlockWrite(t *testing.T) {
	sendStarted := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	sender := &recordingSender{}
	sender.sendFn = func(ctx context.Context, _ []sample.Sample) error {
		once.Do(func() { close(sendStarted) })
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	queued := newTestAsync(t, testQueueConfig(), sender, func(error) bool { return false }, Metrics{})
	startOutput(t, queued)

	if err := queued.Write(context.Background(), []sample.Sample{testSample(1)}); err != nil {
		t.Fatalf("first Write() returned unexpected error: %v", err)
	}
	select {
	case <-sendStarted:
	case <-time.After(time.Second):
		t.Fatal("sender did not receive first batch")
	}

	writeDone := make(chan error, 1)
	go func() {
		writeDone <- queued.Write(context.Background(), []sample.Sample{testSample(2)})
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("second Write() returned unexpected error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Write() blocked behind downstream sender")
	}
	close(release)
	closeOutput(t, queued)
}

func TestAsyncOutputRejectsInvalidBatchAtomically(t *testing.T) {
	sender := &recordingSender{batches: make(chan []sample.Sample, 1)}
	queued := newTestAsync(t, testQueueConfig(), sender, func(error) bool { return false }, Metrics{})
	startOutput(t, queued)

	batch := []sample.Sample{testSample(1), testSample(2)}
	batch[1].PollID = ""
	if err := queued.Write(context.Background(), batch); err == nil {
		t.Fatal("Write() accepted an invalid batch")
	}
	if err := queued.Flush(context.Background()); err != nil {
		t.Fatalf("Flush() returned unexpected error: %v", err)
	}
	select {
	case got := <-sender.batches:
		t.Fatalf("invalid batch was partially sent: %#v", got)
	default:
	}
	closeOutput(t, queued)
}

func newTestAsync(t *testing.T, config QueueConfig, sender Sender, retryable RetryClassifier, metrics Metrics) *AsyncOutput {
	t.Helper()
	queued, err := NewAsync("remote_write", config, sender, retryable, metrics)
	if err != nil {
		t.Fatalf("NewAsync() returned unexpected error: %v", err)
	}
	return queued
}

func testQueueConfig() QueueConfig {
	return QueueConfig{
		Capacity:        10,
		MaxBatchSamples: 1,
		FlushInterval:   time.Hour,
		OverflowPolicy:  DropOldest,
		RetryMinBackoff: time.Millisecond,
		RetryMaxBackoff: time.Second,
		RequestTimeout:  time.Second,
	}
}

func testSample(value float64) sample.Sample {
	return sample.Sample{
		Name:      "sysUpTime",
		Value:     value,
		Timestamp: 1,
		Labels:    map[string]string{"site": "dc01"},
		Type:      sample.MetricCounter,
		DeviceID:  "switch-01",
		PollID:    "poll-01",
	}
}

func startOutput(t *testing.T, queued *AsyncOutput) {
	t.Helper()
	if err := queued.Start(context.Background()); err != nil {
		t.Fatalf("Start() returned unexpected error: %v", err)
	}
}

func closeOutput(t *testing.T, queued *AsyncOutput) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := queued.Close(ctx); err != nil {
		t.Fatalf("Close() returned unexpected error: %v", err)
	}
}

func waitBatch(t *testing.T, batches <-chan []sample.Sample) []sample.Sample {
	t.Helper()
	select {
	case batch := <-batches:
		return batch
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for output batch")
		return nil
	}
}

func counterValue(t *testing.T, counter prometheus.Counter) float64 {
	t.Helper()
	metric := &dto.Metric{}
	if err := counter.Write(metric); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	return metric.GetCounter().GetValue()
}
