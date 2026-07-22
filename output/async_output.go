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
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/snmp_exporter/sample"
)

const DropOldest = "drop_oldest"

type QueueConfig struct {
	Capacity        int           `yaml:"capacity"`
	MaxBatchSamples int           `yaml:"maxBatchSamples"`
	FlushInterval   time.Duration `yaml:"flushInterval"`
	OverflowPolicy  string        `yaml:"overflowPolicy,omitempty"`
	RetryMinBackoff time.Duration `yaml:"retryMinBackoff,omitempty"`
	RetryMaxBackoff time.Duration `yaml:"retryMaxBackoff,omitempty"`
	RequestTimeout  time.Duration `yaml:"requestTimeout,omitempty"`
}

type lifecycleState uint8

const (
	stateNew lifecycleState = iota
	stateStarting
	stateRunning
	stateClosed
)

// AsyncOutput operates a bounded ring buffer and performs batching, retry, and
// downstream delivery outside polling workers.
type AsyncOutput struct {
	id        string
	config    QueueConfig
	sender    Sender
	retryable RetryClassifier
	metrics   Metrics
	logger    *slog.Logger
	now       func() time.Time
	waitRetry func(context.Context, time.Duration) bool
	threshold chan struct{}
	flushNow  chan struct{}
	done      chan struct{}

	mu        sync.Mutex
	state     lifecycleState
	accepting bool
	queue     ringBuffer
	inflight  int
	changed   chan struct{}
	runCtx    context.Context
	cancel    context.CancelFunc

	// deliveryFailures is owned by the run goroutine. It spans batches so a
	// permanent downstream failure cannot emit one log line per flush interval.
	deliveryFailures     uint64
	deliveryFailureSince time.Time
}

func NewAsync(id string, config QueueConfig, sender Sender, retryable RetryClassifier, metrics Metrics, logger *slog.Logger) (*AsyncOutput, error) {
	if id == "" {
		return nil, fmt.Errorf("output ID is required")
	}
	if config.OverflowPolicy == "" {
		config.OverflowPolicy = DropOldest
	}
	if err := ValidateQueueConfig(config); err != nil {
		return nil, err
	}
	if sender == nil {
		return nil, fmt.Errorf("output sender is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("output logger is required")
	}
	if retryable == nil {
		retryable = func(error) bool { return true }
	}

	return &AsyncOutput{
		id:        id,
		config:    config,
		sender:    sender,
		retryable: retryable,
		metrics:   metrics,
		logger:    logger.With("component", "output", "output", id),
		now:       time.Now,
		waitRetry: waitForRetry,
		threshold: make(chan struct{}, 1),
		flushNow:  make(chan struct{}, 1),
		done:      make(chan struct{}),
		queue:     newRingBuffer(config.Capacity),
		changed:   make(chan struct{}),
	}, nil
}

// ValidateQueueConfig validates queue and retry limits without allocating or
// starting an output. An empty overflow policy uses the drop_oldest default.
func ValidateQueueConfig(config QueueConfig) error {
	if config.Capacity <= 0 {
		return fmt.Errorf("output queue capacity must be positive")
	}
	if config.MaxBatchSamples <= 0 {
		return fmt.Errorf("output max batch samples must be positive")
	}
	if config.FlushInterval <= 0 {
		return fmt.Errorf("output flush interval must be positive")
	}
	if config.OverflowPolicy != "" && config.OverflowPolicy != DropOldest {
		return fmt.Errorf("unsupported output overflow policy %q", config.OverflowPolicy)
	}
	if config.RetryMinBackoff <= 0 {
		return fmt.Errorf("output retry minimum backoff must be positive")
	}
	if config.RetryMaxBackoff < config.RetryMinBackoff {
		return fmt.Errorf("output retry maximum backoff must be greater than or equal to minimum backoff")
	}
	if config.RequestTimeout <= 0 {
		return fmt.Errorf("output request timeout must be positive")
	}
	return nil
}

func (q *AsyncOutput) ID() string { return q.id }

func (q *AsyncOutput) Start(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("output context is required")
	}
	q.mu.Lock()
	if q.state != stateNew {
		q.mu.Unlock()
		return fmt.Errorf("output %q cannot be started in its current state", q.id)
	}
	q.state = stateStarting
	q.mu.Unlock()

	if err := q.sender.Start(ctx); err != nil {
		q.mu.Lock()
		q.state = stateClosed
		q.signalChangedLocked()
		q.mu.Unlock()
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	q.mu.Lock()
	q.runCtx = runCtx
	q.cancel = cancel
	q.accepting = true
	q.state = stateRunning
	q.signalChangedLocked()
	q.mu.Unlock()
	go q.run(runCtx)
	return nil
}

// Write validates and copies the complete batch before enqueueing it. It never
// performs downstream I/O.
func (q *AsyncOutput) Write(ctx context.Context, batch []sample.Sample) error {
	if ctx == nil {
		return fmt.Errorf("output write context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(batch) == 0 {
		return nil
	}
	frozen := make([]sample.Sample, len(batch))
	for index := range batch {
		if err := batch[index].Validate(); err != nil {
			q.addSamples("rejected", 1)
			return fmt.Errorf("invalid output sample at index %d: %w", index, err)
		}
		frozen[index] = batch[index].Clone()
	}

	q.mu.Lock()
	if q.state != stateRunning {
		q.mu.Unlock()
		return ErrNotStarted
	}
	if !q.accepting {
		q.mu.Unlock()
		return ErrClosed
	}
	dropped := 0
	for _, current := range frozen {
		if q.queue.push(current) {
			dropped++
		}
	}
	depth := q.queue.size
	q.signalChangedLocked()
	q.mu.Unlock()

	q.addSamples("enqueued", len(frozen))
	q.addDropped("queue_full", dropped)
	q.setQueueDepth(depth)
	if depth >= q.config.MaxBatchSamples {
		q.notify(q.threshold)
	}
	return nil
}

func (q *AsyncOutput) Flush(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("output flush context is required")
	}
	for {
		q.mu.Lock()
		if q.state == stateNew || q.state == stateStarting {
			q.mu.Unlock()
			return ErrNotStarted
		}
		if q.queue.size == 0 && q.inflight == 0 {
			q.mu.Unlock()
			return nil
		}
		changed := q.changed
		runCtx := q.runCtx
		q.mu.Unlock()

		q.notify(q.flushNow)
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		case <-runCtx.Done():
			return ErrClosed
		}
	}
}

func (q *AsyncOutput) Ready() error {
	q.mu.Lock()
	running := q.state == stateRunning
	q.mu.Unlock()
	if !running {
		return ErrNotStarted
	}
	return q.sender.Ready()
}

func (q *AsyncOutput) Close(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("output close context is required")
	}
	q.mu.Lock()
	if q.state == stateClosed {
		q.mu.Unlock()
		return nil
	}
	if q.state != stateRunning {
		q.mu.Unlock()
		return ErrNotStarted
	}
	q.accepting = false
	q.signalChangedLocked()
	cancel := q.cancel
	q.mu.Unlock()

	flushErr := q.Flush(ctx)
	cancel()
	var waitErr error
	select {
	case <-q.done:
	case <-ctx.Done():
		waitErr = ctx.Err()
	}

	q.mu.Lock()
	dropped := q.queue.discard()
	q.inflight = 0
	q.state = stateClosed
	q.signalChangedLocked()
	q.mu.Unlock()
	q.addDropped("shutdown", dropped)
	q.setQueueDepth(0)

	closeErr := q.sender.Close(ctx)
	return errors.Join(flushErr, waitErr, closeErr)
}

func (q *AsyncOutput) run(ctx context.Context) {
	defer close(q.done)
	ticker := time.NewTicker(q.config.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-q.threshold:
			q.drain(ctx, false)
		case <-q.flushNow:
			q.drain(ctx, true)
		case <-ticker.C:
			q.drain(ctx, true)
		}
	}
}

func (q *AsyncOutput) drain(ctx context.Context, flushAll bool) {
	for {
		batch := q.takeBatch(flushAll)
		if len(batch) == 0 {
			return
		}
		err := q.sendWithRetry(ctx, batch)
		reason := ""
		if err != nil {
			if ctx.Err() != nil {
				reason = "shutdown"
			} else {
				reason = "non_retryable"
			}
		}
		q.finishBatch(len(batch), err, reason)
		if ctx.Err() != nil {
			return
		}
	}
}

func (q *AsyncOutput) takeBatch(flushAll bool) []sample.Sample {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.queue.size == 0 || (!flushAll && q.queue.size < q.config.MaxBatchSamples) {
		return nil
	}
	batch := q.queue.pop(q.config.MaxBatchSamples)
	q.inflight = len(batch)
	q.signalChangedLocked()
	q.setQueueDepth(q.queue.size)
	return batch
}

func (q *AsyncOutput) finishBatch(count int, err error, dropReason string) {
	q.mu.Lock()
	q.inflight = 0
	q.signalChangedLocked()
	q.mu.Unlock()
	if err == nil {
		q.addSamples("sent", count)
		if q.metrics.LastSuccessSeconds != nil {
			q.metrics.LastSuccessSeconds.WithLabelValues(q.id).Set(float64(q.now().Unix()))
		}
		return
	}
	q.addDropped(dropReason, count)
}

func (q *AsyncOutput) sendWithRetry(ctx context.Context, batch []sample.Sample) error {
	backoff := q.config.RetryMinBackoff
	for {
		requestCtx, cancel := context.WithTimeout(ctx, q.config.RequestTimeout)
		err := q.sender.Send(requestCtx, batch)
		cancel()
		if err == nil {
			q.logDeliveryRecovered(len(batch))
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !q.retryable(err) {
			q.logDeliveryFailure(err, len(batch), false, 0)
			return err
		}
		q.logDeliveryFailure(err, len(batch), true, backoff)
		if q.metrics.RetriesTotal != nil {
			q.metrics.RetriesTotal.WithLabelValues(q.id).Inc()
		}
		if !q.waitRetry(ctx, backoff) {
			return ctx.Err()
		}
		if backoff < q.config.RetryMaxBackoff {
			backoff = min(backoff*2, q.config.RetryMaxBackoff)
		}
	}
}

func (q *AsyncOutput) logDeliveryFailure(err error, batchSamples int, retrying bool, retryIn time.Duration) {
	if q.deliveryFailures == 0 {
		q.deliveryFailureSince = q.now()
	}
	q.deliveryFailures++
	if !shouldLogFailure(q.deliveryFailures) {
		return
	}

	attributes := []any{
		"err", err,
		"batch_samples", batchSamples,
		"consecutive_failures", q.deliveryFailures,
	}
	if retrying {
		attributes = append(attributes, "retry_in", retryIn)
		q.logger.Warn("Output delivery failed; retrying", attributes...)
		return
	}
	q.logger.Warn("Output delivery failed; dropping batch", attributes...)
}

func (q *AsyncOutput) logDeliveryRecovered(batchSamples int) {
	if q.deliveryFailures == 0 {
		return
	}
	failures := q.deliveryFailures
	failureSince := q.deliveryFailureSince
	q.deliveryFailures = 0
	q.deliveryFailureSince = time.Time{}
	q.logger.Info("Output delivery recovered",
		"batch_samples", batchSamples,
		"failed_attempts", failures,
		"failure_duration", q.now().Sub(failureSince),
	)
}

func shouldLogFailure(failures uint64) bool {
	// Log the first failure and powers of two after that. At a capped retry
	// interval this provides periodic evidence of a continuing outage without
	// writing one warning for every request.
	return failures != 0 && failures&(failures-1) == 0
}

func (q *AsyncOutput) signalChangedLocked() {
	close(q.changed)
	q.changed = make(chan struct{})
}

func (q *AsyncOutput) notify(channel chan<- struct{}) {
	select {
	case channel <- struct{}{}:
	default:
	}
}

func (q *AsyncOutput) addSamples(status string, count int) {
	if count > 0 && q.metrics.SamplesTotal != nil {
		q.metrics.SamplesTotal.WithLabelValues(q.id, status).Add(float64(count))
	}
}

func (q *AsyncOutput) addDropped(reason string, count int) {
	if count > 0 && q.metrics.DroppedTotal != nil {
		q.metrics.DroppedTotal.WithLabelValues(q.id, reason).Add(float64(count))
	}
}

func (q *AsyncOutput) setQueueDepth(depth int) {
	if q.metrics.QueueDepth != nil {
		q.metrics.QueueDepth.WithLabelValues(q.id).Set(float64(depth))
	}
}

func waitForRetry(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
