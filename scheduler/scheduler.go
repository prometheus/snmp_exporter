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

// Package scheduler implements bounded, non-overlapping active device polling.
package scheduler

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/prometheus/snmp_exporter/collector"
	snmpconfig "github.com/prometheus/snmp_exporter/config"
	"github.com/prometheus/snmp_exporter/inventory"
	"github.com/prometheus/snmp_exporter/sample"
)

var (
	ErrNotStarted = errors.New("scheduler is not started")
	ErrStopped    = errors.New("scheduler is stopped")
)

// Config controls bounded scheduler resources and retry behavior.
type Config struct {
	Workers           int
	QueueSize         int
	DeliveryQueueSize int
	Jitter            time.Duration
	QueueRetry        time.Duration
	MaxBackoff        time.Duration
}

// Sink receives immutable batches outside polling workers. Output
// implementations should honor context cancellation.
type Sink interface {
	Write(context.Context, []sample.Sample) error
}

type deviceState struct {
	device       inventory.DeviceSnapshot
	profile      collector.ProfileSnapshot
	credentials  collector.Credentials
	nextRun      time.Time
	running      bool
	failureCount uint32
	generation   uint64
	heapIndex    int
}

type pollJob struct {
	deviceID    string
	generation  uint64
	target      collector.TargetSnapshot
	profile     collector.ProfileSnapshot
	credentials collector.Credentials
	timeout     time.Duration
}

type pollCompletion struct {
	deviceID   string
	generation uint64
	profile    string
	startedAt  time.Time
	finishedAt time.Time
	result     collector.PollResult
	err        error
}

type reconcileRequest struct {
	inventory *inventory.Snapshot
	profiles  *snmpconfig.Config
	done      chan error
}

// Scheduler owns device timing state in one event loop.
type Scheduler struct {
	config  Config
	poller  collector.Poller
	sink    Sink
	logger  *slog.Logger
	metrics Metrics

	clock    clock
	jitterFn func(time.Duration) time.Duration

	jobs       chan pollJob
	completed  chan pollCompletion
	deliveries chan []sample.Sample
	reconcile  chan reconcileRequest

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	stopped chan struct{}
	wg      sync.WaitGroup
}

// New creates a scheduler without starting goroutines.
func New(config Config, poller collector.Poller, sink Sink, logger *slog.Logger, metrics Metrics) (*Scheduler, error) {
	if config.Workers <= 0 {
		return nil, fmt.Errorf("scheduler workers must be positive")
	}
	if config.QueueSize <= 0 {
		return nil, fmt.Errorf("scheduler queue size must be positive")
	}
	if config.DeliveryQueueSize <= 0 {
		return nil, fmt.Errorf("scheduler delivery queue size must be positive")
	}
	if config.Jitter < 0 {
		return nil, fmt.Errorf("scheduler jitter must not be negative")
	}
	if config.QueueRetry <= 0 {
		return nil, fmt.Errorf("scheduler queue retry must be positive")
	}
	if config.MaxBackoff <= 0 {
		return nil, fmt.Errorf("scheduler max backoff must be positive")
	}
	if poller == nil {
		return nil, fmt.Errorf("scheduler poller is required")
	}
	if sink == nil {
		return nil, fmt.Errorf("scheduler sink is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("scheduler logger is required")
	}

	return &Scheduler{
		config:     config,
		poller:     poller,
		sink:       sink,
		logger:     logger,
		metrics:    metrics,
		clock:      realClock{},
		jitterFn:   randomJitter,
		jobs:       make(chan pollJob, config.QueueSize),
		completed:  make(chan pollCompletion, config.Workers),
		deliveries: make(chan []sample.Sample, config.DeliveryQueueSize),
		reconcile:  make(chan reconcileRequest),
		stopped:    make(chan struct{}),
	}, nil
}

// Start launches the scheduler event loop, worker pool, and isolated delivery
// loop. A Scheduler cannot be restarted after Stop.
func (s *Scheduler) Start(parent context.Context) error {
	if parent == nil {
		return fmt.Errorf("scheduler context is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return fmt.Errorf("scheduler already started")
	}
	s.started = true
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel

	s.wg.Add(1)
	go s.run(ctx)
	for workerID := 0; workerID < s.config.Workers; workerID++ {
		s.wg.Add(1)
		go s.worker(ctx, workerID)
	}
	s.wg.Add(1)
	go s.deliver(ctx)
	go func() {
		s.wg.Wait()
		close(s.stopped)
	}()
	return nil
}

// Reconcile atomically validates and applies an inventory snapshot. A rejected
// reconciliation leaves all current scheduling state unchanged.
func (s *Scheduler) Reconcile(ctx context.Context, snapshot *inventory.Snapshot, profiles *snmpconfig.Config) error {
	if ctx == nil {
		return fmt.Errorf("reconcile context is required")
	}
	s.mu.Lock()
	started := s.started
	s.mu.Unlock()
	if !started {
		return ErrNotStarted
	}

	request := reconcileRequest{
		inventory: snapshot,
		profiles:  profiles,
		done:      make(chan error, 1),
	}
	select {
	case s.reconcile <- request:
	case <-s.stopped:
		return ErrStopped
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-request.done:
		return err
	case <-s.stopped:
		return ErrStopped
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stop cancels scheduled and active polls, then waits for owned goroutines.
func (s *Scheduler) Stop(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("stop context is required")
	}
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return ErrNotStarted
	}
	cancel := s.cancel
	s.mu.Unlock()
	cancel()

	select {
	case <-s.stopped:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Scheduler) run(ctx context.Context) {
	defer s.wg.Done()
	defer close(s.jobs)

	states := make(map[string]*deviceState)
	schedule := &deviceHeap{}
	heap.Init(schedule)
	timer := s.clock.NewTimer(24 * time.Hour)
	defer timer.Stop()

	for {
		s.resetTimer(timer, schedule)
		select {
		case <-ctx.Done():
			return
		case request := <-s.reconcile:
			request.done <- s.applyReconcile(states, schedule, request, s.clock.Now())
		case completion := <-s.completed:
			s.handleCompletion(states, schedule, completion)
		case <-timer.C():
			s.dispatchDue(states, schedule, s.clock.Now())
		}
	}
}

func (s *Scheduler) applyReconcile(states map[string]*deviceState, schedule *deviceHeap, request reconcileRequest, now time.Time) error {
	desired, err := buildDesired(request.inventory, request.profiles)
	if err != nil {
		return err
	}

	for id, current := range states {
		next, exists := desired[id]
		if !exists {
			schedule.remove(current)
			delete(states, id)
			continue
		}
		if sameRuntime(current, next) {
			delete(desired, id)
			continue
		}
		current.device = next.device
		current.profile = next.profile
		current.credentials = next.credentials
		current.failureCount = 0
		current.generation++
		current.nextRun = now.Add(s.jitterFn(s.config.Jitter))
		schedule.schedule(current)
		delete(desired, id)
	}

	for id, state := range desired {
		state.nextRun = now.Add(s.jitterFn(s.config.Jitter))
		state.generation = 1
		state.heapIndex = -1
		states[id] = state
		schedule.schedule(state)
	}
	return nil
}

func buildDesired(snapshot *inventory.Snapshot, profiles *snmpconfig.Config) (map[string]*deviceState, error) {
	if snapshot == nil {
		return nil, fmt.Errorf("inventory snapshot is required")
	}
	if profiles == nil {
		return nil, fmt.Errorf("SNMP configuration is required")
	}
	desired := make(map[string]*deviceState)
	for id, device := range snapshot.Devices() {
		if !device.Enabled {
			continue
		}
		module, ok := profiles.Modules[device.Profile]
		if !ok || module == nil {
			return nil, fmt.Errorf("profile %q does not exist for device %q", device.Profile, id)
		}
		auth, ok := profiles.Auths[device.Auth]
		if !ok || auth == nil {
			return nil, fmt.Errorf("auth %q does not exist for device %q", device.Auth, id)
		}
		desired[id] = &deviceState{
			device:      device,
			profile:     collector.ProfileSnapshot{Name: device.Profile, Module: module},
			credentials: collector.Credentials{Name: device.Auth, Auth: auth},
			heapIndex:   -1,
		}
	}
	return desired, nil
}

func sameRuntime(current, next *deviceState) bool {
	return current.device.ID == next.device.ID &&
		current.device.Address == next.device.Address &&
		current.device.Profile == next.device.Profile &&
		current.device.Auth == next.device.Auth &&
		current.device.Interval == next.device.Interval &&
		current.device.Timeout == next.device.Timeout &&
		maps.Equal(current.device.Labels, next.device.Labels) &&
		current.profile.Module == next.profile.Module &&
		current.credentials.Auth == next.credentials.Auth
}

func (s *Scheduler) resetTimer(timer timer, schedule *deviceHeap) {
	duration := 24 * time.Hour
	if schedule.Len() > 0 {
		duration = (*schedule)[0].nextRun.Sub(s.clock.Now())
		if duration < 0 {
			duration = 0
		}
	}
	timer.Reset(duration)
}

func (s *Scheduler) dispatchDue(_ map[string]*deviceState, schedule *deviceHeap, now time.Time) {
	for schedule.Len() > 0 {
		state := (*schedule)[0]
		if state.nextRun.After(now) {
			break
		}
		heap.Pop(schedule)
		if state.running {
			s.incSkipped("overlap")
			state.nextRun = nextScheduledRun(state.nextRun, state.device.Interval, now)
			schedule.schedule(state)
			continue
		}

		job := pollJob{
			deviceID:   state.device.ID,
			generation: state.generation,
			target: collector.TargetSnapshot{
				Address:  state.device.Address,
				DeviceID: state.device.ID,
				Labels:   cloneLabels(state.device.Labels),
			},
			profile:     state.profile,
			credentials: state.credentials,
			timeout:     state.device.Timeout,
		}
		select {
		case s.jobs <- job:
			state.running = true
			state.nextRun = nextScheduledRun(state.nextRun, state.device.Interval, now)
		default:
			s.incSkipped("queue_full")
			state.nextRun = now.Add(s.config.QueueRetry)
		}
		schedule.schedule(state)
	}
	if s.metrics.QueueDepth != nil {
		s.metrics.QueueDepth.Set(float64(len(s.jobs)))
	}
}

func (s *Scheduler) handleCompletion(states map[string]*deviceState, schedule *deviceHeap, completion pollCompletion) {
	duration := completion.finishedAt.Sub(completion.startedAt)
	if !completion.result.StartedAt.IsZero() && !completion.result.EndedAt.IsZero() {
		duration = completion.result.EndedAt.Sub(completion.result.StartedAt)
	}
	if s.metrics.PollDuration != nil {
		s.metrics.PollDuration.WithLabelValues(completion.profile).Observe(duration.Seconds())
	}
	if s.metrics.SNMPPackets != nil {
		s.metrics.SNMPPackets.Add(float64(completion.result.Packets))
	}
	if s.metrics.SNMPRetries != nil {
		s.metrics.SNMPRetries.Add(float64(completion.result.Retries))
	}

	if completion.err != nil {
		if s.metrics.PollTotal != nil {
			s.metrics.PollTotal.WithLabelValues("error", completion.profile).Inc()
		}
		s.logger.Warn("Device poll failed",
			"component", "scheduler",
			"device_id", completion.deviceID,
			"profile", completion.profile,
			"err", completion.err,
		)
	} else {
		if s.metrics.PollTotal != nil {
			s.metrics.PollTotal.WithLabelValues("success", completion.profile).Inc()
		}
	}
	s.enqueueDelivery(completion.result.Samples)

	state, exists := states[completion.deviceID]
	if !exists {
		return
	}
	state.running = false

	if completion.generation != state.generation {
		state.failureCount = 0
		if !state.nextRun.After(completion.finishedAt) {
			state.nextRun = completion.finishedAt.Add(s.jitterFn(s.config.Jitter))
		}
		schedule.schedule(state)
		return
	}

	if completion.err != nil {
		state.failureCount++
		state.nextRun = completion.finishedAt.Add(s.backoff(state.device.Interval, state.failureCount))
		schedule.schedule(state)
		return
	}
	state.failureCount = 0
	if !state.nextRun.After(completion.finishedAt) {
		state.nextRun = nextScheduledRun(state.nextRun, state.device.Interval, completion.finishedAt)
	}
	schedule.schedule(state)
}

func (s *Scheduler) worker(ctx context.Context, workerID int) {
	defer s.wg.Done()
	logger := s.logger.With("component", "worker", "worker", workerID)
	for {
		select {
		case <-ctx.Done():
			return
		case job, ok := <-s.jobs:
			if !ok {
				return
			}
			if ctx.Err() != nil {
				return
			}
			if s.metrics.QueueDepth != nil {
				s.metrics.QueueDepth.Set(float64(len(s.jobs)))
			}
			if s.metrics.WorkerActive != nil {
				s.metrics.WorkerActive.Inc()
			}
			startedAt := s.clock.Now()
			pollCtx, cancel := context.WithTimeout(ctx, job.timeout)
			result, err := s.poller.Poll(pollCtx, job.target, job.profile, job.credentials)
			cancel()
			finishedAt := s.clock.Now()
			if s.metrics.WorkerActive != nil {
				s.metrics.WorkerActive.Dec()
			}
			completion := pollCompletion{
				deviceID:   job.deviceID,
				generation: job.generation,
				profile:    job.profile.Name,
				startedAt:  startedAt,
				finishedAt: finishedAt,
				result:     result,
				err:        err,
			}
			select {
			case s.completed <- completion:
			case <-ctx.Done():
				logger.Debug("Dropping poll completion during shutdown", "device_id", job.deviceID)
				return
			}
		}
	}
}

func (s *Scheduler) enqueueDelivery(samples []sample.Sample) {
	if len(samples) == 0 {
		return
	}
	batch := make([]sample.Sample, len(samples))
	for i := range samples {
		batch[i] = samples[i].Clone()
	}
	select {
	case s.deliveries <- batch:
	default:
		s.incSkipped("delivery_queue_full")
	}
}

func (s *Scheduler) deliver(ctx context.Context) {
	defer s.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case batch := <-s.deliveries:
			if err := s.sink.Write(ctx, batch); err != nil && ctx.Err() == nil {
				s.logger.Warn("Output rejected sample batch", "component", "scheduler", "err", err)
			}
		}
	}
}

func (s *Scheduler) backoff(interval time.Duration, failures uint32) time.Duration {
	backoff := interval
	for count := uint32(1); count < failures && backoff < s.config.MaxBackoff; count++ {
		if backoff > s.config.MaxBackoff/2 {
			backoff = s.config.MaxBackoff
			break
		}
		backoff *= 2
	}
	if backoff > s.config.MaxBackoff {
		backoff = s.config.MaxBackoff
	}
	if backoff == s.config.MaxBackoff {
		return backoff
	}
	maximumJitter := min(s.config.Jitter, s.config.MaxBackoff-backoff)
	return backoff + s.jitterFn(maximumJitter)
}

func (s *Scheduler) incSkipped(reason string) {
	if s.metrics.PollSkipped != nil {
		s.metrics.PollSkipped.WithLabelValues(reason).Inc()
	}
}

func nextScheduledRun(previous time.Time, interval time.Duration, now time.Time) time.Time {
	next := previous.Add(interval)
	if next.After(now) {
		return next
	}
	missed := now.Sub(next)/interval + 1
	return next.Add(missed * interval)
}

func randomJitter(maximum time.Duration) time.Duration {
	if maximum <= 0 {
		return 0
	}
	if maximum == time.Duration(1<<63-1) {
		return time.Duration(rand.Int64())
	}
	return time.Duration(rand.Int64N(int64(maximum) + 1))
}

func cloneLabels(labels map[string]string) map[string]string {
	if labels == nil {
		return nil
	}
	cloned := make(map[string]string, len(labels))
	for name, value := range labels {
		cloned[name] = value
	}
	return cloned
}
