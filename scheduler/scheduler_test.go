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

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"

	"github.com/prometheus/snmp_exporter/collector"
	snmpconfig "github.com/prometheus/snmp_exporter/config"
	"github.com/prometheus/snmp_exporter/inventory"
	"github.com/prometheus/snmp_exporter/sample"
)

type fakeClock struct {
	mu          sync.Mutex
	now         time.Time
	timers      []*fakeTimer
	resetEvents chan struct{}
}

type fakeTimer struct {
	clock    *fakeClock
	channel  chan time.Time
	deadline time.Time
	active   bool
}

func newFakeClock(now time.Time) *fakeClock {
	return &fakeClock{now: now, resetEvents: make(chan struct{}, 100)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) NewTimer(duration time.Duration) timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := &fakeTimer{clock: c, channel: make(chan time.Time, 1)}
	result.resetLocked(duration)
	c.timers = append(c.timers, result)
	return result
}

func (c *fakeClock) Advance(duration time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
	fired := false
	for _, current := range c.timers {
		if current.active && !current.deadline.After(c.now) {
			current.active = false
			current.channel <- c.now
			fired = true
		}
	}
	return fired
}

func (c *fakeClock) advanceAndWait(t *testing.T, duration time.Duration) {
	t.Helper()
	for {
		select {
		case <-c.resetEvents:
		default:
			goto drained
		}
	}
drained:
	if !c.Advance(duration) {
		t.Fatalf("clock advance by %s did not fire a timer", duration)
	}
	select {
	case <-c.resetEvents:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not reset its timer after clock advance")
	}
}

func (c *fakeClock) waitForDeadline(t *testing.T, want time.Time) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		matches := len(c.timers) == 1 && c.timers[0].active && c.timers[0].deadline.Equal(want)
		c.mu.Unlock()
		if matches {
			return
		}
		runtime.Gosched()
	}
	t.Fatalf("scheduler timer did not reach deadline %v", want)
}

func (t *fakeTimer) C() <-chan time.Time { return t.channel }

func (t *fakeTimer) Reset(duration time.Duration) {
	t.clock.mu.Lock()
	t.resetLocked(duration)
	t.clock.mu.Unlock()
	select {
	case t.clock.resetEvents <- struct{}{}:
	default:
	}
}

func (t *fakeTimer) resetLocked(duration time.Duration) {
	t.deadline = t.clock.now.Add(duration)
	t.active = true
	if duration <= 0 {
		t.active = false
		select {
		case t.channel <- t.clock.now:
		default:
		}
	}
}

func (t *fakeTimer) Stop() {
	t.clock.mu.Lock()
	t.active = false
	t.clock.mu.Unlock()
}

type pollResponse struct {
	result collector.PollResult
	err    error
}

type controlledPoller struct {
	started   chan string
	responses chan pollResponse

	mu        sync.Mutex
	active    int
	maxActive int
}

func newControlledPoller() *controlledPoller {
	return &controlledPoller{
		started:   make(chan string, 10),
		responses: make(chan pollResponse),
	}
}

func (p *controlledPoller) Poll(ctx context.Context, target collector.TargetSnapshot, _ collector.ProfileSnapshot, _ collector.Credentials) (collector.PollResult, error) {
	p.mu.Lock()
	p.active++
	if p.active > p.maxActive {
		p.maxActive = p.active
	}
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.active--
		p.mu.Unlock()
	}()

	p.started <- target.DeviceID
	select {
	case response := <-p.responses:
		return response.result, response.err
	case <-ctx.Done():
		return collector.PollResult{}, ctx.Err()
	}
}

func (p *controlledPoller) maximumActive() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.maxActive
}

type scriptedPoller struct {
	mu      sync.Mutex
	errors  []error
	count   int
	started chan int
}

func (p *scriptedPoller) Poll(_ context.Context, target collector.TargetSnapshot, _ collector.ProfileSnapshot, _ collector.Credentials) (collector.PollResult, error) {
	p.mu.Lock()
	p.count++
	call := p.count
	var err error
	if call <= len(p.errors) {
		err = p.errors[call-1]
	}
	p.mu.Unlock()
	p.started <- call
	return collector.PollResult{
		Samples: []sample.Sample{{
			Name:      "sysUpTime",
			Value:     float64(call),
			Timestamp: 1,
			Type:      sample.MetricCounter,
			DeviceID:  target.DeviceID,
			PollID:    fmt.Sprintf("poll-%d", call),
		}},
	}, err
}

type channelSink struct {
	batches chan []sample.Sample
}

func (s *channelSink) Write(ctx context.Context, batch []sample.Sample) error {
	select {
	case s.batches <- batch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type blockingSink struct {
	started chan struct{}
	once    sync.Once
}

func (s *blockingSink) Write(ctx context.Context, _ []sample.Sample) error {
	s.once.Do(func() { close(s.started) })
	<-ctx.Done()
	return ctx.Err()
}

func TestSchedulerPreventsOverlapAndReconcilesDelete(t *testing.T) {
	fake := newFakeClock(time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC))
	poller := newControlledPoller()
	sink := &channelSink{batches: make(chan []sample.Sample, 10)}
	scheduler := newTestScheduler(t, fake, poller, sink, Metrics{})
	startScheduler(t, scheduler)

	profiles := testProfiles()
	if err := scheduler.Reconcile(context.Background(), loadInventory(t, false), profiles); err != nil {
		t.Fatalf("Reconcile() returned unexpected error: %v", err)
	}
	waitForCall(t, poller.started, "switch-01")

	fake.advanceAndWait(t, 20*time.Second)
	select {
	case deviceID := <-poller.started:
		t.Fatalf("overlapping poll started for %q", deviceID)
	default:
	}

	poller.responses <- pollResponse{result: pollResult("switch-01", "poll-01")}
	waitForBatch(t, sink.batches)
	fake.advanceAndWait(t, 10*time.Second)
	waitForCall(t, poller.started, "switch-01")
	if poller.maximumActive() != 1 {
		t.Fatalf("maximum concurrent polls for one device = %d, want 1", poller.maximumActive())
	}

	poller.responses <- pollResponse{result: pollResult("switch-01", "poll-02")}
	waitForBatch(t, sink.batches)
	if err := scheduler.Reconcile(context.Background(), loadInventory(t, true), profiles); err != nil {
		t.Fatalf("delete Reconcile() returned unexpected error: %v", err)
	}
	fake.Advance(time.Minute)
	select {
	case deviceID := <-poller.started:
		t.Fatalf("poll started for deleted device %q", deviceID)
	default:
	}
	stopScheduler(t, scheduler)
}

func TestSchedulerAppliesExponentialBackoff(t *testing.T) {
	fake := newFakeClock(time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC))
	poller := &scriptedPoller{
		errors:  []error{errors.New("first failure"), errors.New("second failure")},
		started: make(chan int, 10),
	}
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)
	sink := &channelSink{batches: make(chan []sample.Sample, 10)}
	scheduler := newTestScheduler(t, fake, poller, sink, metrics)
	startScheduler(t, scheduler)

	if err := scheduler.Reconcile(context.Background(), loadInventory(t, false), testProfiles()); err != nil {
		t.Fatalf("Reconcile() returned unexpected error: %v", err)
	}
	waitForCall(t, poller.started, 1)
	waitForCounter(t, metrics.PollTotal.WithLabelValues("error", "if_mib"), 1)

	if fake.Advance(9 * time.Second) {
		t.Fatal("poll timer fired before first backoff elapsed")
	}
	fake.advanceAndWait(t, time.Second)
	waitForCall(t, poller.started, 2)
	waitForCounter(t, metrics.PollTotal.WithLabelValues("error", "if_mib"), 2)
	fake.waitForDeadline(t, fake.Now().Add(20*time.Second))

	if fake.Advance(19 * time.Second) {
		t.Fatal("poll timer fired before exponential backoff elapsed")
	}
	fake.advanceAndWait(t, time.Second)
	waitForCall(t, poller.started, 3)
	stopScheduler(t, scheduler)
}

func TestBlockedDeliveryDoesNotBlockPolling(t *testing.T) {
	fake := newFakeClock(time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC))
	poller := &scriptedPoller{started: make(chan int, 10)}
	sink := &blockingSink{started: make(chan struct{})}
	scheduler := newTestScheduler(t, fake, poller, sink, Metrics{})
	startScheduler(t, scheduler)

	if err := scheduler.Reconcile(context.Background(), loadInventory(t, false), testProfiles()); err != nil {
		t.Fatalf("Reconcile() returned unexpected error: %v", err)
	}
	waitForCall(t, poller.started, 1)
	select {
	case <-sink.started:
	case <-time.After(time.Second):
		t.Fatal("delivery did not reach blocking sink")
	}

	fake.advanceAndWait(t, 10*time.Second)
	waitForCall(t, poller.started, 2)
	stopScheduler(t, scheduler)
}

func TestDispatchDueReschedulesWhenQueueIsFull(t *testing.T) {
	now := time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC)
	registry := prometheus.NewRegistry()
	metrics := NewMetrics(registry)
	poller := &scriptedPoller{started: make(chan int, 1)}
	sink := &channelSink{batches: make(chan []sample.Sample, 1)}
	scheduler, err := New(Config{
		Workers:           1,
		QueueSize:         1,
		DeliveryQueueSize: 1,
		QueueRetry:        2 * time.Second,
		MaxBackoff:        time.Minute,
	}, poller, sink, promslog.NewNopLogger(), metrics)
	if err != nil {
		t.Fatalf("New() returned unexpected error: %v", err)
	}

	states := map[string]*deviceState{}
	schedule := &deviceHeap{}
	heap.Init(schedule)
	for _, id := range []string{"switch-01", "switch-02"} {
		state := &deviceState{
			device: inventory.DeviceSnapshot{
				ID:       id,
				Address:  "udp://192.0.2.1:161",
				Interval: 10 * time.Second,
				Timeout:  time.Second,
			},
			nextRun:    now,
			generation: 1,
			heapIndex:  -1,
		}
		states[id] = state
		schedule.schedule(state)
	}

	scheduler.dispatchDue(states, schedule, now)
	if len(scheduler.jobs) != 1 {
		t.Fatalf("worker queue depth = %d, want 1", len(scheduler.jobs))
	}
	if schedule.Len() != 2 {
		t.Fatalf("scheduled entries = %d, want one per device", schedule.Len())
	}
	if got := counterValue(t, metrics.PollSkipped.WithLabelValues("queue_full")); got != 1 {
		t.Fatalf("queue_full skipped counter = %v, want 1", got)
	}
	if next := (*schedule)[0].nextRun; !next.Equal(now.Add(2 * time.Second)) {
		t.Fatalf("queue-full retry = %v, want %v", next, now.Add(2*time.Second))
	}
}

func newTestScheduler(t *testing.T, fake *fakeClock, poller collector.Poller, sink Sink, metrics Metrics) *Scheduler {
	t.Helper()
	result, err := New(Config{
		Workers:           2,
		QueueSize:         4,
		DeliveryQueueSize: 2,
		Jitter:            0,
		QueueRetry:        time.Second,
		MaxBackoff:        time.Minute,
	}, poller, sink, promslog.NewNopLogger(), metrics)
	if err != nil {
		t.Fatalf("New() returned unexpected error: %v", err)
	}
	result.clock = fake
	result.jitterFn = func(time.Duration) time.Duration { return 0 }
	return result
}

func startScheduler(t *testing.T, scheduler *Scheduler) {
	t.Helper()
	if err := scheduler.Start(context.Background()); err != nil {
		t.Fatalf("Start() returned unexpected error: %v", err)
	}
}

func stopScheduler(t *testing.T, scheduler *Scheduler) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := scheduler.Stop(ctx); err != nil {
		t.Fatalf("Stop() returned unexpected error: %v", err)
	}
}

func loadInventory(t *testing.T, empty bool) *inventory.Snapshot {
	t.Helper()
	lines := []string{"devices:"}
	if !empty {
		lines = append(lines,
			"  - id: switch-01",
			"    address: udp://192.0.2.1:161",
			"    profile: if_mib",
			"    auth: public_v2",
			"    interval: 10s",
			"    timeout: 1s",
		)
	}
	path := filepath.Join(t.TempDir(), "devices.yml")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write inventory fixture: %v", err)
	}
	loaded, err := inventory.NewLoader(10*time.Second, time.Second).Load([]string{path}, testProfiles())
	if err != nil {
		t.Fatalf("load inventory fixture: %v", err)
	}
	return loaded
}

func testProfiles() *snmpconfig.Config {
	return &snmpconfig.Config{
		Modules: map[string]*snmpconfig.Module{"if_mib": {}},
		Auths:   map[string]*snmpconfig.Auth{"public_v2": {Version: 2}},
	}
}

func pollResult(deviceID, pollID string) collector.PollResult {
	return collector.PollResult{Samples: []sample.Sample{{
		Name:      "sysUpTime",
		Value:     1,
		Timestamp: 1,
		Type:      sample.MetricCounter,
		DeviceID:  deviceID,
		PollID:    pollID,
	}}}
}

func waitForCall[T comparable](t *testing.T, calls <-chan T, want T) {
	t.Helper()
	select {
	case got := <-calls:
		if got != want {
			t.Fatalf("poll call = %v, want %v", got, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for poll call %v", want)
	}
}

func waitForBatch(t *testing.T, batches <-chan []sample.Sample) {
	t.Helper()
	select {
	case <-batches:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for output batch")
	}
}

func waitForCounter(t *testing.T, counter prometheus.Counter, want float64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if counterValue(t, counter) >= want {
			return
		}
		runtime.Gosched()
	}
	t.Fatalf("counter did not reach %v", want)
}

func counterValue(t *testing.T, counter prometheus.Counter) float64 {
	t.Helper()
	metric := &dto.Metric{}
	if err := counter.Write(metric); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	return metric.GetCounter().GetValue()
}
