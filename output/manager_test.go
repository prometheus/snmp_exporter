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

	"github.com/prometheus/snmp_exporter/sample"
)

type fakeOutput struct {
	id       string
	readyErr error

	mu      sync.Mutex
	started int
	writes  int
	flushed int
	closed  int
}

func (o *fakeOutput) ID() string { return o.id }
func (o *fakeOutput) Start(context.Context) error {
	o.mu.Lock()
	o.started++
	o.mu.Unlock()
	return nil
}
func (o *fakeOutput) Write(context.Context, []sample.Sample) error {
	o.mu.Lock()
	o.writes++
	o.mu.Unlock()
	return nil
}
func (o *fakeOutput) Flush(context.Context) error {
	o.mu.Lock()
	o.flushed++
	o.mu.Unlock()
	return nil
}
func (o *fakeOutput) Ready() error { return o.readyErr }
func (o *fakeOutput) Close(context.Context) error {
	o.mu.Lock()
	o.closed++
	o.mu.Unlock()
	return nil
}

func (o *fakeOutput) counts() (started, writes, flushed, closed int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.started, o.writes, o.flushed, o.closed
}

func TestManagerSwapsSingleActiveOutput(t *testing.T) {
	first := &fakeOutput{id: "first"}
	manager, err := NewManager(first)
	if err != nil {
		t.Fatalf("NewManager() returned unexpected error: %v", err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start() returned unexpected error: %v", err)
	}
	if err := manager.Write(context.Background(), []sample.Sample{testSample(1)}); err != nil {
		t.Fatalf("initial Write() returned unexpected error: %v", err)
	}

	second := &fakeOutput{id: "second"}
	if err := manager.Swap(context.Background(), second); err != nil {
		t.Fatalf("Swap() returned unexpected error: %v", err)
	}
	if err := manager.Write(context.Background(), []sample.Sample{testSample(2)}); err != nil {
		t.Fatalf("post-swap Write() returned unexpected error: %v", err)
	}

	firstStarted, firstWrites, firstFlushed, firstClosed := first.counts()
	if firstStarted != 1 || firstWrites != 1 || firstFlushed != 1 || firstClosed != 1 {
		t.Fatalf("first output lifecycle = %d/%d/%d/%d, want 1/1/1/1", firstStarted, firstWrites, firstFlushed, firstClosed)
	}
	secondStarted, secondWrites, _, _ := second.counts()
	if secondStarted != 1 || secondWrites != 1 {
		t.Fatalf("second output start/writes = %d/%d, want 1/1", secondStarted, secondWrites)
	}

	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("Close() returned unexpected error: %v", err)
	}
	_, _, secondFlushed, secondClosed := second.counts()
	if secondFlushed != 1 || secondClosed != 1 {
		t.Fatalf("second output flush/close = %d/%d, want 1/1", secondFlushed, secondClosed)
	}
}

func TestManagerKeepsCurrentOutputWhenReplacementIsNotReady(t *testing.T) {
	first := &fakeOutput{id: "first"}
	manager, err := NewManager(first)
	if err != nil {
		t.Fatalf("NewManager() returned unexpected error: %v", err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start() returned unexpected error: %v", err)
	}

	readinessError := errors.New("not ready")
	replacement := &fakeOutput{id: "replacement", readyErr: readinessError}
	if err := manager.Swap(context.Background(), replacement); !errors.Is(err, readinessError) {
		t.Fatalf("Swap() error = %v, want readiness error", err)
	}
	if err := manager.Write(context.Background(), []sample.Sample{testSample(1)}); err != nil {
		t.Fatalf("Write() after rejected swap returned unexpected error: %v", err)
	}

	_, writes, flushed, closed := first.counts()
	if writes != 1 || flushed != 0 || closed != 0 {
		t.Fatalf("current output changed after rejected swap: writes/flush/close = %d/%d/%d", writes, flushed, closed)
	}
	_, _, _, replacementClosed := replacement.counts()
	if replacementClosed != 1 {
		t.Fatalf("rejected replacement close count = %d, want 1", replacementClosed)
	}
}

func TestManagerKeepsCurrentOutputWhenSwapCallbackFails(t *testing.T) {
	first := &fakeOutput{id: "first"}
	manager, err := NewManager(first)
	if err != nil {
		t.Fatalf("NewManager() returned unexpected error: %v", err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("Start() returned unexpected error: %v", err)
	}

	replacement := &fakeOutput{id: "replacement"}
	callbackErr := errors.New("reconcile failed")
	cleanupErr, activationErr := manager.SwapWith(context.Background(), replacement, func() error {
		return callbackErr
	})
	if cleanupErr != nil || !errors.Is(activationErr, callbackErr) {
		t.Fatalf("SwapWith() errors = %v/%v, want nil/%v", cleanupErr, activationErr, callbackErr)
	}
	if err := manager.Write(context.Background(), []sample.Sample{testSample(1)}); err != nil {
		t.Fatalf("Write() after rejected swap returned unexpected error: %v", err)
	}

	_, writes, flushed, closed := first.counts()
	if writes != 1 || flushed != 0 || closed != 0 {
		t.Fatalf("current output changed after callback failure: writes/flush/close = %d/%d/%d", writes, flushed, closed)
	}
	_, _, _, replacementClosed := replacement.counts()
	if replacementClosed != 1 {
		t.Fatalf("rejected replacement close count = %d, want 1", replacementClosed)
	}
}
