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
	"sync"

	"github.com/prometheus/snmp_exporter/sample"
)

// Manager routes writes to exactly one active output.
type Manager struct {
	mu      sync.RWMutex
	active  Output
	runCtx  context.Context
	started bool
}

func NewManager(active Output) (*Manager, error) {
	if active == nil {
		return nil, ErrNoActive
	}
	return &Manager{active: active}, nil
}

func (m *Manager) Start(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("output manager context is required")
	}
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return fmt.Errorf("output manager already started")
	}
	active := m.active
	m.mu.Unlock()

	if err := active.Start(ctx); err != nil {
		return err
	}
	if err := active.Ready(); err != nil {
		_ = active.Close(context.Background())
		return err
	}

	m.mu.Lock()
	m.runCtx = ctx
	m.started = true
	m.mu.Unlock()
	return nil
}

func (m *Manager) Write(ctx context.Context, batch []sample.Sample) error {
	m.mu.RLock()
	active := m.active
	started := m.started
	m.mu.RUnlock()
	if !started {
		return ErrNotStarted
	}
	if active == nil {
		return ErrNoActive
	}
	return active.Write(ctx, batch)
}

func (m *Manager) Ready() error {
	m.mu.RLock()
	active := m.active
	started := m.started
	m.mu.RUnlock()
	if !started {
		return ErrNotStarted
	}
	if active == nil {
		return ErrNoActive
	}
	return active.Ready()
}

// Swap starts and readiness-checks next before atomically routing new writes to
// it. The old output is then flushed and closed without holding the manager
// lock, so polling remains independent from output I/O.
func (m *Manager) Swap(ctx context.Context, next Output) error {
	cleanupErr, activationErr := m.SwapWith(ctx, next, nil)
	return errors.Join(activationErr, cleanupErr)
}

// SwapWith starts and readiness-checks next, then invokes beforeSwap before
// changing the active output. If preparation or beforeSwap fails, next is
// closed and the current output remains active. Once beforeSwap succeeds, the
// output switch cannot fail; cleanupErr only reports flushing/closing the old
// output after the new output is already active.
func (m *Manager) SwapWith(ctx context.Context, next Output, beforeSwap func() error) (cleanupErr, activationErr error) {
	if ctx == nil {
		return nil, fmt.Errorf("output swap context is required")
	}
	if next == nil {
		return nil, ErrNoActive
	}
	m.mu.RLock()
	runCtx := m.runCtx
	started := m.started
	m.mu.RUnlock()
	if !started {
		return nil, ErrNotStarted
	}

	if err := next.Start(runCtx); err != nil {
		return nil, fmt.Errorf("start output %q: %w", next.ID(), err)
	}
	if err := next.Ready(); err != nil {
		_ = next.Close(ctx)
		return nil, fmt.Errorf("output %q is not ready: %w", next.ID(), err)
	}
	if beforeSwap != nil {
		if err := beforeSwap(); err != nil {
			_ = next.Close(ctx)
			return nil, err
		}
	}

	m.mu.Lock()
	old := m.active
	m.active = next
	m.mu.Unlock()

	if old != nil {
		cleanupErr = errors.Join(old.Flush(ctx), old.Close(ctx))
	}
	return cleanupErr, nil
}

func (m *Manager) Close(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("output close context is required")
	}
	m.mu.Lock()
	if !m.started {
		m.mu.Unlock()
		return ErrNotStarted
	}
	active := m.active
	m.active = nil
	m.started = false
	m.mu.Unlock()

	if active == nil {
		return nil
	}
	return errors.Join(active.Flush(ctx), active.Close(ctx))
}
