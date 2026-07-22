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

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/common/promslog"

	"github.com/prometheus/snmp_exporter/config"
	"github.com/prometheus/snmp_exporter/inventory"
	"github.com/prometheus/snmp_exporter/output"
	"github.com/prometheus/snmp_exporter/sample"
)

var nopLogger = promslog.NewNopLogger()

func TestLoadRuntimeSnapshot(t *testing.T) {
	configPath, inventoryPath, outputPath := writeRuntimeFiles(t)

	snapshot, err := loadRuntimeSnapshot(
		nopLogger,
		[]string{configPath},
		false,
		[]string{inventoryPath},
		outputPath,
		time.Minute,
		45*time.Second,
	)
	if err != nil {
		t.Fatalf("loadRuntimeSnapshot() returned unexpected error: %v", err)
	}
	if snapshot.inventory.Len() != 1 {
		t.Fatalf("inventory length = %d, want 1", snapshot.inventory.Len())
	}
	if snapshot.output.Sender.Endpoint != "https://mimir.example.com/api/v1/push" {
		t.Fatalf("remote write endpoint = %q", snapshot.output.Sender.Endpoint)
	}
	device, ok := snapshot.inventory.Device("switch-01")
	if !ok || device.Interval != time.Minute || device.Timeout != 45*time.Second {
		t.Fatalf("device defaults = %#v", device)
	}
}

func TestLoadRuntimeSnapshotRequiresInventoryAndOutput(t *testing.T) {
	configPath, inventoryPath, outputPath := writeRuntimeFiles(t)
	tests := []struct {
		name      string
		inventory []string
		output    string
		wantErr   string
	}{
		{name: "missing inventory", output: outputPath, wantErr: "--inventory.file is required"},
		{name: "missing output", inventory: []string{inventoryPath}, wantErr: "--output.file is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadRuntimeSnapshot(
				nopLogger, []string{configPath}, false, tt.inventory, tt.output,
				time.Minute, 45*time.Second,
			)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("loadRuntimeSnapshot() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadRuntimeSnapshotRejectsInvalidInventoryBeforeActivation(t *testing.T) {
	configPath, inventoryPath, outputPath := writeRuntimeFiles(t)
	content, err := os.ReadFile(inventoryPath)
	if err != nil {
		t.Fatalf("read inventory: %v", err)
	}
	writeMainTestFile(t, inventoryPath, strings.Replace(string(content), "profile: if_mib", "profile: missing", 1))

	_, err = loadRuntimeSnapshot(
		nopLogger, []string{configPath}, false, []string{inventoryPath}, outputPath,
		time.Minute, 45*time.Second,
	)
	if err == nil || !strings.Contains(err.Error(), "profile \"missing\" does not exist") {
		t.Fatalf("loadRuntimeSnapshot() error = %v, want missing profile error", err)
	}
}

type fakeReadiness struct{ err error }

func (r fakeReadiness) Ready() error { return r.err }

func TestCollectorHTTPHandlerDoesNotExposeExporterEndpoints(t *testing.T) {
	handler := newHTTPHandler("/metrics", fakeReadiness{})
	for _, path := range []string{"/snmp", "/config", "/"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, http.NoBody))
		if recorder.Code != http.StatusNotFound {
			t.Errorf("GET %s status = %d, want 404", path, recorder.Code)
		}
	}

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/-/healthy", http.NoBody))
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d, want 200", health.Code)
	}
}

func TestCollectorHTTPHandlerReportsReadiness(t *testing.T) {
	handler := newHTTPHandler("/metrics", fakeReadiness{err: errors.New("not ready")})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", http.NoBody))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness status = %d, want 503", recorder.Code)
	}
}

func TestCollectorReloadEndpoint(t *testing.T) {
	reloadCh = make(chan chan error)
	done := make(chan struct{})
	go func() {
		rc := <-reloadCh
		rc <- nil
		close(done)
	}()

	handler := newHTTPHandler("/metrics", fakeReadiness{})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/-/reload", http.NoBody))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "Reloaded\n" {
		t.Fatalf("reload response = %d/%q, want 200/Reloaded", recorder.Code, recorder.Body.String())
	}
	<-done

	methodNotAllowed := httptest.NewRecorder()
	handler.ServeHTTP(methodNotAllowed, httptest.NewRequest(http.MethodGet, "/-/reload", http.NoBody))
	if methodNotAllowed.Code != http.StatusBadRequest {
		t.Fatalf("GET reload status = %d, want 400", methodNotAllowed.Code)
	}
}

type recordingRuntimeScheduler struct {
	reconcileErr error
	reconciles   int
	stops        int
	snapshot     *inventory.Snapshot
	profiles     *config.Config
}

func (s *recordingRuntimeScheduler) Reconcile(_ context.Context, snapshot *inventory.Snapshot, profiles *config.Config) error {
	s.reconciles++
	s.snapshot = snapshot
	s.profiles = profiles
	return s.reconcileErr
}

func (s *recordingRuntimeScheduler) Stop(context.Context) error {
	s.stops++
	return nil
}

type recordingOutput struct {
	started int
	flushed int
	closed  int
}

func (*recordingOutput) ID() string { return "previous" }
func (o *recordingOutput) Start(context.Context) error {
	o.started++
	return nil
}
func (*recordingOutput) Write(context.Context, []sample.Sample) error { return nil }
func (o *recordingOutput) Flush(context.Context) error {
	o.flushed++
	return nil
}
func (*recordingOutput) Ready() error { return nil }
func (o *recordingOutput) Close(context.Context) error {
	o.closed++
	return nil
}

func TestCollectorRuntimeReloadsProfilesInventoryAndOutput(t *testing.T) {
	configPath, inventoryPath, outputPath := writeRuntimeFiles(t)
	snapshot, err := loadRuntimeSnapshot(
		nopLogger, []string{configPath}, false, []string{inventoryPath}, outputPath,
		time.Minute, 45*time.Second,
	)
	if err != nil {
		t.Fatalf("loadRuntimeSnapshot() returned unexpected error: %v", err)
	}

	previous := &recordingOutput{}
	manager, err := output.NewManager(previous)
	if err != nil {
		t.Fatalf("NewManager() returned unexpected error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := manager.Start(ctx); err != nil {
		t.Fatalf("output manager Start() returned unexpected error: %v", err)
	}
	reconciler := &recordingRuntimeScheduler{}
	runtime := &collectorRuntime{
		scheduler: reconciler,
		output:    manager,
		logger:    nopLogger,
	}

	if err := runtime.Reload(ctx, snapshot); err != nil {
		t.Fatalf("Reload() returned unexpected error: %v", err)
	}
	if reconciler.reconciles != 1 || reconciler.snapshot != snapshot.inventory || reconciler.profiles != snapshot.profiles {
		t.Fatalf("scheduler reconcile state = %#v, want the complete replacement snapshot", reconciler)
	}
	if previous.started != 1 || previous.flushed != 1 || previous.closed != 1 {
		t.Fatalf("previous output lifecycle = %d/%d/%d, want 1/1/1", previous.started, previous.flushed, previous.closed)
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("close replacement output: %v", err)
	}
}

func TestCollectorRuntimeKeepsPreviousOutputWhenReconcileFails(t *testing.T) {
	configPath, inventoryPath, outputPath := writeRuntimeFiles(t)
	snapshot, err := loadRuntimeSnapshot(
		nopLogger, []string{configPath}, false, []string{inventoryPath}, outputPath,
		time.Minute, 45*time.Second,
	)
	if err != nil {
		t.Fatalf("loadRuntimeSnapshot() returned unexpected error: %v", err)
	}

	previous := &recordingOutput{}
	manager, err := output.NewManager(previous)
	if err != nil {
		t.Fatalf("NewManager() returned unexpected error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := manager.Start(ctx); err != nil {
		t.Fatalf("output manager Start() returned unexpected error: %v", err)
	}
	reconcileErr := errors.New("reconcile failed")
	runtime := &collectorRuntime{
		scheduler: &recordingRuntimeScheduler{reconcileErr: reconcileErr},
		output:    manager,
		logger:    nopLogger,
	}

	if err := runtime.Reload(ctx, snapshot); !errors.Is(err, reconcileErr) {
		t.Fatalf("Reload() error = %v, want %v", err, reconcileErr)
	}
	if previous.flushed != 0 || previous.closed != 0 {
		t.Fatalf("previous output changed after rejected reload: flush/close = %d/%d", previous.flushed, previous.closed)
	}
	if err := manager.Ready(); err != nil {
		t.Fatalf("previous output is not active after rejected reload: %v", err)
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("close previous output: %v", err)
	}
}

func writeRuntimeFiles(t *testing.T) (configPath, inventoryPath, outputPath string) {
	t.Helper()
	directory := t.TempDir()
	configPath = filepath.Join(directory, "snmp.yml")
	inventoryPath = filepath.Join(directory, "devices.yml")
	outputPath = filepath.Join(directory, "outputs.yml")
	writeMainTestFile(t, configPath, strings.Join([]string{
		"auths:",
		"  public_v2:",
		"    community: public",
		"    version: 2",
		"modules:",
		"  if_mib:",
		"    walk: []",
		"    metrics: []",
	}, "\n")+"\n")
	writeMainTestFile(t, inventoryPath, strings.Join([]string{
		"devices:",
		"  - id: switch-01",
		"    address: udp://192.0.2.1:161",
		"    profile: if_mib",
		"    auth: public_v2",
	}, "\n")+"\n")
	writeMainTestFile(t, outputPath, strings.Join([]string{
		"output:",
		"  type: remote_write",
		"  remoteWrite:",
		"    endpoint: https://mimir.example.com/api/v1/push",
		"    queue: {}",
	}, "\n")+"\n")
	return configPath, inventoryPath, outputPath
}

func writeMainTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write test config %q: %v", path, err)
	}
}
