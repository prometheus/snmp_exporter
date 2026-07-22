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

// Package output owns the single active output and bounded asynchronous
// delivery shared by downstream implementations.
package output

import (
	"context"
	"errors"

	"github.com/prometheus/snmp_exporter/sample"
)

var (
	ErrNotStarted = errors.New("output is not started")
	ErrClosed     = errors.New("output is closed")
	ErrNoActive   = errors.New("no active output")
)

// Output is the lifecycle contract managed by Manager.
type Output interface {
	ID() string
	Start(context.Context) error
	Write(context.Context, []sample.Sample) error
	Flush(context.Context) error
	Ready() error
	Close(context.Context) error
}

// Sender performs one downstream batch request. AsyncOutput owns its retry,
// batching, and backpressure behavior.
type Sender interface {
	Start(context.Context) error
	Send(context.Context, []sample.Sample) error
	Ready() error
	Close(context.Context) error
}

// RetryClassifier reports whether an error is safe to retry.
type RetryClassifier func(error) bool
