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

package remotewrite

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/snappy"
	"github.com/prometheus/prometheus/prompb"

	"github.com/prometheus/snmp_exporter/output"
	"github.com/prometheus/snmp_exporter/sample"
)

func TestSenderWritesPrometheusRemoteWriteRequest(t *testing.T) {
	received := make(chan *prompb.WriteRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", request.Method)
		}
		if got := request.Header.Get("Content-Encoding"); got != "snappy" {
			t.Errorf("Content-Encoding = %q, want snappy", got)
		}
		if got := request.Header.Get("Content-Type"); got != "application/x-protobuf" {
			t.Errorf("Content-Type = %q, want application/x-protobuf", got)
		}
		if got := request.Header.Get("X-Prometheus-Remote-Write-Version"); got != "0.1.0" {
			t.Errorf("remote write version = %q, want 0.1.0", got)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer secret-token" {
			t.Errorf("Authorization header was not supplied")
		}
		if got := request.Header.Get("X-Scope-OrgID"); got != "tenant-01" {
			t.Errorf("X-Scope-OrgID = %q, want tenant-01", got)
		}

		compressed, err := io.ReadAll(request.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		protobuf, err := snappy.Decode(nil, compressed)
		if err != nil {
			t.Errorf("decode snappy body: %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		decoded := &prompb.WriteRequest{}
		if err := decoded.Unmarshal(protobuf); err != nil {
			t.Errorf("unmarshal write request: %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		received <- decoded
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	provider := HeaderProviderFunc(func(context.Context) (http.Header, error) {
		return http.Header{
			"Authorization": []string{"Bearer secret-token"},
			"X-Scope-OrgID": []string{"tenant-01"},
		}, nil
	})
	sender := newStartedSender(t, Config{Endpoint: server.URL, MaxInFlight: 2}, server.Client(), provider)
	if err := sender.Send(context.Background(), []sample.Sample{remoteSample("sysUpTime", 1000, 42, nil)}); err != nil {
		t.Fatalf("Send() returned unexpected error: %v", err)
	}
	select {
	case request := <-received:
		if len(request.Timeseries) != 1 || len(request.Timeseries[0].Samples) != 1 {
			t.Fatalf("decoded request = %#v, want one series/sample", request)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not receive remote write request")
	}
}

func TestSenderDoesNotExposeResponseBody(t *testing.T) {
	const secretBody = "secret-token-should-not-leak"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte(secretBody))
	}))
	defer server.Close()

	sender := newStartedSender(t, Config{Endpoint: server.URL, MaxInFlight: 1}, server.Client(), nil)
	err := sender.Send(context.Background(), []sample.Sample{remoteSample("sysUpTime", 1, 1, nil)})
	if err == nil {
		t.Fatal("Send() returned nil for HTTP 401")
	}
	if strings.Contains(err.Error(), secretBody) {
		t.Fatalf("Send() error leaked response body: %v", err)
	}
	if IsRetryable(err) {
		t.Fatalf("HTTP 401 was classified as retryable: %v", err)
	}
}

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "429", err: HTTPError{StatusCode: http.StatusTooManyRequests}, want: true},
		{name: "500", err: HTTPError{StatusCode: http.StatusInternalServerError}, want: true},
		{name: "400", err: HTTPError{StatusCode: http.StatusBadRequest}, want: false},
		{name: "transport", err: transportError{}, want: true},
		{name: "permanent", err: permanentError{message: "invalid config"}, want: false},
		{name: "context cancellation", err: context.Canceled, want: false},
		{name: "unknown", err: errors.New("unknown"), want: false},
	}
	for _, current := range tests {
		t.Run(current.name, func(t *testing.T) {
			if got := IsRetryable(current.err); got != current.want {
				t.Fatalf("IsRetryable(%v) = %v, want %v", current.err, got, current.want)
			}
		})
	}
}

func TestSenderBoundsConcurrentRequests(t *testing.T) {
	var active atomic.Int32
	var maximum atomic.Int32
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		current := active.Add(1)
		for {
			previous := maximum.Load()
			if current <= previous || maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		entered <- struct{}{}
		select {
		case <-release:
			writer.WriteHeader(http.StatusNoContent)
		case <-request.Context().Done():
		}
		active.Add(-1)
	}))
	defer server.Close()

	sender := newStartedSender(t, Config{Endpoint: server.URL, MaxInFlight: 1}, server.Client(), nil)
	errs := make(chan error, 2)
	for index := 0; index < 2; index++ {
		go func(value float64) {
			errs <- sender.Send(context.Background(), []sample.Sample{remoteSample("sysUpTime", 1, value, nil)})
		}(float64(index))
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first request did not reach server")
	}
	select {
	case <-entered:
		t.Fatal("second request entered while first request was in flight")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	for index := 0; index < 2; index++ {
		if err := <-errs; err != nil {
			t.Fatalf("Send() returned unexpected error: %v", err)
		}
	}
	if maximum.Load() != 1 {
		t.Fatalf("maximum in-flight requests = %d, want 1", maximum.Load())
	}
}

func TestNewRejectsCredentialsInEndpointWithoutLeakingThem(t *testing.T) {
	const password = "secret-password"
	_, err := New(Config{
		Endpoint:    "https://user:" + password + "@mimir.example.com/api/v1/push",
		MaxInFlight: 1,
	}, nil, nil)
	if err == nil {
		t.Fatal("New() accepted credentials in endpoint")
	}
	if strings.Contains(err.Error(), password) {
		t.Fatalf("New() error leaked endpoint password: %v", err)
	}
}

func TestNewOutputUsesSharedAsyncQueue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	asyncOutput, err := NewOutput(
		Config{Endpoint: server.URL, MaxInFlight: 1},
		output.QueueConfig{
			Capacity:        10,
			MaxBatchSamples: 2,
			FlushInterval:   time.Second,
			OverflowPolicy:  output.DropOldest,
			RetryMinBackoff: time.Millisecond,
			RetryMaxBackoff: time.Second,
			RequestTimeout:  time.Second,
		},
		server.Client(),
		nil,
		output.Metrics{},
	)
	if err != nil {
		t.Fatalf("NewOutput() returned unexpected error: %v", err)
	}
	if asyncOutput.ID() != "remote_write" {
		t.Fatalf("output ID = %q, want remote_write", asyncOutput.ID())
	}
}

func TestAsyncOutputRetriesTransientHTTPStatus(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			writer.WriteHeader(http.StatusTooManyRequests)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	asyncOutput, err := NewOutput(
		Config{Endpoint: server.URL, MaxInFlight: 1},
		output.QueueConfig{
			Capacity:        10,
			MaxBatchSamples: 1,
			FlushInterval:   time.Hour,
			OverflowPolicy:  output.DropOldest,
			RetryMinBackoff: time.Millisecond,
			RetryMaxBackoff: 10 * time.Millisecond,
			RequestTimeout:  time.Second,
		},
		server.Client(),
		nil,
		output.Metrics{},
	)
	if err != nil {
		t.Fatalf("NewOutput() returned unexpected error: %v", err)
	}
	if err := asyncOutput.Start(context.Background()); err != nil {
		t.Fatalf("Start() returned unexpected error: %v", err)
	}
	if err := asyncOutput.Write(context.Background(), []sample.Sample{remoteSample("sysUpTime", 1, 1, nil)}); err != nil {
		t.Fatalf("Write() returned unexpected error: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := asyncOutput.Flush(ctx); err != nil {
		t.Fatalf("Flush() returned unexpected error: %v", err)
	}
	if requests.Load() != 2 {
		t.Fatalf("HTTP requests = %d, want one retry after HTTP 429", requests.Load())
	}
	if err := asyncOutput.Close(ctx); err != nil {
		t.Fatalf("Close() returned unexpected error: %v", err)
	}
}

func newStartedSender(t *testing.T, config Config, client httpDoer, provider HeaderProvider) *Sender {
	t.Helper()
	sender, err := New(config, client, provider)
	if err != nil {
		t.Fatalf("New() returned unexpected error: %v", err)
	}
	if err := sender.Start(context.Background()); err != nil {
		t.Fatalf("Start() returned unexpected error: %v", err)
	}
	t.Cleanup(func() {
		if err := sender.Close(context.Background()); err != nil {
			t.Errorf("Close() returned unexpected error: %v", err)
		}
	})
	return sender
}
