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
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"

	"github.com/prometheus/snmp_exporter/output"
	"github.com/prometheus/snmp_exporter/sample"
)

const defaultUserAgent = "snmp-collector"

type Config struct {
	Endpoint    string `yaml:"endpoint"`
	MaxInFlight int    `yaml:"maxInFlight,omitempty"`
	UserAgent   string `yaml:"userAgent,omitempty"`
}

// HeaderProvider resolves request headers at send time so credential rotation
// does not require reconstructing the sender.
type HeaderProvider interface {
	Headers(context.Context) (http.Header, error)
}

type HeaderProviderFunc func(context.Context) (http.Header, error)

func (f HeaderProviderFunc) Headers(ctx context.Context) (http.Header, error) {
	return f(ctx)
}

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Sender sends Prometheus Remote Write v1 requests to Mimir or another
// compatible receiver.
type Sender struct {
	endpoint  *url.URL
	client    httpDoer
	headers   HeaderProvider
	userAgent string
	inFlight  chan struct{}

	mu      sync.RWMutex
	started bool
	closed  bool
}

var _ output.Sender = (*Sender)(nil)

func New(config Config, client httpDoer, headers HeaderProvider) (*Sender, error) {
	if config.Endpoint == "" {
		return nil, fmt.Errorf("remote write endpoint is required")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid remote write endpoint")
	}
	if endpoint.Scheme != "http" && endpoint.Scheme != "https" {
		return nil, fmt.Errorf("remote write endpoint must use http or https")
	}
	if endpoint.Host == "" {
		return nil, fmt.Errorf("remote write endpoint is missing a host")
	}
	if endpoint.User != nil {
		return nil, fmt.Errorf("remote write endpoint must not contain credentials")
	}
	if endpoint.Fragment != "" {
		return nil, fmt.Errorf("remote write endpoint must not contain a fragment")
	}
	if config.MaxInFlight <= 0 {
		return nil, fmt.Errorf("remote write max in-flight requests must be positive")
	}
	if client == nil {
		client = &http.Client{}
	}
	userAgent := config.UserAgent
	if userAgent == "" {
		userAgent = defaultUserAgent
	}
	return &Sender{
		endpoint:  endpoint,
		client:    client,
		headers:   headers,
		userAgent: userAgent,
		inFlight:  make(chan struct{}, config.MaxInFlight),
	}, nil
}

// NewOutput composes the Remote Write sender with the shared asynchronous
// queue. It does not create another queue inside the sender.
func NewOutput(config Config, queue output.QueueConfig, client httpDoer, headers HeaderProvider, metrics output.Metrics, logger *slog.Logger) (*output.AsyncOutput, error) {
	sender, err := New(config, client, headers)
	if err != nil {
		return nil, err
	}
	return output.NewAsync("remote_write", queue, sender, IsRetryable, metrics, logger)
}

func (s *Sender) Start(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return output.ErrClosed
	}
	if s.started {
		return fmt.Errorf("remote write sender already started")
	}
	s.started = true
	return nil
}

func (s *Sender) Send(ctx context.Context, batch []sample.Sample) error {
	s.mu.RLock()
	started, closed := s.started, s.closed
	s.mu.RUnlock()
	if !started {
		return permanentError{message: output.ErrNotStarted.Error()}
	}
	if closed {
		return permanentError{message: output.ErrClosed.Error()}
	}

	body, err := encode(batch)
	if err != nil {
		return permanentError{message: err.Error()}
	}
	select {
	case s.inFlight <- struct{}{}:
		defer func() { <-s.inFlight }()
	case <-ctx.Done():
		return ctx.Err()
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return permanentError{message: "build remote write request"}
	}
	if s.headers != nil {
		headers, err := s.headers.Headers(ctx)
		if err != nil {
			return transportError{}
		}
		for name, values := range headers {
			for _, value := range values {
				request.Header.Add(name, value)
			}
		}
	}
	request.Header.Set("Content-Encoding", "snappy")
	request.Header.Set("Content-Type", "application/x-protobuf")
	request.Header.Set("User-Agent", s.userAgent)
	request.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")

	response, err := s.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return transportError{}
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return HTTPError{StatusCode: response.StatusCode}
	}
	return nil
}

func (s *Sender) Ready() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.started {
		return output.ErrNotStarted
	}
	if s.closed {
		return output.ErrClosed
	}
	return nil
}

func (s *Sender) Close(context.Context) error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	if closer, ok := s.client.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
	return nil
}
