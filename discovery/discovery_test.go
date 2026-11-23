// Copyright The Prometheus Authors
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
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/prometheus/prometheus/discovery/targetgroup"

	"github.com/prometheus/snmp_exporter/collector"
	"github.com/prometheus/snmp_exporter/config"
)

func TestDiscoveryInterval(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	t.Run("run at scheduled interval", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			disco := New(nil, nil, "", &net.IPNet{
				IP:   net.IP{172, 20, 20, 20},
				Mask: net.IPMask{255, 255, 255, 255},
			}, collector.Metrics{}, logger)
			disco.Interval = time.Minute * 4
			var nCalled atomic.Uint64
			disco.fingerprintFn = func(_ context.Context, _ net.IP, _ *config.Auth) ([]string, error) {
				nCalled.Add(1)
				return []string{"if_mib"}, nil
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			// buffered channel to avoid blocking on send
			up := make(chan []*targetgroup.Group, 16)
			go disco.Run(ctx, up)
			synctest.Wait()
			time.Sleep(time.Minute * 21)
			if nCalled.Load() != 6 {
				t.Errorf("expected discovery to run 6 times (one initial + 5 scheduled), got %d", nCalled.Load())
			}
		})
	})
	t.Run("uses default interval", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			disco := New(nil, nil, "", &net.IPNet{
				IP:   net.IP{172, 20, 20, 20},
				Mask: net.IPMask{255, 255, 255, 255},
			}, collector.Metrics{}, logger)
			var nCalled atomic.Uint64
			disco.fingerprintFn = func(_ context.Context, _ net.IP, _ *config.Auth) ([]string, error) {
				nCalled.Add(1)
				return []string{"if_mib"}, nil
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			// buffered channel to avoid blocking on send
			up := make(chan []*targetgroup.Group, 16)
			go disco.Run(ctx, up)
			synctest.Wait()
			time.Sleep(time.Minute * 21)
			if nCalled.Load() != 5 {
				t.Errorf("expected discovery to run 5 times (one initial + 4 scheduled), got %d", nCalled.Load())
			}
		})
	})
}
