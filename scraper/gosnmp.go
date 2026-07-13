// Copyright 2024 The Prometheus Authors
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

package scraper

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

type GoSNMPWrapper struct {
	c      *gosnmp.GoSNMP
	logger *slog.Logger
	// opts records every option fn passed to SetOptions so Clone can replay
	// them on the copy. Replaying re-invokes each fn, recreating hook
	// closures (OnSent etc.) with fresh per-connection state rather than
	// sharing the parent's closures across goroutines.
	opts []func(*gosnmp.GoSNMP)
}

func NewGoSNMP(logger *slog.Logger, target, srcAddress string, debug bool) (*GoSNMPWrapper, error) {
	transport := "udp"
	if s := strings.SplitN(target, "://", 2); len(s) == 2 {
		transport = s[0]
		target = s[1]
	}
	port := uint16(161)
	if host, _port, err := net.SplitHostPort(target); err == nil {
		target = host
		p, err := strconv.Atoi(_port)
		if err != nil {
			return nil, fmt.Errorf("error converting port number to int for target %q: %w", target, err)
		}
		if p < 0 || p > 65535 {
			return nil, fmt.Errorf("port number out of range for target %q", target)
		}
		port = uint16(p)
	} else if host, _, err := net.SplitHostPort(target + ":0"); err == nil {
		// Strip brackets from IPv6 addresses like "[::1]" that have no port.
		target = host
	}
	g := &gosnmp.GoSNMP{
		Transport: transport,
		Target:    target,
		Port:      port,
		LocalAddr: srcAddress,
	}
	if debug {
		g.Logger = gosnmp.NewLogger(slog.NewLogLogger(logger.Handler(), slog.LevelDebug))
	}
	return &GoSNMPWrapper{c: g, logger: logger}, nil
}

// SetOptions applies fns to the underlying client and records them for
// replay by Clone. Option fns accumulate across calls; when several set the
// same field or hook, the one applied last wins.
func (g *GoSNMPWrapper) SetOptions(fns ...func(*gosnmp.GoSNMP)) {
	g.opts = append(g.opts, fns...)
	for _, fn := range fns {
		fn(g.c)
	}
}

func (g *GoSNMPWrapper) Connect() error {
	st := time.Now()
	err := g.c.Connect()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return fmt.Errorf("scrape cancelled after %s (possible timeout) connecting to target %s",
				time.Since(st), g.c.Target)
		}
		return fmt.Errorf("error connecting to target %s: %w", g.c.Target, err)
	}
	return nil
}

func (g *GoSNMPWrapper) Close() error {
	return g.c.Close()
}

// cloneLocalAddr returns addr with its port component replaced by "0" so
// each clone binds a fresh ephemeral source port. The port must be
// normalized rather than stripped: gosnmp passes LocalAddr verbatim to
// net.ResolveUDPAddr, which requires "host:port" form. Keeping a fixed
// port would instead cause "bind: address already in use" when multiple
// clones connect. An empty addr or one without a port component is
// returned unchanged.
func cloneLocalAddr(addr string) string {
	if addr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr // no port component, return as-is
	}
	return net.JoinHostPort(host, "0")
}

// Clone returns a new unconnected GoSNMPWrapper copying transport/auth
// settings. The caller must call Connect() before using the clone.
//
// Conn is intentionally not copied: connections are not goroutine-safe, so
// the clone must Connect() independently. LocalAddr has its port normalized
// to 0 so each clone binds a fresh source port (see cloneLocalAddr).
//
// Hook fields (OnSent/OnRecv/OnRetry/OnFinish/PreSend) are not copied
// directly either — their closures hold per-connection state. Instead,
// every option fn previously applied via SetOptions is replayed on the
// clone, recreating the hooks with fresh state that still feeds the shared
// (thread-safe) counters.
//
// If GoSNMP gains new configuration fields in a future version they must be
// added here manually; the struct copy (`c := *g.c`) cannot be used because
// GoSNMP embeds sync.Mutex and go vet (copylocks) rejects copying a lock value.
func (g *GoSNMPWrapper) Clone() SNMPScraper {
	clone := &gosnmp.GoSNMP{
		Transport:                   g.c.Transport,
		Target:                      g.c.Target,
		Port:                        g.c.Port,
		LocalAddr:                   cloneLocalAddr(g.c.LocalAddr),
		Version:                     g.c.Version,
		Community:                   g.c.Community,
		MsgFlags:                    g.c.MsgFlags,
		SecurityModel:               g.c.SecurityModel,
		ContextEngineID:             g.c.ContextEngineID,
		ContextName:                 g.c.ContextName,
		Logger:                      g.c.Logger,
		AppOpts:                     g.c.AppOpts,
		Retries:                     g.c.Retries,
		Timeout:                     g.c.Timeout,
		ExponentialTimeout:          g.c.ExponentialTimeout,
		MaxRepetitions:              g.c.MaxRepetitions,
		MaxOids:                     g.c.MaxOids,
		UseUnconnectedUDPSocket:     g.c.UseUnconnectedUDPSocket,
		Context:                     g.c.Context,
		Control:                     g.c.Control,
		TrapSecurityParametersTable: g.c.TrapSecurityParametersTable,
	}
	if g.c.SecurityParameters != nil {
		clone.SecurityParameters = g.c.SecurityParameters.Copy()
	}
	w := &GoSNMPWrapper{c: clone, logger: g.logger}
	// Replay recorded options (metrics hooks, walk params) on the clone.
	// Field values were already copied above; the point is re-running the
	// closures so the clone gets its own hook instances.
	w.SetOptions(g.opts...)
	return w
}

func (g *GoSNMPWrapper) Get(oids []string) (*gosnmp.SnmpPacket, error) {
	g.logger.Debug("Getting OIDs", "oids", oids)
	st := time.Now()
	results, err := g.c.Get(oids)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			err = fmt.Errorf("scrape cancelled after %s (possible timeout) getting target %s",
				time.Since(st), g.c.Target)
		} else {
			err = fmt.Errorf("error getting target %s: %w", g.c.Target, err)
		}
		return results, err
	}
	g.logger.Debug("Get of OIDs completed", "oids", oids, "duration_seconds", time.Since(st))
	return results, err
}

func (g *GoSNMPWrapper) WalkAll(oid string) ([]gosnmp.SnmpPDU, error) {
	var results []gosnmp.SnmpPDU
	var err error
	g.logger.Debug("Walking subtree", "oid", oid)
	st := time.Now()
	if g.c.Version == gosnmp.Version1 {
		results, err = g.c.WalkAll(oid)
	} else {
		results, err = g.c.BulkWalkAll(oid)
	}
	if err != nil {
		if errors.Is(err, context.Canceled) {
			err = fmt.Errorf("scrape canceled after %s (possible timeout) walking target %s",
				time.Since(st), g.c.Target)
		} else {
			err = fmt.Errorf("error walking target %s: %w", g.c.Target, err)
		}
		return results, err
	}
	g.logger.Debug("Walk of subtree completed", "oid", oid, "duration_seconds", time.Since(st))
	return results, err
}
