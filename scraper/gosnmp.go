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
		port = uint16(p)
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

func (g *GoSNMPWrapper) SetOptions(fns ...func(*gosnmp.GoSNMP)) {
	for _, fn := range fns {
		fn(g.c)
	}
}

func (g *GoSNMPWrapper) Connect() error {
	st := time.Now()
	err := g.c.Connect()
	if err != nil {
		if err == context.Canceled {
			return fmt.Errorf("scrape cancelled after %s (possible timeout) connecting to target %s",
				time.Since(st), g.c.Target)
		}
		return fmt.Errorf("error connecting to target %s: %s", g.c.Target, err)
	}
	return nil
}

func (g *GoSNMPWrapper) Close() error {
	return g.c.Conn.Close()
}

func (g *GoSNMPWrapper) Get(oids []string) (results *gosnmp.SnmpPacket, err error) {
	g.logger.Debug("Getting OIDs", "oids", oids)
	st := time.Now()
	results, err = g.c.Get(oids)
	if err != nil {
		if err == context.Canceled {
			err = fmt.Errorf("scrape cancelled after %s (possible timeout) getting target %s",
				time.Since(st), g.c.Target)
		} else {
			err = fmt.Errorf("error getting target %s: %s", g.c.Target, err)
		}
		return
	}
	g.logger.Debug("Get of OIDs completed", "oids", oids, "duration_seconds", time.Since(st))
	return
}

func (g *GoSNMPWrapper) WalkAll(oid string) (results []gosnmp.SnmpPDU, err error) {
	g.logger.Debug("Walking subtree", "oid", oid)
	st := time.Now()
	if g.c.Version == gosnmp.Version1 {
		results, err = g.c.WalkAll(oid)
	} else {
		results, err = g.c.BulkWalkAll(oid)
	}
	if err != nil {
		if err == context.Canceled {
			err = fmt.Errorf("scrape canceled after %s (possible timeout) walking target %s",
				time.Since(st), g.c.Target)
		} else {
			err = fmt.Errorf("error walking target %s: %s", g.c.Target, err)
		}
		return
	}
	g.logger.Debug("Walk of subtree completed", "oid", oid, "duration_seconds", time.Since(st))
	return
}
