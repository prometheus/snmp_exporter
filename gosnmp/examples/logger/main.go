// Copyright 2021 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// building this code with the gosnmp_nodebug tag will completely disable compiler-level logging.
// If you however want to enable or disable logging at runtime you could choose to do so as folow:
package main

import (
	"log"
	"os"

	g "github.com/gosnmp/gosnmp"
)

func main() {

	stdout_logger := g.NewLogger(log.New(os.Stdout, "", 0)) // enable logging with stdout
	disabled_logger := g.NewLogger(nil)                     // disable logging

	params := &g.GoSNMP{
		Target:    "127.0.0.1",
		Port:      uint16(1161),
		Community: "public",
	}
	params.Connect() // no logger specified, logging is disabled
	params.Conn.Close()

	params.Logger = stdout_logger
	params.Connect() // logging enabled using stdout
	params.Conn.Close()

	params.Logger = disabled_logger
	params.Connect() // logging is disabled
	params.Conn.Close()
}

// on v1.31 with logging enabled, and Logger variable is not set
// go test -v -bench=. -benchmem -benchtime=100000x -tags all
// BenchmarkSendOneRequest-24        100000             70542 ns/op            3088 B/op         84 allocs/op

// on v1.31 with logging enabled, and Logger variable is set to NewLogger(nil)
// go test -v -bench=. -benchmem -benchtime=100000x -tags all
// BenchmarkSendOneRequest-24        100000             70377 ns/op            3088 B/op         84 allocs/op
