// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package main

import (
	"fmt"
	"log"
	"syscall"
	"time"

	g "github.com/gosnmp/gosnmp"
)

func main() {
	// build our own GoSNMP struct, rather than using g.Default
	params := &g.GoSNMP{
		Target:                  "192.168.1.1",
		Port:                    161,
		Version:                 g.Version2c,
		Community:               "public",
		Timeout:                 time.Duration(30) * time.Second,
		UseUnconnectedUDPSocket: false,
		// Use a the Control function to bind the underlying socket
		// to the VRF device on Linux. The VRF must already exists.
		// https://www.kernel.org/doc/Documentation/networking/vrf.txt
		Control: func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.BindToDevice(int(fd), "VRF1")
			})
		},
		// Specify an IP address within the VRF
		LocalAddr: "192.168.1.2:0",
	}
	err := params.Connect()
	if err != nil {
		log.Fatalf("Connect() err: %v", err)
	}
	defer params.Conn.Close()

	oids := []string{"1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.7.0"}
	result, err2 := params.Get(oids) // Get() accepts up to g.MAX_OIDS
	if err2 != nil {
		log.Fatalf("Get() err: %v", err2)
	}

	for i, variable := range result.Variables {
		fmt.Printf("%d: oid: %s ", i, variable.Name)

		// the Value of each variable returned by Get() implements
		// interface{}. You could do a type switch...
		switch variable.Type {
		case g.OctetString:
			fmt.Printf("string: %s\n", string(variable.Value.([]byte)))
		default:
			// ... or often you're just interested in numeric values.
			// ToBigInt() will return the Value as a BigInt, for plugging
			// into your calculations.
			fmt.Printf("number: %d\n", g.ToBigInt(variable.Value))
		}
	}
}
