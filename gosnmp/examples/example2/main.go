// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

/*
Example usage and output:

$ GOSNMP_TARGET=10.12.0.1 GOSNMP_PORT=161 go run main.go
SEND INIT
SENDING PACKET: gosnmp.SnmpPacket{Version:0x1, MsgFlags:0x0, SecurityModel:0x0, SecurityParameters:gosnmp.SnmpV3SecurityParameters(nil), ContextEngineID:"", ContextName:"", Community:"public", PDUType:0xa0, MsgID:0x0, RequestID:0x48ef671d, MsgMaxSize:0x0, Error:0x0, ErrorIndex:0x0, NonRepeaters:0x0, MaxRepetitions:0x0, Variables:[]gosnmp.SnmpPDU{gosnmp.SnmpPDU{Name:"1.3.6.1.2.1.1.4.0", Type:0x5, Value:interface {}(nil)}, gosnmp.SnmpPDU{Name:"1.3.6.1.2.1.1.7.0", Type:0x5, Value:interface {}(nil)}}, Logger:gosnmp.Logger(nil), SnmpTrap:gosnmp.SnmpTrap{Variables:[]gosnmp.SnmpPDU(nil), IsInform:false, Enterprise:"", AgentAddress:"", GenericTrap:0, SpecificTrap:0, Timestamp:0x0}}
WAITING RESPONSE...
2021/01/03 13:31:15 Query latency in seconds: 0.000625777
GET RESPONSE OK: [48 63 2 1 1 4 6 112 117 98 108 105 99 162 50 2 4 72 239 103 29 2 1 0 2 1 0 48 36 48 19 6 8 43 6 1 2 1 1 4 0 4 7 99 111 110 116 97 99 116 48 13 6 8 43 6 1 2 1 1 7 0 2 1 78]
Packet sanity verified, we got all the bytes (65)
parseRawField: version
Parsed version 1
parseRawField: community
Parsed community public
UnmarshalPayload Meet PDUType 0xa2. Offset 13
getResponseLength: 52
parseRawField: request id
requestID: 1223649053
parseRawField: error-status
errorStatus: 0
parseRawField: error index
error-index: 0
vblLength: 38
parseRawField: OID
OID: .1.3.6.1.2.1.1.4.0
decodeValue: msg: value
decodeValue: type is OctetString
decodeValue: value is []byte{0x63, 0x6f, 0x6e, 0x74, 0x61, 0x63, 0x74}
parseRawField: OID
OID: .1.3.6.1.2.1.1.7.0
decodeValue: msg: value
decodeValue: type is Integer
decodeValue: value is 78
0: oid: .1.3.6.1.2.1.1.4.0 string: contact
1: oid: .1.3.6.1.2.1.1.7.0 number: 78

*/

package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	g "github.com/gosnmp/gosnmp"
)

func main() {

	// get Target and Port from environment
	envTarget := os.Getenv("GOSNMP_TARGET")
	envPort := os.Getenv("GOSNMP_PORT")
	if len(envTarget) <= 0 {
		log.Fatalf("environment variable not set: GOSNMP_TARGET")
	}
	if len(envPort) <= 0 {
		log.Fatalf("environment variable not set: GOSNMP_PORT")
	}
	port, _ := strconv.ParseUint(envPort, 10, 16)

	// Build our own GoSNMP struct, rather than using g.Default.
	// Do verbose logging of packets.
	params := &g.GoSNMP{
		Target:    envTarget,
		Port:      uint16(port),
		Community: "public",
		Version:   g.Version2c,
		Timeout:   time.Duration(2) * time.Second,
		Logger:    g.NewLogger(log.New(os.Stdout, "", 0)),
	}
	err := params.Connect()
	if err != nil {
		log.Fatalf("Connect() err: %v", err)
	}
	defer params.Conn.Close()

	// Function handles for collecting metrics on query latencies.
	var sent time.Time
	params.OnSent = func(x *g.GoSNMP) {
		sent = time.Now()
	}
	params.OnRecv = func(x *g.GoSNMP) {
		log.Println("Query latency in seconds:", time.Since(sent).Seconds())
	}

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
