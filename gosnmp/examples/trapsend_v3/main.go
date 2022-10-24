// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package main

import (
	_ "crypto/md5"
	_ "crypto/sha1"
	"log"
	"os"
	"time"

	g "github.com/gosnmp/gosnmp"
)

func main() {

	// Default is a pointer to a GoSNMP struct that contains sensible defaults
	// eg port 161, community public, etc

	params := &g.GoSNMP{
		Target:        "127.0.0.1",
		Port:          162,
		Version:       g.Version3,
		Timeout:       time.Duration(30) * time.Second,
		SecurityModel: g.UserSecurityModel,
		MsgFlags:      g.AuthPriv,
		Logger:        g.NewLogger(log.New(os.Stdout, "", 0)),
		SecurityParameters: &g.UsmSecurityParameters{UserName: "user",
			AuthoritativeEngineID:    "1234",
			AuthenticationProtocol:   g.SHA,
			AuthenticationPassphrase: "password",
			PrivacyProtocol:          g.DES,
			PrivacyPassphrase:        "password",
		},
	}
	err := params.Connect()
	if err != nil {
		log.Fatalf("Connect() err: %v", err)
	}
	defer params.Conn.Close()

	pdu := g.SnmpPDU{
		Name:  ".1.3.6.1.6.3.1.1.4.1.0",
		Type:  g.ObjectIdentifier,
		Value: ".1.3.6.1.6.3.1.1.5.1",
	}

	trap := g.SnmpTrap{
		Variables: []g.SnmpPDU{pdu},
	}

	_, err = params.SendTrap(trap)
	if err != nil {
		log.Fatalf("SendTrap() err: %v", err)
	}
}
