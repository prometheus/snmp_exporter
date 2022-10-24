// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

//go:build all || trap
// +build all trap

package gosnmp

import (
	"io/ioutil"
	"log"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	trapTestAddress = "127.0.0.1"

	// TODO this is bad. Listen and Connect expect different address formats
	// so we need an int version and a string version - they should be the same.
	trapTestPort       = 9162
	trapTestPortString = "9162"

	trapTestOid     = ".1.2.1234.4.5"
	trapTestPayload = "TRAPTEST1234"

	trapTestEnterpriseOid = ".1.2.1234"
	trapTestAgentAddress  = "127.0.0.1"
	trapTestGenericTrap   = 6
	trapTestSpecificTrap  = 55
	trapTestTimestamp     = 300
)

var testsUnmarshalTrap = []struct {
	in  func() []byte
	out *SnmpPacket
}{
	{genericV3Trap,
		&SnmpPacket{
			Version:   Version3,
			PDUType:   SNMPv2Trap,
			RequestID: 957979745,
			MsgFlags:  AuthNoPriv,
			SecurityParameters: &UsmSecurityParameters{
				UserName:                 "myuser",
				AuthenticationProtocol:   MD5,
				AuthenticationPassphrase: "mypassword",
				Logger:                   NewLogger(log.New(ioutil.Discard, "", 0)),
			},
		},
	},
}

func TestUnmarshalTrap(t *testing.T) {
	Default.Logger = NewLogger(log.New(ioutil.Discard, "", 0))

SANITY:
	for i, test := range testsUnmarshalTrap {

		Default.SecurityParameters = test.out.SecurityParameters.Copy()
		Default.Version = Version3
		var buf = test.in()
		res, err := Default.UnmarshalTrap(buf, true)
		require.NoError(t, err, "unmarshalTrap failed")
		if res == nil {
			t.Errorf("#%d, UnmarshalTrap returned nil", i)
			continue SANITY
		}

		// test enough fields fields to ensure unmarshalling was successful.
		// full unmarshal testing is performed in TestUnmarshal
		if res.Version != test.out.Version {
			t.Errorf("#%d Version result: %v, test: %v", i, res.Version, test.out.Version)
		}
		if res.RequestID != test.out.RequestID {
			t.Errorf("#%d RequestID result: %v, test: %v", i, res.RequestID, test.out.RequestID)
		}
	}
}

func genericV3Trap() []byte {
	return []byte{
		0x30, 0x81, 0xd7, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x62, 0xaf,
		0x5a, 0x8e, 0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x01, 0x02, 0x01,
		0x03, 0x04, 0x33, 0x30, 0x31, 0x04, 0x11, 0x80, 0x00, 0x1f, 0x88, 0x80,
		0x77, 0xdf, 0xe4, 0x4f, 0xaa, 0x70, 0x02, 0x58, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x01, 0x0f, 0x02, 0x01, 0x00, 0x04, 0x06, 0x6d, 0x79, 0x75, 0x73,
		0x65, 0x72, 0x04, 0x0c, 0xd8, 0xb6, 0x9c, 0xb8, 0x22, 0x91, 0xfc, 0x65,
		0xb6, 0x84, 0xcb, 0xfe, 0x04, 0x00, 0x30, 0x81, 0x89, 0x04, 0x11, 0x80,
		0x00, 0x1f, 0x88, 0x80, 0x77, 0xdf, 0xe4, 0x4f, 0xaa, 0x70, 0x02, 0x58,
		0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0xa7, 0x72, 0x02, 0x04, 0x39, 0x19,
		0x9c, 0x61, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x64, 0x30, 0x0f,
		0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00, 0x43, 0x03,
		0x15, 0x2f, 0xec, 0x30, 0x14, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x06, 0x03,
		0x01, 0x01, 0x04, 0x01, 0x00, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x02, 0x01,
		0x01, 0x30, 0x16, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01,
		0x00, 0x04, 0x0a, 0x72, 0x65, 0x64, 0x20, 0x6c, 0x61, 0x70, 0x74, 0x6f,
		0x70, 0x30, 0x0d, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x07,
		0x00, 0x02, 0x01, 0x05, 0x30, 0x14, 0x06, 0x07, 0x2b, 0x06, 0x01, 0x02,
		0x01, 0x01, 0x02, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x02, 0x03,
		0x04, 0x05}
}

func makeTestTrapHandler(t *testing.T, done chan int, version SnmpVersion) func(*SnmpPacket, *net.UDPAddr) {
	Default.Logger = NewLogger(log.New(ioutil.Discard, "", 0))
	return func(packet *SnmpPacket, addr *net.UDPAddr) {
		//log.Printf("got trapdata from %s\n", addr.IP)
		defer close(done)

		if version == Version1 {
			if packet.Enterprise != trapTestEnterpriseOid {
				t.Fatalf("incorrect trap Enterprise OID received, expected %s got %s", trapTestEnterpriseOid, packet.Enterprise)
			}
			if packet.AgentAddress != trapTestAgentAddress {
				t.Fatalf("incorrect trap Agent Address received, expected %s got %s", trapTestAgentAddress, packet.AgentAddress)
			}
			if packet.GenericTrap != trapTestGenericTrap {
				t.Fatalf("incorrect trap Generic Trap identifier received, expected %v got %v", trapTestGenericTrap, packet.GenericTrap)
			}
			if packet.SpecificTrap != trapTestSpecificTrap {
				t.Fatalf("incorrect trap Specific Trap identifier received, expected %v got %v", trapTestSpecificTrap, packet.SpecificTrap)
			}
			if packet.Timestamp != trapTestTimestamp {
				t.Fatalf("incorrect trap Timestamp received, expected %v got %v", trapTestTimestamp, packet.Timestamp)
			}
		}

		for _, v := range packet.Variables {
			switch v.Type {
			case OctetString:
				b := v.Value.([]byte)
				// log.Printf("OID: %s, string: %x\n", v.Name, b)

				// Only one OctetString in the payload, so it must be the expected one
				if v.Name != trapTestOid {
					t.Fatalf("incorrect trap OID received, expected %s got %s", trapTestOid, v.Name)
				}
				if string(b) != trapTestPayload {
					t.Fatalf("incorrect trap payload received, expected %s got %x", trapTestPayload, b)
				}
			default:
				// log.Printf("trap: %+v\n", v)
			}
		}
	}
}

// TODO: This restores global state set by other tests so that these tests can
// run. Tests should be avoiding use of global state where possible (and, if
// possible, use of global state other than possibly loggers should be
// eliminated entirely).
func TestRestoreGlobals(t *testing.T) {
	Default.Version = Version2c
	Default.SecurityModel = 0
	Default.SecurityParameters = nil
}

// test sending a basic SNMP trap, using our own listener to receive
func TestSendTrapBasic(t *testing.T) {
	done := make(chan int)

	tl := NewTrapListener()
	defer tl.Close()

	tl.OnNewTrap = makeTestTrapHandler(t, done, Version2c)
	tl.Params = Default

	// listener goroutine
	errch := make(chan error)
	go func() {
		// defer close(errch)
		err := tl.Listen(net.JoinHostPort(trapTestAddress, trapTestPortString))
		if err != nil {
			errch <- err
		}
	}()

	// Wait until the listener is ready.
	select {
	case <-tl.Listening():
	case err := <-errch:
		t.Fatalf("error in listen: %v", err)
	}
	ts := &GoSNMP{
		Target:    trapTestAddress,
		Port:      trapTestPort,
		Community: "public",
		Version:   Version2c,
		Timeout:   time.Duration(2) * time.Second,
		Retries:   3,
		MaxOids:   MaxOids,
		Logger:    NewLogger(log.New(ioutil.Discard, "", 0)),
	}

	err := ts.Connect()
	if err != nil {
		t.Fatalf("Connect() err: %v", err)
	}
	defer ts.Conn.Close()

	pdu := SnmpPDU{
		Name:  trapTestOid,
		Type:  OctetString,
		Value: trapTestPayload,
	}

	trap := SnmpTrap{
		Variables: []SnmpPDU{pdu},
	}

	_, err = ts.SendTrap(trap)
	if err != nil {
		t.Fatalf("SendTrap() err: %v", err)
	}

	// wait for response from handler
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for trap to be received")
	}
}

// test sending a basic SNMP inform and receiving the response
func TestSendInformBasic(t *testing.T) {
	done := make(chan int)

	tl := NewTrapListener()
	defer tl.Close()

	tl.OnNewTrap = makeTestTrapHandler(t, done, Version2c)
	tl.Params = Default

	// listener goroutine
	errch := make(chan error)
	go func() {
		// defer close(errch)
		err := tl.Listen(net.JoinHostPort(trapTestAddress, trapTestPortString))
		if err != nil {
			errch <- err
		}
	}()

	// Wait until the listener is ready.
	select {
	case <-tl.Listening():
	case err := <-errch:
		t.Fatalf("error in listen: %v", err)
	}

	ts := &GoSNMP{
		Target:    trapTestAddress,
		Port:      trapTestPort,
		Community: "public",
		Version:   Version2c,
		Timeout:   time.Duration(2) * time.Second,
		Retries:   3,
		MaxOids:   MaxOids,
	}

	err := ts.Connect()
	if err != nil {
		t.Fatalf("Connect() err: %v", err)
	}
	defer ts.Conn.Close()

	pdu := SnmpPDU{
		Name:  trapTestOid,
		Type:  OctetString,
		Value: trapTestPayload,
	}

	// Make it an inform.
	trap := SnmpTrap{
		Variables: []SnmpPDU{pdu},
		IsInform:  true,
	}

	var resp *SnmpPacket
	resp, err = ts.SendTrap(trap)
	if err != nil {
		t.Fatalf("SendTrap() err: %v", err)
	}

	// wait for response from handler
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for trap to be received")
	}

	if resp.PDUType != GetResponse {
		t.Fatal("Inform response is not a response PDU")
	}

	for i, tv := range trap.Variables {
		rv := resp.Variables[i+1]
		if reflect.DeepEqual(tv, rv) {
			t.Fatalf("Expected variable %d = %#v, got %#v", i, tv, rv)
		}
	}
}

// test the listener is not blocked if Listening is not used
func TestSendTrapWithoutWaitingOnListen(t *testing.T) {
	done := make(chan int)

	tl := NewTrapListener()
	defer tl.Close()

	tl.OnNewTrap = makeTestTrapHandler(t, done, Version2c)
	tl.Params = Default

	errch := make(chan error)
	listening := make(chan bool)
	go func() {
		// Reduce the chance of necessity for a restart.
		listening <- true

		err := tl.Listen(net.JoinHostPort(trapTestAddress, trapTestPortString))
		if err != nil {
			errch <- err
		}
	}()

	select {
	case <-listening:
	case err := <-errch:
		t.Fatalf("error in listen: %v", err)
	}

	ts := &GoSNMP{
		Target:    trapTestAddress,
		Port:      trapTestPort,
		Community: "public",
		Version:   Version2c,
		Timeout:   time.Duration(2) * time.Second,
		Retries:   3,
		MaxOids:   MaxOids,
	}

	err := ts.Connect()
	if err != nil {
		t.Fatalf("Connect() err: %v", err)
	}
	defer ts.Conn.Close()

	pdu := SnmpPDU{
		Name:  trapTestOid,
		Type:  OctetString,
		Value: trapTestPayload,
	}

	trap := SnmpTrap{
		Variables: []SnmpPDU{pdu},
	}

	_, err = ts.SendTrap(trap)
	if err != nil {
		t.Fatalf("SendTrap() err: %v", err)
	}

	// Wait for a response from the handler and restart the SendTrap
	// if the listener wasn't ready.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_, err = ts.SendTrap(trap)
		if err != nil {
			t.Fatalf("restarted SendTrap() err: %v", err)
		}

		t.Log("restarted")

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for trap to be received")
		}
	}
}

// test sending a basic SNMP trap, using our own listener to receive
func TestSendV1Trap(t *testing.T) {
	done := make(chan int)

	tl := NewTrapListener()
	defer tl.Close()

	tl.OnNewTrap = makeTestTrapHandler(t, done, Version1)
	tl.Params = Default

	// listener goroutine
	errch := make(chan error)
	go func() {
		err := tl.Listen(net.JoinHostPort(trapTestAddress, trapTestPortString))
		if err != nil {
			errch <- err
		}
	}()

	// Wait until the listener is ready.
	select {
	case <-tl.Listening():
	case err := <-errch:
		t.Fatalf("error in listen: %v", err)
	}

	ts := &GoSNMP{
		Target: trapTestAddress,
		Port:   trapTestPort,
		//Community: "public",
		Version: Version1,
		Timeout: time.Duration(2) * time.Second,
		Retries: 3,
		MaxOids: MaxOids,
	}

	err := ts.Connect()
	if err != nil {
		t.Fatalf("Connect() err: %v", err)
	}
	defer ts.Conn.Close()

	pdu := SnmpPDU{
		Name:  trapTestOid,
		Type:  OctetString,
		Value: trapTestPayload,
	}

	trap := SnmpTrap{
		Variables:    []SnmpPDU{pdu},
		Enterprise:   trapTestEnterpriseOid,
		AgentAddress: trapTestAgentAddress,
		GenericTrap:  trapTestGenericTrap,
		SpecificTrap: trapTestSpecificTrap,
		Timestamp:    trapTestTimestamp,
	}

	_, err = ts.SendTrap(trap)
	if err != nil {
		t.Fatalf("SendTrap() err: %v", err)
	}

	// wait for response from handler
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for trap to be received")
	}
}

func TestSendV3TrapNoAuthNoPriv(t *testing.T) {
	done := make(chan int)

	tl := NewTrapListener()
	defer tl.Close()

	sp := &UsmSecurityParameters{
		UserName:                 "test",
		AuthoritativeEngineBoots: 1,
		AuthoritativeEngineTime:  1,
		AuthoritativeEngineID:    string([]byte{0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04}),
	}

	tl.OnNewTrap = makeTestTrapHandler(t, done, Version3)
	tl.Params = Default
	tl.Params.Version = Version3
	tl.Params.SecurityParameters = sp
	tl.Params.SecurityModel = UserSecurityModel
	tl.Params.MsgFlags = NoAuthNoPriv

	// listener goroutine
	errch := make(chan error)
	go func() {
		err := tl.Listen(net.JoinHostPort(trapTestAddress, trapTestPortString))
		if err != nil {
			errch <- err
		}
	}()

	// Wait until the listener is ready.
	select {
	case <-tl.Listening():
	case err := <-errch:
		t.Fatalf("error in listen: %v", err)
	}

	ts := &GoSNMP{
		Target: trapTestAddress,
		Port:   trapTestPort,
		//Community: "public",
		Version:            Version3,
		Timeout:            time.Duration(2) * time.Second,
		Retries:            3,
		MaxOids:            MaxOids,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: sp,
		MsgFlags:           NoAuthNoPriv,
	}

	err := ts.Connect()
	if err != nil {
		t.Fatalf("Connect() err: %v", err)
	}
	defer ts.Conn.Close()

	pdu := SnmpPDU{
		Name:  trapTestOid,
		Type:  OctetString,
		Value: trapTestPayload,
	}

	trap := SnmpTrap{
		Variables:    []SnmpPDU{pdu},
		Enterprise:   trapTestEnterpriseOid,
		AgentAddress: trapTestAgentAddress,
		GenericTrap:  trapTestGenericTrap,
		SpecificTrap: trapTestSpecificTrap,
		Timestamp:    trapTestTimestamp,
	}

	_, err = ts.SendTrap(trap)
	if err != nil {
		t.Fatalf("SendTrap() err: %v", err)
	}

	// wait for response from handler
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for trap to be received")
	}

}

func TestSendV3TrapMD5AuthNoPriv(t *testing.T) {
	done := make(chan int)

	tl := NewTrapListener()
	defer tl.Close()

	sp := &UsmSecurityParameters{
		UserName:                 "test",
		AuthenticationProtocol:   MD5,
		AuthenticationPassphrase: "password",
		AuthoritativeEngineBoots: 1,
		AuthoritativeEngineTime:  1,
		AuthoritativeEngineID:    string([]byte{0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04}),
	}

	tl.OnNewTrap = makeTestTrapHandler(t, done, Version3)
	tl.Params = Default
	tl.Params.Version = Version3
	tl.Params.SecurityParameters = sp
	tl.Params.SecurityModel = UserSecurityModel
	tl.Params.MsgFlags = AuthNoPriv

	// listener goroutine
	errch := make(chan error)
	go func() {
		err := tl.Listen(net.JoinHostPort(trapTestAddress, trapTestPortString))
		if err != nil {
			errch <- err
		}
	}()

	// Wait until the listener is ready.
	select {
	case <-tl.Listening():
	case err := <-errch:
		t.Fatalf("error in listen: %v", err)
	}

	ts := &GoSNMP{
		Target: trapTestAddress,
		Port:   trapTestPort,
		//Community: "public",
		Version:            Version3,
		Timeout:            time.Duration(2) * time.Second,
		Retries:            3,
		MaxOids:            MaxOids,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: sp,
		MsgFlags:           AuthNoPriv,
	}

	err := ts.Connect()
	if err != nil {
		t.Fatalf("Connect() err: %v", err)
	}
	defer ts.Conn.Close()

	pdu := SnmpPDU{
		Name:  trapTestOid,
		Type:  OctetString,
		Value: trapTestPayload,
	}

	trap := SnmpTrap{
		Variables:    []SnmpPDU{pdu},
		Enterprise:   trapTestEnterpriseOid,
		AgentAddress: trapTestAgentAddress,
		GenericTrap:  trapTestGenericTrap,
		SpecificTrap: trapTestSpecificTrap,
		Timestamp:    trapTestTimestamp,
	}

	_, err = ts.SendTrap(trap)
	if err != nil {
		t.Fatalf("SendTrap() err: %v", err)
	}

	// wait for response from handler
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for trap to be received")
	}

}

func TestSendV3TrapSHAAuthNoPriv(t *testing.T) {
	done := make(chan int)

	tl := NewTrapListener()
	defer tl.Close()

	sp := &UsmSecurityParameters{
		UserName:                 "test",
		AuthenticationProtocol:   SHA,
		AuthenticationPassphrase: "password",
		AuthoritativeEngineBoots: 1,
		AuthoritativeEngineTime:  1,
		AuthoritativeEngineID:    string([]byte{0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04}),
	}

	tl.OnNewTrap = makeTestTrapHandler(t, done, Version3)
	tl.Params = Default
	tl.Params.Version = Version3
	tl.Params.SecurityParameters = sp
	tl.Params.SecurityModel = UserSecurityModel
	tl.Params.MsgFlags = AuthNoPriv

	// listener goroutine
	errch := make(chan error)
	go func() {
		err := tl.Listen(net.JoinHostPort(trapTestAddress, trapTestPortString))
		if err != nil {
			errch <- err
		}
	}()

	// Wait until the listener is ready.
	select {
	case <-tl.Listening():
	case err := <-errch:
		t.Fatalf("error in listen: %v", err)
	}

	ts := &GoSNMP{
		Target: trapTestAddress,
		Port:   trapTestPort,
		//Community: "public",
		Version:            Version3,
		Timeout:            time.Duration(2) * time.Second,
		Retries:            3,
		MaxOids:            MaxOids,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: sp,
		MsgFlags:           AuthNoPriv,
	}

	err := ts.Connect()
	if err != nil {
		t.Fatalf("Connect() err: %v", err)
	}
	defer ts.Conn.Close()

	pdu := SnmpPDU{
		Name:  trapTestOid,
		Type:  OctetString,
		Value: trapTestPayload,
	}

	trap := SnmpTrap{
		Variables:    []SnmpPDU{pdu},
		Enterprise:   trapTestEnterpriseOid,
		AgentAddress: trapTestAgentAddress,
		GenericTrap:  trapTestGenericTrap,
		SpecificTrap: trapTestSpecificTrap,
		Timestamp:    trapTestTimestamp,
	}

	_, err = ts.SendTrap(trap)
	if err != nil {
		t.Fatalf("SendTrap() err: %v", err)
	}

	// wait for response from handler
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for trap to be received")
	}

}
func TestSendV3TrapSHAAuthDESPriv(t *testing.T) {
	done := make(chan int)

	tl := NewTrapListener()
	defer tl.Close()

	sp := &UsmSecurityParameters{
		UserName:                 "test",
		AuthenticationProtocol:   SHA,
		AuthenticationPassphrase: "password",
		PrivacyProtocol:          DES,
		PrivacyPassphrase:        "password",
		AuthoritativeEngineBoots: 1,
		AuthoritativeEngineTime:  1,
		AuthoritativeEngineID:    string([]byte{0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04}),
	}

	tl.OnNewTrap = makeTestTrapHandler(t, done, Version3)
	tl.Params = Default
	tl.Params.Version = Version3
	tl.Params.SecurityParameters = sp
	tl.Params.SecurityModel = UserSecurityModel
	tl.Params.MsgFlags = AuthPriv

	// listener goroutine
	errch := make(chan error)
	go func() {
		err := tl.Listen(net.JoinHostPort(trapTestAddress, trapTestPortString))
		if err != nil {
			errch <- err
		}
	}()

	// Wait until the listener is ready.
	select {
	case <-tl.Listening():
	case err := <-errch:
		t.Fatalf("error in listen: %v", err)
	}

	ts := &GoSNMP{
		Target: trapTestAddress,
		Port:   trapTestPort,
		//Community: "public",
		Version:            Version3,
		Timeout:            time.Duration(2) * time.Second,
		Retries:            3,
		MaxOids:            MaxOids,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: sp,
		MsgFlags:           AuthPriv,
	}

	err := ts.Connect()
	if err != nil {
		t.Fatalf("Connect() err: %v", err)
	}
	defer ts.Conn.Close()

	pdu := SnmpPDU{
		Name:  trapTestOid,
		Type:  OctetString,
		Value: trapTestPayload,
	}

	trap := SnmpTrap{
		Variables:    []SnmpPDU{pdu},
		Enterprise:   trapTestEnterpriseOid,
		AgentAddress: trapTestAgentAddress,
		GenericTrap:  trapTestGenericTrap,
		SpecificTrap: trapTestSpecificTrap,
		Timestamp:    trapTestTimestamp,
	}

	_, err = ts.SendTrap(trap)
	if err != nil {
		t.Fatalf("SendTrap() err: %v", err)
	}

	// wait for response from handler
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for trap to be received")
	}

}

func TestSendV3TrapSHAAuthAESPriv(t *testing.T) {
	done := make(chan int)

	tl := NewTrapListener()
	defer tl.Close()

	sp := &UsmSecurityParameters{
		UserName:                 "test",
		AuthenticationProtocol:   SHA,
		AuthenticationPassphrase: "password",
		PrivacyProtocol:          AES,
		PrivacyPassphrase:        "password",
		AuthoritativeEngineBoots: 1,
		AuthoritativeEngineTime:  1,
		AuthoritativeEngineID:    string([]byte{0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04}),
	}

	tl.OnNewTrap = makeTestTrapHandler(t, done, Version3)
	tl.Params = Default
	tl.Params.Version = Version3
	tl.Params.SecurityParameters = sp
	tl.Params.SecurityModel = UserSecurityModel
	tl.Params.MsgFlags = AuthPriv

	// listener goroutine
	errch := make(chan error)
	go func() {
		err := tl.Listen(net.JoinHostPort(trapTestAddress, trapTestPortString))
		if err != nil {
			errch <- err
		}
	}()

	// Wait until the listener is ready.
	select {
	case <-tl.Listening():
	case err := <-errch:
		t.Fatalf("error in listen: %v", err)
	}

	ts := &GoSNMP{
		Target: trapTestAddress,
		Port:   trapTestPort,
		//Community: "public",
		Version:            Version3,
		Timeout:            time.Duration(2) * time.Second,
		Retries:            3,
		MaxOids:            MaxOids,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: sp,
		MsgFlags:           AuthPriv,
	}

	err := ts.Connect()
	if err != nil {
		t.Fatalf("Connect() err: %v", err)
	}
	defer ts.Conn.Close()

	pdu := SnmpPDU{
		Name:  trapTestOid,
		Type:  OctetString,
		Value: trapTestPayload,
	}

	trap := SnmpTrap{
		Variables:    []SnmpPDU{pdu},
		Enterprise:   trapTestEnterpriseOid,
		AgentAddress: trapTestAgentAddress,
		GenericTrap:  trapTestGenericTrap,
		SpecificTrap: trapTestSpecificTrap,
		Timestamp:    trapTestTimestamp,
	}

	_, err = ts.SendTrap(trap)
	if err != nil {
		t.Fatalf("SendTrap() err: %v", err)
	}

	// wait for response from handler
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for trap to be received")
	}

}

func TestSendV3TrapSHAAuthAES192Priv(t *testing.T) {
	done := make(chan int)

	tl := NewTrapListener()
	defer tl.Close()

	sp := &UsmSecurityParameters{
		UserName:                 "test",
		AuthenticationProtocol:   SHA,
		AuthenticationPassphrase: "password",
		PrivacyProtocol:          AES192,
		PrivacyPassphrase:        "password",
		AuthoritativeEngineBoots: 1,
		AuthoritativeEngineTime:  1,
		AuthoritativeEngineID:    string([]byte{0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04}),
	}

	tl.OnNewTrap = makeTestTrapHandler(t, done, Version3)
	tl.Params = Default
	tl.Params.Version = Version3
	tl.Params.SecurityParameters = sp
	tl.Params.SecurityModel = UserSecurityModel
	tl.Params.MsgFlags = AuthPriv

	// listener goroutine
	errch := make(chan error)
	go func() {
		err := tl.Listen(net.JoinHostPort(trapTestAddress, trapTestPortString))
		if err != nil {
			errch <- err
		}
	}()

	// Wait until the listener is ready.
	select {
	case <-tl.Listening():
	case err := <-errch:
		t.Fatalf("error in listen: %v", err)
	}

	ts := &GoSNMP{
		Target: trapTestAddress,
		Port:   trapTestPort,
		//Community: "public",
		Version:            Version3,
		Timeout:            time.Duration(2) * time.Second,
		Retries:            3,
		MaxOids:            MaxOids,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: sp,
		MsgFlags:           AuthPriv,
	}

	err := ts.Connect()
	if err != nil {
		t.Fatalf("Connect() err: %v", err)
	}
	defer ts.Conn.Close()

	pdu := SnmpPDU{
		Name:  trapTestOid,
		Type:  OctetString,
		Value: trapTestPayload,
	}

	trap := SnmpTrap{
		Variables:    []SnmpPDU{pdu},
		Enterprise:   trapTestEnterpriseOid,
		AgentAddress: trapTestAgentAddress,
		GenericTrap:  trapTestGenericTrap,
		SpecificTrap: trapTestSpecificTrap,
		Timestamp:    trapTestTimestamp,
	}

	_, err = ts.SendTrap(trap)
	if err != nil {
		t.Fatalf("SendTrap() err: %v", err)
	}

	// wait for response from handler
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for trap to be received")
	}

}
func TestSendV3TrapSHAAuthAES192CPriv(t *testing.T) {
	done := make(chan int)

	tl := NewTrapListener()
	defer tl.Close()

	sp := &UsmSecurityParameters{
		UserName:                 "test",
		AuthenticationProtocol:   SHA,
		AuthenticationPassphrase: "password",
		PrivacyProtocol:          AES192C,
		PrivacyPassphrase:        "password",
		AuthoritativeEngineBoots: 1,
		AuthoritativeEngineTime:  1,
		AuthoritativeEngineID:    string([]byte{0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04}),
	}

	tl.OnNewTrap = makeTestTrapHandler(t, done, Version3)
	tl.Params = Default
	tl.Params.Version = Version3
	tl.Params.SecurityParameters = sp
	tl.Params.SecurityModel = UserSecurityModel
	tl.Params.MsgFlags = AuthPriv

	// listener goroutine
	errch := make(chan error)
	go func() {
		err := tl.Listen(net.JoinHostPort(trapTestAddress, trapTestPortString))
		if err != nil {
			errch <- err
		}
	}()

	// Wait until the listener is ready.
	select {
	case <-tl.Listening():
	case err := <-errch:
		t.Fatalf("error in listen: %v", err)
	}

	ts := &GoSNMP{
		Target: trapTestAddress,
		Port:   trapTestPort,
		//Community: "public",
		Version:            Version3,
		Timeout:            time.Duration(2) * time.Second,
		Retries:            3,
		MaxOids:            MaxOids,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: sp,
		MsgFlags:           AuthPriv,
	}

	err := ts.Connect()
	if err != nil {
		t.Fatalf("Connect() err: %v", err)
	}
	defer ts.Conn.Close()

	pdu := SnmpPDU{
		Name:  trapTestOid,
		Type:  OctetString,
		Value: trapTestPayload,
	}

	trap := SnmpTrap{
		Variables:    []SnmpPDU{pdu},
		Enterprise:   trapTestEnterpriseOid,
		AgentAddress: trapTestAgentAddress,
		GenericTrap:  trapTestGenericTrap,
		SpecificTrap: trapTestSpecificTrap,
		Timestamp:    trapTestTimestamp,
	}

	_, err = ts.SendTrap(trap)
	if err != nil {
		t.Fatalf("SendTrap() err: %v", err)
	}

	// wait for response from handler
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for trap to be received")
	}
}
func TestSendV3TrapSHAAuthAES256Priv(t *testing.T) {
	done := make(chan int)

	tl := NewTrapListener()
	defer tl.Close()

	sp := &UsmSecurityParameters{
		UserName:                 "test",
		AuthenticationProtocol:   SHA,
		AuthenticationPassphrase: "password",
		PrivacyProtocol:          AES256,
		PrivacyPassphrase:        "password",
		AuthoritativeEngineBoots: 1,
		AuthoritativeEngineTime:  1,
		AuthoritativeEngineID:    string([]byte{0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04}),
	}

	tl.OnNewTrap = makeTestTrapHandler(t, done, Version3)
	tl.Params = Default
	tl.Params.Version = Version3
	tl.Params.SecurityParameters = sp
	tl.Params.SecurityModel = UserSecurityModel
	tl.Params.MsgFlags = AuthPriv

	// listener goroutine
	errch := make(chan error)
	go func() {
		err := tl.Listen(net.JoinHostPort(trapTestAddress, trapTestPortString))
		if err != nil {
			errch <- err
		}
	}()

	// Wait until the listener is ready.
	select {
	case <-tl.Listening():
	case err := <-errch:
		t.Fatalf("error in listen: %v", err)
	}

	ts := &GoSNMP{
		Target: trapTestAddress,
		Port:   trapTestPort,
		//Community: "public",
		Version:            Version3,
		Timeout:            time.Duration(2) * time.Second,
		Retries:            3,
		MaxOids:            MaxOids,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: sp,
		MsgFlags:           AuthPriv,
	}

	err := ts.Connect()
	if err != nil {
		t.Fatalf("Connect() err: %v", err)
	}
	defer ts.Conn.Close()

	pdu := SnmpPDU{
		Name:  trapTestOid,
		Type:  OctetString,
		Value: trapTestPayload,
	}

	trap := SnmpTrap{
		Variables:    []SnmpPDU{pdu},
		Enterprise:   trapTestEnterpriseOid,
		AgentAddress: trapTestAgentAddress,
		GenericTrap:  trapTestGenericTrap,
		SpecificTrap: trapTestSpecificTrap,
		Timestamp:    trapTestTimestamp,
	}

	_, err = ts.SendTrap(trap)
	if err != nil {
		t.Fatalf("SendTrap() err: %v", err)
	}

	// wait for response from handler
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for trap to be received")
	}

}
func TestSendV3TrapSHAAuthAES256CPriv(t *testing.T) {
	done := make(chan int)

	tl := NewTrapListener()
	defer tl.Close()

	sp := &UsmSecurityParameters{
		UserName:                 "test",
		AuthenticationProtocol:   SHA,
		AuthenticationPassphrase: "password",
		PrivacyProtocol:          AES256C,
		PrivacyPassphrase:        "password",
		AuthoritativeEngineBoots: 1,
		AuthoritativeEngineTime:  1,
		AuthoritativeEngineID:    string([]byte{0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04}),
	}

	tl.OnNewTrap = makeTestTrapHandler(t, done, Version3)
	tl.Params = Default
	tl.Params.Version = Version3
	tl.Params.SecurityParameters = sp
	tl.Params.SecurityModel = UserSecurityModel
	tl.Params.MsgFlags = AuthPriv

	// listener goroutine
	errch := make(chan error)
	go func() {
		err := tl.Listen(net.JoinHostPort(trapTestAddress, trapTestPortString))
		if err != nil {
			errch <- err
		}
	}()

	// Wait until the listener is ready.
	select {
	case <-tl.Listening():
	case err := <-errch:
		t.Fatalf("error in listen: %v", err)
	}

	ts := &GoSNMP{
		Target: trapTestAddress,
		Port:   trapTestPort,
		//Community: "public",
		Version:            Version3,
		Timeout:            time.Duration(2) * time.Second,
		Retries:            3,
		MaxOids:            MaxOids,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: sp,
		MsgFlags:           AuthPriv,
	}

	err := ts.Connect()
	if err != nil {
		t.Fatalf("Connect() err: %v", err)
	}
	defer ts.Conn.Close()

	pdu := SnmpPDU{
		Name:  trapTestOid,
		Type:  OctetString,
		Value: trapTestPayload,
	}

	trap := SnmpTrap{
		Variables:    []SnmpPDU{pdu},
		Enterprise:   trapTestEnterpriseOid,
		AgentAddress: trapTestAgentAddress,
		GenericTrap:  trapTestGenericTrap,
		SpecificTrap: trapTestSpecificTrap,
		Timestamp:    trapTestTimestamp,
	}

	_, err = ts.SendTrap(trap)
	if err != nil {
		t.Fatalf("SendTrap() err: %v", err)
	}

	// wait for response from handler
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for trap to be received")
	}

}

func TestSendV3EngineIdDiscovery(t *testing.T) {
	tl := NewTrapListener()
	defer tl.Close()
	authorativeEngineID := string([]byte{0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04})
	unknownEngineID := string([]byte{0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x05})
	sp := &UsmSecurityParameters{
		UserName:                 "test",
		AuthenticationProtocol:   SHA,
		AuthenticationPassphrase: "password",
		PrivacyProtocol:          AES256,
		PrivacyPassphrase:        "password",
		AuthoritativeEngineBoots: 1,
		AuthoritativeEngineTime:  1,
		AuthoritativeEngineID:    authorativeEngineID,
	}
	tl.Params = Default
	tl.Params.Version = Version3
	tl.Params.SecurityParameters = sp
	tl.Params.SecurityModel = UserSecurityModel
	tl.Params.MsgFlags = AuthPriv

	// listener goroutine
	errch := make(chan error)
	go func() {
		err := tl.Listen(net.JoinHostPort(trapTestAddress, trapTestPortString))
		if err != nil {
			errch <- err
		}
	}()

	// Wait until the listener is ready.
	select {
	case <-tl.Listening():
	case err := <-errch:
		t.Fatalf("error in listen: %v", err)
	}

	ts := &GoSNMP{
		Target: trapTestAddress,
		Port:   trapTestPort,
		//Community: "public",
		Version:            Version3,
		Timeout:            time.Duration(2) * time.Second,
		Retries:            3,
		MaxOids:            MaxOids,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: sp,
		MsgFlags:           AuthPriv,
	}

	err := ts.Connect()
	if err != nil {
		t.Fatalf("Connect() err: %v", err)
	}
	defer ts.Conn.Close()

	getEngineIDRequest := SnmpPacket{
		Version:            Version3,
		MsgFlags:           Reportable,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: &UsmSecurityParameters{},
		ContextEngineID:    unknownEngineID,
		PDUType:            GetRequest,
		MsgID:              1824792385,
		RequestID:          1411852680,
		MsgMaxSize:         65507,
	}
	result, err := ts.sendOneRequest(&getEngineIDRequest, true)
	require.NoError(t, err, "sendOneRequest failed")
	require.Equal(t, result.SecurityParameters.(*UsmSecurityParameters).AuthoritativeEngineID, authorativeEngineID, "invalid authoritativeEngineID")
	require.Equal(t, result.PDUType, Report, "invalid received PDUType")
}
