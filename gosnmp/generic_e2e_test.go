// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// This set of end-to-end integration tests execute gosnmp against a real
// SNMP MIB-2 host. Potential test systems could include a router, NAS box, printer,
// or a linux box running snmpd, snmpsimd.py, etc.
//
// Ensure "gosnmp-test-host" is defined in your hosts file, and points to your
// generic test system.

//go:build all || end2end
// +build all end2end

package gosnmp

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func getTarget(t *testing.T) (string, uint16) {
	var envTarget string
	var envPort string

	// set this flag to true in v3_testing_credentials.go if you want to use the
	// public SNMP demo service for tests
	if isUsingSnmpLabs() {
		envTarget = "demo.snmplabs.com"
		envPort = "161"
	} else {
		envTarget = os.Getenv("GOSNMP_TARGET")
		envPort = os.Getenv("GOSNMP_PORT")
	}

	if len(envTarget) <= 0 {
		t.Skip("environment variable not set: GOSNMP_TARGET")
	}

	if len(envPort) <= 0 {
		t.Skip("environment variable not set: GOSNMP_PORT")
	}
	port, _ := strconv.ParseUint(envPort, 10, 16)

	if port > 65535 {
		t.Skipf("invalid port number %d", port)
	}

	return envTarget, uint16(port)
}

func setupConnection(t *testing.T) {
	target, port := getTarget(t)

	Default.Target = target
	Default.Port = port

	err := Default.Connect()
	if err != nil {
		if len(target) > 0 {
			t.Fatalf("Connection failed. Is snmpd reachable on %s:%d?\n(err: %v)",
				target, port, err)
		}
	}
}

func setupConnectionInstance(gs *GoSNMP, t *testing.T) {
	target, port := getTarget(t)

	gs.Target = target
	gs.Port = port

	err := gs.Connect()
	if err != nil {
		if len(target) > 0 {
			t.Fatalf("Connection failed. Is snmpd reachable on %s:%d?\n(err: %v)",
				target, port, err)
		}
	}
}

func setupConnectionIPv4(t *testing.T) {
	target, port := getTarget(t)

	Default.Target = target
	Default.Port = port

	err := Default.ConnectIPv4()
	if err != nil {
		if len(target) > 0 {
			t.Fatalf("Connection failed. Is snmpd reachable on %s:%d?\n(err: %v)",
				target, port, err)
		}
	}
}

/*
TODO work out ipv6 networking, etc

func setupConnectionIPv6(t *testing.T) {
	envTarget := os.Getenv("GOSNMP_TARGET_IPV6")
	envPort := os.Getenv("GOSNMP_PORT_IPV6")

	if len(envTarget) <= 0 {
		t.Error("environment variable not set: GOSNMP_TARGET_IPV6")
	}
	Default.Target = envTarget

	if len(envPort) <= 0 {
		t.Error("environment variable not set: GOSNMP_PORT_IPV6")
	}
	port, _ := strconv.ParseUint(envPort, 10, 16)
	Default.Port = uint16(port)

	err := Default.ConnectIPv6()
	if err != nil {
		if len(envTarget) > 0 {
			t.Fatalf("Connection failed. Is snmpd reachable on %s:%s?\n(err: %v)",
				envTarget, envPort, err)
		}
	}
}
*/

func TestGenericBasicGet(t *testing.T) {
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestGenericBasicGetIPv4Only(t *testing.T) {
	setupConnectionIPv4(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

/*
func TestGenericBasicGetIPv6Only(t *testing.T) {
	setupConnectionIPv6(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}
*/

func TestGenericMultiGet(t *testing.T) {
	setupConnection(t)
	defer Default.Conn.Close()

	oids := []string{
		".1.3.6.1.2.1.1.1.0", // SNMP MIB-2 sysDescr
		".1.3.6.1.2.1.1.5.0", // SNMP MIB-2 sysName
	}
	result, err := Default.Get(oids)
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 2 {
		t.Fatalf("Expected result of size 2")
	}
	for _, v := range result.Variables {
		if v.Type != OctetString {
			t.Fatalf("Expected OctetString")
		}
	}
}

func TestGenericGetNext(t *testing.T) {
	setupConnection(t)
	defer Default.Conn.Close()

	sysDescrOid := ".1.3.6.1.2.1.1.1.0" // SNMP MIB-2 sysDescr
	result, err := Default.GetNext([]string{sysDescrOid})
	if err != nil {
		t.Fatalf("GetNext() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Name == sysDescrOid {
		t.Fatalf("Expected next OID")
	}
}

func TestGenericWalk(t *testing.T) {
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.WalkAll("")
	if err != nil {
		t.Fatalf("WalkAll() Failed with error => %v", err)
	}
	if len(result) <= 1 {
		t.Fatalf("Expected multiple values, got %d", len(result))
	}
}

func TestGenericBulkWalk(t *testing.T) {
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.BulkWalkAll("")
	if err != nil {
		t.Fatalf("BulkWalkAll() Failed with error => %v", err)
	}
	if len(result) <= 1 {
		t.Fatalf("Expected multiple values, got %d", len(result))
	}
}

func TestV1BulkWalkError(t *testing.T) {
	g := &GoSNMP{
		Version: Version1,
	}
	setupConnectionInstance(g, t)

	g.Conn.Close()

	_, err := g.BulkWalkAll("")
	if err == nil {
		t.Fatalf("BulkWalkAll() should fail in SNMPv1 but returned nil")
	}
}

// Standard exception/error tests

func TestMaxOids(t *testing.T) {
	setupConnection(t)
	defer Default.Conn.Close()

	Default.MaxOids = 1

	var err error
	oids := []string{".1.3.6.1.2.1.1.7.0",
		".1.3.6.1.2.1.2.2.1.10.1"} // 2 arbitrary Oids
	errString := "oid count (2) is greater than MaxOids (1)"

	_, err = Default.Get(oids)
	if err == nil {
		t.Fatalf("Expected too many oids failure. Got nil")
	} else if err.Error() != errString {
		t.Fatalf("Expected too many oids failure. Got => %v", err)
	}

	_, err = Default.GetNext(oids)
	if err == nil {
		t.Fatalf("Expected too many oids failure. Got nil")
	} else if err.Error() != errString {
		t.Fatalf("Expected too many oids failure. Got => %v", err)
	}

	_, err = Default.GetBulk(oids, 0, 0)
	if err == nil {
		t.Fatalf("Expected too many oids failure. Got nil")
	} else if err.Error() != errString {
		t.Fatalf("Expected too many oids failure. Got => %v", err)
	}
}

func TestGenericFailureUnknownHost(t *testing.T) {
	unknownHost := fmt.Sprintf("gosnmp-test-unknown-host-%d", time.Now().UTC().UnixNano())
	Default.Target = unknownHost
	err := Default.Connect()
	if err == nil {
		t.Fatalf("Expected connection failure due to unknown host")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "no such host") {
		t.Fatalf("Expected connection error of type 'no such host'! Got => %v", err)
	}
	_, err = Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err == nil {
		t.Fatalf("Expected get to fail due to missing connection")
	}
}

func TestGenericFailureConnectionTimeout(t *testing.T) {
	t.Skip("local testing - skipping this slow one") // TODO test tag, or something
	envTarget := os.Getenv("GOSNMP_TARGET")
	if len(envTarget) <= 0 {
		t.Skip("local testing - skipping this slow one")
	}

	Default.Target = "198.51.100.1" // Black hole
	err := Default.Connect()
	if err != nil {
		t.Fatalf("Did not expect connection error with IP address")
	}
	_, err = Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err == nil {
		t.Fatalf("Expected Get() to fail due to invalid IP")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("Expected timeout error. Got => %v", err)
	}
}

func TestGenericFailureConnectionRefused(t *testing.T) {
	Default.Target = "127.0.0.1"
	Default.Port = 1 // Don't expect SNMP to be running here!
	err := Default.Connect()
	if err != nil {
		t.Fatalf("Did not expect connection error with IP address")
	}
	_, err = Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err == nil {
		t.Fatalf("Expected Get() to fail due to invalid port")
	}
	if !(strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "forcibly closed")) {
		t.Fatalf("Expected connection refused error. Got => %v", err)
	}
}

func TestSnmpV3NoAuthNoPrivBasicGet(t *testing.T) {
	Default.Version = Version3
	Default.MsgFlags = NoAuthNoPriv
	Default.SecurityModel = UserSecurityModel
	Default.SecurityParameters = &UsmSecurityParameters{UserName: getUserName(t, NoAuth, NoPriv)}
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthMD5NoPrivGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	Default.Version = Version3
	Default.MsgFlags = AuthNoPriv
	Default.SecurityModel = UserSecurityModel
	Default.SecurityParameters = &UsmSecurityParameters{UserName: getUserName(t, MD5, NoPriv), AuthenticationProtocol: MD5, AuthenticationPassphrase: getAuthKey(t, MD5, NoPriv)}
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthMD5PrivAES256CGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	Default.Version = Version3
	Default.MsgFlags = AuthPriv
	Default.SecurityModel = UserSecurityModel
	Default.SecurityParameters = &UsmSecurityParameters{
		UserName:               getUserName(t, MD5, AES256C),
		AuthenticationProtocol: MD5, AuthenticationPassphrase: getAuthKey(t, MD5, AES256C),
		PrivacyProtocol: AES256C, PrivacyPassphrase: getPrivKey(t, MD5, AES256C),
	}
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthSHANoPrivGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	Default.Version = Version3
	Default.MsgFlags = AuthNoPriv
	Default.SecurityModel = UserSecurityModel
	Default.SecurityParameters = &UsmSecurityParameters{UserName: getUserName(t, SHA, NoPriv), AuthenticationProtocol: SHA, AuthenticationPassphrase: getAuthKey(t, SHA, NoPriv)}
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthSHAPrivAESGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	Default.Version = Version3
	Default.MsgFlags = AuthPriv
	Default.SecurityModel = UserSecurityModel
	Default.SecurityParameters = &UsmSecurityParameters{
		UserName:               getUserName(t, SHA, AES),
		AuthenticationProtocol: SHA, AuthenticationPassphrase: getAuthKey(t, SHA, AES),
		PrivacyProtocol: AES, PrivacyPassphrase: getPrivKey(t, SHA, AES),
	}
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthSHAPrivAES256CGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	Default.Version = Version3
	Default.MsgFlags = AuthPriv
	Default.SecurityModel = UserSecurityModel
	Default.SecurityParameters = &UsmSecurityParameters{
		UserName:               getUserName(t, SHA, AES256C),
		AuthenticationProtocol: SHA, AuthenticationPassphrase: getAuthKey(t, SHA, AES256C),
		PrivacyProtocol: AES256C, PrivacyPassphrase: getPrivKey(t, SHA, AES256C),
	}
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthSHA224NoPrivGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	Default.Version = Version3
	Default.MsgFlags = AuthNoPriv
	Default.SecurityModel = UserSecurityModel
	Default.SecurityParameters = &UsmSecurityParameters{UserName: getUserName(t, SHA224, NoPriv), AuthenticationProtocol: SHA224, AuthenticationPassphrase: getAuthKey(t, SHA224, NoPriv)}
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthSHA256NoPrivGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	Default.Version = Version3
	Default.MsgFlags = AuthNoPriv
	Default.SecurityModel = UserSecurityModel
	Default.SecurityParameters = &UsmSecurityParameters{UserName: getUserName(t, SHA256, NoPriv), AuthenticationProtocol: SHA256, AuthenticationPassphrase: getAuthKey(t, SHA256, NoPriv)}
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthSHA384NoPrivGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	Default.Version = Version3
	Default.MsgFlags = AuthNoPriv
	Default.SecurityModel = UserSecurityModel
	Default.SecurityParameters = &UsmSecurityParameters{UserName: getUserName(t, SHA384, NoPriv), AuthenticationProtocol: SHA384, AuthenticationPassphrase: getAuthKey(t, SHA384, NoPriv)}
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthSHA512NoPrivGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	Default.Version = Version3
	Default.MsgFlags = AuthNoPriv
	Default.SecurityModel = UserSecurityModel
	Default.SecurityParameters = &UsmSecurityParameters{UserName: getUserName(t, SHA512, NoPriv), AuthenticationProtocol: SHA512, AuthenticationPassphrase: getAuthKey(t, SHA512, NoPriv)}
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthSHA512PrivAES192Get(t *testing.T) {
	t.Skip("AES-192 Blumenthal is currently known to have issues.")
	Default.Version = Version3
	Default.MsgFlags = AuthPriv
	Default.SecurityModel = UserSecurityModel
	Default.SecurityParameters = &UsmSecurityParameters{
		UserName:               getUserName(t, SHA512, AES192),
		AuthenticationProtocol: SHA512, AuthenticationPassphrase: getAuthKey(t, SHA512, AES192),
		PrivacyProtocol: AES192, PrivacyPassphrase: getPrivKey(t, SHA512, AES192),
	}

	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthSHA512PrivAES192CGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	Default.Version = Version3
	Default.MsgFlags = AuthPriv
	Default.SecurityModel = UserSecurityModel
	Default.SecurityParameters = &UsmSecurityParameters{
		UserName:               getUserName(t, SHA512, AES192C),
		AuthenticationProtocol: SHA512, AuthenticationPassphrase: getAuthKey(t, SHA512, AES192C),
		PrivacyProtocol: AES192C, PrivacyPassphrase: getPrivKey(t, SHA512, AES192C),
	}

	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

// SHA 512 + AES256C (Reeder)
func TestSnmpV3AuthSHA512PrivAES256CGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	Default.Version = Version3
	Default.MsgFlags = AuthPriv
	Default.SecurityModel = UserSecurityModel
	Default.SecurityParameters = &UsmSecurityParameters{
		UserName:               getUserName(t, SHA512, AES256C),
		AuthenticationProtocol: SHA512, AuthenticationPassphrase: getAuthKey(t, SHA512, AES256C),
		PrivacyProtocol: AES256C, PrivacyPassphrase: getPrivKey(t, SHA512, AES256C),
	}
	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthMD5PrivDESGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	Default.Version = Version3
	Default.MsgFlags = AuthPriv
	Default.SecurityModel = UserSecurityModel

	Default.SecurityParameters = &UsmSecurityParameters{UserName: getUserName(t, MD5, DES),
		AuthenticationProtocol:   MD5,
		AuthenticationPassphrase: getAuthKey(t, MD5, DES),
		PrivacyProtocol:          DES,
		PrivacyPassphrase:        getPrivKey(t, MD5, DES)}

	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthSHAPrivDESGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	Default.Version = Version3
	Default.MsgFlags = AuthPriv
	Default.SecurityModel = UserSecurityModel
	Default.SecurityParameters = &UsmSecurityParameters{UserName: getUserName(t, SHA, DES),
		AuthenticationProtocol:   SHA,
		AuthenticationPassphrase: getAuthKey(t, SHA, DES),
		PrivacyProtocol:          DES,
		PrivacyPassphrase:        getPrivKey(t, SHA, DES)}

	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3AuthMD5PrivAESGet(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	Default.Version = Version3
	Default.MsgFlags = AuthPriv
	Default.SecurityModel = UserSecurityModel

	Default.SecurityParameters = &UsmSecurityParameters{UserName: getUserName(t, MD5, AES),
		AuthenticationProtocol:   MD5,
		AuthenticationPassphrase: getAuthKey(t, MD5, AES),
		PrivacyProtocol:          AES,
		PrivacyPassphrase:        getPrivKey(t, MD5, AES)}

	setupConnection(t)
	defer Default.Conn.Close()

	result, err := Default.Get([]string{".1.3.6.1.2.1.1.1.0"}) // SNMP MIB-2 sysDescr
	if err != nil {
		t.Fatalf("Get() failed with error => %v", err)
	}
	if len(result.Variables) != 1 {
		t.Fatalf("Expected result of size 1")
	}
	if result.Variables[0].Type != OctetString {
		t.Fatalf("Expected sysDescr to be OctetString")
	}
	sysDescr := result.Variables[0].Value.([]byte)
	if len(sysDescr) == 0 {
		t.Fatalf("Got a zero length sysDescr")
	}
}

func TestSnmpV3PrivEmptyPrivatePassword(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	Default.Version = Version3
	Default.MsgFlags = AuthPriv
	Default.SecurityModel = UserSecurityModel
	Default.SecurityParameters = &UsmSecurityParameters{UserName: getUserName(t, SHA, AES),
		AuthenticationProtocol:   SHA,
		AuthenticationPassphrase: getAuthKey(t, SHA, AES),
		PrivacyProtocol:          AES,
		PrivacyPassphrase:        ""}

	err := Default.Connect()
	if err == nil {
		t.Fatalf("Expected validation error for empty PrivacyPassphrase")
	}
}

func TestSnmpV3AuthNoPrivEmptyPrivatePassword(t *testing.T) {
	if !isUsingSnmpLabs() {
		t.Skip("This test is currently only working when using demo.snmplabs.com as test device.")
	}
	Default.Version = Version3
	Default.MsgFlags = AuthNoPriv
	Default.SecurityModel = UserSecurityModel
	Default.SecurityParameters = &UsmSecurityParameters{UserName: getUserName(t, SHA, NoPriv),
		AuthenticationProtocol:   SHA,
		AuthenticationPassphrase: getAuthKey(t, SHA, NoPriv),
		PrivacyProtocol:          AES,
		PrivacyPassphrase:        getPrivKey(t, SHA, NoPriv)}

	err := Default.Connect()
	if err == nil {
		t.Fatalf("Expected validation error for empty PrivacyPassphrase")
	}
}
