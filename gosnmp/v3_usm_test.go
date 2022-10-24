package gosnmp

import (
	"encoding/hex"
	"io/ioutil"
	"log"
	"testing"

	"github.com/stretchr/testify/require"
)

/**
 * This tests use hex dumps from real network traffic produced using net-snmp's snmpget with demo.snmplabs.com as SNMP agent.
 */

func authorativeEngineID(t *testing.T) string {
	// engine ID of demo.snmplabs.com
	engineID, err := hex.DecodeString("80004fb805636c6f75644dab22cc")
	require.NoError(t, err, "EngineId decoding failed.")

	return string(engineID)
}

func correctKeySHA224(t *testing.T) []byte {
	correctKey, err := hex.DecodeString("f2a2ebaa9677ad286255596286ca4fb7ec22f52405cb0aac334c5f15")
	require.NoError(t, err, "Correct key initialization failed.")

	return correctKey
}

func packetSHA224NoAuthentication(t *testing.T) []byte {
	packet, err := hex.DecodeString("308184020103300e02025f84020205c0040105020103043f303d040e80004fb805636c6f75644dab22cc02012b0203203ea5040f7573722d7368613232342d6e6f6e650410000000000000000000000000000000000400302e040e80004fb805636c6f75644dab22cc0400a01a02023ced020100020100300e300c06082b060102010101000500")

	require.NoError(t, err, "Non-authenticated packet data SHA224 decoding failed.")
	return packet
}

func packetSHA224Authenticated(t *testing.T) []byte {
	packet, err := hex.DecodeString("308184020103300e02025f84020205c0040105020103043f303d040e80004fb805636c6f75644dab22cc02012b0203203ea5040f7573722d7368613232342d6e6f6e65041066cd2d9b04cd48b02a9df0c77dc3415d0400302e040e80004fb805636c6f75644dab22cc0400a01a02023ced020100020100300e300c06082b060102010101000500")

	require.NoError(t, err, "Authenticated packet data SHA224 decoding failed.")
	return packet
}

func packetSHA224AuthenticationParams(t *testing.T) string {
	params, err := hex.DecodeString("66cd2d9b04cd48b02a9df0c77dc3415d")

	require.NoError(t, err, "Authentication parameters SHA224 decoding failed.")
	return string(params)
}

func TestAuthenticationSHA224(t *testing.T) {
	var err error

	sp := UsmSecurityParameters{
		localAESSalt:             0,
		localDESSalt:             0,
		AuthoritativeEngineBoots: 43,
		AuthoritativeEngineID:    authorativeEngineID(t),
		AuthoritativeEngineTime:  2113189,
		UserName:                 "usr-sha224-none",
		AuthenticationParameters: "",
		PrivacyParameters:        nil,
		AuthenticationProtocol:   SHA224,
		PrivacyProtocol:          0,
		AuthenticationPassphrase: "authkey1",
		PrivacyPassphrase:        "",
		SecretKey:                nil,
		Logger:                   NewLogger(log.New(ioutil.Discard, "", 0)),
		PrivacyKey:               nil,
	}

	sp.SecretKey, err = genlocalkey(sp.AuthenticationProtocol,
		sp.AuthenticationPassphrase,
		sp.AuthoritativeEngineID)

	require.NoError(t, err, "Generation of key failed")
	require.Equal(t, correctKeySHA224(t), sp.SecretKey, "Wrong key generated")

	srcPacket := packetSHA224NoAuthentication(t)
	err = sp.authenticate(srcPacket)
	require.NoError(t, err, "Authentication of packet failed")

	require.Equal(t, packetSHA224Authenticated(t), srcPacket, "Wrong message authentication parameters.")
}

func TestIsAuthenticaSHA224(t *testing.T) {
	var err error

	sp := UsmSecurityParameters{
		localAESSalt:             0,
		localDESSalt:             0,
		AuthoritativeEngineBoots: 43,
		AuthoritativeEngineID:    authorativeEngineID(t),
		AuthoritativeEngineTime:  2113189,
		UserName:                 "usr-sha224-none",
		AuthenticationParameters: packetSHA224AuthenticationParams(t),
		PrivacyParameters:        nil,
		AuthenticationProtocol:   SHA224,
		PrivacyProtocol:          0,
		AuthenticationPassphrase: "authkey1",
		PrivacyPassphrase:        "",
		SecretKey:                nil,
		PrivacyKey:               nil,
		Logger:                   NewLogger(log.New(ioutil.Discard, "", 0)),
	}

	sp.SecretKey, err = genlocalkey(sp.AuthenticationProtocol,
		sp.AuthenticationPassphrase,
		sp.AuthoritativeEngineID)

	require.NoError(t, err, "Generation of key failed")
	require.Equal(t, correctKeySHA224(t), sp.SecretKey, "Wrong key generated")

	srcPacket := packetSHA224NoAuthentication(t)

	snmpPacket := SnmpPacket{
		SecurityParameters: &sp,
	}

	authentic, err := sp.isAuthentic(srcPacket, &snmpPacket)
	require.NoError(t, err, "Authentication check of key failed")
	require.True(t, authentic, "Packet was not considered to be authentic")
}

func correctKeySHA512(t *testing.T) []byte {
	correctKey, err := hex.DecodeString("c336e5e6396926813d623984610e8f0cd7f419da75c82ac50927c84fd92027f7cdd849ce983036dca67bfb1e8fde2a8c2d45cd2f0d3e0b0b929f7dda462a58cf")
	require.NoError(t, err, "Correct key initialization failed.")

	return correctKey
}

func packetSHA512NoAuthentication(t *testing.T) []byte {
	packet, err := hex.DecodeString("3081a4020103300e0202366e020205c0040105020103045f305d040e80004fb805636c6f75644dab22cc02012b0203203eea040f7573722d7368613531322d6e6f6e6504300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400302e040e80004fb805636c6f75644dab22cc0400a01a020214d9020100020100300e300c06082b060102010101000500")

	require.NoError(t, err, "Not-authenticated packet data SHA512 decoding failed.")
	return packet
}

func packetSHA512Authenticated(t *testing.T) []byte {
	packet, err := hex.DecodeString("3081a4020103300e0202366e020205c0040105020103045f305d040e80004fb805636c6f75644dab22cc02012b0203203eea040f7573722d7368613531322d6e6f6e65043026f8087ced336a394642b8698eba9810929a9bfa44afbf43975a7ad6c4cc55bd279b549a77ec56d791467612747d6f570400302e040e80004fb805636c6f75644dab22cc0400a01a020214d9020100020100300e300c06082b060102010101000500")

	require.NoError(t, err, "Authenticated packet data SHA512 decoding failed.")
	return packet
}

func packetSHA512AuthenticationParams(t *testing.T) string {
	params, err := hex.DecodeString("26f8087ced336a394642b8698eba9810929a9bfa44afbf43975a7ad6c4cc55bd279b549a77ec56d791467612747d6f57")

	require.NoError(t, err, "Authentication parameters SHA512 decoding failed.")
	return string(params)
}

func TestAuthenticationSHA512(t *testing.T) {
	var err error

	sp := UsmSecurityParameters{
		localAESSalt:             0,
		localDESSalt:             0,
		AuthoritativeEngineBoots: 43,
		AuthoritativeEngineID:    authorativeEngineID(t),
		AuthoritativeEngineTime:  2113258,
		UserName:                 "usr-sha512-none",
		AuthenticationParameters: "",
		PrivacyParameters:        nil,
		AuthenticationProtocol:   SHA512,
		PrivacyProtocol:          0,
		AuthenticationPassphrase: "authkey1",
		PrivacyPassphrase:        "",
		SecretKey:                nil,
		PrivacyKey:               nil,
		Logger:                   NewLogger(log.New(ioutil.Discard, "", 0)),
	}

	sp.SecretKey, err = genlocalkey(sp.AuthenticationProtocol,
		sp.AuthenticationPassphrase,
		sp.AuthoritativeEngineID)

	require.NoError(t, err, "Generation of key failed")
	require.Equal(t, correctKeySHA512(t), sp.SecretKey, "Wrong key generated")

	srcPacket := packetSHA512NoAuthentication(t)
	err = sp.authenticate(srcPacket)
	require.NoError(t, err, "Generation of key failed")

	require.Equal(t, packetSHA512Authenticated(t), srcPacket, "Wrong message authentication parameters.")
}

func TestIsAuthenticaSHA512(t *testing.T) {
	var err error

	sp := UsmSecurityParameters{
		localAESSalt:             0,
		localDESSalt:             0,
		AuthoritativeEngineBoots: 43,
		AuthoritativeEngineID:    authorativeEngineID(t),
		AuthoritativeEngineTime:  2113189,
		UserName:                 "usr-sha512-none",
		AuthenticationParameters: packetSHA512AuthenticationParams(t),
		PrivacyParameters:        nil,
		AuthenticationProtocol:   SHA512,
		PrivacyProtocol:          0,
		AuthenticationPassphrase: "authkey1",
		PrivacyPassphrase:        "",
		SecretKey:                nil,
		Logger:                   NewLogger(log.New(ioutil.Discard, "", 0)),
		PrivacyKey:               nil,
	}

	sp.SecretKey, err = genlocalkey(sp.AuthenticationProtocol,
		sp.AuthenticationPassphrase,
		sp.AuthoritativeEngineID)

	require.NoError(t, err, "Generation of key failed")
	require.Equal(t, correctKeySHA512(t), sp.SecretKey, "Wrong key generated")

	srcPacket := packetSHA512NoAuthentication(t)

	snmpPacket := SnmpPacket{
		SecurityParameters: &sp,
	}

	authentic, err := sp.isAuthentic(srcPacket, &snmpPacket)
	require.NoError(t, err, "Authentication check of key failed")
	require.True(t, authentic, "Packet was not considered to be authentic")
}
