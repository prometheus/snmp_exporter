// Copyright 2012-2016 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"fmt"
	"log"
	"net"
	"time"
)

//
// Sending Traps ie GoSNMP acting as an Agent
//

// SendTrap sends a SNMP Trap (v2c/v3 only)
//
// pdus[0] can a pdu of Type TimeTicks (with the desired uint32 epoch
// time).  Otherwise a TimeTicks pdu will be prepended, with time set to
// now. This mirrors the behaviour of the Net-SNMP command-line tools.
//
// SendTrap doesn't wait for a return packet from the NMS (Network
// Management Station).
//
// See also Listen() and examples for creating an NMS.
func (x *GoSNMP) SendTrap(pdus []SnmpPDU) (result *SnmpPacket, err error) {
	switch x.Version {
	case Version2c, Version3:
		// do nothing
	default:
		err = fmt.Errorf("SendTrap doesn't support %s", x.Version)
		return nil, err
	}

	if len(pdus) == 0 {
		return nil, fmt.Errorf("Sendtrap requires at least 1 pdu")
	}

	if pdus[0].Type == TimeTicks {
		// check is uint32
		if _, ok := pdus[0].Value.(uint32); !ok {
			return nil, fmt.Errorf("Sendtrap TimeTick must be uint32")
		}
	}

	// add a timetick to start, set to now
	now := uint32(time.Now().Unix())
	timetickPDU := SnmpPDU{"", TimeTicks, now, x.Logger}
	// prepend timetickPDU
	copy(pdus[1:], pdus)
	pdus[0] = timetickPDU

	packetOut := x.mkSnmpPacket(SNMPv2Trap, pdus, 0, 0)

	// all sends wait for the return packet, except for SNMPv2Trap
	// -> wait is false
	return x.send(packetOut, false)
}

//
// Receiving Traps ie GoSNMP acting as an NMS (Network Management
// Station).
//
// GoSNMP.unmarshal() currently only handles SNMPv2Trap (ie v2c, v3)
//

// A TrapListener defineds parameters for running a SNMP Trap receiver.
// nil values will be replaced by default values.
type TrapListener struct {
	OnNewTrap func(s *SnmpPacket, u *net.UDPAddr)
	Params    *GoSNMP
}

// Listen listens on the UDP address addr and calls the OnNewTrap
// function specified in *TrapListener for every trap recieved.
func (t *TrapListener) Listen(addr string) (err error) {
	if t.Params == nil {
		t.Params = Default
	}

	if t.OnNewTrap == nil {
		t.OnNewTrap = debugTrapHandler
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	for {
		var buf [4096]byte
		rlen, remote, err := conn.ReadFromUDP(buf[:])
		if err != nil {
			t.Params.logPrintf("TrapListener: error in read %s\n", err)
		}

		msg := buf[:rlen]
		traps := t.Params.unmarshalTrap(msg)
		if traps != nil {
			t.OnNewTrap(traps, remote)
		}
	}
}

// Default trap handler
func debugTrapHandler(s *SnmpPacket, u *net.UDPAddr) {
	log.Printf("got trapdata from %+v: %+v\n", u, s)
}

// Unmarshal SNMP Trap
func (x *GoSNMP) unmarshalTrap(trap []byte) (result *SnmpPacket) {
	result = new(SnmpPacket)

	if x.SecurityParameters != nil {
		result.SecurityParameters = x.SecurityParameters.Copy()
	}

	cursor, err := x.unmarshalHeader(trap, result)
	if err != nil {
		x.logPrintf("unmarshalTrap: %s\n", err)
		return nil
	}

	if result.Version == Version3 {
		if result.SecurityModel == UserSecurityModel {
			err = x.testAuthentication(trap, result)
			if err != nil {
				x.logPrintf("unmarshalTrap v3 auth: %s\n", err)
				return nil
			}
		}
		trap, cursor, err = x.decryptPacket(trap, cursor, result)
	}
	err = x.unmarshalPayload(trap, cursor, result)
	if err != nil {
		x.logPrintf("unmarshalTrap: %s\n", err)
		return nil
	}
	return result
}
