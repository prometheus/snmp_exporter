package main

import (
  "testing"
  "reflect"

  "github.com/soniah/gosnmp"
)

func TestOidToList(t *testing.T) {
  cases := []struct {
    oid string
    result []int
  }{
    {
      oid: "1",
      result: []int{1},
    },
    {
      oid: "1.2.3.4",
      result: []int{1,2,3,4},
    },
  }
  for _, c := range cases {
    got := oidToList(c.oid)
    if !reflect.DeepEqual(got, c.result) {
      t.Errorf("oidToList(%v): got %v, want %v", c.oid, got, c.result)
    }
  }
}

func TestSplitOid(t *testing.T) {
  cases := []struct {
    oid []int
    count int
    resultHead []int
    resultTail []int
  }{
    {
      oid: []int{1,2,3,4},
      count: 2,
      resultHead: []int{1,2},
      resultTail: []int{3,4},
    },
    {
      oid: []int{1,2},
      count: 4,
      resultHead: []int{1,2,0,0},
      resultTail: []int{},
    },
    {
      oid: []int{},
      count: 2,
      resultHead: []int{0,0},
      resultTail: []int{},
    },
  }
  for _, c := range cases {
    head, tail := splitOid(c.oid, c.count)
    if !reflect.DeepEqual(head, c.resultHead) || !reflect.DeepEqual(tail, c.resultTail){
      t.Errorf("splitOid(%s, %d): got [%v, %v], want [%v, %v]", c.oid, c.count, head, tail, c.resultHead, c.resultTail)
    }
  }
}

func TestPduValueAsString(t *testing.T) {
  cases := []struct {
    pdu *gosnmp.SnmpPDU
    result string
  }{
    {
      pdu: &gosnmp.SnmpPDU{Value: int(-1)},
      result: "-1",
    },
    {
      pdu: &gosnmp.SnmpPDU{Value: uint(1)},
      result: "1",
    },
    {
      pdu: &gosnmp.SnmpPDU{Value: int64(-1000000000000)},
      result: "-1000000000000",
    },
    {
      pdu: &gosnmp.SnmpPDU{Value: ".1.2.3.4", Type: gosnmp.ObjectIdentifier},
      result: "1.2.3.4",
    },
    {
      pdu: &gosnmp.SnmpPDU{Value: "1.2.3.4", Type: gosnmp.IPAddress},
      result: "1.2.3.4",
    },
    {
      pdu: &gosnmp.SnmpPDU{Value: []byte{65, 66}},
      result: "AB",
    },
    {
      pdu: &gosnmp.SnmpPDU{Value: []byte{127, 128, 255}},
      result: "\x7f\x80\xff",
    },
    {
      pdu: &gosnmp.SnmpPDU{Value: nil},
      result: "",
    },
  }
  for _, c := range cases {
    got := pduValueAsString(c.pdu)
    if !reflect.DeepEqual(got, c.result) {
      t.Errorf("pduValueAsString(%v): got %q, want %q", c.pdu, got, c.result)
    }
  }
}
