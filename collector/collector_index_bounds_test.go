package collector

import "testing"

// Regression test for the unbounded-allocation hardening: a variable-length
// OctetString/DisplayString index whose declared length is read from the
// (untrusted, device-supplied) SNMP response OID must not drive an unbounded
// make([]int, length)/make([]byte, length). A crafted huge length is clamped
// to maxIndexOctetStringLength instead of OOM-ing or panicking in makeslice.
func TestIndexOidsAsStringBoundsVariableLength(t *testing.T) {
	// A huge declared length with only one sub-identifier present must be clamped.
	for _, typ := range []string{"OctetString", "DisplayString"} {
		s, _, _ := indexOidsAsString([]int{1 << 31}, typ, 0, false, nil)
		// DisplayString -> len(parts); OctetString -> "0x"+hex (2x). Allow margin.
		if len(s) > maxIndexOctetStringLength*2+16 {
			t.Fatalf("%s index length not bounded: got %d", typ, len(s))
		}
	}
	// An absurd declared length must no longer reach make([]..., N) and panic.
	_, _, _ = indexOidsAsString([]int{1 << 62}, "DisplayString", 0, false, nil)
}
