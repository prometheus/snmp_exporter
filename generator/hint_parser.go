// Copyright 2025 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"strconv"

	"github.com/prometheus/snmp_exporter/config"
)

// parseDisplayHint parses an RFC 2579 DISPLAY-HINT string for OCTET STRING
// into a slice of FormatOp. Returns an error for invalid or unsupported hints.
//
// RFC 2579 Section 3.1 defines the octet-format specification with five parts:
//  1. Optional '*' repeat indicator - first byte of value is repeat count
//  2. Octet length - decimal digits specifying bytes to consume
//  3. Format - 'd' decimal, 'x' hex, 'o' octal, 'a' ASCII, 't' UTF-8
//  4. Optional separator - single character after each application
//  5. Optional terminator - single character after repeat group (requires '*' and separator)
//
// The collector implements RFC 2579's implicit repetition rule: the last spec
// repeats until data is exhausted. Trailing separator is suppressed.
//
// Examples:
//   - "1d.1d.1d.1d" (InetAddressIPv4) -> 4 specs: {1,d,.}, {1,d,.}, {1,d,.}, {1,d}
//   - "1x:" (PhysAddress) -> 1 spec: {1,x,:} - collector repeats for all bytes
//   - "2x:2x:2x:2x:2x:2x:2x:2x" (InetAddressIPv6) -> 8 specs: {2,x,:} ... {2,x}
//   - "*1x:/1x:" (hypothetical) -> {*,1,x,:,/} - first byte is count
func parseDisplayHint(hint string) ([]config.FormatOp, error) {
	if hint == "" {
		return nil, errors.New("empty hint")
	}

	var ops []config.FormatOp
	pos := 0

	for pos < len(hint) {
		op := config.FormatOp{}

		// (1) Optional '*' repeat indicator
		if pos < len(hint) && hint[pos] == '*' {
			op.StarPrefix = true
			pos++
		}

		// (2) Octet length - one or more decimal digits (required)
		if pos >= len(hint) || !isDigit(hint[pos]) {
			return nil, errors.New("expected octet length")
		}
		start := pos
		for pos < len(hint) && isDigit(hint[pos]) {
			pos++
		}
		take, err := strconv.Atoi(hint[start:pos])
		if err != nil {
			return nil, err
		}
		op.Take = take

		// (3) Format character - d/x/o/a/t (required)
		if pos >= len(hint) {
			return nil, errors.New("expected format character")
		}
		switch hint[pos] {
		case 'd', 'x', 'o', 'a', 't':
			op.Fmt = string(hint[pos])
			pos++
		default:
			return nil, errors.New("invalid format character: " + string(hint[pos]))
		}

		// (4) Optional separator - any character except digit and '*'
		if pos < len(hint) && !isDigit(hint[pos]) && hint[pos] != '*' {
			op.Sep = string(hint[pos])
			pos++

			// (5) Optional terminator - only valid if StarPrefix is set
			if op.StarPrefix && pos < len(hint) && !isDigit(hint[pos]) && hint[pos] != '*' {
				op.Term = string(hint[pos])
				pos++
			}
		}

		ops = append(ops, op)
	}

	if len(ops) == 0 {
		return nil, errors.New("no format specifications parsed")
	}

	return ops, nil
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}
