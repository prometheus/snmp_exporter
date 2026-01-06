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

package collector

import (
	"strconv"
	"strings"
)

// hextable matches encoding/hex.hextable but uses uppercase for RFC 2579 'x' format.
const hextable = "0123456789ABCDEF"

// writeHex encodes src as uppercase hexadecimal, matching encoding/hex.Encode.
func writeHex(w *strings.Builder, src []byte) {
	for _, v := range src {
		w.WriteByte(hextable[v>>4])
		w.WriteByte(hextable[v&0x0f])
	}
}

// writeUint writes a uint64 in the given base to a strings.Builder.
// Uses strconv.AppendUint with a stack buffer to avoid allocation.
func writeUint(w *strings.Builder, val uint64, base int) {
	var buf [20]byte // uint64 max is 20 decimal digits
	w.Write(strconv.AppendUint(buf[:0], val, base))
}

// applyDisplayHint parses an RFC 2579 DISPLAY-HINT string and applies it to
// raw bytes in a single pass.
//
// Returns (result, true) on success, or ("", false) on any parse error.
// The caller should fall back to default formatting when ok is false.
//
// RFC 2579 Section 3.1 defines the octet-format specification:
//   - Optional '*' repeat indicator: first byte of value is repeat count
//   - Octet length: decimal digits specifying bytes to consume per application
//   - Format: 'd' decimal, 'x' hex, 'o' octal, 'a' ASCII, 't' UTF-8
//   - Optional separator: single character after each application
//   - Optional terminator: single character after repeat group (requires '*')
//
// The last format specification repeats until all data is exhausted (implicit
// repetition rule). Trailing separators are suppressed.
//
// Examples:
//   - "1d.1d.1d.1d" on [192,168,1,1] → "192.168.1.1"
//   - "1x:" on [0,26,43,60,77,94] → "00:1a:2b:3c:4d:5e"
//   - "255a" on [72,101,108,108,111] → "Hello"
func applyDisplayHint(hint string, data []byte) (string, bool) {
	if hint == "" || len(data) == 0 {
		return "", false
	}

	var result strings.Builder
	result.Grow(len(data) * 4) // Preallocate for typical output

	hintPos := 0
	dataPos := 0

	// Track the start of the last spec for implicit repetition
	lastSpecStart := 0
	// Track whether the last spec consumes data (for infinite loop prevention)
	lastSpecConsumesByte := false

	for dataPos < len(data) {
		specStart := hintPos

		// If we've exhausted the hint, restart from the last spec (implicit repetition)
		if hintPos >= len(hint) {
			// Guard against infinite loop: if last spec doesn't consume data, bail
			if !lastSpecConsumesByte {
				return "", false
			}
			hintPos = lastSpecStart
			specStart = lastSpecStart
		}

		// (1) Optional '*' repeat indicator
		starPrefix := false
		if hintPos < len(hint) && hint[hintPos] == '*' {
			starPrefix = true
			hintPos++
		}

		// (2) Octet length - one or more decimal digits (required)
		if hintPos >= len(hint) || !isDigit(hint[hintPos]) {
			// Parse error: expected digits
			return "", false
		}

		take := 0
		for hintPos < len(hint) && isDigit(hint[hintPos]) {
			take = take*10 + int(hint[hintPos]-'0')
			hintPos++
		}

		if take < 0 {
			// Overflow wrapped to negative
			return "", false
		}

		// (3) Format character (required)
		if hintPos >= len(hint) {
			// Parse error: expected format character
			return "", false
		}

		fmtChar := hint[hintPos]
		if fmtChar != 'd' && fmtChar != 'x' && fmtChar != 'o' && fmtChar != 'a' && fmtChar != 't' {
			// Invalid format character
			return "", false
		}
		hintPos++

		// (4) Optional separator
		var sep byte
		hasSep := false
		if hintPos < len(hint) && !isDigit(hint[hintPos]) && hint[hintPos] != '*' {
			sep = hint[hintPos]
			hasSep = true
			hintPos++
		}

		// (5) Optional terminator (only valid with starPrefix)
		var term byte
		hasTerm := false
		if starPrefix && hintPos < len(hint) && !isDigit(hint[hintPos]) && hint[hintPos] != '*' {
			term = hint[hintPos]
			hasTerm = true
			hintPos++
		}

		// Remember this spec for implicit repetition
		lastSpecStart = specStart
		// A spec consumes data if take > 0, or if starPrefix (consumes repeat count byte)
		lastSpecConsumesByte = (take > 0) || starPrefix

		// Apply the spec to data
		repeatCount := 1
		if starPrefix && dataPos < len(data) {
			repeatCount = int(data[dataPos])
			dataPos++
		}

		for r := 0; r < repeatCount && dataPos < len(data); r++ {
			end := dataPos + take
			if end > len(data) || end < dataPos { // catch overflow
				end = len(data)
			}
			chunk := data[dataPos:end]

			// Format the chunk using stack-allocated buffers
			switch fmtChar {
			case 'd':
				if len(chunk) > 8 {
					return "", false
				}
				// Big-endian unsigned integer
				var val uint64
				for _, b := range chunk {
					val = (val << 8) | uint64(b)
				}
				writeUint(&result, val, 10)
			case 'x':
				writeHex(&result, chunk)
			case 'o':
				if len(chunk) > 8 {
					return "", false
				}
				// Big-endian octal
				var val uint64
				for _, b := range chunk {
					val = (val << 8) | uint64(b)
				}
				writeUint(&result, val, 8)
			case 'a', 't':
				// ASCII/UTF-8 - write bytes directly
				result.Write(chunk)
			}
			dataPos = end

			// Emit separator (suppressed if at end of data or before terminator)
			moreData := dataPos < len(data)
			if hasSep && moreData && (!hasTerm || r != repeatCount-1) {
				result.WriteByte(sep)
			}
		}

		// Emit terminator after repeat group
		if hasTerm && dataPos < len(data) {
			result.WriteByte(term)
		}
	}

	return result.String(), true
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}
