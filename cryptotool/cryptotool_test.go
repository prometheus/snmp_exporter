// Copyright 2018 The Prometheus Authors
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
	"testing"
)

func TestAesGcm(t *testing.T) {
	data := []struct {
		input      string
		passphrase string
	}{
		{"input", "passphrase"},
		{"input", ""},
		{"", "passphrase"},
		{"Long input with more than 16 characters", "passphrase"},
		{"input", "Long password with more then 16 characters"},
	}
	for _, d := range data {
		enc := encryptStringAesGcm([]byte(d.input), d.passphrase)
		dec, _ := decryptStringAesGcm(enc, d.passphrase)
		if string(dec) != d.input {
			t.Errorf("Decrypt passphrase %v\n  Input: %v\n  Expect: %v\n  Actual: %v", d.passphrase, enc, d.input, enc)
		}
	}
}

func TestAesGcmEmptyError(t *testing.T) {
	_, err := decryptStringAesGcm([]byte(""), "password")
	if err == nil {
		t.Errorf("decryptStringAesGcm did not return an error for an empty ciphertext")
	}
}

func TestAesGcmInvalidError(t *testing.T) {
	_, err := decryptStringAesGcm([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "password")
	if err == nil {
		t.Errorf("decryptStringAesGcm did not return an error for a bad ciphertext")
	}
}
