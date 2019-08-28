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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
)

func passphraseToAesKey(password string) []byte {
	key := sha256.Sum256([]byte(password))
	return key[:]
}

func encryptStringAesGcm(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher(passphraseToAesKey(passphrase))
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func decryptStringAesGcm(data []byte, passphrase string) ([]byte, error) {
	block, _ := aes.NewCipher(passphraseToAesKey(passphrase))
	gcm, _ := cipher.NewGCM(block)
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New(fmt.Sprintf("AesGcm cipher size of %0d too short (Should be at least %0d)\n", len(data), nonceSize))
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func main() {
	if len(os.Args) != 4 {
		fmt.Printf("Usage: %s [encryptAesGcm|encryptAesGcm] <passphrase> <data string>\n", os.Args[0])
		os.Exit(1)
	} else {
		if os.Args[1] == "encryptAesGcm" {
			ciphertext := encryptStringAesGcm([]byte(os.Args[3]), os.Args[2])
			fmt.Println(base64.StdEncoding.EncodeToString(ciphertext))
		} else if os.Args[1] == "decryptAesGcm" {
			ciphertext, err := base64.StdEncoding.DecodeString(os.Args[3])
			if err != nil {
				log.Fatalf("base64 decode error: %s", err)
			}
			plaintext, err := decryptStringAesGcm(ciphertext, os.Args[2])
			if err != nil {
				log.Fatalf("decryptStringAesGcm error: %s", err)
			}
			fmt.Println(string(plaintext))
		} else {
			log.Fatalf("Usage: %s [encryptAesGcm|decryptAesGcm] <passphrase> <data string>\n", os.Args[0])
		}
	}
}
