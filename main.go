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
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"gopkg.in/alecthomas/kingpin.v2"
	yaml "gopkg.in/yaml.v2"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"

	"github.com/prometheus/snmp_exporter/config"
)

var (
	encryptionAesGcm     = kingpin.Flag("encryption.aesgcm", "AES-GCM passphrase for community encryption.").Default("").String()
	encryptionAesGcmFile = kingpin.Flag("encryption.aesgcm.file", "File containing AES-GCM passphrase for community encryption.").Default("").String()
	configFile           = kingpin.Flag("config.file", "Path to configuration file.").Default("snmp.yml").String()
	listenAddress        = kingpin.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":9116").String()
	dryRun               = kingpin.Flag("dry-run", "Only verify configuration is valid and exit.").Default("false").Bool()

	encryptionAesGcmKey [32]byte

	// Metrics about the SNMP exporter itself.
	snmpDuration = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "snmp_collection_duration_seconds",
			Help: "Duration of collections by the SNMP exporter",
		},
		[]string{"module"},
	)
	snmpRequestErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "snmp_request_errors_total",
			Help: "Errors in requests to the SNMP exporter",
		},
	)
	sc = &SafeConfig{
		C: &config.Config{},
	}
	reloadCh chan chan error
)

func init() {
	prometheus.MustRegister(snmpDuration)
	prometheus.MustRegister(snmpRequestErrors)
	prometheus.MustRegister(version.NewCollector("snmp_exporter"))
}

func handler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "'target' parameter must be specified", 400)
		snmpRequestErrors.Inc()
		return
	}
	moduleName := r.URL.Query().Get("module")
	if moduleName == "" {
		moduleName = "if_mib"
	}
	communityString := r.URL.Query().Get("community")
	if communityString != "" && len(encryptionAesGcmKey) == 32 {
		ciphertext, err := base64.StdEncoding.DecodeString(communityString)
		if err != nil {
			http.Error(w, "'community' parameter must be base64 encoded AES-GCM string", 400)
			snmpRequestErrors.Inc()
			return
		}
		plaintext, err := decryptStringAesGcm(ciphertext, encryptionAesGcmKey)
		if err != nil {
			http.Error(w, "'community' parameter must be valid AES-GCM ciphertext", 400)
			snmpRequestErrors.Inc()
			return
		}
		communityString = string(plaintext)
	} else {
		communityString = "" // We only support encrypted communityStrings !
	}
	sc.RLock()
	module, ok := (*(sc.C))[moduleName]
	sc.RUnlock()
	if !ok {
		http.Error(w, fmt.Sprintf("Unknown module '%s'", moduleName), 400)
		snmpRequestErrors.Inc()
		return
	}
	log.Debugf("Scraping target '%s' with module '%s'", target, moduleName)

	start := time.Now()
	registry := prometheus.NewRegistry()
	collector := collector{target: target, module: module, community: communityString}
	registry.MustRegister(collector)
	// Delegate http serving to Prometheus client library, which will call collector.Collect.
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
	duration := time.Since(start).Seconds()
	snmpDuration.WithLabelValues(moduleName).Observe(duration)
	log.Debugf("Scrape of target '%s' with module '%s' took %f seconds", target, moduleName, duration)
}

func updateConfiguration(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		rc := make(chan error)
		reloadCh <- rc
		if err := <-rc; err != nil {
			http.Error(w, fmt.Sprintf("failed to reload config: %s", err), http.StatusInternalServerError)
		}
	default:
		log.Errorf("POST method expected")
		http.Error(w, "POST method expected", 400)
	}
}

type SafeConfig struct {
	sync.RWMutex
	C *config.Config
}

func (sc *SafeConfig) ReloadConfig(configFile string) (err error) {
	conf, err := config.LoadFile(configFile)
	if err != nil {
		log.Errorf("Error parsing config file: %s", err)
		return err
	}
	sc.Lock()
	sc.C = conf
	sc.Unlock()
	log.Infoln("Loaded config file")
	return nil
}

func decryptStringAesGcm(data []byte, key [32]byte) ([]byte, error) {
	block, _ := aes.NewCipher(key[:])
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

func getFirstLineFromFile(filename string) (line string, err error) {
	if _, err := os.Stat(filename); err == nil {
		file, err := os.Open(filename)
		if err != nil {
			return "", err
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		if scanner.Scan() {
			return scanner.Text(), nil
		} else {
			if err := scanner.Err(); err != nil {
				return "", err
			}
		}
		return "", nil
	} else {
		return "", errors.New(fmt.Sprintf("File %s does not exist", filename))
	}
}

func main() {
	log.AddFlags(kingpin.CommandLine)
	kingpin.Version(version.Print("snmp_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	log.Infoln("Starting snmp exporter", version.Info())
	log.Infoln("Build context", version.BuildContext())

	// Bail early if the config is bad.
	var err error
	sc.C, err = config.LoadFile(*configFile)
	if err != nil {
		log.Fatalf("Error parsing config file: %s", err)
	}

	if *encryptionAesGcmFile != "" {
		firstLine, err := getFirstLineFromFile(*encryptionAesGcmFile)
		if err == nil {
			*encryptionAesGcm = firstLine
		} else {
			log.Infof("Failed to load encryption passphrase from %s: %s", *encryptionAesGcmFile, err)
		}
	}
	if *encryptionAesGcm != "" {
		// We cache the 32 byte AES key from the SHA256 hash of the passphrase
		encryptionAesGcmKey = sha256.Sum256([]byte(*encryptionAesGcm))
	}

	// Exit if in dry-run mode.
	if *dryRun {
		log.Infoln("Configuration parsed successfully.")
		return
	}

	// Initialize metrics.
	for module := range *sc.C {
		snmpDuration.WithLabelValues(module)
	}

	hup := make(chan os.Signal, 1)
	reloadCh = make(chan chan error)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-hup:
				if err := sc.ReloadConfig(*configFile); err != nil {
					log.Errorf("Error reloading config: %s", err)
				}
			case rc := <-reloadCh:
				if err := sc.ReloadConfig(*configFile); err != nil {
					log.Errorf("Error reloading config: %s", err)
					rc <- err
				} else {
					rc <- nil
				}
			}
		}
	}()

	http.Handle("/metrics", promhttp.Handler())       // Normal metrics endpoint for SNMP exporter itself.
	http.HandleFunc("/snmp", handler)                 // Endpoint to do SNMP scrapes.
	http.HandleFunc("/-/reload", updateConfiguration) // Endpoint to reload configuration.

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
            <head>
            <title>SNMP Exporter</title>
            <style>
            label{
            display:inline-block;
            width:75px;
            }
            form label {
            margin: 10px;
            }
            form input {
            margin: 10px;
            }
            </style>
            </head>
            <body>
            <h1>SNMP Exporter</h1>
            <form action="/snmp">
            <label>Target:</label> <input type="text" name="target" placeholder="X.X.X.X" value="1.2.3.4"><br>
            <label>Module:</label> <input type="text" name="module" placeholder="module" value="if_mib"><br>
            <label>Community</label> <input type="text" name="community" placeholder="community" value="public"><br>
            <input type="submit" value="Submit">
            </form>
            <p><a href="/config">Config</a></p>
            </body>
            </html>`))
	})

	http.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		sc.RLock()
		c, err := yaml.Marshal(sc.C)
		sc.RUnlock()
		if err != nil {
			log.Warnf("Error marshaling configuration: %v", err)
			http.Error(w, err.Error(), 500)
			return
		}
		w.Write(c)
	})

	log.Infof("Listening on %s", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
