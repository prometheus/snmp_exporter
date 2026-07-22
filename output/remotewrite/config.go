// Copyright 2026 The Prometheus Authors
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

package remotewrite

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v2"

	"github.com/prometheus/snmp_exporter/output"
)

const (
	OutputAPIVersion = "snmpcollector.io/v1alpha1"
	OutputKind       = "OutputConfig"
	OutputType       = "remote_write"
)

var environmentNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type outputConfigFile struct {
	APIVersion string          `yaml:"apiVersion,omitempty"`
	Kind       string          `yaml:"kind,omitempty"`
	Output     fileOutputBlock `yaml:"output"`
}

type fileOutputBlock struct {
	Type        string                 `yaml:"type"`
	RemoteWrite *fileRemoteWriteConfig `yaml:"remoteWrite,omitempty"`
	ClickHouse  interface{}            `yaml:"clickhouse,omitempty"`
}

type fileRemoteWriteConfig struct {
	Config        `yaml:",inline"`
	CredentialRef string             `yaml:"credentialRef,omitempty"`
	HeaderEnv     map[string]string  `yaml:"headerEnv,omitempty"`
	Queue         output.QueueConfig `yaml:"queue"`
}

// RuntimeConfig is a validated, detached view of the active Remote Write
// output. HeaderEnv contains environment variable names, never secret values.
type RuntimeConfig struct {
	Revision      string
	Sender        Config
	Queue         output.QueueConfig
	CredentialRef string
	HeaderEnv     map[string]string
}

// LoadConfigFile strictly parses one outputs.yml file and applies operational
// defaults. Blocks for inactive output types are deliberately not interpreted.
func LoadConfigFile(path string) (*RuntimeConfig, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read output config %q: %w", path, err)
	}

	var parsed outputConfigFile
	if err := yaml.UnmarshalStrict(content, &parsed); err != nil {
		return nil, fmt.Errorf("parse output config %q: %w", path, err)
	}
	if parsed.APIVersion != "" && parsed.APIVersion != OutputAPIVersion {
		return nil, fmt.Errorf("output config %q has unsupported apiVersion %q", path, parsed.APIVersion)
	}
	if parsed.Kind != "" && parsed.Kind != OutputKind {
		return nil, fmt.Errorf("output config %q has unsupported kind %q", path, parsed.Kind)
	}
	if parsed.Output.Type != OutputType {
		return nil, fmt.Errorf("output config %q has unsupported active output type %q", path, parsed.Output.Type)
	}
	if parsed.Output.RemoteWrite == nil {
		return nil, fmt.Errorf("output config %q is missing the active remoteWrite block", path)
	}

	raw := parsed.Output.RemoteWrite
	applyDefaults(raw)
	if _, err := New(raw.Config, nil, nil); err != nil {
		return nil, fmt.Errorf("validate output config %q: %w", path, err)
	}
	if err := output.ValidateQueueConfig(raw.Queue); err != nil {
		return nil, fmt.Errorf("validate output config %q: %w", path, err)
	}
	if raw.CredentialRef != "" && len(raw.HeaderEnv) != 0 {
		return nil, fmt.Errorf("output config %q must use only one of credentialRef or headerEnv", path)
	}
	for headerName, environmentName := range raw.HeaderEnv {
		if !validHeaderName(headerName) {
			return nil, fmt.Errorf("output config %q contains invalid header name", path)
		}
		if !environmentNameRE.MatchString(environmentName) {
			return nil, fmt.Errorf("output config %q contains invalid environment variable name for header %q", path, headerName)
		}
	}

	sum := sha256.Sum256(content)
	return &RuntimeConfig{
		Revision:      hex.EncodeToString(sum[:]),
		Sender:        raw.Config,
		Queue:         raw.Queue,
		CredentialRef: raw.CredentialRef,
		HeaderEnv:     cloneStringMap(raw.HeaderEnv),
	}, nil
}

func applyDefaults(config *fileRemoteWriteConfig) {
	if config.MaxInFlight == 0 {
		config.MaxInFlight = 4
	}
	if config.Queue.Capacity == 0 {
		config.Queue.Capacity = 10000
	}
	if config.Queue.MaxBatchSamples == 0 {
		config.Queue.MaxBatchSamples = 2000
	}
	if config.Queue.FlushInterval == 0 {
		config.Queue.FlushInterval = 2 * time.Second
	}
	if config.Queue.OverflowPolicy == "" {
		config.Queue.OverflowPolicy = output.DropOldest
	}
	if config.Queue.RetryMinBackoff == 0 {
		config.Queue.RetryMinBackoff = time.Second
	}
	if config.Queue.RetryMaxBackoff == 0 {
		config.Queue.RetryMaxBackoff = 30 * time.Second
	}
	if config.Queue.RequestTimeout == 0 {
		config.Queue.RequestTimeout = 30 * time.Second
	}
}

// EnvHeaderProvider resolves header values for every request, allowing secret
// rotation by updating the process environment without rebuilding the sender.
type EnvHeaderProvider struct {
	headerEnv map[string]string
	lookupEnv func(string) (string, bool)
}

func NewEnvHeaderProvider(headerEnv map[string]string) (*EnvHeaderProvider, error) {
	return newEnvHeaderProvider(headerEnv, os.LookupEnv)
}

func newEnvHeaderProvider(headerEnv map[string]string, lookupEnv func(string) (string, bool)) (*EnvHeaderProvider, error) {
	if lookupEnv == nil {
		return nil, fmt.Errorf("environment lookup is required")
	}
	for headerName, environmentName := range headerEnv {
		if !validHeaderName(headerName) {
			return nil, fmt.Errorf("invalid remote write header name")
		}
		if !environmentNameRE.MatchString(environmentName) {
			return nil, fmt.Errorf("invalid environment variable name for remote write header %q", headerName)
		}
	}
	return &EnvHeaderProvider{
		headerEnv: cloneStringMap(headerEnv),
		lookupEnv: lookupEnv,
	}, nil
}

func (p *EnvHeaderProvider) Headers(context.Context) (http.Header, error) {
	headers := make(http.Header, len(p.headerEnv))
	for headerName, environmentName := range p.headerEnv {
		value, exists := p.lookupEnv(environmentName)
		if !exists {
			return nil, fmt.Errorf("environment variable %q for remote write header %q is not set", environmentName, headerName)
		}
		if strings.ContainsAny(value, "\r\n") {
			return nil, fmt.Errorf("environment value for remote write header %q is invalid", headerName)
		}
		headers.Set(headerName, value)
	}
	return headers, nil
}

func validHeaderName(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		current := value[index]
		if current >= 'a' && current <= 'z' ||
			current >= 'A' && current <= 'Z' ||
			current >= '0' && current <= '9' ||
			strings.ContainsRune("!#$%&'*+-.^_\x60|~", rune(current)) {
			continue
		}
		return false
	}
	return true
}

func cloneStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	cloned := make(map[string]string, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}
