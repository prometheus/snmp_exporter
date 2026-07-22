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

// Package inventory loads and validates the devices polled by the collector.
package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"go.yaml.in/yaml/v2"

	snmpconfig "github.com/prometheus/snmp_exporter/config"
)

const (
	APIVersion = "snmpcollector.io/v1alpha1"
	Kind       = "DeviceList"
)

var labelNameRE = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

type inventoryFile struct {
	APIVersion string       `yaml:"apiVersion,omitempty"`
	Kind       string       `yaml:"kind,omitempty"`
	Devices    []fileDevice `yaml:"devices"`
}

type fileDevice struct {
	ID       string            `yaml:"id"`
	Address  string            `yaml:"address"`
	Profile  string            `yaml:"profile"`
	Auth     string            `yaml:"auth"`
	Interval time.Duration     `yaml:"interval,omitempty"`
	Timeout  time.Duration     `yaml:"timeout,omitempty"`
	Enabled  *bool             `yaml:"enabled,omitempty"`
	Labels   map[string]string `yaml:"labels,omitempty"`
}

// DeviceSnapshot is the immutable configuration used for one scheduled poll.
type DeviceSnapshot struct {
	ID       string
	Address  string
	Profile  string
	Auth     string
	Interval time.Duration
	Timeout  time.Duration
	Enabled  bool
	Labels   map[string]string
}

func (d DeviceSnapshot) clone() DeviceSnapshot {
	d.Labels = cloneLabels(d.Labels)
	return d
}

// Snapshot is a validated inventory revision. Its maps are private so callers
// cannot mutate the last-known-good state in place.
type Snapshot struct {
	revision string
	devices  map[string]DeviceSnapshot
}

// Revision returns the SHA-256 revision of all loaded inventory files.
func (s *Snapshot) Revision() string {
	if s == nil {
		return ""
	}
	return s.revision
}

// Len returns the number of devices, including disabled devices.
func (s *Snapshot) Len() int {
	if s == nil {
		return 0
	}
	return len(s.devices)
}

// Device returns an independent copy of one device snapshot.
func (s *Snapshot) Device(id string) (DeviceSnapshot, bool) {
	if s == nil {
		return DeviceSnapshot{}, false
	}
	device, ok := s.devices[id]
	return device.clone(), ok
}

// Devices returns independent copies keyed by device ID.
func (s *Snapshot) Devices() map[string]DeviceSnapshot {
	if s == nil {
		return nil
	}
	devices := make(map[string]DeviceSnapshot, len(s.devices))
	for id, device := range s.devices {
		devices[id] = device.clone()
	}
	return devices
}

// Loader applies collector-wide defaults and validates references against the
// existing snmp.yml configuration.
type Loader struct {
	DefaultInterval time.Duration
	DefaultTimeout  time.Duration
}

// NewLoader constructs an inventory loader. Defaults must be positive and are
// applied only when a device omits the corresponding value.
func NewLoader(defaultInterval, defaultTimeout time.Duration) *Loader {
	return &Loader{DefaultInterval: defaultInterval, DefaultTimeout: defaultTimeout}
}

// Load reads one or more paths or glob patterns and builds a snapshot without
// modifying any currently active Store.
func (l *Loader) Load(paths []string, profiles *snmpconfig.Config) (*Snapshot, error) {
	if l == nil {
		return nil, fmt.Errorf("inventory loader is required")
	}
	if l.DefaultInterval <= 0 {
		return nil, fmt.Errorf("default interval must be positive")
	}
	if l.DefaultTimeout <= 0 {
		return nil, fmt.Errorf("default timeout must be positive")
	}
	if profiles == nil {
		return nil, fmt.Errorf("SNMP configuration is required")
	}

	files, err := expandPaths(paths)
	if err != nil {
		return nil, err
	}

	hash := sha256.New()
	devices := make(map[string]DeviceSnapshot)
	for _, path := range files {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read inventory file %q: %w", path, err)
		}
		hash.Write([]byte(path))
		hash.Write([]byte{0})
		hash.Write(content)
		hash.Write([]byte{0})

		var parsed inventoryFile
		if err := yaml.UnmarshalStrict(content, &parsed); err != nil {
			return nil, fmt.Errorf("parse inventory file %q: %w", path, err)
		}
		if err := validateHeader(parsed, path); err != nil {
			return nil, err
		}
		for index, raw := range parsed.Devices {
			device, err := l.buildDevice(raw, profiles)
			if err != nil {
				return nil, fmt.Errorf("inventory file %q device %d: %w", path, index, err)
			}
			if _, exists := devices[device.ID]; exists {
				return nil, fmt.Errorf("duplicate device ID %q", device.ID)
			}
			devices[device.ID] = device
		}
	}

	return &Snapshot{
		revision: hex.EncodeToString(hash.Sum(nil)),
		devices:  devices,
	}, nil
}

func (l *Loader) buildDevice(raw fileDevice, profiles *snmpconfig.Config) (DeviceSnapshot, error) {
	if raw.ID == "" {
		return DeviceSnapshot{}, fmt.Errorf("device ID is required")
	}
	if err := validateAddress(raw.Address); err != nil {
		return DeviceSnapshot{}, err
	}
	if raw.Profile == "" {
		return DeviceSnapshot{}, fmt.Errorf("profile is required for device %q", raw.ID)
	}
	if _, exists := profiles.Modules[raw.Profile]; !exists {
		return DeviceSnapshot{}, fmt.Errorf("profile %q does not exist for device %q", raw.Profile, raw.ID)
	}
	if raw.Auth == "" {
		return DeviceSnapshot{}, fmt.Errorf("auth is required for device %q", raw.ID)
	}
	if _, exists := profiles.Auths[raw.Auth]; !exists {
		return DeviceSnapshot{}, fmt.Errorf("auth %q does not exist for device %q", raw.Auth, raw.ID)
	}

	interval := raw.Interval
	if interval == 0 {
		interval = l.DefaultInterval
	}
	timeout := raw.Timeout
	if timeout == 0 {
		timeout = l.DefaultTimeout
	}
	if interval <= 0 {
		return DeviceSnapshot{}, fmt.Errorf("interval must be positive for device %q", raw.ID)
	}
	if timeout <= 0 {
		return DeviceSnapshot{}, fmt.Errorf("timeout must be positive for device %q", raw.ID)
	}
	if interval < timeout {
		return DeviceSnapshot{}, fmt.Errorf("interval %s must be greater than or equal to timeout %s for device %q", interval, timeout, raw.ID)
	}
	if err := validateLabels(raw.Labels); err != nil {
		return DeviceSnapshot{}, fmt.Errorf("device %q: %w", raw.ID, err)
	}

	enabled := true
	if raw.Enabled != nil {
		enabled = *raw.Enabled
	}
	return DeviceSnapshot{
		ID:       raw.ID,
		Address:  raw.Address,
		Profile:  raw.Profile,
		Auth:     raw.Auth,
		Interval: interval,
		Timeout:  timeout,
		Enabled:  enabled,
		Labels:   cloneLabels(raw.Labels),
	}, nil
}

func validateHeader(parsed inventoryFile, path string) error {
	if parsed.APIVersion != "" && parsed.APIVersion != APIVersion {
		return fmt.Errorf("inventory file %q has unsupported apiVersion %q", path, parsed.APIVersion)
	}
	if parsed.Kind != "" && parsed.Kind != Kind {
		return fmt.Errorf("inventory file %q has unsupported kind %q", path, parsed.Kind)
	}
	return nil
}

func validateAddress(address string) error {
	if address == "" {
		return fmt.Errorf("device address is required")
	}
	parsed, err := url.Parse(address)
	if err != nil {
		return fmt.Errorf("invalid device address")
	}
	if parsed.Scheme != "udp" && parsed.Scheme != "tcp" {
		return fmt.Errorf("device address must use udp or tcp")
	}
	if parsed.Hostname() == "" {
		return fmt.Errorf("device address is missing a host")
	}
	if parsed.User != nil {
		return fmt.Errorf("device address must not contain credentials")
	}
	if parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("device address must not contain a path, query, or fragment")
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return fmt.Errorf("device address has an invalid port")
		}
	}
	return nil
}

func validateLabels(labels map[string]string) error {
	for name, value := range labels {
		if name == "__name__" {
			return fmt.Errorf("label %q is reserved", name)
		}
		if !labelNameRE.MatchString(name) {
			return fmt.Errorf("invalid label name %q", name)
		}
		if !utf8.ValidString(value) {
			return fmt.Errorf("label %q has an invalid UTF-8 value", name)
		}
	}
	return nil
}

func expandPaths(patterns []string) ([]string, error) {
	if len(patterns) == 0 {
		return nil, fmt.Errorf("at least one inventory file is required")
	}
	unique := make(map[string]struct{})
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("expand inventory path %q: %w", pattern, err)
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("no inventory file matches %q", pattern)
		}
		for _, match := range matches {
			unique[match] = struct{}{}
		}
	}
	files := make([]string, 0, len(unique))
	for path := range unique {
		files = append(files, path)
	}
	sort.Strings(files)
	return files, nil
}

func cloneLabels(labels map[string]string) map[string]string {
	if labels == nil {
		return nil
	}
	cloned := make(map[string]string, len(labels))
	for name, value := range labels {
		cloned[name] = value
	}
	return cloned
}

// Store atomically publishes only fully loaded and validated snapshots.
type Store struct {
	current atomic.Pointer[Snapshot]
}

// Current returns the active immutable snapshot, or nil before the first
// successful reload.
func (s *Store) Current() *Snapshot {
	return s.current.Load()
}

// Reload builds a complete replacement and publishes it atomically. On error,
// the previous snapshot remains active.
func (s *Store) Reload(loader *Loader, paths []string, profiles *snmpconfig.Config) error {
	snapshot, err := loader.Load(paths, profiles)
	if err != nil {
		return err
	}
	s.current.Store(snapshot)
	return nil
}
