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
	"fmt"

	"github.com/prometheus/snmp_exporter/config"
)

// The generator config.
type Config struct {
	Modules map[string]*ModuleConfig `yaml:"modules"`
}

type MetricOverrides struct {
	Ignore         bool                              `yaml:"ignore,omitempty"`
	RegexpExtracts map[string][]config.RegexpExtract `yaml:"regex_extracts,omitempty"`
	Type           string                            `yaml:"type,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *MetricOverrides) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain MetricOverrides
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	// Ensure type for override is valid if one is defined.
	typ, ok := metricType(c.Type)
	if c.Type != "" && (!ok || typ != c.Type) {
		return fmt.Errorf("invalid metric type override '%s'", c.Type)
	}

	return nil
}

type ModuleConfig struct {
	Walk       []string                   `yaml:"walk"`
	Lookups    []*Lookup                  `yaml:"lookups"`
	WalkParams config.WalkParams          `yaml:",inline"`
	Overrides  map[string]MetricOverrides `yaml:"overrides"`
}

type Lookup struct {
	SourceIndexes     []string `yaml:"source_indexes"`
	Lookup            string   `yaml:"lookup"`
	DropSourceIndexes bool     `yaml:"drop_source_indexes,omitempty"`
}
