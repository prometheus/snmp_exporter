package main

import "github.com/prometheus/snmp_exporter/config"

// The generator config.
type Config struct {
	Modules map[string]*ModuleConfig `yaml:"modules"`
}

func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Config
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	return nil
}

type MetricOverrides struct {
	RegexpExtracts map[string][]config.RegexpExtract `yaml:"regex_extracts,omitempty"`
	Type           string                            `yaml:"type,omitempty"`
}

func (c *MetricOverrides) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain MetricOverrides
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	return nil
}

type ModuleConfig struct {
	Walk       []string                   `yaml:"walk"`
	Lookups    []*Lookup                  `yaml:"lookups"`
	WalkParams config.WalkParams          `yaml:",inline"`
	Overrides  map[string]MetricOverrides `yaml:"overrides"`
}

func (c *ModuleConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain ModuleConfig
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	return nil
}

type Lookup struct {
	OldIndex string `yaml:"old_index"`
	NewIndex string `yaml:"new_index"`
}

func (c *Lookup) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Lookup
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	return nil
}
