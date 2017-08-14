package main

import "github.com/prometheus/snmp_exporter/config"

// The generator config.
type Config struct {
	Modules map[string]*ModuleConfig `yaml:"modules"`

	XXX map[string]interface{} `yaml:",inline"`
}

func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Config
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	if err := config.CheckOverflow(c.XXX, "module"); err != nil {
		return err
	}
	return nil
}

type MetricOverrides struct {
	RegexpExtracts map[string][]config.RegexpExtract `yaml:"regex_extracts,omitempty"`

	XXX map[string]interface{} `yaml:",inline"`
}

func (c *MetricOverrides) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain MetricOverrides
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	if err := config.CheckOverflow(c.XXX, "overrides"); err != nil {
		return err
	}
	return nil
}

type ModuleConfig struct {
	Walk       []string                   `yaml:"walk"`
	Lookups    []*Lookup                  `yaml:"lookups"`
	WalkParams config.WalkParams          `yaml:",inline"`
	Overrides  map[string]MetricOverrides `yaml:"overrides"`

	XXX map[string]interface{} `yaml:",inline"`
}

func (c *ModuleConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain ModuleConfig
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	if err := config.CheckOverflow(c.XXX, "module"); err != nil {
		return err
	}
	return nil
}

type Lookup struct {
	OldIndex string `yaml:"old_index"`
	NewIndex string `yaml:"new_index"`

	XXX map[string]interface{} `yaml:",inline"`
}

func (c *Lookup) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Lookup
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	if err := config.CheckOverflow(c.XXX, "module"); err != nil {
		return err
	}
	return nil
}
