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
	RegexpExtracts map[string][]config.RegexpExtract `yaml:"regex_extracts,omitempty"`
	Type           string                            `yaml:"type,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *MetricOverrides) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain MetricOverrides
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	// Ensure type for override is valid.
	switch c.Type {
	case "gauge", "counter", "OctetString", "DisplayString",
		"PhysAddress48", "Float", "Double", "IpAddr", "":
	default:
		return fmt.Errorf("Invalid metric type override '%s'", c.Type)
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
	OldIndex string `yaml:"old_index"`
	NewIndex string `yaml:"new_index"`
}
