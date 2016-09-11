package main

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

func LoadFile(filename string) (*Config, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	err = yaml.Unmarshal(content, cfg)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

type Config map[string]*Module

type Module struct {
	// A list of OIDs.
	Walk    []string  `yaml:"walk"`
	Metrics []*Metric `yaml:"metrics"`
	// TODO: Security

	// TODO: Use these.
	XXX map[string]interface{} `yaml:",inline"`
}

type Metric struct {
	Name    string    `yaml:"name"`
	Oid     string    `yaml:"oid"`
	Indexes []*Index  `yaml:"indexes,omitempty"`
	Lookups []*Lookup `yaml:"lookups,omitempty"`

	XXX map[string]interface{} `yaml:",inline"`
}

type Index struct {
	Labelname string `yaml:"labelname"`
	Type      string `yaml:"type"`

	XXX map[string]interface{} `yaml:",inline"`
}

type Lookup struct {
	Labels    []string `yaml:"labels"`
	Labelname string   `yaml:"labelname"`
	Oid       string   `yaml:"oid"`

	XXX map[string]interface{} `yaml:",inline"`
}
