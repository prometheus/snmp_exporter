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

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/gosnmp/gosnmp"
	"gopkg.in/yaml.v2"
)

func LoadFile(paths []string, expandEnvVars bool) (*Config, error) {
	cfg := &Config{}
	for _, p := range paths {
		files, err := filepath.Glob(p)
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			content, err := os.ReadFile(f)
			if err != nil {
				return nil, err
			}
			err = yaml.UnmarshalStrict(content, cfg)
			if err != nil {
				return nil, err
			}
		}
	}

	if expandEnvVars {
		var err error
		for i, auth := range cfg.Auths {
			if auth.Username != "" {
				cfg.Auths[i].Username, err = substituteEnvVariables(auth.Username)
				if err != nil {
					return nil, err
				}
			}
			if auth.Password != "" {
				password, err := substituteEnvVariables(string(auth.Password))
				if err != nil {
					return nil, err
				}
				cfg.Auths[i].Password.Set(password)
			}
			if auth.PrivPassword != "" {
				privPassword, err := substituteEnvVariables(string(auth.PrivPassword))
				if err != nil {
					return nil, err
				}
				cfg.Auths[i].PrivPassword.Set(privPassword)
			}
		}
	}

	return cfg, nil
}

var (
	defaultRetries = 3

	DefaultAuth = Auth{
		Community:     "public",
		SecurityLevel: "noAuthNoPriv",
		AuthProtocol:  "MD5",
		PrivProtocol:  "DES",
		Version:       2,
	}
	DefaultWalkParams = WalkParams{
		MaxRepetitions:          25,
		Retries:                 &defaultRetries,
		Timeout:                 time.Second * 5,
		UseUnconnectedUDPSocket: false,
		AllowNonIncreasingOIDs:  false,
	}
	DefaultModule = Module{
		WalkParams: DefaultWalkParams,
	}
	DefaultRegexpExtract = RegexpExtract{
		Value: "$1",
	}
)

// Config for the snmp_exporter.
type Config struct {
	Auths   map[string]*Auth   `yaml:"auths,omitempty"`
	Modules map[string]*Module `yaml:"modules,omitempty"`
	Version int                `yaml:"version,omitempty"`
}

type WalkParams struct {
	MaxRepetitions          uint32        `yaml:"max_repetitions,omitempty"`
	Retries                 *int          `yaml:"retries,omitempty"`
	Timeout                 time.Duration `yaml:"timeout,omitempty"`
	UseUnconnectedUDPSocket bool          `yaml:"use_unconnected_udp_socket,omitempty"`
	AllowNonIncreasingOIDs  bool          `yaml:"allow_nonincreasing_oids,omitempty"`
}

type Module struct {
	// A list of OIDs.
	Walk       []string        `yaml:"walk,omitempty"`
	Get        []string        `yaml:"get,omitempty"`
	Metrics    []*Metric       `yaml:"metrics"`
	WalkParams WalkParams      `yaml:",inline"`
	Filters    []DynamicFilter `yaml:"filters,omitempty"`
}

func (c *Module) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultModule
	type plain Module
	return unmarshal((*plain)(c))
}

// ConfigureSNMP sets the various version and auth settings.
func (c Auth) ConfigureSNMP(g *gosnmp.GoSNMP, snmpContext string) {
	switch c.Version {
	case 1:
		g.Version = gosnmp.Version1
	case 2:
		g.Version = gosnmp.Version2c
	case 3:
		g.Version = gosnmp.Version3
	}
	g.Community = string(c.Community)

	if snmpContext == "" {
		g.ContextName = c.ContextName
	} else {
		g.ContextName = snmpContext
	}

	// v3 security settings.
	g.SecurityModel = gosnmp.UserSecurityModel
	usm := &gosnmp.UsmSecurityParameters{
		UserName: c.Username,
	}
	auth, priv := false, false
	switch c.SecurityLevel {
	case "noAuthNoPriv":
		g.MsgFlags = gosnmp.NoAuthNoPriv
	case "authNoPriv":
		g.MsgFlags = gosnmp.AuthNoPriv
		auth = true
	case "authPriv":
		g.MsgFlags = gosnmp.AuthPriv
		auth = true
		priv = true
	}
	if auth {
		usm.AuthenticationPassphrase = string(c.Password)
		switch c.AuthProtocol {
		case "SHA":
			usm.AuthenticationProtocol = gosnmp.SHA
		case "SHA224":
			usm.AuthenticationProtocol = gosnmp.SHA224
		case "SHA256":
			usm.AuthenticationProtocol = gosnmp.SHA256
		case "SHA384":
			usm.AuthenticationProtocol = gosnmp.SHA384
		case "SHA512":
			usm.AuthenticationProtocol = gosnmp.SHA512
		case "MD5":
			usm.AuthenticationProtocol = gosnmp.MD5
		}
	}
	if priv {
		usm.PrivacyPassphrase = string(c.PrivPassword)
		switch c.PrivProtocol {
		case "DES":
			usm.PrivacyProtocol = gosnmp.DES
		case "AES":
			usm.PrivacyProtocol = gosnmp.AES
		case "AES192":
			usm.PrivacyProtocol = gosnmp.AES192
		case "AES192C":
			usm.PrivacyProtocol = gosnmp.AES192C
		case "AES256":
			usm.PrivacyProtocol = gosnmp.AES256
		case "AES256C":
			usm.PrivacyProtocol = gosnmp.AES256C
		}
	}
	g.SecurityParameters = usm
}

type Filters struct {
	Static  []StaticFilter  `yaml:"static,omitempty"`
	Dynamic []DynamicFilter `yaml:"dynamic,omitempty"`
}

type StaticFilter struct {
	Targets []string `yaml:"targets,omitempty"`
	Indices []string `yaml:"indices,omitempty"`
}
type DynamicFilter struct {
	Oid     string   `yaml:"oid"`
	Targets []string `yaml:"targets,omitempty"`
	Values  []string `yaml:"values,omitempty"`
}

type Metric struct {
	Name            string                     `yaml:"name"`
	Oid             string                     `yaml:"oid"`
	Type            string                     `yaml:"type"`
	Help            string                     `yaml:"help"`
	Indexes         []*Index                   `yaml:"indexes,omitempty"`
	Lookups         []*Lookup                  `yaml:"lookups,omitempty"`
	RegexpExtracts  map[string][]RegexpExtract `yaml:"regex_extracts,omitempty"`
	DateTimePattern string                     `yaml:"datetime_pattern,omitempty"`
	EnumValues      map[int]string             `yaml:"enum_values,omitempty"`
	Offset          float64                    `yaml:"offset,omitempty"`
	Scale           float64                    `yaml:"scale,omitempty"`
}

type Index struct {
	Labelname  string         `yaml:"labelname"`
	Type       string         `yaml:"type"`
	FixedSize  int            `yaml:"fixed_size,omitempty"`
	Implied    bool           `yaml:"implied,omitempty"`
	EnumValues map[int]string `yaml:"enum_values,omitempty"`
}

type Lookup struct {
	Labels    []string `yaml:"labels"`
	Labelname string   `yaml:"labelname"`
	Oid       string   `yaml:"oid,omitempty"`
	Type      string   `yaml:"type,omitempty"`
}

// Secret is a string that must not be revealed on marshaling.
type Secret string

func (s *Secret) Set(value string) {
	*s = Secret(value)
}

// Hack for creating snmp.yml with the secret.
var (
	DoNotHideSecrets = false
)

// MarshalYAML implements the yaml.Marshaler interface.
func (s Secret) MarshalYAML() (interface{}, error) {
	if DoNotHideSecrets {
		return string(s), nil
	}
	if s != "" {
		return "<secret>", nil
	}
	return nil, nil
}

type Auth struct {
	Community     Secret `yaml:"community,omitempty"`
	SecurityLevel string `yaml:"security_level,omitempty"`
	Username      string `yaml:"username,omitempty"`
	Password      Secret `yaml:"password,omitempty"`
	AuthProtocol  string `yaml:"auth_protocol,omitempty"`
	PrivProtocol  string `yaml:"priv_protocol,omitempty"`
	PrivPassword  Secret `yaml:"priv_password,omitempty"`
	ContextName   string `yaml:"context_name,omitempty"`
	Version       int    `yaml:"version,omitempty"`
}

func (c *Auth) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultAuth
	type plain Auth
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}

	if c.Version < 1 || c.Version > 3 {
		return fmt.Errorf("SNMP version must be 1, 2 or 3. Got: %d", c.Version)
	}
	if c.Version == 3 {
		switch c.SecurityLevel {
		case "authPriv":
			if c.PrivPassword == "" {
				return fmt.Errorf("priv password is missing, required for SNMPv3 with priv")
			}
			if c.PrivProtocol != "DES" && c.PrivProtocol != "AES" && c.PrivProtocol != "AES192" && c.PrivProtocol != "AES192C" && c.PrivProtocol != "AES256" && c.PrivProtocol != "AES256C" {
				return fmt.Errorf("priv protocol must be DES or AES")
			}
			fallthrough
		case "authNoPriv":
			if c.Password == "" {
				return fmt.Errorf("auth password is missing, required for SNMPv3 with auth")
			}
			if c.AuthProtocol != "MD5" && c.AuthProtocol != "SHA" && c.AuthProtocol != "SHA224" && c.AuthProtocol != "SHA256" && c.AuthProtocol != "SHA384" && c.AuthProtocol != "SHA512" {
				return fmt.Errorf("auth protocol must be SHA or MD5")
			}
			fallthrough
		case "noAuthNoPriv":
			if c.Username == "" {
				return fmt.Errorf("auth username is missing, required for SNMPv3")
			}
		default:
			return fmt.Errorf("security level must be one of authPriv, authNoPriv or noAuthNoPriv")
		}
	}
	return nil
}

type RegexpExtract struct {
	Value string `yaml:"value"`
	Regex Regexp `yaml:"regex"`
}

func (c *RegexpExtract) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultRegexpExtract
	type plain RegexpExtract
	return unmarshal((*plain)(c))
}

// Regexp encapsulates a regexp.Regexp and makes it YAML marshalable.
type Regexp struct {
	*regexp.Regexp
}

// MarshalYAML implements the yaml.Marshaler interface.
func (re Regexp) MarshalYAML() (interface{}, error) {
	if re.Regexp != nil {
		return re.String(), nil
	}
	return nil, nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (re *Regexp) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	regex, err := regexp.Compile("^(?:" + s + ")$")
	if err != nil {
		return err
	}
	re.Regexp = regex
	return nil
}

func substituteEnvVariables(value string) (string, error) {
	result := os.Expand(value, func(s string) string {
		return os.Getenv(s)
	})
	if result == "" {
		return "", errors.New(value + " environment variable not found")
	}
	return result, nil
}
