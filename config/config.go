package config

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"
	"time"

	"github.com/soniah/gosnmp"
	"gopkg.in/yaml.v2"
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

var (
	DefaultAuth = Auth{
		Community:     "public",
		SecurityLevel: "noAuthNoPriv",
		AuthProtocol:  "MD5",
		PrivProtocol:  "DES",
	}
	DefaultWalkParams = WalkParams{
		Version:        2,
		MaxRepetitions: 25,
		Retries:        3,
		Timeout:        time.Second * 20,
		Auth:           DefaultAuth,
	}
	DefaultModule = Module{
		WalkParams: DefaultWalkParams,
	}
	DefaultRegexpExtract = RegexpExtract{
		Value: "$1",
	}
)

// Config for the snmp_exporter.
type Config map[string]*Module

type WalkParams struct {
	Version        int           `yaml:"version,omitempty"`
	MaxRepetitions uint8         `yaml:"max_repetitions,omitempty"`
	Retries        int           `yaml:"retries,omitempty"`
	Timeout        time.Duration `yaml:"timeout,omitempty"`
	Auth           Auth          `yaml:"auth,omitempty"`

	XXX map[string]interface{} `yaml:",inline"`
}

type Module struct {
	// A list of OIDs.
	Walk       []string   `yaml:"walk"`
	Metrics    []*Metric  `yaml:"metrics"`
	WalkParams WalkParams `yaml:",inline"`

	XXX map[string]interface{} `yaml:",inline"`
}

func (c *WalkParams) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultWalkParams
	type plain WalkParams
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	if err := CheckOverflow(c.XXX, "module"); err != nil {
		return err
	}

	if c.Version < 1 || c.Version > 3 {
		return fmt.Errorf("SNMP version must be 1, 2 or 3. Got: %d", c.Version)
	}
	if c.Version == 3 {
		if c.Auth.Username == "" {
			return fmt.Errorf("Auth username is missing, required for SNMPv3")
		}
		if c.Auth.SecurityLevel != "authPriv" &&
			c.Auth.SecurityLevel != "authNoPriv" && c.Auth.SecurityLevel != "noAuthNoPriv" {
			return fmt.Errorf("Security level must be one of authPriv, authNoPriv or noAuthNoPriv")
		}
		if c.Auth.Password == "" && c.Auth.SecurityLevel != "noAuthNoPriv" {
			return fmt.Errorf("Auth password is missing, required for SNMPv3 with auth.")
		}
		if c.Auth.AuthProtocol != "MD5" && c.Auth.AuthProtocol != "SHA" {
			return fmt.Errorf("Auth protocol must be SHA or MD5.")
		}
		if c.Auth.PrivProtocol != "DES" && c.Auth.PrivProtocol != "AES" {
			return fmt.Errorf("Priv protocol must be DES or AES.")
		}
		if c.Auth.PrivPassword == "" && c.Auth.SecurityLevel == "authPriv" {
			return fmt.Errorf("Priv password is missing, required for SNMPv3 with priv.")
		}
	}
	return nil
}

func (c *Module) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultModule
	type plain Module
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	if err := CheckOverflow(c.XXX, "module"); err != nil {
		return err
	}
	return nil
}

// configureSNMP sets the various version and auth settings.
func (c WalkParams) ConfigureSNMP(g *gosnmp.GoSNMP) {
	switch c.Version {
	case 1:
		g.Version = gosnmp.Version1
	case 2:
		g.Version = gosnmp.Version2c
	case 3:
		g.Version = gosnmp.Version3
	}
	g.Community = string(c.Auth.Community)
	g.ContextName = string(c.Auth.ContextName)

	// v3 security settings.
	g.SecurityModel = gosnmp.UserSecurityModel
	switch c.Auth.SecurityLevel {
	case "noAuthNoPriv":
		g.MsgFlags = gosnmp.NoAuthNoPriv
	case "authNoPriv":
		g.MsgFlags = gosnmp.AuthNoPriv
	case "authPriv":
		g.MsgFlags = gosnmp.AuthPriv
	}
	usm := &gosnmp.UsmSecurityParameters{
		UserName:                 c.Auth.Username,
		AuthenticationPassphrase: string(c.Auth.Password),
		PrivacyPassphrase:        string(c.Auth.PrivPassword),
	}
	switch c.Auth.AuthProtocol {
	case "SHA":
		usm.AuthenticationProtocol = gosnmp.SHA
	case "MD5":
		usm.AuthenticationProtocol = gosnmp.MD5
	}
	switch c.Auth.PrivProtocol {
	case "DES":
		usm.PrivacyProtocol = gosnmp.DES
	case "AES":
		usm.PrivacyProtocol = gosnmp.AES
	}
	g.SecurityParameters = usm
}

type Metric struct {
	Name           string                     `yaml:"name"`
	Oid            string                     `yaml:"oid"`
	Type           string                     `yaml:"type"`
	Help           string                     `yaml:"help"`
	Indexes        []*Index                   `yaml:"indexes,omitempty"`
	Lookups        []*Lookup                  `yaml:"lookups,omitempty"`
	RegexpExtracts map[string][]RegexpExtract `yaml:"regex_extracts,omitempty"`
}

func (c *Metric) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Metric
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	return nil
}

type Index struct {
	Labelname string `yaml:"labelname"`
	Type      string `yaml:"type"`
	FixedSize int    `yaml:"fixed_size,omitempty"`

	XXX map[string]interface{} `yaml:",inline"`
}

func (c *Index) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Index
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	if err := CheckOverflow(c.XXX, "module"); err != nil {
		return err
	}
	return nil
}

type Lookup struct {
	Labels    []string `yaml:"labels"`
	Labelname string   `yaml:"labelname"`
	Oid       string   `yaml:"oid"`
	Type      string   `yaml:"type"`

	XXX map[string]interface{} `yaml:",inline"`
}

func (c *Lookup) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Lookup
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	if err := CheckOverflow(c.XXX, "module"); err != nil {
		return err
	}
	return nil
}

// Secret is a string that must not be revealed on marshaling.
type Secret string

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

//UnmarshalYAML implements the yaml.Unmarshaler interface for Secrets.
func (s *Secret) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Secret
	return unmarshal((*plain)(s))
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

	XXX map[string]interface{} `yaml:",inline"`
}

func (c *Auth) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultAuth
	type plain Auth
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	if err := CheckOverflow(c.XXX, "module"); err != nil {
		return err
	}
	return nil
}

type RegexpExtract struct {
	Value string `yaml:"value"`
	Regex Regexp `yaml:"regex"`

	XXX map[string]interface{} `yaml:",inline"`
}

func (c *RegexpExtract) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultRegexpExtract
	type plain RegexpExtract
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	if err := CheckOverflow(c.XXX, "regex_extract"); err != nil {
		return err
	}
	return nil
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

func CheckOverflow(m map[string]interface{}, ctx string) error {
	if len(m) > 0 {
		var keys []string
		for k := range m {
			keys = append(keys, k)
		}
		return fmt.Errorf("unknown fields in %s: %s", ctx, strings.Join(keys, ", "))
	}
	return nil
}
