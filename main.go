package main

import (
  "flag"
  "time"
  "io/ioutil"

  "github.com/prometheus/common/log"
  "gopkg.in/yaml.v2"
  "github.com/soniah/gosnmp"
)

var (
  configFile = flag.String(
    "config.file", "snmp.yml",
    "Path to configuration file.",
  )
  listenAddress = flag.String(
    "web.listen-address", ":9104",
    "Address to listen on for web interface and telemetry.",
  )
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
  Walk []string  `yaml:"walk"`
  Metrics []Metric `yaml:"metrics"`
  // TODO: Security

  // TODO: Use these.
  XXX map[string]interface{} `yaml:",inline"`
}

type Metric struct {
  Name string `yaml:"name"`
  Oid string `yaml:"oid"`
  Indexes []*Index `yaml:"indexes,omitempty"`
  Lookups []*Lookup `yaml:"lookups,omitempty"`

  XXX map[string]interface{} `yaml:",inline"`
}

type Index struct {
  Labelname string `yaml:"labelname"`
  Type string `yaml:"type"`

  XXX map[string]interface{} `yaml:",inline"`
}

type Lookup struct {
  Labels []string `yaml:"labels"`
  Labelname string `yaml:"labelname"`
  Oid string `yaml:"oid"`

  XXX map[string]interface{} `yaml:",inline"`
}

func main() {
  flag.Parse()

  cfg, err := LoadFile(*configFile)
  if err != nil {
    log.Errorf("Error parsing config file: %s", err)
    return
  }
  _ = cfg

  snmp := gosnmp.GoSNMP{}
  snmp.Target = "192.168.1.2"
  snmp.Port = 161
  snmp.Version = gosnmp.Version2c
  snmp.Community = "public"
  snmp.Retries = 3
  snmp.MaxRepetitions = 25
  snmp.Timeout = time.Second * 60

  err = snmp.Connect()
  if err != nil {
    log.Errorf("Error connecting to target %s: %s", snmp.Target, err)
    return
  }
  defer snmp.Conn.Close()
  pdus, err := snmp.BulkWalkAll("1.3.6.1.2.1.2")
  if err != nil {
    log.Errorf("Error walking target %s: %s", snmp.Target, err)
    return
  }
  for _, pdu := range pdus {
    println(pdu.Name)
  }
}
