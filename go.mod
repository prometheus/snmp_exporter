module github.com/prometheus/snmp_exporter

require (
	github.com/go-kit/kit v0.10.0
	github.com/prometheus/client_golang v1.10.0
	github.com/prometheus/client_model v0.2.0
	github.com/prometheus/common v0.23.0
	github.com/prometheus/exporter-toolkit v0.5.1
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/golang/mock v1.6.0
	github.com/stretchr/testify v1.7.1
)

require (
	github.com/gosnmp/gosnmp v1.35.0
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

go 1.16
