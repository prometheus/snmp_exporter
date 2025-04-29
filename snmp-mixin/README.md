# SNMP Mixin

The SNMP Mixin is a set of configurable, reusable, and extensible alerts and
dashboards based on the metrics exported by snmp_exporter. The mixin creates
recording and alerting rules for Prometheus and suitable dashboard descriptions
for Grafana.

To use them, you need to have `mixtool` and `jsonnetfmt` installed. If you
have a working Go development environment, it's easiest to run the following:
```bash
$ go install github.com/monitoring-mixins/mixtool/cmd/mixtool@latest
$ go install github.com/google/go-jsonnet/cmd/jsonnetfmt@latest
```

You can then build the Prometheus rules files `alerts.yaml` and
`rules.yaml` and a directory `dashboard_out` with the JSON dashboard files
for Grafana:
```sh
$ make build
```

For more advanced uses of mixins, see
https://github.com/monitoring-mixins/docs.
