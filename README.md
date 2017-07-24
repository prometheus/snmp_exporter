# Prometheus SNMP Exporter

This is an exporter that exposes information gathered from SNMP
for use by the Prometheus monitoring system.

There are two components. An exporter that does the actual scraping, and a
[generator](https://github.com/prometheus/snmp_exporter/tree/master/generator)
(which depends on NetSNMP) that creates the configuration for use by the
exporter.

## Installation

Binaries can be downloaded from the [Github
releases](https://github.com/prometheus/snmp_exporter/releases) page.

## Usage

```
./snmp_exporter
```

Visit http://localhost:9116/snmp?target=1.2.3.4 where 1.2.3.4 is the IP of the
SNMP device to get metrics from. You can also specify a `module` parameter, to
choose which module to use from the config file.

## Configuration

TODO

## Prometheus Configuration

The snmp exporter needs to be passed the address as a parameter, this can be
done with relabelling.

Example config:
```YAML
scrape_configs:
  - job_name: 'snmp'
    static_configs:
      - targets:
        - 192.168.1.2  # SNMP device.
    metrics_path: /snmp
    params:
      module: [default]
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9116  # SNMP exporter.
```

This setup allows Prometheus to provide scheduling and service discovery, as
unlike all other exporters running an exporter on the machine from which we are
getting the metrics from is not possible.
