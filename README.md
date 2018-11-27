# Prometheus SNMP Exporter

This is an exporter that exposes information gathered from SNMP
for use by the Prometheus monitoring system.

There are two components. An exporter that does the actual scraping, and a
[generator](generator/) (which depends on NetSNMP) that creates the
configuration for use by the exporter.

## Installation

Binaries can be downloaded from the [Github
releases](https://github.com/prometheus/snmp_exporter/releases) page.

## Usage

```sh
./snmp_exporter
```

Visit http://localhost:9116/snmp?target=1.2.3.4 where 1.2.3.4 is the IP of the
SNMP device to get metrics from. You can also specify a `module` parameter, to
choose which module to use from the config file.

## Configuration

The snmp exporter reads from a `snmp.yml` config file by default. This file is
not intended to be written by hand, rather use the [generator](generator/) to
generate it for you.

The default `snmp.yml` covers a variety of common hardware for which
MIBs are available to the public, walking them using SNMP v2 GETBULK.

You'll need to use the generator in all but the simplest of setups. It is
needed to customize which objects are walked, use non-public MIBs or specify
authentication parameters.

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
      module: [if_mib]
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9116  # The SNMP exporter's real hostname:port.
```

This setup allows Prometheus to provide scheduling and service discovery, as
unlike all other exporters running an exporter on the machine from which we are
getting the metrics from is not possible.

## Large counter value handling

In order to provide accurate counters for large Counter64 values, the exporter will automatically
wrap the value every 2^53 to avoid 64-bit float rounding.

To disable this feature, use the command line flag `--no-snmp.wrap-large-counters`.
