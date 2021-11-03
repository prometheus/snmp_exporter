# Prometheus SNMP Exporter

This exporter is the recommended way to expose SNMP data in a format which
Prometheus can ingest.

To simply get started, it's recommended to use the `if_mib` module with
switches, access points, or routers.

# Concepts

While SNMP uses a hierarchical data structure and Prometheus uses an
n-dimnensional matrix, the two systems map perfectly, and without the need
to walk through data by hand. `snmp_exporter` maps the data for you.

## Prometheus

Prometheus is able to map SNMP index instances to labels. For example, the `ifEntry` specifies an INDEX of  `ifIndex`. This becomes the `ifIndex` label in Prometheus.

If an SNMP entry has multiple index values, each value is mapped to a separate Prometheus label.

## SNMP

SNMP is structured in OID trees, described by MIBs. OID subtrees have the same
order across different locations in the tree. The order under
`1.3.6.1.2.1.2.2.1.1` (`ifIndex`) is the same as in `1.3.6.1.2.1.2.2.1.2`
(`ifDescr`), `1.3.6.1.2.1.31.1.1.1.10` (`ifHCOutOctets`), etc. The numbers are
OIDs, the names in parentheses are the names from a MIB, in this case
[IF-MIB](http://www.oidview.com/mibs/0/IF-MIB.html).

## Mapping

Given a device with an interface at number 2, a partial `snmpwalk` return looks
like:

```
1.3.6.1.2.1.2.2.1.1.2 = INTEGER: 2         # ifIndex for '2' is literally just '2'
1.3.6.1.2.1.2.2.1.2.2 = STRING: "eth0"     # ifDescr
1.3.6.1.2.1.31.1.1.1.1 = STRING: "eth0"    # IfName
1.3.6.1.2.1.31.1.1.1.10.2 = INTEGER: 1000  # ifHCOutOctets, 1000 bytes
1.3.6.1.2.1.31.1.1.1.18.2 = STRING: ""     # ifAlias
```

`snmp_exporter` combines all of this data into:

```
ifHCOutOctets{ifAlias="",ifDescr="eth0",ifIndex="2",ifName="eth0"} 1000
```

# Scaling

A single instance of `snmp_exporter` can be run for thousands of devices.

# Usage

## Installation

Binaries can be downloaded from the [Github
releases](https://github.com/prometheus/snmp_exporter/releases) page and need no
special installation.

We also provide a sample [systemd unit file](examples/systemd/snmp_exporter.service).

## Running

Start `snmp_exporter` as a daemon or from CLI:

```sh
./snmp_exporter
```

Visit http://localhost:9116/snmp?module=if_mib&target=1.2.3.4 where `1.2.3.4` is the IP or
FQDN of the SNMP device to get metrics from and `if_mib` is the default module, defined
in `snmp.yml`.

## Configuration

The default configuration file name is `snmp.yml` and should not be edited
by hand. If you need to change it, see
[Generating configuration](#generating-configuration).

The default `snmp.yml` covers a variety of common hardware walking them
using SNMP v2 GETBULK.

## Prometheus Configuration

`target` and `module` can be passed as a parameter through relabelling.

Example config:
```YAML
scrape_configs:
  - job_name: 'snmp'
    static_configs:
      - targets:
        - 192.168.1.2  # SNMP device.
        - switch.local # SNMP device.
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

Similarly to [blackbox_exporter](https://github.com/prometheus/blackbox_exporter),
`snmp_exporter` is meant to run on a few central machines and can be thought of
like a "Prometheus proxy".

### TLS and basic authentication

The SNMP Exporter supports TLS and basic authentication. This enables better
control of the various HTTP endpoints.

To use TLS and/or basic authentication, you need to pass a configuration file
using the `--web.config.file` parameter. The format of the file is described
[in the exporter-toolkit repository](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md).

Note that the TLS and basic authentication settings affect all HTTP endpoints:
/metrics for scraping, /snmp for scraping SNMP devices, and the web UI.

### Generating configuration

Most use cases should be covered by our [default configuration](snmp.yml).
If you need to generate your own configuration from MIBs, you can use the
[generator](generator/).

Use the generator if you need to customize which objects are walked or use
non-public MIBs.

## Large counter value handling

In order to provide accurate counters for large Counter64 values, the exporter
will automatically wrap the value every 2^53 to avoid 64-bit float rounding.
Prometheus handles this gracefully for you and you will not notice any negative
effects.

If you need to disable this feature for non-Prometheus systems, use the
command line flag `--no-snmp.wrap-large-counters`.
