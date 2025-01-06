# Prometheus SNMP Exporter

This exporter is the recommended way to expose SNMP data in a format which
Prometheus can ingest.

To simply get started, it's recommended to use the `if_mib` module with
switches, access points, or routers using the `public_v2` auth module,
which should be a read-only access community on the target device.

Note, community strings in SNMP are not considered secrets, as they are sent
unencrypted in SNMP v1 and v2c. For secure access, SNMP v3 is required.

# Concepts

While SNMP uses a hierarchical data structure and Prometheus uses an
n-dimensional matrix, the two systems map perfectly, and without the need
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
1.3.6.1.2.1.31.1.1.1.1.2 = STRING: "eth0"  # IfName
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

Visit <http://localhost:9116/snmp?target=192.0.0.8> where `192.0.0.8` is the IP or
FQDN of the SNMP device to get metrics from. Note that this will use the default transport (`udp`),
default port (`161`), default auth (`public_v2`) and default module (`if_mib`). The auth and module
must be defined in the `snmp.yml` file.

For example, if you have an auth named `my_secure_v3` for walking `ddwrt`, the URL would look like
<http://localhost:9116/snmp?auth=my_secure_v3&module=ddwrt&target=192.0.0.8>.

To configure a different transport and/or port, use the syntax `[transport://]host[:port]`.

For example, to scrape a device using `tcp` on port `1161`, the URL would look like
<http://localhost:9116/snmp?auth=my_secure_v3&module=ddwrt&target=tcp%3A%2F%2F192.0.0.8%3A1161>.

Note that [URL encoding](https://en.wikipedia.org/wiki/URL_encoding) should be used for `target` due
to the `:` and `/` characters. Prometheus encodes query parameters automatically and manual encoding
is not necessary within the Prometheus configuration file.

Metrics concerning the operation of the exporter itself are available at the
endpoint <http://localhost:9116/metrics>.

It is possible to supply an optional `snmp_context` parameter in the URL, like this:
<http://localhost:9116/snmp?auth=my_secure_v3&module=ddwrt&target=192.0.0.8&snmp_context=vrf-mgmt>
The `snmp_context` parameter in the URL would override the `context_name` parameter in the `snmp.yml` file.

## Multi-Module Handling
The multi-module functionality allows you to specify multiple modules, enabling the retrieval of information from several modules in a single scrape.
The concurrency can be specified using the snmp-exporter option `--snmp.module-concurrency` (the default is 1).

Note: This implementation does not perform any de-duplication of walks between different modules.

There are two ways to specify multiple modules. You can either separate them with a comma or define multiple params_module.
The URLs would look like this:

For comma separation:
```
http://localhost:9116/snmp?module=if_mib,arista_sw&target=192.0.0.8
```

For multiple params_module:
```
http://localhost:9116/snmp?module=if_mib&module=arista_sw&target=192.0.0.8
```

Prometheus Example:
```YAML

  - job_name: 'my'
    params:
      module: 
        - if_mib
        - synology
        - ucd_la_table
```

## Configuration

The default configuration file name is `snmp.yml` and should not be edited
by hand. If you need to change it, see
[Generating configuration](#generating-configuration).

The default `snmp.yml` file covers a variety of common hardware walking them
using SNMP v2 GETBULK.

The `--config.file` parameter can be used multiple times to load more than one file.
It also supports [glob filename matching](https://pkg.go.dev/path/filepath#Glob), e.g. `snmp*.yml`.

The `--config.expand-environment-variables` parameter allows passing environment variables into some fields of the configuration file. The `username`, `password` & `priv_password` fields in the auths section are supported. Defaults to disabled.

Duplicate `module` or `auth` entries are treated as invalid and can not be loaded.

## Prometheus Configuration

The URL params `target`, `auth`, and `module` can be controlled through relabelling.

Example config:
```YAML
scrape_configs:
  - job_name: 'snmp'
    static_configs:
      - targets:
        - 192.168.1.2  # SNMP device.
        - switch.local # SNMP device.
        - tcp://192.168.1.3:1161  # SNMP device using TCP transport and custom port.
    metrics_path: /snmp
    params:
      auth: [public_v2]
      module: [if_mib]
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9116  # The SNMP exporter's real hostname:port.

  # Global exporter-level metrics
  - job_name: 'snmp_exporter'
    static_configs:
      - targets: ['localhost:9116']
```

You could pass `username`, `password` & `priv_password` via environment variables of your choice in below format. 
If the variables exist in the environment, they are resolved on the fly otherwise the string in the config file is passed as-is.

This requires the `--config.expand-environment-variables` flag be set.

```YAML
auths:
  example_with_envs:
    community: mysecret
    security_level: SomethingReadOnly
    username: ${ARISTA_USERNAME}
    password: ${ARISTA_PASSWORD}
    auth_protocol: SHA256
    priv_protocol: AES
    priv_password: ${ARISTA_PRIV_PASSWORD}
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

# Once you have it running

It can be opaque to get started with all this, but in our own experience,
snmp_exporter is honestly the best way to interact with SNMP. To make it
easier for others, please consider contributing back your configurations to
us.
`snmp.yml` config should be accompanied by generator config.
For your dashboard, alerts, and recording rules, please consider
contributing them to <https://github.com/prometheus/snmp_exporter/tree/main/snmp-mixin>.
