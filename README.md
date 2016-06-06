# Prometheus SNMP Exporter

This is an exporter that exposes information gathered from SNMP
for use by the Prometheus monitoring system.

## Installation

```Shell
apt-get install libsnmp-python  # On older Debian-based distros.
apt-get install python-netsnmp  # On newer Debian-based distros.
yum install net-snmp-python     # On Red Hat-based distros.

pip install snmp_exporter
```

## Usage

```
snmp_exporter [config_file] [port]
```

`config_file` contains what OIDs to scrape and how to process them.
`config_file` defaults to `snmp.yml`. `port` defaults to 9116.

Visit http://localhost:9116/metrics?address=1.2.3.4 where 1.2.3.4 is the IP of the
SNMP device to get metrics from. You can also specify a `module` parameter, to
choose which module to use from the config file.

## Prometheus Configuration

The snmp exporter needs to be passed the address as a parameter, this can be
done with relabelling.

Example config:
```YAML
scrape_configs:
  - job_name: 'snmp'
    target_groups:
      - targets:
        - 192.168.1.2  # SNMP device.
    params:
      module: [default]
    relabel_configs:
      - source_labels: [__address__]
        regex: (.*?)(:80)?
        target_label: __param_address
        replacement: ${1}
      - source_labels: [__param_address]
        regex: (.*)
        target_label: instance
        replacement: ${1}
      - source_labels: []
        regex: .*
        target_label: __address__
        replacement: 127.0.0.1:9116  # SNMP exporter.
```

This setup allows Prometheus to provide scheduling and service discovery, as
unlike all other exporters running an exporter on the machine from which we are
getting the metrics from is not possible.

## Design

There are two components. An exporter that does the actual scraping,
and a generator that creates the configuration for use by the exporter.
Only the exporter is written so far.

This is to allow for customisation of what's done during the scrape as many
special cases are expected.  The varying levels of SNMP MIB-parsing support
across different languages also means that a single language may not be
practical.

## Extending modules

To add new modules to be scraped by the SNMP exporter, edit the yaml files
found under snmp.yml.d, and then run:

    cat snmp.yml.d/*.yml > snmp.yml

That file can then be used as the configuration file.
