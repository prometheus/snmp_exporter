
# SNMP Exporter Device Discovery

This service uses the snmp_exporters fingerprinting module to dynamically discover devices on a specified network.

You can use it as an `http_sd` module in order to discover & fingerprint all devices on your network.

It is built the same way as the regular snmp_exporter by running `make` in the project root.

If you just want to build the discovery service, run the following:

```
PROMU_BINARIES=snmp_exporter_discovery make common-build
```

## Usage

The discovery service uses the same configuration file as the snmp_exporter.
You **must** ensure that this is always the case as otherwise the discovery endpoint could return modules that are not present in the exporters set of available modules.

Configuration of the discovery service is provided through command line arguments.
In the most basic example, you just need to provide the `--discovery.network` parameter.

```
./snmp_exporter_discovery --discovery.network 172.20.20.0/24
```

You can find all parameters and their default values by using `--help`.

Once running, you can configure prometheus to use the discovery endpoint to find network devices like this

```
scrape_configs:
  - job_name: "snmp"
    http_sd_configs:
      - url: "http://127.0.0.1:9117/discovery" # The discovery services address
    metrics_path: /snmp
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9116 # The SNMP exporter's real hostname:port.
```
