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
choose which module to use from the config file. You can also specify an
(base64 encoded AES-GCM encrypted) 'community' paramter, to override the 
community string from the config file.

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
    file_sd_configs:
      - files:
        - '/data/*.json'
    metrics_path: /snmp
    params:
      module: [if_mib]
      community: [public]
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - source_labels: [community]
        target_label: __param_community
      - source_labels: [module]
        target_label: __param_module
      - target_label: __address__
        replacement: 127.0.0.1:9116  # The SNMP exporter's real hostname:port.
```

Optionally, provide a json file as a file based service discovery. Only
(base64 encoded AES-GCM encrypted) community and module are needed. Other 
labels are optional for snmp_exporter purposes.

```JSON
[
  {
    "targets": [ "192.168.1.2" ],
    "labels": {
      "name": "router",
      "community": "Xj3Ag6RZwwSm5PiBoongcPnxCb3q7yLe9Ptcfi7JZCMQNA==",
      "module": "ddwrt"
    }
  }
]
```

This setup allows Prometheus to provide scheduling and service discovery, as
unlike all other exporters running an exporter on the machine from which we are
getting the metrics from is not possible.

## Encrypting the community string

To avoid exposing the community string in the URL and target list, the
community string is encrypted with AES-GCM and then encoded in base64. The
key for the encryption is defined via a command line parameter for snmp_exporter.

The snmp_exporter must be run with the parameter --encryption.aesgcm="password"
to define the passphrase used for encryption/description. To avoid exposing
the password, there is the option for using the parameter
--encryption.aesgcm.file="passwordfile.txt" instead. Store the passphrase in
the first line of the file. 

In the [cryptotool](./cryptotool) folder, there is a tool to encrypt (and
decrypt) your community string with a passphrase. (In this implementation,
the sha256 hash of your passphrase is used for the 32byte key needed for AES)

To encrypt your community of 'public' with the passphrase 'password'

```sh
./cryptotool encryptAesGcm password public
Xj3Ag6RZwwSm5PiBoongcPnxCb3q7yLe9Ptcfi7JZCMQNA==
```

Test the decryption with the same tool

```sh
./cryptotool decryptAesGcm password Xj3Ag6RZwwSm5PiBoongcPnxCb3q7yLe9Ptcfi7JZCMQNA==
public
```

AES GCM is used instead of AES CFB due to the ability to have a random initial 
vector. This means each ciphertext generated is unique even with the same passphrase 
and community string. If you have multiple devices with the same community, you
should generate multiple encrypted community strings. This way, no one will
know that multiple devices have the same community string.

## Large counter value handling

In order to provide accurate counters for large Counter64 values, the exporter will automatically
wrap the value every 2^53 to avoid 64-bit float rounding.

To disable this feature, use the command line flag `--no-snmp.wrap-large-counters`.
