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


## Authentication

### SNMPv2

The default configuration is to use SNMPv2 with the community `public`.  This can be changed in the yaml config.  NOTE: Version 2 implies SNMP version 2c.

#### Authentication parameters

Name | Description
--------|------------
community | Community string defined on the device

Example:
```YAML
default:
  version: 2
  auth:
    community: SomeCommunityString
  walk:
    - ...
  metrics:
    - ...
```

### SNMPv1

For SNMPv1, the authentication also requires a community string which will default to 'public'.

#### Authentication parameters

Name | Description
--------|-----------
community | Community string defined on the device

Example:
````YAML
default:
  version: 1
  auth:
    community: SomeCommunityString
  walk:
    - ...
  metrics:
    - ...
````

## SNMPv3

For SNMPv3, the authentication requires different parameters.  The `auth_protocol` defaults to `MD5` and the `priv_protocol` defaults to `DES`.  The `security_level` defaults to `noAuthNoPriv`.

#### Authentication parameters

Name | Description | required
--------|--------------|--------------
username | A string representing the name of the user | yes
password |  If messages sent on behalf of this user can be authenticated, the (private) authentication key for use with the authentication protocol. Defined as authKey in RFC3414 | if security_level = authNoPriv or authPriv
auth_protocol | An indication of whether messages sent on behalf of this user can be authenticated, and if so, the type of authentication protocol which is used. 2 protocols are defined in RFC3414: MD5 (HMAC-MD5-96) and SHA (HMAC-SHA-96) | if security_level = authNoPriv or authPriv
priv_protocol | An indication of whether messages sent on behalf of this user can be protected from disclosure, and if so, the type of privacy protocol which is used. Only one protocol is defined in RFC3414: DES (CBC-DES Symmetric Encryption Protocol) | if security_level = authPriv
security_level | The Level of Security from which the User-based Security module determines if the message needs to be protected from disclosure and if the message needs to be authenticated. | yes (see security settings under table)
priv_password | If messages sent on behalf of this user can be en/decrypted, the (private) privacy key for use with the privacy protocol. Defined as privKey in RFC3414 | if security_level = authPriv 

Security_level has 3 settings:
* noAuthNoPriv: no authentication or privacy
* authNoPriv: user authentication, without privacy
* authPriv: user authentication and privacy

Example:
```YAML
default:
  version: 3
  auth:
    username: SomeUser
    password: TotallySecret
    auth_protocol: SHA
    priv_protocol: AES
    security_level: SomethingReadOnly
    priv_password: SomeOtherSecret
  walk:
    - ...
  metrics:
    - ...
```

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
