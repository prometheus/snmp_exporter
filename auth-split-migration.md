# Module and Auth Split Migration

Starting from `snmp_exporter` [release v0.23.0](https://github.com/prometheus/snmp_exporter/releases/tag/v0.23.0) the configuration file format for the `snmp_exporter` has been changed. Configuration files for [release v0.22.0](https://github.com/prometheus/snmp_exporter/releases/tag/v0.22.0) and before will not work. The configuration was split from a flat list of modules to separate metric walking/mapping modules and authentication configurations.

This change necessitates migration of the generator config and `snmp_exporter` config to the new format.

The complete `generator` format is [documented in generator/README.md#file-format](generator/README.md#file-format)

The complete `snmp_exporter` format is [documented in /generator/FORMAT.md](/generator/FORMAT.md).

See the main [README](/README#Configuration) for the Prometheus configuration examples.

## Examples

A generator containing the following config:

```yaml
modules:
  sys_uptime:
    version: 2
    walk:
    - sysUpTime
  auth:
    community: public
```

Would now become:

```yaml
auths:
  public_v2:
    community: public
    version: 2
modules:
  sys_uptime:
    walk:
    - sysUpTime
```

The newly generated `snmp_exporter` config would be:

```yaml
# WARNING: This file was auto-generated using snmp_exporter generator, manual changes will be lost.
auths:
  public_v2:
    community: public
    security_level: noAuthNoPriv
    auth_protocol: MD5
    priv_protocol: DES
    version: 2
modules:
  if_mib:
    get:
    - 1.3.6.1.2.1.1.3.0
    metrics:
    - name: sysUpTime
      oid: 1.3.6.1.2.1.1.3
      type: gauge
      help: The time (in hundredths of a second) since the network management portion
        of the system was last re-initialized. - 1.3.6.1.2.1.1.3
```
