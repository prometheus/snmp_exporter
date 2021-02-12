## 0.20.0 / 2021-02-12

NOTE: This is a safe harbor release. Future releases will have breaking changes to the configuration format.

* [ENHANCEMENT] Remove vendoring
* [ENHANCEMENT] Add TLS support

## 0.19.0 / 2020-08-31

* [ENHANCEMENT] Support EnumAsInfo as an index (#559)
* [ENHANCEMENT] Allow lookup chaining for uints (#527)

## 0.18.0 / 2020-05-26

* [FEATURE] Allow lookup chaining in a basic way (#489)
* [BUGFIX] Reduce and fix timeouts for SNMP requests (#511)

## 0.17.0 / 2020-02-17

* [ENHANCEMENT] Use contexts with SNMP, so the http connection closing stops the SNMP walk. (#481)
* [ENHANCEMENT] Sanitize the snmp probe query params by only allowing them to be specified once. (#467)

## 0.16.1 / 2019-12-10

* [FEATURE] Support BITS values. (#465)
* [ENHANCEMENT] Add option to fail on parse errors in the generator. (#382)
* [ENHANCEMENT] Switch logging to go-kit (#447)
* [BUGFIX] Handle trailing linefeed in NetSNMP output adding 1 to the error count (#398)

## 0.15.0 / 2019-02-12

This release includes changes to both the generator.yml format and the default output of the generator for lookups.

* [CHANGE] Support multi-index lookups. This changes old_index to be a list old_indexes in generator.yml. (#339)
* [CHANGE] Allow keeping of old labels from lookups, enabled by default (#339)
* [CHANGE] The previous example modules if_mib_ifalias, if_mib_ifdescr, and if_mib_ifname have been removed from snmp.yml/generator.yml. These labels are now all available on the default if_mib example module (#339)
* [FEATURE] Add EnumAsInfo and EnumAsStateSet type overrides (#378)
* [ENHANCEMENT] Better error messages when an index can't be handled (#369)

## 0.14.0 / 2018-12-04

* [FEATURE] Add dry-run option to validate configuration (#363)
* [FEATURE] Add support for LLDP-MIB's LldpPortId (#337)
* [ENHANCEMENT] Add automatic Cou nter64 wrapping (#351)
* [ENHANCEMENT] Add comment that snmp.yaml is auto-generated (#364)
* [BUGFIX] Fix signal handling (#353)

## 0.13.0 / 2018-09-12

* [FEATURE] Add support for IMPLIED indexes
* [FEATURE] Add support for InetAddress
* [FEATURE] Add support for overriding InetAddress when index size is incorrectly missing, as seen in some Juniper devices

## 0.12.0 / 2018-08-15

* [FEATURE] Support added for DateAndTime textual convention (#322)
* [BUGFIX] Avoid false positives when looking for display strings (#312)

## 0.11.0 / 2018-05-30

* [FEATURE] Generator: Support ignoring specific metrics
* [FEATURE] Generator: Support overriding the type of metrics
* [BUGFIX] Don't panic on invalid utf-8 data, just fail the scrape

## 0.10.0 / 2018-04-26

* [FEATURE] Use GET rather than GETBULK if specific non-table object or table object instance is listed in generator module walk
* [BUGFIX] Better handle SNMP v3 auth config, fixing some validation
* [BUGFIX] Fail the scrape rather than exposing invalid UTF-8 label values
* [BUGFIX] Remove incorrect InetAddress implementation

## 0.9.0 / 2018-02-26

* [FEATURE] Support for Opaque Float/Double types

## 0.8.0 / 2017-11-20

* [FEATURE] Support SNMP v3 context names
* [FEATURE] Support fixed-size string indexes

## 0.7.0 / 2017-10-09

* [FEATURE] Generator detects a broader range of display strings, including SnmpAdminString
* [BUGFIX] Pull in upstream fix for spurious results when walk matched no oids 

## 0.6.0 / 2017-08-22

* [CHANGE] Default module is now `if_mib` rather than `default`. `if_mib` has no lookups, and `if_mib_*` has replaced  `default_*`. `if_mib_ifdescr` has the old behaviour of `default`.
* [BUGFIX] Don't hide secrets when generating snmp.yml
* [BUGFIX] Correctly handle different auth settings across modules

## 0.5.0 / 2017-08-15

* [FEATURE] Expose config on /config
* [FEATURE] Add help text to metrics
* [FEATURE] Allow for extracting numeric metrics from string objects via regular expressions
* [FEATURE/CHANGE] Config now only reloaded on SIGHUP or /-/reload
* [CHANGE] Switch to kingpin flags, all flags now have two hyphens rather than one
* [CHANGE] Remove Fortinet example module
* [BUGFIX] Handle Counter64s with values >=2^63 correctly
* [BUGFIX] Sanitize metric names
* [BUGFIX] Add back objects marked no-access to generator output

## v0.4.0 / 2017-06-06

* [FEATURE] Add Homepage on /. #135
* [ENHANCEMENT] Add ddwrt OIDs to generator. #147
* [ENHANCEMENT] Add synology OIDs to generator. #149, #154
* [ENHANCEMENT] Use lookup node's index label in the generator. #162
* [BUGFIX] Fix `authNoPriv` in config parsing. #141
* [BUGFIX] Update gosnmp vendoring to fix timeouts/errors. #139, #171

## 0.3.0 / 2017-03-15

* [FEATURE] Support MAC Addresses and IP addresses as object values
* [ENHANCEMENT] Allow compiling generator under FreeBSD
* [ENHANCEMENT] Workaround RFC1213-MIB being too old to have type hints
* [BUGFIX] Represent OctetStrings as hex

## 0.2.0 / 2017-01-25

* [FEATURE] Add config generator
* [FEATURE] Add support for strings in PDUs
* [FEATURE] Add debug logging
* [FEATURE] Add -version flag
* [BUGFIX] Correctly handle missing label lookups


## 0.1.0 / 2016-09-23

This is a port to Go from the original Python version.

Behaviour is largely the same (the same config file will work), however the URL has changed a bit: It's now /snmp?target=1.2.3.4 where previously it was /metrics?address=1.2.3.4

As this is a rewrite, a full list of changes will not be provided.


## 0.0.6 / 2016-08-13

* [FEATURE] SNMP v1 support
* [FEATURE] SNMP v3 support
* [FEATURE] InetAddress supported as part of a table index
* [FEATURE] OctetString supported as part of a table index
* [FEATURE] Cisco WLC example added to config
* [FEATURE] Example systemd config
* [ENHANCEMENT] Handle devices that remove trailing 0s in OIDs
* [ENHANCEMENT] Python 3 support
* [BUGFIX] Fixed rendering of MAC addresses


## 0.0.5 / 2016-01-30

This release is breaking. To convert your config to work with the new release, indent all the lines and then prepend the line`default:`

* [FEATURE] Support multiple modules inside one config


## 0.0.4 / 2016-01-08

This release changes the SNMP exporter to use the NetSNMP Python bindings, which are faster and use less CPU.
This needs manual installation of the bindings:

```
apt-get install libsnmp-python  # On older Debian-based distros.
apt-get install python-netsnmp  # On newer Debian-based distros.
yum install net-snmp-python     # On Red Hat-based distros.
```

* [FEATURE] Support for setting community
* [ENHANCEMENT] Switch to NetSNMP Python bindings
* [ENHANCEMENT] Rule lookup is done with a tree rather than a linear search
* [ENHANCEMENT] Various tweaks for dodgy hardware
