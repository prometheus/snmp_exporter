## v0.5.0 / 2017-08-15

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
* [IMPROVEMENT] Add ddwrt OIDs to generator. #147
* [IMPROVEMENT] Add synology OIDs to generator. #149, #154
* [IMPROVEMENT] Use lookup node's index label in the generator. #162
* [BUGFIX] Fix `authNoPriv` in config parsing. #141
* [BUGFIX] Update gosnmp vendoring to fix timeouts/errors. #139, #171

## v0.3.0 / 2017-03-15

* [FEATURE] Support MAC Addresses and IP addresses as object values
* [ENHANCEMENT] Allow compiling generator under FreeBSD
* [ENHANCEMENT] Workaround RFC1213-MIB being too old to have type hints
* [BUGFIX] Represent OctetStrings as hex

## v0.2.0 / 2017-01-25

* [FEATURE] Add config generator
* [FEATURE] Add support for strings in PDUs
* [FEATURE] Add debug logging
* [FEATURE] Add -version flag
* [BUGFIX] Correctly handle missing label lookups

## v0.1.0 / 2016-09-23

This is a port to Go from the original Python version.

Behaviour is largely the same (the same config file will work), however the URL has changed a bit: It's now /snmp?target=1.2.3.4 where previously it was /metrics?address=1.2.3.4

As this is a rewrite, a full list of changes will not be provided.

## v0.0.6 / 2016-08-13

* [FEATURE] SNMP v1 support
* [FEATURE] SNMP v3 support
* [FEATURE] InetAddress supported as part of a table index
* [FEATURE] OctetString supported as part of a table index
* [FEATURE] Cisco WLC example added to config
* [FEATURE] Example systemd config
* [ENHANCEMENT] Handle devices that remove trailing 0s in OIDs
* [ENHANCEMENT] Python 3 support
* [BUGFIX] Fixed rendering of MAC addresses

## v0.0.5 / 2016-01-30

This release is breaking. To convert your config to work with the new release, indent all the lines and then prepend the linedefault:

* [FEATURE] Support multiple modules inside one config

## v0.0.4 / 2016-01-08

This release changes the SNMP exporter to use the NetSNMP Python bindings, which are faster and use less CPU.
This needs manual installation of the bindings:

    apt-get install libsnmp-python  # On older Debian-based distros.
    apt-get install python-netsnmp  # On newer Debian-based distros.
    yum install net-snmp-python     # On Red Hat-based distros.

* [FEATURE] Support for setting community
* [ENHANCEMENT] Switch to NetSNMP Python bindings
* [ENHANCEMENT] Rule lookup is done with a tree rather than a linear search
* [ENHANCEMENT] Various tweaks for dodgy hardware

## v0.0.3 / 2015-08-02

## v0.0.2 / 2015-08-02
