
# SNMP Exporter Config Generator

This config generator uses NetSNMP to parse MIBs, and generates configs for the snmp_exporter using them.

## Building

Due to the dynamic dependency on NetSNMP, you must build the generator yourself.

```
# Debian-based distributions.
sudo apt-get install unzip build-essential libsnmp-dev # Debian-based distros
# Redhat-based distributions.
sudo yum install gcc make net-snmp net-snmp-utils net-snmp-libs net-snmp-devel # RHEL-based distros

git clone https://github.com/prometheus/snmp_exporter.git
cd snmp_exporter/generator
make generator mibs
```
## Preparation

It is recommended to have a directory per device family which contains the mibs dir for the device family,
a logical link to the generator executable and the generator.yml configuration file. This is to avoid name space collisions
in the MIB definition. Keep only the required MIBS in the mibs directory for the devices.
Then merge all the resulting snmp.yml files into one main file that will be used by the snmp_exporter collector.

## Running

```sh
make generate
```

The generator reads in the simplified collection instructions from `generator.yml` and writes to `snmp.yml`. Only the snmp.yml file is used
by the snmp_exporter executable to collect data from the snmp enabled devices.

Additional command are available for debugging, use the `help` command to see them.

After building, you can pass a directories of mibs, a path to the `generator.yml`
file and the intended path of your output file e.g. `snmp.yml` to the `generate`
command like so,
```bash
./generator generate \
  -m /tmp/deviceFamilyMibs \
  -m /tmp/sharedMibs \
  -g /tmp/generator.yml \
  -o /tmp/snmp.yml
```

### MIB Parsing options

The parsing of MIBs can be controlled using the `--snmp.mibopts` flag. The available values depend on the net-snmp version used to build the generator.

Example from net-snmp 5.9.1:

```
Toggle various defaults controlling MIB parsing:
  u:  allow the use of underlines in MIB symbols
  c:  disallow the use of "--" to terminate comments
  d:  save the DESCRIPTIONs of the MIB objects
  e:  disable errors when MIB symbols conflict
  w:  enable warnings when MIB symbols conflict
  W:  enable detailed warnings when MIB symbols conflict
  R:  replace MIB symbols from latest module
```

## Docker Users

If you would like to run the generator in docker to generate your `snmp.yml` config run the following commands.

The Docker image expects a directory containing the `generator.yml` and a directory called `mibs` that contains all MIBs you wish to use.

This example will generate the example `snmp.yml` which is included in the top level of the snmp_exporter repo:

```sh
make docker-generate
```

## File Format

`generator.yml` provides a list of auths and modules. Each module defines what to collect from a device type.
The simplest module is just a name and a set of OIDs to walk.

```yaml
auths:
  auth_name:
    version: 2  # SNMP version to use. Defaults to 2.
                # 1 will use GETNEXT, 2 and 3 use GETBULK.

    # Community string is used with SNMP v1 and v2. Defaults to "public".
    community: public

    # v3 has different and more complex settings.
    # Which are required depends on the security_level.
    # The equivalent options on NetSNMP commands like snmpbulkwalk
    # and snmpget are also listed. See snmpcmd(1).
    username: user  # Required, no default. -u option to NetSNMP.
    security_level: noAuthNoPriv  # Defaults to noAuthNoPriv. -l option to NetSNMP.
                                  # Can be noAuthNoPriv, authNoPriv or authPriv.
    password: pass  # Has no default. Also known as authKey, -A option to NetSNMP.
                    # Required if security_level is authNoPriv or authPriv.
    auth_protocol: MD5  # MD5, SHA, SHA224, SHA256, SHA384, or SHA512. Defaults to MD5. -a option to NetSNMP.
                        # Used if security_level is authNoPriv or authPriv.
    priv_protocol: DES  # DES, AES, AES192, AES256, AES192C, or AES256C. Defaults to DES. -x option to NetSNMP.
                        # Used if security_level is authPriv.
    priv_password: otherPass # Has no default. Also known as privKey, -X option to NetSNMP.
                             # Required if security_level is authPriv.
    context_name: context # Has no default. -n option to NetSNMP.
                          # Required if context is configured on the device.

modules:
  module_name:  # The module name. You can have as many modules as you want.
    # List of OIDs to walk. Can also be SNMP object names or specific instances.
    # Object names can be fully-qualified with the MIB name separated by `::`.
    walk:
      - 1.3.6.1.2.1.2              # Same as "interfaces"
      - "SNMPv2-MIB::sysUpTime"    # Same as "1.3.6.1.2.1.1.3"
      - 1.3.6.1.2.1.31.1.1.1.6.40  # Instance of "ifHCInOctets" with index "40"
      - 1.3.6.1.2.1.2.2.1.4        # Same as ifMtu (used for filter example)
      - bsnDot11EssSsid            # Same as 1.3.6.1.4.1.14179.2.1.1.1.2 (used for filter example)

    max_repetitions: 25  # How many objects to request with GET/GETBULK, defaults to 25.
                         # May need to be reduced for buggy devices.
    retries: 3   # How many times to retry a failed request, defaults to 3.
    timeout: 5s  # Timeout for each individual SNMP request, defaults to 5s.

    allow_nonincreasing_oids: false # Do not check whether the returned OIDs are increasing, defaults to false
                                    # Some agents return OIDs out of order, but can complete the walk anyway.
                                    # -Cc option of NetSNMP

    use_unconnected_udp_socket: false # Use a unconnected udp socket, defaults to false
                                      # Some multi-homed network gear isn't smart enough to send SNMP responses
                                      # from the address it received the requests on. To work around that,
                                      # we can open unconnected UDP socket and use sendto/recvfrom

    lookups:  # Optional list of lookups to perform.
              # The default for `keep_source_indexes` is false. Indexes must be unique for this option to be used.

      # If the index of a table is bsnDot11EssIndex, usually that'd be the label
      # on the resulting metrics from that table. Instead, use the index to
      # lookup the bsnDot11EssSsid table entry and create a bsnDot11EssSsid label
      # with that value.
      - source_indexes: [bsnDot11EssIndex]
        lookup: bsnDot11EssSsid
        drop_source_indexes: false  # If true, delete source index labels for this lookup.
                                    # This avoids label clutter when the new index is unique.

      # It is also possible to chain lookups or use multiple labels to gather label values.
      # This might be helpful to resolve multiple index labels to a proper human readable label.
      # Please be aware that ordering matters here.

      # In this example, we first do a lookup to get the `cbQosConfigIndex` as another label.
      - source_indexes: [cbQosPolicyIndex, cbQosObjectsIndex]
        lookup: cbQosConfigIndex
      # Using the newly added label, we have another lookup to fetch the `cbQosCMName` based on `cbQosConfigIndex`.
      - source_indexes: [cbQosConfigIndex]
        lookup: cbQosCMName

    overrides: # Allows for per-module overrides of bits of MIBs
      metricName:
        ignore: true # Drops the metric from the output.
        help: "string" # Override the generated HELP text provided by the MIB Description.
        name: "string" # Override the OID name provided in the MIB Description.
        regex_extracts:
          Temp: # A new metric will be created appending this to the metricName to become metricNameTemp.
            - regex: '(.*)' # Regex to extract a value from the returned SNMP walks's value.
              value: '$1' # The result will be parsed as a float64, defaults to $1.
          Status:
            - regex: '.*Example'
              value: '1' # The first entry whose regex matches and whose value parses wins.
            - regex: '.*'
              value: '0'
        datetime_pattern: # Used if type = ParseDateAndTime. Uses the strptime format (See: man 3 strptime)
        offset: 1.0 # Add the value to the same. Applied after scale.
        scale: 1.0 # Scale the value of the sample by this value.
        type: DisplayString # Override the metric type, possible types are:
                             #   gauge:   An integer with type gauge.
                             #   counter: An integer with type counter.
                             #   OctetString: A bit string, rendered as 0xff34.
                             #   DateAndTime: An RFC 2579 DateAndTime byte sequence. If the device has no time zone data, UTC is used.
                             #   ParseDateAndTime: Parse a DisplayString and return the timestamp. See datetime_pattern config option
                             #   NTPTimeStamp: Parse the NTP timestamp (RFC-1305, March 1992, Section 3.1) and return Unix timestamp as float.
                             #   DisplayString: An ASCII or UTF-8 string.
                             #   PhysAddress48: A 48 bit MAC address, rendered as 00:01:02:03:04:ff.
                             #   Float: A 32 bit floating-point value with type gauge.
                             #   Double: A 64 bit floating-point value with type gauge.
                             #   InetAddressIPv4: An IPv4 address, rendered as 192.0.0.8.
                             #   InetAddressIPv6: An IPv6 address, rendered as 0102:0304:0506:0708:090A:0B0C:0D0E:0F10.
                             #   InetAddress: An InetAddress per RFC 4001. Must be preceded by an InetAddressType.
                             #   InetAddressMissingSize: An InetAddress that violates section 4.1 of RFC 4001 by
                             #       not having the size in the index. Must be preceded by an InetAddressType.
                             #   EnumAsInfo: An enum for which a single timeseries is created. Good for constant values.
                             #   EnumAsStateSet: An enum with a time series per state. Good for variable low-cardinality enums.
                             #   Bits: An RFC 2578 BITS construct, which produces a StateSet with a time series per bit.

    filters: # Define filters to collect only a subset of OID table indices
      static: # static filters are handled in the generator. They will convert walks to multiple gets with the specified indices
              # in the resulting snmp.yml output.
              # the index filter will reduce a walk of a table to only the defined indices to get
              # If one of the target OIDs is used in a lookup, the filter will apply ALL tables using this lookup
              # For a network switch, this could be used to collect a subset of interfaces such as uplinks
              # For a router, this could be used to collect all real ports but not vlans and other virtual interfaces
              # Specifying ifAlias or ifName if they are used in lookups with ifIndex will apply to the filter to
              # all the OIDs that depend on the lookup, such as ifSpeed, ifInHcOctets, etc.
              # This feature applies to any table(s) OIDs using a common index
        - targets:
          - bsnDot11EssSsid
          indices: ["2","3","4"]  # List of interface indices to get

      dynamic: # dynamic filters are handed by the snmp exporter. The generator will simply pass on the configuration in the snmp.yml.
               # The exporter will do a snmp walk of the oid and will restrict snmp walk made on the targets
               # to the index matching the value in the values list.
               # This would be typically used to specify a filter for interfaces with a certain name in ifAlias, ifSpeed or admin status.
               # For example, only get interfaces that a gig and faster, or get interfaces that are named Up or interfaces that are admin Up
        - oid: 1.3.6.1.2.1.2.2.1.7
          targets:
            - "1.3.6.1.2.1.2.2.1.4"
          values: ["1", "2"]
```

### EnumAsInfo and EnumAsStateSet

SNMP contains the concept of integer indexed enumerations (enums). There are two ways
to represent these strings in Prometheus. They can be "info" metrics, or they can be
"state sets". SNMP does not specify which should be used, and it's up to the use case
of the data. Some users may also prefer the raw integer value, rather than the string.

In order to set enum integer to string mapping, you must use one of the two overrides.

`EnumAsInfo` should be used for properties that provide inventory-like data. For example
a device type, the name of a colour etc. It is important that this value is constant.

`EnumAsStateSet` should be used for things that represent state or that you might want
to alert on. For example the link state, is it up or down, is it in an error state,
whether a panel is open or closed etc. Please be careful to not use this for high
cardinality values as it will generate 1 time series per possible value.

## Where to get MIBs

Some of these are quite sluggish, so use wget to download.

Put the extracted mibs in a location NetSNMP can read them from. `$HOME/.snmp/mibs` is one option.

* Cisco: ftp://ftp.cisco.com/pub/mibs/v2/v2.tar.gz
* APC: https://download.schneider-electric.com/files?p_File_Name=powernet432.mib
* Servertech: ftp://ftp.servertech.com/Pub/SNMP/sentry3/Sentry3.mib
* Palo Alto PanOS 7.0 enterprise MIBs: https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/zip/technical-documentation/snmp-mib-modules/PAN-MIB-MODULES-7.0.zip
* Arista Networks: https://www.arista.com/assets/data/docs/MIBS/ARISTA-ENTITY-SENSOR-MIB.txt
                   https://www.arista.com/assets/data/docs/MIBS/ARISTA-SW-IP-FORWARDING-MIB.txt
                   https://www.arista.com/assets/data/docs/MIBS/ARISTA-SMI-MIB.txt
* Synology: https://global.download.synology.com/download/Document/Software/DeveloperGuide/Firmware/DSM/All/enu/Synology_MIB_File.zip
* MikroTik: http://download2.mikrotik.com/Mikrotik.mib
* UCD-SNMP-MIB (Net-SNMP): http://www.net-snmp.org/docs/mibs/UCD-SNMP-MIB.txt
* Ubiquiti Networks: http://dl.ubnt-ut.com/snmp/UBNT-MIB
                     http://dl.ubnt-ut.com/snmp/UBNT-UniFi-MIB
                     https://dl.ubnt.com/firmwares/airos-ubnt-mib/ubnt-mib.zip

https://github.com/librenms/librenms/tree/master/mibs can also be a good source of MIBs.

http://oidref.com is recommended for browsing MIBs.
