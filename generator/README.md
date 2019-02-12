
# SNMP Exporter Config Generator

This config generator uses NetSNMP to parse MIBs, and generates configs for the snmp_exporter using them.

## Building

Due to the dynamic dependency on NetSNMP, you must build the generator yourself.

```
# Debian-based distributions.
sudo apt-get install build-essential libsnmp-dev # Debian-based distros
# Redhat-based distributions.
sudo yum install gcc gcc-g++ make net-snmp net-snmp-utils net-snmp-libs net-snmp-devel # RHEL-based distros

go get github.com/prometheus/snmp_exporter/generator
cd ${GOPATH-$HOME/go}/src/github.com/prometheus/snmp_exporter/generator
go build
make mibs
```

## Running

```sh
export MIBDIRS=$HOME/.snmp/mibs:mibs:/usr/share/snmp/mibs
./generator generate
```

The generator reads in from `generator.yml` and writes to `snmp.yml`.

Additional command are available for debugging, use the `help` command to see them.

## Docker Users

If you would like to run the generator in docker to generate your `snmp.yml` config run the following commands.

```sh
docker build -t snmp-generator .
docker run -ti \
  -v $HOME/.snmp/mibs:/root/.snmp/mibs \
  -v $PWD/generator.yml:/opt/generator.yml:ro \
  -v $PWD/out/:/opt/ \
  snmp-generator generate
```

## File Format

`generator.yml` provides a list of modules. The simplest module is just a name
and a set of OIDs to walk.

```yaml
modules:
  module_name:  # The module name. You can have as many modules as you want.
    walk:       # List of OIDs to walk. Can also be SNMP object names or specific instances.
      - 1.3.6.1.2.1.2              # Same as "interfaces"
      - sysUpTime                  # Same as "1.3.6.1.2.1.1.3"
      - 1.3.6.1.2.1.31.1.1.1.6.40  # Instance of "ifHCInOctets" with index "40"

    version: 2  # SNMP version to use. Defaults to 2.
                # 1 will use GETNEXT, 2 and 3 use GETBULK.
    max_repetitions: 25  # How many objects to request with GET/GETBULK, defaults to 25.
                         # May need to be reduced for buggy devices.
    retries: 3   # How many times to retry a failed request, defaults to 3.
    timeout: 10s # Timeout for each walk, defaults to 10s.

    auth:
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
      auth_protocol: SHA  # MD5 or SHA, defaults to SHA. -a option to NetSNMP.
                          # Used if security_level is authNoPriv or authPriv.
      priv_protocol: DES  # DES or AES, defaults to DES. -x option to NetSNMP.
                          # Used if security_level is authPriv.
      priv_password: otherPass # Has no default. Also known as privKey, -X option to NetSNMP.
                               # Required if security_level is authPriv.
      context_name: context # Has no default. -n option to NetSNMP.
                            # Required if context is configured on the device.

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

     overrides: # Allows for per-module overrides of bits of MIBs
       metricName:
         ignore: true # Drops the metric from the output.
         regex_extracts:
           Temp: # A new metric will be created appending this to the metricName to become metricNameTemp.
             - regex: '(.*)' # Regex to extract a value from the returned SNMP walks's value.
               value: '$1' # The result will be parsed as a float64, defaults to $1.
           Status:
             - regex: '.*Example'
               value: '1'
             - regex: '.*'
               value: '0'
         type: DisplayString # Override the metric type, possible types are:
                             #   gauge:   An integer with type gauge.
                             #   counter: An integer with type counter.
                             #   OctetString: A bit string, rendered as 0xff34.
                             #   DateAndTime: An RFC 2579 DateAndTime byte sequence. If the device has no time zone data, UTC is used.
                             #   DisplayString: An ASCII or UTF-8 string.
                             #   PhysAddress48: A 48 bit MAC address, rendered as 00:01:02:03:04:ff.
                             #   Float: A 32 bit floating-point value with type gauge.
                             #   Double: A 64 bit floating-point value with type gauge.
                             #   InetAddressIPv4: An IPv4 address, rendered as 1.2.3.4.
                             #   InetAddressIPv6: An IPv6 address, rendered as 0102:0304:0506:0708:090A:0B0C:0D0E:0F10.
                             #   InetAddress: An InetAddress per RFC 4001. Must be preceded by an InetAddressType.
                             #   InetAddressMissingSize: An InetAddress that violates section 4.1 of RFC 4001 by
                             #       not having the size in the index. Must be preceded by an InetAddressType.
                             #   EnumAsInfo: An enum for which a single timeseries is created. Good for constant values.
                             #   EnumAsStateSet: An enum with a time series per state. Good for variable low-cardinality enums.
```

## Where to get MIBs

Some of these are quite sluggish, so use wget to download.

Put the extracted mibs in a location NetSNMP can read them from. `$HOME/.snmp/mibs` is one option.

* Cisco: ftp://ftp.cisco.com/pub/mibs/v2/v2.tar.gz
* APC: https://download.schneider-electric.com/files?p_File_Name=powernet426.mib
* Servertech: ftp://ftp.servertech.com/Pub/SNMP/sentry3/Sentry3.mib
* Palo Alto PanOS 7.0 enterprise MIBs: https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/zip/technical-documentation/snmp-mib-modules/PAN-MIB-MODULES-7.0.zip
* Arista Networks: https://www.arista.com/assets/data/docs/MIBS/ARISTA-ENTITY-SENSOR-MIB.txt
                   https://www.arista.com/assets/data/docs/MIBS/ARISTA-SW-IP-FORWARDING-MIB.txt
                   https://www.arista.com/assets/data/docs/MIBS/ARISTA-SMI-MIB.txt
* Synology: https://global.download.synology.com/download/Document/MIBGuide/Synology_MIB_File.zip
* MikroTik: http://download2.mikrotik.com/Mikrotik.mib
* UCD-SNMP-MIB (Net-SNMP): http://www.net-snmp.org/docs/mibs/UCD-SNMP-MIB.txt
* Ubiquiti Networks: http://dl.ubnt-ut.com/snmp/UBNT-MIB
                     http://dl.ubnt-ut.com/snmp/UBNT-UniFi-MIB
                     https://dl.ubnt.com/firmwares/airos-ubnt-mib/ubnt-mib.zip

https://github.com/librenms/librenms/tree/master/mibs can also be a good source of MIBs.

http://oidref.com is recommended for browsing MIBs.
