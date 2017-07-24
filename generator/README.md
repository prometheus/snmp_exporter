
# SNMP Exporter Config Generator

This config generator uses NetSNMP to parse MIBs, and generates configs for the snmp_exporter using them.

## Building

Due to the dynamic dependency on NetSNMP, you must build the generator yourself.

```
sudo apt-get install build-essential libsnmp-dev snmp-mibs-downloader  # Debian-based distros
go get github.com/prometheus/snmp_exporter/generator
cd ${GOPATH-$HOME/go}/src/github.com/prometheus/snmp_exporter/generator
go build
```

## Running

```
./generator generate
```

The generator reads in from `generator.yml` and writes to `snmp.yml`.

Additional command are available for debugging, use the `help` command to see them.

## File Format

`generator.yml` provides a list of modules. The simplest module is just a name
and a set of OIDs to walk.

```
modules:
  module_name:  # The module name. You can have as many modules as you want.
    walk:       # List of OIDs to walk. Can also be SNMP object names.
      - 1.3.6.1.2.1.2  # Same as "interfaces"

    version: 2  # SNMP version to use. Defaults to 2.
                # 1 will use GETNEXT, 2 and 3 use GETBULK.

    auth:
      # Community string is used with SNMP v1 and v2. Defaults to "public".
      community: public

      # v3 has different and more complex settings.
      # Which are required depends on the security_level.
      # The equivilent options on NetSNMP commands like snmpbulkwalk
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

    lookups:  # Optional list of lookups to perform.
              # This must only be used when the new index is unique.

      # If the index of a table is bsnDot11EssIndex, usually that'd be the label
      # on the resulting metrics from that table. Instead, use the index to
      # lookup the bsnDot11EssSsid table entry and create a bsnDot11EssSsid label
      # with that value.
      - old_index: bsnDot11EssIndex
        new_index: bsnDot11EssSsid
```

## Where to get MIBs

Some of these are quite sluggish, so use wget to download.

Put the extracted mibs in a location NetSNMP can read them from. `$HOME/.snmp/mibs` is one option.

* Cisco: ftp://ftp.cisco.com/pub/mibs/v2/v2.tar.gz
* APC: ftp://ftp.apc.com/apc/public/software/pnetmib/mib/421/powernet421.mib
* Fortinet: http://kb.fortinet.com/kb/documentLink.do?externalID=11607
* Servertech: ftp://ftp.servertech.com/Pub/SNMP/sentry3/Sentry3.mib
* Palo Alto PanOS 7.0 enterprise MIBs: https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/zip/technical-documentation/snmp-mib-modules/PAN-MIB-MODULES-7.0.zip
* Arista Networks: https://www.arista.com/assets/data/docs/MIBS/ARISTA-ENTITY-SENSOR-MIB.txt
                   https://www.arista.com/assets/data/docs/MIBS/ARISTA-SW-IP-FORWARDING-MIB.txt
                   https://www.arista.com/assets/data/docs/MIBS/ARISTA-SMI-MIB.txt
* Synology: http://dedl.synology.com/download/Document/MIBGuide/Synology_MIB_File.zip
* UCD-SNMP-MIB (Net-SNMP): http://www.net-snmp.org/docs/mibs/UCD-SNMP-MIB.txt

https://github.com/librenms/librenms/tree/master/mibs can also be a good source of MIBs.

http://oidref.com is recommended for browsing MIBs.


