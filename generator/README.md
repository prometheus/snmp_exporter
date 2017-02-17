
# SNMP Exporter Config Generator

This config generator uses NetSNMP to parse MIBs, and generates configs for the snmp_exporter using them.

## Building

```
sudo apt-get install build-essential libsnmp-dev snmp-mibs-downloader  # Debian-based distros
go build
```

## Running

```
./generator generate
```

The generator reads in from `generator.yml` and writes to `snmp.yml`.

Additional command are available for debugging, use the `help` command to see them.

## Where to get MIBs

Some of these are quite sluggish, so use wget to download.

Put the extracted mibs in a location NetSNMP can read them from. `$HOME/.snmp/mibs` is one option.

* Cisco: ftp://ftp.cisco.com/pub/mibs/v2/v2.tar.gz
* APC: ftp://ftp.apc.com/apc/public/software/pnetmib/mib/419/powernet419.mib
* Fortinet: http://kb.fortinet.com/kb/documentLink.do?externalID=11607
* Servertech: ftp://ftp.servertech.com/Pub/SNMP/sentry3/Sentry3.mib
* Palo Alto: https://www.paloaltonetworks.com/documentation/misc/snmp-mibs.html
* Palo Alto PanOS 7.1 enterprise MIBs: https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/zip/technical-documentation/snmp-mib-modules/PAN-MIB-MODULES-7.1.zip

https://github.com/librenms/librenms/tree/master/mibs can also be a good source of MIBs.

