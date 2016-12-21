
# SNMP Exporter Config Generator

This config generator uses NetSNMP to parse MIBs, and generates configs for the snmp_exporter using them.

## Building

```
sudo apt-get install build-essential libsnmp-dev snmp-mibs-downloader  # Debian-based distros
go build
```

## Running

```
./generator
```

The generator reads in from `generator.yml` and writes to `snmp.yml`.

## Where to get MIBs

Some of these are quite sluggish, so use wget to download.

Put the extracted mibs in a location NetSNMP can read them from. `$HOME/.snmp/mibs` is one option.

* Cisco: ftp://ftp.cisco.com/pub/mibs/v2/v2.tar.gz
* APC: ftp://ftp.apc.com/apc/public/software/pnetmib/mib/419/powernet419.mib
