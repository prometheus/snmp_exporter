
# SNMP Exporter Config Generator Tutorial

This tutorial explains how to config `generator.yml` uses NetSNMP to parse MIBs which we indeed required, and generates `snmp.yml` config for the snmp_exporter using them.

## Build the generator bundle

```
sudo apt-get install build-essential libsnmp-dev snmp-mibs-downloader  # Debian-based distros
go get github.com/prometheus/snmp_exporter/generator
cd ${GOPATH-$HOME/go}/src/github.com/prometheus/snmp_exporter/generator
go build
```

## Preparing MIBs

For example, if we want to scrape `hwCpuDevTable` metrics, we could use the [HUAWEI-CPU MIB](https://github.com/librenms/librenms/blob/master/mibs/huawei/HUAWEI-CPU#L26).

As the MIB shown, `hwCpuDevTable` has some imports, they're:

* `hwDev` from `HUAWEI-MIB`;
* `hwFrameIndex`, `hwSlotIndex` from `HUAWEI-DEVICE-MIB`;
*  `OBJECT-GROUP`, `MODULE-COMPLIANCE` from `SNMPv2-CONF`;
*  `Gauge`, `OBJECT-TYPE`, `MODULE-IDENTITY` from `SNMPv2-SMI`.

Dependencies could be found in [HUAWEI-MIB](https://github.com/librenms/librenms/blob/master/mibs/huawei/HUAWEI-MIB), [HUAWEI-DEVICE-MIB](https://github.com/librenms/librenms/blob/master/mibs/huawei/HUAWEI-DEVICE), [IF-MIB](https://github.com/librenms/librenms/blob/master/mibs/IF-MIB)(as SNMPv2-SMI, SNMPv2-CONF is from that). BTW, don't forget the `HUAWEI-CPU` MIB itself.

Put the `HUAWEI-MIB`, `HUAWEI-DEVICE-MIB`, `IF-MIB`, `HUAWEI-CPU` in a location NetSNMP can read them from. `$HOME/.snmp/mibs` is one option.

## Preparing generator.yml

As we need to scrape `hwCpuDevTable`, our generator.yml would be:

```
modules:
# we need to generate hwCpuDevTable metrics.
  huawei:
    walk: [hwCpuDevTable]
```

## Running

```
./generator generate
```

The generator reads in from `generator.yml` and writes to `snmp.yml`. In our case, the output `snmp.yml` would be:

```
huawei:
  walk:
  - 1.3.6.1.4.1.2011.6.3.4
  metrics:
  - name: hwCpuDevIndex
    oid: 1.3.6.1.4.1.2011.6.3.4.1.1
    type: gauge
    indexes:
    - labelname: hwFrameIndex
      type: gauge
    - labelname: hwSlotIndex
      type: gauge
    - labelname: hwCpuDevIndex
      type: gauge
  - name: hwCpuDevDuty
    oid: 1.3.6.1.4.1.2011.6.3.4.1.2
    type: gauge
    indexes:
    - labelname: hwFrameIndex
      type: gauge
    - labelname: hwSlotIndex
      type: gauge
    - labelname: hwCpuDevIndex
      type: gauge
  - name: hwAvgDuty1min
    oid: 1.3.6.1.4.1.2011.6.3.4.1.3
    type: gauge
    indexes:
    - labelname: hwFrameIndex
      type: gauge
    - labelname: hwSlotIndex
      type: gauge
    - labelname: hwCpuDevIndex
      type: gauge
  - name: hwAvgDuty5min
    oid: 1.3.6.1.4.1.2011.6.3.4.1.4
    type: gauge
    indexes:
    - labelname: hwFrameIndex
      type: gauge
    - labelname: hwSlotIndex
      type: gauge
    - labelname: hwCpuDevIndex
      type: gauge
```

Now we get the `snmp.yml`, and additional auth message would be required if there is.
