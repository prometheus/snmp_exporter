# Prometheus SNMP Exporter
This project is from https://github.com/prometheus/snmp_exporter/ . But had some improve.

## Different
New feature: 
Filter: allow you set filters 
this will get target data that oid  1.3.6.1.2.1.31.1.1.1.6 notEquals 0 
```
    filters:
    - oid: 1.3.6.1.2.1.31.1.1.1.6
      operation: notEquals
      targets:
      - 1.3.6.1.2.1.31.1.1.1.6
      - 1.3.6.1.2.1.31.1.1.1.10
      - 1.3.6.1.2.1.2.2.1.8
      - 1.3.6.1.2.1.2.2.1.3
      values:
      - "0"
```
All you set : notEquals/equals/regNotEquals/regEquals


Generator:
```
    filters:
      dynamic:
      - targets:
        - ifHCInOctets
        - ifHCOutOctets
        - ifOperStatus
        - ifType
        oid: 1.3.6.1.2.1.31.1.1.1.6
        operation: notEquals
        values: ["0"]
```
