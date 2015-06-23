# Prometheus SNMP Exporter

Work in progress

## Usage

`config` contains what OIDs to scrape and how to process them. It initially
supports enough for the standard interface stats.

Run `snmp_exporter.py`, and then visit http://localhost:9116/?address=1.2.3.4
where 1.2.3.4 is the IP of the SNMP device to get metrics.
