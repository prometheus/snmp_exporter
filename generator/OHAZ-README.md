# OHAZ Readme

For general information about the generator as provided by Prometheus, read the regular README.md.

# OHAZ special procedure

To use the Generator for OHAZ's customized 'generator.yml', we must add MIBs from a private repository.

## Private MIBs

This problem exists because some of the MIBs we use are downloaded from behind logins or privately provided by manufacturers. These are not necessarily public or acceptable for committing to our public Github repo.

These MIBs are stored in the `ohaz-soh` repository under `snmpGenFiles`.

To deploy our fully customized SNMP config, copy the files from the `ohaz-soh` repository into the `mibs` directory here before running `make generate`.
