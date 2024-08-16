FROM scratch

COPY snmp_exporter /
COPY snmp.yml       /snmp.yml

EXPOSE      9116
ENTRYPOINT  [ "/bin/snmp_exporter" ]
CMD         [ "--config.file=/snmp.yml" ]
