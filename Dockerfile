FROM scratch

COPY snmp_exporter /
COPY snmp.yml       /snmp_exporter.yml

EXPOSE      9116
ENTRYPOINT  [ "/bin/snmp_exporter" ]
CMD         [ "--config.file=/snmp.yml" ]
