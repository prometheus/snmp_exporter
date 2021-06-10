FROM golang as builder

WORKDIR /snmp_exporter
COPY . .

RUN go build -v

FROM golang

WORKDIR /src
COPY --from=builder /snmp_exporter/snmp_exporter /bin/snmp_exporter
COPY snmp.yml       /etc/snmp_exporter/snmp.yml

EXPOSE      9116
ENTRYPOINT  [ "/bin/snmp_exporter" ]
CMD         [ "--config.file=/etc/snmp_exporter/snmp.yml" ]
