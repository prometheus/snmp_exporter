FROM golang as builder

ENV GOOS="linux"
ENV CGO_ENABLED=0

WORKDIR /snmp_exporter
COPY . .

RUN go build -v

FROM alpine

WORKDIR /src
COPY --from=builder /snmp_exporter/snmp_exporter /bin/snmp_exporter
RUN chmod +x /bin/snmp_exporter
COPY snmp.yml       /etc/snmp_exporter/snmp.yml

EXPOSE      9116
ENTRYPOINT  [ "/bin/snmp_exporter" ]
CMD         [ "--config.file=/etc/snmp_exporter/snmp.yml" ]
