FROM golang:alpine as builder
WORKDIR /app
RUN apk update && apk upgrade && apk add --no-cache ca-certificates
RUN update-ca-certificates

FROM scratch

COPY snmp_exporter /
COPY snmp.yml       /snmp.yml
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE      9116
ENTRYPOINT  [ "/snmp_exporter" ]
CMD         [ "--config.file=/snmp.yml" ]
