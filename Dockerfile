ARG ARCH="amd64"
ARG OS="linux"
FROM quay.io/prometheus/busybox-${OS}-${ARCH}:latest
LABEL maintainer="The Prometheus Authors <prometheus-developers@googlegroups.com>"
LABEL org.opencontainers.image.authors="The Prometheus Authors"
LABEL org.opencontainers.image.vendor="Prometheus"
LABEL org.opencontainers.image.title="snmp_collector"
LABEL org.opencontainers.image.description="Active SNMP collector with remote-write output"
LABEL org.opencontainers.image.licenses="Apache License 2.0"
LABEL io.prometheus.image.variant="busybox"

ARG ARCH="amd64"
ARG OS="linux"
COPY .build/${OS}-${ARCH}/snmp_collector  /bin/snmp_collector
COPY snmp.yml       /etc/snmp_collector/snmp.yml
COPY LICENSE        /LICENSE
COPY NOTICE         /NOTICE


EXPOSE      9116
ENTRYPOINT  [ "/bin/snmp_collector" ]
CMD         [ "--config.file=/etc/snmp_collector/snmp.yml", "--inventory.file=/etc/snmp_collector/devices.yml", "--output.file=/etc/snmp_collector/outputs.yml" ]
