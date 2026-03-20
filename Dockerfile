ARG ARCH="amd64"
ARG OS="linux"
FROM quay.io/prometheus/busybox-${OS}-${ARCH}:latest
LABEL maintainer="The Prometheus Authors <prometheus-developers@googlegroups.com>"
LABEL org.opencontainers.image.authors="The Prometheus Authors"
LABEL org.opencontainers.image.vendor="Prometheus"
LABEL org.opencontainers.image.title="snmp_exporter"
LABEL org.opencontainers.image.description="Prometheus SNMP Exporter"
LABEL org.opencontainers.image.source="https://github.com/prometheus/snmp_exporter"
LABEL org.opencontainers.image.url="https://github.com/prometheus/snmp_exporter"
LABEL org.opencontainers.image.documentation="https://github.com/prometheus/snmp_exporter/blob/main/README.md"
LABEL org.opencontainers.image.licenses="Apache License 2.0"
LABEL io.prometheus.image.variant="busybox"

ARG ARCH="amd64"
ARG OS="linux"
COPY .build/${OS}-${ARCH}/snmp_exporter  /bin/snmp_exporter
COPY snmp.yml       /etc/snmp_exporter/snmp.yml
COPY LICENSE        /LICENSE
COPY NOTICE         /NOTICE


EXPOSE      9116
ENTRYPOINT  [ "/bin/snmp_exporter" ]
CMD         [ "--config.file=/etc/snmp_exporter/snmp.yml" ]
