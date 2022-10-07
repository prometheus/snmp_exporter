# syntax=docker/dockerfile:1.0.0-experimental


FROM 916869144969.dkr.ecr.us-east-1.amazonaws.com/customink/python:bionic

LABEL maintainer="The Prometheus Authors <prometheus-developers@googlegroups.com>"


# RUN apt update -y && \
#     apt install -y build-essential diffutils libsnmp-dev p7zip-full


ARG ARCH="amd64"
ARG OS="linux"
# COPY .build/${OS}-${ARCH}/snmp_exporter  /bin/snmp_exporter
# COPY snmp.yml       /etc/snmp_exporter/snmp.yml

EXPOSE      9116
ENTRYPOINT  [ "/bin/snmp_exporter" ]
CMD         [ "--config.file=/etc/snmp_exporter/snmp.yml" ]

RUN --mount=type=ssh