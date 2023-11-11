FROM golang:latest

ARG REPO_TAG=main
RUN apt-get update && \
    apt-get install -y libsnmp-dev unzip && \
    go install github.com/prometheus/snmp_exporter/generator@"$REPO_TAG"

WORKDIR "/opt"

ENTRYPOINT ["/go/bin/generator"]

ENV MIBDIRS mibs

CMD ["generate"]
