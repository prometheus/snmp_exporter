FROM golang:latest

RUN apt-get update && \
    apt-get install -y libsnmp-dev p7zip-full && \
    go get github.com/prometheus/snmp_exporter/generator && \
    cd /go/src/github.com/prometheus/snmp_exporter/generator && \
    go get -v . && \
    go install

WORKDIR "/opt"

ENTRYPOINT ["/go/bin/generator"]

ENV MIBDIRS mibs

CMD ["generate"]
