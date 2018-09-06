FROM golang:latest

RUN sed -i 's/main$/main non-free/' /etc/apt/sources.list # Enable the non-free repository
RUN apt-get update && apt-get install -y libsnmp-dev snmp-mibs-downloader

RUN go get github.com/prometheus/snmp_exporter/generator
RUN cd /go/src/github.com/prometheus/snmp_exporter/generator \
    go get -v . && \
    go install

# Move the default generator file to the expected location
RUN cp /go/src/github.com/prometheus/snmp_exporter/generator/generator.yml /opt/

WORKDIR "/opt"

ENTRYPOINT ["/go/bin/generator"]

CMD ["generate"]
