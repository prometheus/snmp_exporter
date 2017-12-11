FROM golang:latest

RUN apt-get update && apt-get install -y libsnmp-dev

# Pull published snmp_exporter dependency so that we have access to
# shared code in the snmp_exporter project
RUN go get github.com/prometheus/snmp_exporter/generator

WORKDIR /go/src/github.com/prometheus/snmp_exporter/generator/

# Copy local generator directory so we can develop locally and test
COPY . .
RUN go get -v . && go install

# Move the default generator file to the expected location
RUN cp /go/src/github.com/prometheus/snmp_exporter/generator/generator.yml /opt/

WORKDIR "/opt"

ENTRYPOINT ["/go/bin/generator"]

CMD ["generate"]
