FROM golang:1.9.2

# snmp-mibs-downloader is in the multiverse
RUN echo "deb http://http.us.debian.org/debian stretch non-free" >> /etc/apt/sources.list

RUN apt-get update && apt-get install -y \
  build-essential \
  libsnmp-dev \
  snmp-mibs-downloader

RUN go get github.com/prometheus/snmp_exporter/generator

# Move the default generator file to the expected location
RUN cp /go/src/github.com/prometheus/snmp_exporter/generator/generator.yml /opt/
RUN cd /go/src/github.com/prometheus/snmp_exporter/generator && go install

WORKDIR "/opt"

# Run in a shell - redirect stdout to /dev/null and spit out the resulting config
CMD /go/bin/generator generate > /dev/null 2>&1 && cat /opt/snmp.yml
