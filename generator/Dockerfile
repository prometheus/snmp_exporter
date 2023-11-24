FROM golang:bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends libsnmp-dev

ARG REPO_TAG=main
RUN go install github.com/prometheus/snmp_exporter/generator@"$REPO_TAG"

FROM debian:bookworm-slim

WORKDIR "/opt"

ENTRYPOINT ["/bin/generator"]

ENV MIBDIRS=mibs

CMD ["generate"]

RUN apt-get update \
    && apt-get install -y --no-install-recommends libsnmp40 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /go/bin/generator /bin/generator
