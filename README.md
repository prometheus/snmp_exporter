# SNMP Collector

`snmp_collector` actively polls an inventory of SNMP devices and sends the
resulting samples to a Prometheus Remote Write compatible endpoint. It does not
provide the pull-based `/snmp` exporter endpoint.

The polling and PDU conversion core is derived from
[`prometheus/snmp_exporter`](https://github.com/prometheus/snmp_exporter), so
the generated `snmp.yml` format and generator remain compatible.

## Configuration

The collector requires all three configuration layers:

- `snmp.yml` and optional additional `--config.file` files define modules and
  SNMP authentication profiles.
- `devices.yml` defines device addresses, profiles, authentication, schedules,
  and custom labels.
- `outputs.yml` defines the active Remote Write destination and queue.

Example device:

```yaml
devices:
  - id: core-switch-01
    address: udp://10.10.10.1:161
    profile: if_mib
    auth: site_v3
    interval: 60s
    timeout: 45s
    enabled: true
    labels:
      site: dc01
      role: core
```

Every output series automatically receives `device_id` and `device_ip` labels.
The `device_ip` value is extracted from the inventory address without the
transport or port.

## Build

Go 1.25 or newer is required. The release tooling uses the Go version declared
in `.promu.yml`.

```sh
go build -o bin/snmp_collector .
go test ./...
```

The Prometheus release tooling is also available:

```sh
make build
```

## Validate configuration

Both `--inventory.file` and `--output.file` are mandatory.
Copy `auth.example.yml` to the ignored `auth.yml`, set the referenced
environment variables, and enable environment expansion.

```sh
./bin/snmp_collector \
  --config.file=snmp.yml \
  --config.file=auth.yml \
  --config.expand-environment-variables \
  --inventory.file=devices.yml \
  --output.file=outputs.yml \
  --dry-run
```

## Run

```sh
./bin/snmp_collector \
  --config.file=snmp.yml \
  --config.file=auth.yml \
  --config.expand-environment-variables \
  --inventory.file=devices.yml \
  --output.file=outputs.yml
```

The operational HTTP server listens on `:9116` by default.

| Endpoint | Purpose |
|---|---|
| `/metrics` | Internal collector, scheduler, Go runtime, and output metrics |
| `/-/healthy` | Liveness check |
| `/readyz` | Output pipeline readiness check |
| `POST /-/reload` | Reload profiles, authentication, inventory, and output |

The device metrics themselves are sent through Remote Write; they are not
served by `/metrics`. The removed `/snmp` and `/config` endpoints return 404.

## Reload

Reload all configuration without restarting:

```sh
curl -X POST http://localhost:9116/-/reload
```

Sending `SIGHUP` performs the same operation. The collector parses and
validates all files, prepares the replacement output, reconciles the scheduler,
and then activates the new output. Validation, output startup, or scheduler
reconciliation failures leave the previous runtime active.

## Container

The image expects `devices.yml` and `outputs.yml` to be mounted at runtime;
site credentials should not be baked into an image.

```sh
docker run --rm -p 9116:9116 \
  -v "$PWD/devices.yml:/etc/snmp_collector/devices.yml:ro" \
  -v "$PWD/outputs.yml:/etc/snmp_collector/outputs.yml:ro" \
  -v "$PWD/auth.yml:/etc/snmp_collector/auth.yml:ro" \
  snmp-collector:local \
  --config.file=/etc/snmp_collector/snmp.yml \
  --config.file=/etc/snmp_collector/auth.yml \
  --config.expand-environment-variables \
  --inventory.file=/etc/snmp_collector/devices.yml \
  --output.file=/etc/snmp_collector/outputs.yml
```

## Generating profiles

The checked-in `snmp.yml` covers common hardware. To add vendor MIBs or change
walked objects, use the generator under [`generator/`](generator/README.md).
