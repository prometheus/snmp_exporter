# Sample SNMP configurations

Practical configuration samples for common setups. They use modules already
present in the default [`snmp.yml`](../../snmp.yml) (`if_mib`, `system`,
`hrSystem`, `hrStorage`, and others).

Authentication details for SNMPv1/v2c/v3 are also documented in the
[generator file format](../../generator/README.md#file-format).

## Architecture

```
Prometheus --HTTP--> snmp_exporter --SNMP (UDP/TCP 161)--> device
```

* Prometheus scrapes the exporter over HTTP(S).
* The exporter scrapes the target device over SNMP.
* **HTTP proxies (including Zscaler) do not carry SNMP.** Place
  `snmp_exporter` on a host that has direct IP reachability to the devices
  (management VRF/VLAN, DC network, VPN, or bastion with SNMP allowed).
* If Prometheus must reach the exporter through a corporate HTTP proxy, use
  Prometheus `proxy_url` on the scrape job. That only affects the
  Prometheus → exporter path.

## Scenario 1: Developer workstation (local SNMP agent)

Use this to exercise the exporter against a machine you control.

### Enable a local SNMP agent

**Linux (snmpd):**

```sh
# Debian/Ubuntu
sudo apt-get install snmpd snmp
# Allow localhost (and optionally your LAN) in /etc/snmp/snmpd.conf, e.g.:
#   rocommunity public 127.0.0.1
#   agentAddress udp:127.0.0.1:161
sudo systemctl enable --now snmpd
snmpwalk -v2c -c public 127.0.0.1 system
```

**macOS:**

Recent macOS releases no longer ship `snmpd`. Practical options:

1. Install Net-SNMP via Homebrew and run `snmpd` with a local `snmpd.conf`, or
2. Run a small SNMP agent in Docker for learning (example):

```sh
docker run --rm -p 1161:161/udp polinux/snmpd
# Then scrape target tcp://127.0.0.1:1161 or udp on 1161 depending on image.
```

Confirm with `snmpwalk` before wiring Prometheus.

### Scrape the workstation

1. Start the exporter with the default config:

   ```sh
   ./snmp_exporter --config.file=snmp.yml
   ```

2. Manual check (defaults: `auth=public_v2`, `module=if_mib`):

   ```sh
   curl 'http://localhost:9116/snmp?target=127.0.0.1&auth=public_v2&module=if_mib'
   # Host resources (when the agent implements HOST-RESOURCES-MIB):
   curl 'http://localhost:9116/snmp?target=127.0.0.1&auth=public_v2&module=hrSystem'
   curl 'http://localhost:9116/snmp?target=127.0.0.1&auth=public_v2&module=system'
   ```

3. Prometheus job: see [`prometheus-workstation.yml`](prometheus-workstation.yml).

Useful default modules for hosts: `system`, `if_mib`, `hrSystem`, `hrStorage`,
`hrDevice`. Prefer a read-only community or SNMPv3 on any shared network.

## Scenario 2: Routers and switches (work / lab network)

### Placement relative to proxies (Zscaler and similar)

Corporate HTTP/HTTPS proxies (Zscaler Internet Access, Blue Coat, etc.) sit on
web traffic. SNMP uses UDP (or TCP) to port 161 and is not tunneled through
those proxies.

Recommended pattern:

1. Run `snmp_exporter` in a network segment that can reach device management
   addresses (core/DC, OOB/management VRF, or jump host with SNMP permitted).
2. Point Prometheus at that exporter (`__address__` replacement). Use
   `proxy_url` only if *Prometheus* needs an HTTP proxy to reach the exporter.
3. Do not expect Zscaler (or similar) to “proxy SNMP” to switches/routers.

If devices are only reachable over a VPN, run the exporter on a host that is
joined to that VPN or management network.

### Auth and modules

Most switches/routers work with the built-in `if_mib` module. Start with a
read-only SNMPv2c community (`public_v2` in the default config), then move to
SNMPv3 where policy requires it.

Extra auth definitions (custom community + SNMPv3) live in
[`snmp-auth-samples.yml`](snmp-auth-samples.yml). Load them **in addition** to
the default modules file so you do not hand-edit `snmp.yml`:

```sh
./snmp_exporter \
  --config.file=snmp.yml \
  --config.file=examples/sample-configs/snmp-auth-samples.yml \
  --config.expand-environment-variables
```

`--config.expand-environment-variables` is only required when using the
`${ENV_…}` placeholders in the SNMPv3 sample.

Prometheus jobs: see [`prometheus-network-devices.yml`](prometheus-network-devices.yml).

Manual checks:

```sh
# SNMPv2c (default public_v2)
curl 'http://localhost:9116/snmp?target=192.0.2.10&auth=public_v2&module=if_mib'

# Custom community from snmp-auth-samples.yml
curl 'http://localhost:9116/snmp?target=192.0.2.10&auth=readonly_v2c&module=if_mib'

# SNMPv3 authPriv (set env vars first; see snmp-auth-samples.yml)
curl 'http://localhost:9116/snmp?target=192.0.2.10&auth=network_v3_authpriv&module=if_mib'

# TCP transport / non-default port
curl 'http://localhost:9116/snmp?target=tcp%3A%2F%2F192.0.2.10%3A1161&auth=public_v2&module=if_mib'
```

Vendor-specific modules (Cisco, Juniper, Arista, …) are listed in
[`snmp.yml`](../../snmp.yml). Use them only when the device supports the
underlying MIBs.

## Scenario 3: Generator auth snippets

When generating your own `snmp.yml`, define auths in `generator.yml` as
documented in [generator/README.md](../../generator/README.md#file-format).
Minimal examples:

```yaml
auths:
  public_v2:
    version: 2
    community: public

  readonly_v2c:
    version: 2
    community: readonly-community

  network_v3_authpriv:
    version: 3
    username: snmp-ro
    security_level: authPriv
    password: auth-secret
    auth_protocol: SHA
    priv_protocol: AES
    priv_password: priv-secret
```

Regenerate with the generator, then point the exporter at the produced
`snmp.yml`. Prefer environment-variable expansion for secrets in production
(see the main [README](../../README.md#prometheus-configuration)).

## Files in this directory

| File | Purpose |
|------|---------|
| [`snmp-auth-samples.yml`](snmp-auth-samples.yml) | Extra exporter auths (SNMPv2c + SNMPv3) |
| [`prometheus-workstation.yml`](prometheus-workstation.yml) | Prometheus scrape job for a local agent |
| [`prometheus-network-devices.yml`](prometheus-network-devices.yml) | Prometheus scrape jobs for network gear |

Replace example community strings, usernames, passwords, and addresses before
use in any shared environment.
