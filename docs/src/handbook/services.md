# Services

`set services …` configures the box-wide network services. (SSH lives here too,
but is documented with [System & management](system.md#ssh-daemon).)

## DNS (LAN resolver)

A forwarding resolver (dnsmasq) for the LAN, with split-horizon overrides and
ad/tracker blocklists.

| Field | Meaning |
|---|---|
| `upstream` | Upstream resolvers to forward to (comma-separated). |
| `serve-on` | Interfaces to listen on for LAN queries. |
| `host-override <name> <ip>` | A local DNS record (split-horizon). |
| `blocklist <domain>` | Sinkhole a domain (ad/tracker/malware blocking). |
| `dnssec` | `yes` / `no` / `allow-downgrade`. |
| `cache-size` | Max cached answers. |
| `local-domain` | Site local domain. |

```text
set services dns upstream 9.9.9.9,1.1.1.1
set services dns serve-on eth1
set services dns host-override nas.home 10.0.0.5
set services dns blocklist ads.example.com
```

## NTP server

```text
set services ntp upstream pool.ntp.org
set services ntp serve-on eth1
```

`upstream` = the sources the box syncs to; `serve-on` = the interfaces whose
subnet may query the box.

## LLDP, SNMP, mDNS

| Service | Fields |
|---|---|
| `lldp` | `enable`, `interface` (comma-separated; omit = all). |
| `snmp` | `community` (v2c read-only secret), `listen`, `location`, `contact`, `allow` (source CIDRs). |
| `mdns` | `interface` (≥2 interfaces to reflect Bonjour/mDNS between). |

```text
set services lldp enable true
set services snmp community s3cret
set services snmp allow 10.0.0.0/24
set services mdns interface eth1,eth2
```

## Dynamic DNS

Keep a hostname's record current (ddclient).

| Field | Meaning |
|---|---|
| `provider` | ddclient protocol: `dyndns2` (default), `cloudflare`, `duckdns`, `noip`. |
| `server` | The provider's update endpoint host. |
| `hostname` | The FQDN to keep up to date. |
| `login` / `password` | Account login / password or API token (secret). |
| `interface` | Interface whose address to publish (else the detected web IP). |

```text
set services dyndns provider cloudflare
set services dyndns hostname fw.example.com
set services dyndns login user@example.com
set services dyndns password <api-token>
```

## DHCP relay

Relay DHCP from a client subnet to an upstream server (when the server isn't on
the box).

```text
set services dhcp-relay interface eth1,eth0     # client + upstream links
set services dhcp-relay server 10.0.100.10
```

## Reverse proxy / L7 load balancer

`services reverse-proxy <name>` terminates a listen port (optionally with TLS
from the [on-box PKI](vpn.md#pki)) and forwards to one or more backends
(round-robin).

| Field | Meaning |
|---|---|
| `port` | Listen port (default 443). |
| `certificate` | TLS termination cert — a `pki certificate` name (omit ⇒ plain HTTP). |
| `backends` | Upstream `host:port` targets (round-robin; repeatable). |
| `disabled` | Administratively disable this frontend. |

```text
set services reverse-proxy web port 443
set services reverse-proxy web certificate site-cert
set services reverse-proxy web backends 10.0.0.10:8080,10.0.0.11:8080
```
