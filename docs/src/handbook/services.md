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
the box). Works for **IPv4** (`server`) and **IPv6** (`server6`) independently —
a link can relay either family or both.

```text
set services dhcp-relay interface eth1,eth0     # client + upstream links
set services dhcp-relay server  10.0.100.10     # IPv4 upstream (uses the link's giaddr)
set services dhcp-relay server6 2001:db8:100::10 # IPv6 upstream (or ff05::1:3, the relay multicast)
```

| Field | Meaning |
|---|---|
| `interface` | Interfaces to relay on — both the client-facing link(s) and the link toward the server. |
| `server` | Upstream DHCPv4 server(s). Each relay interface needs a static `address` (stamped as the giaddr). |
| `server6` | Upstream DHCPv6 server(s), or the well-known relay multicast `ff05::1:3`. Each relay interface needs a static `address6`. |

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

## Remote syslog

`services syslog target <host>` ships the appliance's journal to one or more
collectors as RFC 5424 syslog — what Graylog, rsyslog, syslog-ng and a SIEM all
speak. It **adds** a copy on the wire; the local journal is untouched, so losing
the collector never costs you the local log.

| Field | Meaning |
|---|---|
| `port` | Collector port (default 514). |
| `proto` | `udp` (default) or `tcp`. |
| `level` | Minimum severity — that level **and above** (default `info`). |

```text
set services syslog target 10.0.0.9
set services syslog target logs.example.com port 6514
set services syslog target logs.example.com proto tcp
set services syslog target logs.example.com level warning
```

A bare `target <host>` already forwards: every field has a working default.
Remove one collector with `delete services syslog target <host>`, or stop
forwarding entirely with `delete services syslog`.

Worth knowing:

- **`level` is a floor, not a match.** `warning` ships warning, err, crit, alert
  and emerg. `debug` ships everything the journal holds, which is rarely what you
  want on the wire.
- **A named collector is resolved by the appliance**, and a dual-stack name may
  resolve to either family — make sure the collector listens on the one it
  advertises.
- **UDP cannot report a failure.** A collector that is down loses those messages
  silently; `tcp` notices. Either way each target gets its own buffer, so a
  collector that stops answering never blocks the appliance's logging.
- The journal cursor is kept in `/var/lib/sentinel/rsyslog`, so a restart resumes
  where it left off instead of re-shipping the whole journal.
