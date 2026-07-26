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

## Alert notifications

`services alerts` is the opposite of remote syslog: syslog ships everything
somewhere for later, an alert tells a human *now*. The event it exists for is a
**failed unit** — an appliance whose data plane died still answers ping and still
answers SSH, so nothing reveals it until traffic is already broken.

The event source is **systemd**, via an `OnFailure=` drop-in Sentinel installs on
the units whose failure means the box stopped doing its job (the data plane, the
routing daemon, the DNS/DHCP/relay/VPN/proxy services). Not every unit: alerting
on the mDNS reflector would train you to ignore the alert.

```text
set services alerts webhook https://hooks.example.com/sentinel
set services alerts mail to noc@example.com
set services alerts mail relay smtp.example.com
set services alerts mail user fw@example.com
set services alerts mail password <secret>
```

A webhook receives a JSON body — `source`, `host`, `subject`, `detail` — where
`detail` is the failed unit's last journal lines, so the alert is actionable
without going to the box. `webhook` is repeatable; remove one with `delete
services alerts webhook <url>`.

| Mail field | Meaning |
|---|---|
| `to` | Recipient. Required to send. |
| `relay` | Smarthost to submit through. Required to send. |
| `from` | Envelope sender (default `sentinel@<hostname>`). |
| `port` | Submission port (default 587). |
| `user` / `password` | SMTP AUTH. The rendered msmtp config is 0600. |
| `starttls` | Encrypt the submission. Default **true**. |

Mail goes out through **msmtp**, a send-only client — the appliance never runs a
listening mail server.

Worth knowing:

- **Half a mail target is refused at commit.** A recipient with no relay, or a
  password with no user, would look configured and never deliver — and nobody goes
  looking for the alert that never arrived.
- **Credentials without STARTTLS are refused**, not warned about: submitting a
  relay password over a cleartext link hands it to anyone on the path.
- **Delivery is best-effort and never fails the box.** Every target is tried, one
  bad target does not stop the others, and the handler still exits successfully —
  a notification failure must not turn one broken service into a restart storm.
  What went wrong goes to the journal, which syslog forwarding then ships.
- `delete services alerts` removes the drop-ins again, so no handler is left
  pointing at an endpoint you no longer configured.

## Intrusion detection

Watch a link and raise an alert when traffic matches a rule (roadmap C11).

```
set services ids interface eth1
set services ids rule alert icmp any any -> $HOME_NET any (msg:"echo request from outside"; itype:8; sid:1000001; rev:1;)
```

The detector is **Suricata**, reading the named interfaces through AF_PACKET. It
sees traffic because the eBPF data plane ends an allowed packet on `XDP_PASS` and
lets the kernel route it — so the detector observes exactly what the firewall
admitted, which is the interesting half.

| Field | Meaning |
|---|---|
| `interface` | A link to watch. Repeatable. Nothing runs until one is set. |
| `home-net` | An address range that counts as inside. Default: the RFC 1918 blocks plus CGNAT space. |
| `rule` | One Suricata rule, written as the rest of the line. Repeatable. |
| `ruleset` | Absolute path to a rule file on the box. Repeatable. |

Rules written here are the rest of the command line, so no quoting is needed:

```
set services ids rule alert http any any -> any any (msg:"admin panel"; http.uri; content:"/admin"; sid:1000002; rev:1;)
```

A rule is **replaced by its sid**, so re-issuing one with the same `sid:` edits it
rather than adding a second — two rules sharing a sid stop Suricata loading
either. Delete by sid: `delete services ids rule 1000002`.

For a published ruleset (Emerging Threats, say), put the file on the box and name
it with `ruleset`; the configuration keeps the path, not megabytes of rules that
would immediately go stale.

### It detects, it does not block

Suricata can drop, but only in an IPS mode that needs NFQUEUE or an inline
AF_PACKET pair — either would put a second verdict stage behind the eBPF
firewall, and a packet could then vanish for a reason `show firewall` cannot
explain. Blocking stays with the data plane that owns the policy. A rule written
with `drop` or `reject` is **refused at commit** rather than accepted and quietly
ignored: use `alert`, and write a firewall rule for the block.

### Reading alerts

```
show ids                  # what is watched, and whether the detector runs
show ids alerts           # the 20 most recent
show ids alerts 100
```

Alerts go into the **journal**, so they rotate like everything else and reach a
SIEM through `services syslog` with no extra configuration.

Worth knowing:

- **An interface with no rules is refused at commit.** It would look exactly like
  a working detector from the outside and detect nothing.
- **A rule that Suricata would reject is refused too** — a missing `sid:`, a short
  header, an unknown action. Suricata refuses to start on a bad rule, so one typo
  would take down the whole ruleset rather than one line.
- **A `ruleset` path that does not exist is skipped with a warning**, and
  `show ids` marks it `MISSING`. Partial coverage from the rules that do load beats
  a detector that will not start.
- **`sentinel-ids.service` is alerted on** (see above), because a dead detector is
  the textbook silent failure: nothing looks wrong, and the absence of alerts reads
  as good news.
