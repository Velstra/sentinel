# Firewall & NAT

Sentinel's firewall is **zone-based** and enforced in the eBPF/XDP data plane.
Every firewalled interface belongs to a *zone*; posture (stateful, ICMP,
default action) is set globally and overridden per zone; and `rule`s open
specific proto/port/source between zones. NAT (masquerade, port-forward,
NAT64, NPTv6) lives under `nat`.

## Zones & posture

A zone is just a name you assign to interfaces (`set interface eth0 zone wan`).
`firewall global` sets the defaults every zone inherits; `firewall zone <name>`
overrides them for one zone.

| Field (`global` / `zone <name>`) | Meaning |
|---|---|
| `default-action` | Default ingress action: `accept` / `drop` / `reject`. |
| `stateful` | Track flows so return traffic is allowed (`true`/`false`). |
| `block-icmp` | Drop inbound ICMP by default (`true`/`false`). |
| `log` | Log matched traffic by default (`true`/`false`). |
| `block <IP\|CIDR>` | Drop a source everywhere (`global`) or on one zone. |
| `description` | (zone only) free-text label. |

```text
set firewall global default-action drop        # deny by default
set firewall global stateful true
set firewall zone wan block-icmp true          # quiet on the WAN
set firewall zone lan default-action accept    # trust the LAN
```

## Rules

`firewall rule <name>` is a zone-to-zone allow/deny. A rule with a `proto` +
`port` is a specific service rule; a broad rule (`from`/`to`/`action` only)
sets a zone-pair posture.

| Field | Meaning |
|---|---|
| `from` | Ingress zone the rule applies on. |
| `to` | Destination zone — matched as that zone's subnets (see below). |
| `action` | `accept` / `drop` / `reject`. |
| `proto` | `tcp` / `udp`. |
| `port` | Destination port or range (`443`, `8000-8100`). |
| `source` | Source address/CIDR (default: any). |
| `destination` | Destination address/CIDR (default: any). |
| `source-group` / `destination-group` / `port-group` | Match an [alias](#groups-aliases) instead. |
| `limit` / `burst` | Rate-limit the new flows this rule admits (see below). |
| `log` | Log packets matching this rule (`true`/`false`). |
| `schedule` | A time-based activation window (see below). |
| `description` / `disabled` | Label / administratively disable. |

```text
# Allow HTTPS from the WAN to a published service:
set firewall rule https-in from wan
set firewall rule https-in to lan
set firewall rule https-in proto tcp
set firewall rule https-in port 443
set firewall rule https-in action accept

# Let the LAN out, except to one network:
set firewall rule no-lab from lan
set firewall rule no-lab proto tcp
set firewall rule no-lab port 443
set firewall rule no-lab action drop
set firewall rule no-lab destination 192.168.4.0/24
```

### The destination zone

On a port rule, `to <zone>` is enforced by matching **that zone's subnets** as the
destination — the data plane matches addresses, not zone names. Two cases it
cannot cover, and a commit warns about each:

- **The rule already constrains its source.** A rule matches one address end, and
  an explicit `source` is the narrower, operator-written one, so it keeps that end
  and `to` stays documentation. Split the rule if the destination zone must bind.
- **The destination zone has no statically addressed interface** (all DHCP, or
  unaddressed). There is no subnet to match, so the rule applies toward every zone.

On a *broad* rule (no proto/port) `to` never narrows anything: a broad rule sets
its from-zone's ingress posture, which applies toward every destination. Give the
rule a proto/port to make the destination zone enforceable.

A rule constrains **one end**: a `source` (or `source-group`) or a
`destination` (or `destination-group`), never both. The data plane ranks each
end in its own longest-prefix table, and a rule can only sit in one of them, so
one naming both ends would enforce half of what it says. A commit refuses it and
tells you to split it in two.

Across both ends, **the more specific rule wins** — a `/24` destination beats a
`/8` source on the same port. Where two matching rules are equally specific the
denying one wins, so the outcome never depends on which table was consulted
first.

### Rate limits

`limit <n>` caps how many **new flows** an accept rule admits per second; `burst`
sizes how much idle time it may bank, defaulting to one second's worth of the
limit.

```text
set firewall rule ssh-in from wan
set firewall rule ssh-in proto tcp
set firewall rule ssh-in port 22
set firewall rule ssh-in action accept
set firewall rule ssh-in limit 5
set firewall rule ssh-in burst 10
```

Established connections are never metered — the limit bounds how fast new
connections are accepted, not how fast an accepted one may transfer. Excess is
dropped rather than rejected: answering every excess packet would turn a flood
aimed at the box into a flood aimed at whatever source the packets claim.
`show firewall statistics` counts them under `dropped_rate_limit`, separately from
`dropped_rule`, so a limit biting is distinguishable from a rule denying.

A limit is refused on anything it could not throttle — a `drop`/`reject` rule, or a
broad rule with no proto/port — rather than accepted and quietly ignored.

### Time-based rules

A rule may carry a weekly local-time schedule; it is only in force while its
window is open (a systemd timer re-applies at the boundaries).

```text
set firewall rule guest-wifi from guest
set firewall rule guest-wifi proto tcp
set firewall rule guest-wifi port 0-65535
set firewall rule guest-wifi action accept
set firewall rule guest-wifi schedule days mon,tue,wed,thu,fri
set firewall rule guest-wifi schedule start 09:00
set firewall rule guest-wifi schedule end 17:00
```

## IPv6 and extension headers

Rules apply to both families: the same `proto` + `port` match is evaluated for IPv4
and IPv6 packets against the same zone policy. (A rule's `source` CIDR is IPv4-only
today, so a v6 packet is matched only by the source-less rules for its zone.)

For IPv6 the data plane **walks the extension-header chain** (RFC 8200) to find the
real upper-layer protocol before matching. That matters because the alternative is a
bypass: classifying by the fixed header's next-header alone means a Hop-by-Hop or
Destination-Options header placed in front of TCP reads as an unknown protocol with
no ports, so no port rule matches — and under `default-action accept` such a packet
would simply pass. Up to eight headers are followed; a longer or truncated chain
matches no rule and therefore falls to the zone's default action.

Behind a **non-first fragment** the protocol is still resolved, but ports are not
read — those bytes are payload, and treating them as a TCP header would hand an
attacker a fragmentation bypass instead. Port-specific rules therefore do not match
a non-first fragment; protocol-level rules and the default action still do.

`nix build .#checks.x86_64-linux.v6exthdr -L` verifies this on two VMs, with a
separate destination port per variant so plain, single-header and chained packets can
be told apart in the log.

## Groups (aliases)

Named address / port sets you reference from rules, so one edit updates every
rule that uses them.

```text
set firewall group address-group admins address 10.0.0.10,10.0.0.11
set firewall group port-group web port 80,443,8443

set firewall rule mgmt from lan
set firewall rule mgmt proto tcp
set firewall rule mgmt source-group admins
set firewall rule mgmt port-group web
set firewall rule mgmt action accept
```

### Domain groups

A domain group holds **DNS names**, resolved to addresses at commit time and
re-resolved every 15 minutes. Rules reference it through the same
`source-group` / `destination-group` field as an address group — the names share
one namespace, so a group cannot exist as both.

```text
set firewall group domain-group trackers domain ads.example.com,metrics.example.net

set firewall rule no-trackers from lan
set firewall rule no-trackers proto tcp
set firewall rule no-trackers port 443
set firewall rule no-trackers action drop
set firewall rule no-trackers destination-group trackers
```

Only IPv4 answers are used — the rule tables match IPv4 addresses — and each
becomes a `/32`.

**A failed lookup keeps the last good answer.** The resolved addresses are cached
on disk, and a name that will not resolve falls back to its cache rather than
contributing nothing. That matters because a domain group usually *blocks*
something: an empty group matches nothing, and a rule that blocks nothing allows
everything. A DNS outage must not quietly undo the rule. A name that has never
resolved does contribute nothing, and says so at commit.

This tracks a name, not a service. A large site behind many rotating addresses, or
one sharing an address with sites you do not mean to match, is a poor fit — for
DNS-level blocking use `service dns` blocklists instead.

## NAT

`nat` has four kinds of translation:

| Node | What it does |
|---|---|
| `source` | SNAT / masquerade a zone's outbound traffic (the classic WAN NAT). |
| `destination` | Inbound DNAT port-forward to an internal host. |
| `nat64` | Stateful IPv6→IPv4 translation (tayga) + DNS64 (unbound). |
| `npt66` | Stateless IPv6 prefix translation (RFC 6296, checksum-neutral). |

### Source NAT (masquerade)

```text
set nat source wan-masq zone wan            # masquerade everything leaving wan
```

### Destination NAT (port-forward)

| Field | Meaning |
|---|---|
| `zone` | Ingress zone (the public side). |
| `proto` | `tcp` / `udp`. |
| `port` | Public destination port. |
| `to` | Internal target `ip` or `ip:port`. |
| `hairpin` | NAT reflection — reach the service via the public IP from inside. |

```text
set nat destination web zone wan
set nat destination web proto tcp
set nat destination web port 443
set nat destination web to 10.0.0.10:8443
set nat destination web hairpin true
```

### NAT64 / NPTv6

```text
set nat nat64 enabled true
set nat nat64 prefix 64:ff9b::/96
set nat nat64 pool 100.64.0.0/24
set nat nat64 interface eth1
set nat nat64 dns64 true
```

`npt66` maps an internal ULA prefix to a delegated external prefix statelessly —
configured per interface via `[nat.npt66]` (internal ↔ external `/48`s); see
`show nat`.

## Load-balanced services

`load-balancer` is its own top-level node — a virtual address in front of a
backend pool, translated in the XDP data plane rather than by a userspace proxy.

| Field | Meaning |
|---|---|
| `zone` | Ingress zone clients arrive from; the service is keyed under its policy. |
| `vip` | The virtual address clients connect to. |
| `proto` | `tcp` / `udp`. |
| `port` | The virtual port clients connect to. |
| `backend` | A pool member, `ip` (keep the client's port) or `ip:port`. Repeat to add. |

```text
set load-balancer web zone wan
set load-balancer web vip 203.0.113.10
set load-balancer web proto tcp
set load-balancer web port 443
set load-balancer web backend 10.0.0.11:8443
set load-balancer web backend 10.0.0.12
```

Committing a service **opens the firewall for its port** in that zone (a visible
`pass` rule an explicit rule of your own overrides), and only one service may
hold a given `(zone, proto, port)`. The pool normally lives on an internal zone,
so a backend's reply arrives on a different zone than the request did; the data
plane rewrites it back to the VIP either way.

> **The internal zone must permit its own outbound traffic.** A backend's reply
> is, to the firewall, an ordinary outbound packet from the internal zone. If
> that zone denies by default and no rule admits the direction, the reply is
> dropped and the client sees a connection that opens and then stalls. The same
> applies to a port-forward's internal host.

See
[Load balancer](../operations/configure.md) for the full surface, and
`services reverse-proxy` when you need TLS termination or HTTP-aware routing
instead.
