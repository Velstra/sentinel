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
| `source-validation` | Reject spoofed source addresses: `disable` / `loose` / `strict`. |
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

## Blocking by country (GeoIP)

```text
set firewall zone wan geoip-block CN,RU
```

Every source address in those countries is dropped on that zone. The addresses
come from a database **extracted into the image at build time**: a firewall that
can only block a country while it can reach a geolocation service is not one you
can put on an isolated network, and the update path for the data is the image's,
not a second one.

`set firewall global geoip-block <CC>` sets the list every zone inherits; a zone's
own list is **added to** it, not swapped for it — a country blocked everywhere
should not quietly become reachable because one zone named a different one.

**It blocks sources, not destinations.** This stops those countries reaching you;
it does not stop your users reaching them.

A country becomes ordinary CIDRs in the same blocklist your own `block` entries go
into, so the data plane never learns what a country is and a geo-block is counted
as `dropped_blocklist` like any other. That has a visible cost: one country is
thousands of prefixes (China ~8k, Russia ~13k, the United States ~155k), the
blocklist holds 262144 across every zone, and the commit refuses a config that
would exceed it rather than leaving a half-programmed firewall. `show firewall`
prints what each zone's list costs:

```text
geoip blocks:
  wan      CN,RU  (20983 prefixes)
```

A country the image has no addresses for is **refused at commit**, not treated as
an empty list — a rule that silently blocks nothing is the worst possible outcome
for a feature whose whole job is to block.

`nix build .#checks.x86_64-linux.geoip -L` verifies it end to end against a
substituted database: a neighbour reachable before, unreachable once its country
is blocked, and reachable again once it is not.

## Source validation (anti-spoofing)

A packet claiming a source address it could not possibly have come from is the
oldest trick there is: it is how a WAN neighbour pretends to be on your LAN, and
how your own network becomes somebody else's reflection amplifier. Source
validation answers that with the routing table — it looks up a route back to the
sender and asks whether the answer makes sense for the interface the packet
arrived on.

```text
set firewall zone wan source-validation strict
```

| Mode | The rule |
|---|---|
| `disable` | Accept any source address. **The default.** |
| `loose` | The source must be routable *somewhere*. |
| `strict` | ...and by the interface it arrived on. |

**`strict` is the real anti-spoofing rule** (BCP 38 / RFC 3704): a source whose
return path leaves by another interface cannot be the sender, so it is dropped.
It is also the mode that breaks things — wherever routing is asymmetric, a reply
legitimately returns by a different path than the request took, and `strict`
drops that traffic with no other symptom. A second WAN uplink is the usual cause,
and the commit warns when it sees one.

`loose` is what to reach for there. It cannot tell a LAN address arriving on the
WAN from a real one, but it still refuses everything that could never answer at
all — unrouted space, bogons, the addresses an amplification attack is built on.

Neither mode is switched on for you, and that is deliberate: this feature drops
traffic, and *which* traffic depends on your routing table rather than on
anything written in the config.

**Always accepted, in every mode:** a `0.0.0.0` source (that is how a DHCP client
asks for its first address — validating it would make a DHCP server unreachable
the moment you turned this on) and IPv6 link-local sources (`fe80::/10`), which
are not routable by definition and carry Neighbor Discovery, Router
Advertisement and DHCPv6. **Never accepted, in every mode:** loopback,
multicast and broadcast *sources*, which have routes but can never send.

Drops are counted, not silent:

```text
sentinel show firewall             # names each zone that validates
sentinel show firewall statistics  # dropped_spoofed
```

A rising `dropped_spoofed` on an edge interface is someone spoofing. A rising one
on an internal interface is usually asymmetric routing meeting `strict`, and the
answer there is `loose`.

`nix build .#checks.x86_64-linux.spoofing -L` verifies this on two VMs: it forges
a LAN source onto the WAN link and asserts `strict` catches it, `loose` does not
(it is routable, just not here), a loopback source is refused by both, and honest
traffic keeps flowing throughout.

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

#### Deterministic CGNAT

Carrier NAT has to answer *who was behind this address and port*. Logging every
translation is one way; giving each internal address a **fixed block** of WAN ports
is the better one — the question is then answered by arithmetic, and one record of
the block layout covers every flow inside it.

```text
set nat source wan-masq zone wan
set nat source wan-masq cgnat-block-size 512      # ports per internal address
set nat source wan-masq cgnat-base-port 32768     # optional; this is the default
```

```text
show nat                       # the configured layout
show nat cgnat 10.0.0.7        # which ports that address holds
```

`show nat cgnat` asks the **agent**, which computes the answer with the same code
that hands the ports out — so what you report and what was actually used cannot
drift apart. A layout that cannot work (a block that does not fit above its base
port, a base port sizing nothing) is refused at commit rather than quietly falling
back to ordinary masquerade.

The default base port leaves the well-known and registered ports free, so
port-forwards on the same address are unaffected.

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

## Seeing what is on the wire

The data plane records every NAT'd connection in its state table, and each entry
counts the traffic it accounted for. Two views read it:

```text
show flows                 # the live state table, with per-flow packets/bytes
show top-talkers           # hosts ranked by the volume attributed to them
```

`top-talkers` ranks by **bytes**, not by connection count — a host holding four
hundred idle keep-alives is not the reason a link is full — and still reports the
connection count beside it, because one flow moving ten gigabytes and ten
thousand flows moving ten gigabytes are different problems.

A host is named by the traffic it **caused**. For a masqueraded connection the
state entry describes the reply, so its source is the remote server while the
internal client that asked for the traffic is the entry's NAT target; the
ranking attributes it to that client. Otherwise the view would answer "which
server sent us the most", which is rarely the question.

Three limits worth knowing:

- **Only NAT'd connections are counted.** Traffic the firewall passes without
  translating (routed between two internal zones, say) has no state entry to
  account against and does not appear.
- **The counters are per appliance and are not replicated.** After an HA
  failover the new active node counts the flows it forwards from zero — the
  bytes it is reporting are the bytes it actually carried, and summing the pair
  would otherwise double them.
- **Byte counts are of the frame on the wire**, headers included, which is what
  a link's capacity is measured in.

## SYN-flood protection (SYN proxy)

```text
set firewall syn-protect 443
set firewall syn-protect 8080 mss 1400
delete firewall syn-protect 443
```

A SYN flood costs the attacker one small packet and costs the server a
half-open connection held for tens of seconds against an address that was never
real. `syn-protect` makes the firewall stop believing a SYN: it answers the
handshake itself, with a cookie derived from the connection's own identity, and
keeps **no state at all**. Only a client that actually receives that answer can
return it, so a spoofed source never gets past — and the flood costs the
appliance one reply packet each and nothing more.

When a client does return a valid cookie, the firewall opens the real connection
to the server and joins the two halves together. From then on the connection is
ordinary; `show firewall statistics` reports what happened:

| Counter | Meaning |
|---|---|
| `synproxy_challenged` | SYNs answered with a cookie. Under attack this is the flood being absorbed. |
| `synproxy_admitted` | Clients that returned a valid cookie and reached the server. |
| `synproxy_rejected` | ACKs carrying no cookie this appliance minted — spoofed, or expired. |
| `synproxy_spliced` | Servers that answered and had their connection joined to a client's. |

Read `challenged` and `admitted` together: a large gap between them *is* the
attack being stopped.

**What a protected connection gives up.** The firewall has to answer before it
can ask the server what it would have agreed to, so it offers an MSS and nothing
else — no window scaling, no SACK, no timestamps — and passes the same bare
options on to the server, so both ends agree. In practice that caps a single
connection's receive window at 64 KiB (about 6 MB/s on a 10 ms path) and makes
loss recovery slower. Protect the ports where a flood is the greater risk, not
every port.

Two further limits worth knowing:

- It is **TCP over IPv4** only.
- A port-forward that also **changes** the port cannot be protected: the proxy
  matches the two directions of a connection by the service port, which a port
  rewrite breaks. Forwarding the address is fine — `443 → 10.0.0.10:443` works,
  `443 → 10.0.0.10:8443` does not.

The cookie key is drawn from the kernel's random source when the first protected
port is configured, and never leaves the appliance.
