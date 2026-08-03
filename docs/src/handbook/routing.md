# Routing (protocols)

Dynamic routing is served by the **wren** control plane. `set protocols …`
configures static routes, the IGPs (OSPF/OSPFv3, RIP/RIPng, Babel, IS-IS), BGP,
first-hop redundancy (VRRP), liveness (BFD), VRFs and multicast. Route policy
(prefix-lists, route-maps) lives under `policy`.

Start with a router-id (a 32-bit id written as an IPv4 address):

```text
set protocols router-id 10.0.0.1
```

## Static routes

| Field | Meaning |
|---|---|
| `via <ip>` | Next-hop gateway. |
| `dev <if>` | Outgoing interface (on-link route). |
| `metric <n>` | Route metric (lower wins). |
| `vrf <name>` | The VRF this route belongs to. |

```text
set protocols static 192.168.50.0/24 via 10.0.0.254
set protocols static 2001:db8:50::/48 via 2001:db8:0:1::254
```

## BGP

```text
set protocols bgp local-as 65001
set protocols bgp router-id 10.0.0.1
set protocols bgp network 10.0.0.0/24
set protocols bgp neighbor 10.0.0.2 remote-as 65002
```

Instance-level fields: `local-as`, `router-id`, `hold-time`, `cluster-id`,
`network`, `redistribute` (static/connected), `community` /
`large-community` / `ext-community`, `multipath`, `confederation id|member`,
`aggregate <prefix> summary-only`, `roa <prefix> origin-as`, `rpki
reject-invalid|rtr`, `ebgp-require-policy`, `vrf`.

Per-neighbor fields (`set protocols bgp neighbor <ip> …`):

| Field | Meaning |
|---|---|
| `remote-as` | The peer's AS number. |
| `local-as` | Override this speaker's AS for this session. |
| `update-source` | Source address for the outgoing session. |
| `ebgp-multihop` | Session TTL for a distant eBGP peer. |
| `ttl-security` | GTSM max hops (1–254). |
| `password` / `ao-key` / `ao-key-id` | TCP-MD5 / TCP-AO authentication. |
| `passive` / `shutdown` | Wait for the peer / administratively down. |
| `hold-time` | Per-session hold-time in the OPEN. |
| `route-reflector-client` | This iBGP peer is an RR client. |
| `max-prefix` | Tear the session down over this many prefixes. |
| `default-originate` | Advertise a default route to the peer. |
| `add-path` / `extended-nexthop` | ADD-PATH (RFC 7911) / IPv4-over-IPv6 next hop. |
| `evpn` / `flowspec` / `srpolicy` / `link-state` | Negotiate the extra address families. |
| `role` | BGP Role (RFC 9234): provider/customer/peer/rs-server/rs-client. |
| `import` / `export` | Inbound / outbound route policy (a filter name). |
| `bfd` (+`bfd-auth-*`) | Run a BFD session to the peer for fast failure detection. |
| `description` | Free-form label. |

## OSPF (v2) & OSPFv3 (IPv6)

```text
set protocols ospf interface eth1 area 0.0.0.0
set protocols ospf network-type point-to-point
set protocols ospf redistribute static

set protocols ospf3 interface eth1 area 0.0.0.0     # IPv6
```

Common fields: `interface <if> [area <id>]`, `area`, `router-priority`, `cost`,
`network-type` (broadcast/point-to-point), `passive-interface`, `redistribute`
(+`redistribute-metric`), area types (`stub-area`, `nssa-area`,
`totally-stubby-area`, …), auth (`auth-type`/`auth-key`/`auth-key-id`),
`hello-interval`/`dead-interval`, `graceful-restart`, `bfd`, `vrf`. OSPFv3 adds
`instance-id`.

## RIP / RIPng / Babel / IS-IS

```text
set protocols rip interface eth1
set protocols rip redistribute connected

set protocols babel interface eth1
set protocols babel network 10.0.0.0/24

set protocols isis interface eth1
set protocols isis system-id 0000.0000.0001
set protocols isis area 49.0001
set protocols isis level 2
set protocols isis auth-type hmac-sha256
set protocols isis auth-key s3cr3t
```

All the IGPs share `interface`, `redistribute`, `redistribute-metric`, `bfd`
and `vrf`; each adds its own knobs (Babel: `network`/`router-id`; IS-IS:
`system-id`/`area`/`level`/`priority`/`metric`/`network-type`/`l2-to-l1-leaking`).

**Authenticate IS-IS.** It rides directly on the data link, with no IP layer to
filter at, so on an untrusted segment any host can otherwise form an adjacency and
inject LSPs. `auth-type` takes `text` (a cleartext password — readable by anyone
watching the link), `hmac-md5` (RFC 5304, no key id) or `hmac-sha256` (RFC 5310,
with `auth-key-id`). Prefer `hmac-sha256`; reach for `hmac-md5` when the neighbour
is another vendor, since that is what most default to. Both ends of a link must
agree on the **scheme** as well as the key — the two digests are not
interchangeable.

`nix build .#checks.x86_64-linux.isisauth -L` verifies this on two real VMs:
matching HMAC-SHA-256 keys bring the adjacency up and flood prefixes, changing one
side's key tears it down again, and HMAC-MD5 works the same way.

## VRRP (first-hop redundancy) {#vrrp}

Two boxes share a virtual IP; the higher-priority one is master and owns it,
failing over on loss. See the [HA pair example](examples.md#ha-pair).

| Field | Meaning |
|---|---|
| `interface` | The NIC the virtual router runs on. |
| `vrid` | Virtual router id (1–255). |
| `priority` | Election priority (higher wins). |
| `virtual-address` | The shared virtual IP. |
| `advert-interval` | Advertisement interval (milliseconds). |
| `preempt` | Preempt a lower-priority master (`true`/`false`). |
| `prefix-length` | Prefix length for each virtual address. |
| `track-interface` / `priority-decrement` | Demote while a tracked NIC is down. |

```text
set protocols vrrp lan-vip interface eth1
set protocols vrrp lan-vip vrid 20
set protocols vrrp lan-vip priority 200         # 100 on the backup
set protocols vrrp lan-vip virtual-address 10.0.0.1
set protocols vrrp lan-vip prefix-length 24
```

## BFD

Sub-second failure detection that BGP/OSPF/static routing hang off of. Set
global timing defaults under `protocols bfd` (`min-tx`, `min-rx`,
`detect-mult`, auth, `echo`); enable it per protocol with `… bfd true`.

## VRFs, multicast & policy

- **`protocols vrf <name>`** — a named isolated routing table (`table`, `rd`,
  `interface`, `import`/`export`).
- **`protocols multicast`** — IGMP/MLD querier + RFC 4605 proxy (`igmp`, `mld`,
  `igmp-version`, per-`interface` `role` querier/upstream/downstream).
- **`policy prefix-list <name> rule <seq>`** (`prefix`/`ge`/`le`) and
  **`policy route-map <name> rule <seq>`** (`action`, `match …`, `set …`) build
  reusable route filters. Attach them to a BGP neighbor (`import`/`export`), a
  VRF, or a redistribution with **`protocols export <proto> <route-map>`** /
  **`protocols import <proto> <route-map>`**.

```text
set policy prefix-list LAN rule 10 prefix 10.0.0.0/8
set policy prefix-list LAN rule 10 le 24
set policy route-map TO-PEER rule 10 action permit
set policy route-map TO-PEER rule 10 match prefix-list LAN
set policy route-map TO-PEER rule 20 action deny
set protocols bgp neighbor 10.0.0.2 export TO-PEER
```


## Routes that go nowhere

```text
set protocols static 203.0.113.0/24 blackhole true
set protocols static 203.0.113.0/24 distance 254
```

A route with no next hop discards what it matches — the kernel's own blackhole
type. Two uses: null-routing a prefix, and holding a BGP summary up so it is
announced whether or not anything inside it is currently reachable.

`distance` is the usual convention where **lower wins**. It is what makes a
static route *float*: give it a distance worse than the protocol you expect to
learn the prefix from, and it sits unused until that protocol stops offering it.

A blackhole with a `via` is refused rather than one of them quietly winning.

## Policy routing

Ordinary routing asks one question: where is this going? These rules ask the
others — where it came from, over which link, to which port — and send the answer
to a different routing table.

```text
set policy route guests-out source 10.9.0.0/24
set policy route guests-out table 100
```

| Field | Meaning |
|---|---|
| `table` | The table matching traffic consults (required). |
| `source` / `destination` | Host or CIDR. |
| `interface` | The interface it arrived on. |
| `proto`, `source-port`, `destination-port` | `tcp` or `udp`, and its ports. |
| `priority` | Where it sits among the others (lower is consulted first). |
| `disabled` | Off without deleting it. |

Rendered as kernel routing-policy rules. **The appliance owns the priority band
10000–19999 and reconciles only that band**, so a rule somebody else put in the
table is left alone.

A rule with no address selector belongs to **both** families and is installed
twice, because the kernel has no rule that spans them — the kind of thing that is
invisible until half the traffic is not steered.

Refused rather than handed to the kernel: a table of 0 or one of the kernel's own
(253–255), a port with no protocol to key it, and a source and destination in
different address families.

```text
show policy route          # what the kernel is actually consulting
```

## Sending a route somewhere else

```text
set policy route-map to-transit rule 10 set next-hop 2001:db8::1
```

Route maps could already change how a route is *chosen* — metric, preference,
communities. This changes where it is forwarded.

It replaces the route's **whole** next-hop set: a multipath route sent via one
named gateway has one next hop by definition. A route that had none — a discard
route — stops discarding.

An address, not a hostname, and refused at commit: this decides where traffic
goes, and a name that stopped resolving would move it without the configuration
having changed. The families are deliberately not checked against each other — an
IPv4 route via an IPv6 next hop is RFC 5549.

## Multicast and VRFs

Both have their own tab in the console and their own `show`:

```text
set protocols multicast enabled true
set protocols multicast igmp true
set protocols multicast interface eth0 role downstream

set protocols vrf tenant-a table 100
set protocols vrf tenant-a interface eth1

show multicast          # the kernel's forwarding cache
show vrf                # the instances that are running
```

Multicast is not forwarded by default: a router has to be told to listen for the
reports that say who wants a group. An interface either faces receivers
(`downstream`) or faces the source (`upstream`).

## BGP: aggregates, authorisations, confederation, RPKI

```text
set protocols bgp aggregate 10.0.0.0/8 summary-only true
set protocols bgp roa 192.0.2.0/24 origin-as 64500
set protocols bgp confederation id 65000
set protocols bgp rpki rtr 192.0.2.1:3323
```

An aggregate announces one prefix in place of the more specific ones inside it;
`summary-only` suppresses those, and without it both go out — a bigger table for
the same reachability. A local ROA says which AS may originate a prefix where
there is no RTR server to ask.

## What may be redistributed

`redistribute` accepts every source the routing daemon knows: `connected`,
`static`, `kernel`, `rip`, `ospf`, `isis`, `babel`, `bgp` — minus whichever
protocol is doing the redistributing.

OSPFv3 is the exception: the daemon has `redistribute-static` and nothing else,
so static is the only source it can carry, and the CLI offers only that rather
than accepting a value that would be refused on apply.
