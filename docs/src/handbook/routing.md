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
```

All the IGPs share `interface`, `redistribute`, `redistribute-metric`, `bfd`
and `vrf`; each adds its own knobs (Babel: `network`/`router-id`; IS-IS:
`system-id`/`area`/`level`/`priority`/`metric`/`network-type`/`l2-to-l1-leaking`).

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
set policy prefix-list LAN rule 10 prefix 10.0.0.0/8 le 24
set policy route-map TO-PEER rule 10 action permit
set policy route-map TO-PEER rule 10 match prefix-list LAN
set policy route-map TO-PEER rule 20 action deny
set protocols bgp neighbor 10.0.0.2 export TO-PEER
```
