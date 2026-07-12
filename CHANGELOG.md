# Changelog

## [Unreleased]

## [0.3.2] — 2026-07-12

## [0.3.1] — 2026-07-12

## [0.3.0] — 2026-07-11

Completes NAT and the interface-type matrix, adds time-based firewall rules and a
stateful DHCPv6 server, and brings high availability to the appliance: CLI-
configurable SSH with per-user logins, and config sync across an HA pair. Ships
with a complete CLI handbook. Each slice ships with a `nixosTest` that loads the
real config (and, where it touches the datapath, the real eBPF) in a sandboxed VM.

### Firewall & NAT

- **Hairpin NAT (NAT reflection)** — the eBPF-datapath piece deferred in 0.2.0:
  reach a port-forwarded service via its public IP from inside
  (`nat destination … hairpin`).
- **NPTv6 / NAT66** (RFC 6296) — stateless, checksum-neutral IPv6 prefix
  translation (`nat npt66`).
- **Time-based firewall rules** — a rule may carry a weekly local-time schedule
  (`rule … schedule days/start/end`) and is only in force while its window is
  open; a systemd timer re-applies at the boundaries.

### Interfaces

- **MACsec (802.1AE)** encrypted point-to-point links and **L2TPv3** Ethernet
  pseudowires, completing the VyOS interface-type parity list.

### Services

- **Stateful DHCPv6 server** (`interface … router-advert dhcp6-pool`).
- Dynamic-DNS PATH fix (`ddclient` gets iproute2 + util-linux); end-to-end mDNS
  reflector and DHCP-relay VM tests.

### High availability & management

- **SSH management, CLI-configurable** — `services ssh` (daemon port / listen /
  password-auth, key-only by default) and `system login <user>` (per-user SSH
  keys + crypt(3) hashed passwords, VyOS-style; accounts created at commit via
  `mutableUsers`).
- **HA config sync** — `system config-sync` pushes the running config to peer
  firewalls on every commit, over the existing REST API (shared bearer secret,
  loop-safe).
- **VRRP, BFD and OSPFv3** are now covered by end-to-end 2-node `nixosTest`s
  (VRRP virtual-IP failover, BFD sub-second fast-detection, OSPFv3 IPv6 adjacency)
  — including a fix to the wren daemon so graceful shutdown (and thus a clean VRRP
  hand-off) runs under `systemctl stop`, not just Ctrl-C.

### Documentation

- A complete **CLI handbook** in the mdBook — every command by section, with
  worked examples and four full example configurations, auto-published to GitHub
  Pages.

## [0.2.0] — 2026-07-07

A large release. Sentinel gains a coherent VyOS/JunOS-style configuration
shell, the full per-object routing surface, an on-box PKI, a REST management
API, NAT64/DNS64, and a reboot-persistence fix — all still driving the one
declarative config model.

### Added

- **A single-paradigm configuration shell (pure VyOS/JunOS).** The config is a
  tree and every command names a path in it: `set` / `delete` / `show` /
  `edit` (+ `up` / `top` / `exit`), with the transactional `commit` /
  `commit-confirm` / `save` / `rollback` / `compare` lifecycle. Every line
  means exactly one thing — there is no implicit `set`, no bare-path context
  shorthand, and no absolute-path mode switching. The edit context renders as
  its own `[edit …]` banner line above a short prompt, and a `*` in the prompt
  marks uncommitted edits. Per-object configuration throughout (interfaces,
  rules, NAT, zones, neighbors, areas).
- **A readable CLI presentation layer.** Grouped, aligned, coloured `help`
  (with `help <command>` details and examples), contextual Tab/`?` completion
  with per-keyword descriptions, colour-coded errors/warnings/success (TTY
  only, `NO_COLOR` respected), and did-you-mean guidance — mistyped commands,
  retired spellings (`no`/`do`/`end`), and bare config paths all point at the
  correct VyOS spelling.
- **Value hints everywhere (vtysh style).** Every value position shows what to
  type: `<A.B.C.D>`, `<X:X::X:X>`, `<A.B.C.D/M>`, `<1-65535>`, `<1-4094>`,
  `<xx:xx:xx:xx:xx:xx>`, `<host:port>`, … as display-only completion entries
  (Tab never inserts them) plus a dimmed inline ghost hint at single-value
  positions. Live names are offered wherever a value references something that
  exists: interfaces, zones, rules, NAT rules, groups, route filters, VRFs,
  IPsec connections, PKI CAs/certificates, WireGuard tunnels. The completion
  list is typographically layered (bold keywords, italic hints, dim
  descriptions) and the command word highlights green/red as you type.
- **C14 — MACVLAN + QinQ.** `type = macvlan` (a pseudo-NIC with its own MAC on
  a parent, `macvlan-mode`), and `vlan-protocol 802.1ad` on a VLAN subinterface
  for 802.1ad QinQ (stack a C-tag VLAN on an S-tag VLAN) — rendered as networkd
  netdevs.
- **L2 done right: bridge/bond members and 802.1Q on the device.** Membership
  now lives on the bridge/bond itself — `set interface br0 member eth1`
  (repeatable, per-member delete); the old per-NIC `master` field is gone. A
  bridge can be `vlan-aware` with per-port `vlan-tagged <ids>` and
  `vlan-untagged <pvid>` (rendered as networkd `VLANFiltering=` +
  `[BridgeVLAN]`). A VLAN subinterface named `<parent>.<id>` infers `parent`
  and `vlan` from its name at commit.
- **WireGuard moved under `vpn`.** `set interface wg0 type wireguard` creates
  the interface (address/zone as usual); keys and peers live at
  `set vpn wireguard wg0 private-key|listen-port|peer <pubkey> …` next to
  IPsec — cross-checked both ways at commit.
- **Config-model audit fixes.** `firewall rule … to <zone>` is now optional
  and draws an explicit commit warning (the datapath does not enforce the
  destination zone yet — rules apply from their source zone); broad
  drop/reject rules are rejected with the working alternative named. List
  fields (BGP communities/networks, IGP interface/redistribute lists, group
  members, service upstreams, VRRP addresses, …) gained per-item add/remove
  instead of replace-on-set. Dozens of new validations: injection-shaped
  characters in SNMP/dyndns/DNS free-text (also rejected again at render
  time), VRF table ranges + collision with multi-WAN policy tables,
  OSPF/IS-IS `dead > hello`, BFD/VRRP/ROA ranges, DHCP pools inside the
  interface subnet, IPsec PSK length, NAT port 0, `protocols import` keyed to
  the routing daemon's actual protocol set. Multi-WAN health checks honour
  per-uplink intervals; a disabled PPPoE interface tears its session down;
  OSPFv3 `redistribute` values the daemon can't express error instead of
  silently vanishing.
- **Full per-neighbour BGP.** Every wren neighbor field is now reachable:
  `local-as`, `update-source`, `ebgp-multihop`, `description`, `shutdown`,
  `hold-time`, and more; route-maps, communities,
  RPKI, confederation, and aggregate-address.
- **Routing policy (`policy`).** VyOS-style `set policy prefix-list` +
  `set policy route-map` with explicit `match` / `set` clauses and
  `match prefix-list`, replacing `[[protocols.filter]]`; route-maps are
  referenced by BGP neighbours, VRFs and redistribution.
- **Per-object IGP + routing surface.** OSPFv2 / OSPFv3 (areas, auth, timers,
  stub/NSSA), IS-IS, RIP / RIPng, Babel, VRRP with interface/route tracking,
  global BFD, multicast (IGMP/MLD), VRFs, and per-protocol redistribution
  filters.
- **C18 — services parity.** LLDP, read-only SNMP, Wake-on-LAN, mDNS repeater,
  dynamic DNS, and DHCP relay.
- **C17 — OpenConnect VPN server.** An AnyConnect-compatible TLS road-warrior
  VPN (`set vpn openconnect …`, served by ocserv): client address pool, pushed
  DNS/routes or full-tunnel, password auth, TLS identity from the on-box PKI —
  the client-VPN modality alongside site-to-site IPsec and peer WireGuard.
- **C19 — PKI + ACME.** An on-box certificate authority with leaf issuance
  (runtime, idempotent, private keys mode `0600`) plus ACME / Let's Encrypt
  account configuration.
- **C12 — REST management API.** `sentinel api`: a bearer-token REST server
  over the *same* config model the CLI edits. `GET`/`PUT /api/v1/config` run the
  exact parse → live-apply → persist path a CLI `commit` takes; `GET
  /api/v1/status` and `/api/v1/show/*` proxy the operational `show` data. No
  UI-vs-CLI config drift.
- **C10 — NAT64 / DNS64.** tayga (NAT64) + unbound (DNS64) for IPv6-only
  networks reaching IPv4 destinations, with a documented no-ALG stance.
  (Hairpin NAT is deferred — it needs the eBPF datapath.)
- **C13 — signed update channel.** `[update]` pins a channel URL + an Ed25519
  release-signing key; `sentinel update check`/`install` fetch a signed
  manifest, verify its detached signature against the pinned key and the image's
  SHA-256 before ever writing an A/B slot — the authenticity gate in front of
  the existing verified-boot slot switch.
- **Per-object polish.** Description and `disabled` on interfaces, firewall
  rules, NAT rules, and zones; DHCP static mappings plus lease / domain /
  router / DNS options; DNS cache-size and local-domain tunables.
- **Integration tests.** Per-protocol routing nixosTests (OSPFv3, IS-IS,
  RIPng, Babel, VRRP, BFD) alongside the existing BGP/OSPF/RIP checks, plus
  new `api`, `pki`, `nat64`, `lldp`, `snmp`, and `dhcp-relay` VM tests and
  interface/service tunable coverage.

### Changed

- **Explicit `ApplyMode { Live, Boot }`** through the config-apply pipeline, so
  boot-time reconciliation and live `commit` share one code path with distinct,
  intentional behaviour.

### Fixed

- **Reboot persistence.** Saved config now fully survives a reboot: fixed a
  boot-time deadlock and the missing runtime re-apply that could leave a
  rebooted appliance short of its saved state.

## [0.1.0] — 2026-07-05

First tagged release of the Sentinel immutable firewall/router appliance.

### Included
- Named zones + per-zone posture, VLANs, firewall (address/port groups,
  port ranges, per-rule log, source-CIDR, reject), NAT (masquerade + DNAT
  port-forwards).
- WireGuard (C1); DHCPv4 + RA/SLAAC + DNS (dnsmasq: forwarding, host-
  overrides, blocklists) + NTP (C7); dual-stack IPv6 + DHCPv6-PD.
- Bridges + bonding, per-interface MTU/MAC (C14 part); full routing CLI
  (BGP/OSPF/OSPFv3/IS-IS/RIP/RIPng/Babel/VRRP/static).
- **PPPoE client + TCP-MSS clamping (C5)** — real WAN uplinks.
- **QoS / traffic shaping (C8)** — per-interface CAKE / fq_codel.
- **C22 — L7 reverse proxy / load balancer.** `services reverse-proxy <name>`
  terminates TLS on a listen port using an on-box PKI certificate and forwards
  to one or more backends round-robin (HAProxy) — HTTP-aware routing + TLS
  termination on top of the datapath's L4 path.
- Verified boot / A-B / secure boot / atomic commit with commit-confirm,
  config archive, rollback-N, diff (C21).

### Not yet included (roadmap)
- IPsec (C2), multi-WAN (C6), stateful HA (C9), IDS/IPS (C11), REST/Web UI
  + AAA (C12), signed update channel (C13), PKI/ACME (C19), and the rest of
  the C-track parity list.

[0.2.0]: https://github.com/Velstra/sentinel/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Velstra/sentinel/releases/tag/v0.1.0
