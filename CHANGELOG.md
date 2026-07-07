# Changelog

## [0.2.0] — 2026-07-07

A large release. Sentinel gains a Cisco/vtysh-style hierarchical CLI, the full
per-object routing surface, an on-box PKI, a REST management API, NAT64/DNS64,
and a reboot-persistence fix — all still driving the one declarative config
model.

### Added

- **Hierarchical context CLI.** A Cisco / Dell OS / vtysh-style nested-context
  shell layered on top of the flat VyOS-style grammar: enter contexts
  (`interface eth0`, `protocols bgp`, `neighbor <ip>`, …), implicit `set`,
  `no` to delete, `do` to run an operational command from config mode,
  `exit`/`end`, and an IOS-style absolute-path mode switch that jumps between
  contexts. Per-object configuration throughout (interfaces, rules, NAT, zones,
  neighbors, areas).
- **Full per-neighbour BGP.** Every wren neighbor field is now reachable:
  `local-as`, `update-source`, `ebgp-multihop`, `description`, `shutdown`,
  `hold-time`, and more; route-maps via `[[protocols.filter]]`, communities,
  RPKI, confederation, and aggregate-address.
- **Per-object IGP + routing surface.** OSPFv2 / OSPFv3 (areas, auth, timers,
  stub/NSSA), IS-IS, RIP / RIPng, Babel, VRRP with interface/route tracking,
  global BFD, multicast (IGMP/MLD), VRFs, and per-protocol redistribution
  filters.
- **C18 — services parity.** LLDP, read-only SNMP, Wake-on-LAN, mDNS repeater,
  dynamic DNS, and DHCP relay.
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
- Verified boot / A-B / secure boot / atomic commit with commit-confirm,
  config archive, rollback-N, diff (C21).

### Not yet included (roadmap)
- IPsec (C2), multi-WAN (C6), stateful HA (C9), IDS/IPS (C11), REST/Web UI
  + AAA (C12), signed update channel (C13), PKI/ACME (C19), and the rest of
  the C-track parity list.

[0.2.0]: https://github.com/Velstra/sentinel/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Velstra/sentinel/releases/tag/v0.1.0
