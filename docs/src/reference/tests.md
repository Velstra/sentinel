# Select a verification test

<a id="test-suite-nixostests"></a><a id="also-here"></a><a id="also-here-1"></a>

Run a narrow check when evaluating an operating claim. The names below refer to the current flake; use `nix flake show` for the complete list at your checkout.

```sh
nix build .#checks.x86_64-linux.commitconfirm -L
nix build .#checks.x86_64-linux.ha-witness-failover -L
nix build .#checks.x86_64-linux.bootfallback -L
```

These checks cover a timed configuration rollback, forwarding authority in a multi-VM HA pair, and a failed candidate boot, respectively. Use an x86-64 KVM host.

## Image & boot integrity

| Check | Coverage |
|---|---|
| `verified-boot` | dm-verity store mounts, the UKI boots, a clean boot is **blessed** |
| `secureboot` | boots under **enforcing** Secure Boot |
| `install` | single-disk **and** RAID1 installs lay down a bootable layout |
| `install-iso` | live-boot install from the bundled image → bootable ESP |
| `update` | an A/B update writes + re-types slot B; the bootloader default switches |
| `updatechannel` | the **crypto gate** in front of the slot writer rejects an unsigned update |
| `reboot` | a **genuine** `machine.reboot()` brings the whole running config back, not just the files |

## Config lifecycle & management

| Check | Coverage |
|---|---|
| `commit` | `commit` applies hostname/zone/address live; `save` persists across reboot |
| `commitconfirm` | a timed commit auto-reverts unless `confirm`ed — the safety net for editing a firewall over its own link |
| `confighistory` | every `save` archives a revision, `show system commit` lists them, `rollback <N>` restores one |
| `configsync` | a commit on the primary pushes the running config to the backup's API, which applies **and** persists it |
| `api` | CLI/API management operations against the appliance backend. |
| `console` | Browser validation of management operations, staged changes and their outcomes. |
| `contract` | the compiled agent config keeps the shape the data plane reads |
| `shipped` | what the image actually carries |
| `wizard` | the installer's click-through, answered end to end |

## Firewall (eBPF data plane)

| Check | Coverage |
|---|---|
| `reject` | a rejected TCP port answers with a **RST**, not a silent drop |
| `rejectudp` | a rejected UDP port answers with **ICMP port-unreachable** |
| `log` | per-rule logging fires for a logged drop and a logged pass, and stays quiet otherwise |
| `srcfilter` | a rule's `source` CIDR matches the intended client and only that one |
| `nat` | Packet translations and stateful reverse-path handling. |
| `fwgroups` | address and port groups expand at compile time to the full sources × ports product |
| `fwdomain` | Resolves domain-group membership for firewall matching. |
| `fwschedule` | a rule with a weekly schedule is in the data plane **only** inside its window |
| `v6exthdr` | IPv6 extension headers do not bypass a rule — the chain is walked to the real protocol |
| `icmptype` | Matches ICMP and ICMPv6 rules by message type. |
| `rulescope` | Scopes rules by ingress interface within a zone. |
| `evpn` | Exchanges tenant reachability across peer routing sessions. |
| `macgroup` | Selects configured groups of link-layer addresses. |
| `egress` | Applies the policy in the intended egress direction. |
| `srcprefix` | every source-prefix **length** matches, not just the convenient ones |
| `v6rules` | a rule scoped to IPv6 lands in its own trie and does not open the v4 one |

## NAT

| Check | Coverage |
|---|---|
| `nat` | Packet translations and stateful reverse-path handling. |
| `synproxy` | Exercises the configured SYN proxy with a real connection. |
| `masq` | masquerade SNATs a private LAN client out of the WAN address |
| `hairpin` | an internal client reaches a port-forwarded service via the box's **own** public IP |
| `npt66` | stateless, checksum-neutral IPv6 prefix translation (RFC 6296) |
| `nat64` | an IPv6-only client reaches an IPv4-only server through the box, DNS64 included |
| `conntracksync` | the conntrack map is mirrored to the peer, so an established flow survives failover |

## Routing (Wren control plane)

| Check | Coverage |
|---|---|
| `bgp` | two appliances peer eBGP and each learns the other's network |
| `policy` | a VyOS-style route-map filters and rewrites what BGP exports |
| `ospf` | an OSPFv2 point-to-point adjacency; each side learns the other's redistributed network |
| `ospf3` | the same over IPv6 (OSPFv3, RFC 5340) |
| `rip` | RIPv2 — a distance-vector paradigm alongside BGP's path-vector and OSPF's link-state |
| `ripng` | RIPng (RFC 2080), the IPv6 sibling |
| `babel` | Babel (RFC 8966) over IPv6 |
| `isis` | IS-IS (ISO 10589 + RFC 1195) — a link-state IGP running directly over L2 |
| `isisauth` | Verifies IS-IS authentication between neighbors. |
| `bfd` | BFD (RFC 5880) under BGP detects a path failure fast |
| `vrrp` | two boxes share a virtual IP; the higher priority owns it and hands it over on loss |
| `staticv6` | static routes are dual-stack — a v6 prefix reaches the kernel IPv6 FIB |
| `multiwan` | health-checked uplink failover plus policy routing across two upstreams |
| `routingimport` | Checks route import policy against received prefixes. |
| `ospfinterop` | Establishes an OSPF adjacency with the test peer and checks exchanged routes. |

## Interfaces & L2

| Check | Coverage |
|---|---|
| `l2` | a bridge and a bond, synthesised on the same networkd render path as VLANs |
| `c14` | MACVLAN and QinQ, the two remaining networkd-rendered L2 types |
| `macsec` | 802.1AE link encryption comes up from a pre-shared key |
| `l2tp` | a static L2TPv3 Ethernet pseudowire over the underlay |
| `tunnel` | kernel GRE tunnels between two appliances |
| `linkopts` | per-interface MTU (jumbo frames / PPPoE) and MAC cloning reach the link |
| `linkbehaviour` | per-link forwarding, ARP and DHCP-client identity reach the kernel, and a mirror carries traffic |
| `vti` | Brings up a route-based IPsec/VTI path. |
| `wireless` | Verifies wireless configuration rendering; test radio behavior with actual hardware. |
| `wwan` | Verifies modem configuration rendering; carrier and hardware behavior require a modem. |
| `dualstack` | one interface carries an independent static IPv4 **and** IPv6 address |

## Address & name services

| Check | Coverage |
|---|---|
| `dhcp` | the built-in DHCP server leases to a LAN client |
| `dhcp6` | stateful DHCPv6 leases — the stateful sibling of `ra` |
| `ra` | IPv6 Router Advertisements give a client a SLAAC address |
| `dhcp6pd` | DHCPv6-PD requests a delegated prefix upstream (the German-ISP WAN v6 model) |
| `dhcprelay` | Exercises DHCP relay across client and server segments. |
| `dhcprelay6` | the IPv6 sibling of the relay |
| `dns` | the DNS forwarder resolves for the LAN against an authoritative upstream |
| `ntp` | the box serves time to the LAN from an upstream source |
| `mdns` | the mDNS reflector bridges discovery between two segments |
| `dyndns` | the dyndns2 client updates a provider when the WAN address changes |

## WAN & shaping

| Check | Coverage |
|---|---|
| `pppoe` | a PPPoE session against a real concentrator, plus MSS clamping |
| `qos` | a CAKE shaper is live in the kernel at the configured bandwidth |

## VPN

| Check | Coverage |
|---|---|
| `wireguard` | a WireGuard interface and tunnel render to a `Kind=wireguard` netdev with a 0640 key |
| `ipsec` | an IKEv2 site-to-site tunnel establishes and carries traffic between protected subnets |
| `openconnect` | a road-warrior client dials in and reaches a host behind the box |

## Services

| Check | Coverage |
|---|---|
| `ssh` | `set services ssh` tunes the daemon; `set system login` creates real accounts and keys |
| `snmp` | a read-only v2c poll answers, and the rendered config stays 0640 |
| `lldp` | LLDP neighbours are discovered between two boxes (the daemon is off by default) |
| `pki` | a local CA and a leaf signed by it land under `/var/lib/sentinel/pki` with the right modes |
| `reverseproxy` | TLS terminates on :443 with an on-box leaf and load-balances to a backend |
| `geoip` | Checks country-prefix policy using the test database. |
| `acme` | Issues and installs a certificate in the test environment. |
| `bcastrelay` | Relays the selected UDP broadcast service across configured interfaces. |
| `syslog` | Delivers appliance log records to a remote collector. |
| `alerts` | Delivers a notification when a monitored unit fails. |
| `spoofing` | Compares accepted and rejected sources under source-validation modes. |
| `ids` | Observes the configured detector emitting an event for test traffic. |
| `portal` | Tests guest admission and expiry against the dataplane. |
| `portmap` | Verifies a client mapping against the agent’s live NAT-PMP table. |

<a id="rust-unit-tests"></a><a id="why-some-things-are-verified-structurally"></a><a id="loading--verifying-ebpf"></a>

## Rust and browser checks

```sh
cargo test --workspace --locked
tests/console/run.sh
```

The browser suite drives the real management API over a disposable configuration. The hardware and dataplane claims require the corresponding VM or hardware checks. See the [console test reference](console.md).
