# Test suite (nixosTests)

Sentinel is verified by **70 nixosTests** plus the Rust unit tests. The nixosTests
boot real QEMU/OVMF VMs — several of them two or three at a time on shared virtual
segments — so they need `/dev/kvm`.

```shell
nix flake check                                   # evaluate every check
nix build .#checks.x86_64-linux.<name> -L         # run one
```

The tables below group them by what they exercise; `nix flake show` is the
authoritative list.

## Image & boot integrity

| Check | Boots | Proves |
|---|---|---|
| `verified-boot` | the **real** signed image (OVMF) | dm-verity store mounts, the UKI boots, a clean boot is **blessed** |
| `secureboot` | the signed image, **keys enrolled** | boots under **enforcing** Secure Boot |
| `install` | a live env, blank disks | single-disk **and** RAID1 installs lay down a bootable layout |
| `install-iso` | the **ISO** | live-boot install from the bundled image → bootable ESP |
| `update` | slot A of the image | an A/B update writes + re-types slot B; the bootloader default switches |
| `updatechannel` | the appliance | the **crypto gate** in front of the slot writer rejects an unsigned update |
| `reboot` | the appliance | a **genuine** `machine.reboot()` brings the whole running config back, not just the files |

## Config lifecycle & management

| Check | Proves |
|---|---|
| `commit` | `commit` applies hostname/zone/address live; `save` persists across reboot |
| `commitconfirm` | a timed commit auto-reverts unless `confirm`ed — the safety net for editing a firewall over its own link |
| `confighistory` | every `save` archives a revision, `show system commit` lists them, `rollback <N>` restores one |
| `configsync` | a commit on the primary pushes the running config to the backup's API, which applies **and** persists it |
| `api` | the REST management API drives one config model end to end; `/health` is unauthenticated, the rest is not |

## Firewall (eBPF data plane)

| Check | Proves |
|---|---|
| `reject` | a rejected TCP port answers with a **RST**, not a silent drop |
| `rejectudp` | a rejected UDP port answers with **ICMP port-unreachable** |
| `log` | per-rule logging fires for a logged drop and a logged pass, and stays quiet otherwise |
| `srcfilter` | a rule's `source` CIDR matches the intended client and only that one |
| `nat` | (also) a rule's `destination` CIDR admits one target and denies another, and a rule's rate `limit` holds its bucket's bound |
| `fwgroups` | address and port groups expand at compile time to the full sources × ports product |
| `fwdomain` | a domain group resolves to addresses the rules match on, the answer is cached, and a **failed lookup keeps it** rather than emptying a blocking rule |
| `fwschedule` | a rule with a weekly schedule is in the data plane **only** inside its window |
| `v6exthdr` | IPv6 extension headers do not bypass a rule — the chain is walked to the real protocol |

## NAT

| Check | Proves |
|---|---|
| `nat` | a `[[port-forward]]` DNATs an inbound connection to an internal host; a load-balanced VIP reaches a pool in **another zone** and its reply is un-NAT'd; both still work when the internal zone denies by default |
| `masq` | masquerade SNATs a private LAN client out of the WAN address |
| `hairpin` | an internal client reaches a port-forwarded service via the box's **own** public IP |
| `npt66` | stateless, checksum-neutral IPv6 prefix translation (RFC 6296) |
| `nat64` | an IPv6-only client reaches an IPv4-only server through the box, DNS64 included |
| `conntracksync` | the conntrack map is mirrored to the peer, so an established flow survives failover |

## Routing (Wren control plane)

| Check | Proves |
|---|---|
| `bgp` | two appliances peer eBGP and each learns the other's network |
| `policy` | a VyOS-style route-map filters and rewrites what BGP exports |
| `ospf` | an OSPFv2 point-to-point adjacency; each side learns the other's redistributed network |
| `ospf3` | the same over IPv6 (OSPFv3, RFC 5340) |
| `rip` | RIPv2 — a distance-vector paradigm alongside BGP's path-vector and OSPF's link-state |
| `ripng` | RIPng (RFC 2080), the IPv6 sibling |
| `babel` | Babel (RFC 8966) over IPv6 |
| `isis` | IS-IS (ISO 10589 + RFC 1195) — a link-state IGP running directly over L2 |
| `isisauth` | IS-IS authentication: matching HMAC keys form an adjacency, a changed key tears it down; HMAC-MD5 **and** HMAC-SHA-256 |
| `bfd` | BFD (RFC 5880) under BGP detects a path failure fast |
| `vrrp` | two boxes share a virtual IP; the higher priority owns it and hands it over on loss |
| `staticv6` | static routes are dual-stack — a v6 prefix reaches the kernel IPv6 FIB |
| `multiwan` | health-checked uplink failover plus policy routing across two upstreams |

## Interfaces & L2

| Check | Proves |
|---|---|
| `l2` | a bridge and a bond, synthesised on the same networkd render path as VLANs |
| `c14` | MACVLAN and QinQ, the two remaining networkd-rendered L2 types |
| `macsec` | 802.1AE link encryption comes up from a pre-shared key |
| `l2tp` | a static L2TPv3 Ethernet pseudowire over the underlay |
| `tunnel` | kernel GRE tunnels between two appliances |
| `linkopts` | per-interface MTU (jumbo frames / PPPoE) and MAC cloning reach the link |
| `dualstack` | one interface carries an independent static IPv4 **and** IPv6 address |

## Address & name services

| Check | Proves |
|---|---|
| `dhcp` | the built-in DHCP server leases to a LAN client |
| `dhcp6` | stateful DHCPv6 leases — the stateful sibling of `ra` |
| `ra` | IPv6 Router Advertisements give a client a SLAAC address |
| `dhcp6pd` | DHCPv6-PD requests a delegated prefix upstream (the German-ISP WAN v6 model) |
| `dhcp-relay`, `dhcprelay` | DHCP relay across two segments, for a client whose own segment has no server |
| `dhcprelay6` | the IPv6 sibling of the relay |
| `dns` | the DNS forwarder resolves for the LAN against an authoritative upstream |
| `ntp` | the box serves time to the LAN from an upstream source |
| `mdns` | the mDNS reflector bridges discovery between two segments |
| `dyndns` | the dyndns2 client updates a provider when the WAN address changes |

## WAN & shaping

| Check | Proves |
|---|---|
| `pppoe` | a PPPoE session against a real concentrator, plus MSS clamping |
| `qos` | a CAKE shaper is live in the kernel at the configured bandwidth |

## VPN

| Check | Proves |
|---|---|
| `wireguard` | a WireGuard interface and tunnel render to a `Kind=wireguard` netdev with a 0640 key |
| `ipsec` | an IKEv2 site-to-site tunnel establishes and carries traffic between protected subnets |
| `openconnect` | a road-warrior client dials in and reaches a host behind the box |

## Services

| Check | Proves |
|---|---|
| `ssh` | `set services ssh` tunes the daemon; `set system login` creates real accounts and keys |
| `snmp` | a read-only v2c poll answers, and the rendered config stays 0640 |
| `lldp` | LLDP neighbours are discovered between two boxes (the daemon is off by default) |
| `pki` | a local CA and a leaf signed by it land under `/var/lib/sentinel/pki` with the right modes |
| `reverseproxy` | TLS terminates on :443 with an on-box leaf and load-balances to a backend |
| `ids` | real traffic on the wire becomes an alert an operator can read — which is also what proves the detector sees anything at all behind an XDP data plane |

## Rust unit tests

```shell
cargo test                       # 274 unit tests
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

CI (`.github/workflows/ci.yml`) runs fmt + clippy + test + release build on every
push/PR. The heavier nixosTests are run locally / on a KVM-capable runner.

## Why some things are verified structurally

`machine.reboot()` of an OVMF image **hangs** in the nixosTest harness (a
firmware-vars / `-no-reboot` quirk). So a test that would otherwise reboot an OVMF
image — the A/B slot switch — verifies the **structure** instead: the slot is written
and re-typed, the bootloader default is switched, the data partition is separate and
writable. The boot-counting/bless mechanism is proven on its own in `verified-boot`
(`Marked boot as 'good'`), and `secureboot` uses pre-enrolled vars and a single boot
for the same reason. Reboot persistence itself *is* tested for real, on the plain
appliance image, by `reboot`.

## Loading & verifying eBPF

The eBPF data plane can only be **loaded/verified by a privileged host** (it needs
root to attach XDP). The nixosTests run that inside their sandboxed VMs — which is
why the firewall and NAT checks above, not the unit tests, are the real proof of the
datapath. On a dev box, loading the agent against a live kernel is a manual,
root-only step; it is not part of `cargo test`.
