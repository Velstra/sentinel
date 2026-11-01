# Test suite (nixosTests)

Sentinel has Rust unit tests, compiler and map-contract checks, and a
browser suite that drives the web console against a running appliance. The nixosTests
boot real QEMU/OVMF VMs — several of them two or three at a time on shared virtual
segments — so they need `/dev/kvm`.

```shell
nix flake check --no-build                        # evaluate every check
nix flake check                                   # evaluate and run every check
./tests/evaluate-flake.sh                        # bounded evaluation plus VM diagnostic/override interfaces
nix build .#checks.x86_64-linux.<name> -L         # run one
```

The tables below group them by what they exercise; `nix flake show` is the
authoritative list.

The unit tests need nothing but a checkout:

```shell
cargo test --workspace
tests/console/run.sh                              # the browser suite
```

`checks.contract` is the other sandbox check, and the one that closes a seam no
suite on either side was exercising: it builds a configuration that uses the
corners, compiles it, and hands the result to the **pinned** data plane's own
`velstra validate`. Pinned matters — it is the contract with the agent that will
actually be deployed. It exists because a rule naming ICMP compiled cleanly here
and was rejected by that loader on the box: both repositories were tested and
the join between them was not.

The browser suite is dependency-free — it drives Chromium over CDP using node's
own WebSocket — and every test in it exists because the thing it checks was once
broken in a way that looked fine: the page loaded, the layout was right, and the
button did nothing. `tests/console/coverage.mjs` is the companion tool: it
instruments the page and asks it which configuration paths it can actually
write, which is how ten sections that could be typed and not clicked were found.

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
| `api` | the REST management API drives one config model end to end; health, login and OpenAPI documentation are public, management operations require authentication; the console fetches nothing external; its API paths answer; zone, NAT, routing, VPN and DHCP changes use the CLI commit path; command exports replay faithfully; complete-candidate validation cannot apply or save; packet capture sees real ICMP and refuses filters that become options; command refusals are reported; unrelated stack members are refused |

### Also here

| Check | Proves |
|---|---|
| `console` | the web console in a **real browser**: every section opens, a create panel stages a command the CLI accepts, applying writes the file, a wrong password is refused and says so |
| `contract` | the compiled agent config keeps the shape the data plane reads |
| `reconcile` | failed VXLAN/SRv6 controller updates preserve active filtering and retry the same revision; a late egress device installs its deferred route and carries real traffic without restarting |
| `wren-reconcile` | real Wren/XDP traffic: failed installs and withdrawals retry without duplicate advertisements; unavailable ARP observations preserve forwarding; recovery applies cached routes; empty withdrawals need no ARP lookup; gateway MAC changes converge without a route event |
| `state-device` | boot-owned state despite colliding labels; real plaintext and encrypted RAID reboots, password requests, fsck, operator diagnostics and persistent markers; foreign data remains untouched |
| `shipped` | what the image actually carries |
| `wizard` | the installer's click-through, answered end to end |

## Firewall (eBPF data plane)

| Check | Proves |
|---|---|
| `ebpf-verifier` | real-kernel verification and JIT of every embedded XDP/TC program; tenant hooks recover after interface replacement without descriptor leaks; broken statistics output and exhausted descriptors preserve packet filtering, and query/portal/mapping sockets recover without a restart |
| `startup-continuity` | fresh verification fails closed; an established IPv6 TCP socket survives a killed agent, paused kernel verification and activation, retaining state maps |
| `scope-lifecycle` | stable semantic policy scopes through renumbering, deletion, restart and API import/export |
| `stateful-packet-validation` | actual packaged IPv6 packet entries reject truncated and inconsistent protocol headers |
| `rule-contexts` | independent IPv4/IPv6 ingress/egress rules at the same match, 64 real HTTP verdicts, deletion, saved configuration and cold boot |
| `config-transaction` | a full kernel map rejects the candidate without admitting forbidden packets; the same revision recovers after capacity returns; temporary NAT grants survive rollback and successful updates; standalone configured forwards cannot be replaced or removed by temporary grants; failed rollback blocks traffic |
| `egress-transaction` | packet capture at the receiving namespace proves a failed update never detaches the previous egress filter; an unresponsive controller cannot prevent bounded agent shutdown |
| `reject` | a rejected TCP port answers with a **RST**, not a silent drop |
| `rejectudp` | a rejected UDP port answers with **ICMP port-unreachable** |
| `log` | per-rule logging fires for a logged drop and a logged pass, and stays quiet otherwise |
| `srcfilter` | a rule's `source` CIDR matches the intended client and only that one |
| `nat` | (also) a rule's `destination` CIDR admits one target and denies another, and a rule's rate `limit` holds its bucket's bound |
| `fwgroups` | address and port groups expand at compile time to the full sources × ports product |
| `fwdomain` | a domain group resolves to addresses the rules match on, the answer is cached, and a **failed lookup keeps it** rather than emptying a blocking rule |
| `fwschedule` | a rule with a weekly schedule is in the data plane **only** inside its window |
| `v6exthdr` | IPv6 extension headers do not bypass a rule — the chain is walked to the real protocol |
| `icmptype` | a rule that names an ICMP **type** matches that type and not the protocol: a ping is stopped by an `echo-request` rule and not by one for a different type, and the two families are numbered apart (`echo-request` is 8 in ICMP, 128 in ICMPv6) |
| `rulescope` | a rule scoped to one address family stops that family and leaves the other alone, and one scoped to `out` refuses a connection **this box originates** while the same port arriving from outside is untouched |
| `flowspec` | real Wren advertisements stop packets and withdrawal restores traffic; unsupported matches are refused; an established flow cannot bypass a discard with HA state synchronization active; global enforcement works without zones and can be disabled and reenabled through config alone |
| `evpn` | the appliance's one `[evpn]` statement reaches **both** lower halves: two boxes bring up a BGP session with the EVPN address family negotiated, and each data plane's own loader accepts the overlay it was given |
| `macgroup` | a rule naming a `mac-group` stops the device whose address it holds, and a group naming a different device does not — so the match is on the address, not on everything |

### Also here

| Check | Proves |
|---|---|
| `egress` | deny-by-default must not gag the box: it still answers what it admits, can start a conversation of its own, can ping — and a stateful deny-by-default zone brings the egress hook with it, with no rule helping |
| `srcprefix` | every source-prefix **length** matches, not just the convenient ones |
| `v6rules` | a rule scoped to IPv6 lands in its own trie and does not open the v4 one |

## NAT

| Check | Proves |
|---|---|
| `nat` | a `[[port-forward]]` DNATs an inbound connection to an internal host; a load-balanced VIP reaches a pool in **another zone** and its reply is un-NAT'd; both still work when the internal zone denies by default |
| `synproxy` | a client reaches a syn-protected server through the full cookie splice, and 200 spoofed SYNs are absorbed without one reaching it |
| `masq` | masquerade SNATs a private LAN client out of the WAN address; a 1 MiB transfer is accounted to that client in `show top-talkers`; the IPFIX exporter sends a well-formed RFC 7011 message; an acknowledged TCP stream survives an unchanged commit without replacing runtime files or restarting the firewall and routing daemons |
| `hairpin` | an internal client reaches a port-forwarded service via the box's **own** public IP |
| `npt66` | stateless, checksum-neutral IPv6 prefix translation (RFC 6296) |
| `nat64` | an IPv6-only client reaches an IPv4-only server through the box, DNS64 included |
| `conntracksync` | NAT traffic creates state that is transferred to two peers; this check verifies replication, not survival of an established TCP connection during failover |

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
| `routingimport` | the half `policy` does not cover: an **import** filter declines to install what the peer offers, a VRF's static is in its own table and nowhere else, and redistribution rides an export filter |
| `ospfinterop` | OSPFv2 against **FRR** rather than against ourselves — reaches Full, is still Full a minute later, and a route crosses it |

## Interfaces & L2

| Check | Proves |
|---|---|
| `l2` | a bridge and a bond, synthesised on the same networkd render path as VLANs |
| `c14` | MACVLAN and QinQ, the two remaining networkd-rendered L2 types |
| `macsec` | 802.1AE link encryption comes up from a pre-shared key |
| `l2tp` | a static L2TPv3 Ethernet pseudowire over the underlay |
| `tunnel` | kernel GRE tunnels between two appliances |
| `linkopts` | per-interface MTU (jumbo frames / PPPoE) and MAC cloning reach the link |
| `linkbehaviour` | per-link forwarding, ARP and DHCP-client identity reach the kernel, and a mirror carries traffic |
| `vti` | a route-based IPsec tunnel: the link is a real `xfrm` device, the child SA carries its id both ways, and **withdrawing the route stops the traffic with the SA untouched** — which a policy-based tunnel cannot do from one side |
| `wireless` | an access point and a station over two simulated radios: hostapd puts the link in AP mode, a client associates **over the air** with the passphrase, and — from its own network namespace, so the kernel cannot short-circuit the path — carries IP traffic |
| `wwan` | the cellular dial script through its unit, against a stand-in for `mmcli` that reports **two** modems: which one is dialled, that the SIM is unlocked through its own path rather than the modem index, and that a dropped bearer is re-dialled |
| `dualstack` | one interface carries an independent static IPv4 **and** IPv6 address |

## Address & name services

| Check | Proves |
|---|---|
| `dhcp` | the built-in DHCP server leases to a LAN client |
| `dhcp6` | stateful DHCPv6 leases — the stateful sibling of `ra` |
| `ra` | IPv6 Router Advertisements give a client a SLAAC address |
| `dhcp6pd` | DHCPv6-PD requests a delegated prefix upstream (the German-ISP WAN v6 model) |
| `dhcprelay` | DHCP relay across two segments: a client whose own segment has no server gets a lease from the far one, with the data plane attached so the relay is proved to work *through* it |
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
| `wireguard` | a real WireGuard interface and peer; private 0640 units remain unreadable to an ordinary operator, unchanged commits preserve the unit, interface and daemon identities, and binary drift and restrictive permission drift recover |
| `ipsec` | an IKEv2 site-to-site tunnel establishes and carries traffic between protected subnets |
| `openconnect` | a road-warrior client dials in and reaches a host behind the box |

## Services

| Check | Proves |
|---|---|
| `ssh` | `set services ssh` tunes the daemon; `set system login` creates real accounts and keys |
| `login-reconcile` | real SSH/PAM verifies password removal, rotation, whole-login revocation, private password transport, password-only ownership, legacy keys, idempotency, write/service failures, boot reconciliation, power-loss recovery and disabled SSH without deleting account IDs or touching unrelated users |
| `service-reconcile` | real daemon recovery after a unit stop, unchanged-configuration idempotency, missing-file drift, refused starts/stops, rollback and retry without saving a false success |
| `vlan-lifecycle` | actual tagged HTTP and firewall drops; ownership and no-op identity; immutable ID/parent and QinQ replacement; foreign-device/dependency refusal; DOWN staging during a real agent startup fault and automatic recovery; interrupted alias recovery, proven legacy migration, kernel deletion and saved VLAN recreation after reboot |
| `network-reconcile` | VLAN parent cycles are refused before runtime changes and duplicate tag constraints match the real kernel, including different TPIDs; unavailable networkd prevents a false successful commit/save; pending reloads retry even after all unit files were written, acknowledged unchanged units need no reload, and saved addressing survives a real reboot |
| `datapath-lifetime` | real XDP ingress and TC egress policies survive SIGKILL and service stop; per-interface readiness rejects actual detached hooks and wrong policy mappings; restarts adopt pinned links under a shared closed gate, conflicting writers are refused, partial replacement stays closed, failed hook retirement reports its cause and recovers without a restart, and only explicit privileged cleanup removes owned hooks |
| `agent-readiness` | real daemon startup failure cannot be committed/saved as success through CLI or API; rollback preserves desired state, retry converges, a repeated apply repairs a blocked active daemon with a frozen configuration map, healthy unchanged services preserve their identities, and removing the last zoned interface restores the actual fallback without stale hooks |
| `xdp-mode-transition` | a real jumbo-MTU native-to-generic replacement uses a pinned ingress guard; a partial startup failure and a kernel state with no XDP hook remain closed without a daemon, then retry restores TCP connectivity and filtering and retires the guard |
| `snmp` | a read-only v2c poll answers, and the rendered config stays 0640 |
| `lldp` | LLDP neighbours are discovered between two boxes (the daemon is off by default) |
| `pki` | a local CA and a leaf signed by it land under `/var/lib/sentinel/pki` with the right modes |
| `reverseproxy` | Operator commits keep TLS keys private; HTTPS/TCP balancing, issuing-CA verification, wrong-hostname/untrusted-CA rejection, and unchanged proxy identity across unrelated commits |
| `geoip` | a neighbour is reachable, then unreachable once its country is blocked, then reachable again — with a substituted database so the assertion is about the mechanism |
| `acme` | a certificate is really issued — the appliance registers with a Pebble directory, serves the http-01 challenge on :80, and Pebble fetches it back before signing |
| `bcastrelay` | a broadcast on one segment reaches another carrying the ORIGINAL sender's address — the property request/response discovery depends on — and arrives exactly once |
| `syslog` | the journal really leaves the box as RFC 5424 and a collector receives it — which is what proves the appliance can be watched from somewhere that survives it |
| `alerts` | a unit that fails delivers a webhook and a mail, driven by systemd's own `OnFailure=` rather than by a log scrape, so the alert fires on the event and not on a message that mentions one |
| `spoofing` | a forged LAN source on the WAN link is refused by `strict` but not by `loose` (it is routable, just not there), a loopback source by both, and honest traffic keeps flowing throughout |
| `ids` | real traffic on the wire becomes an alert an operator can read — which is also what proves the detector sees anything at all behind an XDP data plane; then that an alert blocks its source in the data plane, and that `never-block` stops it; and a TLS handshake announcing a `sni-block`ed name gets the **server** blocked, not the client |
| `portal` | a guest zone holds every device until somebody logs in: DHCP still works from behind the gate, the portal page is reachable while nothing else is, the wrong passphrase admits nobody, a login puts that device through, and `clear portal session` holds it again. Also the run that puts the gate in front of the **verifier** |
| `portmap` | a host on the inside opens its own inbound port by NAT-PMP, and the mapping is read back out of the **agent** — so what is asserted is the data plane's own table, not a tally kept beside it; a privileged port is refused with nothing granted alongside the refusal, and both the protocol's delete and `clear port-mapping` take it away. That the resulting forward then DNATs is `nat`'s subject, not re-proven here |

## Rust unit tests

```shell
cargo test                       # 478 unit tests
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

`link-defaults` checks measured physical MTU/MAC restoration, unchanged apply and targeted drift repair, actual IPv4/IPv6 HTTP and denied IPv4 ICMP, early invalid-source-MAC refusal, persistent state after warm reboot, full-interface removal, and a real foreign same-name device appearing before another commit.

`link-driver-limit` repeats the physical-link lifecycle with a real virtio MTU ceiling of 1500 and verifies direct kernel rejection of 9000 plus networkd clamping, unchanged saved/running configuration, rollback and IPv4/IPv6 connectivity.

`ipv6-egress` checks actual IPv4/IPv6 TCP and UDP traffic, live outbound policy updates, family/direction scopes, IPv6 source/destination CIDRs, destination blocklist counters, ICMPv6 type filtering and captured Destination Options TCP packets. The separate privileged packet suite checks IPv6 TCP, UDP and echo protocol-state admission, resets, explicit prohibitions and shared rule budgets.

`masquerade-policy` exercises a real LAN namespace through a WAN to a separate VM. It checks policy before source translation, local WAN TCP/ICMP stateful replies, source CIDRs, live deny/allow changes and destination blocklists. Negative requests require both an egress drop counter increase and no SYN at the peer; positive captures and translated source addresses prevent reply-only drops from masquerading as outbound enforcement.

`napt-reservation` uses real forwarded TCP/UDP connections and four CPU-pinned senders to exhaust a one-port CGNAT block. It requires drops before packets reach the peer, stable translated ports, exact payload delivery and continued traffic on the existing connection. It also exercises competing reservations for a free port; no fallback may escape the subscriber block or replace its owner.

### Shared rate budgets

`nix build .#checks.x86_64-linux.rate-budget -L` runs the actual XDP
entry point on four pinned CPUs. It checks exact shared packet/byte credits,
exhaustion, bounded lock contention, counters, and traffic recovery. The test
injects a future refill clock to separate concurrency correctness from VM
scheduling time. It does not qualify connection lifecycle tracking or IPv6
stateful replies.

### FlowSpec with HA synchronization

The `flowspec` VM check enables conntrack synchronization, imports a firewall grant through the peer socket, and verifies the grant in the map referenced by the attached XDP program. A BGP FlowSpec discard must remove the matching grants while synchronization remains enabled; withdrawal restores connectivity.

This checks shared map ownership and revocation. It does not qualify authenticated synchronization or complete stateful failover.
