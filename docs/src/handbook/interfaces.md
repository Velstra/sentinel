# Interfaces

`set interface <name> …` configures a NIC: its firewall zone, addresses, and
optionally a virtual type (VLAN, bridge, bond, tunnel, …). The interface name
is either a real NIC (`eth0`), a VLAN subinterface (`eth0.20`), or a name you
pick for a virtual device (`wg0`, `br0`, `gre1`).

## Common fields

| Field | Meaning |
|---|---|
| `zone` | The firewall zone this NIC belongs to (see [Firewall & NAT](firewall.md)). |
| `address` | Static IPv4 CIDR (`10.0.0.1/24`) or `dhcp`. |
| `address6` | Static IPv6 CIDR, `auto` (SLAAC) or `dhcp` (DHCPv6). |
| `description` | Free-text label (rendered as a unit comment). |
| `disabled` | Administratively disable this NIC (`true`/`false`). |
| `mtu` | Link MTU in bytes (e.g. `1492` for PPPoE, `9000` jumbo). |
| `mac` | Override the link MAC (MAC cloning), e.g. `52:54:00:12:34:56`. |

```text
set interface eth0 zone wan
set interface eth0 address dhcp
set interface eth1 zone lan
set interface eth1 address 10.0.0.1/24
set interface eth1 address6 2001:db8:0:1::1/64
```

## VLANs (802.1Q / QinQ)

Name a subinterface `<parent>.<id>` to infer it, or set `parent`/`vlan`
explicitly. `vlan-protocol 802.1ad` makes it a QinQ service tag.

```text
set interface eth1.20 zone iot          # infers parent eth1, vlan 20
set interface eth1.20 address 10.0.20.1/24
```

| Field | Meaning |
|---|---|
| `parent` | Parent interface (for a VLAN subinterface or macvlan). |
| `vlan` | 802.1Q VLAN id 1–4094 (with `parent`). |
| `vlan-protocol` | `802.1q` (default) or `802.1ad` (QinQ S-tag). |

## Virtual interface types

`set interface <name> type <…>` turns a name into a virtual device:

| Type | What it is |
|---|---|
| `bridge` | An L2 switch; enslave NICs with `member` (optionally `vlan-aware`). |
| `bond` | Link aggregation; enslave NICs with `member` + `bond-mode`. |
| `wireguard` | A WireGuard tunnel; keys/peers under [`vpn wireguard`](vpn.md#wireguard). |
| `pppoe` | A PPPoE client over a raw uplink NIC (VDSL/fibre WAN). |
| `gre` / `ipip` / `gretap` | Kernel L3/L2 tunnels (`local`/`remote`, optional `key`/`ttl`). |
| `macvlan` | A pseudo-NIC on a `parent` with its own MAC (`macvlan-mode`). |
| `macsec` | An encrypted 802.1AE link on a `parent` (`macsec-key`/`macsec-peer`). |
| `l2tpv3` | An L2TPv3 Ethernet pseudowire between `local`/`remote` (`key` = tunnel id). |
| `vti` | A route-based IPsec link (`vti-key` = its id); bind a tunnel with `vpn ipsec <n> vti`. |
| `wireless` | A radio; `[interface.wireless]` says whether it makes a network or joins one. |
| `wwan` | A cellular modem; `[interface.wwan]` is the bearer it dials. |
| `dummy` | A link that is always up, for an address no cable can take away. |

### Bridges & bonds

```text
set interface br0 type bridge
set interface br0 member eth1
set interface br0 member eth2
set interface br0 zone lan
set interface br0 address 10.0.0.1/24

set interface bond0 type bond
set interface bond0 bond-mode 802.3ad      # or active-backup, balance-rr, …
set interface bond0 member eth3
set interface bond0 member eth4
```

A `vlan-aware` bridge does 802.1Q filtering; its member ports take
`vlan-tagged <id,…>` and a `vlan-untagged <id>` (PVID).

### Tunnels

```text
set interface gre1 type gre
set interface gre1 local 203.0.113.1
set interface gre1 remote 198.51.100.1
set interface gre1 key 42                  # gre/gretap only
set interface gre1 zone tunnel
set interface gre1 address 10.255.0.1/30
```

## PPPoE (VDSL / fibre)

A `type = pppoe` interface dials a PPPoE session over a raw uplink NIC. Put the
credentials under the interface's `pppoe` node:

| `pppoe` field | Meaning |
|---|---|
| `username` / `password` | ISP login (password stored 0600). |
| `service-name` / `ac-name` | Optional PPPoE service / access-concentrator names. |
| `mru` | PPP MRU in bytes (default = mtu or 1492). |

```text
set interface wan0 type pppoe
set interface wan0 parent eth0             # the raw NIC the session runs over
set interface wan0 zone wan
set interface wan0 pppoe username user@isp
set interface wan0 pppoe password secret
set interface wan0 mtu 1492
```

## IPv6 addressing & prefix delegation

| Field | Meaning |
|---|---|
| `address6 auto` | SLAAC (accept RAs). |
| `address6 dhcp` | Stateful DHCPv6. |
| `pd-from <uplink>` | Request a delegated prefix from this uplink (DHCPv6-PD). |
| `pd-subnet <0-255>` | Which `/64` of the delegated prefix to use on this LAN. |

```text
set interface wan0 address6 dhcp
set interface wan0 pd-from wan0            # request a prefix on the WAN
set interface eth1 pd-from wan0            # …carve a /64 for the LAN
set interface eth1 pd-subnet 1
```

## Serving the LAN: DHCP & Router Advertisements

An interface with a static subnet can hand out addresses and advertise itself.

`dhcp-server` (IPv4):

| Field | Meaning |
|---|---|
| `enable` / `disable` | Turn the server on/off. |
| `pool-offset` / `pool-size` | First address offset in the subnet, and pool size. |
| `dns` | DNS servers to advertise (comma-separated). |
| `lease-time` | Lease time (`12h`, `1h30m`, or seconds). |
| `default-router` | Override the advertised gateway. |
| `domain` | Domain name to advertise. |
| `static-mapping <name> mac <mac> ip <ip>` | A fixed lease. |

`router-advert` (IPv6 SLAAC / stateful DHCPv6):

| Field | Meaning |
|---|---|
| `enable` / `disable` | Turn the RA sender on/off. |
| `prefix` | `/64` prefixes to advertise (comma-separated). |
| `dns` | IPv6 DNS servers to advertise. |
| `managed` / `other-config` | The M / O flags. |
| `router-lifetime` | Router lifetime seconds (`0` = not a default router). |
| `dhcp6-pool` | A stateful DHCPv6 address pool (`start` / `end` / `lease-time`). |

```text
set interface eth1 dhcp-server enable
set interface eth1 dhcp-server pool-offset 100
set interface eth1 dhcp-server pool-size 100
set interface eth1 dhcp-server dns 10.0.0.1
set interface eth1 dhcp-server static-mapping printer mac 52:54:00:aa:bb:cc ip 10.0.0.5

set interface eth1 router-advert enable
set interface eth1 router-advert prefix 2001:db8:0:1::/64
```

## Egress QoS (bufferbloat)

`qos` shapes traffic leaving an interface — CAKE on a WAN uplink kills
bufferbloat outright.

| Field | Meaning |
|---|---|
| `discipline` | `cake` (shaper + AQM) or `fq_codel` (AQM only). |
| `bandwidth` | CAKE shaping rate, e.g. `100mbit` (or `unlimited`). |
| `rtt` | CAKE path RTT — a time (`100ms`) or a preset (`internet`, `lan`, …). |
| `nat` / `ack-filter` | CAKE per-host fairness through NAT / thin redundant ACKs. |
| `diffserv` | CAKE tin mode (`besteffort`/`diffserv3`/`diffserv4`/`diffserv8`). |
| `target` / `interval` / `limit` | fq_codel knobs. |

```text
set interface wan0 qos discipline cake
set interface wan0 qos bandwidth 100mbit
set interface wan0 qos rtt internet
```

## MACsec

An encrypted point-to-point link on a `parent` NIC, keyed by a pre-shared key
and the peer's MAC:

```text
set interface eth2 type macsec
set interface eth2 parent eth1
set interface eth2 macsec-key 0123…(32/64 hex)…
set interface eth2 macsec-peer 52:54:00:de:ad:be
set interface eth2 zone lan
```


## Clamping TCP MSS

```text
set interface tun0 mss 1360
set interface tun0 mss pmtu
```

A tunnel is where this bites. The two ends agree an MSS from *their* MTUs during
the handshake, and neither knows about the encapsulation in between — so the
session establishes, small requests work, and the first large response
disappears. It looks like an application fault for as long as it takes somebody
to think of MTU.

PPPoE is clamped automatically because its MTU is not negotiable. A WireGuard or
GRE link has to be told. `pmtu` clamps to whatever the path turns out to be;
a number clamps to that number.

## Offload

Seven features were already settable; the full set the kernel exposes is now
there: `gro`, `gso`, `tso`, `lro`, `sg`, `rx`, `tx`, `rxvlan`, `txvlan`,
`ntuple`, `rxhash`.

```text
set interface eth0 offload gro true
set interface eth0 offload rxhash true
```

## Router advertisements

How IPv6 hosts learn there is a router and what prefix to use.

```text
set interface eth0 router-advert enable
set interface eth0 router-advert prefix 2001:db8:1::/64
set interface eth0 router-advert managed true
set interface eth0 router-advert dhcp6-pool start 2001:db8:1::1000
set interface eth0 router-advert dhcp6-pool end   2001:db8:1::2000
```

`managed` sends hosts to DHCPv6 for an address as well; `other-config` sends
them there for everything *but* the address.

`enable` takes no value — it is a verb, not a setting, which is why the console
gives it a button rather than a field. Turning it off is deleting the block.

## DHCP reservations

```text
set interface eth0 dhcp-server static-mapping printer mac 00:11:22:33:44:55
set interface eth0 dhcp-server static-mapping printer ip 10.0.0.9
```

The same address every time, for a machine that has to be findable. The name is
not the MAC on purpose: a machine can be replaced without the reservation losing
what it was for.

The address must be in the server's subnet but **outside its pool**, or the
server will hand it to somebody else as well.

## NIC hardware

```text
set interface eth3 ethernet speed 1000
set interface eth3 ethernet duplex full
set interface eth3 ethernet rx-ring 4096
set interface eth3 ethernet tx-ring 4096
set interface eth3 ethernet rx-usecs 50
set interface eth3 ethernet adaptive-tx true
```

`speed` and `duplex` are **one setting in two halves** and are refused apart:
`ethtool` applies them together, and a card handed only one keeps
autonegotiating — the link comes up at the wrong speed with nothing reporting a
problem. Forcing them is for the case where the far side does not negotiate: an
old switch port, a media converter, a direct-attach cable. It is also a good way
to break a working link, so autonegotiation stays the default.

`rx-ring` is the first answer to a NIC dropping packets under burst — the symptom
is `rx_dropped` climbing while the CPU is idle.

The coalescing settings trade latency for interrupts. On a firewall forwarding
small packets that trade is usually worth making; `0` is what a latency-sensitive
link wants. `adaptive-rx`/`adaptive-tx` hand the choice to the driver instead,
and are refused alongside a fixed `rx-usecs`/`tx-usecs` — asking the driver to
both hold a number and vary it is asking for neither.

**Every one of these is best-effort.** A card that does not implement ring
resizing, refuses a coalescing value, or has no notion of a forced speed draws a
warning naming the setting; the rest still apply and the commit succeeds. A
virtio NIC in a virtual machine has none of the three, which is exactly why the
commit must not fail on them.

## Bridge detail

Set on the **bridge device**, not on its ports:

```text
set interface br0 bridge stp true
set interface br0 bridge priority 4096
set interface br0 bridge hello-time 2
set interface br0 bridge max-age 20
set interface br0 bridge forward-delay 15
set interface br0 bridge ageing-time 300
set interface br0 bridge igmp-snooping true
set interface br0 bridge igmp-querier true
```

`stp` is off by default, and that is right for a bridge whose ports are known:
spanning tree costs `forward-delay` seconds of silence at every link-up. Turn it
on the moment a loop is *possible* — two ports to the same switch, or a port an
operator can patch anywhere — because the alternative is a broadcast storm.
The four timers are only read when it runs, so setting one without it is refused
rather than silently ignored.

`ageing-time` is how long a learned MAC stays in the forwarding table; `0`
disables learning and turns the bridge into a hub.

With `stp` on, the configured ageing time is **not** what the bridge uses for the
first `max-age + forward-delay` seconds after a topology change: 802.1D says to
age the forwarding database out faster while the topology settles, and Linux uses
`2 x forward-delay` for that window. `ip -d link show br0` reports
`topology_change 1` while it lasts. The setting is applied throughout — the
kernel is overriding it, and it stops when the topology-change timer expires.

`igmp-snooping` forwards a multicast group only to the ports that asked for it —
without it, every group floods every port, which is what turns one video or
discovery stream into a load on the whole segment. Snooping needs somebody to
ask: on a segment with no multicast router, `igmp-querier` makes the bridge ask,
and without it the memberships time out and the groups flood again. A querier
without snooping is refused.

### As a port of a bridge

Set on the **member**, because each port has its own:

```text
set interface eth5 bridge-port cost 100
set interface eth5 bridge-port priority 32
set interface eth5 bridge-port learning false
```

`cost` is what decides which of two paths to the root is blocked. Setting it by
hand is how you choose *which* link is blocked instead of letting the speed
heuristic choose. `learning false` makes the port flood-only — what a monitoring
or IDS port wants, so a device listening there cannot attract traffic merely by
being seen.

## Bond detail

```text
set interface bond0 bond hash-policy layer3+4
set interface bond0 bond lacp-rate fast
set interface bond0 bond min-links 2
set interface bond0 bond primary eth3
set interface bond0 bond mii-interval 100
set interface bond0 bond arp-interval 2000
set interface bond0 bond arp-target 10.0.0.1
```

**`hash-policy` is the one that surprises people.** The default `layer2` puts
every frame between one pair of MACs on one member, so a bond between two
switches carries a single conversation at the speed of one link no matter how
many are in it. `layer3+4` hashes on IP and port, which is what makes an
aggregate behave like the sum of its parts.

`min-links` is the number of members that must be up for the bond itself to be
up. Leave it at the default where half an aggregate is better than none; raise it
where half an aggregate is *worse*, because the traffic it attracts will not fit.

`primary` is the member preferred while it is up (active-backup and the
balance-tlb/alb modes). Without it a failover does not fail back. It must be one
of the bond's own members.

**Two kinds of failure detection, and they catch different things.**
`mii-interval` is carrier detection: it notices an unplugged cable and nothing
else. `arp-interval` with `arp-target` probes an address reached *through* the
bond — its gateway, typically — and notices the failure that matters most on an
aggregate: a link that is up and carries nothing because the switch on the far
side is wedged. An interval with no target monitors nothing and targets with no
interval are never probed, so the two are refused apart.

## Cellular (`wwan`)

```text
set interface wwan0 type wwan
set interface wwan0 zone wan
set interface wwan0 address dhcp
set interface wwan0 wwan apn internet
set interface wwan0 wwan ip-type ipv4v6
```

The `[interface.wwan]` block gets the **bearer** up; the address comes from
`address dhcp` the way it does on any other uplink, and a link without it is
refused. A modem is a WAN link that happens to dial, and giving it its own kind
of addressing would be a second path to the same answer. It pairs with
multi-WAN failover unchanged.

`username`/`password` are PAP/CHAP where the operator wants them, which most do
not, and they are set together — a password with nobody to be is a credential
the modem cannot send.

**Think before setting a `pin`.** A wrong PIN tried three times locks the card,
and a box that re-dials on failure is a box that will try three times. The dial
script asks the modem whether the SIM is actually locked before sending one, and
a malformed PIN is refused at commit rather than spent against the card — but
the safest SIM in an appliance is one with the PIN disabled.

The modem is located by the network device it provides, not by a ModemManager
index. Indices are assigned in probe order and move when a modem is re-plugged
or a second one appears, and dialling the wrong modem is worse than not
dialling.

The dial script loops. A cellular bearer drops — a tunnel, a cell change, an
operator-side timeout — and an uplink that dials once is an uplink that is down
until somebody notices.

### What is not verified here

There is no modem in a virtual machine, so unlike every other interface type in
this handbook, this one has no check that proves it works end to end. What is
tested is the rendering: which `mmcli` invocation is built from which
configuration, that a PIN is only sent when one is set and only to a locked SIM,
and that the modem is found by its interface rather than by an index. That it
then dials will first be proven by real hardware.

## Wireless

An access point — this box makes the network:

```text
set interface wlan0 type wireless
set interface wlan0 zone lan
set interface wlan0 address 10.0.10.1/24
set interface wlan0 wireless mode access-point
set interface wlan0 wireless ssid velstra
set interface wlan0 wireless country DE
set interface wlan0 wireless channel 6
set interface wlan0 wireless band n
set interface wlan0 wireless wpa mode wpa2+wpa3
set interface wlan0 wireless wpa passphrase <pre-shared-key>
```

A station — this box joins somebody else's:

```text
set interface wlan0 type wireless
set interface wlan0 wireless mode station
set interface wlan0 wireless ssid <their-network>
set interface wlan0 wireless wpa passphrase <their-key>
```

`band` carries the frequency as well as the generation: `b`, `g` and `n` are
2.4 GHz, `a`, `ac` and `ax` are 5 GHz. `country` is what makes channels and
powers legal, and it is **required on an access point** — a radio with no
regulatory domain is held to the intersection of every regime, which on 5 GHz is
almost nothing.

An access point also needs WPA. An open network is refused rather than warned
about: it is not a thing to arrive at by leaving something out. A *station* may
join an open network, because that one is somebody else's and refusing to join
it protects nobody.

`wpa2+wpa3` is a transition network that takes both. WPA3 is SAE with mandatory
management-frame protection; in the transition mode that protection becomes
optional, because otherwise the WPA2 clients the mode exists for cannot
associate.

`hide-ssid` keeps the name out of beacons. Worth knowing what it does and does
not do: it hides the network from a casual scan and from nobody else, because a
client that knows the name broadcasts it while looking. A hidden network is
announced by its own clients instead of by its access point.

`isolate-stations` stops associated clients reaching each other over the air —
what a guest network wants, and what a network with a printer on it does not.

The rendered radio configuration contains the pre-shared key, so it is written
0600 in a 0700 directory. Unlike IPsec there is no separate secrets file to split
it into: hostapd and wpa_supplicant each want the key inside their one config.

### What is not here

VyOS exposes about 150 nodes for a radio, and roughly 130 of them are the
HT/VHT/HE capability trees — a passthrough of hostapd's own flags, each
meaningful only with a particular chipset and each able to make a working radio
refuse to come up. What is offered here is what decides whether the network
exists, who may join it, and on which channel. If a specific capability turns out
to be needed on real hardware, it is a small addition; guessing at 130 of them in
advance is not.

## Route-based IPsec (`vti`)

```text
set interface vti0 type vti
set interface vti0 vti-key 42
set interface vti0 zone vpn
set interface vti0 address 10.255.0.1/30
set interface vti0 mss pmtu
```

A link whose traffic is encrypted by whichever `[[vpn.ipsec]]` connection binds
to it with `set vpn ipsec <name> vti vti0`. What makes it worth having is that
the tunnel then has an *interface*: its reach is a route rather than a
negotiated list of subnets, it can carry a firewall zone, and it can be clamped.
The full explanation is under [IPsec](vpn.md).

## Per-link IPv4 and IPv6 behaviour

These are kernel switches that belong to one link rather than to the box. The
firewall decides whether a packet may pass; these decide whether the link is a
router at all, whose ARP it answers, and which address it announces itself
under.

```text
set interface eth0 ip disable-forwarding true
set interface eth0 ip proxy-arp true
set interface eth0 ip arp-cache-timeout 30
set interface eth0 ipv6 disable-forwarding true
set interface eth0 ipv6 no-link-local true
set interface eth0 ipv6 dad-transmits 2
set interface eth0 ipv6 accept-dad 2
```

`disable-forwarding` is set per family because a link is routinely a router for
one and a host for the other. A management port is the usual case for turning
both off: reachable, and not a path through the box.

Forwarding is written into every link's configuration in both directions, not
only when it is switched off. A router that says nothing about forwarding is at
the mercy of whatever the network manager's own default happens to be, and the
symptom when that default is "off" is a link that carries traffic *to* the box
and none *through* it — with a global `ip_forward` of 1 the whole time.

### The ARP block

Most of this section is ARP, and the reason is multi-homing. On a box with
several NICs in the same subnet — a firewall, in other words — Linux will by
default answer an ARP request on any of them and source a request from whichever
address it likes. The peer's cache then depends on which reply arrived last, and
a redundant pair of links becomes a pair of hosts that disagree about who owns
an address.

```text
set interface eth0 ip arp-filter true      # only answer for an address on this link
set interface eth0 ip arp-ignore true      # the reply half of the same rule
set interface eth0 ip arp-announce true    # source from an address on the target's subnet
set interface eth0 ip arp-accept true      # learn from gratuitous ARP (faster failover)
```

`proxy-arp` is the opposite instruction — answer *here* for hosts that live
elsewhere — which is why setting it together with `arp-ignore` is refused at
commit rather than silently resolved by the kernel ignoring the proxy.
`proxy-arp-pvlan` extends it between isolated ports of one private VLAN, and
needs `proxy-arp`.

`directed-broadcast` forwards a subnet-directed broadcast onto the link.
Wake-on-LAN across a router wants it; it is also the amplifier half of a smurf
attack, so it stays off until asked for.

## DHCP client options

What this link's client sends and accepts. A residential or business uplink
frequently keys the subscriber off one of these, and the failure mode when it is
missing is not an error message — it is a line that never gets an address.

```text
set interface wan0 address dhcp
set interface wan0 dhcp client-id mac
set interface wan0 dhcp host-name fw
set interface wan0 dhcp vendor-class-id sentinel
set interface wan0 dhcp user-class residential
set interface wan0 dhcp no-default-route true
set interface wan0 dhcp default-route-distance 210
set interface wan0 dhcp reject 192.0.2.9
```

`client-id` is a choice — `mac` or `duid` — and not free text. Other vendors let
you type an arbitrary client identifier because their client is `dhclient`; this
box's network layer builds DHCP option 61 itself, and an arbitrary string handed
to it is discarded without a word. The choice is what actually reaches the wire,
so that is what the setting offers.

It is not a cosmetic choice. `mac` keys the lease to the NIC, so it survives a
reinstall of the appliance; the default `duid` is derived from the machine-id, so
a rebuilt router asks for a different lease. `set interface wan0 dhcp duid <hex>`
pins the DUID instead, and needs `client-id duid` to carry it.

`no-default-route` takes the address and the DNS from the lease but not the
route — for a second uplink whose route is chosen by policy rather than by
whichever server answered first. Two DHCP uplinks with the same
`default-route-distance` are a coin toss; distinct metrics are a primary and a
backup. `reject` refuses offers from a server address or CIDR, which is the
rogue-DHCP case and the one where a lab server on the same wire is faster than
the real one.

```text
set interface wan0 address6 dhcp
set interface wan0 dhcpv6 duid 00:03:00:01:02:00:00:00:00:01
set interface wan0 dhcpv6 rapid-commit true
set interface wan0 dhcpv6 parameters-only true
set interface wan0 dhcpv6 no-release true
```

A fixed `duid` is worth setting on a line with a delegated prefix. The DUID is
otherwise derived from the machine-id, so reinstalling the appliance changes it,
the ISP delegates a different prefix, and every LAN address changes because the
router was rebuilt.

`parameters-only` asks for DNS, NTP and domain but not for an address — the
stateless case, where the address comes from SLAAC.

Both blocks need the matching `address`/`address6` set to `dhcp`; configuring
one without the other is refused at commit, because there would be no client to
carry it.

## Port mirroring

```text
set interface eth1 mirror-ingress mon0
set interface eth1 mirror-egress mon0
```

Every frame arriving on (or leaving) `eth1` is copied to `mon0` — a SPAN port.
What an IDS is fed from, and the first thing to reach for when the packet
counters disagree with the story.

The copy is a copy: the original still goes wherever it was going, and a
destination that cannot keep up drops the mirror rather than the traffic. The
two directions are set separately because one is usually what is wanted —
mirroring both doubles the destination's load and makes a transit flow appear
twice.

The destination must be a configured interface, and may not be the source
itself. Both are refused at commit, because a mirror pointing at a link that
does not exist is a monitor port that is quietly dark, and that failure looks
exactly like "there was no interesting traffic".

Mirroring attaches a `clsact` qdisc, which carries an ingress and an egress
filter hook without owning the root — so it coexists with the `qos` shaper on
the same link, and with the data plane's own TC program.
