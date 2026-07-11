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
