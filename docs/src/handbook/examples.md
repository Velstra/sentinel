# Example configurations

Complete, commented sessions that tie the sections together. Each is a full
`configure` transcript — paste, `commit`, `save`.

## Home / SOHO router {#soho}

DHCP WAN with masquerade; a trusted LAN that gets DHCP, DNS and IPv6; CAKE on
the uplink to kill bufferbloat; one inbound port-forward; deny-by-default.

```text
set system hostname home-fw

# WAN — DHCP uplink, masqueraded, quiet
set interface eth0 zone wan
set interface eth0 address dhcp
set interface eth0 address6 dhcp
set interface eth0 qos discipline cake
set interface eth0 qos bandwidth 100mbit
set interface eth0 qos rtt internet
set nat source wan-masq zone wan

# LAN — static, serves DHCP + DNS + IPv6 RA
set interface eth1 zone lan
set interface eth1 address 10.0.0.1/24
set interface eth1 dhcp-server enable
set interface eth1 dhcp-server pool-offset 100
set interface eth1 dhcp-server pool-size 100
set interface eth1 dhcp-server dns 10.0.0.1
set interface eth1 router-advert enable
set interface eth1 pd-from eth0
set services dns upstream 9.9.9.9,1.1.1.1
set services dns serve-on eth1
set services dns blocklist ads.doubleclick.net

# Firewall — deny by default; LAN may initiate; publish one service
set firewall global default-action drop
set firewall global stateful true
set firewall zone lan default-action accept
set firewall zone wan block-icmp true
set nat destination web zone wan
set nat destination web proto tcp
set nat destination web port 443
set nat destination web to 10.0.0.10:8443
set nat destination web hairpin true
set firewall rule web-in from wan
set firewall rule web-in to lan
set firewall rule web-in proto tcp
set firewall rule web-in port 443
set firewall rule web-in action accept

# Management — key-only SSH for one admin
set system login admin ssh-key ssh-ed25519 AAAAC3Nz…I admin@laptop

commit
save
```

## Branch office with a site-to-site VPN {#branch}

The SOHO base plus an IKEv2 IPsec tunnel to headquarters, and a firewall rule
letting the two protected subnets talk.

```text
set vpn ipsec hq local 203.0.113.10
set vpn ipsec hq remote 198.51.100.20
set vpn ipsec hq local-subnet 10.0.0.0/24
set vpn ipsec hq remote-subnet 10.1.0.0/24
set vpn ipsec hq psk <pre-shared-key>

set firewall rule hq-in from wan
set firewall rule hq-in to lan
set firewall rule hq-in source 10.1.0.0/24
set firewall rule hq-in action accept

commit
save
```

`show vpn ipsec sas` should list the tunnel as `ESTABLISHED`.

## Dynamic-routing core (OSPF) {#ospf}

A transit box speaking OSPF on two internal links, redistributing its statics,
with BFD for fast failure detection.

```text
set system hostname core-1
set protocols router-id 10.255.0.1

set interface eth1 zone core
set interface eth1 address 10.10.0.1/30
set interface eth2 zone core
set interface eth2 address 10.10.0.5/30

set protocols ospf interface eth1 area 0.0.0.0
set protocols ospf interface eth2 area 0.0.0.0
set protocols ospf network-type point-to-point
set protocols ospf redistribute static
set protocols ospf bfd true

set firewall global default-action accept   # a trusted core; tighten as needed

commit
save
```

`show ip ospf neighbors` should reach `Full`; `show ip route` shows the learned
routes as `proto ospf`.

## Active/standby HA pair {#ha-pair}

HA is **experimental**. Use the current [pairing guide](ha.md), which separates
witness authority, witnessless two-node mode and legacy VRRP. Prepare distinct
member identities and an independent management recovery path before pairing.

VRRP, config sync and conntrack sync configured separately do not form a fenced
cluster and do not guarantee that an established NAT connection survives a
partition or failover. Do not copy one member's addresses, hardware bindings or
SSH listener to another. Run the exact pairing and flow-continuity tests for
the image you intend to use; a matching configuration file is not that proof.

---

For the operational side of running these boxes — installing to disk, updating
A/B slots, rolling back — see the [Operations](../operations/install.md)
chapters.
