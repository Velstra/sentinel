//! The declarative appliance configuration — the single source of truth for an
//! **immutable** Sentinel box.
//!
//! Sentinel is not a mutable system you log into and tweak (VyOS-style). The
//! whole appliance state is one declarative document: you *declare* interfaces,
//! zones, and firewall rules, and the box reconciles to it atomically. This
//! module is the model + parser + validator the CLI is built on; compiling it
//! down to the Velstra data-plane config is the next slice.

use std::{
    collections::{BTreeMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

/// A commented starting config, emitted by `sentinel config init`.
pub const EXAMPLE: &str = r#"# Velstra Sentinel — declarative appliance config.
# Declare the whole box here; `sentinel config apply` reconciles to it.

[system]
hostname = "sentinel-fw"

# Global firewall defaults — every zone inherits these unless it overrides them.
# stateful: allow return traffic for established flows (default true).
# block_icmp: drop inbound ICMP (default false).  blocklist: global source drops.
[firewall]
stateful = true
block_icmp = false
blocklist = []

# Per-zone posture overrides. Zones are arbitrary names; each becomes one
# data-plane policy. Here ICMP is blocked on the WAN but allowed elsewhere.
[zone.wan]
block_icmp = true

[zone.lan]
block_icmp = false

# Interfaces are assigned to a zone. Address is "dhcp" or a CIDR. A VLAN
# subinterface adds `parent` + `vlan`.
[[interface]]
name = "wan0"
zone = "wan"
address = "dhcp"

[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"
# A free-text label (shown in `show`, rendered as a comment on the networkd
# unit) and an administrative disable (link kept down + dropped from the data
# plane) are available on any interface:
# description = "office LAN"
# disabled = false
# Dual-stack: add a static IPv6 (or "auto" for SLAAC / accept-RA).
# address6 = "2001:db8:1::1/64"

# A LAN DHCP server on lan0: hand out a pool, advertise DNS + a gateway, and
# pin a couple of hosts to fixed addresses. In TOML lease-time is seconds (the
# CLI additionally accepts a human duration like 12h / 1h30m).
# [interface.dhcp-server]
# pool-offset = 100
# pool-size = 100
# dns = ["10.0.0.1"]
# lease-time = 43200
# default-router = "10.0.0.1"
# domain = "lan.example"
# [[interface.dhcp-server.static-mapping]]
# name = "printer"
# mac = "52:54:00:12:34:56"
# ip = "10.0.0.20"

# A VLAN subinterface on lan0, in its own zone (802.1Q tagged link). `parent`
# and `vlan` are inferred from a `<parent>.<id>` name, so naming it "lan0.20" is
# enough; set them explicitly only to override — a name/value mismatch is an error.
# [[interface]]
# name = "lan0.20"
# zone = "iot"
# address = "10.0.20.1/24"

# IPv6 on the LAN by SLAAC: advertise a /64 and hosts autoconfigure. The router
# also binds its own address from the prefix, so no separate v6 address needed.
# [interface.router-advert]
# prefixes = ["2001:db8:1::/64"]
# dns = ["2001:db8:1::1"]

# Stateful DHCPv6 instead of SLAAC (roadmap C7): hand out addresses from a pool
# inside the advertised prefix. The Managed (M) flag is forced on so clients ask
# via DHCPv6; a dnsmasq server on the interface leases the addresses.
# [interface.router-advert]
# prefixes = ["2001:db8:1::/64"]
# dhcp6-pool = { start = "2001:db8:1::100", end = "2001:db8:1::1ff", lease-time = 43200 }

# A bridge (switch) that holds the LAN address; the member NICs are listed on
# the device itself with a `member` array (repeated `member <nic>` in the CLI):
# [[interface]]
# name = "br0"
# type = "bridge"
# zone = "lan"
# address = "10.0.0.1/24"
# member = ["lan1", "lan2"]
#
# A bond (link aggregation) — set the mode and the members on the device:
# [[interface]]
# name = "bond0"
# type = "bond"
# bond-mode = "active-backup"
# member = ["lan3", "lan4"]
#
# A VLAN-aware bridge does 802.1Q filtering in the switch: mark the bridge
# `vlan-aware`, then give each member port its tagged VLAN ids and/or a single
# untagged (PVID) VLAN:
# [[interface]]
# name = "br1"
# type = "bridge"
# vlan-aware = true
# member = ["lan5", "lan6"]
# [[interface]]
# name = "lan5"
# vlan-tagged = [10, 20]
# vlan-untagged = 1
#
# MACVLAN (roadmap C14): a pseudo-NIC with its own MAC on a parent link.
# [[interface]]
# name = "mv0"
# type = "macvlan"
# parent = "eth0"
# macvlan-mode = "bridge"        # bridge (default) | private | vepa | passthru
# address = "10.0.0.9/24"
#
# QinQ (roadmap C14): stack a C-tag VLAN on an 802.1ad S-tag VLAN.
# [[interface]]
# name = "eth0.100"              # the outer S-VLAN (service tag)
# parent = "eth0"
# vlan = 100
# vlan-protocol = "802.1ad"
# [[interface]]
# name = "eth0.100.20"           # the inner C-VLAN, riding the S-VLAN
# parent = "eth0.100"
# vlan = 20

# A broad rule (no proto/port) opens a zone's posture with `action = "accept"`
# — here the LAN may initiate outbound. The WAN stays default-drop (the global
# `default-action`), so nothing is needed to keep inbound traffic out; a broad
# `drop`/`reject` rule is a datapath no-op and is rejected at commit — express an
# explicit deny with `firewall zone <z> default-action drop` instead.
# `to = "<zone>"` is optional and declares zone-pair intent; the datapath does
# not enforce the destination zone yet, so setting it draws a commit warning.
[[rule]]
name = "lan-out"
from = "lan"
action = "accept"

# Port rules open a specific proto/port even on a default-drop zone — here,
# inbound HTTPS from the WAN.
[[rule]]
name = "allow-https-in"
from = "wan"
action = "accept"
proto = "tcp"
port = 443

# Box-wide services live under [services.*]. A LAN-facing DNS forwarder (built
# on systemd-resolved, no extra daemon) forwards client queries to upstream
# resolvers and listens for them on lan0:
# [services.dns]
# upstream = ["9.9.9.9", "1.1.1.1"]
# serve-on = ["lan0"]
# cache-size = 1000        # max cached answers (dnsmasq default is 150)
# local-domain = "lan.example"  # answered locally + handed to clients
#
# A LAN NTP server (built on chrony): sync to upstreams, serve lan0's subnet.
# [services.ntp]
# upstream = ["pool.ntp.org"]
# serve-on = ["lan0"]
#
# LLDP link-layer discovery (built on lldpd): advertise + learn neighbours.
# [services.lldp]
# enable = true
# interface = ["lan0", "wan0"]   # omit for every interface
#
# A read-only SNMP agent (built on net-snmp): v2c, scoped to the NOC subnet.
# [services.snmp]
# community = "public"
# location = "rack 4"
# contact = "noc@example"
# allow = ["10.0.0.0/24"]
#
# An mDNS reflector (built on avahi): bridge Bonjour between two segments.
# [services.mdns]
# interface = ["lan0", "iot0"]
#
# A dynamic-DNS client (built on ddclient): keep an FQDN pointed at the WAN IP.
# [services.dyndns]
# provider = "cloudflare"
# hostname = "fw.example.com"
# login = "user@example"
# password = "secret-token"
# interface = "wan0"
#
# A DHCP relay (built on isc dhcrelay): forward DHCP to an upstream server.
# [services.dhcp-relay]
# interface = ["lan0"]
# server = ["10.0.99.1"]
#
# L7 reverse proxy / load balancer (roadmap C22): terminate TLS on a listen
# port (cert from the on-box PKI) and forward to one or more backends
# round-robin. Omit `certificate` for a plain-HTTP proxy.
# [[services.reverse-proxy]]
# name = "web"
# port = 443
# certificate = "web-cert"          # a [[pki.certificate]] name (or "acme")
# backends = ["10.0.0.10:8080", "10.0.0.11:8080"]

# NAT is its own thing (address translation, not filtering). Source NAT
# masquerades a zone's outbound traffic to its egress IP; destination NAT is an
# inbound port-forward.
# [[nat.source]]
# name = "wan-masq"
# zone = "wan"
#
# [[nat.destination]]
# name = "web"
# zone = "wan"
# proto = "tcp"
# port = 443
# to = "10.0.0.10:8443"
#
# NAT64 (roadmap C10): an IPv6-only LAN reaching the IPv4 internet. tayga
# translates 64:ff9b::<v4> → real IPv4 out of `pool`; DNS64 (unbound on
# `interface`) synthesises AAAA for v4-only names so clients need no config.
# Sentinel ships NO application-layer gateways (FTP/SIP ALG) — the modern secure
# default; apps needing NAT traversal use STUN/ICE/TURN.
# [nat.nat64]
# enabled = true
# prefix = "64:ff9b::/96"   # default (RFC 6052 well-known); omit to use it
# pool = "192.0.2.0/24"     # IPv4 source pool for translated flows
# interface = "lan6"        # the IPv6-only side (DNS64 binds its v6 address)
# dns64 = true              # synthesize AAAA (needs [services.dns] upstream)

# Multi-WAN (roadmap C6): two uplinks with health-checked failover. The lowest
# `priority` is the primary; if its health check fails, the default route swings
# to the backup and swings back on recovery. Each uplink also gets its own
# policy-routing table (default route via its gateway). Set mode = "load-balance"
# to spread flows across both uplinks by `weight` instead.
# [multiwan]
# mode = "failover"
#
# [[multiwan.uplink]]
# interface = "wan0"
# priority = 10
# gateway = "192.0.2.1"
# [multiwan.uplink.health-check]
# targets = ["1.1.1.1", "8.8.8.8"]
# interval = 5
# fail = 3
# rise = 3
#
# [[multiwan.uplink]]
# interface = "wan1"
# priority = 20
# gateway = "198.51.100.1"
# [multiwan.uplink.health-check]
# targets = ["1.0.0.1"]
#
# [[vpn.ipsec]]
# name = "site-a"
# local = "203.0.113.1"
# remote = "198.51.100.1"
# local-subnet = "10.0.0.0/24"
# remote-subnet = "10.1.0.0/24"
# psk = "change-me-to-a-strong-shared-secret"
#
# WireGuard (roadmap C1): create a `type = "wireguard"` interface (address/zone
# like any interface), then configure its keys + peers under vpn, keyed by the
# interface name. `private-key` accepts a literal key or `generate` in the CLI.
# [[interface]]
# name = "wg0"
# type = "wireguard"
# zone = "vpn"
# address = "10.9.0.1/24"
# [[vpn.wireguard]]
# name = "wg0"
# private-key = "OK+2...base64-32-bytes...=="
# listen-port = 51820
# [[vpn.wireguard.peer]]
# public-key = "HIGw...peer-pubkey...=="
# allowed-ips = ["10.9.0.2/32"]
# endpoint = "203.0.113.9:51820"
# persistent-keepalive = 25
#
# OpenConnect (roadmap C17): an AnyConnect-compatible TLS road-warrior VPN for
# client devices — a single server, not a tunnel list. Its TLS identity is a
# leaf issued by the on-box PKI (C19). Each connecting client is handed an
# address from `pool`; `routes` are the subnets pushed to the client (omit +
# `default-route = true` for a full tunnel). Users authenticate by password.
# [vpn.openconnect]
# certificate = "vpn-server"    # a [[pki.certificate]] name (or "acme")
# port = 443
# pool = "10.99.0.0/24"
# dns = ["10.0.0.1"]
# routes = ["10.0.0.0/24"]      # split tunnel; omit for `default-route = true`
# zone = "vpn"
# [[vpn.openconnect.user]]
# name = "alice"
# password = "change-me"

# Dynamic routing (the Wren control plane). BGP with a fully-specified peer and
# a named route filter used as its import policy. Every field maps 1:1 onto the
# Wren daemon's config.
# [protocols]
# router-id = "10.0.0.1"
#
# [protocols.bgp]
# local-as = 65001
# hold-time = 90
# network = ["10.11.0.0/24"]
# redistribute = ["static", "connected"]
# community = ["65001:100"]
# multipath = 4
# ebgp-require-policy = true
#
# [[protocols.bgp.aggregate]]
# prefix = "10.11.0.0/16"
# summary-only = true
#
# [[protocols.bgp.neighbor]]
# address = "10.10.0.2"
# remote-as = 65002
# local-as = 65099             # per-session AS override (IOS/FRR local-as)
# update-source = "10.10.0.11" # source address for the outgoing session
# description = "R2 transit uplink"
# hold-time = 30               # per-session hold-time (negotiated = min)
# shutdown = false             # true = administratively down
# password = "peer-secret"
# ttl-security = 1             # or ebgp-multihop = 4 for a distant peer
# max-prefix = 1000
# role = "customer"
# import = "from-peer"
# export = "to-peer"
# bfd = true
#
# Routing policy (VyOS-style): a prefix-list and a route-map that references it.
# The route-map is named from a neighbour's import/export (above), a VRF's
# import/export, or the redistribution maps (below).
# [[policy.prefix-list]]
# name = "LAN"
# [[policy.prefix-list.rule]]
# seq = 10
# prefix = "10.0.0.0/8"
# le = 24
# [[policy.route-map]]
# name = "from-peer"
# default = "reject"
# [[policy.route-map.rule]]
# seq = 10
# action = "permit"
# match-prefix-list = "LAN"
# set-metric = 100
#
# OSPFv2 with an area border interface, authentication, timers and a stub area.
# [protocols.ospf]
# interfaces = ["eth0"]
# area = "0.0.0.0"
# router-priority = 5
# passive-interfaces = ["eth2"]
# auth-type = "md5"
# auth-key = "s3cret"
# hello-interval = 5
# dead-interval = 20
# graceful-restart = true
# bfd = true
# vrf = "blue"
# [[protocols.ospf.interface]]
# name = "eth1"
# area = "0.0.0.1"
#
# A VRF (isolated routing table), a static route placed in it, and BGP bound to it.
# [[protocols.vrf]]
# name = "blue"
# table = 100
# interfaces = ["eth3"]
# import = "from-peer"
# [[protocols.static]]
# prefix = "10.9.0.0/24"
# via = "10.0.0.2"
# vrf = "blue"
#
# Global BFD defaults, IGMP/MLD multicast, and redistribution export filters.
# [protocols.bfd]
# min-tx = 250
# min-rx = 250
# detect-mult = 4
# [protocols.multicast]
# enabled = true
# [[protocols.multicast.interface]]
# name = "lan0"
# role = "querier"
# [protocols.export]
# kernel = "from-peer"
# import = { static = "from-peer" }

# Signed update channel (roadmap C13): the A/B image updater
# (`sentinel update`) only writes a slot if the release manifest is signed by
# this pinned Ed25519 key. `url` holds manifest.json + its .sig + the images;
# `public-key` is the PEM (or `file:<path>` so it can live in the image).
# [update]
# url = "https://updates.example.com/sentinel/stable"
# public-key = "file:/etc/sentinel/update-key.pem"
"#;

/// The whole declarative appliance config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Appliance {
    pub system: System,
    /// Global firewall posture (stateful inspection, ICMP, source blocklist).
    /// Omitted in older configs ⇒ defaults (stateful on, ICMP allowed, no
    /// blocklist); skipped on output when it is exactly the default so saved
    /// files stay clean.
    #[serde(default, skip_serializing_if = "Firewall::is_default")]
    pub firewall: Firewall,
    /// Per-zone posture overrides, keyed by zone name (`[zone.wan]` …). A zone
    /// need not appear here — referencing it from an interface is enough; this
    /// table only carries non-default posture.
    #[serde(default, rename = "zone", skip_serializing_if = "BTreeMap::is_empty")]
    pub zones: BTreeMap<String, ZoneCfg>,
    #[serde(default, rename = "interface")]
    pub interfaces: Vec<Interface>,
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
    /// NAT — address translation, a top-level category distinct from the
    /// firewall (which only *filters*). `[[nat.source]]` masquerades a zone's
    /// outbound traffic; `[[nat.destination]]` is an inbound DNAT port-forward.
    /// Omitted from saved configs when empty.
    #[serde(default, skip_serializing_if = "Nat::is_empty")]
    pub nat: Nat,
    /// Load-balanced virtual services (roadmap C22): a VIP fronting a pool of
    /// real servers, DNAT-rewritten in XDP. Distinct from `[[nat.destination]]`,
    /// which forwards to exactly one host — a load balancer spreads connections
    /// across several and keeps each one pinned to its backend.
    #[serde(
        default,
        rename = "load-balancer",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub load_balancers: Vec<LoadBalancer>,
    /// Dynamic routing (the Wren control plane): a router-id, static routes and
    /// BGP. Compiled to `/run/sentinel/wren.toml` and served by `wren.service`;
    /// operational state is inspected with `wren show …`. Omitted from saved
    /// configs when nothing is configured.
    #[serde(default, skip_serializing_if = "Protocols::is_empty")]
    pub protocols: Protocols,
    /// Box-wide network services the appliance *offers* (as opposed to filtering
    /// or routing): the DNS forwarder today, NTP / mDNS / LLDP / SNMP / … as they
    /// land. Grouped under one `[services.*]` category (the VyOS `service` model)
    /// so the top level stays uncluttered as services multiply. Interface-scoped
    /// services (a per-link DHCP server, Router Advertisements) stay on the
    /// `[[interface]]` instead — those are one-per-link, not one-per-box. Omitted
    /// from saved configs when nothing is configured.
    #[serde(default, skip_serializing_if = "Services::is_empty")]
    pub services: Services,
    /// Multi-WAN (roadmap C6): several WAN uplinks with health-checked failover
    /// or load-balancing + policy-based routing. A distinct top-level category
    /// (like [`Nat`]) because it *steers* packets across links — neither pure
    /// filtering (`firewall`) nor route computation (`protocols`). Omitted from
    /// saved configs when no uplink is declared.
    #[serde(default, skip_serializing_if = "MultiWan::is_empty")]
    pub multiwan: MultiWan,
    /// VPN services (roadmap C2): IKEv2 site-to-site IPsec today (strongSwan);
    /// OpenVPN / road-warrior land here later. A distinct top-level category
    /// grouped like [`Services`] so VPN types share one namespace. Omitted from
    /// saved configs when no tunnel is declared.
    #[serde(default, skip_serializing_if = "Vpn::is_empty")]
    pub vpn: Vpn,
    /// Public-key infrastructure (roadmap C19): an on-box certificate authority
    /// to issue certs for VPN/management, plus an ACME (Let's Encrypt) client for
    /// public certs. Its own top-level domain (like [`Vpn`]), not a "service".
    /// Key material is minted at commit time into the persistent
    /// `/var/lib/sentinel/pki` store (never in the image); the config carries only
    /// the declarative definitions. Omitted from saved configs when empty.
    #[serde(default, skip_serializing_if = "Pki::is_empty")]
    pub pki: Pki,
    /// Routing policy (VyOS-style `[policy]`): named prefix-lists + route-maps,
    /// referenced by BGP neighbours, VRFs and redistribution. Its own top-level
    /// node so route-maps + prefix-lists live under one place instead of inside
    /// `[protocols]`. Omitted from saved configs when empty.
    #[serde(default, skip_serializing_if = "Policy::is_empty")]
    pub policy: Policy,
    /// Signed update channel (roadmap C13): where to fetch A/B image updates from
    /// and the pinned public key that must have signed them. The slot-write +
    /// boot-switch already exist (`sentinel update`); this adds the authenticity
    /// gate in front of it, so only a release signed by the pinned key is ever
    /// written to a slot. Omitted from saved configs when not configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update: Option<UpdateChannel>,
}

/// The signed update channel (`[update]`, roadmap C13). `sentinel update check`
/// fetches a signed manifest from `url`, verifies its detached signature against
/// the pinned `public-key` (an Ed25519 key), and only then trusts the version +
/// image digest it names; `sentinel update install` re-verifies before writing
/// the image to the inactive A/B slot. The pinned key is the trust anchor for
/// the whole distribution path — in production it is baked into the immutable
/// image; carrying it in config here lets an operator pin their own channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateChannel {
    /// Base URL of the update channel — the directory holding `manifest.json`
    /// (+ its `.sig`) and the images it names. Must be `https://` (or `file://`
    /// for a local/offline mirror). Required.
    pub url: String,
    /// The pinned Ed25519 public key that release manifests must be signed with,
    /// PEM (`-----BEGIN PUBLIC KEY-----`). Required — an unsigned or
    /// wrong-key manifest is refused. A `file:`-prefixed value reads the PEM
    /// from that path instead (so the key can live in the image, not the config).
    #[serde(rename = "public-key")]
    pub public_key: String,
}

/// IPFIX flow export (roadmap C12). The data plane already counts every
/// translated connection; this ships those counts to a collector so the box can
/// answer what happened, not only what is happening.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowExport {
    /// Where the collector listens, `host:port`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector: Option<String>,
    /// Seconds between exports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    /// IPFIX observation domain — what tells one appliance's records from
    /// another's at a collector receiving both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<u32>,
}

impl FlowExport {
    /// Nothing configured — the whole block stays out of a saved config.
    pub fn is_empty(&self) -> bool {
        self.collector.is_none()
    }
}

/// The box-wide services category (`[services.*]`). A thin grouping so DNS, NTP
/// and the rest share one namespace instead of sprawling across the top level.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Services {
    /// IPFIX flow export to a collector (`[services.flow-export]`).
    #[serde(
        default,
        rename = "flow-export",
        skip_serializing_if = "FlowExport::is_empty"
    )]
    pub flow_export: FlowExport,
    /// The LAN DNS forwarder (`[services.dns]`).
    #[serde(default, skip_serializing_if = "Dns::is_empty")]
    pub dns: Dns,
    /// The LAN NTP server (`[services.ntp]`).
    #[serde(default, skip_serializing_if = "Ntp::is_empty")]
    pub ntp: Ntp,
    /// LLDP link-layer discovery (`[services.lldp]`).
    #[serde(default, skip_serializing_if = "Lldp::is_empty")]
    pub lldp: Lldp,
    /// Read-only SNMP agent (`[services.snmp]`).
    #[serde(default, skip_serializing_if = "Snmp::is_empty")]
    pub snmp: Snmp,
    /// SSH management access (`[services.ssh]`).
    #[serde(default, skip_serializing_if = "Ssh::is_empty")]
    pub ssh: Ssh,
    /// mDNS reflector (`[services.mdns]`).
    #[serde(default, skip_serializing_if = "Mdns::is_empty")]
    pub mdns: Mdns,
    /// Dynamic-DNS client (`[services.dyndns]`).
    #[serde(default, skip_serializing_if = "Dyndns::is_empty")]
    pub dyndns: Dyndns,
    /// DHCP relay agent (`[services.dhcp-relay]`).
    #[serde(
        default,
        rename = "dhcp-relay",
        skip_serializing_if = "DhcpRelay::is_empty"
    )]
    pub dhcp_relay: DhcpRelay,
    /// L7 reverse-proxy / load-balancer frontends (`[[services.reverse-proxy]]`,
    /// roadmap C22): each terminates a listen port (optionally with TLS from the
    /// on-box PKI) and forwards to one or more backends (round-robin).
    #[serde(
        default,
        rename = "reverse-proxy",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub reverse_proxy: Vec<ReverseProxy>,
    /// Remote syslog forwarding (`[services.syslog]`, roadmap C12).
    #[serde(default, skip_serializing_if = "Syslog::is_empty")]
    pub syslog: Syslog,
    /// Alert notifications (`[services.alerts]`, roadmap C23).
    #[serde(default, skip_serializing_if = "Alerts::is_empty")]
    pub alerts: Alerts,
    /// Intrusion detection (`[services.ids]`, roadmap C11).
    #[serde(default, skip_serializing_if = "Ids::is_empty")]
    pub ids: Ids,
    /// UDP broadcast relays (`[[services.broadcast-relay]]`, roadmap C18).
    #[serde(
        default,
        rename = "broadcast-relay",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub broadcast_relay: Vec<BroadcastRelay>,
    /// Captive portal for a guest zone (`[services.portal]`, roadmap C20).
    #[serde(default, skip_serializing_if = "Portal::is_empty")]
    pub portal: Portal,
    /// NAT-PMP port mapping (`[services.port-mapping]`, roadmap C18).
    #[serde(
        default,
        rename = "port-mapping",
        skip_serializing_if = "PortMapping::is_empty"
    )]
    pub port_mapping: PortMapping,
}

impl Services {
    /// True when no service is configured — lets `[services]` be omitted.
    pub fn is_empty(&self) -> bool {
        self.dns.is_empty()
            && self.ntp.is_empty()
            && self.lldp.is_empty()
            && self.snmp.is_empty()
            && self.ssh.is_empty()
            && self.mdns.is_empty()
            && self.dyndns.is_empty()
            && self.dhcp_relay.is_empty()
            && self.reverse_proxy.is_empty()
            && self.syslog.is_empty()
            && self.alerts.is_empty()
            && self.ids.is_empty()
            && self.broadcast_relay.is_empty()
            && self.portal.is_empty()
            && self.port_mapping.is_empty()
    }
}

/// NAT-PMP port mapping (`[services.port-mapping]`, roadmap C18).
///
/// This is the one service where a host on the **inside** opens an inbound port
/// with no person deciding — a console or a call app asking for what it needs
/// instead of waiting for somebody to configure it. That is a real transfer of
/// authority, so nothing here has a default that switches it on: naming the zone
/// allowed to ask is what turns it on, and naming the uplink is what says where
/// the port is opened.
///
/// UPnP IGD is deliberately not offered. It is SOAP over HTTP with device
/// discovery and XML descriptions, i.e. a much larger parser on a port every LAN
/// host can reach, for the same outcome NAT-PMP reaches in four message types.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortMapping {
    /// The zone whose hosts may ask. Unset ⇒ off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// The zone a mapping is opened on — the uplink.
    #[serde(default, rename = "wan-zone", skip_serializing_if = "Option::is_none")]
    pub wan_zone: Option<String>,
    /// The longest mapping handed out, in seconds. Unset ⇒
    /// [`DEFAULT_MAPPING_LIFETIME`]. A client asking for longer is granted this
    /// and told so, which is what the protocol has a lifetime field for.
    #[serde(
        default,
        rename = "max-lifetime",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_lifetime: Option<u64>,
    /// Allow a host to claim an external port below 1024. Off unless asked for:
    /// a LAN host taking port 22 or 443 on the uplink is either a mistake or an
    /// attempt to stand in front of something the operator runs.
    #[serde(
        default,
        rename = "allow-privileged",
        skip_serializing_if = "Option::is_none"
    )]
    pub allow_privileged: Option<bool>,
}

/// The longest mapping handed out when the config names no ceiling: two hours,
/// which is what PCP suggests and long enough that a client renewing at half the
/// lifetime does so rarely.
pub const DEFAULT_MAPPING_LIFETIME: u64 = 7200;

impl PortMapping {
    /// True when no zone may ask — a zone is what turns this on.
    pub fn is_empty(&self) -> bool {
        self.zone.is_none()
    }

    /// The longest mapping handed out.
    pub fn max_lifetime(&self) -> u64 {
        self.max_lifetime.unwrap_or(DEFAULT_MAPPING_LIFETIME)
    }
}

/// A captive portal for one zone (`[services.portal]`, roadmap C20).
///
/// The gate itself lives in the data plane: a device on the named zone reaches
/// the appliance and nothing else until it has been admitted, and an admission
/// is a run-time fact with a deadline rather than a change to this file. What is
/// configured here is the *policy around* that gate — which zone, what a visitor
/// has to do to get in, and for how long.
///
/// How a device finds the portal is **RFC 8910**: the DHCP server hands out the
/// portal's URI in option 114, and the client's own operating system opens it.
/// There is no HTTP interception, for the reason given in the firewall handbook:
/// intercepting means parsing and rewriting somebody's connection, and it stops
/// working the moment that connection is TLS — which today it is.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Portal {
    /// The zone held behind the portal. Unset ⇒ no portal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// TCP port the portal page listens on. Unset ⇒ [`DEFAULT_PORTAL_PORT`].
    ///
    /// Not 80: the appliance's own management surfaces already contend for the
    /// well-known ports, and a portal announced by option 114 carries its port in
    /// the URI, so nothing is gained by squatting on one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// What a visitor must type. Unset ⇒ **click-through**: the page states the
    /// terms and a button admits the device.
    ///
    /// Kept as written rather than hashed, and deliberately: this is a shared
    /// secret printed on a card by the door, not a credential belonging to a
    /// person. Hashing it would stop the operator reading back what they set
    /// while protecting nothing that is not already on that card.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
    /// How long an admission lasts, in seconds. Unset ⇒
    /// [`DEFAULT_PORTAL_SESSION`].
    #[serde(
        default,
        rename = "session-timeout",
        skip_serializing_if = "Option::is_none"
    )]
    pub session_timeout: Option<u64>,
    /// A line of text shown on the page — the network's name, the terms, who to
    /// ask. Unset ⇒ a plain welcome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// The portal's default listen port. See [`Portal::port`].
pub const DEFAULT_PORTAL_PORT: u16 = 8082;

/// How long an admission lasts when the config names no length: one hour, the
/// same bound the agent applies to a run-time block.
pub const DEFAULT_PORTAL_SESSION: u64 = 3600;

impl Portal {
    /// True when no portal is configured — a zone is what turns it on.
    pub fn is_empty(&self) -> bool {
        self.zone.is_none()
    }

    /// The port the page listens on.
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(DEFAULT_PORTAL_PORT)
    }

    /// How long one admission lasts.
    pub fn session_timeout(&self) -> u64 {
        self.session_timeout.unwrap_or(DEFAULT_PORTAL_SESSION)
    }
}

/// Alert notifications (`[services.alerts]`, roadmap C23).
///
/// Remote syslog ships *everything* somewhere for later; an alert is the opposite
/// — it tells a human, now, about the few events that mean the appliance is not
/// doing its job. The one that matters most is a **failed unit**: an appliance
/// whose data plane died is still pingable and still answers SSH, so nothing
/// reveals it until traffic is already broken.
///
/// The event source is **systemd**, via an `OnFailure=` drop-in on each unit
/// Sentinel owns — not a log scrape. A pattern match on the journal would fire on
/// a message that merely mentions a failure, and would miss one that never logged.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alerts {
    /// Endpoints to POST a JSON alert to. Repeatable; `https` or `http`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub webhook: Vec<String>,
    /// Where to mail an alert (`[services.alerts.mail]`).
    #[serde(default, skip_serializing_if = "AlertMail::is_empty")]
    pub mail: AlertMail,
}

impl Alerts {
    pub fn is_empty(&self) -> bool {
        self.webhook.is_empty() && self.mail.is_empty()
    }
}

/// Default submission port for alert mail — 587 (RFC 6409 message submission),
/// not 25: a relay that accepts authenticated submission is what an appliance
/// actually has credentials for.
pub const DEFAULT_ALERT_MAIL_PORT: u16 = 587;

/// Mail delivery for alerts (`[services.alerts.mail]`), realised by **msmtp** —
/// a send-only SMTP client, so the appliance never runs a listening mail server.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertMail {
    /// The recipient. Unset ⇒ no mail is sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// The envelope sender. Unset ⇒ `sentinel@<hostname>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// The smarthost to submit through. Required for mail to work.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    /// Its port. Unset ⇒ 587.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// SMTP AUTH user. Unset ⇒ submit unauthenticated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// SMTP AUTH password. Rendered into a 0600 msmtp config, never
    /// world-readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Use STARTTLS. Defaults to **true** — an appliance mailing a password over
    /// a cleartext link would leak it, so turning encryption off has to be a
    /// written decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starttls: Option<bool>,
}

impl AlertMail {
    pub fn is_empty(&self) -> bool {
        self.to.is_none()
            && self.from.is_none()
            && self.relay.is_none()
            && self.port.is_none()
            && self.user.is_none()
            && self.password.is_none()
            && self.starttls.is_none()
    }

    /// Whether enough is set to actually send: a recipient and a smarthost.
    pub fn is_deliverable(&self) -> bool {
        self.to.is_some() && self.relay.is_some()
    }
}

/// Default remote-syslog port — 514, the IANA-assigned syslog port every
/// collector listens on out of the box.
pub const DEFAULT_SYSLOG_PORT: u16 = 514;

/// The first WAN port deterministic CGNAT hands out when none is given: the start
/// of the ephemeral range, so the well-known and registered ports stay free for
/// port-forwards on the same address.
pub const DEFAULT_CGNAT_BASE_PORT: u16 = 32768;

/// Remote syslog forwarding (`[services.syslog]`, roadmap C12).
///
/// An appliance whose logs only exist on the appliance is one you cannot
/// investigate after it reboots, and cannot correlate with anything else on the
/// network. This ships the journal to one or more collectors as RFC 5424 syslog,
/// which is what Graylog / rsyslog / syslog-ng / a SIEM all speak.
///
/// Realised by **rsyslog** reading the journal (`imjournal`) and forwarding
/// (`omfwd`) — the journal is already the single sink every Sentinel service logs
/// to, so there is nothing to re-plumb.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Syslog {
    /// Where to ship. Empty ⇒ forwarding is off (the local journal is unaffected
    /// either way — this adds a copy, it never redirects).
    #[serde(default, rename = "target", skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<SyslogTarget>,
}

impl Syslog {
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }
}

/// One syslog collector (`[[services.syslog.target]]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyslogTarget {
    /// The collector's address or hostname.
    pub host: String,
    /// Its port. Unset ⇒ 514.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// `udp` (default) or `tcp`. UDP cannot tell you it failed; TCP can, at the
    /// cost of needing somewhere to buffer when the collector is away — see
    /// `net.rs`, which always renders that buffer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proto: Option<SyslogProto>,
    /// The minimum severity to ship. Unset ⇒ `info` — `debug` ships everything
    /// the journal holds, which is rarely what an operator wants on the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<SyslogLevel>,
    /// Which facilities to ship, as syslog facility names (`auth`, `daemon`,
    /// `local7`, …). Empty ⇒ all of them.
    ///
    /// A collector that only wants the authentication trail should not be sent
    /// every kernel message to filter out again — and on a link that is charged
    /// for or watched, "ship it all and sort it there" is not free.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub facility: Vec<String>,
}

/// The transport for a syslog target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyslogProto {
    Udp,
    Tcp,
}

/// A syslog severity (RFC 5424 §6.2.1), named as operators name them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyslogLevel {
    Emerg,
    Alert,
    Crit,
    Err,
    Warning,
    Notice,
    Info,
    Debug,
}

impl SyslogLevel {
    /// The rsyslog selector spelling (`*.<level>` ships that level *and above*).
    pub fn rsyslog(self) -> &'static str {
        match self {
            SyslogLevel::Emerg => "emerg",
            SyslogLevel::Alert => "alert",
            SyslogLevel::Crit => "crit",
            SyslogLevel::Err => "err",
            SyslogLevel::Warning => "warning",
            SyslogLevel::Notice => "notice",
            SyslogLevel::Info => "info",
            SyslogLevel::Debug => "debug",
        }
    }
}

/// The address ranges `HOME_NET` covers when the operator names none: the three
/// RFC 1918 blocks plus RFC 6598 CGNAT space. Nearly every published rule is
/// written as "external → home", so an empty `HOME_NET` silently matches nothing
/// and the whole ruleset goes quiet — the one failure mode an IDS must not have.
pub const DEFAULT_IDS_HOME_NET: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
];

/// Intrusion detection (`[services.ids]`, roadmap C11).
///
/// Suricata watching named interfaces through AF_PACKET. It works here because
/// the data plane ends an allowed packet on `XDP_PASS` and lets the kernel route
/// it, so the packet still traverses the stack where AF_PACKET can see it.
///
/// **Detection only — it does not drop.** Suricata's IPS modes need either
/// NFQUEUE or an inline AF_PACKET pair, and both would put a second, competing
/// verdict stage behind the eBPF firewall: a packet could then vanish for a reason
/// `show firewall` cannot explain. Blocking belongs to the data plane that already
/// owns the policy, so an alert here is evidence, not an action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ids {
    /// Interfaces to watch. Empty ⇒ intrusion detection is off.
    #[serde(default, rename = "interface", skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
    /// What counts as "inside" for rules written against `$HOME_NET`. Unset ⇒
    /// [`DEFAULT_IDS_HOME_NET`].
    #[serde(default, rename = "home-net", skip_serializing_if = "Vec::is_empty")]
    pub home_net: Vec<String>,
    /// Rules written inline in the configuration, one Suricata rule per entry.
    #[serde(default, rename = "rule", skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<String>,
    /// Server names to refuse (roadmap C23). Matched against the **SNI** a TLS
    /// client announces, so it works for a name the client resolved somewhere
    /// this appliance never saw — over DoH, from a cache, or as a literal
    /// address. A leading dot matches the domain and everything under it.
    #[serde(default, rename = "sni-block", skip_serializing_if = "Vec::is_empty")]
    pub sni_block: Vec<String>,
    /// Absolute paths to rule files the operator put on the box (an Emerging
    /// Threats set, say). Kept as paths rather than content because a ruleset is
    /// megabytes and does not belong in a configuration file.
    #[serde(default, rename = "ruleset", skip_serializing_if = "Vec::is_empty")]
    pub rulesets: Vec<String>,
    /// Have an alert block its source in the data plane (roadmap C11).
    ///
    /// Off unless asked for. Acting on a detection means dropping traffic on the
    /// strength of a pattern match, and a false positive then takes a real user
    /// off the network — that is a decision an operator makes, not a default.
    #[serde(
        default,
        rename = "block-on-alert",
        skip_serializing_if = "Option::is_none"
    )]
    pub block_on_alert: Option<bool>,
    /// The least severe alert that blocks. Suricata numbers severity with **1 as
    /// the most severe**, so this is an upper bound. Unset ⇒ 1: only what the
    /// ruleset itself calls critical.
    #[serde(
        default,
        rename = "block-severity",
        skip_serializing_if = "Option::is_none"
    )]
    pub block_severity: Option<u8>,
    /// How long a block lasts, in seconds. Unset ⇒ [`DEFAULT_IDS_BLOCK_SECONDS`].
    #[serde(
        default,
        rename = "block-duration",
        skip_serializing_if = "Option::is_none"
    )]
    pub block_duration: Option<u64>,
    /// Sources that must never be blocked, however they alert.
    ///
    /// This is the lockout guard. An alert can fire on the management network —
    /// a scanner, a monitoring probe, an operator's own traffic — and blocking it
    /// removes the way in to fix the problem, at the moment there is a problem.
    #[serde(default, rename = "never-block", skip_serializing_if = "Vec::is_empty")]
    pub never_block: Vec<String>,
}

/// How long an automatic block lasts when none is configured — an hour. Long
/// enough to see off what triggered it, short enough that a wrong one is an
/// inconvenience rather than an outage.
pub const DEFAULT_IDS_BLOCK_SECONDS: u64 = 3600;

/// The default severity ceiling for an automatic block: only alerts the ruleset
/// itself calls critical (Suricata counts 1 as most severe).
pub const DEFAULT_IDS_BLOCK_SEVERITY: u8 = 1;

impl Ids {
    /// True when nothing is watched — lets `[services.ids]` be omitted.
    pub fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
    }

    /// Whether an alert should block its source.
    pub fn blocks_on_alert(&self) -> bool {
        self.block_on_alert.unwrap_or(false)
    }

    /// The severity ceiling for an automatic block.
    pub fn block_severity(&self) -> u8 {
        self.block_severity.unwrap_or(DEFAULT_IDS_BLOCK_SEVERITY)
    }

    /// How long an automatic block lasts.
    pub fn block_duration(&self) -> u64 {
        self.block_duration.unwrap_or(DEFAULT_IDS_BLOCK_SECONDS)
    }

    /// Whether `addr` is protected from automatic blocking.
    ///
    /// Matched as a prefix, not as a string: `never-block 10.0.0.0/8` has to
    /// protect every host inside it, which is the only way the guard is usable.
    pub fn is_never_blocked(&self, addr: &str) -> bool {
        let Ok(ip) = addr.parse::<std::net::IpAddr>() else {
            // Something that is not an address cannot be matched against a
            // prefix, and blocking it would fail anyway — treat it as protected
            // rather than pass it on to the data plane.
            return true;
        };
        self.never_block.iter().any(|entry| match (&ip, entry) {
            (std::net::IpAddr::V4(v4), e) => ipv4_in_prefix(v4, e),
            (std::net::IpAddr::V6(v6), e) => ipv6_in_prefix(v6, e),
        })
    }

    /// The `HOME_NET` members, configured or default.
    pub fn home_net(&self) -> Vec<String> {
        if self.home_net.is_empty() {
            DEFAULT_IDS_HOME_NET.iter().map(|s| s.to_string()).collect()
        } else {
            self.home_net.clone()
        }
    }
}

/// Default reverse-proxy listen port when none is given — 443 (HTTPS), the
/// common case for a TLS-terminating proxy.
pub const DEFAULT_REVERSE_PROXY_PORT: u16 = 443;

/// One L7 reverse-proxy / load-balancer frontend (`[[services.reverse-proxy]]`,
/// roadmap C22). Rendered by `proxy.rs` into an HAProxy `frontend`/`backend`
/// pair: it binds `port` (TLS-terminated when `certificate` names a PKI leaf,
/// else plain HTTP) and forwards requests to `backends` round-robin. The XDP L4
/// load-balancer (fabric) is the separate high-throughput path; this is the L7
/// tier that does TLS termination + HTTP-aware routing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReverseProxy {
    /// Frontend name — the HAProxy `frontend`/`backend` id + the log tag.
    /// Required; `[A-Za-z0-9_-]` (rendered as a config section name).
    pub name: String,
    /// Administratively disable this frontend without deleting it. Off by default.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
    /// The port to listen on. Defaults to [`DEFAULT_REVERSE_PROXY_PORT`] (443).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// The PKI certificate (`[[pki.certificate]]` name, or `acme`) used to
    /// terminate TLS on the listen port. Unset ⇒ plain HTTP (no termination).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    /// The upstream backends as `host:port`, load-balanced round-robin. At least
    /// one is required.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backends: Vec<String>,
}

impl ReverseProxy {
    /// The effective listen port (explicit or the 443 default).
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(DEFAULT_REVERSE_PROXY_PORT)
    }
}

/// LLDP link-layer discovery (`[services.lldp]`) — the box advertises itself and
/// learns its neighbours over 802.1AB, built on the image's `lldpd` (Sentinel
/// owns its lifecycle: off unless enabled). `show`-able with `lldpctl`. Empty by
/// default (no discovery).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lldp {
    /// Turn LLDP on. Without it the daemon stays stopped (the appliance ships no
    /// neighbour discovery by default).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub enable: bool,
    /// Interfaces to run LLDP on (a whitelist). Each must be a declared
    /// interface. Empty ⇒ every interface (lldpd's default) — the usual case.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interface: Vec<String>,
}

impl Lldp {
    /// True when LLDP is off and unconfigured — lets `[services.lldp]` be omitted.
    pub fn is_empty(&self) -> bool {
        !self.enable && self.interface.is_empty()
    }
}

/// A read-only SNMP agent (`[services.snmp]`) — built on the image's net-snmp
/// `snmpd`, exposing the box's MIBs (interfaces, counters, sysUpTime) to a v2c
/// monitoring station. Read-only by construction (an `rocommunity`; no write
/// community is ever rendered). Empty by default; a `community` turns it on.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snmp {
    /// The v2c read-only community string (the shared secret a poller presents).
    /// Rendered into a 0640 `snmpd.conf`, never world-readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub community: Option<String>,
    /// The address:port the agent listens on (net-snmp `agentaddress`, e.g.
    /// `"udp:161"` or `"udp:10.0.0.1:161"`). Unset ⇒ `udp:161` (all addresses).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    /// The advertised `syslocation` (a free-form string, e.g. `"rack 4"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// The advertised `syscontact` (a free-form string, e.g. `"noc@example"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
    /// Source subnets allowed to poll (IPv4/IPv6 CIDRs or bare IPs). Each becomes
    /// the source clause of an `rocommunity`. Empty ⇒ `default` (any source can
    /// poll with the community) — set at least one to scope it to the NOC.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
}

/// SSH management access (`[services.ssh]`). The image ships a key-only sshd; this
/// section makes it runtime-configurable: which public keys may log in (as the
/// `admin` user), whether the daemon runs at all, and an optional non-default port
/// / listen-address. **Key-only by design** — no password authentication is ever
/// rendered. The keys + a `Port`/`ListenAddress` drop-in are written to the
/// persistent `/var/lib/sentinel/ssh/` so they survive a reboot and sshd reads
/// them on its normal start (no unit-ordering dance).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ssh {
    /// Run the SSH daemon. Defaults to `true` (an appliance is managed over SSH);
    /// set `false` to stop it (e.g. a box reachable only on the console).
    #[serde(default = "default_true")]
    pub enable: bool,
    /// The TCP port sshd listens on. Unset ⇒ 22.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Restrict sshd to this local address (an IPv4/IPv6 the box holds). Unset ⇒
    /// all addresses. Scopes management to, e.g., the LAN or a dedicated mgmt IP.
    #[serde(
        rename = "listen-address",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub listen_address: Option<String>,
    /// How much sshd says about what it is doing (`QUIET`, `FATAL`, `ERROR`,
    /// `INFO`, `VERBOSE`, `DEBUG1`–`DEBUG3`). Unset ⇒ sshd's own default
    /// (`INFO`). `VERBOSE` is the one worth knowing: it logs the fingerprint of
    /// the key that was used, which is what turns "somebody logged in as admin"
    /// into "*this* key logged in as admin".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loglevel: Option<String>,
    /// Allow password logins over SSH. Off by default — the appliance is key-only
    /// (a user's `[[system.login]]` hashed-password is for console + sudo). Turn on
    /// to also accept that password over SSH. The authorized keys themselves live
    /// per-user under `[[system.login]] ssh-key`, not here.
    #[serde(
        rename = "password-authentication",
        default,
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub password_authentication: bool,
}

impl Default for Ssh {
    fn default() -> Self {
        Ssh {
            enable: true,
            port: None,
            listen_address: None,
            loglevel: None,
            password_authentication: false,
        }
    }
}

impl Ssh {
    /// True when SSH is at its defaults (enabled, port 22, all addresses, key-only)
    /// — lets `[services.ssh]` be omitted from a saved config. A box with default
    /// SSH keeps the image's key-only sshd untouched.
    pub fn is_empty(&self) -> bool {
        self.enable
            && self.port.is_none()
            && self.listen_address.is_none()
            && !self.password_authentication
    }
}

impl Snmp {
    /// True when no agent is configured — lets `[services.snmp]` be omitted.
    pub fn is_empty(&self) -> bool {
        self.community.is_none()
            && self.listen.is_none()
            && self.location.is_none()
            && self.contact.is_none()
            && self.allow.is_empty()
    }
}

/// mDNS reflector (`[services.mdns]`) — reflects multicast-DNS (Bonjour/Avahi)
/// service announcements between two or more segments so a printer/Chromecast on
/// one VLAN is discoverable from another. Built on the image's `avahi-daemon` in
/// reflector mode (Sentinel owns its lifecycle). Empty by default.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mdns {
    /// Interfaces to reflect mDNS between. At least two are needed for a reflector
    /// to have anything to bridge; each must be a declared interface.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interface: Vec<String>,
}

impl Mdns {
    /// True when no reflector is configured — lets `[services.mdns]` be omitted.
    pub fn is_empty(&self) -> bool {
        self.interface.is_empty()
    }
}

/// A UDP broadcast relay (`[[services.broadcast-relay]]`, roadmap C18) — carries
/// a broadcast that would otherwise stop at the router onto the other segments,
/// so discovery that assumes one flat LAN keeps working across VLANs (Wake-on-LAN
/// magic packets, SSDP, game-server browsers, industrial gear that announces
/// itself).
///
/// Each relay names one UDP port and the interfaces it bridges; a packet arriving
/// on one is re-emitted on every other. **The original source address is
/// preserved**, which is what makes request/response discovery work: a device
/// answering an SSDP `M-SEARCH` replies unicast to the address it saw, and if
/// that were the router the answer would never reach the asker.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BroadcastRelay {
    /// A name for this relay, used in `show` and to address it from the CLI.
    pub name: String,
    /// A free-text label. Purely documentary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Administratively disable this relay without deleting it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
    /// The UDP port to relay. One port per relay — a relay carrying two unrelated
    /// protocols would have to be reasoned about as two anyway.
    pub port: u16,
    /// The interfaces this relay bridges. At least two: a relay onto the segment
    /// a packet came from has nothing to do.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interface: Vec<String>,
}

/// A dynamic-DNS client (`[services.dyndns]`) — keeps a hostname's A/AAAA record
/// pointed at the box's (possibly dynamic) WAN address, built on the image's
/// `ddclient`. Empty by default; a `hostname` turns it on.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dyndns {
    /// The ddclient protocol (the provider), e.g. `"dyndns2"`, `"cloudflare"`,
    /// `"namecheap"`. Unset ⇒ `dyndns2` (the de-facto default protocol).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// The provider's update endpoint host (ddclient `server=`), e.g.
    /// `"members.dyndns.org"`. Unset ⇒ the provider protocol's built-in default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// The hostname (FQDN) whose record is kept up to date.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// The account login/username at the provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<String>,
    /// The account password / API token. Rendered into a 0640 `ddclient.conf`,
    /// never world-readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// The interface whose address to publish (ddclient `use=if, if=<iface>`).
    /// Each must be a declared interface. Unset ⇒ `use=web` (discover the WAN IP
    /// via the provider's checkip service — the right choice behind CGNAT).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
}

impl Dyndns {
    /// True when no client is configured — lets `[services.dyndns]` be omitted.
    pub fn is_empty(&self) -> bool {
        self.provider.is_none()
            && self.server.is_none()
            && self.hostname.is_none()
            && self.login.is_none()
            && self.password.is_none()
            && self.interface.is_none()
    }
}

/// A DHCP relay agent (`[services.dhcp-relay]`) — forwards DHCP between a
/// client-facing interface and an upstream server on another segment (the box
/// runs no pool itself), built on the image's isc `dhcrelay`. Empty by default;
/// an upstream `server` turns it on.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DhcpRelay {
    /// Interfaces the relay listens/relays on — both the client-facing segment(s)
    /// and the link toward the server. Each must be a declared interface, and
    /// (validated) must NOT also run a `[interface.dhcp-server]` — a link is
    /// either served locally or relayed, never both.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interface: Vec<String>,
    /// Upstream DHCP server addresses to relay requests to (IPv4).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub server: Vec<String>,
    /// Upstream DHCPv6 server addresses to relay requests to (IPv6). A unicast
    /// server address, or the well-known relay multicast `ff05::1:3`. Enables the
    /// v6 relay independently of the v4 one — a link can relay either family or both.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub server6: Vec<String>,
}

impl DhcpRelay {
    /// True when no relay is configured — lets `[services.dhcp-relay]` be omitted.
    pub fn is_empty(&self) -> bool {
        self.interface.is_empty() && self.server.is_empty() && self.server6.is_empty()
    }
}

/// The box-wide NTP server (`[services.ntp]`) — a LAN time source built on the
/// image's chrony (no extra unit): the box syncs to `upstream` time sources and
/// serves clients on the subnets of the `serve-on` interfaces. Empty by default.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ntp {
    /// Upstream NTP sources the box syncs to (IPs or hostnames, e.g.
    /// `"pool.ntp.org"`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upstream: Vec<String>,
    /// Interfaces whose subnet is allowed to query this NTP server. Each must be
    /// a declared interface carrying a static address (its subnet is `allow`ed).
    #[serde(default, rename = "serve-on", skip_serializing_if = "Vec::is_empty")]
    pub serve_on: Vec<String>,
    /// Networks allowed to query this NTP server, written as prefixes.
    ///
    /// `serve-on` answers "which of my links may ask", which is the common case
    /// and needs no arithmetic. This answers "which networks may ask" — for a
    /// client that is not on a directly attached subnet, reached over a tunnel
    /// or a routed segment, where naming a link cannot express it.
    #[serde(default, rename = "allow-from", skip_serializing_if = "Vec::is_empty")]
    pub allow_from: Vec<String>,
}

impl Ntp {
    /// True when no NTP server is configured — lets `[services.ntp]` be omitted.
    pub fn is_empty(&self) -> bool {
        self.upstream.is_empty() && self.serve_on.is_empty() && self.allow_from.is_empty()
    }
}

/// The box-wide DNS forwarder — rendered to a systemd-resolved drop-in. Empty by
/// default (no forwarder); the presence of an upstream + a serving interface is
/// what turns it on.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dns {
    /// Upstream resolvers the box forwards client queries to (IPv4 or IPv6).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upstream: Vec<String>,
    /// Interfaces the LAN resolver (dnsmasq) listens on for client queries. Each
    /// must be a declared interface carrying a static address. Serving turns on
    /// dnsmasq (forwarding + host-overrides + blocklists); the box's own
    /// resolution stays on systemd-resolved.
    #[serde(default, rename = "serve-on", skip_serializing_if = "Vec::is_empty")]
    pub serve_on: Vec<String>,
    /// Encrypted upstreams: `tls://<host>` (DNS over TLS, RFC 7858) or
    /// `https://<host>/dns-query` (DNS over HTTPS, RFC 8484).
    ///
    /// The resolver clients talk to does not change — dnsmasq still answers on
    /// the LAN. What changes is where it asks: a local proxy that speaks TLS
    /// takes its place as the upstream, so the queries leaving this box are no
    /// longer readable by everything between here and the provider.
    ///
    /// **Setting this demotes `upstream` to bootstrap.** An encrypted upstream
    /// named by hostname cannot be reached until something resolves that
    /// hostname, and that something has to be plaintext. Leaving the plaintext
    /// servers in place *as upstreams* would leak every query they still
    /// answered, which is the opposite of what was asked for — so they answer
    /// exactly one question, the one the encrypted upstream's own name poses.
    ///
    /// A `tls://` naming an address rather than a hostname works only where the
    /// provider publishes the address in its certificate. Several do; if the
    /// handshake fails, that is why.
    #[serde(
        default,
        rename = "secure-upstream",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub secure_upstream: Vec<String>,
    /// Which clients may ask, as hosts or CIDRs in either family. Empty ⇒ anyone
    /// that can reach the listener.
    ///
    /// Not the same knob as `serve-on`, which is about *where* the resolver
    /// listens. An open resolver on an interface that faces a provider network
    /// is a reflection amplifier whether or not you meant to run one, and the
    /// listener alone cannot say no to a client on that same segment.
    #[serde(default, rename = "allow-from", skip_serializing_if = "Vec::is_empty")]
    pub allow_from: Vec<String>,
    /// Domains never forwarded upstream — answered `NXDOMAIN` locally instead.
    ///
    /// The canonical use is the reverse zones for private space: without this a
    /// PTR lookup for an RFC 1918 address goes out to the internet, tells a
    /// stranger about the internal addressing, and comes back empty anyway.
    #[serde(default, rename = "dont-query", skip_serializing_if = "Vec::is_empty")]
    pub dont_query: Vec<String>,
    /// Local DNS records: name → IP (v4 or v6). A LAN query for the name is
    /// answered authoritatively with the address instead of being forwarded —
    /// the pfSense "host override" / split-horizon convenience.
    #[serde(
        default,
        rename = "host-override",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub host_override: BTreeMap<String, String>,
    /// Domains to sinkhole: a LAN query for the domain (or any subdomain) is
    /// answered with `0.0.0.0` / `::` instead of being forwarded — the
    /// pfBlocker/pi-hole DNS-blocklist convention (ad/tracker/malware blocking).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocklist: Vec<String>,
    /// DNSSEC validation mode: `"yes"`, `"no"` or `"allow-downgrade"`. Unset ⇒
    /// the appliance default (`no`) — a forwarder trusts its upstream, and many
    /// upstreams break strict validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnssec: Option<String>,
    /// Maximum number of cached DNS answers the LAN resolver (dnsmasq) keeps —
    /// rendered as dnsmasq `cache-size=<n>`. Unset ⇒ dnsmasq's default (150).
    #[serde(
        default,
        rename = "cache-size",
        skip_serializing_if = "Option::is_none"
    )]
    pub cache_size: Option<u32>,
    /// The site's local domain. Rendered as dnsmasq `local=/<domain>/` (queries
    /// for it are answered locally, never forwarded) plus `domain=<domain>` (the
    /// suffix handed to DHCP clients / appended to bare names). `None` ⇒ none.
    #[serde(
        default,
        rename = "local-domain",
        skip_serializing_if = "Option::is_none"
    )]
    pub local_domain: Option<String>,
    /// How long a *negative* answer is cached, in seconds (dnsmasq `neg-ttl`).
    ///
    /// Worth its own knob because the default is to cache the upstream's SOA
    /// minimum, which on a badly configured zone can be hours — and a name that
    /// has just been created then stays "does not exist" for the rest of the
    /// afternoon. Unset ⇒ dnsmasq's own behaviour.
    #[serde(
        default,
        rename = "negative-ttl",
        skip_serializing_if = "Option::is_none"
    )]
    pub negative_ttl: Option<u32>,
    /// Local TXT records (`name` → text), served authoritatively.
    ///
    /// The use that keeps coming up is not documentation: a cluster resolving a
    /// bare suffix — `something.svc` — gets SERVFAIL from the root and treats it
    /// as an outage, so the site serves an empty zone for that suffix to turn
    /// the failure into an honest "no such record".
    #[serde(
        default,
        rename = "txt-record",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub txt_record: BTreeMap<String, String>,
}

impl Dns {
    /// True when no DNS service is configured — lets `[services.dns]` be omitted.
    pub fn is_empty(&self) -> bool {
        self.upstream.is_empty()
            && self.serve_on.is_empty()
            && self.host_override.is_empty()
            && self.blocklist.is_empty()
            && self.dnssec.is_none()
            && self.cache_size.is_none()
            && self.local_domain.is_none()
            && self.negative_ttl.is_none()
            && self.txt_record.is_empty()
    }
}

/// Dynamic routing configuration — the [`Protocols`] tree maps onto the Wren
/// routing daemon's config (`router-id`, `[[static]]`, `[bgp]`). Kept as its own
/// top-level category (like [`Nat`]) because routing is a distinct concern from
/// filtering: Velstra moves/​filters packets, Wren computes the routes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Protocols {
    /// The router id (a 32-bit id, written as an IPv4 address). Also the default
    /// BGP router-id when `[protocols.bgp] router-id` is unset.
    #[serde(default, rename = "router-id", skip_serializing_if = "Option::is_none")]
    pub router_id: Option<String>,
    /// Operator-configured static routes.
    #[serde(default, rename = "static", skip_serializing_if = "Vec::is_empty")]
    pub statics: Vec<StaticRoute>,
    /// OSPFv2 configuration, if the protocol is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ospf: Option<Ospf>,
    /// OSPFv3 (IPv6) configuration, if the protocol is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ospf3: Option<Ospf3>,
    /// RIPv2 (IPv4) configuration, if the protocol is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rip: Option<Rip>,
    /// RIPng (IPv6) configuration, if the protocol is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ripng: Option<Rip>,
    /// Babel (dual-stack) configuration, if the protocol is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub babel: Option<Rip>,
    /// IS-IS configuration, if the protocol is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isis: Option<Isis>,
    /// BGP-4 configuration, if the protocol is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bgp: Option<Bgp>,
    /// VRRP virtual routers (first-hop redundancy / firewall HA).
    #[serde(default, rename = "vrrp", skip_serializing_if = "Vec::is_empty")]
    pub vrrp: Vec<Vrrp>,
    /// VRF (Virtual Routing and Forwarding) instances — named isolated tables.
    #[serde(default, rename = "vrf", skip_serializing_if = "Vec::is_empty")]
    pub vrfs: Vec<VrfDef>,
    /// BFD (RFC 5880) global timing / authentication defaults. Compiled to Wren's
    /// top-level `[bfd]` block; shared by every BFD session a protocol starts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bfd: Option<Bfd>,
    /// Multicast (IGMP/MLD querier + RFC 4605 proxy). Compiled to Wren's
    /// `[multicast]` block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multicast: Option<Multicast>,
    /// Per-protocol import filters (protocol name → filter name), applied to every
    /// route that protocol announces before it enters the RIB. Compiled to Wren's
    /// top-level `[import]` map.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub import: BTreeMap<String, String>,
    /// Export redistribution filters (per consumer protocol → filter name).
    /// Compiled to Wren's top-level `[export]` block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export: Option<Export>,
}

impl Protocols {
    /// True when no routing is configured — lets `[protocols]` be omitted.
    pub fn is_empty(&self) -> bool {
        self.router_id.is_none()
            && self.statics.is_empty()
            && self.ospf.is_none()
            && self.ospf3.is_none()
            && self.rip.is_none()
            && self.ripng.is_none()
            && self.babel.is_none()
            && self.isis.is_none()
            && self.bgp.is_none()
            && self.vrrp.is_empty()
            && self.vrfs.is_empty()
            && self.bfd.is_none()
            && self.multicast.is_none()
            && self.import.is_empty()
            && self.export.is_none()
    }
}

/// OSPFv2 configuration: the interfaces (with a shared area or per-interface
/// areas), authentication, timers, area-type (stub/NSSA) and redistribution. The
/// router-id is the global `[protocols] router-id`. Every field maps 1:1 onto
/// the Wren daemon's `[ospf]` block.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ospf {
    /// Interfaces OSPF runs on (all in [`Ospf::area`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
    /// Per-interface entries with their own area (an area border router with
    /// interfaces in several areas). Interfaces in [`Ospf::interfaces`] use
    /// [`Ospf::area`]; these override the area per interface.
    #[serde(default, rename = "interface", skip_serializing_if = "Vec::is_empty")]
    pub interface: Vec<OspfInterface>,
    /// The area these interfaces belong to (dotted quad, e.g. `"0.0.0.0"`).
    /// Defaults to the backbone `0.0.0.0` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub area: Option<String>,
    /// This router's priority for DR election on these interfaces (0 = never DR).
    #[serde(
        default,
        rename = "router-priority",
        skip_serializing_if = "Option::is_none"
    )]
    pub router_priority: Option<u8>,
    /// The output cost advertised for these interfaces (lower is preferred).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<u16>,
    /// Network type: `"broadcast"` (elects a DR) or `"point-to-point"`.
    #[serde(
        default,
        rename = "network-type",
        skip_serializing_if = "Option::is_none"
    )]
    pub network_type: Option<String>,
    /// Interfaces on which OSPF runs passively (subnet advertised, no adjacency).
    /// Each must also be an OSPF interface.
    #[serde(
        default,
        rename = "passive-interfaces",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub passive_interfaces: Vec<String>,
    /// Route sources redistributed into OSPF as AS-external LSAs (`"static"`,
    /// `"connected"`, `"bgp"`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redistribute: Vec<String>,
    /// The external metric advertised for redistributed routes (default 20).
    #[serde(
        default,
        rename = "redistribute-metric",
        skip_serializing_if = "Option::is_none"
    )]
    pub redistribute_metric: Option<u32>,
    /// Stub areas (no AS-external LSAs; an ABR injects a default), by id.
    #[serde(default, rename = "stub-areas", skip_serializing_if = "Vec::is_empty")]
    pub stub_areas: Vec<String>,
    /// The metric an ABR advertises for the default it injects into stub areas.
    #[serde(
        default,
        rename = "stub-default-cost",
        skip_serializing_if = "Option::is_none"
    )]
    pub stub_default_cost: Option<u32>,
    /// Not-so-stubby areas (NSSA, RFC 3101), by id.
    #[serde(default, rename = "nssa-areas", skip_serializing_if = "Vec::is_empty")]
    pub nssa_areas: Vec<String>,
    /// Totally-stubby ("no-summary" stub) areas, by id.
    #[serde(
        default,
        rename = "totally-stubby-areas",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub totally_stubby_areas: Vec<String>,
    /// Totally-NSSA ("no-summary" NSSA) areas, by id.
    #[serde(
        default,
        rename = "totally-nssa-areas",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub totally_nssa_areas: Vec<String>,
    /// Plain NSSAs into which the ABR additionally injects a type-7 default, by id.
    #[serde(
        default,
        rename = "nssa-default-areas",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub nssa_default_areas: Vec<String>,
    /// Packet authentication scheme: `"none"`, `"text"` or `"md5"`.
    #[serde(default, rename = "auth-type", skip_serializing_if = "Option::is_none")]
    pub auth_type: Option<String>,
    /// The shared authentication key (cleartext password or MD5 secret).
    #[serde(default, rename = "auth-key", skip_serializing_if = "Option::is_none")]
    pub auth_key: Option<String>,
    /// The MD5 key identifier (`auth-type = "md5"` only). Defaults to 1.
    #[serde(
        default,
        rename = "auth-key-id",
        skip_serializing_if = "Option::is_none"
    )]
    pub auth_key_id: Option<u8>,
    /// Enforce RFC 2328 §D.3 anti-replay for `auth-type = "md5"` (default true).
    #[serde(
        default,
        rename = "auth-replay-protection",
        skip_serializing_if = "Option::is_none"
    )]
    pub auth_replay_protection: Option<bool>,
    /// Seconds between Hellos on every OSPF interface (default 10).
    #[serde(
        default,
        rename = "hello-interval",
        skip_serializing_if = "Option::is_none"
    )]
    pub hello_interval: Option<u16>,
    /// Seconds of silence after which a neighbour is declared down (default 40).
    #[serde(
        default,
        rename = "dead-interval",
        skip_serializing_if = "Option::is_none"
    )]
    pub dead_interval: Option<u32>,
    /// Act as a graceful-restart (RFC 3623) restarting router. Defaults to false.
    #[serde(
        default,
        rename = "graceful-restart",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub graceful_restart: bool,
    /// The grace period (seconds) advertised in the Grace-LSA (default 120).
    #[serde(
        default,
        rename = "graceful-restart-period",
        skip_serializing_if = "Option::is_none"
    )]
    pub graceful_restart_period: Option<u32>,
    /// Run a BFD session to each OSPF neighbour for fast failure detection.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub bfd: bool,
    /// The VRF this OSPF instance runs in (a `[[protocols.vrf]]` name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vrf: Option<String>,
}

/// One OSPF/OSPFv3 interface placed in a specific area (`[[…ospf.interface]]`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OspfInterface {
    /// The interface name.
    pub name: String,
    /// The area it belongs to (dotted quad); defaults to the section `area`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub area: Option<String>,
}

/// OSPFv3 (IPv6) configuration — the IPv6 sibling of [`Ospf`]. OSPFv3 adds an
/// Instance ID but has no authentication / stub-area / timer knobs of its own.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ospf3 {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
    /// Per-interface entries with their own area (reuses [`OspfInterface`]).
    #[serde(default, rename = "interface", skip_serializing_if = "Vec::is_empty")]
    pub interface: Vec<OspfInterface>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub area: Option<String>,
    /// This router's priority for DR election on these interfaces (0 = never DR).
    #[serde(
        default,
        rename = "router-priority",
        skip_serializing_if = "Option::is_none"
    )]
    pub router_priority: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<u16>,
    #[serde(
        default,
        rename = "network-type",
        skip_serializing_if = "Option::is_none"
    )]
    pub network_type: Option<String>,
    /// The Instance ID — lets several OSPFv3 instances share one link (default 0).
    #[serde(
        default,
        rename = "instance-id",
        skip_serializing_if = "Option::is_none"
    )]
    pub instance_id: Option<u8>,
    /// Redistribute sources into OSPFv3 (only `"static"` is honoured by the
    /// daemon's OSPFv3 externals).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redistribute: Vec<String>,
    /// The external metric advertised for redistributed routes (default 20).
    #[serde(
        default,
        rename = "redistribute-metric",
        skip_serializing_if = "Option::is_none"
    )]
    pub redistribute_metric: Option<u32>,
    /// Run a BFD session to each Full neighbour for fast failure detection.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub bfd: bool,
}

/// RIP-family configuration shared by RIPv2, RIPng and Babel: which interfaces to
/// run on and what to redistribute. Some knobs only apply to a subset (Wren's
/// RIPng has no `bfd`/`vrf`; only Babel takes `network`/`router-id`) — the CLI
/// grammar restricts them accordingly, and emission only writes the fields the
/// target protocol accepts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rip {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redistribute: Vec<String>,
    #[serde(
        default,
        rename = "redistribute-metric",
        skip_serializing_if = "Option::is_none"
    )]
    pub redistribute_metric: Option<u32>,
    /// Networks originated beyond the connected ones (Babel only), as `addr/len`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network: Vec<String>,
    /// The Router-ID (Babel only), a dotted quad; defaults to `[protocols]
    /// router-id`.
    #[serde(default, rename = "router-id", skip_serializing_if = "Option::is_none")]
    pub router_id: Option<String>,
    /// Run BFD (RFC 5880) to each neighbour (RIP and Babel only).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub bfd: bool,
    /// The VRF this instance runs in, a `[[protocols.vrf]]` name (RIP and Babel
    /// only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vrf: Option<String>,
}

/// IS-IS configuration: the interfaces, this router's identity (system-id / area)
/// and level, with optional network-type and redistribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Isis {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
    /// The 6-byte IS-IS system id (`"0000.0000.0001"`).
    #[serde(default, rename = "system-id", skip_serializing_if = "Option::is_none")]
    pub system_id: Option<String>,
    /// The area address (`"49.0001"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub area: Option<String>,
    /// The IS-IS level: `"1"`, `"2"` or `"1-2"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    /// This router's DIS-election priority (0–127). Defaults to 64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u8>,
    /// The metric advertised for each interface's links. Defaults to 10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metric: Option<u32>,
    /// HelloInterval in seconds. Defaults to 10.
    #[serde(
        default,
        rename = "hello-interval",
        skip_serializing_if = "Option::is_none"
    )]
    pub hello_interval: Option<u64>,
    /// Network type: `"broadcast"` or `"point-to-point"`.
    #[serde(
        default,
        rename = "network-type",
        skip_serializing_if = "Option::is_none"
    )]
    pub network_type: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redistribute: Vec<String>,
    #[serde(
        default,
        rename = "redistribute-metric",
        skip_serializing_if = "Option::is_none"
    )]
    pub redistribute_metric: Option<u32>,
    /// Leak Level-2 prefixes down into this router's Level-1 area (RFC 5302).
    #[serde(
        default,
        rename = "l2-to-l1-leaking",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub l2_to_l1_leaking: bool,
    /// Run BFD (RFC 5880) to each neighbour with an up adjacency.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub bfd: bool,
    /// The VRF this IS-IS instance runs in (a `[[protocols.vrf]]` name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vrf: Option<String>,
    /// PDU authentication: `"text"` (cleartext password, ISO 10589 §9.8),
    /// `"hmac-md5"` (RFC 5304) or `"hmac-sha256"` (RFC 5310). IS-IS rides directly on
    /// the data link, so without this any on-link host can form an adjacency and
    /// inject LSPs. Unset ⇒ no authentication.
    #[serde(default, rename = "auth-type", skip_serializing_if = "Option::is_none")]
    pub auth_type: Option<String>,
    /// The shared secret: the password (`"text"`) or the HMAC key. Required when
    /// `auth-type` is set.
    #[serde(default, rename = "auth-key", skip_serializing_if = "Option::is_none")]
    pub auth_key: Option<String>,
    /// The Key ID advertised beside the digest (`"hmac-sha256"` only; RFC 5304 has
    /// none). Defaults to 1.
    #[serde(
        default,
        rename = "auth-key-id",
        skip_serializing_if = "Option::is_none"
    )]
    pub auth_key_id: Option<u16>,
}

/// A VRRP virtual router (RFC 5798) — first-hop redundancy / firewall HA: a
/// group of routers share a virtual IP, the highest-priority one owning it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vrrp {
    /// A name addressing this virtual router in the CLI (tag-node); not passed to
    /// the daemon, which keys on `interface`+`vrid`.
    pub name: String,
    /// The interface the virtual router runs on.
    pub interface: String,
    /// The virtual router id (1–255), shared by every member of the group.
    pub vrid: u8,
    /// This router's priority (higher wins; 255 = address owner). Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u8>,
    /// Advertisement interval in milliseconds (rounded to centiseconds). Optional.
    #[serde(
        default,
        rename = "advert-interval",
        skip_serializing_if = "Option::is_none"
    )]
    pub advert_interval: Option<u32>,
    /// Whether to preempt a lower-priority master. Unset uses the daemon default
    /// (true).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preempt: Option<bool>,
    /// The prefix length to assign each virtual address with. Unset defaults per
    /// family at the daemon (24 for IPv4, 64 for IPv6).
    #[serde(
        default,
        rename = "prefix-length",
        skip_serializing_if = "Option::is_none"
    )]
    pub prefix_length: Option<u8>,
    /// Interfaces to track: if any is down, effective priority drops by
    /// `priority-decrement`, letting a peer with healthy uplinks take over.
    #[serde(
        default,
        rename = "track-interface",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub track_interfaces: Vec<String>,
    /// How much to subtract from `priority` while a tracked interface is down.
    #[serde(
        default,
        rename = "priority-decrement",
        skip_serializing_if = "Option::is_none"
    )]
    pub priority_decrement: Option<u8>,
    /// The virtual IP address(es) the group presents as the gateway.
    #[serde(
        rename = "virtual-address",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub virtual_address: Vec<String>,
    /// The interface the virtual address(es) live on, when that is *not* the
    /// interface the advertisements go out of.
    ///
    /// A firewall with many tagged segments runs one election over the link it
    /// shares with its peer and holds addresses on the segments it serves.
    /// Without this every segment needs a virtual router and a vrid of its own,
    /// which is a lot of protocol for one question — who is master — that has
    /// the same answer everywhere.
    #[serde(
        default,
        rename = "address-interface",
        skip_serializing_if = "Option::is_none"
    )]
    pub address_interface: Option<String>,
}

/// A static route: `prefix` reached `via` a gateway and/or out `dev` an
/// interface, with an optional `metric`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticRoute {
    /// Destination network in CIDR form (`"0.0.0.0/0"`, `"10.20.0.0/16"`).
    pub prefix: String,
    /// Next-hop gateway address. At least one of `via` / `dev` is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    /// Outgoing interface for an on-link route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev: Option<String>,
    /// Route metric (lower wins). Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metric: Option<u32>,
    /// The VRF this route belongs to (a `[[protocols.vrf]]` name). Unset means the
    /// default VRF (main table).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vrf: Option<String>,
    /// Discard what matches instead of forwarding it. Takes no `via`/`dev` —
    /// having nowhere to send is the point. Two uses: null-routing a prefix, and
    /// holding a BGP summary up so it is announced whether or not anything
    /// inside it is currently reachable.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub blackhole: bool,
    /// Administrative distance, lower wins. Unset ⇒ the protocol's own.
    ///
    /// This is what makes a static route *float*: give it a distance worse than
    /// the protocol you expect to learn the prefix from, and it sits unused
    /// until that protocol stops offering it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distance: Option<u32>,
}

/// BGP-4 configuration: the local AS, an optional router-id, originated
/// networks, redistribution, policy knobs and the peer list. The full surface
/// maps 1:1 onto the Wren daemon's `[bgp]` block.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bgp {
    /// The local autonomous system number (32-bit / 4-octet ASN).
    #[serde(rename = "local-as")]
    pub local_as: u32,
    /// BGP router-id; falls back to `[protocols] router-id` when unset.
    #[serde(default, rename = "router-id", skip_serializing_if = "Option::is_none")]
    pub router_id: Option<String>,
    /// The Hold Time proposed in OPEN, in seconds (default 180 at the daemon).
    #[serde(default, rename = "hold-time", skip_serializing_if = "Option::is_none")]
    pub hold_time: Option<u16>,
    /// Prefixes originated into BGP (advertised to peers).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network: Vec<String>,
    /// Route sources redistributed into BGP (`"static"`, `"connected"`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redistribute: Vec<String>,
    /// The route reflector CLUSTER_ID (dotted quad); defaults to the router-id.
    #[serde(
        default,
        rename = "cluster-id",
        skip_serializing_if = "Option::is_none"
    )]
    pub cluster_id: Option<String>,
    /// The Confederation Identifier (RFC 5065) — the AS shown to true external
    /// peers. When set, `local-as` is this router's Member-AS.
    #[serde(
        default,
        rename = "confederation-id",
        skip_serializing_if = "Option::is_none"
    )]
    pub confederation_id: Option<u32>,
    /// The Member-AS numbers of the other sub-ASes in this confederation.
    #[serde(
        default,
        rename = "confederation-members",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub confederation_members: Vec<u32>,
    /// COMMUNITIES (RFC 1997) attached to every originated route.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub community: Vec<String>,
    /// LARGE_COMMUNITY (RFC 8092) tags attached to every originated route.
    #[serde(
        default,
        rename = "large-community",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub large_community: Vec<String>,
    /// EXTENDED_COMMUNITIES (RFC 4360) attached to every originated route.
    #[serde(
        default,
        rename = "ext-community",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub ext_community: Vec<String>,
    /// The maximum number of equal-cost paths to install as ECMP (BGP multipath).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multipath: Option<usize>,
    /// Address aggregates (RFC 4271 §9.2.2.2): a covering prefix advertised when
    /// a more-specific route falls inside it.
    #[serde(default, rename = "aggregate", skip_serializing_if = "Vec::is_empty")]
    pub aggregate: Vec<BgpAggregate>,
    /// Static RPKI ROAs (RFC 6811) to validate received route origins against.
    #[serde(default, rename = "roa", skip_serializing_if = "Vec::is_empty")]
    pub roa: Vec<BgpRoa>,
    /// An RTR (RFC 8210) validating cache to fetch ROAs from live.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtr: Option<BgpRtr>,
    /// Reject any received route RPKI origin validation classifies as Invalid.
    #[serde(
        default,
        rename = "rpki-reject-invalid",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub rpki_reject_invalid: bool,
    /// RFC 8212 strict default-deny for eBGP: require an explicit policy on every
    /// eBGP peer before it exchanges transit routes.
    #[serde(
        default,
        rename = "ebgp-require-policy",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub ebgp_require_policy: bool,
    /// The VRF this BGP instance runs in (a `[[protocols.vrf]]` name). Unset runs
    /// BGP in the default VRF (main table).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vrf: Option<String>,
    /// BGP peers.
    #[serde(default, rename = "neighbor", skip_serializing_if = "Vec::is_empty")]
    pub neighbors: Vec<BgpNeighbor>,
}

/// One BGP address aggregate (`[[protocols.bgp.aggregate]]`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgpAggregate {
    /// The covering prefix to advertise, as `addr/len`.
    pub prefix: String,
    /// Suppress the contributing more-specifics, advertising only the aggregate.
    #[serde(
        default,
        rename = "summary-only",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub summary_only: bool,
}

/// One static RPKI ROA (`[[protocols.bgp.roa]]`, RFC 6811).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgpRoa {
    /// The authorised prefix, as `addr/len`.
    pub prefix: String,
    /// The longest prefix length the origin may announce within `prefix`.
    #[serde(
        default,
        rename = "max-length",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_length: Option<u8>,
    /// The Autonomous System authorised to originate it.
    #[serde(rename = "origin-as")]
    pub origin_as: u32,
}

/// An RTR validating cache to fetch RPKI ROAs from (`[protocols.bgp.rtr]`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgpRtr {
    /// The cache's `host:port` (the RTR port is conventionally 3323).
    pub server: String,
    /// The refresh interval in seconds; unset uses the cache's advertised value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<u32>,
}

/// A BGP peer: its address, remote AS and the full per-neighbor policy surface.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgpNeighbor {
    /// Peer IP address.
    pub address: String,
    /// The peer's autonomous system number.
    #[serde(rename = "remote-as")]
    pub remote_as: u32,
    /// Wait for the peer to connect rather than initiating the TCP connection.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub passive: bool,
    /// This iBGP peer is a route-reflector client (RFC 4456).
    #[serde(
        default,
        rename = "route-reflector-client",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub route_reflector_client: bool,
    /// GTSM (RFC 5082) maximum number of hops to the peer (1 for a directly
    /// connected eBGP neighbour). Unset disables GTSM.
    #[serde(
        default,
        rename = "ttl-security",
        skip_serializing_if = "Option::is_none"
    )]
    pub ttl_security: Option<u8>,
    /// A TCP-MD5 signature password (RFC 2385). Mutually exclusive with `ao-key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// A TCP-AO master key (RFC 5925). Mutually exclusive with `password`.
    #[serde(default, rename = "ao-key", skip_serializing_if = "Option::is_none")]
    pub ao_key: Option<String>,
    /// The TCP-AO key id (SendID/RecvID), default 100. Ignored without `ao-key`.
    #[serde(default, rename = "ao-key-id", skip_serializing_if = "Option::is_none")]
    pub ao_key_id: Option<u8>,
    /// The maximum number of prefixes to accept from this peer (RFC 4486 §4).
    #[serde(
        default,
        rename = "max-prefix",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_prefix: Option<u32>,
    /// Advertise a default route (`0.0.0.0/0`) to this peer unconditionally.
    #[serde(
        default,
        rename = "default-originate",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub default_originate: bool,
    /// Negotiate ADD-PATH (RFC 7911) with this neighbour for IPv4 unicast.
    #[serde(
        default,
        rename = "add-path",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub add_path: bool,
    /// Negotiate Extended Next Hop Encoding (RFC 5549 / RFC 8950).
    #[serde(
        default,
        rename = "extended-nexthop",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub extended_nexthop: bool,
    /// Negotiate the EVPN address family (RFC 7432) with this neighbour.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub evpn: bool,
    /// Negotiate the FlowSpec address family (RFC 8955) with this neighbour.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub flowspec: bool,
    /// Negotiate the SR Policy address family (RFC 9256) with this neighbour.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub srpolicy: bool,
    /// Negotiate the BGP-LS address family (RFC 7752) with this neighbour.
    #[serde(
        default,
        rename = "link-state",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub link_state: bool,
    /// Inbound route policy: the name of a `[[policy.route-map]]` (import).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub import: Option<String>,
    /// Outbound route policy: the name of a `[[policy.route-map]]` (export).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export: Option<String>,
    /// This speaker's BGP Role toward this neighbour (RFC 9234): `provider`,
    /// `customer`, `peer`, `rs-server` or `rs-client`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Run a BFD (RFC 5880) session to this neighbour for fast failure detection.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub bfd: bool,
    /// Per-neighbour BFD authentication type: `simple`, `keyed-md5`,
    /// `meticulous-md5`, `keyed-sha1` or `meticulous-sha1`.
    #[serde(
        default,
        rename = "bfd-auth-type",
        skip_serializing_if = "Option::is_none"
    )]
    pub bfd_auth_type: Option<String>,
    /// The wire key id for this neighbour's BFD authentication (default 1).
    #[serde(
        default,
        rename = "bfd-auth-key-id",
        skip_serializing_if = "Option::is_none"
    )]
    pub bfd_auth_key_id: Option<u8>,
    /// The shared secret for this neighbour's BFD authentication.
    #[serde(
        default,
        rename = "bfd-auth-key",
        skip_serializing_if = "Option::is_none"
    )]
    pub bfd_auth_key: Option<String>,
    /// Override this speaker's AS for THIS session only (like IOS/FRR
    /// `neighbor X local-as`): sent as My-AS in the OPEN, used for eBGP/iBGP
    /// classification and prepended on eBGP export toward this peer.
    #[serde(default, rename = "local-as", skip_serializing_if = "Option::is_none")]
    pub local_as: Option<u32>,
    /// Bind the outgoing session to this source address (must match the
    /// neighbour's address family).
    #[serde(
        default,
        rename = "update-source",
        skip_serializing_if = "Option::is_none"
    )]
    pub update_source: Option<String>,
    /// Session TTL for a non-directly-connected eBGP peer (1-255). Mutually
    /// exclusive with `ttl-security` (GTSM).
    #[serde(
        default,
        rename = "ebgp-multihop",
        skip_serializing_if = "Option::is_none"
    )]
    pub ebgp_multihop: Option<u8>,
    /// Free-form label for this neighbour, shown in `show bgp neighbors`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Administratively shut the session down: never dial, refuse inbound.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub shutdown: bool,
    /// Per-session hold-time proposed in the OPEN (seconds); the negotiated
    /// value is the minimum of both sides.
    #[serde(default, rename = "hold-time", skip_serializing_if = "Option::is_none")]
    pub hold_time: Option<u16>,
}

/// A named route filter (`[[protocols.filter]]`): an ordered list of rules plus
/// a default action, referenced by name from a neighbour's `import` / `export`.
/// Maps onto Wren's top-level `[[filter]]` block.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    /// The filter's name, referenced from a neighbour's import/export.
    pub name: String,
    /// The action when no rule matches: `"accept"` (default) or `"reject"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// The rules, evaluated in order (first match wins).
    #[serde(default, rename = "rule", skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<FilterRule>,
}

/// One rule of a [`Filter`] (`[[protocols.filter.rule]]`). Conditions present are
/// ANDed; `set-*`/`add-*` modify a matching route before `action` is taken.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterRule {
    /// The rule sequence number (VyOS `rule <N>`): rules are evaluated in
    /// ascending `seq` order, first match wins. Defaults to 0 for a legacy rule
    /// with no explicit number (they keep their file order among equal seqs).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub seq: u32,
    /// Match a named `[[policy.prefix-list]]` (its patterns are ORed into this
    /// rule's prefix match at compile). The VyOS `match prefix-list` clause.
    #[serde(
        default,
        rename = "match-prefix-list",
        skip_serializing_if = "Option::is_none"
    )]
    pub match_prefix_list: Option<String>,
    /// Inline prefix patterns (any-match), e.g. `["10.0.0.0/8+"]`. ORed with the
    /// `match-prefix-list` patterns.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prefix: Vec<String>,
    /// Match this protocol name (`connected`/`static`/`bgp`/…).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// The route's metric must be ≤ this.
    #[serde(default, rename = "metric-le", skip_serializing_if = "Option::is_none")]
    pub metric_le: Option<u32>,
    /// The route's metric must be ≥ this.
    #[serde(default, rename = "metric-ge", skip_serializing_if = "Option::is_none")]
    pub metric_ge: Option<u32>,
    /// Set the matching route's metric to this.
    #[serde(
        default,
        rename = "set-metric",
        skip_serializing_if = "Option::is_none"
    )]
    pub set_metric: Option<u32>,
    /// Add this signed delta to the matching route's metric.
    #[serde(
        default,
        rename = "add-metric",
        skip_serializing_if = "Option::is_none"
    )]
    pub add_metric: Option<i64>,
    /// Send the matching route via this address instead of wherever it said.
    ///
    /// Replaces the route's whole next-hop set, so a multipath route collapses
    /// to this one gateway — which is what naming a single next hop means.
    /// Either family: an IPv4 route via an IPv6 next hop is RFC 5549.
    #[serde(
        default,
        rename = "set-next-hop",
        skip_serializing_if = "Option::is_none"
    )]
    pub set_next_hop: Option<String>,
    /// Set the matching route's administrative preference to this.
    #[serde(
        default,
        rename = "set-preference",
        skip_serializing_if = "Option::is_none"
    )]
    pub set_preference: Option<u32>,
    /// Replace the matching route's communities with these.
    #[serde(
        default,
        rename = "set-community",
        skip_serializing_if = "Option::is_none"
    )]
    pub set_community: Option<Vec<String>>,
    /// Append these communities to the matching route.
    #[serde(
        default,
        rename = "add-community",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub add_community: Vec<String>,
    /// Replace the matching route's large communities with these.
    #[serde(
        default,
        rename = "set-large-community",
        skip_serializing_if = "Option::is_none"
    )]
    pub set_large_community: Option<Vec<String>>,
    /// Append these large communities to the matching route.
    #[serde(
        default,
        rename = "add-large-community",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub add_large_community: Vec<String>,
    /// Replace the matching route's extended communities with these.
    #[serde(
        default,
        rename = "set-ext-community",
        skip_serializing_if = "Option::is_none"
    )]
    pub set_ext_community: Option<Vec<String>>,
    /// Append these extended communities to the matching route.
    #[serde(
        default,
        rename = "add-ext-community",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub add_ext_community: Vec<String>,
    /// Whether a matching route is `"accept"`ed (VyOS `permit`) or `"reject"`ed
    /// (VyOS `deny`). The CLI spells these `permit`/`deny`; both spellings parse.
    pub action: String,
}

/// serde `skip_serializing_if` helper: true when a `u32` is its default (0), so
/// an unnumbered rule's `seq` is omitted from the saved config.
fn is_zero_u32(n: &u32) -> bool {
    *n == 0
}

/// The routing-policy toolbox (`[policy]`, VyOS-style): named prefix-lists and
/// route-maps, grouped under one node. Route-maps are referenced by name from a
/// BGP neighbour's `import`/`export`, a VRF's `import`/`export`, and the
/// per-protocol `[protocols.import]`/`[protocols.export]` redistribution maps —
/// the route-map decides which routes pass and how their attributes are set;
/// prefix-lists are reusable match helpers a route-map rule names via
/// `match prefix-list`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Named prefix-lists (`[[policy.prefix-list]]`) — reusable sets of prefix
    /// ranges a route-map rule matches with `match prefix-list <name>`.
    #[serde(default, rename = "prefix-list", skip_serializing_if = "Vec::is_empty")]
    pub prefix_lists: Vec<PrefixList>,
    /// Named route-maps (`[[policy.route-map]]`) — ordered match/set rules with a
    /// default action, compiled to Wren's top-level `[[filter]]`.
    #[serde(default, rename = "route-map", skip_serializing_if = "Vec::is_empty")]
    pub route_maps: Vec<Filter>,
    /// Policy-based routing (`[[policy.route]]`): send traffic by where it came
    /// from rather than where it is going.
    #[serde(default, rename = "route", skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<PolicyRoute>,
}

impl Policy {
    /// True when no policy object is configured — lets `[policy]` be omitted.
    pub fn is_empty(&self) -> bool {
        self.prefix_lists.is_empty() && self.route_maps.is_empty() && self.routes.is_empty()
    }
}

/// One policy-routing rule (`[[policy.route]]`).
///
/// Ordinary routing asks one question: where is this going? A policy route asks
/// the others — where did it come from, over which link, to which port — and
/// sends the answer to a different routing table. That is what makes a guest
/// network leave by the cheap uplink while everything else takes the good one,
/// and it is the piece multi-WAN needs to be more than failover.
///
/// Rendered as a kernel routing-policy rule (`ip rule`). The appliance owns the
/// priority band 10000-19999 and reconciles only that band, so a rule somebody
/// else put in the table is left alone.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRoute {
    /// A name for the rule, so it can be talked about and edited.
    pub name: String,
    /// Where the traffic has to come from (host or CIDR, either family).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Where it has to be going.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    /// The interface it arrived on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// `tcp` or `udp` — needed before a port can be matched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proto: Option<String>,
    /// Source port, or a `low-high` range.
    #[serde(
        default,
        rename = "source-port",
        skip_serializing_if = "Option::is_none"
    )]
    pub source_port: Option<String>,
    /// Destination port, or a `low-high` range.
    #[serde(
        default,
        rename = "destination-port",
        skip_serializing_if = "Option::is_none"
    )]
    pub destination_port: Option<String>,
    /// The routing table to consult for traffic that matches. Required — a rule
    /// that does not redirect anywhere is not a policy route.
    pub table: u32,
    /// Where this rule sits among the others (lower is consulted first). Unset ⇒
    /// assigned in declaration order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
    /// Off without being deleted.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
}

/// A named prefix-list (`[[policy.prefix-list]]`): an ordered set of prefix
/// ranges. Each entry is a prefix plus optional `ge`/`le` bounds on the match
/// length (VyOS semantics). At compile each entry becomes one Wren prefix
/// pattern (`p/len`, `p/len{ge,le}`), ORed into any route-map rule that names
/// this list. Entries are permit-only (a deny is expressed by a route-map rule
/// `action deny`, not inside the list).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixList {
    /// The list name, referenced by a route-map rule's `match prefix-list`.
    pub name: String,
    /// The entries, keyed and ordered by `seq` (VyOS-style rule numbers).
    #[serde(default, rename = "rule", skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<PrefixEntry>,
}

/// One entry of a [`PrefixList`] (`[[policy.prefix-list.rule]]`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixEntry {
    /// The rule sequence number (ordering; VyOS-style).
    pub seq: u32,
    /// The base prefix, `addr/len`.
    pub prefix: String,
    /// Match prefixes at least this long (VyOS `ge`). Unset ⇒ the prefix's own
    /// length.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ge: Option<u8>,
    /// Match prefixes at most this long (VyOS `le`). Unset ⇒ the address
    /// family's max (32 / 128).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub le: Option<u8>,
}

/// BFD (RFC 5880) global timing / authentication defaults (`[protocols.bfd]`).
/// Shared by every BFD session a protocol starts. Maps onto Wren's `[bfd]`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bfd {
    /// Desired Min TX Interval in milliseconds (default 300).
    #[serde(default, rename = "min-tx", skip_serializing_if = "Option::is_none")]
    pub min_tx: Option<u32>,
    /// Required Min RX Interval in milliseconds (default 300).
    #[serde(default, rename = "min-rx", skip_serializing_if = "Option::is_none")]
    pub min_rx: Option<u32>,
    /// Detect Mult — the session fails after this many missed intervals (default 3).
    #[serde(
        default,
        rename = "detect-mult",
        skip_serializing_if = "Option::is_none"
    )]
    pub detect_mult: Option<u8>,
    /// Authentication type: `simple`, `keyed-md5`, `meticulous-md5`, `keyed-sha1`
    /// or `meticulous-sha1`. Unset runs sessions without authentication.
    #[serde(default, rename = "auth-type", skip_serializing_if = "Option::is_none")]
    pub auth_type: Option<String>,
    /// The authentication key id advertised on the wire (0–255, default 1).
    #[serde(
        default,
        rename = "auth-key-id",
        skip_serializing_if = "Option::is_none"
    )]
    pub auth_key_id: Option<u8>,
    /// The shared secret. Required when `auth-type` is set.
    #[serde(default, rename = "auth-key", skip_serializing_if = "Option::is_none")]
    pub auth_key: Option<String>,
    /// Enable the Echo function on every IPv4 session. Defaults to false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub echo: bool,
    /// The interval between transmitted Echo packets, in milliseconds (default 100).
    #[serde(
        default,
        rename = "echo-interval",
        skip_serializing_if = "Option::is_none"
    )]
    pub echo_interval: Option<u32>,
}

/// Multicast (`[protocols.multicast]`): the IGMP/MLD querier (RFC 3376) and the
/// RFC 4605 proxy. Maps onto Wren's `[multicast]` block.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Multicast {
    /// Whether multicast (IGMP/MLD) is enabled.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub enabled: bool,
    /// Run the IGMP querier/proxy (IPv4). Defaults to true at the daemon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub igmp: Option<bool>,
    /// Run the MLDv2 querier/proxy (IPv6). Defaults to false at the daemon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mld: Option<bool>,
    /// IGMP version to speak by default (2 or 3). Defaults to 3.
    #[serde(
        default,
        rename = "igmp-version",
        skip_serializing_if = "Option::is_none"
    )]
    pub igmp_version: Option<u8>,
    /// The Robustness Variable (QRV). Defaults to 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub robustness: Option<u8>,
    /// The Query Interval in seconds. Defaults to 125.
    #[serde(
        default,
        rename = "query-interval",
        skip_serializing_if = "Option::is_none"
    )]
    pub query_interval: Option<u32>,
    /// The Query Response Interval (max response time) in seconds. Defaults to 10.
    #[serde(
        default,
        rename = "query-response-interval",
        skip_serializing_if = "Option::is_none"
    )]
    pub query_response_interval: Option<u32>,
    /// The interfaces multicast runs on, each with a role.
    #[serde(default, rename = "interface", skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<MulticastInterface>,
}

/// One `[[protocols.multicast.interface]]`: an interface and the role it plays.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MulticastInterface {
    /// The interface name.
    pub name: String,
    /// The role: `querier`, `upstream` (proxy upstream) or `downstream` (proxy
    /// downstream). Defaults to `querier`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// IGMP version for this interface (2 or 3), overriding the section default.
    #[serde(
        default,
        rename = "igmp-version",
        skip_serializing_if = "Option::is_none"
    )]
    pub igmp_version: Option<u8>,
}

/// A VRF instance (`[[protocols.vrf]]`): a named, isolated routing table. Maps
/// onto Wren's `[[vrf]]` block.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VrfDef {
    /// The VRF's name, referenced by static routes and per-protocol `vrf` fields.
    pub name: String,
    /// The kernel routing table id this VRF programs its routes into.
    pub table: u32,
    /// The VRF's Route Distinguisher (RFC 4364, e.g. `"65000:1"`). Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rd: Option<String>,
    /// Interfaces bound to this VRF.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
    /// A named route filter applied to routes entering this VRF.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub import: Option<String>,
    /// A named route filter applied to routes leaving this VRF to the kernel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export: Option<String>,
}

/// Export redistribution filters (`[protocols.export]`): which named filter gates
/// routes leaving the RIB to each consumer. Maps onto Wren's `[export]`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Export {
    /// Filter applied to best-path routes before the kernel forwarding table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    /// Filter applied to best-path routes before redistribution into BGP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bgp: Option<String>,
    /// Filter applied to best-path routes before redistribution into OSPF.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ospf: Option<String>,
    /// Filter applied to best-path routes before redistribution into RIP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rip: Option<String>,
    /// Filter applied to best-path routes before redistribution into RIPng.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ripng: Option<String>,
    /// Filter applied to best-path routes before redistribution into Babel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub babel: Option<String>,
    /// Filter applied to best-path routes before redistribution into IS-IS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isis: Option<String>,
}

/// NAT — Network Address Translation. Kept separate from [`Firewall`] because it
/// *rewrites* addresses rather than *filtering* packets — a different thing that
/// happens at a different stage. Split into source NAT (`[[nat.source]]`,
/// masquerade) and destination NAT (`[[nat.destination]]`, port-forward),
/// mirroring the VyOS `nat source` / `nat destination` model.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nat {
    /// Source NAT: masquerade traffic egressing a zone to that zone's egress IP
    /// (the classic WAN uplink). Enforced in the data plane (Phase 4b).
    #[serde(default, rename = "source", skip_serializing_if = "Vec::is_empty")]
    pub source: Vec<NatSource>,
    /// Destination NAT: inbound port-forwards.
    #[serde(default, rename = "destination", skip_serializing_if = "Vec::is_empty")]
    pub destination: Vec<NatDestination>,
    /// NAT64 (roadmap C10): stateful IPv6→IPv4 translation for an IPv6-only client
    /// network reaching the IPv4 internet, plus optional DNS64 AAAA synthesis.
    /// Omitted from saved configs when unconfigured.
    #[serde(default, skip_serializing_if = "Nat64::is_empty")]
    pub nat64: Nat64,
    /// NPTv6 (roadmap C16, RFC 6296): stateless IPv6 prefix translation between an
    /// internal and an external (provider-delegated) prefix. Checksum-neutral, no
    /// per-flow state.
    #[serde(default, rename = "npt66", skip_serializing_if = "Vec::is_empty")]
    pub npt66: Vec<NatNpt66>,
}

impl Nat {
    /// True when no NAT is configured — lets `[nat]` be omitted from a saved
    /// config that never set any.
    pub fn is_empty(&self) -> bool {
        self.source.is_empty()
            && self.destination.is_empty()
            && self.nat64.is_empty()
            && self.npt66.is_empty()
    }
}

/// A NPTv6 (RFC 6296) prefix-translation rule: on the boundary `interface`, an
/// internal IPv6 source leaving is rewritten to the external prefix, and an
/// external destination arriving is rewritten back — stateless, checksum-neutral.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NatNpt66 {
    pub name: String,
    /// A free-text label, shown in `show`. Purely documentary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The boundary (WAN) interface this translation is applied on.
    pub interface: String,
    /// Internal IPv6 prefix, e.g. `"fd00:1::/48"`.
    pub internal: String,
    /// External (provider-delegated) IPv6 prefix, e.g. `"2001:db8:1::/48"`.
    pub external: String,
}

/// The well-known NAT64 prefix (RFC 6052 §2.1 / RFC 6146) — the default when the
/// operator names no explicit prefix. Always a `/96`.
pub const NAT64_WELL_KNOWN_PREFIX: &str = "64:ff9b::/96";

/// A source-NAT (masquerade) rule: SNAT all traffic egressing `zone` to that
/// zone's egress address. The classic WAN masquerade.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NatSource {
    pub name: String,
    /// A free-text label, shown in `show`. Purely documentary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Administratively disable this masquerade rule: the compiler drops it (the
    /// zone's interfaces are not marked `masquerade`). Off by default.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
    /// The egress (WAN) zone whose outbound traffic is masqueraded — must be
    /// backed by an interface.
    pub zone: String,
    /// Deterministic CGNAT (roadmap C16): ports per internal address. Set together
    /// with `cgnat-base-port` to give every internal address a **fixed block** of
    /// WAN ports, so a WAN port attributes to a subscriber by arithmetic rather
    /// than by logging every translation. Unset ⇒ ordinary masquerade.
    #[serde(
        default,
        rename = "cgnat-block-size",
        skip_serializing_if = "Option::is_none"
    )]
    pub cgnat_block_size: Option<u16>,
    /// The first WAN port CGNAT may hand out. Defaults to 32768 (the ephemeral
    /// range) when a block size is set, leaving the well-known and registered
    /// ports alone.
    #[serde(
        default,
        rename = "cgnat-base-port",
        skip_serializing_if = "Option::is_none"
    )]
    pub cgnat_base_port: Option<u16>,
}

/// A destination-NAT (port-forward) rule: traffic hitting `zone`'s public
/// address on `proto`/`port` is rewritten to the internal host `to` (`"ip"` or
/// `"ip:port"`). The reply is SNAT'd back automatically and the firewall is
/// opened for it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NatDestination {
    pub name: String,
    /// A free-text label, shown in `show`. Purely documentary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Administratively disable this port-forward: the compiler drops it (no
    /// `[[port_forward]]` emitted). Off by default.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
    /// The ingress zone (the public side) — must be backed by an interface.
    pub zone: String,
    pub proto: Proto,
    /// Public destination port matched inbound.
    pub port: u16,
    /// Internal target, `"10.0.0.10"` or `"10.0.0.10:8443"`.
    pub to: String,
    /// Hairpin NAT (NAT reflection): also let internal clients reach this service
    /// via the box's public address. The compiler emits an extra reflection entry
    /// per other zone (matched on the public IP, source-NAT'd to the box's address
    /// on the client's segment) so the internal server's reply routes back through
    /// the box. Requires the ingress zone to have a static address. Off by default.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hairpin: bool,
}

/// A load-balanced virtual service (roadmap C22): traffic reaching `vip` on
/// `proto`/`port` from `zone` is spread across `backends`, each connection pinned
/// to one backend by a source hash so it stays there for its lifetime.
///
/// This is fabric's XDP load balancer, which the appliance had no way to reach —
/// the data plane has had `[[service]]` since phase 3, but nothing emitted it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalancer {
    pub name: String,
    /// A free-text label, shown in `show`. Purely documentary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Administratively disable this service: the compiler drops it. Off by default.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
    /// The zone clients arrive from — the service is matched under that zone's
    /// policy, mirroring `[[nat.destination]]`.
    pub zone: String,
    /// The virtual address clients connect to.
    pub vip: String,
    pub proto: Proto,
    /// The virtual port clients connect to.
    pub port: u16,
    /// The backend pool, each `"ip"` or `"ip:port"`. A bare address keeps the
    /// client's original destination port.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backends: Vec<String>,
}

/// NAT64 (roadmap C10) — stateful IPv6→IPv4 translation. An IPv6-only client
/// network reaches the IPv4 internet by addressing v4 destinations inside a
/// NAT64 prefix (`64:ff9b::<v4>`); the box translates those to real IPv4 with a
/// pooled source address. Realised by **tayga** (a userspace `nat64` tun device)
/// — chosen over Jool because it needs no out-of-tree kernel module, so it runs
/// unmodified in the appliance image and the CI VM. `dns64` layers on an
/// **unbound** resolver that synthesises `AAAA` records inside the prefix for
/// v4-only names, so unmodified IPv6-only clients resolve+reach v4 hosts.
///
/// No ALG: Sentinel ships no FTP/SIP/etc. application-layer gateways — the modern
/// secure default (ALGs mangle payloads, break TLS/SIP-over-TLS and are a
/// recurring CVE source). Applications that need NAT traversal use STUN/ICE/TURN.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nat64 {
    /// Turn NAT64 on. Off by default; the pool (and, for DNS64, a serving
    /// interface) must also be set. Skipped from output when false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub enabled: bool,
    /// The NAT64 translation prefix — an IPv6 `/96`. Unset ⇒ the well-known
    /// [`NAT64_WELL_KNOWN_PREFIX`] (`64:ff9b::/96`, RFC 6052).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// The IPv4 pool (a CIDR like `"192.0.2.0/24"`) tayga draws translated source
    /// addresses from — the box's public/routable v4 space (or a private range
    /// masqueraded out the WAN). Required when `enabled`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool: Option<String>,
    /// The IPv6-only side — a declared interface. DNS64 binds its resolver to this
    /// interface's IPv6 address so only that segment's clients get synthesised
    /// answers. Required when `dns64` is on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Synthesize `AAAA` records inside the NAT64 prefix for v4-only names (an
    /// unbound resolver on `interface`). Off by default. Needs `interface` (with a
    /// static IPv6 address) and an upstream (`[services.dns] upstream`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dns64: bool,
}

impl Nat64 {
    /// True when NAT64 is unconfigured — lets `[nat.nat64]` be omitted.
    pub fn is_empty(&self) -> bool {
        !self.enabled
            && self.prefix.is_none()
            && self.pool.is_none()
            && self.interface.is_none()
            && !self.dns64
    }

    /// The effective translation prefix — the operator's, else the well-known.
    pub fn effective_prefix(&self) -> &str {
        self.prefix.as_deref().unwrap_or(NAT64_WELL_KNOWN_PREFIX)
    }
}

/// Multi-WAN (roadmap C6) — several WAN uplinks reconciled into failover or
/// load-balancing with per-uplink health checks and policy-based routing. The
/// model mirrors VyOS `wan-load-balance`: each uplink owns a routing table (a
/// default route via its gateway), a small daemon pings the uplink's targets,
/// and the winning uplink(s) become the `main`-table default. Empty by default.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiWan {
    /// `failover` (one active uplink, the rest standby — the lowest `priority`
    /// number wins) or `load-balance` (spread flows across every healthy uplink
    /// by `weight`). Defaults to `failover`; skipped on output when default.
    #[serde(default, skip_serializing_if = "WanMode::is_default")]
    pub mode: WanMode,
    /// The WAN uplinks, in configuration order.
    #[serde(default, rename = "uplink", skip_serializing_if = "Vec::is_empty")]
    pub uplinks: Vec<WanUplink>,
    /// Steering policies (`[[multiwan.policy]]`): which traffic prefers which
    /// uplink, and what happens when that uplink stops meeting its SLA.
    #[serde(default, rename = "policy", skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<WanPolicy>,
}

/// One SD-WAN steering policy.
///
/// Failover answers "the uplink died, now what". Steering answers the question
/// before it: *this* traffic belongs on *that* uplink, and should move only when
/// that uplink stops being good enough for it. A video call and a backup want
/// opposite things from the same two links, and priority alone cannot say so.
///
/// The match is the same vocabulary a policy route uses, because it is the same
/// question. What differs is the answer: a policy route names one table, this
/// names an ordered preference and lets the daemon pick.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WanPolicy {
    /// A name, so it can be talked about and edited.
    pub name: String,
    /// Where the traffic comes from (host or CIDR).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Where it is going.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    /// `tcp` or `udp` — needed before a port can be matched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proto: Option<String>,
    /// Source port, or a `low-high` range.
    #[serde(
        default,
        rename = "source-port",
        skip_serializing_if = "Option::is_none"
    )]
    pub source_port: Option<String>,
    /// Destination port, or a `low-high` range.
    #[serde(
        default,
        rename = "destination-port",
        skip_serializing_if = "Option::is_none"
    )]
    pub destination_port: Option<String>,
    /// The uplinks this traffic prefers, best first, by interface name. The
    /// daemon sends it out the first one that is up **and** within its SLA; if
    /// none qualifies it falls back to the first that is merely up, because a
    /// degraded path still beats no path.
    #[serde(default, rename = "uplink", skip_serializing_if = "Vec::is_empty")]
    pub uplinks: Vec<String>,
    /// Refuse to send this traffic at all rather than send it over a path that
    /// does not meet its SLA. For the traffic where a bad answer is worse than
    /// no answer.
    #[serde(default, rename = "strict", skip_serializing_if = "std::ops::Not::not")]
    pub strict: bool,
    /// Off without being deleted.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
}

/// How a [`MultiWan`] group reconciles its uplinks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WanMode {
    /// One active uplink at a time; on its failure the next-preferred healthy
    /// uplink takes the default route (primary/backup).
    #[default]
    Failover,
    /// Spread outbound flows across all healthy uplinks, weighted (a multipath
    /// default route).
    LoadBalance,
}

impl WanMode {
    /// True for the default (`failover`) — lets `mode` be omitted from output.
    pub fn is_default(&self) -> bool {
        matches!(self, WanMode::Failover)
    }
}

/// The base routing-table id Multi-WAN uplinks are numbered from when no
/// explicit `table` is given: uplink `idx` owns `WAN_TABLE_BASE + idx`.
pub const WAN_TABLE_BASE: u32 = 200;
/// Default health-check ping interval (seconds).
pub const WAN_CHECK_INTERVAL: u32 = 5;
/// Default per-ping timeout (seconds).
pub const WAN_CHECK_TIMEOUT: u32 = 2;
/// Default consecutive failures before an uplink is marked down.
pub const WAN_CHECK_FAIL: u32 = 3;
/// Default consecutive successes before a down uplink is marked back up.
pub const WAN_CHECK_RISE: u32 = 3;

impl MultiWan {
    /// True when nothing is configured — no uplink AND the default mode — lets
    /// `[multiwan]` be omitted. A non-default `mode` alone keeps it (so a
    /// mode-without-uplinks misconfiguration round-trips and is caught at commit).
    pub fn is_empty(&self) -> bool {
        self.uplinks.is_empty() && self.mode.is_default()
    }

    /// The routing-table id uplink `u` at index `idx` owns: its explicit
    /// `table`, else the derived `WAN_TABLE_BASE + idx`.
    pub fn table_for(&self, idx: usize, u: &WanUplink) -> u32 {
        u.table.unwrap_or(WAN_TABLE_BASE + idx as u32)
    }
}

/// One WAN uplink in a [`MultiWan`] group.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WanUplink {
    /// The egress interface (a declared `[[interface]]`).
    pub interface: String,
    /// Failover ordering — the lowest number is the preferred (primary) uplink.
    /// Unset ⇒ derived from configuration order (`10 * idx`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
    /// Relative share under `load-balance` (a multipath nexthop weight). Unset ⇒
    /// `1`. Ignored in `failover` mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<u32>,
    /// The policy-routing table id this uplink owns. Unset ⇒ `WAN_TABLE_BASE +
    /// idx` (see [`MultiWan::table_for`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<u32>,
    /// The next-hop gateway for this uplink's default route — an IPv4 address, or
    /// `"dhcp"` (the default) to resolve it from the link's DHCP lease at runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// The health check that decides whether this uplink is up. Declared last so
    /// its TOML sub-table serialises after the scalar keys.
    #[serde(
        default,
        rename = "health-check",
        skip_serializing_if = "HealthCheck::is_default"
    )]
    pub check: HealthCheck,
}

/// A per-uplink health check (roadmap C6): the daemon pings each of `targets`
/// out the uplink every `interval` seconds; `fail` consecutive losses mark the
/// uplink down and `rise` consecutive successes mark it back up. Empty `targets`
/// ⇒ the uplink is assumed up whenever its link is (no active probing).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheck {
    /// IPv4 addresses pinged out the uplink (any one reachable ⇒ up).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<String>,
    /// Seconds between probe rounds (default [`WAN_CHECK_INTERVAL`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<u32>,
    /// Per-ping timeout in seconds (default [`WAN_CHECK_TIMEOUT`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    /// Consecutive failures before marking the uplink down (default
    /// [`WAN_CHECK_FAIL`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail: Option<u32>,
    /// Consecutive successes before marking a down uplink up (default
    /// [`WAN_CHECK_RISE`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rise: Option<u32>,
    /// Round-trip time above which the uplink is **out of SLA**, in
    /// milliseconds. Unset ⇒ latency is measured but never disqualifies.
    ///
    /// Out of SLA is not the same as down. A link that answers every probe in
    /// 400 ms is up by any reachability test and useless for a call, and the
    /// whole point of steering is to notice the difference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency: Option<u32>,
    /// Variation in round-trip time above which the uplink is out of SLA, in
    /// milliseconds. What a call hears before it hears latency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jitter: Option<u32>,
    /// Packet loss above which the uplink is out of SLA, in percent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss: Option<u32>,
    /// Probes sent per round when an SLA threshold is set. One ping cannot
    /// measure loss or jitter, so a threshold needs a sample. Unset ⇒ 5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probes: Option<u32>,
}

impl HealthCheck {
    /// True when nothing is set — lets `health-check` be omitted from output.
    pub fn is_default(&self) -> bool {
        self.targets.is_empty()
            && self.interval.is_none()
            && self.timeout.is_none()
            && self.fail.is_none()
            && self.rise.is_none()
            && self.latency.is_none()
            && self.jitter.is_none()
            && self.loss.is_none()
            && self.probes.is_none()
    }

    /// Whether this check measures quality rather than only reachability.
    pub fn has_sla(&self) -> bool {
        self.latency.is_some() || self.jitter.is_some() || self.loss.is_some()
    }
}

/// VPN services (roadmap C2). Currently IKEv2 site-to-site IPsec (strongSwan);
/// OpenVPN / road-warrior responders land here later. Grouped like [`Services`]
/// so VPN types share one `[vpn.*]` namespace instead of sprawling across the
/// top level. Empty by default.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vpn {
    /// IKEv2 site-to-site IPsec connections (`[[vpn.ipsec]]`), rendered to a
    /// strongSwan swanctl.conf + a 0600 PSK secrets file.
    #[serde(default, rename = "ipsec", skip_serializing_if = "Vec::is_empty")]
    pub ipsec: Vec<IpsecConnection>,
    /// WireGuard tunnels (`[[vpn.wireguard]]`), each keyed by the name of a
    /// `type = "wireguard"` interface. Carries the private key, listen port and
    /// peers — the interface itself only declares the address/zone/mtu.
    #[serde(default, rename = "wireguard", skip_serializing_if = "Vec::is_empty")]
    pub wireguard: Vec<WireguardTunnel>,
    /// The OpenConnect (AnyConnect-compatible) road-warrior VPN server
    /// (`[vpn.openconnect]`), rendered to an `ocserv.conf` + a 0600 password
    /// file. At most one per box — it is a single listening service, unlike the
    /// site-to-site tunnel lists above.
    #[serde(
        default,
        rename = "openconnect",
        skip_serializing_if = "Option::is_none"
    )]
    pub openconnect: Option<OpenConnectServer>,
}

impl Vpn {
    /// True when no VPN is configured — lets `[vpn]` be omitted from output.
    pub fn is_empty(&self) -> bool {
        self.ipsec.is_empty() && self.wireguard.is_empty() && self.openconnect.is_none()
    }
}

/// Default TCP/UDP port the OpenConnect server listens on — 443, so it traverses
/// restrictive networks that only allow HTTPS (the whole point of a TLS VPN).
pub const DEFAULT_OPENCONNECT_PORT: u16 = 443;

/// The OpenConnect (AnyConnect-compatible) VPN server (`[vpn.openconnect]`) —
/// a TLS road-warrior VPN for client devices, complementing site-to-site IPsec
/// and peer-to-peer WireGuard. Rendered by `openconnect.rs` into an `ocserv.conf`
/// (served by `ocserv`) plus a 0600 `ocpasswd` file for the user credentials.
/// The server certificate is a leaf issued by the on-box PKI (C19).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenConnectServer {
    /// Administratively disable the server without deleting its config (parks it
    /// like `interface … disabled`). Off by default.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
    /// TCP (and UDP/DTLS) port to listen on. Defaults to
    /// [`DEFAULT_OPENCONNECT_PORT`] (443).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// The PKI certificate (`[[pki.certificate]]` name, or `acme`) used as the
    /// server's TLS identity. Required — the client validates it.
    pub certificate: String,
    /// The client address pool as a CIDR (e.g. `10.99.0.0/24`): each connected
    /// client is handed an address from it. Required.
    pub pool: String,
    /// DNS resolvers pushed to connected clients. Empty ⇒ none pushed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<String>,
    /// Split-tunnel routes pushed to clients (CIDRs the client sends over the
    /// VPN). Empty with `default-route = false` ⇒ the client keeps its own
    /// default and only the pushed routes go over the tunnel.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<String>,
    /// Push a default route so ALL client traffic goes over the VPN (full
    /// tunnel). Mutually exclusive with a non-empty `routes` list.
    #[serde(
        default,
        rename = "default-route",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub default_route: bool,
    /// The firewall zone the server's `vpn0` tun interface belongs to, so zone
    /// rules apply to VPN clients. Optional (unset ⇒ no zone binding).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// The users allowed to connect (`[[vpn.openconnect.user]]`). Each is a
    /// name + password rendered into the 0600 password file. At least one is
    /// required — a server with no users can accept no one.
    #[serde(default, rename = "user", skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<OpenConnectUser>,
}

impl OpenConnectServer {
    /// The effective listen port (explicit or the 443 default).
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(DEFAULT_OPENCONNECT_PORT)
    }
}

/// One OpenConnect client credential (`[[vpn.openconnect.user]]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenConnectUser {
    /// Login name. Required; `[A-Za-z0-9_.-]` (rendered into a line-based
    /// password file).
    pub name: String,
    /// The account password. Secret — rendered to the 0600 password file,
    /// never into ocserv.conf. Required.
    pub password: String,
}

/// One WireGuard tunnel (`[[vpn.wireguard]]`) — the keys + peers for the
/// `type = "wireguard"` interface named in `name`. The interface declares the
/// link's L3 config (address/zone/mtu); this carries the crypto. Rendered by
/// `net.rs` into the interface's `.netdev` (`[WireGuard]` + `[WireGuardPeer]`
/// sections), which is a secret (private key) installed 0640 root:systemd-network.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireguardTunnel {
    /// The interface this tunnel configures — must name a declared
    /// `type = "wireguard"` interface.
    pub name: String,
    /// WireGuard private key (base64 of 32 raw bytes). Required — a
    /// `type = "wireguard"` interface without one is rejected at commit.
    #[serde(rename = "private-key")]
    pub private_key: String,
    /// UDP port WireGuard listens on. Optional (an outbound-only tunnel needs
    /// none); when set the peer can reach us at this port.
    #[serde(
        default,
        rename = "listen-port",
        skip_serializing_if = "Option::is_none"
    )]
    pub listen_port: Option<u16>,
    /// WireGuard peers reachable over this tunnel.
    #[serde(default, rename = "peer", skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<WgPeer>,
}

/// Default IKE (phase-1) proposal when none is given: AES-256 / SHA-256 with a
/// 2048-bit MODP DH group — a strong, near-universally-interoperable baseline.
pub const DEFAULT_IKE_PROPOSAL: &str = "aes256-sha256-modp2048";
/// Default ESP (phase-2) proposal when none is given — the same suite, so the
/// child SA gets PFS from the modp2048 group.
pub const DEFAULT_ESP_PROPOSAL: &str = "aes256-sha256-modp2048";
/// Default child-SA start action: initiate the tunnel as soon as the config is
/// loaded (the friendly default for a site-to-site that should come up now).
pub const DEFAULT_IPSEC_START_ACTION: &str = "start";

/// One IKEv2 site-to-site IPsec connection (`[[vpn.ipsec]]`) — a policy-based
/// tunnel between two endpoints authenticated with a pre-shared key. Compiled to
/// a strongSwan swanctl `connections`/`children` block plus a 0600 `secrets`
/// entry for the PSK (never written into the world-readable swanctl.conf).
/// Route-based (XFRM-interface) mode with a firewall zone, road-warrior
/// responders (`%any` remotes + EAP) and certificate auth are follow-ups.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpsecConnection {
    /// Connection name — the swanctl connection id and the secrets tag. Required;
    /// restricted to `[A-Za-z0-9_-]` since it is rendered as a config section key.
    pub name: String,
    /// This box's IKE endpoint address (`local_addrs`). Required — an IPv4.
    pub local: String,
    /// The peer's IKE endpoint address (`remote_addrs`). Required — an IPv4.
    pub remote: String,
    /// The local protected subnet — the child SA's `local_ts` traffic selector.
    /// Required — an IPv4 CIDR (or host).
    #[serde(rename = "local-subnet")]
    pub local_subnet: String,
    /// The remote protected subnet — the child SA's `remote_ts`. Required — an
    /// IPv4 CIDR (or host).
    #[serde(rename = "remote-subnet")]
    pub remote_subnet: String,
    /// The pre-shared key. Secret — rendered to a 0600 secrets file, never into
    /// the swanctl.conf. Required.
    pub psk: String,
    /// IKE major version: `2` (IKEv2, the default) or `1` (IKEv1). Unset ⇒ 2.
    #[serde(
        default,
        rename = "ike-version",
        skip_serializing_if = "Option::is_none"
    )]
    pub ike_version: Option<u8>,
    /// IKE (phase-1) cipher proposal (`aes256-sha256-modp2048`, …). Unset ⇒
    /// [`DEFAULT_IKE_PROPOSAL`].
    #[serde(
        default,
        rename = "ike-proposal",
        skip_serializing_if = "Option::is_none"
    )]
    pub ike_proposal: Option<String>,
    /// ESP (phase-2) cipher proposal. Unset ⇒ [`DEFAULT_ESP_PROPOSAL`].
    #[serde(
        default,
        rename = "esp-proposal",
        skip_serializing_if = "Option::is_none"
    )]
    pub esp_proposal: Option<String>,
    /// The local IKE identity (`local.id`). Unset ⇒ the `local` address.
    #[serde(default, rename = "local-id", skip_serializing_if = "Option::is_none")]
    pub local_id: Option<String>,
    /// The remote IKE identity (`remote.id`). Unset ⇒ the `remote` address.
    #[serde(default, rename = "remote-id", skip_serializing_if = "Option::is_none")]
    pub remote_id: Option<String>,
    /// Child-SA start action: `start` (initiate on load — the default), `trap`
    /// (install a policy and initiate on first matching packet) or `none` (wait
    /// for the peer — a responder). Unset ⇒ [`DEFAULT_IPSEC_START_ACTION`].
    #[serde(
        default,
        rename = "start-action",
        skip_serializing_if = "Option::is_none"
    )]
    pub start_action: Option<String>,
}

/// Built-in public-key infrastructure (roadmap C19): an on-box certificate
/// authority for issuing VPN/management certs, plus an ACME (Let's Encrypt)
/// client for public certs. A distinct top-level tree (like [`Vpn`]) — its own
/// domain, not a "service". Key material is generated at commit time into the
/// persistent `/var/lib/sentinel/pki` store; only the declarative definitions
/// live in the config. Empty by default.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pki {
    /// Local certificate authorities (`[[pki.ca]]`) — each self-signed, its key
    /// (0600) + cert generated into `/var/lib/sentinel/pki/ca/<name>/`.
    #[serde(default, rename = "ca", skip_serializing_if = "Vec::is_empty")]
    pub cas: Vec<Ca>,
    /// Issued leaf certificates (`[[pki.certificate]]`) — signed by a local CA or
    /// obtained via ACME.
    #[serde(default, rename = "certificate", skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<Certificate>,
    /// ACME account (`[pki.acme]`) — the directory / email / challenge used to
    /// obtain every `ca = "acme"` certificate. Absent ⇒ no ACME.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme: Option<Acme>,
}

impl Pki {
    /// True when no PKI is configured — lets `[pki]` be omitted from output.
    pub fn is_empty(&self) -> bool {
        self.cas.is_empty() && self.certificates.is_empty() && self.acme.is_none()
    }
}

/// The reserved `ca` value that marks a [`Certificate`] as ACME-obtained rather
/// than signed by a local [`Ca`].
pub const ACME_CA: &str = "acme";
/// Default key type for a CA / leaf when none is given: NIST P-256 (EC) — small,
/// fast and universally accepted for TLS and IKE.
pub const DEFAULT_PKI_KEY_TYPE: &str = "ec";
/// Default validity of a local CA certificate: 10 years.
pub const DEFAULT_CA_VALIDITY_DAYS: u32 = 3650;
/// Default validity of an issued leaf certificate: 825 days (the CA/Browser
/// Forum maximum for a publicly-trusted server certificate).
pub const DEFAULT_CERT_VALIDITY_DAYS: u32 = 825;
/// Default ACME directory: Let's Encrypt production. Point at the staging
/// directory (`…/acme-staging-v02…`) while testing to avoid rate limits.
pub const DEFAULT_ACME_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// One local certificate authority (`[[pki.ca]]`). Self-signed at commit time;
/// its key (0600) + cert live under `/var/lib/sentinel/pki/ca/<name>/` and are
/// never regenerated once present.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ca {
    /// CA name — the store subdirectory and the `ca` reference from a
    /// certificate. Required; restricted to `[A-Za-z0-9_-]` since it names a
    /// filesystem path.
    pub name: String,
    /// The CA certificate's subject common name (`CN`). Required.
    #[serde(rename = "common-name")]
    pub common_name: String,
    /// The subject organization (`O`). Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    /// Key type: `ec` (P-256, the default) or `rsa` (3072-bit). Unset ⇒
    /// [`DEFAULT_PKI_KEY_TYPE`].
    #[serde(default, rename = "key-type", skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    /// Certificate validity in days. Unset ⇒ [`DEFAULT_CA_VALIDITY_DAYS`].
    #[serde(
        default,
        rename = "validity-days",
        skip_serializing_if = "Option::is_none"
    )]
    pub validity_days: Option<u32>,
}

/// One issued leaf certificate (`[[pki.certificate]]`). For a CA-signed cert the
/// key (0600) + cert are generated into `/var/lib/sentinel/pki/certs/<name>/`;
/// for `ca = "acme"` the cert is obtained from the [`Acme`] account instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    /// Certificate name — the store subdirectory. Required; `[A-Za-z0-9_-]`.
    pub name: String,
    /// The signing authority: the name of a local [`Ca`], or [`ACME_CA`]
    /// (`"acme"`) for an ACME-obtained cert. Required.
    pub ca: String,
    /// The subject common name (`CN`). Required.
    #[serde(rename = "common-name")]
    pub common_name: String,
    /// Subject alternative names, each `DNS:<host>` or `IP:<addr>` — modern
    /// clients match on these, not the CN.
    #[serde(
        default,
        rename = "subject-alt-name",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub subject_alt_names: Vec<String>,
    /// Key type: `ec` (default) or `rsa`. Unset ⇒ [`DEFAULT_PKI_KEY_TYPE`].
    #[serde(default, rename = "key-type", skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    /// Intended usage: `server` (the default) or `client` — selects the extended
    /// key usage (serverAuth vs clientAuth). Unset ⇒ server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<String>,
    /// Certificate validity in days. Unset ⇒ [`DEFAULT_CERT_VALIDITY_DAYS`].
    #[serde(
        default,
        rename = "validity-days",
        skip_serializing_if = "Option::is_none"
    )]
    pub validity_days: Option<u32>,
}

/// The ACME account (`[pki.acme]`) used to obtain every `ca = "acme"`
/// certificate. Live issuance needs external reachability (an HTTP-01 / DNS-01
/// challenge) and is performed on hardware; in the appliance the account
/// descriptor is rendered so the config round-trips and the wiring is in place.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acme {
    /// The ACME contact email (account registration + expiry notices). Required.
    pub email: String,
    /// The ACME directory URL. Unset ⇒ [`DEFAULT_ACME_DIRECTORY`] (Let's Encrypt
    /// production).
    #[serde(
        default,
        rename = "directory-url",
        skip_serializing_if = "Option::is_none"
    )]
    pub directory_url: Option<String>,
    /// Challenge type: `http-01` (the default) or `dns-01`. Unset ⇒ http-01.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    /// Whether the ACME terms of service are agreed to (required for issuance).
    #[serde(default, rename = "agree-tos", skip_serializing_if = "Option::is_none")]
    pub agree_tos: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct System {
    pub hostname: String,
    /// Kernel parameters to set (`[system.sysctl]`), as `name = "value"`.
    ///
    /// A deliberate escape hatch, not a feature: the settings a firewall needs
    /// that this schema has no opinion about. `net.ipv4.ip_nonlocal_bind` is the
    /// canonical one — a service binds a virtual address that this box does not
    /// hold right now, which is exactly the situation a VRRP backup is in.
    ///
    /// Written to a drop-in and applied on commit. Only `net.*` and `vm.*` are
    /// accepted: everything else on a firewall is a way to make the box
    /// unbootable from a config file, and an appliance that offers that is
    /// offering a foot-gun rather than a knob.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sysctl: BTreeMap<String, String>,
    /// Local login accounts (`[[system.login]]`, VyOS-style). Each carries the
    /// SSH public keys allowed to log in as that user and an optional pre-hashed
    /// login password (console + sudo). Empty ⇒ only the image's built-in `admin`.
    #[serde(default, rename = "login", skip_serializing_if = "Vec::is_empty")]
    pub logins: Vec<Login>,
    /// Permission groups for management access (`[[system.group]]`).
    ///
    /// A group is where a permission is written down once and a set of people
    /// point at it, rather than each account carrying its own answer — which is
    /// how an appliance ends up with one account nobody dares touch because
    /// nobody remembers what it may do.
    #[serde(default, rename = "group", skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<Group>,
    /// HA config sync (`[system.config-sync]`, roadmap C21): push the running config
    /// to peer firewalls on every commit. Empty ⇒ off.
    #[serde(
        rename = "config-sync",
        default,
        skip_serializing_if = "ConfigSync::is_empty"
    )]
    pub config_sync: ConfigSync,
    /// HA conntrack-state sync (`[system.conntrack-sync]`, roadmap C9): mirror the
    /// eBPF conntrack table to peer firewalls so established (NAT'd) flows survive a
    /// VRRP failover. Empty ⇒ off.
    #[serde(
        rename = "conntrack-sync",
        default,
        skip_serializing_if = "ConntrackSync::is_empty"
    )]
    pub conntrack_sync: ConntrackSync,
    /// Keeping a history of what the box did (`[system.metrics]`).
    #[serde(default, skip_serializing_if = "Metrics::is_default")]
    pub metrics: Metrics,
    /// Where a password is checked when it is not checked here
    /// (`[system.aaa]`). Empty ⇒ local accounts only.
    #[serde(default, skip_serializing_if = "Aaa::is_empty")]
    pub aaa: Aaa,
    /// Serial console (`[system.console]`). A box in a rack is reached over its
    /// serial port when the network it manages is the thing that is broken, and
    /// the speed has to match what is on the other end of the cable.
    #[serde(default, skip_serializing_if = "Console::is_empty")]
    pub console: Console,
    /// How many past revisions the archive keeps (`system commit-revisions`).
    ///
    /// Not a constant, because how far back you can roll is a policy: a box that
    /// is changed twice a year wants a longer memory than one that is changed
    /// twice a day. Unset ⇒ the appliance default.
    #[serde(
        rename = "commit-revisions",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub commit_revisions: Option<u32>,
}

/// Keeping a history (`[system.metrics]`).
///
/// Live counters answer "what is happening"; they cannot answer "was this
/// happening at three in the morning last Tuesday", which is the question an
/// operator actually arrives with. Off by default: a box with a small or
/// read-mostly disk should not start writing to it because a graph might be
/// nice, and saying so is better than a knob nobody finds.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    /// Record a history at all.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub enable: bool,
}

impl Metrics {
    pub fn is_default(&self) -> bool {
        !self.enable
    }
}

/// Authentication that is not local (`[system.aaa]`).
///
/// A local account list is a shadow account list: it has to be maintained
/// alongside the real one, and it is the one nobody remembers to remove
/// somebody from. This is how the directory answers instead.
///
/// The order is deliberate and not configurable: **local first, then the
/// servers in the order given**. A box whose directory is unreachable must
/// still be enterable by the account written on it, and that is precisely the
/// moment the directory is likely to be unreachable.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Aaa {
    /// RADIUS servers, tried in order. The first that answers decides — a
    /// reject from a reachable server is an answer, not a reason to ask the
    /// next one.
    #[serde(default, rename = "radius", skip_serializing_if = "Vec::is_empty")]
    pub radius: Vec<RadiusServer>,
    /// LDAP directories, tried after the RADIUS servers. The first that answers
    /// decides.
    #[serde(default, rename = "ldap", skip_serializing_if = "Vec::is_empty")]
    pub ldap: Vec<LdapServer>,
    /// The permission group an account authenticated by a server gets when this
    /// box has no local entry for it. Unset ⇒ a directory account still needs a
    /// local `[[system.login]]` naming its group, which is the safe default:
    /// without it, everybody in the directory would have management access the
    /// moment a server is configured.
    #[serde(
        default,
        rename = "default-group",
        skip_serializing_if = "Option::is_none"
    )]
    pub default_group: Option<String>,
}

impl Aaa {
    pub fn is_empty(&self) -> bool {
        self.radius.is_empty() && self.ldap.is_empty() && self.default_group.is_none()
    }
}

/// One LDAP directory (`[[system.aaa.ldap]]`).
///
/// A **simple bind** as the user, not a search-then-bind. Searching first needs
/// a service account whose password then sits on the firewall, and a template
/// DN covers the flat directories people actually point a firewall at. If a
/// deployment genuinely needs a search, that is a later addition rather than a
/// reason to keep a second credential here now.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LdapServer {
    /// Its address or hostname.
    pub server: String,
    /// Its port. Unset ⇒ 636 for `ldaps`, 389 otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Where the accounts live — `"ou=people,dc=example,dc=com"`. The bind DN is
    /// `<user-attribute>=<username>,<base-dn>`.
    #[serde(rename = "base-dn")]
    pub base_dn: String,
    /// The attribute naming an account. Unset ⇒ `uid`; Active Directory usually
    /// wants `sAMAccountName` or a userPrincipalName instead.
    #[serde(
        default,
        rename = "user-attribute",
        skip_serializing_if = "Option::is_none"
    )]
    pub user_attribute: Option<String>,
    /// How the connection is protected: `ldaps` (default), `starttls`, or
    /// `none`.
    ///
    /// `none` sends the password in the clear. It exists because a directory on
    /// a loopback or a wire you already control is a real deployment, and
    /// refusing it outright would push people to a worse workaround — but it is
    /// not the default and it is not silent: `commit` says so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<String>,
    /// How long to wait for an answer, in seconds. Unset ⇒ 5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
}

/// One RADIUS server (`[[system.aaa.radius]]`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadiusServer {
    /// Its address or hostname.
    pub server: String,
    /// Its port. Unset ⇒ 1812.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// The shared secret. RFC 2865 hides the password with MD5 against this,
    /// which is not encryption in any modern sense — a RADIUS server belongs on
    /// a segment you already trust, and this is worth saying out loud rather
    /// than leaving for somebody to discover.
    pub secret: String,
    /// How long to wait for an answer, in seconds. Unset ⇒ 3. A login is a
    /// person waiting, so this is short on purpose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
}

/// Serial console (`[system.console]`). `device` is a tty on this box (`ttyS0`,
/// `ttyAMA0`); `speed` is its baud rate. Both or neither — a speed without a
/// device says nothing about which port it applies to.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Console {
    /// The tty, without `/dev/` (`ttyS0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// Baud rate. The usual answers are 9600 and 115200.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub speed: Option<u32>,
}

impl Console {
    pub fn is_empty(&self) -> bool {
        self.device.is_none() && self.speed.is_none()
    }
}

/// HA config sync (`[system.config-sync]`). On every `commit`, the running config
/// is pushed to each `peer`'s Sentinel API (`PUT /api/v1/config`, bearer = the
/// shared `secret`), which applies + persists it — pfSense-XMLRPC-analog, but
/// declarative. A received sync does NOT re-push (only the interactive commit does),
/// so a pair does not loop. Configuring a `secret` also arms the receiving side:
/// this box runs its own API (on `:8080`, token = the secret) so a peer can push to
/// it. Firewall rules gate who may reach that port.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigSync {
    /// Peer firewalls to push the config to — `host` or `host:port` (default port
    /// 8080). Repeatable.
    #[serde(rename = "peer", default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<String>,
    /// The shared bearer token both peers present. Required once any peer is set;
    /// it is written to this box's API token file so a peer may push here too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

impl ConfigSync {
    /// True when no config sync is configured — lets `[system.config-sync]` be
    /// omitted from a saved config.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty() && self.secret.is_none()
    }
}

/// HA conntrack-state sync (`[system.conntrack-sync]`, roadmap C9). The velstra
/// data plane binds a UDP socket on `listen`, pushes its live conntrack entries to
/// each `peer` every `interval` seconds, and applies the entries a peer pushes — a
/// pfsync-analog for the eBPF conntrack table. Together with VRRP (virtual IP) and
/// `[system.config-sync]` (running config) it completes the HA triad: a failover
/// keeps established, NAT'd connections alive instead of dropping every flow.
///
/// The sync stream is **unauthenticated** (like pfsync), so it must run over a
/// trusted/dedicated sync link; firewall rules gate who may reach the port.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConntrackSync {
    /// Address the data plane binds to receive peer state — `host` or `host:port`
    /// (default port `5429`). When peers are set but `listen` is omitted, the box
    /// binds `0.0.0.0:5429`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    /// Peer firewalls to push conntrack state to — `host` or `host:port` (default
    /// port `5429`). Repeatable.
    #[serde(rename = "peer", default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<String>,
    /// Seconds between pushes. Defaults to 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
}

impl ConntrackSync {
    /// Default UDP port for the conntrack-sync socket.
    pub const DEFAULT_PORT: u16 = 5429;

    /// True when no conntrack sync is configured — lets `[system.conntrack-sync]`
    /// be omitted from a saved config.
    pub fn is_empty(&self) -> bool {
        self.listen.is_none() && self.peers.is_empty() && self.interval.is_none()
    }

    /// The `listen` value normalized to `ip:port` for the velstra agent config —
    /// appending the default port when only a host was given, and defaulting the
    /// whole endpoint to `0.0.0.0:PORT` when unset. Returns `None` when not enabled.
    pub fn listen_endpoint(&self) -> Option<String> {
        if self.is_empty() {
            return None;
        }
        Some(match &self.listen {
            Some(l) => with_default_port(l, Self::DEFAULT_PORT),
            None => format!("0.0.0.0:{}", Self::DEFAULT_PORT),
        })
    }

    /// The peers normalized to `ip:port` for the velstra agent config.
    pub fn peer_endpoints(&self) -> Vec<String> {
        self.peers
            .iter()
            .map(|p| with_default_port(p, Self::DEFAULT_PORT))
            .collect()
    }
}

/// Append `:port` to a `host` that has no explicit port; leave a `host:port`
/// (including a bracketed `[v6]:port`) untouched. A bare IPv6 literal (which
/// contains colons but no port) is bracketed and given the default port.
fn with_default_port(host: &str, port: u16) -> String {
    // Already `host:port`? A single trailing `:digits` on an IPv4/hostname, or a
    // bracketed `[v6]:digits`, means a port is present.
    if let Some((h, p)) = host.rsplit_once(':') {
        let has_port = !p.is_empty()
            && p.chars().all(|c| c.is_ascii_digit())
            && (h.starts_with('[') || !h.contains(':'));
        if has_port {
            return host.to_string();
        }
    }
    // A bare IPv6 literal has colons but no port — bracket it.
    if host.parse::<Ipv6Addr>().is_ok() {
        return format!("[{host}]:{port}");
    }
    format!("{host}:{port}")
}

/// A local login account (`[[system.login]]`). Users are reconciled onto the box
/// at commit time (mutableUsers): a named account is created if missing, its SSH
/// keys and (pre-hashed) password are set. The password is for console + sudo;
/// SSH stays key-only unless `[services.ssh] password-authentication` is on.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Login {
    /// The account name (POSIX: starts with a letter, then letters/digits/`-`/`_`).
    pub username: String,
    /// OpenSSH public keys that may log in as this user. Repeatable.
    #[serde(rename = "ssh-key", default, skip_serializing_if = "Vec::is_empty")]
    pub ssh_keys: Vec<String>,
    /// A pre-hashed login password in crypt(3) form (`$6$salt$hash`, as produced by
    /// `mkpasswd -m sha-512`). Never a plaintext password. Unset ⇒ no password
    /// (login only by key). Sets the OS password used for console + sudo.
    #[serde(
        rename = "hashed-password",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hashed_password: Option<String>,
    /// A base32 TOTP secret (RFC 6238). Set ⇒ this account must give a
    /// six-digit code as well as its password to reach the API or the console.
    ///
    /// Console and API only. A second factor on the serial console would lock
    /// somebody out of the port they reach for when the network is down, and a
    /// second factor on SSH belongs to sshd's own configuration, not here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
    /// The permission group this account belongs to, for **management access**
    /// (the API and the console). Unset ⇒ the account can log in to the box but
    /// has no management access at all: shell access and API access are separate
    /// grants, and conflating them would hand every console operator a shell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

/// A permission group (`[[system.group]]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    /// The group name accounts point at.
    pub name: String,
    /// What members may do through the management API and the console.
    pub permission: Permission,
}

/// What a group's members may do through the management interfaces.
///
/// Two levels, and deliberately only two. Every finer split invites the question
/// "may this person change *that* setting", which on a firewall is a question
/// about the ruleset rather than about the person — and a permission model that
/// cannot answer it honestly is worse than one that does not pretend to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Permission {
    /// May read everything: the configuration, the status, every `show`.
    /// May change nothing, run no capture, clear no state.
    ReadOnly,
    /// May do anything the CLI can: change the configuration, apply it, clear
    /// run-time state, take a capture.
    ReadWrite,
}

impl Permission {
    /// Whether this permission allows a request that changes something.
    pub fn may_write(self) -> bool {
        matches!(self, Permission::ReadWrite)
    }

    /// The name it is written as, for messages and for `show`.
    pub fn as_str(self) -> &'static str {
        match self {
            Permission::ReadOnly => "read-only",
            Permission::ReadWrite => "read-write",
        }
    }
}

/// Source-address validation (uRPF, RFC 3704) for a zone's interfaces.
///
/// The question it answers is "could this sender's address really be over
/// there?", asked of the routing table: the box looks up a route back to the
/// packet's source and compares it against the interface the packet came in on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceValidation {
    /// Accept any source address. The default — this drops traffic, and *which*
    /// traffic depends on the routing table, so it is never switched on for you.
    #[default]
    Disable,
    /// The source must be routable somewhere. Catches addresses that could never
    /// answer, and survives asymmetric routing.
    Loose,
    /// The route back to the source must leave by the interface it arrived on.
    /// This is BCP 38 — the rule that stops a WAN neighbour from claiming a LAN
    /// address, and stops your own network from being a spoofing source. It also
    /// drops legitimate traffic wherever routing is asymmetric (two uplinks, a
    /// VPN that returns by another path), which is what `loose` is for.
    Strict,
}

impl SourceValidation {
    /// The word this mode is written as, in TOML and in `show`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disable => "disable",
            Self::Loose => "loose",
            Self::Strict => "strict",
        }
    }
}

/// Global firewall settings, applied to every firewalled (zoned) interface.
/// These map onto Velstra's per-policy `stateful` / `drop_icmp` / `blocklist`
/// — capabilities the data plane already enforces.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Firewall {
    /// Stateful inspection: track allowed flows so return traffic comes back
    /// without an explicit rule. On by default (a real firewall default).
    #[serde(default = "default_true")]
    pub stateful: bool,
    /// Drop inbound ICMP at firewalled interfaces (echo, etc.). Off by default
    /// — ICMP is useful (PMTU, ping); turn on to go quiet.
    #[serde(default)]
    pub block_icmp: bool,
    /// Source IPs/CIDRs dropped outright on every firewalled interface — a
    /// global denylist evaluated before any zone posture.
    #[serde(default)]
    pub blocklist: Vec<String>,
    /// The default ingress action a zone inherits when it neither sets its own
    /// `default_action` nor is opened by a broad accept rule. `drop` by default.
    #[serde(default = "default_drop")]
    pub default_action: Action,
    /// Log matched traffic by default (zones inherit this). Off by default.
    #[serde(default)]
    pub log: bool,
    /// Drop a packet the data plane cannot parse, instead of passing it. Off by
    /// default — a firewall should not black-hole traffic because of its own
    /// parsing limits. Turn it on for a strict deny-by-default posture, where a
    /// packet the filter cannot understand is exactly the one it must not admit.
    /// Applies to the whole box, not per zone: the parse fails before any zone is
    /// known.
    #[serde(default)]
    pub fail_closed: bool,
    /// ISO country codes whose addresses are dropped on every firewalled
    /// interface — the global list every zone inherits (roadmap C15 GeoIP).
    ///
    /// This blocks **sources**: it stops those countries reaching you, not you
    /// reaching them. The addresses come from the image's own database, so it
    /// works on an isolated network and changes only when the image does.
    #[serde(default, rename = "geoip-block", skip_serializing_if = "Vec::is_empty")]
    pub geoip_block: Vec<String>,
    /// Source-address validation (uRPF) every zone inherits. `disable` by
    /// default; set it per zone to validate only where it belongs.
    #[serde(
        rename = "source-validation",
        default,
        skip_serializing_if = "SourceValidation::is_disabled"
    )]
    pub source_validation: SourceValidation,
    /// Named address/port groups (aliases) that rules reference by name.
    #[serde(default, skip_serializing_if = "Groups::is_empty")]
    pub group: Groups,
    /// TCP ports a SYN proxy stands in front of (roadmap C15).
    ///
    /// The firewall answers every SYN to these ports itself, with a cookie, and
    /// only opens the real connection once a client returns it — so a SYN flood
    /// costs one reply packet and no state instead of a half-open connection on
    /// the server. Proxied connections trade window scaling, SACK and
    /// timestamps for that; see the handbook.
    #[serde(default, rename = "syn-protect", skip_serializing_if = "Vec::is_empty")]
    pub syn_protect: Vec<SynProtect>,
}

/// A TCP port protected by the SYN proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SynProtect {
    /// The TCP port to protect.
    pub port: u16,
    /// MSS the synthesised SYN-ACK advertises. Omitted means the untunnelled
    /// Ethernet maximum; lower it where the path is smaller (a tunnel, PPPoE).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mss: Option<u16>,
}

impl SourceValidation {
    /// Serde skip predicate — the default needs no line in a saved config.
    fn is_disabled(&self) -> bool {
        *self == SourceValidation::Disable
    }
}

fn default_true() -> bool {
    true
}

fn default_drop() -> Action {
    Action::Drop
}

impl Default for Firewall {
    fn default() -> Self {
        Firewall {
            stateful: true,
            block_icmp: false,
            blocklist: Vec::new(),
            default_action: Action::Drop,
            log: false,
            fail_closed: false,
            source_validation: SourceValidation::Disable,
            geoip_block: Vec::new(),
            group: Groups::default(),
            syn_protect: Vec::new(),
        }
    }
}

impl Firewall {
    /// True when this is exactly the default posture — used to omit `[firewall]`
    /// from saved configs that never touched it.
    pub fn is_default(&self) -> bool {
        self.stateful
            && !self.block_icmp
            && self.blocklist.is_empty()
            && self.default_action == Action::Drop
            && !self.log
            && !self.fail_closed
            && self.source_validation == SourceValidation::Disable
            && self.geoip_block.is_empty()
            && self.group.is_empty()
    }
}

/// Named firewall groups (aliases): reusable sets of addresses and ports that
/// rules reference by name instead of repeating literals — the VyOS/pfSense
/// "group"/"alias" ergonomic. A rule referencing a group expands at compile time
/// to one data-plane rule per member (addresses stay as CIDRs — a `/24` is one
/// LPM entry, not 256 hosts), so groups cost nothing extra in the data plane.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Groups {
    /// Address groups: name → hosts/CIDRs. Referenced by a rule's `source_group`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub address: BTreeMap<String, Vec<String>>,
    /// Port groups: name → ports/ranges. Referenced by a rule's `port_group`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub port: BTreeMap<String, Vec<PortSpec>>,
    /// Domain groups: name → DNS names, resolved to addresses at apply time and
    /// refreshed on a timer. Referenced by a rule's `source_group` /
    /// `destination_group` exactly like an address group — the apply path folds
    /// the resolved addresses into [`Groups::address`] before the compiler runs,
    /// so a rule never has to know which kind of group it names.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub domain: BTreeMap<String, Vec<String>>,
    /// Feed groups: name → HTTPS URLs of published address lists, fetched and
    /// folded into [`Groups::address`] at apply time exactly like a domain
    /// group. The lists worth having — bogons, exit nodes, a provider's own
    /// prefixes — are maintained elsewhere, and one copied in by hand is wrong
    /// within a week without anybody noticing.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub feed: BTreeMap<String, Vec<String>>,
}

impl Groups {
    /// No groups defined (lets `[firewall]` be omitted when untouched).
    pub fn is_empty(&self) -> bool {
        self.address.is_empty()
            && self.port.is_empty()
            && self.domain.is_empty()
            && self.feed.is_empty()
    }

    /// Whether `name` is a declared address, domain **or** feed group — all
    /// three share a namespace, since a rule references any of them through the
    /// same field and the apply path folds the latter two into the first.
    pub fn has_address_like(&self, name: &str) -> bool {
        self.address.contains_key(name)
            || self.domain.contains_key(name)
            || self.feed.contains_key(name)
    }
}

/// The widest expansion (sources × ports) a single grouped rule may produce —
/// keeps a rule that crosses a big address group with a big port group from
/// flooding the data-plane rule map. Addresses stay as CIDRs, so this is
/// members-times-ports, not hosts-times-ports.
pub const MAX_RULE_EXPANSION: usize = 4096;

/// A named network zone — the trust boundary a firewall reasons about. Zones are
/// arbitrary (`wan`, `lan`, `dmz`, `guest`, `iot`, …); each becomes one Velstra
/// policy. Per-zone posture fields are optional and inherit the global
/// [`Firewall`] defaults when unset, so you can (for example) block ICMP on
/// `wan` but allow it on `lan`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneCfg {
    /// A free-text label for this zone, shown in `show`. Purely documentary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// This zone *is* the appliance: traffic that terminates on the box rather
    /// than passing through it.
    ///
    /// Every other zone is a set of links. This one is a set of addresses — the
    /// ones this box holds — so `to <local zone>` compiles to a destination
    /// match on them. Without it, "what may reach the firewall itself" has no
    /// expression: it is not a link, so it could not be named, and the rules
    /// that govern management access had to be written as zone-wide posture.
    ///
    /// A local zone carries no interface, and validation says so rather than
    /// asking for one.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub local: bool,
    /// Stateful inspection for this zone (inherits `[firewall] stateful`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stateful: Option<bool>,
    /// Drop inbound ICMP on this zone (inherits `[firewall] block_icmp`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_icmp: Option<bool>,
    /// Source IPs/CIDRs dropped on this zone's interfaces (added to the global
    /// blocklist).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocklist: Vec<String>,
    /// Ingress default action for this zone (inherits `[firewall]
    /// default_action`, else `drop`). An explicit value overrides the
    /// rule-derived posture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_action: Option<Action>,
    /// Log matched traffic for this zone (inherits `[firewall] log`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<bool>,
    /// Countries dropped on this zone, **added to** the global `geoip-block`
    /// rather than replacing it: a country blocked everywhere should not quietly
    /// become reachable because one zone named a different one.
    #[serde(default, rename = "geoip-block", skip_serializing_if = "Vec::is_empty")]
    pub geoip_block: Vec<String>,
    /// Source-address validation for this zone (inherits `[firewall]
    /// source-validation`).
    #[serde(
        rename = "source-validation",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub source_validation: Option<SourceValidation>,
}

/// A zone's posture after inheriting the global `[firewall]` defaults — the
/// concrete values the compiler emits onto the zone's Velstra policy.
#[derive(Debug, Clone)]
pub struct ResolvedZone {
    pub stateful: bool,
    pub block_icmp: bool,
    pub blocklist: Vec<String>,
    /// An explicit per-zone default-action override; `None` ⇒ the compiler uses
    /// the rule-derived posture (broad accept ⇒ pass) or the firewall default.
    pub default_action: Option<Action>,
    pub log: bool,
    pub source_validation: SourceValidation,
    /// The countries this zone drops: the global list plus the zone's own.
    pub geoip_block: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    /// A free-text label shown in `show` and rendered as a comment header on the
    /// generated networkd `.network` unit. Purely documentary — never affects the
    /// data plane. `None` for an undocumented interface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Administratively disable this interface: networkd keeps the link down
    /// (`[Link] ActivationPolicy=down`) and the compiler drops it from the Velstra
    /// data plane (no policy binding, so no XDP attach). Off by default.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
    /// The zone this interface belongs to (a key in `[zone.*]` / referenced by
    /// rules). `None` for a NIC the system provides but the operator hasn't
    /// assigned yet (it shows up in the config but is not firewalled until a zone
    /// is set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// `"dhcp"` or a CIDR like `"10.0.0.1/24"`. `None` if not yet configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The interface's IPv6 address — a static CIDR (`"2001:db8:1::1/64"`),
    /// `"auto"` (accept Router Advertisements / SLAAC), or `"dhcp"` (DHCPv6
    /// client — the typical WAN uplink, which can also request a delegated
    /// prefix). Independent of `address`, so an interface can be dual-stack.
    /// `None` for a v4-only interface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address6: Option<String>,
    /// Request a delegated IPv6 prefix (DHCPv6-PD) from the uplink interface
    /// named here — the German-ISP WAN model: the WAN (`address6 = "dhcp"`) gets
    /// a prefix from the ISP, and each `pd-from` interface carves a /64 out of it
    /// and advertises it to its LAN. `None` for an interface that is not a PD
    /// downstream.
    #[serde(default, rename = "pd-from", skip_serializing_if = "Option::is_none")]
    pub pd_from: Option<String>,
    /// The subnet id (0-255) this downstream takes within the delegated prefix —
    /// which /64 of the ISP's block it uses. Defaults to `0`. Set together with
    /// `pd-from`.
    #[serde(default, rename = "pd-subnet", skip_serializing_if = "Option::is_none")]
    pub pd_subnet: Option<u8>,
    /// For an 802.1Q VLAN subinterface: the parent interface it rides on. Set
    /// together with `vlan`. `None` for a physical NIC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// VLAN id (1–4094) for a subinterface. Set together with `parent`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u16>,
    /// The VLAN tag protocol for a subinterface (roadmap C14 QinQ): `802.1q`
    /// (the default C-VLAN) or `802.1ad` (an S-VLAN / service tag). Stacking a
    /// `802.1q` VLAN whose `parent` is an `802.1ad` VLAN gives 802.1ad QinQ
    /// (S-tag outer, C-tag inner). Only valid on a VLAN subinterface.
    #[serde(
        default,
        rename = "vlan-protocol",
        skip_serializing_if = "Option::is_none"
    )]
    pub vlan_protocol: Option<String>,
    /// The MACVLAN mode for a `type = "macvlan"` interface (roadmap C14):
    /// `bridge` (default — the sub-interfaces can talk to each other),
    /// `private`, `vepa`, or `passthru`. Only valid on a macvlan interface.
    #[serde(
        default,
        rename = "macvlan-mode",
        skip_serializing_if = "Option::is_none"
    )]
    pub macvlan_mode: Option<String>,
    /// The pre-shared key (hex, 32 chars = 128-bit or 64 chars = 256-bit) for a
    /// `type = "macsec"` interface (roadmap C14, MACsec / 802.1AE L2 encryption).
    /// Both ends of the link share this key. A secret — rendered into the 0600
    /// `.netdev`. Only valid on a macsec interface.
    #[serde(
        default,
        rename = "macsec-key",
        skip_serializing_if = "Option::is_none"
    )]
    pub macsec_key: Option<String>,
    /// The peer's MAC address on the parent link for a `type = "macsec"` interface
    /// — names the receive secure channel (the peer's SCI). Only valid on a macsec
    /// interface.
    #[serde(
        default,
        rename = "macsec-peer",
        skip_serializing_if = "Option::is_none"
    )]
    pub macsec_peer: Option<String>,
    /// When set, networkd runs a built-in DHCP server on this interface, handing
    /// out leases from the interface's own static subnet. Requires a static
    /// `address` (the server needs a subnet to allocate from).
    #[serde(
        default,
        rename = "dhcp-server",
        skip_serializing_if = "Option::is_none"
    )]
    pub dhcp_server: Option<DhcpServer>,
    /// When set, networkd emits IPv6 Router Advertisements on this interface —
    /// the IPv6 counterpart of the DHCP server. LAN hosts autoconfigure (SLAAC)
    /// an address from each advertised prefix and learn this box as their default
    /// router (and, optionally, DNS). Needs no IPv4 address; the router binds an
    /// address from each advertised prefix itself.
    #[serde(
        default,
        rename = "router-advert",
        skip_serializing_if = "Option::is_none"
    )]
    pub router_advert: Option<RouterAdvert>,
    /// For a **virtual L2 device** — a `bridge` or a `bond` this box creates
    /// (rather than a physical NIC). The device is a networkd `.netdev`
    /// (`Kind=bridge`/`bond`); the member NICs are listed on the device in
    /// `members`. A bridge switches its members; a bond aggregates them (mode via
    /// `bond-mode`). Set on the *device* interface, not its members.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub if_type: Option<IfaceType>,
    /// The member NICs enslaved to this `bridge`/`bond` device — each gets
    /// `Bridge=`/`Bond=` in its own `.network`, derived from this list. Only valid
    /// on a `type = "bridge"`/`"bond"` device; every member must be a declared or
    /// discovered interface, may belong to at most one bond/bridge, and must not
    /// itself be a bond/bridge/VLAN. Empty on a non-device interface.
    #[serde(default, rename = "member", skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,
    /// Bonding mode for a `type = "bond"` device (`"active-backup"`,
    /// `"802.3ad"`, `"balance-rr"`, …). Only meaningful on a bond device;
    /// defaults to `active-backup` when unset.
    #[serde(default, rename = "bond-mode", skip_serializing_if = "Option::is_none")]
    pub bond_mode: Option<String>,
    /// Enable 802.1Q VLAN filtering on a `type = "bridge"` device (networkd
    /// `[Bridge] VLANFiltering=yes`). Only valid on a bridge. When on, each member
    /// port carries its own tagged/untagged VLAN membership (`vlan-tagged` /
    /// `vlan-untagged`). Unset ⇒ a plain, VLAN-unaware bridge.
    #[serde(
        default,
        rename = "vlan-aware",
        skip_serializing_if = "Option::is_none"
    )]
    pub vlan_aware: Option<bool>,
    /// The 802.1Q VLAN ids this port carries **tagged** (one `[BridgeVLAN] VLAN=`
    /// each). Only valid on a member port of a `vlan-aware` bridge. Empty ⇒ the
    /// port carries no tagged VLANs.
    #[serde(default, rename = "vlan-tagged", skip_serializing_if = "Vec::is_empty")]
    pub vlan_tagged: Vec<u16>,
    /// The single **untagged** (PVID + egress-untagged) VLAN id for this port
    /// (`[BridgeVLAN] PVID=`/`EgressUntagged=`). Only valid on a member port of a
    /// `vlan-aware` bridge. `None` ⇒ the port has no untagged VLAN.
    #[serde(
        default,
        rename = "vlan-untagged",
        skip_serializing_if = "Option::is_none"
    )]
    pub vlan_untagged: Option<u16>,
    /// Link MTU in bytes (e.g. `1492` for PPPoE, `9000` for jumbo frames).
    /// `None` leaves the kernel/driver default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    /// Clamp the TCP MSS of segments crossing this link, in bytes, or the string
    /// `"pmtu"` to clamp to whatever the path MTU turns out to be.
    ///
    /// A tunnel is where this bites. The two ends agree an MSS from *their* MTUs
    /// during the handshake, and neither of them knows about the encapsulation
    /// in between — so the session establishes, small requests work, and the
    /// first large response disappears. It looks like an application fault for
    /// as long as it takes somebody to think of MTU. PPPoE is clamped
    /// automatically because its MTU is not negotiable; a WireGuard or GRE link
    /// has to be told.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mss: Option<String>,
    /// Override the link's MAC address (`"52:54:00:12:34:56"`) — MAC cloning, as
    /// some ISPs bind service to the CPE's original MAC. `None` keeps the NIC's
    /// hardware address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// Pin this interface's *name* to a NIC by its MAC (`hw-id`).
    ///
    /// Names are assigned in whatever order the kernel probes the devices, so
    /// `eth2` need not be the same card after a reboot, a firmware update or a
    /// card being swapped. On a firewall that is not cosmetic: a zone follows a
    /// name, so a name that moves takes the policy with it.
    #[serde(default, rename = "hw-id", skip_serializing_if = "Option::is_none")]
    pub hw_id: Option<String>,
    /// Per-NIC offload features (`[interface.offload] gro = true`).
    ///
    /// Both directions are real: turning offload on is throughput, turning it
    /// off is the first thing anyone tries when a NIC reorders or corrupts under
    /// load. Applied with `ethtool -K`, which is where the whole set lives —
    /// `systemd.link` covers only some of these switches.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub offload: BTreeMap<String, bool>,
    /// For a **kernel tunnel** (`type = "gre"|"ipip"|"gretap"`, roadmap C3): the
    /// local endpoint address — the underlay source the tunnel packets leave from
    /// (an address configured on this box). Required on a tunnel; `None` on any
    /// other interface. Must be the same family as `remote`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local: Option<String>,
    /// For a kernel tunnel: the remote endpoint address — the far end's underlay
    /// address the tunnel packets are sent to. Required on a tunnel; `None`
    /// otherwise. Must be the same family as `local`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    /// Optional GRE key (`type = "gre"|"gretap"`) — a 32-bit tag that demultiplexes
    /// several tunnels sharing the same `local`/`remote` pair; both ends must
    /// agree. Not valid on an `ipip` tunnel (IPIP carries no key). `None` for an
    /// unkeyed tunnel.
    #[serde(default, rename = "key", skip_serializing_if = "Option::is_none")]
    pub tunnel_key: Option<u32>,
    /// Outer TTL for a kernel tunnel's encapsulating packets (`1`–`255`); `0`
    /// inherits the inner packet's TTL. `None` leaves the kernel default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u8>,
    /// Egress traffic shaping / queue management on this interface (roadmap C8) —
    /// a `cake` shaper+AQM (the bufferbloat killer for a WAN uplink) or a
    /// `fq_codel` AQM. `None` leaves the kernel default qdisc. Declared as a
    /// sub-table before `pppoe` so it serialises after every scalar interface key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qos: Option<Qos>,
    /// PPPoE client parameters for a `type = "pppoe"` interface — the German
    /// VDSL/fibre WAN model. The session rides over the raw uplink NIC named in
    /// `parent`; `pppoe.username`/`pppoe.password` are the ISP login (the
    /// password is a secret, rendered to a 0600 `chap-secrets`/`pap-secrets`).
    /// `None` for any non-PPPoE interface. Declared last so its TOML sub-table
    /// serialises after every scalar interface key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pppoe: Option<Pppoe>,
}

/// The `type` of a synthesised or client interface. `bridge`/`bond` are
/// **virtual L2 devices** Sentinel creates to enslave members; `wireguard` is a
/// WireGuard tunnel device whose keys + peers are configured under `[[vpn.wireguard]]`;
/// `pppoe` is a PPPoE **client** session brought up over a raw uplink NIC (`parent`);
/// `gre`/`ipip`/`gretap` are **kernel point-to-point tunnels** (roadmap C3) built
/// between two endpoint addresses (`local`/`remote`). Physical NICs and 802.1Q
/// VLAN subinterfaces carry no `type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IfaceType {
    Bridge,
    Bond,
    /// A dummy device (`Kind=dummy`): a link that is always up, carrying an
    /// address that does not depend on any cable. What a router-id, a VRRP
    /// address that must not follow a port, or a service bound to "this box"
    /// wants — a loopback of one's own, addressable from the network.
    Dummy,
    /// A WireGuard tunnel device (`Kind=wireguard`). The private key, listen port
    /// and peers live in the matching [`WireguardTunnel`] under `[[vpn.wireguard]]`.
    Wireguard,
    Pppoe,
    /// A GRE (Generic Routing Encapsulation) L3 tunnel — carries IP, supports an
    /// optional 32-bit `key` to demultiplex several tunnels between the same pair.
    Gre,
    /// An IPIP (IPv4-in-IPv4) L3 tunnel — the simplest encapsulation; no `key`.
    Ipip,
    /// A GRETAP L2 tunnel — GRE carrying Ethernet frames (a virtual bridge port
    /// over GRE); like `gre` but the link is a broadcast-capable L2 device.
    Gretap,
    /// A MACVLAN pseudo-interface (roadmap C14): a virtual NIC with its own MAC
    /// on top of a `parent` physical NIC (`Kind=macvlan` + `[MACVLAN] Mode=`).
    /// Lets one link carry several L2 identities (containers/VMs, a management
    /// address separate from the host, …).
    Macvlan,
    /// A MACsec (802.1AE) device (roadmap C14): a `Kind=macsec` link on a `parent`
    /// NIC that encrypts + authenticates every frame with a pre-shared key. Point
    /// to point; the peer is named by its MAC (`macsec-peer`).
    Macsec,
    /// An L2TPv3 (RFC 3931) static Ethernet pseudowire (roadmap C14): a point-to-
    /// point L2 tunnel between two endpoint IPs (`local`/`remote`) carrying
    /// Ethernet frames over IP. Created imperatively via `ip l2tp` (not networkd);
    /// `key` is the tunnel/session id shared by both ends.
    L2tpv3,
}

/// PPPoE client parameters (a `type = "pppoe"` interface). The session is
/// established by `pppd` over the raw uplink NIC (`parent`) with the `rp-pppoe`
/// plugin; the box's WAN address, default route and DNS come from the peer
/// (IPCP). Credentials are the ISP login — the `password` is a secret rendered
/// to a 0600 `chap-secrets`/`pap-secrets`, never world-readable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pppoe {
    /// The PPPoE/PAP/CHAP username (the ISP login, e.g. a German Telekom
    /// `anschlusskennung...@t-online.de`). Required.
    pub username: String,
    /// The PPPoE password. Secret — rendered to a 0600 secrets file, never into
    /// the world-readable peer options. Required.
    pub password: String,
    /// Optional PPPoE service name (`rp_pppoe_service`); most ISPs need none.
    #[serde(
        default,
        rename = "service-name",
        skip_serializing_if = "Option::is_none"
    )]
    pub service_name: Option<String>,
    /// Optional PPPoE access-concentrator name (`rp_pppoe_ac`) to pin the
    /// session to a specific AC; most ISPs need none.
    #[serde(default, rename = "ac-name", skip_serializing_if = "Option::is_none")]
    pub ac_name: Option<String>,
    /// PPP MRU in bytes. Defaults to the interface `mtu` (or 1492 — the classic
    /// PPPoE-over-1500 value, 8 bytes of PPPoE overhead) when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mru: Option<u16>,
}

/// The Linux bonding modes networkd accepts (`[Bond] Mode=`).
pub const BOND_MODES: &[&str] = &[
    "balance-rr",
    "active-backup",
    "balance-xor",
    "broadcast",
    "802.3ad",
    "balance-tlb",
    "balance-alb",
];

/// The kernel's fallback tunnel devices — each tunnel module auto-creates one of
/// these when it loads (`ip_gre` → `gre0`/`gretap0`, `ipip` → `tunl0`, …). Naming
/// a configured tunnel after a fallback collides with it (networkd reports
/// "Failed to create netdev: File exists"), leaving the unconfigured catch-all in
/// place — which has no `remote`, so it silently black-holes traffic. Reject these
/// names on a tunnel interface and point the operator at a distinct name.
pub const RESERVED_TUNNEL_DEVICES: &[&str] = &[
    "gre0",
    "gretap0",
    "tunl0",
    "erspan0",
    "sit0",
    "ip6tnl0",
    "ip6gre0",
    "ip6gretap0",
];

/// A built-in (systemd-networkd) IPv6 Router Advertiser on an interface — the
/// IPv6 SLAAC counterpart of [`DhcpServer`]. The presence of the block turns RA
/// on; every field refines networkd's defaults. Advertising a prefix lets hosts
/// on the link autoconfigure a global address without any DHCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterAdvert {
    /// IPv6 prefixes advertised for SLAAC — each should be a `/64` (the width
    /// stateless autoconfiguration requires). Hosts on the link form an address
    /// in each; the router also binds one from each prefix to this interface
    /// (`Assign=yes`), so no separate IPv6 address is needed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prefixes: Vec<String>,
    /// IPv6 DNS servers advertised to clients in the RA (RDNSS). Emitted only
    /// when non-empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<String>,
    /// Set the "Managed address configuration" (M) flag: clients should obtain
    /// their address via DHCPv6 rather than SLAAC. Off by default (pure SLAAC).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub managed: bool,
    /// Set the "Other configuration" (O) flag: clients get other settings (DNS,
    /// NTP …) via DHCPv6 while still forming their address by SLAAC. Off by
    /// default.
    #[serde(
        default,
        rename = "other-config",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub other_config: bool,
    /// Router lifetime, in seconds. `0` advertises this box as *not* a default
    /// router (prefix/DNS only — useful for a pure address/DNS advertiser).
    /// Unset ⇒ networkd's default (a sane nonzero lifetime).
    #[serde(
        default,
        rename = "router-lifetime",
        skip_serializing_if = "Option::is_none"
    )]
    pub router_lifetime: Option<u32>,
    /// Stateful DHCPv6 address pool (roadmap C7). When set, this box hands out
    /// addresses from `[start, end]` over DHCPv6 — a dnsmasq server bound to the
    /// interface, since networkd's DHCP server is IPv4-only. The RA's Managed (M)
    /// flag is forced on so clients obtain their address via DHCPv6 rather than
    /// SLAAC. `None` ⇒ pure SLAAC (prefixes are advertised, no address server).
    #[serde(
        default,
        rename = "dhcp6-pool",
        skip_serializing_if = "Option::is_none"
    )]
    pub dhcp6_pool: Option<Dhcp6Pool>,
}

/// A stateful DHCPv6 address pool on a [`RouterAdvert`] (roadmap C7): the box
/// leases IPv6 addresses in `[start, end]` to clients over DHCPv6 via a dnsmasq
/// server bound to the interface. Both endpoints must be in the same /64 as an
/// advertised prefix; the RA's M flag (forced on) is what makes clients ask.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dhcp6Pool {
    /// First address of the pool, e.g. `"2001:db8:1::100"`.
    pub start: String,
    /// Last address of the pool, e.g. `"2001:db8:1::1ff"`.
    pub end: String,
    /// Lease time in seconds. The CLI accepts a human duration (`12h`, `1h30m`,
    /// or a bare number of seconds) and stores the resolved seconds here; rendered
    /// as the dnsmasq `dhcp-range` lease field. Unset ⇒ dnsmasq's default.
    #[serde(
        default,
        rename = "lease-time",
        skip_serializing_if = "Option::is_none"
    )]
    pub lease_time: Option<u32>,
}

/// A built-in (systemd-networkd) DHCP server on an interface that carries a
/// static address. All fields are optional refinements of networkd's defaults;
/// the presence of the block is what turns the server on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpServer {
    /// Offset of the first pool address within the interface's subnet.
    #[serde(
        default,
        rename = "pool-offset",
        skip_serializing_if = "Option::is_none"
    )]
    pub pool_offset: Option<u32>,
    /// Number of addresses in the pool.
    #[serde(default, rename = "pool-size", skip_serializing_if = "Option::is_none")]
    pub pool_size: Option<u32>,
    /// DNS servers advertised to clients (emitted only when non-empty).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<String>,
    /// Default lease time, in seconds. The CLI accepts a human duration
    /// (`12h`, `1h30m`, or a bare number of seconds) and stores the resolved
    /// seconds here; rendered as networkd `DefaultLeaseTimeSec=`.
    #[serde(
        default,
        rename = "lease-time",
        skip_serializing_if = "Option::is_none"
    )]
    pub lease_time: Option<u32>,
    /// The default-router (gateway) address handed to clients (DHCP option 3),
    /// rendered as networkd `[DHCPServer] Router=`. Unset ⇒ networkd advertises
    /// the server's own address (the usual case).
    #[serde(
        default,
        rename = "default-router",
        skip_serializing_if = "Option::is_none"
    )]
    pub default_router: Option<String>,
    /// The domain name handed to clients (DHCP option 15), rendered as a networkd
    /// `[DHCPServer] SendOption=15:string:<domain>`. `None` sends no domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Static host reservations: a fixed address bound to a client MAC. Each
    /// becomes a networkd `[DHCPServerStaticLease]` section. The `name` is a CLI
    /// handle only (networkd keys on MAC + address).
    #[serde(
        default,
        rename = "static-mapping",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub static_mappings: Vec<DhcpStaticLease>,
}

/// A static DHCP reservation on a [`DhcpServer`]: bind `ip` to the client whose
/// hardware address is `mac`. Rendered to a networkd `[DHCPServerStaticLease]`
/// (`MACAddress=` + `Address=`); the `name` is a documentary CLI handle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DhcpStaticLease {
    pub name: String,
    pub mac: String,
    pub ip: String,
}

/// A traffic-shaping / queue-management discipline attached to an interface's
/// egress (roadmap C8). `cake` is a combined shaper + AQM + fairness qdisc (the
/// right default for a WAN uplink — one `bandwidth` knob kills bufferbloat);
/// `fq_codel` is a pure flow-queuing AQM with no built-in shaper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QosDiscipline {
    Cake,
    FqCodel,
}

/// CAKE path-RTT keywords (`rtt <kw>`) — presets that tune CoDel's target for a
/// link class instead of an explicit time.
pub const CAKE_RTT_KEYWORDS: &[&str] = &[
    "datacentre",
    "lan",
    "metro",
    "regional",
    "internet",
    "oceanic",
    "satellite",
    "interplanetary",
];

/// CAKE diffserv/tin modes (`diffserv <mode>`) — how many priority tins CAKE
/// splits traffic into by DSCP.
pub const CAKE_DIFFSERV_MODES: &[&str] = &[
    "besteffort",
    "precedence",
    "diffserv3",
    "diffserv4",
    "diffserv8",
];

/// Per-interface QoS (roadmap C8). The presence of the block attaches a root
/// qdisc to the interface's egress; which fields are meaningful depends on
/// `discipline` (CAKE shapes + classifies; fq_codel only AQMs). Cross-discipline
/// fields are rejected at validation so a config never silently drops a knob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Qos {
    /// The queue discipline: `cake` (shaper + AQM, wants `bandwidth`) or
    /// `fq_codel` (AQM only — shape it with an outer qdisc or run at line rate).
    pub discipline: QosDiscipline,
    /// Shaping rate — a tc rate like `"100mbit"` / `"20gbit"` (or `"unlimited"`).
    /// **CAKE only** (CAKE's built-in shaper); set it a few % under the link's
    /// true rate so the queue lives here, not in the modem. fq_codel does not
    /// shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bandwidth: Option<String>,
    /// CAKE path-RTT hint — a time like `"100ms"` or a keyword
    /// (`internet`, `lan`, …). **CAKE only.**
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt: Option<String>,
    /// CAKE `nat`: look through NAT so per-host fairness keys on the inside (LAN)
    /// address. **CAKE only.**
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub nat: bool,
    /// CAKE `ack-filter`: thin redundant TCP ACKs on an asymmetric link (rescues
    /// the tiny upload of an ADSL/VDSL). **CAKE only.**
    #[serde(
        default,
        rename = "ack-filter",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub ack_filter: bool,
    /// CAKE diffserv/tin mode (`besteffort`/`diffserv3`/…). **CAKE only.**
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diffserv: Option<String>,
    /// fq_codel target delay — a time like `"5ms"`. **fq_codel only.**
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// fq_codel interval — a time like `"100ms"`. **fq_codel only.**
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,
    /// fq_codel backlog packet limit. **fq_codel only.**
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

impl Qos {
    /// True for a `cake` qdisc.
    pub fn is_cake(&self) -> bool {
        self.discipline == QosDiscipline::Cake
    }
}

/// A WireGuard peer: the far end of a tunnel, listed under a `[[vpn.wireguard]]`
/// entry (`[[vpn.wireguard.peer]]`). Keys are the standard base64 encoding of 32
/// raw bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgPeer {
    #[serde(rename = "public-key")]
    pub public_key: String,
    #[serde(default, rename = "allowed-ips", skip_serializing_if = "Vec::is_empty")]
    pub allowed_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(
        default,
        rename = "persistent-keepalive",
        skip_serializing_if = "Option::is_none"
    )]
    pub persistent_keepalive: Option<u16>,
    #[serde(
        default,
        rename = "preshared-key",
        skip_serializing_if = "Option::is_none"
    )]
    pub preshared_key: Option<String>,
}

impl Interface {
    /// A WireGuard interface is a `type = "wireguard"` device; its keys + peers
    /// live in the matching [`WireguardTunnel`] under `[[vpn.wireguard]]`.
    pub fn is_wireguard(&self) -> bool {
        self.if_type == Some(IfaceType::Wireguard)
    }
    /// True for a bond device (`type = "bond"`).
    pub fn is_bond(&self) -> bool {
        self.if_type == Some(IfaceType::Bond)
    }
    /// True for a bridge device (`type = "bridge"`).
    pub fn is_bridge(&self) -> bool {
        self.if_type == Some(IfaceType::Bridge)
    }
    /// True for a virtual L2 device (bridge or bond) this box synthesises. A
    /// `pppoe` client is NOT an L2 device (it has no netdev and enslaves no
    /// members), so it is excluded here.
    pub fn is_virtual_l2(&self) -> bool {
        matches!(
            self.if_type,
            Some(IfaceType::Bridge) | Some(IfaceType::Bond)
        )
    }
    /// True for a PPPoE client interface (`type = "pppoe"`).
    pub fn is_pppoe(&self) -> bool {
        self.if_type == Some(IfaceType::Pppoe)
    }
    /// True for a kernel point-to-point tunnel (`gre`/`ipip`/`gretap`, roadmap C3).
    pub fn is_tunnel(&self) -> bool {
        matches!(
            self.if_type,
            Some(IfaceType::Gre) | Some(IfaceType::Ipip) | Some(IfaceType::Gretap)
        )
    }
    /// True for a tunnel type that carries a GRE key (`gre`/`gretap`); IPIP does not.
    pub fn tunnel_supports_key(&self) -> bool {
        matches!(self.if_type, Some(IfaceType::Gre) | Some(IfaceType::Gretap))
    }
    /// True for a MACVLAN pseudo-interface (`type = "macvlan"`, roadmap C14).
    pub fn is_macvlan(&self) -> bool {
        self.if_type == Some(IfaceType::Macvlan)
    }
    /// True for a MACsec (802.1AE) device (`type = "macsec"`, roadmap C14).
    pub fn is_macsec(&self) -> bool {
        self.if_type == Some(IfaceType::Macsec)
    }
    /// True for an L2TPv3 pseudowire (`type = "l2tpv3"`, roadmap C14).
    pub fn is_l2tpv3(&self) -> bool {
        self.if_type == Some(IfaceType::L2tpv3)
    }
    /// True for a VLAN subinterface (has both `parent` and `vlan`).
    pub fn is_vlan(&self) -> bool {
        self.parent.is_some() && self.vlan.is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Accept,
    Drop,
    Reject,
}

/// L4 protocol for a port rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
    /// ICMP for IPv4. Carries no port, so a rule naming it matches on the
    /// protocol alone — "let these two zones ping each other" is a rule, not a
    /// zone-wide switch.
    Icmp,
    /// ICMPv6 (IANA 58). Its own protocol, not a flavour of ICMP, and the one
    /// that carries neighbour discovery: an IPv6 segment without it does not
    /// work at all.
    #[serde(rename = "icmpv6", alias = "ipv6-icmp", alias = "icmp6")]
    Icmpv6,
    /// VRRP (IANA 112) — what a redundant pair says to each other.
    Vrrp,
    /// ESP (IANA 50) — the payload half of IPsec.
    Esp,
    /// AH (IANA 51) — the authentication half of IPsec.
    Ah,
    /// GRE (IANA 47).
    Gre,
    /// Both TCP and UDP, as one rule. VyOS spells it `tcp_udp` and it earns its
    /// place: a service reached over either — DNS, NTP, a Samba share — is one
    /// decision to an operator, and writing it twice means two rules to keep in
    /// step afterwards. The data plane has no such protocol, so the compiler
    /// emits the pair.
    #[serde(rename = "tcp_udp", alias = "tcp-udp")]
    TcpUdp,
}

impl Proto {
    /// Whether this protocol has ports. Everything else is matched on the
    /// protocol alone; the data plane keys such a rule with port `0`, which is
    /// also what it reads off a packet that has no ports.
    pub fn has_ports(self) -> bool {
        matches!(self, Proto::Tcp | Proto::Udp | Proto::TcpUdp)
    }

    /// What the data plane has to be programmed with. Everything is itself
    /// except `tcp_udp`, which is a convenience of the grammar and becomes the
    /// two rules it stands for.
    pub fn concrete(self) -> &'static [Proto] {
        match self {
            Proto::TcpUdp => &[Proto::Tcp, Proto::Udp],
            Proto::Tcp => &[Proto::Tcp],
            Proto::Udp => &[Proto::Udp],
            Proto::Icmp => &[Proto::Icmp],
            Proto::Icmpv6 => &[Proto::Icmpv6],
            Proto::Vrrp => &[Proto::Vrrp],
            Proto::Esp => &[Proto::Esp],
            Proto::Ah => &[Proto::Ah],
            Proto::Gre => &[Proto::Gre],
        }
    }
}

/// The widest port range a single rule may span (inclusive count). A range is
/// expanded into one data-plane port rule per port at compile time, so this cap
/// keeps a stray `1-65535` from blowing up the map.
pub const MAX_PORT_RANGE: u32 = 1024;

/// A rule's destination-port match: a single port (`443`) or an inclusive range
/// (`"8000-8100"`). In TOML a single port stays a bare integer (`port = 443`) and
/// a range is a string (`port = "8000-8100"`), so existing single-port configs
/// are unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortSpec {
    /// A single destination port.
    Single(u16),
    /// An inclusive `lo..=hi` range.
    Range(u16, u16),
}

impl PortSpec {
    /// Parse the CLI/text form: `"443"` or `"8000-8100"`.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if let Some((lo, hi)) = s.split_once('-') {
            let lo: u16 = lo
                .trim()
                .parse()
                .with_context(|| format!("invalid port {lo:?}"))?;
            let hi: u16 = hi
                .trim()
                .parse()
                .with_context(|| format!("invalid port {hi:?}"))?;
            Ok(PortSpec::Range(lo, hi))
        } else {
            let p: u16 = s.parse().with_context(|| format!("invalid port {s:?}"))?;
            Ok(PortSpec::Single(p))
        }
    }

    /// Inclusive `(lo, hi)` bounds.
    pub fn bounds(self) -> (u16, u16) {
        match self {
            PortSpec::Single(p) => (p, p),
            PortSpec::Range(lo, hi) => (lo, hi),
        }
    }

    /// The ports this spec matches, expanded.
    pub fn ports(self) -> std::ops::RangeInclusive<u16> {
        let (lo, hi) = self.bounds();
        lo..=hi
    }

    /// Reject a port 0, an inverted range, or a range wider than [`MAX_PORT_RANGE`].
    pub fn validate(self) -> Result<()> {
        let (lo, hi) = self.bounds();
        if lo == 0 {
            bail!("port 0 is not valid");
        }
        if lo > hi {
            bail!("port range {lo}-{hi} is inverted (start > end)");
        }
        let count = hi as u32 - lo as u32 + 1;
        if count > MAX_PORT_RANGE {
            bail!("port range {lo}-{hi} spans {count} ports, over the {MAX_PORT_RANGE} cap");
        }
        Ok(())
    }
}

/// Serde for a rule's port list, so every shape an operator has already written
/// keeps working: `port = 443` (integer), `port = "8000-8100"` (string),
/// `port = "139,445"` (a list), `port = [80, 443]` (an array).
///
/// It serialises back the way it came in as far as that is possible — one plain
/// port stays an integer — because a config that rewrites itself on every save
/// makes every diff a lie about what changed.
mod port_list {
    use super::PortSpec;
    use serde::Deserialize;
    use serde::de::{Deserializer, Error as _};
    use serde::ser::{SerializeSeq, Serializer};

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Wire {
        One(u16),
        Text(String),
        Many(Vec<PortSpec>),
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<PortSpec>, D::Error> {
        Ok(match Wire::deserialize(d)? {
            Wire::One(p) => vec![PortSpec::Single(p)],
            Wire::Text(t) => {
                let mut out = Vec::new();
                for one in t.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    out.push(PortSpec::parse(one).map_err(D::Error::custom)?);
                }
                out
            }
            Wire::Many(v) => v,
        })
    }

    pub fn serialize<S: Serializer>(v: &[PortSpec], s: S) -> Result<S::Ok, S::Error> {
        match v {
            [PortSpec::Single(p)] => s.serialize_u16(*p),
            [one] => s.serialize_str(&one.to_string()),
            many => {
                let mut seq = s.serialize_seq(Some(many.len()))?;
                for one in many {
                    seq.serialize_element(one)?;
                }
                seq.end()
            }
        }
    }
}

impl std::fmt::Display for PortSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortSpec::Single(p) => write!(f, "{p}"),
            PortSpec::Range(lo, hi) => write!(f, "{lo}-{hi}"),
        }
    }
}

impl Serialize for PortSpec {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            // A single port round-trips as a bare TOML integer; a range as a string.
            PortSpec::Single(p) => s.serialize_u16(*p),
            PortSpec::Range(lo, hi) => s.serialize_str(&format!("{lo}-{hi}")),
        }
    }
}

impl<'de> Deserialize<'de> for PortSpec {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = PortSpec;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a port number or a \"lo-hi\" range string")
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<PortSpec, E> {
                u16::try_from(v)
                    .map(PortSpec::Single)
                    .map_err(|_| E::custom(format!("port {v} out of range (0–65535)")))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<PortSpec, E> {
                u16::try_from(v)
                    .map(PortSpec::Single)
                    .map_err(|_| E::custom(format!("port {v} out of range (0–65535)")))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<PortSpec, E> {
                PortSpec::parse(v).map_err(|e| E::custom(e.to_string()))
            }
        }
        d.deserialize_any(V)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    /// A free-text label for this rule, shown in `show`. Purely documentary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Administratively disable this rule: the compiler drops it from the Velstra
    /// data plane (no port rule / no effect on the zone's derived posture). Off by
    /// default. Lets an operator park a rule without deleting it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
    /// Source zone name (must be a zone backed by at least one interface).
    pub from: String,
    /// Destination zone name. Optional: without it the rule honestly matches
    /// traffic from `from` toward anywhere — which is exactly what the
    /// datapath enforces today. Setting it declares zone-pair intent and
    /// draws a commit warning until the datapath can match on egress zone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    pub action: Action,
    /// With `port`, makes this a **port rule** (a specific proto/port);
    /// without, it is a **broad** rule that sets the from-zone's posture.
    #[serde(default)]
    pub proto: Option<Proto>,
    /// The destination ports this rule matches: a single port (`port = 443`), an
    /// inclusive range (`port = "8000-8100"`), or several of either
    /// (`port = "139,445"`).
    ///
    /// A list is not sugar. Services that are one service to an operator are
    /// several ports to a firewall — SMB is 139 and 445, IPMI is a handful —
    /// and writing them as separate rules means separate rules to keep in step
    /// afterwards. A named `port-group` is the right answer once the same set
    /// appears twice; this is the answer the first time.
    #[serde(default, with = "port_list", skip_serializing_if = "Vec::is_empty")]
    pub port: Vec<PortSpec>,
    /// Log packets matching this (port) rule, independent of the zone's `log`.
    /// Off by default; only meaningful on a port rule.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub log: bool,
    /// Optional source-address constraint — an IPv4 CIDR (`"10.0.0.0/24"`) or a
    /// bare host (`"198.51.100.7"`). Absent means "from any source". Only
    /// meaningful on a port rule; a more specific source wins over `from any`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Reference an address group (`[firewall.group.address]`) as the source
    /// constraint instead of an inline `source` — mutually exclusive with it.
    #[serde(
        default,
        alias = "source-group",
        skip_serializing_if = "Option::is_none"
    )]
    pub source_group: Option<String>,
    /// Optional destination-address constraint — an IPv4 CIDR or a bare host, same
    /// forms as `source`. Absent means "to any destination", and a more specific
    /// constraint wins over a less specific one whichever end it names.
    ///
    /// Mutually exclusive with `source`/`source-group`: the data plane ranks each
    /// end in its own longest-prefix table and one rule cannot sit in both, so a
    /// rule naming both ends is refused rather than half-enforced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    /// Reference an address group as the destination constraint instead of an
    /// inline `destination` — mutually exclusive with it.
    #[serde(
        default,
        alias = "destination-group",
        skip_serializing_if = "Option::is_none"
    )]
    pub destination_group: Option<String>,
    /// Rate-limit the **new** flows this rule admits, in packets per second.
    /// Absent means unlimited. Only meaningful on an `accept` rule — a limit on a
    /// drop rule would throttle traffic that is refused anyway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// How much idle time the limit may bank, in packets. Defaults to one second's
    /// worth of `limit`, which is what an operator means by "100 a second"; a burst
    /// of one would meter every single packet instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,
    /// Reference a port group (`[firewall.group.port]`) instead of an inline
    /// `port`/range — mutually exclusive with it.
    #[serde(default, alias = "port-group", skip_serializing_if = "Option::is_none")]
    pub port_group: Option<String>,
    /// Time-based activation (roadmap C15): the rule is only in force during this
    /// weekly schedule (local time). Enforced at compile time — the compiler emits
    /// the rule only while the window is open, and a systemd timer re-applies at the
    /// window boundaries. Absent means "always active".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<Schedule>,
}

/// A weekly time window a firewall rule is active in (roadmap C15). Times are the
/// box's **local** time, `"HH:MM"`, and the window does not span midnight
/// (`start < end`). `days` lists the weekdays it applies on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    /// Weekdays the window is open on (at least one).
    pub days: Vec<Day>,
    /// Window start, local `"HH:MM"` (inclusive).
    pub start: String,
    /// Window end, local `"HH:MM"` (exclusive).
    pub end: String,
}

/// A day of the week, `tm_wday`-compatible (`Sun` = 0).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Day {
    Sun,
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
}

impl Day {
    /// The libc `tm_wday` value (Sunday = 0) — matches `localtime_r`.
    pub fn wday(self) -> i32 {
        match self {
            Day::Sun => 0,
            Day::Mon => 1,
            Day::Tue => 2,
            Day::Wed => 3,
            Day::Thu => 4,
            Day::Fri => 5,
            Day::Sat => 6,
        }
    }
    /// The systemd `OnCalendar` day abbreviation.
    pub fn calendar(self) -> &'static str {
        match self {
            Day::Sun => "Sun",
            Day::Mon => "Mon",
            Day::Tue => "Tue",
            Day::Wed => "Wed",
            Day::Thu => "Thu",
            Day::Fri => "Fri",
            Day::Sat => "Sat",
        }
    }
    /// Parse a lowercase day name (`"mon"`), or `None`.
    pub fn parse(s: &str) -> Option<Day> {
        Some(match s {
            "sun" => Day::Sun,
            "mon" => Day::Mon,
            "tue" => Day::Tue,
            "wed" => Day::Wed,
            "thu" => Day::Thu,
            "fri" => Day::Fri,
            "sat" => Day::Sat,
            _ => return None,
        })
    }
}

/// Parse an `"HH:MM"` local time into minutes since midnight (`0..=1439`), or
/// `None` if malformed / out of range.
pub(crate) fn parse_hhmm(s: &str) -> Option<u16> {
    let (h, m) = s.split_once(':')?;
    let h: u16 = h.parse().ok()?;
    let m: u16 = m.parse().ok()?;
    if h > 23 || m > 59 {
        return None;
    }
    Some(h * 60 + m)
}

impl Schedule {
    /// Whether the window is open on `wday` (`tm_wday`, Sun = 0) at `minute`
    /// (minutes since local midnight). Pure — the caller supplies the clock.
    pub fn is_active_at(&self, wday: i32, minute: u16) -> bool {
        let (Some(start), Some(end)) = (parse_hhmm(&self.start), parse_hhmm(&self.end)) else {
            return false;
        };
        self.days.iter().any(|d| d.wday() == wday) && minute >= start && minute < end
    }

    /// Whether the window is open right now, in the box's local time.
    pub fn is_active_now(&self) -> bool {
        // SAFETY: `localtime_r` fills a caller-owned `tm` from a `time_t`; both
        // pointers are valid for the call.
        let now = unsafe { libc::time(std::ptr::null_mut()) };
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        unsafe { libc::localtime_r(&now, &mut tm) };
        let minute = (tm.tm_hour * 60 + tm.tm_min) as u16;
        self.is_active_at(tm.tm_wday, minute)
    }
}

impl Rule {
    /// A broad zone rule (no proto/port) — sets the from-zone's default posture.
    pub fn is_broad(&self) -> bool {
        self.proto.is_none() && self.port.is_empty() && self.port_group.is_none()
    }
    /// A rule the data plane carries as a `(protocol, port)` entry: a literal
    /// port or a port group on TCP/UDP, or any of the port-less protocols, which
    /// match on the protocol alone with the port left at `0`.
    pub fn is_port_rule(&self) -> bool {
        match self.proto {
            None => false,
            Some(p) if p.has_ports() => !self.port.is_empty() || self.port_group.is_some(),
            Some(_) => true,
        }
    }

    /// The source constraints this rule matches, expanding a `source_group`
    /// (each member becomes its own data-plane rule). `None` means "from any";
    /// an unknown group name resolves to nothing (validation rejects it first).
    pub fn resolved_sources(&self, groups: &Groups) -> Vec<Option<String>> {
        if let Some(g) = &self.source_group {
            groups
                .address
                .get(g)
                .map(|m| m.iter().cloned().map(Some).collect())
                .unwrap_or_default()
        } else if let Some(s) = &self.source {
            vec![Some(s.clone())]
        } else {
            vec![None]
        }
    }

    /// The destination constraints this rule matches, expanding a
    /// `destination_group`. `None` means "to any"; mirrors [`Self::resolved_sources`].
    pub fn resolved_destinations(&self, groups: &Groups) -> Vec<Option<String>> {
        if let Some(g) = &self.destination_group {
            groups
                .address
                .get(g)
                .map(|m| m.iter().cloned().map(Some).collect())
                .unwrap_or_default()
        } else if let Some(d) = &self.destination {
            vec![Some(d.clone())]
        } else {
            vec![None]
        }
    }

    /// The ports this rule matches, expanding a `port_group` or a single
    /// spec/range into concrete ports.
    pub fn resolved_ports(&self, groups: &Groups) -> Vec<u16> {
        if let Some(g) = &self.port_group {
            groups
                .port
                .get(g)
                .map(|specs| specs.iter().flat_map(|p| p.ports()).collect())
                .unwrap_or_default()
        } else if !self.port.is_empty() {
            self.port.iter().flat_map(|p| p.ports()).collect()
        } else if self.proto.is_some_and(|p| !p.has_ports()) {
            // One entry at port 0: the data plane reads 0 off a packet that has
            // no ports, so this is the key that matches every packet of this
            // protocol under the rule's address constraints.
            vec![0]
        } else {
            Vec::new()
        }
    }
}

impl Appliance {
    /// Parse and validate a config from TOML text.
    pub fn from_toml(toml_text: &str) -> Result<Self> {
        let mut appliance: Appliance = toml::from_str(toml_text).context("parsing TOML config")?;
        appliance.normalize();
        appliance.validate()?;
        Ok(appliance)
    }

    /// Parse and validate a config from JSON text.
    pub fn from_json(json_text: &str) -> Result<Self> {
        let mut appliance: Appliance =
            serde_json::from_str(json_text).context("parsing JSON config")?;
        appliance.normalize();
        appliance.validate()?;
        Ok(appliance)
    }

    /// Fill in inferred VLAN `parent`/`vlan` from a `<parent>.<id>` interface name
    /// (both derived from the name only when unset and the interface carries no
    /// `type`; explicit values always win, and a name/value mismatch is caught by
    /// [`Self::validate`]). Runs before validation so a bare
    /// `interface eth0.20 address …` works without repeating parent/vlan.
    pub fn normalize(&mut self) {
        for iface in &mut self.interfaces {
            if iface.if_type.is_some() || iface.parent.is_some() || iface.vlan.is_some() {
                continue;
            }
            if let Some((parent, id)) = iface.name.rsplit_once('.') {
                if parent.is_empty() {
                    continue;
                }
                if let Ok(vlan) = id.parse::<u16>() {
                    if (1..=4094).contains(&vlan) {
                        iface.parent = Some(parent.to_string());
                        iface.vlan = Some(vlan);
                    }
                }
            }
        }
    }

    /// Load and validate a config file, picking the format by extension
    /// (`.json` → JSON, anything else → TOML).
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            Self::from_json(&text)
        } else {
            Self::from_toml(&text)
        }
    }

    /// Serialize to canonical TOML.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).context("serializing to TOML")
    }

    /// Serialize to pretty JSON (for editors / a future web UI).
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("serializing to JSON")
    }

    /// Reject configs that parse but are not coherent.
    pub fn validate(&self) -> Result<()> {
        validate_hostname(&self.system.hostname)?;

        // Every blocklist entry must be a valid IPv4 address or CIDR.
        for entry in &self.firewall.blocklist {
            validate_cidr_or_ip(entry).context("firewall.blocklist")?;
        }

        // Per-zone blocklists must also be valid; an optional zone description
        // must be a sane one-line label.
        for (name, z) in &self.zones {
            for entry in &z.blocklist {
                validate_cidr_or_ip(entry).with_context(|| format!("zone {name:?} blocklist"))?;
            }
            if let Some(d) = &z.description {
                validate_description(d).with_context(|| format!("zone {name:?} description"))?;
            }
        }

        let names: HashSet<&str> = self.interfaces.iter().map(|i| i.name.as_str()).collect();
        let mut seen = HashSet::new();
        for iface in &self.interfaces {
            validate_iface_name(&iface.name)?;
            if let Some(d) = &iface.description {
                validate_description(d)
                    .with_context(|| format!("interface {:?} description", iface.name))?;
            }
            if let Some(parent) = &iface.parent {
                validate_iface_name(parent)
                    .with_context(|| format!("interface {:?} parent", iface.name))?;
            }
            if !seen.insert(&iface.name) {
                bail!("duplicate interface {:?}", iface.name);
            }
            if let Some(addr) = &iface.address {
                validate_address(addr).with_context(|| format!("interface {:?}", iface.name))?;
            }
            if let Some(addr6) = &iface.address6 {
                validate_address6(addr6)
                    .with_context(|| format!("interface {:?} address6", iface.name))?;
            }
            // DHCPv6-PD downstream: the uplink must be a declared interface (and
            // a different one). `pd-subnet` without `pd-from` is meaningless.
            if let Some(up) = &iface.pd_from {
                if !self.interfaces.iter().any(|i| &i.name == up) {
                    bail!(
                        "interface {:?}: pd-from {up:?} is not a declared interface",
                        iface.name
                    );
                }
                if up == &iface.name {
                    bail!("interface {:?}: pd-from cannot be itself", iface.name);
                }
            } else if iface.pd_subnet.is_some() {
                bail!("interface {:?}: pd-subnet requires pd-from", iface.name);
            }
            // Link tunables: a sane MTU (IPv6 needs ≥1280; cap at jumbo) and a
            // well-formed MAC when cloning one.
            if let Some(mtu) = iface.mtu {
                if !(68..=9216).contains(&mtu) {
                    bail!(
                        "interface {:?}: mtu {mtu} out of range (68–9216)",
                        iface.name
                    );
                }
            }
            if let Some(mac) = &iface.mac {
                validate_mac(mac).with_context(|| format!("interface {:?} mac", iface.name))?;
            }
            // QoS: validate the shaping parameters and enforce that only knobs
            // that belong to the chosen discipline are set (cross-discipline knobs
            // are a config error, not a silent no-op).
            if let Some(qos) = &iface.qos {
                validate_qos(qos).with_context(|| format!("interface {:?} qos", iface.name))?;
            }
            // VLAN subinterface: parent + vlan come as a pair; vlan in range; the
            // parent must be a declared interface. A PPPoE client and a MACVLAN
            // also carry a `parent` (the raw uplink NIC / the parent link) but no
            // `vlan`, so they are validated separately below — skip the pairing
            // rule for them.
            if !iface.is_pppoe() && !iface.is_macvlan() && !iface.is_macsec() {
                match (&iface.parent, iface.vlan) {
                    (Some(parent), Some(vlan)) => {
                        if !(1..=4094).contains(&vlan) {
                            bail!(
                                "interface {:?}: vlan {vlan} out of range (1–4094)",
                                iface.name
                            );
                        }
                        if !names.contains(parent.as_str()) {
                            bail!(
                                "interface {:?}: parent {parent:?} is not a declared interface",
                                iface.name
                            );
                        }
                        // If the name is `<parent>.<id>`, the explicit parent/vlan
                        // must agree with it (inference filled them when unset, so
                        // reaching here with a mismatch means they were set by hand
                        // to something inconsistent with the name).
                        if let Some((np, nid)) = iface.name.rsplit_once('.') {
                            if let Ok(nvlan) = nid.parse::<u16>() {
                                if (parent != np || vlan != nvlan) && !np.is_empty() {
                                    bail!(
                                        "interface {:?}: name implies parent {np:?} vlan {nvlan}, but parent {parent:?} vlan {vlan} were set",
                                        iface.name
                                    );
                                }
                            }
                        }
                    }
                    (None, None) => {}
                    _ => bail!(
                        "interface {:?}: `parent` and `vlan` must be set together",
                        iface.name
                    ),
                }
            }

            // PPPoE client (`type = "pppoe"`): a session `pppd` brings up over the
            // raw uplink NIC named in `parent`. Requires credentials and a declared
            // parent; the box's address comes from the peer (IPCP), so a static
            // `address`/`address6` on it is a misconfiguration. Cannot also be a
            // VLAN / WireGuard / bridge/bond.
            if iface.is_pppoe() {
                if !iface.name.starts_with("ppp") {
                    bail!(
                        "interface {:?}: a pppoe interface must be named `ppp*` (e.g. ppp0)",
                        iface.name
                    );
                }
                let Some(p) = &iface.pppoe else {
                    bail!(
                        "interface {:?}: type=pppoe requires `pppoe` credentials (username/password)",
                        iface.name
                    );
                };
                if p.username.is_empty() {
                    bail!("interface {:?}: pppoe username is required", iface.name);
                }
                if p.password.is_empty() {
                    bail!("interface {:?}: pppoe password is required", iface.name);
                }
                // These credentials flow verbatim into the root-run pppd options
                // file (`user "…"`, `rp_pppoe_service …`, `rp_pppoe_ac …`) and the
                // CHAP/PAP secrets file. A newline injects a fresh pppd directive
                // (connect, pty, plugin, …) that pppd executes AS ROOT, and a quote
                // or backslash breaks out of the quoted fields — so reject any
                // control character, quote or backslash in every one of them.
                for (field, val) in [("username", &p.username), ("password", &p.password)] {
                    if val
                        .bytes()
                        .any(|b| b.is_ascii_control() || matches!(b, b'"' | b'\\'))
                    {
                        bail!(
                            "interface {:?}: pppoe {field} must not contain a control \
                             character, quote or backslash",
                            iface.name
                        );
                    }
                }
                // service-name / ac-name are rendered *unquoted*, so besides the
                // above they must not contain whitespace or a comment marker that
                // would split the directive or start a new one.
                for (field, val) in [("service-name", &p.service_name), ("ac-name", &p.ac_name)] {
                    if let Some(v) = val {
                        if v.bytes().any(|b| {
                            b.is_ascii_control() || matches!(b, b' ' | b'\t' | b'"' | b'\\' | b'#')
                        }) {
                            bail!(
                                "interface {:?}: pppoe {field} must not contain whitespace, a \
                                 control character, quote, backslash or '#'",
                                iface.name
                            );
                        }
                    }
                }
                match &iface.parent {
                    Some(parent) if names.contains(parent.as_str()) => {
                        if parent == &iface.name {
                            bail!("interface {:?}: pppoe parent cannot be itself", iface.name);
                        }
                    }
                    Some(parent) => bail!(
                        "interface {:?}: pppoe parent {parent:?} is not a declared interface",
                        iface.name
                    ),
                    None => bail!(
                        "interface {:?}: type=pppoe requires a `parent` uplink interface",
                        iface.name
                    ),
                }
                if iface.vlan.is_some() {
                    bail!(
                        "interface {:?}: a pppoe interface cannot also be a VLAN",
                        iface.name
                    );
                }
                if iface.address.is_some() || iface.address6.is_some() {
                    bail!(
                        "interface {:?}: a pppoe interface gets its address from the peer — do not set `address`",
                        iface.name
                    );
                }
                if let Some(mru) = p.mru {
                    if !(68..=9216).contains(&mru) {
                        bail!(
                            "interface {:?}: pppoe mru {mru} out of range (68–9216)",
                            iface.name
                        );
                    }
                }
                // A PPP session has no L2 device to clone a MAC onto, so `mac`
                // is dead here — reject it rather than silently drop it.
                if iface.mac.is_some() {
                    bail!(
                        "interface {:?}: `mac` is not applicable to a pppoe interface \
                         (a PPP session has no L2 device to clone a MAC onto)",
                        iface.name
                    );
                }
            } else if iface.pppoe.is_some() {
                bail!(
                    "interface {:?}: `pppoe` credentials require `type = \"pppoe\"`",
                    iface.name
                );
            }

            // WireGuard: a `type = "wireguard"` device. Its private key, listen
            // port and peers live in the matching `[[vpn.wireguard]]` entry
            // (cross-checked + validated in the vpn pass below); here we only
            // reject combining the tunnel device with a VLAN.
            if iface.is_wireguard() && (iface.parent.is_some() || iface.vlan.is_some()) {
                bail!(
                    "interface {:?}: a wireguard interface cannot also be a VLAN",
                    iface.name
                );
            }

            // Kernel tunnel (`type = gre|ipip|gretap`, roadmap C3): a point-to-point
            // link between two endpoint addresses. Requires `local` + `remote` of the
            // same family; the GRE `key` is only valid on gre/gretap; and a tunnel
            // cannot double as a VLAN. Endpoint
            // addresses are a security boundary too — they are rendered verbatim into
            // a networkd `[Tunnel]` section.
            if iface.is_tunnel() {
                if RESERVED_TUNNEL_DEVICES.contains(&iface.name.as_str()) {
                    bail!(
                        "interface {:?}: name collides with the kernel's fallback tunnel device \
                         (the tunnel module auto-creates it) — use a distinct name like \"tun0\"",
                        iface.name
                    );
                }
                let (Some(local), Some(remote)) = (&iface.local, &iface.remote) else {
                    bail!(
                        "interface {:?}: a tunnel requires both `local` and `remote` endpoint addresses",
                        iface.name
                    );
                };
                let lip = local.parse::<IpAddr>().map_err(|_| {
                    anyhow::anyhow!(
                        "interface {:?}: local {local:?} is not an IP address",
                        iface.name
                    )
                })?;
                let rip = remote.parse::<IpAddr>().map_err(|_| {
                    anyhow::anyhow!(
                        "interface {:?}: remote {remote:?} is not an IP address",
                        iface.name
                    )
                })?;
                if lip.is_ipv4() != rip.is_ipv4() {
                    bail!(
                        "interface {:?}: local {local:?} and remote {remote:?} must be the same IP family",
                        iface.name
                    );
                }
                if iface.tunnel_key.is_some() && !iface.tunnel_supports_key() {
                    bail!(
                        "interface {:?}: a `key` is only valid on a gre/gretap tunnel (ipip carries none)",
                        iface.name
                    );
                }
                if iface.parent.is_some() || iface.vlan.is_some() {
                    bail!("interface {:?}: a tunnel cannot also be a VLAN", iface.name);
                }
            } else if iface.is_l2tpv3() {
                // L2TPv3 (`type = l2tpv3`, roadmap C14): a static Ethernet
                // pseudowire between two endpoint IPs. Needs `local` + `remote` of
                // the same family and a `key` (the shared tunnel/session id); it is
                // not a VLAN. `ttl` is not carried by the `ip l2tp` static setup.
                let (Some(local), Some(remote)) = (&iface.local, &iface.remote) else {
                    bail!(
                        "interface {:?}: an l2tpv3 pseudowire requires both `local` and `remote` endpoint IPs",
                        iface.name
                    );
                };
                let lip = local.parse::<IpAddr>().map_err(|_| {
                    anyhow::anyhow!(
                        "interface {:?}: local {local:?} is not an IP address",
                        iface.name
                    )
                })?;
                let rip = remote.parse::<IpAddr>().map_err(|_| {
                    anyhow::anyhow!(
                        "interface {:?}: remote {remote:?} is not an IP address",
                        iface.name
                    )
                })?;
                if lip.is_ipv4() != rip.is_ipv4() {
                    bail!(
                        "interface {:?}: local {local:?} and remote {remote:?} must be the same IP family",
                        iface.name
                    );
                }
                if iface.tunnel_key.is_none() {
                    bail!(
                        "interface {:?}: an l2tpv3 pseudowire needs a `key` (the tunnel/session id shared by both ends)",
                        iface.name
                    );
                }
                if iface.parent.is_some() || iface.vlan.is_some() {
                    bail!(
                        "interface {:?}: an l2tpv3 pseudowire cannot also be a VLAN",
                        iface.name
                    );
                }
            } else if iface.local.is_some()
                || iface.remote.is_some()
                || iface.tunnel_key.is_some()
                || iface.ttl.is_some()
            {
                bail!(
                    "interface {:?}: local/remote/key/ttl require `type = \"gre\"|\"ipip\"|\"gretap\"|\"l2tpv3\"`",
                    iface.name
                );
            }

            // MACsec (`type = macsec`, roadmap C14): a Kind=macsec link on a parent
            // NIC, encrypted with a pre-shared key. Requires `parent`, a valid hex
            // key (128- or 256-bit), and the peer's MAC; the key/peer fields are only
            // valid on a macsec interface.
            if iface.is_macsec() {
                let Some(parent) = iface.parent.as_deref() else {
                    bail!(
                        "interface {:?}: a macsec interface needs a `parent` NIC to protect",
                        iface.name
                    );
                };
                // The macsec device pins its parent's MAC so its secure-channel id
                // is deterministic and the peer can name it — so the parent must be
                // declared with an explicit `mac`.
                match self.interfaces.iter().find(|x| x.name == parent) {
                    None => bail!(
                        "interface {:?}: macsec parent {parent:?} is not a declared interface",
                        iface.name
                    ),
                    Some(p) if p.mac.is_none() => bail!(
                        "interface {:?}: macsec parent {parent:?} needs an explicit `mac` (the device inherits it for a stable SCI)",
                        iface.name
                    ),
                    Some(_) => {}
                }
                let key = iface.macsec_key.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("interface {:?}: macsec needs a `macsec-key`", iface.name)
                })?;
                if !matches!(key.len(), 32 | 64) || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
                    bail!(
                        "interface {:?}: macsec-key must be 32 hex chars (128-bit) or 64 (256-bit)",
                        iface.name
                    );
                }
                let peer = iface.macsec_peer.as_deref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "interface {:?}: macsec needs a `macsec-peer` MAC address",
                        iface.name
                    )
                })?;
                validate_mac(peer)
                    .with_context(|| format!("interface {:?} macsec-peer", iface.name))?;
            } else if iface.macsec_key.is_some() || iface.macsec_peer.is_some() {
                bail!(
                    "interface {:?}: macsec-key/macsec-peer require `type = \"macsec\"`",
                    iface.name
                );
            }

            // DHCP server: needs the interface's own static subnet to hand out
            // addresses, so a static CIDR `address` is mandatory. Any advertised
            // DNS servers must be valid IPv4 addresses.
            if let Some(dhcp) = &iface.dhcp_server {
                match iface.address.as_deref() {
                    Some(addr) if addr != "dhcp" => {}
                    _ => bail!("dhcp-server requires a static address on {}", iface.name),
                }
                for dns in &dhcp.dns {
                    validate_ipv4(dns)
                        .with_context(|| format!("interface {:?} dhcp-server dns", iface.name))?;
                }
                // `address` is a static CIDR here (checked just above).
                let subnet = iface.address.as_deref().unwrap_or("");
                // The default-router (gateway) handed to clients must be a valid
                // IPv4 that lies inside the server's own subnet.
                if let Some(gw) = &dhcp.default_router {
                    validate_ipv4(gw).with_context(|| {
                        format!("interface {:?} dhcp-server default-router", iface.name)
                    })?;
                    if !ipv4_in_cidr(gw, subnet).unwrap_or(false) {
                        bail!(
                            "interface {:?} dhcp-server default-router {gw}: not inside the server subnet {subnet}",
                            iface.name
                        );
                    }
                }
                // The lease pool (offset addresses in, `size` long) must fit
                // inside the interface's subnet — a pool that runs off the end
                // hands out addresses the subnet doesn't contain.
                if let (Some(off), Some(size)) = (dhcp.pool_offset, dhcp.pool_size) {
                    if !dhcp_pool_fits(subnet, off, size) {
                        bail!(
                            "interface {:?} dhcp-server: pool (offset {off} + size {size}) does not fit inside the subnet {subnet}",
                            iface.name
                        );
                    }
                }
                // Static reservations: a valid MAC and an address inside the
                // server's own subnet (a lease outside it can never be handed out).
                for m in &dhcp.static_mappings {
                    validate_mac(&m.mac).with_context(|| {
                        format!(
                            "interface {:?} dhcp-server static-mapping {:?}",
                            iface.name, m.name
                        )
                    })?;
                    validate_ipv4(&m.ip).with_context(|| {
                        format!(
                            "interface {:?} dhcp-server static-mapping {:?}",
                            iface.name, m.name
                        )
                    })?;
                    if !ipv4_in_cidr(&m.ip, subnet).unwrap_or(false) {
                        bail!(
                            "interface {:?} dhcp-server static-mapping {:?}: ip {} is not inside the server subnet {}",
                            iface.name,
                            m.name,
                            m.ip,
                            subnet
                        );
                    }
                }
            }

            // Router Advertisements: advertised prefixes must be IPv6 CIDRs (a
            // /64 for SLAAC) and any advertised DNS must be IPv6 addresses.
            if let Some(ra) = &iface.router_advert {
                for prefix in &ra.prefixes {
                    validate_ipv6_cidr(prefix).with_context(|| {
                        format!("interface {:?} router-advert prefix", iface.name)
                    })?;
                    // Stateless autoconfiguration (SLAAC) requires a /64.
                    if !prefix.ends_with("/64") {
                        bail!(
                            "interface {:?} router-advert prefix {prefix:?}: must be a /64 (required for SLAAC)",
                            iface.name
                        );
                    }
                }
                for dns in &ra.dns {
                    validate_ipv6(dns)
                        .with_context(|| format!("interface {:?} router-advert dns", iface.name))?;
                }
                // Stateful DHCPv6 pool (roadmap C7): both endpoints must be IPv6,
                // ordered, and — since DHCPv6 hands out addresses from an
                // advertised prefix — fall inside one of the RA's /64 prefixes.
                if let Some(pool) = &ra.dhcp6_pool {
                    let start = pool.start.parse::<Ipv6Addr>().map_err(|_| {
                        anyhow::anyhow!(
                            "interface {:?} router-advert dhcp6-pool start {:?}: not an IPv6 address",
                            iface.name,
                            pool.start
                        )
                    })?;
                    let end = pool.end.parse::<Ipv6Addr>().map_err(|_| {
                        anyhow::anyhow!(
                            "interface {:?} router-advert dhcp6-pool end {:?}: not an IPv6 address",
                            iface.name,
                            pool.end
                        )
                    })?;
                    if start > end {
                        bail!(
                            "interface {:?} router-advert dhcp6-pool: start {:?} is above end {:?}",
                            iface.name,
                            pool.start,
                            pool.end
                        );
                    }
                    if ra.prefixes.is_empty() {
                        bail!(
                            "interface {:?} router-advert dhcp6-pool: needs an advertised prefix the pool sits in",
                            iface.name
                        );
                    }
                    let in_a_prefix = ra
                        .prefixes
                        .iter()
                        .any(|p| ipv6_in_prefix(&start, p) && ipv6_in_prefix(&end, p));
                    if !in_a_prefix {
                        bail!(
                            "interface {:?} router-advert dhcp6-pool: {:?}-{:?} is not inside any advertised prefix",
                            iface.name,
                            pool.start,
                            pool.end
                        );
                    }
                }
            }

            // Bridge / bond: a `type` device cannot also be a VLAN subinterface;
            // `member` is only valid on such a device; a `bond-mode` is only
            // meaningful on a bond; `vlan-aware` only on a bridge. The membership
            // list is cross-checked in a second pass below, once every interface's
            // type is known.
            if iface.is_virtual_l2() && (iface.parent.is_some() || iface.vlan.is_some()) {
                bail!(
                    "interface {:?}: a bridge/bond device cannot also be a VLAN",
                    iface.name
                );
            }
            if !iface.members.is_empty() && !iface.is_virtual_l2() {
                bail!(
                    "interface {:?}: `member` is only valid on a type=bridge/bond device",
                    iface.name
                );
            }

            // MACVLAN (roadmap C14): needs a `parent`, a valid mode, and cannot
            // also be a VLAN. The parent must be a declared/discovered interface.
            if iface.is_macvlan() {
                match &iface.parent {
                    None => bail!(
                        "interface {:?}: a type=macvlan interface needs a `parent` NIC",
                        iface.name
                    ),
                    Some(p) if !self.interfaces.iter().any(|i| &i.name == p) => bail!(
                        "interface {:?}: macvlan parent {p:?} is not a declared interface",
                        iface.name
                    ),
                    Some(_) => {}
                }
                if iface.vlan.is_some() {
                    bail!(
                        "interface {:?}: a macvlan cannot also be a VLAN (drop `vlan`)",
                        iface.name
                    );
                }
            }
            if let Some(mode) = &iface.macvlan_mode {
                if !iface.is_macvlan() {
                    bail!(
                        "interface {:?}: macvlan-mode is only valid on a type=macvlan",
                        iface.name
                    );
                }
                if !matches!(mode.as_str(), "bridge" | "private" | "vepa" | "passthru") {
                    bail!(
                        "interface {:?}: macvlan-mode {mode:?} must be bridge, private, vepa or passthru",
                        iface.name
                    );
                }
            }
            // QinQ (roadmap C14): `vlan-protocol` only on a VLAN subinterface, and
            // one of the two 802.1 tag protocols.
            if let Some(proto) = &iface.vlan_protocol {
                if !iface.is_vlan() {
                    bail!(
                        "interface {:?}: vlan-protocol is only valid on a VLAN subinterface (needs parent + vlan)",
                        iface.name
                    );
                }
                if !matches!(proto.as_str(), "802.1q" | "802.1ad") {
                    bail!(
                        "interface {:?}: vlan-protocol {proto:?} must be 802.1q or 802.1ad",
                        iface.name
                    );
                }
            }
            if let Some(mode) = &iface.bond_mode {
                if !iface.is_bond() {
                    bail!(
                        "interface {:?}: bond-mode is only valid on a type=bond",
                        iface.name
                    );
                }
                if !BOND_MODES.contains(&mode.as_str()) {
                    bail!(
                        "interface {:?}: bond-mode {mode:?} is not one of {BOND_MODES:?}",
                        iface.name
                    );
                }
            }
            if iface.vlan_aware.is_some() && !iface.is_bridge() {
                bail!(
                    "interface {:?}: vlan-aware is only valid on a type=bridge",
                    iface.name
                );
            }
            // Per-port VLAN ids must be in range; their scoping to a vlan-aware
            // bridge is checked in the membership pass (which knows who owns whom).
            for id in iface.vlan_tagged.iter().copied().chain(iface.vlan_untagged) {
                if !(1..=4094).contains(&id) {
                    bail!(
                        "interface {:?}: vlan id {id} out of range (1–4094)",
                        iface.name
                    );
                }
            }
        }

        // Membership pass: resolve each bridge/bond device's `member` list. A
        // member must be a declared/known interface, may belong to at most one
        // bond/bridge, and must not itself be a bond/bridge/VLAN (no nesting or
        // loops). The member → owning-device map also scopes the per-port VLAN
        // filtering below.
        let mut member_of: BTreeMap<&str, &str> = BTreeMap::new();
        for dev in &self.interfaces {
            for m in &dev.members {
                if m == &dev.name {
                    bail!("interface {:?}: cannot enslave itself", dev.name);
                }
                let Some(mi) = self.interfaces.iter().find(|i| &i.name == m) else {
                    bail!(
                        "interface {:?}: member {m:?} is not a declared interface",
                        dev.name
                    );
                };
                if mi.is_virtual_l2()
                    || mi.vlan.is_some()
                    || mi.is_pppoe()
                    || mi.is_wireguard()
                    || mi.is_tunnel()
                {
                    bail!(
                        "interface {:?}: member {m:?} is itself a bridge/bond/VLAN/pppoe/wireguard/tunnel and cannot be enslaved",
                        dev.name
                    );
                }
                if let Some(prev) = member_of.insert(m.as_str(), dev.name.as_str()) {
                    bail!(
                        "interface {m:?}: already a member of {prev:?}, cannot also join {:?}",
                        dev.name
                    );
                }
            }
        }

        // Per-port VLAN filtering (`vlan-tagged`/`vlan-untagged`) is only valid on
        // a port that is a member of a vlan-aware bridge.
        for iface in &self.interfaces {
            if iface.vlan_tagged.is_empty() && iface.vlan_untagged.is_none() {
                continue;
            }
            let bridge = member_of
                .get(iface.name.as_str())
                .and_then(|owner| self.interfaces.iter().find(|d| d.name.as_str() == *owner));
            match bridge {
                Some(b) if b.is_bridge() && b.vlan_aware == Some(true) => {}
                _ => bail!(
                    "interface {:?}: vlan-tagged/vlan-untagged require membership of a vlan-aware bridge",
                    iface.name
                ),
            }
        }

        // Firewall groups (aliases): address members are hosts or CIDRs in either
        // family — the data plane has a longest-prefix trie for each — so a
        // hostname is what cannot apply, not IPv6.
        for (name, members) in &self.firewall.group.address {
            for m in members {
                if validate_cidr_or_ip(m).is_err() {
                    bail!("firewall group address-group {name:?}: {m:?} is not a host or CIDR");
                }
            }
        }
        // A domain group shares the address groups' namespace — a rule references
        // either through the same field, so a name in both would resolve by
        // whichever the merge happened to write last.
        for name in self.firewall.group.domain.keys() {
            if self.firewall.group.address.contains_key(name) {
                bail!(
                    "firewall group domain-group {name:?}: a group of that name already \
                     exists as an address-group; rules reference both the same way"
                );
            }
        }
        for (name, domains) in &self.firewall.group.domain {
            if domains.is_empty() {
                bail!("firewall group domain-group {name:?}: no domains — remove it instead");
            }
            for d in domains {
                validate_domain_name(d)
                    .with_context(|| format!("firewall group domain-group {name:?}: {d:?}"))?;
            }
        }
        for (name, specs) in &self.firewall.group.port {
            for s in specs {
                s.validate()
                    .with_context(|| format!("firewall group port-group {name:?}"))?;
            }
        }

        // Every rule's zones must be backed by at least one *assigned* interface,
        // else the rule can never match — a common, silent misconfiguration.
        let zones_in_use: HashSet<&str> = self
            .interfaces
            .iter()
            .filter_map(|i| i.zone.as_deref())
            .collect();
        // What a NIC is pinned to, and which offload switches it names.
        for i in &self.interfaces {
            if let Some(mac) = &i.hw_id {
                validate_mac(mac).with_context(|| format!("interface {:?} hw-id", i.name))?;
            }
            for feature in i.offload.keys() {
                if !OFFLOAD_FEATURES.contains(&feature.as_str()) {
                    bail!(
                        "interface {:?}: unknown offload feature {feature:?} (known: {})",
                        i.name,
                        OFFLOAD_FEATURES.join(", ")
                    );
                }
            }
        }
        // Kernel parameters: a narrow allow-list on purpose. A firewall that can
        // be made unbootable from its own configuration file is a firewall whose
        // rollback cannot save you.
        for (key, value) in &self.system.sysctl {
            if !(key.starts_with("net.") || key.starts_with("vm.")) {
                bail!("system sysctl {key:?}: only net.* and vm.* parameters may be set here");
            }
            if key.contains('/') || value.contains('\n') {
                bail!("system sysctl {key:?}: not a kernel parameter name/value");
            }
        }
        for rule in &self.rules {
            if let Some(d) = &rule.description {
                validate_description(d)
                    .with_context(|| format!("rule {:?} description", rule.name))?;
            }
            let mut zone_refs = vec![("from", &rule.from)];
            if let Some(to) = &rule.to {
                zone_refs.push(("to", to));
            }
            for (which, zone) in zone_refs {
                // A local zone is the appliance itself, so it has no interface
                // to be in use on — naming one is the whole point.
                let is_local = self.zones.get(zone.as_str()).is_some_and(|z| z.local);
                if !is_local && !zones_in_use.contains(zone.as_str()) {
                    bail!(
                        "rule {:?}: {which} zone {zone:?} has no interface",
                        rule.name
                    );
                }
            }
            // A port match is an inline `port`/range OR a `port-group`, never
            // both; likewise a `source` OR a `source-group`. And a port rule
            // needs a proto paired with a port (either form).
            if !rule.port.is_empty() && rule.port_group.is_some() {
                bail!("rule {:?}: set `port` or `port-group`, not both", rule.name);
            }
            // A port on a protocol that has none is a rule that would match
            // something other than what it says. ICMP's second header byte is a
            // *code*, not a port, and the data plane reads 0 there — so the port
            // would be quietly dropped and the rule would match all of it.
            if let Some(p) = rule.proto {
                if !p.has_ports() && (!rule.port.is_empty() || rule.port_group.is_some()) {
                    bail!(
                        "rule {:?}: {} carries no ports — drop the port to match the \
                         protocol, or name tcp/udp",
                        rule.name,
                        proto_str(p)
                    );
                }
            }
            if rule.source.is_some() && rule.source_group.is_some() {
                bail!(
                    "rule {:?}: set `source` or `source-group`, not both",
                    rule.name
                );
            }
            // A port rule's `to` zone is enforced by matching that zone's subnets
            // as the destination, so it occupies the destination end and cannot be
            // combined with an explicit one — nor with a source constraint, since
            // the data plane ranks one end per rule.
            if rule.to.is_some()
                && rule.is_port_rule()
                && (rule.destination.is_some() || rule.destination_group.is_some())
            {
                bail!(
                    "rule {:?}: `to` is enforced as a destination match, so it cannot be \
                     combined with an explicit `destination` — remove one of them",
                    rule.name
                );
            }
            // A limit throttles what a rule lets through, so it needs a rule that
            // lets something through — and a port to bound. Refused rather than
            // ignored: a configured limit that silently does nothing is the kind of
            // thing an operator only discovers during the flood it was meant to
            // stop.
            if let Some(limit) = rule.limit {
                if limit == 0 {
                    bail!("rule {:?}: `limit` must be at least 1 packet/s", rule.name);
                }
                if rule.action != Action::Accept {
                    bail!(
                        "rule {:?}: `limit` throttles traffic a rule admits, so it only \
                         applies to an `accept` rule",
                        rule.name
                    );
                }
                if !rule.is_port_rule() {
                    bail!(
                        "rule {:?}: `limit` needs a proto/port — a broad rule sets a zone's \
                         posture and has no per-rule budget to spend",
                        rule.name
                    );
                }
            }
            if rule.burst.is_some() && rule.limit.is_none() {
                bail!(
                    "rule {:?}: `burst` sizes a `limit`; set one or remove the burst",
                    rule.name
                );
            }
            if rule.destination.is_some() && rule.destination_group.is_some() {
                bail!(
                    "rule {:?}: set `destination` or `destination-group`, not both",
                    rule.name
                );
            }
            // One rule, one end. The data plane ranks each end in its own
            // longest-prefix table, so a rule constraining both would have to sit in
            // two of them — and whichever one matched would enforce only half of
            // what the rule says. Two rules express it exactly.
            if (rule.source.is_some() || rule.source_group.is_some())
                && (rule.destination.is_some() || rule.destination_group.is_some())
            {
                bail!(
                    "rule {:?}: a rule constrains a source or a destination, not both —                      split it into two rules",
                    rule.name
                );
            }
            // A port without a protocol is a rule that cannot be keyed, and a
            // TCP/UDP rule without a port is not a port rule at all — it only
            // changes the zone's posture, which is rarely what was meant.
            // A port-less protocol is the exception: naming it *is* the match.
            let has_port = !rule.port.is_empty() || rule.port_group.is_some();
            let wants_port = rule.proto.is_some_and(|p| p.has_ports());
            if has_port && rule.proto.is_none() {
                bail!(
                    "rule {:?}: a port needs a `proto` to key it (tcp, udp or tcp_udp)",
                    rule.name
                );
            }
            if wants_port && !has_port {
                bail!(
                    "rule {:?}: `proto` and a port (`port` or `port-group`) must be set together",
                    rule.name
                );
            }
            // A literal port (or range) must be in range and not inverted/too wide.
            for port in &rule.port {
                port.validate()
                    .with_context(|| format!("rule {:?}", rule.name))?;
            }
            // An inline source constraint must be an IPv4 host or CIDR.
            if let Some(src) = &rule.source {
                validate_cidr_or_ip(src).with_context(|| format!("rule {:?} source", rule.name))?;
            }
            if let Some(dst) = &rule.destination {
                validate_cidr_or_ip(dst)
                    .with_context(|| format!("rule {:?} destination", rule.name))?;
            }
            // A broad rule (no proto/port) only *opens* a zone with `accept`; the
            // data plane derives a zone's deny posture from its default-action, so
            // a broad `drop`/`reject` never reaches the datapath — reject it rather
            // than let it silently do nothing.
            if rule.is_broad() && matches!(rule.action, Action::Drop | Action::Reject) {
                bail!(
                    "rule {:?}: broad drop/reject rules are not supported yet — set \
                     `firewall zone {} default-action drop` instead, or give the rule proto/port",
                    rule.name,
                    rule.from
                );
            }
            // A referenced group must be declared.
            if let Some(g) = &rule.source_group {
                if !self.firewall.group.has_address_like(g) {
                    bail!(
                        "rule {:?}: source-group {g:?} is not a declared address or domain group",
                        rule.name
                    );
                }
            }
            if let Some(g) = &rule.destination_group {
                if !self.firewall.group.has_address_like(g) {
                    bail!(
                        "rule {:?}: destination-group {g:?} is not a declared address or \
                         domain group",
                        rule.name
                    );
                }
            }
            if let Some(g) = &rule.port_group {
                if !self.firewall.group.port.contains_key(g) {
                    bail!(
                        "rule {:?}: port-group {g:?} is not a declared port group",
                        rule.name
                    );
                }
            }
            // Time-based schedule (roadmap C15): valid days + HH:MM window that does
            // not span midnight. Only meaningful on a port rule (a broad rule sets a
            // zone's standing posture, which can't flip on a timer).
            if let Some(sched) = &rule.schedule {
                if sched.days.is_empty() {
                    bail!("rule {:?}: schedule needs at least one day", rule.name);
                }
                let start = parse_hhmm(&sched.start).ok_or_else(|| {
                    anyhow::anyhow!(
                        "rule {:?}: schedule start {:?} is not HH:MM",
                        rule.name,
                        sched.start
                    )
                })?;
                let end = parse_hhmm(&sched.end).ok_or_else(|| {
                    anyhow::anyhow!(
                        "rule {:?}: schedule end {:?} is not HH:MM",
                        rule.name,
                        sched.end
                    )
                })?;
                if start >= end {
                    bail!(
                        "rule {:?}: schedule start {:?} must be before end {:?} (a window cannot span midnight)",
                        rule.name,
                        sched.start,
                        sched.end
                    );
                }
                if !rule.is_port_rule() {
                    bail!(
                        "rule {:?}: a schedule is only valid on a port rule (proto + port)",
                        rule.name
                    );
                }
            }
            // Bound the compile-time expansion (sources × ports) so a rule
            // crossing two big groups can't flood the data-plane rule map.
            if rule.is_port_rule() {
                let expansion = rule.resolved_sources(&self.firewall.group).len()
                    * rule.resolved_ports(&self.firewall.group).len();
                if expansion > MAX_RULE_EXPANSION {
                    bail!(
                        "rule {:?}: expands to {expansion} data-plane rules, over the \
                         {MAX_RULE_EXPANSION} cap (shrink the address/port group)",
                        rule.name
                    );
                }
            }
        }

        // Source NAT (masquerade) targets a zone that must have an interface.
        for src in &self.nat.source {
            if let Some(d) = &src.description {
                validate_description(d)
                    .with_context(|| format!("nat source {:?} description", src.name))?;
            }
            if !zones_in_use.contains(src.zone.as_str()) {
                bail!(
                    "nat source {:?}: zone {:?} has no interface",
                    src.name,
                    src.zone
                );
            }
            // A base port without a block size configures nothing; a block size
            // that leaves no room for even one block would silently fall back to
            // ordinary masquerade, which is the opposite of what an operator who
            // asked for deterministic blocks needs.
            if src.cgnat_base_port.is_some() && src.cgnat_block_size.is_none() {
                bail!(
                    "nat source {:?}: `cgnat-base-port` sizes nothing without \
                     `cgnat-block-size`",
                    src.name
                );
            }
            if let Some(size) = src.cgnat_block_size {
                let base = src.cgnat_base_port.unwrap_or(DEFAULT_CGNAT_BASE_PORT);
                if size == 0 {
                    bail!(
                        "nat source {:?}: `cgnat-block-size` must be at least 1",
                        src.name
                    );
                }
                if base == 0 {
                    bail!(
                        "nat source {:?}: `cgnat-base-port` must be at least 1",
                        src.name
                    );
                }
                let space = u32::from(u16::MAX) - u32::from(base) + 1;
                if space < u32::from(size) {
                    bail!(
                        "nat source {:?}: a block of {size} does not fit above port {base} \
                         ({space} ports left)",
                        src.name
                    );
                }
            }
        }

        // Destination NAT (port-forward) targets a zone (must have an interface)
        // and a valid internal host.
        for dst in &self.nat.destination {
            if let Some(d) = &dst.description {
                validate_description(d)
                    .with_context(|| format!("nat destination {:?} description", dst.name))?;
            }
            if !zones_in_use.contains(dst.zone.as_str()) {
                bail!(
                    "nat destination {:?}: zone {:?} has no interface",
                    dst.name,
                    dst.zone
                );
            }
            if dst.port == 0 {
                bail!("nat destination {:?}: port 0 is not valid", dst.name);
            }
            let (_to_ip, to_port) = parse_host_port(&dst.to)
                .with_context(|| format!("nat destination {:?}", dst.name))?;
            // An explicit `ip:0` target port is invalid (a bare `ip` with no
            // colon legitimately parses to 0, meaning "keep the public port").
            if dst.to.contains(':') && to_port == 0 {
                bail!(
                    "nat destination {:?}: target port 0 in {:?} is not valid",
                    dst.name,
                    dst.to
                );
            }
        }

        // Load-balanced services (C22). Every rejection here is a configuration
        // the data plane would accept and then behave surprisingly on.
        let mut lb_names: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        let mut lb_keys: std::collections::BTreeSet<(&str, &str, u16)> =
            std::collections::BTreeSet::new();
        for lb in &self.load_balancers {
            if lb.name.is_empty() {
                bail!("a load-balancer needs a name");
            }
            if !lb_names.insert(lb.name.as_str()) {
                bail!("duplicate load-balancer {:?}", lb.name);
            }
            if let Some(d) = &lb.description {
                validate_description(d)
                    .with_context(|| format!("load-balancer {:?} description", lb.name))?;
            }
            if !zones_in_use.contains(lb.zone.as_str()) {
                bail!(
                    "load-balancer {:?}: zone {:?} has no interface",
                    lb.name,
                    lb.zone
                );
            }
            // The datapath keys a service by (policy, vip, port, proto). A second
            // service on the same tuple would not conflict — it would overwrite
            // the first in the map, silently.
            let proto = match lb.proto {
                Proto::Tcp => "tcp",
                Proto::Udp => "udp",
                other => proto_str(other),
            };
            if !lb_keys.insert((lb.zone.as_str(), proto, lb.port)) {
                bail!(
                    "load-balancer {:?}: zone {:?} already fronts {proto}/{} — one service \
                     per (zone, protocol, port)",
                    lb.name,
                    lb.zone,
                    lb.port
                );
            }
            validate_ipv4(&lb.vip).with_context(|| format!("load-balancer {:?} vip", lb.name))?;
            if lb.port == 0 {
                bail!("load-balancer {:?}: port 0 is not valid", lb.name);
            }
            // No protocol check is needed: `Proto` is tcp|udp, so a protocol the
            // load balancer cannot key a port on is unrepresentable here.
            for backend in &lb.backends {
                let (_ip, port) = parse_host_port(backend)
                    .with_context(|| format!("load-balancer {:?} backend {backend:?}", lb.name))?;
                if backend.contains(':') && port == 0 {
                    bail!(
                        "load-balancer {:?}: backend port 0 in {backend:?} is not valid",
                        lb.name
                    );
                }
            }
            // An empty pool is allowed on purpose: draining a service to zero
            // backends is a normal operation, and the datapath passes the traffic
            // through (counting lb_no_backend) rather than blackholing it.
        }

        // NAT64 (roadmap C10): stateful IPv6→IPv4 translation (tayga) + DNS64.
        let n64 = &self.nat.nat64;
        if n64.enabled {
            // The IPv4 pool tayga maps into is required and must be a real CIDR
            // (not a bare host) — the pool needs a prefix length to size the range.
            let pool = n64.pool.as_deref().ok_or_else(|| {
                anyhow::anyhow!("nat nat64: pool <ipv4-cidr> is required when enabled")
            })?;
            if !pool.contains('/') {
                bail!("nat nat64 pool {pool:?}: expected an IPv4 CIDR like \"192.0.2.0/24\"");
            }
            validate_cidr_or_ip(pool).with_context(|| "nat nat64 pool")?;
            // The translation prefix (operator's or the well-known) must be a
            // valid IPv6 CIDR, and — per RFC 6146 for the well-known form — a /96.
            let prefix = n64.effective_prefix();
            validate_ipv6_cidr(prefix).with_context(|| "nat nat64 prefix")?;
            if !prefix.ends_with("/96") {
                bail!("nat nat64 prefix {prefix:?}: must be a /96 (RFC 6052)");
            }
            // The IPv6-only side interface + its static IPv6 address are required:
            // it is the segment NAT64 serves, DNS64 binds its resolver to that
            // address, and tayga sources its own node/ICMPv6 address from it —
            // mandatory with the well-known prefix and a non-global pool.
            let iface = n64.interface.as_deref().ok_or_else(|| {
                anyhow::anyhow!("nat nat64: needs interface <name> (the IPv6-only side)")
            })?;
            let decl = self
                .interfaces
                .iter()
                .find(|i| i.name == iface)
                .ok_or_else(|| {
                    anyhow::anyhow!("nat nat64 interface {iface:?}: not a declared interface")
                })?;
            match decl.address6.as_deref() {
                Some(a) if a.contains(':') && a.contains('/') => {
                    validate_ipv6_cidr(a)
                        .with_context(|| format!("nat nat64 interface {iface:?} address6"))?;
                }
                _ => bail!(
                    "nat nat64: interface {iface:?} needs a static IPv6 address6 (the v6 side + tayga's node address)"
                ),
            }
            // DNS64 additionally forwards synthesis misses upstream.
            if n64.dns64 && self.services.dns.upstream.is_empty() {
                bail!("nat nat64 dns64: needs an upstream resolver ([services.dns] upstream)");
            }
        }

        // NPTv6 (roadmap C16, RFC 6296): stateless prefix translation. The boundary
        // interface must be declared; both prefixes must be v6 CIDRs of equal length
        // that is a non-zero multiple of 16 bits ≤ /64 (the v1 datapath scope).
        for n in &self.nat.npt66 {
            if let Some(desc) = &n.description {
                validate_description(desc)
                    .with_context(|| format!("nat npt66 {:?} description", n.name))?;
            }
            if !self.interfaces.iter().any(|i| i.name == n.interface) {
                bail!(
                    "nat npt66 {:?}: interface {:?} is not a declared interface",
                    n.name,
                    n.interface
                );
            }
            validate_ipv6_cidr(&n.internal)
                .with_context(|| format!("nat npt66 {:?} internal", n.name))?;
            validate_ipv6_cidr(&n.external)
                .with_context(|| format!("nat npt66 {:?} external", n.name))?;
            let cidr_len = |s: &str| -> u8 {
                s.split('/')
                    .nth(1)
                    .and_then(|l| l.parse().ok())
                    .unwrap_or(0)
            };
            let ilen = cidr_len(&n.internal);
            let elen = cidr_len(&n.external);
            if ilen != elen {
                bail!(
                    "nat npt66 {:?}: internal /{ilen} and external /{elen} prefix lengths must match",
                    n.name
                );
            }
            if ilen == 0 || ilen > 64 || ilen % 16 != 0 {
                bail!(
                    "nat npt66 {:?}: prefix /{ilen} must be a non-zero multiple of 16 bits, ≤ /64",
                    n.name
                );
            }
        }

        // Routing (Wren): validate router-id, static routes and BGP peers.
        if let Some(rid) = &self.protocols.router_id {
            validate_ipv4(rid).with_context(|| "protocols router-id")?;
        }
        // AAA. A server with no secret cannot be talked to at all, and a
        // default group that does not exist would hand a directory account a
        // permission nobody wrote down.
        for r in &self.system.aaa.radius {
            validate_host(&r.server).context("system aaa radius")?;
            if r.secret.is_empty() {
                bail!(
                    "system aaa radius {:?}: needs a shared secret — without one the server \
                     cannot check the answer and will ignore the request",
                    r.server
                );
            }
        }
        for d in &self.system.aaa.ldap {
            validate_host(&d.server).context("system aaa ldap")?;
            if d.base_dn.is_empty() {
                bail!(
                    "system aaa ldap {:?}: needs a base-dn — without it there is no DN to bind as",
                    d.server
                );
            }
        }
        if let Some(g) = &self.system.aaa.default_group {
            if !self.system.groups.iter().any(|x| &x.name == g) {
                bail!("system aaa default-group {g:?}: no such permission group");
            }
        }
        for l in &self.system.logins {
            if let Some(secret) = &l.totp {
                crate::aaa::base32_decode(secret)
                    .with_context(|| format!("system login {:?} totp", l.username))?;
            }
        }
        // Steering: a policy that names an uplink this box does not have would
        // silently never steer anything, which is the worst way for it to fail.
        let mut seen_pol = std::collections::BTreeSet::new();
        for p in &self.multiwan.policies {
            if !seen_pol.insert(p.name.as_str()) {
                bail!("multiwan policy {:?}: declared twice", p.name);
            }
            if p.uplinks.is_empty() {
                bail!(
                    "multiwan policy {:?}: needs at least one uplink to prefer",
                    p.name
                );
            }
            for want in &p.uplinks {
                if !self.multiwan.uplinks.iter().any(|u| &u.interface == want) {
                    bail!(
                        "multiwan policy {:?}: uplink {want:?} is not a configured uplink",
                        p.name
                    );
                }
            }
            if (p.source_port.is_some() || p.destination_port.is_some()) && p.proto.is_none() {
                bail!(
                    "multiwan policy {:?}: a port needs a `proto` to key it (tcp or udp)",
                    p.name
                );
            }
            for (what, v) in [("source", &p.source), ("destination", &p.destination)] {
                if let Some(a) = v {
                    validate_cidr_or_ip(a)
                        .with_context(|| format!("multiwan policy {:?} {what}", p.name))?;
                }
            }
            // Preferring a path that cannot be measured means the preference can
            // never be acted on — the daemon has nothing to compare.
            if p.strict
                && !p
                    .uplinks
                    .iter()
                    .filter_map(|i| self.multiwan.uplinks.iter().find(|u| &u.interface == i))
                    .any(|u| u.check.has_sla())
            {
                bail!(
                    "multiwan policy {:?} is strict, but none of its uplinks has an SLA \
                     threshold to be strict about",
                    p.name
                );
            }
        }
        // Policy routing: a rule that redirects nowhere, or matches a port
        // without saying which protocol's port, is a rule the kernel will
        // refuse — better to say so here, with the name in hand.
        let mut seen_pbr = std::collections::BTreeSet::new();
        for r in &self.policy.routes {
            if !seen_pbr.insert(r.name.as_str()) {
                bail!("policy route {:?}: declared twice", r.name);
            }
            if r.table == 0 {
                bail!(
                    "policy route {:?}: needs a table — a rule that redirects nowhere is not a policy route",
                    r.name
                );
            }
            // 0 and 253-255 are the kernel's own (unspec/default/main/local).
            if (253..=255).contains(&r.table) {
                bail!(
                    "policy route {:?}: table {} is the kernel's own (253-255)",
                    r.name,
                    r.table
                );
            }
            if (r.source_port.is_some() || r.destination_port.is_some()) && r.proto.is_none() {
                bail!(
                    "policy route {:?}: a port needs a `proto` to key it (tcp or udp)",
                    r.name
                );
            }
            for (what, v) in [("source", &r.source), ("destination", &r.destination)] {
                if let Some(a) = v {
                    validate_cidr_or_ip(a)
                        .with_context(|| format!("policy route {:?} {what}", r.name))?;
                }
            }
            // Both ends in one rule is fine; both *families* in one rule is not,
            // because a kernel rule belongs to one.
            if let (Some(s), Some(d)) = (&r.source, &r.destination) {
                if s.contains(':') != d.contains(':') {
                    bail!(
                        "policy route {:?}: source and destination are different address families",
                        r.name
                    );
                }
            }
        }
        for r in &self.protocols.statics {
            // A static route may be IPv4 or IPv6; wren installs either. The
            // nexthop family must match the prefix (no v4 via for a v6 route).
            let prefix_v6 = route_prefix_family(&r.prefix)
                .with_context(|| format!("protocols static route {:?}", r.prefix))?;
            // A discard route is the one that legitimately has nowhere to send.
            if r.blackhole && (r.via.is_some() || r.dev.is_some()) {
                bail!(
                    "protocols static route {:?}: a blackhole discards what it matches, \
                     so it cannot also have a next-hop",
                    r.prefix
                );
            }
            if !r.blackhole && r.via.is_none() && r.dev.is_none() {
                bail!(
                    "protocols static route {:?}: needs a via <ip>, dev <if> or blackhole",
                    r.prefix
                );
            }
            if let Some(via) = &r.via {
                let via_v6 = match ip_family(via) {
                    Some(f) => f,
                    None => bail!(
                        "protocols static route {:?} via {via:?}: not an IP",
                        r.prefix
                    ),
                };
                if via_v6 != prefix_v6 {
                    bail!(
                        "protocols static route {:?}: via {via:?} family does not match the prefix",
                        r.prefix
                    );
                }
            }
        }
        // The set of declared route-map names — a BGP neighbour's import/export,
        // a VRF's import/export and the redistribution maps must reference one of
        // these (they compile to Wren's `[[filter]]` blocks).
        let filter_names: HashSet<&str> = self
            .policy
            .route_maps
            .iter()
            .map(|f| f.name.as_str())
            .collect();
        // The set of declared VRF names — every per-protocol / static `vrf` and a
        // VRF's own name must resolve here.
        let vrf_names: HashSet<&str> = self
            .protocols
            .vrfs
            .iter()
            .map(|v| v.name.as_str())
            .collect();
        let check_filter_ref = |name: &str, whose: &str| -> Result<()> {
            if !filter_names.contains(name) {
                bail!("protocols {whose} references unknown filter {name:?}");
            }
            Ok(())
        };
        let check_vrf_ref = |name: &Option<String>, whose: &str| -> Result<()> {
            if let Some(name) = name {
                if !vrf_names.contains(name.as_str()) {
                    bail!("protocols {whose} references unknown vrf {name:?}");
                }
            }
            Ok(())
        };
        // Static routes may name a VRF (validated once the VRF set is known).
        // AAA. A server with no secret cannot be talked to at all, and a
        // default group that does not exist would hand a directory account a
        // permission nobody wrote down.
        for r in &self.system.aaa.radius {
            validate_host(&r.server).context("system aaa radius")?;
            if r.secret.is_empty() {
                bail!(
                    "system aaa radius {:?}: needs a shared secret — without one the server \
                     cannot check the answer and will ignore the request",
                    r.server
                );
            }
        }
        for d in &self.system.aaa.ldap {
            validate_host(&d.server).context("system aaa ldap")?;
            if d.base_dn.is_empty() {
                bail!(
                    "system aaa ldap {:?}: needs a base-dn — without it there is no DN to bind as",
                    d.server
                );
            }
        }
        if let Some(g) = &self.system.aaa.default_group {
            if !self.system.groups.iter().any(|x| &x.name == g) {
                bail!("system aaa default-group {g:?}: no such permission group");
            }
        }
        for l in &self.system.logins {
            if let Some(secret) = &l.totp {
                crate::aaa::base32_decode(secret)
                    .with_context(|| format!("system login {:?} totp", l.username))?;
            }
        }
        // Steering: a policy that names an uplink this box does not have would
        // silently never steer anything, which is the worst way for it to fail.
        let mut seen_pol = std::collections::BTreeSet::new();
        for p in &self.multiwan.policies {
            if !seen_pol.insert(p.name.as_str()) {
                bail!("multiwan policy {:?}: declared twice", p.name);
            }
            if p.uplinks.is_empty() {
                bail!(
                    "multiwan policy {:?}: needs at least one uplink to prefer",
                    p.name
                );
            }
            for want in &p.uplinks {
                if !self.multiwan.uplinks.iter().any(|u| &u.interface == want) {
                    bail!(
                        "multiwan policy {:?}: uplink {want:?} is not a configured uplink",
                        p.name
                    );
                }
            }
            if (p.source_port.is_some() || p.destination_port.is_some()) && p.proto.is_none() {
                bail!(
                    "multiwan policy {:?}: a port needs a `proto` to key it (tcp or udp)",
                    p.name
                );
            }
            for (what, v) in [("source", &p.source), ("destination", &p.destination)] {
                if let Some(a) = v {
                    validate_cidr_or_ip(a)
                        .with_context(|| format!("multiwan policy {:?} {what}", p.name))?;
                }
            }
            // Preferring a path that cannot be measured means the preference can
            // never be acted on — the daemon has nothing to compare.
            if p.strict
                && !p
                    .uplinks
                    .iter()
                    .filter_map(|i| self.multiwan.uplinks.iter().find(|u| &u.interface == i))
                    .any(|u| u.check.has_sla())
            {
                bail!(
                    "multiwan policy {:?} is strict, but none of its uplinks has an SLA \
                     threshold to be strict about",
                    p.name
                );
            }
        }
        // Policy routing: a rule that redirects nowhere, or matches a port
        // without saying which protocol's port, is a rule the kernel will
        // refuse — better to say so here, with the name in hand.
        let mut seen_pbr = std::collections::BTreeSet::new();
        for r in &self.policy.routes {
            if !seen_pbr.insert(r.name.as_str()) {
                bail!("policy route {:?}: declared twice", r.name);
            }
            if r.table == 0 {
                bail!(
                    "policy route {:?}: needs a table — a rule that redirects nowhere is not a policy route",
                    r.name
                );
            }
            // 0 and 253-255 are the kernel's own (unspec/default/main/local).
            if (253..=255).contains(&r.table) {
                bail!(
                    "policy route {:?}: table {} is the kernel's own (253-255)",
                    r.name,
                    r.table
                );
            }
            if (r.source_port.is_some() || r.destination_port.is_some()) && r.proto.is_none() {
                bail!(
                    "policy route {:?}: a port needs a `proto` to key it (tcp or udp)",
                    r.name
                );
            }
            for (what, v) in [("source", &r.source), ("destination", &r.destination)] {
                if let Some(a) = v {
                    validate_cidr_or_ip(a)
                        .with_context(|| format!("policy route {:?} {what}", r.name))?;
                }
            }
            // Both ends in one rule is fine; both *families* in one rule is not,
            // because a kernel rule belongs to one.
            if let (Some(s), Some(d)) = (&r.source, &r.destination) {
                if s.contains(':') != d.contains(':') {
                    bail!(
                        "policy route {:?}: source and destination are different address families",
                        r.name
                    );
                }
            }
        }
        for r in &self.protocols.statics {
            check_vrf_ref(&r.vrf, &format!("static route {:?}", r.prefix))?;
        }
        // Routing-table ids the Multi-WAN uplinks own (explicit `table` or the
        // derived `WAN_TABLE_BASE + idx`) — a VRF table must not collide.
        let wan_tables: HashSet<u32> = self
            .multiwan
            .uplinks
            .iter()
            .enumerate()
            .map(|(idx, u)| self.multiwan.table_for(idx, u))
            .collect();
        // VRF definitions: a table id (unique, in range, not a WAN table) and
        // import/export naming declared filters.
        let mut seen_vrf_tables: HashSet<u32> = HashSet::new();
        for v in &self.protocols.vrfs {
            if v.name.is_empty() {
                bail!("protocols vrf: a vrf needs a name");
            }
            // 0 and 253–255 (default/main/local) are kernel-reserved.
            if !(1..=252).contains(&v.table) {
                bail!(
                    "protocols vrf {:?}: table {} out of range (1–252; 0 and 253–255 are reserved)",
                    v.name,
                    v.table
                );
            }
            if !seen_vrf_tables.insert(v.table) {
                bail!(
                    "protocols vrf {:?}: table {} is used by more than one vrf",
                    v.name,
                    v.table
                );
            }
            if wan_tables.contains(&v.table) {
                bail!(
                    "protocols vrf {:?}: table {} collides with a multiwan uplink routing table",
                    v.name,
                    v.table
                );
            }
            if let Some(f) = &v.import {
                check_filter_ref(f, &format!("vrf {:?} import", v.name))?;
            }
            if let Some(f) = &v.export {
                check_filter_ref(f, &format!("vrf {:?} export", v.name))?;
            }
        }
        // Global export / import redistribution filters must name declared filters.
        if let Some(export) = &self.protocols.export {
            for (proto, name) in [
                ("kernel", &export.kernel),
                ("bgp", &export.bgp),
                ("ospf", &export.ospf),
                ("rip", &export.rip),
                ("ripng", &export.ripng),
                ("babel", &export.babel),
                ("isis", &export.isis),
            ] {
                if let Some(name) = name {
                    check_filter_ref(name, &format!("export {proto}"))?;
                }
            }
        }
        for (proto, name) in &self.protocols.import {
            if !IMPORT_PROTOCOLS.contains(&proto.as_str()) {
                bail!(
                    "protocols import: unknown protocol {proto:?} (expected one of {IMPORT_PROTOCOLS:?})"
                );
            }
            check_filter_ref(name, &format!("import {proto}"))?;
        }
        if let Some(bgp) = &self.protocols.bgp {
            check_vrf_ref(&bgp.vrf, "bgp vrf")?;
            if bgp.local_as == 0 {
                bail!("protocols bgp: local-as must be non-zero");
            }
            if let Some(rid) = &bgp.router_id {
                validate_ipv4(rid).with_context(|| "protocols bgp router-id")?;
            }
            if let Some(cid) = &bgp.cluster_id {
                validate_ipv4(cid).with_context(|| "protocols bgp cluster-id (dotted quad)")?;
            }
            for net in &bgp.network {
                validate_cidr_or_ip(net)
                    .with_context(|| format!("protocols bgp network {net:?}"))?;
            }
            // Communities attached to every originated route are shape-checked
            // through the same helper the filter rules use.
            for c in bgp
                .community
                .iter()
                .chain(&bgp.large_community)
                .chain(&bgp.ext_community)
            {
                validate_community(c).with_context(|| "protocols bgp community")?;
            }
            for a in &bgp.aggregate {
                validate_cidr_or_ip(&a.prefix)
                    .with_context(|| format!("protocols bgp aggregate {:?}", a.prefix))?;
            }
            for r in &bgp.roa {
                validate_cidr_or_ip(&r.prefix)
                    .with_context(|| format!("protocols bgp roa {:?}", r.prefix))?;
                if r.origin_as == 0 {
                    bail!(
                        "protocols bgp roa {:?}: origin-as must be non-zero",
                        r.prefix
                    );
                }
                if let Some(ml) = r.max_length {
                    if ml > 128 {
                        bail!(
                            "protocols bgp roa {:?}: max-length {ml} out of range (0–128)",
                            r.prefix
                        );
                    }
                }
            }
            if let Some(rtr) = &bgp.rtr {
                if rtr.server.is_empty() {
                    bail!("protocols bgp rtr: server (host:port) must be set");
                }
                validate_endpoint(&rtr.server).with_context(|| "protocols bgp rtr server")?;
            }
            for n in &bgp.neighbors {
                validate_bgp_neighbor(n, &filter_names)?;
            }
        }
        // Routing policy (VyOS `[policy]`): prefix-lists + route-maps. Validate
        // the prefix-lists, then the route-maps (whose `match prefix-list` must
        // name a declared list).
        let prefix_list_names: HashSet<&str> = self
            .policy
            .prefix_lists
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        let mut seen_pl = HashSet::new();
        for pl in &self.policy.prefix_lists {
            if pl.name.is_empty() {
                bail!("policy prefix-list: a name must not be empty");
            }
            if !seen_pl.insert(pl.name.as_str()) {
                bail!("policy prefix-list: duplicate list {:?}", pl.name);
            }
            for e in &pl.entries {
                validate_cidr_or_ip(&e.prefix)
                    .with_context(|| format!("policy prefix-list {:?} prefix", pl.name))?;
                let maxlen = if e.prefix.contains(':') { 128 } else { 32 };
                for (which, b) in [("ge", e.ge), ("le", e.le)] {
                    if let Some(b) = b {
                        if b > maxlen {
                            bail!(
                                "policy prefix-list {:?}: {which} {b} exceeds the max prefix length {maxlen}",
                                pl.name
                            );
                        }
                    }
                }
                if let (Some(ge), Some(le)) = (e.ge, e.le) {
                    if ge > le {
                        bail!(
                            "policy prefix-list {:?}: ge {ge} must be <= le {le}",
                            pl.name
                        );
                    }
                }
            }
        }
        let mut seen_rm = HashSet::new();
        for rm in &self.policy.route_maps {
            if rm.name.is_empty() {
                bail!("policy route-map: a name must not be empty");
            }
            if !seen_rm.insert(rm.name.as_str()) {
                bail!("policy route-map: duplicate route-map {:?}", rm.name);
            }
            for rule in &rm.rules {
                if let Some(pl) = &rule.match_prefix_list {
                    if !prefix_list_names.contains(pl.as_str()) {
                        bail!(
                            "policy route-map {:?}: match prefix-list {pl:?} is not a declared policy prefix-list",
                            rm.name
                        );
                    }
                }
            }
            validate_filter(rm)?;
        }
        if let Some(ospf) = &self.protocols.ospf {
            if let Some(area) = &ospf.area {
                validate_ipv4(area).with_context(|| "protocols ospf area (dotted quad)")?;
            }
            for i in &ospf.interface {
                if let Some(area) = &i.area {
                    validate_ipv4(area)
                        .with_context(|| format!("protocols ospf interface {:?} area", i.name))?;
                }
            }
            for (which, areas) in [
                ("stub-areas", &ospf.stub_areas),
                ("nssa-areas", &ospf.nssa_areas),
                ("totally-stubby-areas", &ospf.totally_stubby_areas),
                ("totally-nssa-areas", &ospf.totally_nssa_areas),
                ("nssa-default-areas", &ospf.nssa_default_areas),
            ] {
                for a in areas {
                    validate_ipv4(a)
                        .with_context(|| format!("protocols ospf {which} (dotted quad)"))?;
                }
            }
            if let Some(at) = &ospf.auth_type {
                if !matches!(at.as_str(), "none" | "text" | "md5") {
                    bail!(
                        "protocols ospf auth-type {at:?}: expected \"none\", \"text\" or \"md5\""
                    );
                }
            }
            validate_ospf_network_type(ospf.network_type.as_deref(), "ospf")?;
            // Timers: a Hello ≥ 1s, and a Dead strictly greater than the Hello
            // (a Dead ≤ Hello would expire a neighbour before its first Hello).
            if ospf.hello_interval == Some(0) {
                bail!("protocols ospf hello-interval must be >= 1 second");
            }
            if let (Some(hello), Some(dead)) = (ospf.hello_interval, ospf.dead_interval) {
                if dead <= hello as u32 {
                    bail!(
                        "protocols ospf dead-interval {dead} must be greater than hello-interval {hello}"
                    );
                }
            }
            check_vrf_ref(&ospf.vrf, "ospf vrf")?;
        }
        if let Some(o) = &self.protocols.ospf3 {
            if let Some(area) = &o.area {
                validate_ipv4(area).with_context(|| "protocols ospf3 area (dotted quad)")?;
            }
            for i in &o.interface {
                if let Some(area) = &i.area {
                    validate_ipv4(area)
                        .with_context(|| format!("protocols ospf3 interface {:?} area", i.name))?;
                }
            }
            validate_ospf_network_type(o.network_type.as_deref(), "ospf3")?;
        }
        // RIP / RIPng / Babel: VRF references, and the RIPng-only restriction that
        // it accepts none of the RIP/Babel extras (Wren's Ripng lacks them).
        if let Some(rip) = &self.protocols.rip {
            check_vrf_ref(&rip.vrf, "rip vrf")?;
        }
        if let Some(ripng) = &self.protocols.ripng {
            if ripng.bfd
                || ripng.vrf.is_some()
                || !ripng.network.is_empty()
                || ripng.router_id.is_some()
            {
                bail!(
                    "protocols ripng: bfd / vrf / network / router-id are not supported for RIPng"
                );
            }
        }
        if let Some(babel) = &self.protocols.babel {
            check_vrf_ref(&babel.vrf, "babel vrf")?;
            for net in &babel.network {
                // Babel is dual-stack; accept an IPv4 or IPv6 prefix.
                route_prefix_family(net)
                    .with_context(|| format!("protocols babel network {net:?}"))?;
            }
            if let Some(rid) = &babel.router_id {
                validate_ipv4(rid).with_context(|| "protocols babel router-id (dotted quad)")?;
            }
        }
        if let Some(isis) = &self.protocols.isis {
            if let Some(lvl) = &isis.level {
                if !matches!(lvl.as_str(), "1" | "2" | "1-2") {
                    bail!("protocols isis level {lvl:?}: expected \"1\", \"2\" or \"1-2\"");
                }
            }
            if let Some(nt) = &isis.network_type {
                if nt != "broadcast" && nt != "point-to-point" {
                    bail!(
                        "protocols isis network-type {nt:?}: expected \"broadcast\" or \"point-to-point\""
                    );
                }
            }
            if let Some(p) = isis.priority {
                if p > 127 {
                    bail!("protocols isis priority {p} out of range (0–127)");
                }
            }
            if isis.hello_interval == Some(0) {
                bail!("protocols isis hello-interval must be >= 1 second");
            }
            // Catch a mistyped scheme or a keyless one here: the daemon would refuse
            // its whole config, so an IS-IS instance that looked committed would come
            // up with no routing at all.
            if let Some(at) = &isis.auth_type {
                if !matches!(at.as_str(), "none" | "text" | "hmac-md5" | "hmac-sha256") {
                    bail!(
                        "protocols isis auth-type {at:?}: expected \"none\", \"text\", \
                         \"hmac-md5\" or \"hmac-sha256\""
                    );
                }
                if at != "none" && isis.auth_key.as_deref().unwrap_or("").is_empty() {
                    bail!("protocols isis auth-type {at:?} requires a non-empty auth-key");
                }
            }
            check_vrf_ref(&isis.vrf, "isis vrf")?;
        }
        for v in &self.protocols.vrrp {
            if v.interface.is_empty() {
                bail!("protocols vrrp: interface must be set");
            }
            if v.vrid == 0 {
                bail!("protocols vrrp {:?}: vrid must be 1–255", v.name);
            }
            // Either family. VRRP over IPv6 is RFC 5798 and the daemon speaks it;
            // refusing it here made a valid dual-stack pair unconfigurable, which
            // is the commonest shape on a firewall with tagged segments.
            let mut families = std::collections::BTreeSet::new();
            for addr in &v.virtual_address {
                let ip: std::net::IpAddr = addr.parse().with_context(|| {
                    format!(
                        "protocols vrrp {:?}: virtual-address {addr:?} is not an IP address",
                        v.name
                    )
                })?;
                families.insert(ip.is_ipv6());
            }
            // One virtual router carries one family: the advertisement itself is
            // sent over one, and a group holding both would be two routers wearing
            // one name — which is what a second `vrid` is for.
            if families.len() > 1 {
                bail!(
                    "protocols vrrp {:?}: virtual-address mixes IPv4 and IPv6 —                      give each family its own group and vrid",
                    v.name
                );
            }
            // The address link, when it is named, has to be one this appliance has.
            if let Some(ai) = &v.address_interface {
                if !self.interfaces.iter().any(|i| &i.name == ai) {
                    bail!(
                        "protocols vrrp {:?}: address-interface {ai:?} is not a configured interface",
                        v.name
                    );
                }
            }
        }
        // BFD global defaults: the authentication type, when set.
        if let Some(bfd) = &self.protocols.bfd {
            if let Some(t) = &bfd.auth_type {
                if !BFD_AUTH_TYPES.contains(&t.as_str()) {
                    bail!("protocols bfd auth-type {t:?} not one of {BFD_AUTH_TYPES:?}");
                }
            }
            if bfd.detect_mult == Some(0) {
                bail!("protocols bfd detect-mult must be >= 1");
            }
            if bfd.min_tx == Some(0) {
                bail!("protocols bfd min-tx must be >= 1 ms");
            }
            if bfd.min_rx == Some(0) {
                bail!("protocols bfd min-rx must be >= 1 ms");
            }
        }
        // Multicast: interface roles and IGMP versions.
        if let Some(mc) = &self.protocols.multicast {
            for i in &mc.interfaces {
                if i.name.is_empty() {
                    bail!("protocols multicast interface: name must be set");
                }
                if let Some(role) = &i.role {
                    if !MULTICAST_ROLES.contains(&role.as_str()) {
                        bail!(
                            "protocols multicast interface {:?}: role {role:?} not one of {MULTICAST_ROLES:?}",
                            i.name
                        );
                    }
                }
                if let Some(v) = i.igmp_version {
                    if v != 2 && v != 3 {
                        bail!(
                            "protocols multicast interface {:?}: igmp-version {v} must be 2 or 3",
                            i.name
                        );
                    }
                }
            }
            if let Some(v) = mc.igmp_version {
                if v != 2 && v != 3 {
                    bail!("protocols multicast igmp-version {v} must be 2 or 3");
                }
            }
        }

        // DNS forwarder: upstreams are IPs (v4 or v6); every serving interface
        // must be declared and carry a static address (the resolver binds its
        // stub listener to that IP); DNSSEC mode is one of the resolved values.
        let dns = &self.services.dns;
        for up in &dns.upstream {
            if validate_ipv4(up).is_err() && validate_ipv6(up).is_err() {
                bail!("services dns upstream {up:?}: not an IPv4 or IPv6 address");
            }
        }
        for iface in &dns.serve_on {
            match self.interfaces.iter().find(|i| &i.name == iface) {
                Some(i) => match i.address.as_deref() {
                    Some(addr) if addr != "dhcp" => {}
                    _ => bail!("services dns serve-on {iface:?}: interface needs a static address"),
                },
                None => bail!("services dns serve-on {iface:?}: not a declared interface"),
            }
        }
        if let Some(mode) = &dns.dnssec {
            if !matches!(mode.as_str(), "yes" | "no" | "allow-downgrade") {
                bail!(
                    "services dns dnssec {mode:?}: expected \"yes\", \"no\" or \"allow-downgrade\""
                );
            }
        }
        // Host-overrides map a name to a literal IP (v4 or v6); blocklist entries
        // are domain names. Serving overrides/blocklists needs a serve-on iface
        // (dnsmasq must have somewhere to listen).
        for (name, ip) in &dns.host_override {
            validate_host(name).with_context(|| "services dns host-override name")?;
            if validate_ipv4(ip).is_err() && validate_ipv6(ip).is_err() {
                bail!("services dns host-override {name:?}: {ip:?} is not an IPv4/IPv6 address");
            }
        }
        for domain in &dns.blocklist {
            validate_host(domain).with_context(|| "services dns blocklist")?;
        }
        if (!dns.host_override.is_empty() || !dns.blocklist.is_empty()) && dns.serve_on.is_empty() {
            bail!("services dns host-override/blocklist need at least one `serve-on` interface");
        }
        // local-domain is rendered into dnsmasq `local=/<domain>/` + `domain=`
        // directives, so it must be a plain domain-label sequence (no slash, no
        // whitespace) — validate_host enforces exactly that label charset.
        if let Some(dom) = &dns.local_domain {
            validate_host(dom).with_context(|| "services dns local-domain")?;
        }

        // NTP server: upstreams are IPs or hostnames; every serving interface
        // must be declared and carry a static address (its subnet is `allow`ed).
        let ntp = &self.services.ntp;
        for up in &ntp.upstream {
            validate_host(up).with_context(|| "services ntp upstream")?;
        }
        for iface in &ntp.serve_on {
            match self.interfaces.iter().find(|i| &i.name == iface) {
                Some(i) => match i.address.as_deref() {
                    Some(addr) if addr != "dhcp" => {}
                    _ => bail!("services ntp serve-on {iface:?}: interface needs a static address"),
                },
                None => bail!("services ntp serve-on {iface:?}: not a declared interface"),
            }
        }

        // LLDP: every listed interface must be a declared interface (no address
        // requirement — LLDP rides any link, addressed or not).
        for iface in &self.services.lldp.interface {
            if !self.interfaces.iter().any(|i| &i.name == iface) {
                bail!("services lldp interface {iface:?}: not a declared interface");
            }
        }

        // SNMP: the source `allow` clauses are IPv4/IPv6 CIDRs or bare IPs; the
        // agent listens on a net-snmp transport spec. Location/contact are opaque
        // strings (rendered quoted). The community itself is unconstrained (a
        // shared secret), but an empty one would be nonsensical.
        let snmp = &self.services.snmp;
        if let Some(c) = &snmp.community {
            if c.is_empty() {
                bail!("services snmp community: must not be empty");
            }
        }
        // `community` is rendered UNQUOTED into snmpd.conf (`rocommunity <community>
        // …`), so a newline injects a fresh directive — e.g. `rwcommunity`, turning
        // the read-only agent read-write — and whitespace splits it into extra
        // tokens. `listen` becomes the `agentaddress` transport spec. Reject any
        // control character, whitespace, quote or backslash in both (location and
        // contact are guarded separately below as they are rendered quoted).
        for (field, val) in [("community", &snmp.community), ("listen", &snmp.listen)] {
            if let Some(v) = val {
                if v.bytes()
                    .any(|b| b.is_ascii_control() || matches!(b, b' ' | b'\t' | b'"' | b'\\'))
                {
                    bail!(
                        "services snmp {field}: must not contain whitespace, a control \
                         character, quote or backslash"
                    );
                }
            }
        }
        // location/contact are rendered as quoted syslocation/syscontact lines in
        // snmpd.conf — a newline, quote or backslash could break out of the line.
        for (field, val) in [("location", &snmp.location), ("contact", &snmp.contact)] {
            if let Some(v) = val {
                if v.bytes().any(|b| matches!(b, b'\n' | b'\r' | b'"' | b'\\')) {
                    bail!("services snmp {field}: must not contain a newline, quote or backslash");
                }
            }
        }
        for src in &snmp.allow {
            if validate_cidr_or_ip(src).is_err() && validate_ipv6_cidr(src).is_err() {
                bail!("services snmp allow {src:?}: not an IPv4/IPv6 address or CIDR");
            }
        }
        if snmp.community.is_none() && !snmp.is_empty() {
            bail!("services snmp: a `community` is required to run the agent");
        }

        // SSH daemon: an optional non-default port (u16, so >0 by construction —
        // reject 0) and an optional listen-address that must be a real IP the box
        // could hold. The keys themselves live per-user under [[system.login]].
        let ssh = &self.services.ssh;
        if let Some(p) = ssh.port {
            if p == 0 {
                bail!("services ssh port: must be 1-65535");
            }
        }
        if let Some(addr) = &ssh.listen_address {
            if validate_ipv4(addr).is_err() && validate_ipv6(addr).is_err() {
                bail!("services ssh listen-address {addr:?}: not an IPv4/IPv6 address");
            }
        }

        // Local login accounts ([[system.login]]): a POSIX-ish username, single-line
        // OpenSSH keys (written verbatim into a per-user authorized_keys, so a
        // newline would inject a second key line), and a crypt(3) hashed password
        // (never plaintext — a value that is not `$id$salt$hash` is almost certainly
        // a plaintext password pasted by mistake, which we must refuse to store).
        let mut seen_users = std::collections::BTreeSet::new();
        for login in &self.system.logins {
            let u = &login.username;
            if !seen_users.insert(u.as_str()) {
                bail!("system login {u:?}: duplicate username");
            }
            let mut chars = u.chars();
            let ok_first = chars
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
            let ok_rest = chars.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
            if u.is_empty() || u.len() > 32 || !ok_first || !ok_rest {
                bail!(
                    "system login {u:?}: not a valid username \
                     (letter/underscore then letters/digits/-/_, max 32)"
                );
            }
            for key in &login.ssh_keys {
                let k = key.trim();
                if k.is_empty() || k.starts_with('#') {
                    bail!("system login {u} ssh-key: must be a non-empty OpenSSH key line");
                }
                if key.bytes().any(|b| matches!(b, b'\n' | b'\r')) {
                    bail!("system login {u} ssh-key: must not contain a newline");
                }
                if k.split_whitespace().count() < 2 {
                    bail!(
                        "system login {u} ssh-key {key:?}: not an OpenSSH key \
                         (expected `<type> <base64> [comment]`)"
                    );
                }
            }
            if let Some(h) = &login.hashed_password {
                // A crypt(3) hash is `$<id>$[params$]<salt>$<hash>` — at least three
                // `$`-separated non-empty fields after the leading `$`. Reject a bare
                // string (a plaintext password) or a `$`-less value.
                let looks_hashed = h.starts_with('$')
                    && h.split('$').filter(|s| !s.is_empty()).count() >= 3
                    && !h.bytes().any(|b| matches!(b, b'\n' | b'\r' | b':'));
                if !looks_hashed {
                    bail!(
                        "system login {u} hashed-password: must be a crypt(3) hash \
                         like `$6$salt$hash` (from `mkpasswd -m sha-512`), not a plaintext password"
                    );
                }
            }
        }

        // HA config sync ([system.config-sync]): each peer is a host or host:port
        // the config is pushed to; a shared secret is required to authenticate the
        // push (and to arm this box's receiving API), so peers without a secret are
        // a misconfiguration that would silently never sync.
        let cs = &self.system.config_sync;
        for peer in &cs.peers {
            validate_sync_peer(peer).map_err(|e| anyhow::anyhow!("system config-sync peer {e}"))?;
        }
        if !cs.peers.is_empty() {
            match &cs.secret {
                Some(s) if !s.is_empty() => {}
                _ => bail!("system config-sync: a `secret` is required to push to peers"),
            }
        }

        // HA conntrack sync ([system.conntrack-sync], C9): the eBPF conntrack table
        // is mirrored to each peer so established NAT flows survive a VRRP failover.
        // `listen` and every `peer` must be a host or host:port; the interval must
        // be a sane, non-zero cadence.
        let cts = &self.system.conntrack_sync;
        if let Some(listen) = &cts.listen {
            validate_sync_peer(listen)
                .map_err(|e| anyhow::anyhow!("system conntrack-sync listen {e}"))?;
        }
        for peer in &cts.peers {
            validate_sync_peer(peer)
                .map_err(|e| anyhow::anyhow!("system conntrack-sync peer {e}"))?;
        }
        if let Some(iv) = cts.interval {
            if iv == 0 || iv > 3600 {
                bail!("system conntrack-sync: interval {iv} must be 1..=3600 seconds");
            }
        }

        // mDNS reflector: every listed interface must be declared, and a reflector
        // needs at least two links to bridge between.
        let mdns = &self.services.mdns;
        for iface in &mdns.interface {
            if !self.interfaces.iter().any(|i| &i.name == iface) {
                bail!("services mdns interface {iface:?}: not a declared interface");
            }
        }
        if !mdns.interface.is_empty() && mdns.interface.len() < 2 {
            bail!("services mdns: a reflector needs at least two interfaces to bridge between");
        }

        // Dynamic DNS: a configured client needs a hostname; the watched interface
        // (if given) must be declared.
        let dd = &self.services.dyndns;
        if !dd.is_empty() && dd.hostname.is_none() {
            bail!("services dyndns: a `hostname` is required");
        }
        if let Some(h) = &dd.hostname {
            validate_host(h).with_context(|| "services dyndns hostname")?;
        }
        if let Some(s) = &dd.server {
            validate_host(s).with_context(|| "services dyndns server")?;
        }
        // login/password are rendered into ddclient.conf lines — a newline or a
        // single-quote could smuggle another directive.
        for (field, val) in [("login", &dd.login), ("password", &dd.password)] {
            if let Some(v) = val {
                if v.bytes().any(|b| matches!(b, b'\n' | b'\r' | b'\'')) {
                    bail!("services dyndns {field}: must not contain a newline or single-quote");
                }
            }
        }
        if let Some(iface) = &dd.interface {
            if !self.interfaces.iter().any(|i| &i.name == iface) {
                bail!("services dyndns interface {iface:?}: not a declared interface");
            }
        }

        // DHCP relay: upstream servers are IPv4; every relay interface must be
        // declared and must NOT also run a local DHCP server (a link is either
        // served locally or relayed upstream, never both).
        let relay = &self.services.dhcp_relay;
        if !relay.is_empty() {
            if relay.server.is_empty() && relay.server6.is_empty() {
                bail!(
                    "services dhcp-relay: at least one upstream `server` (IPv4) or `server6` (IPv6) is required"
                );
            }
            if relay.interface.is_empty() {
                bail!("services dhcp-relay: at least one `interface` to relay on is required");
            }
        }
        for srv in &relay.server {
            validate_ipv4(srv).with_context(|| "services dhcp-relay server")?;
        }
        for srv in &relay.server6 {
            validate_ipv6(srv).with_context(|| "services dhcp-relay server6")?;
        }
        let has_static =
            |a: &Option<String>| matches!(a.as_deref(), Some(x) if x != "dhcp" && x != "auto");
        for iface in &relay.interface {
            match self.interfaces.iter().find(|i| &i.name == iface) {
                Some(i) if i.dhcp_server.is_some() => bail!(
                    "services dhcp-relay interface {iface:?}: already runs a DHCP server (a link is either served or relayed, not both)"
                ),
                // The relay (dnsmasq) listens on the interface's own address and
                // stamps it as the relay source, so a client-facing relay link needs
                // a static address in each relayed family (a `dhcp`/`auto`/unset link
                // cannot relay that family). v4 relay ⇒ needs `address`; v6 relay ⇒
                // needs `address6`.
                Some(i) => {
                    if !relay.server.is_empty() && !has_static(&i.address) {
                        bail!(
                            "services dhcp-relay interface {iface:?}: needs a static `address` to relay IPv4 (stamped as the DHCP giaddr)"
                        );
                    }
                    if !relay.server6.is_empty() && !has_static(&i.address6) {
                        bail!(
                            "services dhcp-relay interface {iface:?}: needs a static `address6` to relay IPv6"
                        );
                    }
                }
                None => bail!("services dhcp-relay interface {iface:?}: not a declared interface"),
            }
        }

        // L7 reverse proxy (roadmap C22): each frontend needs a safe name, a
        // valid port, at least one host:port backend, and — when TLS-terminating
        // — a certificate that names a declared PKI leaf (or ACME). Names and
        // ports must not collide across frontends.
        let mut seen_proxy = HashSet::new();
        let mut seen_proxy_port = HashSet::new();
        for rp in &self.services.reverse_proxy {
            if rp.name.is_empty() {
                bail!("services reverse-proxy: a frontend name must not be empty");
            }
            if !rp
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
            {
                bail!(
                    "services reverse-proxy {:?}: name may only contain letters, digits, '-' and '_'",
                    rp.name
                );
            }
            if !seen_proxy.insert(rp.name.as_str()) {
                bail!("services reverse-proxy: duplicate frontend {:?}", rp.name);
            }
            if rp.port == Some(0) {
                bail!("services reverse-proxy {:?}: port 0 is not valid", rp.name);
            }
            if !seen_proxy_port.insert(rp.port()) {
                bail!(
                    "services reverse-proxy {:?}: port {} is already bound by another frontend",
                    rp.name,
                    rp.port()
                );
            }
            if rp.backends.is_empty() {
                bail!(
                    "services reverse-proxy {:?}: at least one `backend` (host:port) is required",
                    rp.name
                );
            }
            for b in &rp.backends {
                validate_endpoint(b)
                    .with_context(|| format!("services reverse-proxy {:?} backend", rp.name))?;
            }
            if let Some(cert) = &rp.certificate {
                let cert_ok =
                    cert == ACME_CA || self.pki.certificates.iter().any(|c| &c.name == cert);
                if !cert_ok {
                    bail!(
                        "services reverse-proxy {:?}: certificate {cert:?} is not a declared pki certificate",
                        rp.name
                    );
                }
            }
        }

        // UDP broadcast relay (roadmap C18): a relay needs a name nothing else
        // uses, a real port, and interfaces that exist. A relay naming an
        // interface the box does not have would bind nothing and carry nothing,
        // while `show` listed it as configured.
        let mut seen_relay = HashSet::new();
        for r in &self.services.broadcast_relay {
            if r.name.is_empty() {
                bail!("services broadcast-relay: a relay name must not be empty");
            }
            if !seen_relay.insert(r.name.as_str()) {
                bail!("services broadcast-relay: duplicate relay {:?}", r.name);
            }
            crate::relay::validate(r)?;
            for iface in &r.interface {
                if !self.interfaces.iter().any(|i| &i.name == iface) {
                    bail!(
                        "services broadcast-relay {:?}: {iface:?} is not a declared interface",
                        r.name
                    );
                }
            }
        }

        // Remote syslog (roadmap C12): a collector needs a reachable address and a
        // real port. A duplicate target is refused rather than deduped — two
        // identical `omfwd` actions would double every message at the collector,
        // and someone who wrote it twice meant two different collectors.
        let mut seen_syslog = HashSet::new();
        for t in &self.services.syslog.targets {
            if t.host.trim().is_empty() {
                bail!("services syslog: a target needs a `host`");
            }
            validate_host(&t.host).with_context(|| "services syslog target host")?;
            if t.port == Some(0) {
                bail!("services syslog target {:?}: port 0 is not valid", t.host);
            }
            let key = (t.host.as_str(), t.port.unwrap_or(DEFAULT_SYSLOG_PORT));
            if !seen_syslog.insert(key) {
                bail!("services syslog: duplicate target {}:{}", key.0, key.1);
            }
        }

        // Alert notifications (roadmap C23). The point of this block is to refuse
        // a configuration that LOOKS like it alerts and does not: half a mail
        // target is worse than none, because nobody goes looking for the alert
        // that never arrives.
        let alerts = &self.services.alerts;
        let mut seen_hook = HashSet::new();
        for url in &alerts.webhook {
            if !(url.starts_with("https://") || url.starts_with("http://")) {
                bail!("services alerts webhook {url:?}: must be an http(s) URL");
            }
            reject_config_token("services alerts webhook", url)?;
            if !seen_hook.insert(url.as_str()) {
                bail!("services alerts: duplicate webhook {url:?}");
            }
        }
        let mail = &alerts.mail;
        if !mail.is_empty() && !mail.is_deliverable() {
            bail!(
                "services alerts mail: both `to` and `relay` are required to send \
                 (got to={:?}, relay={:?})",
                mail.to,
                mail.relay
            );
        }
        if let Some(relay) = &mail.relay {
            validate_host(relay).with_context(|| "services alerts mail relay")?;
        }
        if mail.port == Some(0) {
            bail!("services alerts mail: port 0 is not valid");
        }
        for (field, addr) in [("to", &mail.to), ("from", &mail.from)] {
            if let Some(a) = addr {
                // Not a full RFC 5322 parse — just enough that msmtp gets an
                // address rather than a word, and that nothing can break out of
                // the rendered config line.
                if !a.contains('@') || a.starts_with('@') || a.ends_with('@') {
                    bail!("services alerts mail {field} {a:?}: not an email address");
                }
                reject_config_token(&format!("services alerts mail {field}"), a)?;
            }
        }
        if mail.password.is_some() && mail.user.is_none() {
            bail!("services alerts mail: a `password` without a `user` cannot authenticate");
        }
        if let Some(user) = &mail.user {
            reject_config_token("services alerts mail user", user)?;
        }
        if let Some(pw) = &mail.password {
            // A password may contain spaces; a newline or quote would still break
            // out of the rendered msmtp line.
            if pw
                .bytes()
                .any(|b| b.is_ascii_control() || matches!(b, b'"' | b'\\'))
            {
                bail!(
                    "services alerts mail password: must not contain a control \
                     character, quote or backslash"
                );
            }
        }
        // An authenticated submission over a cleartext link hands the relay
        // password to anyone on the path. Refusing is better than a warning
        // nobody reads.
        if mail.user.is_some() && mail.starttls == Some(false) {
            bail!(
                "services alerts mail: refusing to send SMTP credentials without \
                 STARTTLS — remove `user`/`password`, or leave `starttls` on"
            );
        }

        // Intrusion detection (roadmap C11). Everything here is refused at commit
        // rather than discovered at run time, because the failure is silent in the
        // worst way: Suricata that will not start, or starts with no rules, leaves
        // an operator believing the box is watched when nothing is.
        // Management groups. Refused rather than warned about: an account
        // pointing at a group that does not exist would be an account with no
        // management access, which reads from the configuration as though it had
        // some.
        let mut seen_group = HashSet::new();
        for g in &self.system.groups {
            validate_hostname(&g.name).with_context(|| format!("system group {:?}", g.name))?;
            if !seen_group.insert(g.name.as_str()) {
                bail!("duplicate system group {:?}", g.name);
            }
        }
        for login in &self.system.logins {
            if let Some(group) = &login.group {
                if !self.system.groups.iter().any(|g| &g.name == group) {
                    bail!(
                        "system login {:?}: group {group:?} is not declared — \
                         add `set system group {group} permission read-only` or \
                         read-write",
                        login.username
                    );
                }
            }
        }

        // C20 captive portal. Everything here is refused rather than warned
        // about, because each failure looks the same from the outside — a guest
        // zone with no way onto the network — and none of them is visible until
        // somebody is standing there with a laptop.
        let portal = &self.services.portal;
        if let Some(zone) = &portal.zone {
            if !self
                .interfaces
                .iter()
                .any(|i| i.zone.as_deref() == Some(zone))
            {
                bail!(
                    "services portal zone {zone:?}: no interface is in that zone, \
                     so there is nobody to hold at the gate"
                );
            }
            // The portal binds the appliance's address in the gated zone and
            // announces it in DHCP option 114. Without a static address there is
            // nothing to bind and nothing to announce — and the gate would close
            // the zone around a page nobody can reach.
            let addressed = self
                .interfaces
                .iter()
                .any(|i| i.zone.as_deref() == Some(zone) && !i.disabled && i.address.is_some());
            if !addressed {
                bail!(
                    "services portal zone {zone:?}: needs an enabled interface with a \
                     static address — that address is what the portal listens on and \
                     what DHCP option 114 points clients at"
                );
            }
            if let Some(pass) = &portal.passphrase {
                if pass.trim().is_empty() {
                    bail!(
                        "services portal passphrase: empty — omit it for a \
                         click-through portal rather than setting nothing"
                    );
                }
                reject_config_token("services portal passphrase", pass)?;
            }
            if let Some(msg) = &portal.message {
                validate_description(msg).context("services portal message")?;
            }
            if let Some(secs) = portal.session_timeout {
                // The agent's own ceiling. Refusing here beats having every login
                // silently granted a shorter session than the config promises.
                if secs == 0 || secs > 86_400 {
                    bail!(
                        "services portal session-timeout {secs}: must be 1..=86400 \
                         seconds — an admission that outlives the visit is an access \
                         nobody remembers granting"
                    );
                }
            }
            if let Some(port) = portal.port {
                if port == 0 {
                    bail!("services portal port 0: not a port");
                }
            }
        }

        // C18 NAT-PMP. Both zones are refused rather than warned about: a wrong
        // one here means either a daemon nobody can reach or — worse — mappings
        // opened on the wrong zone, and neither shows up until somebody's
        // console cannot connect.
        let pm = &self.services.port_mapping;
        if let Some(zone) = &pm.zone {
            let Some(wan) = &pm.wan_zone else {
                bail!(
                    "services port-mapping: needs `wan-zone` — a mapping has to be \
                     opened on some zone, and opening it on all of them would open \
                     the port on the LAN too"
                );
            };
            if wan == zone {
                bail!(
                    "services port-mapping: zone and wan-zone are both {zone:?}; \
                     that maps a port on the very zone the request came from"
                );
            }
            for (what, z) in [("zone", zone), ("wan-zone", wan)] {
                let addressed = self
                    .interfaces
                    .iter()
                    .any(|i| i.zone.as_deref() == Some(z) && !i.disabled && i.address.is_some());
                if !addressed {
                    bail!(
                        "services port-mapping {what} {z:?}: needs an enabled interface \
                         with a static address"
                    );
                }
            }
            if let Some(secs) = pm.max_lifetime {
                // The agent's own ceiling. Refusing here beats granting a client
                // less than the configuration promised it.
                if secs == 0 || secs > 86_400 {
                    bail!(
                        "services port-mapping max-lifetime {secs}: must be 1..=86400 \
                         seconds — an inbound port that outlives what asked for it is \
                         a hole nobody can account for"
                    );
                }
            }
        }

        let ids = &self.services.ids;
        if !ids.is_empty() {
            let mut seen_iface = HashSet::new();
            for name in &ids.interfaces {
                // Deliberately NOT required to be a declared interface: an
                // appliance can perfectly well watch a link whose addressing it
                // does not own, and a check against the config would refuse that.
                validate_iface_name(name).with_context(|| "services ids interface")?;
                if !seen_iface.insert(name.as_str()) {
                    bail!("services ids: interface {name:?} is watched twice");
                }
            }
            for net in &ids.home_net {
                validate_cidr_or_ip(net).with_context(|| "services ids home-net")?;
            }
            if ids.rules.is_empty() && ids.rulesets.is_empty() {
                bail!(
                    "services ids: no rules — add `rule` or `ruleset`, or remove \
                     the interfaces; a detector with no rules detects nothing"
                );
            }
            let mut seen_sid = HashSet::new();
            for rule in &ids.rules {
                let sid = validate_ids_rule(rule)?;
                if !seen_sid.insert(sid) {
                    // Suricata refuses to load a duplicate sid at all, so this
                    // would take down the whole ruleset, not just one rule.
                    bail!("services ids: duplicate rule sid {sid}");
                }
            }
            let mut seen_set = HashSet::new();
            for path in &ids.rulesets {
                if !path.starts_with('/') {
                    bail!(
                        "services ids ruleset {path:?}: must be an absolute path \
                         (the detector's working directory is not the operator's)"
                    );
                }
                reject_config_token("services ids ruleset", path)?;
                if !seen_set.insert(path.as_str()) {
                    bail!("services ids: duplicate ruleset {path:?}");
                }
            }
            for entry in &ids.never_block {
                validate_cidr_or_ip(entry).with_context(|| "services ids never-block")?;
            }
            if let Some(sev) = ids.block_severity {
                // Suricata's own range. A ceiling of 0 blocks nothing while
                // looking switched on, which is the failure this whole block of
                // validation exists to prevent.
                if !(1..=4).contains(&sev) {
                    bail!(
                        "services ids block-severity {sev}: must be 1..=4 \
                         (1 is the most severe)"
                    );
                }
            }
            if ids.block_duration == Some(0) {
                bail!("services ids block-duration: 0 seconds is not a block");
            }
            if !ids.blocks_on_alert()
                && (ids.block_severity.is_some()
                    || ids.block_duration.is_some()
                    || !ids.never_block.is_empty())
            {
                bail!(
                    "services ids: block-severity/block-duration/never-block have \
                     no effect without `block-on-alert true`"
                );
            }
            if ids.blocks_on_alert() && ids.never_block.is_empty() {
                // A warning, not a refusal: which addresses must stay reachable
                // is genuinely the operator's call, and some boxes have no
                // management network to protect. But nobody discovers they needed
                // this before they needed it.
                eprintln!(
                    "warning: services ids: block-on-alert is on with no \
                     `never-block` — an alert on your management network will \
                     block your own way in. Blocks do expire (after {}s).",
                    ids.block_duration()
                );
            }
        }

        // Multi-WAN (roadmap C6): every uplink must name a declared interface,
        // no interface or routing-table id may be shared between uplinks, table
        // ids must avoid the kernel's reserved tables, gateways are IPv4 (or
        // `dhcp`) and health-check targets are IPv4. A single uplink is allowed
        // (it just has nothing to fail over to) — no artificial floor.
        let mw = &self.multiwan;
        if mw.uplinks.is_empty() && !mw.mode.is_default() {
            bail!("multiwan mode set but no uplinks defined");
        }
        let mut seen_if: HashSet<&str> = HashSet::new();
        let mut seen_tbl: HashSet<u32> = HashSet::new();
        for (idx, u) in mw.uplinks.iter().enumerate() {
            if !self.interfaces.iter().any(|i| i.name == u.interface) {
                bail!(
                    "multiwan uplink {:?}: not a declared interface",
                    u.interface
                );
            }
            if !seen_if.insert(u.interface.as_str()) {
                bail!(
                    "multiwan uplink {:?}: an interface may back only one uplink",
                    u.interface
                );
            }
            let tbl = mw.table_for(idx, u);
            // 0 = unspec, 253 = default, 254 = main, 255 = local — kernel-reserved.
            if matches!(tbl, 0 | 253 | 254 | 255) {
                bail!(
                    "multiwan uplink {:?}: table {tbl} is reserved (local/main/default)",
                    u.interface
                );
            }
            if !seen_tbl.insert(tbl) {
                bail!(
                    "multiwan uplink {:?}: routing-table {tbl} is used by more than one uplink",
                    u.interface
                );
            }
            if let Some(w) = u.weight {
                if w == 0 {
                    bail!("multiwan uplink {:?}: weight must be non-zero", u.interface);
                }
            }
            if let Some(gw) = &u.gateway {
                if gw != "dhcp" {
                    validate_ipv4(gw)
                        .with_context(|| format!("multiwan uplink {:?} gateway", u.interface))?;
                }
            }
            for t in &u.check.targets {
                validate_ipv4(t).with_context(|| {
                    format!("multiwan uplink {:?} health-check target", u.interface)
                })?;
            }
            if u.check.interval == Some(0) {
                bail!(
                    "multiwan uplink {:?}: health-check interval must be >= 1 second",
                    u.interface
                );
            }
            if u.check.timeout == Some(0) {
                bail!(
                    "multiwan uplink {:?}: health-check timeout must be >= 1 second",
                    u.interface
                );
            }
        }

        // VPN / IPsec (roadmap C2): a policy-based IKEv2 site-to-site tunnel.
        // Names are unique + section-key-safe; endpoints are IPv4; the traffic
        // selectors are IPv4 CIDRs; a PSK is mandatory; the IKE version,
        // start-action and proposals come from the accepted sets/charset (all
        // three are rendered verbatim into swanctl.conf, so they are a security
        // boundary — a value must not smuggle a config line).
        let mut seen_vpn: HashSet<&str> = HashSet::new();
        for c in &self.vpn.ipsec {
            if c.name.is_empty() {
                bail!("vpn ipsec: a connection name must not be empty");
            }
            if !c
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                bail!(
                    "vpn ipsec {:?}: name may only contain letters, digits, '-' and '_'",
                    c.name
                );
            }
            if !seen_vpn.insert(c.name.as_str()) {
                bail!("vpn ipsec: duplicate connection {:?}", c.name);
            }
            validate_ipv4(&c.local).with_context(|| format!("vpn ipsec {:?} local", c.name))?;
            validate_ipv4(&c.remote).with_context(|| format!("vpn ipsec {:?} remote", c.name))?;
            validate_cidr_or_ip(&c.local_subnet)
                .with_context(|| format!("vpn ipsec {:?} local-subnet", c.name))?;
            validate_cidr_or_ip(&c.remote_subnet)
                .with_context(|| format!("vpn ipsec {:?} remote-subnet", c.name))?;
            if c.psk.is_empty() {
                bail!("vpn ipsec {:?}: psk is required", c.name);
            }
            if c.psk.len() < 8 {
                bail!("vpn ipsec {:?}: psk must be at least 8 characters", c.name);
            }
            // The PSK is rendered inside double quotes in the secrets file — a
            // quote or a newline would break out of it.
            if c.psk.bytes().any(|b| b == b'"' || b == b'\n' || b == b'\r') {
                bail!(
                    "vpn ipsec {:?}: psk must not contain a quote or newline",
                    c.name
                );
            }
            if let Some(v) = c.ike_version {
                if v != 1 && v != 2 {
                    bail!("vpn ipsec {:?}: ike-version {v} must be 1 or 2", c.name);
                }
            }
            if let Some(sa) = &c.start_action {
                if !matches!(sa.as_str(), "start" | "trap" | "none") {
                    bail!(
                        "vpn ipsec {:?}: start-action {sa:?} must be start|trap|none",
                        c.name
                    );
                }
            }
            if let Some(p) = &c.ike_proposal {
                validate_ipsec_proposal(p)
                    .with_context(|| format!("vpn ipsec {:?} ike-proposal", c.name))?;
            }
            if let Some(p) = &c.esp_proposal {
                validate_ipsec_proposal(p)
                    .with_context(|| format!("vpn ipsec {:?} esp-proposal", c.name))?;
            }
            if let Some(id) = &c.local_id {
                validate_ipsec_id(id)
                    .with_context(|| format!("vpn ipsec {:?} local-id", c.name))?;
            }
            if let Some(id) = &c.remote_id {
                validate_ipsec_id(id)
                    .with_context(|| format!("vpn ipsec {:?} remote-id", c.name))?;
            }
        }

        // vpn wireguard (roadmap C1): each tunnel names a `type = "wireguard"`
        // interface and carries its private key, listen port and peers (the keys
        // are a security boundary — rendered verbatim into the interface's
        // `.netdev`). Names are unique and must reference a declared wireguard
        // interface; conversely, every wireguard interface must have exactly one
        // tunnel (its private key lives here, not on the interface).
        let mut seen_wg: HashSet<&str> = HashSet::new();
        for t in &self.vpn.wireguard {
            if !seen_wg.insert(t.name.as_str()) {
                bail!("vpn wireguard: duplicate tunnel {:?}", t.name);
            }
            match self.interfaces.iter().find(|i| i.name == t.name) {
                Some(i) if i.is_wireguard() => {}
                Some(_) => bail!(
                    "vpn wireguard {:?}: interface {:?} is not type=wireguard",
                    t.name,
                    t.name
                ),
                None => bail!(
                    "vpn wireguard {:?}: no such interface (declare `interface {} type wireguard` first)",
                    t.name,
                    t.name
                ),
            }
            if t.private_key.is_empty() {
                bail!("vpn wireguard {:?}: private-key is required", t.name);
            }
            validate_wg_key(&t.private_key)
                .with_context(|| format!("vpn wireguard {:?} private-key", t.name))?;
            if t.listen_port == Some(0) {
                bail!("vpn wireguard {:?}: listen-port 0 is not valid", t.name);
            }
            for peer in &t.peers {
                validate_wg_key(&peer.public_key)
                    .with_context(|| format!("vpn wireguard {:?} peer public-key", t.name))?;
                for cidr in &peer.allowed_ips {
                    validate_cidr_or_ip(cidr)
                        .with_context(|| format!("vpn wireguard {:?} peer allowed-ips", t.name))?;
                }
                if let Some(ep) = &peer.endpoint {
                    validate_endpoint(ep)
                        .with_context(|| format!("vpn wireguard {:?} peer endpoint", t.name))?;
                }
                if let Some(psk) = &peer.preshared_key {
                    validate_wg_key(psk).with_context(|| {
                        format!("vpn wireguard {:?} peer preshared-key", t.name)
                    })?;
                }
            }
        }
        // Every `type = "wireguard"` interface needs its matching tunnel — the
        // private key lives under vpn, so a bare wireguard interface is incomplete.
        for iface in &self.interfaces {
            if iface.is_wireguard() && !seen_wg.contains(iface.name.as_str()) {
                bail!(
                    "interface {:?}: missing vpn wireguard {} private-key",
                    iface.name,
                    iface.name
                );
            }
        }

        // OpenConnect road-warrior server (roadmap C17): a single TLS VPN
        // service. The server cert must be a declared PKI leaf (or ACME); the
        // pool/routes/dns are IP formats; users carry a safe charset + secret
        // that lands in a line-based password file.
        if let Some(oc) = &self.vpn.openconnect {
            if oc.port == Some(0) {
                bail!("vpn openconnect: port 0 is not valid");
            }
            if !oc.pool.contains('/') {
                bail!(
                    "vpn openconnect: pool must be a CIDR with a prefix length (e.g. 10.99.0.0/24)"
                );
            }
            validate_cidr_or_ip(&oc.pool).with_context(
                || "vpn openconnect: pool must be an IPv4 CIDR (e.g. 10.99.0.0/24)",
            )?;
            for d in &oc.dns {
                if d.parse::<IpAddr>().is_err() {
                    bail!("vpn openconnect: dns {d:?} is not an IP address");
                }
            }
            for r in &oc.routes {
                validate_cidr_or_ip(r).with_context(|| format!("vpn openconnect: route {r:?}"))?;
            }
            if oc.default_route && !oc.routes.is_empty() {
                bail!(
                    "vpn openconnect: `default-route` (full tunnel) and an explicit `routes` \
                     list are mutually exclusive"
                );
            }
            // The server certificate must name a declared leaf (or ACME).
            let cert_ok = oc.certificate == ACME_CA
                || self
                    .pki
                    .certificates
                    .iter()
                    .any(|c| c.name == oc.certificate);
            if !cert_ok {
                bail!(
                    "vpn openconnect: certificate {:?} is not a declared pki certificate",
                    oc.certificate
                );
            }
            if let Some(z) = &oc.zone {
                if !zones_in_use.contains(z.as_str()) {
                    bail!("vpn openconnect: zone {z:?} has no interface");
                }
            }
            if oc.users.is_empty() {
                bail!(
                    "vpn openconnect: at least one user is required (a server with no users \
                     can accept no one)"
                );
            }
            let mut seen_user = HashSet::new();
            for u in &oc.users {
                if u.name.is_empty() {
                    bail!("vpn openconnect: a user name must not be empty");
                }
                if !u
                    .name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                {
                    bail!(
                        "vpn openconnect: user {:?} name may only contain letters, digits, \
                         '-', '_' and '.'",
                        u.name
                    );
                }
                if !seen_user.insert(u.name.as_str()) {
                    bail!("vpn openconnect: duplicate user {:?}", u.name);
                }
                if u.password.is_empty() {
                    bail!("vpn openconnect: user {:?} password is required", u.name);
                }
                // The password lands in a line-based password file — a control
                // char (newline) would forge extra entries.
                if u.password.chars().any(|c| c.is_control()) {
                    bail!(
                        "vpn openconnect: user {:?} password must not contain control characters",
                        u.name
                    );
                }
            }
        }

        // PKI (roadmap C19): local CAs, issued leaf certs, an ACME account.
        // Names are unique + store-subdir-safe; subject components and SANs carry
        // only a safe charset (they are rendered into openssl subject / extension
        // arguments, so they are an injection boundary); a leaf's `ca` must name a
        // declared CA or be "acme" (in which case an [pki.acme] account must
        // exist); key types / usages / challenges come from the accepted sets.
        let mut seen_ca: HashSet<&str> = HashSet::new();
        for ca in &self.pki.cas {
            if ca.name.is_empty() {
                bail!("pki ca: a CA name must not be empty");
            }
            if !ca
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                bail!(
                    "pki ca {:?}: name may only contain letters, digits, '-' and '_'",
                    ca.name
                );
            }
            if ca.name == ACME_CA {
                bail!("pki ca: {ACME_CA:?} is reserved for ACME-obtained certificates");
            }
            if !seen_ca.insert(ca.name.as_str()) {
                bail!("pki ca: duplicate CA {:?}", ca.name);
            }
            validate_subject_component(&ca.common_name)
                .with_context(|| format!("pki ca {:?} common-name", ca.name))?;
            if let Some(o) = &ca.organization {
                validate_subject_component(o)
                    .with_context(|| format!("pki ca {:?} organization", ca.name))?;
            }
            if let Some(kt) = &ca.key_type {
                if !matches!(kt.as_str(), "ec" | "rsa") {
                    bail!("pki ca {:?}: key-type {kt:?} must be ec or rsa", ca.name);
                }
            }
            if ca.validity_days == Some(0) {
                bail!("pki ca {:?}: validity-days must be greater than 0", ca.name);
            }
        }
        let mut seen_cert: HashSet<&str> = HashSet::new();
        for cert in &self.pki.certificates {
            if cert.name.is_empty() {
                bail!("pki certificate: a certificate name must not be empty");
            }
            if !cert
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                bail!(
                    "pki certificate {:?}: name may only contain letters, digits, '-' and '_'",
                    cert.name
                );
            }
            if !seen_cert.insert(cert.name.as_str()) {
                bail!("pki certificate: duplicate certificate {:?}", cert.name);
            }
            // The signing authority is a declared local CA, or "acme".
            if cert.ca == ACME_CA {
                if self.pki.acme.is_none() {
                    bail!(
                        "pki certificate {:?}: ca = \"acme\" but no [pki.acme] account is configured",
                        cert.name
                    );
                }
            } else if !self.pki.cas.iter().any(|c| c.name == cert.ca) {
                bail!(
                    "pki certificate {:?}: unknown ca {:?} (declare [[pki.ca]] or use \"acme\")",
                    cert.name,
                    cert.ca
                );
            }
            validate_subject_component(&cert.common_name)
                .with_context(|| format!("pki certificate {:?} common-name", cert.name))?;
            for san in &cert.subject_alt_names {
                validate_san(san).with_context(|| format!("pki certificate {:?}", cert.name))?;
            }
            if let Some(kt) = &cert.key_type {
                if !matches!(kt.as_str(), "ec" | "rsa") {
                    bail!(
                        "pki certificate {:?}: key-type {kt:?} must be ec or rsa",
                        cert.name
                    );
                }
            }
            if let Some(u) = &cert.usage {
                if !matches!(u.as_str(), "server" | "client") {
                    bail!(
                        "pki certificate {:?}: usage {u:?} must be server or client",
                        cert.name
                    );
                }
            }
            if cert.validity_days == Some(0) {
                bail!(
                    "pki certificate {:?}: validity-days must be greater than 0",
                    cert.name
                );
            }
        }
        if let Some(acme) = &self.pki.acme {
            validate_email(&acme.email).context("pki acme email")?;
            if let Some(url) = &acme.directory_url {
                validate_https_url(url).context("pki acme directory-url")?;
            }
            if let Some(ch) = &acme.challenge {
                if !matches!(ch.as_str(), "http-01" | "dns-01") {
                    bail!("pki acme: challenge {ch:?} must be http-01 or dns-01");
                }
            }
        }
        // GeoIP (roadmap C15): a country the image has no addresses for would
        // block nothing while `show` listed it — the worst outcome for a feature
        // whose whole job is to block. And the data plane's blocklist is one map
        // across every policy, so the total across zones is what has to fit.
        {
            // Every declared country is checked, even one no interface uses yet:
            // finding out it is unknown when a zone is first assigned is worse.
            let mut wanted: Vec<String> = self.firewall.geoip_block.clone();
            for z in self.zones.values() {
                for cc in &z.geoip_block {
                    if !wanted.contains(cc) {
                        wanted.push(cc.clone());
                    }
                }
            }
            let mut size: BTreeMap<&str, usize> = BTreeMap::new();
            for cc in &wanted {
                size.insert(cc.as_str(), geoip_prefixes(cc)?.len());
            }
            // The cost is per zone: each zone's policy carries its own copy.
            let mut total = 0usize;
            let mut zones: Vec<&str> = self
                .interfaces
                .iter()
                .filter(|i| !i.disabled)
                .filter_map(|i| i.zone.as_deref())
                .collect();
            zones.sort_unstable();
            zones.dedup();
            for zone in zones {
                for cc in &self.zone_posture(zone).geoip_block {
                    total += size.get(cc.as_str()).copied().unwrap_or(0);
                }
            }
            // Mirrors `velstra_common::MAX_BLOCKLIST`, the source of truth.
            // Duplicated because Sentinel does not link the data-plane crates,
            // and the alternative is finding the ceiling as a half-programmed
            // firewall.
            const MAX_BLOCKLIST: usize = 262_144;
            if total > MAX_BLOCKLIST {
                bail!(
                    "firewall geoip-block: {total} prefixes across all zones exceeds the \
                     data plane's {MAX_BLOCKLIST}; block fewer countries, or block them \
                     on fewer zones"
                );
            }
        }

        // What issuance itself needs, on top of a well-formed account: the rules
        // that would otherwise fail hours later inside a timer, with nobody
        // watching (roadmap C19).
        crate::acme::validate(&self.pki)?;

        // Signed update channel (roadmap C13): the URL must be a fetchable
        // channel and the pinned key must be present (its cryptographic validity
        // is checked by openssl at update time — here we reject the obvious
        // mistakes so a `commit` fails fast rather than an update later).
        if let Some(up) = &self.update {
            if !(up.url.starts_with("https://") || up.url.starts_with("file://")) {
                bail!(
                    "update: url {:?} must be an https:// or file:// URL",
                    up.url
                );
            }
            if up.public_key.trim().is_empty() {
                bail!("update: public-key is required (the pinned release signing key)");
            }
            let key = up.public_key.trim();
            let looks_like_pem = key.contains("BEGIN PUBLIC KEY");
            let is_file_ref = key.starts_with("file:");
            if !looks_like_pem && !is_file_ref {
                bail!(
                    "update: public-key must be a PEM public key (-----BEGIN PUBLIC KEY-----) \
                     or a `file:<path>` reference"
                );
            }
        }
        Ok(())
    }

    /// The resolved posture for a zone: the zone's own override (`[zone.<name>]`)
    /// falling back to the global `[firewall]` defaults. Used by the compiler.
    pub fn zone_posture(&self, zone: &str) -> ResolvedZone {
        let z = self.zones.get(zone);
        let fw = &self.firewall;
        let mut blocklist = fw.blocklist.clone();
        if let Some(z) = z {
            blocklist.extend(z.blocklist.iter().cloned());
        }
        ResolvedZone {
            stateful: z.and_then(|z| z.stateful).unwrap_or(fw.stateful),
            block_icmp: z.and_then(|z| z.block_icmp).unwrap_or(fw.block_icmp),
            blocklist,
            default_action: z.and_then(|z| z.default_action),
            log: z.and_then(|z| z.log).unwrap_or(fw.log),
            source_validation: z
                .and_then(|z| z.source_validation)
                .unwrap_or(fw.source_validation),
            geoip_block: {
                let mut all = fw.geoip_block.clone();
                if let Some(z) = z {
                    for cc in &z.geoip_block {
                        if !all.contains(cc) {
                            all.push(cc.clone());
                        }
                    }
                }
                all
            },
        }
    }

    /// Non-fatal advisories surfaced at commit time (the orchestrator prints
    /// them; nothing here blocks a commit). Today the data plane keys firewall
    /// policies on the *source* zone only, so a rule's `to <zone>` is decorative:
    /// every rule effectively applies from its `from` zone to ALL zones.
    // Printed by the repl orchestrator (a different slice); unused inside the
    // binary until that wiring lands, so silence dead_code here.
    #[allow(dead_code)]
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        // An encrypted upstream named by hostname cannot be reached until
        // something resolves that hostname, and that something has to be
        // plaintext. Without one the box looks like "DNS is broken" rather than
        // like a setting is missing — so it is said here, where somebody is
        // already reading.
        // A directory reached without TLS is a password on the wire. It is
        // allowed — a directory on a wire you already control is a real
        // deployment — but never silently.
        for d in &self.system.aaa.ldap {
            if d.tls.as_deref() == Some("none") {
                out.push(format!(
                    "system aaa ldap {:?}: tls none sends the bind password in the clear",
                    d.server
                ));
            }
        }
        let dns = &self.services.dns;
        if !dns.secure_upstream.is_empty() && dns.upstream.is_empty() {
            let by_name = dns.secure_upstream.iter().any(|u| {
                u.trim_start_matches("tls://")
                    .trim_start_matches("https://")
                    .split(['/', ':'])
                    .next()
                    .is_some_and(|h| h.parse::<std::net::IpAddr>().is_err())
            });
            if by_name {
                out.push(
                    "services dns: an encrypted upstream is named by hostname but no plain \
                     `upstream` is set to bootstrap it — nothing can resolve that name to \
                     connect to it"
                        .to_string(),
                );
            }
        }
        for rule in &self.rules {
            // Only a rule that DECLARES a destination zone warns: `to` is
            // optional, and omitting it states exactly what the datapath does.
            let Some(to) = &rule.to else { continue };
            // A port rule's `to` IS enforced now: the compiler turns it into a
            // destination match on that zone's subnets. What it cannot cover is a
            // zone with no statically addressed interface — there is no subnet to
            // match, so the rule falls back to applying toward every zone.
            if rule.is_port_rule() {
                // A rule constrains one address end. When it already binds the
                // source, that end is taken and `to` cannot also be matched — the
                // source is the narrower, operator-written constraint, so it wins
                // and `to` stays documentation. Warned every commit, because the
                // rule then reaches further than it reads.
                if rule.source.is_some() || rule.source_group.is_some() {
                    out.push(format!(
                        "rule {:?}: `to {to}` is not enforced because the rule constrains its \
                         source — a rule matches one address end, so this applies from {} \
                         toward ALL zones. Split it if the destination zone must bind.",
                        rule.name, rule.from
                    ));
                    continue;
                }
                let addressed = self.interfaces.iter().any(|i| {
                    !i.disabled
                        && i.zone.as_deref() == Some(to.as_str())
                        && i.address.as_deref().is_some_and(|a| a.contains('/'))
                });
                if !addressed {
                    out.push(format!(
                        "rule {:?}: `to {to}` cannot be enforced — zone {to:?} has no \
                         statically addressed interface, so there is no subnet to match \
                         and the rule applies from {} toward ALL zones",
                        rule.name, rule.from
                    ));
                }
                continue;
            }
            // A broad rule sets its from-zone's ingress posture, which is a
            // property of one zone; there is nothing per-destination to enforce.
            out.push(format!(
                "rule {:?}: `to {to}` does not narrow a broad rule — it sets zone {:?}'s \
                 posture, which applies toward every zone. Give the rule a proto/port to \
                 make the destination zone enforceable.",
                rule.name, rule.from
            ));
        }
        for i in &self.interfaces {
            // An enabled interface that carries an address but has no zone is bound
            // to no policy, so the agent never attaches XDP to it and its traffic
            // passes UNFILTERED. That is a valid state (a NIC awaiting assignment, a
            // management port), but a silent one on a firewall — surface it. An
            // address-less interface (e.g. a pure VLAN/PPPoE trunk parent whose
            // children carry the zoned, addressed traffic) is not flagged.
            if !i.disabled && i.zone.is_none() && (i.address.is_some() || i.address6.is_some()) {
                out.push(format!(
                    "interface {:?}: no zone assigned — it is not firewalled and its traffic \
                     passes unfiltered; assign one with `set interface {} zone <name>`",
                    i.name, i.name
                ));
            }
        }
        // A broadcast relay reads from an ordinary socket, so the packets have
        // already passed the XDP firewall by the time it sees them. Under a
        // deny-by-default zone they never arrive, and the relay looks broken
        // while being blameless — the hardest kind of failure to attribute.
        for r in &self.services.broadcast_relay {
            if r.disabled {
                continue;
            }
            let mut unopened: Vec<&str> = Vec::new();
            for iface in &r.interface {
                let Some(zone) = self
                    .interfaces
                    .iter()
                    .find(|i| &i.name == iface)
                    .and_then(|i| i.zone.as_deref())
                else {
                    continue; // an unzoned interface is unfiltered; nothing to open
                };
                if self.zone_posture(zone).default_action == Some(Action::Accept) {
                    continue;
                }
                let admitted = self.rules.iter().any(|rule| {
                    !rule.disabled
                        && rule.from == zone
                        && rule.action == Action::Accept
                        && match rule.proto {
                            Some(Proto::Udp) => rule.port.iter().any(|spec| {
                                let (lo, hi) = spec.bounds();
                                (lo..=hi).contains(&r.port)
                            }),
                            // A broad accept from the zone opens everything,
                            // including this port.
                            None => rule.port.is_empty(),
                            _ => false,
                        }
                });
                if !admitted && !unopened.contains(&zone) {
                    unopened.push(zone);
                }
            }
            for zone in unopened {
                out.push(format!(
                    "services broadcast-relay {:?}: zone {zone:?} does not admit udp/{}, so the \
                     broadcasts are dropped before the relay sees them; add a rule accepting \
                     udp/{} from {zone}",
                    r.name, r.port, r.port
                ));
            }
        }
        // An http-01 challenge is fetched over port 80, from outside. A zone
        // that does not admit it starves the renewal — which then fails in a
        // timer, weeks later, when the certificate is already close to expiry.
        if self
            .pki
            .certificates
            .iter()
            .any(|c| c.ca == ACME_CA && self.pki.acme.is_some())
        {
            // Only a box that actually filters can be starving the challenge:
            // with no zoned interface nothing is being filtered, and warning
            // there would be noise on every fresh appliance.
            let zoned: Vec<&str> = self
                .interfaces
                .iter()
                .filter(|i| !i.disabled)
                .filter_map(|i| i.zone.as_deref())
                .collect();
            let opened = zoned.iter().any(|zone| {
                if self.zone_posture(zone).default_action == Some(Action::Accept) {
                    return true;
                }
                self.rules.iter().any(|rule| {
                    !rule.disabled
                        && rule.from == *zone
                        && rule.action == Action::Accept
                        && match rule.proto {
                            Some(Proto::Tcp) => rule.port.iter().any(|spec| {
                                let (lo, hi) = spec.bounds();
                                (lo..=hi).contains(&80)
                            }),
                            None => rule.port.is_empty(),
                            _ => false,
                        }
                })
            });
            if !zoned.is_empty() && !opened {
                out.push(
                    "pki acme: no zone admits tcp/80, so the http-01 challenge cannot reach \
                     this box and issuance will fail in the renewal timer; add a rule \
                     accepting tcp/80 from the zone the certificate's name resolves to"
                        .to_string(),
                );
            }
        }

        // Strict source validation asks that the route back to a sender leave by
        // the interface it arrived on. With a second uplink that is exactly what
        // fails: a reply may legitimately return by the other one, and the traffic
        // simply disappears — the failure mode nobody debugs to uRPF. Loose still
        // catches unroutable sources without making that assumption.
        if self.multiwan.uplinks.len() > 1 {
            let mut strict: Vec<&str> = self
                .interfaces
                .iter()
                .filter(|i| !i.disabled)
                .filter_map(|i| i.zone.as_deref())
                .filter(|z| self.zone_posture(z).source_validation == SourceValidation::Strict)
                .collect();
            strict.sort_unstable();
            strict.dedup();
            for zone in strict {
                out.push(format!(
                    "zone {zone:?}: `source-validation strict` with {} WAN uplinks will drop \
                     traffic that returns by the other path; use `loose` unless routing is \
                     symmetric",
                    self.multiwan.uplinks.len()
                ));
            }
        }
        out
    }

    /// A human-readable summary for `config show`.
    pub fn summary(&self) -> String {
        let mut out = format!("hostname: {}\n", self.system.hostname);
        out.push_str(&format!("interfaces ({}):\n", self.interfaces.len()));
        for i in &self.interfaces {
            out.push_str(&format!(
                "  {:<8} {:<12} {}\n",
                i.name,
                i.zone.as_deref().unwrap_or("(unassigned)"),
                i.address.as_deref().unwrap_or("(auto)"),
            ));
        }
        // Source validation is silent when it works and invisible when it does
        // not, so a zone that validates says so here. Zones that don't are
        // omitted: listing "disable" against every zone would bury the one line
        // that matters.
        let mut validating: Vec<(&str, &'static str)> = Vec::new();
        for iface in &self.interfaces {
            let Some(zone) = iface.zone.as_deref() else {
                continue;
            };
            if validating.iter().any(|(z, _)| *z == zone) {
                continue;
            }
            let mode = self.zone_posture(zone).source_validation;
            if mode != SourceValidation::Disable {
                validating.push((zone, mode.as_str()));
            }
        }
        if !validating.is_empty() {
            out.push_str("source validation:\n");
            for (zone, mode) in validating {
                out.push_str(&format!("  {zone:<8} {mode}\n"));
            }
        }
        // GeoIP blocks with the number of prefixes each costs: an operator who
        // hits the data plane's ceiling needs to see where it went.
        let mut geo: Vec<(&str, Vec<String>)> = Vec::new();
        for iface in &self.interfaces {
            let Some(zone) = iface.zone.as_deref() else {
                continue;
            };
            if geo.iter().any(|(z, _)| *z == zone) {
                continue;
            }
            let blocked = self.zone_posture(zone).geoip_block;
            if !blocked.is_empty() {
                geo.push((zone, blocked));
            }
        }
        if !geo.is_empty() {
            out.push_str("geoip blocks:\n");
            for (zone, countries) in geo {
                let n: usize = countries
                    .iter()
                    .map(|cc| geoip_prefixes(cc).map(|p| p.len()).unwrap_or(0))
                    .sum();
                out.push_str(&format!(
                    "  {zone:<8} {}  ({n} prefixes)\n",
                    countries.join(",")
                ));
            }
        }
        out.push_str(&format!("rules ({}):\n", self.rules.len()));
        for r in &self.rules {
            let proto_port = match (r.proto, r.port.as_slice()) {
                (Some(p), []) => format!("  {}", proto_str(p)),
                (Some(p), ports) => format!(
                    "  {}/{}",
                    proto_str(p),
                    ports
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                ),
                _ => String::new(),
            };
            out.push_str(&format!(
                "  {:<16} {} -> {}  {}{}\n",
                r.name,
                r.from,
                r.to.as_deref().unwrap_or("any"),
                action_str(r.action),
                proto_port,
            ));
        }
        out
    }
}

/// Where the per-country CIDR lists live. Overridden by `SENTINEL_GEOIP_DIR`,
/// which the image's wrapper sets to the extracted database.
pub fn geoip_dir() -> std::path::PathBuf {
    std::env::var("SENTINEL_GEOIP_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/etc/sentinel/geoip"))
}

/// Accept a country as an ISO 3166-1 alpha-2 code, upper-cased.
///
/// Only the shape is checked here — whether the image actually has addresses for
/// that country is a question for commit time, where the answer can name the
/// database instead of a syntax rule.
pub fn normalise_country(code: &str) -> Result<String> {
    let cc = code.trim().to_ascii_uppercase();
    if cc.len() != 2 || !cc.chars().all(|c| c.is_ascii_alphabetic()) {
        bail!("{code:?} is not a two-letter country code (e.g. CN, RU)");
    }
    Ok(cc)
}

/// The CIDRs the image holds for `country`, both families, or an error naming the
/// country if it has none.
///
/// A country the database does not cover is an **error, not an empty list**: a
/// rule that silently blocks nothing is the worst outcome for a feature whose
/// whole job is to block.
pub fn geoip_prefixes(country: &str) -> Result<Vec<String>> {
    let dir = geoip_dir();
    let mut out = Vec::new();
    for suffix in ["v4", "v6"] {
        let path = dir.join(format!("{country}.{suffix}"));
        let Ok(body) = std::fs::read_to_string(&path) else {
            continue;
        };
        out.extend(
            body.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_string),
        );
    }
    if out.is_empty() {
        bail!(
            "geoip: no addresses for country {country:?} in {} — check the code, or the \
             image's database does not cover it",
            dir.display()
        );
    }
    Ok(out)
}

/// Validate a bare IPv4 address (router-id, gateway, BGP peer — no prefix).
/// Validate a DNS name a domain group may resolve: labels of letters, digits and
/// hyphens, separated by dots, at least two labels. Deliberately strict — a
/// wildcard or a URL here would resolve to nothing and leave the group silently
/// empty, which on a blocking rule means "allowed".
pub(crate) fn validate_domain_name(s: &str) -> Result<()> {
    let name = s.strip_suffix('.').unwrap_or(s);
    if name.is_empty() || name.len() > 253 {
        bail!("{s:?} is not a DNS name");
    }
    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() < 2 {
        bail!("{s:?} needs at least two labels (e.g. \"example.com\")");
    }
    for label in labels {
        if label.is_empty() || label.len() > 63 {
            bail!("{s:?} has an empty or over-long label");
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            bail!("{s:?} may only contain letters, digits, hyphens and dots");
        }
        if label.starts_with('-') || label.ends_with('-') {
            bail!("{s:?} has a label starting or ending with a hyphen");
        }
    }
    Ok(())
}

pub(crate) fn validate_ipv4(s: &str) -> Result<()> {
    s.parse::<Ipv4Addr>()
        .with_context(|| format!("{s:?} is not an IPv4 address"))?;
    Ok(())
}

/// Validate a bare IPv6 address (an advertised RDNSS server — no prefix).
pub(crate) fn validate_ipv6(s: &str) -> Result<()> {
    s.parse::<Ipv6Addr>()
        .with_context(|| format!("{s:?} is not an IPv6 address"))?;
    Ok(())
}

/// Validate a MAC address: six colon-separated hex octets
/// (`"52:54:00:12:34:56"`). A security boundary too — the value is rendered
/// verbatim into a networkd unit, so it must not smuggle other characters.
/// The offload features an interface may name — `ethtool -K`'s own short keys,
/// which is what an operator reading a NIC's manual has in front of them.
pub const OFFLOAD_FEATURES: &[&str] = &[
    "gro", "gso", "tso", "lro", "sg", "rx", "tx", "rxvlan", "txvlan", "ntuple", "rxhash",
];

pub(crate) fn validate_mac(s: &str) -> Result<()> {
    let octets: Vec<&str> = s.split(':').collect();
    if octets.len() != 6
        || !octets
            .iter()
            .all(|o| o.len() == 2 && o.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        bail!("mac {s:?}: expected six colon-separated hex octets");
    }
    Ok(())
}

/// tc rate units accepted for a QoS `bandwidth` (case as tc prints them).
const TC_RATE_UNITS: &[&str] = &[
    "bit", "kbit", "mbit", "gbit", "tbit", "kibit", "mibit", "gibit", "tibit", "bps", "kbps",
    "mbps", "gbps", "tbps",
];

/// tc time units accepted for a QoS `rtt`/`target`/`interval`.
const TC_TIME_UNITS: &[&str] = &["s", "sec", "secs", "ms", "msec", "us", "usec"];

/// Split a `<number><unit>` token into its numeric head and unit tail. The head
/// is the leading run of digits and at most one decimal point.
fn split_number_unit(s: &str) -> (&str, &str) {
    let end = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());
    s.split_at(end)
}

/// Validate a tc rate (`"100mbit"`, `"20gbit"`, a bare number = bytes/sec, or
/// the literal `"unlimited"`). Also an injection guard — only a number plus a
/// known unit ever reaches the `tc` command line.
pub(crate) fn validate_tc_rate(s: &str) -> Result<()> {
    if s == "unlimited" {
        return Ok(());
    }
    let (num, unit) = split_number_unit(s);
    if num.is_empty() || num.parse::<f64>().is_err() {
        bail!("invalid rate {s:?}: expected a number like \"100mbit\" or \"unlimited\"");
    }
    if !unit.is_empty() && !TC_RATE_UNITS.contains(&unit) {
        bail!("invalid rate unit in {s:?}: use bit/kbit/mbit/gbit/tbit or bps/kbps/mbps/gbps");
    }
    Ok(())
}

/// Validate a tc time (`"5ms"`, `"100ms"`, `"1s"`, or a bare number = seconds).
pub(crate) fn validate_tc_time(s: &str) -> Result<()> {
    let (num, unit) = split_number_unit(s);
    if num.is_empty() || num.parse::<f64>().is_err() {
        bail!("invalid time {s:?}: expected a number like \"5ms\" or \"100ms\"");
    }
    if !unit.is_empty() && !TC_TIME_UNITS.contains(&unit) {
        bail!("invalid time unit in {s:?}: use s/ms/us");
    }
    Ok(())
}

/// Validate a per-interface QoS block: check every set value is well-formed and
/// enforce that only the knobs belonging to the chosen discipline are present
/// (a CAKE knob on an fq_codel qdisc — or vice versa — is a config error).
pub(crate) fn validate_qos(qos: &Qos) -> Result<()> {
    if let Some(bw) = &qos.bandwidth {
        validate_tc_rate(bw).context("bandwidth")?;
    }
    if let Some(rtt) = &qos.rtt {
        // rtt is a time OR one of CAKE's link-class keywords.
        if !CAKE_RTT_KEYWORDS.contains(&rtt.as_str()) {
            validate_tc_time(rtt)
                .with_context(|| format!("rtt {rtt:?}: expected a time or a CAKE keyword"))?;
        }
    }
    if let Some(ds) = &qos.diffserv {
        if !CAKE_DIFFSERV_MODES.contains(&ds.as_str()) {
            bail!("invalid diffserv mode {ds:?}: use besteffort/diffserv3/diffserv4/diffserv8");
        }
    }
    if let Some(t) = &qos.target {
        validate_tc_time(t).context("target")?;
    }
    if let Some(i) = &qos.interval {
        validate_tc_time(i).context("interval")?;
    }
    // Cross-discipline knobs: reject rather than silently ignore.
    if qos.is_cake() {
        if qos.target.is_some() || qos.interval.is_some() || qos.limit.is_some() {
            bail!("target/interval/limit are fq_codel knobs — not valid on a cake qdisc");
        }
    } else {
        // fq_codel: no built-in shaper or CAKE-specific classification.
        if qos.bandwidth.is_some()
            || qos.rtt.is_some()
            || qos.nat
            || qos.ack_filter
            || qos.diffserv.is_some()
        {
            bail!(
                "bandwidth/rtt/nat/ack-filter/diffserv are cake knobs — \
                 not valid on an fq_codel qdisc (fq_codel does not shape)"
            );
        }
    }
    Ok(())
}

/// The address family of a bare IP: `Some(true)` for IPv6, `Some(false)` for
/// IPv4, `None` if it is neither. A `prefix/len` is reduced to its address part.
pub(crate) fn ip_family(s: &str) -> Option<bool> {
    let head = s.split('/').next().unwrap_or(s);
    if head.parse::<Ipv4Addr>().is_ok() {
        Some(false)
    } else if head.parse::<Ipv6Addr>().is_ok() {
        Some(true)
    } else {
        None
    }
}

/// Validate a static-route prefix (an IPv4 or IPv6 CIDR, or a bare host) and
/// return its family (`true` = IPv6). Checks the prefix length is in range.
pub(crate) fn route_prefix_family(s: &str) -> Result<bool> {
    match s.split_once('/') {
        Some((ip, pfx)) => {
            let len: u16 = pfx
                .parse()
                .with_context(|| format!("invalid prefix length in {s:?}"))?;
            if ip.parse::<Ipv4Addr>().is_ok() {
                if len > 32 {
                    bail!("prefix /{len} in {s:?} exceeds /32");
                }
                Ok(false)
            } else if ip.parse::<Ipv6Addr>().is_ok() {
                if len > 128 {
                    bail!("prefix /{len} in {s:?} exceeds /128");
                }
                Ok(true)
            } else {
                bail!("invalid IP in {s:?}")
            }
        }
        None => ip_family(s).with_context(|| format!("{s:?} is not an IP or CIDR")),
    }
}

/// Validate a host that is either an IP literal (v4/v6) or a DNS hostname — used
/// for an NTP upstream, which may be given by name (`pool.ntp.org`) or address.
/// Reject a value that cannot be rendered as a single bare token: whitespace, a
/// control character, a quote or a backslash. Every consumer here (an msmtp
/// directive, a curl argument) takes the rest of a line or an argv slot, so one of
/// these turns a value into extra configuration.
fn reject_config_token(field: &str, v: &str) -> Result<()> {
    if v.bytes()
        .any(|b| b.is_ascii_control() || matches!(b, b' ' | b'\t' | b'"' | b'\\'))
    {
        bail!("{field}: must not contain whitespace, a control character, quote or backslash");
    }
    Ok(())
}

/// The rule actions Suricata accepts. `drop`/`reject` are refused below: they are
/// only honoured in an IPS mode Sentinel deliberately does not run.
const IDS_RULE_ACTIONS: &[&str] = &["alert", "pass", "drop", "reject", "rejectsrc", "rejectdst"];

/// Check one inline Suricata rule far enough to keep a typo from taking the whole
/// ruleset down, and return its `sid`.
///
/// Not a Suricata parser — the detector is the authority on its own grammar. This
/// catches the mistakes that are both common and catastrophic: a rule Suricata
/// refuses to load makes it exit, and an exiting detector means nothing is watched
/// at all. A rule that merely fails to *match* is the operator's business.
pub(crate) fn validate_ids_rule(rule: &str) -> Result<u32> {
    let r = rule.trim();
    if r.is_empty() {
        bail!("services ids: an empty rule");
    }
    if r.contains('\n') {
        bail!("services ids rule: one rule per entry — {r:?} spans lines");
    }
    let action = r.split_whitespace().next().unwrap_or_default();
    if !IDS_RULE_ACTIONS.contains(&action) {
        bail!(
            "services ids rule: {action:?} is not a rule action \
             (expected one of {})",
            IDS_RULE_ACTIONS.join(", ")
        );
    }
    // A verdict action would be silently inert: Suricata only enforces it in an
    // IPS mode, and Sentinel runs detection alongside the eBPF data plane rather
    // than in the forwarding path. Saying so at commit beats a rule that appears
    // to block for as long as nobody tests it.
    if action != "alert" && action != "pass" {
        bail!(
            "services ids rule: {action:?} only takes effect in IPS mode, which \
             Sentinel does not run — the eBPF firewall owns blocking. Use `alert` \
             and write a firewall rule for the drop."
        );
    }
    let body_start = r.find('(');
    let (Some(open), true) = (body_start, r.ends_with(')')) else {
        bail!("services ids rule: no `(...)` option block in {r:?}");
    };
    let body = &r[open + 1..r.len() - 1];
    // action proto src sport direction dst dport — Suricata rejects the rule
    // outright if the header is short, which stops the whole load.
    if r[..open].split_whitespace().count() != 7 {
        bail!(
            "services ids rule: the header before `(` must be \
             `<action> <proto> <src> <sport> <dir> <dst> <dport>` — got {:?}",
            r[..open].trim()
        );
    }
    let sid = body
        .split(';')
        .map(str::trim)
        .find_map(|opt| opt.strip_prefix("sid:"))
        .ok_or_else(|| {
            anyhow::anyhow!("services ids rule: no `sid:` in {r:?} — Suricata requires one")
        })?;
    let sid: u32 = sid
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("services ids rule: sid {sid:?} is not a number"))?;
    if !body.contains("msg:") {
        bail!(
            "services ids rule sid {sid}: no `msg:` — an alert with no message is \
             unreadable in the log it lands in"
        );
    }
    Ok(sid)
}

pub(crate) fn validate_host(s: &str) -> Result<()> {
    if s.parse::<Ipv4Addr>().is_ok() || s.parse::<Ipv6Addr>().is_ok() {
        return Ok(());
    }
    let ok = !s.is_empty()
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        });
    if !ok {
        bail!("{s:?} is not a valid host (IP or hostname)");
    }
    Ok(())
}

/// Validate an HA peer/listen endpoint: a bare host (IPv4 / IPv6 / hostname) or
/// `host:port` (`[v6]:port` for an IPv6 literal). Shared by config-sync and
/// conntrack-sync so both accept the same forms. The bare forms are tried first so
/// a colon-bearing IPv6 literal is not mis-split as `host:port`.
pub(crate) fn validate_sync_peer(peer: &str) -> Result<()> {
    let bare = validate_ipv4(peer).is_ok()
        || validate_ipv6(peer).is_ok()
        || validate_hostname(peer).is_ok();
    let host_port = peer.rsplit_once(':').is_some_and(|(h, p)| {
        !p.is_empty()
            && p.chars().all(|c| c.is_ascii_digit())
            && (validate_ipv4(h).is_ok()
                || validate_hostname(h).is_ok()
                || h.strip_prefix('[')
                    .and_then(|x| x.strip_suffix(']'))
                    .is_some_and(|v6| validate_ipv6(v6).is_ok()))
    });
    if !bare && !host_port {
        bail!("{peer:?}: not a host or host:port");
    }
    Ok(())
}

/// Whether `addr` falls inside the IPv6 CIDR `prefix` (`"2001:db8::/64"`). A
/// malformed prefix, a missing length, or `len > 128` returns `false` (the prefix
/// is validated as a CIDR elsewhere); used to keep a stateful DHCPv6 pool inside
/// one of the interface's advertised prefixes.
/// Whether `addr` falls inside the IPv4 CIDR `prefix`. A bare address counts as
/// a `/32`, because that is how an operator writes "this one host".
pub(crate) fn ipv4_in_prefix(addr: &Ipv4Addr, prefix: &str) -> bool {
    let (net, len) = match prefix.split_once('/') {
        Some((n, l)) => (n, l.parse::<u32>().ok()),
        None => (prefix, Some(32)),
    };
    let (Ok(net), Some(len)) = (net.parse::<Ipv4Addr>(), len) else {
        return false;
    };
    if len > 32 {
        return false;
    }
    let mask: u32 = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    (u32::from(*addr) & mask) == (u32::from(net) & mask)
}

pub(crate) fn ipv6_in_prefix(addr: &Ipv6Addr, prefix: &str) -> bool {
    let Some((net, len)) = prefix.split_once('/') else {
        return false;
    };
    let (Ok(net), Ok(len)) = (net.parse::<Ipv6Addr>(), len.parse::<u32>()) else {
        return false;
    };
    if len > 128 {
        return false;
    }
    let mask: u128 = if len == 0 {
        0
    } else {
        u128::MAX << (128 - len)
    };
    (u128::from(*addr) & mask) == (u128::from(net) & mask)
}

/// Validate an IPv6 CIDR such as an advertised RA prefix (`2001:db8:1::/64`).
pub(crate) fn validate_ipv6_cidr(s: &str) -> Result<()> {
    let (ip, prefix) = s
        .split_once('/')
        .with_context(|| format!("prefix {s:?} must be an IPv6 CIDR like \"2001:db8:1::/64\""))?;
    ip.parse::<Ipv6Addr>()
        .with_context(|| format!("invalid IPv6 in {s:?}"))?;
    let prefix: u8 = prefix
        .parse()
        .with_context(|| format!("invalid prefix in {s:?}"))?;
    if prefix > 128 {
        bail!("prefix /{prefix} in {s:?} exceeds /128");
    }
    Ok(())
}

/// Validate a system hostname to the RFC 1123 label charset. A security
/// boundary as well as correctness: the hostname is rendered into the shell's
/// `PS1`, systemd units and `/etc/hostname`, so it must not carry shell
/// metacharacters, whitespace or other unexpected bytes.
pub(crate) fn validate_hostname(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 63 {
        bail!("system.hostname: must be 1–63 characters");
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        bail!("system.hostname {name:?}: only ASCII letters, digits and '-' are allowed");
    }
    if name.starts_with('-') || name.ends_with('-') {
        bail!("system.hostname {name:?}: must not start or end with '-'");
    }
    Ok(())
}

/// Validate a network-interface name. This is a security boundary, not just
/// cosmetics: interface names flow verbatim into hand-written systemd-networkd
/// unit files and their filenames (`src/net.rs`). Without this check a name
/// containing `/` or `..` escapes the runtime unit directory (path traversal)
/// and a name containing a newline injects arbitrary `.network`/`.netdev`
/// directives. Restrict to the kernel's `IFNAMSIZ` charset (Linux permits at
/// most 15 bytes and forbids `/` and whitespace in link names anyway).
pub(crate) fn validate_iface_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 15 {
        bail!("interface name {name:?}: must be 1–15 characters");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
    {
        bail!("interface name {name:?}: only ASCII letters, digits, '.', '_' and '-' are allowed");
    }
    Ok(())
}

/// The BGP Roles a speaker may take toward a neighbour (RFC 9234).
const BGP_ROLES: &[&str] = &["provider", "customer", "peer", "rs-server", "rs-client"];

/// The protocol names an `[import]` map may key on — wren's authoritative set
/// (`protocol_from_name` in wren-daemon). A stray key used to be silently
/// dropped by the daemon, so an unknown one is a commit error. Note this is
/// NOT the `[export]` set: import filters route *sources* (incl. connected/
/// static), export has fixed per-protocol fields; there is no `ripng` source.
const IMPORT_PROTOCOLS: &[&str] = &[
    "connected",
    "static",
    "kernel",
    "rip",
    "ospf",
    "isis",
    "babel",
    "bgp",
];

/// The multicast interface roles Wren accepts (its `MulticastRole`, lowercase).
const MULTICAST_ROLES: &[&str] = &["querier", "upstream", "downstream"];

/// The per-neighbour BFD authentication types Wren accepts.
const BFD_AUTH_TYPES: &[&str] = &[
    "simple",
    "keyed-md5",
    "meticulous-md5",
    "keyed-sha1",
    "meticulous-sha1",
];

/// Validate one BGP neighbour: its address/AS plus the policy knobs, with
/// import/export referring to a declared filter (`filter_names`).
fn validate_bgp_neighbor(n: &BgpNeighbor, filter_names: &HashSet<&str>) -> Result<()> {
    // Either family: wren speaks MP-BGP, and an IPv6 peering is not exotic — on
    // a dual-stacked network most sessions are one. Refusing it here made every
    // v6 neighbour unconfigurable while the daemon underneath was ready for it.
    n.address
        .parse::<std::net::IpAddr>()
        .map(|_| ())
        .with_context(|| format!("protocols bgp neighbor {:?}", n.address))?;
    if n.remote_as == 0 {
        bail!(
            "protocols bgp neighbor {:?}: remote-as must be non-zero",
            n.address
        );
    }
    if let Some(role) = &n.role {
        if !BGP_ROLES.contains(&role.as_str()) {
            bail!(
                "protocols bgp neighbor {:?}: role {role:?} not one of {BGP_ROLES:?}",
                n.address
            );
        }
    }
    if let Some(hops) = n.ttl_security {
        if !(1..=254).contains(&hops) {
            bail!(
                "protocols bgp neighbor {:?}: ttl-security {hops} out of range 1..=254",
                n.address
            );
        }
    }
    if let Some(max) = n.max_prefix {
        if max == 0 {
            bail!(
                "protocols bgp neighbor {:?}: max-prefix must be non-zero",
                n.address
            );
        }
    }
    // TCP-MD5 (RFC 2385) and TCP-AO (RFC 5925) are different TCP options that
    // cannot both protect one session.
    if n.password.is_some() && n.ao_key.is_some() {
        bail!(
            "protocols bgp neighbor {:?}: password (TCP-MD5) and ao-key (TCP-AO) are mutually exclusive",
            n.address
        );
    }
    if let Some(t) = &n.bfd_auth_type {
        if !BFD_AUTH_TYPES.contains(&t.as_str()) {
            bail!(
                "protocols bgp neighbor {:?}: bfd-auth-type {t:?} not one of {BFD_AUTH_TYPES:?}",
                n.address
            );
        }
    }
    for (which, name) in [("import", &n.import), ("export", &n.export)] {
        if let Some(name) = name {
            if !filter_names.contains(name.as_str()) {
                bail!(
                    "protocols bgp neighbor {:?}: {which} references unknown filter {name:?}",
                    n.address
                );
            }
        }
    }
    if n.local_as == Some(0) {
        bail!(
            "protocols bgp neighbor {:?}: local-as must be non-zero",
            n.address
        );
    }
    if let Some(src) = &n.update_source {
        // The session's source is an address this box holds, in whichever
        // family the session runs.
        src.parse::<std::net::IpAddr>()
            .map(|_| ())
            .with_context(|| format!("protocols bgp neighbor {:?} update-source", n.address))?;
    }
    if let Some(ttl) = n.ebgp_multihop {
        if ttl == 0 {
            bail!(
                "protocols bgp neighbor {:?}: ebgp-multihop must be 1..=255",
                n.address
            );
        }
        // RFC 5082 practice: GTSM and a relaxed multihop TTL contradict each
        // other on one session — wren rejects the combination too.
        if n.ttl_security.is_some() {
            bail!(
                "protocols bgp neighbor {:?}: ebgp-multihop and ttl-security are mutually exclusive",
                n.address
            );
        }
    }
    if let Some(hold) = n.hold_time {
        if hold != 0 && hold < 3 {
            bail!(
                "protocols bgp neighbor {:?}: hold-time must be 0 or >= 3 seconds (RFC 4271)",
                n.address
            );
        }
    }
    Ok(())
}

/// Validate one named route filter: the default/rule actions ∈ {accept,reject},
/// non-empty prefix patterns and well-formed community tags.
fn validate_filter(f: &Filter) -> Result<()> {
    if f.name.is_empty() {
        bail!("protocols filter: a filter needs a name");
    }
    if let Some(d) = &f.default {
        validate_filter_action(d)
            .with_context(|| format!("protocols filter {:?} default", f.name))?;
    }
    for (i, r) in f.rules.iter().enumerate() {
        validate_filter_action(&r.action)
            .with_context(|| format!("protocols filter {:?} rule {i} action", f.name))?;
        for p in &r.prefix {
            if p.is_empty() {
                bail!(
                    "protocols filter {:?} rule {i}: empty prefix pattern",
                    f.name
                );
            }
            validate_filter_prefix(p)
                .with_context(|| format!("protocols filter {:?} rule {i} prefix", f.name))?;
        }
        let communities = [
            r.set_community.as_deref().unwrap_or(&[]),
            &r.add_community,
            r.set_large_community.as_deref().unwrap_or(&[]),
            &r.add_large_community,
            r.set_ext_community.as_deref().unwrap_or(&[]),
            &r.add_ext_community,
        ];
        for set in communities {
            for c in set {
                validate_community(c)
                    .with_context(|| format!("protocols filter {:?} rule {i}", f.name))?;
            }
        }
    }
    Ok(())
}

/// Validate a route-filter prefix pattern: an IPv4 or IPv6 CIDR, optionally with
/// a Wren match-modifier suffix — a trailing `+` (this and more-specific), `-`
/// (this and less-specific), or a `{min,max}` length range. The base CIDR is
/// checked v4-or-v6; the modifier is stripped first so it does not confuse the
/// parse.
fn validate_filter_prefix(p: &str) -> Result<()> {
    // Drop a `{min,max}` length-range suffix, then a trailing `+`/`-` modifier.
    let base = p.split('{').next().unwrap_or(p);
    let base = base.trim_end_matches(['+', '-']);
    route_prefix_family(base)
        .map(|_| ())
        .with_context(|| format!("prefix pattern {p:?} is not a valid IPv4/IPv6 CIDR"))
}

/// A filter action must be `accept` or `reject`.
fn validate_filter_action(a: &str) -> Result<()> {
    if a != "accept" && a != "reject" {
        bail!("action {a:?}: expected \"accept\" or \"reject\"");
    }
    Ok(())
}

/// A community tag is a well-known name or an `asn:value`-shaped token (this is
/// a shape check; the Wren daemon does the definitive parse).
fn validate_community(c: &str) -> Result<()> {
    const WELL_KNOWN: &[&str] = &["no-export", "no-advertise", "no-export-subconfed"];
    if WELL_KNOWN.contains(&c) {
        return Ok(());
    }
    if c.split(':').count() < 2 || c.split(':').any(|p| p.is_empty()) {
        bail!("community {c:?}: expected a well-known name or `asn:value`");
    }
    Ok(())
}

/// Validate an OSPF/OSPFv3 `network-type` (`broadcast` / `point-to-point`).
fn validate_ospf_network_type(nt: Option<&str>, proto: &str) -> Result<()> {
    if let Some(nt) = nt {
        if nt != "broadcast" && nt != "point-to-point" {
            bail!(
                "protocols {proto} network-type {nt:?}: expected \"broadcast\" or \"point-to-point\""
            );
        }
    }
    Ok(())
}

/// Validate an interface address: `"dhcp"` or an IPv4 CIDR.
fn validate_address(addr: &str) -> Result<()> {
    if addr == "dhcp" {
        return Ok(());
    }
    let (ip, prefix) = addr
        .split_once('/')
        .with_context(|| format!("address {addr:?} must be \"dhcp\" or an IPv4 CIDR"))?;
    ip.parse::<Ipv4Addr>()
        .with_context(|| format!("invalid IPv4 in {addr:?}"))?;
    let prefix: u8 = prefix
        .parse()
        .with_context(|| format!("invalid prefix in {addr:?}"))?;
    if prefix > 32 {
        bail!("prefix /{prefix} in {addr:?} exceeds /32");
    }
    Ok(())
}

/// Validate an interface's IPv6 address: `"auto"` (SLAAC / accept-RA), `"dhcp"`
/// (DHCPv6 client) or a static IPv6 CIDR (`"2001:db8:1::1/64"`).
fn validate_address6(addr: &str) -> Result<()> {
    if addr == "auto" || addr == "dhcp" {
        return Ok(());
    }
    validate_ipv6_cidr(addr)
}

/// Parse a port-forward target `"ip"` or `"ip:port"` into an IPv4 + a port
/// (`0` when omitted, meaning "keep the public port").
pub(crate) fn parse_host_port(s: &str) -> Result<(Ipv4Addr, u16)> {
    let (ip, port) = match s.rsplit_once(':') {
        Some((ip, port)) => (
            ip,
            port.parse::<u16>()
                .with_context(|| format!("invalid port in {s:?}"))?,
        ),
        None => (s, 0),
    };
    let ip = ip
        .parse::<Ipv4Addr>()
        .with_context(|| format!("invalid IPv4 in {s:?}"))?;
    Ok((ip, port))
}

/// True when the IPv4 `ip` falls inside the IPv4 CIDR `cidr` (host bits masked).
/// Returns an error if either side fails to parse — the caller treats that as
/// "not inside". Used to keep a DHCP static reservation within the server subnet.
pub(crate) fn ipv4_in_cidr(ip: &str, cidr: &str) -> Result<bool> {
    let addr: Ipv4Addr = ip
        .parse()
        .with_context(|| format!("{ip:?} is not an IPv4 address"))?;
    let (net, prefix) = cidr
        .split_once('/')
        .with_context(|| format!("{cidr:?} is not an IPv4 CIDR"))?;
    let net: Ipv4Addr = net
        .parse()
        .with_context(|| format!("invalid IPv4 in {cidr:?}"))?;
    let prefix: u8 = prefix
        .parse()
        .with_context(|| format!("invalid prefix in {cidr:?}"))?;
    if prefix > 32 {
        bail!("prefix /{prefix} in {cidr:?} exceeds /32");
    }
    // A /0 masks everything (mask 0); shifting a u32 by 32 is UB, so special-case.
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ok((u32::from(addr) & mask) == (u32::from(net) & mask))
}

/// True when a DHCP lease pool (`size` addresses starting at host-offset
/// `offset`) fits inside the IPv4 `cidr`. networkd numbers `PoolOffset` from the
/// network address, so the pool occupies indices `offset ..= offset + size - 1`,
/// which must stay within the subnet's address count. Returns false on a
/// malformed CIDR or a zero-length pool.
pub(crate) fn dhcp_pool_fits(cidr: &str, offset: u32, size: u32) -> bool {
    if size == 0 {
        return false;
    }
    let Some((_net, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    // Total addresses in the subnet (u64 so a /0 does not overflow).
    let count: u64 = 1u64 << (32 - prefix as u64);
    offset >= 1 && (offset as u64) + (size as u64) <= count
}

/// Validate a free-text `description` (interface/rule/zone/nat label): non-empty
/// after trimming and within a sane length, and free of control characters — the
/// value is echoed into a networkd comment / the CLI, so it must stay one line.
pub(crate) fn validate_description(s: &str) -> Result<()> {
    const MAX_DESCRIPTION_LEN: usize = 256;
    if s.trim().is_empty() {
        bail!("description must not be empty");
    }
    if s.len() > MAX_DESCRIPTION_LEN {
        bail!("description too long ({} > {MAX_DESCRIPTION_LEN})", s.len());
    }
    if s.chars().any(|c| c.is_control()) {
        bail!("description must not contain control characters (incl. newlines)");
    }
    Ok(())
}

/// Validate a firewall blocklist entry: a bare IPv4 (`192.0.2.5`) or an IPv4
/// CIDR (`10.6.6.0/24`).
pub(crate) fn validate_cidr_or_ip(s: &str) -> Result<()> {
    // Either family. The data plane ranks each in its own longest-prefix trie,
    // and which one a constraint belongs to follows from what it says — so an
    // operator writing `fd12::/64` means what they mean by `10.0.0.0/8` and does
    // not have to know there are two tries underneath.
    let v6 = s.contains(':');
    if let Some((ip, prefix)) = s.split_once('/') {
        if v6 {
            ip.parse::<std::net::Ipv6Addr>()
                .with_context(|| format!("invalid IPv6 in {s:?}"))?;
            let prefix: u8 = prefix
                .parse()
                .with_context(|| format!("invalid prefix in {s:?}"))?;
            if prefix > 128 {
                bail!("prefix /{prefix} in {s:?} exceeds /128");
            }
            return Ok(());
        }
        ip.parse::<Ipv4Addr>()
            .with_context(|| format!("invalid IPv4 in {s:?}"))?;
        let prefix: u8 = prefix
            .parse()
            .with_context(|| format!("invalid prefix in {s:?}"))?;
        if prefix > 32 {
            bail!("prefix /{prefix} in {s:?} exceeds /32");
        }
    } else if v6 {
        s.parse::<std::net::Ipv6Addr>()
            .with_context(|| format!("invalid IP/CIDR {s:?}"))?;
    } else {
        s.parse::<Ipv4Addr>()
            .with_context(|| format!("invalid IP/CIDR {s:?}"))?;
    }
    Ok(())
}

/// Validate a WireGuard key (private, peer public, or preshared): the standard
/// base64 encoding of exactly 32 raw bytes — the `wg` tool's format.
pub(crate) fn validate_wg_key(s: &str) -> Result<()> {
    let raw = STANDARD
        .decode(s)
        .with_context(|| format!("wireguard key {s:?} is not valid base64"))?;
    if raw.len() != 32 {
        bail!(
            "wireguard key {s:?} decodes to {} bytes, expected 32",
            raw.len()
        );
    }
    Ok(())
}

/// Validate an IPsec cipher proposal token (`aes256-sha256-modp2048`, or
/// comma-separated alternatives). Rendered verbatim into swanctl.conf, so it must
/// carry only the charon proposal charset — no whitespace, quotes or newlines
/// that could smuggle another config directive.
pub(crate) fn validate_ipsec_proposal(s: &str) -> Result<()> {
    if s.is_empty() {
        bail!("ipsec proposal is empty");
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b',')
    {
        bail!("ipsec proposal {s:?}: only letters, digits, '-' and ',' are allowed");
    }
    Ok(())
}

/// Validate an IPsec IKE identity (`local-id`/`remote-id`) — an IP, an FQDN, a
/// user-FQDN (`user@example.com`) or a `%any` wildcard. Rendered verbatim into
/// swanctl.conf, so it is a security boundary: restrict it to a safe charset that
/// still covers the common identity forms, and forbid anything that could break
/// out of the `id = <value>` line.
pub(crate) fn validate_ipsec_id(s: &str) -> Result<()> {
    if s.is_empty() {
        bail!("ipsec id is empty");
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'@' | b':' | b'%'))
    {
        bail!(
            "ipsec id {s:?}: only letters, digits and '.-_@:%' are allowed \
             (use an IP, FQDN, user@fqdn or %any)"
        );
    }
    Ok(())
}

/// Validate a certificate subject component (a CN or O, roadmap C19). It is
/// rendered into an openssl `-subj "/CN=…"` argument, so it must not carry the
/// `/` or `=` separators, a quote/backslash or a control character that would
/// break the field apart.
pub(crate) fn validate_subject_component(s: &str) -> Result<()> {
    if s.is_empty() {
        bail!("certificate subject component is empty");
    }
    if s.len() > 64 {
        bail!("certificate subject component {s:?}: max 64 characters");
    }
    if s.bytes()
        .any(|b| matches!(b, b'/' | b'=' | b'"' | b'\\') || b.is_ascii_control())
    {
        bail!(
            "certificate subject component {s:?}: '/', '=', '\"', '\\' and control \
             characters are not allowed"
        );
    }
    Ok(())
}

/// Validate a certificate Subject Alternative Name: `DNS:<hostname>` or
/// `IP:<address>`. Rendered verbatim into an openssl extension file, so both the
/// tag and the value are constrained.
pub(crate) fn validate_san(s: &str) -> Result<()> {
    let (tag, value) = s
        .split_once(':')
        .with_context(|| format!("subject-alt-name {s:?} must be DNS:<host> or IP:<addr>"))?;
    match tag {
        "DNS" => validate_host(value).with_context(|| format!("subject-alt-name {s:?}"))?,
        "IP" => {
            if value.parse::<Ipv4Addr>().is_err() && value.parse::<Ipv6Addr>().is_err() {
                bail!("subject-alt-name {s:?}: {value:?} is not an IP address");
            }
        }
        other => bail!("subject-alt-name {s:?}: tag {other:?} must be DNS or IP"),
    }
    Ok(())
}

/// Validate an ACME contact email — a minimal, injection-safe check (exactly one
/// `@`, no whitespace or control characters), not full RFC 5322.
pub(crate) fn validate_email(s: &str) -> Result<()> {
    let ok = s.matches('@').count() == 1
        && !s.starts_with('@')
        && !s.ends_with('@')
        && s.bytes()
            .all(|b| !b.is_ascii_whitespace() && !b.is_ascii_control());
    if !ok {
        bail!("{s:?} is not a valid email address");
    }
    Ok(())
}

/// Validate an ACME directory URL: an `https://…` URL free of whitespace and
/// control characters (a security-relevant endpoint — plain http would expose
/// the account key exchange).
pub(crate) fn validate_https_url(s: &str) -> Result<()> {
    if !s.starts_with("https://") || s.len() <= "https://".len() {
        bail!("{s:?} must be an https:// URL");
    }
    if s.bytes()
        .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        bail!("{s:?}: URL must not contain whitespace or control characters");
    }
    Ok(())
}

/// Validate a WireGuard peer endpoint `host:port`: the host is an IPv4 literal
/// or a DNS hostname, the port is 1..=65535.
pub(crate) fn validate_endpoint(s: &str) -> Result<()> {
    let (host, port) = s
        .rsplit_once(':')
        .with_context(|| format!("endpoint {s:?} must be host:port"))?;
    let port: u16 = port
        .parse()
        .with_context(|| format!("invalid port in endpoint {s:?}"))?;
    if port == 0 {
        bail!("endpoint {s:?}: port 0 is not valid");
    }
    if host.is_empty() {
        bail!("endpoint {s:?}: host is empty");
    }
    // An IPv4 literal is fine; otherwise require a plausible DNS hostname (labels
    // of alphanumerics/hyphen, dot-separated) so we don't smuggle an INI newline.
    if host.parse::<Ipv4Addr>().is_ok() {
        return Ok(());
    }
    let ok = host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    });
    if !ok {
        bail!("endpoint {s:?}: host is not a valid IPv4 or hostname");
    }
    Ok(())
}

fn action_str(a: Action) -> &'static str {
    match a {
        Action::Accept => "accept",
        Action::Drop => "drop",
        Action::Reject => "reject",
    }
}

fn proto_str(p: Proto) -> &'static str {
    match p {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
        Proto::Icmp => "icmp",
        Proto::Icmpv6 => "icmpv6",
        Proto::Vrrp => "vrrp",
        Proto::Esp => "esp",
        Proto::Ah => "ah",
        Proto::Gre => "gre",
        Proto::TcpUdp => "tcp_udp",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_example_config_is_valid() {
        let a = Appliance::from_toml(EXAMPLE).expect("example must parse + validate");
        assert_eq!(a.system.hostname, "sentinel-fw");
        assert_eq!(a.interfaces.len(), 2);
        assert_eq!(a.rules.len(), 2); // 1 broad accept + 1 port rule
        // The port rule has proto+port; the broad ones don't.
        assert_eq!(a.rules.iter().filter(|r| r.is_port_rule()).count(), 1);
    }

    #[test]
    fn rejects_duplicate_interfaces() {
        let toml = r#"
            [system]
            hostname = "x"
            [[interface]]
            name = "eth0"
            zone = "wan"
            address = "dhcp"
            [[interface]]
            name = "eth0"
            zone = "lan"
            address = "10.0.0.1/24"
        "#;
        assert!(Appliance::from_toml(toml).is_err());
    }

    #[test]
    fn rejects_interface_name_with_path_traversal() {
        // A '/' (or '..') in an interface name would escape the networkd runtime
        // unit directory when net.rs joins it onto a path.
        let toml = r#"
            [system]
            hostname = "x"
            [[interface]]
            name = "../../etc/evil"
            zone = "wan"
            address = "dhcp"
        "#;
        assert!(Appliance::from_toml(toml).is_err());
    }

    #[test]
    fn rejects_interface_name_with_newline_injection() {
        // A newline would inject extra INI directives into the rendered .network
        // file, which is line-oriented with no quoting.
        let toml = "[system]\nhostname = \"x\"\n[[interface]]\nname = \"eth0\\n[Network]\\nIPForward=yes\"\nzone = \"wan\"\naddress = \"dhcp\"\n";
        assert!(Appliance::from_toml(toml).is_err());
    }

    #[test]
    fn accepts_ordinary_and_vlan_interface_names() {
        assert!(validate_iface_name("eth0").is_ok());
        assert!(validate_iface_name("eth1.20").is_ok());
        assert!(validate_iface_name("wan-uplink_0").is_ok());
        assert!(validate_iface_name("").is_err());
        assert!(validate_iface_name("thisnameistoolong").is_err()); // > 15
    }

    #[test]
    fn rejects_rule_zone_without_interface() {
        let toml = r#"
            [system]
            hostname = "x"
            [[interface]]
            name = "eth0"
            zone = "lan"
            address = "10.0.0.1/24"
            [[rule]]
            name = "r"
            from = "lan"
            to = "dmz"
            action = "accept"
        "#;
        // `dmz` has no interface → invalid.
        assert!(Appliance::from_toml(toml).is_err());
    }

    #[test]
    fn rejects_bad_address_and_empty_hostname() {
        assert!(validate_address("10.0.0.1/33").is_err());
        assert!(validate_address("not-an-ip").is_err());
        assert!(validate_address("dhcp").is_ok());
        assert!(validate_address("192.168.1.1/24").is_ok());
    }

    #[test]
    fn nat_tables_round_trip_through_toml() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"

[[nat.source]]
name = "wan-masq"
zone = "wan"

[[nat.destination]]
name = "web"
zone = "wan"
proto = "tcp"
port = 443
to = "10.0.0.10:8443"
"#;
        let a = Appliance::from_toml(toml).expect("nat config parses + validates");
        assert_eq!(a.nat.source.len(), 1);
        assert_eq!(a.nat.destination.len(), 1);
        // Serialize back out and reparse — the `[[nat.source]]`/`[[nat.destination]]`
        // tables must survive a save→load cycle unchanged.
        let out = a.to_toml().unwrap();
        assert!(out.contains("[[nat.source]]"), "got:\n{out}");
        assert!(out.contains("[[nat.destination]]"), "got:\n{out}");
        let b = Appliance::from_toml(&out).expect("re-parses");
        assert_eq!(b.nat.source[0].zone, "wan");
        assert_eq!(b.nat.destination[0].to, "10.0.0.10:8443");
    }

    #[test]
    fn multiwan_round_trips_and_validates() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
address = "dhcp"
[[interface]]
name = "wan1"
zone = "wan"
address = "dhcp"

[multiwan]
mode = "load-balance"

[[multiwan.uplink]]
interface = "wan0"
priority = 10
gateway = "192.0.2.1"
[multiwan.uplink.health-check]
targets = ["1.1.1.1"]
interval = 5

[[multiwan.uplink]]
interface = "wan1"
priority = 20
"#;
        let a = Appliance::from_toml(toml).expect("multiwan config parses + validates");
        assert_eq!(a.multiwan.mode, WanMode::LoadBalance);
        assert_eq!(a.multiwan.uplinks.len(), 2);
        // Derived table ids: no explicit `table` ⇒ WAN_TABLE_BASE + idx.
        assert_eq!(a.multiwan.table_for(0, &a.multiwan.uplinks[0]), 200);
        assert_eq!(a.multiwan.table_for(1, &a.multiwan.uplinks[1]), 201);
        // Round-trips through TOML unchanged.
        let out = a.to_toml().unwrap();
        assert!(out.contains("[[multiwan.uplink]]"), "got:\n{out}");
        assert!(out.contains("mode = \"load-balance\""), "got:\n{out}");
        let b = Appliance::from_toml(&out).expect("re-parses");
        assert_eq!(b.multiwan.uplinks[0].gateway.as_deref(), Some("192.0.2.1"));
        assert_eq!(
            b.multiwan.uplinks[0].check.targets,
            vec!["1.1.1.1".to_string()]
        );
    }

    #[test]
    fn pki_round_trips_and_validates() {
        let toml = r#"
[system]
hostname = "fw"

[[pki.ca]]
name = "corp"
common-name = "corp.example.com"
organization = "Example Inc"
key-type = "ec"
validity-days = 3650

[[pki.certificate]]
name = "vpn-server"
ca = "corp"
common-name = "vpn.example.com"
subject-alt-name = ["DNS:vpn.example.com", "IP:10.0.0.1"]
usage = "server"

[pki.acme]
email = "admin@example.com"
challenge = "http-01"
agree-tos = true
"#;
        let a = Appliance::from_toml(toml).expect("pki config parses + validates");
        assert_eq!(a.pki.cas.len(), 1);
        assert_eq!(a.pki.cas[0].name, "corp");
        assert_eq!(a.pki.cas[0].organization.as_deref(), Some("Example Inc"));
        assert_eq!(a.pki.certificates.len(), 1);
        assert_eq!(a.pki.certificates[0].ca, "corp");
        assert_eq!(
            a.pki.certificates[0].subject_alt_names,
            vec!["DNS:vpn.example.com".to_string(), "IP:10.0.0.1".to_string()]
        );
        assert_eq!(
            a.pki.acme.as_ref().map(|c| c.email.as_str()),
            Some("admin@example.com")
        );
        // Round-trips through TOML unchanged, and `[pki]` is emitted.
        let out = a.to_toml().unwrap();
        assert!(out.contains("[[pki.ca]]"), "got:\n{out}");
        assert!(out.contains("[[pki.certificate]]"), "got:\n{out}");
        assert!(out.contains("[pki.acme]"), "got:\n{out}");
        let b = Appliance::from_toml(&out).expect("re-parses");
        assert_eq!(b.pki.certificates[0].common_name, "vpn.example.com");
    }

    #[test]
    fn pki_empty_is_omitted_from_output() {
        let a = Appliance::from_toml("[system]\nhostname = \"fw\"\n").unwrap();
        assert!(a.pki.is_empty());
        assert!(!a.to_toml().unwrap().contains("[pki"));
    }

    #[test]
    fn pki_rejects_cert_referencing_undeclared_ca() {
        let toml = r#"
[system]
hostname = "fw"
[[pki.certificate]]
name = "leaf"
ca = "ghost"
common-name = "leaf.example.com"
"#;
        let err = Appliance::from_toml(toml).unwrap_err().to_string();
        assert!(err.contains("unknown ca"), "got: {err}");
    }

    #[test]
    fn pki_rejects_acme_cert_without_account() {
        let toml = r#"
[system]
hostname = "fw"
[[pki.certificate]]
name = "public"
ca = "acme"
common-name = "www.example.com"
"#;
        let err = Appliance::from_toml(toml).unwrap_err().to_string();
        assert!(err.contains("no [pki.acme] account"), "got: {err}");
    }

    #[test]
    fn pki_rejects_bad_key_type_san_and_challenge() {
        let bad_key = "[system]\nhostname=\"fw\"\n[[pki.ca]]\nname=\"c\"\ncommon-name=\"c\"\nkey-type=\"dsa\"\n";
        assert!(
            Appliance::from_toml(bad_key)
                .unwrap_err()
                .to_string()
                .contains("key-type")
        );
        let bad_san = "[system]\nhostname=\"fw\"\n[[pki.ca]]\nname=\"c\"\ncommon-name=\"c\"\n[[pki.certificate]]\nname=\"l\"\nca=\"c\"\ncommon-name=\"l\"\nsubject-alt-name=[\"EMAIL:a@b\"]\n";
        assert!(
            format!("{:#}", Appliance::from_toml(bad_san).unwrap_err())
                .contains("must be DNS or IP")
        );
        let bad_ch =
            "[system]\nhostname=\"fw\"\n[pki.acme]\nemail=\"a@b.com\"\nchallenge=\"tls-alpn-01\"\n";
        assert!(
            Appliance::from_toml(bad_ch)
                .unwrap_err()
                .to_string()
                .contains("challenge")
        );
    }

    #[test]
    fn multiwan_rejects_unknown_interface_and_dup_table() {
        // An uplink naming an interface that isn't declared is rejected.
        let bad_if = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
[[multiwan.uplink]]
interface = "nope0"
"#;
        assert!(Appliance::from_toml(bad_if).is_err());
        // Two uplinks pinned to the same routing table collide.
        let dup_tbl = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
[[interface]]
name = "wan1"
zone = "wan"
[[multiwan.uplink]]
interface = "wan0"
table = 201
[[multiwan.uplink]]
interface = "wan1"
table = 201
"#;
        assert!(Appliance::from_toml(dup_tbl).is_err());
        // The main table (254) is reserved.
        let reserved = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
[[multiwan.uplink]]
interface = "wan0"
table = 254
"#;
        assert!(Appliance::from_toml(reserved).is_err());
    }

    #[test]
    fn portspec_parses_single_and_range() {
        assert_eq!(PortSpec::parse("443").unwrap(), PortSpec::Single(443));
        assert_eq!(
            PortSpec::parse("8000-8100").unwrap(),
            PortSpec::Range(8000, 8100)
        );
        // Whitespace around the dash is tolerated.
        assert_eq!(
            PortSpec::parse(" 100 - 200 ").unwrap(),
            PortSpec::Range(100, 200)
        );
        assert!(PortSpec::parse("not-a-port").is_err());
        assert!(PortSpec::parse("70000").is_err()); // > u16
    }

    #[test]
    fn portspec_rejects_inverted_zero_and_oversized() {
        assert!(PortSpec::Single(0).validate().is_err());
        assert!(PortSpec::Range(200, 100).validate().is_err()); // inverted
        assert!(PortSpec::Range(443, 443).validate().is_ok());
        // Exactly the cap is allowed; one past it is not.
        let lo = 1000;
        let hi = lo + MAX_PORT_RANGE as u16 - 1;
        assert!(PortSpec::Range(lo, hi).validate().is_ok());
        assert!(PortSpec::Range(lo, hi + 1).validate().is_err());
    }

    #[test]
    fn portspec_single_is_integer_range_is_string_in_toml() {
        // A single port stays a bare integer; a range becomes a string. Both
        // survive a save→load cycle.
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
[[interface]]
name = "lan0"
zone = "lan"
[[rule]]
name = "https"
from = "wan"
to = "lan"
action = "accept"
proto = "tcp"
port = 443
[[rule]]
name = "range"
from = "wan"
to = "lan"
action = "accept"
proto = "tcp"
port = "8000-8100"
"#;
        let a = Appliance::from_toml(toml).expect("range config parses");
        assert_eq!(a.rules[0].port, vec![PortSpec::Single(443)]);
        assert_eq!(a.rules[1].port, vec![PortSpec::Range(8000, 8100)]);
        let out = a.to_toml().unwrap();
        assert!(out.contains("port = 443"), "single stays integer:\n{out}");
        assert!(
            out.contains("port = \"8000-8100\""),
            "range stays string:\n{out}"
        );
        // Re-parse the saved form unchanged.
        let b = Appliance::from_toml(&out).unwrap();
        assert_eq!(b.rules[1].port, vec![PortSpec::Range(8000, 8100)]);
    }

    #[test]
    fn rejects_oversized_port_range_in_a_rule() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
[[interface]]
name = "lan0"
zone = "lan"
[[rule]]
name = "huge"
from = "wan"
to = "lan"
action = "accept"
proto = "tcp"
port = "1-65535"
"#;
        // The range is far over the cap → validation rejects it.
        assert!(Appliance::from_toml(toml).is_err());
    }

    #[test]
    fn firewall_groups_validate_references_and_exclusivity() {
        let base = |rule: &str| {
            format!(
                r#"
[system]
hostname = "fw"
[firewall.group.address]
mgmt = ["10.0.0.0/24"]
[firewall.group.port]
web = [80, 443]
[[interface]]
name = "wan0"
zone = "wan"
[[interface]]
name = "lan0"
zone = "lan"
[[rule]]
name = "r"
from = "wan"
to = "lan"
action = "accept"
proto = "tcp"
{rule}
"#
            )
        };
        // A rule referencing declared groups is accepted.
        assert!(
            Appliance::from_toml(&base("source_group = \"mgmt\"\nport_group = \"web\"")).is_ok()
        );
        // An unknown group is rejected.
        assert!(Appliance::from_toml(&base("port_group = \"nope\"")).is_err());
        assert!(
            Appliance::from_toml(&base("source_group = \"nope\"\nport_group = \"web\"")).is_err()
        );
        // A literal and a group on the same axis is rejected (ambiguous).
        assert!(
            Appliance::from_toml(&base("port = 22\nport_group = \"web\"")).is_err(),
            "port and port-group are mutually exclusive"
        );
        assert!(
            Appliance::from_toml(&base(
                "source = \"10.1.0.0/24\"\nsource_group = \"mgmt\"\nport_group = \"web\""
            ))
            .is_err(),
            "source and source-group are mutually exclusive"
        );
        // A bad address-group member (a hostname, not an IP/CIDR) is rejected.
        let bad = r#"
[system]
hostname = "fw"
[firewall.group.address]
mgmt = ["not-an-ip"]
[[interface]]
name = "wan0"
zone = "wan"
"#;
        assert!(Appliance::from_toml(bad).is_err());
    }

    #[test]
    fn zoneless_addressed_interface_draws_a_warning() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
address = "203.0.113.2/24"
[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"
[[interface]]
name = "mgmt0"
address = "192.168.9.1/24"
[[interface]]
name = "spare0"
[[rule]]
name = "allow-out"
from = "lan"
action = "accept"
"#;
        let a = Appliance::from_toml(toml).expect("valid config");
        let warns = a.warnings();
        // The zoneless but ADDRESSED NIC is flagged as unfirewalled...
        assert!(
            warns
                .iter()
                .any(|w| w.contains("mgmt0") && w.contains("no zone")),
            "expected a zoneless-interface warning for mgmt0, got: {warns:?}"
        );
        // ...while a zoned interface never is, and an address-less NIC (a pure
        // trunk/spare) is not noise-warned.
        assert!(
            !warns
                .iter()
                .any(|w| w.contains("wan0") || w.contains("lan0") || w.contains("spare0")),
            "only the zoneless addressed NIC should warn, got: {warns:?}"
        );
    }

    #[test]
    fn mtu_and_mac_parse_and_validate() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
address = "dhcp"
mtu = 1492
mac = "52:54:00:12:34:56"
"#;
        let a = Appliance::from_toml(toml).expect("mtu/mac config validates");
        assert_eq!(a.interfaces[0].mtu, Some(1492));
        assert_eq!(a.interfaces[0].mac.as_deref(), Some("52:54:00:12:34:56"));
        assert!(Appliance::from_toml(&a.to_toml().unwrap()).is_ok());
        // A silly MTU and a malformed MAC are rejected.
        assert!(validate_mac("52:54:00:12:34").is_err()); // 5 octets
        assert!(validate_mac("zz:54:00:12:34:56").is_err()); // non-hex
        let bad_mtu = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
mtu = 42
"#;
        assert!(Appliance::from_toml(bad_mtu).is_err());
    }

    #[test]
    fn static_routes_are_dual_stack() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
address = "10.0.0.1/24"

[[protocols.static]]
prefix = "192.0.2.0/24"
via = "10.0.0.254"

[[protocols.static]]
prefix = "2001:db8:beef::/48"
via = "2001:db8:0::1"
"#;
        let a = Appliance::from_toml(toml).expect("dual-stack static routes validate");
        assert_eq!(a.protocols.statics.len(), 2);
        assert_eq!(a.protocols.statics[1].prefix, "2001:db8:beef::/48");
        // A v4 nexthop for a v6 prefix is rejected (family mismatch).
        let mismatch = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
address = "10.0.0.1/24"
[[protocols.static]]
prefix = "2001:db8:beef::/48"
via = "10.0.0.254"
"#;
        assert!(Appliance::from_toml(mismatch).is_err());
    }

    #[test]
    fn dhcpv6_pd_parses_and_validates() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
address = "dhcp"
address6 = "dhcp"
[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"
pd-from = "wan0"
pd-subnet = 1
"#;
        let a = Appliance::from_toml(toml).expect("DHCPv6-PD config parses + validates");
        assert_eq!(a.interfaces[0].address6.as_deref(), Some("dhcp"));
        assert_eq!(a.interfaces[1].pd_from.as_deref(), Some("wan0"));
        assert_eq!(a.interfaces[1].pd_subnet, Some(1));
        let out = a.to_toml().unwrap();
        assert!(out.contains("pd-from = \"wan0\""), "got:\n{out}");
        assert!(Appliance::from_toml(&out).is_ok());
        // pd-from pointing at an undeclared interface is rejected.
        let bad = r#"
[system]
hostname = "fw"
[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"
pd-from = "nope0"
"#;
        assert!(Appliance::from_toml(bad).is_err());
    }

    #[test]
    fn dual_stack_address6_parses_and_validates() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"
address6 = "2001:db8:1::1/64"
[[interface]]
name = "wan0"
zone = "wan"
address = "dhcp"
address6 = "auto"
"#;
        let a = Appliance::from_toml(toml).expect("dual-stack config parses + validates");
        assert_eq!(
            a.interfaces[0].address6.as_deref(),
            Some("2001:db8:1::1/64")
        );
        assert_eq!(a.interfaces[1].address6.as_deref(), Some("auto"));
        // Round-trips.
        let out = a.to_toml().unwrap();
        assert!(
            out.contains("address6 = \"2001:db8:1::1/64\""),
            "got:\n{out}"
        );
        assert!(Appliance::from_toml(&out).is_ok());
        // An IPv4 CIDR in address6 is rejected (it must be v6 or "auto").
        let bad = r#"
[system]
hostname = "fw"
[[interface]]
name = "lan0"
zone = "lan"
address6 = "10.0.0.1/24"
"#;
        assert!(Appliance::from_toml(bad).is_err());
    }

    #[test]
    fn bridge_and_bond_parse_and_validate() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "br0"
type = "bridge"
zone = "lan"
address = "10.0.0.1/24"
member = ["lan1"]
[[interface]]
name = "lan1"
[[interface]]
name = "bond0"
type = "bond"
bond-mode = "802.3ad"
member = ["lan2"]
[[interface]]
name = "lan2"
"#;
        let a = Appliance::from_toml(toml).expect("bridge/bond config parses + validates");
        assert_eq!(a.interfaces[0].if_type, Some(IfaceType::Bridge));
        assert_eq!(a.interfaces[0].members, vec!["lan1".to_string()]);
        assert!(a.interfaces[2].is_bond());
        assert_eq!(a.interfaces[2].bond_mode.as_deref(), Some("802.3ad"));
        assert_eq!(a.interfaces[2].members, vec!["lan2".to_string()]);
        // Round-trips through TOML (type + members survive).
        let out = a.to_toml().unwrap();
        assert!(out.contains("type = \"bridge\""), "got:\n{out}");
        assert!(out.contains("member = [\"lan2\"]"), "got:\n{out}");
        assert!(Appliance::from_toml(&out).is_ok());
    }

    #[test]
    fn pppoe_client_parses_validates_and_round_trips() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "eth0"
[[interface]]
name = "ppp0"
type = "pppoe"
parent = "eth0"
zone = "wan"
mtu = 1492
[interface.pppoe]
username = "user@isp.de"
password = "s3cret"
service-name = "internet"
mru = 1492
"#;
        let a = Appliance::from_toml(toml).expect("pppoe config parses + validates");
        let ppp = &a.interfaces[1];
        assert!(ppp.is_pppoe());
        assert!(!ppp.is_virtual_l2(), "pppoe is not an L2 device");
        assert_eq!(ppp.parent.as_deref(), Some("eth0"));
        let p = ppp.pppoe.as_ref().unwrap();
        assert_eq!(p.username, "user@isp.de");
        assert_eq!(p.password, "s3cret");
        assert_eq!(p.service_name.as_deref(), Some("internet"));
        // Round-trips (type + credentials survive TOML).
        let out = a.to_toml().unwrap();
        assert!(out.contains("type = \"pppoe\""), "got:\n{out}");
        assert!(out.contains("username = \"user@isp.de\""), "got:\n{out}");
        assert!(Appliance::from_toml(&out).is_ok());
    }

    #[test]
    fn rejects_pppoe_credential_injection() {
        // A newline in a PPPoE credential injects a fresh pppd options directive
        // (connect, pty, plugin, …) that pppd runs AS ROOT — the credentials must
        // be charset-validated, not merely checked for emptiness.
        let base = |user: &str| {
            format!(
                "[system]\nhostname = \"fw\"\n\
                 [[interface]]\nname = \"eth0\"\n\
                 [[interface]]\nname = \"ppp0\"\ntype = \"pppoe\"\nparent = \"eth0\"\nzone = \"wan\"\n\
                 [interface.pppoe]\nusername = {user}\npassword = \"s3cret\"\n"
            )
        };
        // A clean username validates; a newline- or quote-bearing one is rejected.
        assert!(Appliance::from_toml(&base("\"user@isp.de\"")).is_ok());
        assert!(Appliance::from_toml(&base("\"user\\nconnect /bin/sh\"")).is_err());
        assert!(Appliance::from_toml(&base("\"user\\\"evil\"")).is_err());
    }

    #[test]
    fn rejects_snmp_community_and_listen_injection() {
        // A newline in the community injects an `rwcommunity` directive into
        // snmpd.conf (read-only agent → read-write); the listen spec is likewise
        // rendered verbatim. Both must be charset-validated.
        let cfg = |line: &str| format!("[system]\nhostname = \"fw\"\n[services.snmp]\n{line}\n");
        assert!(Appliance::from_toml(&cfg("community = \"public\"")).is_ok());
        assert!(Appliance::from_toml(&cfg("community = \"public\\nrwcommunity secret\"")).is_err());
        assert!(
            Appliance::from_toml(&cfg(
                "community = \"public\"\nlisten = \"udp:161\\nrwcommunity x\""
            ))
            .is_err()
        );
    }

    #[test]
    fn pppoe_rejects_bad_configs() {
        // type=pppoe without credentials is rejected.
        let no_creds = r#"
[system]
hostname = "fw"
[[interface]]
name = "eth0"
[[interface]]
name = "ppp0"
type = "pppoe"
parent = "eth0"
"#;
        assert!(Appliance::from_toml(no_creds).is_err());
        // A pppoe parent that isn't a declared interface is rejected.
        let bad_parent = r#"
[system]
hostname = "fw"
[[interface]]
name = "ppp0"
type = "pppoe"
parent = "eth9"
[interface.pppoe]
username = "u"
password = "p"
"#;
        assert!(Appliance::from_toml(bad_parent).is_err());
        // A non-`ppp*` name for a pppoe interface is rejected.
        let bad_name = r#"
[system]
hostname = "fw"
[[interface]]
name = "eth0"
[[interface]]
name = "wan0"
type = "pppoe"
parent = "eth0"
[interface.pppoe]
username = "u"
password = "p"
"#;
        assert!(Appliance::from_toml(bad_name).is_err());
        // A static address on a pppoe interface (its address comes from the peer)
        // is rejected.
        let with_addr = r#"
[system]
hostname = "fw"
[[interface]]
name = "eth0"
[[interface]]
name = "ppp0"
type = "pppoe"
parent = "eth0"
address = "10.0.0.1/24"
[interface.pppoe]
username = "u"
password = "p"
"#;
        assert!(Appliance::from_toml(with_addr).is_err());
        // `pppoe` credentials without type=pppoe are rejected.
        let creds_no_type = r#"
[system]
hostname = "fw"
[[interface]]
name = "eth0"
[interface.pppoe]
username = "u"
password = "p"
"#;
        assert!(Appliance::from_toml(creds_no_type).is_err());
    }

    #[test]
    fn qos_parses_validates_and_round_trips() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "eth0"
address = "10.0.0.1/24"
[interface.qos]
discipline = "cake"
bandwidth = "100mbit"
rtt = "internet"
nat = true
ack-filter = true
diffserv = "diffserv4"
"#;
        let a = Appliance::from_toml(toml).expect("cake qos parses + validates");
        let q = a.interfaces[0].qos.as_ref().unwrap();
        assert!(q.is_cake());
        assert_eq!(q.bandwidth.as_deref(), Some("100mbit"));
        assert_eq!(q.diffserv.as_deref(), Some("diffserv4"));
        assert!(q.nat && q.ack_filter);
        // Round-trips: the sub-table survives serialize→parse.
        let out = a.to_toml().unwrap();
        assert!(out.contains("[interface.qos]"), "got:\n{out}");
        assert!(out.contains("discipline = \"cake\""), "got:\n{out}");
        let a2 = Appliance::from_toml(&out).expect("qos re-parses");
        assert_eq!(
            a2.interfaces[0].qos.as_ref().unwrap().bandwidth.as_deref(),
            Some("100mbit")
        );

        // fq_codel with its own knobs.
        let fq = r#"
[system]
hostname = "fw"
[[interface]]
name = "eth0"
address = "10.0.0.1/24"
[interface.qos]
discipline = "fq_codel"
target = "5ms"
interval = "100ms"
limit = 1200
"#;
        let a = Appliance::from_toml(fq).expect("fq_codel qos parses");
        let q = a.interfaces[0].qos.as_ref().unwrap();
        assert!(!q.is_cake());
        assert_eq!(q.target.as_deref(), Some("5ms"));
        assert_eq!(q.limit, Some(1200));
    }

    #[test]
    fn qos_rejects_bad_and_cross_discipline_configs() {
        let base = |block: &str| {
            format!(
                "[system]\nhostname = \"fw\"\n[[interface]]\nname = \"eth0\"\naddress = \"10.0.0.1/24\"\n[interface.qos]\n{block}"
            )
        };
        // fq_codel knobs on a cake qdisc are rejected.
        assert!(Appliance::from_toml(&base("discipline = \"cake\"\ntarget = \"5ms\"\n")).is_err());
        // cake knobs on an fq_codel qdisc are rejected (fq_codel doesn't shape).
        assert!(
            Appliance::from_toml(&base(
                "discipline = \"fq_codel\"\nbandwidth = \"100mbit\"\n"
            ))
            .is_err()
        );
        // A malformed tc rate is rejected.
        assert!(
            Appliance::from_toml(&base(
                "discipline = \"cake\"\nbandwidth = \"100furlongs\"\n"
            ))
            .is_err()
        );
        // A malformed tc time is rejected.
        assert!(
            Appliance::from_toml(&base("discipline = \"fq_codel\"\ntarget = \"soon\"\n")).is_err()
        );
        // An unknown diffserv mode is rejected.
        assert!(
            Appliance::from_toml(&base("discipline = \"cake\"\ndiffserv = \"diffserv5\"\n"))
                .is_err()
        );
        // Direct validator checks.
        assert!(validate_tc_rate("100mbit").is_ok());
        assert!(validate_tc_rate("unlimited").is_ok());
        assert!(validate_tc_rate("20gbit").is_ok());
        assert!(validate_tc_rate("100furlongs").is_err());
        assert!(validate_tc_time("5ms").is_ok());
        assert!(validate_tc_time("1s").is_ok());
        assert!(validate_tc_time("nope").is_err());
    }

    #[test]
    fn bridge_bond_reject_bad_master_mode_and_combos() {
        // `member` on a non-device interface is rejected.
        let member_on_plain = r#"
[system]
hostname = "fw"
[[interface]]
name = "eth0"
zone = "lan"
member = ["eth1"]
[[interface]]
name = "eth1"
"#;
        assert!(Appliance::from_toml(member_on_plain).is_err());
        // A member that is not a declared interface is rejected.
        let unknown_member = r#"
[system]
hostname = "fw"
[[interface]]
name = "br0"
type = "bridge"
member = ["ghost"]
"#;
        assert!(Appliance::from_toml(unknown_member).is_err());
        // A member enslaved to two devices is rejected.
        let double_member = r#"
[system]
hostname = "fw"
[[interface]]
name = "br0"
type = "bridge"
member = ["eth1"]
[[interface]]
name = "bond0"
type = "bond"
member = ["eth1"]
[[interface]]
name = "eth1"
"#;
        assert!(Appliance::from_toml(double_member).is_err());
        // A member that is itself a bridge/bond is rejected (no nesting).
        let nested_member = r#"
[system]
hostname = "fw"
[[interface]]
name = "br0"
type = "bridge"
member = ["bond0"]
[[interface]]
name = "bond0"
type = "bond"
"#;
        assert!(Appliance::from_toml(nested_member).is_err());
        // bond-mode on a bridge is rejected.
        let mode_on_bridge = r#"
[system]
hostname = "fw"
[[interface]]
name = "br0"
type = "bridge"
bond-mode = "active-backup"
"#;
        assert!(Appliance::from_toml(mode_on_bridge).is_err());
        // an unknown bonding mode is rejected.
        let bad_mode = r#"
[system]
hostname = "fw"
[[interface]]
name = "bond0"
type = "bond"
bond-mode = "round-robin"
"#;
        assert!(Appliance::from_toml(bad_mode).is_err());
    }

    #[test]
    fn wireguard_moves_under_vpn() {
        let key = "OK+2ftLGli1Dle9tRWx5Bj0eLc0X7KcInScVBpg+3lc=";
        let toml = format!(
            r#"
[system]
hostname = "fw"
[[interface]]
name = "wg0"
type = "wireguard"
zone = "vpn"
address = "10.9.0.1/24"
[[vpn.wireguard]]
name = "wg0"
private-key = "{key}"
listen-port = 51820
[[vpn.wireguard.peer]]
public-key = "{key}"
allowed-ips = ["10.9.0.2/32"]
endpoint = "203.0.113.9:51820"
persistent-keepalive = 25
"#
        );
        let a = Appliance::from_toml(&toml).expect("wireguard config parses + validates");
        assert!(a.interfaces[0].is_wireguard());
        assert_eq!(a.vpn.wireguard.len(), 1);
        assert_eq!(a.vpn.wireguard[0].name, "wg0");
        assert_eq!(a.vpn.wireguard[0].peers.len(), 1);
        // Round-trips.
        let out = a.to_toml().unwrap();
        assert!(out.contains("type = \"wireguard\""), "got:\n{out}");
        assert!(out.contains("[[vpn.wireguard]]"), "got:\n{out}");
        assert!(Appliance::from_toml(&out).is_ok());
    }

    #[test]
    fn wireguard_iface_without_tunnel_is_rejected() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "wg0"
type = "wireguard"
address = "10.9.0.1/24"
"#;
        // A type=wireguard interface with no [[vpn.wireguard]] entry is an error.
        assert!(Appliance::from_toml(toml).is_err());
    }

    #[test]
    fn wireguard_tunnel_without_iface_is_rejected() {
        let key = "OK+2ftLGli1Dle9tRWx5Bj0eLc0X7KcInScVBpg+3lc=";
        let toml = format!(
            r#"
[system]
hostname = "fw"
[[vpn.wireguard]]
name = "wg0"
private-key = "{key}"
"#
        );
        // A tunnel that names no declared wireguard interface is an error.
        assert!(Appliance::from_toml(&toml).is_err());
    }

    #[test]
    fn vlan_parent_and_id_inferred_from_name() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "eth0"
zone = "lan"
address = "10.0.0.1/24"
[[interface]]
name = "eth0.20"
zone = "iot"
address = "10.0.20.1/24"
"#;
        let a = Appliance::from_toml(toml).expect("vlan inference parses + validates");
        assert_eq!(a.interfaces[1].parent.as_deref(), Some("eth0"));
        assert_eq!(a.interfaces[1].vlan, Some(20));
        // A name/value mismatch is rejected.
        let mismatch = r#"
[system]
hostname = "fw"
[[interface]]
name = "eth0"
zone = "lan"
address = "10.0.0.1/24"
[[interface]]
name = "eth0.20"
parent = "eth0"
vlan = 30
zone = "iot"
address = "10.0.20.1/24"
"#;
        assert!(Appliance::from_toml(mismatch).is_err());
    }

    #[test]
    fn vlan_aware_bridge_ports_parse_and_validate() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "br0"
type = "bridge"
vlan-aware = true
zone = "lan"
address = "10.0.0.1/24"
member = ["lan1"]
[[interface]]
name = "lan1"
vlan-tagged = [10, 20]
vlan-untagged = 1
"#;
        let a = Appliance::from_toml(toml).expect("vlan-aware bridge parses + validates");
        assert_eq!(a.interfaces[0].vlan_aware, Some(true));
        assert_eq!(a.interfaces[1].vlan_tagged, vec![10u16, 20u16]);
        assert_eq!(a.interfaces[1].vlan_untagged, Some(1));
        assert!(Appliance::from_toml(&a.to_toml().unwrap()).is_ok());
        // vlan-aware on a non-bridge is rejected.
        let aware_on_bond = r#"
[system]
hostname = "fw"
[[interface]]
name = "bond0"
type = "bond"
vlan-aware = true
"#;
        assert!(Appliance::from_toml(aware_on_bond).is_err());
        // vlan-tagged on a port that isn't a member of a vlan-aware bridge.
        let orphan_tagged = r#"
[system]
hostname = "fw"
[[interface]]
name = "eth0"
zone = "lan"
vlan-tagged = [10]
"#;
        assert!(Appliance::from_toml(orphan_tagged).is_err());
    }

    #[test]
    fn tunnel_parses_validates_and_round_trips() {
        // A well-formed keyed GRE tunnel parses, validates and survives a
        // TOML round-trip (endpoints, key, ttl, zone + inner address preserved).
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "tun0"
type = "gre"
zone = "vpn"
address = "172.16.0.1/30"
local = "10.0.0.1"
remote = "10.0.0.2"
key = 42
ttl = 64
"#;
        let a = Appliance::from_toml(toml).expect("gre tunnel parses + validates");
        let gre = a.interfaces.iter().find(|i| i.name == "tun0").unwrap();
        assert_eq!(gre.if_type, Some(IfaceType::Gre));
        assert_eq!(gre.local.as_deref(), Some("10.0.0.1"));
        assert_eq!(gre.remote.as_deref(), Some("10.0.0.2"));
        assert_eq!(gre.tunnel_key, Some(42));
        assert_eq!(gre.ttl, Some(64));
        let out = a.to_toml().expect("serialises");
        Appliance::from_toml(&out).expect("re-parses");
    }

    #[test]
    fn tunnel_rejects_bad_combos() {
        // A tunnel without endpoints is rejected.
        let no_endpoints = r#"
[system]
hostname = "fw"
[[interface]]
name = "tun0"
type = "gre"
"#;
        assert!(Appliance::from_toml(no_endpoints).is_err());
        // Mismatched endpoint families (v4 local, v6 remote) are rejected.
        let mixed = r#"
[system]
hostname = "fw"
[[interface]]
name = "tun0"
type = "gre"
local = "10.0.0.1"
remote = "2001:db8::2"
"#;
        assert!(Appliance::from_toml(mixed).is_err());
        // A key on an IPIP tunnel (which carries none) is rejected.
        let ipip_key = r#"
[system]
hostname = "fw"
[[interface]]
name = "ipip0"
type = "ipip"
local = "10.0.0.1"
remote = "10.0.0.2"
key = 7
"#;
        assert!(Appliance::from_toml(ipip_key).is_err());
        // local/remote without a tunnel `type` is rejected.
        let orphan = r#"
[system]
hostname = "fw"
[[interface]]
name = "eth0"
local = "10.0.0.1"
remote = "10.0.0.2"
"#;
        assert!(Appliance::from_toml(orphan).is_err());
        // A tunnel named after the kernel's fallback device (`gre0`) is rejected:
        // it would collide with the module's auto-created catch-all and black-hole.
        let fallback_name = r#"
[system]
hostname = "fw"
[[interface]]
name = "gre0"
type = "gre"
local = "10.0.0.1"
remote = "10.0.0.2"
"#;
        assert!(Appliance::from_toml(fallback_name).is_err());
    }

    #[test]
    fn dns_forwarder_parses_validates_and_round_trips() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"

[services.dns]
upstream = ["9.9.9.9", "2620:fe::fe"]
serve-on = ["lan0"]
dnssec = "no"
"#;
        let a = Appliance::from_toml(toml).expect("dns config parses + validates");
        assert_eq!(a.services.dns.upstream, vec!["9.9.9.9", "2620:fe::fe"]);
        assert_eq!(a.services.dns.serve_on, vec!["lan0"]);
        let out = a.to_toml().unwrap();
        assert!(out.contains("[services.dns]"), "got:\n{out}");
        let b = Appliance::from_toml(&out).expect("re-parses");
        assert_eq!(b.services.dns.upstream.len(), 2);
    }

    #[test]
    fn ntp_server_parses_validates_and_round_trips() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"

[services.ntp]
upstream = ["pool.ntp.org", "10.0.0.99"]
serve-on = ["lan0"]
"#;
        let a = Appliance::from_toml(toml).expect("ntp config parses + validates");
        assert_eq!(a.services.ntp.upstream, vec!["pool.ntp.org", "10.0.0.99"]);
        assert_eq!(a.services.ntp.serve_on, vec!["lan0"]);
        let out = a.to_toml().unwrap();
        assert!(out.contains("[services.ntp]"), "got:\n{out}");
        assert!(Appliance::from_toml(&out).is_ok());
        // serve-on an interface without a static address is rejected.
        let bad = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
address = "dhcp"
[services.ntp]
serve-on = ["wan0"]
"#;
        assert!(Appliance::from_toml(bad).is_err());
    }

    #[test]
    fn box_services_parse_validate_and_round_trip() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"
[[interface]]
name = "iot0"
zone = "iot"
address = "10.0.7.1/24"

[services.lldp]
enable = true
interface = ["lan0", "iot0"]

[services.snmp]
community = "public"
location = "rack 4"
contact = "noc@example"
allow = ["10.0.0.0/24", "fd00::/64"]

[services.mdns]
interface = ["lan0", "iot0"]

[services.dyndns]
provider = "cloudflare"
hostname = "fw.example.com"
login = "user@example"
password = "secret-token"
interface = "lan0"

[services.dhcp-relay]
interface = ["iot0"]
server = ["10.0.0.99"]
"#;
        let a = Appliance::from_toml(toml).expect("box services parse + validate");
        assert!(a.services.lldp.enable);
        assert_eq!(a.services.lldp.interface, vec!["lan0", "iot0"]);
        assert_eq!(a.services.snmp.community.as_deref(), Some("public"));
        assert_eq!(a.services.snmp.allow.len(), 2);
        assert_eq!(a.services.mdns.interface, vec!["lan0", "iot0"]);
        assert_eq!(
            a.services.dyndns.hostname.as_deref(),
            Some("fw.example.com")
        );
        assert_eq!(a.services.dhcp_relay.server, vec!["10.0.0.99"]);
        let out = a.to_toml().unwrap();
        for section in [
            "[services.lldp]",
            "[services.snmp]",
            "[services.mdns]",
            "[services.dyndns]",
            "[services.dhcp-relay]",
        ] {
            assert!(out.contains(section), "missing {section}:\n{out}");
        }
        let b = Appliance::from_toml(&out).expect("re-parses");
        assert_eq!(b.services.dhcp_relay.interface, vec!["iot0"]);
    }

    #[test]
    fn dhcp_relay_v6_parses_validates_and_round_trips() {
        let base = |relay: &str| {
            format!(
                r#"
[system]
hostname = "fw"
[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"
address6 = "2001:db8:1::1/64"
[services.dhcp-relay]
interface = ["lan0"]
{relay}
"#
            )
        };
        // A v6-only relay (server6, no v4 server) validates and round-trips.
        let a = Appliance::from_toml(&base("server6 = [\"2001:db8:99::1\", \"ff05::1:3\"]"))
            .expect("v6 relay parses + validates");
        assert_eq!(
            a.services.dhcp_relay.server6,
            vec!["2001:db8:99::1", "ff05::1:3"]
        );
        assert!(a.services.dhcp_relay.server.is_empty());
        let round = Appliance::from_toml(&a.to_toml().unwrap()).unwrap();
        assert_eq!(
            round.services.dhcp_relay.server6,
            a.services.dhcp_relay.server6
        );

        // Dual-stack (server + server6) also validates.
        assert!(
            Appliance::from_toml(&base(
                "server = [\"10.0.0.99\"]\nserver6 = [\"2001:db8:99::1\"]"
            ))
            .is_ok()
        );

        // Bad: server6 that is not an IPv6.
        assert!(Appliance::from_toml(&base("server6 = [\"not-a-v6\"]")).is_err());

        // Bad: relaying v6 on an interface without a static `address6`.
        let no_v6 = r#"
[system]
hostname = "fw"
[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"
[services.dhcp-relay]
interface = ["lan0"]
server6 = ["2001:db8:99::1"]
"#;
        assert!(Appliance::from_toml(no_v6).is_err());
    }

    #[test]
    fn box_services_reject_invalid_config() {
        // SNMP allow that is not an IP/CIDR is rejected.
        let bad_snmp = r#"
[system]
hostname = "fw"
[services.snmp]
community = "public"
allow = ["not-a-cidr"]
"#;
        assert!(Appliance::from_toml(bad_snmp).is_err());

        // A DHCP relay on the same interface as a DHCP server is rejected.
        let both = r#"
[system]
hostname = "fw"
[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"
[interface.dhcp-server]
pool-offset = 100
pool-size = 100
[services.dhcp-relay]
interface = ["lan0"]
server = ["10.0.99.1"]
"#;
        assert!(Appliance::from_toml(both).is_err());

        // An mDNS reflector with a single interface is rejected.
        let one_iface = r#"
[system]
hostname = "fw"
[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"
[services.mdns]
interface = ["lan0"]
"#;
        assert!(Appliance::from_toml(one_iface).is_err());

        // A dyndns client without a hostname is rejected.
        let no_host = r#"
[system]
hostname = "fw"
[services.dyndns]
provider = "dyndns2"
login = "user"
"#;
        assert!(Appliance::from_toml(no_host).is_err());
    }

    #[test]
    fn dns_forwarder_rejects_bad_upstream_and_serve_on() {
        // serve-on an interface with no static address is rejected.
        let no_addr = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
address = "dhcp"
[services.dns]
serve-on = ["wan0"]
"#;
        assert!(Appliance::from_toml(no_addr).is_err());
        // A non-IP upstream is rejected.
        let bad_up = r#"
[system]
hostname = "fw"
[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"
[services.dns]
upstream = ["not-an-ip"]
serve-on = ["lan0"]
"#;
        assert!(Appliance::from_toml(bad_up).is_err());
    }

    #[test]
    fn router_advert_parses_and_round_trips() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"

[interface.router-advert]
prefixes = ["2001:db8:1::/64"]
dns = ["2001:db8:1::1"]
other-config = true
router-lifetime = 1800
"#;
        let a = Appliance::from_toml(toml).expect("RA config parses + validates");
        let ra = a.interfaces[0].router_advert.as_ref().expect("has RA");
        assert_eq!(ra.prefixes, vec!["2001:db8:1::/64"]);
        assert_eq!(ra.dns, vec!["2001:db8:1::1"]);
        assert!(ra.other_config && !ra.managed);
        assert_eq!(ra.router_lifetime, Some(1800));
        // Survives a save → load cycle.
        let out = a.to_toml().unwrap();
        assert!(out.contains("[interface.router-advert]"), "got:\n{out}");
        let b = Appliance::from_toml(&out).expect("re-parses");
        assert_eq!(
            b.interfaces[0]
                .router_advert
                .as_ref()
                .unwrap()
                .prefixes
                .len(),
            1
        );
    }

    #[test]
    fn dhcp6_pool_parses_validates_and_round_trips() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"

[interface.router-advert]
prefixes = ["2001:db8:1::/64"]
dhcp6-pool = { start = "2001:db8:1::100", end = "2001:db8:1::1ff", lease-time = 43200 }
"#;
        let a = Appliance::from_toml(toml).expect("dhcp6-pool parses + validates");
        let pool = a.interfaces[0]
            .router_advert
            .as_ref()
            .unwrap()
            .dhcp6_pool
            .as_ref()
            .expect("has a pool");
        assert_eq!(pool.start, "2001:db8:1::100");
        assert_eq!(pool.end, "2001:db8:1::1ff");
        assert_eq!(pool.lease_time, Some(43200));
        // Survives save → load.
        let out = a.to_toml().unwrap();
        assert!(out.contains("dhcp6-pool"), "got:\n{out}");
        assert!(Appliance::from_toml(&out).is_ok());
    }

    #[test]
    fn dhcp6_pool_rejects_bad_combos() {
        let base = |pool: &str| {
            format!(
                r#"
[system]
hostname = "fw"
[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"
[interface.router-advert]
prefixes = ["2001:db8:1::/64"]
dhcp6-pool = {pool}
"#
            )
        };
        // start above end.
        assert!(
            Appliance::from_toml(&base(
                r#"{ start = "2001:db8:1::200", end = "2001:db8:1::100" }"#
            ))
            .is_err()
        );
        // pool outside every advertised prefix.
        assert!(
            Appliance::from_toml(&base(
                r#"{ start = "2001:db8:2::10", end = "2001:db8:2::20" }"#
            ))
            .is_err()
        );
        // a non-IPv6 endpoint.
        assert!(
            Appliance::from_toml(&base(r#"{ start = "10.0.0.1", end = "2001:db8:1::20" }"#))
                .is_err()
        );
        // a pool with no advertised prefix to sit in.
        let no_prefix = r#"
[system]
hostname = "fw"
[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"
[interface.router-advert]
dhcp6-pool = { start = "2001:db8:1::10", end = "2001:db8:1::20" }
"#;
        assert!(Appliance::from_toml(no_prefix).is_err());
    }

    #[test]
    fn router_advert_rejects_bad_prefix_and_dns() {
        // A non-/64-shaped but syntactically bad prefix (IPv4) is rejected.
        let bad_prefix = r#"
[system]
hostname = "fw"
[[interface]]
name = "lan0"
zone = "lan"
[interface.router-advert]
prefixes = ["10.0.0.0/24"]
"#;
        assert!(Appliance::from_toml(bad_prefix).is_err());
        // An IPv4 RDNSS in an IPv6 RA is rejected.
        let bad_dns = r#"
[system]
hostname = "fw"
[[interface]]
name = "lan0"
zone = "lan"
[interface.router-advert]
prefixes = ["2001:db8:1::/64"]
dns = ["10.0.0.1"]
"#;
        assert!(Appliance::from_toml(bad_dns).is_err());
    }

    #[test]
    fn toml_json_roundtrip_is_lossless() {
        let a = Appliance::from_toml(EXAMPLE).unwrap();
        // TOML -> JSON -> TOML preserves the config.
        let via_json = Appliance::from_json(&a.to_json().unwrap()).unwrap();
        let via_toml = Appliance::from_toml(&a.to_toml().unwrap()).unwrap();
        assert_eq!(a.summary(), via_json.summary());
        assert_eq!(a.summary(), via_toml.summary());
    }

    #[test]
    fn nat64_parses_validates_and_round_trips() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "lan6"
zone = "lan"
address6 = "2001:db8:64::1/64"
[zone.lan]
[services.dns]
upstream = ["10.64.2.2"]
[nat.nat64]
enabled = true
prefix = "64:ff9b::/96"
pool = "192.0.2.0/24"
interface = "lan6"
dns64 = true
"#;
        let a = Appliance::from_toml(toml).expect("nat64 config parses + validates");
        assert!(a.nat.nat64.enabled && a.nat.nat64.dns64);
        assert_eq!(a.nat.nat64.effective_prefix(), "64:ff9b::/96");
        assert_eq!(a.nat.nat64.pool.as_deref(), Some("192.0.2.0/24"));
        assert!(!a.nat.is_empty());
        // Round-trips through TOML losslessly.
        let b = Appliance::from_toml(&a.to_toml().unwrap()).expect("re-parses");
        assert_eq!(a.summary(), b.summary());
        // The well-known prefix is the default when omitted.
        let dflt = Nat64 {
            enabled: true,
            pool: Some("192.0.2.0/24".into()),
            ..Default::default()
        };
        assert_eq!(dflt.effective_prefix(), NAT64_WELL_KNOWN_PREFIX);
    }

    #[test]
    fn nat64_validation_rejects_bad_config() {
        let base = |body: &str| {
            format!(
                "[system]\nhostname = \"fw\"\n[[interface]]\nname = \"lan6\"\nzone = \"lan\"\naddress6 = \"2001:db8:64::1/64\"\n[zone.lan]\n[services.dns]\nupstream = [\"10.64.2.2\"]\n{body}"
            )
        };
        // enabled without a pool.
        assert!(
            Appliance::from_toml(&base("[nat.nat64]\nenabled = true\ninterface = \"lan6\"\n"))
                .is_err()
        );
        // enabled without an interface (the v6 side is required).
        assert!(
            Appliance::from_toml(&base(
                "[nat.nat64]\nenabled = true\npool = \"192.0.2.0/24\"\n"
            ))
            .is_err()
        );
        // A pool that is a bare host, not a CIDR.
        assert!(
            Appliance::from_toml(&base(
                "[nat.nat64]\nenabled = true\npool = \"192.0.2.1\"\ninterface = \"lan6\"\n"
            ))
            .is_err()
        );
        // A prefix that is not a /96.
        assert!(Appliance::from_toml(&base(
            "[nat.nat64]\nenabled = true\npool = \"192.0.2.0/24\"\ninterface = \"lan6\"\nprefix = \"64:ff9b::/64\"\n"
        ))
        .is_err());
        // dns64 naming an undeclared interface.
        assert!(Appliance::from_toml(&base(
            "[nat.nat64]\nenabled = true\npool = \"192.0.2.0/24\"\ninterface = \"nope\"\ndns64 = true\n"
        ))
        .is_err());
        // A valid dns64 config parses.
        assert!(Appliance::from_toml(&base(
            "[nat.nat64]\nenabled = true\npool = \"192.0.2.0/24\"\ninterface = \"lan6\"\ndns64 = true\n"
        ))
        .is_ok());
    }

    #[test]
    fn nat64_dns64_requires_upstream() {
        // dns64 on, interface with static v6, but no [services.dns] upstream.
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "lan6"
zone = "lan"
address6 = "2001:db8:64::1/64"
[zone.lan]
[nat.nat64]
enabled = true
pool = "192.0.2.0/24"
interface = "lan6"
dns64 = true
"#;
        assert!(Appliance::from_toml(toml).is_err());
    }

    #[test]
    fn bgp_full_neighbor_and_filter_parse_validate_and_round_trip() {
        let toml = r#"
[system]
hostname = "r1"
[protocols]
router-id = "10.0.0.1"
[protocols.bgp]
local-as = 65001
hold-time = 90
confederation-id = 65000
confederation-members = [65002]
community = ["65001:100", "no-export"]
multipath = 4
ebgp-require-policy = true
[[protocols.bgp.roa]]
prefix = "10.0.0.0/8"
max-length = 24
origin-as = 65001
[[protocols.bgp.neighbor]]
address = "10.10.0.2"
remote-as = 65002
passive = true
route-reflector-client = true
ttl-security = 1
password = "s3cret"
max-prefix = 1000
role = "customer"
import = "from-peer"
export = "to-peer"
bfd = true
bfd-auth-type = "meticulous-sha1"
[[policy.route-map]]
name = "from-peer"
default = "reject"
[[policy.route-map.rule]]
seq = 10
prefix = ["10.0.0.0/8+"]
set-metric = 100
set-community = ["65001:200"]
action = "accept"
[[policy.route-map]]
name = "to-peer"
"#;
        let a = Appliance::from_toml(toml).expect("full bgp config parses + validates");
        let bgp = a.protocols.bgp.as_ref().unwrap();
        assert_eq!(bgp.hold_time, Some(90));
        assert_eq!(bgp.confederation_members, vec![65002]);
        let n = &bgp.neighbors[0];
        assert!(n.passive && n.route_reflector_client && n.bfd);
        assert_eq!(n.ttl_security, Some(1));
        assert_eq!(n.role.as_deref(), Some("customer"));
        assert_eq!(n.import.as_deref(), Some("from-peer"));
        assert_eq!(a.policy.route_maps.len(), 2);
        assert_eq!(a.policy.route_maps[0].rules[0].action, "accept");
        // Round-trips through TOML losslessly.
        let b = Appliance::from_toml(&a.to_toml().unwrap()).expect("re-parses");
        assert_eq!(a.summary(), b.summary());
    }

    #[test]
    fn bgp_and_filter_validation_rejects_bad_values() {
        let base = "[system]\nhostname = \"r1\"\n[protocols]\n[protocols.bgp]\nlocal-as = 65001\n";
        // An unknown role is rejected.
        let bad_role = format!(
            "{base}[[protocols.bgp.neighbor]]\naddress = \"10.0.0.2\"\nremote-as = 65002\nrole = \"bogus\"\n"
        );
        assert!(Appliance::from_toml(&bad_role).is_err());
        // ttl-security out of range is rejected.
        let bad_ttl = format!(
            "{base}[[protocols.bgp.neighbor]]\naddress = \"10.0.0.2\"\nremote-as = 65002\nttl-security = 255\n"
        );
        assert!(Appliance::from_toml(&bad_ttl).is_err());
        // An import referencing an undeclared filter is rejected.
        let dangling = format!(
            "{base}[[protocols.bgp.neighbor]]\naddress = \"10.0.0.2\"\nremote-as = 65002\nimport = \"nope\"\n"
        );
        assert!(Appliance::from_toml(&dangling).is_err());
        // A route-map rule with a non-accept/reject action is rejected.
        let bad_action = "[system]\nhostname = \"r1\"\n[[policy.route-map]]\nname = \"f\"\n[[policy.route-map.rule]]\naction = \"drop\"\n";
        assert!(Appliance::from_toml(bad_action).is_err());
    }

    #[test]
    fn protocols_igp_full_surface_parses_validates_and_round_trips() {
        let toml = r#"
[system]
hostname = "r1"
[protocols]
router-id = "10.0.0.1"
import = { static = "f1" }
[[policy.route-map]]
name = "f1"
default = "accept"
[[protocols.vrf]]
name = "blue"
table = 100
interfaces = ["eth3"]
import = "f1"
[[protocols.static]]
prefix = "10.9.0.0/24"
via = "10.0.0.2"
vrf = "blue"
[protocols.export]
kernel = "f1"
[protocols.ospf]
interfaces = ["eth0"]
router-priority = 5
auth-type = "md5"
hello-interval = 5
graceful-restart = true
bfd = true
vrf = "blue"
[[protocols.ospf.interface]]
name = "eth1"
area = "0.0.0.1"
[protocols.ospf3]
interfaces = ["eth0"]
instance-id = 2
[protocols.babel]
interfaces = ["eth0"]
network = ["2001:db8::/64"]
bfd = true
vrf = "blue"
[protocols.bfd]
min-tx = 250
auth-type = "meticulous-sha1"
echo = true
[protocols.multicast]
enabled = true
[[protocols.multicast.interface]]
name = "wan0"
role = "upstream"
[[protocols.vrrp]]
name = "v1"
interface = "eth0"
vrid = 10
advert-interval = 500
preempt = false
track-interface = ["eth1"]
priority-decrement = 30
virtual-address = ["10.0.0.254"]
"#;
        let a = Appliance::from_toml(toml).expect("parses + validates");
        let p = &a.protocols;
        assert_eq!(
            p.ospf.as_ref().unwrap().interface[0].area.as_deref(),
            Some("0.0.0.1")
        );
        assert_eq!(p.ospf3.as_ref().unwrap().instance_id, Some(2));
        assert_eq!(p.vrfs[0].table, 100);
        assert_eq!(
            p.multicast.as_ref().unwrap().interfaces[0].role.as_deref(),
            Some("upstream")
        );
        assert_eq!(p.vrrp[0].preempt, Some(false));
        // Round-trips through its own serialization.
        let a2 = Appliance::from_toml(&a.to_toml().unwrap()).expect("re-parses");
        assert_eq!(a2.protocols.bfd.as_ref().unwrap().min_tx, Some(250));
    }

    #[test]
    fn protocols_new_validation_rejects_bad_values() {
        let base = "[system]\nhostname = \"r1\"\n[protocols]\n";
        // RIPng rejects the RIP/Babel-only extras.
        assert!(Appliance::from_toml(&format!("{base}[protocols.ripng]\nbfd = true\n")).is_err());
        // An unknown VRF reference is rejected.
        assert!(
            Appliance::from_toml(&format!("{base}[protocols.ospf]\nvrf = \"nope\"\n")).is_err()
        );
        // A bad multicast role is rejected.
        assert!(Appliance::from_toml(&format!(
            "{base}[protocols.multicast]\nenabled = true\n[[protocols.multicast.interface]]\nname = \"lan0\"\nrole = \"bogus\"\n"
        ))
        .is_err());
        // A bad OSPF auth-type is rejected.
        assert!(
            Appliance::from_toml(&format!("{base}[protocols.ospf]\nauth-type = \"sha256\"\n"))
                .is_err()
        );
        // Same for IS-IS: a mistyped scheme, and a scheme with no key. Both would let
        // the daemon reject its whole config, so IS-IS would come up with no routing.
        assert!(
            Appliance::from_toml(&format!(
                "{base}[protocols.isis]\nauth-type = \"hmac-sha-256\"\nauth-key = \"k\"\n"
            ))
            .is_err()
        );
        assert!(
            Appliance::from_toml(&format!(
                "{base}[protocols.isis]\nauth-type = \"hmac-md5\"\n"
            ))
            .is_err()
        );
        // The three valid schemes with a key are accepted.
        for t in ["text", "hmac-md5", "hmac-sha256"] {
            Appliance::from_toml(&format!(
                "{base}[protocols.isis]\nauth-type = \"{t}\"\nauth-key = \"s3cr3t\"\n"
            ))
            .unwrap_or_else(|e| panic!("isis auth-type {t:?} should be valid: {e}"));
        }
        // An export referencing an undeclared filter is rejected.
        assert!(
            Appliance::from_toml(&format!("{base}[protocols.export]\nkernel = \"nope\"\n"))
                .is_err()
        );
    }

    #[test]
    fn schedule_activity_and_validation() {
        use super::{Day, Schedule, parse_hhmm};
        assert_eq!(parse_hhmm("09:30"), Some(570));
        assert_eq!(parse_hhmm("24:00"), None);
        assert_eq!(parse_hhmm("noon"), None);

        // mon-fri 09:00-17:00.
        let s = Schedule {
            days: vec![Day::Mon, Day::Tue, Day::Wed, Day::Thu, Day::Fri],
            start: "09:00".into(),
            end: "17:00".into(),
        };
        // Wednesday (wday 3) at 12:00 → open.
        assert!(s.is_active_at(3, 12 * 60));
        // Wednesday at 08:59 → closed (before start); 17:00 → closed (end exclusive).
        assert!(!s.is_active_at(3, 8 * 60 + 59));
        assert!(!s.is_active_at(3, 17 * 60));
        // Sunday (wday 0) at noon → closed (not in the day set).
        assert!(!s.is_active_at(0, 12 * 60));

        // Validation: a schedule needs a port rule, a valid HH:MM window, start<end.
        let base = "[system]\nhostname = \"fw\"\n[[interface]]\nname=\"eth0\"\nzone=\"lan\"\n";
        // Good: a scheduled port rule.
        assert!(Appliance::from_toml(&format!(
            "{base}[[rule]]\nname=\"r\"\nfrom=\"lan\"\naction=\"accept\"\nproto=\"tcp\"\nport=443\n[rule.schedule]\ndays=[\"mon\"]\nstart=\"09:00\"\nend=\"17:00\"\n"
        )).is_ok());
        // Bad: start after end.
        assert!(Appliance::from_toml(&format!(
            "{base}[[rule]]\nname=\"r\"\nfrom=\"lan\"\naction=\"accept\"\nproto=\"tcp\"\nport=443\n[rule.schedule]\ndays=[\"mon\"]\nstart=\"17:00\"\nend=\"09:00\"\n"
        )).is_err());
        // Bad: schedule on a broad rule (no port).
        assert!(Appliance::from_toml(&format!(
            "{base}[[rule]]\nname=\"r\"\nfrom=\"lan\"\naction=\"accept\"\n[rule.schedule]\ndays=[\"mon\"]\nstart=\"09:00\"\nend=\"17:00\"\n"
        )).is_err());
    }

    #[test]
    fn ssh_and_login_parse_validate_and_round_trip() {
        let base = "[system]\nhostname = \"fw\"\n";
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc admin@host";
        // A real sha-512 crypt hash shape ($6$salt$hash).
        let hash = "$6$abcdefghijklmnop$0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab.";

        // [services.ssh] daemon settings + a [[system.login]] user with a key and a
        // hashed password: parse, validate, survive a TOML round-trip.
        let toml = format!(
            "[system]\nhostname = \"fw\"\n[[system.login]]\nusername = \"ops\"\nssh-key = [\"{key}\"]\nhashed-password = \"{hash}\"\n[services.ssh]\nport = 2222\nlisten-address = \"10.0.0.1\"\npassword-authentication = true\n"
        );
        let a = Appliance::from_toml(&toml).expect("ssh + login parse + validate");
        assert_eq!(a.services.ssh.port, Some(2222));
        assert!(a.services.ssh.password_authentication);
        assert_eq!(a.system.logins.len(), 1);
        assert_eq!(a.system.logins[0].username, "ops");
        assert_eq!(a.system.logins[0].ssh_keys, vec![key.to_string()]);
        assert_eq!(a.system.logins[0].hashed_password.as_deref(), Some(hash));
        let round = Appliance::from_toml(&a.to_toml().unwrap()).unwrap();
        assert_eq!(round.system.logins[0].ssh_keys, a.system.logins[0].ssh_keys);
        assert!(round.services.ssh.password_authentication);

        // Default SSH (no section, no logins) is `is_empty` → omitted from a save.
        let plain = Appliance::from_toml(base).unwrap();
        assert!(plain.services.ssh.is_empty());
        assert!(plain.system.logins.is_empty());
        assert!(!plain.to_toml().unwrap().contains("[services.ssh]"));

        // Bad: a login key with a newline (would inject a second authorized_keys line).
        assert!(
            Appliance::from_toml(&format!(
                "{base}[[system.login]]\nusername = \"ops\"\nssh-key = [\"{key}\\nssh-rsa B x\"]\n"
            ))
            .is_err()
        );
        // Bad: a plaintext password where a crypt hash is required.
        assert!(
            Appliance::from_toml(&format!(
                "{base}[[system.login]]\nusername = \"ops\"\nhashed-password = \"hunter2\"\n"
            ))
            .is_err()
        );
        // Bad: an invalid username.
        assert!(
            Appliance::from_toml(&format!(
                "{base}[[system.login]]\nusername = \"1bad name\"\n"
            ))
            .is_err()
        );
        // Bad: a listen-address that is not an IP.
        assert!(
            Appliance::from_toml(&format!(
                "{base}[services.ssh]\nlisten-address = \"not-an-ip\"\n"
            ))
            .is_err()
        );
    }

    #[test]
    fn config_sync_parses_validates_and_round_trips() {
        let base = "[system]\nhostname = \"fw\"\n";

        // A full [system.config-sync] parses, validates, round-trips.
        let toml = format!(
            "{base}[system.config-sync]\npeer = [\"10.0.0.2\", \"10.0.0.3:9000\"]\nsecret = \"s3cr3t\"\n"
        );
        let a = Appliance::from_toml(&toml).expect("config-sync parses + validates");
        assert_eq!(
            a.system.config_sync.peers,
            vec!["10.0.0.2", "10.0.0.3:9000"]
        );
        assert_eq!(a.system.config_sync.secret.as_deref(), Some("s3cr3t"));
        let round = Appliance::from_toml(&a.to_toml().unwrap()).unwrap();
        assert_eq!(round.system.config_sync.peers, a.system.config_sync.peers);

        // Default (no section) is empty → omitted from a save.
        let plain = Appliance::from_toml(base).unwrap();
        assert!(plain.system.config_sync.is_empty());
        assert!(!plain.to_toml().unwrap().contains("config-sync"));

        // Bad: a peer without a secret can never sync.
        assert!(
            Appliance::from_toml(&format!(
                "{base}[system.config-sync]\npeer = [\"10.0.0.2\"]\n"
            ))
            .is_err()
        );
        // Bad: a peer that is not a host / host:port.
        assert!(
            Appliance::from_toml(&format!(
                "{base}[system.config-sync]\npeer = [\"10.0.0.2:bad\"]\nsecret = \"x\"\n"
            ))
            .is_err()
        );
    }

    #[test]
    fn with_default_port_normalizes_endpoints() {
        // Bare host → default port; explicit port preserved; IPv6 literal bracketed.
        assert_eq!(with_default_port("10.0.0.2", 5429), "10.0.0.2:5429");
        assert_eq!(with_default_port("10.0.0.2:9999", 5429), "10.0.0.2:9999");
        assert_eq!(with_default_port("fw.local", 5429), "fw.local:5429");
        assert_eq!(with_default_port("fd00::2", 5429), "[fd00::2]:5429");
        assert_eq!(with_default_port("[fd00::2]:7000", 5429), "[fd00::2]:7000");
    }

    #[test]
    fn conntrack_sync_parses_validates_and_round_trips() {
        let base = "[system]\nhostname = \"fw\"\n";

        // A full [system.conntrack-sync] parses, validates, round-trips, and
        // normalizes to ip:port endpoints for the agent config.
        let toml = format!(
            "{base}[system.conntrack-sync]\nlisten = \"0.0.0.0\"\npeer = [\"10.9.0.2\", \"10.9.0.3:6000\"]\ninterval = 2\n"
        );
        let a = Appliance::from_toml(&toml).expect("conntrack-sync parses + validates");
        let cts = &a.system.conntrack_sync;
        assert_eq!(cts.listen_endpoint().as_deref(), Some("0.0.0.0:5429"));
        assert_eq!(
            cts.peer_endpoints(),
            vec!["10.9.0.2:5429".to_string(), "10.9.0.3:6000".to_string()]
        );
        assert_eq!(cts.interval, Some(2));
        let round = Appliance::from_toml(&a.to_toml().unwrap()).unwrap();
        assert_eq!(round.system.conntrack_sync.peers, cts.peers);

        // Peers-only (no listen) still enables sync and defaults the bind endpoint.
        let a = Appliance::from_toml(&format!(
            "{base}[system.conntrack-sync]\npeer = [\"10.9.0.2\"]\n"
        ))
        .unwrap();
        assert_eq!(
            a.system.conntrack_sync.listen_endpoint().as_deref(),
            Some("0.0.0.0:5429")
        );

        // Default (no section) is empty → omitted from a save, no endpoints.
        let plain = Appliance::from_toml(base).unwrap();
        assert!(plain.system.conntrack_sync.is_empty());
        assert!(plain.system.conntrack_sync.listen_endpoint().is_none());
        assert!(!plain.to_toml().unwrap().contains("conntrack-sync"));

        // Bad: a peer that is not a host / host:port.
        assert!(
            Appliance::from_toml(&format!(
                "{base}[system.conntrack-sync]\npeer = [\"10.9.0.2:bad\"]\n"
            ))
            .is_err()
        );
        // Bad: an out-of-range interval.
        assert!(
            Appliance::from_toml(&format!(
                "{base}[system.conntrack-sync]\nlisten = \"0.0.0.0\"\ninterval = 0\n"
            ))
            .is_err()
        );
    }
}
