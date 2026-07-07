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

# A VLAN subinterface on lan0, in its own zone:
# [[interface]]
# name = "lan0.20"
# parent = "lan0"
# vlan = 20
# zone = "iot"
# address = "10.0.20.1/24"

# IPv6 on the LAN by SLAAC: advertise a /64 and hosts autoconfigure. The router
# also binds its own address from the prefix, so no separate v6 address needed.
# [interface.router-advert]
# prefixes = ["2001:db8:1::/64"]
# dns = ["2001:db8:1::1"]

# A bridge (switch) that holds the LAN address, with NICs enslaved to it:
# [[interface]]
# name = "br0"
# type = "bridge"
# zone = "lan"
# address = "10.0.0.1/24"
# [[interface]]
# name = "lan1"
# master = "br0"
#
# A bond (link aggregation) — set the mode on the device, enslave with master:
# [[interface]]
# name = "bond0"
# type = "bond"
# bond-mode = "active-backup"
# [[interface]]
# name = "lan2"
# master = "bond0"

# Broad zone rules set a zone's posture (action: accept | drop | reject).
[[rule]]
name = "lan-to-wan"
from = "lan"
to = "wan"
action = "accept"

[[rule]]
name = "wan-to-lan"
from = "wan"
to = "lan"
action = "drop"

# Port rules open a specific proto/port even on a default-drop zone — here,
# inbound HTTPS from the WAN.
[[rule]]
name = "allow-https-in"
from = "wan"
to = "lan"
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
# A route filter: reject the default, accept a prefix range with a set MED.
# [[protocols.filter]]
# name = "from-peer"
# default = "reject"
# [[protocols.filter.rule]]
# prefix = ["10.0.0.0/8+"]
# set-metric = 100
# action = "accept"
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
}

/// The box-wide services category (`[services.*]`). A thin grouping so DNS, NTP
/// and the rest share one namespace instead of sprawling across the top level.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Services {
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
}

impl Services {
    /// True when no service is configured — lets `[services]` be omitted.
    pub fn is_empty(&self) -> bool {
        self.dns.is_empty()
            && self.ntp.is_empty()
            && self.lldp.is_empty()
            && self.snmp.is_empty()
            && self.mdns.is_empty()
            && self.dyndns.is_empty()
            && self.dhcp_relay.is_empty()
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
}

impl DhcpRelay {
    /// True when no relay is configured — lets `[services.dhcp-relay]` be omitted.
    pub fn is_empty(&self) -> bool {
        self.interface.is_empty() && self.server.is_empty()
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
}

impl Ntp {
    /// True when no NTP server is configured — lets `[services.ntp]` be omitted.
    pub fn is_empty(&self) -> bool {
        self.upstream.is_empty() && self.serve_on.is_empty()
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
    /// Named route filters (import/export policy), referenced by name from a BGP
    /// neighbour's `import` / `export`. Compiled to Wren's top-level `[[filter]]`.
    #[serde(default, rename = "filter", skip_serializing_if = "Vec::is_empty")]
    pub filters: Vec<Filter>,
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
            && self.filters.is_empty()
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
    /// Inbound route policy: the name of a `[[protocols.filter]]` (import map).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub import: Option<String>,
    /// Outbound route policy: the name of a `[[protocols.filter]]` (export map).
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
    /// Prefix patterns (any-match), e.g. `["10.0.0.0/8+"]`.
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
    /// Whether a matching route is `"accept"`ed or `"reject"`ed.
    pub action: String,
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
}

impl Nat {
    /// True when no NAT is configured — lets `[nat]` be omitted from a saved
    /// config that never set any.
    pub fn is_empty(&self) -> bool {
        self.source.is_empty() && self.destination.is_empty() && self.nat64.is_empty()
    }
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
    /// True when no uplink is configured — lets `[multiwan]` be omitted.
    pub fn is_empty(&self) -> bool {
        self.uplinks.is_empty()
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
}

impl HealthCheck {
    /// True when nothing is set — lets `health-check` be omitted from output.
    pub fn is_default(&self) -> bool {
        self.targets.is_empty()
            && self.interval.is_none()
            && self.timeout.is_none()
            && self.fail.is_none()
            && self.rise.is_none()
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
}

impl Vpn {
    /// True when no VPN is configured — lets `[vpn]` be omitted from output.
    pub fn is_empty(&self) -> bool {
        self.ipsec.is_empty()
    }
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
    /// Named address/port groups (aliases) that rules reference by name.
    #[serde(default, skip_serializing_if = "Groups::is_empty")]
    pub group: Groups,
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
            group: Groups::default(),
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
}

impl Groups {
    /// No groups defined (lets `[firewall]` be omitted when untouched).
    pub fn is_empty(&self) -> bool {
        self.address.is_empty() && self.port.is_empty()
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
    /// WireGuard private key (base64 of 32 raw bytes). Its presence makes this a
    /// WireGuard interface (`Kind=wireguard`); the `.netdev` carrying it is a
    /// secret and is written mode 0600.
    #[serde(
        default,
        rename = "private-key",
        skip_serializing_if = "Option::is_none"
    )]
    pub private_key: Option<String>,
    /// UDP port WireGuard listens on. Optional (an outbound-only tunnel needs
    /// none); when set the peer can reach us at this port.
    #[serde(
        default,
        rename = "listen-port",
        skip_serializing_if = "Option::is_none"
    )]
    pub listen_port: Option<u16>,
    /// WireGuard peers reachable over this interface.
    #[serde(default, rename = "peer", skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<WgPeer>,
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
    /// (`Kind=bridge`/`bond`); member NICs point at it with `master`. A bridge
    /// switches its members; a bond aggregates them (mode via `bond-mode`). Set
    /// on the *device* interface, not its members.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub if_type: Option<IfaceType>,
    /// Enslave this interface to a `bridge`/`bond` device named here (the inverse
    /// of `if_type`): the member gets `Bridge=`/`Bond=` in its `.network`. The
    /// master must be a declared `type = "bridge"`/`"bond"` interface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master: Option<String>,
    /// Bonding mode for a `type = "bond"` device (`"active-backup"`,
    /// `"802.3ad"`, `"balance-rr"`, …). Only meaningful on a bond device;
    /// defaults to `active-backup` when unset.
    #[serde(default, rename = "bond-mode", skip_serializing_if = "Option::is_none")]
    pub bond_mode: Option<String>,
    /// Link MTU in bytes (e.g. `1492` for PPPoE, `9000` for jumbo frames).
    /// `None` leaves the kernel/driver default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    /// Override the link's MAC address (`"52:54:00:12:34:56"`) — MAC cloning, as
    /// some ISPs bind service to the CPE's original MAC. `None` keeps the NIC's
    /// hardware address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
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
/// **virtual L2 devices** Sentinel creates to enslave members; `pppoe` is a
/// PPPoE **client** session brought up over a raw uplink NIC (`parent`);
/// `gre`/`ipip`/`gretap` are **kernel point-to-point tunnels** (roadmap C3) built
/// between two endpoint addresses (`local`/`remote`). Physical NICs and
/// VLAN/WireGuard links carry no `type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IfaceType {
    Bridge,
    Bond,
    Pppoe,
    /// A GRE (Generic Routing Encapsulation) L3 tunnel — carries IP, supports an
    /// optional 32-bit `key` to demultiplex several tunnels between the same pair.
    Gre,
    /// An IPIP (IPv4-in-IPv4) L3 tunnel — the simplest encapsulation; no `key`.
    Ipip,
    /// A GRETAP L2 tunnel — GRE carrying Ethernet frames (a virtual bridge port
    /// over GRE); like `gre` but the link is a broadcast-capable L2 device.
    Gretap,
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

/// A WireGuard peer: the far end of a tunnel on a `[[interface]]` that carries a
/// `private-key`. Keys are the standard base64 encoding of 32 raw bytes.
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
    /// A WireGuard interface is any interface that carries a `private-key`.
    pub fn is_wireguard(&self) -> bool {
        self.private_key.is_some()
    }
    /// True for a bond device (`type = "bond"`).
    pub fn is_bond(&self) -> bool {
        self.if_type == Some(IfaceType::Bond)
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
    /// Destination zone name.
    pub to: String,
    pub action: Action,
    /// With `port`, makes this a **port rule** (a specific proto/port);
    /// without, it is a **broad** rule that sets the from-zone's posture.
    #[serde(default)]
    pub proto: Option<Proto>,
    /// A single port (`port = 443`) or an inclusive range (`port = "8000-8100"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<PortSpec>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_group: Option<String>,
    /// Reference a port group (`[firewall.group.port]`) instead of an inline
    /// `port`/range — mutually exclusive with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_group: Option<String>,
}

impl Rule {
    /// A broad zone rule (no proto/port) — sets the from-zone's default posture.
    pub fn is_broad(&self) -> bool {
        self.proto.is_none() && self.port.is_none() && self.port_group.is_none()
    }
    /// A specific proto/port rule (a literal port/range or a port group).
    pub fn is_port_rule(&self) -> bool {
        self.proto.is_some() && (self.port.is_some() || self.port_group.is_some())
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

    /// The ports this rule matches, expanding a `port_group` or a single
    /// spec/range into concrete ports.
    pub fn resolved_ports(&self, groups: &Groups) -> Vec<u16> {
        if let Some(g) = &self.port_group {
            groups
                .port
                .get(g)
                .map(|specs| specs.iter().flat_map(|p| p.ports()).collect())
                .unwrap_or_default()
        } else if let Some(p) = &self.port {
            p.ports().collect()
        } else {
            Vec::new()
        }
    }
}

impl Appliance {
    /// Parse and validate a config from TOML text.
    pub fn from_toml(toml_text: &str) -> Result<Self> {
        let appliance: Appliance = toml::from_str(toml_text).context("parsing TOML config")?;
        appliance.validate()?;
        Ok(appliance)
    }

    /// Parse and validate a config from JSON text.
    pub fn from_json(json_text: &str) -> Result<Self> {
        let appliance: Appliance =
            serde_json::from_str(json_text).context("parsing JSON config")?;
        appliance.validate()?;
        Ok(appliance)
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
            // parent must be a declared interface. A PPPoE client also carries a
            // `parent` (its raw uplink NIC) but no `vlan`, so it is validated
            // separately below — skip the pairing rule for it.
            if !iface.is_pppoe() {
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
                if iface.is_wireguard() {
                    bail!(
                        "interface {:?}: a pppoe interface cannot also be WireGuard",
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
            } else if iface.pppoe.is_some() {
                bail!(
                    "interface {:?}: `pppoe` credentials require `type = \"pppoe\"`",
                    iface.name
                );
            }

            // WireGuard: a `private-key` turns an interface into a WG tunnel.
            if iface.is_wireguard() {
                if iface.parent.is_some() || iface.vlan.is_some() {
                    bail!(
                        "interface {:?}: a wireguard interface cannot also be a VLAN",
                        iface.name
                    );
                }
                let key = iface.private_key.as_deref().unwrap();
                validate_wg_key(key)
                    .with_context(|| format!("interface {:?} private-key", iface.name))?;
                if let Some(port) = iface.listen_port {
                    if port == 0 {
                        bail!("interface {:?}: listen-port 0 is not valid", iface.name);
                    }
                }
                for peer in &iface.peers {
                    validate_wg_key(&peer.public_key)
                        .with_context(|| format!("interface {:?} peer public-key", iface.name))?;
                    for cidr in &peer.allowed_ips {
                        validate_cidr_or_ip(cidr).with_context(|| {
                            format!("interface {:?} peer allowed-ips", iface.name)
                        })?;
                    }
                    if let Some(ep) = &peer.endpoint {
                        validate_endpoint(ep)
                            .with_context(|| format!("interface {:?} peer endpoint", iface.name))?;
                    }
                    if let Some(psk) = &peer.preshared_key {
                        validate_wg_key(psk).with_context(|| {
                            format!("interface {:?} peer preshared-key", iface.name)
                        })?;
                    }
                }
            } else if iface.listen_port.is_some() || !iface.peers.is_empty() {
                bail!(
                    "interface {:?}: listen-port/peer require private-key",
                    iface.name
                );
            }

            // Kernel tunnel (`type = gre|ipip|gretap`, roadmap C3): a point-to-point
            // link between two endpoint addresses. Requires `local` + `remote` of the
            // same family; the GRE `key` is only valid on gre/gretap; and a tunnel
            // cannot double as a VLAN / WireGuard / bridge/bond / member. Endpoint
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
                if iface.is_wireguard() {
                    bail!(
                        "interface {:?}: a tunnel cannot also be WireGuard",
                        iface.name
                    );
                }
                if iface.master.is_some() {
                    bail!(
                        "interface {:?}: a tunnel cannot be enslaved to a bridge/bond",
                        iface.name
                    );
                }
            } else if iface.local.is_some()
                || iface.remote.is_some()
                || iface.tunnel_key.is_some()
                || iface.ttl.is_some()
            {
                bail!(
                    "interface {:?}: local/remote/key/ttl require `type = \"gre\"|\"ipip\"|\"gretap\"`",
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
                if let Some(gw) = &dhcp.default_router {
                    validate_ipv4(gw).with_context(|| {
                        format!("interface {:?} dhcp-server default-router", iface.name)
                    })?;
                }
                // Static reservations: a valid MAC and an address inside the
                // server's own subnet (a lease outside it can never be handed
                // out). `address` is a static CIDR here (checked just above).
                let subnet = iface.address.as_deref().unwrap_or("");
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
                }
                for dns in &ra.dns {
                    validate_ipv6(dns)
                        .with_context(|| format!("interface {:?} router-advert dns", iface.name))?;
                }
            }

            // Bridge / bond: a `type` device cannot also be a VLAN or WireGuard;
            // a `bond-mode` is only meaningful on a bond; a `master` must name a
            // declared bridge/bond device (checked in a second pass below, once
            // every interface's type is known).
            if iface.is_virtual_l2() && (iface.parent.is_some() || iface.is_wireguard()) {
                bail!(
                    "interface {:?}: a bridge/bond device cannot also be a VLAN or WireGuard",
                    iface.name
                );
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
        }

        // Enslavement pass: every `master` must reference a declared bridge/bond
        // device, and a device cannot enslave to itself.
        for iface in &self.interfaces {
            if let Some(master) = &iface.master {
                match self.interfaces.iter().find(|i| &i.name == master) {
                    Some(m) if m.is_virtual_l2() => {}
                    Some(_) => bail!(
                        "interface {:?}: master {master:?} is not a bridge/bond device",
                        iface.name
                    ),
                    None => bail!(
                        "interface {:?}: master {master:?} is not a declared interface",
                        iface.name
                    ),
                }
                if master == &iface.name {
                    bail!("interface {:?}: cannot enslave to itself", iface.name);
                }
            }
        }

        // Firewall groups (aliases): address members must be IPv4 hosts or CIDRs
        // (the data plane matches sources by longest prefix, so a hostname can't
        // apply); port members must be valid ports/ranges.
        for (name, members) in &self.firewall.group.address {
            for m in members {
                if validate_ipv4(m).is_err() && validate_address(m).is_err() {
                    bail!(
                        "firewall group address-group {name:?}: {m:?} is not an IPv4 host or CIDR"
                    );
                }
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
        for rule in &self.rules {
            if let Some(d) = &rule.description {
                validate_description(d)
                    .with_context(|| format!("rule {:?} description", rule.name))?;
            }
            for (which, zone) in [("from", &rule.from), ("to", &rule.to)] {
                if !zones_in_use.contains(zone.as_str()) {
                    bail!(
                        "rule {:?}: {which} zone {zone:?} has no interface",
                        rule.name
                    );
                }
            }
            // A port match is an inline `port`/range OR a `port-group`, never
            // both; likewise a `source` OR a `source-group`. And a port rule
            // needs a proto paired with a port (either form).
            if rule.port.is_some() && rule.port_group.is_some() {
                bail!("rule {:?}: set `port` or `port-group`, not both", rule.name);
            }
            if rule.source.is_some() && rule.source_group.is_some() {
                bail!(
                    "rule {:?}: set `source` or `source-group`, not both",
                    rule.name
                );
            }
            let has_port = rule.port.is_some() || rule.port_group.is_some();
            if rule.proto.is_some() != has_port {
                bail!(
                    "rule {:?}: `proto` and a port (`port` or `port-group`) must be set together",
                    rule.name
                );
            }
            // A literal port (or range) must be in range and not inverted/too wide.
            if let Some(port) = rule.port {
                port.validate()
                    .with_context(|| format!("rule {:?}", rule.name))?;
            }
            // A referenced group must be declared.
            if let Some(g) = &rule.source_group {
                if !self.firewall.group.address.contains_key(g) {
                    bail!(
                        "rule {:?}: source-group {g:?} is not a declared address group",
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
            parse_host_port(&dst.to).with_context(|| format!("nat destination {:?}", dst.name))?;
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

        // Routing (Wren): validate router-id, static routes and BGP peers.
        if let Some(rid) = &self.protocols.router_id {
            validate_ipv4(rid).with_context(|| "protocols router-id")?;
        }
        for r in &self.protocols.statics {
            // A static route may be IPv4 or IPv6; wren installs either. The
            // nexthop family must match the prefix (no v4 via for a v6 route).
            let prefix_v6 = route_prefix_family(&r.prefix)
                .with_context(|| format!("protocols static route {:?}", r.prefix))?;
            if r.via.is_none() && r.dev.is_none() {
                bail!(
                    "protocols static route {:?}: needs a via <ip> or dev <if>",
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
        // The set of declared filter names — a BGP neighbour's import/export must
        // reference one of these (they compile to Wren's `[[filter]]` blocks).
        let filter_names: HashSet<&str> = self
            .protocols
            .filters
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
        for r in &self.protocols.statics {
            check_vrf_ref(&r.vrf, &format!("static route {:?}", r.prefix))?;
        }
        // VRF definitions: a table id, and import/export naming declared filters.
        for v in &self.protocols.vrfs {
            if v.name.is_empty() {
                bail!("protocols vrf: a vrf needs a name");
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
            }
            if let Some(rtr) = &bgp.rtr {
                if rtr.server.is_empty() {
                    bail!("protocols bgp rtr: server (host:port) must be set");
                }
            }
            for n in &bgp.neighbors {
                validate_bgp_neighbor(n, &filter_names)?;
            }
        }
        for f in &self.protocols.filters {
            validate_filter(f)?;
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
            check_vrf_ref(&isis.vrf, "isis vrf")?;
        }
        for v in &self.protocols.vrrp {
            if v.interface.is_empty() {
                bail!("protocols vrrp: interface must be set");
            }
            for addr in &v.virtual_address {
                validate_ipv4(addr)
                    .with_context(|| format!("protocols vrrp vrid {} virtual-address", v.vrid))?;
            }
        }
        // BFD global defaults: the authentication type, when set.
        if let Some(bfd) = &self.protocols.bfd {
            if let Some(t) = &bfd.auth_type {
                if !BFD_AUTH_TYPES.contains(&t.as_str()) {
                    bail!("protocols bfd auth-type {t:?} not one of {BFD_AUTH_TYPES:?}");
                }
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
        for src in &snmp.allow {
            if validate_cidr_or_ip(src).is_err() && validate_ipv6_cidr(src).is_err() {
                bail!("services snmp allow {src:?}: not an IPv4/IPv6 address or CIDR");
            }
        }
        if snmp.community.is_none() && !snmp.is_empty() {
            bail!("services snmp: a `community` is required to run the agent");
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
            if relay.server.is_empty() {
                bail!("services dhcp-relay: at least one upstream `server` is required");
            }
            if relay.interface.is_empty() {
                bail!("services dhcp-relay: at least one `interface` to relay on is required");
            }
        }
        for srv in &relay.server {
            validate_ipv4(srv).with_context(|| "services dhcp-relay server")?;
        }
        for iface in &relay.interface {
            match self.interfaces.iter().find(|i| &i.name == iface) {
                Some(i) if i.dhcp_server.is_some() => bail!(
                    "services dhcp-relay interface {iface:?}: already runs a DHCP server (a link is either served or relayed, not both)"
                ),
                // The relay (dnsmasq) listens on the interface's own address and
                // stamps it as the DHCP giaddr, so a client-facing relay link
                // needs a static address (a `dhcp`/unset link cannot relay).
                Some(i) => match i.address.as_deref() {
                    Some(addr) if addr != "dhcp" => {}
                    _ => bail!(
                        "services dhcp-relay interface {iface:?}: needs a static address (the relay stamps it as the DHCP giaddr)"
                    ),
                },
                None => bail!("services dhcp-relay interface {iface:?}: not a declared interface"),
            }
        }

        // Multi-WAN (roadmap C6): every uplink must name a declared interface,
        // no interface or routing-table id may be shared between uplinks, table
        // ids must avoid the kernel's reserved tables, gateways are IPv4 (or
        // `dhcp`) and health-check targets are IPv4. A single uplink is allowed
        // (it just has nothing to fail over to) — no artificial floor.
        let mw = &self.multiwan;
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
        }
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
        out.push_str(&format!("rules ({}):\n", self.rules.len()));
        for r in &self.rules {
            let proto_port = match (r.proto, r.port) {
                (Some(p), Some(port)) => format!("  {}/{port}", proto_str(p)),
                _ => String::new(),
            };
            out.push_str(&format!(
                "  {:<16} {} -> {}  {}{}\n",
                r.name,
                r.from,
                r.to,
                action_str(r.action),
                proto_port,
            ));
        }
        out
    }
}

/// Validate a bare IPv4 address (router-id, gateway, BGP peer — no prefix).
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
    validate_ipv4(&n.address).with_context(|| format!("protocols bgp neighbor {:?}", n.address))?;
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
        validate_ipv4(src)
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
    if let Some((ip, prefix)) = s.split_once('/') {
        ip.parse::<Ipv4Addr>()
            .with_context(|| format!("invalid IPv4 in {s:?}"))?;
        let prefix: u8 = prefix
            .parse()
            .with_context(|| format!("invalid prefix in {s:?}"))?;
        if prefix > 32 {
            bail!("prefix /{prefix} in {s:?} exceeds /32");
        }
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
        assert_eq!(a.rules.len(), 3); // 2 broad + 1 port rule
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
        assert_eq!(a.rules[0].port, Some(PortSpec::Single(443)));
        assert_eq!(a.rules[1].port, Some(PortSpec::Range(8000, 8100)));
        let out = a.to_toml().unwrap();
        assert!(out.contains("port = 443"), "single stays integer:\n{out}");
        assert!(
            out.contains("port = \"8000-8100\""),
            "range stays string:\n{out}"
        );
        // Re-parse the saved form unchanged.
        let b = Appliance::from_toml(&out).unwrap();
        assert_eq!(b.rules[1].port, Some(PortSpec::Range(8000, 8100)));
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
[[interface]]
name = "lan1"
master = "br0"
[[interface]]
name = "bond0"
type = "bond"
bond-mode = "802.3ad"
[[interface]]
name = "lan2"
master = "bond0"
"#;
        let a = Appliance::from_toml(toml).expect("bridge/bond config parses + validates");
        assert_eq!(a.interfaces[0].if_type, Some(IfaceType::Bridge));
        assert_eq!(a.interfaces[1].master.as_deref(), Some("br0"));
        assert!(a.interfaces[2].is_bond());
        assert_eq!(a.interfaces[2].bond_mode.as_deref(), Some("802.3ad"));
        // Round-trips through TOML (type + master survive).
        let out = a.to_toml().unwrap();
        assert!(out.contains("type = \"bridge\""), "got:\n{out}");
        assert!(out.contains("master = \"bond0\""), "got:\n{out}");
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
        // master pointing at a non-device interface is rejected.
        let bad_master = r#"
[system]
hostname = "fw"
[[interface]]
name = "eth0"
zone = "lan"
[[interface]]
name = "eth1"
master = "eth0"
"#;
        assert!(Appliance::from_toml(bad_master).is_err());
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
[[protocols.filter]]
name = "from-peer"
default = "reject"
[[protocols.filter.rule]]
prefix = ["10.0.0.0/8+"]
set-metric = 100
set-community = ["65001:200"]
action = "accept"
[[protocols.filter]]
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
        assert_eq!(a.protocols.filters.len(), 2);
        assert_eq!(a.protocols.filters[0].rules[0].action, "accept");
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
        // A filter rule with a non-accept/reject action is rejected.
        let bad_action = "[system]\nhostname = \"r1\"\n[protocols]\n[[protocols.filter]]\nname = \"f\"\n[[protocols.filter.rule]]\naction = \"drop\"\n";
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
[[protocols.filter]]
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
        // An export referencing an undeclared filter is rejected.
        assert!(
            Appliance::from_toml(&format!("{base}[protocols.export]\nkernel = \"nope\"\n"))
                .is_err()
        );
    }
}
