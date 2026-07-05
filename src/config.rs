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
    net::{Ipv4Addr, Ipv6Addr},
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
# Dual-stack: add a static IPv6 (or "auto" for SLAAC / accept-RA).
# address6 = "2001:db8:1::1/64"

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
#
# A LAN NTP server (built on chrony): sync to upstreams, serve lan0's subnet.
# [services.ntp]
# upstream = ["pool.ntp.org"]
# serve-on = ["lan0"]

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
}

impl Services {
    /// True when no service is configured — lets `[services]` be omitted.
    pub fn is_empty(&self) -> bool {
        self.dns.is_empty() && self.ntp.is_empty()
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
}

impl Dns {
    /// True when no DNS service is configured — lets `[services.dns]` be omitted.
    pub fn is_empty(&self) -> bool {
        self.upstream.is_empty()
            && self.serve_on.is_empty()
            && self.host_override.is_empty()
            && self.blocklist.is_empty()
            && self.dnssec.is_none()
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
    }
}

/// OSPFv2 configuration: a single area whose interfaces run OSPF, with optional
/// cost / network-type and redistribution. The router-id is the global
/// `[protocols] router-id`. (Multi-area / stub / NSSA are supported by the Wren
/// daemon but not yet surfaced here.)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ospf {
    /// Interfaces OSPF runs on (all in [`Ospf::area`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
    /// The area these interfaces belong to (dotted quad, e.g. `"0.0.0.0"`).
    /// Defaults to the backbone `0.0.0.0` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub area: Option<String>,
    /// The output cost advertised for these interfaces (lower is preferred).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<u16>,
    /// Network type: `"broadcast"` (elects a DR) or `"point-to-point"`.
    #[serde(default, rename = "network-type", skip_serializing_if = "Option::is_none")]
    pub network_type: Option<String>,
    /// Route sources redistributed into OSPF as AS-external LSAs (`"static"`,
    /// `"connected"`, `"bgp"`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redistribute: Vec<String>,
}

/// OSPFv3 (IPv6) configuration — the IPv6 sibling of [`Ospf`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ospf3 {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub area: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<u16>,
    #[serde(default, rename = "network-type", skip_serializing_if = "Option::is_none")]
    pub network_type: Option<String>,
    /// Redistribute sources into OSPFv3 (only `"static"` is honoured by the
    /// daemon's OSPFv3 externals).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redistribute: Vec<String>,
}

/// RIP-family configuration shared by RIPv2, RIPng and Babel (they take the same
/// knobs: which interfaces to run on, and what to redistribute).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rip {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redistribute: Vec<String>,
    #[serde(default, rename = "redistribute-metric", skip_serializing_if = "Option::is_none")]
    pub redistribute_metric: Option<u32>,
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
    /// Network type: `"broadcast"` or `"point-to-point"`.
    #[serde(default, rename = "network-type", skip_serializing_if = "Option::is_none")]
    pub network_type: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redistribute: Vec<String>,
    #[serde(default, rename = "redistribute-metric", skip_serializing_if = "Option::is_none")]
    pub redistribute_metric: Option<u32>,
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
    /// The virtual IP address(es) the group presents as the gateway.
    #[serde(rename = "virtual-address", skip_serializing_if = "Vec::is_empty", default)]
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
}

/// BGP-4 configuration: the local AS, an optional router-id, originated
/// networks, redistribution and the peer list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bgp {
    /// The local autonomous system number (32-bit / 4-octet ASN).
    #[serde(rename = "local-as")]
    pub local_as: u32,
    /// BGP router-id; falls back to `[protocols] router-id` when unset.
    #[serde(default, rename = "router-id", skip_serializing_if = "Option::is_none")]
    pub router_id: Option<String>,
    /// Prefixes originated into BGP (advertised to peers).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network: Vec<String>,
    /// Route sources redistributed into BGP (`"static"`, `"connected"`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redistribute: Vec<String>,
    /// BGP peers.
    #[serde(default, rename = "neighbor", skip_serializing_if = "Vec::is_empty")]
    pub neighbors: Vec<BgpNeighbor>,
}

/// A BGP peer: its address and remote AS.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgpNeighbor {
    /// Peer IP address.
    pub address: String,
    /// The peer's autonomous system number.
    #[serde(rename = "remote-as")]
    pub remote_as: u32,
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
}

impl Nat {
    /// True when no NAT is configured — lets `[nat]` be omitted from a saved
    /// config that never set any.
    pub fn is_empty(&self) -> bool {
        self.source.is_empty() && self.destination.is_empty()
    }
}

/// A source-NAT (masquerade) rule: SNAT all traffic egressing `zone` to that
/// zone's egress address. The classic WAN masquerade.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NatSource {
    pub name: String,
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
    /// The ingress zone (the public side) — must be backed by an interface.
    pub zone: String,
    pub proto: Proto,
    /// Public destination port matched inbound.
    pub port: u16,
    /// Internal target, `"10.0.0.10"` or `"10.0.0.10:8443"`.
    pub to: String,
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
    #[serde(default, rename = "private-key", skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    /// UDP port WireGuard listens on. Optional (an outbound-only tunnel needs
    /// none); when set the peer can reach us at this port.
    #[serde(default, rename = "listen-port", skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    /// WireGuard peers reachable over this interface.
    #[serde(default, rename = "peer", skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<WgPeer>,
    /// When set, networkd runs a built-in DHCP server on this interface, handing
    /// out leases from the interface's own static subnet. Requires a static
    /// `address` (the server needs a subnet to allocate from).
    #[serde(default, rename = "dhcp-server", skip_serializing_if = "Option::is_none")]
    pub dhcp_server: Option<DhcpServer>,
    /// When set, networkd emits IPv6 Router Advertisements on this interface —
    /// the IPv6 counterpart of the DHCP server. LAN hosts autoconfigure (SLAAC)
    /// an address from each advertised prefix and learn this box as their default
    /// router (and, optionally, DNS). Needs no IPv4 address; the router binds an
    /// address from each advertised prefix itself.
    #[serde(default, rename = "router-advert", skip_serializing_if = "Option::is_none")]
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
/// PPPoE **client** session brought up over a raw uplink NIC (`parent`). Physical
/// NICs and VLAN/WireGuard links carry no `type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IfaceType {
    Bridge,
    Bond,
    Pppoe,
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
    #[serde(default, rename = "service-name", skip_serializing_if = "Option::is_none")]
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
    #[serde(default, rename = "router-lifetime", skip_serializing_if = "Option::is_none")]
    pub router_lifetime: Option<u32>,
}

/// A built-in (systemd-networkd) DHCP server on an interface that carries a
/// static address. All fields are optional refinements of networkd's defaults;
/// the presence of the block is what turns the server on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpServer {
    /// Offset of the first pool address within the interface's subnet.
    #[serde(default, rename = "pool-offset", skip_serializing_if = "Option::is_none")]
    pub pool_offset: Option<u32>,
    /// Number of addresses in the pool.
    #[serde(default, rename = "pool-size", skip_serializing_if = "Option::is_none")]
    pub pool_size: Option<u32>,
    /// DNS servers advertised to clients (emitted only when non-empty).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<String>,
    /// Default lease time, in seconds.
    #[serde(default, rename = "lease-time", skip_serializing_if = "Option::is_none")]
    pub lease_time: Option<u32>,
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
    #[serde(default, rename = "persistent-keepalive", skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive: Option<u16>,
    #[serde(default, rename = "preshared-key", skip_serializing_if = "Option::is_none")]
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
        matches!(self.if_type, Some(IfaceType::Bridge) | Some(IfaceType::Bond))
    }
    /// True for a PPPoE client interface (`type = "pppoe"`).
    pub fn is_pppoe(&self) -> bool {
        self.if_type == Some(IfaceType::Pppoe)
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

        // Per-zone blocklists must also be valid.
        for (name, z) in &self.zones {
            for entry in &z.blocklist {
                validate_cidr_or_ip(entry).with_context(|| format!("zone {name:?} blocklist"))?;
            }
        }

        let names: HashSet<&str> = self.interfaces.iter().map(|i| i.name.as_str()).collect();
        let mut seen = HashSet::new();
        for iface in &self.interfaces {
            validate_iface_name(&iface.name)?;
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
                    bail!("interface {:?}: pd-from {up:?} is not a declared interface", iface.name);
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
                    bail!("interface {:?}: mtu {mtu} out of range (68–9216)", iface.name);
                }
            }
            if let Some(mac) = &iface.mac {
                validate_mac(mac).with_context(|| format!("interface {:?} mac", iface.name))?;
            }
            // VLAN subinterface: parent + vlan come as a pair; vlan in range; the
            // parent must be a declared interface. A PPPoE client also carries a
            // `parent` (its raw uplink NIC) but no `vlan`, so it is validated
            // separately below — skip the pairing rule for it.
            if !iface.is_pppoe() {
                match (&iface.parent, iface.vlan) {
                    (Some(parent), Some(vlan)) => {
                        if !(1..=4094).contains(&vlan) {
                            bail!("interface {:?}: vlan {vlan} out of range (1–4094)", iface.name);
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
                    bail!("interface {:?}: a pppoe interface cannot also be a VLAN", iface.name);
                }
                if iface.is_wireguard() {
                    bail!("interface {:?}: a pppoe interface cannot also be WireGuard", iface.name);
                }
                if iface.address.is_some() || iface.address6.is_some() {
                    bail!(
                        "interface {:?}: a pppoe interface gets its address from the peer — do not set `address`",
                        iface.name
                    );
                }
                if let Some(mru) = p.mru {
                    if !(68..=9216).contains(&mru) {
                        bail!("interface {:?}: pppoe mru {mru} out of range (68–9216)", iface.name);
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
                    validate_ipv6(dns).with_context(|| {
                        format!("interface {:?} router-advert dns", iface.name)
                    })?;
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
                    bail!("interface {:?}: bond-mode is only valid on a type=bond", iface.name);
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
        let zones_in_use: HashSet<&str> =
            self.interfaces.iter().filter_map(|i| i.zone.as_deref()).collect();
        for rule in &self.rules {
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
                bail!("rule {:?}: set `source` or `source-group`, not both", rule.name);
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
                    bail!("rule {:?}: port-group {g:?} is not a declared port group", rule.name);
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
            if !zones_in_use.contains(dst.zone.as_str()) {
                bail!(
                    "nat destination {:?}: zone {:?} has no interface",
                    dst.name,
                    dst.zone
                );
            }
            parse_host_port(&dst.to)
                .with_context(|| format!("nat destination {:?}", dst.name))?;
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
                bail!("protocols static route {:?}: needs a via <ip> or dev <if>", r.prefix);
            }
            if let Some(via) = &r.via {
                let via_v6 = match ip_family(via) {
                    Some(f) => f,
                    None => bail!("protocols static route {:?} via {via:?}: not an IP", r.prefix),
                };
                if via_v6 != prefix_v6 {
                    bail!(
                        "protocols static route {:?}: via {via:?} family does not match the prefix",
                        r.prefix
                    );
                }
            }
        }
        if let Some(bgp) = &self.protocols.bgp {
            if bgp.local_as == 0 {
                bail!("protocols bgp: local-as must be non-zero");
            }
            if let Some(rid) = &bgp.router_id {
                validate_ipv4(rid).with_context(|| "protocols bgp router-id")?;
            }
            for net in &bgp.network {
                validate_cidr_or_ip(net)
                    .with_context(|| format!("protocols bgp network {net:?}"))?;
            }
            for n in &bgp.neighbors {
                validate_ipv4(&n.address)
                    .with_context(|| format!("protocols bgp neighbor {:?}", n.address))?;
                if n.remote_as == 0 {
                    bail!("protocols bgp neighbor {:?}: remote-as must be non-zero", n.address);
                }
            }
        }
        if let Some(ospf) = &self.protocols.ospf {
            if let Some(area) = &ospf.area {
                validate_ipv4(area).with_context(|| "protocols ospf area (dotted quad)")?;
            }
            validate_ospf_network_type(ospf.network_type.as_deref(), "ospf")?;
        }
        if let Some(o) = &self.protocols.ospf3 {
            if let Some(area) = &o.area {
                validate_ipv4(area).with_context(|| "protocols ospf3 area (dotted quad)")?;
            }
            validate_ospf_network_type(o.network_type.as_deref(), "ospf3")?;
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
                bail!("services dns dnssec {mode:?}: expected \"yes\", \"no\" or \"allow-downgrade\"");
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
    if octets.len() != 6 || !octets.iter().all(|o| o.len() == 2 && o.bytes().all(|b| b.is_ascii_hexdigit())) {
        bail!("mac {s:?}: expected six colon-separated hex octets");
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
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
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
        bail!(
            "interface name {name:?}: only ASCII letters, digits, '.', '_' and '-' are allowed"
        );
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
        bail!("wireguard key {s:?} decodes to {} bytes, expected 32", raw.len());
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
    fn portspec_parses_single_and_range() {
        assert_eq!(PortSpec::parse("443").unwrap(), PortSpec::Single(443));
        assert_eq!(
            PortSpec::parse("8000-8100").unwrap(),
            PortSpec::Range(8000, 8100)
        );
        // Whitespace around the dash is tolerated.
        assert_eq!(PortSpec::parse(" 100 - 200 ").unwrap(), PortSpec::Range(100, 200));
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
        assert!(Appliance::from_toml(&base("source_group = \"mgmt\"\nport_group = \"web\"")).is_ok());
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
        assert_eq!(a.interfaces[0].address6.as_deref(), Some("2001:db8:1::1/64"));
        assert_eq!(a.interfaces[1].address6.as_deref(), Some("auto"));
        // Round-trips.
        let out = a.to_toml().unwrap();
        assert!(out.contains("address6 = \"2001:db8:1::1/64\""), "got:\n{out}");
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
        assert_eq!(b.interfaces[0].router_advert.as_ref().unwrap().prefixes.len(), 1);
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
}
