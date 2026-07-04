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
    net::Ipv4Addr,
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

# A VLAN subinterface on lan0, in its own zone:
# [[interface]]
# name = "lan0.20"
# parent = "lan0"
# vlan = 20
# zone = "iot"
# address = "10.0.20.1/24"

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
    }
}

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
}

impl Rule {
    /// A broad zone rule (no proto/port) — sets the from-zone's default posture.
    pub fn is_broad(&self) -> bool {
        self.proto.is_none() && self.port.is_none()
    }
    /// A specific proto/port rule.
    pub fn is_port_rule(&self) -> bool {
        self.proto.is_some() && self.port.is_some()
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
            // VLAN subinterface: parent + vlan come as a pair; vlan in range; the
            // parent must be a declared interface.
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
            // proto and port are a pair: a port rule needs both, a broad rule
            // neither.
            if rule.proto.is_some() != rule.port.is_some() {
                bail!(
                    "rule {:?}: `proto` and `port` must be set together",
                    rule.name
                );
            }
            // A port (or range) must be in range and not inverted/too wide.
            if let Some(port) = rule.port {
                port.validate()
                    .with_context(|| format!("rule {:?}", rule.name))?;
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
            validate_cidr_or_ip(&r.prefix)
                .with_context(|| format!("protocols static route {:?}", r.prefix))?;
            if r.via.is_none() && r.dev.is_none() {
                bail!("protocols static route {:?}: needs a via <ip> or dev <if>", r.prefix);
            }
            if let Some(via) = &r.via {
                validate_ipv4(via)
                    .with_context(|| format!("protocols static route {:?} via", r.prefix))?;
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
    fn toml_json_roundtrip_is_lossless() {
        let a = Appliance::from_toml(EXAMPLE).unwrap();
        // TOML -> JSON -> TOML preserves the config.
        let via_json = Appliance::from_json(&a.to_json().unwrap()).unwrap();
        let via_toml = Appliance::from_toml(&a.to_toml().unwrap()).unwrap();
        assert_eq!(a.summary(), via_json.summary());
        assert_eq!(a.summary(), via_toml.summary());
    }
}
