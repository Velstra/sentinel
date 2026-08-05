//! Compile the declarative appliance config into a **Velstra agent config**.
//!
//! Velstra's data plane decides a packet's fate at its **ingress interface**:
//! each interface is bound to a policy, and the policy carries a default action
//! plus (later) rules. So we map each Sentinel interface to a per-**zone** policy
//! and give that policy an ingress posture derived from the zone's rules:
//!
//! * a zone whose rules let it *initiate* (any `from = <zone>, action = accept`)
//!   gets `default_action = pass`,
//! * every other zone gets `default_action = drop` (e.g. WAN: block inbound),
//! * all policies are `stateful`, so return traffic for allowed flows comes back.
//!
//! This is the **zone ingress posture** — a real, working firewall from the
//! declared zones. The precise per-destination-zone matrix (and port rules) is
//! the next slice; this module emits a subset of Velstra's `FileConfig`, and
//! Velstra fills the rest with defaults (its schema is `deny_unknown_fields` +
//! `default`, so the subset must use only known field names — it does).

use std::collections::BTreeMap;

use serde::Serialize;

use crate::config::{Action, Appliance, Proto};

/// The MSS a departing SYN may advertise on this link, if it needs a ceiling.
///
/// `pmtu` means "as much as this link can carry": the MTU less a 20-byte IPv4
/// header and a 20-byte TCP header. A PPPoE session gets one without being asked,
/// because that is the case that otherwise fails silently — the link comes up,
/// small traffic works, and anything large hangs.
fn mss_ceiling(i: &crate::config::Interface) -> Option<u16> {
    const HEADERS: u16 = 40;
    const PPPOE_MTU: u16 = 1492;
    let mtu = i.mtu.unwrap_or(PPPOE_MTU);
    match i.mss.as_deref() {
        Some("pmtu") => Some(mtu.saturating_sub(HEADERS)),
        Some(n) => n.parse().ok(),
        None if i.if_type == Some(crate::config::IfaceType::Pppoe) => Some(PPPOE_MTU - HEADERS),
        None => None,
    }
}

/// The subset of Velstra's agent `FileConfig` we emit. Field names and the
/// `policy`/`interface` array renames match Velstra's TOML schema exactly.
#[derive(Debug, Serialize)]
pub struct VelstraConfig {
    default_action: &'static str,
    stateful: bool,
    drop_icmp: bool,
    log: bool,
    /// Source-address validation (uRPF) for the default policy. Omitted when
    /// disabled, which is velstra's own default.
    #[serde(skip_serializing_if = "is_disabled")]
    source_validation: &'static str,
    /// Host-wide: drop a packet the data plane cannot parse rather than pass it.
    /// Not a per-policy field — the parse fails before any policy is known — so
    /// it is emitted once, at the top level.
    ///
    /// **Always emitted, in both states.** It used to be omitted when off, on
    /// the reasoning that the data plane's own default was the same — which
    /// meant two defaults had to agree, in two repositories, for a
    /// security-relevant decision. Stating it every time leaves one place the
    /// answer comes from.
    fail_closed: bool,
    // Inline array of strings — still a scalar for TOML ordering, so it must
    // precede the `[[policy]]`/`[[interface]]` tables below.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    blocklist: Vec<String>,
    #[serde(rename = "policy")]
    policies: Vec<Policy>,
    #[serde(rename = "interface")]
    interfaces: Vec<Interface>,
    #[serde(rename = "port_forward", skip_serializing_if = "Vec::is_empty")]
    port_forwards: Vec<PortForwardOut>,
    #[serde(rename = "npt66", skip_serializing_if = "Vec::is_empty")]
    npt66: Vec<Npt66Out>,
    /// C15 SYN proxy (`[[synproxy]]`) — the TCP ports whose handshake the data
    /// plane completes on the server's behalf.
    #[serde(rename = "synproxy", skip_serializing_if = "Vec::is_empty")]
    synproxy: Vec<SynProxyOut>,
    /// C12 IPFIX flow export (`[flow_export]`).
    #[serde(rename = "flow_export", skip_serializing_if = "Option::is_none")]
    flow_export: Option<FlowExportOut>,
    /// C22 load-balanced services (`[[service]]`) — fabric's XDP L4 load
    /// balancer, which had no way in from the appliance config.
    #[serde(rename = "service", skip_serializing_if = "Vec::is_empty")]
    services: Vec<ServiceOut>,
    /// C9 stateful-HA conntrack sync (`[conntrack_sync]`). Present only when the
    /// appliance has `[system.conntrack-sync]`. A single table emitted after the
    /// `[[…]]` arrays — velstra reads it order-independently.
    #[serde(skip_serializing_if = "Option::is_none")]
    conntrack_sync: Option<ConntrackSyncOut>,
    /// The overlay this box terminates, when EVPN is configured. Omitted
    /// otherwise, which is what leaves the data plane in plain routing mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    overlay: Option<OverlayOut>,
}

/// `[overlay]` in the emitted data-plane config: how this box wraps and unwraps
/// tenant frames.
///
/// The control plane decides *where* a frame goes — that is the routing daemon's
/// half of EVPN — and this decides *how* it travels. Only the local identity is
/// here; which MAC lives behind which peer arrives at run time, learned rather
/// than written.
#[derive(Debug, Serialize)]
struct OverlayOut {
    local_vtep: String,
    underlay_iface: String,
    encap: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    underlay_mtu: Option<u16>,
}

/// One `[[service]]` in the emitted velstra config: a VIP fronting a pool.
#[derive(Debug, Serialize)]
struct ServiceOut {
    /// The ingress zone's policy id — the datapath looks a service up under the
    /// arriving packet's policy, so a VIP is reachable from the zone it is
    /// declared on.
    policy: u32,
    vip: String,
    port: u16,
    proto: &'static str,
    #[serde(rename = "backends")]
    backends: Vec<BackendOut>,
    /// Always true on an appliance. A VIP is declared on the zone clients reach it
    /// from, while its pool lives on an internal zone, so the backend's reply
    /// arrives under a *different* policy than the request did. Without this the
    /// datapath's conntrack entry — scoped to the ingress policy, which is right for
    /// a multi-tenant fabric — never matches that reply, and the client receives a
    /// packet from the backend's own address instead of from the VIP.
    router_nat: bool,
}

/// One backend behind a [`ServiceOut`].
#[derive(Debug, Serialize)]
struct BackendOut {
    ip: String,
    /// Absent ⇒ keep the client's original destination port.
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
}

/// The `[conntrack_sync]` block in the emitted velstra config — endpoints already
/// normalized to `ip:port` by the appliance layer.
#[derive(Debug, Serialize)]
struct ConntrackSyncOut {
    listen: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    peer: Vec<String>,
    interval_secs: u64,
}

/// One `[[npt66]]` entry in the emitted velstra config — a NPTv6 (RFC 6296)
/// prefix translation bound to a boundary interface.
#[derive(Debug, Serialize)]
struct Npt66Out {
    interface: String,
    internal: String,
    external: String,
}

/// The `[flow_export]` table in the emitted velstra config — the agent owns the
/// conntrack table, so it is the agent that exports from it.
#[derive(Debug, Serialize)]
struct FlowExportOut {
    collector: String,
    interval_secs: u64,
    observation_domain: u32,
}

/// Default export interval: often enough that a graph has shape, rarely enough
/// that the export is not itself the traffic.
const DEFAULT_EXPORT_INTERVAL: u64 = 30;

/// One `[[synproxy]]` entry in the emitted velstra config — a TCP port whose
/// handshake the data plane completes on the server's behalf.
#[derive(Debug, Serialize)]
struct SynProxyOut {
    port: u16,
    mss: u16,
}

/// The MSS a SYN proxy advertises when the appliance config does not say: a
/// 1500-byte Ethernet MTU less the IPv4 and TCP headers. Duplicated from
/// `velstra-config`'s own default rather than shared, because the appliance does
/// not link the data-plane crates; the emitted config always states the value,
/// so the two can never quietly disagree about what was configured.
const DEFAULT_SYNPROXY_MSS: u16 = 1460;

#[derive(Debug, Serialize)]
struct Policy {
    id: u32,
    name: String,
    default_action: &'static str,
    stateful: bool,
    drop_icmp: bool,
    log: bool,
    #[serde(skip_serializing_if = "is_disabled")]
    source_validation: &'static str,
    // Scalars above, the array-of-tables below (TOML requires this order).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    blocklist: Vec<String>,
    /// C20: the captive-portal gate for this zone. A sub-table, so it comes
    /// after the scalars and before the `[[policy.port_rule]]` array.
    #[serde(skip_serializing_if = "Option::is_none")]
    portal: Option<PortalOut>,
    #[serde(rename = "port_rule", skip_serializing_if = "Vec::is_empty")]
    port_rules: Vec<PortRule>,
}

/// Which policy id each zone in use compiles to.
///
/// Assigned by sorted zone name so a recompile is deterministic — the map keys
/// the data plane uses for conntrack and rules must not move because an
/// interface was added. Exposed because the portal has to name a zone's policy
/// to the agent, and a second implementation of this rule would eventually
/// admit devices to the wrong zone.
pub fn zone_policy_ids(appliance: &Appliance) -> BTreeMap<&str, u32> {
    let mut zone_names: Vec<&str> = appliance
        .interfaces
        .iter()
        .filter(|i| !i.disabled)
        .filter_map(|i| i.zone.as_deref())
        .collect();
    zone_names.sort_unstable();
    zone_names.dedup();
    zone_names
        .into_iter()
        .enumerate()
        .map(|(i, name)| (name, i as u32 + 1))
        .collect()
}

/// The gate for `zone`, or `None` when it is not the zone behind the portal.
///
/// The addresses are the appliance's own in that zone, taken from the first
/// enabled interface that has one — the same address the portal binds and the
/// same one DHCP option 114 announces, because all three have to be the address
/// the client can actually reach, and deriving them from one place is what keeps
/// them the same.
fn portal_gate(appliance: &Appliance, zone: &str) -> Option<PortalOut> {
    if appliance.services.portal.zone.as_deref() != Some(zone) {
        return None;
    }
    let addressed = |pick: fn(&crate::config::Interface) -> Option<&String>| {
        appliance
            .interfaces
            .iter()
            .filter(|i| !i.disabled && i.zone.as_deref() == Some(zone))
            .find_map(|i| pick(i).map(|a| a.split('/').next().unwrap_or(a).to_string()))
    };
    let out = PortalOut {
        address: addressed(|i| i.address.as_ref()),
        address6: addressed(|i| i.address6.as_ref()),
    };
    // Validation refuses a portal zone with no IPv4 address, so this is the
    // belt to that brace: emitting an empty gate would set the portal flag on a
    // zone whose gate matches nothing, closing it around a page nobody can load.
    if out.address.is_none() && out.address6.is_none() {
        return None;
    }
    Some(out)
}

/// The appliance's own addresses in a gated zone — what a device that has not
/// been admitted is still allowed to reach (roadmap C20).
#[derive(Debug, Serialize)]
struct PortalOut {
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address6: Option<String>,
}

#[derive(Debug, Serialize)]
struct PortRule {
    /// Which configured rule this came from. Carried in memory so the appliance
    /// can say what a live flow was admitted by, and never serialised — the data
    /// plane keys on `(policy, proto, port, address)` and has no use for a name.
    #[serde(skip)]
    name: String,
    proto: &'static str,
    port: u16,
    action: &'static str,
    /// Log packets matching this rule. Omitted when false (the common case).
    #[serde(skip_serializing_if = "is_false")]
    log: bool,
    /// Optional source CIDR ("10.0.0.0/24"). Omitted when the rule is `from any`.
    #[serde(skip_serializing_if = "Option::is_none")]
    src: Option<String>,
    /// The sender's hardware address this rule is a verdict on. Never set
    /// together with a port or an address: the data plane consults MACs once
    /// from the Ethernet header, not as a dimension of its rule tries.
    #[serde(rename = "src-mac", skip_serializing_if = "Option::is_none")]
    src_mac: Option<String>,
    /// Optional destination CIDR. Omitted when the rule is `to any`. Never set
    /// together with `src` — the data plane ranks one end per rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    dst: Option<String>,
    /// New-flow rate limit in packets/s. Omitted when the rule is unlimited.
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<u32>,
    /// Burst capacity in packets. Omitted to let the data plane default it to one
    /// second's worth of `limit`.
    #[serde(skip_serializing_if = "Option::is_none")]
    burst: Option<u32>,
    /// The ICMP/ICMPv6 type, already resolved from whatever name the operator
    /// wrote. Omitted when the rule matches every type.
    #[serde(rename = "icmp-type", skip_serializing_if = "Option::is_none")]
    icmp_type: Option<u8>,
    /// Which address family this rule is for. Omitted when it is for both.
    #[serde(skip_serializing_if = "Option::is_none")]
    family: Option<String>,
    /// Which direction this rule is for. Omitted when it is for both.
    #[serde(skip_serializing_if = "Option::is_none")]
    direction: Option<String>,
}

#[derive(Debug, Serialize)]
struct Interface {
    name: String,
    policy: u32,
    /// The overlay segment this port is on, when an EVPN instance names it.
    ///
    /// Deliberately separate from `policy`: the ruleset a port is filtered by
    /// and the segment its frames belong to are different questions, and several
    /// ports on one segment may want different rules. Omitted ⇒ the data plane
    /// defaults it to `policy`, the single-tenant convenience.
    #[serde(skip_serializing_if = "Option::is_none")]
    vni: Option<u32>,
    /// Clamp the MSS a departing SYN advertises to this. Omitted when the link
    /// does not need one.
    #[serde(skip_serializing_if = "Option::is_none")]
    mss: Option<u16>,
    /// Source-NAT (masquerade) traffic leaving this interface — set when the
    /// interface's zone has a `[[nat.source]]` rule. Omitted when false.
    #[serde(skip_serializing_if = "is_false")]
    masquerade: bool,
    /// Deterministic CGNAT (roadmap C16): the first WAN port and the ports each
    /// internal address gets. Both omitted unless the zone's masquerade rule asks
    /// for blocks — the data plane's own default is the plain hash-spread NAPT.
    #[serde(skip_serializing_if = "is_zero_u16")]
    cgnat_base_port: u16,
    #[serde(skip_serializing_if = "is_zero_u16")]
    cgnat_block_size: u16,
}

fn is_zero_u16(v: &u16) -> bool {
    *v == 0
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_disabled(mode: &&'static str) -> bool {
    **mode == *"disable"
}

/// A zone's blocklist with its GeoIP countries expanded into it.
///
/// The countries become ordinary CIDRs in the same list an operator's own entries
/// go into, so the data plane needs no idea what a country is — one blocklist,
/// one lookup, and `show firewall statistics` attributes a geo-block to
/// `dropped_blocklist` like any other. The cost is a large emitted config, which
/// is an implementation detail nobody reads; the alternative is a second matching
/// dimension in the hot path for something a prefix list already expresses.
///
/// A country whose data is missing is refused at commit (`config::validate`), so
/// by the time this runs every lookup succeeds; a failure here would mean the
/// image changed underneath a saved config, and dropping the entry silently is
/// the one thing a blocklist must never do — hence the panic-free `expect`-less
/// path that simply keeps what it could resolve and lets validate speak.
fn geo_blocklist(posture: &crate::config::ResolvedZone) -> Vec<String> {
    let mut out = posture.blocklist.clone();
    for country in &posture.geoip_block {
        if let Ok(prefixes) = crate::config::geoip_prefixes(country) {
            out.extend(prefixes);
        }
    }
    out
}

#[derive(Debug, Serialize)]
struct PortForwardOut {
    policy: u32,
    proto: &'static str,
    port: u16,
    dst_ip: String,
    dst_port: u16,
    /// Hairpin (NAT reflection) match guard — only DNAT when the packet's
    /// destination equals this (the box's public IP). Absent ⇒ match any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    match_dst: Option<String>,
    /// Hairpin source-NAT address (the box's IP on the client's segment). Absent
    /// ⇒ no source rewrite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    snat_ip: Option<String>,
}

impl VelstraConfig {
    /// Render as the TOML the Velstra agent loads with `--config`.
    pub fn to_toml(&self) -> anyhow::Result<String> {
        use anyhow::Context;
        toml::to_string_pretty(self).context("serializing the velstra config")
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

/// Map a Sentinel action to a Velstra action. Velstra now enforces `reject`
/// directly (a TCP RST / drop), so it is emitted as-is rather than collapsing to
/// `drop`.
fn action_str(a: Action) -> &'static str {
    match a {
        Action::Accept => "pass",
        Action::Drop => "drop",
        Action::Reject => "reject",
    }
}

/// Compile a Sentinel appliance config into a Velstra agent config. Each named
/// zone in use becomes one policy, carrying its resolved posture (zone override
/// over the global `[firewall]` defaults). Policy ids are assigned by sorted zone
/// name so recompiles are deterministic (stable conntrack/map keys).
pub fn compile(appliance: &Appliance) -> VelstraConfig {
    let fw = &appliance.firewall;

    // The zones actually in use (a zone with no assigned interface needs no
    // policy; interfaces the system provides but that aren't assigned a zone yet
    // are simply not firewalled). Sorted + deduped → stable ids starting at 1.
    // An administratively disabled interface is dropped from the data plane
    // entirely: it contributes no zone and gets no policy binding (so the agent
    // never attaches XDP to it). A disabled rule / NAT entry is likewise skipped
    // below.
    let ids = zone_policy_ids(appliance);
    let zone_names: Vec<&str> = ids.keys().copied().collect();

    // The IPv4 subnets a zone owns, as network CIDRs derived from its interfaces'
    // static addresses ("10.2.0.1/24" -> "10.2.0.0/24"). This is what makes a
    // rule's `to <zone>` enforceable: the data plane matches addresses, not zone
    // names, so the destination zone has to be spelled as the prefixes it holds.
    // A `dhcp` or address-less interface contributes nothing — `warnings()` tells
    // the operator when that leaves a `to` unenforceable.
    // The network an address sits in, as a CIDR string — the form the data plane
    // matches on. Both families: a rule's destination carries its own family, and
    // the data plane routes it to the v4 or v6 trie accordingly.
    let network_of = |cidr: &str| -> Option<String> {
        let (addr, prefix) = cidr.split_once('/')?;
        let bits: u32 = prefix.parse().ok()?;
        if let Ok(ip) = addr.parse::<std::net::Ipv4Addr>() {
            if bits > 32 {
                return None;
            }
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            return Some(format!(
                "{}/{bits}",
                std::net::Ipv4Addr::from(u32::from(ip) & mask)
            ));
        }
        let ip: std::net::Ipv6Addr = addr.parse().ok()?;
        if bits > 128 {
            return None;
        }
        let mask = if bits == 0 {
            0
        } else {
            u128::MAX << (128 - bits)
        };
        Some(format!(
            "{}/{bits}",
            std::net::Ipv6Addr::from(u128::from(ip) & mask)
        ))
    };

    let zone_subnets = |zone: &str| -> Vec<String> {
        // The appliance itself is a set of addresses, not a set of links: `to
        // <local zone>` means "terminating here", so it compiles to this box's
        // own addresses as host routes — in both families, or a dual-stacked box
        // could only bind rules toward half of itself.
        if appliance.zones.get(zone).is_some_and(|z| z.local) {
            return appliance
                .interfaces
                .iter()
                .filter(|i| !i.disabled)
                .flat_map(|i| [i.address.as_deref(), i.address6.as_deref()])
                .flatten()
                .filter_map(|cidr| {
                    let (addr, _) = cidr.split_once('/')?;
                    if addr.parse::<std::net::Ipv4Addr>().is_ok() {
                        Some(format!("{addr}/32"))
                    } else if addr.parse::<std::net::Ipv6Addr>().is_ok() {
                        Some(format!("{addr}/128"))
                    } else {
                        None
                    }
                })
                .collect();
        }
        appliance
            .interfaces
            .iter()
            .filter(|i| !i.disabled && i.zone.as_deref() == Some(zone))
            .flat_map(|i| [i.address.as_deref(), i.address6.as_deref()])
            .flatten()
            .filter_map(network_of)
            .collect()
    };

    let policies = zone_names
        .iter()
        .map(|&zone| {
            let posture = appliance.zone_posture(zone);
            // Default action: an explicit per-zone override wins; otherwise the
            // posture comes from broad rules (pass if this zone may initiate),
            // falling back to the global firewall default action.
            let default_action = match posture.default_action {
                Some(a) => action_str(a),
                None => {
                    let initiates = appliance.rules.iter().any(|r| {
                        !r.disabled && r.from == zone && r.is_broad() && r.action == Action::Accept
                    });
                    if initiates {
                        "pass"
                    } else {
                        action_str(fw.default_action)
                    }
                }
            };
            // Specific proto/port rules become Velstra port rules on this policy.
            // A port *range* or a `port-group` expands to one data-plane rule per
            // port, and a `source-group` fans out over its member CIDRs — so a
            // grouped rule emits the full (sources × ports) product here (the data
            // plane keys on a single `(proto, port[, src])`). The width is capped
            // at validate time so this stays small.
            let groups = &appliance.firewall.group;
            // A rule naming a mac-group becomes one data-plane rule per member.
            // It carries no protocol and no port by construction — validation
            // refuses those beside it — so it never reaches the tries at all.
            let mac_rules: Vec<PortRule> = appliance
                .rules
                .iter()
                .filter(|r| !r.disabled && r.from == zone)
                .filter_map(|r| r.source_mac_group.as_ref().map(|g| (r, g)))
                .flat_map(|(r, g)| {
                    let action = action_str(r.action);
                    groups
                        .mac
                        .get(g)
                        .cloned()
                        .unwrap_or_default()
                        .into_iter()
                        .map(move |mac| PortRule {
                            name: r.name.clone(),
                            proto: "tcp",
                            port: 0,
                            action,
                            log: false,
                            src: None,
                            dst: None,
                            limit: None,
                            burst: None,
                            icmp_type: None,
                            src_mac: Some(mac),
                            family: None,
                            direction: None,
                        })
                })
                .collect();
            let port_rules = appliance
                .rules
                .iter()
                // A scheduled rule (roadmap C15) is emitted only while its weekly
                // window is open (local time); a systemd timer re-applies at the
                // boundaries. An unscheduled rule is always emitted.
                .filter(|r| {
                    !r.disabled
                        && r.from == zone
                        && r.is_port_rule()
                        && r.schedule.as_ref().is_none_or(|s| s.is_active_now())
                })
                .flat_map(|r| {
                    // `is_port_rule()` already implies a proto, but guard the unwrap
                    // so a future change to that predicate can never panic the
                    // compile: a proto-less rule simply contributes no port rules.
                    // `tcp_udp` is one rule to an operator and two to the data
                    // plane, which has no such protocol. Expanding it here means
                    // nothing downstream has to know the grammar has a word for
                    // "either".
                    let Some(protos) = r.proto.map(|p| p.concrete()) else {
                        return Vec::new();
                    };
                    let action = action_str(r.action);
                    let log = r.log;
                    // A rule constrains one end or the other — validation refuses
                    // both — so exactly one of these expands to something other
                    // than a single `None`, and the product stays one entry per
                    // (constraint, port).
                    let sources = r.resolved_sources(groups);
                    // `to <zone>` is enforced as a destination match on that zone's
                    // subnets — validation has already refused it alongside an
                    // explicit source or destination, so exactly one of these three
                    // ever contributes. A zone with no static subnet yields nothing
                    // to match and falls back to "any" (with a commit warning).
                    // …but only when the rule has not already bound its source: one
                    // rule matches one address end, and an explicit source is the
                    // narrower, operator-written constraint. `warnings()` says so at
                    // every commit rather than letting it pass unremarked.
                    let binds_source = r.source.is_some() || r.source_group.is_some();
                    let zoned: Vec<Option<String>> = match &r.to {
                        Some(z) if !binds_source => zone_subnets(z).into_iter().map(Some).collect(),
                        _ => Vec::new(),
                    };
                    let destinations = if zoned.is_empty() {
                        r.resolved_destinations(groups)
                    } else {
                        zoned
                    };
                    let ports = r.resolved_ports(groups);
                    let mut out = Vec::with_capacity(
                        protos.len() * sources.len() * destinations.len() * ports.len(),
                    );
                    for &p in protos {
                        let proto = proto_str(p);
                        // Resolved here rather than at parse time because
                        // `tcp_udp` expands to several protocols and a name
                        // means a different number in each family. Validation
                        // has already refused a type on a protocol without any,
                        // so a failure here cannot happen — and if it somehow
                        // did, matching every type would be the wrong way to be
                        // wrong, so it becomes a type nothing sends.
                        let icmp_type = r.icmp_type.as_deref().map(|t| {
                            crate::config::resolve_icmp_type(
                                t,
                                matches!(p, crate::config::Proto::Icmpv6),
                            )
                            .unwrap_or(u8::MAX)
                        });
                        for src in &sources {
                            for dst in &destinations {
                                for &port in &ports {
                                    out.push(PortRule {
                                        name: r.name.clone(),
                                        proto,
                                        port,
                                        action,
                                        log,
                                        src: src.clone(),
                                        dst: dst.clone(),
                                        limit: r.limit,
                                        burst: r.burst,
                                        icmp_type,
                                        src_mac: None,
                                        family: r.family.clone(),
                                        direction: r.direction.clone(),
                                    });
                                }
                            }
                        }
                    }
                    out
                })
                .collect();
            // C22: open the firewall for each load-balanced service on this zone.
            //
            // The data plane special-cases a *port-forward* (a matching
            // PORT_FORWARDS entry passes the packet regardless of the zone's
            // default action) but has no such rule for a service, so under a
            // default-drop zone — the normal configuration — a VIP would be
            // silently unreachable. Emitting a real `pass` rule instead of adding
            // another datapath special case has the advantage that the opening is
            // *visible*: it shows up in the compiled config an operator inspects.
            let mut port_rules: Vec<PortRule> = port_rules;
            port_rules.extend(mac_rules);
            for lb in appliance
                .load_balancers
                .iter()
                .filter(|l| !l.disabled && l.zone == zone)
            {
                let rule = PortRule {
                    // Not an operator's rule: the compiler opens the VIP's port
                    // itself, and saying so beats attributing a flow to a rule
                    // nobody wrote.
                    name: format!("(load-balancer {})", lb.name),
                    proto: proto_str(lb.proto),
                    port: lb.port,
                    action: "pass",
                    log: false,
                    src: None,
                    dst: None,
                    limit: None,
                    burst: None,
                    icmp_type: None,
                    src_mac: None,
                    family: None,
                    direction: None,
                };
                // An explicit rule the operator wrote for the same (proto, port)
                // wins — including a `drop`, which is how you take a VIP out of
                // service without deleting it.
                if !port_rules
                    .iter()
                    .any(|r| r.proto == rule.proto && r.port == rule.port && r.src.is_none())
                {
                    port_rules.push(rule);
                }
            }
            Policy {
                id: ids[zone],
                name: zone.to_string(),
                default_action,
                stateful: posture.stateful,
                drop_icmp: posture.block_icmp,
                log: posture.log,
                source_validation: posture.source_validation.as_str(),
                blocklist: geo_blocklist(&posture),
                portal: portal_gate(appliance, zone),
                port_rules,
            }
        })
        .collect();

    // Zones that have a source-NAT (masquerade) rule — their interfaces get
    // `masquerade = true` so the data plane SNATs traffic leaving them.
    // Zone → its masquerade rule's CGNAT layout (`(0, 0)` for plain masquerade).
    // A map rather than a set, because the layout has to reach the interfaces of
    // exactly the zone that asked for it.
    let masq_zones: BTreeMap<&str, (u16, u16)> = appliance
        .nat
        .source
        .iter()
        .filter(|s| !s.disabled)
        .map(|s| {
            let layout = match s.cgnat_block_size {
                Some(size) => (
                    s.cgnat_base_port
                        .unwrap_or(crate::config::DEFAULT_CGNAT_BASE_PORT),
                    size,
                ),
                None => (0, 0),
            };
            (s.zone.as_str(), layout)
        })
        .collect();

    let interfaces = appliance
        .interfaces
        .iter()
        .filter(|i| !i.disabled)
        .filter_map(|i| {
            i.zone.as_deref().map(|zone| Interface {
                name: i.name.clone(),
                policy: ids[zone],
                // An EVPN instance names the ports on its segment; that binding
                // is what puts a frame from this port into that VNI.
                vni: appliance
                    .evpn
                    .instances
                    .iter()
                    .find(|inst| inst.interfaces.iter().any(|n| n == &i.name))
                    .map(|inst| inst.vni),
                // `pmtu` is resolved here rather than carried down: the data
                // plane clamps to a number, and the number a tunnel needs is its
                // MTU less the IPv4 and TCP headers.
                mss: mss_ceiling(i),
                masquerade: masq_zones.contains_key(zone),
                cgnat_base_port: masq_zones.get(zone).map_or(0, |l| l.0),
                cgnat_block_size: masq_zones.get(zone).map_or(0, |l| l.1),
            })
        })
        .collect();

    // A zone's static IPv4 (the box's own address on that segment), taken from the
    // first enabled interface in the zone with a parseable static v4 CIDR. `dhcp`
    // (or an address-less) interface yields `None`. Used to resolve hairpin match /
    // SNAT addresses at compile time.
    let zone_ipv4 = |zone: &str| -> Option<std::net::Ipv4Addr> {
        appliance
            .interfaces
            .iter()
            .filter(|i| !i.disabled && i.zone.as_deref() == Some(zone))
            .find_map(|i| {
                let addr = i.address.as_deref()?;
                addr.split('/').next()?.parse::<std::net::Ipv4Addr>().ok()
            })
    };

    // Destination NAT (port-forwards) binds to its ingress zone's policy; `to`
    // splits into the internal ip:port (validated already, so a parse miss just
    // drops the entry). Source NAT (masquerade) is enforced in Phase 4b.
    //
    // A `hairpin` destination additionally emits one **reflection** entry per other
    // zone: an internal client dialling the box's public IP is DNAT'd to the server
    // and source-NAT'd to the box's address on that segment, so the reply routes
    // back through the box. Reflection needs the ingress zone's public IP known at
    // compile time — skipped (with the plain forward still emitted) when the
    // ingress zone is DHCP/address-less.
    // C15: the SYN proxy is named by port, so it needs no zone resolution — the
    // appliance's own default MSS is filled in here rather than in the data
    // plane, so what was decided is visible in the emitted config.
    let synproxy: Vec<SynProxyOut> = fw
        .syn_protect
        .iter()
        .map(|s| SynProxyOut {
            port: s.port,
            mss: s.mss.unwrap_or(DEFAULT_SYNPROXY_MSS),
        })
        .collect();

    let mut port_forwards: Vec<PortForwardOut> = Vec::new();
    for dst in appliance.nat.destination.iter().filter(|d| !d.disabled) {
        let Some(&policy) = ids.get(dst.zone.as_str()) else {
            continue;
        };
        let Ok((ip, port)) = crate::config::parse_host_port(&dst.to) else {
            continue;
        };
        let proto = proto_str(dst.proto);
        let dst_ip = ip.to_string();
        // The plain forward on the ingress (public) zone.
        port_forwards.push(PortForwardOut {
            policy,
            proto,
            port: dst.port,
            dst_ip: dst_ip.clone(),
            dst_port: port,
            match_dst: None,
            snat_ip: None,
        });
        if !dst.hairpin {
            continue;
        }
        let Some(public_ip) = zone_ipv4(&dst.zone) else {
            continue; // no static public IP → reflection can't be resolved.
        };
        for (&zname, &zpolicy) in ids.iter().filter(|(z, _)| **z != dst.zone.as_str()) {
            let Some(box_ip) = zone_ipv4(zname) else {
                continue; // this internal zone has no static box address → skip.
            };
            port_forwards.push(PortForwardOut {
                policy: zpolicy,
                proto,
                port: dst.port,
                dst_ip: dst_ip.clone(),
                dst_port: port,
                match_dst: Some(public_ip.to_string()),
                snat_ip: Some(box_ip.to_string()),
            });
        }
    }

    // C22 load-balanced services — one `[[service]]` per enabled load balancer,
    // scoped to its ingress zone's policy.
    let mut services: Vec<ServiceOut> = Vec::new();
    for lb in appliance.load_balancers.iter().filter(|l| !l.disabled) {
        let Some(&policy) = ids.get(lb.zone.as_str()) else {
            continue;
        };
        let mut backends = Vec::with_capacity(lb.backends.len());
        for spec in &lb.backends {
            let Ok((ip, port)) = crate::config::parse_host_port(spec) else {
                continue;
            };
            backends.push(BackendOut {
                ip: ip.to_string(),
                // A bare address parses to port 0, which the datapath reads as
                // "keep the client's port" — express that as an absent field
                // rather than emitting a literal 0.
                port: (port != 0).then_some(port),
            });
        }
        services.push(ServiceOut {
            policy,
            vip: lb.vip.clone(),
            port: lb.port,
            proto: proto_str(lb.proto),
            backends,
            router_nat: true,
        });
    }

    // NPTv6 (RFC 6296) — one `[[npt66]]` per rule, bound to its boundary interface.
    let npt66 = appliance
        .nat
        .npt66
        .iter()
        .map(|n| Npt66Out {
            interface: n.interface.clone(),
            internal: n.internal.clone(),
            external: n.external.clone(),
        })
        .collect();

    // C9 conntrack sync — emit `[conntrack_sync]` only when configured, with the
    // endpoints already normalized to `ip:port` by the appliance layer.
    let cts = &appliance.system.conntrack_sync;
    let conntrack_sync = cts.listen_endpoint().map(|listen| ConntrackSyncOut {
        listen,
        peer: cts.peer_endpoints(),
        interval_secs: cts.interval.unwrap_or(1),
    });

    VelstraConfig {
        // Deny by default; interfaces opt into their zone policy.
        default_action: action_str(fw.default_action),
        stateful: fw.stateful,
        drop_icmp: fw.block_icmp,
        log: fw.log,
        source_validation: fw.source_validation.as_str(),
        fail_closed: fw.fail_closed,
        blocklist: fw.blocklist.clone(),
        policies,
        interfaces,
        port_forwards,
        npt66,
        synproxy,
        flow_export: appliance
            .services
            .flow_export
            .collector
            .as_ref()
            .map(|c| FlowExportOut {
                collector: c.clone(),
                interval_secs: appliance
                    .services
                    .flow_export
                    .interval
                    .unwrap_or(DEFAULT_EXPORT_INTERVAL),
                observation_domain: appliance.services.flow_export.domain.unwrap_or(1),
            }),
        services,
        conntrack_sync,
        overlay: (!appliance.evpn.is_empty()).then(|| {
            let e = &appliance.evpn;
            OverlayOut {
                local_vtep: e.vtep_ip.clone().unwrap_or_default(),
                underlay_iface: e.underlay_interface.clone().unwrap_or_default(),
                // Unset means VXLAN, which is what every switch speaks — so the
                // default is the interoperable one rather than the newer one.
                encap: match e.encapsulation.as_deref() {
                    Some("geneve") => "geneve",
                    _ => "vxlan",
                },
                udp_port: e.udp_port,
                underlay_mtu: e.mtu,
            }
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Appliance;

    /// Point the country database at a temporary directory holding two small
    /// countries, so the expansion can be asserted exactly rather than against
    /// whatever the image happens to ship.
    ///
    /// The variable it sets is process-wide and the harness runs tests in
    /// parallel, so this takes a lock. Without it one test removes the variable —
    /// or deletes the directory — while another is still reading through it, and
    /// the resulting failure looks like the feature rather than the fixture.
    fn with_geoip<T>(tag: &str, body: impl FnOnce() -> T) -> T {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        // Poisoning only means an earlier test panicked; the fixture is rebuilt
        // from scratch below either way.
        let _held = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("sentinel-geoip-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("XA.v4"), "10.1.0.0/16\n10.2.0.0/16\n").unwrap();
        std::fs::write(dir.join("XA.v6"), "2001:db8:a::/48\n").unwrap();
        std::fs::write(dir.join("XB.v4"), "10.9.0.0/16\n").unwrap();
        // SAFETY: the lock above makes this the only test touching the variable;
        // it is restored before the lock is released.
        unsafe { std::env::set_var("SENTINEL_GEOIP_DIR", &dir) };
        let out = body();
        unsafe { std::env::remove_var("SENTINEL_GEOIP_DIR") };
        let _ = std::fs::remove_dir_all(&dir);
        out
    }

    #[test]
    fn a_blocked_country_becomes_ordinary_cidrs_on_its_zone() {
        let toml = r#"
[system]
hostname = "fw"

[firewall]
geoip-block = ["XA"]
blocklist = ["203.0.113.7"]

[zone.wan]
geoip-block = ["XB"]

[[interface]]
name = "wan0"
zone = "wan"

[[interface]]
name = "lan0"
zone = "lan"
"#;
        let (wan, lan) = with_geoip("expand", || {
            let appliance = Appliance::from_toml(toml).unwrap();
            let cfg = compile(&appliance);
            let of = |name: &str| {
                cfg.policies
                    .iter()
                    .find(|p| p.name == name)
                    .unwrap()
                    .blocklist
                    .clone()
            };
            (of("wan"), of("lan"))
        });

        // The zone's own country is ADDED to the global one, not swapped for it:
        // a country blocked everywhere must not become reachable because a zone
        // named a different one.
        assert!(wan.contains(&"10.1.0.0/16".to_string()));
        assert!(wan.contains(&"2001:db8:a::/48".to_string()));
        assert!(wan.contains(&"10.9.0.0/16".to_string()));
        // The operator's own entry survives alongside them.
        assert!(wan.contains(&"203.0.113.7".to_string()));
        // LAN inherits only the global country.
        assert!(lan.contains(&"10.1.0.0/16".to_string()));
        assert!(!lan.contains(&"10.9.0.0/16".to_string()));
    }

    #[test]
    fn an_unknown_country_is_refused_rather_than_blocking_nothing() {
        let toml = r#"
[system]
hostname = "fw"

[firewall]
geoip-block = ["ZZ"]
"#;
        let err = with_geoip("unknown", || {
            Appliance::from_toml(toml).unwrap_err().to_string()
        });
        assert!(err.contains("no addresses for country"), "got: {err}");
    }

    #[test]
    fn source_validation_reaches_the_zone_that_asked_for_it() {
        let toml = r#"
[system]
hostname = "fw"

[firewall]
source-validation = "loose"

[zone.wan]
source-validation = "strict"

[[interface]]
name = "wan0"
zone = "wan"

[[interface]]
name = "lan0"
zone = "lan"
"#;
        let appliance = Appliance::from_toml(toml).unwrap();
        let cfg = compile(&appliance);
        let wan = cfg.policies.iter().find(|p| p.name == "wan").unwrap();
        let lan = cfg.policies.iter().find(|p| p.name == "lan").unwrap();
        // The edge validates strictly; the inside inherits the global `loose`.
        assert_eq!(wan.source_validation, "strict");
        assert_eq!(lan.source_validation, "loose");

        let rendered = cfg.to_toml().unwrap();
        assert!(
            rendered.contains(r#"source_validation = "strict""#),
            "{rendered}"
        );
    }

    #[test]
    fn disabled_source_validation_writes_nothing() {
        // The default must not appear in the emitted config: an agent reading it
        // would behave identically, and a line that says "disable" invites the
        // reader to think something is switched on.
        let appliance = Appliance::from_toml(crate::config::EXAMPLE).unwrap();
        let rendered = compile(&appliance).to_toml().unwrap();
        assert!(!rendered.contains("source_validation"), "{rendered}");
    }

    /// The agent renders a table, not JSON, so this reads one back — including
    /// the header and the "… n more" footer, which must not become flows.
    #[test]
    fn the_agents_flow_table_parses_back() {
        let text = "\
  policy proto source                destination           nat                     packets    bytes
  2      tcp   198.51.100.7:51234    10.0.0.5:443          dst→10.0.0.5:443             120    14 kB
  2      udp   198.51.100.9:5353     10.0.0.5:53           dst→10.0.0.5:53                4   380 B
  … 12 more (of 14 total)
";
        let flows = parse_flows(text);
        assert_eq!(flows.len(), 2, "the header and the footer became flows");
        assert_eq!(flows[0].policy, 2);
        assert_eq!(flows[0].proto, "tcp");
        assert_eq!(flows[0].dst_port, 443);
        assert_eq!(flows[0].packets, 120);
        assert_eq!(flows[1].dst_port, 53);
    }

    /// The whole point of attribution: which accept rules are carrying traffic
    /// and which are carrying none — matched against the *compiled* rules, so
    /// the ranking is the one the data plane applies rather than a second
    /// implementation of it.
    #[test]
    fn flows_are_attributed_to_the_rule_that_admitted_them() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "eth0"
zone = "lan"
[[interface]]
name = "eth1"
zone = "wan"
[zone.wan]
default_action = "drop"
[[rule]]
name = "web-in"
from = "wan"
action = "accept"
proto = "tcp"
port = 443
[[rule]]
name = "office-ssh"
from = "wan"
source = "203.0.113.0/24"
action = "accept"
proto = "tcp"
port = 22
[[rule]]
name = "legacy-smb"
from = "wan"
action = "accept"
proto = "tcp"
port = 445
"#;
        let appliance = Appliance::from_toml(toml).expect("parses");
        let cfg = compile(&appliance);
        let wan = cfg.policies.iter().find(|p| p.name == "wan").unwrap().id;

        let flow = |dport: u16, src: &str, packets: u64| Flow {
            policy: wan,
            proto: "tcp".into(),
            src: src.parse().unwrap(),
            dst: "10.0.0.5".parse().unwrap(),
            dst_port: dport,
            packets,
        };
        let hits = attribute(
            &cfg,
            &[
                flow(443, "198.51.100.7", 10),
                flow(443, "198.51.100.8", 5),
                // From the office, so the source-scoped rule takes it.
                flow(22, "203.0.113.9", 3),
            ],
        );

        assert_eq!(
            hits["web-in"],
            Hits {
                flows: 2,
                packets: 15
            }
        );
        assert_eq!(
            hits["office-ssh"],
            Hits {
                flows: 1,
                packets: 3
            }
        );
        // A rule carrying nothing is *present* and zero, not missing — that is
        // the whole report.
        assert_eq!(hits["legacy-smb"], Hits::default());

        // An SSH flow from somewhere else matches no rule: the source-scoped
        // rule does not cover it and there is no `from any` rule on 22.
        let elsewhere = attribute(&cfg, &[flow(22, "192.0.2.1", 99)]);
        assert_eq!(elsewhere["office-ssh"], Hits::default());
    }

    /// A rule naming a protocol that has no ports must reach the data plane as a
    /// rule, not vanish into the zone's posture. Port `0` is the key the data
    /// plane reads off a packet that carries no ports, so this is what matches
    /// every ICMP packet the rule scopes — and nothing else.
    #[test]
    fn a_port_less_protocol_compiles_to_a_rule_on_port_zero() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "eth0"
zone = "lan"
[[interface]]
name = "eth1"
zone = "wan"
[zone.wan]
default_action = "drop"
[[rule]]
name = "icmp-in"
from = "wan"
action = "accept"
proto = "icmp"
"#;
        let appliance = Appliance::from_toml(toml).expect("parses");
        let cfg = compile(&appliance);
        let wan = cfg
            .policies
            .iter()
            .find(|p| p.port_rules.iter().any(|r| r.proto == "icmp"))
            .expect("the wan policy carries the icmp rule");
        let rule = wan.port_rules.iter().find(|r| r.proto == "icmp").unwrap();
        assert_eq!(rule.port, 0, "an ICMP rule is keyed on port 0");
        // `accept` is `pass` on the wire — the data plane's own word for it.
        assert_eq!(rule.action, "pass");
    }

    /// `to <zone>` binds on the zone's subnets — in **both** families. It used
    /// to collect only IPv4, so on a v6-only segment the destination silently
    /// widened to every zone: the rule still passed traffic, just far more of it
    /// than it said. On the translated production configuration this was 31
    /// rules, and 1392 destination constraints that were never programmed.
    #[test]
    fn a_destination_zone_binds_on_both_families() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "eth0"
zone = "lan"
address = "10.0.0.1/24"
address6 = "2001:db8:1::1/64"
[[interface]]
name = "eth1"
zone = "wan"
[zone.wan]
default_action = "drop"
[[rule]]
name = "web-in"
from = "wan"
to = "lan"
action = "accept"
proto = "tcp"
port = 443
"#;
        let appliance = Appliance::from_toml(toml).expect("parses");
        let cfg = compile(&appliance);
        let dsts: Vec<&str> = cfg
            .policies
            .iter()
            .flat_map(|p| p.port_rules.iter())
            .filter_map(|r| r.dst.as_deref())
            .collect();
        assert!(
            dsts.contains(&"10.0.0.0/24"),
            "the v4 subnet is missing: {dsts:?}"
        );
        assert!(
            dsts.contains(&"2001:db8:1::/64"),
            "the v6 subnet is missing, so the rule widens to every zone: {dsts:?}"
        );
    }

    /// The local zone is the box, in both families too — otherwise a dual-stacked
    /// appliance could only bind rules toward half of itself.
    #[test]
    fn the_local_zone_is_this_box_in_both_families() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "eth0"
zone = "lan"
address = "10.0.0.1/24"
address6 = "2001:db8:1::1/64"
[zone.firewall]
local = true
[[rule]]
name = "ssh-in"
from = "lan"
to = "firewall"
action = "accept"
proto = "tcp"
port = 22
"#;
        let appliance = Appliance::from_toml(toml).expect("parses");
        let cfg = compile(&appliance);
        let dsts: Vec<&str> = cfg
            .policies
            .iter()
            .flat_map(|p| p.port_rules.iter())
            .filter_map(|r| r.dst.as_deref())
            .collect();
        assert!(dsts.contains(&"10.0.0.1/32"), "{dsts:?}");
        assert!(dsts.contains(&"2001:db8:1::1/128"), "{dsts:?}");
    }

    /// `tcp_udp` is one rule to an operator and two to the data plane, which
    /// has no such protocol. It exists because a service reached over either —
    /// DNS, NTP, a Samba share — is one decision, and writing it twice means two
    /// rules to keep in step afterwards.
    #[test]
    fn tcp_udp_compiles_to_both_protocols() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "eth0"
zone = "lan"
[[interface]]
name = "eth1"
zone = "wan"
[zone.wan]
default_action = "drop"
[[rule]]
name = "dns-in"
from = "wan"
action = "accept"
proto = "tcp_udp"
port = 53
"#;
        let appliance = Appliance::from_toml(toml).expect("parses");
        let cfg = compile(&appliance);
        let rules: Vec<&str> = cfg
            .policies
            .iter()
            .flat_map(|p| p.port_rules.iter())
            .filter(|r| r.port == 53)
            .map(|r| r.proto)
            .collect();
        assert_eq!(rules, ["tcp", "udp"], "one rule, both protocols");
        // And nothing downstream ever sees the word: the data plane has no
        // protocol number for "either".
        assert!(
            !cfg.policies
                .iter()
                .flat_map(|p| p.port_rules.iter())
                .any(|r| r.proto == "tcp_udp"),
            "tcp_udp reached the data plane instead of being expanded"
        );
    }

    #[test]
    fn compiles_example_to_zone_ingress_posture() {
        let appliance = Appliance::from_toml(crate::config::EXAMPLE).unwrap();
        let cfg = compile(&appliance);

        // One interface binding per declared interface.
        assert_eq!(cfg.interfaces.len(), 2);
        // Policy ids are assigned by sorted zone name: lan=1, wan=2.
        let wan = cfg.policies.iter().find(|p| p.name == "wan").unwrap();
        let lan = cfg.policies.iter().find(|p| p.name == "lan").unwrap();
        assert_eq!((lan.id, wan.id), (1, 2));
        let wan_if = cfg.interfaces.iter().find(|i| i.name == "wan0").unwrap();
        assert_eq!(wan_if.policy, wan.id);

        // Per-zone posture: WAN blocks ICMP (its [zone.wan] override), LAN
        // inherits the firewall default (ICMP allowed).
        assert!(wan.drop_icmp, "wan zone blocks icmp");
        assert!(!lan.drop_icmp, "lan zone allows icmp");
        assert_eq!(wan.default_action, "drop"); // no broad accept-from-wan rule
        assert_eq!(lan.default_action, "pass"); // lan-to-wan accept lets lan initiate
        assert!(wan.stateful && lan.stateful);

        // The inbound-HTTPS port rule lands on the WAN policy as a pass for tcp/443.
        assert_eq!(wan.port_rules.len(), 1);
        assert_eq!(wan.port_rules[0].proto, "tcp");
        assert_eq!(wan.port_rules[0].port, 443);
        assert_eq!(wan.port_rules[0].action, "pass");
        assert!(lan.port_rules.is_empty());

        // It renders to TOML the agent can load.
        let toml = cfg.to_toml().unwrap();
        assert!(toml.contains("[[interface]]"));
        assert!(toml.contains("[[policy]]"));
        assert!(toml.contains("[[policy.port_rule]]"));
    }

    #[test]
    fn firewall_settings_flow_into_top_level_and_each_policy() {
        let cfg_toml = r#"
[system]
hostname = "fw"

[firewall]
stateful = false
block_icmp = true
blocklist = ["10.6.6.0/24", "192.0.2.5"]

[[interface]]
name = "wan0"
zone = "wan"

[[interface]]
name = "lan0"
zone = "lan"

[[rule]]
name = "lan-out"
from = "lan"
to = "wan"
action = "accept"
"#;
        let appliance = Appliance::from_toml(cfg_toml).unwrap();
        let cfg = compile(&appliance);

        // Top-level posture reflects the [firewall] section.
        assert!(!cfg.stateful);
        assert!(cfg.drop_icmp);
        assert_eq!(cfg.blocklist, ["10.6.6.0/24", "192.0.2.5"]);

        // Every zone policy inherits the global posture + blocklist, so it
        // applies to traffic on assigned interfaces (not just policy 0).
        for p in &cfg.policies {
            assert!(!p.stateful, "policy {} stateful", p.name);
            assert!(p.drop_icmp, "policy {} drop_icmp", p.name);
            assert_eq!(p.blocklist, ["10.6.6.0/24", "192.0.2.5"]);
        }

        // It renders with the fabric field names (deny_unknown_fields-safe).
        let toml = cfg.to_toml().unwrap();
        assert!(toml.contains("drop_icmp = true"));
        assert!(toml.contains("blocklist = ["));
    }

    #[test]
    fn default_firewall_keeps_stateful_on_and_omits_empty_blocklist() {
        let appliance = Appliance::from_toml(crate::config::EXAMPLE).unwrap();
        let cfg = compile(&appliance);
        assert!(cfg.stateful);
        assert!(!cfg.drop_icmp);
        assert!(cfg.blocklist.is_empty());
        // An empty blocklist is skipped, so the agent never sees `blocklist = []`.
        assert!(!cfg.to_toml().unwrap().contains("blocklist"));
    }

    #[test]
    fn disabled_interfaces_rules_and_nat_are_dropped_from_the_data_plane() {
        let toml = r#"
[system]
hostname = "fw"

[[interface]]
name = "wan0"
zone = "wan"

[[interface]]
name = "lan0"
zone = "lan"

# A disabled interface: its zone contributes no policy and it gets no binding
# (so the agent never attaches XDP to it).
[[interface]]
name = "dmz0"
zone = "dmz"
disabled = true

# An active inbound rule and a parked (disabled) one on the same zone pair.
[[rule]]
name = "allow-https-in"
from = "wan"
to = "lan"
action = "accept"
proto = "tcp"
port = 443

[[rule]]
name = "parked"
from = "wan"
to = "lan"
action = "accept"
proto = "tcp"
port = 8080
disabled = true

# A disabled port-forward is not emitted; an active one is.
[[nat.destination]]
name = "web"
zone = "wan"
proto = "tcp"
port = 443
to = "10.0.0.10:8443"

[[nat.destination]]
name = "parked-fwd"
zone = "wan"
proto = "tcp"
port = 2222
to = "10.0.0.11:22"
disabled = true
"#;
        let appliance = Appliance::from_toml(toml).unwrap();
        let cfg = compile(&appliance);

        // The disabled interface's zone (dmz) produced no policy, and only the
        // two enabled interfaces are bound.
        assert!(
            cfg.policies.iter().all(|p| p.name != "dmz"),
            "disabled interface's zone must not become a policy"
        );
        assert_eq!(cfg.interfaces.len(), 2);
        assert!(cfg.interfaces.iter().all(|i| i.name != "dmz0"));

        // Only the enabled port rule survives on the WAN policy.
        let wan = cfg.policies.iter().find(|p| p.name == "wan").unwrap();
        assert_eq!(wan.port_rules.len(), 1);
        assert_eq!(wan.port_rules[0].port, 443);

        // Only the enabled port-forward is emitted.
        assert_eq!(cfg.port_forwards.len(), 1);
        assert_eq!(cfg.port_forwards[0].port, 443);
    }

    #[test]
    fn port_range_expands_to_one_port_rule_per_port() {
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
name = "passive-ftp"
from = "wan"
to = "lan"
action = "accept"
proto = "tcp"
port = "8000-8002"
"#;
        let cfg = compile(&Appliance::from_toml(toml).unwrap());
        let wan = cfg.policies.iter().find(|p| p.name == "wan").unwrap();
        // The 3-port range became three single-port rules.
        let ports: Vec<u16> = wan.port_rules.iter().map(|r| r.port).collect();
        assert_eq!(ports, vec![8000, 8001, 8002]);
        assert!(
            wan.port_rules
                .iter()
                .all(|r| r.proto == "tcp" && r.action == "pass")
        );
    }

    /// C22: fabric's XDP load balancer had no way in from the appliance config —
    /// the data plane has had `[[service]]` since phase 3 and nothing emitted it.
    #[test]
    fn a_load_balancer_becomes_a_service_scoped_to_its_zone() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
[[interface]]
name = "lan0"
zone = "lan"
[[load-balancer]]
name = "web"
zone = "wan"
vip = "203.0.113.10"
proto = "tcp"
port = 443
backends = ["10.0.0.11:8443", "10.0.0.12"]
"#;
        let appliance = Appliance::from_toml(toml).unwrap();
        appliance.clone().validate().expect("valid");
        let cfg = compile(&appliance);

        assert_eq!(cfg.services.len(), 1);
        let svc = &cfg.services[0];
        // The datapath keys a service by the *arriving* packet's policy, so the
        // service must carry the ingress zone's id, not a global one.
        let wan_policy = cfg.policies.iter().find(|p| p.name == "wan").unwrap().id;
        assert_eq!(svc.policy, wan_policy);
        assert_eq!(svc.vip, "203.0.113.10");
        assert_eq!(svc.port, 443);
        assert_eq!(svc.proto, "tcp");
        // …and it must claim the router-NAT conntrack namespace. On an appliance
        // the pool answers through an internal zone, so the reply arrives under a
        // different policy than the request; scoped to the ingress policy (right
        // for a multi-tenant fabric) that reply is never rewritten back to the VIP
        // and the client drops it as coming from a stranger.
        assert!(svc.router_nat, "an appliance service is router-NAT'd");

        assert_eq!(svc.backends.len(), 2);
        assert_eq!(svc.backends[0].ip, "10.0.0.11");
        assert_eq!(svc.backends[0].port, Some(8443));
        // A bare address means "keep the client's port", which the datapath reads
        // from an absent field — emitting a literal 0 would mean port zero.
        assert_eq!(svc.backends[1].ip, "10.0.0.12");
        assert_eq!(svc.backends[1].port, None);

        // The firewall must be opened for the VIP, or a default-drop zone (the
        // normal configuration) makes it silently unreachable: the data plane
        // special-cases a port-forward but knows nothing about a service.
        let wan = cfg.policies.iter().find(|p| p.name == "wan").unwrap();
        let opened = wan
            .port_rules
            .iter()
            .find(|r| r.port == 443 && r.proto == "tcp")
            .expect("the service port is opened");
        assert_eq!(opened.action, "pass");

        let out = cfg.to_toml().unwrap();
        assert!(out.contains("[[service]]"), "service emitted:\n{out}");
        assert!(out.contains("vip = \"203.0.113.10\""), "{out}");
    }

    /// Until now only the *source* end could be constrained, so "allow the lan out,
    /// but not to this network" was inexpressible. The destination is a second
    /// longest-prefix dimension in the data plane, and the compiler has to keep the
    /// two apart: a rule sits in one table or the other.
    #[test]
    fn a_rule_can_constrain_the_destination_instead_of_the_source() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "lan0"
zone = "lan"
[[interface]]
name = "wan0"
zone = "wan"
[[rule]]
name = "no-doc-server"
from = "lan"
proto = "tcp"
port = 443
action = "drop"
destination = "192.168.4.0/24"
[[rule]]
name = "trusted-in"
from = "wan"
proto = "tcp"
port = 22
action = "accept"
source = "198.51.100.0/24"
"#;
        let appliance = Appliance::from_toml(toml).unwrap();
        appliance.clone().validate().expect("valid");
        let cfg = compile(&appliance);

        let lan = cfg.policies.iter().find(|p| p.name == "lan").unwrap();
        let blocked = lan.port_rules.iter().find(|r| r.port == 443).unwrap();
        assert_eq!(blocked.dst.as_deref(), Some("192.168.4.0/24"));
        assert!(blocked.src.is_none(), "one end per rule");

        let wan = cfg.policies.iter().find(|p| p.name == "wan").unwrap();
        let allowed = wan.port_rules.iter().find(|r| r.port == 22).unwrap();
        assert_eq!(allowed.src.as_deref(), Some("198.51.100.0/24"));
        assert!(allowed.dst.is_none());

        // Both ends reach the emitted config under the names the agent parses.
        let out = cfg.to_toml().unwrap();
        assert!(out.contains(r#"dst = "192.168.4.0/24""#), "{out}");
        assert!(out.contains(r#"src = "198.51.100.0/24""#), "{out}");
    }

    /// An address group works on either end, expanding to one data-plane rule per
    /// member — the same treatment `source-group` already gets.
    #[test]
    fn a_destination_group_expands_to_one_rule_per_member() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "lan0"
zone = "lan"
[firewall.group.address]
blocked = ["192.168.4.0/24", "203.0.113.9"]
[[rule]]
name = "no-go"
from = "lan"
proto = "tcp"
port = 443
action = "drop"
destination-group = "blocked"
"#;
        let appliance = Appliance::from_toml(toml).unwrap();
        appliance.clone().validate().expect("valid");
        let cfg = compile(&appliance);
        let lan = cfg.policies.iter().find(|p| p.name == "lan").unwrap();
        let dsts: Vec<&str> = lan
            .port_rules
            .iter()
            .filter(|r| r.port == 443)
            .filter_map(|r| r.dst.as_deref())
            .collect();
        assert_eq!(dsts, vec!["192.168.4.0/24", "203.0.113.9"]);
    }

    /// `to <zone>` used to be accepted and then ignored, so an `accept` rule aimed
    /// at one zone actually opened the port toward every zone — a rule that lets in
    /// more than it reads as. It is now matched as the destination zone's subnets.
    #[test]
    fn a_destination_zone_is_enforced_as_that_zones_subnets() {
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
name = "dmz0"
zone = "dmz"
address = "10.9.0.1/24"
[[rule]]
name = "https-in"
from = "wan"
to = "dmz"
proto = "tcp"
port = 443
action = "accept"
"#;
        let appliance = Appliance::from_toml(toml).unwrap();
        appliance.clone().validate().expect("valid");
        assert!(
            appliance.warnings().is_empty(),
            "an enforceable `to` must not warn: {:?}",
            appliance.warnings()
        );
        let cfg = compile(&appliance);
        let wan = cfg.policies.iter().find(|p| p.name == "wan").unwrap();
        let opened: Vec<&str> = wan
            .port_rules
            .iter()
            .filter(|r| r.port == 443)
            .filter_map(|r| r.dst.as_deref())
            .collect();
        // The dmz subnet, as a NETWORK address — the interface carries the box's own
        // host address, which would match only the box itself.
        assert_eq!(opened, vec!["10.9.0.0/24"]);
    }

    /// A rule that already binds its source keeps doing so: one rule matches one
    /// address end, and the source is the narrower constraint. `to` then stays
    /// documentation — and the commit says so, because the rule reaches further
    /// than it reads.
    #[test]
    fn a_source_constraint_keeps_the_address_end_and_the_zone_warns() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
address = "203.0.113.2/24"
[[interface]]
name = "dmz0"
zone = "dmz"
address = "10.9.0.1/24"
[[rule]]
name = "https-in"
from = "wan"
to = "dmz"
proto = "tcp"
port = 443
action = "accept"
source = "198.51.100.0/24"
"#;
        let appliance = Appliance::from_toml(toml).unwrap();
        appliance.clone().validate().expect("valid");
        let warns = appliance.warnings();
        assert!(
            warns.iter().any(|w| w.contains("constrains its source")),
            "{warns:?}"
        );
        let cfg = compile(&appliance);
        let rule = cfg
            .policies
            .iter()
            .find(|p| p.name == "wan")
            .unwrap()
            .port_rules
            .iter()
            .find(|r| r.port == 443)
            .unwrap();
        assert_eq!(rule.src.as_deref(), Some("198.51.100.0/24"));
        assert!(rule.dst.is_none(), "one address end per rule");
    }

    /// A destination zone with nothing but a DHCP interface has no subnet to match,
    /// so the rule silently applies everywhere — which is exactly the case the
    /// commit warning has to keep covering.
    #[test]
    fn an_unaddressed_destination_zone_still_warns() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
address = "dhcp"
[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"
[[rule]]
name = "out"
from = "lan"
to = "wan"
proto = "tcp"
port = 443
action = "accept"
"#;
        let appliance = Appliance::from_toml(toml).unwrap();
        appliance.clone().validate().expect("valid");
        let warns = appliance.warnings();
        assert!(
            warns.iter().any(|w| w.contains("cannot be enforced")),
            "{warns:?}"
        );
        let cfg = compile(&appliance);
        let rule = cfg
            .policies
            .iter()
            .find(|p| p.name == "lan")
            .unwrap()
            .port_rules
            .iter()
            .find(|r| r.port == 443)
            .unwrap();
        assert!(rule.dst.is_none());
    }

    /// A rate limit reaches the data plane on the rule it belongs to, and the burst
    /// stays absent when unset so the agent applies its own default rather than the
    /// compiler inventing one.
    #[test]
    fn a_rate_limit_flows_onto_the_port_rule() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
[[rule]]
name = "ssh-in"
from = "wan"
proto = "tcp"
port = 22
action = "accept"
limit = 5
"#;
        let appliance = Appliance::from_toml(toml).unwrap();
        appliance.clone().validate().expect("valid");
        let cfg = compile(&appliance);
        let rule = cfg
            .policies
            .iter()
            .find(|p| p.name == "wan")
            .unwrap()
            .port_rules
            .iter()
            .find(|r| r.port == 22)
            .unwrap();
        assert_eq!(rule.limit, Some(5));
        assert_eq!(rule.burst, None, "an unset burst is the agent's to default");
        let out = cfg.to_toml().unwrap();
        assert!(out.contains("limit = 5"), "{out}");
        assert!(!out.contains("burst"), "{out}");
    }

    /// A limit that cannot bite is refused, not ignored — a configured limit that
    /// silently does nothing is discovered during the flood it was meant to stop.
    #[test]
    fn a_limit_needs_an_accept_rule_with_a_port() {
        let base = |extra: &str| {
            format!(
                r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
[[rule]]
name = "r"
from = "wan"
action = "accept"
{extra}
"#
            )
        };
        // `from_toml` already validates, so either step may carry the refusal.
        let refuse = |toml: String| -> String {
            match Appliance::from_toml(&toml) {
                Err(e) => e.to_string(),
                Ok(a) => a
                    .validate()
                    .expect_err("this configuration must be refused")
                    .to_string(),
            }
        };
        // A broad rule has no per-rule budget: it sets the zone's posture.
        let err = refuse(base("limit = 5"));
        assert!(err.contains("proto/port"), "{err}");

        // Throttling a rule that already denies throttles nothing.
        let err = refuse(
            base("proto = \"tcp\"\nport = 22\nlimit = 5")
                .replace("action = \"accept\"", "action = \"drop\""),
        );
        assert!(err.contains("admits"), "{err}");

        // A burst with nothing to size is a typo, not a configuration.
        let err = refuse(base("proto = \"tcp\"\nport = 22\nburst = 10"));
        assert!(err.contains("sizes a `limit`"), "{err}");
    }

    /// Deterministic CGNAT reaches the data plane on the interfaces of the zone
    /// whose masquerade rule asked for it — and only those, so a second uplink
    /// keeps ordinary NAPT.
    #[test]
    fn cgnat_blocks_land_on_the_masqueraded_zones_interfaces() {
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
[[nat.source]]
name = "carrier"
zone = "wan"
cgnat-block-size = 512
"#;
        let appliance = Appliance::from_toml(toml).unwrap();
        appliance.clone().validate().expect("valid");
        let cfg = compile(&appliance);
        let wan = cfg.interfaces.iter().find(|i| i.name == "wan0").unwrap();
        assert!(wan.masquerade);
        assert_eq!(wan.cgnat_block_size, 512);
        // The base port defaults to the ephemeral range, leaving the well-known
        // ports free for port-forwards on the same address.
        assert_eq!(wan.cgnat_base_port, 32768);
        // The internal side is not a CGNAT egress and must carry nothing.
        let lan = cfg.interfaces.iter().find(|i| i.name == "lan0").unwrap();
        assert!(!lan.masquerade);
        assert_eq!(lan.cgnat_block_size, 0);
        // Omitted from the emitted config when unset, so the data plane's own
        // default (plain hash-spread NAPT) applies rather than a zero layout.
        let out = cfg.to_toml().unwrap();
        assert!(out.contains("cgnat_block_size = 512"), "{out}");
        assert_eq!(out.matches("cgnat_block_size").count(), 1, "{out}");
    }

    /// A layout that cannot work is refused at commit, not silently downgraded to
    /// ordinary masquerade — an operator who asked for blocks would otherwise
    /// believe they had them.
    #[test]
    fn an_unworkable_cgnat_layout_is_refused() {
        let base = |extra: &str| {
            format!(
                r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
address = "203.0.113.2/24"
[[nat.source]]
name = "carrier"
zone = "wan"
{extra}
"#
            )
        };
        let refuse = |toml: String| -> String {
            match Appliance::from_toml(&toml) {
                Err(e) => e.to_string(),
                Ok(a) => a
                    .validate()
                    .expect_err("this layout must be refused")
                    .to_string(),
            }
        };
        // A block that does not fit above its base port.
        let err = refuse(base("cgnat-block-size = 1024\ncgnat-base-port = 65000"));
        assert!(err.contains("does not fit"), "{err}");
        // A base port with nothing to size.
        let err = refuse(base("cgnat-base-port = 40000"));
        assert!(err.contains("sizes nothing"), "{err}");
    }

    /// An explicit rule the operator wrote wins over the automatic opening — that
    /// is how a VIP is taken out of service without deleting it.
    #[test]
    fn an_explicit_rule_overrides_the_load_balancer_opening() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
[[load-balancer]]
name = "web"
zone = "wan"
vip = "203.0.113.10"
proto = "tcp"
port = 443
backends = ["10.0.0.11:8443"]
[[rule]]
name = "vip-off"
from = "wan"
to = "wan"
action = "drop"
proto = "tcp"
port = 443
"#;
        let cfg = compile(&Appliance::from_toml(toml).unwrap());
        let wan = cfg.policies.iter().find(|p| p.name == "wan").unwrap();
        let matching: Vec<&PortRule> = wan.port_rules.iter().filter(|r| r.port == 443).collect();
        assert_eq!(
            matching.len(),
            1,
            "no duplicate rule was added: {matching:?}"
        );
        assert_eq!(matching[0].action, "drop");
    }

    /// A disabled service must vanish from the data plane, not merely be marked.
    #[test]
    fn a_disabled_load_balancer_emits_nothing() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
[[load-balancer]]
name = "web"
zone = "wan"
vip = "203.0.113.10"
proto = "tcp"
port = 443
disabled = true
backends = ["10.0.0.11:8443"]
"#;
        let cfg = compile(&Appliance::from_toml(toml).unwrap());
        assert!(cfg.services.is_empty());
        assert!(!cfg.to_toml().unwrap().contains("[[service]]"));
    }

    #[test]
    fn rule_log_flag_flows_onto_the_port_rule() {
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
name = "ssh-watch"
from = "wan"
to = "lan"
action = "accept"
proto = "tcp"
port = 22
log = true
"#;
        let cfg = compile(&Appliance::from_toml(toml).unwrap());
        let wan = cfg.policies.iter().find(|p| p.name == "wan").unwrap();
        assert_eq!(wan.port_rules.len(), 1);
        assert!(
            wan.port_rules[0].log,
            "log flag should carry onto the port rule"
        );
        let out = cfg.to_toml().unwrap();
        assert!(
            out.contains("log = true"),
            "log emitted to velstra config:\n{out}"
        );
    }

    #[test]
    fn rule_source_flows_onto_the_port_rule() {
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
name = "ssh-from-mgmt"
from = "wan"
to = "lan"
action = "accept"
proto = "tcp"
port = 22
source = "10.0.0.0/24"
"#;
        let cfg = compile(&Appliance::from_toml(toml).unwrap());
        let wan = cfg.policies.iter().find(|p| p.name == "wan").unwrap();
        assert_eq!(wan.port_rules.len(), 1);
        assert_eq!(wan.port_rules[0].src.as_deref(), Some("10.0.0.0/24"));
        let out = cfg.to_toml().unwrap();
        assert!(
            out.contains(r#"src = "10.0.0.0/24""#),
            "source emitted to velstra config:\n{out}"
        );
    }

    #[test]
    fn rule_groups_expand_to_the_cartesian_product() {
        // An address-group of 2 CIDRs × a port-group of 3 ports → 6 port rules
        // on the wan policy, one per (source, port).
        let toml = r#"
[system]
hostname = "fw"
[firewall.group.address]
mgmt = ["10.0.0.0/24", "192.0.2.5"]
[firewall.group.port]
web = [80, 443, "8080-8080"]
[[interface]]
name = "wan0"
zone = "wan"
[[interface]]
name = "lan0"
zone = "lan"
[[rule]]
name = "grouped"
from = "wan"
to = "lan"
action = "accept"
proto = "tcp"
source_group = "mgmt"
port_group = "web"
"#;
        let cfg = compile(&Appliance::from_toml(toml).unwrap());
        let wan = cfg.policies.iter().find(|p| p.name == "wan").unwrap();
        assert_eq!(wan.port_rules.len(), 6, "2 sources × 3 ports");
        // Every source CIDR is present, paired with every port.
        let mut seen: Vec<(String, u16)> = wan
            .port_rules
            .iter()
            .map(|r| (r.src.clone().unwrap(), r.port))
            .collect();
        seen.sort();
        assert_eq!(
            seen,
            vec![
                ("10.0.0.0/24".into(), 80),
                ("10.0.0.0/24".into(), 443),
                ("10.0.0.0/24".into(), 8080),
                ("192.0.2.5".into(), 80),
                ("192.0.2.5".into(), 443),
                ("192.0.2.5".into(), 8080),
            ]
        );
        assert!(
            wan.port_rules
                .iter()
                .all(|r| r.proto == "tcp" && r.action == "pass")
        );
    }

    /// The agent owns the conntrack table, so it is the agent that exports from
    /// it — and the emitted config always states the interval and domain even
    /// when the appliance config left them out, so the two cannot quietly
    /// disagree about a value neither of them printed.
    #[test]
    fn flow_export_is_emitted_with_the_values_it_will_use() {
        let toml = r#"
[system]
hostname = "fw"
[services.flow-export]
collector = "10.0.0.50:4739"
"#;
        let cfg = compile(&Appliance::from_toml(toml).unwrap());
        let fx = cfg.flow_export.as_ref().expect("no flow export emitted");
        assert_eq!(fx.collector, "10.0.0.50:4739");
        assert_eq!(fx.interval_secs, DEFAULT_EXPORT_INTERVAL);
        assert_eq!(fx.observation_domain, 1);

        let out = toml::to_string(&cfg).unwrap();
        assert!(out.contains("[flow_export]"), "{out}");
        assert!(out.contains("interval_secs = 30"), "{out}");
    }

    /// No collector, no block: an appliance that exports nothing should not
    /// carry a table saying so.
    #[test]
    fn no_collector_emits_no_flow_export() {
        let cfg = compile(&Appliance::from_toml("[system]\nhostname = \"fw\"\n").unwrap());
        assert!(cfg.flow_export.is_none());
    }

    /// The emitted config always states the MSS, even when the appliance config
    /// left it out. The data plane has a default of its own, and two defaults
    /// that could drift apart is exactly the bug that never gets found — so the
    /// appliance decides and says so.
    #[test]
    fn a_syn_protected_port_is_emitted_with_the_mss_it_will_advertise() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
[[firewall.syn-protect]]
port = 443
[[firewall.syn-protect]]
port = 8080
mss = 1400
"#;
        let cfg = compile(&Appliance::from_toml(toml).unwrap());
        assert_eq!(cfg.synproxy.len(), 2);
        assert_eq!((cfg.synproxy[0].port, cfg.synproxy[0].mss), (443, 1460));
        assert_eq!((cfg.synproxy[1].port, cfg.synproxy[1].mss), (8080, 1400));

        let out = toml::to_string(&cfg).unwrap();
        assert!(out.contains("[[synproxy]]"), "{out}");
        assert!(out.contains("mss = 1460"), "{out}");
    }

    #[test]
    /// The gate the data plane enforces is the zone's policy plus the
    /// appliance's own address in it. Both halves have to reach the agent config
    /// together, and only for the gated zone.
    fn a_portal_gates_exactly_its_own_zone() {
        let toml = r#"
[system]
hostname = "fw"

[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"

[[interface]]
name = "guest0"
zone = "guest"
address = "192.168.50.1/24"
address6 = "2001:db8:50::1/64"

[services.portal]
zone = "guest"
passphrase = "sommer"
"#;
        let appliance = Appliance::from_toml(toml).unwrap();
        appliance.validate().unwrap();
        let out = compile(&appliance).to_toml().unwrap();

        // The gated zone carries the appliance's own addresses…
        assert!(out.contains("[policy.portal]"), "{out}");
        assert!(out.contains("address = \"192.168.50.1\""), "{out}");
        assert!(out.contains("address6 = \"2001:db8:50::1\""), "{out}");
        // …and exactly one zone does.
        assert_eq!(out.matches("[policy.portal]").count(), 1, "{out}");
    }

    /// NAT-PMP hands a host on the inside the power to open an inbound port, so
    /// the two zones are refused rather than defaulted: a wrong one means either
    /// a daemon nobody can reach or mappings opened on the wrong zone.
    #[test]
    fn port_mapping_needs_both_zones_and_they_must_differ() {
        let base = r#"
[system]
hostname = "fw"

[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"

[[interface]]
name = "wan0"
zone = "wan"
address = "203.0.113.7/24"
"#;
        // Both zones, addressed, and different: accepted, and it resolves.
        let ok = format!("{base}\n[services.port-mapping]\nzone = \"lan\"\nwan-zone = \"wan\"\n");
        let appliance = Appliance::from_toml(&ok).unwrap();
        let state = crate::portmap::resolve(&appliance).expect("no settings");
        assert_eq!(state.bind.to_string(), "10.0.0.1:5351");
        assert_eq!(state.external.to_string(), "203.0.113.7");
        // Opened on the uplink's policy, not the asking zone's.
        let ids = zone_policy_ids(&appliance);
        assert_eq!(state.wan_policy, ids["wan"]);
        assert_ne!(state.wan_policy, ids["lan"]);
        // Off unless asked for.
        assert!(!state.allow_privileged);

        // No uplink named: a mapping would have nowhere to be opened.
        let no_wan = format!("{base}\n[services.port-mapping]\nzone = \"lan\"\n");
        assert!(Appliance::from_toml(&no_wan).is_err());
        // Both the same: that maps a port on the very zone the request came from.
        let same = format!("{base}\n[services.port-mapping]\nzone = \"lan\"\nwan-zone = \"lan\"\n");
        assert!(Appliance::from_toml(&same).is_err());
    }

    #[test]
    /// A portal on a zone with no interface, or with no address to bind, is
    /// refused at commit: each of those looks the same from outside — a guest
    /// zone nobody can get onto — and none is visible until someone tries.
    fn a_portal_needs_a_zone_that_can_carry_it() {
        let base = r#"
[system]
hostname = "fw"

[[interface]]
name = "guest0"
zone = "guest"
"#;
        // No interface in that zone at all. (`from_toml` validates, so a
        // refusal here is the same refusal a `commit` gives.)
        let nowhere = format!("{base}\n[services.portal]\nzone = \"lounge\"\n");
        assert!(Appliance::from_toml(&nowhere).is_err());
        // The zone exists but has no address for the portal to listen on.
        let addressless = format!("{base}\n[services.portal]\nzone = \"guest\"\n");
        assert!(Appliance::from_toml(&addressless).is_err());
    }

    #[test]
    fn port_forward_emits_zone_policy_and_split_target() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
[[interface]]
name = "lan0"
zone = "lan"
[[nat.destination]]
name = "web"
zone = "wan"
proto = "tcp"
port = 443
to = "10.0.0.10:8443"
"#;
        let cfg = compile(&Appliance::from_toml(toml).unwrap());
        assert_eq!(cfg.port_forwards.len(), 1);
        let pf = &cfg.port_forwards[0];
        assert_eq!(pf.policy, 2); // wan sorts after lan → id 2
        assert_eq!((pf.proto, pf.port), ("tcp", 443));
        assert_eq!((pf.dst_ip.as_str(), pf.dst_port), ("10.0.0.10", 8443));
        let out = cfg.to_toml().unwrap();
        assert!(out.contains("[[port_forward]]"), "{out}");
        assert!(out.contains("dst_ip = \"10.0.0.10\""), "{out}");
    }

    #[test]
    fn hairpin_destination_emits_a_reflection_entry_per_internal_zone() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
address = "198.51.100.1/24"
[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"
[[nat.destination]]
name = "web"
zone = "wan"
proto = "tcp"
port = 443
to = "10.0.0.10:8443"
hairpin = true
"#;
        let cfg = compile(&Appliance::from_toml(toml).unwrap());
        // ids: lan=1, wan=2. A plain WAN forward plus one reflection entry for lan.
        assert_eq!(cfg.port_forwards.len(), 2);
        // The plain forward binds the wan (ingress) policy with no match/snat.
        let plain = cfg.port_forwards.iter().find(|p| p.policy == 2).unwrap();
        assert_eq!((plain.dst_ip.as_str(), plain.dst_port), ("10.0.0.10", 8443));
        assert!(plain.match_dst.is_none() && plain.snat_ip.is_none());
        // The reflection entry binds the lan policy: match the public IP, SNAT the
        // source to the box's lan address so the reply routes back through the box.
        let refl = cfg.port_forwards.iter().find(|p| p.policy == 1).unwrap();
        assert_eq!(refl.match_dst.as_deref(), Some("198.51.100.1"));
        assert_eq!(refl.snat_ip.as_deref(), Some("10.0.0.1"));
        assert_eq!((refl.dst_ip.as_str(), refl.dst_port), ("10.0.0.10", 8443));
        let out = cfg.to_toml().unwrap();
        assert!(out.contains("match_dst = \"198.51.100.1\""), "{out}");
        assert!(out.contains("snat_ip = \"10.0.0.1\""), "{out}");
    }

    #[test]
    fn hairpin_without_static_public_ip_skips_reflection() {
        // A DHCP wan → the public IP is unknown at compile time, so only the plain
        // forward is emitted (no reflection entry that couldn't match anything).
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
address = "dhcp"
[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"
[[nat.destination]]
name = "web"
zone = "wan"
proto = "tcp"
port = 443
to = "10.0.0.10:8443"
hairpin = true
"#;
        let cfg = compile(&Appliance::from_toml(toml).unwrap());
        assert_eq!(cfg.port_forwards.len(), 1);
        assert!(cfg.port_forwards[0].match_dst.is_none());
    }

    #[test]
    fn npt66_emits_a_prefix_translation_entry() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
address6 = "2001:db8:1::1/64"
[[nat.npt66]]
name = "v6"
interface = "wan0"
internal = "fd00:1::/48"
external = "2001:db8:1::/48"
"#;
        let cfg = compile(&Appliance::from_toml(toml).unwrap());
        assert_eq!(cfg.npt66.len(), 1);
        let n = &cfg.npt66[0];
        assert_eq!(n.interface, "wan0");
        assert_eq!(
            (n.internal.as_str(), n.external.as_str()),
            ("fd00:1::/48", "2001:db8:1::/48")
        );
        let out = cfg.to_toml().unwrap();
        assert!(out.contains("[[npt66]]"), "{out}");
        assert!(out.contains("internal = \"fd00:1::/48\""), "{out}");
        assert!(out.contains("external = \"2001:db8:1::/48\""), "{out}");
    }

    #[test]
    fn masquerade_zone_marks_its_interfaces() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
[[interface]]
name = "lan0"
zone = "lan"
[[nat.source]]
name = "wan-masq"
zone = "wan"
"#;
        let cfg = compile(&Appliance::from_toml(toml).unwrap());
        let wan_if = cfg.interfaces.iter().find(|i| i.name == "wan0").unwrap();
        let lan_if = cfg.interfaces.iter().find(|i| i.name == "lan0").unwrap();
        assert!(wan_if.masquerade, "wan zone has a nat source → masquerade");
        assert!(!lan_if.masquerade, "lan has no nat source");
        let out = cfg.to_toml().unwrap();
        assert!(out.contains("masquerade = true"), "{out}");
    }

    #[test]
    fn rendered_toml_round_trips_as_a_velstra_config() {
        // The emitted TOML must at least parse as a generic TOML document with
        // the expected shape (a full check lives in fabric's velstra-config).
        let appliance = Appliance::from_toml(crate::config::EXAMPLE).unwrap();
        let toml = compile(&appliance).to_toml().unwrap();
        let value: toml::Value = toml::from_str(&toml).unwrap();
        assert_eq!(value["default_action"].as_str(), Some("drop"));
        assert!(value["policy"].as_array().unwrap().len() == 2);
    }

    #[test]
    fn fail_closed_is_emitted_only_when_turned_on() {
        let appliance = |extra: &str| {
            let toml = format!(
                r#"
[system]
hostname = "fw"
[firewall]
{extra}
[[interface]]
name = "lan0"
zone = "lan"
"#
            );
            Appliance::from_toml(&toml).unwrap()
        };

        // On by default now: this appliance denies by default, and a packet the
        // filter cannot parse is exactly the one that posture must not admit.
        let cfg = compile(&appliance(""));
        assert!(cfg.fail_closed);
        let out = cfg.to_toml().unwrap();
        assert!(out.contains("fail_closed = true"), "{out}");

        // Turned off explicitly: emitted as `false` rather than omitted. The
        // data plane has a default of its own, and letting two defaults in two
        // repositories agree on a security decision is how they stop agreeing.
        let cfg = compile(&appliance("fail_closed = false"));
        assert!(!cfg.fail_closed);
        let out = cfg.to_toml().unwrap();
        assert!(out.contains("fail_closed = false"), "{out}");

        // On: emitted as a top-level scalar velstra reads into its FAIL_CLOSED map.
        let cfg = compile(&appliance("fail_closed = true"));
        assert!(cfg.fail_closed);
        let out = cfg.to_toml().unwrap();
        let value: toml::Value = toml::from_str(&out).unwrap();
        assert_eq!(value["fail_closed"].as_bool(), Some(true), "{out}");
    }

    #[test]
    fn conntrack_sync_emits_normalized_endpoints() {
        // A `[system.conntrack-sync]` with a bare-host peer + custom interval emits
        // a `[conntrack_sync]` block whose endpoints carry the default UDP port and
        // whose interval is passed through.
        let toml = r#"
[system]
hostname = "fw"
[system.conntrack-sync]
listen = "0.0.0.0:5429"
peer = ["10.9.0.2"]
interval = 3
[[interface]]
name = "lan0"
zone = "lan"
"#;
        let cfg = compile(&Appliance::from_toml(toml).unwrap());
        let cts = cfg.conntrack_sync.as_ref().expect("emitted");
        assert_eq!(cts.listen, "0.0.0.0:5429");
        assert_eq!(cts.peer, vec!["10.9.0.2:5429".to_string()]);
        assert_eq!(cts.interval_secs, 3);

        // And it renders as a `[conntrack_sync]` table velstra can parse.
        let out = cfg.to_toml().unwrap();
        assert!(out.contains("[conntrack_sync]"), "{out}");
        let value: toml::Value = toml::from_str(&out).unwrap();
        assert_eq!(
            value["conntrack_sync"]["listen"].as_str(),
            Some("0.0.0.0:5429")
        );
    }

    #[test]
    fn no_conntrack_sync_omits_the_block() {
        let appliance = Appliance::from_toml(crate::config::EXAMPLE).unwrap();
        let cfg = compile(&appliance);
        assert!(cfg.conntrack_sync.is_none());
        assert!(!cfg.to_toml().unwrap().contains("conntrack_sync"));
    }

    /// The MSS ceiling reaches the data plane as a *number*. It used to be an
    /// nftables ruleset saying "whatever this route's MTU turns out to be", which
    /// put the translation in the kernel where nobody could look at it.
    #[test]
    fn a_tunnel_carries_its_mss_ceiling_into_the_data_plane() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "eth0"
zone = "wan"
address = "192.0.2.1/24"
[[interface]]
name = "ppp0"
type = "pppoe"
parent = "eth0"
zone = "wan"
[interface.pppoe]
username = "u"
password = "p"
[[interface]]
name = "tun0"
type = "gre"
local = "192.0.2.1"
remote = "198.51.100.1"
mss = "1360"
zone = "wan"
"#;
        let appliance = Appliance::from_toml(toml).expect("parses");
        let out = compile(&appliance).to_toml().expect("compiles");
        // 1492 (PPPoE) less an IPv4 and a TCP header — a PPPoE link gets one
        // without asking, because that is the case that fails silently.
        assert!(out.contains("mss = 1452"), "{out}");
        assert!(out.contains("mss = 1360"), "{out}");
        // The plain uplink asked for nothing and is not a tunnel: clamping every
        // interface would shrink segments that fit perfectly.
        assert_eq!(out.matches("mss = ").count(), 2, "{out}");
    }
}

// ---- attribution ----------------------------------------------------------

/// One live flow, as the data plane reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    pub policy: u32,
    pub proto: String,
    pub src: std::net::IpAddr,
    pub dst: std::net::IpAddr,
    pub dst_port: u16,
    pub packets: u64,
}

/// What a rule is currently carrying.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hits {
    pub flows: u64,
    pub packets: u64,
}

/// Attribute live flows to the rules that admitted them.
///
/// Not a hardware counter — the data plane counts globally, not per rule — but
/// the answer to the question people actually have: which rules are carrying
/// traffic, and which are carrying none. The matching is done against the
/// **compiled** rules rather than the configured ones, so it applies the same
/// ranking the data plane does (longest prefix wins; on an equal prefix the
/// stricter action) and cannot drift from what is loaded.
///
/// Only `accept` rules are counted, and the caller must say so. A rule that
/// drops leaves no flow behind — the packet is gone — so a zero against a drop
/// rule would mean "nothing got through here", which is what it is *for*, and
/// reporting that as "never matched" would invite somebody to delete the rule
/// that is doing its job.
pub fn attribute(cfg: &VelstraConfig, flows: &[Flow]) -> BTreeMap<String, Hits> {
    let mut out: BTreeMap<String, Hits> = BTreeMap::new();
    // Every accept rule starts at zero, so a rule carrying nothing is present in
    // the answer rather than missing from it.
    for policy in &cfg.policies {
        for r in &policy.port_rules {
            if r.action == "pass" && !r.name.is_empty() {
                out.entry(r.name.clone()).or_default();
            }
        }
    }
    for flow in flows {
        let Some(policy) = cfg.policies.iter().find(|p| p.id == flow.policy) else {
            continue;
        };
        let mut best: Option<(&PortRule, u8)> = None;
        for r in &policy.port_rules {
            if r.proto != flow.proto || (r.port != 0 && r.port != flow.dst_port) {
                continue;
            }
            // One end per rule — the data plane ranks a source-scoped and a
            // destination-scoped rule against each other by prefix length, and
            // this has to agree with it.
            let bits = match (&r.src, &r.dst) {
                (Some(cidr), _) => match cidr_contains(cidr, flow.src) {
                    Some(b) => b,
                    None => continue,
                },
                (_, Some(cidr)) => match cidr_contains(cidr, flow.dst) {
                    Some(b) => b,
                    None => continue,
                },
                (None, None) => 0,
            };
            if best.is_none_or(|(_, b)| bits > b) {
                best = Some((r, bits));
            }
        }
        if let Some((r, _)) = best {
            if r.action == "pass" && !r.name.is_empty() {
                let e = out.entry(r.name.clone()).or_default();
                e.flows += 1;
                e.packets += flow.packets;
            }
        }
    }
    out
}

/// Parse the agent's flow table.
///
/// The agent renders a fixed-width table rather than JSON, so this reads it back
/// — which means it has to be forgiving: a header line, a "… n more" footer and
/// a NAT column that is only meaningful for some rows. Anything that does not
/// parse is skipped rather than failing the whole report, because a report that
/// vanishes on one odd line is worse than one that is short by it.
pub fn parse_flows(text: &str) -> Vec<Flow> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 7 {
            continue;
        }
        let Ok(policy) = f[0].parse::<u32>() else {
            continue; // the header, or the footer
        };
        let split = |s: &str| -> Option<(std::net::IpAddr, u16)> {
            let (ip, port) = s.rsplit_once(':')?;
            Some((ip.parse().ok()?, port.parse().ok()?))
        };
        let (Some((src, _)), Some((dst, dst_port))) = (split(f[2]), split(f[3])) else {
            continue;
        };
        out.push(Flow {
            policy,
            proto: f[1].to_string(),
            src,
            dst,
            dst_port,
            packets: f[5].parse().unwrap_or(0),
        });
    }
    out
}

/// Whether `addr` is inside `cidr`, and how specific that was. `None` when it is
/// not, or when the two are different address families.
fn cidr_contains(cidr: &str, addr: std::net::IpAddr) -> Option<u8> {
    let (net, len) = cidr.split_once('/')?;
    let len: u8 = len.parse().ok()?;
    match (net.parse().ok()?, addr) {
        (std::net::IpAddr::V4(n), std::net::IpAddr::V4(a)) => {
            if len > 32 {
                return None;
            }
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            (u32::from(n) & mask == u32::from(a) & mask).then_some(len)
        }
        (std::net::IpAddr::V6(n), std::net::IpAddr::V6(a)) => {
            if len > 128 {
                return None;
            }
            let mask = if len == 0 {
                0
            } else {
                u128::MAX << (128 - len)
            };
            (u128::from(n) & mask == u128::from(a) & mask).then_some(len)
        }
        _ => None,
    }
}
