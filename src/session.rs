//! An interactive configuration session — the VyOS/JunOS-style `configure`
//! context.
//!
//! You edit a **candidate** config with `set`/`delete`, `show` it, then `commit`
//! (validate + activate) and `save` (persist to disk). Because Sentinel's model
//! is declarative, the candidate is just a draft of the [`Appliance`] document;
//! fields can be set one at a time (so the draft holds optionals) and are
//! materialized into a validated [`Appliance`] at commit/save time.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::config::{
    Action, Appliance, Bgp, BgpAggregate, BgpNeighbor, BgpRoa, BgpRtr, DhcpServer, Dns, Filter,
    FilterRule, Firewall, Groups, HealthCheck, IfaceType, Interface, IpsecConnection, Isis,
    MultiWan, Nat, NatDestination, NatSource, Ntp, Ospf, Ospf3, PortSpec, Pppoe, Proto, Protocols,
    Qos, QosDiscipline, Rip, RouterAdvert, Rule, Services, StaticRoute, System, Vpn, Vrrp, WanMode,
    WanUplink, WgPeer, ZoneCfg,
};

/// Default on-disk location of the active appliance config. Writable and
/// persistent (survives reboots); the flake reads it at rebuild time.
pub const DEFAULT_CONFIG: &str = "/var/lib/sentinel/appliance.toml";

/// A partially-specified interface (fields filled in incrementally).
#[derive(Debug, Clone, Default)]
struct IfaceDraft {
    zone: Option<String>,
    address: Option<String>,
    address6: Option<String>,
    pd_from: Option<String>,
    pd_subnet: Option<u8>,
    parent: Option<String>,
    vlan: Option<u16>,
    // WireGuard: a `private-key` makes this a WG tunnel; peers ride on it.
    private_key: Option<String>,
    listen_port: Option<u16>,
    peers: Vec<(String, PeerDraft)>,
    // A built-in DHCP server serving this interface's static subnet.
    dhcp_server: Option<DhcpServerDraft>,
    // An IPv6 Router Advertiser (SLAAC) on this interface.
    router_advert: Option<RouterAdvertDraft>,
    // Virtual L2 device kind (bridge/bond) + bond mode, and (for a member) the
    // bridge/bond it is enslaved to.
    if_type: Option<IfaceType>,
    master: Option<String>,
    bond_mode: Option<String>,
    // Link tunables.
    mtu: Option<u16>,
    mac: Option<String>,
    // Kernel tunnel (type = gre/ipip/gretap): endpoint addresses + GRE key + TTL.
    local: Option<String>,
    remote: Option<String>,
    tunnel_key: Option<u32>,
    ttl: Option<u8>,
    // Egress traffic shaping (cake / fq_codel).
    qos: Option<QosDraft>,
    // PPPoE client (a `type = pppoe` uplink): credentials + tunables.
    pppoe: Option<PppoeDraft>,
}

impl IfaceDraft {
    /// Mutable access to the WireGuard peer keyed by public key `pk`, inserting
    /// it if new (peers are identified by their public key).
    fn peer_mut(&mut self, pk: &str) -> &mut PeerDraft {
        if let Some(i) = self.peers.iter().position(|(k, _)| k == pk) {
            return &mut self.peers[i].1;
        }
        self.peers.push((pk.to_string(), PeerDraft::default()));
        &mut self.peers.last_mut().unwrap().1
    }

    /// Mutable access to the DHCP-server sub-draft, enabling it (inserting a
    /// default) if not yet present. Setting any `dhcp-server` field first turns
    /// the server on, mirroring how the first peer field creates the peer.
    fn dhcp_mut(&mut self) -> &mut DhcpServerDraft {
        self.dhcp_server
            .get_or_insert_with(DhcpServerDraft::default)
    }

    /// Mutable access to the RA sub-draft, enabling it (inserting a default) if
    /// not yet present — the first `router-advert` field turns the advertiser
    /// on, mirroring `dhcp_mut`.
    fn ra_mut(&mut self) -> &mut RouterAdvertDraft {
        self.router_advert
            .get_or_insert_with(RouterAdvertDraft::default)
    }

    /// Mutable access to the PPPoE sub-draft, inserting a default if not yet
    /// present — the first `pppoe` field creates it, mirroring `dhcp_mut`.
    fn pppoe_mut(&mut self) -> &mut PppoeDraft {
        self.pppoe.get_or_insert_with(PppoeDraft::default)
    }

    /// Mutable access to the QoS sub-draft, inserting a default if not yet
    /// present — the first `qos` field creates it, mirroring `pppoe_mut`.
    fn qos_mut(&mut self) -> &mut QosDraft {
        self.qos.get_or_insert_with(QosDraft::default)
    }
}

/// A partially-specified QoS block (fields filled in incrementally). The
/// discipline is required at commit; the rest are per-discipline knobs validated
/// at materialize time by [`crate::config::validate_qos`].
#[derive(Debug, Clone, Default)]
struct QosDraft {
    discipline: Option<QosDiscipline>,
    bandwidth: Option<String>,
    rtt: Option<String>,
    nat: bool,
    ack_filter: bool,
    diffserv: Option<String>,
    target: Option<String>,
    interval: Option<String>,
    limit: Option<u32>,
}

/// A partially-specified PPPoE client (fields filled in incrementally).
#[derive(Debug, Clone, Default)]
struct PppoeDraft {
    username: Option<String>,
    password: Option<String>,
    service_name: Option<String>,
    ac_name: Option<String>,
    mru: Option<u16>,
}

/// A partially-specified DHCP server (fields filled in incrementally).
#[derive(Debug, Clone, Default)]
struct DhcpServerDraft {
    pool_offset: Option<u32>,
    pool_size: Option<u32>,
    dns: Vec<String>,
    lease_time: Option<u32>,
}

/// A partially-specified IPv6 Router Advertiser (fields filled in incrementally).
#[derive(Debug, Clone, Default)]
struct RouterAdvertDraft {
    prefixes: Vec<String>,
    dns: Vec<String>,
    managed: bool,
    other_config: bool,
    router_lifetime: Option<u32>,
}

/// A partially-specified WireGuard peer (keyed by its public key in the draft).
#[derive(Debug, Clone, Default)]
struct PeerDraft {
    allowed_ips: Vec<String>,
    endpoint: Option<String>,
    persistent_keepalive: Option<u16>,
    preshared_key: Option<String>,
}

/// A partially-specified rule.
#[derive(Debug, Clone, Default)]
struct RuleDraft {
    from: Option<String>,
    to: Option<String>,
    action: Option<Action>,
    proto: Option<Proto>,
    port: Option<PortSpec>,
    log: Option<bool>,
    source: Option<String>,
    source_group: Option<String>,
    port_group: Option<String>,
}

/// A partially-specified source-NAT (masquerade) rule.
#[derive(Debug, Clone, Default)]
struct NatSrcDraft {
    zone: Option<String>,
}

/// A partially-specified destination-NAT (port-forward) rule.
#[derive(Debug, Clone, Default)]
struct NatDstDraft {
    zone: Option<String>,
    proto: Option<Proto>,
    port: Option<u16>,
    to: Option<String>,
}

/// A partially-specified per-zone posture override.
#[derive(Debug, Clone, Default)]
struct ZoneDraft {
    stateful: Option<bool>,
    block_icmp: Option<bool>,
    blocklist: Vec<String>,
    default_action: Option<Action>,
    log: Option<bool>,
}

/// The candidate's global firewall posture. `None` fields fall back to the
/// [`Firewall`] defaults at materialize time; the blocklist is just a set of
/// entries.
#[derive(Debug, Clone, Default)]
struct FirewallDraft {
    stateful: Option<bool>,
    block_icmp: Option<bool>,
    blocklist: Vec<String>,
    default_action: Option<Action>,
    log: Option<bool>,
}

/// A partially-specified static route (keyed by its prefix).
#[derive(Debug, Clone, Default)]
struct StaticDraft {
    via: Option<String>,
    dev: Option<String>,
    metric: Option<u32>,
}

/// The candidate's BGP configuration — the full surface Wren's `[bgp]` accepts.
#[derive(Debug, Clone, Default)]
struct BgpDraft {
    local_as: Option<u32>,
    router_id: Option<String>,
    hold_time: Option<u16>,
    network: Vec<String>,
    redistribute: Vec<String>,
    cluster_id: Option<String>,
    confederation_id: Option<u32>,
    confederation_members: Vec<u32>,
    community: Vec<String>,
    large_community: Vec<String>,
    ext_community: Vec<String>,
    multipath: Option<usize>,
    rpki_reject_invalid: bool,
    ebgp_require_policy: bool,
    /// The RTR validating cache (`server`, `refresh`), if set.
    rtr: RtrDraft,
    /// Address aggregates, keyed by prefix.
    aggregate: Vec<(String, bool)>,
    /// Static RPKI ROAs, keyed by prefix.
    roa: Vec<(String, RoaDraft)>,
    /// Peers, keyed by address.
    neighbors: Vec<(String, NeighborDraft)>,
}

/// The RTR validating cache draft (`[protocols.bgp.rtr]`).
#[derive(Debug, Clone, Default)]
struct RtrDraft {
    server: Option<String>,
    refresh: Option<u32>,
}

impl RtrDraft {
    fn is_empty(&self) -> bool {
        self.server.is_none() && self.refresh.is_none()
    }
}

/// One static ROA's non-key fields (keyed by prefix in [`BgpDraft::roa`]).
#[derive(Debug, Clone, Default)]
struct RoaDraft {
    max_length: Option<u8>,
    origin_as: Option<u32>,
}

/// A partially-specified BGP neighbor (keyed by its address). Boolean flags
/// default off; `remote-as` is required to materialize.
#[derive(Debug, Clone, Default)]
struct NeighborDraft {
    remote_as: Option<u32>,
    passive: bool,
    route_reflector_client: bool,
    ttl_security: Option<u8>,
    password: Option<String>,
    ao_key: Option<String>,
    ao_key_id: Option<u8>,
    max_prefix: Option<u32>,
    default_originate: bool,
    add_path: bool,
    extended_nexthop: bool,
    evpn: bool,
    flowspec: bool,
    srpolicy: bool,
    link_state: bool,
    import: Option<String>,
    export: Option<String>,
    role: Option<String>,
    bfd: bool,
    bfd_auth_type: Option<String>,
    bfd_auth_key_id: Option<u8>,
    bfd_auth_key: Option<String>,
}

impl BgpDraft {
    /// True when nothing has been set — lets `[protocols.bgp]` stay absent.
    fn is_empty(&self) -> bool {
        self.local_as.is_none()
            && self.router_id.is_none()
            && self.hold_time.is_none()
            && self.network.is_empty()
            && self.redistribute.is_empty()
            && self.cluster_id.is_none()
            && self.confederation_id.is_none()
            && self.confederation_members.is_empty()
            && self.community.is_empty()
            && self.large_community.is_empty()
            && self.ext_community.is_empty()
            && self.multipath.is_none()
            && !self.rpki_reject_invalid
            && !self.ebgp_require_policy
            && self.rtr.is_empty()
            && self.aggregate.is_empty()
            && self.roa.is_empty()
            && self.neighbors.is_empty()
    }
}

/// A partially-specified route filter (keyed by name in [`Draft::filters`]).
#[derive(Debug, Clone, Default)]
struct FilterDraft {
    default: Option<String>,
    /// Rules keyed by an integer index, kept sorted by that index.
    rules: Vec<(u32, FilterRuleDraft)>,
}

/// One filter rule's fields (keyed by an integer index in [`FilterDraft::rules`]).
#[derive(Debug, Clone, Default)]
struct FilterRuleDraft {
    prefix: Vec<String>,
    protocol: Option<String>,
    metric_le: Option<u32>,
    metric_ge: Option<u32>,
    set_metric: Option<u32>,
    add_metric: Option<i64>,
    set_preference: Option<u32>,
    set_community: Vec<String>,
    add_community: Vec<String>,
    set_large_community: Vec<String>,
    add_large_community: Vec<String>,
    set_ext_community: Vec<String>,
    add_ext_community: Vec<String>,
    action: Option<String>,
}

impl FilterDraft {
    /// Mutable access to the rule at index `idx`, inserting it (kept sorted by
    /// index) if new.
    fn rule_mut(&mut self, idx: u32) -> &mut FilterRuleDraft {
        if let Some(i) = self.rules.iter().position(|(n, _)| *n == idx) {
            return &mut self.rules[i].1;
        }
        self.rules.push((idx, FilterRuleDraft::default()));
        self.rules.sort_by_key(|(n, _)| *n);
        let i = self.rules.iter().position(|(n, _)| *n == idx).unwrap();
        &mut self.rules[i].1
    }
}

/// The candidate's OSPFv2 configuration.
#[derive(Debug, Clone, Default)]
struct OspfDraft {
    interfaces: Vec<String>,
    area: Option<String>,
    cost: Option<u16>,
    network_type: Option<String>,
    redistribute: Vec<String>,
}

impl OspfDraft {
    /// True when nothing has been set — lets `[protocols.ospf]` stay absent.
    fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
            && self.area.is_none()
            && self.cost.is_none()
            && self.network_type.is_none()
            && self.redistribute.is_empty()
    }
}

/// A RIP-family draft (RIPv2 / RIPng / Babel — same knobs).
#[derive(Debug, Clone, Default)]
struct RipDraft {
    interfaces: Vec<String>,
    redistribute: Vec<String>,
    redistribute_metric: Option<u32>,
}

impl RipDraft {
    fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
            && self.redistribute.is_empty()
            && self.redistribute_metric.is_none()
    }
}

/// Build a [`RipDraft`] from a saved RIP-family config section.
fn rip_to_draft(r: &Rip) -> RipDraft {
    RipDraft {
        interfaces: r.interfaces.clone(),
        redistribute: r.redistribute.clone(),
        redistribute_metric: r.redistribute_metric,
    }
}

/// Build a [`BgpDraft`] from a saved `[protocols.bgp]` section.
fn bgp_to_draft(b: &Bgp) -> BgpDraft {
    BgpDraft {
        local_as: Some(b.local_as),
        router_id: b.router_id.clone(),
        hold_time: b.hold_time,
        network: b.network.clone(),
        redistribute: b.redistribute.clone(),
        cluster_id: b.cluster_id.clone(),
        confederation_id: b.confederation_id,
        confederation_members: b.confederation_members.clone(),
        community: b.community.clone(),
        large_community: b.large_community.clone(),
        ext_community: b.ext_community.clone(),
        multipath: b.multipath,
        rpki_reject_invalid: b.rpki_reject_invalid,
        ebgp_require_policy: b.ebgp_require_policy,
        rtr: b.rtr.as_ref().map_or_else(RtrDraft::default, |r| RtrDraft {
            server: Some(r.server.clone()),
            refresh: r.refresh,
        }),
        aggregate: b
            .aggregate
            .iter()
            .map(|a| (a.prefix.clone(), a.summary_only))
            .collect(),
        roa: b
            .roa
            .iter()
            .map(|r| {
                (
                    r.prefix.clone(),
                    RoaDraft {
                        max_length: r.max_length,
                        origin_as: Some(r.origin_as),
                    },
                )
            })
            .collect(),
        neighbors: b
            .neighbors
            .iter()
            .map(|n| (n.address.clone(), neighbor_to_draft(n)))
            .collect(),
    }
}

/// Build a [`NeighborDraft`] from a saved BGP neighbour.
fn neighbor_to_draft(n: &BgpNeighbor) -> NeighborDraft {
    NeighborDraft {
        remote_as: Some(n.remote_as),
        passive: n.passive,
        route_reflector_client: n.route_reflector_client,
        ttl_security: n.ttl_security,
        password: n.password.clone(),
        ao_key: n.ao_key.clone(),
        ao_key_id: n.ao_key_id,
        max_prefix: n.max_prefix,
        default_originate: n.default_originate,
        add_path: n.add_path,
        extended_nexthop: n.extended_nexthop,
        evpn: n.evpn,
        flowspec: n.flowspec,
        srpolicy: n.srpolicy,
        link_state: n.link_state,
        import: n.import.clone(),
        export: n.export.clone(),
        role: n.role.clone(),
        bfd: n.bfd,
        bfd_auth_type: n.bfd_auth_type.clone(),
        bfd_auth_key_id: n.bfd_auth_key_id,
        bfd_auth_key: n.bfd_auth_key.clone(),
    }
}

/// Build a [`FilterDraft`] from a saved `[[protocols.filter]]`. Rules take their
/// 1-based position as their (stable, sorted) index.
fn filter_to_draft(f: &Filter) -> FilterDraft {
    FilterDraft {
        default: f.default.clone(),
        rules: f
            .rules
            .iter()
            .enumerate()
            .map(|(i, r)| {
                (
                    (i + 1) as u32,
                    FilterRuleDraft {
                        prefix: r.prefix.clone(),
                        protocol: r.protocol.clone(),
                        metric_le: r.metric_le,
                        metric_ge: r.metric_ge,
                        set_metric: r.set_metric,
                        add_metric: r.add_metric,
                        set_preference: r.set_preference,
                        set_community: r.set_community.clone().unwrap_or_default(),
                        add_community: r.add_community.clone(),
                        set_large_community: r.set_large_community.clone().unwrap_or_default(),
                        add_large_community: r.add_large_community.clone(),
                        set_ext_community: r.set_ext_community.clone().unwrap_or_default(),
                        add_ext_community: r.add_ext_community.clone(),
                        action: Some(r.action.clone()),
                    },
                )
            })
            .collect(),
    }
}

/// Materialize a [`BgpDraft`] into a validated [`Bgp`]. `local-as` is required.
fn bgp_from_draft(d: &BgpDraft) -> Result<Bgp> {
    Ok(Bgp {
        local_as: d
            .local_as
            .ok_or_else(|| anyhow::anyhow!("protocols bgp: local-as not set"))?,
        router_id: d.router_id.clone(),
        hold_time: d.hold_time,
        network: d.network.clone(),
        redistribute: d.redistribute.clone(),
        cluster_id: d.cluster_id.clone(),
        confederation_id: d.confederation_id,
        confederation_members: d.confederation_members.clone(),
        community: d.community.clone(),
        large_community: d.large_community.clone(),
        ext_community: d.ext_community.clone(),
        multipath: d.multipath,
        aggregate: d
            .aggregate
            .iter()
            .map(|(prefix, summary_only)| BgpAggregate {
                prefix: prefix.clone(),
                summary_only: *summary_only,
            })
            .collect(),
        roa: d
            .roa
            .iter()
            .map(|(prefix, r)| {
                Ok(BgpRoa {
                    prefix: prefix.clone(),
                    max_length: r.max_length,
                    origin_as: r.origin_as.ok_or_else(|| {
                        anyhow::anyhow!("protocols bgp roa {prefix:?}: origin-as not set")
                    })?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
        rtr: d.rtr.server.as_ref().map(|server| BgpRtr {
            server: server.clone(),
            refresh: d.rtr.refresh,
        }),
        rpki_reject_invalid: d.rpki_reject_invalid,
        ebgp_require_policy: d.ebgp_require_policy,
        neighbors: d
            .neighbors
            .iter()
            .map(|(address, n)| neighbor_from_draft(address, n))
            .collect::<Result<Vec<_>>>()?,
    })
}

/// Materialize a [`NeighborDraft`] into a [`BgpNeighbor`]. `remote-as` is
/// required.
fn neighbor_from_draft(address: &str, n: &NeighborDraft) -> Result<BgpNeighbor> {
    Ok(BgpNeighbor {
        address: address.to_string(),
        remote_as: n.remote_as.ok_or_else(|| {
            anyhow::anyhow!("protocols bgp neighbor {address:?}: remote-as not set")
        })?,
        passive: n.passive,
        route_reflector_client: n.route_reflector_client,
        ttl_security: n.ttl_security,
        password: n.password.clone(),
        ao_key: n.ao_key.clone(),
        ao_key_id: n.ao_key_id,
        max_prefix: n.max_prefix,
        default_originate: n.default_originate,
        add_path: n.add_path,
        extended_nexthop: n.extended_nexthop,
        evpn: n.evpn,
        flowspec: n.flowspec,
        srpolicy: n.srpolicy,
        link_state: n.link_state,
        import: n.import.clone(),
        export: n.export.clone(),
        role: n.role.clone(),
        bfd: n.bfd,
        bfd_auth_type: n.bfd_auth_type.clone(),
        bfd_auth_key_id: n.bfd_auth_key_id,
        bfd_auth_key: n.bfd_auth_key.clone(),
    })
}

/// Materialize a [`FilterDraft`] into a [`Filter`]. Every rule needs an `action`.
fn filter_from_draft(name: &str, d: &FilterDraft) -> Result<Filter> {
    let some_if = |v: &[String]| (!v.is_empty()).then(|| v.to_vec());
    Ok(Filter {
        name: name.to_string(),
        default: d.default.clone(),
        rules: d
            .rules
            .iter()
            .map(|(idx, r)| {
                Ok(FilterRule {
                    prefix: r.prefix.clone(),
                    protocol: r.protocol.clone(),
                    metric_le: r.metric_le,
                    metric_ge: r.metric_ge,
                    set_metric: r.set_metric,
                    add_metric: r.add_metric,
                    set_preference: r.set_preference,
                    set_community: some_if(&r.set_community),
                    add_community: r.add_community.clone(),
                    set_large_community: some_if(&r.set_large_community),
                    add_large_community: r.add_large_community.clone(),
                    set_ext_community: some_if(&r.set_ext_community),
                    add_ext_community: r.add_ext_community.clone(),
                    action: r.action.clone().ok_or_else(|| {
                        anyhow::anyhow!("protocols filter {name:?} rule {idx}: action not set")
                    })?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    })
}

/// An IS-IS draft.
#[derive(Debug, Clone, Default)]
struct IsisDraft {
    interfaces: Vec<String>,
    system_id: Option<String>,
    area: Option<String>,
    level: Option<String>,
    network_type: Option<String>,
    redistribute: Vec<String>,
    redistribute_metric: Option<u32>,
}

impl IsisDraft {
    fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
            && self.system_id.is_none()
            && self.area.is_none()
            && self.level.is_none()
            && self.network_type.is_none()
            && self.redistribute.is_empty()
            && self.redistribute_metric.is_none()
    }
}

/// A VRRP virtual-router draft (keyed by a CLI name).
#[derive(Debug, Clone, Default)]
struct VrrpDraft {
    interface: Option<String>,
    vrid: Option<u8>,
    priority: Option<u8>,
    virtual_address: Vec<String>,
}

/// The candidate config — a draft with optional fields, keyed by name so list
/// items (interfaces, rules) are addressable VyOS-"tag-node" style. Insertion
/// order is preserved for stable `show` output.
#[derive(Debug, Clone, Default)]
struct Draft {
    hostname: Option<String>,
    firewall: FirewallDraft,
    /// Named firewall groups (aliases) — address + port sets referenced by rules.
    groups: Groups,
    zones: BTreeMap<String, ZoneDraft>,
    interfaces: Vec<(String, IfaceDraft)>,
    rules: Vec<(String, RuleDraft)>,
    nat_source: Vec<(String, NatSrcDraft)>,
    nat_destination: Vec<(String, NatDstDraft)>,
    router_id: Option<String>,
    statics: Vec<(String, StaticDraft)>,
    ospf: OspfDraft,
    ospf3: OspfDraft,
    rip: RipDraft,
    ripng: RipDraft,
    babel: RipDraft,
    isis: IsisDraft,
    bgp: BgpDraft,
    vrrp: Vec<(String, VrrpDraft)>,
    /// Named route filters (import/export policy), keyed by name.
    filters: Vec<(String, FilterDraft)>,
    dns: DnsDraft,
    ntp: NtpDraft,
    /// Multi-WAN (roadmap C6): failover/load-balance mode + the uplinks, keyed by
    /// interface in configuration order.
    multiwan_mode: Option<WanMode>,
    uplinks: Vec<(String, UplinkDraft)>,
    /// IPsec tunnels (roadmap C2): IKEv2 site-to-site connections, keyed by name
    /// in configuration order.
    ipsec: Vec<(String, IpsecDraft)>,
}

/// A partially-specified DNS forwarder (`[services.dns]`).
#[derive(Debug, Clone, Default)]
struct DnsDraft {
    upstream: Vec<String>,
    serve_on: Vec<String>,
    host_override: BTreeMap<String, String>,
    blocklist: Vec<String>,
    dnssec: Option<String>,
}

/// A partially-specified NTP server (`[services.ntp]`).
#[derive(Debug, Clone, Default)]
struct NtpDraft {
    upstream: Vec<String>,
    serve_on: Vec<String>,
}

/// A partially-specified Multi-WAN uplink (`[[multiwan.uplink]]`), keyed by its
/// interface in the draft. The health-check fields are flattened in here (the
/// CLI addresses them as `… check <field>`) and split back into a
/// [`HealthCheck`] at materialize time.
#[derive(Debug, Clone, Default)]
struct UplinkDraft {
    priority: Option<u32>,
    weight: Option<u32>,
    table: Option<u32>,
    gateway: Option<String>,
    targets: Vec<String>,
    interval: Option<u32>,
    timeout: Option<u32>,
    fail: Option<u32>,
    rise: Option<u32>,
}

/// A partially-specified IPsec connection (`[[vpn.ipsec]]`), keyed by its name in
/// the draft. The required fields (endpoints, subnets, psk) are `Option` here and
/// checked at materialize/validate time so the CLI can build a connection up
/// incrementally.
#[derive(Debug, Clone, Default)]
struct IpsecDraft {
    local: Option<String>,
    remote: Option<String>,
    local_subnet: Option<String>,
    remote_subnet: Option<String>,
    psk: Option<String>,
    ike_version: Option<u8>,
    ike_proposal: Option<String>,
    esp_proposal: Option<String>,
    local_id: Option<String>,
    remote_id: Option<String>,
    start_action: Option<String>,
}

impl Draft {
    /// Mutable access to the static route with `prefix`, inserting it if new.
    fn static_mut(&mut self, prefix: &str) -> &mut StaticDraft {
        if let Some(i) = self.statics.iter().position(|(p, _)| p == prefix) {
            return &mut self.statics[i].1;
        }
        self.statics
            .push((prefix.to_string(), StaticDraft::default()));
        &mut self.statics.last_mut().unwrap().1
    }

    /// Mutable access to the BGP peer `addr`, inserting it if new.
    fn bgp_neighbor_mut(&mut self, addr: &str) -> &mut NeighborDraft {
        if let Some(i) = self.bgp.neighbors.iter().position(|(a, _)| a == addr) {
            return &mut self.bgp.neighbors[i].1;
        }
        self.bgp
            .neighbors
            .push((addr.to_string(), NeighborDraft::default()));
        &mut self.bgp.neighbors.last_mut().unwrap().1
    }

    /// Mutable access to the `summary-only` flag of the BGP aggregate `prefix`,
    /// inserting the aggregate if new.
    fn bgp_aggregate_mut(&mut self, prefix: &str) -> &mut bool {
        if let Some(i) = self.bgp.aggregate.iter().position(|(p, _)| p == prefix) {
            return &mut self.bgp.aggregate[i].1;
        }
        self.bgp.aggregate.push((prefix.to_string(), false));
        &mut self.bgp.aggregate.last_mut().unwrap().1
    }

    /// Mutable access to the static ROA keyed by `prefix`, inserting it if new.
    fn bgp_roa_mut(&mut self, prefix: &str) -> &mut RoaDraft {
        if let Some(i) = self.bgp.roa.iter().position(|(p, _)| p == prefix) {
            return &mut self.bgp.roa[i].1;
        }
        self.bgp.roa.push((prefix.to_string(), RoaDraft::default()));
        &mut self.bgp.roa.last_mut().unwrap().1
    }

    /// Mutable access to the route filter `name`, inserting it if new.
    fn filter_mut(&mut self, name: &str) -> &mut FilterDraft {
        if let Some(i) = self.filters.iter().position(|(n, _)| n == name) {
            return &mut self.filters[i].1;
        }
        self.filters
            .push((name.to_string(), FilterDraft::default()));
        &mut self.filters.last_mut().unwrap().1
    }

    /// The RIP-family draft (`rip` / `ripng` / `babel`) named by `proto`.
    fn rip_family_mut(&mut self, proto: &str) -> &mut RipDraft {
        match proto {
            "rip" => &mut self.rip,
            "ripng" => &mut self.ripng,
            _ => &mut self.babel,
        }
    }

    /// Mutable access to the VRRP instance `name`, inserting it if new.
    fn vrrp_mut(&mut self, name: &str) -> &mut VrrpDraft {
        if let Some(i) = self.vrrp.iter().position(|(n, _)| n == name) {
            return &mut self.vrrp[i].1;
        }
        self.vrrp.push((name.to_string(), VrrpDraft::default()));
        &mut self.vrrp.last_mut().unwrap().1
    }

    /// Mutable access to the Multi-WAN uplink on interface `iface`, inserting it
    /// if new (uplinks are keyed by their interface).
    fn uplink_mut(&mut self, iface: &str) -> &mut UplinkDraft {
        if let Some(i) = self.uplinks.iter().position(|(n, _)| n == iface) {
            return &mut self.uplinks[i].1;
        }
        self.uplinks
            .push((iface.to_string(), UplinkDraft::default()));
        &mut self.uplinks.last_mut().unwrap().1
    }

    /// Mutable access to the IPsec connection `name`, inserting it if new (IPsec
    /// connections are keyed by their name in configuration order).
    fn ipsec_mut(&mut self, name: &str) -> &mut IpsecDraft {
        if let Some(i) = self.ipsec.iter().position(|(n, _)| n == name) {
            return &mut self.ipsec[i].1;
        }
        self.ipsec.push((name.to_string(), IpsecDraft::default()));
        &mut self.ipsec.last_mut().unwrap().1
    }
}

impl Draft {
    fn iface_mut(&mut self, name: &str) -> &mut IfaceDraft {
        if let Some(i) = self.interfaces.iter().position(|(n, _)| n == name) {
            return &mut self.interfaces[i].1;
        }
        self.interfaces
            .push((name.to_string(), IfaceDraft::default()));
        &mut self.interfaces.last_mut().unwrap().1
    }

    fn rule_mut(&mut self, name: &str) -> &mut RuleDraft {
        if let Some(i) = self.rules.iter().position(|(n, _)| n == name) {
            return &mut self.rules[i].1;
        }
        self.rules.push((name.to_string(), RuleDraft::default()));
        &mut self.rules.last_mut().unwrap().1
    }

    fn zone_mut(&mut self, name: &str) -> &mut ZoneDraft {
        self.zones.entry(name.to_string()).or_default()
    }

    fn nat_source_mut(&mut self, name: &str) -> &mut NatSrcDraft {
        if let Some(i) = self.nat_source.iter().position(|(n, _)| n == name) {
            return &mut self.nat_source[i].1;
        }
        self.nat_source
            .push((name.to_string(), NatSrcDraft::default()));
        &mut self.nat_source.last_mut().unwrap().1
    }

    fn nat_destination_mut(&mut self, name: &str) -> &mut NatDstDraft {
        if let Some(i) = self.nat_destination.iter().position(|(n, _)| n == name) {
            return &mut self.nat_destination[i].1;
        }
        self.nat_destination
            .push((name.to_string(), NatDstDraft::default()));
        &mut self.nat_destination.last_mut().unwrap().1
    }

    fn from_appliance(a: &Appliance) -> Self {
        Draft {
            hostname: Some(a.system.hostname.clone()),
            firewall: FirewallDraft {
                stateful: Some(a.firewall.stateful),
                block_icmp: Some(a.firewall.block_icmp),
                blocklist: a.firewall.blocklist.clone(),
                default_action: Some(a.firewall.default_action),
                log: Some(a.firewall.log),
            },
            groups: a.firewall.group.clone(),
            zones: a
                .zones
                .iter()
                .map(|(name, z)| {
                    (
                        name.clone(),
                        ZoneDraft {
                            stateful: z.stateful,
                            block_icmp: z.block_icmp,
                            blocklist: z.blocklist.clone(),
                            default_action: z.default_action,
                            log: z.log,
                        },
                    )
                })
                .collect(),
            interfaces: a
                .interfaces
                .iter()
                .map(|i| {
                    (
                        i.name.clone(),
                        IfaceDraft {
                            zone: i.zone.clone(),
                            address: i.address.clone(),
                            address6: i.address6.clone(),
                            pd_from: i.pd_from.clone(),
                            pd_subnet: i.pd_subnet,
                            parent: i.parent.clone(),
                            vlan: i.vlan,
                            private_key: i.private_key.clone(),
                            listen_port: i.listen_port,
                            peers: i
                                .peers
                                .iter()
                                .map(|p| {
                                    (
                                        p.public_key.clone(),
                                        PeerDraft {
                                            allowed_ips: p.allowed_ips.clone(),
                                            endpoint: p.endpoint.clone(),
                                            persistent_keepalive: p.persistent_keepalive,
                                            preshared_key: p.preshared_key.clone(),
                                        },
                                    )
                                })
                                .collect(),
                            dhcp_server: i.dhcp_server.as_ref().map(|d| DhcpServerDraft {
                                pool_offset: d.pool_offset,
                                pool_size: d.pool_size,
                                dns: d.dns.clone(),
                                lease_time: d.lease_time,
                            }),
                            router_advert: i.router_advert.as_ref().map(|r| RouterAdvertDraft {
                                prefixes: r.prefixes.clone(),
                                dns: r.dns.clone(),
                                managed: r.managed,
                                other_config: r.other_config,
                                router_lifetime: r.router_lifetime,
                            }),
                            if_type: i.if_type,
                            master: i.master.clone(),
                            bond_mode: i.bond_mode.clone(),
                            mtu: i.mtu,
                            mac: i.mac.clone(),
                            local: i.local.clone(),
                            remote: i.remote.clone(),
                            tunnel_key: i.tunnel_key,
                            ttl: i.ttl,
                            qos: i.qos.as_ref().map(|q| QosDraft {
                                discipline: Some(q.discipline),
                                bandwidth: q.bandwidth.clone(),
                                rtt: q.rtt.clone(),
                                nat: q.nat,
                                ack_filter: q.ack_filter,
                                diffserv: q.diffserv.clone(),
                                target: q.target.clone(),
                                interval: q.interval.clone(),
                                limit: q.limit,
                            }),
                            pppoe: i.pppoe.as_ref().map(|p| PppoeDraft {
                                username: Some(p.username.clone()),
                                password: Some(p.password.clone()),
                                service_name: p.service_name.clone(),
                                ac_name: p.ac_name.clone(),
                                mru: p.mru,
                            }),
                        },
                    )
                })
                .collect(),
            rules: a
                .rules
                .iter()
                .map(|r| {
                    (
                        r.name.clone(),
                        RuleDraft {
                            from: Some(r.from.clone()),
                            to: Some(r.to.clone()),
                            action: Some(r.action),
                            proto: r.proto,
                            port: r.port,
                            log: Some(r.log),
                            source: r.source.clone(),
                            source_group: r.source_group.clone(),
                            port_group: r.port_group.clone(),
                        },
                    )
                })
                .collect(),
            nat_source: a
                .nat
                .source
                .iter()
                .map(|s| {
                    (
                        s.name.clone(),
                        NatSrcDraft {
                            zone: Some(s.zone.clone()),
                        },
                    )
                })
                .collect(),
            nat_destination: a
                .nat
                .destination
                .iter()
                .map(|d| {
                    (
                        d.name.clone(),
                        NatDstDraft {
                            zone: Some(d.zone.clone()),
                            proto: Some(d.proto),
                            port: Some(d.port),
                            to: Some(d.to.clone()),
                        },
                    )
                })
                .collect(),
            router_id: a.protocols.router_id.clone(),
            statics: a
                .protocols
                .statics
                .iter()
                .map(|s| {
                    (
                        s.prefix.clone(),
                        StaticDraft {
                            via: s.via.clone(),
                            dev: s.dev.clone(),
                            metric: s.metric,
                        },
                    )
                })
                .collect(),
            ospf: a
                .protocols
                .ospf
                .as_ref()
                .map(|o| OspfDraft {
                    interfaces: o.interfaces.clone(),
                    area: o.area.clone(),
                    cost: o.cost,
                    network_type: o.network_type.clone(),
                    redistribute: o.redistribute.clone(),
                })
                .unwrap_or_default(),
            ospf3: a
                .protocols
                .ospf3
                .as_ref()
                .map(|o| OspfDraft {
                    interfaces: o.interfaces.clone(),
                    area: o.area.clone(),
                    cost: o.cost,
                    network_type: o.network_type.clone(),
                    redistribute: o.redistribute.clone(),
                })
                .unwrap_or_default(),
            rip: a
                .protocols
                .rip
                .as_ref()
                .map(rip_to_draft)
                .unwrap_or_default(),
            ripng: a
                .protocols
                .ripng
                .as_ref()
                .map(rip_to_draft)
                .unwrap_or_default(),
            babel: a
                .protocols
                .babel
                .as_ref()
                .map(rip_to_draft)
                .unwrap_or_default(),
            isis: a
                .protocols
                .isis
                .as_ref()
                .map(|i| IsisDraft {
                    interfaces: i.interfaces.clone(),
                    system_id: i.system_id.clone(),
                    area: i.area.clone(),
                    level: i.level.clone(),
                    network_type: i.network_type.clone(),
                    redistribute: i.redistribute.clone(),
                    redistribute_metric: i.redistribute_metric,
                })
                .unwrap_or_default(),
            vrrp: a
                .protocols
                .vrrp
                .iter()
                .map(|v| {
                    (
                        v.name.clone(),
                        VrrpDraft {
                            interface: Some(v.interface.clone()),
                            vrid: Some(v.vrid),
                            priority: v.priority,
                            virtual_address: v.virtual_address.clone(),
                        },
                    )
                })
                .collect(),
            bgp: a
                .protocols
                .bgp
                .as_ref()
                .map(bgp_to_draft)
                .unwrap_or_default(),
            filters: a
                .protocols
                .filters
                .iter()
                .map(|f| (f.name.clone(), filter_to_draft(f)))
                .collect(),
            dns: DnsDraft {
                upstream: a.services.dns.upstream.clone(),
                serve_on: a.services.dns.serve_on.clone(),
                host_override: a.services.dns.host_override.clone(),
                blocklist: a.services.dns.blocklist.clone(),
                dnssec: a.services.dns.dnssec.clone(),
            },
            ntp: NtpDraft {
                upstream: a.services.ntp.upstream.clone(),
                serve_on: a.services.ntp.serve_on.clone(),
            },
            multiwan_mode: (!a.multiwan.mode.is_default()).then_some(a.multiwan.mode),
            uplinks: a
                .multiwan
                .uplinks
                .iter()
                .map(|u| {
                    (
                        u.interface.clone(),
                        UplinkDraft {
                            priority: u.priority,
                            weight: u.weight,
                            table: u.table,
                            gateway: u.gateway.clone(),
                            targets: u.check.targets.clone(),
                            interval: u.check.interval,
                            timeout: u.check.timeout,
                            fail: u.check.fail,
                            rise: u.check.rise,
                        },
                    )
                })
                .collect(),
            ipsec: a
                .vpn
                .ipsec
                .iter()
                .map(|c| {
                    (
                        c.name.clone(),
                        IpsecDraft {
                            local: Some(c.local.clone()),
                            remote: Some(c.remote.clone()),
                            local_subnet: Some(c.local_subnet.clone()),
                            remote_subnet: Some(c.remote_subnet.clone()),
                            psk: Some(c.psk.clone()),
                            ike_version: c.ike_version,
                            ike_proposal: c.ike_proposal.clone(),
                            esp_proposal: c.esp_proposal.clone(),
                            local_id: c.local_id.clone(),
                            remote_id: c.remote_id.clone(),
                            start_action: c.start_action.clone(),
                        },
                    )
                })
                .collect(),
        }
    }
}

/// A running configuration session.
pub struct Session {
    draft: Draft,
    path: PathBuf,
    /// Unsaved/uncommitted edits since the last load/commit.
    dirty: bool,
}

impl Session {
    /// Open a session, loading `path` as the candidate if it exists.
    pub fn load(path: &Path) -> Result<Self> {
        let draft = if path.exists() {
            Draft::from_appliance(&Appliance::load(path)?)
        } else {
            Draft::default()
        };
        Ok(Self {
            draft,
            path: path.to_path_buf(),
            dirty: false,
        })
    }

    /// Merge in interfaces the system provides that aren't already in the config,
    /// so they appear (unassigned) in `show` — VyOS-style. These are system facts,
    /// not edits, so the session is not marked dirty.
    pub fn merge_discovered(&mut self, names: Vec<String>) {
        for name in names {
            if !self.draft.interfaces.iter().any(|(n, _)| n == &name) {
                self.draft.interfaces.push((name, IfaceDraft::default()));
            }
        }
    }

    /// An empty in-memory session (no backing file) — used by tests.
    #[cfg(test)]
    fn empty() -> Self {
        Self {
            draft: Draft::default(),
            path: PathBuf::from("/dev/null"),
            dirty: false,
        }
    }

    pub fn dirty(&self) -> bool {
        self.dirty
    }

    /// The backing config file (where `save` writes and the running/boot config
    /// lives) — `commit-confirm` reverts to it.
    pub fn config_path(&self) -> &Path {
        &self.path
    }

    /// The interface names currently in the candidate (system-discovered +
    /// operator-added) — completion offers these for `set/delete interface …`.
    pub fn interface_names(&self) -> Vec<String> {
        self.draft
            .interfaces
            .iter()
            .map(|(n, _)| n.clone())
            .collect()
    }

    /// The rule names currently in the candidate — completion offers these for
    /// `set/delete rule …`.
    pub fn rule_names(&self) -> Vec<String> {
        self.draft.rules.iter().map(|(n, _)| n.clone()).collect()
    }

    /// The source-NAT (masquerade) rule names — completion offers these for
    /// `set/delete nat source …`.
    pub fn nat_source_names(&self) -> Vec<String> {
        self.draft
            .nat_source
            .iter()
            .map(|(n, _)| n.clone())
            .collect()
    }

    /// The destination-NAT (port-forward) rule names — completion offers these
    /// for `set/delete nat destination …`.
    pub fn nat_destination_names(&self) -> Vec<String> {
        self.draft
            .nat_destination
            .iter()
            .map(|(n, _)| n.clone())
            .collect()
    }

    /// The declared address-group names — completion offers these for a rule's
    /// `source-group` value and `delete firewall group address-group …`.
    pub fn address_group_names(&self) -> Vec<String> {
        self.draft.groups.address.keys().cloned().collect()
    }

    /// The declared port-group names — completion offers these for a rule's
    /// `port-group` value and `delete firewall group port-group …`.
    pub fn port_group_names(&self) -> Vec<String> {
        self.draft.groups.port.keys().cloned().collect()
    }

    /// The zone names known to the candidate — those referenced by an interface
    /// plus those with an explicit `[zone.*]` override. Completion offers these
    /// for `set interface <n> zone …` and `set rule <n> from/to …`.
    pub fn zone_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .draft
            .interfaces
            .iter()
            .filter_map(|(_, d)| d.zone.clone())
            .chain(self.draft.zones.keys().cloned())
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// `set <path...> <value>` — set one config node.
    pub fn set(&mut self, args: &[&str]) -> Result<()> {
        match args {
            // Host-wide settings.
            ["system", "hostname", v] => self.draft.hostname = Some((*v).to_string()),

            // Interfaces (incl. VLAN subinterfaces).
            ["interface", name, "zone", v] => {
                self.draft.iface_mut(name).zone = Some((*v).to_string())
            }
            ["interface", name, "address", v] => {
                validate_address(v)?;
                self.draft.iface_mut(name).address = Some((*v).to_string());
            }
            ["interface", name, "address6", v] => {
                if *v != "auto" && *v != "dhcp" {
                    crate::config::validate_ipv6_cidr(v)?;
                }
                self.draft.iface_mut(name).address6 = Some((*v).to_string());
            }
            ["interface", name, "pd-from", v] => {
                self.draft.iface_mut(name).pd_from = Some((*v).to_string());
            }
            ["interface", name, "pd-subnet", v] => {
                let id: u8 = v
                    .parse()
                    .with_context(|| format!("invalid pd-subnet {v:?}"))?;
                self.draft.iface_mut(name).pd_subnet = Some(id);
            }
            ["interface", name, "parent", v] => {
                self.draft.iface_mut(name).parent = Some((*v).to_string())
            }
            ["interface", name, "vlan", v] => {
                self.draft.iface_mut(name).vlan = Some(
                    v.parse()
                        .with_context(|| format!("invalid vlan id {v:?}"))?,
                );
            }

            // WireGuard interface + peers.
            ["interface", name, "private-key", "generate"] => {
                let (private, public) = crate::wgkey::generate_keypair()?;
                self.draft.iface_mut(name).private_key = Some(private);
                // The operator needs the public key to hand to the far end.
                println!("generated wireguard key for {name}; public key: {public}");
            }
            ["interface", name, "private-key", v] => {
                validate_wg_key(v)?;
                self.draft.iface_mut(name).private_key = Some((*v).to_string());
            }
            ["interface", name, "listen-port", v] => {
                let port: u16 = v
                    .parse()
                    .with_context(|| format!("invalid listen-port {v:?}"))?;
                if port == 0 {
                    bail!("listen-port 0 is not valid");
                }
                self.draft.iface_mut(name).listen_port = Some(port);
            }
            ["interface", name, "peer", pk, "allowed-ips", v] => {
                validate_wg_key(pk)?;
                let ips: Vec<String> = v.split(',').map(|s| s.trim().to_string()).collect();
                for ip in &ips {
                    validate_block_entry(ip)?;
                }
                self.draft.iface_mut(name).peer_mut(pk).allowed_ips = ips;
            }
            ["interface", name, "peer", pk, "endpoint", v] => {
                validate_wg_key(pk)?;
                validate_endpoint(v)?;
                self.draft.iface_mut(name).peer_mut(pk).endpoint = Some((*v).to_string());
            }
            ["interface", name, "peer", pk, "keepalive", v] => {
                validate_wg_key(pk)?;
                let k: u16 = v
                    .parse()
                    .with_context(|| format!("invalid keepalive {v:?}"))?;
                self.draft.iface_mut(name).peer_mut(pk).persistent_keepalive = Some(k);
            }
            ["interface", name, "peer", pk, "preshared-key", v] => {
                validate_wg_key(pk)?;
                validate_wg_key(v)?;
                self.draft.iface_mut(name).peer_mut(pk).preshared_key = Some((*v).to_string());
            }

            // Built-in DHCP server on an interface (needs a static address).
            // `enable` just switches it on; the sub-fields refine the pool/DNS.
            ["interface", name, "dhcp-server", "enable"] => {
                self.draft.iface_mut(name).dhcp_mut();
            }
            ["interface", name, "dhcp-server", "disable"] => {
                self.draft.iface_mut(name).dhcp_server = None;
            }
            ["interface", name, "dhcp-server", "pool-offset", v] => {
                let off: u32 = v
                    .parse()
                    .with_context(|| format!("invalid pool-offset {v:?}"))?;
                self.draft.iface_mut(name).dhcp_mut().pool_offset = Some(off);
            }
            ["interface", name, "dhcp-server", "pool-size", v] => {
                let size: u32 = v
                    .parse()
                    .with_context(|| format!("invalid pool-size {v:?}"))?;
                self.draft.iface_mut(name).dhcp_mut().pool_size = Some(size);
            }
            ["interface", name, "dhcp-server", "dns", v] => {
                let servers: Vec<String> = v.split(',').map(|s| s.trim().to_string()).collect();
                for s in &servers {
                    validate_ipv4(s)?;
                }
                self.draft.iface_mut(name).dhcp_mut().dns = servers;
            }
            ["interface", name, "dhcp-server", "lease-time", v] => {
                let lease: u32 = v
                    .parse()
                    .with_context(|| format!("invalid lease-time {v:?}"))?;
                self.draft.iface_mut(name).dhcp_mut().lease_time = Some(lease);
            }

            // IPv6 Router Advertisements (SLAAC) on an interface. `enable` just
            // switches it on; `prefix`/`dns` accept comma-separated lists.
            ["interface", name, "router-advert", "enable"] => {
                self.draft.iface_mut(name).ra_mut();
            }
            ["interface", name, "router-advert", "disable"] => {
                self.draft.iface_mut(name).router_advert = None;
            }
            ["interface", name, "router-advert", "prefix", v] => {
                let prefixes: Vec<String> = v.split(',').map(|s| s.trim().to_string()).collect();
                for p in &prefixes {
                    crate::config::validate_ipv6_cidr(p)?;
                }
                self.draft.iface_mut(name).ra_mut().prefixes = prefixes;
            }
            ["interface", name, "router-advert", "dns", v] => {
                let servers: Vec<String> = v.split(',').map(|s| s.trim().to_string()).collect();
                for s in &servers {
                    validate_ipv6(s)?;
                }
                self.draft.iface_mut(name).ra_mut().dns = servers;
            }
            ["interface", name, "router-advert", "managed", v] => {
                self.draft.iface_mut(name).ra_mut().managed = parse_bool(v)?;
            }
            ["interface", name, "router-advert", "other-config", v] => {
                self.draft.iface_mut(name).ra_mut().other_config = parse_bool(v)?;
            }
            ["interface", name, "router-advert", "router-lifetime", v] => {
                let life: u32 = v
                    .parse()
                    .with_context(|| format!("invalid router-lifetime {v:?}"))?;
                self.draft.iface_mut(name).ra_mut().router_lifetime = Some(life);
            }

            // Bridge / bond: `type` makes this a virtual L2 device, `master`
            // enslaves it to one, `bond-mode` sets a bond's aggregation mode.
            ["interface", name, "type", v] => {
                let ty = match *v {
                    "bridge" => IfaceType::Bridge,
                    "bond" => IfaceType::Bond,
                    "pppoe" => IfaceType::Pppoe,
                    "gre" => IfaceType::Gre,
                    "ipip" => IfaceType::Ipip,
                    "gretap" => IfaceType::Gretap,
                    other => {
                        bail!(
                            "interface type {other:?}: expected \"bridge\", \"bond\", \"pppoe\", \"gre\", \"ipip\" or \"gretap\""
                        )
                    }
                };
                self.draft.iface_mut(name).if_type = Some(ty);
            }
            ["interface", name, "master", v] => {
                self.draft.iface_mut(name).master = Some((*v).to_string());
            }
            ["interface", name, "bond-mode", v] => {
                if !crate::config::BOND_MODES.contains(v) {
                    bail!(
                        "bond-mode {v:?}: expected one of {:?}",
                        crate::config::BOND_MODES
                    );
                }
                self.draft.iface_mut(name).bond_mode = Some((*v).to_string());
            }
            ["interface", name, "mtu", v] => {
                let mtu: u16 = v.parse().with_context(|| format!("invalid mtu {v:?}"))?;
                self.draft.iface_mut(name).mtu = Some(mtu);
            }
            ["interface", name, "mac", v] => {
                crate::config::validate_mac(v)?;
                self.draft.iface_mut(name).mac = Some((*v).to_string());
            }

            // Kernel tunnel endpoints/tunables (a `type = gre|ipip|gretap` link,
            // roadmap C3). `local`/`remote` are bare endpoint IPs; `key` is the
            // optional GRE key; `ttl` is the outer TTL. Cross-type consistency
            // (both endpoints, same family, key only on gre/gretap) is checked at
            // commit by `validate`.
            ["interface", name, "local", v] => {
                v.parse::<std::net::IpAddr>()
                    .with_context(|| format!("invalid tunnel local endpoint {v:?}"))?;
                self.draft.iface_mut(name).local = Some((*v).to_string());
            }
            ["interface", name, "remote", v] => {
                v.parse::<std::net::IpAddr>()
                    .with_context(|| format!("invalid tunnel remote endpoint {v:?}"))?;
                self.draft.iface_mut(name).remote = Some((*v).to_string());
            }
            ["interface", name, "key", v] => {
                let key: u32 = v
                    .parse()
                    .with_context(|| format!("invalid tunnel key {v:?} (0–4294967295)"))?;
                self.draft.iface_mut(name).tunnel_key = Some(key);
            }
            ["interface", name, "ttl", v] => {
                let ttl: u8 = v
                    .parse()
                    .with_context(|| format!("invalid tunnel ttl {v:?} (0–255)"))?;
                self.draft.iface_mut(name).ttl = Some(ttl);
            }

            // PPPoE client credentials/tunables (a `type = pppoe` uplink). The
            // password is stored here and rendered to a 0600 secrets file, never
            // into the world-readable peer options.
            ["interface", name, "pppoe", "username", v] => {
                self.draft.iface_mut(name).pppoe_mut().username = Some((*v).to_string());
            }
            ["interface", name, "pppoe", "password", v] => {
                self.draft.iface_mut(name).pppoe_mut().password = Some((*v).to_string());
            }
            ["interface", name, "pppoe", "service-name", v] => {
                self.draft.iface_mut(name).pppoe_mut().service_name = Some((*v).to_string());
            }
            ["interface", name, "pppoe", "ac-name", v] => {
                self.draft.iface_mut(name).pppoe_mut().ac_name = Some((*v).to_string());
            }
            ["interface", name, "pppoe", "mru", v] => {
                let mru: u16 = v.parse().with_context(|| format!("invalid mru {v:?}"))?;
                self.draft.iface_mut(name).pppoe_mut().mru = Some(mru);
            }

            // QoS / traffic shaping (roadmap C8). The first `qos` field creates
            // the block; `discipline` picks cake or fq_codel. Values are format-
            // validated here (tc rate/time) and cross-discipline-checked at commit.
            ["interface", name, "qos", "discipline", v] => {
                let d = match *v {
                    "cake" => QosDiscipline::Cake,
                    "fq_codel" | "fq-codel" => QosDiscipline::FqCodel,
                    other => bail!("qos discipline {other:?}: expected \"cake\" or \"fq_codel\""),
                };
                self.draft.iface_mut(name).qos_mut().discipline = Some(d);
            }
            ["interface", name, "qos", "bandwidth", v] => {
                crate::config::validate_tc_rate(v)?;
                self.draft.iface_mut(name).qos_mut().bandwidth = Some((*v).to_string());
            }
            ["interface", name, "qos", "rtt", v] => {
                if !crate::config::CAKE_RTT_KEYWORDS.contains(v) {
                    crate::config::validate_tc_time(v)?;
                }
                self.draft.iface_mut(name).qos_mut().rtt = Some((*v).to_string());
            }
            ["interface", name, "qos", "nat", v] => {
                self.draft.iface_mut(name).qos_mut().nat = parse_bool(v)?;
            }
            ["interface", name, "qos", "ack-filter", v] => {
                self.draft.iface_mut(name).qos_mut().ack_filter = parse_bool(v)?;
            }
            ["interface", name, "qos", "diffserv", v] => {
                if !crate::config::CAKE_DIFFSERV_MODES.contains(v) {
                    bail!(
                        "qos diffserv {v:?}: expected one of {:?}",
                        crate::config::CAKE_DIFFSERV_MODES
                    );
                }
                self.draft.iface_mut(name).qos_mut().diffserv = Some((*v).to_string());
            }
            ["interface", name, "qos", "target", v] => {
                crate::config::validate_tc_time(v)?;
                self.draft.iface_mut(name).qos_mut().target = Some((*v).to_string());
            }
            ["interface", name, "qos", "interval", v] => {
                crate::config::validate_tc_time(v)?;
                self.draft.iface_mut(name).qos_mut().interval = Some((*v).to_string());
            }
            ["interface", name, "qos", "limit", v] => {
                let limit: u32 = v
                    .parse()
                    .with_context(|| format!("invalid qos limit {v:?}"))?;
                self.draft.iface_mut(name).qos_mut().limit = Some(limit);
            }

            // --- firewall { … } — everything firewall lives under this node ---

            // firewall global: the defaults every zone inherits.
            ["firewall", "global", "stateful", v] => {
                self.draft.firewall.stateful = Some(parse_bool(v)?)
            }
            ["firewall", "global", "block-icmp", v] => {
                self.draft.firewall.block_icmp = Some(parse_bool(v)?)
            }
            ["firewall", "global", "default-action", v] => {
                self.draft.firewall.default_action = Some(parse_action(v)?)
            }
            ["firewall", "global", "log", v] => self.draft.firewall.log = Some(parse_bool(v)?),
            ["firewall", "global", "block", v] => {
                validate_block_entry(v)?;
                push_unique(&mut self.draft.firewall.blocklist, v);
            }

            // firewall zone <name>: per-zone posture overrides.
            ["firewall", "zone", name, "stateful", v] => {
                self.draft.zone_mut(name).stateful = Some(parse_bool(v)?)
            }
            ["firewall", "zone", name, "block-icmp", v] => {
                self.draft.zone_mut(name).block_icmp = Some(parse_bool(v)?)
            }
            ["firewall", "zone", name, "default-action", v] => {
                self.draft.zone_mut(name).default_action = Some(parse_action(v)?)
            }
            ["firewall", "zone", name, "log", v] => {
                self.draft.zone_mut(name).log = Some(parse_bool(v)?)
            }
            ["firewall", "zone", name, "block", v] => {
                validate_block_entry(v)?;
                push_unique(&mut self.draft.zone_mut(name).blocklist, v);
            }

            // firewall rule <name>: zone-to-zone rules.
            ["firewall", "rule", name, "from", v] => {
                self.draft.rule_mut(name).from = Some((*v).to_string())
            }
            ["firewall", "rule", name, "to", v] => {
                self.draft.rule_mut(name).to = Some((*v).to_string())
            }
            ["firewall", "rule", name, "action", v] => {
                self.draft.rule_mut(name).action = Some(parse_action(v)?)
            }
            ["firewall", "rule", name, "proto", v] => {
                self.draft.rule_mut(name).proto = Some(parse_proto(v)?)
            }
            ["firewall", "rule", name, "port", v] => {
                self.draft.rule_mut(name).port = Some(PortSpec::parse(v)?);
            }
            ["firewall", "rule", name, "log", v] => {
                self.draft.rule_mut(name).log = Some(parse_bool(v)?)
            }
            ["firewall", "rule", name, "source", v] => {
                self.draft.rule_mut(name).source = Some((*v).to_string())
            }
            ["firewall", "rule", name, "source-group", v] => {
                self.draft.rule_mut(name).source_group = Some((*v).to_string())
            }
            ["firewall", "rule", name, "port-group", v] => {
                self.draft.rule_mut(name).port_group = Some((*v).to_string())
            }

            // firewall group <kind> <name>: named aliases (address/port sets)
            // referenced by a rule's source-group / port-group. Members are a
            // comma-separated list and replace the group's contents.
            ["firewall", "group", "address-group", name, "address", v] => {
                let members: Vec<String> = v
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect();
                self.draft
                    .groups
                    .address
                    .insert((*name).to_string(), members);
            }
            ["firewall", "group", "port-group", name, "port", v] => {
                let mut specs = Vec::new();
                for tok in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    specs.push(PortSpec::parse(tok)?);
                }
                self.draft.groups.port.insert((*name).to_string(), specs);
            }

            // --- nat { … } — address translation, its own top-level node ---

            // nat source <name>: masquerade (SNAT) a zone's outbound traffic.
            ["nat", "source", name, "zone", v] => {
                self.draft.nat_source_mut(name).zone = Some((*v).to_string())
            }

            // nat destination <name>: inbound DNAT port-forward.
            ["nat", "destination", name, "zone", v] => {
                self.draft.nat_destination_mut(name).zone = Some((*v).to_string())
            }
            ["nat", "destination", name, "proto", v] => {
                self.draft.nat_destination_mut(name).proto = Some(parse_proto(v)?)
            }
            ["nat", "destination", name, "port", v] => {
                self.draft.nat_destination_mut(name).port =
                    Some(v.parse().with_context(|| format!("invalid port {v:?}"))?);
            }
            ["nat", "destination", name, "to", v] => {
                crate::config::parse_host_port(v)?;
                self.draft.nat_destination_mut(name).to = Some((*v).to_string());
            }

            // services dns: the box-wide LAN DNS forwarder (systemd-resolved).
            ["services", "dns", "upstream", v] => {
                let ups: Vec<String> = v.split(',').map(|s| s.trim().to_string()).collect();
                for u in &ups {
                    if validate_ipv4(u).is_err() && validate_ipv6(u).is_err() {
                        bail!("services dns upstream {u:?}: not an IPv4 or IPv6 address");
                    }
                }
                self.draft.dns.upstream = ups;
            }
            ["services", "dns", "serve-on", v] => {
                self.draft.dns.serve_on = v.split(',').map(|s| s.trim().to_string()).collect();
            }
            // A local DNS record: `host-override <name> <ip>` (split-horizon).
            ["services", "dns", "host-override", name, ip] => {
                if validate_ipv4(ip).is_err() && validate_ipv6(ip).is_err() {
                    bail!("services dns host-override {name:?}: {ip:?} is not an IP");
                }
                self.draft
                    .dns
                    .host_override
                    .insert((*name).to_string(), (*ip).to_string());
            }
            // A sinkholed domain: `blocklist <domain>` (append, deduped).
            ["services", "dns", "blocklist", v] => {
                push_unique(&mut self.draft.dns.blocklist, v);
            }
            ["services", "dns", "dnssec", v] => {
                if !matches!(*v, "yes" | "no" | "allow-downgrade") {
                    bail!(
                        "services dns dnssec {v:?}: expected \"yes\", \"no\" or \"allow-downgrade\""
                    );
                }
                self.draft.dns.dnssec = Some((*v).to_string());
            }

            // services ntp: the box-wide LAN NTP server (chrony).
            ["services", "ntp", "upstream", v] => {
                let ups: Vec<String> = v.split(',').map(|s| s.trim().to_string()).collect();
                for u in &ups {
                    crate::config::validate_host(u)?;
                }
                self.draft.ntp.upstream = ups;
            }
            ["services", "ntp", "serve-on", v] => {
                self.draft.ntp.serve_on = v.split(',').map(|s| s.trim().to_string()).collect();
            }

            // protocols: dynamic routing (the Wren control plane).
            ["protocols", "router-id", v] => {
                self.draft.router_id = Some((*v).to_string());
            }
            ["protocols", "static", prefix, "via", v] => {
                self.draft.static_mut(prefix).via = Some((*v).to_string());
            }
            ["protocols", "static", prefix, "dev", v] => {
                self.draft.static_mut(prefix).dev = Some((*v).to_string());
            }
            ["protocols", "static", prefix, "metric", v] => {
                self.draft.static_mut(prefix).metric =
                    Some(v.parse().with_context(|| format!("invalid metric {v:?}"))?);
            }
            ["protocols", "bgp", "local-as", v] => {
                self.draft.bgp.local_as =
                    Some(v.parse().with_context(|| format!("invalid AS {v:?}"))?);
            }
            ["protocols", "bgp", "router-id", v] => {
                self.draft.bgp.router_id = Some((*v).to_string());
            }
            ["protocols", "bgp", "hold-time", v] => {
                self.draft.bgp.hold_time = Some(
                    v.parse()
                        .with_context(|| format!("invalid hold-time {v:?}"))?,
                );
            }
            ["protocols", "bgp", "cluster-id", v] => {
                self.draft.bgp.cluster_id = Some((*v).to_string());
            }
            ["protocols", "bgp", "multipath", v] => {
                self.draft.bgp.multipath = Some(
                    v.parse()
                        .with_context(|| format!("invalid multipath {v:?}"))?,
                );
            }
            ["protocols", "bgp", "network", v] => {
                let net = (*v).to_string();
                if !self.draft.bgp.network.contains(&net) {
                    self.draft.bgp.network.push(net);
                }
            }
            ["protocols", "bgp", "redistribute", v] => {
                let src = (*v).to_string();
                if !self.draft.bgp.redistribute.contains(&src) {
                    self.draft.bgp.redistribute.push(src);
                }
            }
            ["protocols", "bgp", "community", v] => {
                let c = (*v).to_string();
                if !self.draft.bgp.community.contains(&c) {
                    self.draft.bgp.community.push(c);
                }
            }
            ["protocols", "bgp", "large-community", v] => {
                let c = (*v).to_string();
                if !self.draft.bgp.large_community.contains(&c) {
                    self.draft.bgp.large_community.push(c);
                }
            }
            ["protocols", "bgp", "ext-community", v] => {
                let c = (*v).to_string();
                if !self.draft.bgp.ext_community.contains(&c) {
                    self.draft.bgp.ext_community.push(c);
                }
            }
            ["protocols", "bgp", "ebgp-require-policy", v] => {
                self.draft.bgp.ebgp_require_policy = parse_bool(v)?;
            }
            ["protocols", "bgp", "confederation", "id", v] => {
                self.draft.bgp.confederation_id =
                    Some(v.parse().with_context(|| format!("invalid AS {v:?}"))?);
            }
            ["protocols", "bgp", "confederation", "member", v] => {
                let asn = v.parse().with_context(|| format!("invalid AS {v:?}"))?;
                if !self.draft.bgp.confederation_members.contains(&asn) {
                    self.draft.bgp.confederation_members.push(asn);
                }
            }
            ["protocols", "bgp", "rpki", "reject-invalid", v] => {
                self.draft.bgp.rpki_reject_invalid = parse_bool(v)?;
            }
            ["protocols", "bgp", "rpki", "rtr", v] => {
                self.draft.bgp.rtr.server = Some((*v).to_string());
            }
            ["protocols", "bgp", "rpki", "rtr-refresh", v] => {
                self.draft.bgp.rtr.refresh = Some(
                    v.parse()
                        .with_context(|| format!("invalid refresh {v:?}"))?,
                );
            }
            ["protocols", "bgp", "aggregate", prefix] => {
                self.draft.bgp_aggregate_mut(prefix);
            }
            ["protocols", "bgp", "aggregate", prefix, "summary-only", v] => {
                *self.draft.bgp_aggregate_mut(prefix) = parse_bool(v)?;
            }
            ["protocols", "bgp", "roa", prefix, "origin-as", v] => {
                self.draft.bgp_roa_mut(prefix).origin_as =
                    Some(v.parse().with_context(|| format!("invalid AS {v:?}"))?);
            }
            ["protocols", "bgp", "roa", prefix, "max-length", v] => {
                self.draft.bgp_roa_mut(prefix).max_length = Some(
                    v.parse()
                        .with_context(|| format!("invalid max-length {v:?}"))?,
                );
            }
            ["protocols", "bgp", "neighbor", addr, field, v] => {
                self.set_neighbor_field(addr, field, v)?;
            }
            ["protocols", "filter", name, "default", v] => {
                self.draft.filter_mut(name).default = Some((*v).to_string());
            }
            ["protocols", "filter", name, "rule", n, field, v] => {
                let idx = n
                    .parse()
                    .with_context(|| format!("invalid rule index {n:?}"))?;
                self.set_filter_rule_field(name, idx, field, v)?;
            }
            ["protocols", "ospf", "interface", v] => {
                let iface = (*v).to_string();
                if !self.draft.ospf.interfaces.contains(&iface) {
                    self.draft.ospf.interfaces.push(iface);
                }
            }
            ["protocols", "ospf", "area", v] => {
                self.draft.ospf.area = Some((*v).to_string());
            }
            ["protocols", "ospf", "cost", v] => {
                self.draft.ospf.cost =
                    Some(v.parse().with_context(|| format!("invalid cost {v:?}"))?);
            }
            ["protocols", "ospf", "network-type", v] => {
                self.draft.ospf.network_type = Some((*v).to_string());
            }
            ["protocols", "ospf", "redistribute", v] => {
                let src = (*v).to_string();
                if !self.draft.ospf.redistribute.contains(&src) {
                    self.draft.ospf.redistribute.push(src);
                }
            }

            // ospf3 (OSPFv3, IPv6) — same fields as ospf.
            ["protocols", "ospf3", "interface", v] => {
                let i = (*v).to_string();
                if !self.draft.ospf3.interfaces.contains(&i) {
                    self.draft.ospf3.interfaces.push(i);
                }
            }
            ["protocols", "ospf3", "area", v] => self.draft.ospf3.area = Some((*v).to_string()),
            ["protocols", "ospf3", "cost", v] => {
                self.draft.ospf3.cost =
                    Some(v.parse().with_context(|| format!("invalid cost {v:?}"))?);
            }
            ["protocols", "ospf3", "network-type", v] => {
                self.draft.ospf3.network_type = Some((*v).to_string());
            }
            ["protocols", "ospf3", "redistribute", v] => {
                let src = (*v).to_string();
                if !self.draft.ospf3.redistribute.contains(&src) {
                    self.draft.ospf3.redistribute.push(src);
                }
            }

            // rip / ripng / babel — same knobs (RipDraft).
            [
                "protocols",
                proto @ ("rip" | "ripng" | "babel"),
                "interface",
                v,
            ] => {
                let d = self.draft.rip_family_mut(proto);
                let i = (*v).to_string();
                if !d.interfaces.contains(&i) {
                    d.interfaces.push(i);
                }
            }
            [
                "protocols",
                proto @ ("rip" | "ripng" | "babel"),
                "redistribute",
                v,
            ] => {
                let d = self.draft.rip_family_mut(proto);
                let s = (*v).to_string();
                if !d.redistribute.contains(&s) {
                    d.redistribute.push(s);
                }
            }
            [
                "protocols",
                proto @ ("rip" | "ripng" | "babel"),
                "redistribute-metric",
                v,
            ] => {
                self.draft.rip_family_mut(proto).redistribute_metric =
                    Some(v.parse().with_context(|| format!("invalid metric {v:?}"))?);
            }

            // isis (IS-IS).
            ["protocols", "isis", "interface", v] => {
                let i = (*v).to_string();
                if !self.draft.isis.interfaces.contains(&i) {
                    self.draft.isis.interfaces.push(i);
                }
            }
            ["protocols", "isis", "system-id", v] => {
                self.draft.isis.system_id = Some((*v).to_string());
            }
            ["protocols", "isis", "area", v] => self.draft.isis.area = Some((*v).to_string()),
            ["protocols", "isis", "level", v] => self.draft.isis.level = Some((*v).to_string()),
            ["protocols", "isis", "network-type", v] => {
                self.draft.isis.network_type = Some((*v).to_string());
            }
            ["protocols", "isis", "redistribute", v] => {
                let s = (*v).to_string();
                if !self.draft.isis.redistribute.contains(&s) {
                    self.draft.isis.redistribute.push(s);
                }
            }
            ["protocols", "isis", "redistribute-metric", v] => {
                self.draft.isis.redistribute_metric =
                    Some(v.parse().with_context(|| format!("invalid metric {v:?}"))?);
            }

            // vrrp (a named virtual router).
            ["protocols", "vrrp", name, "interface", v] => {
                self.draft.vrrp_mut(name).interface = Some((*v).to_string());
            }
            ["protocols", "vrrp", name, "vrid", v] => {
                self.draft.vrrp_mut(name).vrid =
                    Some(v.parse().with_context(|| format!("invalid vrid {v:?}"))?);
            }
            ["protocols", "vrrp", name, "priority", v] => {
                self.draft.vrrp_mut(name).priority = Some(
                    v.parse()
                        .with_context(|| format!("invalid priority {v:?}"))?,
                );
            }
            ["protocols", "vrrp", name, "virtual-address", v] => {
                let d = self.draft.vrrp_mut(name);
                let a = (*v).to_string();
                if !d.virtual_address.contains(&a) {
                    d.virtual_address.push(a);
                }
            }

            // multiwan (roadmap C6): failover/load-balance mode + per-uplink
            // policy-routing and health checks. Uplinks are keyed by interface.
            ["multiwan", "mode", v] => {
                self.draft.multiwan_mode = Some(parse_wan_mode(v)?);
            }
            ["multiwan", "uplink", iface, "priority", v] => {
                self.draft.uplink_mut(iface).priority = Some(
                    v.parse()
                        .with_context(|| format!("invalid priority {v:?}"))?,
                );
            }
            ["multiwan", "uplink", iface, "weight", v] => {
                self.draft.uplink_mut(iface).weight =
                    Some(v.parse().with_context(|| format!("invalid weight {v:?}"))?);
            }
            ["multiwan", "uplink", iface, "table", v] => {
                self.draft.uplink_mut(iface).table =
                    Some(v.parse().with_context(|| format!("invalid table {v:?}"))?);
            }
            ["multiwan", "uplink", iface, "gateway", v] => {
                if *v != "dhcp" {
                    validate_ipv4(v)?;
                }
                self.draft.uplink_mut(iface).gateway = Some((*v).to_string());
            }
            ["multiwan", "uplink", iface, "check", "target", v] => {
                validate_ipv4(v)?;
                let d = self.draft.uplink_mut(iface);
                let t = (*v).to_string();
                if !d.targets.contains(&t) {
                    d.targets.push(t);
                }
            }
            ["multiwan", "uplink", iface, "check", "interval", v] => {
                self.draft.uplink_mut(iface).interval = Some(
                    v.parse()
                        .with_context(|| format!("invalid interval {v:?}"))?,
                );
            }
            ["multiwan", "uplink", iface, "check", "timeout", v] => {
                self.draft.uplink_mut(iface).timeout = Some(
                    v.parse()
                        .with_context(|| format!("invalid timeout {v:?}"))?,
                );
            }
            ["multiwan", "uplink", iface, "check", "fail", v] => {
                self.draft.uplink_mut(iface).fail = Some(
                    v.parse()
                        .with_context(|| format!("invalid fail count {v:?}"))?,
                );
            }
            ["multiwan", "uplink", iface, "check", "rise", v] => {
                self.draft.uplink_mut(iface).rise = Some(
                    v.parse()
                        .with_context(|| format!("invalid rise count {v:?}"))?,
                );
            }

            // vpn ipsec (roadmap C2): IKEv2 site-to-site tunnels, keyed by name.
            ["vpn", "ipsec", name, "local", v] => {
                validate_ipv4(v)?;
                self.draft.ipsec_mut(name).local = Some((*v).to_string());
            }
            ["vpn", "ipsec", name, "remote", v] => {
                validate_ipv4(v)?;
                self.draft.ipsec_mut(name).remote = Some((*v).to_string());
            }
            ["vpn", "ipsec", name, "local-subnet", v] => {
                crate::config::validate_cidr_or_ip(v)?;
                self.draft.ipsec_mut(name).local_subnet = Some((*v).to_string());
            }
            ["vpn", "ipsec", name, "remote-subnet", v] => {
                crate::config::validate_cidr_or_ip(v)?;
                self.draft.ipsec_mut(name).remote_subnet = Some((*v).to_string());
            }
            ["vpn", "ipsec", name, "psk", v] => {
                self.draft.ipsec_mut(name).psk = Some((*v).to_string());
            }
            ["vpn", "ipsec", name, "ike-version", v] => {
                let n: u8 = v
                    .parse()
                    .with_context(|| format!("invalid ike-version {v:?}"))?;
                if n != 1 && n != 2 {
                    bail!("ike-version {n} must be 1 or 2");
                }
                self.draft.ipsec_mut(name).ike_version = Some(n);
            }
            ["vpn", "ipsec", name, "ike-proposal", v] => {
                crate::config::validate_ipsec_proposal(v)?;
                self.draft.ipsec_mut(name).ike_proposal = Some((*v).to_string());
            }
            ["vpn", "ipsec", name, "esp-proposal", v] => {
                crate::config::validate_ipsec_proposal(v)?;
                self.draft.ipsec_mut(name).esp_proposal = Some((*v).to_string());
            }
            ["vpn", "ipsec", name, "local-id", v] => {
                crate::config::validate_ipsec_id(v)?;
                self.draft.ipsec_mut(name).local_id = Some((*v).to_string());
            }
            ["vpn", "ipsec", name, "remote-id", v] => {
                crate::config::validate_ipsec_id(v)?;
                self.draft.ipsec_mut(name).remote_id = Some((*v).to_string());
            }
            ["vpn", "ipsec", name, "start-action", v] => {
                if !matches!(*v, "start" | "trap" | "none") {
                    bail!("invalid start-action {v:?} (expected start|trap|none)");
                }
                self.draft.ipsec_mut(name).start_action = Some((*v).to_string());
            }

            _ => bail!(
                "unknown set path. The config tree (Tab/`?` explores each level):\n  \
                 set system hostname <name>\n  \
                 set interface <name> zone <zone>\n  \
                 set interface <name> address <dhcp|CIDR>\n  \
                 set interface <name> <parent <iface> | vlan <id>>\n  \
                 set interface <name> type <gre|ipip|gretap> local <ip> remote <ip> [key <n>] [ttl <n>]\n  \
                 set firewall global <stateful|block-icmp|log> <true|false>\n  \
                 set firewall global default-action <accept|drop|reject>\n  \
                 set firewall global block <IP|CIDR>\n  \
                 set firewall zone <name> <stateful|block-icmp|log> <true|false>\n  \
                 set firewall zone <name> default-action <accept|drop|reject>\n  \
                 set firewall zone <name> block <IP|CIDR>\n  \
                 set firewall rule <name> <from|to> <zone>\n  \
                 set firewall rule <name> action <accept|drop|reject>\n  \
                 set firewall rule <name> <proto tcp|udp | port <n|lo-hi> | log <true|false> | source <cidr>>\n  \
                 set nat source <name> zone <zone>\n  \
                 set nat destination <name> <zone <z> | proto <p> | port <n> | to <ip[:port]>>\n  \
                 set protocols router-id <ip>\n  \
                 set protocols static <prefix> <via <ip> | dev <if> | metric <n>>\n  \
                 set protocols bgp <local-as <n> | router-id <ip> | hold-time <n> | network <prefix> | redistribute <src> | community <c> | multipath <n>>\n  \
                 set protocols bgp <confederation id <n> | confederation member <n> | rpki reject-invalid <bool> | rpki rtr <host:port> | ebgp-require-policy <bool>>\n  \
                 set protocols bgp aggregate <prefix> summary-only <bool>\n  \
                 set protocols bgp neighbor <ip> <remote-as <n> | passive <bool> | route-reflector-client <bool> | password <k> | ttl-security <n> | max-prefix <n> | role <r> | import <f> | export <f> | bfd <bool> | ...>\n  \
                 set protocols filter <name> default <accept|reject>\n  \
                 set protocols filter <name> rule <n> <prefix <p> | protocol <p> | metric-le <n> | set-metric <n> | set-community <c> | action <accept|reject> | ...>\n  \
                 set protocols ospf <interface <if> | area <id> | cost <n> | network-type <broadcast|point-to-point> | redistribute <src>>\n  \
                 set protocols ospf3 <interface <if> | area <id> | cost <n> | network-type <..> | redistribute <src>>\n  \
                 set protocols <rip|ripng|babel> <interface <if> | redistribute <src> | redistribute-metric <n>>\n  \
                 set protocols isis <interface <if> | system-id <id> | area <id> | level <1|2|1-2> | network-type <..> | redistribute <src>>\n  \
                 set protocols vrrp <name> <interface <if> | vrid <n> | priority <n> | virtual-address <ip>>\n  \
                 set multiwan mode <failover|load-balance>\n  \
                 set multiwan uplink <if> <priority <n> | weight <n> | table <n> | gateway <ip|dhcp>>\n  \
                 set multiwan uplink <if> check <target <ip> | interval <n> | timeout <n> | fail <n> | rise <n>>\n  \
                 set vpn ipsec <name> <local <ip> | remote <ip> | local-subnet <cidr> | remote-subnet <cidr> | psk <key>>\n  \
                 set vpn ipsec <name> <ike-version <1|2> | ike-proposal <p> | esp-proposal <p> | local-id <id> | remote-id <id> | start-action <start|trap|none>>"
            ),
        }
        self.dirty = true;
        Ok(())
    }

    /// `delete <path...>` — remove a node or clear a field.
    /// Clear one field of an OSPF/OSPFv3 draft (both share [`OspfDraft`]).
    fn del_ospf_field(o: &mut OspfDraft, field: &str) -> Result<()> {
        match field {
            "interface" => o.interfaces.clear(),
            "area" => o.area = None,
            "cost" => o.cost = None,
            "network-type" => o.network_type = None,
            "redistribute" => o.redistribute.clear(),
            other => bail!("ospf has no field {other:?}"),
        }
        Ok(())
    }

    /// Clear one field of a BGP neighbour draft (boolean flags revert to off).
    fn del_neighbor_field(n: &mut NeighborDraft, field: &str) -> Result<()> {
        match field {
            "remote-as" => n.remote_as = None,
            "passive" => n.passive = false,
            "route-reflector-client" => n.route_reflector_client = false,
            "ttl-security" => n.ttl_security = None,
            "password" => n.password = None,
            "ao-key" => n.ao_key = None,
            "ao-key-id" => n.ao_key_id = None,
            "max-prefix" => n.max_prefix = None,
            "default-originate" => n.default_originate = false,
            "add-path" => n.add_path = false,
            "extended-nexthop" => n.extended_nexthop = false,
            "evpn" => n.evpn = false,
            "flowspec" => n.flowspec = false,
            "srpolicy" => n.srpolicy = false,
            "link-state" => n.link_state = false,
            "import" => n.import = None,
            "export" => n.export = None,
            "role" => n.role = None,
            "bfd" => n.bfd = false,
            "bfd-auth-type" => n.bfd_auth_type = None,
            "bfd-auth-key-id" => n.bfd_auth_key_id = None,
            "bfd-auth-key" => n.bfd_auth_key = None,
            other => bail!("bgp neighbor has no field {other:?}"),
        }
        Ok(())
    }

    /// Clear one field of a filter rule draft.
    fn del_filter_rule_field(r: &mut FilterRuleDraft, field: &str) -> Result<()> {
        match field {
            "prefix" => r.prefix.clear(),
            "protocol" => r.protocol = None,
            "metric-le" => r.metric_le = None,
            "metric-ge" => r.metric_ge = None,
            "set-metric" => r.set_metric = None,
            "add-metric" => r.add_metric = None,
            "set-preference" => r.set_preference = None,
            "set-community" => r.set_community.clear(),
            "add-community" => r.add_community.clear(),
            "set-large-community" => r.set_large_community.clear(),
            "add-large-community" => r.add_large_community.clear(),
            "set-ext-community" => r.set_ext_community.clear(),
            "add-ext-community" => r.add_ext_community.clear(),
            "action" => r.action = None,
            other => bail!("filter rule has no field {other:?}"),
        }
        Ok(())
    }

    /// Set one field of the BGP neighbour `addr` (inserting the neighbour if new).
    fn set_neighbor_field(&mut self, addr: &str, field: &str, v: &str) -> Result<()> {
        let n = self.draft.bgp_neighbor_mut(addr);
        match field {
            "remote-as" => {
                n.remote_as = Some(v.parse().with_context(|| format!("invalid AS {v:?}"))?)
            }
            "passive" => n.passive = parse_bool(v)?,
            "route-reflector-client" => n.route_reflector_client = parse_bool(v)?,
            "ttl-security" => {
                n.ttl_security = Some(
                    v.parse()
                        .with_context(|| format!("invalid ttl-security {v:?}"))?,
                )
            }
            "password" => n.password = Some(v.to_string()),
            "ao-key" => n.ao_key = Some(v.to_string()),
            "ao-key-id" => {
                n.ao_key_id = Some(
                    v.parse()
                        .with_context(|| format!("invalid ao-key-id {v:?}"))?,
                )
            }
            "max-prefix" => {
                n.max_prefix = Some(
                    v.parse()
                        .with_context(|| format!("invalid max-prefix {v:?}"))?,
                )
            }
            "default-originate" => n.default_originate = parse_bool(v)?,
            "add-path" => n.add_path = parse_bool(v)?,
            "extended-nexthop" => n.extended_nexthop = parse_bool(v)?,
            "evpn" => n.evpn = parse_bool(v)?,
            "flowspec" => n.flowspec = parse_bool(v)?,
            "srpolicy" => n.srpolicy = parse_bool(v)?,
            "link-state" => n.link_state = parse_bool(v)?,
            "import" => n.import = Some(v.to_string()),
            "export" => n.export = Some(v.to_string()),
            "role" => n.role = Some(v.to_string()),
            "bfd" => n.bfd = parse_bool(v)?,
            "bfd-auth-type" => n.bfd_auth_type = Some(v.to_string()),
            "bfd-auth-key-id" => {
                n.bfd_auth_key_id =
                    Some(v.parse().with_context(|| format!("invalid key-id {v:?}"))?)
            }
            "bfd-auth-key" => n.bfd_auth_key = Some(v.to_string()),
            other => bail!("bgp neighbor has no field {other:?}"),
        }
        Ok(())
    }

    /// Set one field of the rule `idx` of filter `name` (inserting either if new).
    fn set_filter_rule_field(&mut self, name: &str, idx: u32, field: &str, v: &str) -> Result<()> {
        let r = self.draft.filter_mut(name).rule_mut(idx);
        let push = |set: &mut Vec<String>| {
            if !set.iter().any(|x| x == v) {
                set.push(v.to_string());
            }
        };
        match field {
            "prefix" => push(&mut r.prefix),
            "protocol" => r.protocol = Some(v.to_string()),
            "metric-le" => {
                r.metric_le = Some(v.parse().with_context(|| format!("invalid metric {v:?}"))?)
            }
            "metric-ge" => {
                r.metric_ge = Some(v.parse().with_context(|| format!("invalid metric {v:?}"))?)
            }
            "set-metric" => {
                r.set_metric = Some(v.parse().with_context(|| format!("invalid metric {v:?}"))?)
            }
            "add-metric" => {
                r.add_metric = Some(v.parse().with_context(|| format!("invalid metric {v:?}"))?)
            }
            "set-preference" => {
                r.set_preference = Some(
                    v.parse()
                        .with_context(|| format!("invalid preference {v:?}"))?,
                )
            }
            "set-community" => push(&mut r.set_community),
            "add-community" => push(&mut r.add_community),
            "set-large-community" => push(&mut r.set_large_community),
            "add-large-community" => push(&mut r.add_large_community),
            "set-ext-community" => push(&mut r.set_ext_community),
            "add-ext-community" => push(&mut r.add_ext_community),
            "action" => r.action = Some(v.to_string()),
            other => bail!("filter rule has no field {other:?}"),
        }
        Ok(())
    }

    pub fn delete(&mut self, args: &[&str]) -> Result<()> {
        match args {
            ["system", "hostname"] => self.draft.hostname = None,

            ["interface", name] => {
                let before = self.draft.interfaces.len();
                self.draft.interfaces.retain(|(n, _)| n != name);
                if self.draft.interfaces.len() == before {
                    bail!("no interface {name:?}");
                }
            }
            ["interface", name, "address"] => self.iface(name)?.address = None,
            ["interface", name, "address6"] => self.iface(name)?.address6 = None,
            ["interface", name, "pd-from"] => self.iface(name)?.pd_from = None,
            ["interface", name, "pd-subnet"] => self.iface(name)?.pd_subnet = None,
            ["interface", name, "zone"] => self.iface(name)?.zone = None,
            ["interface", name, "parent"] => self.iface(name)?.parent = None,
            ["interface", name, "vlan"] => self.iface(name)?.vlan = None,
            ["interface", name, "private-key"] => self.iface(name)?.private_key = None,
            ["interface", name, "listen-port"] => self.iface(name)?.listen_port = None,
            ["interface", name, "type"] => self.iface(name)?.if_type = None,
            ["interface", name, "master"] => self.iface(name)?.master = None,
            ["interface", name, "bond-mode"] => self.iface(name)?.bond_mode = None,
            ["interface", name, "mtu"] => self.iface(name)?.mtu = None,
            ["interface", name, "mac"] => self.iface(name)?.mac = None,
            ["interface", name, "local"] => self.iface(name)?.local = None,
            ["interface", name, "remote"] => self.iface(name)?.remote = None,
            ["interface", name, "key"] => self.iface(name)?.tunnel_key = None,
            ["interface", name, "ttl"] => self.iface(name)?.ttl = None,
            ["interface", name, "qos"] => self.iface(name)?.qos = None,
            ["interface", name, "qos", field] => {
                let i = self.iface(name)?;
                let Some(q) = i.qos.as_mut() else {
                    bail!("interface {name:?} has no qos config");
                };
                match *field {
                    "bandwidth" => q.bandwidth = None,
                    "rtt" => q.rtt = None,
                    "nat" => q.nat = false,
                    "ack-filter" => q.ack_filter = false,
                    "diffserv" => q.diffserv = None,
                    "target" => q.target = None,
                    "interval" => q.interval = None,
                    "limit" => q.limit = None,
                    "discipline" => bail!(
                        "qos discipline is required; `delete interface {name} qos` removes the whole block"
                    ),
                    other => bail!("qos has no field {other:?}"),
                }
            }
            ["interface", name, "pppoe"] => self.iface(name)?.pppoe = None,
            ["interface", name, "pppoe", field] => {
                let i = self.iface(name)?;
                let Some(p) = i.pppoe.as_mut() else {
                    bail!("interface {name:?} has no pppoe config");
                };
                match *field {
                    "service-name" => p.service_name = None,
                    "ac-name" => p.ac_name = None,
                    "mru" => p.mru = None,
                    "username" | "password" => bail!(
                        "pppoe {field} is required; `delete interface {name} pppoe` removes the whole client"
                    ),
                    other => bail!("pppoe has no field {other:?}"),
                }
            }
            ["interface", name, "peer", pk] => {
                let i = self.iface(name)?;
                let before = i.peers.len();
                i.peers.retain(|(k, _)| k != pk);
                if i.peers.len() == before {
                    bail!("interface {name:?} has no peer {pk:?}");
                }
            }
            ["interface", name, "peer", pk, field] => {
                let i = self.iface(name)?;
                let Some(idx) = i.peers.iter().position(|(k, _)| k == pk) else {
                    bail!("interface {name:?} has no peer {pk:?}");
                };
                let p = &mut i.peers[idx].1;
                match *field {
                    "allowed-ips" => p.allowed_ips.clear(),
                    "endpoint" => p.endpoint = None,
                    "keepalive" => p.persistent_keepalive = None,
                    "preshared-key" => p.preshared_key = None,
                    other => bail!("peer has no field {other:?}"),
                }
            }
            ["interface", name, "dhcp-server"] => self.iface(name)?.dhcp_server = None,
            ["interface", name, "dhcp-server", field] => {
                let i = self.iface(name)?;
                let Some(d) = i.dhcp_server.as_mut() else {
                    bail!("interface {name:?} has no dhcp-server");
                };
                match *field {
                    "pool-offset" => d.pool_offset = None,
                    "pool-size" => d.pool_size = None,
                    "dns" => d.dns.clear(),
                    "lease-time" => d.lease_time = None,
                    other => bail!("dhcp-server has no field {other:?}"),
                }
            }
            ["interface", name, "router-advert"] => self.iface(name)?.router_advert = None,
            ["interface", name, "router-advert", field] => {
                let i = self.iface(name)?;
                let Some(r) = i.router_advert.as_mut() else {
                    bail!("interface {name:?} has no router-advert");
                };
                match *field {
                    "prefix" => r.prefixes.clear(),
                    "dns" => r.dns.clear(),
                    "managed" => r.managed = false,
                    "other-config" => r.other_config = false,
                    "router-lifetime" => r.router_lifetime = None,
                    other => bail!("router-advert has no field {other:?}"),
                }
            }

            // firewall global …
            ["firewall", "global", "block", v] => {
                let before = self.draft.firewall.blocklist.len();
                self.draft.firewall.blocklist.retain(|e| e != v);
                if self.draft.firewall.blocklist.len() == before {
                    bail!("{v:?} is not in the global blocklist");
                }
            }
            ["firewall", "global", field] => match *field {
                "stateful" => self.draft.firewall.stateful = None,
                "block-icmp" => self.draft.firewall.block_icmp = None,
                "default-action" => self.draft.firewall.default_action = None,
                "log" => self.draft.firewall.log = None,
                other => bail!("firewall global has no field {other:?}"),
            },

            // firewall zone <name> …
            ["firewall", "zone", name] => {
                if self.draft.zones.remove(*name).is_none() {
                    bail!("no zone overrides for {name:?}");
                }
            }
            ["firewall", "zone", name, "block", v] => {
                let z = self
                    .draft
                    .zones
                    .get_mut(*name)
                    .ok_or_else(|| anyhow::anyhow!("no zone {name:?}"))?;
                let before = z.blocklist.len();
                z.blocklist.retain(|e| e != v);
                if z.blocklist.len() == before {
                    bail!("{v:?} is not in zone {name:?} blocklist");
                }
            }
            ["firewall", "zone", name, field] => {
                let z = self
                    .draft
                    .zones
                    .get_mut(*name)
                    .ok_or_else(|| anyhow::anyhow!("no zone {name:?}"))?;
                match *field {
                    "stateful" => z.stateful = None,
                    "block-icmp" => z.block_icmp = None,
                    "default-action" => z.default_action = None,
                    "log" => z.log = None,
                    other => bail!("zone has no field {other:?}"),
                }
            }

            // firewall rule <name> …
            ["firewall", "rule", name] => {
                let before = self.draft.rules.len();
                self.draft.rules.retain(|(n, _)| n != name);
                if self.draft.rules.len() == before {
                    bail!("no rule {name:?}");
                }
            }
            ["firewall", "rule", name, field] => {
                let r = self.rule(name)?;
                match *field {
                    "from" => r.from = None,
                    "to" => r.to = None,
                    "action" => r.action = None,
                    "proto" => r.proto = None,
                    "port" => r.port = None,
                    "log" => r.log = None,
                    "source" => r.source = None,
                    "source-group" => r.source_group = None,
                    "port-group" => r.port_group = None,
                    other => bail!("rule has no field {other:?}"),
                }
            }

            // firewall group <kind> <name>: remove a whole named alias.
            ["firewall", "group", "address-group", name] => {
                if self.draft.groups.address.remove(*name).is_none() {
                    bail!("no address-group {name:?}");
                }
            }
            ["firewall", "group", "port-group", name] => {
                if self.draft.groups.port.remove(*name).is_none() {
                    bail!("no port-group {name:?}");
                }
            }

            // nat source <name>
            ["nat", "source", name] => {
                let before = self.draft.nat_source.len();
                self.draft.nat_source.retain(|(n, _)| n != name);
                if self.draft.nat_source.len() == before {
                    bail!("no nat source {name:?}");
                }
            }
            ["nat", "source", name, "zone"] => {
                self.nat_source(name)?.zone = None;
            }

            // nat destination <name>
            ["nat", "destination", name] => {
                let before = self.draft.nat_destination.len();
                self.draft.nat_destination.retain(|(n, _)| n != name);
                if self.draft.nat_destination.len() == before {
                    bail!("no nat destination {name:?}");
                }
            }
            ["nat", "destination", name, field] => {
                let d = self.nat_destination(name)?;
                match *field {
                    "zone" => d.zone = None,
                    "proto" => d.proto = None,
                    "port" => d.port = None,
                    "to" => d.to = None,
                    other => bail!("nat destination has no field {other:?}"),
                }
            }

            // services: box-wide offered services. Bare `delete services` clears
            // them all; `delete services dns`/`ntp` turns off just that one.
            ["services"] => {
                self.draft.dns = DnsDraft::default();
                self.draft.ntp = NtpDraft::default();
            }
            ["services", "dns"] => self.draft.dns = DnsDraft::default(),
            // Remove one host-override by name, or one blocklist entry by value.
            ["services", "dns", "host-override", name] => {
                if self.draft.dns.host_override.remove(*name).is_none() {
                    bail!("no host-override {name:?}");
                }
            }
            ["services", "dns", "blocklist", v] => {
                let before = self.draft.dns.blocklist.len();
                self.draft.dns.blocklist.retain(|e| e != v);
                if self.draft.dns.blocklist.len() == before {
                    bail!("{v:?} is not in the dns blocklist");
                }
            }
            ["services", "dns", field] => {
                let d = &mut self.draft.dns;
                match *field {
                    "upstream" => d.upstream.clear(),
                    "serve-on" => d.serve_on.clear(),
                    "host-override" => d.host_override.clear(),
                    "blocklist" => d.blocklist.clear(),
                    "dnssec" => d.dnssec = None,
                    other => bail!("services dns has no field {other:?}"),
                }
            }
            ["services", "ntp"] => self.draft.ntp = NtpDraft::default(),
            ["services", "ntp", field] => {
                let n = &mut self.draft.ntp;
                match *field {
                    "upstream" => n.upstream.clear(),
                    "serve-on" => n.serve_on.clear(),
                    other => bail!("services ntp has no field {other:?}"),
                }
            }

            // protocols: dynamic routing (Wren).
            // Bare `delete protocols` clears the ENTIRE routing subtree, not just
            // the router-id — otherwise a configured ospf/bgp/… silently survives.
            ["protocols"] => {
                self.draft.router_id = None;
                self.draft.statics.clear();
                self.draft.ospf = OspfDraft::default();
                self.draft.ospf3 = OspfDraft::default();
                self.draft.rip = RipDraft::default();
                self.draft.ripng = RipDraft::default();
                self.draft.babel = RipDraft::default();
                self.draft.isis = IsisDraft::default();
                self.draft.bgp = BgpDraft::default();
                self.draft.vrrp.clear();
                self.draft.filters.clear();
            }
            ["protocols", "router-id"] => self.draft.router_id = None,
            ["protocols", "static", prefix] => {
                let before = self.draft.statics.len();
                self.draft.statics.retain(|(p, _)| p != prefix);
                if self.draft.statics.len() == before {
                    bail!("no static route {prefix:?}");
                }
            }
            ["protocols", "bgp"] => self.draft.bgp = BgpDraft::default(),
            ["protocols", "bgp", "neighbor", addr] => {
                let before = self.draft.bgp.neighbors.len();
                self.draft.bgp.neighbors.retain(|(a, _)| a != addr);
                if self.draft.bgp.neighbors.len() == before {
                    bail!("no bgp neighbor {addr:?}");
                }
            }
            ["protocols", "bgp", "neighbor", addr, field] => {
                match self.draft.bgp.neighbors.iter_mut().find(|(a, _)| a == addr) {
                    Some((_, n)) => Self::del_neighbor_field(n, field)?,
                    None => bail!("no bgp neighbor {addr:?}"),
                }
            }
            ["protocols", "bgp", "aggregate", prefix] => {
                let before = self.draft.bgp.aggregate.len();
                self.draft.bgp.aggregate.retain(|(p, _)| p != prefix);
                if self.draft.bgp.aggregate.len() == before {
                    bail!("no bgp aggregate {prefix:?}");
                }
            }
            ["protocols", "bgp", "aggregate", prefix, "summary-only"] => {
                *self.draft.bgp_aggregate_mut(prefix) = false;
            }
            ["protocols", "bgp", "roa", prefix] => {
                let before = self.draft.bgp.roa.len();
                self.draft.bgp.roa.retain(|(p, _)| p != prefix);
                if self.draft.bgp.roa.len() == before {
                    bail!("no bgp roa {prefix:?}");
                }
            }
            ["protocols", "bgp", "roa", prefix, field] => {
                match self.draft.bgp.roa.iter_mut().find(|(p, _)| p == prefix) {
                    Some((_, r)) => match *field {
                        "origin-as" => r.origin_as = None,
                        "max-length" => r.max_length = None,
                        other => bail!("bgp roa has no field {other:?}"),
                    },
                    None => bail!("no bgp roa {prefix:?}"),
                }
            }
            ["protocols", "bgp", "confederation"] => {
                self.draft.bgp.confederation_id = None;
                self.draft.bgp.confederation_members.clear();
            }
            ["protocols", "bgp", "confederation", field] => {
                let b = &mut self.draft.bgp;
                match *field {
                    "id" => b.confederation_id = None,
                    "member" => b.confederation_members.clear(),
                    other => bail!("bgp confederation has no field {other:?}"),
                }
            }
            ["protocols", "bgp", "rpki"] => {
                self.draft.bgp.rpki_reject_invalid = false;
                self.draft.bgp.rtr = RtrDraft::default();
            }
            ["protocols", "bgp", "rpki", field] => {
                let b = &mut self.draft.bgp;
                match *field {
                    "reject-invalid" => b.rpki_reject_invalid = false,
                    "rtr" => b.rtr.server = None,
                    "rtr-refresh" => b.rtr.refresh = None,
                    other => bail!("bgp rpki has no field {other:?}"),
                }
            }
            ["protocols", "bgp", field] => {
                let b = &mut self.draft.bgp;
                match *field {
                    "local-as" => b.local_as = None,
                    "router-id" => b.router_id = None,
                    "hold-time" => b.hold_time = None,
                    "cluster-id" => b.cluster_id = None,
                    "multipath" => b.multipath = None,
                    "network" => b.network.clear(),
                    "redistribute" => b.redistribute.clear(),
                    "community" => b.community.clear(),
                    "large-community" => b.large_community.clear(),
                    "ext-community" => b.ext_community.clear(),
                    "ebgp-require-policy" => b.ebgp_require_policy = false,
                    other => bail!("bgp has no field {other:?}"),
                }
            }
            ["protocols", "filter", name] => {
                let before = self.draft.filters.len();
                self.draft.filters.retain(|(n, _)| n != name);
                if self.draft.filters.len() == before {
                    bail!("no filter {name:?}");
                }
            }
            ["protocols", "filter", name, "default"] => {
                match self.draft.filters.iter_mut().find(|(n, _)| n == name) {
                    Some((_, f)) => f.default = None,
                    None => bail!("no filter {name:?}"),
                }
            }
            ["protocols", "filter", name, "rule", n] => {
                let idx: u32 = n
                    .parse()
                    .with_context(|| format!("invalid rule index {n:?}"))?;
                match self.draft.filters.iter_mut().find(|(fn_, _)| fn_ == name) {
                    Some((_, f)) => {
                        let before = f.rules.len();
                        f.rules.retain(|(i, _)| *i != idx);
                        if f.rules.len() == before {
                            bail!("no rule {idx} in filter {name:?}");
                        }
                    }
                    None => bail!("no filter {name:?}"),
                }
            }
            ["protocols", "filter", name, "rule", n, field] => {
                let idx: u32 = n
                    .parse()
                    .with_context(|| format!("invalid rule index {n:?}"))?;
                match self.draft.filters.iter_mut().find(|(fn_, _)| fn_ == name) {
                    Some((_, f)) => match f.rules.iter_mut().find(|(i, _)| *i == idx) {
                        Some((_, r)) => Self::del_filter_rule_field(r, field)?,
                        None => bail!("no rule {idx} in filter {name:?}"),
                    },
                    None => bail!("no filter {name:?}"),
                }
            }
            ["protocols", "ospf"] => self.draft.ospf = OspfDraft::default(),
            ["protocols", "ospf", field] => Self::del_ospf_field(&mut self.draft.ospf, field)?,
            ["protocols", "ospf3"] => self.draft.ospf3 = OspfDraft::default(),
            ["protocols", "ospf3", field] => Self::del_ospf_field(&mut self.draft.ospf3, field)?,
            ["protocols", proto @ ("rip" | "ripng" | "babel")] => {
                *self.draft.rip_family_mut(proto) = RipDraft::default()
            }
            ["protocols", proto @ ("rip" | "ripng" | "babel"), field] => {
                let d = self.draft.rip_family_mut(proto);
                match *field {
                    "interface" => d.interfaces.clear(),
                    "redistribute" => d.redistribute.clear(),
                    "redistribute-metric" => d.redistribute_metric = None,
                    other => bail!("{proto} has no field {other:?}"),
                }
            }
            ["protocols", "isis"] => self.draft.isis = IsisDraft::default(),
            ["protocols", "isis", field] => {
                let i = &mut self.draft.isis;
                match *field {
                    "interface" => i.interfaces.clear(),
                    "system-id" => i.system_id = None,
                    "area" => i.area = None,
                    "level" => i.level = None,
                    "network-type" => i.network_type = None,
                    "redistribute" => i.redistribute.clear(),
                    "redistribute-metric" => i.redistribute_metric = None,
                    other => bail!("isis has no field {other:?}"),
                }
            }
            ["protocols", "vrrp", name] => {
                let before = self.draft.vrrp.len();
                self.draft.vrrp.retain(|(n, _)| n != name);
                if self.draft.vrrp.len() == before {
                    bail!("no vrrp {name:?}");
                }
            }
            ["protocols", "vrrp", name, field] => {
                let d = self
                    .draft
                    .vrrp
                    .iter_mut()
                    .find(|(n, _)| n == name)
                    .map(|(_, d)| d)
                    .ok_or_else(|| anyhow::anyhow!("no vrrp {name:?}"))?;
                match *field {
                    "interface" => d.interface = None,
                    "vrid" => d.vrid = None,
                    "priority" => d.priority = None,
                    "virtual-address" => d.virtual_address.clear(),
                    other => bail!("vrrp has no field {other:?}"),
                }
            }

            // multiwan (roadmap C6). Bare `delete multiwan` clears the whole
            // group; the rest clear a single uplink, one of its fields, or the
            // health check.
            ["multiwan"] => {
                self.draft.multiwan_mode = None;
                self.draft.uplinks.clear();
            }
            ["multiwan", "mode"] => self.draft.multiwan_mode = None,
            ["multiwan", "uplink", iface] => {
                let before = self.draft.uplinks.len();
                self.draft.uplinks.retain(|(n, _)| n != iface);
                if self.draft.uplinks.len() == before {
                    bail!("no multiwan uplink {iface:?}");
                }
            }
            ["multiwan", "uplink", iface, "check"] => {
                let d = self.uplink(iface)?;
                d.targets.clear();
                d.interval = None;
                d.timeout = None;
                d.fail = None;
                d.rise = None;
            }
            ["multiwan", "uplink", iface, "check", "target", v] => {
                let d = self.uplink(iface)?;
                let before = d.targets.len();
                d.targets.retain(|t| t != v);
                if d.targets.len() == before {
                    bail!("{v:?} is not a health-check target of uplink {iface:?}");
                }
            }
            ["multiwan", "uplink", iface, "check", field] => {
                let d = self.uplink(iface)?;
                match *field {
                    "target" => d.targets.clear(),
                    "interval" => d.interval = None,
                    "timeout" => d.timeout = None,
                    "fail" => d.fail = None,
                    "rise" => d.rise = None,
                    other => bail!("multiwan health-check has no field {other:?}"),
                }
            }
            ["multiwan", "uplink", iface, field] => {
                let d = self.uplink(iface)?;
                match *field {
                    "priority" => d.priority = None,
                    "weight" => d.weight = None,
                    "table" => d.table = None,
                    "gateway" => d.gateway = None,
                    other => bail!("multiwan uplink has no field {other:?}"),
                }
            }

            // vpn ipsec (roadmap C2). Bare `delete vpn` clears every tunnel; the
            // rest clear one connection or one of its optional fields (the
            // required endpoints/subnets/psk can only be replaced, not cleared —
            // delete the whole connection to remove them).
            ["vpn"] => self.draft.ipsec.clear(),
            ["vpn", "ipsec"] => self.draft.ipsec.clear(),
            ["vpn", "ipsec", name] => {
                let before = self.draft.ipsec.len();
                self.draft.ipsec.retain(|(n, _)| n != name);
                if self.draft.ipsec.len() == before {
                    bail!("no vpn ipsec connection {name:?}");
                }
            }
            ["vpn", "ipsec", name, field] => {
                let d = self.ipsec(name)?;
                match *field {
                    "ike-version" => d.ike_version = None,
                    "ike-proposal" => d.ike_proposal = None,
                    "esp-proposal" => d.esp_proposal = None,
                    "local-id" => d.local_id = None,
                    "remote-id" => d.remote_id = None,
                    "start-action" => d.start_action = None,
                    "local" | "remote" | "local-subnet" | "remote-subnet" | "psk" => bail!(
                        "vpn ipsec {name:?}: {field} is required — delete the whole connection \
                         (`delete vpn ipsec {name}`) to remove it"
                    ),
                    other => bail!("vpn ipsec connection has no field {other:?}"),
                }
            }
            _ => bail!("unknown delete path"),
        }
        self.dirty = true;
        Ok(())
    }

    fn iface(&mut self, name: &str) -> Result<&mut IfaceDraft> {
        self.draft
            .interfaces
            .iter_mut()
            .find(|(n, _)| n == name)
            .map(|(_, d)| d)
            .ok_or_else(|| anyhow::anyhow!("no interface {name:?}"))
    }

    fn rule(&mut self, name: &str) -> Result<&mut RuleDraft> {
        self.draft
            .rules
            .iter_mut()
            .find(|(n, _)| n == name)
            .map(|(_, d)| d)
            .ok_or_else(|| anyhow::anyhow!("no rule {name:?}"))
    }

    fn nat_source(&mut self, name: &str) -> Result<&mut NatSrcDraft> {
        self.draft
            .nat_source
            .iter_mut()
            .find(|(n, _)| n == name)
            .map(|(_, d)| d)
            .ok_or_else(|| anyhow::anyhow!("no nat source {name:?}"))
    }

    fn nat_destination(&mut self, name: &str) -> Result<&mut NatDstDraft> {
        self.draft
            .nat_destination
            .iter_mut()
            .find(|(n, _)| n == name)
            .map(|(_, d)| d)
            .ok_or_else(|| anyhow::anyhow!("no nat destination {name:?}"))
    }

    fn uplink(&mut self, iface: &str) -> Result<&mut UplinkDraft> {
        self.draft
            .uplinks
            .iter_mut()
            .find(|(n, _)| n == iface)
            .map(|(_, d)| d)
            .ok_or_else(|| anyhow::anyhow!("no multiwan uplink {iface:?}"))
    }

    fn ipsec(&mut self, name: &str) -> Result<&mut IpsecDraft> {
        self.draft
            .ipsec
            .iter_mut()
            .find(|(n, _)| n == name)
            .map(|(_, d)| d)
            .ok_or_else(|| anyhow::anyhow!("no vpn ipsec connection {name:?}"))
    }

    /// Render the candidate in a readable, hierarchical (JunOS-curly) form.
    pub fn show(&self) -> String {
        render_draft(&self.draft, false)
    }

    /// Render the candidate scoped to one top-level section — the VyOS
    /// `show <path>` view. Unknown sections yield an error line.
    pub fn show_only(&self, section: &str) -> String {
        match section {
            "system" | "interface" | "interfaces" | "firewall" | "nat" | "protocols"
            | "services" | "multiwan" | "vpn" => {
                let out = render_draft_only(&self.draft, false, Some(section));
                if out.is_empty() {
                    format!("(no {section} configuration)\n")
                } else {
                    out
                }
            }
            other => format!(
                "error: unknown section {other:?} (system | interfaces | firewall | nat | protocols | services | multiwan | vpn)\n"
            ),
        }
    }

    /// `compare` — a VyOS-style line diff of the candidate against the
    /// **saved** config on disk (the last `save`d state). Empty when nothing
    /// changed. System-provided but unconfigured interfaces (no role/address)
    /// are excluded so they don't show up as spurious additions.
    pub fn compare(&self) -> Result<String> {
        let baseline = if self.path.exists() {
            Draft::from_appliance(&Appliance::load(&self.path)?)
        } else {
            Draft::default()
        };
        let old = render_draft(&baseline, true);
        let new = render_draft(&self.draft, true);
        if old == new {
            return Ok(String::new()); // unchanged — `unified` would echo context
        }
        Ok(crate::diff::unified(&old, &new))
    }

    /// `compare <N>` — diff the candidate against archived revision `N`
    /// (0 = newest). The config-history counterpart to plain `compare` (roadmap
    /// C21: "archive/history with diff").
    pub fn compare_revision(&self, n: usize) -> Result<String> {
        let rev = self.revision_draft(n)?;
        let old = render_draft(&rev, true);
        let new = render_draft(&self.draft, true);
        Ok(diff_or_empty(&old, &new))
    }

    /// `compare <N> <M>` — diff archived revision `N` against revision `M`.
    pub fn compare_revisions(&self, n: usize, m: usize) -> Result<String> {
        let old = render_draft(&self.revision_draft(n)?, true);
        let new = render_draft(&self.revision_draft(m)?, true);
        Ok(diff_or_empty(&old, &new))
    }

    /// Load archived revision `n` as a draft (for `compare`).
    fn revision_draft(&self, n: usize) -> Result<Draft> {
        let toml = crate::archive::read_revision(&self.path, n)?;
        Ok(Draft::from_appliance(&Appliance::from_toml(&toml)?))
    }

    /// Build a validated [`Appliance`] from the candidate, reporting any
    /// required field that hasn't been set.
    fn materialize(&self) -> Result<Appliance> {
        let hostname = self
            .draft
            .hostname
            .clone()
            .ok_or_else(|| anyhow::anyhow!("system hostname is not set"))?;
        // A QoS block needs a discipline before it can materialize (the config
        // `Qos.discipline` is not optional). Catch a `qos` set without one here,
        // with a clear message, before the infallible interface map below.
        for (name, d) in &self.draft.interfaces {
            if let Some(q) = &d.qos {
                if q.discipline.is_none() {
                    bail!(
                        "interface {name:?}: qos requires a discipline \
                         (set interface {name} qos discipline cake|fq_codel)"
                    );
                }
            }
        }
        // Interfaces may be unassigned (a NIC the system provides that the
        // operator hasn't given a zone/address yet) — they stay in the config but
        // aren't firewalled, so role/address are optional here.
        let interfaces: Vec<Interface> = self
            .draft
            .interfaces
            .iter()
            .map(|(name, d)| Interface {
                name: name.clone(),
                zone: d.zone.clone(),
                address: d.address.clone(),
                address6: d.address6.clone(),
                pd_from: d.pd_from.clone(),
                pd_subnet: d.pd_subnet,
                parent: d.parent.clone(),
                vlan: d.vlan,
                private_key: d.private_key.clone(),
                listen_port: d.listen_port,
                peers: d
                    .peers
                    .iter()
                    .map(|(pk, p)| WgPeer {
                        public_key: pk.clone(),
                        allowed_ips: p.allowed_ips.clone(),
                        endpoint: p.endpoint.clone(),
                        persistent_keepalive: p.persistent_keepalive,
                        preshared_key: p.preshared_key.clone(),
                    })
                    .collect(),
                dhcp_server: d.dhcp_server.as_ref().map(|s| DhcpServer {
                    pool_offset: s.pool_offset,
                    pool_size: s.pool_size,
                    dns: s.dns.clone(),
                    lease_time: s.lease_time,
                }),
                router_advert: d.router_advert.as_ref().map(|r| RouterAdvert {
                    prefixes: r.prefixes.clone(),
                    dns: r.dns.clone(),
                    managed: r.managed,
                    other_config: r.other_config,
                    router_lifetime: r.router_lifetime,
                }),
                if_type: d.if_type,
                master: d.master.clone(),
                bond_mode: d.bond_mode.clone(),
                mtu: d.mtu,
                mac: d.mac.clone(),
                local: d.local.clone(),
                remote: d.remote.clone(),
                tunnel_key: d.tunnel_key,
                ttl: d.ttl,
                qos: d.qos.as_ref().map(|q| Qos {
                    // Discipline presence is guaranteed by the pre-check above.
                    discipline: q.discipline.expect("qos discipline set (checked above)"),
                    bandwidth: q.bandwidth.clone(),
                    rtt: q.rtt.clone(),
                    nat: q.nat,
                    ack_filter: q.ack_filter,
                    diffserv: q.diffserv.clone(),
                    target: q.target.clone(),
                    interval: q.interval.clone(),
                    limit: q.limit,
                }),
                // Missing username/password become empty strings that `validate`
                // rejects with a clear "required" error (mirrors how a missing
                // WireGuard key is caught there, not here).
                pppoe: d.pppoe.as_ref().map(|p| Pppoe {
                    username: p.username.clone().unwrap_or_default(),
                    password: p.password.clone().unwrap_or_default(),
                    service_name: p.service_name.clone(),
                    ac_name: p.ac_name.clone(),
                    mru: p.mru,
                }),
            })
            .collect();
        let rules = self
            .draft
            .rules
            .iter()
            .map(|(name, d)| {
                Ok(Rule {
                    name: name.clone(),
                    from: d
                        .from
                        .clone()
                        .ok_or_else(|| anyhow::anyhow!("rule {name:?}: from not set"))?,
                    to: d
                        .to
                        .clone()
                        .ok_or_else(|| anyhow::anyhow!("rule {name:?}: to not set"))?,
                    action: d
                        .action
                        .ok_or_else(|| anyhow::anyhow!("rule {name:?}: action not set"))?,
                    proto: d.proto,
                    port: d.port,
                    log: d.log.unwrap_or(false),
                    source: d.source.clone(),
                    source_group: d.source_group.clone(),
                    port_group: d.port_group.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let firewall = Firewall {
            stateful: self.draft.firewall.stateful.unwrap_or(true),
            block_icmp: self.draft.firewall.block_icmp.unwrap_or(false),
            blocklist: self.draft.firewall.blocklist.clone(),
            default_action: self.draft.firewall.default_action.unwrap_or(Action::Drop),
            log: self.draft.firewall.log.unwrap_or(false),
            group: self.draft.groups.clone(),
        };
        let zones: BTreeMap<String, ZoneCfg> = self
            .draft
            .zones
            .iter()
            .map(|(name, z)| {
                (
                    name.clone(),
                    ZoneCfg {
                        stateful: z.stateful,
                        block_icmp: z.block_icmp,
                        blocklist: z.blocklist.clone(),
                        default_action: z.default_action,
                        log: z.log,
                    },
                )
            })
            .collect();
        let nat_source = self
            .draft
            .nat_source
            .iter()
            .map(|(name, d)| {
                Ok(NatSource {
                    name: name.clone(),
                    zone: d
                        .zone
                        .clone()
                        .ok_or_else(|| anyhow::anyhow!("nat source {name:?}: zone not set"))?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let nat_destination =
            self.draft
                .nat_destination
                .iter()
                .map(|(name, d)| {
                    Ok(NatDestination {
                        name: name.clone(),
                        zone: d.zone.clone().ok_or_else(|| {
                            anyhow::anyhow!("nat destination {name:?}: zone not set")
                        })?,
                        proto: d.proto.ok_or_else(|| {
                            anyhow::anyhow!("nat destination {name:?}: proto not set")
                        })?,
                        port: d.port.ok_or_else(|| {
                            anyhow::anyhow!("nat destination {name:?}: port not set")
                        })?,
                        to: d.to.clone().ok_or_else(|| {
                            anyhow::anyhow!("nat destination {name:?}: to not set")
                        })?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
        // protocols: dynamic routing (Wren).
        let statics = self
            .draft
            .statics
            .iter()
            .map(|(prefix, d)| StaticRoute {
                prefix: prefix.clone(),
                via: d.via.clone(),
                dev: d.dev.clone(),
                metric: d.metric,
            })
            .collect();
        let bgp = if self.draft.bgp.is_empty() {
            None
        } else {
            Some(bgp_from_draft(&self.draft.bgp)?)
        };
        let ospf = if self.draft.ospf.is_empty() {
            None
        } else {
            Some(Ospf {
                interfaces: self.draft.ospf.interfaces.clone(),
                area: self.draft.ospf.area.clone(),
                cost: self.draft.ospf.cost,
                network_type: self.draft.ospf.network_type.clone(),
                redistribute: self.draft.ospf.redistribute.clone(),
            })
        };
        let ospf3 = if self.draft.ospf3.is_empty() {
            None
        } else {
            Some(Ospf3 {
                interfaces: self.draft.ospf3.interfaces.clone(),
                area: self.draft.ospf3.area.clone(),
                cost: self.draft.ospf3.cost,
                network_type: self.draft.ospf3.network_type.clone(),
                redistribute: self.draft.ospf3.redistribute.clone(),
            })
        };
        let rip_from = |d: &RipDraft| Rip {
            interfaces: d.interfaces.clone(),
            redistribute: d.redistribute.clone(),
            redistribute_metric: d.redistribute_metric,
        };
        let rip = (!self.draft.rip.is_empty()).then(|| rip_from(&self.draft.rip));
        let ripng = (!self.draft.ripng.is_empty()).then(|| rip_from(&self.draft.ripng));
        let babel = (!self.draft.babel.is_empty()).then(|| rip_from(&self.draft.babel));
        let isis = if self.draft.isis.is_empty() {
            None
        } else {
            Some(Isis {
                interfaces: self.draft.isis.interfaces.clone(),
                system_id: self.draft.isis.system_id.clone(),
                area: self.draft.isis.area.clone(),
                level: self.draft.isis.level.clone(),
                network_type: self.draft.isis.network_type.clone(),
                redistribute: self.draft.isis.redistribute.clone(),
                redistribute_metric: self.draft.isis.redistribute_metric,
            })
        };
        let vrrp = self
            .draft
            .vrrp
            .iter()
            .map(|(name, d)| {
                Ok(Vrrp {
                    name: name.clone(),
                    interface: d
                        .interface
                        .clone()
                        .ok_or_else(|| anyhow::anyhow!("vrrp {name:?}: interface not set"))?,
                    vrid: d
                        .vrid
                        .ok_or_else(|| anyhow::anyhow!("vrrp {name:?}: vrid not set"))?,
                    priority: d.priority,
                    virtual_address: d.virtual_address.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let filters = self
            .draft
            .filters
            .iter()
            .map(|(name, d)| filter_from_draft(name, d))
            .collect::<Result<Vec<_>>>()?;
        let protocols = Protocols {
            router_id: self.draft.router_id.clone(),
            statics,
            ospf,
            ospf3,
            rip,
            ripng,
            babel,
            isis,
            bgp,
            vrrp,
            filters,
        };

        // multiwan (roadmap C6): the failover/load-balance uplinks. Health-check
        // fields split back out into a HealthCheck; validation checks each uplink
        // names a declared interface + tables/interfaces are unique.
        let multiwan = MultiWan {
            mode: self.draft.multiwan_mode.unwrap_or_default(),
            uplinks: self
                .draft
                .uplinks
                .iter()
                .map(|(iface, d)| WanUplink {
                    interface: iface.clone(),
                    priority: d.priority,
                    weight: d.weight,
                    table: d.table,
                    gateway: d.gateway.clone(),
                    check: HealthCheck {
                        targets: d.targets.clone(),
                        interval: d.interval,
                        timeout: d.timeout,
                        fail: d.fail,
                        rise: d.rise,
                    },
                })
                .collect(),
        };

        // vpn ipsec (roadmap C2): the IKEv2 site-to-site tunnels. Required fields
        // fall back to empty strings so validation surfaces a clear "X is
        // required" / "not an IPv4" message rather than silently dropping a
        // half-specified connection.
        let vpn = Vpn {
            ipsec: self
                .draft
                .ipsec
                .iter()
                .map(|(name, d)| IpsecConnection {
                    name: name.clone(),
                    local: d.local.clone().unwrap_or_default(),
                    remote: d.remote.clone().unwrap_or_default(),
                    local_subnet: d.local_subnet.clone().unwrap_or_default(),
                    remote_subnet: d.remote_subnet.clone().unwrap_or_default(),
                    psk: d.psk.clone().unwrap_or_default(),
                    ike_version: d.ike_version,
                    ike_proposal: d.ike_proposal.clone(),
                    esp_proposal: d.esp_proposal.clone(),
                    local_id: d.local_id.clone(),
                    remote_id: d.remote_id.clone(),
                    start_action: d.start_action.clone(),
                })
                .collect(),
        };

        let appliance = Appliance {
            system: System { hostname },
            firewall,
            zones,
            interfaces,
            rules,
            nat: Nat {
                source: nat_source,
                destination: nat_destination,
            },
            protocols,
            services: Services {
                dns: Dns {
                    upstream: self.draft.dns.upstream.clone(),
                    serve_on: self.draft.dns.serve_on.clone(),
                    host_override: self.draft.dns.host_override.clone(),
                    blocklist: self.draft.dns.blocklist.clone(),
                    dnssec: self.draft.dns.dnssec.clone(),
                },
                ntp: Ntp {
                    upstream: self.draft.ntp.upstream.clone(),
                    serve_on: self.draft.ntp.serve_on.clone(),
                },
            },
            multiwan,
            vpn,
        };
        appliance.validate()?;
        Ok(appliance)
    }

    /// Validate + activate the candidate. Returns the committed config.
    pub fn commit(&mut self) -> Result<Appliance> {
        let appliance = self.materialize()?;
        self.dirty = false;
        Ok(appliance)
    }

    /// Persist the (validated) candidate to disk. Writes to `path` or, if given,
    /// `to`.
    pub fn save(&mut self, to: Option<&Path>) -> Result<PathBuf> {
        let appliance = self.materialize()?;
        let path = to.unwrap_or(&self.path).to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        // Atomic write: a temp file then rename. rename only needs write on the
        // directory (the admin has it via the wheel group), so this replaces a
        // root-owned/read-only seed file cleanly — and the agent never sees a
        // half-written config.
        let toml = appliance.to_toml()?;
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, &toml).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, &path).with_context(|| format!("installing {}", path.display()))?;
        self.dirty = false;
        // Archive this revision (only when saving the box's own config, not an
        // ad-hoc `save <path>` export). Best-effort — a failed archive must never
        // fail the save that already landed.
        if to.is_none() {
            if let Err(e) = crate::archive::archive_config(&path, &toml) {
                eprintln!("warning: could not archive this config revision: {e}");
            }
        }
        Ok(path)
    }

    /// Discard all edits, reloading from the backing file (or empty).
    pub fn discard(&mut self) -> Result<()> {
        self.draft = if self.path.exists() {
            Draft::from_appliance(&Appliance::load(&self.path)?)
        } else {
            Draft::default()
        };
        self.dirty = false;
        Ok(())
    }
}

/// Diff two rendered configs, returning empty when identical (so `compare`
/// reports "no differences" rather than echoing the whole config as context).
fn diff_or_empty(old: &str, new: &str) -> String {
    if old == new {
        String::new()
    } else {
        crate::diff::unified(old, new)
    }
}

/// Render a draft in JunOS-curly form. When `skip_empty_ifaces` is set,
/// interfaces with neither a role nor an address are omitted (used by
/// `compare`, where system-provided placeholders aren't real configuration).
fn render_draft(draft: &Draft, skip_empty_ifaces: bool) -> String {
    render_draft_only(draft, skip_empty_ifaces, None)
}

/// Render a saved appliance config in the hierarchical config syntax — the
/// operational-mode `show configuration` view (VyOS-style).
pub fn render_appliance(a: &Appliance) -> String {
    render_draft_only(&Draft::from_appliance(a), true, None)
}

/// Render the draft in config syntax, optionally scoped to ONE top-level section
/// (`system` / `interface` / `firewall` / `nat` / `protocols`) — the VyOS
/// `show <path>` view. `None` renders everything.
fn render_draft_only(draft: &Draft, skip_empty_ifaces: bool, only: Option<&str>) -> String {
    // Which top-level section a filter token selects ("interfaces" ≡ "interface").
    let want = |section: &str| match only {
        None => true,
        Some("interfaces") => section == "interface",
        Some(o) => o == section,
    };
    let mut out = String::new();
    if want("system") {
        if let Some(h) = &draft.hostname {
            out.push_str(&format!("system {{\n    hostname {h}\n}}\n"));
        }
    }
    // Interfaces are top-level (like VyOS), between `system` and `firewall`.
    for (name, i) in &draft.interfaces {
        if !want("interface") {
            break;
        }
        if skip_empty_ifaces
            && i.zone.is_none()
            && i.address.is_none()
            && i.address6.is_none()
            && i.pd_from.is_none()
            && i.pd_subnet.is_none()
            && i.parent.is_none()
            && i.vlan.is_none()
            && i.private_key.is_none()
            && i.listen_port.is_none()
            && i.peers.is_empty()
            && i.dhcp_server.is_none()
            && i.router_advert.is_none()
            && i.if_type.is_none()
            && i.master.is_none()
            && i.bond_mode.is_none()
            && i.mtu.is_none()
            && i.mac.is_none()
            && i.local.is_none()
            && i.remote.is_none()
            && i.tunnel_key.is_none()
            && i.ttl.is_none()
            && i.qos.is_none()
            && i.pppoe.is_none()
        {
            continue;
        }
        out.push_str(&format!("interface {name} {{\n"));
        if let Some(ty) = i.if_type {
            let s = match ty {
                IfaceType::Bridge => "bridge",
                IfaceType::Bond => "bond",
                IfaceType::Pppoe => "pppoe",
                IfaceType::Gre => "gre",
                IfaceType::Ipip => "ipip",
                IfaceType::Gretap => "gretap",
            };
            out.push_str(&format!("    type {s}\n"));
        }
        if let Some(z) = &i.zone {
            out.push_str(&format!("    zone {z}\n"));
        }
        if let Some(a) = &i.address {
            out.push_str(&format!("    address {a}\n"));
        }
        if let Some(a6) = &i.address6 {
            out.push_str(&format!("    address6 {a6}\n"));
        }
        if let Some(up) = &i.pd_from {
            out.push_str(&format!("    pd-from {up}\n"));
        }
        if let Some(id) = i.pd_subnet {
            out.push_str(&format!("    pd-subnet {id}\n"));
        }
        if let Some(m) = &i.master {
            out.push_str(&format!("    master {m}\n"));
        }
        if let Some(mode) = &i.bond_mode {
            out.push_str(&format!("    bond-mode {mode}\n"));
        }
        if let Some(mtu) = i.mtu {
            out.push_str(&format!("    mtu {mtu}\n"));
        }
        if let Some(mac) = &i.mac {
            out.push_str(&format!("    mac {mac}\n"));
        }
        if let Some(local) = &i.local {
            out.push_str(&format!("    local {local}\n"));
        }
        if let Some(remote) = &i.remote {
            out.push_str(&format!("    remote {remote}\n"));
        }
        if let Some(key) = i.tunnel_key {
            out.push_str(&format!("    key {key}\n"));
        }
        if let Some(ttl) = i.ttl {
            out.push_str(&format!("    ttl {ttl}\n"));
        }
        if let Some(p) = &i.parent {
            out.push_str(&format!("    parent {p}\n"));
        }
        if let Some(v) = i.vlan {
            out.push_str(&format!("    vlan {v}\n"));
        }
        if let Some(pk) = &i.private_key {
            out.push_str(&format!("    private-key {pk}\n"));
            // Operators need the derived public key to hand to the far end.
            if let Ok(public) = crate::wgkey::public_from_private(pk) {
                out.push_str(&format!("    # public-key {public}\n"));
            }
        }
        if let Some(port) = i.listen_port {
            out.push_str(&format!("    listen-port {port}\n"));
        }
        for (peer_pk, p) in &i.peers {
            out.push_str(&format!("    peer {peer_pk} {{\n"));
            if !p.allowed_ips.is_empty() {
                out.push_str(&format!(
                    "        allowed-ips {}\n",
                    p.allowed_ips.join(",")
                ));
            }
            if let Some(ep) = &p.endpoint {
                out.push_str(&format!("        endpoint {ep}\n"));
            }
            if let Some(k) = p.persistent_keepalive {
                out.push_str(&format!("        keepalive {k}\n"));
            }
            if let Some(psk) = &p.preshared_key {
                out.push_str(&format!("        preshared-key {psk}\n"));
            }
            out.push_str("    }\n");
        }
        if let Some(q) = &i.qos {
            out.push_str("    qos {\n");
            if let Some(d) = q.discipline {
                let s = match d {
                    QosDiscipline::Cake => "cake",
                    QosDiscipline::FqCodel => "fq_codel",
                };
                out.push_str(&format!("        discipline {s}\n"));
            }
            if let Some(bw) = &q.bandwidth {
                out.push_str(&format!("        bandwidth {bw}\n"));
            }
            if let Some(rtt) = &q.rtt {
                out.push_str(&format!("        rtt {rtt}\n"));
            }
            if q.nat {
                out.push_str("        nat true\n");
            }
            if q.ack_filter {
                out.push_str("        ack-filter true\n");
            }
            if let Some(ds) = &q.diffserv {
                out.push_str(&format!("        diffserv {ds}\n"));
            }
            if let Some(t) = &q.target {
                out.push_str(&format!("        target {t}\n"));
            }
            if let Some(iv) = &q.interval {
                out.push_str(&format!("        interval {iv}\n"));
            }
            if let Some(l) = q.limit {
                out.push_str(&format!("        limit {l}\n"));
            }
            out.push_str("    }\n");
        }
        if let Some(p) = &i.pppoe {
            out.push_str("    pppoe {\n");
            if let Some(u) = &p.username {
                out.push_str(&format!("        username {u}\n"));
            }
            if let Some(pw) = &p.password {
                out.push_str(&format!("        password {pw}\n"));
            }
            if let Some(sn) = &p.service_name {
                out.push_str(&format!("        service-name {sn}\n"));
            }
            if let Some(ac) = &p.ac_name {
                out.push_str(&format!("        ac-name {ac}\n"));
            }
            if let Some(mru) = p.mru {
                out.push_str(&format!("        mru {mru}\n"));
            }
            out.push_str("    }\n");
        }
        if let Some(d) = &i.dhcp_server {
            out.push_str("    dhcp-server {\n");
            if let Some(off) = d.pool_offset {
                out.push_str(&format!("        pool-offset {off}\n"));
            }
            if let Some(size) = d.pool_size {
                out.push_str(&format!("        pool-size {size}\n"));
            }
            if !d.dns.is_empty() {
                out.push_str(&format!("        dns {}\n", d.dns.join(",")));
            }
            if let Some(lease) = d.lease_time {
                out.push_str(&format!("        lease-time {lease}\n"));
            }
            out.push_str("    }\n");
        }
        if let Some(r) = &i.router_advert {
            out.push_str("    router-advert {\n");
            if !r.prefixes.is_empty() {
                out.push_str(&format!("        prefix {}\n", r.prefixes.join(",")));
            }
            if !r.dns.is_empty() {
                out.push_str(&format!("        dns {}\n", r.dns.join(",")));
            }
            if r.managed {
                out.push_str("        managed true\n");
            }
            if r.other_config {
                out.push_str("        other-config true\n");
            }
            if let Some(life) = r.router_lifetime {
                out.push_str(&format!("        router-lifetime {life}\n"));
            }
            out.push_str("    }\n");
        }
        out.push_str("}\n");
    }

    // The firewall (filtering) is nested under one `firewall { … }` node
    // (VyOS-style): `global` (the defaults), then `zone` and `rule` sub-trees.
    // NAT (translation) is rendered separately, below.
    let mut fwi = String::new(); // inner body, indented one level
    let fw = &draft.firewall;
    if fw.stateful.is_some()
        || fw.block_icmp.is_some()
        || fw.default_action.is_some()
        || fw.log.is_some()
        || !fw.blocklist.is_empty()
    {
        fwi.push_str("    global {\n");
        if let Some(s) = fw.stateful {
            fwi.push_str(&format!("        stateful {s}\n"));
        }
        if let Some(b) = fw.block_icmp {
            fwi.push_str(&format!("        block-icmp {b}\n"));
        }
        if let Some(a) = fw.default_action {
            fwi.push_str(&format!("        default-action {}\n", action_str(a)));
        }
        if let Some(l) = fw.log {
            fwi.push_str(&format!("        log {l}\n"));
        }
        for e in &fw.blocklist {
            fwi.push_str(&format!("        block {e}\n"));
        }
        fwi.push_str("    }\n");
    }
    for (name, z) in &draft.zones {
        fwi.push_str(&format!("    zone {name} {{\n"));
        if let Some(s) = z.stateful {
            fwi.push_str(&format!("        stateful {s}\n"));
        }
        if let Some(b) = z.block_icmp {
            fwi.push_str(&format!("        block-icmp {b}\n"));
        }
        if let Some(a) = z.default_action {
            fwi.push_str(&format!("        default-action {}\n", action_str(a)));
        }
        if let Some(l) = z.log {
            fwi.push_str(&format!("        log {l}\n"));
        }
        for e in &z.blocklist {
            fwi.push_str(&format!("        block {e}\n"));
        }
        fwi.push_str("    }\n");
    }
    if !draft.groups.address.is_empty() || !draft.groups.port.is_empty() {
        fwi.push_str("    group {\n");
        for (name, members) in &draft.groups.address {
            fwi.push_str(&format!("        address-group {name} {{\n"));
            if !members.is_empty() {
                fwi.push_str(&format!("            address {}\n", members.join(",")));
            }
            fwi.push_str("        }\n");
        }
        for (name, specs) in &draft.groups.port {
            fwi.push_str(&format!("        port-group {name} {{\n"));
            if !specs.is_empty() {
                let ports: Vec<String> = specs.iter().map(PortSpec::to_string).collect();
                fwi.push_str(&format!("            port {}\n", ports.join(",")));
            }
            fwi.push_str("        }\n");
        }
        fwi.push_str("    }\n");
    }
    for (name, r) in &draft.rules {
        fwi.push_str(&format!("    rule {name} {{\n"));
        if let Some(z) = &r.from {
            fwi.push_str(&format!("        from {z}\n"));
        }
        if let Some(z) = &r.to {
            fwi.push_str(&format!("        to {z}\n"));
        }
        if let Some(a) = r.action {
            fwi.push_str(&format!("        action {}\n", action_str(a)));
        }
        if let Some(p) = r.proto {
            fwi.push_str(&format!("        proto {}\n", proto_str(p)));
        }
        if let Some(p) = r.port {
            fwi.push_str(&format!("        port {p}\n"));
        }
        if let Some(l) = r.log {
            fwi.push_str(&format!("        log {l}\n"));
        }
        if let Some(s) = &r.source {
            fwi.push_str(&format!("        source {s}\n"));
        }
        if let Some(g) = &r.source_group {
            fwi.push_str(&format!("        source-group {g}\n"));
        }
        if let Some(g) = &r.port_group {
            fwi.push_str(&format!("        port-group {g}\n"));
        }
        fwi.push_str("    }\n");
    }
    if want("firewall") && !fwi.is_empty() {
        out.push_str("firewall {\n");
        out.push_str(&fwi);
        out.push_str("}\n");
    }

    // NAT is its own top-level node (address translation, not filtering), split
    // into `source` (masquerade) and `destination` (port-forward) sub-trees.
    let mut nati = String::new();
    for (name, s) in &draft.nat_source {
        nati.push_str(&format!("    source {name} {{\n"));
        if let Some(z) = &s.zone {
            nati.push_str(&format!("        zone {z}\n"));
        }
        nati.push_str("    }\n");
    }
    for (name, d) in &draft.nat_destination {
        nati.push_str(&format!("    destination {name} {{\n"));
        if let Some(z) = &d.zone {
            nati.push_str(&format!("        zone {z}\n"));
        }
        if let Some(p) = d.proto {
            nati.push_str(&format!("        proto {}\n", proto_str(p)));
        }
        if let Some(p) = d.port {
            nati.push_str(&format!("        port {p}\n"));
        }
        if let Some(t) = &d.to {
            nati.push_str(&format!("        to {t}\n"));
        }
        nati.push_str("    }\n");
    }
    if want("nat") && !nati.is_empty() {
        out.push_str("nat {\n");
        out.push_str(&nati);
        out.push_str("}\n");
    }

    // protocols { … } — dynamic routing (Wren).
    let mut proto = String::new();
    if let Some(rid) = &draft.router_id {
        proto.push_str(&format!("    router-id {rid}\n"));
    }
    for (prefix, s) in &draft.statics {
        proto.push_str(&format!("    static {prefix} {{\n"));
        if let Some(v) = &s.via {
            proto.push_str(&format!("        via {v}\n"));
        }
        if let Some(d) = &s.dev {
            proto.push_str(&format!("        dev {d}\n"));
        }
        if let Some(m) = s.metric {
            proto.push_str(&format!("        metric {m}\n"));
        }
        proto.push_str("    }\n");
    }
    if !draft.ospf.is_empty() {
        proto.push_str("    ospf {\n");
        if let Some(a) = &draft.ospf.area {
            proto.push_str(&format!("        area {a}\n"));
        }
        for iface in &draft.ospf.interfaces {
            proto.push_str(&format!("        interface {iface}\n"));
        }
        if let Some(c) = draft.ospf.cost {
            proto.push_str(&format!("        cost {c}\n"));
        }
        if let Some(nt) = &draft.ospf.network_type {
            proto.push_str(&format!("        network-type {nt}\n"));
        }
        for src in &draft.ospf.redistribute {
            proto.push_str(&format!("        redistribute {src}\n"));
        }
        proto.push_str("    }\n");
    }
    if !draft.ospf3.is_empty() {
        proto.push_str("    ospf3 {\n");
        if let Some(a) = &draft.ospf3.area {
            proto.push_str(&format!("        area {a}\n"));
        }
        for iface in &draft.ospf3.interfaces {
            proto.push_str(&format!("        interface {iface}\n"));
        }
        if let Some(c) = draft.ospf3.cost {
            proto.push_str(&format!("        cost {c}\n"));
        }
        if let Some(nt) = &draft.ospf3.network_type {
            proto.push_str(&format!("        network-type {nt}\n"));
        }
        for src in &draft.ospf3.redistribute {
            proto.push_str(&format!("        redistribute {src}\n"));
        }
        proto.push_str("    }\n");
    }
    for (name, r) in [
        ("rip", &draft.rip),
        ("ripng", &draft.ripng),
        ("babel", &draft.babel),
    ] {
        if r.is_empty() {
            continue;
        }
        proto.push_str(&format!("    {name} {{\n"));
        for iface in &r.interfaces {
            proto.push_str(&format!("        interface {iface}\n"));
        }
        for src in &r.redistribute {
            proto.push_str(&format!("        redistribute {src}\n"));
        }
        if let Some(m) = r.redistribute_metric {
            proto.push_str(&format!("        redistribute-metric {m}\n"));
        }
        proto.push_str("    }\n");
    }
    if !draft.isis.is_empty() {
        proto.push_str("    isis {\n");
        if let Some(s) = &draft.isis.system_id {
            proto.push_str(&format!("        system-id {s}\n"));
        }
        if let Some(a) = &draft.isis.area {
            proto.push_str(&format!("        area {a}\n"));
        }
        if let Some(l) = &draft.isis.level {
            proto.push_str(&format!("        level {l}\n"));
        }
        for iface in &draft.isis.interfaces {
            proto.push_str(&format!("        interface {iface}\n"));
        }
        if let Some(nt) = &draft.isis.network_type {
            proto.push_str(&format!("        network-type {nt}\n"));
        }
        for src in &draft.isis.redistribute {
            proto.push_str(&format!("        redistribute {src}\n"));
        }
        if let Some(m) = draft.isis.redistribute_metric {
            proto.push_str(&format!("        redistribute-metric {m}\n"));
        }
        proto.push_str("    }\n");
    }
    for (name, v) in &draft.vrrp {
        proto.push_str(&format!("    vrrp {name} {{\n"));
        if let Some(i) = &v.interface {
            proto.push_str(&format!("        interface {i}\n"));
        }
        if let Some(id) = v.vrid {
            proto.push_str(&format!("        vrid {id}\n"));
        }
        if let Some(p) = v.priority {
            proto.push_str(&format!("        priority {p}\n"));
        }
        for a in &v.virtual_address {
            proto.push_str(&format!("        virtual-address {a}\n"));
        }
        proto.push_str("    }\n");
    }
    if !draft.bgp.is_empty() {
        let b = &draft.bgp;
        proto.push_str("    bgp {\n");
        if let Some(a) = b.local_as {
            proto.push_str(&format!("        local-as {a}\n"));
        }
        if let Some(rid) = &b.router_id {
            proto.push_str(&format!("        router-id {rid}\n"));
        }
        if let Some(h) = b.hold_time {
            proto.push_str(&format!("        hold-time {h}\n"));
        }
        if let Some(c) = &b.cluster_id {
            proto.push_str(&format!("        cluster-id {c}\n"));
        }
        if let Some(m) = b.multipath {
            proto.push_str(&format!("        multipath {m}\n"));
        }
        for net in &b.network {
            proto.push_str(&format!("        network {net}\n"));
        }
        for src in &b.redistribute {
            proto.push_str(&format!("        redistribute {src}\n"));
        }
        for c in &b.community {
            proto.push_str(&format!("        community {c}\n"));
        }
        for c in &b.large_community {
            proto.push_str(&format!("        large-community {c}\n"));
        }
        for c in &b.ext_community {
            proto.push_str(&format!("        ext-community {c}\n"));
        }
        if let Some(id) = b.confederation_id {
            proto.push_str(&format!("        confederation id {id}\n"));
        }
        for m in &b.confederation_members {
            proto.push_str(&format!("        confederation member {m}\n"));
        }
        if b.rpki_reject_invalid {
            proto.push_str("        rpki reject-invalid true\n");
        }
        if let Some(s) = &b.rtr.server {
            proto.push_str(&format!("        rpki rtr {s}\n"));
        }
        if let Some(r) = b.rtr.refresh {
            proto.push_str(&format!("        rpki rtr-refresh {r}\n"));
        }
        if b.ebgp_require_policy {
            proto.push_str("        ebgp-require-policy true\n");
        }
        for (prefix, summary_only) in &b.aggregate {
            proto.push_str(&format!("        aggregate {prefix} {{\n"));
            if *summary_only {
                proto.push_str("            summary-only true\n");
            }
            proto.push_str("        }\n");
        }
        for (prefix, r) in &b.roa {
            proto.push_str(&format!("        roa {prefix} {{\n"));
            if let Some(o) = r.origin_as {
                proto.push_str(&format!("            origin-as {o}\n"));
            }
            if let Some(m) = r.max_length {
                proto.push_str(&format!("            max-length {m}\n"));
            }
            proto.push_str("        }\n");
        }
        for (addr, n) in &b.neighbors {
            render_neighbor(&mut proto, addr, n);
        }
        proto.push_str("    }\n");
    }
    for (name, f) in &draft.filters {
        render_filter(&mut proto, name, f);
    }
    if want("protocols") && !proto.is_empty() {
        out.push_str("protocols {\n");
        out.push_str(&proto);
        out.push_str("}\n");
    }

    // services: box-wide offered services (dns, ntp), each nested one level.
    let d = &draft.dns;
    let n = &draft.ntp;
    let dns_set = !(d.upstream.is_empty()
        && d.serve_on.is_empty()
        && d.host_override.is_empty()
        && d.blocklist.is_empty()
        && d.dnssec.is_none());
    let ntp_set = !(n.upstream.is_empty() && n.serve_on.is_empty());
    if want("services") && (dns_set || ntp_set) {
        out.push_str("services {\n");
        if dns_set {
            out.push_str("    dns {\n");
            if !d.upstream.is_empty() {
                out.push_str(&format!("        upstream {}\n", d.upstream.join(",")));
            }
            if !d.serve_on.is_empty() {
                out.push_str(&format!("        serve-on {}\n", d.serve_on.join(",")));
            }
            for (name, ip) in &d.host_override {
                out.push_str(&format!("        host-override {name} {ip}\n"));
            }
            for domain in &d.blocklist {
                out.push_str(&format!("        blocklist {domain}\n"));
            }
            if let Some(mode) = &d.dnssec {
                out.push_str(&format!("        dnssec {mode}\n"));
            }
            out.push_str("    }\n");
        }
        if ntp_set {
            out.push_str("    ntp {\n");
            if !n.upstream.is_empty() {
                out.push_str(&format!("        upstream {}\n", n.upstream.join(",")));
            }
            if !n.serve_on.is_empty() {
                out.push_str(&format!("        serve-on {}\n", n.serve_on.join(",")));
            }
            out.push_str("    }\n");
        }
        out.push_str("}\n");
    }

    // multiwan { … } — WAN uplinks with failover/load-balance + health checks.
    if want("multiwan") && !draft.uplinks.is_empty() {
        out.push_str("multiwan {\n");
        if let Some(mode) = draft.multiwan_mode {
            out.push_str(&format!("    mode {}\n", wan_mode_str(mode)));
        }
        for (iface, u) in &draft.uplinks {
            out.push_str(&format!("    uplink {iface} {{\n"));
            if let Some(p) = u.priority {
                out.push_str(&format!("        priority {p}\n"));
            }
            if let Some(w) = u.weight {
                out.push_str(&format!("        weight {w}\n"));
            }
            if let Some(t) = u.table {
                out.push_str(&format!("        table {t}\n"));
            }
            if let Some(gw) = &u.gateway {
                out.push_str(&format!("        gateway {gw}\n"));
            }
            let check_set = !u.targets.is_empty()
                || u.interval.is_some()
                || u.timeout.is_some()
                || u.fail.is_some()
                || u.rise.is_some();
            if check_set {
                out.push_str("        check {\n");
                for t in &u.targets {
                    out.push_str(&format!("            target {t}\n"));
                }
                if let Some(v) = u.interval {
                    out.push_str(&format!("            interval {v}\n"));
                }
                if let Some(v) = u.timeout {
                    out.push_str(&format!("            timeout {v}\n"));
                }
                if let Some(v) = u.fail {
                    out.push_str(&format!("            fail {v}\n"));
                }
                if let Some(v) = u.rise {
                    out.push_str(&format!("            rise {v}\n"));
                }
                out.push_str("        }\n");
            }
            out.push_str("    }\n");
        }
        out.push_str("}\n");
    }

    // vpn { ipsec <name> { … } } — IKEv2 site-to-site IPsec (roadmap C2).
    if want("vpn") && !draft.ipsec.is_empty() {
        out.push_str("vpn {\n");
        for (name, c) in &draft.ipsec {
            out.push_str(&format!("    ipsec {name} {{\n"));
            if let Some(v) = &c.local {
                out.push_str(&format!("        local {v}\n"));
            }
            if let Some(v) = &c.remote {
                out.push_str(&format!("        remote {v}\n"));
            }
            if let Some(v) = &c.local_subnet {
                out.push_str(&format!("        local-subnet {v}\n"));
            }
            if let Some(v) = &c.remote_subnet {
                out.push_str(&format!("        remote-subnet {v}\n"));
            }
            if let Some(v) = &c.psk {
                out.push_str(&format!("        psk {v}\n"));
            }
            if let Some(v) = c.ike_version {
                out.push_str(&format!("        ike-version {v}\n"));
            }
            if let Some(v) = &c.ike_proposal {
                out.push_str(&format!("        ike-proposal {v}\n"));
            }
            if let Some(v) = &c.esp_proposal {
                out.push_str(&format!("        esp-proposal {v}\n"));
            }
            if let Some(v) = &c.local_id {
                out.push_str(&format!("        local-id {v}\n"));
            }
            if let Some(v) = &c.remote_id {
                out.push_str(&format!("        remote-id {v}\n"));
            }
            if let Some(v) = &c.start_action {
                out.push_str(&format!("        start-action {v}\n"));
            }
            out.push_str("    }\n");
        }
        out.push_str("}\n");
    }

    if out.is_empty() && !skip_empty_ifaces {
        out.push_str("(empty configuration)\n");
    }
    out
}

/// Append `v` to `list` unless it's already present (idempotent `set … block`).
fn push_unique(list: &mut Vec<String>, v: &str) {
    if !list.iter().any(|e| e == v) {
        list.push(v.to_string());
    }
}

fn parse_action(s: &str) -> Result<Action> {
    Ok(match s {
        "accept" => Action::Accept,
        "drop" => Action::Drop,
        "reject" => Action::Reject,
        _ => bail!("invalid action {s:?} (expected accept|drop|reject)"),
    })
}

fn parse_proto(s: &str) -> Result<Proto> {
    Ok(match s {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        _ => bail!("invalid proto {s:?} (expected tcp|udp)"),
    })
}

/// Push `            <key> <val>\n` (12-space indent) when `val` is present.
fn push_field(out: &mut String, key: &str, val: Option<String>) {
    if let Some(v) = val {
        out.push_str(&format!("            {key} {v}\n"));
    }
}

/// Render one BGP neighbour as a nested `neighbor <addr> { … }` block (8-space
/// header, 12-space fields). Booleans print only when set; options when present.
fn render_neighbor(out: &mut String, addr: &str, n: &NeighborDraft) {
    out.push_str(&format!("        neighbor {addr} {{\n"));
    push_field(out, "remote-as", n.remote_as.map(|a| a.to_string()));
    push_field(out, "ttl-security", n.ttl_security.map(|t| t.to_string()));
    push_field(out, "password", n.password.clone());
    push_field(out, "ao-key", n.ao_key.clone());
    push_field(out, "ao-key-id", n.ao_key_id.map(|v| v.to_string()));
    push_field(out, "max-prefix", n.max_prefix.map(|v| v.to_string()));
    push_field(out, "import", n.import.clone());
    push_field(out, "export", n.export.clone());
    push_field(out, "role", n.role.clone());
    push_field(out, "bfd-auth-type", n.bfd_auth_type.clone());
    push_field(
        out,
        "bfd-auth-key-id",
        n.bfd_auth_key_id.map(|v| v.to_string()),
    );
    push_field(out, "bfd-auth-key", n.bfd_auth_key.clone());
    for (k, set) in [
        ("passive", n.passive),
        ("route-reflector-client", n.route_reflector_client),
        ("default-originate", n.default_originate),
        ("add-path", n.add_path),
        ("extended-nexthop", n.extended_nexthop),
        ("evpn", n.evpn),
        ("flowspec", n.flowspec),
        ("srpolicy", n.srpolicy),
        ("link-state", n.link_state),
        ("bfd", n.bfd),
    ] {
        if set {
            out.push_str(&format!("            {k} true\n"));
        }
    }
    out.push_str("        }\n");
}

/// Render one route filter as a nested `filter <name> { … }` block (4-space
/// header, `rule <n>` at 8 spaces, rule fields at 12).
fn render_filter(out: &mut String, name: &str, f: &FilterDraft) {
    out.push_str(&format!("    filter {name} {{\n"));
    if let Some(d) = &f.default {
        out.push_str(&format!("        default {d}\n"));
    }
    for (idx, r) in &f.rules {
        out.push_str(&format!("        rule {idx} {{\n"));
        for p in &r.prefix {
            out.push_str(&format!("            prefix {p}\n"));
        }
        push_field(out, "protocol", r.protocol.clone());
        push_field(out, "metric-le", r.metric_le.map(|v| v.to_string()));
        push_field(out, "metric-ge", r.metric_ge.map(|v| v.to_string()));
        push_field(out, "set-metric", r.set_metric.map(|v| v.to_string()));
        push_field(out, "add-metric", r.add_metric.map(|v| v.to_string()));
        push_field(
            out,
            "set-preference",
            r.set_preference.map(|v| v.to_string()),
        );
        for (k, set) in [
            ("set-community", &r.set_community),
            ("add-community", &r.add_community),
            ("set-large-community", &r.set_large_community),
            ("add-large-community", &r.add_large_community),
            ("set-ext-community", &r.set_ext_community),
            ("add-ext-community", &r.add_ext_community),
        ] {
            for c in set {
                out.push_str(&format!("            {k} {c}\n"));
            }
        }
        push_field(out, "action", r.action.clone());
        out.push_str("        }\n");
    }
    out.push_str("    }\n");
}

fn parse_bool(s: &str) -> Result<bool> {
    Ok(match s {
        "true" | "on" | "yes" => true,
        "false" | "off" | "no" => false,
        _ => bail!("invalid boolean {s:?} (expected true|false)"),
    })
}

fn parse_wan_mode(s: &str) -> Result<WanMode> {
    Ok(match s {
        "failover" => WanMode::Failover,
        "load-balance" => WanMode::LoadBalance,
        _ => bail!("invalid multiwan mode {s:?} (expected failover|load-balance)"),
    })
}

/// The rendered keyword for a Multi-WAN mode (the inverse of [`parse_wan_mode`]).
fn wan_mode_str(m: WanMode) -> &'static str {
    match m {
        WanMode::Failover => "failover",
        WanMode::LoadBalance => "load-balance",
    }
}

/// A firewall blocklist entry: an IPv4 or IPv4 CIDR. Delegates to the config
/// validator so set-time feedback matches commit-time validation.
fn validate_block_entry(s: &str) -> Result<()> {
    crate::config::validate_cidr_or_ip(s)
}

/// A WireGuard key (base64 of 32 bytes). Delegates to the config validator so
/// set-time feedback matches commit-time validation.
fn validate_wg_key(s: &str) -> Result<()> {
    crate::config::validate_wg_key(s)
}

/// A WireGuard peer endpoint (`host:port`). Delegates to the config validator.
fn validate_endpoint(s: &str) -> Result<()> {
    crate::config::validate_endpoint(s)
}

/// A bare IPv4 address (e.g. a DHCP-advertised DNS server). Delegates to the
/// config validator.
fn validate_ipv4(s: &str) -> Result<()> {
    crate::config::validate_ipv4(s)
}

/// A bare IPv6 address (e.g. an RA-advertised RDNSS server). Delegates to the
/// config validator.
fn validate_ipv6(s: &str) -> Result<()> {
    crate::config::validate_ipv6(s)
}

fn validate_address(addr: &str) -> Result<()> {
    if addr == "dhcp" {
        return Ok(());
    }
    let (ip, prefix) = addr
        .split_once('/')
        .with_context(|| format!("address {addr:?} must be \"dhcp\" or an IPv4 CIDR"))?;
    ip.parse::<std::net::Ipv4Addr>()
        .with_context(|| format!("invalid IPv4 in {addr:?}"))?;
    let prefix: u8 = prefix
        .parse()
        .with_context(|| format!("invalid prefix in {addr:?}"))?;
    if prefix > 32 {
        bail!("prefix /{prefix} exceeds /32");
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

    fn run(session: &mut Session, line: &str) -> Result<()> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts[0] {
            "set" => session.set(&parts[1..]),
            "delete" => session.delete(&parts[1..]),
            _ => panic!("test helper only does set/delete"),
        }
    }

    #[test]
    fn builds_a_config_incrementally_and_commits() {
        let mut s = Session::empty();
        for line in [
            "set system hostname fw1",
            "set interface wan0 zone wan",
            "set interface wan0 address dhcp",
            "set interface lan0 zone lan",
            "set interface lan0 address 10.0.0.1/24",
            "set firewall rule lan-out from lan",
            "set firewall rule lan-out to wan",
            "set firewall rule lan-out action accept",
        ] {
            run(&mut s, line).unwrap();
        }
        assert!(s.dirty());
        let a = s.commit().expect("valid config commits");
        assert_eq!(a.system.hostname, "fw1");
        assert_eq!(a.interfaces.len(), 2);
        assert_eq!(a.rules.len(), 1);
        assert!(!s.dirty());
    }

    #[test]
    fn multiwan_cli_builds_uplinks_shows_and_commits() {
        let mut s = Session::empty();
        for line in [
            "set system hostname fw",
            "set interface wan0 zone wan",
            "set interface wan1 zone wan",
            "set multiwan mode failover",
            "set multiwan uplink wan0 priority 10",
            "set multiwan uplink wan0 gateway 10.1.0.254",
            "set multiwan uplink wan0 check target 1.1.1.1",
            "set multiwan uplink wan0 check interval 2",
            "set multiwan uplink wan0 check fail 2",
            "set multiwan uplink wan1 priority 20",
            "set multiwan uplink wan1 gateway 10.2.0.254",
        ] {
            run(&mut s, line).unwrap();
        }
        // The show block round-trips the uplinks + the nested health check.
        let shown = s.show_only("multiwan");
        assert!(shown.contains("multiwan {"), "got:\n{shown}");
        assert!(shown.contains("uplink wan0 {"), "got:\n{shown}");
        assert!(shown.contains("gateway 10.1.0.254"), "got:\n{shown}");
        assert!(shown.contains("check {"), "got:\n{shown}");
        assert!(shown.contains("target 1.1.1.1"), "got:\n{shown}");

        let a = s.commit().expect("valid multiwan commits");
        assert_eq!(a.multiwan.mode, WanMode::Failover);
        assert_eq!(a.multiwan.uplinks.len(), 2);
        assert_eq!(a.multiwan.uplinks[0].priority, Some(10));
        assert_eq!(a.multiwan.uplinks[0].check.fail, Some(2));

        // Deleting one field, one target, and a whole uplink all work.
        run(&mut s, "delete multiwan uplink wan0 check target 1.1.1.1").unwrap();
        run(&mut s, "delete multiwan uplink wan1").unwrap();
        let b = s.commit().expect("still valid after deletes");
        assert_eq!(b.multiwan.uplinks.len(), 1);
        assert!(b.multiwan.uplinks[0].check.targets.is_empty());
    }

    #[test]
    fn multiwan_uplink_needs_a_declared_interface() {
        let mut s = Session::empty();
        run(&mut s, "set system hostname fw").unwrap();
        run(&mut s, "set multiwan uplink wan9 priority 10").unwrap();
        // wan9 isn't a declared interface → commit-time validation rejects it.
        let err = s.commit().unwrap_err().to_string();
        assert!(err.contains("not a declared interface"), "got: {err}");
    }

    #[test]
    fn ipsec_cli_builds_shows_commits_and_deletes() {
        let mut s = Session::empty();
        for line in [
            "set system hostname gw",
            "set vpn ipsec site local 203.0.113.1",
            "set vpn ipsec site remote 198.51.100.1",
            "set vpn ipsec site local-subnet 10.0.0.0/24",
            "set vpn ipsec site remote-subnet 10.1.0.0/24",
            "set vpn ipsec site psk super-secret-key",
            "set vpn ipsec site start-action trap",
        ] {
            run(&mut s, line).unwrap();
        }
        // The show block round-trips the connection + its fields.
        let shown = s.show_only("vpn");
        assert!(shown.contains("vpn {"), "got:\n{shown}");
        assert!(shown.contains("ipsec site {"), "got:\n{shown}");
        assert!(shown.contains("local 203.0.113.1"), "got:\n{shown}");
        assert!(shown.contains("remote-subnet 10.1.0.0/24"), "got:\n{shown}");
        assert!(shown.contains("start-action trap"), "got:\n{shown}");

        let a = s.commit().expect("valid ipsec commits");
        assert_eq!(a.vpn.ipsec.len(), 1);
        let c = &a.vpn.ipsec[0];
        assert_eq!(c.name, "site");
        assert_eq!(c.local, "203.0.113.1");
        assert_eq!(c.remote_subnet, "10.1.0.0/24");
        assert_eq!(c.psk, "super-secret-key");
        assert_eq!(c.start_action.as_deref(), Some("trap"));

        // Deleting an optional field, then the whole connection.
        run(&mut s, "delete vpn ipsec site start-action").unwrap();
        let b = s.commit().expect("still valid after field delete");
        assert!(b.vpn.ipsec[0].start_action.is_none());
        run(&mut s, "delete vpn ipsec site").unwrap();
        let d = s.commit().expect("still valid after connection delete");
        assert!(d.vpn.ipsec.is_empty());
    }

    #[test]
    fn ipsec_requires_a_psk_and_valid_endpoints() {
        let mut s = Session::empty();
        run(&mut s, "set system hostname gw").unwrap();
        run(&mut s, "set vpn ipsec site local 203.0.113.1").unwrap();
        run(&mut s, "set vpn ipsec site remote 198.51.100.1").unwrap();
        run(&mut s, "set vpn ipsec site local-subnet 10.0.0.0/24").unwrap();
        run(&mut s, "set vpn ipsec site remote-subnet 10.1.0.0/24").unwrap();
        // No psk yet → commit-time validation rejects it.
        let err = s.commit().unwrap_err().to_string();
        assert!(err.contains("psk is required"), "got: {err}");
        // A bad endpoint is rejected at set time.
        let bad = run(&mut s, "set vpn ipsec site remote not-an-ip").unwrap_err();
        assert!(bad.to_string().contains("IPv4"), "got: {bad}");
    }

    #[test]
    fn commit_reports_missing_required_fields() {
        let mut s = Session::empty();
        run(&mut s, "set interface wan0 zone wan").unwrap();
        // No hostname, and wan0 has no address yet.
        let err = s.commit().unwrap_err().to_string();
        assert!(err.contains("hostname"), "got: {err}");
    }

    #[test]
    fn delete_removes_nodes_and_fields() {
        let mut s = Session::empty();
        run(&mut s, "set system hostname fw1").unwrap();
        run(&mut s, "set interface wan0 zone wan").unwrap();
        run(&mut s, "set interface wan0 address dhcp").unwrap();
        run(&mut s, "delete interface wan0 address").unwrap();
        assert!(s.commit().is_ok()); // address is optional (unconfigured NIC)
        run(&mut s, "delete interface wan0").unwrap();
        run(&mut s, "set system hostname fw1").unwrap();
        assert!(s.commit().is_ok()); // no interfaces, just a hostname
        // Deleting something absent is an error.
        assert!(run(&mut s, "delete firewall rule nope").is_err());
    }

    #[test]
    fn rejects_invalid_values() {
        let mut s = Session::empty();
        assert!(run(&mut s, "set interface x vlan notanumber").is_err());
        assert!(run(&mut s, "set interface x address 10.0.0.1/33").is_err());
        assert!(run(&mut s, "set firewall rule r port 70000").is_err());
        assert!(run(&mut s, "set bogus path here").is_err());
    }

    #[test]
    fn zones_and_vlans_set_and_commit() {
        let mut s = Session::empty();
        for line in [
            "set system hostname fw1",
            // per-zone ICMP: blocked on wan, allowed on iot's parent default
            "set firewall zone wan block-icmp true",
            // masquerade is NAT, its own category now
            "set nat source wan-masq zone wan",
            "set interface eth0 zone wan",
            "set interface eth0 address dhcp",
            "set interface eth1 zone lan",
            "set interface eth1 address 10.0.0.1/24",
            // a VLAN subinterface on eth1, in its own zone
            "set interface eth1.20 parent eth1",
            "set interface eth1.20 vlan 20",
            "set interface eth1.20 zone iot",
            "set interface eth1.20 address 10.0.20.1/24",
        ] {
            run(&mut s, line).unwrap();
        }
        let a = s.commit().expect("multi-zone + vlan config commits");
        assert_eq!(a.zones.get("wan").unwrap().block_icmp, Some(true));
        assert_eq!(a.nat.source.len(), 1);
        assert_eq!(a.nat.source[0].zone, "wan");
        let vlan = a.interfaces.iter().find(|i| i.name == "eth1.20").unwrap();
        assert_eq!(
            (vlan.parent.as_deref(), vlan.vlan),
            (Some("eth1"), Some(20))
        );
        assert_eq!(vlan.zone.as_deref(), Some("iot"));
        // zone_names offers every referenced/declared zone for completion.
        assert_eq!(s.zone_names(), ["iot", "lan", "wan"]);

        // A VLAN id out of range is rejected at commit.
        run(&mut s, "set interface bad parent eth1").unwrap();
        run(&mut s, "set interface bad vlan 9000").unwrap();
        assert!(s.commit().is_err());
    }

    #[test]
    fn compare_diffs_candidate_against_saved() {
        let dir = std::env::temp_dir().join(format!("sentinel-cmp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.toml");

        // Seed and save a baseline config.
        let mut s = Session::load(&path).unwrap();
        run(&mut s, "set system hostname fw1").unwrap();
        s.save(None).unwrap();

        // Reload: no edits yet ⇒ no diff.
        let mut s = Session::load(&path).unwrap();
        assert!(s.compare().unwrap().is_empty(), "fresh load has no changes");

        // Edit the hostname ⇒ a -/+ pair.
        run(&mut s, "set system hostname fw2").unwrap();
        let diff = s.compare().unwrap();
        assert!(diff.contains("-    hostname fw1"), "got:\n{diff}");
        assert!(diff.contains("+    hostname fw2"), "got:\n{diff}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn compare_against_archived_revisions() {
        let dir = std::env::temp_dir().join(format!("sentinel-cmprev-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.toml");

        // Two saved revisions: h1 then h2. Each `save` archives one.
        let mut s = Session::load(&path).unwrap();
        run(&mut s, "set system hostname h1").unwrap();
        s.save(None).unwrap();
        run(&mut s, "set system hostname h2").unwrap();
        s.save(None).unwrap();

        // Reload so the candidate is the saved config (how `compare` is really
        // used — a fresh session, then diff against history). The candidate is h2
        // and revision 0 is the just-saved h2 → no diff; revision 1 is h1.
        let s = Session::load(&path).unwrap();
        assert!(
            s.compare_revision(0).unwrap().is_empty(),
            "candidate matches newest revision"
        );
        let d = s.compare_revision(1).unwrap();
        assert!(
            d.contains("h1") && d.contains("h2"),
            "candidate vs older revision:\n{d}"
        );
        // revision 1 (h1) vs revision 0 (h2).
        let d2 = s.compare_revisions(1, 0).unwrap();
        assert!(d2.contains("-    hostname h1"), "got:\n{d2}");
        assert!(d2.contains("+    hostname h2"), "got:\n{d2}");
        // An out-of-range revision errors.
        assert!(s.compare_revision(9).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn firewall_settings_set_delete_and_materialize() {
        let mut s = Session::empty();
        run(&mut s, "set system hostname fw1").unwrap();
        run(&mut s, "set firewall global stateful false").unwrap();
        run(&mut s, "set firewall global block-icmp true").unwrap();
        run(&mut s, "set firewall global block 10.6.6.0/24").unwrap();
        run(&mut s, "set firewall global block 192.0.2.5").unwrap();
        // Adding a duplicate is a no-op, not a second entry.
        run(&mut s, "set firewall global block 192.0.2.5").unwrap();

        let a = s.commit().expect("valid firewall config commits");
        assert!(!a.firewall.stateful);
        assert!(a.firewall.block_icmp);
        assert_eq!(a.firewall.blocklist, ["10.6.6.0/24", "192.0.2.5"]);

        // `show` nests everything under one firewall { global { … } } block.
        let shown = s.show();
        assert!(shown.contains("firewall {"), "got:\n{shown}");
        assert!(shown.contains("global {"), "got:\n{shown}");
        assert!(shown.contains("stateful false"));
        assert!(shown.contains("block 10.6.6.0/24"));

        // Delete a blocklist entry; removing an absent one errors.
        run(&mut s, "delete firewall global block 10.6.6.0/24").unwrap();
        assert!(run(&mut s, "delete firewall global block 10.6.6.0/24").is_err());
        let a = s.commit().unwrap();
        assert_eq!(a.firewall.blocklist, ["192.0.2.5"]);

        // A bad blocklist entry is rejected at set time.
        assert!(run(&mut s, "set firewall global block not-an-ip").is_err());
        assert!(run(&mut s, "set firewall global stateful maybe").is_err());
    }

    #[test]
    fn nat_source_and_destination_set_render_and_materialize() {
        let mut s = Session::empty();
        for line in [
            "set system hostname fw1",
            "set interface wan0 zone wan",
            "set interface wan0 address dhcp",
            "set interface lan0 zone lan",
            "set interface lan0 address 10.0.0.1/24",
            // SNAT (masquerade) is `nat source`, DNAT (port-forward) is `nat destination`.
            "set nat source wan-masq zone wan",
            "set nat destination web zone wan",
            "set nat destination web proto tcp",
            "set nat destination web port 443",
            "set nat destination web to 10.0.0.10:8443",
        ] {
            run(&mut s, line).unwrap();
        }

        // `show` renders NAT as its own top-level node, not under firewall.
        let shown = s.show();
        assert!(shown.contains("nat {"), "got:\n{shown}");
        assert!(shown.contains("source wan-masq {"), "got:\n{shown}");
        assert!(shown.contains("destination web {"), "got:\n{shown}");
        assert!(!shown.contains("port-forward"), "got:\n{shown}");

        let a = s.commit().expect("nat config commits");
        assert_eq!(a.nat.source.len(), 1);
        assert_eq!(
            (a.nat.source[0].name.as_str(), a.nat.source[0].zone.as_str()),
            ("wan-masq", "wan")
        );
        assert_eq!(a.nat.destination.len(), 1);
        let d = &a.nat.destination[0];
        assert_eq!(
            (d.zone.as_str(), d.port, d.to.as_str()),
            ("wan", 443, "10.0.0.10:8443")
        );

        // Completion name helpers see the new rules.
        assert_eq!(s.nat_source_names(), ["wan-masq"]);
        assert_eq!(s.nat_destination_names(), ["web"]);

        // Delete a field, then a whole rule; deleting an absent one errors.
        run(&mut s, "delete nat destination web port").unwrap();
        assert!(s.commit().is_err(), "port is required on a destination NAT");
        run(&mut s, "set nat destination web port 443").unwrap();
        run(&mut s, "delete nat source wan-masq").unwrap();
        assert!(s.commit().is_ok());
        assert!(run(&mut s, "delete nat destination nope").is_err());
    }

    #[test]
    fn pppoe_client_sets_renders_and_commits() {
        let mut s = Session::empty();
        run(&mut s, "set system hostname fw1").unwrap();
        run(&mut s, "set interface eth0 zone wan").unwrap();
        run(&mut s, "set interface ppp0 type pppoe").unwrap();
        run(&mut s, "set interface ppp0 parent eth0").unwrap();
        run(&mut s, "set interface ppp0 zone wan").unwrap();
        run(&mut s, "set interface ppp0 pppoe username user@isp.de").unwrap();
        run(&mut s, "set interface ppp0 pppoe password s3cret").unwrap();
        run(&mut s, "set interface ppp0 pppoe service-name internet").unwrap();
        run(&mut s, "set interface ppp0 pppoe mru 1492").unwrap();

        // The config view renders the pppoe sub-block round-trippably.
        let shown = s.show();
        assert!(shown.contains("interface ppp0"), "got:\n{shown}");
        assert!(shown.contains("type pppoe"), "got:\n{shown}");
        assert!(shown.contains("pppoe {"), "got:\n{shown}");
        assert!(shown.contains("username user@isp.de"), "got:\n{shown}");
        assert!(shown.contains("password s3cret"), "got:\n{shown}");
        assert!(shown.contains("service-name internet"), "got:\n{shown}");
        assert!(shown.contains("mru 1492"), "got:\n{shown}");

        // It validates + materializes into an Appliance.
        let a = s.commit().expect("pppoe config commits");
        let ppp = a.interfaces.iter().find(|i| i.name == "ppp0").unwrap();
        assert!(ppp.is_pppoe());
        let p = ppp.pppoe.as_ref().unwrap();
        assert_eq!(p.username, "user@isp.de");
        assert_eq!(p.password, "s3cret");
        assert_eq!(p.service_name.as_deref(), Some("internet"));
        assert_eq!(p.mru, Some(1492));

        // Deleting a single pppoe field, then the whole client.
        run(&mut s, "delete interface ppp0 pppoe mru").unwrap();
        assert!(!s.show().contains("mru 1492"));
        run(&mut s, "delete interface ppp0 pppoe").unwrap();
        assert!(!s.show().contains("pppoe {"));
    }

    #[test]
    fn gre_tunnel_sets_renders_commits_and_deletes() {
        let mut s = Session::empty();
        run(&mut s, "set system hostname fw1").unwrap();
        run(&mut s, "set interface eth0 address 10.0.0.1/24").unwrap();
        run(&mut s, "set interface tun0 type gre").unwrap();
        run(&mut s, "set interface tun0 local 10.0.0.1").unwrap();
        run(&mut s, "set interface tun0 remote 10.0.0.2").unwrap();
        run(&mut s, "set interface tun0 address 172.16.0.1/30").unwrap();
        run(&mut s, "set interface tun0 zone vpn").unwrap();
        run(&mut s, "set interface tun0 key 42").unwrap();
        run(&mut s, "set interface tun0 ttl 64").unwrap();

        // The config view renders the tunnel scalars round-trippably.
        let shown = s.show();
        assert!(shown.contains("interface tun0"), "got:\n{shown}");
        assert!(shown.contains("type gre"), "got:\n{shown}");
        assert!(shown.contains("local 10.0.0.1"), "got:\n{shown}");
        assert!(shown.contains("remote 10.0.0.2"), "got:\n{shown}");
        assert!(shown.contains("key 42"), "got:\n{shown}");
        assert!(shown.contains("ttl 64"), "got:\n{shown}");

        // It validates + materializes into an Appliance.
        let a = s.commit().expect("gre tunnel config commits");
        let gre = a.interfaces.iter().find(|i| i.name == "tun0").unwrap();
        assert!(gre.is_tunnel());
        assert_eq!(gre.local.as_deref(), Some("10.0.0.1"));
        assert_eq!(gre.remote.as_deref(), Some("10.0.0.2"));
        assert_eq!(gre.tunnel_key, Some(42));
        assert_eq!(gre.ttl, Some(64));

        // A bogus endpoint is rejected at set time; a key on ipip at commit time.
        assert!(run(&mut s, "set interface tun0 remote not-an-ip").is_err());
        // Deleting the key drops it from the view.
        run(&mut s, "delete interface tun0 key").unwrap();
        assert!(!s.show().contains("key 42"));
    }

    #[test]
    fn qos_sets_renders_commits_and_deletes() {
        let mut s = Session::empty();
        run(&mut s, "set system hostname fw1").unwrap();
        run(&mut s, "set interface eth0 address 10.0.0.1/24").unwrap();
        run(&mut s, "set interface eth0 qos discipline cake").unwrap();
        run(&mut s, "set interface eth0 qos bandwidth 100mbit").unwrap();
        run(&mut s, "set interface eth0 qos rtt internet").unwrap();
        run(&mut s, "set interface eth0 qos nat true").unwrap();
        run(&mut s, "set interface eth0 qos diffserv diffserv4").unwrap();

        let shown = s.show();
        assert!(shown.contains("qos {"), "got:\n{shown}");
        assert!(shown.contains("discipline cake"), "got:\n{shown}");
        assert!(shown.contains("bandwidth 100mbit"), "got:\n{shown}");
        assert!(shown.contains("rtt internet"), "got:\n{shown}");
        assert!(shown.contains("nat true"), "got:\n{shown}");
        assert!(shown.contains("diffserv diffserv4"), "got:\n{shown}");

        let a = s.commit().expect("qos config commits");
        let q = a
            .interfaces
            .iter()
            .find(|i| i.name == "eth0")
            .unwrap()
            .qos
            .as_ref()
            .unwrap();
        assert!(q.is_cake());
        assert_eq!(q.bandwidth.as_deref(), Some("100mbit"));
        assert!(q.nat);

        // A cake knob is rejected under fq_codel — reload, switch, expect a
        // commit error (cross-discipline knob).
        run(&mut s, "set interface eth0 qos discipline fq_codel").unwrap();
        assert!(
            s.commit().is_err(),
            "bandwidth is a cake knob; must fail on fq_codel"
        );

        // Deleting one field, then the whole block.
        run(&mut s, "delete interface eth0 qos bandwidth").unwrap();
        run(&mut s, "delete interface eth0 qos nat").unwrap();
        run(&mut s, "delete interface eth0 qos diffserv").unwrap();
        run(&mut s, "delete interface eth0 qos rtt").unwrap();
        assert!(s.commit().is_ok(), "fq_codel with no cake knobs commits");
        run(&mut s, "delete interface eth0 qos").unwrap();
        assert!(!s.show().contains("qos {"));
    }

    #[test]
    fn show_renders_partial_drafts() {
        let mut s = Session::empty();
        run(&mut s, "set system hostname fw1").unwrap();
        run(&mut s, "set interface wan0 zone wan").unwrap();
        let shown = s.show();
        assert!(shown.contains("hostname fw1"));
        assert!(shown.contains("interface wan0"));
        assert!(shown.contains("zone wan"));
    }

    #[test]
    fn bgp_full_neighbor_and_filter_set_show_commit_round_trip() {
        let mut s = Session::empty();
        for line in [
            "set system hostname r1",
            "set protocols router-id 10.0.0.1",
            "set protocols bgp local-as 65001",
            "set protocols bgp hold-time 90",
            "set protocols bgp confederation id 65000",
            "set protocols bgp confederation member 65002",
            "set protocols bgp community 65001:100",
            "set protocols bgp multipath 4",
            "set protocols bgp ebgp-require-policy true",
            "set protocols bgp rpki reject-invalid true",
            "set protocols bgp rpki rtr 10.0.0.9:3323",
            "set protocols bgp aggregate 10.11.0.0/16 summary-only true",
            "set protocols bgp roa 10.11.0.0/16 origin-as 65001",
            "set protocols bgp roa 10.11.0.0/16 max-length 24",
            "set protocols bgp neighbor 10.10.0.2 remote-as 65002",
            "set protocols bgp neighbor 10.10.0.2 passive true",
            "set protocols bgp neighbor 10.10.0.2 route-reflector-client true",
            "set protocols bgp neighbor 10.10.0.2 ttl-security 1",
            "set protocols bgp neighbor 10.10.0.2 password s3cret",
            "set protocols bgp neighbor 10.10.0.2 max-prefix 1000",
            "set protocols bgp neighbor 10.10.0.2 role customer",
            "set protocols bgp neighbor 10.10.0.2 import from-peer",
            "set protocols bgp neighbor 10.10.0.2 export to-peer",
            "set protocols bgp neighbor 10.10.0.2 bfd true",
            "set protocols bgp neighbor 10.10.0.2 bfd-auth-type meticulous-sha1",
            "set protocols filter from-peer default reject",
            "set protocols filter from-peer rule 10 prefix 10.0.0.0/8+",
            "set protocols filter from-peer rule 10 set-metric 100",
            "set protocols filter from-peer rule 10 set-community 65001:200",
            "set protocols filter from-peer rule 10 action accept",
            "set protocols filter to-peer default accept",
        ] {
            run(&mut s, line).unwrap();
        }

        // `show` renders nested neighbor + filter blocks.
        let shown = s.show();
        assert!(shown.contains("neighbor 10.10.0.2 {"), "got:\n{shown}");
        assert!(
            shown.contains("route-reflector-client true"),
            "got:\n{shown}"
        );
        assert!(shown.contains("import from-peer"), "got:\n{shown}");
        assert!(shown.contains("filter from-peer {"), "got:\n{shown}");
        assert!(shown.contains("rule 10 {"), "got:\n{shown}");
        assert!(shown.contains("action accept"), "got:\n{shown}");

        // It materializes into a validated Appliance carrying every field.
        let a = s.commit().expect("full bgp + filter config commits");
        let bgp = a.protocols.bgp.as_ref().unwrap();
        assert_eq!(bgp.hold_time, Some(90));
        assert_eq!(bgp.confederation_id, Some(65000));
        assert_eq!(bgp.aggregate[0].prefix, "10.11.0.0/16");
        assert!(bgp.aggregate[0].summary_only);
        assert_eq!(bgp.roa[0].origin_as, 65001);
        assert_eq!(bgp.rtr.as_ref().unwrap().server, "10.0.0.9:3323");
        let n = &bgp.neighbors[0];
        assert!(n.passive && n.route_reflector_client && n.bfd);
        assert_eq!(n.password.as_deref(), Some("s3cret"));
        assert_eq!(n.role.as_deref(), Some("customer"));
        assert_eq!(n.import.as_deref(), Some("from-peer"));
        assert_eq!(a.protocols.filters.len(), 2);

        // Re-loading the drafted config reproduces the same routing view (rule
        // indices renumber to their 1-based position on reload).
        let reloaded = render_appliance(&a);
        assert!(
            reloaded.contains("neighbor 10.10.0.2 {"),
            "got:\n{reloaded}"
        );
        assert!(reloaded.contains("password s3cret"), "got:\n{reloaded}");
        assert!(
            reloaded.contains("rpki rtr 10.0.0.9:3323"),
            "got:\n{reloaded}"
        );
        assert!(reloaded.contains("filter from-peer {"), "got:\n{reloaded}");
        assert!(
            reloaded.contains("set-community 65001:200"),
            "got:\n{reloaded}"
        );
        // The materialized config re-parses + re-validates from its own TOML.
        Appliance::from_toml(&a.to_toml().unwrap()).expect("re-parses");

        // Deleting a neighbour field and a filter rule works.
        run(&mut s, "delete protocols bgp neighbor 10.10.0.2 passive").unwrap();
        assert!(!s.show().contains("passive true"));
        run(&mut s, "delete protocols filter from-peer rule 10").unwrap();
        assert!(!s.show().contains("rule 10 {"));
        assert!(run(&mut s, "delete protocols filter nope").is_err());
    }
}
