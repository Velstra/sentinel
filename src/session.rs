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
    Acme, Action, Appliance, Bfd, Bgp, BgpAggregate, BgpNeighbor, BgpRoa, BgpRtr, Ca, Certificate,
    DhcpRelay, DhcpServer, DhcpStaticLease, Dns, Dyndns, Export, Filter, FilterRule, Firewall,
    Groups, HealthCheck, IfaceType, Interface, IpsecConnection, Isis, Lldp, Mdns, MultiWan,
    Multicast, MulticastInterface, Nat, Nat64, NatDestination, NatSource, Ntp, OpenConnectServer,
    OpenConnectUser, Ospf, Ospf3, OspfInterface, Pki, Policy, PortSpec, Pppoe, PrefixEntry,
    PrefixList, Proto, Protocols, Qos, QosDiscipline, ReverseProxy, Rip, RouterAdvert, Rule,
    Services, Snmp, StaticRoute, System, UpdateChannel, Vpn, VrfDef, Vrrp, WanMode, WanUplink,
    WgPeer, WireguardTunnel, ZoneCfg,
};

/// Default on-disk location of the active appliance config. Writable and
/// persistent (survives reboots); the flake reads it at rebuild time.
pub const DEFAULT_CONFIG: &str = "/var/lib/sentinel/appliance.toml";

/// A partially-specified interface (fields filled in incrementally).
#[derive(Debug, Clone, Default)]
struct IfaceDraft {
    // Documentary label + administrative disable.
    description: Option<String>,
    disabled: Option<bool>,
    zone: Option<String>,
    address: Option<String>,
    address6: Option<String>,
    pd_from: Option<String>,
    pd_subnet: Option<u8>,
    parent: Option<String>,
    vlan: Option<u16>,
    // 802.1ad QinQ tag protocol on a VLAN subinterface, and the MACVLAN mode on
    // a `type = macvlan` pseudo-NIC (roadmap C14).
    vlan_protocol: Option<String>,
    macvlan_mode: Option<String>,
    // A built-in DHCP server serving this interface's static subnet.
    dhcp_server: Option<DhcpServerDraft>,
    // An IPv6 Router Advertiser (SLAAC) on this interface.
    router_advert: Option<RouterAdvertDraft>,
    // Virtual L2 device kind (bridge/bond/wireguard) + bond mode, the member NICs
    // enslaved to a bridge/bond, and (for a vlan-aware bridge) the filtering flag /
    // per-port tagged+untagged VLAN membership.
    if_type: Option<IfaceType>,
    members: Vec<String>,
    bond_mode: Option<String>,
    vlan_aware: Option<bool>,
    vlan_tagged: Vec<u16>,
    vlan_untagged: Option<u16>,
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
    default_router: Option<String>,
    domain: Option<String>,
    // Static reservations, keyed by their CLI name in configuration order.
    static_mappings: Vec<(String, StaticLeaseDraft)>,
}

/// A partially-specified static DHCP reservation (mac + ip filled in
/// incrementally, keyed by name in the parent [`DhcpServerDraft`]).
#[derive(Debug, Clone, Default)]
struct StaticLeaseDraft {
    mac: Option<String>,
    ip: Option<String>,
}

impl DhcpServerDraft {
    /// Mutable access to the static reservation named `name`, inserting it if new
    /// (reservations are keyed by their CLI name in configuration order).
    fn static_lease_mut(&mut self, name: &str) -> &mut StaticLeaseDraft {
        if let Some(i) = self.static_mappings.iter().position(|(n, _)| n == name) {
            return &mut self.static_mappings[i].1;
        }
        self.static_mappings
            .push((name.to_string(), StaticLeaseDraft::default()));
        &mut self.static_mappings.last_mut().unwrap().1
    }
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
    description: Option<String>,
    disabled: Option<bool>,
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
    description: Option<String>,
    disabled: Option<bool>,
    zone: Option<String>,
}

/// A partially-specified destination-NAT (port-forward) rule.
#[derive(Debug, Clone, Default)]
struct NatDstDraft {
    description: Option<String>,
    disabled: Option<bool>,
    zone: Option<String>,
    proto: Option<Proto>,
    port: Option<u16>,
    to: Option<String>,
}

/// A partially-specified per-zone posture override.
#[derive(Debug, Clone, Default)]
struct ZoneDraft {
    description: Option<String>,
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
    vrf: Option<String>,
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
    vrf: Option<String>,
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
    local_as: Option<u32>,
    update_source: Option<String>,
    ebgp_multihop: Option<u8>,
    description: Option<String>,
    shutdown: bool,
    hold_time: Option<u16>,
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
            && self.vrf.is_none()
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
    /// The named `[[policy.prefix-list]]` this rule matches (`match prefix-list`).
    match_prefix_list: Option<String>,
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

/// A partially-specified prefix-list (keyed by name in [`Draft::prefix_lists`]).
#[derive(Debug, Clone, Default)]
struct PrefixListDraft {
    /// Entries keyed by their sequence number, kept sorted by it.
    entries: Vec<(u32, PrefixEntryDraft)>,
}

/// One prefix-list entry's fields (keyed by `seq` in [`PrefixListDraft::entries`]).
#[derive(Debug, Clone, Default)]
struct PrefixEntryDraft {
    prefix: Option<String>,
    ge: Option<u8>,
    le: Option<u8>,
}

impl PrefixListDraft {
    /// Mutable access to the entry at sequence `seq`, inserting it (kept sorted
    /// by `seq`) if new.
    fn entry_mut(&mut self, seq: u32) -> &mut PrefixEntryDraft {
        if let Some(i) = self.entries.iter().position(|(n, _)| *n == seq) {
            return &mut self.entries[i].1;
        }
        self.entries.push((seq, PrefixEntryDraft::default()));
        self.entries.sort_by_key(|(n, _)| *n);
        let i = self.entries.iter().position(|(n, _)| *n == seq).unwrap();
        &mut self.entries[i].1
    }
}

/// The candidate's OSPFv2/OSPFv3 configuration. A superset draft shared by both
/// (`ospf` / `ospf3`); the CLI grammar only offers each protocol its own valid
/// fields (e.g. auth / stub-areas / timers / vrf are OSPFv2-only, `instance-id`
/// is OSPFv3-only), and materialize/emission read only the relevant subset.
#[derive(Debug, Clone, Default)]
struct OspfDraft {
    interfaces: Vec<String>,
    /// Per-interface areas, keyed by interface name (`interface <name> area <id>`).
    interface_areas: Vec<(String, Option<String>)>,
    area: Option<String>,
    router_priority: Option<u8>,
    cost: Option<u16>,
    network_type: Option<String>,
    passive_interfaces: Vec<String>,
    redistribute: Vec<String>,
    redistribute_metric: Option<u32>,
    stub_areas: Vec<String>,
    stub_default_cost: Option<u32>,
    nssa_areas: Vec<String>,
    totally_stubby_areas: Vec<String>,
    totally_nssa_areas: Vec<String>,
    nssa_default_areas: Vec<String>,
    auth_type: Option<String>,
    auth_key: Option<String>,
    auth_key_id: Option<u8>,
    auth_replay_protection: Option<bool>,
    hello_interval: Option<u16>,
    dead_interval: Option<u32>,
    graceful_restart: bool,
    graceful_restart_period: Option<u32>,
    instance_id: Option<u8>,
    bfd: bool,
    vrf: Option<String>,
}

impl OspfDraft {
    /// True when nothing has been set — lets `[protocols.ospf]` stay absent.
    fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
            && self.interface_areas.is_empty()
            && self.area.is_none()
            && self.router_priority.is_none()
            && self.cost.is_none()
            && self.network_type.is_none()
            && self.passive_interfaces.is_empty()
            && self.redistribute.is_empty()
            && self.redistribute_metric.is_none()
            && self.stub_areas.is_empty()
            && self.stub_default_cost.is_none()
            && self.nssa_areas.is_empty()
            && self.totally_stubby_areas.is_empty()
            && self.totally_nssa_areas.is_empty()
            && self.nssa_default_areas.is_empty()
            && self.auth_type.is_none()
            && self.auth_key.is_none()
            && self.auth_key_id.is_none()
            && self.auth_replay_protection.is_none()
            && self.hello_interval.is_none()
            && self.dead_interval.is_none()
            && !self.graceful_restart
            && self.graceful_restart_period.is_none()
            && self.instance_id.is_none()
            && !self.bfd
            && self.vrf.is_none()
    }

    /// Mutable access to the per-interface area entry for `name`, inserting it.
    fn interface_area_mut(&mut self, name: &str) -> &mut Option<String> {
        if let Some(i) = self.interface_areas.iter().position(|(n, _)| n == name) {
            return &mut self.interface_areas[i].1;
        }
        self.interface_areas.push((name.to_string(), None));
        &mut self.interface_areas.last_mut().unwrap().1
    }
}

/// A RIP-family draft (RIPv2 / RIPng / Babel — same knobs). `network` /
/// `router_id` are Babel-only and `bfd` / `vrf` are RIP+Babel-only; the CLI
/// grammar restricts them and emission only writes what the target accepts.
#[derive(Debug, Clone, Default)]
struct RipDraft {
    interfaces: Vec<String>,
    redistribute: Vec<String>,
    redistribute_metric: Option<u32>,
    network: Vec<String>,
    router_id: Option<String>,
    bfd: bool,
    vrf: Option<String>,
}

impl RipDraft {
    fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
            && self.redistribute.is_empty()
            && self.redistribute_metric.is_none()
            && self.network.is_empty()
            && self.router_id.is_none()
            && !self.bfd
            && self.vrf.is_none()
    }
}

/// Build a [`RipDraft`] from a saved RIP-family config section.
fn rip_to_draft(r: &Rip) -> RipDraft {
    RipDraft {
        interfaces: r.interfaces.clone(),
        redistribute: r.redistribute.clone(),
        redistribute_metric: r.redistribute_metric,
        network: r.network.clone(),
        router_id: r.router_id.clone(),
        bfd: r.bfd,
        vrf: r.vrf.clone(),
    }
}

/// Build an [`OspfDraft`] from a saved `[protocols.ospf]` (OSPFv2) section.
fn ospf_to_draft(o: &Ospf) -> OspfDraft {
    OspfDraft {
        interfaces: o.interfaces.clone(),
        interface_areas: o
            .interface
            .iter()
            .map(|i| (i.name.clone(), i.area.clone()))
            .collect(),
        area: o.area.clone(),
        router_priority: o.router_priority,
        cost: o.cost,
        network_type: o.network_type.clone(),
        passive_interfaces: o.passive_interfaces.clone(),
        redistribute: o.redistribute.clone(),
        redistribute_metric: o.redistribute_metric,
        stub_areas: o.stub_areas.clone(),
        stub_default_cost: o.stub_default_cost,
        nssa_areas: o.nssa_areas.clone(),
        totally_stubby_areas: o.totally_stubby_areas.clone(),
        totally_nssa_areas: o.totally_nssa_areas.clone(),
        nssa_default_areas: o.nssa_default_areas.clone(),
        auth_type: o.auth_type.clone(),
        auth_key: o.auth_key.clone(),
        auth_key_id: o.auth_key_id,
        auth_replay_protection: o.auth_replay_protection,
        hello_interval: o.hello_interval,
        dead_interval: o.dead_interval,
        graceful_restart: o.graceful_restart,
        graceful_restart_period: o.graceful_restart_period,
        instance_id: None,
        bfd: o.bfd,
        vrf: o.vrf.clone(),
    }
}

/// Build an [`OspfDraft`] from a saved `[protocols.ospf3]` (OSPFv3) section.
fn ospf3_to_draft(o: &Ospf3) -> OspfDraft {
    OspfDraft {
        interfaces: o.interfaces.clone(),
        interface_areas: o
            .interface
            .iter()
            .map(|i| (i.name.clone(), i.area.clone()))
            .collect(),
        area: o.area.clone(),
        router_priority: o.router_priority,
        cost: o.cost,
        network_type: o.network_type.clone(),
        redistribute: o.redistribute.clone(),
        redistribute_metric: o.redistribute_metric,
        instance_id: o.instance_id,
        bfd: o.bfd,
        ..OspfDraft::default()
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
        vrf: b.vrf.clone(),
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
        local_as: n.local_as,
        update_source: n.update_source.clone(),
        ebgp_multihop: n.ebgp_multihop,
        description: n.description.clone(),
        shutdown: n.shutdown,
        hold_time: n.hold_time,
    }
}

/// Build a [`FilterDraft`] from a saved `[[policy.route-map]]`. Each rule keeps
/// its explicit `seq` (VyOS rule number); a legacy rule with no number falls
/// back to its 1-based position.
fn filter_to_draft(f: &Filter) -> FilterDraft {
    FilterDraft {
        default: f.default.clone(),
        rules: f
            .rules
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let idx = if r.seq != 0 { r.seq } else { (i + 1) as u32 };
                (
                    idx,
                    FilterRuleDraft {
                        match_prefix_list: r.match_prefix_list.clone(),
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
        vrf: d.vrf.clone(),
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
        local_as: n.local_as,
        update_source: n.update_source.clone(),
        ebgp_multihop: n.ebgp_multihop,
        description: n.description.clone(),
        shutdown: n.shutdown,
        hold_time: n.hold_time,
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
                    seq: *idx,
                    match_prefix_list: r.match_prefix_list.clone(),
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
                        anyhow::anyhow!("policy route-map {name:?} rule {idx}: action not set")
                    })?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    })
}

/// Build a [`PrefixListDraft`] from a saved `[[policy.prefix-list]]`.
fn prefix_list_to_draft(pl: &PrefixList) -> PrefixListDraft {
    PrefixListDraft {
        entries: pl
            .entries
            .iter()
            .map(|e| {
                (
                    e.seq,
                    PrefixEntryDraft {
                        prefix: Some(e.prefix.clone()),
                        ge: e.ge,
                        le: e.le,
                    },
                )
            })
            .collect(),
    }
}

/// Materialize a [`PrefixListDraft`] into a [`PrefixList`]. Every entry needs a
/// base prefix; `ge`/`le` bounds are optional.
fn prefix_list_from_draft(name: &str, d: &PrefixListDraft) -> Result<PrefixList> {
    Ok(PrefixList {
        name: name.to_string(),
        entries: d
            .entries
            .iter()
            .map(|(seq, e)| {
                Ok(PrefixEntry {
                    seq: *seq,
                    prefix: e.prefix.clone().ok_or_else(|| {
                        anyhow::anyhow!("policy prefix-list {name:?} rule {seq}: prefix not set")
                    })?,
                    ge: e.ge,
                    le: e.le,
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
    priority: Option<u8>,
    metric: Option<u32>,
    hello_interval: Option<u64>,
    network_type: Option<String>,
    redistribute: Vec<String>,
    redistribute_metric: Option<u32>,
    l2_to_l1_leaking: bool,
    bfd: bool,
    vrf: Option<String>,
}

impl IsisDraft {
    fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
            && self.system_id.is_none()
            && self.area.is_none()
            && self.level.is_none()
            && self.priority.is_none()
            && self.metric.is_none()
            && self.hello_interval.is_none()
            && self.network_type.is_none()
            && self.redistribute.is_empty()
            && self.redistribute_metric.is_none()
            && !self.l2_to_l1_leaking
            && !self.bfd
            && self.vrf.is_none()
    }
}

/// A VRRP virtual-router draft (keyed by a CLI name).
#[derive(Debug, Clone, Default)]
struct VrrpDraft {
    interface: Option<String>,
    vrid: Option<u8>,
    priority: Option<u8>,
    advert_interval: Option<u32>,
    preempt: Option<bool>,
    prefix_length: Option<u8>,
    track_interfaces: Vec<String>,
    priority_decrement: Option<u8>,
    virtual_address: Vec<String>,
}

/// The candidate's global BFD timing / authentication defaults (`[protocols.bfd]`).
#[derive(Debug, Clone, Default)]
struct BfdDraft {
    min_tx: Option<u32>,
    min_rx: Option<u32>,
    detect_mult: Option<u8>,
    auth_type: Option<String>,
    auth_key_id: Option<u8>,
    auth_key: Option<String>,
    echo: bool,
    echo_interval: Option<u32>,
}

impl BfdDraft {
    fn is_empty(&self) -> bool {
        self.min_tx.is_none()
            && self.min_rx.is_none()
            && self.detect_mult.is_none()
            && self.auth_type.is_none()
            && self.auth_key_id.is_none()
            && self.auth_key.is_none()
            && !self.echo
            && self.echo_interval.is_none()
    }
}

/// The candidate's multicast configuration (`[protocols.multicast]`).
#[derive(Debug, Clone, Default)]
struct MulticastDraft {
    enabled: bool,
    igmp: Option<bool>,
    mld: Option<bool>,
    igmp_version: Option<u8>,
    robustness: Option<u8>,
    query_interval: Option<u32>,
    query_response_interval: Option<u32>,
    /// Interfaces keyed by name (role + optional per-interface igmp-version).
    interfaces: Vec<(String, MulticastIfaceDraft)>,
}

impl MulticastDraft {
    fn is_empty(&self) -> bool {
        !self.enabled
            && self.igmp.is_none()
            && self.mld.is_none()
            && self.igmp_version.is_none()
            && self.robustness.is_none()
            && self.query_interval.is_none()
            && self.query_response_interval.is_none()
            && self.interfaces.is_empty()
    }

    /// Mutable access to the multicast interface `name`, inserting it if new.
    fn interface_mut(&mut self, name: &str) -> &mut MulticastIfaceDraft {
        if let Some(i) = self.interfaces.iter().position(|(n, _)| n == name) {
            return &mut self.interfaces[i].1;
        }
        self.interfaces
            .push((name.to_string(), MulticastIfaceDraft::default()));
        &mut self.interfaces.last_mut().unwrap().1
    }
}

/// One multicast interface's fields (keyed by name in [`MulticastDraft`]).
#[derive(Debug, Clone, Default)]
struct MulticastIfaceDraft {
    role: Option<String>,
    igmp_version: Option<u8>,
}

/// A VRF draft (keyed by name in [`Draft::vrfs`]).
#[derive(Debug, Clone, Default)]
struct VrfDraft {
    table: Option<u32>,
    rd: Option<String>,
    interfaces: Vec<String>,
    import: Option<String>,
    export: Option<String>,
}

/// The candidate's global export redistribution filters (`[protocols.export]`).
#[derive(Debug, Clone, Default)]
struct ExportDraft {
    kernel: Option<String>,
    bgp: Option<String>,
    ospf: Option<String>,
    rip: Option<String>,
    ripng: Option<String>,
    babel: Option<String>,
    isis: Option<String>,
}

impl ExportDraft {
    fn is_empty(&self) -> bool {
        self.kernel.is_none()
            && self.bgp.is_none()
            && self.ospf.is_none()
            && self.rip.is_none()
            && self.ripng.is_none()
            && self.babel.is_none()
            && self.isis.is_none()
    }
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
    /// NAT64 + DNS64 (roadmap C10) — a single-instance sub-tree under `[nat]`.
    nat64: Nat64Draft,
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
    /// VRF instances, keyed by name in configuration order.
    vrfs: Vec<(String, VrfDraft)>,
    /// Global BFD timing / authentication defaults (`[protocols.bfd]`).
    bfd: BfdDraft,
    /// Multicast (IGMP/MLD querier + RFC 4605 proxy).
    multicast: MulticastDraft,
    /// Named prefix-lists (`[[policy.prefix-list]]`), keyed by name.
    prefix_lists: Vec<(String, PrefixListDraft)>,
    /// Named route-maps (`[[policy.route-map]]`, import/export policy), keyed by
    /// name.
    filters: Vec<(String, FilterDraft)>,
    /// Per-protocol import filters (protocol → filter name).
    import: BTreeMap<String, String>,
    /// Global export redistribution filters (`[protocols.export]`).
    export: ExportDraft,
    dns: DnsDraft,
    ntp: NtpDraft,
    lldp: LldpDraft,
    snmp: SnmpDraft,
    mdns: MdnsDraft,
    dyndns: DyndnsDraft,
    dhcp_relay: DhcpRelayDraft,
    /// Multi-WAN (roadmap C6): failover/load-balance mode + the uplinks, keyed by
    /// interface in configuration order.
    multiwan_mode: Option<WanMode>,
    uplinks: Vec<(String, UplinkDraft)>,
    /// IPsec tunnels (roadmap C2): IKEv2 site-to-site connections, keyed by name
    /// in configuration order.
    ipsec: Vec<(String, IpsecDraft)>,
    /// WireGuard tunnels (roadmap C1): keys + peers for each `type = "wireguard"`
    /// interface, keyed by interface name in configuration order.
    wireguard: Vec<(String, WgTunnelDraft)>,
    /// PKI (roadmap C19): local CAs + issued certs, each keyed by name in
    /// configuration order, plus the optional ACME account.
    pki_cas: Vec<(String, PkiCaDraft)>,
    pki_certs: Vec<(String, PkiCertDraft)>,
    acme: Option<AcmeDraft>,
    /// OpenConnect (roadmap C17): the single TLS road-warrior VPN server, or
    /// `None` when unconfigured. A singleton (unlike the ipsec/wireguard lists)
    /// created on the first `set vpn openconnect …`.
    openconnect: Option<OpenConnectDraft>,
    /// Signed update channel (roadmap C13): the pinned channel URL + release
    /// signing key, or `None` when unconfigured. A singleton created on the first
    /// `set update …`.
    update: Option<UpdateChannelDraft>,
    /// L7 reverse-proxy / load-balancer frontends (roadmap C22), keyed by name in
    /// sorted order (a `BTreeMap`, so materialise/show are name-ordered). Each
    /// terminates a listen port (optionally TLS via a PKI cert) and forwards to
    /// one or more backends round-robin.
    reverse_proxy: BTreeMap<String, ReverseProxyDraft>,
}

/// A partially-specified DNS forwarder (`[services.dns]`).
#[derive(Debug, Clone, Default)]
struct DnsDraft {
    upstream: Vec<String>,
    serve_on: Vec<String>,
    host_override: BTreeMap<String, String>,
    blocklist: Vec<String>,
    dnssec: Option<String>,
    cache_size: Option<u32>,
    local_domain: Option<String>,
}

/// A partially-specified NTP server (`[services.ntp]`).
#[derive(Debug, Clone, Default)]
struct NtpDraft {
    upstream: Vec<String>,
    serve_on: Vec<String>,
}

/// A partially-specified LLDP config (`[services.lldp]`).
#[derive(Debug, Clone, Default)]
struct LldpDraft {
    enable: bool,
    interface: Vec<String>,
}

/// A partially-specified SNMP agent (`[services.snmp]`).
#[derive(Debug, Clone, Default)]
struct SnmpDraft {
    community: Option<String>,
    listen: Option<String>,
    location: Option<String>,
    contact: Option<String>,
    allow: Vec<String>,
}

/// A partially-specified mDNS reflector (`[services.mdns]`).
#[derive(Debug, Clone, Default)]
struct MdnsDraft {
    interface: Vec<String>,
}

/// A partially-specified dynamic-DNS client (`[services.dyndns]`).
#[derive(Debug, Clone, Default)]
struct DyndnsDraft {
    provider: Option<String>,
    server: Option<String>,
    hostname: Option<String>,
    login: Option<String>,
    password: Option<String>,
    interface: Option<String>,
}

/// A partially-specified DHCP relay (`[services.dhcp-relay]`).
#[derive(Debug, Clone, Default)]
struct DhcpRelayDraft {
    interface: Vec<String>,
    server: Vec<String>,
}

/// A partially-specified NAT64 config (`[nat.nat64]`, roadmap C10).
#[derive(Debug, Clone, Default)]
struct Nat64Draft {
    enabled: Option<bool>,
    prefix: Option<String>,
    pool: Option<String>,
    interface: Option<String>,
    dns64: Option<bool>,
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

/// A partially-specified WireGuard tunnel (`[[vpn.wireguard]]`), keyed by the
/// interface name in the draft. `private-key` is required at commit; peers are
/// keyed by their public key so fields fill in incrementally.
#[derive(Debug, Clone, Default)]
struct WgTunnelDraft {
    private_key: Option<String>,
    listen_port: Option<u16>,
    peers: Vec<(String, PeerDraft)>,
}

impl WgTunnelDraft {
    /// Mutable access to the peer keyed by public key `pk`, inserting it if new
    /// (peers are identified by their public key).
    fn peer_mut(&mut self, pk: &str) -> &mut PeerDraft {
        if let Some(i) = self.peers.iter().position(|(k, _)| k == pk) {
            return &mut self.peers[i].1;
        }
        self.peers.push((pk.to_string(), PeerDraft::default()));
        &mut self.peers.last_mut().unwrap().1
    }
}

/// A partially-specified OpenConnect server (`[vpn.openconnect]`, roadmap C17).
/// A singleton, so it lives behind an `Option` on the draft rather than in a
/// keyed list. `certificate` + `pool` + at least one user are required at
/// commit; everything else is optional and checked by `validate()`.
#[derive(Debug, Clone, Default)]
struct OpenConnectDraft {
    disabled: bool,
    port: Option<u16>,
    certificate: Option<String>,
    pool: Option<String>,
    dns: Vec<String>,
    routes: Vec<String>,
    default_route: bool,
    zone: Option<String>,
    /// Client credentials keyed by login name (`user <name> password …`).
    users: BTreeMap<String, OcUserDraft>,
}

/// A partially-specified OpenConnect user (`[[vpn.openconnect.user]]`). Keyed by
/// name in [`OpenConnectDraft::users`]; `password` is required at commit.
#[derive(Debug, Clone, Default)]
struct OcUserDraft {
    password: Option<String>,
}

/// A partially-specified signed update channel (`[update]`, roadmap C13). A
/// singleton behind an `Option` on the draft. Both `url` and `public-key` are
/// required at commit — a half-specified channel materialises with an empty
/// string for the missing side so `validate()` surfaces a clear "required".
#[derive(Debug, Clone, Default)]
struct UpdateChannelDraft {
    url: Option<String>,
    public_key: Option<String>,
}

/// A partially-specified local CA (`[[pki.ca]]`, roadmap C19), keyed by its name
/// in the draft. `common-name` is required (checked at materialize time).
#[derive(Debug, Clone, Default)]
struct PkiCaDraft {
    common_name: Option<String>,
    organization: Option<String>,
    key_type: Option<String>,
    validity_days: Option<u32>,
}

/// A partially-specified issued certificate (`[[pki.certificate]]`, roadmap
/// C19), keyed by its name. `ca` + `common-name` are required.
#[derive(Debug, Clone, Default)]
struct PkiCertDraft {
    ca: Option<String>,
    common_name: Option<String>,
    subject_alt_names: Vec<String>,
    key_type: Option<String>,
    usage: Option<String>,
    validity_days: Option<u32>,
}

/// A partially-specified ACME account (`[pki.acme]`, roadmap C19). `email` is
/// required.
#[derive(Debug, Clone, Default)]
struct AcmeDraft {
    email: Option<String>,
    directory_url: Option<String>,
    challenge: Option<String>,
    agree_tos: Option<bool>,
}

/// A partially-specified L7 reverse-proxy frontend (`[[services.reverse-proxy]]`,
/// roadmap C22). Keyed by name in [`Draft::reverse_proxy`]; at least one backend
/// (`host:port`) is required at commit, and `port`/`certificate` are validated by
/// `config::validate()`. `port` unset ⇒ 443; `certificate` unset ⇒ plain HTTP.
#[derive(Debug, Clone, Default)]
struct ReverseProxyDraft {
    disabled: Option<bool>,
    port: Option<u16>,
    certificate: Option<String>,
    backends: Vec<String>,
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

    /// Mutable access to the route-map `name`, inserting it if new.
    fn filter_mut(&mut self, name: &str) -> &mut FilterDraft {
        if let Some(i) = self.filters.iter().position(|(n, _)| n == name) {
            return &mut self.filters[i].1;
        }
        self.filters
            .push((name.to_string(), FilterDraft::default()));
        &mut self.filters.last_mut().unwrap().1
    }

    /// Mutable access to the prefix-list `name`, inserting it if new.
    fn prefix_list_mut(&mut self, name: &str) -> &mut PrefixListDraft {
        if let Some(i) = self.prefix_lists.iter().position(|(n, _)| n == name) {
            return &mut self.prefix_lists[i].1;
        }
        self.prefix_lists
            .push((name.to_string(), PrefixListDraft::default()));
        &mut self.prefix_lists.last_mut().unwrap().1
    }

    /// The RIP-family draft (`rip` / `ripng` / `babel`) named by `proto`.
    fn rip_family_mut(&mut self, proto: &str) -> &mut RipDraft {
        match proto {
            "rip" => &mut self.rip,
            "ripng" => &mut self.ripng,
            _ => &mut self.babel,
        }
    }

    /// The OSPF-family draft (`ospf` / `ospf3`) named by `proto`.
    fn ospf_family_mut(&mut self, proto: &str) -> &mut OspfDraft {
        match proto {
            "ospf3" => &mut self.ospf3,
            _ => &mut self.ospf,
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

    /// Mutable access to the VRF `name`, inserting it if new.
    fn vrf_mut(&mut self, name: &str) -> &mut VrfDraft {
        if let Some(i) = self.vrfs.iter().position(|(n, _)| n == name) {
            return &mut self.vrfs[i].1;
        }
        self.vrfs.push((name.to_string(), VrfDraft::default()));
        &mut self.vrfs.last_mut().unwrap().1
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

    /// Mutable access to the WireGuard tunnel keyed by interface `name`, inserting
    /// it if new (tunnels are keyed by interface name in configuration order).
    fn wireguard_mut(&mut self, name: &str) -> &mut WgTunnelDraft {
        if let Some(i) = self.wireguard.iter().position(|(n, _)| n == name) {
            return &mut self.wireguard[i].1;
        }
        self.wireguard
            .push((name.to_string(), WgTunnelDraft::default()));
        &mut self.wireguard.last_mut().unwrap().1
    }

    /// Mutable access to the OpenConnect server, creating an empty one on first
    /// touch (it is a singleton, so `set vpn openconnect …` materialises it).
    fn openconnect_mut(&mut self) -> &mut OpenConnectDraft {
        self.openconnect
            .get_or_insert_with(OpenConnectDraft::default)
    }

    /// Mutable access to the reverse-proxy frontend `name`, inserting an empty one
    /// on first touch (frontends are keyed by name).
    fn reverse_proxy_mut(&mut self, name: &str) -> &mut ReverseProxyDraft {
        self.reverse_proxy.entry(name.to_string()).or_default()
    }

    /// Mutable access to the signed update channel, creating an empty one on
    /// first touch (a singleton, so `set update …` materialises it).
    fn update_mut(&mut self) -> &mut UpdateChannelDraft {
        self.update.get_or_insert_with(UpdateChannelDraft::default)
    }

    /// Mutable access to the local CA `name`, inserting it if new (CAs are keyed
    /// by name in configuration order).
    fn pki_ca_mut(&mut self, name: &str) -> &mut PkiCaDraft {
        if let Some(i) = self.pki_cas.iter().position(|(n, _)| n == name) {
            return &mut self.pki_cas[i].1;
        }
        self.pki_cas.push((name.to_string(), PkiCaDraft::default()));
        &mut self.pki_cas.last_mut().unwrap().1
    }

    /// Mutable access to the certificate `name`, inserting it if new.
    fn pki_cert_mut(&mut self, name: &str) -> &mut PkiCertDraft {
        if let Some(i) = self.pki_certs.iter().position(|(n, _)| n == name) {
            return &mut self.pki_certs[i].1;
        }
        self.pki_certs
            .push((name.to_string(), PkiCertDraft::default()));
        &mut self.pki_certs.last_mut().unwrap().1
    }

    /// Mutable access to the ACME account, creating it on first reference.
    fn acme_mut(&mut self) -> &mut AcmeDraft {
        self.acme.get_or_insert_with(AcmeDraft::default)
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
                            description: z.description.clone(),
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
                            description: i.description.clone(),
                            // Only carry the flag when set, so a round-trip never
                            // renders `disabled false`.
                            disabled: i.disabled.then_some(true),
                            zone: i.zone.clone(),
                            address: i.address.clone(),
                            address6: i.address6.clone(),
                            pd_from: i.pd_from.clone(),
                            pd_subnet: i.pd_subnet,
                            parent: i.parent.clone(),
                            vlan: i.vlan,
                            vlan_protocol: i.vlan_protocol.clone(),
                            macvlan_mode: i.macvlan_mode.clone(),
                            dhcp_server: i.dhcp_server.as_ref().map(|d| DhcpServerDraft {
                                pool_offset: d.pool_offset,
                                pool_size: d.pool_size,
                                dns: d.dns.clone(),
                                lease_time: d.lease_time,
                                default_router: d.default_router.clone(),
                                domain: d.domain.clone(),
                                static_mappings: d
                                    .static_mappings
                                    .iter()
                                    .map(|l| {
                                        (
                                            l.name.clone(),
                                            StaticLeaseDraft {
                                                mac: Some(l.mac.clone()),
                                                ip: Some(l.ip.clone()),
                                            },
                                        )
                                    })
                                    .collect(),
                            }),
                            router_advert: i.router_advert.as_ref().map(|r| RouterAdvertDraft {
                                prefixes: r.prefixes.clone(),
                                dns: r.dns.clone(),
                                managed: r.managed,
                                other_config: r.other_config,
                                router_lifetime: r.router_lifetime,
                            }),
                            if_type: i.if_type,
                            members: i.members.clone(),
                            bond_mode: i.bond_mode.clone(),
                            vlan_aware: i.vlan_aware,
                            vlan_tagged: i.vlan_tagged.clone(),
                            vlan_untagged: i.vlan_untagged,
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
                            description: r.description.clone(),
                            disabled: r.disabled.then_some(true),
                            from: Some(r.from.clone()),
                            to: r.to.clone(),
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
                            description: s.description.clone(),
                            disabled: s.disabled.then_some(true),
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
                            description: d.description.clone(),
                            disabled: d.disabled.then_some(true),
                            zone: Some(d.zone.clone()),
                            proto: Some(d.proto),
                            port: Some(d.port),
                            to: Some(d.to.clone()),
                        },
                    )
                })
                .collect(),
            nat64: Nat64Draft {
                enabled: a.nat.nat64.enabled.then_some(true),
                prefix: a.nat.nat64.prefix.clone(),
                pool: a.nat.nat64.pool.clone(),
                interface: a.nat.nat64.interface.clone(),
                dns64: a.nat.nat64.dns64.then_some(true),
            },
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
                            vrf: s.vrf.clone(),
                        },
                    )
                })
                .collect(),
            ospf: a
                .protocols
                .ospf
                .as_ref()
                .map(ospf_to_draft)
                .unwrap_or_default(),
            ospf3: a
                .protocols
                .ospf3
                .as_ref()
                .map(ospf3_to_draft)
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
                    priority: i.priority,
                    metric: i.metric,
                    hello_interval: i.hello_interval,
                    network_type: i.network_type.clone(),
                    redistribute: i.redistribute.clone(),
                    redistribute_metric: i.redistribute_metric,
                    l2_to_l1_leaking: i.l2_to_l1_leaking,
                    bfd: i.bfd,
                    vrf: i.vrf.clone(),
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
                            advert_interval: v.advert_interval,
                            preempt: v.preempt,
                            prefix_length: v.prefix_length,
                            track_interfaces: v.track_interfaces.clone(),
                            priority_decrement: v.priority_decrement,
                            virtual_address: v.virtual_address.clone(),
                        },
                    )
                })
                .collect(),
            vrfs: a
                .protocols
                .vrfs
                .iter()
                .map(|v| {
                    (
                        v.name.clone(),
                        VrfDraft {
                            table: Some(v.table),
                            rd: v.rd.clone(),
                            interfaces: v.interfaces.clone(),
                            import: v.import.clone(),
                            export: v.export.clone(),
                        },
                    )
                })
                .collect(),
            bfd: a
                .protocols
                .bfd
                .as_ref()
                .map(|b| BfdDraft {
                    min_tx: b.min_tx,
                    min_rx: b.min_rx,
                    detect_mult: b.detect_mult,
                    auth_type: b.auth_type.clone(),
                    auth_key_id: b.auth_key_id,
                    auth_key: b.auth_key.clone(),
                    echo: b.echo,
                    echo_interval: b.echo_interval,
                })
                .unwrap_or_default(),
            multicast: a
                .protocols
                .multicast
                .as_ref()
                .map(|m| MulticastDraft {
                    enabled: m.enabled,
                    igmp: m.igmp,
                    mld: m.mld,
                    igmp_version: m.igmp_version,
                    robustness: m.robustness,
                    query_interval: m.query_interval,
                    query_response_interval: m.query_response_interval,
                    interfaces: m
                        .interfaces
                        .iter()
                        .map(|i| {
                            (
                                i.name.clone(),
                                MulticastIfaceDraft {
                                    role: i.role.clone(),
                                    igmp_version: i.igmp_version,
                                },
                            )
                        })
                        .collect(),
                })
                .unwrap_or_default(),
            bgp: a
                .protocols
                .bgp
                .as_ref()
                .map(bgp_to_draft)
                .unwrap_or_default(),
            prefix_lists: a
                .policy
                .prefix_lists
                .iter()
                .map(|pl| (pl.name.clone(), prefix_list_to_draft(pl)))
                .collect(),
            filters: a
                .policy
                .route_maps
                .iter()
                .map(|f| (f.name.clone(), filter_to_draft(f)))
                .collect(),
            import: a.protocols.import.clone(),
            export: a
                .protocols
                .export
                .as_ref()
                .map(|e| ExportDraft {
                    kernel: e.kernel.clone(),
                    bgp: e.bgp.clone(),
                    ospf: e.ospf.clone(),
                    rip: e.rip.clone(),
                    ripng: e.ripng.clone(),
                    babel: e.babel.clone(),
                    isis: e.isis.clone(),
                })
                .unwrap_or_default(),
            dns: DnsDraft {
                upstream: a.services.dns.upstream.clone(),
                serve_on: a.services.dns.serve_on.clone(),
                host_override: a.services.dns.host_override.clone(),
                blocklist: a.services.dns.blocklist.clone(),
                dnssec: a.services.dns.dnssec.clone(),
                cache_size: a.services.dns.cache_size,
                local_domain: a.services.dns.local_domain.clone(),
            },
            ntp: NtpDraft {
                upstream: a.services.ntp.upstream.clone(),
                serve_on: a.services.ntp.serve_on.clone(),
            },
            lldp: LldpDraft {
                enable: a.services.lldp.enable,
                interface: a.services.lldp.interface.clone(),
            },
            snmp: SnmpDraft {
                community: a.services.snmp.community.clone(),
                listen: a.services.snmp.listen.clone(),
                location: a.services.snmp.location.clone(),
                contact: a.services.snmp.contact.clone(),
                allow: a.services.snmp.allow.clone(),
            },
            mdns: MdnsDraft {
                interface: a.services.mdns.interface.clone(),
            },
            dyndns: DyndnsDraft {
                provider: a.services.dyndns.provider.clone(),
                server: a.services.dyndns.server.clone(),
                hostname: a.services.dyndns.hostname.clone(),
                login: a.services.dyndns.login.clone(),
                password: a.services.dyndns.password.clone(),
                interface: a.services.dyndns.interface.clone(),
            },
            dhcp_relay: DhcpRelayDraft {
                interface: a.services.dhcp_relay.interface.clone(),
                server: a.services.dhcp_relay.server.clone(),
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
            wireguard: a
                .vpn
                .wireguard
                .iter()
                .map(|t| {
                    (
                        t.name.clone(),
                        WgTunnelDraft {
                            private_key: Some(t.private_key.clone()),
                            listen_port: t.listen_port,
                            peers: t
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
                        },
                    )
                })
                .collect(),
            pki_cas: a
                .pki
                .cas
                .iter()
                .map(|c| {
                    (
                        c.name.clone(),
                        PkiCaDraft {
                            common_name: Some(c.common_name.clone()),
                            organization: c.organization.clone(),
                            key_type: c.key_type.clone(),
                            validity_days: c.validity_days,
                        },
                    )
                })
                .collect(),
            pki_certs: a
                .pki
                .certificates
                .iter()
                .map(|c| {
                    (
                        c.name.clone(),
                        PkiCertDraft {
                            ca: Some(c.ca.clone()),
                            common_name: Some(c.common_name.clone()),
                            subject_alt_names: c.subject_alt_names.clone(),
                            key_type: c.key_type.clone(),
                            usage: c.usage.clone(),
                            validity_days: c.validity_days,
                        },
                    )
                })
                .collect(),
            acme: a.pki.acme.as_ref().map(|c| AcmeDraft {
                email: Some(c.email.clone()),
                directory_url: c.directory_url.clone(),
                challenge: c.challenge.clone(),
                agree_tos: c.agree_tos,
            }),
            openconnect: a.vpn.openconnect.as_ref().map(|oc| OpenConnectDraft {
                disabled: oc.disabled,
                port: oc.port,
                certificate: Some(oc.certificate.clone()),
                pool: Some(oc.pool.clone()),
                dns: oc.dns.clone(),
                routes: oc.routes.clone(),
                default_route: oc.default_route,
                zone: oc.zone.clone(),
                users: oc
                    .users
                    .iter()
                    .map(|u| {
                        (
                            u.name.clone(),
                            OcUserDraft {
                                password: Some(u.password.clone()),
                            },
                        )
                    })
                    .collect(),
            }),
            update: a.update.as_ref().map(|u| UpdateChannelDraft {
                url: Some(u.url.clone()),
                public_key: Some(u.public_key.clone()),
            }),
            reverse_proxy: a
                .services
                .reverse_proxy
                .iter()
                .map(|rp| {
                    (
                        rp.name.clone(),
                        ReverseProxyDraft {
                            disabled: rp.disabled.then_some(true),
                            port: rp.port,
                            certificate: rp.certificate.clone(),
                            backends: rp.backends.clone(),
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

    /// The reverse-proxy frontend names — completion offers these for
    /// `set/delete services reverse-proxy …`. Consumed by `repl.rs` once its
    /// completion table is wired for the C22 grammar (added separately).
    #[allow(dead_code)]
    pub fn reverse_proxy_names(&self) -> Vec<String> {
        self.draft.reverse_proxy.keys().cloned().collect()
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

    /// The declared route-map names — completion offers these for a BGP
    /// neighbour's / VRF's import/export, the redistribution maps and
    /// `delete policy route-map …`.
    pub fn filter_names(&self) -> Vec<String> {
        self.draft.filters.iter().map(|(n, _)| n.clone()).collect()
    }

    /// The declared prefix-list names — completion offers these for a route-map
    /// rule's `match prefix-list` and `delete policy prefix-list …`.
    pub fn prefix_list_names(&self) -> Vec<String> {
        self.draft
            .prefix_lists
            .iter()
            .map(|(n, _)| n.clone())
            .collect()
    }

    /// The declared VRF names — completion offers these for a per-protocol /
    /// static `vrf` value and `delete protocols vrf …`.
    pub fn vrf_names(&self) -> Vec<String> {
        self.draft.vrfs.iter().map(|(n, _)| n.clone()).collect()
    }

    /// The declared IPsec connection names — completion offers these for
    /// `set/delete vpn ipsec …`.
    pub fn ipsec_names(&self) -> Vec<String> {
        self.draft.ipsec.iter().map(|(n, _)| n.clone()).collect()
    }

    /// The declared PKI CA names — completion offers these for a certificate's
    /// `ca` value and `set/delete pki ca …`.
    pub fn pki_ca_names(&self) -> Vec<String> {
        self.draft.pki_cas.iter().map(|(n, _)| n.clone()).collect()
    }

    /// The declared PKI certificate names — completion offers these for
    /// `set/delete pki certificate …`.
    pub fn pki_certificate_names(&self) -> Vec<String> {
        self.draft
            .pki_certs
            .iter()
            .map(|(n, _)| n.clone())
            .collect()
    }

    /// The declared WireGuard tunnel names (keys of `[[vpn.wireguard]]`) —
    /// completion offers these for `set/delete vpn wireguard …`.
    pub fn wireguard_names(&self) -> Vec<String> {
        self.draft
            .wireguard
            .iter()
            .map(|(n, _)| n.clone())
            .collect()
    }

    /// `set <path...> <value>` — set one config node.
    pub fn set(&mut self, args: &[&str]) -> Result<()> {
        match args {
            // Host-wide settings.
            ["system", "hostname", v] => self.draft.hostname = Some((*v).to_string()),

            // Interfaces (incl. VLAN subinterfaces).
            // Bare `set interface <name>` just declares the node (a NIC with no
            // config yet — e.g. a bridge/bond member port that carries no address).
            ["interface", name] => {
                self.draft.iface_mut(name);
            }
            // A free-text description may contain spaces, so the tail is captured
            // and rejoined; `disabled` is a bool.
            ["interface", name, "description", rest @ ..] if !rest.is_empty() => {
                let desc = rest.join(" ");
                crate::config::validate_description(&desc)?;
                self.draft.iface_mut(name).description = Some(desc);
            }
            ["interface", name, "disabled", v] => {
                self.draft.iface_mut(name).disabled = Some(parse_bool(v)?);
            }
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

            // Per-port 802.1Q VLAN filtering (only on a member of a vlan-aware
            // bridge): a CSV of tagged ids, and a single untagged (PVID) id.
            ["interface", name, "vlan-tagged", v] => {
                let mut ids = Vec::new();
                for part in v.split(',') {
                    let id: u16 = part
                        .trim()
                        .parse()
                        .with_context(|| format!("invalid vlan id {part:?}"))?;
                    ids.push(id);
                }
                self.draft.iface_mut(name).vlan_tagged = ids;
            }
            ["interface", name, "vlan-untagged", v] => {
                self.draft.iface_mut(name).vlan_untagged = Some(
                    v.parse()
                        .with_context(|| format!("invalid vlan id {v:?}"))?,
                );
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
                for s in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    validate_ipv4(s)?;
                }
                append_csv(&mut self.draft.iface_mut(name).dhcp_mut().dns, v);
            }
            ["interface", name, "dhcp-server", "lease-time", v] => {
                // Accept a human duration (`12h`, `1h30m`) or bare seconds.
                let lease = parse_duration_secs(v)?;
                self.draft.iface_mut(name).dhcp_mut().lease_time = Some(lease);
            }
            ["interface", name, "dhcp-server", "default-router", v] => {
                validate_ipv4(v)?;
                self.draft.iface_mut(name).dhcp_mut().default_router = Some((*v).to_string());
            }
            ["interface", name, "dhcp-server", "domain", v] => {
                self.draft.iface_mut(name).dhcp_mut().domain = Some((*v).to_string());
            }
            // A static reservation: `static-mapping <name> mac <mac> ip <ip>` in
            // one line, or the mac/ip set separately (both filled by commit).
            [
                "interface",
                name,
                "dhcp-server",
                "static-mapping",
                lname,
                "mac",
                mac,
                "ip",
                ip,
            ] => {
                crate::config::validate_mac(mac)?;
                validate_ipv4(ip)?;
                let lease = self
                    .draft
                    .iface_mut(name)
                    .dhcp_mut()
                    .static_lease_mut(lname);
                lease.mac = Some((*mac).to_string());
                lease.ip = Some((*ip).to_string());
            }
            [
                "interface",
                name,
                "dhcp-server",
                "static-mapping",
                lname,
                "mac",
                mac,
            ] => {
                crate::config::validate_mac(mac)?;
                self.draft
                    .iface_mut(name)
                    .dhcp_mut()
                    .static_lease_mut(lname)
                    .mac = Some((*mac).to_string());
            }
            [
                "interface",
                name,
                "dhcp-server",
                "static-mapping",
                lname,
                "ip",
                ip,
            ] => {
                validate_ipv4(ip)?;
                self.draft
                    .iface_mut(name)
                    .dhcp_mut()
                    .static_lease_mut(lname)
                    .ip = Some((*ip).to_string());
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
                for p in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    crate::config::validate_ipv6_cidr(p)?;
                }
                append_csv(&mut self.draft.iface_mut(name).ra_mut().prefixes, v);
            }
            ["interface", name, "router-advert", "dns", v] => {
                for s in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    validate_ipv6(s)?;
                }
                append_csv(&mut self.draft.iface_mut(name).ra_mut().dns, v);
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

            // Bridge / bond / wireguard: `type` makes this a virtual device;
            // `member` enslaves a NIC to a bridge/bond (repeatable → appends);
            // `bond-mode` sets a bond's aggregation mode; `vlan-aware` turns on
            // 802.1Q filtering on a bridge.
            ["interface", name, "type", v] => {
                let ty = match *v {
                    "bridge" => IfaceType::Bridge,
                    "bond" => IfaceType::Bond,
                    "wireguard" => IfaceType::Wireguard,
                    "pppoe" => IfaceType::Pppoe,
                    "gre" => IfaceType::Gre,
                    "ipip" => IfaceType::Ipip,
                    "gretap" => IfaceType::Gretap,
                    "macvlan" => IfaceType::Macvlan,
                    other => {
                        bail!(
                            "interface type {other:?}: expected \"bridge\", \"bond\", \"wireguard\", \"pppoe\", \"gre\", \"ipip\", \"gretap\" or \"macvlan\""
                        )
                    }
                };
                self.draft.iface_mut(name).if_type = Some(ty);
            }
            ["interface", name, "member", v] => {
                let members = &mut self.draft.iface_mut(name).members;
                if !members.iter().any(|m| m == v) {
                    members.push((*v).to_string());
                }
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
            // 802.1ad QinQ tag protocol on a VLAN subinterface, and the MACVLAN
            // mode on a `type = macvlan` pseudo-NIC (roadmap C14). The cross-field
            // constraints (VLAN-only / macvlan-only) are enforced by `validate`.
            ["interface", name, "vlan-protocol", v] => {
                if !matches!(*v, "802.1q" | "802.1ad") {
                    bail!("vlan-protocol {v:?}: expected \"802.1q\" or \"802.1ad\"");
                }
                self.draft.iface_mut(name).vlan_protocol = Some((*v).to_string());
            }
            ["interface", name, "macvlan-mode", v] => {
                if !matches!(*v, "bridge" | "private" | "vepa" | "passthru") {
                    bail!(
                        "macvlan-mode {v:?}: expected \"bridge\", \"private\", \"vepa\" or \"passthru\""
                    );
                }
                self.draft.iface_mut(name).macvlan_mode = Some((*v).to_string());
            }
            ["interface", name, "vlan-aware", v] => {
                self.draft.iface_mut(name).vlan_aware = Some(parse_bool(v)?);
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
            ["firewall", "zone", name, "description", rest @ ..] if !rest.is_empty() => {
                let desc = rest.join(" ");
                crate::config::validate_description(&desc)?;
                self.draft.zone_mut(name).description = Some(desc);
            }
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
            ["firewall", "rule", name, "description", rest @ ..] if !rest.is_empty() => {
                let desc = rest.join(" ");
                crate::config::validate_description(&desc)?;
                self.draft.rule_mut(name).description = Some(desc);
            }
            ["firewall", "rule", name, "disabled", v] => {
                self.draft.rule_mut(name).disabled = Some(parse_bool(v)?)
            }
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
                let list = self
                    .draft
                    .groups
                    .address
                    .entry((*name).to_string())
                    .or_default();
                append_csv(list, v);
            }
            ["firewall", "group", "port-group", name, "port", v] => {
                let list = self
                    .draft
                    .groups
                    .port
                    .entry((*name).to_string())
                    .or_default();
                for tok in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    let spec = PortSpec::parse(tok)?;
                    if !list.contains(&spec) {
                        list.push(spec);
                    }
                }
            }

            // --- nat { … } — address translation, its own top-level node ---

            // nat source <name>: masquerade (SNAT) a zone's outbound traffic.
            ["nat", "source", name, "description", rest @ ..] if !rest.is_empty() => {
                let desc = rest.join(" ");
                crate::config::validate_description(&desc)?;
                self.draft.nat_source_mut(name).description = Some(desc);
            }
            ["nat", "source", name, "disabled", v] => {
                self.draft.nat_source_mut(name).disabled = Some(parse_bool(v)?)
            }
            ["nat", "source", name, "zone", v] => {
                self.draft.nat_source_mut(name).zone = Some((*v).to_string())
            }

            // nat destination <name>: inbound DNAT port-forward.
            ["nat", "destination", name, "description", rest @ ..] if !rest.is_empty() => {
                let desc = rest.join(" ");
                crate::config::validate_description(&desc)?;
                self.draft.nat_destination_mut(name).description = Some(desc);
            }
            ["nat", "destination", name, "disabled", v] => {
                self.draft.nat_destination_mut(name).disabled = Some(parse_bool(v)?)
            }
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

            // nat nat64: stateful IPv6→IPv4 translation (tayga) + DNS64 (unbound).
            // A single-instance sub-tree (no name key). Deep validation (prefix /96,
            // pool CIDR, interface declared) runs at materialize time.
            ["nat", "nat64", "enabled", v] => self.draft.nat64.enabled = Some(parse_bool(v)?),
            ["nat", "nat64", "prefix", v] => self.draft.nat64.prefix = Some((*v).to_string()),
            ["nat", "nat64", "pool", v] => self.draft.nat64.pool = Some((*v).to_string()),
            ["nat", "nat64", "interface", v] => self.draft.nat64.interface = Some((*v).to_string()),
            ["nat", "nat64", "dns64", v] => self.draft.nat64.dns64 = Some(parse_bool(v)?),

            // services dns: the box-wide LAN DNS forwarder (systemd-resolved).
            ["services", "dns", "upstream", v] => {
                for u in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    if validate_ipv4(u).is_err() && validate_ipv6(u).is_err() {
                        bail!("services dns upstream {u:?}: not an IPv4 or IPv6 address");
                    }
                }
                append_csv(&mut self.draft.dns.upstream, v);
            }
            ["services", "dns", "serve-on", v] => {
                append_csv(&mut self.draft.dns.serve_on, v);
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
            ["services", "dns", "cache-size", v] => {
                self.draft.dns.cache_size = Some(
                    v.parse()
                        .with_context(|| format!("invalid cache-size {v:?}"))?,
                );
            }
            ["services", "dns", "local-domain", v] => {
                self.draft.dns.local_domain = Some((*v).to_string());
            }

            // services ntp: the box-wide LAN NTP server (chrony).
            ["services", "ntp", "upstream", v] => {
                for u in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    crate::config::validate_host(u)?;
                }
                append_csv(&mut self.draft.ntp.upstream, v);
            }
            ["services", "ntp", "serve-on", v] => {
                append_csv(&mut self.draft.ntp.serve_on, v);
            }

            // services lldp: box-wide LLDP link-layer discovery (lldpd).
            ["services", "lldp", "enable", v] => {
                self.draft.lldp.enable = parse_bool(v)?;
            }
            ["services", "lldp", "interface", v] => {
                append_csv(&mut self.draft.lldp.interface, v);
            }

            // services snmp: box-wide read-only SNMP agent (net-snmp).
            ["services", "snmp", "community", v] => {
                self.draft.snmp.community = Some((*v).to_string());
            }
            ["services", "snmp", "listen", v] => {
                self.draft.snmp.listen = Some((*v).to_string());
            }
            // location/contact are free-form strings — absorb trailing words
            // (the `description` convention: `location rack 4`, unquoted).
            ["services", "snmp", "location", rest @ ..] if !rest.is_empty() => {
                self.draft.snmp.location = Some(rest.join(" "));
            }
            ["services", "snmp", "contact", rest @ ..] if !rest.is_empty() => {
                self.draft.snmp.contact = Some(rest.join(" "));
            }
            ["services", "snmp", "allow", v] => {
                for s in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    if crate::config::validate_cidr_or_ip(s).is_err()
                        && crate::config::validate_ipv6_cidr(s).is_err()
                    {
                        bail!("services snmp allow {s:?}: not an IPv4/IPv6 address or CIDR");
                    }
                }
                append_csv(&mut self.draft.snmp.allow, v);
            }

            // services mdns: box-wide mDNS reflector (avahi).
            ["services", "mdns", "interface", v] => {
                append_csv(&mut self.draft.mdns.interface, v);
            }

            // services dyndns: box-wide dynamic-DNS client (ddclient).
            ["services", "dyndns", "provider", v] => {
                self.draft.dyndns.provider = Some((*v).to_string());
            }
            ["services", "dyndns", "server", v] => {
                self.draft.dyndns.server = Some((*v).to_string());
            }
            ["services", "dyndns", "hostname", v] => {
                self.draft.dyndns.hostname = Some((*v).to_string());
            }
            ["services", "dyndns", "login", v] => {
                self.draft.dyndns.login = Some((*v).to_string());
            }
            ["services", "dyndns", "password", v] => {
                self.draft.dyndns.password = Some((*v).to_string());
            }
            ["services", "dyndns", "interface", v] => {
                self.draft.dyndns.interface = Some((*v).to_string());
            }

            // services dhcp-relay: box-wide DHCP relay agent (isc dhcrelay).
            ["services", "dhcp-relay", "interface", v] => {
                append_csv(&mut self.draft.dhcp_relay.interface, v);
            }
            ["services", "dhcp-relay", "server", v] => {
                for s in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    validate_ipv4(s)?;
                }
                append_csv(&mut self.draft.dhcp_relay.server, v);
            }

            // services reverse-proxy <name> (roadmap C22): the L7 TLS-terminating
            // load balancer (HAProxy). `backends` append+dedup (CSV) like the
            // other list fields; validation (port≠0/unique across frontends, cert
            // declared in pki, ≥1 `host:port` backend) runs at commit.
            ["services", "reverse-proxy", name, "port", v] => {
                let port: u16 = v.parse().with_context(|| format!("invalid port {v:?}"))?;
                if port == 0 {
                    bail!("port 0 is not valid");
                }
                self.draft.reverse_proxy_mut(name).port = Some(port);
            }
            ["services", "reverse-proxy", name, "certificate", v] => {
                self.draft.reverse_proxy_mut(name).certificate = Some((*v).to_string());
            }
            ["services", "reverse-proxy", name, "backends", v] => {
                append_csv(&mut self.draft.reverse_proxy_mut(name).backends, v);
            }
            ["services", "reverse-proxy", name, "disabled", v] => {
                self.draft.reverse_proxy_mut(name).disabled = Some(parse_bool(v)?);
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
                append_csv(&mut self.draft.bgp.network, v);
            }
            ["protocols", "bgp", "redistribute", v] => {
                append_csv(&mut self.draft.bgp.redistribute, v);
            }
            ["protocols", "bgp", "community", v] => {
                append_csv(&mut self.draft.bgp.community, v);
            }
            ["protocols", "bgp", "large-community", v] => {
                append_csv(&mut self.draft.bgp.large_community, v);
            }
            ["protocols", "bgp", "ext-community", v] => {
                append_csv(&mut self.draft.bgp.ext_community, v);
            }
            ["protocols", "bgp", "ebgp-require-policy", v] => {
                self.draft.bgp.ebgp_require_policy = parse_bool(v)?;
            }
            ["protocols", "bgp", "confederation", "id", v] => {
                self.draft.bgp.confederation_id =
                    Some(v.parse().with_context(|| format!("invalid AS {v:?}"))?);
            }
            ["protocols", "bgp", "confederation", "member", v] => {
                for tok in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    let asn: u32 = tok.parse().with_context(|| format!("invalid AS {tok:?}"))?;
                    if !self.draft.bgp.confederation_members.contains(&asn) {
                        self.draft.bgp.confederation_members.push(asn);
                    }
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
            // A neighbour description may contain spaces, so its tail is
            // captured and rejoined (like interface/rule descriptions).
            [
                "protocols",
                "bgp",
                "neighbor",
                addr,
                "description",
                rest @ ..,
            ] if !rest.is_empty() => {
                let desc = rest.join(" ");
                crate::config::validate_description(&desc)?;
                self.draft.bgp_neighbor_mut(addr).description = Some(desc);
            }
            ["protocols", "bgp", "neighbor", addr, field, v] => {
                self.set_neighbor_field(addr, field, v)?;
            }
            // Routing policy (VyOS `[policy]`): prefix-lists + route-maps. A
            // prefix-list entry is `prefix`/`ge`/`le`; a route-map rule has an
            // `action` plus `match`/`set` clauses. `permit`/`deny` map to the
            // stored `accept`/`reject`.
            ["policy", "prefix-list", name, "rule", n, field, v] => {
                let seq = n
                    .parse()
                    .with_context(|| format!("invalid rule seq {n:?}"))?;
                self.set_prefix_list_entry(name, seq, field, v)?;
            }
            ["policy", "route-map", name, "default", v] => {
                self.draft.filter_mut(name).default = Some(permit_deny_to_action(v)?);
            }
            ["policy", "route-map", name, "rule", n, "action", v] => {
                let seq = n
                    .parse()
                    .with_context(|| format!("invalid rule seq {n:?}"))?;
                self.draft.filter_mut(name).rule_mut(seq).action = Some(permit_deny_to_action(v)?);
            }
            ["policy", "route-map", name, "rule", n, "match", field, v] => {
                let seq = n
                    .parse()
                    .with_context(|| format!("invalid rule seq {n:?}"))?;
                self.set_route_map_match(name, seq, field, v)?;
            }
            ["policy", "route-map", name, "rule", n, "set", field, v] => {
                let seq = n
                    .parse()
                    .with_context(|| format!("invalid rule seq {n:?}"))?;
                self.set_route_map_set(name, seq, field, v)?;
            }
            ["protocols", "ospf", "interface", v] => {
                append_csv(&mut self.draft.ospf.interfaces, v);
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
                append_csv(&mut self.draft.ospf.redistribute, v);
            }

            // ospf3 (OSPFv3, IPv6) — same fields as ospf.
            ["protocols", "ospf3", "interface", v] => {
                append_csv(&mut self.draft.ospf3.interfaces, v);
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
                append_csv(&mut self.draft.ospf3.redistribute, v);
            }

            // rip / ripng / babel — same knobs (RipDraft).
            [
                "protocols",
                proto @ ("rip" | "ripng" | "babel"),
                "interface",
                v,
            ] => {
                append_csv(&mut self.draft.rip_family_mut(proto).interfaces, v);
            }
            [
                "protocols",
                proto @ ("rip" | "ripng" | "babel"),
                "redistribute",
                v,
            ] => {
                append_csv(&mut self.draft.rip_family_mut(proto).redistribute, v);
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
                append_csv(&mut self.draft.isis.interfaces, v);
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
                append_csv(&mut self.draft.isis.redistribute, v);
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
                append_csv(&mut self.draft.vrrp_mut(name).virtual_address, v);
            }

            // static route VRF placement.
            ["protocols", "static", prefix, "vrf", v] => {
                self.draft.static_mut(prefix).vrf = Some((*v).to_string());
            }

            // bgp VRF placement.
            ["protocols", "bgp", "vrf", v] => {
                self.draft.bgp.vrf = Some((*v).to_string());
            }

            // ospf / ospf3 additional fields (per-interface areas, timers, auth,
            // area types, graceful-restart, bfd, vrf). `proto` selects the draft.
            [
                "protocols",
                proto @ ("ospf" | "ospf3"),
                "interface",
                name,
                "area",
                id,
            ] => {
                *self.draft.ospf_family_mut(proto).interface_area_mut(name) =
                    Some((*id).to_string());
            }
            [
                "protocols",
                proto @ ("ospf" | "ospf3"),
                "router-priority",
                v,
            ] => {
                self.draft.ospf_family_mut(proto).router_priority = Some(
                    v.parse()
                        .with_context(|| format!("invalid priority {v:?}"))?,
                );
            }
            [
                "protocols",
                proto @ ("ospf" | "ospf3"),
                "redistribute-metric",
                v,
            ] => {
                self.draft.ospf_family_mut(proto).redistribute_metric =
                    Some(v.parse().with_context(|| format!("invalid metric {v:?}"))?);
            }
            ["protocols", proto @ ("ospf" | "ospf3"), "bfd", v] => {
                self.draft.ospf_family_mut(proto).bfd = parse_bool(v)?;
            }
            ["protocols", "ospf3", "instance-id", v] => {
                self.draft.ospf3.instance_id = Some(
                    v.parse()
                        .with_context(|| format!("invalid instance-id {v:?}"))?,
                );
            }
            ["protocols", "ospf", "passive-interface", v] => {
                append_csv(&mut self.draft.ospf.passive_interfaces, v);
            }
            [
                "protocols",
                "ospf",
                field @ ("stub-area"
                | "nssa-area"
                | "totally-stubby-area"
                | "totally-nssa-area"
                | "nssa-default-area"),
                v,
            ] => {
                let d = &mut self.draft.ospf;
                let set = match *field {
                    "stub-area" => &mut d.stub_areas,
                    "nssa-area" => &mut d.nssa_areas,
                    "totally-stubby-area" => &mut d.totally_stubby_areas,
                    "totally-nssa-area" => &mut d.totally_nssa_areas,
                    _ => &mut d.nssa_default_areas,
                };
                append_csv(set, v);
            }
            ["protocols", "ospf", "stub-default-cost", v] => {
                self.draft.ospf.stub_default_cost =
                    Some(v.parse().with_context(|| format!("invalid cost {v:?}"))?);
            }
            ["protocols", "ospf", "auth-type", v] => {
                self.draft.ospf.auth_type = Some((*v).to_string());
            }
            ["protocols", "ospf", "auth-key", v] => {
                self.draft.ospf.auth_key = Some((*v).to_string());
            }
            ["protocols", "ospf", "auth-key-id", v] => {
                self.draft.ospf.auth_key_id =
                    Some(v.parse().with_context(|| format!("invalid key-id {v:?}"))?);
            }
            ["protocols", "ospf", "auth-replay-protection", v] => {
                self.draft.ospf.auth_replay_protection = Some(parse_bool(v)?);
            }
            ["protocols", "ospf", "hello-interval", v] => {
                self.draft.ospf.hello_interval = Some(
                    v.parse()
                        .with_context(|| format!("invalid hello-interval {v:?}"))?,
                );
            }
            ["protocols", "ospf", "dead-interval", v] => {
                self.draft.ospf.dead_interval = Some(
                    v.parse()
                        .with_context(|| format!("invalid dead-interval {v:?}"))?,
                );
            }
            ["protocols", "ospf", "graceful-restart", v] => {
                self.draft.ospf.graceful_restart = parse_bool(v)?;
            }
            ["protocols", "ospf", "graceful-restart-period", v] => {
                self.draft.ospf.graceful_restart_period =
                    Some(v.parse().with_context(|| format!("invalid period {v:?}"))?);
            }
            ["protocols", "ospf", "vrf", v] => {
                self.draft.ospf.vrf = Some((*v).to_string());
            }

            // rip / babel extras (bfd, vrf); babel-only network / router-id.
            ["protocols", proto @ ("rip" | "babel"), "bfd", v] => {
                self.draft.rip_family_mut(proto).bfd = parse_bool(v)?;
            }
            ["protocols", proto @ ("rip" | "babel"), "vrf", v] => {
                self.draft.rip_family_mut(proto).vrf = Some((*v).to_string());
            }
            ["protocols", "babel", "network", v] => {
                append_csv(&mut self.draft.rip_family_mut("babel").network, v);
            }
            ["protocols", "babel", "router-id", v] => {
                self.draft.rip_family_mut("babel").router_id = Some((*v).to_string());
            }

            // isis additional fields.
            ["protocols", "isis", "priority", v] => {
                self.draft.isis.priority = Some(
                    v.parse()
                        .with_context(|| format!("invalid priority {v:?}"))?,
                );
            }
            ["protocols", "isis", "metric", v] => {
                self.draft.isis.metric =
                    Some(v.parse().with_context(|| format!("invalid metric {v:?}"))?);
            }
            ["protocols", "isis", "hello-interval", v] => {
                self.draft.isis.hello_interval = Some(
                    v.parse()
                        .with_context(|| format!("invalid hello-interval {v:?}"))?,
                );
            }
            ["protocols", "isis", "l2-to-l1-leaking", v] => {
                self.draft.isis.l2_to_l1_leaking = parse_bool(v)?;
            }
            ["protocols", "isis", "bfd", v] => {
                self.draft.isis.bfd = parse_bool(v)?;
            }
            ["protocols", "isis", "vrf", v] => {
                self.draft.isis.vrf = Some((*v).to_string());
            }

            // vrrp additional fields.
            ["protocols", "vrrp", name, "advert-interval", v] => {
                self.draft.vrrp_mut(name).advert_interval = Some(
                    v.parse()
                        .with_context(|| format!("invalid advert-interval {v:?}"))?,
                );
            }
            ["protocols", "vrrp", name, "preempt", v] => {
                self.draft.vrrp_mut(name).preempt = Some(parse_bool(v)?);
            }
            ["protocols", "vrrp", name, "prefix-length", v] => {
                self.draft.vrrp_mut(name).prefix_length = Some(
                    v.parse()
                        .with_context(|| format!("invalid prefix-length {v:?}"))?,
                );
            }
            ["protocols", "vrrp", name, "track-interface", v] => {
                append_csv(&mut self.draft.vrrp_mut(name).track_interfaces, v);
            }
            ["protocols", "vrrp", name, "priority-decrement", v] => {
                self.draft.vrrp_mut(name).priority_decrement = Some(
                    v.parse()
                        .with_context(|| format!("invalid priority-decrement {v:?}"))?,
                );
            }

            // bfd (global timing / authentication defaults).
            ["protocols", "bfd", field, v] => {
                let b = &mut self.draft.bfd;
                match *field {
                    "min-tx" => {
                        b.min_tx = Some(v.parse().with_context(|| format!("invalid ms {v:?}"))?)
                    }
                    "min-rx" => {
                        b.min_rx = Some(v.parse().with_context(|| format!("invalid ms {v:?}"))?)
                    }
                    "detect-mult" => {
                        b.detect_mult =
                            Some(v.parse().with_context(|| format!("invalid mult {v:?}"))?)
                    }
                    "auth-type" => b.auth_type = Some((*v).to_string()),
                    "auth-key-id" => {
                        b.auth_key_id =
                            Some(v.parse().with_context(|| format!("invalid key-id {v:?}"))?)
                    }
                    "auth-key" => b.auth_key = Some((*v).to_string()),
                    "echo" => b.echo = parse_bool(v)?,
                    "echo-interval" => {
                        b.echo_interval =
                            Some(v.parse().with_context(|| format!("invalid ms {v:?}"))?)
                    }
                    other => bail!("protocols bfd has no field {other:?}"),
                }
            }

            // multicast (IGMP/MLD querier + RFC 4605 proxy).
            ["protocols", "multicast", "interface", name, "role", v] => {
                self.draft.multicast.interface_mut(name).role = Some((*v).to_string());
            }
            [
                "protocols",
                "multicast",
                "interface",
                name,
                "igmp-version",
                v,
            ] => {
                self.draft.multicast.interface_mut(name).igmp_version = Some(
                    v.parse()
                        .with_context(|| format!("invalid igmp-version {v:?}"))?,
                );
            }
            ["protocols", "multicast", field, v] => {
                let m = &mut self.draft.multicast;
                match *field {
                    "enabled" => m.enabled = parse_bool(v)?,
                    "igmp" => m.igmp = Some(parse_bool(v)?),
                    "mld" => m.mld = Some(parse_bool(v)?),
                    "igmp-version" => {
                        m.igmp_version = Some(
                            v.parse()
                                .with_context(|| format!("invalid version {v:?}"))?,
                        )
                    }
                    "robustness" => {
                        m.robustness = Some(
                            v.parse()
                                .with_context(|| format!("invalid robustness {v:?}"))?,
                        )
                    }
                    "query-interval" => {
                        m.query_interval = Some(
                            v.parse()
                                .with_context(|| format!("invalid interval {v:?}"))?,
                        )
                    }
                    "query-response-interval" => {
                        m.query_response_interval = Some(
                            v.parse()
                                .with_context(|| format!("invalid interval {v:?}"))?,
                        )
                    }
                    other => bail!("protocols multicast has no field {other:?}"),
                }
            }

            // vrf (a named isolated routing table, keyed by name).
            ["protocols", "vrf", name, "interface", v] => {
                append_csv(&mut self.draft.vrf_mut(name).interfaces, v);
            }
            ["protocols", "vrf", name, field, v] => {
                let d = self.draft.vrf_mut(name);
                match *field {
                    "table" => {
                        d.table = Some(v.parse().with_context(|| format!("invalid table {v:?}"))?)
                    }
                    "rd" => d.rd = Some((*v).to_string()),
                    "import" => d.import = Some((*v).to_string()),
                    "export" => d.export = Some((*v).to_string()),
                    other => bail!("protocols vrf has no field {other:?}"),
                }
            }

            // global export redistribution filters (per consumer protocol).
            ["protocols", "export", proto, v] => {
                let e = &mut self.draft.export;
                let name = Some((*v).to_string());
                match *proto {
                    "kernel" => e.kernel = name,
                    "bgp" => e.bgp = name,
                    "ospf" => e.ospf = name,
                    "rip" => e.rip = name,
                    "ripng" => e.ripng = name,
                    "babel" => e.babel = name,
                    "isis" => e.isis = name,
                    other => bail!("protocols export has no protocol {other:?}"),
                }
            }
            // global per-protocol import filters (protocol → filter name).
            ["protocols", "import", proto, v] => {
                self.draft
                    .import
                    .insert((*proto).to_string(), (*v).to_string());
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

            // vpn wireguard (roadmap C1): keys + peers for a `type = "wireguard"`
            // interface, keyed by the interface name.
            ["vpn", "wireguard", name, "private-key", "generate"] => {
                let (private, public) = crate::wgkey::generate_keypair()?;
                self.draft.wireguard_mut(name).private_key = Some(private);
                // The operator needs the public key to hand to the far end.
                println!("generated wireguard key for {name}; public key: {public}");
            }
            ["vpn", "wireguard", name, "private-key", v] => {
                validate_wg_key(v)?;
                self.draft.wireguard_mut(name).private_key = Some((*v).to_string());
            }
            ["vpn", "wireguard", name, "listen-port", v] => {
                let port: u16 = v
                    .parse()
                    .with_context(|| format!("invalid listen-port {v:?}"))?;
                if port == 0 {
                    bail!("listen-port 0 is not valid");
                }
                self.draft.wireguard_mut(name).listen_port = Some(port);
            }
            ["vpn", "wireguard", name, "peer", pk, "allowed-ips", v] => {
                validate_wg_key(pk)?;
                for ip in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    validate_block_entry(ip)?;
                }
                append_csv(
                    &mut self.draft.wireguard_mut(name).peer_mut(pk).allowed_ips,
                    v,
                );
            }
            ["vpn", "wireguard", name, "peer", pk, "endpoint", v] => {
                validate_wg_key(pk)?;
                validate_endpoint(v)?;
                self.draft.wireguard_mut(name).peer_mut(pk).endpoint = Some((*v).to_string());
            }
            ["vpn", "wireguard", name, "peer", pk, "keepalive", v] => {
                validate_wg_key(pk)?;
                let k: u16 = v
                    .parse()
                    .with_context(|| format!("invalid keepalive {v:?}"))?;
                self.draft
                    .wireguard_mut(name)
                    .peer_mut(pk)
                    .persistent_keepalive = Some(k);
            }
            ["vpn", "wireguard", name, "peer", pk, "preshared-key", v] => {
                validate_wg_key(pk)?;
                validate_wg_key(v)?;
                self.draft.wireguard_mut(name).peer_mut(pk).preshared_key = Some((*v).to_string());
            }

            // vpn openconnect (roadmap C17): the single TLS road-warrior VPN
            // server. Deep validation (CIDR/IP formats, cert must name a declared
            // leaf, ≥1 user) lives in config `validate()` and runs at commit — here
            // we only shape the draft. `dns`/`routes` append+dedup like the other
            // list fields; users are keyed by login name.
            ["vpn", "openconnect", "certificate", v] => {
                self.draft.openconnect_mut().certificate = Some((*v).to_string());
            }
            ["vpn", "openconnect", "port", v] => {
                let port: u16 = v.parse().with_context(|| format!("invalid port {v:?}"))?;
                if port == 0 {
                    bail!("port 0 is not valid");
                }
                self.draft.openconnect_mut().port = Some(port);
            }
            ["vpn", "openconnect", "pool", v] => {
                self.draft.openconnect_mut().pool = Some((*v).to_string());
            }
            ["vpn", "openconnect", "dns", v] => {
                append_csv(&mut self.draft.openconnect_mut().dns, v);
            }
            ["vpn", "openconnect", "routes", v] => {
                append_csv(&mut self.draft.openconnect_mut().routes, v);
            }
            ["vpn", "openconnect", "default-route", v] => {
                self.draft.openconnect_mut().default_route = parse_bool(v)?;
            }
            ["vpn", "openconnect", "zone", v] => {
                self.draft.openconnect_mut().zone = Some((*v).to_string());
            }
            ["vpn", "openconnect", "disabled", v] => {
                self.draft.openconnect_mut().disabled = parse_bool(v)?;
            }
            ["vpn", "openconnect", "user", name, "password", v] => {
                self.draft
                    .openconnect_mut()
                    .users
                    .entry((*name).to_string())
                    .or_default()
                    .password = Some((*v).to_string());
            }

            // pki (roadmap C19): local CAs, issued certs, the ACME account.
            ["pki", "ca", name, "common-name", v] => {
                crate::config::validate_subject_component(v)?;
                self.draft.pki_ca_mut(name).common_name = Some((*v).to_string());
            }
            ["pki", "ca", name, "organization", v] => {
                crate::config::validate_subject_component(v)?;
                self.draft.pki_ca_mut(name).organization = Some((*v).to_string());
            }
            ["pki", "ca", name, "key-type", v] => {
                if !matches!(*v, "ec" | "rsa") {
                    bail!("invalid key-type {v:?} (expected ec|rsa)");
                }
                self.draft.pki_ca_mut(name).key_type = Some((*v).to_string());
            }
            ["pki", "ca", name, "validity-days", v] => {
                let n: u32 = v
                    .parse()
                    .with_context(|| format!("invalid validity-days {v:?}"))?;
                if n == 0 {
                    bail!("validity-days must be greater than 0");
                }
                self.draft.pki_ca_mut(name).validity_days = Some(n);
            }
            ["pki", "certificate", name, "ca", v] => {
                self.draft.pki_cert_mut(name).ca = Some((*v).to_string());
            }
            ["pki", "certificate", name, "common-name", v] => {
                crate::config::validate_subject_component(v)?;
                self.draft.pki_cert_mut(name).common_name = Some((*v).to_string());
            }
            ["pki", "certificate", name, "subject-alt-name", v] => {
                crate::config::validate_san(v)?;
                push_unique(&mut self.draft.pki_cert_mut(name).subject_alt_names, v);
            }
            ["pki", "certificate", name, "key-type", v] => {
                if !matches!(*v, "ec" | "rsa") {
                    bail!("invalid key-type {v:?} (expected ec|rsa)");
                }
                self.draft.pki_cert_mut(name).key_type = Some((*v).to_string());
            }
            ["pki", "certificate", name, "usage", v] => {
                if !matches!(*v, "server" | "client") {
                    bail!("invalid usage {v:?} (expected server|client)");
                }
                self.draft.pki_cert_mut(name).usage = Some((*v).to_string());
            }
            ["pki", "certificate", name, "validity-days", v] => {
                let n: u32 = v
                    .parse()
                    .with_context(|| format!("invalid validity-days {v:?}"))?;
                if n == 0 {
                    bail!("validity-days must be greater than 0");
                }
                self.draft.pki_cert_mut(name).validity_days = Some(n);
            }
            ["pki", "acme", "email", v] => {
                crate::config::validate_email(v)?;
                self.draft.acme_mut().email = Some((*v).to_string());
            }
            ["pki", "acme", "directory-url", v] => {
                crate::config::validate_https_url(v)?;
                self.draft.acme_mut().directory_url = Some((*v).to_string());
            }
            ["pki", "acme", "challenge", v] => {
                if !matches!(*v, "http-01" | "dns-01") {
                    bail!("invalid challenge {v:?} (expected http-01|dns-01)");
                }
                self.draft.acme_mut().challenge = Some((*v).to_string());
            }
            ["pki", "acme", "agree-tos", v] => {
                self.draft.acme_mut().agree_tos = Some(parse_bool(v)?);
            }

            // update (roadmap C13): the single signed update channel. `url` is a
            // single token; `public-key` may be a `file:<path>` ref or an inline
            // PEM whose whitespace-split tokens are rejoined. Format/PEM checks
            // live in config `validate()` and run at commit.
            ["update", "url", v] => {
                self.draft.update_mut().url = Some((*v).to_string());
            }
            ["update", "public-key", rest @ ..] if !rest.is_empty() => {
                self.draft.update_mut().public_key = Some(rest.join(" "));
            }

            _ => bail!(
                "unknown set path. The config tree (Tab/`?` explores each level):\n  \
                 set system hostname <name>\n  \
                 set interface <name> zone <zone>\n  \
                 set interface <name> address <dhcp|CIDR>\n  \
                 set interface <name> <parent <iface> | vlan <id>>  (or name it <parent>.<id> to infer)\n  \
                 set interface <name> type <bridge|bond|wireguard|pppoe|gre|ipip|gretap>\n  \
                 set interface <name> <member <nic> | bond-mode <m> | vlan-aware <bool>>\n  \
                 set interface <name> <vlan-tagged <id,...> | vlan-untagged <id>>  (port of a vlan-aware bridge)\n  \
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
                 set nat nat64 <enabled <true|false> | prefix <64:ff9b::/96> | pool <v4-cidr> | interface <if> | dns64 <true|false>>\n  \
                 set protocols router-id <ip>\n  \
                 set protocols static <prefix> <via <ip> | dev <if> | metric <n>>\n  \
                 set protocols bgp <local-as <n> | router-id <ip> | hold-time <n> | network <prefix> | redistribute <src> | community <c> | multipath <n>>\n  \
                 set protocols bgp <confederation id <n> | confederation member <n> | rpki reject-invalid <bool> | rpki rtr <host:port> | ebgp-require-policy <bool>>\n  \
                 set protocols bgp aggregate <prefix> summary-only <bool>\n  \
                 set protocols bgp neighbor <ip> <remote-as <n> | local-as <n> | update-source <ip> | ebgp-multihop <n> | description <text> | shutdown <bool> | hold-time <s> | passive <bool> | route-reflector-client <bool> | password <k> | ttl-security <n> | max-prefix <n> | role <r> | import <f> | export <f> | bfd <bool> | ...>\n  \
                 set policy prefix-list <name> rule <seq> <prefix <addr/len> | ge <n> | le <n>>\n  \
                 set policy route-map <name> default <permit|deny>\n  \
                 set policy route-map <name> rule <seq> <action <permit|deny> | match <prefix-list <name> | prefix <p> | protocol <p> | metric-le <n> | metric-ge <n>> | set <metric <n> | preference <n> | community <c> | add-community <c> | ...>>\n  \
                 set protocols ospf <interface <if> [area <id>] | area <id> | router-priority <n> | cost <n> | network-type <..> | passive-interface <if> | redistribute <src> | redistribute-metric <n> | stub-area <id> | nssa-area <id> | auth-type <none|text|md5> | auth-key <k> | hello-interval <n> | dead-interval <n> | graceful-restart <bool> | bfd <bool> | vrf <name>>\n  \
                 set protocols ospf3 <interface <if> [area <id>] | area <id> | router-priority <n> | cost <n> | network-type <..> | instance-id <n> | redistribute <src> | redistribute-metric <n> | bfd <bool>>\n  \
                 set protocols <rip|babel> <interface <if> | redistribute <src> | redistribute-metric <n> | bfd <bool> | vrf <name>>; babel also network <p> | router-id <ip>\n  \
                 set protocols ripng <interface <if> | redistribute <src> | redistribute-metric <n>>\n  \
                 set protocols isis <interface <if> | system-id <id> | area <id> | level <1|2|1-2> | priority <n> | metric <n> | hello-interval <n> | network-type <..> | redistribute <src> | l2-to-l1-leaking <bool> | bfd <bool> | vrf <name>>\n  \
                 set protocols vrrp <name> <interface <if> | vrid <n> | priority <n> | advert-interval <ms> | preempt <bool> | prefix-length <n> | track-interface <if> | priority-decrement <n> | virtual-address <ip>>\n  \
                 set protocols vrf <name> <table <n> | rd <v> | interface <if> | import <filter> | export <filter>>\n  \
                 set protocols bfd <min-tx <ms> | min-rx <ms> | detect-mult <n> | auth-type <t> | auth-key-id <n> | auth-key <k> | echo <bool> | echo-interval <ms>>\n  \
                 set protocols multicast <enabled <bool> | igmp <bool> | mld <bool> | igmp-version <2|3> | robustness <n> | query-interval <n> | query-response-interval <n> | interface <name> <role <querier|upstream|downstream> | igmp-version <n>>>\n  \
                 set protocols export <kernel|bgp|ospf|rip|ripng|babel|isis> <filter>\n  \
                 set protocols import <proto> <filter>\n  \
                 set protocols static <prefix> vrf <name>\n  \
                 set protocols bgp vrf <name>\n  \
                 set multiwan mode <failover|load-balance>\n  \
                 set multiwan uplink <if> <priority <n> | weight <n> | table <n> | gateway <ip|dhcp>>\n  \
                 set multiwan uplink <if> check <target <ip> | interval <n> | timeout <n> | fail <n> | rise <n>>\n  \
                 set vpn ipsec <name> <local <ip> | remote <ip> | local-subnet <cidr> | remote-subnet <cidr> | psk <key>>\n  \
                 set vpn ipsec <name> <ike-version <1|2> | ike-proposal <p> | esp-proposal <p> | local-id <id> | remote-id <id> | start-action <start|trap|none>>\n  \
                 set vpn wireguard <ifname> <private-key <key|generate> | listen-port <port>>\n  \
                 set vpn wireguard <ifname> peer <pubkey> <allowed-ips <cidr,...> | endpoint <host:port> | keepalive <s> | preshared-key <key>>\n  \
                 set pki ca <name> <common-name <cn> | organization <o> | key-type <ec|rsa> | validity-days <n>>\n  \
                 set pki certificate <name> <ca <ca-name|acme> | common-name <cn> | subject-alt-name <DNS:host|IP:addr> | key-type <ec|rsa> | usage <server|client> | validity-days <n>>\n  \
                 set pki acme <email <addr> | directory-url <https-url> | challenge <http-01|dns-01> | agree-tos <bool>>\n  \
                 set update <url <https-url|file-url> | public-key <PEM|file:path>>"
            ),
        }
        self.dirty = true;
        Ok(())
    }

    /// `delete <path...>` — remove a node or clear a field.
    /// Clear one field of an OSPF/OSPFv3 draft (both share [`OspfDraft`]).
    fn del_ospf_field(o: &mut OspfDraft, field: &str) -> Result<()> {
        match field {
            "interface" => {
                o.interfaces.clear();
                o.interface_areas.clear();
            }
            "area" => o.area = None,
            "router-priority" => o.router_priority = None,
            "cost" => o.cost = None,
            "network-type" => o.network_type = None,
            "passive-interface" => o.passive_interfaces.clear(),
            "redistribute" => o.redistribute.clear(),
            "redistribute-metric" => o.redistribute_metric = None,
            "stub-area" => o.stub_areas.clear(),
            "stub-default-cost" => o.stub_default_cost = None,
            "nssa-area" => o.nssa_areas.clear(),
            "totally-stubby-area" => o.totally_stubby_areas.clear(),
            "totally-nssa-area" => o.totally_nssa_areas.clear(),
            "nssa-default-area" => o.nssa_default_areas.clear(),
            "auth-type" => o.auth_type = None,
            "auth-key" => o.auth_key = None,
            "auth-key-id" => o.auth_key_id = None,
            "auth-replay-protection" => o.auth_replay_protection = None,
            "hello-interval" => o.hello_interval = None,
            "dead-interval" => o.dead_interval = None,
            "graceful-restart" => o.graceful_restart = false,
            "graceful-restart-period" => o.graceful_restart_period = None,
            "instance-id" => o.instance_id = None,
            "bfd" => o.bfd = false,
            "vrf" => o.vrf = None,
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
            "local-as" => n.local_as = None,
            "update-source" => n.update_source = None,
            "ebgp-multihop" => n.ebgp_multihop = None,
            "description" => n.description = None,
            "shutdown" => n.shutdown = false,
            "hold-time" => n.hold_time = None,
            other => bail!("bgp neighbor has no field {other:?}"),
        }
        Ok(())
    }

    /// Clear one `match` field of a route-map rule draft. `item`, if given,
    /// removes just that entry from a repeatable list (`match prefix`).
    fn del_route_map_match(r: &mut FilterRuleDraft, field: &str, item: Option<&str>) -> Result<()> {
        match field {
            "prefix-list" => r.match_prefix_list = None,
            "prefix" => del_from_list(&mut r.prefix, item, "match prefix")?,
            "protocol" => r.protocol = None,
            "metric-le" => r.metric_le = None,
            "metric-ge" => r.metric_ge = None,
            other => bail!("route-map match has no field {other:?}"),
        }
        Ok(())
    }

    /// Clear one `set` field of a route-map rule draft. `item`, if given, removes
    /// just that entry from a repeatable community list (`set add-community` …).
    fn del_route_map_set(r: &mut FilterRuleDraft, field: &str, item: Option<&str>) -> Result<()> {
        match field {
            "metric" => r.set_metric = None,
            "add-metric" => r.add_metric = None,
            "preference" => r.set_preference = None,
            "community" => del_from_list(&mut r.set_community, item, "set community")?,
            "add-community" => del_from_list(&mut r.add_community, item, "set add-community")?,
            "large-community" => {
                del_from_list(&mut r.set_large_community, item, "set large-community")?
            }
            "add-large-community" => {
                del_from_list(&mut r.add_large_community, item, "set add-large-community")?
            }
            "ext-community" => del_from_list(&mut r.set_ext_community, item, "set ext-community")?,
            "add-ext-community" => {
                del_from_list(&mut r.add_ext_community, item, "set add-ext-community")?
            }
            other => bail!("route-map set has no field {other:?}"),
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
            "local-as" => {
                n.local_as = Some(v.parse().with_context(|| format!("invalid AS {v:?}"))?)
            }
            "update-source" => n.update_source = Some(v.to_string()),
            "ebgp-multihop" => {
                n.ebgp_multihop = Some(
                    v.parse()
                        .with_context(|| format!("invalid ebgp-multihop {v:?}"))?,
                )
            }
            "description" => n.description = Some(v.to_string()),
            "shutdown" => n.shutdown = parse_bool(v)?,
            "hold-time" => {
                n.hold_time = Some(
                    v.parse()
                        .with_context(|| format!("invalid hold-time {v:?}"))?,
                )
            }
            other => bail!("bgp neighbor has no field {other:?}"),
        }
        Ok(())
    }

    /// Set one `match` field of route-map `name` rule `seq` (inserting either if
    /// new). Conditions are ANDed; `match prefix` appends (repeatable).
    fn set_route_map_match(&mut self, name: &str, seq: u32, field: &str, v: &str) -> Result<()> {
        let r = self.draft.filter_mut(name).rule_mut(seq);
        match field {
            "prefix-list" => r.match_prefix_list = Some(v.to_string()),
            "prefix" => append_csv(&mut r.prefix, v),
            "protocol" => r.protocol = Some(v.to_string()),
            "metric-le" => {
                r.metric_le = Some(v.parse().with_context(|| format!("invalid metric {v:?}"))?)
            }
            "metric-ge" => {
                r.metric_ge = Some(v.parse().with_context(|| format!("invalid metric {v:?}"))?)
            }
            other => bail!("route-map match has no field {other:?}"),
        }
        Ok(())
    }

    /// Set one `set` field of route-map `name` rule `seq` (inserting either if
    /// new). A bare `community` replaces the set; `add-community` appends — same
    /// distinction for large- and ext-communities.
    fn set_route_map_set(&mut self, name: &str, seq: u32, field: &str, v: &str) -> Result<()> {
        let r = self.draft.filter_mut(name).rule_mut(seq);
        match field {
            "metric" => {
                r.set_metric = Some(v.parse().with_context(|| format!("invalid metric {v:?}"))?)
            }
            "add-metric" => {
                r.add_metric = Some(v.parse().with_context(|| format!("invalid metric {v:?}"))?)
            }
            "preference" => {
                r.set_preference = Some(
                    v.parse()
                        .with_context(|| format!("invalid preference {v:?}"))?,
                )
            }
            "community" => append_csv(&mut r.set_community, v),
            "add-community" => append_csv(&mut r.add_community, v),
            "large-community" => append_csv(&mut r.set_large_community, v),
            "add-large-community" => append_csv(&mut r.add_large_community, v),
            "ext-community" => append_csv(&mut r.set_ext_community, v),
            "add-ext-community" => append_csv(&mut r.add_ext_community, v),
            other => bail!("route-map set has no field {other:?}"),
        }
        Ok(())
    }

    /// Set one field (`prefix`/`ge`/`le`) of prefix-list `name` entry `seq`
    /// (inserting either if new).
    fn set_prefix_list_entry(&mut self, name: &str, seq: u32, field: &str, v: &str) -> Result<()> {
        let e = self.draft.prefix_list_mut(name).entry_mut(seq);
        match field {
            "prefix" => e.prefix = Some(v.to_string()),
            "ge" => e.ge = Some(v.parse().with_context(|| format!("invalid ge {v:?}"))?),
            "le" => e.le = Some(v.parse().with_context(|| format!("invalid le {v:?}"))?),
            other => bail!("prefix-list rule has no field {other:?}"),
        }
        Ok(())
    }

    /// Existing rule `seq` of route-map `name`, for `delete` (never inserts).
    fn route_map_rule_mut(&mut self, name: &str, seq: u32) -> Result<&mut FilterRuleDraft> {
        let Some((_, f)) = self.draft.filters.iter_mut().find(|(n, _)| n == name) else {
            bail!("no route-map {name:?}");
        };
        let Some((_, r)) = f.rules.iter_mut().find(|(i, _)| *i == seq) else {
            bail!("no rule {seq} in route-map {name:?}");
        };
        Ok(r)
    }

    /// Existing prefix-list `name`, for `delete` (never inserts).
    fn prefix_list_draft_mut(&mut self, name: &str) -> Result<&mut PrefixListDraft> {
        self.draft
            .prefix_lists
            .iter_mut()
            .find(|(n, _)| n == name)
            .map(|(_, pl)| pl)
            .ok_or_else(|| anyhow::anyhow!("no prefix-list {name:?}"))
    }

    /// Existing entry `seq` of prefix-list `name`, for `delete` (never inserts).
    fn prefix_list_entry_mut(&mut self, name: &str, seq: u32) -> Result<&mut PrefixEntryDraft> {
        let pl = self.prefix_list_draft_mut(name)?;
        pl.entries
            .iter_mut()
            .find(|(i, _)| *i == seq)
            .map(|(_, e)| e)
            .ok_or_else(|| anyhow::anyhow!("no rule {seq} in prefix-list {name:?}"))
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
            ["interface", name, "description"] => self.iface(name)?.description = None,
            ["interface", name, "disabled"] => self.iface(name)?.disabled = None,
            ["interface", name, "address"] => self.iface(name)?.address = None,
            ["interface", name, "address6"] => self.iface(name)?.address6 = None,
            ["interface", name, "pd-from"] => self.iface(name)?.pd_from = None,
            ["interface", name, "pd-subnet"] => self.iface(name)?.pd_subnet = None,
            ["interface", name, "zone"] => self.iface(name)?.zone = None,
            ["interface", name, "parent"] => self.iface(name)?.parent = None,
            ["interface", name, "vlan"] => self.iface(name)?.vlan = None,
            ["interface", name, "type"] => self.iface(name)?.if_type = None,
            ["interface", name, "bond-mode"] => self.iface(name)?.bond_mode = None,
            ["interface", name, "vlan-protocol"] => self.iface(name)?.vlan_protocol = None,
            ["interface", name, "macvlan-mode"] => self.iface(name)?.macvlan_mode = None,
            ["interface", name, "vlan-aware"] => self.iface(name)?.vlan_aware = None,
            ["interface", name, "vlan-tagged"] => self.iface(name)?.vlan_tagged.clear(),
            ["interface", name, "vlan-untagged"] => self.iface(name)?.vlan_untagged = None,
            // `delete interface X member` clears all members; `... member <nic>`
            // removes one.
            ["interface", name, "member"] => self.iface(name)?.members.clear(),
            ["interface", name, "member", m] => {
                let i = self.iface(name)?;
                let before = i.members.len();
                i.members.retain(|x| x != m);
                if i.members.len() == before {
                    bail!("interface {name:?} has no member {m:?}");
                }
            }
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
            ["interface", name, "dhcp-server"] => self.iface(name)?.dhcp_server = None,
            // A single static reservation by name (before the catch-all field arm).
            ["interface", name, "dhcp-server", "static-mapping", lname] => {
                let i = self.iface(name)?;
                let Some(d) = i.dhcp_server.as_mut() else {
                    bail!("interface {name:?} has no dhcp-server");
                };
                let before = d.static_mappings.len();
                d.static_mappings.retain(|(n, _)| n != lname);
                if d.static_mappings.len() == before {
                    bail!("interface {name:?} dhcp-server has no static-mapping {lname:?}");
                }
            }
            // Remove one advertised DNS server (the whole list clears via the
            // `dns` field arm below).
            ["interface", name, "dhcp-server", "dns", v] => {
                let i = self.iface(name)?;
                let Some(d) = i.dhcp_server.as_mut() else {
                    bail!("interface {name:?} has no dhcp-server");
                };
                if !remove_item(&mut d.dns, v) {
                    bail!("interface {name:?} dhcp-server has no dns {v:?}");
                }
            }
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
                    "default-router" => d.default_router = None,
                    "domain" => d.domain = None,
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
                    "description" => z.description = None,
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
                    "description" => r.description = None,
                    "disabled" => r.disabled = None,
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
            ["nat", "source", name, field] => {
                let s = self.nat_source(name)?;
                match *field {
                    "zone" => s.zone = None,
                    "description" => s.description = None,
                    "disabled" => s.disabled = None,
                    other => bail!("nat source has no field {other:?}"),
                }
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
                    "description" => d.description = None,
                    "disabled" => d.disabled = None,
                    "zone" => d.zone = None,
                    "proto" => d.proto = None,
                    "port" => d.port = None,
                    "to" => d.to = None,
                    other => bail!("nat destination has no field {other:?}"),
                }
            }

            // nat nat64 — the whole sub-tree, or one field.
            ["nat", "nat64"] => self.draft.nat64 = Nat64Draft::default(),
            ["nat", "nat64", field] => {
                let n = &mut self.draft.nat64;
                match *field {
                    "enabled" => n.enabled = None,
                    "prefix" => n.prefix = None,
                    "pool" => n.pool = None,
                    "interface" => n.interface = None,
                    "dns64" => n.dns64 = None,
                    other => bail!("nat nat64 has no field {other:?}"),
                }
            }

            // services: box-wide offered services. Bare `delete services` clears
            // them all; `delete services dns`/`ntp` turns off just that one.
            ["services"] => {
                self.draft.dns = DnsDraft::default();
                self.draft.ntp = NtpDraft::default();
                self.draft.lldp = LldpDraft::default();
                self.draft.snmp = SnmpDraft::default();
                self.draft.mdns = MdnsDraft::default();
                self.draft.dyndns = DyndnsDraft::default();
                self.draft.dhcp_relay = DhcpRelayDraft::default();
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
                    "cache-size" => d.cache_size = None,
                    "local-domain" => d.local_domain = None,
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
            ["services", "lldp"] => self.draft.lldp = LldpDraft::default(),
            ["services", "lldp", field] => {
                let l = &mut self.draft.lldp;
                match *field {
                    "enable" => l.enable = false,
                    "interface" => l.interface.clear(),
                    other => bail!("services lldp has no field {other:?}"),
                }
            }
            ["services", "snmp"] => self.draft.snmp = SnmpDraft::default(),
            ["services", "snmp", field] => {
                let s = &mut self.draft.snmp;
                match *field {
                    "community" => s.community = None,
                    "listen" => s.listen = None,
                    "location" => s.location = None,
                    "contact" => s.contact = None,
                    "allow" => s.allow.clear(),
                    other => bail!("services snmp has no field {other:?}"),
                }
            }
            ["services", "mdns"] => self.draft.mdns = MdnsDraft::default(),
            ["services", "mdns", field] => {
                let m = &mut self.draft.mdns;
                match *field {
                    "interface" => m.interface.clear(),
                    other => bail!("services mdns has no field {other:?}"),
                }
            }
            ["services", "dyndns"] => self.draft.dyndns = DyndnsDraft::default(),
            ["services", "dyndns", field] => {
                let d = &mut self.draft.dyndns;
                match *field {
                    "provider" => d.provider = None,
                    "server" => d.server = None,
                    "hostname" => d.hostname = None,
                    "login" => d.login = None,
                    "password" => d.password = None,
                    "interface" => d.interface = None,
                    other => bail!("services dyndns has no field {other:?}"),
                }
            }
            ["services", "dhcp-relay"] => self.draft.dhcp_relay = DhcpRelayDraft::default(),
            ["services", "dhcp-relay", field] => {
                let r = &mut self.draft.dhcp_relay;
                match *field {
                    "interface" => r.interface.clear(),
                    "server" => r.server.clear(),
                    other => bail!("services dhcp-relay has no field {other:?}"),
                }
            }

            // services reverse-proxy <name> (roadmap C22): the whole frontend, one
            // backend, or a reset field.
            ["services", "reverse-proxy", name] => {
                if self.draft.reverse_proxy.remove(*name).is_none() {
                    bail!("no reverse-proxy frontend {name:?}");
                }
            }
            ["services", "reverse-proxy", name, "backends", v] => {
                let rp = self.reverse_proxy(name)?;
                if !remove_item(&mut rp.backends, v) {
                    bail!("reverse-proxy {name:?} has no backend {v:?}");
                }
            }
            ["services", "reverse-proxy", name, field] => {
                let rp = self.reverse_proxy(name)?;
                match *field {
                    "port" => rp.port = None,
                    "certificate" => rp.certificate = None,
                    "backends" => rp.backends.clear(),
                    "disabled" => rp.disabled = None,
                    other => bail!("services reverse-proxy has no field {other:?}"),
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
                self.draft.vrfs.clear();
                self.draft.bfd = BfdDraft::default();
                self.draft.multicast = MulticastDraft::default();
                self.draft.import.clear();
                self.draft.export = ExportDraft::default();
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
                    "vrf" => b.vrf = None,
                    other => bail!("bgp has no field {other:?}"),
                }
            }
            // Routing policy (VyOS `[policy]`): prefix-lists + route-maps.
            ["policy"] => {
                self.draft.prefix_lists.clear();
                self.draft.filters.clear();
            }
            ["policy", "prefix-list", name] => {
                let before = self.draft.prefix_lists.len();
                self.draft.prefix_lists.retain(|(n, _)| n != name);
                if self.draft.prefix_lists.len() == before {
                    bail!("no prefix-list {name:?}");
                }
            }
            ["policy", "prefix-list", name, "rule", n] => {
                let seq = parse_seq(n)?;
                let pl = self.prefix_list_draft_mut(name)?;
                let before = pl.entries.len();
                pl.entries.retain(|(i, _)| *i != seq);
                if pl.entries.len() == before {
                    bail!("no rule {seq} in prefix-list {name:?}");
                }
            }
            ["policy", "prefix-list", name, "rule", n, field] => {
                let seq = parse_seq(n)?;
                let e = self.prefix_list_entry_mut(name, seq)?;
                match *field {
                    "prefix" => e.prefix = None,
                    "ge" => e.ge = None,
                    "le" => e.le = None,
                    other => bail!("prefix-list rule has no field {other:?}"),
                }
            }
            ["policy", "route-map", name] => {
                let before = self.draft.filters.len();
                self.draft.filters.retain(|(n, _)| n != name);
                if self.draft.filters.len() == before {
                    bail!("no route-map {name:?}");
                }
            }
            ["policy", "route-map", name, "default"] => {
                match self.draft.filters.iter_mut().find(|(n, _)| n == name) {
                    Some((_, f)) => f.default = None,
                    None => bail!("no route-map {name:?}"),
                }
            }
            ["policy", "route-map", name, "rule", n] => {
                let seq = parse_seq(n)?;
                match self.draft.filters.iter_mut().find(|(fn_, _)| fn_ == name) {
                    Some((_, f)) => {
                        let before = f.rules.len();
                        f.rules.retain(|(i, _)| *i != seq);
                        if f.rules.len() == before {
                            bail!("no rule {seq} in route-map {name:?}");
                        }
                    }
                    None => bail!("no route-map {name:?}"),
                }
            }
            ["policy", "route-map", name, "rule", n, "action"] => {
                self.route_map_rule_mut(name, parse_seq(n)?)?.action = None;
            }
            ["policy", "route-map", name, "rule", n, "match", field] => {
                let r = self.route_map_rule_mut(name, parse_seq(n)?)?;
                Self::del_route_map_match(r, field, None)?;
            }
            ["policy", "route-map", name, "rule", n, "match", field, item] => {
                let r = self.route_map_rule_mut(name, parse_seq(n)?)?;
                Self::del_route_map_match(r, field, Some(item))?;
            }
            ["policy", "route-map", name, "rule", n, "set", field] => {
                let r = self.route_map_rule_mut(name, parse_seq(n)?)?;
                Self::del_route_map_set(r, field, None)?;
            }
            ["policy", "route-map", name, "rule", n, "set", field, item] => {
                let r = self.route_map_rule_mut(name, parse_seq(n)?)?;
                Self::del_route_map_set(r, field, Some(item))?;
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
                    "network" => d.network.clear(),
                    "router-id" => d.router_id = None,
                    "bfd" => d.bfd = false,
                    "vrf" => d.vrf = None,
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
                    "priority" => i.priority = None,
                    "metric" => i.metric = None,
                    "hello-interval" => i.hello_interval = None,
                    "network-type" => i.network_type = None,
                    "redistribute" => i.redistribute.clear(),
                    "redistribute-metric" => i.redistribute_metric = None,
                    "l2-to-l1-leaking" => i.l2_to_l1_leaking = false,
                    "bfd" => i.bfd = false,
                    "vrf" => i.vrf = None,
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
                    "advert-interval" => d.advert_interval = None,
                    "preempt" => d.preempt = None,
                    "prefix-length" => d.prefix_length = None,
                    "track-interface" => d.track_interfaces.clear(),
                    "priority-decrement" => d.priority_decrement = None,
                    "virtual-address" => d.virtual_address.clear(),
                    other => bail!("vrrp has no field {other:?}"),
                }
            }
            // static route per-field delete (currently only `vrf`).
            ["protocols", "static", prefix, "vrf"] => {
                match self.draft.statics.iter_mut().find(|(p, _)| p == prefix) {
                    Some((_, d)) => d.vrf = None,
                    None => bail!("no static route {prefix:?}"),
                }
            }
            // bfd global defaults.
            ["protocols", "bfd"] => self.draft.bfd = BfdDraft::default(),
            ["protocols", "bfd", field] => {
                let b = &mut self.draft.bfd;
                match *field {
                    "min-tx" => b.min_tx = None,
                    "min-rx" => b.min_rx = None,
                    "detect-mult" => b.detect_mult = None,
                    "auth-type" => b.auth_type = None,
                    "auth-key-id" => b.auth_key_id = None,
                    "auth-key" => b.auth_key = None,
                    "echo" => b.echo = false,
                    "echo-interval" => b.echo_interval = None,
                    other => bail!("protocols bfd has no field {other:?}"),
                }
            }
            // multicast.
            ["protocols", "multicast"] => self.draft.multicast = MulticastDraft::default(),
            ["protocols", "multicast", "interface", name] => {
                let before = self.draft.multicast.interfaces.len();
                self.draft.multicast.interfaces.retain(|(n, _)| n != name);
                if self.draft.multicast.interfaces.len() == before {
                    bail!("no multicast interface {name:?}");
                }
            }
            ["protocols", "multicast", "interface", name, field] => {
                match self
                    .draft
                    .multicast
                    .interfaces
                    .iter_mut()
                    .find(|(n, _)| n == name)
                {
                    Some((_, d)) => match *field {
                        "role" => d.role = None,
                        "igmp-version" => d.igmp_version = None,
                        other => bail!("multicast interface has no field {other:?}"),
                    },
                    None => bail!("no multicast interface {name:?}"),
                }
            }
            ["protocols", "multicast", field] => {
                let m = &mut self.draft.multicast;
                match *field {
                    "enabled" => m.enabled = false,
                    "igmp" => m.igmp = None,
                    "mld" => m.mld = None,
                    "igmp-version" => m.igmp_version = None,
                    "robustness" => m.robustness = None,
                    "query-interval" => m.query_interval = None,
                    "query-response-interval" => m.query_response_interval = None,
                    other => bail!("protocols multicast has no field {other:?}"),
                }
            }
            // vrf instances.
            ["protocols", "vrf", name] => {
                let before = self.draft.vrfs.len();
                self.draft.vrfs.retain(|(n, _)| n != name);
                if self.draft.vrfs.len() == before {
                    bail!("no vrf {name:?}");
                }
            }
            ["protocols", "vrf", name, field] => {
                match self.draft.vrfs.iter_mut().find(|(n, _)| n == name) {
                    Some((_, d)) => match *field {
                        "table" => d.table = None,
                        "rd" => d.rd = None,
                        "interface" => d.interfaces.clear(),
                        "import" => d.import = None,
                        "export" => d.export = None,
                        other => bail!("protocols vrf has no field {other:?}"),
                    },
                    None => bail!("no vrf {name:?}"),
                }
            }
            // global export / import redistribution filters.
            ["protocols", "export"] => self.draft.export = ExportDraft::default(),
            ["protocols", "export", proto] => {
                let e = &mut self.draft.export;
                match *proto {
                    "kernel" => e.kernel = None,
                    "bgp" => e.bgp = None,
                    "ospf" => e.ospf = None,
                    "rip" => e.rip = None,
                    "ripng" => e.ripng = None,
                    "babel" => e.babel = None,
                    "isis" => e.isis = None,
                    other => bail!("protocols export has no protocol {other:?}"),
                }
            }
            ["protocols", "import"] => self.draft.import.clear(),
            ["protocols", "import", proto] => {
                if self.draft.import.remove(*proto).is_none() {
                    bail!("no import filter for {proto:?}");
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

            // vpn ipsec (roadmap C2). Bare `delete vpn` clears every VPN tunnel
            // (ipsec + wireguard); the rest clear one connection or one of its
            // optional fields (the required endpoints/subnets/psk can only be
            // replaced, not cleared — delete the whole connection to remove them).
            ["vpn"] => {
                self.draft.ipsec.clear();
                self.draft.wireguard.clear();
            }
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

            // vpn wireguard (roadmap C1). `delete vpn wireguard` clears every
            // tunnel; `... <name>` one tunnel; `... <name> listen-port` an optional
            // field; `... <name> peer <pk>` one peer, or `... peer <pk> <field>` one
            // of its optional fields (private-key can only be replaced).
            ["vpn", "wireguard"] => self.draft.wireguard.clear(),
            ["vpn", "wireguard", name] => {
                let before = self.draft.wireguard.len();
                self.draft.wireguard.retain(|(n, _)| n != name);
                if self.draft.wireguard.len() == before {
                    bail!("no vpn wireguard tunnel {name:?}");
                }
            }
            ["vpn", "wireguard", name, "listen-port"] => {
                self.wireguard(name)?.listen_port = None;
            }
            ["vpn", "wireguard", name, "peer", pk] => {
                let t = self.wireguard(name)?;
                let before = t.peers.len();
                t.peers.retain(|(k, _)| k != pk);
                if t.peers.len() == before {
                    bail!("vpn wireguard {name:?} has no peer {pk:?}");
                }
            }
            ["vpn", "wireguard", name, "peer", pk, field] => {
                let t = self.wireguard(name)?;
                let Some(idx) = t.peers.iter().position(|(k, _)| k == pk) else {
                    bail!("vpn wireguard {name:?} has no peer {pk:?}");
                };
                let p = &mut t.peers[idx].1;
                match *field {
                    "allowed-ips" => p.allowed_ips.clear(),
                    "endpoint" => p.endpoint = None,
                    "keepalive" => p.persistent_keepalive = None,
                    "preshared-key" => p.preshared_key = None,
                    other => bail!("wireguard peer has no field {other:?}"),
                }
            }
            ["vpn", "wireguard", name, "private-key"] => bail!(
                "vpn wireguard {name:?}: private-key is required — delete the whole tunnel \
                 (`delete vpn wireguard {name}`) to remove it"
            ),

            // vpn openconnect (roadmap C17). Bare `delete vpn openconnect` removes
            // the whole server; a per-item `... dns <ip>` / `... routes <cidr>`
            // drops one entry; `... user <name>` one credential; any other
            // `... <field>` resets an optional field or clears a list. The
            // required `certificate`/`pool` can only be replaced — delete the
            // whole server to remove them.
            ["vpn", "openconnect"] => self.draft.openconnect = None,
            ["vpn", "openconnect", "dns", v] => {
                let oc = self.openconnect()?;
                if !remove_item(&mut oc.dns, v) {
                    bail!("vpn openconnect has no dns {v:?}");
                }
            }
            ["vpn", "openconnect", "routes", v] => {
                let oc = self.openconnect()?;
                if !remove_item(&mut oc.routes, v) {
                    bail!("vpn openconnect has no route {v:?}");
                }
            }
            ["vpn", "openconnect", "user", name] => {
                let oc = self.openconnect()?;
                if oc.users.remove(*name).is_none() {
                    bail!("vpn openconnect has no user {name:?}");
                }
            }
            ["vpn", "openconnect", field] => {
                let oc = self.openconnect()?;
                match *field {
                    "port" => oc.port = None,
                    "dns" => oc.dns.clear(),
                    "routes" => oc.routes.clear(),
                    "default-route" => oc.default_route = false,
                    "zone" => oc.zone = None,
                    "disabled" => oc.disabled = false,
                    "certificate" | "pool" => bail!(
                        "vpn openconnect: {field} is required — delete the whole server \
                         (`delete vpn openconnect`) to remove it"
                    ),
                    other => bail!("vpn openconnect has no field {other:?}"),
                }
            }

            // pki (roadmap C19). Bare `delete pki` clears the whole tree; the rest
            // clear one CA / cert / the ACME account or one of their optional
            // fields (the required common-name / ca can only be replaced — delete
            // the whole object to remove them).
            ["pki"] => {
                self.draft.pki_cas.clear();
                self.draft.pki_certs.clear();
                self.draft.acme = None;
            }
            ["pki", "ca"] => self.draft.pki_cas.clear(),
            ["pki", "ca", name] => {
                let before = self.draft.pki_cas.len();
                self.draft.pki_cas.retain(|(n, _)| n != name);
                if self.draft.pki_cas.len() == before {
                    bail!("no pki ca {name:?}");
                }
            }
            ["pki", "ca", name, field] => {
                let d = self.pki_ca(name)?;
                match *field {
                    "organization" => d.organization = None,
                    "key-type" => d.key_type = None,
                    "validity-days" => d.validity_days = None,
                    "common-name" => bail!(
                        "pki ca {name:?}: common-name is required — delete the whole CA \
                         (`delete pki ca {name}`) to remove it"
                    ),
                    other => bail!("pki ca has no field {other:?}"),
                }
            }
            ["pki", "certificate"] => self.draft.pki_certs.clear(),
            ["pki", "certificate", name] => {
                let before = self.draft.pki_certs.len();
                self.draft.pki_certs.retain(|(n, _)| n != name);
                if self.draft.pki_certs.len() == before {
                    bail!("no pki certificate {name:?}");
                }
            }
            ["pki", "certificate", name, "subject-alt-name", v] => {
                let d = self.pki_cert(name)?;
                let before = d.subject_alt_names.len();
                d.subject_alt_names.retain(|s| s != v);
                if d.subject_alt_names.len() == before {
                    bail!("pki certificate {name:?}: no subject-alt-name {v:?}");
                }
            }
            ["pki", "certificate", name, field] => {
                let d = self.pki_cert(name)?;
                match *field {
                    "subject-alt-name" => d.subject_alt_names.clear(),
                    "key-type" => d.key_type = None,
                    "usage" => d.usage = None,
                    "validity-days" => d.validity_days = None,
                    "ca" | "common-name" => bail!(
                        "pki certificate {name:?}: {field} is required — delete the whole \
                         certificate (`delete pki certificate {name}`) to remove it"
                    ),
                    other => bail!("pki certificate has no field {other:?}"),
                }
            }
            ["pki", "acme"] => self.draft.acme = None,
            ["pki", "acme", field] => {
                let Some(d) = self.draft.acme.as_mut() else {
                    bail!("no pki acme account configured");
                };
                match *field {
                    "directory-url" => d.directory_url = None,
                    "challenge" => d.challenge = None,
                    "agree-tos" => d.agree_tos = None,
                    "email" => bail!(
                        "pki acme: email is required — delete the whole account \
                         (`delete pki acme`) to remove it"
                    ),
                    other => bail!("pki acme has no field {other:?}"),
                }
            }

            // update (roadmap C13). Bare `delete update` removes the whole
            // channel; `... url` / `... public-key` clears one field (both are
            // required, so a lone remaining field fails commit — clear the block
            // to fully remove it).
            ["update"] => self.draft.update = None,
            ["update", field] => {
                let Some(d) = self.draft.update.as_mut() else {
                    bail!("no update channel configured");
                };
                match *field {
                    "url" => d.url = None,
                    "public-key" => d.public_key = None,
                    other => bail!("update has no field {other:?}"),
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

    fn reverse_proxy(&mut self, name: &str) -> Result<&mut ReverseProxyDraft> {
        self.draft
            .reverse_proxy
            .get_mut(name)
            .ok_or_else(|| anyhow::anyhow!("no reverse-proxy frontend {name:?}"))
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

    fn wireguard(&mut self, name: &str) -> Result<&mut WgTunnelDraft> {
        self.draft
            .wireguard
            .iter_mut()
            .find(|(n, _)| n == name)
            .map(|(_, d)| d)
            .ok_or_else(|| anyhow::anyhow!("no vpn wireguard tunnel {name:?}"))
    }

    fn openconnect(&mut self) -> Result<&mut OpenConnectDraft> {
        self.draft
            .openconnect
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("no vpn openconnect server"))
    }

    fn pki_ca(&mut self, name: &str) -> Result<&mut PkiCaDraft> {
        self.draft
            .pki_cas
            .iter_mut()
            .find(|(n, _)| n == name)
            .map(|(_, d)| d)
            .ok_or_else(|| anyhow::anyhow!("no pki ca {name:?}"))
    }

    fn pki_cert(&mut self, name: &str) -> Result<&mut PkiCertDraft> {
        self.draft
            .pki_certs
            .iter_mut()
            .find(|(n, _)| n == name)
            .map(|(_, d)| d)
            .ok_or_else(|| anyhow::anyhow!("no pki certificate {name:?}"))
    }

    /// Render the candidate in a readable, hierarchical (JunOS-curly) form.
    pub fn show(&self) -> String {
        render_draft(&self.draft, false)
    }

    /// Render the candidate scoped to one top-level section — the VyOS
    /// `show <path>` view. Unknown sections yield an error line.
    pub fn show_only(&self, section: &str) -> String {
        match section {
            "system" | "interface" | "interfaces" | "firewall" | "nat" | "protocols" | "policy"
            | "services" | "multiwan" | "vpn" | "pki" | "update" => {
                let out = render_draft_only(&self.draft, false, Some(section));
                if out.is_empty() {
                    format!("(no {section} configuration)\n")
                } else {
                    out
                }
            }
            other => format!(
                "error: unknown section {other:?} (system | interfaces | firewall | nat | protocols | policy | services | multiwan | vpn | pki | update)\n"
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
                description: d.description.clone(),
                disabled: d.disabled.unwrap_or(false),
                zone: d.zone.clone(),
                address: d.address.clone(),
                address6: d.address6.clone(),
                pd_from: d.pd_from.clone(),
                pd_subnet: d.pd_subnet,
                parent: d.parent.clone(),
                vlan: d.vlan,
                vlan_protocol: d.vlan_protocol.clone(),
                macvlan_mode: d.macvlan_mode.clone(),
                dhcp_server: d.dhcp_server.as_ref().map(|s| DhcpServer {
                    pool_offset: s.pool_offset,
                    pool_size: s.pool_size,
                    dns: s.dns.clone(),
                    lease_time: s.lease_time,
                    default_router: s.default_router.clone(),
                    domain: s.domain.clone(),
                    // A reservation missing its mac/ip becomes empty strings that
                    // `validate` rejects with a clear error (mirrors pppoe above).
                    static_mappings: s
                        .static_mappings
                        .iter()
                        .map(|(lname, l)| DhcpStaticLease {
                            name: lname.clone(),
                            mac: l.mac.clone().unwrap_or_default(),
                            ip: l.ip.clone().unwrap_or_default(),
                        })
                        .collect(),
                }),
                router_advert: d.router_advert.as_ref().map(|r| RouterAdvert {
                    prefixes: r.prefixes.clone(),
                    dns: r.dns.clone(),
                    managed: r.managed,
                    other_config: r.other_config,
                    router_lifetime: r.router_lifetime,
                }),
                if_type: d.if_type,
                members: d.members.clone(),
                bond_mode: d.bond_mode.clone(),
                vlan_aware: d.vlan_aware,
                vlan_tagged: d.vlan_tagged.clone(),
                vlan_untagged: d.vlan_untagged,
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
                    description: d.description.clone(),
                    disabled: d.disabled.unwrap_or(false),
                    from: d
                        .from
                        .clone()
                        .ok_or_else(|| anyhow::anyhow!("rule {name:?}: from not set"))?,
                    to: d.to.clone(),
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
                        description: z.description.clone(),
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
                    description: d.description.clone(),
                    disabled: d.disabled.unwrap_or(false),
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
                        description: d.description.clone(),
                        disabled: d.disabled.unwrap_or(false),
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
                vrf: d.vrf.clone(),
            })
            .collect();
        let bgp = if self.draft.bgp.is_empty() {
            None
        } else {
            Some(bgp_from_draft(&self.draft.bgp)?)
        };
        let ospf_interfaces = |o: &OspfDraft| {
            o.interface_areas
                .iter()
                .map(|(name, area)| OspfInterface {
                    name: name.clone(),
                    area: area.clone(),
                })
                .collect::<Vec<_>>()
        };
        let ospf = if self.draft.ospf.is_empty() {
            None
        } else {
            let o = &self.draft.ospf;
            Some(Ospf {
                interfaces: o.interfaces.clone(),
                interface: ospf_interfaces(o),
                area: o.area.clone(),
                router_priority: o.router_priority,
                cost: o.cost,
                network_type: o.network_type.clone(),
                passive_interfaces: o.passive_interfaces.clone(),
                redistribute: o.redistribute.clone(),
                redistribute_metric: o.redistribute_metric,
                stub_areas: o.stub_areas.clone(),
                stub_default_cost: o.stub_default_cost,
                nssa_areas: o.nssa_areas.clone(),
                totally_stubby_areas: o.totally_stubby_areas.clone(),
                totally_nssa_areas: o.totally_nssa_areas.clone(),
                nssa_default_areas: o.nssa_default_areas.clone(),
                auth_type: o.auth_type.clone(),
                auth_key: o.auth_key.clone(),
                auth_key_id: o.auth_key_id,
                auth_replay_protection: o.auth_replay_protection,
                hello_interval: o.hello_interval,
                dead_interval: o.dead_interval,
                graceful_restart: o.graceful_restart,
                graceful_restart_period: o.graceful_restart_period,
                bfd: o.bfd,
                vrf: o.vrf.clone(),
            })
        };
        let ospf3 = if self.draft.ospf3.is_empty() {
            None
        } else {
            let o = &self.draft.ospf3;
            Some(Ospf3 {
                interfaces: o.interfaces.clone(),
                interface: ospf_interfaces(o),
                area: o.area.clone(),
                router_priority: o.router_priority,
                cost: o.cost,
                network_type: o.network_type.clone(),
                instance_id: o.instance_id,
                redistribute: o.redistribute.clone(),
                redistribute_metric: o.redistribute_metric,
                bfd: o.bfd,
            })
        };
        let rip_from = |d: &RipDraft| Rip {
            interfaces: d.interfaces.clone(),
            redistribute: d.redistribute.clone(),
            redistribute_metric: d.redistribute_metric,
            network: d.network.clone(),
            router_id: d.router_id.clone(),
            bfd: d.bfd,
            vrf: d.vrf.clone(),
        };
        let rip = (!self.draft.rip.is_empty()).then(|| rip_from(&self.draft.rip));
        let ripng = (!self.draft.ripng.is_empty()).then(|| rip_from(&self.draft.ripng));
        let babel = (!self.draft.babel.is_empty()).then(|| rip_from(&self.draft.babel));
        let isis = if self.draft.isis.is_empty() {
            None
        } else {
            let i = &self.draft.isis;
            Some(Isis {
                interfaces: i.interfaces.clone(),
                system_id: i.system_id.clone(),
                area: i.area.clone(),
                level: i.level.clone(),
                priority: i.priority,
                metric: i.metric,
                hello_interval: i.hello_interval,
                network_type: i.network_type.clone(),
                redistribute: i.redistribute.clone(),
                redistribute_metric: i.redistribute_metric,
                l2_to_l1_leaking: i.l2_to_l1_leaking,
                bfd: i.bfd,
                vrf: i.vrf.clone(),
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
                    advert_interval: d.advert_interval,
                    preempt: d.preempt,
                    prefix_length: d.prefix_length,
                    track_interfaces: d.track_interfaces.clone(),
                    priority_decrement: d.priority_decrement,
                    virtual_address: d.virtual_address.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let vrfs = self
            .draft
            .vrfs
            .iter()
            .map(|(name, d)| {
                Ok(VrfDef {
                    name: name.clone(),
                    table: d
                        .table
                        .ok_or_else(|| anyhow::anyhow!("vrf {name:?}: table not set"))?,
                    rd: d.rd.clone(),
                    interfaces: d.interfaces.clone(),
                    import: d.import.clone(),
                    export: d.export.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let bfd = (!self.draft.bfd.is_empty()).then(|| {
            let b = &self.draft.bfd;
            Bfd {
                min_tx: b.min_tx,
                min_rx: b.min_rx,
                detect_mult: b.detect_mult,
                auth_type: b.auth_type.clone(),
                auth_key_id: b.auth_key_id,
                auth_key: b.auth_key.clone(),
                echo: b.echo,
                echo_interval: b.echo_interval,
            }
        });
        let multicast = (!self.draft.multicast.is_empty()).then(|| {
            let m = &self.draft.multicast;
            Multicast {
                enabled: m.enabled,
                igmp: m.igmp,
                mld: m.mld,
                igmp_version: m.igmp_version,
                robustness: m.robustness,
                query_interval: m.query_interval,
                query_response_interval: m.query_response_interval,
                interfaces: m
                    .interfaces
                    .iter()
                    .map(|(name, d)| MulticastInterface {
                        name: name.clone(),
                        role: d.role.clone(),
                        igmp_version: d.igmp_version,
                    })
                    .collect(),
            }
        });
        // Routing policy (VyOS `[policy]`): prefix-lists + route-maps live under
        // their own top-level node, not inside `protocols`.
        let prefix_lists = self
            .draft
            .prefix_lists
            .iter()
            .map(|(name, d)| prefix_list_from_draft(name, d))
            .collect::<Result<Vec<_>>>()?;
        let route_maps = self
            .draft
            .filters
            .iter()
            .map(|(name, d)| filter_from_draft(name, d))
            .collect::<Result<Vec<_>>>()?;
        let export = (!self.draft.export.is_empty()).then(|| {
            let e = &self.draft.export;
            Export {
                kernel: e.kernel.clone(),
                bgp: e.bgp.clone(),
                ospf: e.ospf.clone(),
                rip: e.rip.clone(),
                ripng: e.ripng.clone(),
                babel: e.babel.clone(),
                isis: e.isis.clone(),
            }
        });
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
            vrfs,
            bfd,
            multicast,
            import: self.draft.import.clone(),
            export,
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
            // WireGuard tunnels (roadmap C1). A missing private-key falls back to
            // an empty string so validation surfaces a clear "private-key is
            // required" rather than silently dropping a half-specified tunnel.
            wireguard: self
                .draft
                .wireguard
                .iter()
                .map(|(name, d)| WireguardTunnel {
                    name: name.clone(),
                    private_key: d.private_key.clone().unwrap_or_default(),
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
                })
                .collect(),
            // OpenConnect road-warrior server (roadmap C17). Required fields
            // (certificate/pool) fall back to empty strings so validation
            // surfaces a clear "X is required" message rather than silently
            // dropping a half-specified server. Users are emitted in name order
            // (the BTreeMap keys).
            openconnect: self.draft.openconnect.as_ref().map(|oc| OpenConnectServer {
                disabled: oc.disabled,
                port: oc.port,
                certificate: oc.certificate.clone().unwrap_or_default(),
                pool: oc.pool.clone().unwrap_or_default(),
                dns: oc.dns.clone(),
                routes: oc.routes.clone(),
                default_route: oc.default_route,
                zone: oc.zone.clone(),
                users: oc
                    .users
                    .iter()
                    .map(|(name, u)| OpenConnectUser {
                        name: name.clone(),
                        password: u.password.clone().unwrap_or_default(),
                    })
                    .collect(),
            }),
        };

        // pki (roadmap C19): local CAs, issued certs, the ACME account. Required
        // fields fall back to empty strings so validation surfaces a clear "X is
        // required" message rather than silently dropping a half-specified object.
        let pki = Pki {
            cas: self
                .draft
                .pki_cas
                .iter()
                .map(|(name, d)| Ca {
                    name: name.clone(),
                    common_name: d.common_name.clone().unwrap_or_default(),
                    organization: d.organization.clone(),
                    key_type: d.key_type.clone(),
                    validity_days: d.validity_days,
                })
                .collect(),
            certificates: self
                .draft
                .pki_certs
                .iter()
                .map(|(name, d)| Certificate {
                    name: name.clone(),
                    ca: d.ca.clone().unwrap_or_default(),
                    common_name: d.common_name.clone().unwrap_or_default(),
                    subject_alt_names: d.subject_alt_names.clone(),
                    key_type: d.key_type.clone(),
                    usage: d.usage.clone(),
                    validity_days: d.validity_days,
                })
                .collect(),
            acme: self.draft.acme.as_ref().map(|d| Acme {
                email: d.email.clone().unwrap_or_default(),
                directory_url: d.directory_url.clone(),
                challenge: d.challenge.clone(),
                agree_tos: d.agree_tos,
            }),
        };

        let mut appliance = Appliance {
            system: System { hostname },
            firewall,
            zones,
            interfaces,
            rules,
            nat: Nat {
                source: nat_source,
                destination: nat_destination,
                nat64: Nat64 {
                    enabled: self.draft.nat64.enabled.unwrap_or(false),
                    prefix: self.draft.nat64.prefix.clone(),
                    pool: self.draft.nat64.pool.clone(),
                    interface: self.draft.nat64.interface.clone(),
                    dns64: self.draft.nat64.dns64.unwrap_or(false),
                },
            },
            protocols,
            policy: Policy {
                prefix_lists,
                route_maps,
            },
            services: Services {
                dns: Dns {
                    upstream: self.draft.dns.upstream.clone(),
                    serve_on: self.draft.dns.serve_on.clone(),
                    host_override: self.draft.dns.host_override.clone(),
                    blocklist: self.draft.dns.blocklist.clone(),
                    dnssec: self.draft.dns.dnssec.clone(),
                    cache_size: self.draft.dns.cache_size,
                    local_domain: self.draft.dns.local_domain.clone(),
                },
                ntp: Ntp {
                    upstream: self.draft.ntp.upstream.clone(),
                    serve_on: self.draft.ntp.serve_on.clone(),
                },
                lldp: Lldp {
                    enable: self.draft.lldp.enable,
                    interface: self.draft.lldp.interface.clone(),
                },
                snmp: Snmp {
                    community: self.draft.snmp.community.clone(),
                    listen: self.draft.snmp.listen.clone(),
                    location: self.draft.snmp.location.clone(),
                    contact: self.draft.snmp.contact.clone(),
                    allow: self.draft.snmp.allow.clone(),
                },
                mdns: Mdns {
                    interface: self.draft.mdns.interface.clone(),
                },
                dyndns: Dyndns {
                    provider: self.draft.dyndns.provider.clone(),
                    server: self.draft.dyndns.server.clone(),
                    hostname: self.draft.dyndns.hostname.clone(),
                    login: self.draft.dyndns.login.clone(),
                    password: self.draft.dyndns.password.clone(),
                    interface: self.draft.dyndns.interface.clone(),
                },
                dhcp_relay: DhcpRelay {
                    interface: self.draft.dhcp_relay.interface.clone(),
                    server: self.draft.dhcp_relay.server.clone(),
                },
                // L7 reverse-proxy frontends (roadmap C22), name-ordered by the
                // BTreeMap key. `config::validate()` enforces port/cert/backend
                // rules — we just carry the draft across.
                reverse_proxy: self
                    .draft
                    .reverse_proxy
                    .iter()
                    .map(|(name, d)| ReverseProxy {
                        name: name.clone(),
                        disabled: d.disabled.unwrap_or(false),
                        port: d.port,
                        certificate: d.certificate.clone(),
                        backends: d.backends.clone(),
                    })
                    .collect(),
            },
            multiwan,
            vpn,
            pki,
            // Signed update channel (roadmap C13). A required field left unset
            // falls back to an empty string so `validate()` surfaces a clear "X
            // is required" rather than silently dropping a half-specified
            // channel; a block with neither field set materialises to None.
            update: self.draft.update.as_ref().and_then(|u| {
                if u.url.is_none() && u.public_key.is_none() {
                    None
                } else {
                    Some(UpdateChannel {
                        url: u.url.clone().unwrap_or_default(),
                        public_key: u.public_key.clone().unwrap_or_default(),
                    })
                }
            }),
        };
        // Fill inferred VLAN parent/vlan from `<parent>.<id>` names before
        // validating (mirrors `Appliance::from_toml`).
        appliance.normalize();
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
        // Archive only when saving the box's own config, not an ad-hoc
        // `save <path>` export.
        let written = persist_appliance(&appliance, &path, to.is_none())?;
        self.dirty = false;
        Ok(written)
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

/// Persist a validated appliance to `path` — the single save path shared by the
/// CLI `save` and the REST API `PUT /config`, so a config written through either
/// surface lands byte-identically (the "one config model" guarantee). Writes the
/// canonical TOML atomically (temp file + rename, which needs write only on the
/// directory, so it replaces a root-owned/read-only seed file cleanly and the
/// agent never sees a half-written config) and, when `archive` is set, records a
/// revision. Archiving is best-effort — a failed archive must never fail the
/// save that already landed.
pub fn persist_appliance(appliance: &Appliance, path: &Path, archive: bool) -> Result<PathBuf> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let toml = appliance.to_toml()?;
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, &toml).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("installing {}", path.display()))?;
    if archive {
        if let Err(e) = crate::archive::archive_config(path, &toml) {
            eprintln!("warning: could not archive this config revision: {e}");
        }
    }
    Ok(path.to_path_buf())
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
            && i.description.is_none()
            && i.disabled != Some(true)
            && i.zone.is_none()
            && i.address.is_none()
            && i.address6.is_none()
            && i.pd_from.is_none()
            && i.pd_subnet.is_none()
            && i.parent.is_none()
            && i.vlan.is_none()
            && i.vlan_protocol.is_none()
            && i.macvlan_mode.is_none()
            && i.dhcp_server.is_none()
            && i.router_advert.is_none()
            && i.if_type.is_none()
            && i.members.is_empty()
            && i.bond_mode.is_none()
            && i.vlan_aware.is_none()
            && i.vlan_tagged.is_empty()
            && i.vlan_untagged.is_none()
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
        if let Some(desc) = &i.description {
            out.push_str(&format!("    description {desc}\n"));
        }
        if i.disabled == Some(true) {
            out.push_str("    disabled true\n");
        }
        if let Some(ty) = i.if_type {
            let s = match ty {
                IfaceType::Bridge => "bridge",
                IfaceType::Bond => "bond",
                IfaceType::Wireguard => "wireguard",
                IfaceType::Pppoe => "pppoe",
                IfaceType::Gre => "gre",
                IfaceType::Ipip => "ipip",
                IfaceType::Gretap => "gretap",
                IfaceType::Macvlan => "macvlan",
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
        for m in &i.members {
            out.push_str(&format!("    member {m}\n"));
        }
        if let Some(mode) = &i.bond_mode {
            out.push_str(&format!("    bond-mode {mode}\n"));
        }
        if let Some(aware) = i.vlan_aware {
            out.push_str(&format!("    vlan-aware {aware}\n"));
        }
        if !i.vlan_tagged.is_empty() {
            let ids = i
                .vlan_tagged
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(",");
            out.push_str(&format!("    vlan-tagged {ids}\n"));
        }
        if let Some(u) = i.vlan_untagged {
            out.push_str(&format!("    vlan-untagged {u}\n"));
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
        if let Some(proto) = &i.vlan_protocol {
            out.push_str(&format!("    vlan-protocol {proto}\n"));
        }
        if let Some(mode) = &i.macvlan_mode {
            out.push_str(&format!("    macvlan-mode {mode}\n"));
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
            if let Some(gw) = &d.default_router {
                out.push_str(&format!("        default-router {gw}\n"));
            }
            if let Some(dom) = &d.domain {
                out.push_str(&format!("        domain {dom}\n"));
            }
            for (lname, l) in &d.static_mappings {
                out.push_str(&format!("        static-mapping {lname} {{\n"));
                if let Some(mac) = &l.mac {
                    out.push_str(&format!("            mac {mac}\n"));
                }
                if let Some(ip) = &l.ip {
                    out.push_str(&format!("            ip {ip}\n"));
                }
                out.push_str("        }\n");
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
        if let Some(desc) = &z.description {
            fwi.push_str(&format!("        description {desc}\n"));
        }
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
        if let Some(desc) = &r.description {
            fwi.push_str(&format!("        description {desc}\n"));
        }
        if r.disabled == Some(true) {
            fwi.push_str("        disabled true\n");
        }
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
        if let Some(desc) = &s.description {
            nati.push_str(&format!("        description {desc}\n"));
        }
        if s.disabled == Some(true) {
            nati.push_str("        disabled true\n");
        }
        if let Some(z) = &s.zone {
            nati.push_str(&format!("        zone {z}\n"));
        }
        nati.push_str("    }\n");
    }
    for (name, d) in &draft.nat_destination {
        nati.push_str(&format!("    destination {name} {{\n"));
        if let Some(desc) = &d.description {
            nati.push_str(&format!("        description {desc}\n"));
        }
        if d.disabled == Some(true) {
            nati.push_str("        disabled true\n");
        }
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
    // NAT64 + DNS64 (roadmap C10) — a single-instance sub-tree under nat.
    let n64 = &draft.nat64;
    if n64.enabled.is_some()
        || n64.prefix.is_some()
        || n64.pool.is_some()
        || n64.interface.is_some()
        || n64.dns64.is_some()
    {
        nati.push_str("    nat64 {\n");
        if n64.enabled == Some(true) {
            nati.push_str("        enabled true\n");
        }
        if let Some(p) = &n64.prefix {
            nati.push_str(&format!("        prefix {p}\n"));
        }
        if let Some(p) = &n64.pool {
            nati.push_str(&format!("        pool {p}\n"));
        }
        if let Some(i) = &n64.interface {
            nati.push_str(&format!("        interface {i}\n"));
        }
        if n64.dns64 == Some(true) {
            nati.push_str("        dns64 true\n");
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
        if let Some(vrf) = &s.vrf {
            proto.push_str(&format!("        vrf {vrf}\n"));
        }
        proto.push_str("    }\n");
    }
    if !draft.ospf.is_empty() {
        proto.push_str("    ospf {\n");
        render_ospf_body(&mut proto, &draft.ospf, false);
        proto.push_str("    }\n");
    }
    if !draft.ospf3.is_empty() {
        proto.push_str("    ospf3 {\n");
        render_ospf_body(&mut proto, &draft.ospf3, true);
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
        for net in &r.network {
            proto.push_str(&format!("        network {net}\n"));
        }
        if let Some(rid) = &r.router_id {
            proto.push_str(&format!("        router-id {rid}\n"));
        }
        for src in &r.redistribute {
            proto.push_str(&format!("        redistribute {src}\n"));
        }
        if let Some(m) = r.redistribute_metric {
            proto.push_str(&format!("        redistribute-metric {m}\n"));
        }
        if r.bfd {
            proto.push_str("        bfd true\n");
        }
        if let Some(vrf) = &r.vrf {
            proto.push_str(&format!("        vrf {vrf}\n"));
        }
        proto.push_str("    }\n");
    }
    if !draft.isis.is_empty() {
        let i = &draft.isis;
        proto.push_str("    isis {\n");
        if let Some(s) = &i.system_id {
            proto.push_str(&format!("        system-id {s}\n"));
        }
        if let Some(a) = &i.area {
            proto.push_str(&format!("        area {a}\n"));
        }
        if let Some(l) = &i.level {
            proto.push_str(&format!("        level {l}\n"));
        }
        for iface in &i.interfaces {
            proto.push_str(&format!("        interface {iface}\n"));
        }
        if let Some(p) = i.priority {
            proto.push_str(&format!("        priority {p}\n"));
        }
        if let Some(m) = i.metric {
            proto.push_str(&format!("        metric {m}\n"));
        }
        if let Some(h) = i.hello_interval {
            proto.push_str(&format!("        hello-interval {h}\n"));
        }
        if let Some(nt) = &i.network_type {
            proto.push_str(&format!("        network-type {nt}\n"));
        }
        for src in &i.redistribute {
            proto.push_str(&format!("        redistribute {src}\n"));
        }
        if let Some(m) = i.redistribute_metric {
            proto.push_str(&format!("        redistribute-metric {m}\n"));
        }
        if i.l2_to_l1_leaking {
            proto.push_str("        l2-to-l1-leaking true\n");
        }
        if i.bfd {
            proto.push_str("        bfd true\n");
        }
        if let Some(vrf) = &i.vrf {
            proto.push_str(&format!("        vrf {vrf}\n"));
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
        if let Some(a) = v.advert_interval {
            proto.push_str(&format!("        advert-interval {a}\n"));
        }
        if let Some(p) = v.preempt {
            proto.push_str(&format!("        preempt {p}\n"));
        }
        if let Some(pl) = v.prefix_length {
            proto.push_str(&format!("        prefix-length {pl}\n"));
        }
        for t in &v.track_interfaces {
            proto.push_str(&format!("        track-interface {t}\n"));
        }
        if let Some(pd) = v.priority_decrement {
            proto.push_str(&format!("        priority-decrement {pd}\n"));
        }
        for a in &v.virtual_address {
            proto.push_str(&format!("        virtual-address {a}\n"));
        }
        proto.push_str("    }\n");
    }
    if !draft.bfd.is_empty() {
        let b = &draft.bfd;
        proto.push_str("    bfd {\n");
        if let Some(v) = b.min_tx {
            proto.push_str(&format!("        min-tx {v}\n"));
        }
        if let Some(v) = b.min_rx {
            proto.push_str(&format!("        min-rx {v}\n"));
        }
        if let Some(v) = b.detect_mult {
            proto.push_str(&format!("        detect-mult {v}\n"));
        }
        if let Some(v) = &b.auth_type {
            proto.push_str(&format!("        auth-type {v}\n"));
        }
        if let Some(v) = b.auth_key_id {
            proto.push_str(&format!("        auth-key-id {v}\n"));
        }
        if let Some(v) = &b.auth_key {
            proto.push_str(&format!("        auth-key {v}\n"));
        }
        if b.echo {
            proto.push_str("        echo true\n");
        }
        if let Some(v) = b.echo_interval {
            proto.push_str(&format!("        echo-interval {v}\n"));
        }
        proto.push_str("    }\n");
    }
    if !draft.multicast.is_empty() {
        let m = &draft.multicast;
        proto.push_str("    multicast {\n");
        if m.enabled {
            proto.push_str("        enabled true\n");
        }
        if let Some(v) = m.igmp {
            proto.push_str(&format!("        igmp {v}\n"));
        }
        if let Some(v) = m.mld {
            proto.push_str(&format!("        mld {v}\n"));
        }
        if let Some(v) = m.igmp_version {
            proto.push_str(&format!("        igmp-version {v}\n"));
        }
        if let Some(v) = m.robustness {
            proto.push_str(&format!("        robustness {v}\n"));
        }
        if let Some(v) = m.query_interval {
            proto.push_str(&format!("        query-interval {v}\n"));
        }
        if let Some(v) = m.query_response_interval {
            proto.push_str(&format!("        query-response-interval {v}\n"));
        }
        for (name, d) in &m.interfaces {
            proto.push_str(&format!("        interface {name} {{\n"));
            if let Some(role) = &d.role {
                proto.push_str(&format!("            role {role}\n"));
            }
            if let Some(v) = d.igmp_version {
                proto.push_str(&format!("            igmp-version {v}\n"));
            }
            proto.push_str("        }\n");
        }
        proto.push_str("    }\n");
    }
    for (name, v) in &draft.vrfs {
        proto.push_str(&format!("    vrf {name} {{\n"));
        if let Some(t) = v.table {
            proto.push_str(&format!("        table {t}\n"));
        }
        if let Some(rd) = &v.rd {
            proto.push_str(&format!("        rd {rd}\n"));
        }
        for iface in &v.interfaces {
            proto.push_str(&format!("        interface {iface}\n"));
        }
        if let Some(f) = &v.import {
            proto.push_str(&format!("        import {f}\n"));
        }
        if let Some(f) = &v.export {
            proto.push_str(&format!("        export {f}\n"));
        }
        proto.push_str("    }\n");
    }
    if !draft.export.is_empty() {
        let e = &draft.export;
        proto.push_str("    export {\n");
        for (proto_name, name) in [
            ("kernel", &e.kernel),
            ("bgp", &e.bgp),
            ("ospf", &e.ospf),
            ("rip", &e.rip),
            ("ripng", &e.ripng),
            ("babel", &e.babel),
            ("isis", &e.isis),
        ] {
            if let Some(name) = name {
                proto.push_str(&format!("        {proto_name} {name}\n"));
            }
        }
        proto.push_str("    }\n");
    }
    for (proto_name, name) in &draft.import {
        proto.push_str(&format!("    import {proto_name} {name}\n"));
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
        if let Some(vrf) = &b.vrf {
            proto.push_str(&format!("        vrf {vrf}\n"));
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
    if want("protocols") && !proto.is_empty() {
        out.push_str("protocols {\n");
        out.push_str(&proto);
        out.push_str("}\n");
    }

    // policy: the routing-policy toolbox (VyOS `[policy]`), a top-level node —
    // prefix-lists then route-maps, each with VyOS `match`/`set` grouping.
    if want("policy") {
        let mut pol = String::new();
        for (name, d) in &draft.prefix_lists {
            render_prefix_list(&mut pol, name, d);
        }
        for (name, f) in &draft.filters {
            render_route_map(&mut pol, name, f);
        }
        if !pol.is_empty() {
            out.push_str("policy {\n");
            out.push_str(&pol);
            out.push_str("}\n");
        }
    }

    // services: box-wide offered services (dns, ntp), each nested one level.
    let d = &draft.dns;
    let n = &draft.ntp;
    let dns_set = !(d.upstream.is_empty()
        && d.serve_on.is_empty()
        && d.host_override.is_empty()
        && d.blocklist.is_empty()
        && d.dnssec.is_none()
        && d.cache_size.is_none()
        && d.local_domain.is_none());
    let ntp_set = !(n.upstream.is_empty() && n.serve_on.is_empty());
    let lldp = &draft.lldp;
    let snmp = &draft.snmp;
    let mdns = &draft.mdns;
    let dyndns = &draft.dyndns;
    let relay = &draft.dhcp_relay;
    let lldp_set = lldp.enable || !lldp.interface.is_empty();
    let snmp_set = snmp.community.is_some()
        || snmp.listen.is_some()
        || snmp.location.is_some()
        || snmp.contact.is_some()
        || !snmp.allow.is_empty();
    let mdns_set = !mdns.interface.is_empty();
    let dyndns_set = dyndns.provider.is_some()
        || dyndns.server.is_some()
        || dyndns.hostname.is_some()
        || dyndns.login.is_some()
        || dyndns.password.is_some()
        || dyndns.interface.is_some();
    let relay_set = !relay.interface.is_empty() || !relay.server.is_empty();
    let rproxy = &draft.reverse_proxy;
    let rproxy_set = !rproxy.is_empty();
    let any_service = dns_set
        || ntp_set
        || lldp_set
        || snmp_set
        || mdns_set
        || dyndns_set
        || relay_set
        || rproxy_set;
    if want("services") && any_service {
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
            if let Some(n) = d.cache_size {
                out.push_str(&format!("        cache-size {n}\n"));
            }
            if let Some(dom) = &d.local_domain {
                out.push_str(&format!("        local-domain {dom}\n"));
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
        if lldp_set {
            out.push_str("    lldp {\n");
            if lldp.enable {
                out.push_str("        enable true\n");
            }
            if !lldp.interface.is_empty() {
                out.push_str(&format!("        interface {}\n", lldp.interface.join(",")));
            }
            out.push_str("    }\n");
        }
        if snmp_set {
            out.push_str("    snmp {\n");
            if let Some(c) = &snmp.community {
                out.push_str(&format!("        community {c}\n"));
            }
            if let Some(l) = &snmp.listen {
                out.push_str(&format!("        listen {l}\n"));
            }
            if let Some(l) = &snmp.location {
                out.push_str(&format!("        location {l}\n"));
            }
            if let Some(c) = &snmp.contact {
                out.push_str(&format!("        contact {c}\n"));
            }
            if !snmp.allow.is_empty() {
                out.push_str(&format!("        allow {}\n", snmp.allow.join(",")));
            }
            out.push_str("    }\n");
        }
        if mdns_set {
            out.push_str("    mdns {\n");
            out.push_str(&format!("        interface {}\n", mdns.interface.join(",")));
            out.push_str("    }\n");
        }
        if dyndns_set {
            out.push_str("    dyndns {\n");
            if let Some(p) = &dyndns.provider {
                out.push_str(&format!("        provider {p}\n"));
            }
            if let Some(s) = &dyndns.server {
                out.push_str(&format!("        server {s}\n"));
            }
            if let Some(h) = &dyndns.hostname {
                out.push_str(&format!("        hostname {h}\n"));
            }
            if let Some(l) = &dyndns.login {
                out.push_str(&format!("        login {l}\n"));
            }
            if let Some(p) = &dyndns.password {
                out.push_str(&format!("        password {p}\n"));
            }
            if let Some(i) = &dyndns.interface {
                out.push_str(&format!("        interface {i}\n"));
            }
            out.push_str("    }\n");
        }
        if relay_set {
            out.push_str("    dhcp-relay {\n");
            if !relay.interface.is_empty() {
                out.push_str(&format!(
                    "        interface {}\n",
                    relay.interface.join(",")
                ));
            }
            if !relay.server.is_empty() {
                out.push_str(&format!("        server {}\n", relay.server.join(",")));
            }
            out.push_str("    }\n");
        }
        // reverse-proxy <name> { … } — L7 frontends, name-ordered (BTreeMap).
        for (name, rp) in rproxy {
            out.push_str(&format!("    reverse-proxy {name} {{\n"));
            if let Some(port) = rp.port {
                out.push_str(&format!("        port {port}\n"));
            }
            if let Some(cert) = &rp.certificate {
                out.push_str(&format!("        certificate {cert}\n"));
            }
            for backend in &rp.backends {
                out.push_str(&format!("        backends {backend}\n"));
            }
            if rp.disabled == Some(true) {
                out.push_str("        disabled true\n");
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

    // vpn { ipsec <name> { … } wireguard <name> { … } openconnect { … } } —
    // IKEv2 site-to-site IPsec (roadmap C2) + WireGuard tunnels (roadmap C1) +
    // the OpenConnect road-warrior server (roadmap C17).
    if want("vpn")
        && (!draft.ipsec.is_empty() || !draft.wireguard.is_empty() || draft.openconnect.is_some())
    {
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
        for (name, t) in &draft.wireguard {
            out.push_str(&format!("    wireguard {name} {{\n"));
            if let Some(pk) = &t.private_key {
                out.push_str(&format!("        private-key {pk}\n"));
                // Operators need the derived public key to hand to the far end.
                if let Ok(public) = crate::wgkey::public_from_private(pk) {
                    out.push_str(&format!("        # public-key {public}\n"));
                }
            }
            if let Some(port) = t.listen_port {
                out.push_str(&format!("        listen-port {port}\n"));
            }
            for (peer_pk, p) in &t.peers {
                out.push_str(&format!("        peer {peer_pk} {{\n"));
                if !p.allowed_ips.is_empty() {
                    out.push_str(&format!(
                        "            allowed-ips {}\n",
                        p.allowed_ips.join(",")
                    ));
                }
                if let Some(ep) = &p.endpoint {
                    out.push_str(&format!("            endpoint {ep}\n"));
                }
                if let Some(k) = p.persistent_keepalive {
                    out.push_str(&format!("            keepalive {k}\n"));
                }
                if let Some(psk) = &p.preshared_key {
                    out.push_str(&format!("            preshared-key {psk}\n"));
                }
                out.push_str("        }\n");
            }
            out.push_str("    }\n");
        }
        // openconnect { … } — the singleton TLS road-warrior server. Secrets
        // (user passwords) are shown verbatim, matching how wireguard private-key
        // and ipsec psk render above.
        if let Some(oc) = &draft.openconnect {
            out.push_str("    openconnect {\n");
            if oc.disabled {
                out.push_str("        disabled true\n");
            }
            if let Some(cert) = &oc.certificate {
                out.push_str(&format!("        certificate {cert}\n"));
            }
            if let Some(port) = oc.port {
                out.push_str(&format!("        port {port}\n"));
            }
            if let Some(pool) = &oc.pool {
                out.push_str(&format!("        pool {pool}\n"));
            }
            if !oc.dns.is_empty() {
                out.push_str(&format!("        dns {}\n", oc.dns.join(",")));
            }
            if !oc.routes.is_empty() {
                out.push_str(&format!("        routes {}\n", oc.routes.join(",")));
            }
            if oc.default_route {
                out.push_str("        default-route true\n");
            }
            if let Some(zone) = &oc.zone {
                out.push_str(&format!("        zone {zone}\n"));
            }
            for (name, u) in &oc.users {
                out.push_str(&format!("        user {name} {{\n"));
                if let Some(pw) = &u.password {
                    out.push_str(&format!("            password {pw}\n"));
                }
                out.push_str("        }\n");
            }
            out.push_str("    }\n");
        }
        out.push_str("}\n");
    }

    // pki { ca <name> { … } certificate <name> { … } acme { … } } — roadmap C19.
    if want("pki")
        && (!draft.pki_cas.is_empty() || !draft.pki_certs.is_empty() || draft.acme.is_some())
    {
        out.push_str("pki {\n");
        for (name, c) in &draft.pki_cas {
            out.push_str(&format!("    ca {name} {{\n"));
            if let Some(v) = &c.common_name {
                out.push_str(&format!("        common-name {v}\n"));
            }
            if let Some(v) = &c.organization {
                out.push_str(&format!("        organization {v}\n"));
            }
            if let Some(v) = &c.key_type {
                out.push_str(&format!("        key-type {v}\n"));
            }
            if let Some(v) = c.validity_days {
                out.push_str(&format!("        validity-days {v}\n"));
            }
            out.push_str("    }\n");
        }
        for (name, c) in &draft.pki_certs {
            out.push_str(&format!("    certificate {name} {{\n"));
            if let Some(v) = &c.ca {
                out.push_str(&format!("        ca {v}\n"));
            }
            if let Some(v) = &c.common_name {
                out.push_str(&format!("        common-name {v}\n"));
            }
            for san in &c.subject_alt_names {
                out.push_str(&format!("        subject-alt-name {san}\n"));
            }
            if let Some(v) = &c.key_type {
                out.push_str(&format!("        key-type {v}\n"));
            }
            if let Some(v) = &c.usage {
                out.push_str(&format!("        usage {v}\n"));
            }
            if let Some(v) = c.validity_days {
                out.push_str(&format!("        validity-days {v}\n"));
            }
            out.push_str("    }\n");
        }
        if let Some(a) = &draft.acme {
            out.push_str("    acme {\n");
            if let Some(v) = &a.email {
                out.push_str(&format!("        email {v}\n"));
            }
            if let Some(v) = &a.directory_url {
                out.push_str(&format!("        directory-url {v}\n"));
            }
            if let Some(v) = &a.challenge {
                out.push_str(&format!("        challenge {v}\n"));
            }
            if let Some(v) = a.agree_tos {
                out.push_str(&format!("        agree-tos {v}\n"));
            }
            out.push_str("    }\n");
        }
        out.push_str("}\n");
    }

    // update { … } — the signed update channel (roadmap C13). The pinned key is
    // shown verbatim, matching how wireguard private-key / ipsec psk render
    // (in practice it is a short `file:<path>` ref).
    if want("update") {
        if let Some(u) = &draft.update {
            out.push_str("update {\n");
            if let Some(url) = &u.url {
                out.push_str(&format!("    url {url}\n"));
            }
            if let Some(key) = &u.public_key {
                out.push_str(&format!("    public-key {key}\n"));
            }
            out.push_str("}\n");
        }
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

/// Append every comma-separated item in `v` to `list`, de-duplicating (an item
/// already present is not re-added). The shared `set … <field> <v[,v…]>` idiom
/// for a list that appends rather than replaces — a single value is just a CSV
/// of length one, so `set … <field> <one>` keeps working.
fn append_csv(list: &mut Vec<String>, v: &str) {
    for item in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if !list.iter().any(|e| e == item) {
            list.push(item.to_string());
        }
    }
}

/// Remove a single (trimmed) item from `list` — the `delete … <field> <v>`
/// counterpart of [`append_csv`]. Returns whether anything was removed, so the
/// caller can bail with "not present".
fn remove_item(list: &mut Vec<String>, v: &str) -> bool {
    let v = v.trim();
    let before = list.len();
    list.retain(|e| e != v);
    list.len() != before
}

/// Clear a repeatable draft list, or (when `item` is given) remove just that one
/// entry — the `delete … <field> [<item>]` shape shared by the route-map
/// `match`/`set` clear helpers. Bails if a named `item` is not present.
fn del_from_list(list: &mut Vec<String>, item: Option<&str>, what: &str) -> Result<()> {
    match item {
        Some(v) => {
            if !remove_item(list, v) {
                bail!("no {what} {v:?}");
            }
        }
        None => list.clear(),
    }
    Ok(())
}

/// Parse a VyOS rule/entry sequence number token.
fn parse_seq(n: &str) -> Result<u32> {
    n.parse().with_context(|| format!("invalid rule seq {n:?}"))
}

/// Map the CLI's `permit`/`deny` route-map action to the stored `accept`/`reject`
/// (what config/Wren expect). Accepts the stored spellings too, so a config
/// loaded from disk round-trips.
fn permit_deny_to_action(v: &str) -> Result<String> {
    Ok(match v {
        "permit" | "accept" => "accept".to_string(),
        "deny" | "reject" => "reject".to_string(),
        other => bail!("expected permit or deny, got {other:?}"),
    })
}

/// The inverse of [`permit_deny_to_action`] for `show`: render the stored
/// `accept`/`reject` as the CLI's `permit`/`deny`.
fn action_to_permit_deny(a: &str) -> &str {
    match a {
        "accept" => "permit",
        "reject" => "deny",
        other => other,
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
/// Render the body of an `ospf { … }` / `ospf3 { … }` block (fields at 8 spaces).
/// `is_v3` selects the OSPFv3-only knobs (`instance-id`) versus the OSPFv2-only
/// ones (auth / stub areas / timers / graceful-restart / vrf).
fn render_ospf_body(out: &mut String, o: &OspfDraft, is_v3: bool) {
    if let Some(a) = &o.area {
        out.push_str(&format!("        area {a}\n"));
    }
    for iface in &o.interfaces {
        out.push_str(&format!("        interface {iface}\n"));
    }
    for (name, area) in &o.interface_areas {
        match area {
            Some(a) => out.push_str(&format!("        interface {name} area {a}\n")),
            None => out.push_str(&format!("        interface {name}\n")),
        }
    }
    if let Some(p) = o.router_priority {
        out.push_str(&format!("        router-priority {p}\n"));
    }
    if let Some(c) = o.cost {
        out.push_str(&format!("        cost {c}\n"));
    }
    if let Some(nt) = &o.network_type {
        out.push_str(&format!("        network-type {nt}\n"));
    }
    if is_v3 {
        if let Some(id) = o.instance_id {
            out.push_str(&format!("        instance-id {id}\n"));
        }
    }
    for iface in &o.passive_interfaces {
        out.push_str(&format!("        passive-interface {iface}\n"));
    }
    for src in &o.redistribute {
        out.push_str(&format!("        redistribute {src}\n"));
    }
    if let Some(m) = o.redistribute_metric {
        out.push_str(&format!("        redistribute-metric {m}\n"));
    }
    if !is_v3 {
        for (field, areas) in [
            ("stub-area", &o.stub_areas),
            ("nssa-area", &o.nssa_areas),
            ("totally-stubby-area", &o.totally_stubby_areas),
            ("totally-nssa-area", &o.totally_nssa_areas),
            ("nssa-default-area", &o.nssa_default_areas),
        ] {
            for a in areas {
                out.push_str(&format!("        {field} {a}\n"));
            }
        }
        if let Some(c) = o.stub_default_cost {
            out.push_str(&format!("        stub-default-cost {c}\n"));
        }
        if let Some(v) = &o.auth_type {
            out.push_str(&format!("        auth-type {v}\n"));
        }
        if let Some(v) = &o.auth_key {
            out.push_str(&format!("        auth-key {v}\n"));
        }
        if let Some(v) = o.auth_key_id {
            out.push_str(&format!("        auth-key-id {v}\n"));
        }
        if let Some(v) = o.auth_replay_protection {
            out.push_str(&format!("        auth-replay-protection {v}\n"));
        }
        if let Some(v) = o.hello_interval {
            out.push_str(&format!("        hello-interval {v}\n"));
        }
        if let Some(v) = o.dead_interval {
            out.push_str(&format!("        dead-interval {v}\n"));
        }
        if o.graceful_restart {
            out.push_str("        graceful-restart true\n");
        }
        if let Some(v) = o.graceful_restart_period {
            out.push_str(&format!("        graceful-restart-period {v}\n"));
        }
    }
    if o.bfd {
        out.push_str("        bfd true\n");
    }
    if !is_v3 {
        if let Some(vrf) = &o.vrf {
            out.push_str(&format!("        vrf {vrf}\n"));
        }
    }
}

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
    push_field(out, "local-as", n.local_as.map(|v| v.to_string()));
    push_field(out, "update-source", n.update_source.clone());
    push_field(out, "ebgp-multihop", n.ebgp_multihop.map(|v| v.to_string()));
    push_field(out, "description", n.description.clone());
    push_field(out, "hold-time", n.hold_time.map(|v| v.to_string()));
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
        ("shutdown", n.shutdown),
    ] {
        if set {
            out.push_str(&format!("            {k} true\n"));
        }
    }
    out.push_str("        }\n");
}

/// Render one prefix-list as a nested `prefix-list <name> { … }` block (4-space
/// header, `rule <seq>` at 8 spaces, entry fields at 12).
fn render_prefix_list(out: &mut String, name: &str, d: &PrefixListDraft) {
    out.push_str(&format!("    prefix-list {name} {{\n"));
    for (seq, e) in &d.entries {
        out.push_str(&format!("        rule {seq} {{\n"));
        if let Some(p) = &e.prefix {
            out.push_str(&format!("            prefix {p}\n"));
        }
        if let Some(g) = e.ge {
            out.push_str(&format!("            ge {g}\n"));
        }
        if let Some(l) = e.le {
            out.push_str(&format!("            le {l}\n"));
        }
        out.push_str("        }\n");
    }
    out.push_str("    }\n");
}

/// Render one route-map as a nested `route-map <name> { … }` block with VyOS
/// `match`/`set` grouping (4-space header, `rule <seq>` at 8, `action` +
/// `match`/`set` at 12, their fields at 16). The stored `accept`/`reject` render
/// back as `permit`/`deny`.
fn render_route_map(out: &mut String, name: &str, f: &FilterDraft) {
    out.push_str(&format!("    route-map {name} {{\n"));
    if let Some(d) = &f.default {
        out.push_str(&format!("        default {}\n", action_to_permit_deny(d)));
    }
    for (seq, r) in &f.rules {
        out.push_str(&format!("        rule {seq} {{\n"));
        if let Some(a) = &r.action {
            out.push_str(&format!(
                "            action {}\n",
                action_to_permit_deny(a)
            ));
        }
        // match { … } — only when a condition is present.
        let has_match = r.match_prefix_list.is_some()
            || !r.prefix.is_empty()
            || r.protocol.is_some()
            || r.metric_le.is_some()
            || r.metric_ge.is_some();
        if has_match {
            out.push_str("            match {\n");
            if let Some(pl) = &r.match_prefix_list {
                out.push_str(&format!("                prefix-list {pl}\n"));
            }
            for p in &r.prefix {
                out.push_str(&format!("                prefix {p}\n"));
            }
            if let Some(p) = &r.protocol {
                out.push_str(&format!("                protocol {p}\n"));
            }
            if let Some(m) = r.metric_le {
                out.push_str(&format!("                metric-le {m}\n"));
            }
            if let Some(m) = r.metric_ge {
                out.push_str(&format!("                metric-ge {m}\n"));
            }
            out.push_str("            }\n");
        }
        // set { … } — only when an attribute change is present.
        let has_set = r.set_metric.is_some()
            || r.add_metric.is_some()
            || r.set_preference.is_some()
            || !r.set_community.is_empty()
            || !r.add_community.is_empty()
            || !r.set_large_community.is_empty()
            || !r.add_large_community.is_empty()
            || !r.set_ext_community.is_empty()
            || !r.add_ext_community.is_empty();
        if has_set {
            out.push_str("            set {\n");
            if let Some(m) = r.set_metric {
                out.push_str(&format!("                metric {m}\n"));
            }
            if let Some(m) = r.add_metric {
                out.push_str(&format!("                add-metric {m}\n"));
            }
            if let Some(p) = r.set_preference {
                out.push_str(&format!("                preference {p}\n"));
            }
            for (k, set) in [
                ("community", &r.set_community),
                ("add-community", &r.add_community),
                ("large-community", &r.set_large_community),
                ("add-large-community", &r.add_large_community),
                ("ext-community", &r.set_ext_community),
                ("add-ext-community", &r.add_ext_community),
            ] {
                for c in set {
                    out.push_str(&format!("                {k} {c}\n"));
                }
            }
            out.push_str("            }\n");
        }
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

/// Parse a lease-time as a human duration into seconds. Accepts a bare number
/// (seconds — the historical form) or a compound of `<n>d`/`<n>h`/`<n>m`/`<n>s`
/// units (`12h`, `1h30m`, `7d`). Rejects empty, zero, or unknown units — the
/// resolved seconds render as networkd `DefaultLeaseTimeSec=`.
fn parse_duration_secs(s: &str) -> Result<u32> {
    if s.is_empty() {
        bail!("empty lease-time");
    }
    // A bare number is seconds (back-compatible with the old u32 form).
    if let Ok(n) = s.parse::<u32>() {
        if n == 0 {
            bail!("lease-time must be greater than zero");
        }
        return Ok(n);
    }
    let mut total: u64 = 0;
    let mut num = String::new();
    let mut saw_unit = false;
    for c in s.chars() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        if num.is_empty() {
            bail!("invalid lease-time {s:?}: expected <n>d/<n>h/<n>m/<n>s or bare seconds");
        }
        let v: u64 = num.parse().unwrap();
        let mult = match c {
            'd' => 86_400,
            'h' => 3_600,
            'm' => 60,
            's' => 1,
            _ => bail!("invalid lease-time unit {c:?} in {s:?} (use d/h/m/s)"),
        };
        total += v * mult;
        num.clear();
        saw_unit = true;
    }
    if !num.is_empty() {
        bail!("invalid lease-time {s:?}: trailing number without a unit");
    }
    if !saw_unit || total == 0 {
        bail!("lease-time {s:?} resolves to zero");
    }
    u32::try_from(total).map_err(|_| anyhow::anyhow!("lease-time {s:?} is too large"))
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
    fn box_services_cli_builds_shows_and_commits() {
        let mut s = Session::empty();
        for line in [
            "set system hostname fw",
            "set interface lan0 zone lan",
            "set interface lan0 address 10.0.0.1/24",
            "set interface iot0 zone iot",
            "set interface iot0 address 10.0.7.1/24",
            // LLDP on the two links.
            "set services lldp enable true",
            "set services lldp interface lan0,iot0",
            // Read-only SNMP scoped to the LAN.
            "set services snmp community public",
            "set services snmp location rack-4",
            "set services snmp allow 10.0.0.0/24",
            // mDNS reflector between the two zones.
            "set services mdns interface lan0,iot0",
            // Dynamic-DNS client watching the LAN address.
            "set services dyndns provider cloudflare",
            "set services dyndns hostname fw.example.com",
            "set services dyndns password secret-token",
            "set services dyndns interface lan0",
            // DHCP relay from iot0 to an upstream server.
            "set services dhcp-relay interface iot0",
            "set services dhcp-relay server 10.0.0.99",
        ] {
            run(&mut s, line).unwrap();
        }

        // `show` renders every new leaf under services.
        let shown = s.show();
        for needle in [
            "lldp {",
            "enable true",
            "interface lan0,iot0",
            "snmp {",
            "community public",
            "location rack-4",
            "allow 10.0.0.0/24",
            "mdns {",
            "dyndns {",
            "provider cloudflare",
            "hostname fw.example.com",
            "dhcp-relay {",
            "server 10.0.0.99",
        ] {
            assert!(shown.contains(needle), "show missing {needle:?}:\n{shown}");
        }

        // It materializes into a validated Appliance carrying every service.
        let a = s.commit().expect("box services commit");
        assert!(a.services.lldp.enable);
        assert_eq!(a.services.lldp.interface, vec!["lan0", "iot0"]);
        assert_eq!(a.services.snmp.community.as_deref(), Some("public"));
        assert_eq!(a.services.snmp.allow, vec!["10.0.0.0/24"]);
        assert_eq!(a.services.mdns.interface, vec!["lan0", "iot0"]);
        assert_eq!(
            a.services.dyndns.hostname.as_deref(),
            Some("fw.example.com")
        );
        assert_eq!(a.services.dhcp_relay.server, vec!["10.0.0.99"]);

        // A full TOML round-trip (save → reload) preserves them.
        let toml = a.to_toml().unwrap();
        let b = Appliance::from_toml(&toml).expect("re-parses");
        assert!(b.services.lldp.enable);
        assert_eq!(b.services.dhcp_relay.interface, vec!["iot0"]);

        // `delete services snmp` clears just that one; the rest survive.
        run(&mut s, "delete services snmp").unwrap();
        let a2 = s.commit().expect("still valid after deleting snmp");
        assert!(a2.services.snmp.is_empty());
        assert!(a2.services.lldp.enable);
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
    fn pki_cli_builds_shows_commits_and_deletes() {
        let mut s = Session::empty();
        for line in [
            "set system hostname gw",
            "set pki ca corp common-name corp.example.com",
            "set pki ca corp organization Example",
            "set pki ca corp key-type ec",
            "set pki certificate vpn-server ca corp",
            "set pki certificate vpn-server common-name vpn.example.com",
            "set pki certificate vpn-server subject-alt-name DNS:vpn.example.com",
            "set pki certificate vpn-server usage server",
            "set pki acme email admin@example.com",
            "set pki acme challenge http-01",
            "set pki acme agree-tos true",
        ] {
            run(&mut s, line).unwrap();
        }
        // The show block round-trips the CA, cert and ACME account.
        let shown = s.show_only("pki");
        assert!(shown.contains("pki {"), "got:\n{shown}");
        assert!(shown.contains("ca corp {"), "got:\n{shown}");
        assert!(shown.contains("certificate vpn-server {"), "got:\n{shown}");
        assert!(
            shown.contains("subject-alt-name DNS:vpn.example.com"),
            "got:\n{shown}"
        );
        assert!(shown.contains("acme {"), "got:\n{shown}");

        let a = s.commit().expect("valid pki commits");
        assert_eq!(a.pki.cas.len(), 1);
        assert_eq!(a.pki.cas[0].common_name, "corp.example.com");
        assert_eq!(a.pki.certificates.len(), 1);
        assert_eq!(a.pki.certificates[0].ca, "corp");
        assert_eq!(
            a.pki.acme.as_ref().map(|c| c.email.as_str()),
            Some("admin@example.com")
        );

        // Delete an optional field, one SAN, then the whole objects.
        run(&mut s, "delete pki certificate vpn-server usage").unwrap();
        let b = s.commit().expect("still valid after field delete");
        assert!(b.pki.certificates[0].usage.is_none());
        run(&mut s, "delete pki acme").unwrap();
        run(&mut s, "delete pki certificate vpn-server").unwrap();
        run(&mut s, "delete pki ca corp").unwrap();
        let d = s.commit().expect("still valid after object deletes");
        assert!(d.pki.is_empty());
    }

    #[test]
    fn reverse_proxy_cli_builds_shows_commits_and_roundtrips() {
        let mut s = Session::empty();
        for line in [
            "set system hostname gw",
            "set pki ca corp common-name corp.example.com",
            "set pki certificate web-cert ca corp",
            "set pki certificate web-cert common-name web.example.com",
            "set services reverse-proxy web port 443",
            "set services reverse-proxy web certificate web-cert",
            "set services reverse-proxy web backends 10.0.0.10:8080,10.0.0.11:8080",
            // A second frontend on a different port exercises the keyed list.
            "set services reverse-proxy api port 8443",
            "set services reverse-proxy api backends 10.0.0.20:9000",
        ] {
            run(&mut s, line).unwrap();
        }
        // show nests both frontends under services, name-ordered (api before web).
        let shown = s.show_only("services");
        assert!(shown.contains("reverse-proxy api {"), "got:\n{shown}");
        assert!(shown.contains("reverse-proxy web {"), "got:\n{shown}");
        assert!(
            shown.find("reverse-proxy api {") < shown.find("reverse-proxy web {"),
            "frontends should be name-ordered:\n{shown}"
        );
        assert!(shown.contains("certificate web-cert"), "got:\n{shown}");
        assert!(shown.contains("backends 10.0.0.10:8080"), "got:\n{shown}");
        assert!(shown.contains("backends 10.0.0.11:8080"), "got:\n{shown}");

        let a = s.commit().expect("valid reverse-proxy commits");
        assert_eq!(a.services.reverse_proxy.len(), 2);
        assert_eq!(a.services.reverse_proxy[0].name, "api");
        assert_eq!(a.services.reverse_proxy[0].port(), 8443);
        assert_eq!(a.services.reverse_proxy[1].name, "web");
        assert_eq!(a.services.reverse_proxy[1].port(), 443);
        assert_eq!(
            a.services.reverse_proxy[1].certificate.as_deref(),
            Some("web-cert")
        );
        assert_eq!(a.services.reverse_proxy[1].backends.len(), 2);

        // from_appliance ∘ materialize is the identity on the frontends.
        let round = Session {
            draft: Draft::from_appliance(&a),
            path: PathBuf::from("/dev/null"),
            dirty: false,
        };
        let b = round.materialize().expect("re-materialises");
        assert_eq!(
            a.services.reverse_proxy.len(),
            b.services.reverse_proxy.len()
        );
        assert_eq!(
            a.services.reverse_proxy[1].name,
            b.services.reverse_proxy[1].name
        );
        assert_eq!(
            a.services.reverse_proxy[1].backends,
            b.services.reverse_proxy[1].backends
        );
        assert_eq!(
            a.services.reverse_proxy[1].certificate,
            b.services.reverse_proxy[1].certificate
        );
    }

    #[test]
    fn reverse_proxy_backends_append_and_remove() {
        let mut s = Session::empty();
        for line in [
            "set system hostname gw",
            "set services reverse-proxy web backends 10.0.0.10:80",
            "set services reverse-proxy web backends 10.0.0.11:80,10.0.0.12:80",
            // A duplicate is deduped by append_csv, not appended twice.
            "set services reverse-proxy web backends 10.0.0.10:80",
        ] {
            run(&mut s, line).unwrap();
        }
        // No certificate ⇒ plain-HTTP frontend, which is still valid.
        let a = s.commit().expect("plain-HTTP proxy is valid");
        assert_eq!(
            a.services.reverse_proxy[0].backends,
            ["10.0.0.10:80", "10.0.0.11:80", "10.0.0.12:80"]
        );

        run(
            &mut s,
            "delete services reverse-proxy web backends 10.0.0.11:80",
        )
        .unwrap();
        let b = s.commit().expect("still valid after backend remove");
        assert_eq!(
            b.services.reverse_proxy[0].backends,
            ["10.0.0.10:80", "10.0.0.12:80"]
        );

        let err = run(
            &mut s,
            "delete services reverse-proxy web backends 9.9.9.9:80",
        )
        .unwrap_err();
        assert!(err.to_string().contains("no backend"), "got: {err}");
    }

    #[test]
    fn reverse_proxy_delete_frontend_and_field() {
        let mut s = Session::empty();
        for line in [
            "set system hostname gw",
            "set services reverse-proxy web port 8080",
            "set services reverse-proxy web backends 10.0.0.10:80",
        ] {
            run(&mut s, line).unwrap();
        }
        // Reset the port field back to the 443 default.
        run(&mut s, "delete services reverse-proxy web port").unwrap();
        let a = s.commit().expect("valid after field delete");
        assert!(a.services.reverse_proxy[0].port.is_none());
        assert_eq!(a.services.reverse_proxy[0].port(), 443);

        // Delete the whole frontend — services empties out.
        run(&mut s, "delete services reverse-proxy web").unwrap();
        let b = s.commit().expect("valid after frontend delete");
        assert!(b.services.reverse_proxy.is_empty());

        // Deleting an absent frontend errors.
        let err = run(&mut s, "delete services reverse-proxy web").unwrap_err();
        assert!(
            err.to_string().contains("no reverse-proxy frontend"),
            "got: {err}"
        );
    }

    #[test]
    fn pki_rejects_cert_with_unknown_ca_and_bad_san() {
        let mut s = Session::empty();
        run(&mut s, "set system hostname gw").unwrap();
        run(&mut s, "set pki certificate leaf ca ghost").unwrap();
        run(
            &mut s,
            "set pki certificate leaf common-name leaf.example.com",
        )
        .unwrap();
        // The CA is undeclared → commit-time validation rejects it.
        let err = s.commit().unwrap_err().to_string();
        assert!(err.contains("unknown ca"), "got: {err}");
        // A malformed SAN is rejected at set time.
        let bad = run(
            &mut s,
            "set pki certificate leaf subject-alt-name vpn.example.com",
        )
        .unwrap_err();
        assert!(bad.to_string().contains("DNS:<host>"), "got: {bad}");
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
    fn vlan_parent_id_inferred_from_dotted_name() {
        let mut s = Session::empty();
        for line in [
            "set system hostname fw",
            "set interface eth0 zone lan",
            "set interface eth0 address 10.0.0.1/24",
            // Just the name + address — parent/vlan are inferred at commit.
            "set interface eth0.20 zone iot",
            "set interface eth0.20 address 10.0.20.1/24",
        ] {
            run(&mut s, line).unwrap();
        }
        let a = s.commit().expect("inferred vlan commits");
        let vlan = a.interfaces.iter().find(|i| i.name == "eth0.20").unwrap();
        assert_eq!(
            (vlan.parent.as_deref(), vlan.vlan),
            (Some("eth0"), Some(20))
        );
    }

    #[test]
    fn wireguard_cli_builds_shows_commits_and_deletes() {
        let key = "OK+2ftLGli1Dle9tRWx5Bj0eLc0X7KcInScVBpg+3lc=";
        let mut s = Session::empty();
        for line in [
            "set system hostname gw".to_string(),
            "set interface wg0 type wireguard".to_string(),
            "set interface wg0 zone vpn".to_string(),
            "set interface wg0 address 10.9.0.1/24".to_string(),
            "set nat source vpn-masq zone vpn".to_string(),
            format!("set vpn wireguard wg0 private-key {key}"),
            "set vpn wireguard wg0 listen-port 51820".to_string(),
            format!("set vpn wireguard wg0 peer {key} allowed-ips 10.9.0.2/32"),
            format!("set vpn wireguard wg0 peer {key} endpoint 203.0.113.9:51820"),
            format!("set vpn wireguard wg0 peer {key} keepalive 25"),
        ] {
            run(&mut s, &line).unwrap();
        }
        // The interface shows the type; the crypto shows under vpn.
        let iface = s.show_only("interface");
        assert!(iface.contains("type wireguard"), "got:\n{iface}");
        let vpn = s.show_only("vpn");
        assert!(vpn.contains("wireguard wg0 {"), "got:\n{vpn}");
        assert!(vpn.contains("listen-port 51820"), "got:\n{vpn}");
        assert!(vpn.contains(&format!("peer {key} {{")), "got:\n{vpn}");

        let a = s.commit().expect("valid wireguard commits");
        assert!(
            a.interfaces
                .iter()
                .any(|i| i.name == "wg0" && i.is_wireguard())
        );
        assert_eq!(a.vpn.wireguard.len(), 1);
        assert_eq!(a.vpn.wireguard[0].name, "wg0");
        assert_eq!(a.vpn.wireguard[0].peers.len(), 1);

        // A type=wireguard interface with no tunnel is rejected.
        run(&mut s, "set interface wg1 type wireguard").unwrap();
        assert!(s.commit().is_err());

        // Delete the orphan interface, then a peer, then the whole tunnel.
        run(&mut s, "delete interface wg1").unwrap();
        run(&mut s, &format!("delete vpn wireguard wg0 peer {key}")).unwrap();
        let b = s.commit().expect("still valid after peer delete");
        assert!(b.vpn.wireguard[0].peers.is_empty());
    }

    /// Seed a session with the PKI leaf + zoned interface an OpenConnect server
    /// needs to pass commit-time validation, so the OpenConnect tests only have
    /// to exercise their own surface.
    #[cfg(test)]
    fn openconnect_prereqs(s: &mut Session) {
        for line in [
            "set system hostname gw",
            "set pki ca corp common-name corp.example.com",
            "set pki certificate vpn-server ca corp",
            "set pki certificate vpn-server common-name vpn.example.com",
            "set interface eth1 zone vpn",
            "set interface eth1 address 10.99.0.1/24",
        ] {
            run(s, line).unwrap();
        }
    }

    #[test]
    fn openconnect_cli_builds_shows_commits_and_deletes() {
        let mut s = Session::empty();
        openconnect_prereqs(&mut s);
        for line in [
            "set vpn openconnect certificate vpn-server",
            "set vpn openconnect port 4443",
            "set vpn openconnect pool 10.99.0.0/24",
            "set vpn openconnect dns 10.99.0.1",
            "set vpn openconnect routes 10.0.0.0/8",
            "set vpn openconnect zone vpn",
            "set vpn openconnect user alice password s3cret",
        ] {
            run(&mut s, line).unwrap();
        }
        // The show block round-trips the server + its fields + the user.
        let shown = s.show_only("vpn");
        assert!(shown.contains("vpn {"), "got:\n{shown}");
        assert!(shown.contains("openconnect {"), "got:\n{shown}");
        assert!(shown.contains("certificate vpn-server"), "got:\n{shown}");
        assert!(shown.contains("port 4443"), "got:\n{shown}");
        assert!(shown.contains("pool 10.99.0.0/24"), "got:\n{shown}");
        assert!(shown.contains("dns 10.99.0.1"), "got:\n{shown}");
        assert!(shown.contains("routes 10.0.0.0/8"), "got:\n{shown}");
        assert!(shown.contains("zone vpn"), "got:\n{shown}");
        assert!(shown.contains("user alice {"), "got:\n{shown}");
        // Secrets render verbatim, matching wireguard private-key / ipsec psk.
        assert!(shown.contains("password s3cret"), "got:\n{shown}");

        let a = s.commit().expect("valid openconnect commits");
        let oc = a.vpn.openconnect.as_ref().expect("server present");
        assert_eq!(oc.certificate, "vpn-server");
        assert_eq!(oc.port(), 4443);
        assert_eq!(oc.pool, "10.99.0.0/24");
        assert_eq!(oc.dns, vec!["10.99.0.1".to_string()]);
        assert_eq!(oc.routes, vec!["10.0.0.0/8".to_string()]);
        assert_eq!(oc.zone.as_deref(), Some("vpn"));
        assert_eq!(oc.users.len(), 1);
        assert_eq!(oc.users[0].name, "alice");
        assert_eq!(oc.users[0].password, "s3cret");

        // `default-route` and an explicit `routes` list are mutually exclusive —
        // drop the routes first, then full-tunnel commits.
        run(&mut s, "delete vpn openconnect routes").unwrap();
        run(&mut s, "set vpn openconnect default-route true").unwrap();
        let b = s.commit().expect("full-tunnel commits");
        assert!(b.vpn.openconnect.as_ref().unwrap().default_route);

        // Reset an optional field, then delete the whole server.
        run(&mut s, "delete vpn openconnect port").unwrap();
        let c = s.commit().expect("still valid after field delete");
        assert!(c.vpn.openconnect.as_ref().unwrap().port.is_none());
        run(&mut s, "delete vpn openconnect").unwrap();
        let d = s.commit().expect("still valid after server delete");
        assert!(d.vpn.openconnect.is_none());
    }

    #[test]
    fn openconnect_dns_and_routes_append_and_remove() {
        let mut s = Session::empty();
        openconnect_prereqs(&mut s);
        run(&mut s, "set vpn openconnect certificate vpn-server").unwrap();
        run(&mut s, "set vpn openconnect pool 10.99.0.0/24").unwrap();
        run(&mut s, "set vpn openconnect user bob password pw").unwrap();
        // Append with dedup: a CSV plus a repeat of an existing entry.
        run(&mut s, "set vpn openconnect dns 10.99.0.1,10.99.0.2").unwrap();
        run(&mut s, "set vpn openconnect dns 10.99.0.1").unwrap();
        run(
            &mut s,
            "set vpn openconnect routes 10.0.0.0/8,172.16.0.0/12",
        )
        .unwrap();
        let a = s.commit().expect("commits");
        let oc = a.vpn.openconnect.as_ref().unwrap();
        assert_eq!(
            oc.dns,
            vec!["10.99.0.1".to_string(), "10.99.0.2".to_string()]
        );
        assert_eq!(
            oc.routes,
            vec!["10.0.0.0/8".to_string(), "172.16.0.0/12".to_string()]
        );

        // Per-item removal drops one entry, leaving the rest.
        run(&mut s, "delete vpn openconnect dns 10.99.0.1").unwrap();
        run(&mut s, "delete vpn openconnect routes 10.0.0.0/8").unwrap();
        let b = s.commit().expect("still valid after item removal");
        let oc = b.vpn.openconnect.as_ref().unwrap();
        assert_eq!(oc.dns, vec!["10.99.0.2".to_string()]);
        assert_eq!(oc.routes, vec!["172.16.0.0/12".to_string()]);

        // Removing an absent item is an error.
        let err = run(&mut s, "delete vpn openconnect dns 8.8.8.8").unwrap_err();
        assert!(err.to_string().contains("no dns"), "got: {err}");
    }

    #[test]
    fn openconnect_users_add_and_delete() {
        let mut s = Session::empty();
        openconnect_prereqs(&mut s);
        run(&mut s, "set vpn openconnect certificate vpn-server").unwrap();
        run(&mut s, "set vpn openconnect pool 10.99.0.0/24").unwrap();
        run(&mut s, "set vpn openconnect user alice password a").unwrap();
        run(&mut s, "set vpn openconnect user bob password b").unwrap();
        let a = s.commit().expect("two users commit");
        assert_eq!(a.vpn.openconnect.as_ref().unwrap().users.len(), 2);

        // Deleting one user leaves the other (a server must keep ≥1 user).
        run(&mut s, "delete vpn openconnect user alice").unwrap();
        let b = s.commit().expect("still valid with one user");
        let users = &b.vpn.openconnect.as_ref().unwrap().users;
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].name, "bob");

        // Deleting the last user leaves a server that can accept no one.
        run(&mut s, "delete vpn openconnect user bob").unwrap();
        let err = s.commit().unwrap_err().to_string();
        assert!(err.contains("at least one user"), "got: {err}");

        // Deleting an absent user is an error.
        let err = run(&mut s, "delete vpn openconnect user ghost").unwrap_err();
        assert!(err.to_string().contains("no user"), "got: {err}");
    }

    #[test]
    fn openconnect_materialize_round_trips() {
        let mut s = Session::empty();
        openconnect_prereqs(&mut s);
        for line in [
            "set vpn openconnect certificate vpn-server",
            "set vpn openconnect port 443",
            "set vpn openconnect pool 10.99.0.0/24",
            "set vpn openconnect dns 10.99.0.1,10.99.0.2",
            "set vpn openconnect routes 10.0.0.0/8",
            "set vpn openconnect zone vpn",
            "set vpn openconnect disabled true",
            "set vpn openconnect user alice password a",
            "set vpn openconnect user bob password b",
        ] {
            run(&mut s, line).unwrap();
        }
        let a = s.commit().expect("commits");
        // from_appliance ∘ materialize is the identity on the server.
        let round = Session {
            draft: Draft::from_appliance(&a),
            path: PathBuf::from("/dev/null"),
            dirty: false,
        };
        let b = round.materialize().expect("re-materialises");
        let (oc0, oc1) = (
            a.vpn.openconnect.as_ref().unwrap(),
            b.vpn.openconnect.as_ref().unwrap(),
        );
        assert_eq!(oc0.disabled, oc1.disabled);
        assert_eq!(oc0.port, oc1.port);
        assert_eq!(oc0.certificate, oc1.certificate);
        assert_eq!(oc0.pool, oc1.pool);
        assert_eq!(oc0.dns, oc1.dns);
        assert_eq!(oc0.routes, oc1.routes);
        assert_eq!(oc0.default_route, oc1.default_route);
        assert_eq!(oc0.zone, oc1.zone);
        let names0: Vec<_> = oc0.users.iter().map(|u| &u.name).collect();
        let names1: Vec<_> = oc1.users.iter().map(|u| &u.name).collect();
        assert_eq!(names0, names1);
    }

    #[test]
    fn bridge_members_set_on_device_and_delete() {
        let mut s = Session::empty();
        for line in [
            "set system hostname fw",
            "set interface br0 type bridge",
            "set interface br0 zone lan",
            "set interface br0 address 10.0.0.1/24",
            "set interface br0 member eth1",
            "set interface br0 member eth2",
            "set interface eth1",
            "set interface eth2",
        ] {
            run(&mut s, line).unwrap();
        }
        let shown = s.show_only("interface");
        assert!(shown.contains("member eth1"), "got:\n{shown}");
        assert!(shown.contains("member eth2"), "got:\n{shown}");
        let a = s.commit().expect("bridge with members commits");
        let br = a.interfaces.iter().find(|i| i.name == "br0").unwrap();
        assert_eq!(br.members, vec!["eth1".to_string(), "eth2".to_string()]);

        // Remove one member; the other survives.
        run(&mut s, "delete interface br0 member eth1").unwrap();
        let b = s.commit().unwrap();
        let br = b.interfaces.iter().find(|i| i.name == "br0").unwrap();
        assert_eq!(br.members, vec!["eth2".to_string()]);

        // `member` on a non-device interface is rejected at commit.
        run(&mut s, "set interface eth2 member eth1").unwrap();
        assert!(s.commit().is_err());
    }

    #[test]
    fn vlan_aware_bridge_ports_set_and_commit() {
        let mut s = Session::empty();
        for line in [
            "set system hostname fw",
            "set interface br0 type bridge",
            "set interface br0 vlan-aware true",
            "set interface br0 zone lan",
            "set interface br0 address 10.0.0.1/24",
            "set interface br0 member eth1",
            "set interface eth1 vlan-tagged 10,20",
            "set interface eth1 vlan-untagged 1",
        ] {
            run(&mut s, line).unwrap();
        }
        let shown = s.show_only("interface");
        assert!(shown.contains("vlan-aware true"), "got:\n{shown}");
        assert!(shown.contains("vlan-tagged 10,20"), "got:\n{shown}");
        assert!(shown.contains("vlan-untagged 1"), "got:\n{shown}");
        let a = s.commit().expect("vlan-aware bridge commits");
        let eth1 = a.interfaces.iter().find(|i| i.name == "eth1").unwrap();
        assert_eq!(eth1.vlan_tagged, vec![10u16, 20u16]);
        assert_eq!(eth1.vlan_untagged, Some(1));

        // vlan-tagged on a port outside a vlan-aware bridge is rejected.
        run(&mut s, "set interface eth3 vlan-tagged 10").unwrap();
        assert!(s.commit().is_err());
    }

    #[test]
    fn macvlan_interface_set_show_commit_roundtrip() {
        let mut s = Session::empty();
        for line in [
            "set system hostname fw",
            // The parent NIC must be a declared interface for validate() to pass.
            "set interface eth0 zone wan",
            "set interface mv0 type macvlan",
            "set interface mv0 parent eth0",
            "set interface mv0 macvlan-mode bridge",
            "set interface mv0 zone lan",
            "set interface mv0 address 10.20.0.1/24",
        ] {
            run(&mut s, line).unwrap();
        }
        let shown = s.show_only("interface");
        assert!(shown.contains("type macvlan"), "got:\n{shown}");
        assert!(shown.contains("parent eth0"), "got:\n{shown}");
        assert!(shown.contains("macvlan-mode bridge"), "got:\n{shown}");

        let a = s.commit().expect("macvlan interface commits");
        let mv0 = a.interfaces.iter().find(|i| i.name == "mv0").unwrap();
        assert_eq!(mv0.if_type, Some(IfaceType::Macvlan));
        assert_eq!(mv0.macvlan_mode.as_deref(), Some("bridge"));
        assert_eq!(mv0.parent.as_deref(), Some("eth0"));

        // from_appliance ∘ materialize is the identity on the macvlan fields.
        let round = Session {
            draft: Draft::from_appliance(&a),
            path: PathBuf::from("/dev/null"),
            dirty: false,
        };
        let b = round.materialize().expect("re-materialises");
        let mv0b = b.interfaces.iter().find(|i| i.name == "mv0").unwrap();
        assert_eq!(mv0b.if_type, Some(IfaceType::Macvlan));
        assert_eq!(mv0b.macvlan_mode.as_deref(), Some("bridge"));
        assert_eq!(mv0b.parent.as_deref(), Some("eth0"));

        // A macvlan-mode value outside the set is rejected at set-time.
        assert!(run(&mut s, "set interface mv0 macvlan-mode bogus").is_err());
    }

    #[test]
    fn qinq_stack_set_show_commit() {
        let mut s = Session::empty();
        for line in [
            "set system hostname fw",
            "set interface eth0 zone wan",
            // S-VLAN: an 802.1ad service tag riding the physical NIC.
            "set interface svlan parent eth0",
            "set interface svlan vlan 100",
            "set interface svlan vlan-protocol 802.1ad",
            // C-VLAN: a plain 802.1q customer tag stacked on the S-VLAN → QinQ.
            "set interface cvlan parent svlan",
            "set interface cvlan vlan 200",
            "set interface cvlan zone lan",
            "set interface cvlan address 10.30.0.1/24",
        ] {
            run(&mut s, line).unwrap();
        }
        let shown = s.show_only("interface");
        assert!(shown.contains("vlan-protocol 802.1ad"), "got:\n{shown}");

        let a = s.commit().expect("QinQ stack commits");
        let svlan = a.interfaces.iter().find(|i| i.name == "svlan").unwrap();
        assert_eq!(svlan.vlan_protocol.as_deref(), Some("802.1ad"));
        assert_eq!(svlan.vlan, Some(100));
        let cvlan = a.interfaces.iter().find(|i| i.name == "cvlan").unwrap();
        assert_eq!(cvlan.parent.as_deref(), Some("svlan"));
        assert_eq!(cvlan.vlan, Some(200));

        // vlan-protocol only accepts 802.1q / 802.1ad.
        assert!(run(&mut s, "set interface svlan vlan-protocol 802.1x").is_err());
    }

    #[test]
    fn macvlan_and_qinq_fields_delete() {
        let mut s = Session::empty();
        for line in [
            "set system hostname fw",
            "set interface eth0 zone wan",
            "set interface mv0 type macvlan",
            "set interface mv0 parent eth0",
            "set interface mv0 macvlan-mode vepa",
            "set interface svlan parent eth0",
            "set interface svlan vlan 100",
            "set interface svlan vlan-protocol 802.1ad",
        ] {
            run(&mut s, line).unwrap();
        }
        assert!(s.show_only("interface").contains("macvlan-mode vepa"));
        assert!(s.show_only("interface").contains("vlan-protocol 802.1ad"));

        run(&mut s, "delete interface mv0 macvlan-mode").unwrap();
        run(&mut s, "delete interface svlan vlan-protocol").unwrap();
        let shown = s.show_only("interface");
        assert!(!shown.contains("macvlan-mode"), "got:\n{shown}");
        assert!(!shown.contains("vlan-protocol"), "got:\n{shown}");
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
    fn per_object_polish_sets_shows_commits_and_round_trips() {
        let mut s = Session::empty();
        for line in [
            "set system hostname fw1",
            // Interface description + administrative disable.
            "set interface wan0 zone wan",
            "set interface wan0 address dhcp",
            "set interface lan0 zone lan",
            "set interface lan0 address 10.0.0.1/24",
            "set interface lan0 description office LAN uplink",
            "set interface dmz0 zone dmz",
            "set interface dmz0 disabled true",
            // DHCP server with the new options + a one-line static reservation.
            "set interface lan0 dhcp-server pool-offset 100",
            "set interface lan0 dhcp-server pool-size 100",
            "set interface lan0 dhcp-server dns 10.0.0.1",
            "set interface lan0 dhcp-server lease-time 12h",
            "set interface lan0 dhcp-server default-router 10.0.0.254",
            "set interface lan0 dhcp-server domain lan.example",
            "set interface lan0 dhcp-server static-mapping printer mac 52:54:00:12:34:56 ip 10.0.0.20",
            // Zone description + rule description/disabled.
            "set firewall zone lan description trusted inside",
            "set firewall rule web description inbound https",
            "set firewall rule web from wan",
            "set firewall rule web to lan",
            "set firewall rule web action accept",
            "set firewall rule web proto tcp",
            "set firewall rule web port 443",
            "set firewall rule parked from wan",
            "set firewall rule parked to lan",
            "set firewall rule parked action accept",
            "set firewall rule parked disabled true",
            // NAT description + disable on both source and destination.
            "set nat source wan-masq zone wan",
            "set nat source wan-masq description egress masquerade",
            "set nat destination fwd zone wan",
            "set nat destination fwd proto tcp",
            "set nat destination fwd port 443",
            "set nat destination fwd to 10.0.0.10:8443",
            "set nat destination fwd description park me",
            "set nat destination fwd disabled true",
            // DNS resolver tuning.
            "set services dns upstream 9.9.9.9",
            "set services dns serve-on lan0",
            "set services dns cache-size 1000",
            "set services dns local-domain lan.example",
        ] {
            run(&mut s, line).unwrap();
        }

        // `show` renders every new leaf.
        let shown = s.show();
        for needle in [
            "description office LAN uplink",
            "disabled true",
            "lease-time 43200", // 12h resolved to seconds
            "default-router 10.0.0.254",
            "domain lan.example",
            "static-mapping printer {",
            "mac 52:54:00:12:34:56",
            "ip 10.0.0.20",
            "description trusted inside",
            "description inbound https",
            "description egress masquerade",
            "cache-size 1000",
            "local-domain lan.example",
        ] {
            assert!(shown.contains(needle), "show missing {needle:?}:\n{shown}");
        }

        // It materializes into a validated Appliance carrying every field.
        let a = s.commit().expect("per-object polish commits");
        let lan = a.interfaces.iter().find(|i| i.name == "lan0").unwrap();
        assert_eq!(lan.description.as_deref(), Some("office LAN uplink"));
        assert!(!lan.disabled);
        let dmz = a.interfaces.iter().find(|i| i.name == "dmz0").unwrap();
        assert!(dmz.disabled);
        let dhcp = lan.dhcp_server.as_ref().unwrap();
        assert_eq!(dhcp.lease_time, Some(43_200));
        assert_eq!(dhcp.default_router.as_deref(), Some("10.0.0.254"));
        assert_eq!(dhcp.domain.as_deref(), Some("lan.example"));
        assert_eq!(dhcp.static_mappings.len(), 1);
        assert_eq!(
            (
                dhcp.static_mappings[0].mac.as_str(),
                dhcp.static_mappings[0].ip.as_str()
            ),
            ("52:54:00:12:34:56", "10.0.0.20")
        );
        assert_eq!(
            a.zones.get("lan").and_then(|z| z.description.as_deref()),
            Some("trusted inside")
        );
        let web = a.rules.iter().find(|r| r.name == "web").unwrap();
        assert_eq!(web.description.as_deref(), Some("inbound https"));
        let parked = a.rules.iter().find(|r| r.name == "parked").unwrap();
        assert!(parked.disabled);
        assert_eq!(
            a.nat.source[0].description.as_deref(),
            Some("egress masquerade")
        );
        assert!(a.nat.destination[0].disabled);
        assert_eq!(a.services.dns.cache_size, Some(1000));
        assert_eq!(a.services.dns.local_domain.as_deref(), Some("lan.example"));

        // Full round-trip: reload the committed Appliance into a fresh draft and
        // re-render — every field survives from_appliance → render.
        let round = render_appliance(&a);
        for needle in [
            "description office LAN uplink",
            "disabled true",
            "lease-time 43200",
            "default-router 10.0.0.254",
            "static-mapping printer {",
            "mac 52:54:00:12:34:56",
            "description trusted inside",
            "description inbound https",
            "cache-size 1000",
            "local-domain lan.example",
        ] {
            assert!(
                round.contains(needle),
                "round-trip missing {needle:?}:\n{round}"
            );
        }

        // Deleting a single static reservation, then a description field.
        run(
            &mut s,
            "delete interface lan0 dhcp-server static-mapping printer",
        )
        .unwrap();
        assert!(!s.show().contains("static-mapping printer"));
        run(&mut s, "delete interface lan0 description").unwrap();
        assert!(!s.show().contains("description office LAN uplink"));
    }

    #[test]
    fn lease_time_rejects_zero_and_unknown_units() {
        let mut s = Session::empty();
        run(&mut s, "set interface lan0 zone lan").unwrap();
        // A bare zero, an unknown unit, and a compound that resolves to zero.
        assert!(run(&mut s, "set interface lan0 dhcp-server lease-time 0").is_err());
        assert!(run(&mut s, "set interface lan0 dhcp-server lease-time 5y").is_err());
        // A valid compound resolves to seconds.
        run(&mut s, "set interface lan0 dhcp-server lease-time 1h30m").unwrap();
        assert!(s.show().contains("lease-time 5400"), "got:\n{}", s.show());
    }

    #[test]
    fn static_mapping_ip_must_be_inside_the_server_subnet() {
        let mut s = Session::empty();
        run(&mut s, "set system hostname fw").unwrap();
        run(&mut s, "set interface lan0 zone lan").unwrap();
        run(&mut s, "set interface lan0 address 10.0.0.1/24").unwrap();
        run(&mut s, "set interface lan0 dhcp-server pool-size 50").unwrap();
        // An address outside 10.0.0.0/24 can never be handed out ⇒ rejected.
        run(
            &mut s,
            "set interface lan0 dhcp-server static-mapping bad mac 52:54:00:aa:bb:cc ip 10.9.9.9",
        )
        .unwrap();
        assert!(s.commit().is_err(), "out-of-subnet reservation must fail");
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
            "set policy route-map from-peer default deny",
            "set policy route-map from-peer rule 10 match prefix 10.0.0.0/8+",
            "set policy route-map from-peer rule 10 set metric 100",
            "set policy route-map from-peer rule 10 set community 65001:200",
            "set policy route-map from-peer rule 10 action permit",
            "set policy route-map to-peer default permit",
        ] {
            run(&mut s, line).unwrap();
        }

        // `show` renders nested neighbor + route-map blocks.
        let shown = s.show();
        assert!(shown.contains("neighbor 10.10.0.2 {"), "got:\n{shown}");
        assert!(
            shown.contains("route-reflector-client true"),
            "got:\n{shown}"
        );
        assert!(shown.contains("import from-peer"), "got:\n{shown}");
        assert!(shown.contains("route-map from-peer {"), "got:\n{shown}");
        assert!(shown.contains("rule 10 {"), "got:\n{shown}");
        // permit/deny render, not the stored accept/reject.
        assert!(shown.contains("action permit"), "got:\n{shown}");
        assert!(shown.contains("default deny"), "got:\n{shown}");

        // It materializes into a validated Appliance carrying every field.
        let a = s.commit().expect("full bgp + route-map config commits");
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
        assert_eq!(a.policy.route_maps.len(), 2);
        // permit/deny stored as accept/reject.
        assert_eq!(a.policy.route_maps[0].default.as_deref(), Some("reject"));
        assert_eq!(a.policy.route_maps[0].rules[0].action, "accept");

        // Re-loading the drafted config reproduces the same routing view (rule
        // numbers are preserved by their explicit `seq`).
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
        assert!(
            reloaded.contains("route-map from-peer {"),
            "got:\n{reloaded}"
        );
        assert!(reloaded.contains("community 65001:200"), "got:\n{reloaded}");
        // The materialized config re-parses + re-validates from its own TOML.
        Appliance::from_toml(&a.to_toml().unwrap()).expect("re-parses");

        // Deleting a neighbour field and a route-map rule works.
        run(&mut s, "delete protocols bgp neighbor 10.10.0.2 passive").unwrap();
        assert!(!s.show().contains("passive true"));
        run(&mut s, "delete policy route-map from-peer rule 10").unwrap();
        assert!(!s.show().contains("rule 10 {"));
        assert!(run(&mut s, "delete policy route-map nope").is_err());
    }

    #[test]
    fn policy_prefix_list_and_route_map_round_trip() {
        let mut s = Session::empty();
        for line in [
            "set system hostname r1",
            // A prefix-list with two ge/le-bounded entries.
            "set policy prefix-list LAN rule 10 prefix 10.0.0.0/8",
            "set policy prefix-list LAN rule 10 le 24",
            "set policy prefix-list LAN rule 20 prefix 192.168.0.0/16",
            "set policy prefix-list LAN rule 20 ge 24",
            "set policy prefix-list LAN rule 20 le 30",
            // A route-map: rule 10 permits LAN prefixes and rewrites attributes;
            // rule 20 denies everything else.
            "set policy route-map IMPORT default deny",
            "set policy route-map IMPORT rule 10 action permit",
            "set policy route-map IMPORT rule 10 match prefix-list LAN",
            "set policy route-map IMPORT rule 10 set metric 100",
            "set policy route-map IMPORT rule 10 set community 65001:100",
            "set policy route-map IMPORT rule 20 action deny",
        ] {
            run(&mut s, line).unwrap();
        }

        // `show` renders the top-level policy block with match/set grouping.
        let shown = s.show();
        assert!(shown.contains("policy {"), "got:\n{shown}");
        assert!(shown.contains("prefix-list LAN {"), "got:\n{shown}");
        assert!(shown.contains("le 24"), "got:\n{shown}");
        assert!(shown.contains("route-map IMPORT {"), "got:\n{shown}");
        assert!(shown.contains("match {"), "got:\n{shown}");
        assert!(shown.contains("prefix-list LAN"), "got:\n{shown}");
        assert!(shown.contains("set {"), "got:\n{shown}");
        assert!(shown.contains("community 65001:100"), "got:\n{shown}");
        assert!(shown.contains("action permit"), "got:\n{shown}");

        // Materialize: policy is a top-level node; permit/deny stored as
        // accept/reject; the prefix-list keeps its seq/bounds.
        let a = s.commit().expect("policy config commits");
        assert_eq!(a.policy.prefix_lists.len(), 1);
        assert_eq!(a.policy.prefix_lists[0].entries.len(), 2);
        assert_eq!(a.policy.prefix_lists[0].entries[1].seq, 20);
        assert_eq!(a.policy.prefix_lists[0].entries[1].ge, Some(24));
        assert_eq!(a.policy.route_maps.len(), 1);
        let rm = &a.policy.route_maps[0];
        assert_eq!(rm.default.as_deref(), Some("reject"));
        assert_eq!(rm.rules[0].seq, 10);
        assert_eq!(rm.rules[0].action, "accept");
        assert_eq!(rm.rules[0].match_prefix_list.as_deref(), Some("LAN"));
        assert_eq!(rm.rules[0].set_metric, Some(100));
        assert_eq!(rm.rules[1].action, "reject");

        // from_appliance ∘ materialize is the identity on the policy node.
        let round = Session {
            draft: Draft::from_appliance(&a),
            path: PathBuf::from("/dev/null"),
            dirty: false,
        };
        let b = round.materialize().expect("re-materialises");
        assert_eq!(b.policy.prefix_lists.len(), 1);
        assert_eq!(b.policy.prefix_lists[0].entries[1].le, Some(30));
        assert_eq!(b.policy.route_maps[0].rules[0].set_metric, Some(100));
        assert_eq!(b.policy.route_maps[0].rules[1].action, "reject");
        // And it re-parses + re-validates from its own TOML.
        Appliance::from_toml(&a.to_toml().unwrap()).expect("re-parses");
    }

    #[test]
    fn policy_append_and_per_item_remove() {
        let mut s = Session::empty();
        for line in [
            "set system hostname r1",
            "set policy route-map M default permit",
            "set policy route-map M rule 10 action permit",
            "set policy route-map M rule 10 match prefix 10.0.0.0/8",
            "set policy route-map M rule 10 match prefix 172.16.0.0/12",
            "set policy route-map M rule 10 set add-community 65001:1",
            "set policy route-map M rule 10 set add-community 65001:2",
        ] {
            run(&mut s, line).unwrap();
        }
        let a = s.commit().expect("commits");
        let r = &a.policy.route_maps[0].rules[0];
        assert_eq!(r.prefix.len(), 2);
        assert_eq!(r.add_community.len(), 2);

        // A per-item remove drops just the named entry, leaving the rest.
        run(
            &mut s,
            "delete policy route-map M rule 10 match prefix 10.0.0.0/8",
        )
        .unwrap();
        run(
            &mut s,
            "delete policy route-map M rule 10 set add-community 65001:1",
        )
        .unwrap();
        let a = s.commit().expect("commits");
        let r = &a.policy.route_maps[0].rules[0];
        assert_eq!(r.prefix, ["172.16.0.0/12"]);
        assert_eq!(r.add_community, ["65001:2"]);
        // Removing an absent item is an error.
        assert!(
            run(
                &mut s,
                "delete policy route-map M rule 10 match prefix 8.8.8.8/32"
            )
            .is_err()
        );
    }

    #[test]
    fn policy_delete_rule_and_whole_object() {
        let mut s = Session::empty();
        for line in [
            "set system hostname r1",
            "set policy prefix-list PL rule 10 prefix 10.0.0.0/8",
            "set policy route-map M rule 10 action permit",
            "set policy route-map M rule 20 action deny",
        ] {
            run(&mut s, line).unwrap();
        }
        // Delete a single route-map rule.
        run(&mut s, "delete policy route-map M rule 20").unwrap();
        assert_eq!(s.commit().unwrap().policy.route_maps[0].rules.len(), 1);
        // Delete a whole prefix-list and a whole route-map.
        run(&mut s, "delete policy prefix-list PL").unwrap();
        run(&mut s, "delete policy route-map M").unwrap();
        let a = s.commit().unwrap();
        assert!(a.policy.is_empty());
        assert!(run(&mut s, "delete policy prefix-list PL").is_err());
    }

    #[test]
    fn policy_permit_deny_maps_to_accept_reject() {
        let mut s = Session::empty();
        run(&mut s, "set system hostname r1").unwrap();
        run(&mut s, "set policy route-map M default permit").unwrap();
        run(&mut s, "set policy route-map M rule 10 action deny").unwrap();
        // Commit stores accept/reject.
        let a = s.commit().unwrap();
        assert_eq!(a.policy.route_maps[0].default.as_deref(), Some("accept"));
        assert_eq!(a.policy.route_maps[0].rules[0].action, "reject");
        // Show renders permit/deny, never accept/reject.
        let shown = s.show();
        assert!(shown.contains("default permit"), "got:\n{shown}");
        assert!(shown.contains("action deny"), "got:\n{shown}");
        assert!(!shown.contains("accept"), "got:\n{shown}");
        assert!(!shown.contains("reject"), "got:\n{shown}");
    }

    #[test]
    fn igp_full_surface_set_show_commit_round_trip() {
        let mut s = Session::empty();
        for line in [
            "set system hostname r1",
            "set protocols router-id 10.0.0.1",
            // VRFs first, so per-protocol / static references resolve.
            "set protocols vrf blue table 100",
            "set protocols vrf blue rd 65000:1",
            "set protocols vrf blue interface eth3",
            "set protocols vrf blue import from-peer",
            "set protocols vrf blue export from-peer",
            "set policy route-map from-peer default deny",
            "set protocols static 10.9.0.0/24 via 10.0.0.2",
            "set protocols static 10.9.0.0/24 vrf blue",
            // OSPFv2 full surface.
            "set protocols ospf interface eth0",
            "set protocols ospf interface eth1 area 0.0.0.1",
            "set protocols ospf area 0.0.0.0",
            "set protocols ospf router-priority 5",
            "set protocols ospf cost 15",
            "set protocols ospf network-type point-to-point",
            "set protocols ospf passive-interface eth2",
            "set protocols ospf redistribute static",
            "set protocols ospf redistribute-metric 40",
            "set protocols ospf stub-area 0.0.0.2",
            "set protocols ospf stub-default-cost 5",
            "set protocols ospf nssa-area 0.0.0.3",
            "set protocols ospf totally-stubby-area 0.0.0.4",
            "set protocols ospf totally-nssa-area 0.0.0.5",
            "set protocols ospf nssa-default-area 0.0.0.6",
            "set protocols ospf auth-type md5",
            "set protocols ospf auth-key s3cret",
            "set protocols ospf auth-key-id 7",
            "set protocols ospf auth-replay-protection true",
            "set protocols ospf hello-interval 5",
            "set protocols ospf dead-interval 20",
            "set protocols ospf graceful-restart true",
            "set protocols ospf graceful-restart-period 90",
            "set protocols ospf bfd true",
            "set protocols ospf vrf blue",
            // OSPFv3.
            "set protocols ospf3 interface eth0",
            "set protocols ospf3 interface eth1 area 0.0.0.1",
            "set protocols ospf3 router-priority 3",
            "set protocols ospf3 instance-id 2",
            "set protocols ospf3 redistribute static",
            "set protocols ospf3 redistribute-metric 30",
            "set protocols ospf3 bfd true",
            // RIP + RIPng + Babel.
            "set protocols rip interface eth0",
            "set protocols rip bfd true",
            "set protocols rip vrf blue",
            "set protocols ripng interface eth0",
            "set protocols babel interface eth0",
            "set protocols babel network 2001:db8::/64",
            "set protocols babel router-id 10.0.0.1",
            "set protocols babel bfd true",
            "set protocols babel vrf blue",
            // IS-IS.
            "set protocols isis interface eth0",
            "set protocols isis system-id 1921.6800.1001",
            "set protocols isis area 49.0001",
            "set protocols isis level 1-2",
            "set protocols isis priority 100",
            "set protocols isis metric 20",
            "set protocols isis hello-interval 3",
            "set protocols isis l2-to-l1-leaking true",
            "set protocols isis bfd true",
            "set protocols isis vrf blue",
            // BGP vrf.
            "set protocols bgp local-as 65001",
            "set protocols bgp vrf blue",
            // VRRP full.
            "set protocols vrrp v1 interface eth0",
            "set protocols vrrp v1 vrid 10",
            "set protocols vrrp v1 priority 200",
            "set protocols vrrp v1 advert-interval 500",
            "set protocols vrrp v1 preempt false",
            "set protocols vrrp v1 prefix-length 24",
            "set protocols vrrp v1 track-interface eth1",
            "set protocols vrrp v1 priority-decrement 30",
            "set protocols vrrp v1 virtual-address 10.0.0.254",
            // BFD global.
            "set protocols bfd min-tx 250",
            "set protocols bfd min-rx 250",
            "set protocols bfd detect-mult 4",
            "set protocols bfd auth-type meticulous-sha1",
            "set protocols bfd auth-key-id 1",
            "set protocols bfd auth-key bfdsecret",
            "set protocols bfd echo true",
            "set protocols bfd echo-interval 100",
            // Multicast.
            "set protocols multicast enabled true",
            "set protocols multicast mld true",
            "set protocols multicast robustness 2",
            "set protocols multicast query-interval 30",
            "set protocols multicast interface lan0 role querier",
            "set protocols multicast interface wan0 role upstream",
            "set protocols multicast interface wan0 igmp-version 3",
            "set protocols multicast interface lan1 role downstream",
            // Global export / import filters.
            "set protocols export kernel from-peer",
            "set protocols export bgp from-peer",
            "set protocols import static from-peer",
            "set protocols import connected from-peer",
        ] {
            run(&mut s, line).unwrap();
        }

        let shown = s.show();
        for needle in [
            "interface eth1 area 0.0.0.1",
            "router-priority 5",
            "passive-interface eth2",
            "stub-area 0.0.0.2",
            "auth-type md5",
            "hello-interval 5",
            "graceful-restart true",
            "instance-id 2",
            "l2-to-l1-leaking true",
            "advert-interval 500",
            "preempt false",
            "track-interface eth1",
            "bfd {",
            "multicast {",
            "role upstream",
            "vrf blue {",
            "table 100",
            "export {",
            "import static from-peer",
        ] {
            assert!(shown.contains(needle), "missing {needle:?} in:\n{shown}");
        }

        // Materializes into a validated Appliance carrying the new fields.
        let a = s.commit().expect("full IGP config commits");
        let p = &a.protocols;
        let ospf = p.ospf.as_ref().unwrap();
        assert_eq!(ospf.router_priority, Some(5));
        assert_eq!(ospf.interface[0].area.as_deref(), Some("0.0.0.1"));
        assert_eq!(ospf.stub_areas, ["0.0.0.2"]);
        assert_eq!(ospf.auth_type.as_deref(), Some("md5"));
        assert!(ospf.graceful_restart && ospf.bfd);
        assert_eq!(ospf.vrf.as_deref(), Some("blue"));
        assert_eq!(p.ospf3.as_ref().unwrap().instance_id, Some(2));
        assert!(p.rip.as_ref().unwrap().bfd);
        let babel = p.babel.as_ref().unwrap();
        assert_eq!(babel.network, ["2001:db8::/64"]);
        assert_eq!(babel.router_id.as_deref(), Some("10.0.0.1"));
        let isis = p.isis.as_ref().unwrap();
        assert_eq!(isis.priority, Some(100));
        assert!(isis.l2_to_l1_leaking);
        let v = &p.vrrp[0];
        assert_eq!(v.advert_interval, Some(500));
        assert_eq!(v.preempt, Some(false));
        assert_eq!(v.track_interfaces, ["eth1"]);
        assert_eq!(p.bgp.as_ref().unwrap().vrf.as_deref(), Some("blue"));
        let bfd = p.bfd.as_ref().unwrap();
        assert_eq!(bfd.min_tx, Some(250));
        assert!(bfd.echo);
        let mc = p.multicast.as_ref().unwrap();
        assert!(mc.enabled);
        assert_eq!(mc.interfaces.len(), 3);
        assert_eq!(mc.interfaces[1].role.as_deref(), Some("upstream"));
        assert_eq!(p.vrfs[0].table, 100);
        assert_eq!(p.vrfs[0].import.as_deref(), Some("from-peer"));
        assert_eq!(p.statics[0].vrf.as_deref(), Some("blue"));
        assert_eq!(
            p.export.as_ref().unwrap().kernel.as_deref(),
            Some("from-peer")
        );
        assert_eq!(
            p.import.get("static").map(String::as_str),
            Some("from-peer")
        );

        // Full round-trip: the materialized config re-parses + re-validates, and
        // reloading it renders the same view.
        let toml = a.to_toml().unwrap();
        let a2 = Appliance::from_toml(&toml).expect("re-parses");
        a2.validate().expect("re-validates");
        let reloaded = render_appliance(&a2);
        for needle in [
            "interface eth1 area 0.0.0.1",
            "auth-type md5",
            "instance-id 2",
            "l2-to-l1-leaking true",
            "advert-interval 500",
            "multicast {",
            "vrf blue {",
        ] {
            assert!(
                reloaded.contains(needle),
                "reload missing {needle:?} in:\n{reloaded}"
            );
        }

        // Deletes work for a representative set of new fields.
        run(&mut s, "delete protocols ospf graceful-restart").unwrap();
        assert!(!s.show().contains("graceful-restart true"));
        run(&mut s, "delete protocols bfd").unwrap();
        assert!(!s.show().contains("bfd {"));
        run(&mut s, "delete protocols multicast interface wan0").unwrap();
        assert!(!s.show().contains("interface wan0"));
        run(&mut s, "delete protocols vrf blue interface").unwrap();
        run(&mut s, "delete protocols import static").unwrap();
        assert!(!s.show().contains("import static from-peer"));
    }

    #[test]
    fn ripng_rejects_unsupported_extras_via_grammar() {
        let mut s = Session::empty();
        run(&mut s, "set system hostname r1").unwrap();
        // The grammar offers no `bfd` / `vrf` / `network` / `router-id` on ripng.
        assert!(run(&mut s, "set protocols ripng bfd true").is_err());
        assert!(run(&mut s, "set protocols ripng vrf blue").is_err());
        assert!(run(&mut s, "set protocols ripng network 10.0.0.0/8").is_err());
    }

    #[test]
    fn update_channel_builds_shows_commits_and_round_trips() {
        let mut s = Session::empty();
        run(&mut s, "set system hostname box").unwrap();
        run(
            &mut s,
            "set update url https://updates.velstra.example/sentinel",
        )
        .unwrap();
        run(
            &mut s,
            "set update public-key file:/etc/sentinel/release.pem",
        )
        .unwrap();

        // The show block round-trips the channel + its fields.
        let shown = s.show_only("update");
        assert!(shown.contains("update {"), "got:\n{shown}");
        assert!(
            shown.contains("url https://updates.velstra.example/sentinel"),
            "got:\n{shown}"
        );
        assert!(
            shown.contains("public-key file:/etc/sentinel/release.pem"),
            "got:\n{shown}"
        );

        let a = s.commit().expect("valid update channel commits");
        let up = a.update.as_ref().expect("channel present");
        assert_eq!(up.url, "https://updates.velstra.example/sentinel");
        assert_eq!(up.public_key, "file:/etc/sentinel/release.pem");

        // A fresh session seeded from the committed appliance shows the same.
        let reloaded = Session {
            draft: Draft::from_appliance(&a),
            path: PathBuf::from("/dev/null"),
            dirty: false,
        }
        .show_only("update");
        assert!(
            reloaded.contains("url https://updates.velstra.example/sentinel"),
            "reload:\n{reloaded}"
        );
        assert!(
            reloaded.contains("public-key file:/etc/sentinel/release.pem"),
            "reload:\n{reloaded}"
        );
    }

    #[test]
    fn update_channel_delete_field_and_whole_block() {
        let mut s = Session::empty();
        run(&mut s, "set system hostname box").unwrap();
        run(&mut s, "set update url https://u.example/ch").unwrap();
        run(&mut s, "set update public-key file:/etc/k.pem").unwrap();

        // Clearing a required field leaves the block dangling — commit then fails
        // fast with the config-layer "required" message rather than dropping it.
        run(&mut s, "delete update public-key").unwrap();
        let err = s.commit().unwrap_err().to_string();
        assert!(err.contains("public-key is required"), "got: {err}");

        // Restoring it commits again.
        run(&mut s, "set update public-key file:/etc/k.pem").unwrap();
        s.commit().expect("valid again after restore");

        // Deleting the whole block removes it entirely (a config with no channel
        // is valid).
        run(&mut s, "delete update").unwrap();
        let a = s.commit().expect("valid with no channel");
        assert!(a.update.is_none());
        assert!(!s.show().contains("update {"));

        // Deleting a field of an absent channel is an error.
        let err = run(&mut s, "delete update url").unwrap_err().to_string();
        assert!(err.contains("no update channel"), "got: {err}");
    }

    #[test]
    fn update_channel_materialize_round_trips() {
        let mut s = Session::empty();
        run(&mut s, "set system hostname box").unwrap();
        run(&mut s, "set update url file:///srv/mirror/sentinel").unwrap();
        run(&mut s, "set update public-key file:/etc/sentinel/k.pem").unwrap();

        let a = s.commit().expect("valid update channel commits");
        // from_appliance ∘ materialize is the identity on the channel.
        let round = Session {
            draft: Draft::from_appliance(&a),
            path: PathBuf::from("/dev/null"),
            dirty: false,
        };
        let b = round.materialize().expect("re-materialises");
        assert_eq!(
            a.update.as_ref().unwrap().url,
            b.update.as_ref().unwrap().url
        );
        assert_eq!(
            a.update.as_ref().unwrap().public_key,
            b.update.as_ref().unwrap().public_key
        );
    }
}
