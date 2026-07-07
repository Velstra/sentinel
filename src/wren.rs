//! Compile the appliance's `[protocols]` config into the TOML the Wren routing
//! daemon loads (`/run/sentinel/wren.toml`).
//!
//! The appliance config ([`crate::config::Protocols`]) is already shaped after
//! Wren's schema, so this is a thin translation: it adds Wren's per-protocol
//! `enabled = true` flag and resolves the BGP router-id fallback to the global
//! `[protocols] router-id`. Serialized field order keeps the top-level scalar
//! (`router-id`) before the `[[static]]` / `[bgp]` tables, as TOML requires.

use crate::config::Appliance;
use serde::Serialize;

/// The Wren daemon's top-level config, serialized to `/run/sentinel/wren.toml`.
#[derive(Debug, Serialize)]
pub struct WrenConfig {
    #[serde(rename = "router-id", skip_serializing_if = "Option::is_none")]
    router_id: Option<String>,
    #[serde(rename = "static", skip_serializing_if = "Vec::is_empty")]
    statics: Vec<WrenStatic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ospf: Option<WrenOspf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ospf3: Option<WrenOspf3>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rip: Option<WrenRip>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ripng: Option<WrenRip>,
    #[serde(skip_serializing_if = "Option::is_none")]
    babel: Option<WrenRip>,
    #[serde(skip_serializing_if = "Option::is_none")]
    isis: Option<WrenIsis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bgp: Option<WrenBgp>,
    #[serde(rename = "vrrp", skip_serializing_if = "Vec::is_empty")]
    vrrp: Vec<WrenVrrp>,
    #[serde(rename = "vrf", skip_serializing_if = "Vec::is_empty")]
    vrfs: Vec<WrenVrf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bfd: Option<WrenBfd>,
    #[serde(skip_serializing_if = "Option::is_none")]
    multicast: Option<WrenMulticast>,
    #[serde(rename = "filter", skip_serializing_if = "Vec::is_empty")]
    filters: Vec<WrenFilter>,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    import: std::collections::BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    export: Option<WrenExport>,
}

#[derive(Debug, Serialize)]
struct WrenStatic {
    prefix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    via: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dev: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metric: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vrf: Option<String>,
}

#[derive(Debug, Serialize)]
struct WrenBgp {
    enabled: bool,
    #[serde(rename = "local-as")]
    local_as: u32,
    #[serde(rename = "router-id", skip_serializing_if = "Option::is_none")]
    router_id: Option<String>,
    #[serde(rename = "hold-time", skip_serializing_if = "Option::is_none")]
    hold_time: Option<u16>,
    #[serde(rename = "cluster-id", skip_serializing_if = "Option::is_none")]
    cluster_id: Option<String>,
    #[serde(rename = "confederation-id", skip_serializing_if = "Option::is_none")]
    confederation_id: Option<u32>,
    #[serde(
        rename = "confederation-members",
        skip_serializing_if = "Vec::is_empty"
    )]
    confederation_members: Vec<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    community: Vec<String>,
    #[serde(rename = "large-community", skip_serializing_if = "Vec::is_empty")]
    large_community: Vec<String>,
    #[serde(rename = "ext-community", skip_serializing_if = "Vec::is_empty")]
    ext_community: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    network: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    redistribute: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    multipath: Option<usize>,
    #[serde(
        rename = "rpki-reject-invalid",
        skip_serializing_if = "std::ops::Not::not"
    )]
    rpki_reject_invalid: bool,
    #[serde(
        rename = "ebgp-require-policy",
        skip_serializing_if = "std::ops::Not::not"
    )]
    ebgp_require_policy: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    vrf: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rtr: Option<WrenRtr>,
    #[serde(rename = "aggregate", skip_serializing_if = "Vec::is_empty")]
    aggregate: Vec<WrenAggregate>,
    #[serde(rename = "roa", skip_serializing_if = "Vec::is_empty")]
    roa: Vec<WrenRoa>,
    #[serde(rename = "neighbor", skip_serializing_if = "Vec::is_empty")]
    neighbors: Vec<WrenNeighbor>,
}

#[derive(Debug, Serialize)]
struct WrenRtr {
    server: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh: Option<u32>,
}

#[derive(Debug, Serialize)]
struct WrenAggregate {
    prefix: String,
    #[serde(rename = "summary-only", skip_serializing_if = "std::ops::Not::not")]
    summary_only: bool,
}

#[derive(Debug, Serialize)]
struct WrenRoa {
    prefix: String,
    #[serde(rename = "max-length", skip_serializing_if = "Option::is_none")]
    max_length: Option<u8>,
    #[serde(rename = "origin-as")]
    origin_as: u32,
}

#[derive(Debug, Serialize)]
struct WrenNeighbor {
    address: String,
    #[serde(rename = "remote-as")]
    remote_as: u32,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    passive: bool,
    #[serde(
        rename = "route-reflector-client",
        skip_serializing_if = "std::ops::Not::not"
    )]
    route_reflector_client: bool,
    #[serde(rename = "ttl-security", skip_serializing_if = "Option::is_none")]
    ttl_security: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    #[serde(rename = "ao-key", skip_serializing_if = "Option::is_none")]
    ao_key: Option<String>,
    #[serde(rename = "ao-key-id", skip_serializing_if = "Option::is_none")]
    ao_key_id: Option<u8>,
    #[serde(rename = "max-prefix", skip_serializing_if = "Option::is_none")]
    max_prefix: Option<u32>,
    #[serde(
        rename = "default-originate",
        skip_serializing_if = "std::ops::Not::not"
    )]
    default_originate: bool,
    #[serde(rename = "add-path", skip_serializing_if = "std::ops::Not::not")]
    add_path: bool,
    #[serde(
        rename = "extended-nexthop",
        skip_serializing_if = "std::ops::Not::not"
    )]
    extended_nexthop: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    evpn: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    flowspec: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    srpolicy: bool,
    #[serde(rename = "link-state", skip_serializing_if = "std::ops::Not::not")]
    link_state: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    import: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    export: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    bfd: bool,
    #[serde(rename = "bfd-auth-type", skip_serializing_if = "Option::is_none")]
    bfd_auth_type: Option<String>,
    #[serde(rename = "bfd-auth-key-id", skip_serializing_if = "Option::is_none")]
    bfd_auth_key_id: Option<u8>,
    #[serde(rename = "bfd-auth-key", skip_serializing_if = "Option::is_none")]
    bfd_auth_key: Option<String>,
    #[serde(rename = "local-as", skip_serializing_if = "Option::is_none")]
    local_as: Option<u32>,
    #[serde(rename = "update-source", skip_serializing_if = "Option::is_none")]
    update_source: Option<String>,
    #[serde(rename = "ebgp-multihop", skip_serializing_if = "Option::is_none")]
    ebgp_multihop: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    shutdown: bool,
    #[serde(rename = "hold-time", skip_serializing_if = "Option::is_none")]
    hold_time: Option<u16>,
}

#[derive(Debug, Serialize)]
struct WrenFilter {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    default: Option<String>,
    #[serde(rename = "rule", skip_serializing_if = "Vec::is_empty")]
    rules: Vec<WrenFilterRule>,
}

#[derive(Debug, Serialize)]
struct WrenFilterRule {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    prefix: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(rename = "metric-le", skip_serializing_if = "Option::is_none")]
    metric_le: Option<u32>,
    #[serde(rename = "metric-ge", skip_serializing_if = "Option::is_none")]
    metric_ge: Option<u32>,
    #[serde(rename = "set-metric", skip_serializing_if = "Option::is_none")]
    set_metric: Option<u32>,
    #[serde(rename = "add-metric", skip_serializing_if = "Option::is_none")]
    add_metric: Option<i64>,
    #[serde(rename = "set-preference", skip_serializing_if = "Option::is_none")]
    set_preference: Option<u32>,
    #[serde(rename = "set-community", skip_serializing_if = "Option::is_none")]
    set_community: Option<Vec<String>>,
    #[serde(rename = "add-community", skip_serializing_if = "Vec::is_empty")]
    add_community: Vec<String>,
    #[serde(
        rename = "set-large-community",
        skip_serializing_if = "Option::is_none"
    )]
    set_large_community: Option<Vec<String>>,
    #[serde(rename = "add-large-community", skip_serializing_if = "Vec::is_empty")]
    add_large_community: Vec<String>,
    #[serde(rename = "set-ext-community", skip_serializing_if = "Option::is_none")]
    set_ext_community: Option<Vec<String>>,
    #[serde(rename = "add-ext-community", skip_serializing_if = "Vec::is_empty")]
    add_ext_community: Vec<String>,
    action: String,
}

#[derive(Debug, Serialize)]
struct WrenOspf {
    enabled: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    interfaces: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    area: Option<String>,
    #[serde(rename = "router-priority", skip_serializing_if = "Option::is_none")]
    router_priority: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cost: Option<u16>,
    #[serde(rename = "network-type", skip_serializing_if = "Option::is_none")]
    network_type: Option<String>,
    #[serde(rename = "passive-interfaces", skip_serializing_if = "Vec::is_empty")]
    passive_interfaces: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    redistribute: Vec<String>,
    #[serde(
        rename = "redistribute-metric",
        skip_serializing_if = "Option::is_none"
    )]
    redistribute_metric: Option<u32>,
    #[serde(rename = "stub-areas", skip_serializing_if = "Vec::is_empty")]
    stub_areas: Vec<String>,
    #[serde(rename = "stub-default-cost", skip_serializing_if = "Option::is_none")]
    stub_default_cost: Option<u32>,
    #[serde(rename = "nssa-areas", skip_serializing_if = "Vec::is_empty")]
    nssa_areas: Vec<String>,
    #[serde(rename = "totally-stubby-areas", skip_serializing_if = "Vec::is_empty")]
    totally_stubby_areas: Vec<String>,
    #[serde(rename = "totally-nssa-areas", skip_serializing_if = "Vec::is_empty")]
    totally_nssa_areas: Vec<String>,
    #[serde(rename = "nssa-default-areas", skip_serializing_if = "Vec::is_empty")]
    nssa_default_areas: Vec<String>,
    #[serde(rename = "auth-type", skip_serializing_if = "Option::is_none")]
    auth_type: Option<String>,
    #[serde(rename = "auth-key", skip_serializing_if = "Option::is_none")]
    auth_key: Option<String>,
    #[serde(rename = "auth-key-id", skip_serializing_if = "Option::is_none")]
    auth_key_id: Option<u8>,
    #[serde(
        rename = "auth-replay-protection",
        skip_serializing_if = "Option::is_none"
    )]
    auth_replay_protection: Option<bool>,
    #[serde(rename = "hello-interval", skip_serializing_if = "Option::is_none")]
    hello_interval: Option<u16>,
    #[serde(rename = "dead-interval", skip_serializing_if = "Option::is_none")]
    dead_interval: Option<u32>,
    #[serde(
        rename = "graceful-restart",
        skip_serializing_if = "std::ops::Not::not"
    )]
    graceful_restart: bool,
    #[serde(
        rename = "graceful-restart-period",
        skip_serializing_if = "Option::is_none"
    )]
    graceful_restart_period: Option<u32>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    bfd: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    vrf: Option<String>,
    // Array-of-tables — must serialize after every scalar field of `[ospf]`.
    #[serde(rename = "interface", skip_serializing_if = "Vec::is_empty")]
    interface: Vec<WrenOspfInterface>,
}

#[derive(Debug, Serialize)]
struct WrenOspfInterface {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    area: Option<String>,
}

#[derive(Debug, Serialize)]
struct WrenOspf3 {
    enabled: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    interfaces: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    area: Option<String>,
    #[serde(rename = "router-priority", skip_serializing_if = "Option::is_none")]
    router_priority: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cost: Option<u16>,
    #[serde(rename = "network-type", skip_serializing_if = "Option::is_none")]
    network_type: Option<String>,
    #[serde(rename = "instance-id", skip_serializing_if = "Option::is_none")]
    instance_id: Option<u8>,
    /// OSPFv3 only redistributes static externals (a bool in wren's schema).
    #[serde(
        rename = "redistribute-static",
        skip_serializing_if = "std::ops::Not::not"
    )]
    redistribute_static: bool,
    #[serde(
        rename = "redistribute-metric",
        skip_serializing_if = "Option::is_none"
    )]
    redistribute_metric: Option<u32>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    bfd: bool,
    // Array-of-tables — must serialize after every scalar field of `[ospf3]`.
    #[serde(rename = "interface", skip_serializing_if = "Vec::is_empty")]
    interface: Vec<WrenOspfInterface>,
}

#[derive(Debug, Serialize)]
struct WrenRip {
    enabled: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    interfaces: Vec<String>,
    /// Babel only (RIP/RIPng ignore these — populated only for the babel table).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    network: Vec<String>,
    #[serde(rename = "router-id", skip_serializing_if = "Option::is_none")]
    router_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    redistribute: Vec<String>,
    #[serde(
        rename = "redistribute-metric",
        skip_serializing_if = "Option::is_none"
    )]
    redistribute_metric: Option<u32>,
    /// RIP and Babel only (RIPng's schema has no `bfd`/`vrf`).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    bfd: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    vrf: Option<String>,
}

#[derive(Debug, Serialize)]
struct WrenIsis {
    enabled: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    interfaces: Vec<String>,
    #[serde(rename = "system-id", skip_serializing_if = "Option::is_none")]
    system_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    area: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metric: Option<u32>,
    #[serde(rename = "hello-interval", skip_serializing_if = "Option::is_none")]
    hello_interval: Option<u64>,
    #[serde(rename = "network-type", skip_serializing_if = "Option::is_none")]
    network_type: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    redistribute: Vec<String>,
    #[serde(
        rename = "redistribute-metric",
        skip_serializing_if = "Option::is_none"
    )]
    redistribute_metric: Option<u32>,
    #[serde(
        rename = "l2-to-l1-leaking",
        skip_serializing_if = "std::ops::Not::not"
    )]
    l2_to_l1_leaking: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    bfd: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    vrf: Option<String>,
}

#[derive(Debug, Serialize)]
struct WrenVrrp {
    interface: String,
    vrid: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u8>,
    #[serde(rename = "advert-interval", skip_serializing_if = "Option::is_none")]
    advert_interval: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preempt: Option<bool>,
    #[serde(rename = "prefix-length", skip_serializing_if = "Option::is_none")]
    prefix_length: Option<u8>,
    #[serde(rename = "track-interface", skip_serializing_if = "Vec::is_empty")]
    track_interfaces: Vec<String>,
    #[serde(rename = "priority-decrement", skip_serializing_if = "Option::is_none")]
    priority_decrement: Option<u8>,
    #[serde(rename = "virtual-address", skip_serializing_if = "Vec::is_empty")]
    virtual_address: Vec<String>,
}

#[derive(Debug, Serialize)]
struct WrenBfd {
    #[serde(rename = "min-tx", skip_serializing_if = "Option::is_none")]
    min_tx: Option<u32>,
    #[serde(rename = "min-rx", skip_serializing_if = "Option::is_none")]
    min_rx: Option<u32>,
    #[serde(rename = "detect-mult", skip_serializing_if = "Option::is_none")]
    detect_mult: Option<u8>,
    #[serde(rename = "auth-type", skip_serializing_if = "Option::is_none")]
    auth_type: Option<String>,
    #[serde(rename = "auth-key-id", skip_serializing_if = "Option::is_none")]
    auth_key_id: Option<u8>,
    #[serde(rename = "auth-key", skip_serializing_if = "Option::is_none")]
    auth_key: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    echo: bool,
    #[serde(rename = "echo-interval", skip_serializing_if = "Option::is_none")]
    echo_interval: Option<u32>,
}

#[derive(Debug, Serialize)]
struct WrenMulticast {
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    igmp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mld: Option<bool>,
    #[serde(rename = "igmp-version", skip_serializing_if = "Option::is_none")]
    igmp_version: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    robustness: Option<u8>,
    #[serde(rename = "query-interval", skip_serializing_if = "Option::is_none")]
    query_interval: Option<u32>,
    #[serde(
        rename = "query-response-interval",
        skip_serializing_if = "Option::is_none"
    )]
    query_response_interval: Option<u32>,
    // Array-of-tables — must serialize after every scalar field of `[multicast]`.
    #[serde(rename = "interface", skip_serializing_if = "Vec::is_empty")]
    interfaces: Vec<WrenMulticastInterface>,
}

#[derive(Debug, Serialize)]
struct WrenMulticastInterface {
    name: String,
    role: String,
    #[serde(rename = "igmp-version", skip_serializing_if = "Option::is_none")]
    igmp_version: Option<u8>,
}

#[derive(Debug, Serialize)]
struct WrenVrf {
    name: String,
    table: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    rd: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    interfaces: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    import: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    export: Option<String>,
}

#[derive(Debug, Serialize)]
struct WrenExport {
    #[serde(skip_serializing_if = "Option::is_none")]
    kernel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bgp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ospf: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ripng: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    babel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    isis: Option<String>,
}

impl WrenConfig {
    /// Render as the TOML the Wren daemon loads with `--config`.
    pub fn to_toml(&self) -> anyhow::Result<String> {
        use anyhow::Context;
        toml::to_string_pretty(self).context("serializing the wren config")
    }
}

/// Compile the appliance's routing config into a Wren config. The BGP router-id
/// falls back to the global `[protocols] router-id` when unset.
pub fn compile_wren(appliance: &Appliance) -> WrenConfig {
    let p = &appliance.protocols;

    let statics = p
        .statics
        .iter()
        .map(|s| WrenStatic {
            prefix: s.prefix.clone(),
            via: s.via.clone(),
            dev: s.dev.clone(),
            metric: s.metric,
            vrf: s.vrf.clone(),
        })
        .collect();

    let bgp = p.bgp.as_ref().map(|b| WrenBgp {
        enabled: true,
        local_as: b.local_as,
        router_id: b.router_id.clone().or_else(|| p.router_id.clone()),
        hold_time: b.hold_time,
        cluster_id: b.cluster_id.clone(),
        confederation_id: b.confederation_id,
        confederation_members: b.confederation_members.clone(),
        community: b.community.clone(),
        large_community: b.large_community.clone(),
        ext_community: b.ext_community.clone(),
        network: b.network.clone(),
        redistribute: b.redistribute.clone(),
        multipath: b.multipath,
        rpki_reject_invalid: b.rpki_reject_invalid,
        ebgp_require_policy: b.ebgp_require_policy,
        vrf: b.vrf.clone(),
        rtr: b.rtr.as_ref().map(|r| WrenRtr {
            server: r.server.clone(),
            refresh: r.refresh,
        }),
        aggregate: b
            .aggregate
            .iter()
            .map(|a| WrenAggregate {
                prefix: a.prefix.clone(),
                summary_only: a.summary_only,
            })
            .collect(),
        roa: b
            .roa
            .iter()
            .map(|r| WrenRoa {
                prefix: r.prefix.clone(),
                max_length: r.max_length,
                origin_as: r.origin_as,
            })
            .collect(),
        neighbors: b.neighbors.iter().map(compile_neighbor).collect(),
    });

    let filters = p.filters.iter().map(compile_filter).collect();

    let ospf_interfaces = |ifs: &[crate::config::OspfInterface]| {
        ifs.iter()
            .map(|i| WrenOspfInterface {
                name: i.name.clone(),
                area: i.area.clone(),
            })
            .collect::<Vec<_>>()
    };
    let ospf = p.ospf.as_ref().map(|o| WrenOspf {
        enabled: true,
        interfaces: o.interfaces.clone(),
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
        interface: ospf_interfaces(&o.interface),
    });

    let ospf3 = p.ospf3.as_ref().map(|o| WrenOspf3 {
        enabled: true,
        interfaces: o.interfaces.clone(),
        area: o.area.clone(),
        router_priority: o.router_priority,
        cost: o.cost,
        network_type: o.network_type.clone(),
        instance_id: o.instance_id,
        // OSPFv3 only redistributes static externals (bool in wren's schema).
        redistribute_static: o.redistribute.iter().any(|s| s == "static"),
        redistribute_metric: o.redistribute_metric,
        bfd: o.bfd,
        interface: ospf_interfaces(&o.interface),
    });

    // RIP, RIPng and Babel share the appliance `Rip` shape, but Wren's RIPng
    // accepts none of the extras and only Babel takes `network`/`router-id` — so
    // each protocol emits just the fields its Wren schema has.
    let rip = p.rip.as_ref().map(|r| WrenRip {
        enabled: true,
        interfaces: r.interfaces.clone(),
        network: Vec::new(),
        router_id: None,
        redistribute: r.redistribute.clone(),
        redistribute_metric: r.redistribute_metric,
        bfd: r.bfd,
        vrf: r.vrf.clone(),
    });
    let ripng = p.ripng.as_ref().map(|r| WrenRip {
        enabled: true,
        interfaces: r.interfaces.clone(),
        network: Vec::new(),
        router_id: None,
        redistribute: r.redistribute.clone(),
        redistribute_metric: r.redistribute_metric,
        bfd: false,
        vrf: None,
    });
    let babel = p.babel.as_ref().map(|r| WrenRip {
        enabled: true,
        interfaces: r.interfaces.clone(),
        network: r.network.clone(),
        router_id: r.router_id.clone(),
        redistribute: r.redistribute.clone(),
        redistribute_metric: r.redistribute_metric,
        bfd: r.bfd,
        vrf: r.vrf.clone(),
    });

    let isis = p.isis.as_ref().map(|i| WrenIsis {
        enabled: true,
        interfaces: i.interfaces.clone(),
        system_id: i.system_id.clone(),
        area: i.area.clone(),
        // The appliance grammar speaks IOS-style levels ("1" | "2" | "1-2");
        // wren's schema wants "l1" | "l2" | "l1l2". Translate here so the
        // operator spelling never leaks into the daemon config.
        level: i.level.as_deref().map(|l| {
            match l {
                "1" => "l1",
                "2" => "l2",
                "1-2" => "l1l2",
                other => other, // already a wren spelling ("l1", "l2", "l1l2")
            }
            .to_string()
        }),
        priority: i.priority,
        metric: i.metric,
        hello_interval: i.hello_interval,
        network_type: i.network_type.clone(),
        redistribute: i.redistribute.clone(),
        redistribute_metric: i.redistribute_metric,
        l2_to_l1_leaking: i.l2_to_l1_leaking,
        bfd: i.bfd,
        vrf: i.vrf.clone(),
    });

    let vrrp = p
        .vrrp
        .iter()
        .map(|v| WrenVrrp {
            interface: v.interface.clone(),
            vrid: v.vrid,
            priority: v.priority,
            advert_interval: v.advert_interval,
            preempt: v.preempt,
            prefix_length: v.prefix_length,
            track_interfaces: v.track_interfaces.clone(),
            priority_decrement: v.priority_decrement,
            virtual_address: v.virtual_address.clone(),
        })
        .collect();

    let vrfs = p
        .vrfs
        .iter()
        .map(|v| WrenVrf {
            name: v.name.clone(),
            table: v.table,
            rd: v.rd.clone(),
            interfaces: v.interfaces.clone(),
            import: v.import.clone(),
            export: v.export.clone(),
        })
        .collect();

    let bfd = p.bfd.as_ref().map(|b| WrenBfd {
        min_tx: b.min_tx,
        min_rx: b.min_rx,
        detect_mult: b.detect_mult,
        auth_type: b.auth_type.clone(),
        auth_key_id: b.auth_key_id,
        auth_key: b.auth_key.clone(),
        echo: b.echo,
        echo_interval: b.echo_interval,
    });

    let multicast = p.multicast.as_ref().map(|m| WrenMulticast {
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
            .map(|i| WrenMulticastInterface {
                name: i.name.clone(),
                role: i.role.clone().unwrap_or_else(|| "querier".to_string()),
                igmp_version: i.igmp_version,
            })
            .collect(),
    });

    let export = p.export.as_ref().map(|e| WrenExport {
        kernel: e.kernel.clone(),
        bgp: e.bgp.clone(),
        ospf: e.ospf.clone(),
        rip: e.rip.clone(),
        ripng: e.ripng.clone(),
        babel: e.babel.clone(),
        isis: e.isis.clone(),
    });

    WrenConfig {
        router_id: p.router_id.clone(),
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
        filters,
        import: p.import.clone(),
        export,
    }
}

/// Translate one appliance BGP neighbour into its Wren form (a thin field copy —
/// the appliance model is already shaped after Wren's schema).
fn compile_neighbor(n: &crate::config::BgpNeighbor) -> WrenNeighbor {
    WrenNeighbor {
        address: n.address.clone(),
        remote_as: n.remote_as,
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

/// Translate one appliance route filter into its Wren `[[filter]]` form.
fn compile_filter(f: &crate::config::Filter) -> WrenFilter {
    WrenFilter {
        name: f.name.clone(),
        default: f.default.clone(),
        rules: f
            .rules
            .iter()
            .map(|r| WrenFilterRule {
                prefix: r.prefix.clone(),
                protocol: r.protocol.clone(),
                metric_le: r.metric_le,
                metric_ge: r.metric_ge,
                set_metric: r.set_metric,
                add_metric: r.add_metric,
                set_preference: r.set_preference,
                set_community: r.set_community.clone(),
                add_community: r.add_community.clone(),
                set_large_community: r.set_large_community.clone(),
                add_large_community: r.add_large_community.clone(),
                set_ext_community: r.set_ext_community.clone(),
                add_ext_community: r.add_ext_community.clone(),
                action: r.action.clone(),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Appliance;

    #[test]
    fn bgp_compiles_with_enabled_and_router_id_fallback() {
        let toml = r#"
[system]
hostname = "r1"
[protocols]
router-id = "10.0.0.1"
[protocols.bgp]
local-as = 65001
network = ["10.11.0.0/24"]
redistribute = ["static"]
[[protocols.bgp.neighbor]]
address = "10.10.0.2"
remote-as = 65002
"#;
        let appliance = Appliance::from_toml(toml).unwrap();
        let out = compile_wren(&appliance).to_toml().unwrap();
        assert!(out.contains("router-id = \"10.0.0.1\""), "{out}");
        assert!(out.contains("enabled = true"), "{out}");
        assert!(out.contains("local-as = 65001"), "{out}");
        assert!(out.contains("remote-as = 65002"), "{out}");
        assert!(out.contains("[[bgp.neighbor]]"), "{out}");
        // The BGP router-id falls back to the global protocols router-id.
        let bgp_section = out.split("[bgp]").nth(1).unwrap();
        assert!(bgp_section.contains("router-id = \"10.0.0.1\""), "{out}");
    }

    #[test]
    fn ospf_compiles_with_enabled_and_fields() {
        let toml = r#"
[system]
hostname = "r1"
[protocols]
router-id = "10.0.0.1"
[protocols.ospf]
interfaces = ["eth1"]
area = "0.0.0.0"
network-type = "point-to-point"
redistribute = ["static"]
"#;
        let appliance = Appliance::from_toml(toml).unwrap();
        let out = compile_wren(&appliance).to_toml().unwrap();
        assert!(out.contains("[ospf]"), "{out}");
        let ospf = out.split("[ospf]").nth(1).unwrap();
        assert!(ospf.contains("enabled = true"), "{out}");
        assert!(ospf.contains("area = \"0.0.0.0\""), "{out}");
        assert!(ospf.contains("network-type = \"point-to-point\""), "{out}");
        assert!(ospf.contains("\"eth1\""), "{out}");
    }

    #[test]
    fn all_igps_and_vrrp_compile() {
        let toml = r#"
[system]
hostname = "r1"
[protocols]
router-id = "10.0.0.1"
[protocols.ospf3]
interfaces = ["eth1"]
redistribute = ["static"]
[protocols.rip]
interfaces = ["eth1"]
redistribute = ["connected"]
[protocols.ripng]
interfaces = ["eth1"]
[protocols.babel]
interfaces = ["eth1"]
[protocols.isis]
interfaces = ["eth1"]
system-id = "0000.0000.0001"
area = "49.0001"
level = "2"
[[protocols.vrrp]]
name = "gw"
interface = "eth1"
vrid = 10
priority = 200
virtual-address = ["10.0.0.254"]
"#;
        let appliance = Appliance::from_toml(toml).unwrap();
        let out = compile_wren(&appliance).to_toml().unwrap();
        assert!(out.contains("[ospf3]"), "{out}");
        assert!(out.contains("redistribute-static = true"), "{out}");
        assert!(out.contains("[rip]"), "{out}");
        assert!(out.contains("[ripng]"), "{out}");
        assert!(out.contains("[babel]"), "{out}");
        assert!(out.contains("[isis]"), "{out}");
        assert!(out.contains("system-id = \"0000.0000.0001\""), "{out}");
        assert!(out.contains("[[vrrp]]"), "{out}");
        assert!(out.contains("vrid = 10"), "{out}");
        // Every enabled protocol carries `enabled = true`.
        assert_eq!(out.matches("enabled = true").count(), 5, "{out}");
    }

    #[test]
    fn full_igp_surface_emits_wren_spellings() {
        let toml = r#"
[system]
hostname = "r1"
[protocols]
router-id = "10.0.0.1"
import = { static = "f1", connected = "f1" }
[[protocols.filter]]
name = "f1"
default = "accept"
[[protocols.vrf]]
name = "blue"
table = 100
rd = "65000:1"
interfaces = ["eth3"]
import = "f1"
export = "f1"
[[protocols.static]]
prefix = "10.9.0.0/24"
via = "10.0.0.2"
vrf = "blue"
[protocols.export]
kernel = "f1"
bgp = "f1"
[protocols.ospf]
interfaces = ["eth0"]
area = "0.0.0.0"
router-priority = 5
passive-interfaces = ["eth2"]
redistribute = ["static"]
redistribute-metric = 40
stub-areas = ["0.0.0.2"]
stub-default-cost = 5
nssa-default-areas = ["0.0.0.6"]
auth-type = "md5"
auth-key = "s3cret"
auth-key-id = 7
auth-replay-protection = true
hello-interval = 5
dead-interval = 20
graceful-restart = true
graceful-restart-period = 90
bfd = true
vrf = "blue"
[[protocols.ospf.interface]]
name = "eth1"
area = "0.0.0.1"
[protocols.ospf3]
interfaces = ["eth0"]
router-priority = 3
instance-id = 2
redistribute = ["static"]
redistribute-metric = 30
bfd = true
[[protocols.ospf3.interface]]
name = "eth1"
area = "0.0.0.1"
[protocols.rip]
interfaces = ["eth0"]
bfd = true
vrf = "blue"
[protocols.ripng]
interfaces = ["eth0"]
[protocols.babel]
interfaces = ["eth0"]
network = ["2001:db8::/64"]
router-id = "10.0.0.1"
bfd = true
vrf = "blue"
[protocols.isis]
interfaces = ["eth0"]
system-id = "1921.6800.1001"
level = "2"
priority = 100
metric = 20
hello-interval = 3
l2-to-l1-leaking = true
bfd = true
vrf = "blue"
[protocols.bfd]
min-tx = 250
min-rx = 250
detect-mult = 4
auth-type = "meticulous-sha1"
auth-key-id = 1
auth-key = "bfdsecret"
echo = true
echo-interval = 100
[protocols.multicast]
enabled = true
mld = true
robustness = 2
query-interval = 30
[[protocols.multicast.interface]]
name = "lan0"
role = "querier"
[[protocols.multicast.interface]]
name = "wan0"
role = "upstream"
igmp-version = 3
[[protocols.vrrp]]
name = "v1"
interface = "eth0"
vrid = 10
priority = 200
advert-interval = 500
preempt = false
prefix-length = 24
track-interface = ["eth1"]
priority-decrement = 30
virtual-address = ["10.0.0.254"]
"#;
        let appliance = Appliance::from_toml(toml).unwrap();
        appliance.validate().expect("valid appliance");
        let out = compile_wren(&appliance).to_toml().unwrap();
        for needle in [
            // OSPFv2.
            "[[ospf.interface]]",
            "router-priority = 5",
            "passive-interfaces = [\"eth2\"]",
            "redistribute-metric = 40",
            "stub-areas = [\"0.0.0.2\"]",
            "stub-default-cost = 5",
            "nssa-default-areas = [\"0.0.0.6\"]",
            "auth-type = \"md5\"",
            "auth-replay-protection = true",
            "hello-interval = 5",
            "dead-interval = 20",
            "graceful-restart = true",
            "graceful-restart-period = 90",
            // OSPFv3.
            "[[ospf3.interface]]",
            "instance-id = 2",
            // Babel-only network/router-id + rip/babel bfd.
            "network = [\"2001:db8::/64\"]",
            // IS-IS. The IOS-style level "2" translates to wren's "l2".
            "level = \"l2\"",
            "l2-to-l1-leaking = true",
            // VRRP.
            "advert-interval = 500",
            "preempt = false",
            "prefix-length = 24",
            "track-interface = [\"eth1\"]",
            "priority-decrement = 30",
            // Global BFD.
            "[bfd]",
            "min-tx = 250",
            "detect-mult = 4",
            "echo = true",
            // Multicast.
            "[multicast]",
            "[[multicast.interface]]",
            "role = \"upstream\"",
            // VRF + static vrf + export + import.
            "[[vrf]]",
            "table = 100",
            "rd = \"65000:1\"",
            "vrf = \"blue\"",
            "[export]",
            "kernel = \"f1\"",
            "[import]",
        ] {
            assert!(out.contains(needle), "missing {needle:?} in:\n{out}");
        }
        // RIPng must NOT carry the RIP/Babel-only extras (Wren's Ripng rejects them).
        let ripng = out
            .split("[ripng]")
            .nth(1)
            .unwrap()
            .split("[babel]")
            .next()
            .unwrap();
        assert!(!ripng.contains("bfd"), "ripng must not emit bfd:\n{ripng}");
        assert!(!ripng.contains("vrf"), "ripng must not emit vrf:\n{ripng}");
    }

    #[test]
    fn static_route_compiles() {
        let toml = r#"
[system]
hostname = "r1"
[protocols]
[[protocols.static]]
prefix = "0.0.0.0/0"
via = "192.168.1.254"
"#;
        let appliance = Appliance::from_toml(toml).unwrap();
        let out = compile_wren(&appliance).to_toml().unwrap();
        assert!(out.contains("[[static]]"), "{out}");
        assert!(out.contains("prefix = \"0.0.0.0/0\""), "{out}");
        assert!(out.contains("via = \"192.168.1.254\""), "{out}");
    }

    #[test]
    fn empty_protocols_yields_empty_config() {
        let toml = r#"
[system]
hostname = "r1"
"#;
        let appliance = Appliance::from_toml(toml).unwrap();
        let out = compile_wren(&appliance).to_toml().unwrap();
        assert!(!out.contains("[bgp]"), "{out}");
        assert!(!out.contains("router-id"), "{out}");
    }

    #[test]
    fn full_neighbor_emits_every_field_with_wren_spelling() {
        let toml = r#"
[system]
hostname = "r1"
[protocols]
router-id = "10.0.0.1"
[protocols.bgp]
local-as = 65001
[[protocols.bgp.neighbor]]
address = "10.10.0.2"
remote-as = 65002
passive = true
route-reflector-client = true
ttl-security = 1
password = "s3cret"
max-prefix = 1000
default-originate = true
add-path = true
extended-nexthop = true
evpn = true
flowspec = true
srpolicy = true
link-state = true
import = "in"
export = "out"
role = "customer"
bfd = true
bfd-auth-type = "meticulous-sha1"
bfd-auth-key-id = 7
bfd-auth-key = "k"
local-as = 65099
update-source = "10.10.0.11"
description = "R2 transit uplink"
shutdown = true
hold-time = 30
[[protocols.bgp.neighbor]]
address = "10.10.0.3"
remote-as = 65003
ebgp-multihop = 4
[[protocols.filter]]
name = "in"
[[protocols.filter]]
name = "out"
"#;
        let appliance = Appliance::from_toml(toml).unwrap();
        let out = compile_wren(&appliance).to_toml().unwrap();
        // Every per-neighbor field appears with wren's exact TOML spelling.
        for needle in [
            "passive = true",
            "route-reflector-client = true",
            "ttl-security = 1",
            "password = \"s3cret\"",
            "max-prefix = 1000",
            "default-originate = true",
            "add-path = true",
            "extended-nexthop = true",
            "evpn = true",
            "flowspec = true",
            "srpolicy = true",
            "link-state = true",
            "import = \"in\"",
            "export = \"out\"",
            "role = \"customer\"",
            "bfd = true",
            "bfd-auth-type = \"meticulous-sha1\"",
            "bfd-auth-key-id = 7",
            "bfd-auth-key = \"k\"",
            "local-as = 65099",
            "update-source = \"10.10.0.11\"",
            "ebgp-multihop = 4",
            "description = \"R2 transit uplink\"",
            "shutdown = true",
            "hold-time = 30",
        ] {
            assert!(out.contains(needle), "missing {needle:?} in:\n{out}");
        }
    }

    #[test]
    fn filters_compile_to_top_level_filter_blocks() {
        let toml = r#"
[system]
hostname = "r1"
[protocols]
[[protocols.filter]]
name = "peer-in"
default = "reject"
[[protocols.filter.rule]]
prefix = ["10.0.0.0/8+", "192.168.0.0/16"]
protocol = "bgp"
metric-le = 100
set-metric = 50
set-community = ["65001:100"]
add-large-community = ["65001:1:2"]
action = "accept"
"#;
        let appliance = Appliance::from_toml(toml).unwrap();
        let out = compile_wren(&appliance).to_toml().unwrap();
        assert!(out.contains("[[filter]]"), "{out}");
        assert!(out.contains("name = \"peer-in\""), "{out}");
        assert!(out.contains("default = \"reject\""), "{out}");
        assert!(out.contains("[[filter.rule]]"), "{out}");
        assert!(out.contains("metric-le = 100"), "{out}");
        assert!(out.contains("set-metric = 50"), "{out}");
        assert!(out.contains("set-community = [\"65001:100\"]"), "{out}");
        assert!(
            out.contains("add-large-community = [\"65001:1:2\"]"),
            "{out}"
        );
        assert!(out.contains("action = \"accept\""), "{out}");
    }

    #[test]
    fn rpki_confederation_and_aggregate_compile() {
        let toml = r#"
[system]
hostname = "r1"
[protocols]
router-id = "10.0.0.1"
[protocols.bgp]
local-as = 65001
hold-time = 90
cluster-id = "10.0.0.1"
confederation-id = 65000
confederation-members = [65002, 65003]
community = ["65001:100"]
multipath = 4
rpki-reject-invalid = true
ebgp-require-policy = true
[protocols.bgp.rtr]
server = "10.0.0.9:3323"
refresh = 300
[[protocols.bgp.aggregate]]
prefix = "10.0.0.0/8"
summary-only = true
[[protocols.bgp.roa]]
prefix = "10.0.0.0/8"
max-length = 24
origin-as = 65001
"#;
        let appliance = Appliance::from_toml(toml).unwrap();
        let out = compile_wren(&appliance).to_toml().unwrap();
        assert!(out.contains("hold-time = 90"), "{out}");
        assert!(out.contains("cluster-id = \"10.0.0.1\""), "{out}");
        assert!(out.contains("confederation-id = 65000"), "{out}");
        assert!(out.contains("confederation-members = ["), "{out}");
        assert!(out.contains("65002") && out.contains("65003"), "{out}");
        assert!(out.contains("multipath = 4"), "{out}");
        assert!(out.contains("rpki-reject-invalid = true"), "{out}");
        assert!(out.contains("ebgp-require-policy = true"), "{out}");
        assert!(out.contains("[bgp.rtr]"), "{out}");
        assert!(out.contains("server = \"10.0.0.9:3323\""), "{out}");
        assert!(out.contains("[[bgp.aggregate]]"), "{out}");
        assert!(out.contains("summary-only = true"), "{out}");
        assert!(out.contains("[[bgp.roa]]"), "{out}");
        assert!(out.contains("origin-as = 65001"), "{out}");
    }
}
