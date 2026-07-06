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
    #[serde(rename = "filter", skip_serializing_if = "Vec::is_empty")]
    filters: Vec<WrenFilter>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    cost: Option<u16>,
    #[serde(rename = "network-type", skip_serializing_if = "Option::is_none")]
    network_type: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    redistribute: Vec<String>,
}

#[derive(Debug, Serialize)]
struct WrenOspf3 {
    enabled: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    interfaces: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    area: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cost: Option<u16>,
    #[serde(rename = "network-type", skip_serializing_if = "Option::is_none")]
    network_type: Option<String>,
    /// OSPFv3 only redistributes static externals (a bool in wren's schema).
    #[serde(
        rename = "redistribute-static",
        skip_serializing_if = "std::ops::Not::not"
    )]
    redistribute_static: bool,
}

#[derive(Debug, Serialize)]
struct WrenRip {
    enabled: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    interfaces: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    redistribute: Vec<String>,
    #[serde(
        rename = "redistribute-metric",
        skip_serializing_if = "Option::is_none"
    )]
    redistribute_metric: Option<u32>,
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
    #[serde(rename = "network-type", skip_serializing_if = "Option::is_none")]
    network_type: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    redistribute: Vec<String>,
    #[serde(
        rename = "redistribute-metric",
        skip_serializing_if = "Option::is_none"
    )]
    redistribute_metric: Option<u32>,
}

#[derive(Debug, Serialize)]
struct WrenVrrp {
    interface: String,
    vrid: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<u8>,
    #[serde(rename = "virtual-address", skip_serializing_if = "Vec::is_empty")]
    virtual_address: Vec<String>,
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

    let ospf = p.ospf.as_ref().map(|o| WrenOspf {
        enabled: true,
        interfaces: o.interfaces.clone(),
        area: o.area.clone(),
        cost: o.cost,
        network_type: o.network_type.clone(),
        redistribute: o.redistribute.clone(),
    });

    let ospf3 = p.ospf3.as_ref().map(|o| WrenOspf3 {
        enabled: true,
        interfaces: o.interfaces.clone(),
        area: o.area.clone(),
        cost: o.cost,
        network_type: o.network_type.clone(),
        // OSPFv3 only redistributes static externals (bool in wren's schema).
        redistribute_static: o.redistribute.iter().any(|s| s == "static"),
    });

    // RIP, RIPng and Babel share the appliance `Rip` shape.
    let rip_like = |r: &crate::config::Rip| WrenRip {
        enabled: true,
        interfaces: r.interfaces.clone(),
        redistribute: r.redistribute.clone(),
        redistribute_metric: r.redistribute_metric,
    };
    let rip = p.rip.as_ref().map(rip_like);
    let ripng = p.ripng.as_ref().map(rip_like);
    let babel = p.babel.as_ref().map(rip_like);

    let isis = p.isis.as_ref().map(|i| WrenIsis {
        enabled: true,
        interfaces: i.interfaces.clone(),
        system_id: i.system_id.clone(),
        area: i.area.clone(),
        level: i.level.clone(),
        network_type: i.network_type.clone(),
        redistribute: i.redistribute.clone(),
        redistribute_metric: i.redistribute_metric,
    });

    let vrrp = p
        .vrrp
        .iter()
        .map(|v| WrenVrrp {
            interface: v.interface.clone(),
            vrid: v.vrid,
            priority: v.priority,
            virtual_address: v.virtual_address.clone(),
        })
        .collect();

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
        filters,
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
