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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    network: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    redistribute: Vec<String>,
    #[serde(rename = "neighbor", skip_serializing_if = "Vec::is_empty")]
    neighbors: Vec<WrenNeighbor>,
}

#[derive(Debug, Serialize)]
struct WrenNeighbor {
    address: String,
    #[serde(rename = "remote-as")]
    remote_as: u32,
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
    #[serde(rename = "redistribute-static", skip_serializing_if = "std::ops::Not::not")]
    redistribute_static: bool,
}

#[derive(Debug, Serialize)]
struct WrenRip {
    enabled: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    interfaces: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    redistribute: Vec<String>,
    #[serde(rename = "redistribute-metric", skip_serializing_if = "Option::is_none")]
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
    #[serde(rename = "redistribute-metric", skip_serializing_if = "Option::is_none")]
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
        network: b.network.clone(),
        redistribute: b.redistribute.clone(),
        neighbors: b
            .neighbors
            .iter()
            .map(|n| WrenNeighbor {
                address: n.address.clone(),
                remote_as: n.remote_as,
            })
            .collect(),
    });

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
}
