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
    bgp: Option<WrenBgp>,
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

    WrenConfig {
        router_id: p.router_id.clone(),
        statics,
        ospf,
        bgp,
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
