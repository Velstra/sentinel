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

use serde::Serialize;

use crate::config::{Action, Appliance, Proto, Zone};

/// The subset of Velstra's agent `FileConfig` we emit. Field names and the
/// `policy`/`interface` array renames match Velstra's TOML schema exactly.
#[derive(Debug, Serialize)]
pub struct VelstraConfig {
    default_action: &'static str,
    stateful: bool,
    #[serde(rename = "policy")]
    policies: Vec<Policy>,
    #[serde(rename = "interface")]
    interfaces: Vec<Interface>,
}

#[derive(Debug, Serialize)]
struct Policy {
    id: u32,
    name: String,
    default_action: &'static str,
    stateful: bool,
    // Scalars above, the array-of-tables below (TOML requires this order).
    #[serde(rename = "port_rule", skip_serializing_if = "Vec::is_empty")]
    port_rules: Vec<PortRule>,
}

#[derive(Debug, Serialize)]
struct PortRule {
    proto: &'static str,
    port: u16,
    action: &'static str,
}

#[derive(Debug, Serialize)]
struct Interface {
    name: String,
    policy: u32,
}

impl VelstraConfig {
    /// Render as the TOML the Velstra agent loads with `--config`.
    pub fn to_toml(&self) -> anyhow::Result<String> {
        use anyhow::Context;
        toml::to_string_pretty(self).context("serializing the velstra config")
    }
}

/// A stable policy id per zone, so recompiles are deterministic.
fn zone_id(z: Zone) -> u32 {
    match z {
        Zone::Wan => 1,
        Zone::Lan => 2,
        Zone::Dmz => 3,
    }
}

fn zone_name(z: Zone) -> &'static str {
    match z {
        Zone::Wan => "wan",
        Zone::Lan => "lan",
        Zone::Dmz => "dmz",
    }
}

fn proto_str(p: Proto) -> &'static str {
    match p {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    }
}

/// Map a Sentinel action to a Velstra action. Velstra has no `reject`, so it
/// collapses to `drop` (silently dropped rather than actively refused).
fn action_str(a: Action) -> &'static str {
    match a {
        Action::Accept => "pass",
        Action::Drop | Action::Reject => "drop",
    }
}

/// Compile a Sentinel appliance config into a Velstra agent config.
pub fn compile(appliance: &Appliance) -> VelstraConfig {
    // The zones actually in use (a zone with no assigned interface needs no
    // policy; interfaces the system provides but that aren't assigned a zone yet
    // are simply not firewalled).
    let mut zones: Vec<Zone> = appliance.interfaces.iter().filter_map(|i| i.role).collect();
    zones.sort_by_key(|z| zone_id(*z));
    zones.dedup();

    let policies = zones
        .iter()
        .map(|&zone| {
            // Posture comes from broad rules: pass if this zone may initiate.
            let initiates = appliance
                .rules
                .iter()
                .any(|r| r.from == zone && r.is_broad() && r.action == Action::Accept);
            // Specific proto/port rules become Velstra port rules on this policy.
            let port_rules = appliance
                .rules
                .iter()
                .filter(|r| r.from == zone && r.is_port_rule())
                .map(|r| PortRule {
                    proto: proto_str(r.proto.unwrap()),
                    port: r.port.unwrap(),
                    action: action_str(r.action),
                })
                .collect();
            Policy {
                id: zone_id(zone),
                name: zone_name(zone).to_string(),
                default_action: if initiates { "pass" } else { "drop" },
                stateful: true,
                port_rules,
            }
        })
        .collect();

    let interfaces = appliance
        .interfaces
        .iter()
        .filter_map(|i| {
            i.role.map(|role| Interface {
                name: i.name.clone(),
                policy: zone_id(role),
            })
        })
        .collect();

    VelstraConfig {
        // Deny by default; interfaces opt into their zone policy.
        default_action: "drop",
        stateful: true,
        policies,
        interfaces,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Appliance;

    #[test]
    fn compiles_example_to_zone_ingress_posture() {
        let appliance = Appliance::from_toml(crate::config::EXAMPLE).unwrap();
        let cfg = compile(&appliance);

        // One interface binding per declared interface.
        assert_eq!(cfg.interfaces.len(), 2);
        // wan0 -> policy 1, lan0 -> policy 2.
        let wan_if = cfg.interfaces.iter().find(|i| i.name == "wan0").unwrap();
        assert_eq!(wan_if.policy, 1);

        // A policy per used zone, with the right posture.
        let wan = cfg.policies.iter().find(|p| p.id == 1).unwrap();
        let lan = cfg.policies.iter().find(|p| p.id == 2).unwrap();
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
    fn rendered_toml_round_trips_as_a_velstra_config() {
        // The emitted TOML must at least parse as a generic TOML document with
        // the expected shape (a full check lives in fabric's velstra-config).
        let appliance = Appliance::from_toml(crate::config::EXAMPLE).unwrap();
        let toml = compile(&appliance).to_toml().unwrap();
        let value: toml::Value = toml::from_str(&toml).unwrap();
        assert_eq!(value["default_action"].as_str(), Some("drop"));
        assert!(value["policy"].as_array().unwrap().len() == 2);
    }
}
