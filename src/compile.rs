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

/// The subset of Velstra's agent `FileConfig` we emit. Field names and the
/// `policy`/`interface` array renames match Velstra's TOML schema exactly.
#[derive(Debug, Serialize)]
pub struct VelstraConfig {
    default_action: &'static str,
    stateful: bool,
    drop_icmp: bool,
    log: bool,
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
}

#[derive(Debug, Serialize)]
struct Policy {
    id: u32,
    name: String,
    default_action: &'static str,
    stateful: bool,
    drop_icmp: bool,
    log: bool,
    // Scalars above, the array-of-tables below (TOML requires this order).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    blocklist: Vec<String>,
    #[serde(rename = "port_rule", skip_serializing_if = "Vec::is_empty")]
    port_rules: Vec<PortRule>,
}

#[derive(Debug, Serialize)]
struct PortRule {
    proto: &'static str,
    port: u16,
    action: &'static str,
    /// Log packets matching this rule. Omitted when false (the common case).
    #[serde(skip_serializing_if = "is_false")]
    log: bool,
    /// Optional source CIDR ("10.0.0.0/24"). Omitted when the rule is `from any`.
    #[serde(skip_serializing_if = "Option::is_none")]
    src: Option<String>,
}

#[derive(Debug, Serialize)]
struct Interface {
    name: String,
    policy: u32,
    /// Source-NAT (masquerade) traffic leaving this interface — set when the
    /// interface's zone has a `[[nat.source]]` rule. Omitted when false.
    #[serde(skip_serializing_if = "is_false")]
    masquerade: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Serialize)]
struct PortForwardOut {
    policy: u32,
    proto: &'static str,
    port: u16,
    dst_ip: String,
    dst_port: u16,
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
    let mut zone_names: Vec<&str> =
        appliance.interfaces.iter().filter_map(|i| i.zone.as_deref()).collect();
    zone_names.sort_unstable();
    zone_names.dedup();
    let ids: BTreeMap<&str, u32> = zone_names
        .iter()
        .enumerate()
        .map(|(i, name)| (*name, i as u32 + 1))
        .collect();

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
                        r.from == zone && r.is_broad() && r.action == Action::Accept
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
            let port_rules = appliance
                .rules
                .iter()
                .filter(|r| r.from == zone && r.is_port_rule())
                .flat_map(|r| {
                    let proto = proto_str(r.proto.unwrap());
                    let action = action_str(r.action);
                    let log = r.log;
                    let sources = r.resolved_sources(groups);
                    let ports = r.resolved_ports(groups);
                    let mut out = Vec::with_capacity(sources.len() * ports.len());
                    for src in &sources {
                        for &port in &ports {
                            out.push(PortRule {
                                proto,
                                port,
                                action,
                                log,
                                src: src.clone(),
                            });
                        }
                    }
                    out
                })
                .collect();
            Policy {
                id: ids[zone],
                name: zone.to_string(),
                default_action,
                stateful: posture.stateful,
                drop_icmp: posture.block_icmp,
                log: posture.log,
                blocklist: posture.blocklist,
                port_rules,
            }
        })
        .collect();

    // Zones that have a source-NAT (masquerade) rule — their interfaces get
    // `masquerade = true` so the data plane SNATs traffic leaving them.
    let masq_zones: std::collections::HashSet<&str> =
        appliance.nat.source.iter().map(|s| s.zone.as_str()).collect();

    let interfaces = appliance
        .interfaces
        .iter()
        .filter_map(|i| {
            i.zone.as_deref().map(|zone| Interface {
                name: i.name.clone(),
                policy: ids[zone],
                masquerade: masq_zones.contains(zone),
            })
        })
        .collect();

    // Destination NAT (port-forwards) binds to its ingress zone's policy; `to`
    // splits into the internal ip:port (validated already, so a parse miss just
    // drops the entry). Source NAT (masquerade) is enforced in Phase 4b.
    let port_forwards = appliance
        .nat
        .destination
        .iter()
        .filter_map(|dst| {
            let policy = *ids.get(dst.zone.as_str())?;
            let (ip, port) = crate::config::parse_host_port(&dst.to).ok()?;
            Some(PortForwardOut {
                policy,
                proto: proto_str(dst.proto),
                port: dst.port,
                dst_ip: ip.to_string(),
                dst_port: port,
            })
        })
        .collect();

    VelstraConfig {
        // Deny by default; interfaces opt into their zone policy.
        default_action: action_str(fw.default_action),
        stateful: fw.stateful,
        drop_icmp: fw.block_icmp,
        log: fw.log,
        blocklist: fw.blocklist.clone(),
        policies,
        interfaces,
        port_forwards,
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
        assert!(wan.port_rules.iter().all(|r| r.proto == "tcp" && r.action == "pass"));
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
        assert!(wan.port_rules[0].log, "log flag should carry onto the port rule");
        let out = cfg.to_toml().unwrap();
        assert!(out.contains("log = true"), "log emitted to velstra config:\n{out}");
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
        assert!(wan.port_rules.iter().all(|r| r.proto == "tcp" && r.action == "pass"));
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
}
