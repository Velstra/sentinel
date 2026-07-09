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
    let mut zone_names: Vec<&str> = appliance
        .interfaces
        .iter()
        .filter(|i| !i.disabled)
        .filter_map(|i| i.zone.as_deref())
        .collect();
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
            let port_rules = appliance
                .rules
                .iter()
                .filter(|r| !r.disabled && r.from == zone && r.is_port_rule())
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
    let masq_zones: std::collections::HashSet<&str> = appliance
        .nat
        .source
        .iter()
        .filter(|s| !s.disabled)
        .map(|s| s.zone.as_str())
        .collect();

    let interfaces = appliance
        .interfaces
        .iter()
        .filter(|i| !i.disabled)
        .filter_map(|i| {
            i.zone.as_deref().map(|zone| Interface {
                name: i.name.clone(),
                policy: ids[zone],
                masquerade: masq_zones.contains(zone),
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
