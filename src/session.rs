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
    Action, Appliance, Bgp, BgpNeighbor, Firewall, Interface, Nat, NatDestination, NatSource,
    PortSpec, Proto, Protocols, Rule, StaticRoute, System, ZoneCfg,
};

/// Default on-disk location of the active appliance config. Writable and
/// persistent (survives reboots); the flake reads it at rebuild time.
pub const DEFAULT_CONFIG: &str = "/var/lib/sentinel/appliance.toml";

/// A partially-specified interface (fields filled in incrementally).
#[derive(Debug, Clone, Default)]
struct IfaceDraft {
    zone: Option<String>,
    address: Option<String>,
    parent: Option<String>,
    vlan: Option<u16>,
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

/// The candidate's BGP configuration.
#[derive(Debug, Clone, Default)]
struct BgpDraft {
    local_as: Option<u32>,
    router_id: Option<String>,
    network: Vec<String>,
    redistribute: Vec<String>,
    /// Peers, keyed by address → remote AS.
    neighbors: Vec<(String, u32)>,
}

impl BgpDraft {
    /// True when nothing has been set — lets `[protocols.bgp]` stay absent.
    fn is_empty(&self) -> bool {
        self.local_as.is_none()
            && self.router_id.is_none()
            && self.network.is_empty()
            && self.redistribute.is_empty()
            && self.neighbors.is_empty()
    }
}

/// The candidate config — a draft with optional fields, keyed by name so list
/// items (interfaces, rules) are addressable VyOS-"tag-node" style. Insertion
/// order is preserved for stable `show` output.
#[derive(Debug, Clone, Default)]
struct Draft {
    hostname: Option<String>,
    firewall: FirewallDraft,
    zones: BTreeMap<String, ZoneDraft>,
    interfaces: Vec<(String, IfaceDraft)>,
    rules: Vec<(String, RuleDraft)>,
    nat_source: Vec<(String, NatSrcDraft)>,
    nat_destination: Vec<(String, NatDstDraft)>,
    router_id: Option<String>,
    statics: Vec<(String, StaticDraft)>,
    bgp: BgpDraft,
}

impl Draft {
    /// Mutable access to the static route with `prefix`, inserting it if new.
    fn static_mut(&mut self, prefix: &str) -> &mut StaticDraft {
        if let Some(i) = self.statics.iter().position(|(p, _)| p == prefix) {
            return &mut self.statics[i].1;
        }
        self.statics.push((prefix.to_string(), StaticDraft::default()));
        &mut self.statics.last_mut().unwrap().1
    }

    /// Set the remote AS of the BGP peer `addr`, inserting it if new.
    fn bgp_neighbor_set(&mut self, addr: &str, remote_as: u32) {
        if let Some(i) = self.bgp.neighbors.iter().position(|(a, _)| a == addr) {
            self.bgp.neighbors[i].1 = remote_as;
        } else {
            self.bgp.neighbors.push((addr.to_string(), remote_as));
        }
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
                            parent: i.parent.clone(),
                            vlan: i.vlan,
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
                        },
                    )
                })
                .collect(),
            nat_source: a
                .nat
                .source
                .iter()
                .map(|s| (s.name.clone(), NatSrcDraft { zone: Some(s.zone.clone()) }))
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
            bgp: a
                .protocols
                .bgp
                .as_ref()
                .map(|b| BgpDraft {
                    local_as: Some(b.local_as),
                    router_id: b.router_id.clone(),
                    network: b.network.clone(),
                    redistribute: b.redistribute.clone(),
                    neighbors: b
                        .neighbors
                        .iter()
                        .map(|n| (n.address.clone(), n.remote_as))
                        .collect(),
                })
                .unwrap_or_default(),
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
                self.draft
                    .interfaces
                    .push((name, IfaceDraft::default()));
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

    /// The interface names currently in the candidate (system-discovered +
    /// operator-added) — completion offers these for `set/delete interface …`.
    pub fn interface_names(&self) -> Vec<String> {
        self.draft.interfaces.iter().map(|(n, _)| n.clone()).collect()
    }

    /// The rule names currently in the candidate — completion offers these for
    /// `set/delete rule …`.
    pub fn rule_names(&self) -> Vec<String> {
        self.draft.rules.iter().map(|(n, _)| n.clone()).collect()
    }

    /// The source-NAT (masquerade) rule names — completion offers these for
    /// `set/delete nat source …`.
    pub fn nat_source_names(&self) -> Vec<String> {
        self.draft.nat_source.iter().map(|(n, _)| n.clone()).collect()
    }

    /// The destination-NAT (port-forward) rule names — completion offers these
    /// for `set/delete nat destination …`.
    pub fn nat_destination_names(&self) -> Vec<String> {
        self.draft.nat_destination.iter().map(|(n, _)| n.clone()).collect()
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
            ["interface", name, "parent", v] => {
                self.draft.iface_mut(name).parent = Some((*v).to_string())
            }
            ["interface", name, "vlan", v] => {
                self.draft.iface_mut(name).vlan =
                    Some(v.parse().with_context(|| format!("invalid vlan id {v:?}"))?);
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
            ["protocols", "bgp", "neighbor", addr, "remote-as", v] => {
                let remote_as = v.parse().with_context(|| format!("invalid AS {v:?}"))?;
                self.draft.bgp_neighbor_set(addr, remote_as);
            }
            _ => bail!(
                "unknown set path. The config tree (Tab/`?` explores each level):\n  \
                 set system hostname <name>\n  \
                 set interface <name> zone <zone>\n  \
                 set interface <name> address <dhcp|CIDR>\n  \
                 set interface <name> <parent <iface> | vlan <id>>\n  \
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
                 set protocols bgp <local-as <n> | router-id <ip> | network <prefix> | redistribute <src>>\n  \
                 set protocols bgp neighbor <ip> remote-as <n>"
            ),
        }
        self.dirty = true;
        Ok(())
    }

    /// `delete <path...>` — remove a node or clear a field.
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
            ["interface", name, "zone"] => self.iface(name)?.zone = None,
            ["interface", name, "parent"] => self.iface(name)?.parent = None,
            ["interface", name, "vlan"] => self.iface(name)?.vlan = None,

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
                    other => bail!("rule has no field {other:?}"),
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

            // protocols: dynamic routing (Wren).
            ["protocols"] => self.draft.router_id = None,
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
            ["protocols", "bgp", field] => {
                let b = &mut self.draft.bgp;
                match *field {
                    "local-as" => b.local_as = None,
                    "router-id" => b.router_id = None,
                    "network" => b.network.clear(),
                    "redistribute" => b.redistribute.clear(),
                    other => bail!("bgp has no field {other:?}"),
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

    /// Render the candidate in a readable, hierarchical (JunOS-curly) form.
    pub fn show(&self) -> String {
        render_draft(&self.draft, false)
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

    /// Build a validated [`Appliance`] from the candidate, reporting any
    /// required field that hasn't been set.
    fn materialize(&self) -> Result<Appliance> {
        let hostname = self
            .draft
            .hostname
            .clone()
            .ok_or_else(|| anyhow::anyhow!("system hostname is not set"))?;
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
                parent: d.parent.clone(),
                vlan: d.vlan,
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
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let firewall = Firewall {
            stateful: self.draft.firewall.stateful.unwrap_or(true),
            block_icmp: self.draft.firewall.block_icmp.unwrap_or(false),
            blocklist: self.draft.firewall.blocklist.clone(),
            default_action: self.draft.firewall.default_action.unwrap_or(Action::Drop),
            log: self.draft.firewall.log.unwrap_or(false),
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
        let nat_destination = self
            .draft
            .nat_destination
            .iter()
            .map(|(name, d)| {
                Ok(NatDestination {
                    name: name.clone(),
                    zone: d
                        .zone
                        .clone()
                        .ok_or_else(|| anyhow::anyhow!("nat destination {name:?}: zone not set"))?,
                    proto: d
                        .proto
                        .ok_or_else(|| anyhow::anyhow!("nat destination {name:?}: proto not set"))?,
                    port: d
                        .port
                        .ok_or_else(|| anyhow::anyhow!("nat destination {name:?}: port not set"))?,
                    to: d
                        .to
                        .clone()
                        .ok_or_else(|| anyhow::anyhow!("nat destination {name:?}: to not set"))?,
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
            Some(Bgp {
                local_as: self
                    .draft
                    .bgp
                    .local_as
                    .ok_or_else(|| anyhow::anyhow!("protocols bgp: local-as not set"))?,
                router_id: self.draft.bgp.router_id.clone(),
                network: self.draft.bgp.network.clone(),
                redistribute: self.draft.bgp.redistribute.clone(),
                neighbors: self
                    .draft
                    .bgp
                    .neighbors
                    .iter()
                    .map(|(address, remote_as)| BgpNeighbor {
                        address: address.clone(),
                        remote_as: *remote_as,
                    })
                    .collect(),
            })
        };
        let protocols = Protocols {
            router_id: self.draft.router_id.clone(),
            statics,
            bgp,
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
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, appliance.to_toml()?)
            .with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("installing {}", path.display()))?;
        self.dirty = false;
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

/// Render a draft in JunOS-curly form. When `skip_empty_ifaces` is set,
/// interfaces with neither a role nor an address are omitted (used by
/// `compare`, where system-provided placeholders aren't real configuration).
fn render_draft(draft: &Draft, skip_empty_ifaces: bool) -> String {
    let mut out = String::new();
    if let Some(h) = &draft.hostname {
        out.push_str(&format!("system {{\n    hostname {h}\n}}\n"));
    }
    // Interfaces are top-level (like VyOS), between `system` and `firewall`.
    for (name, i) in &draft.interfaces {
        if skip_empty_ifaces
            && i.zone.is_none()
            && i.address.is_none()
            && i.parent.is_none()
            && i.vlan.is_none()
        {
            continue;
        }
        out.push_str(&format!("interface {name} {{\n"));
        if let Some(z) = &i.zone {
            out.push_str(&format!("    zone {z}\n"));
        }
        if let Some(a) = &i.address {
            out.push_str(&format!("    address {a}\n"));
        }
        if let Some(p) = &i.parent {
            out.push_str(&format!("    parent {p}\n"));
        }
        if let Some(v) = i.vlan {
            out.push_str(&format!("    vlan {v}\n"));
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
        fwi.push_str("    }\n");
    }
    if !fwi.is_empty() {
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
    if !nati.is_empty() {
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
    if !draft.bgp.is_empty() {
        proto.push_str("    bgp {\n");
        if let Some(a) = draft.bgp.local_as {
            proto.push_str(&format!("        local-as {a}\n"));
        }
        if let Some(rid) = &draft.bgp.router_id {
            proto.push_str(&format!("        router-id {rid}\n"));
        }
        for net in &draft.bgp.network {
            proto.push_str(&format!("        network {net}\n"));
        }
        for src in &draft.bgp.redistribute {
            proto.push_str(&format!("        redistribute {src}\n"));
        }
        for (addr, remote_as) in &draft.bgp.neighbors {
            proto.push_str(&format!("        neighbor {addr} remote-as {remote_as}\n"));
        }
        proto.push_str("    }\n");
    }
    if !proto.is_empty() {
        out.push_str("protocols {\n");
        out.push_str(&proto);
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

fn parse_bool(s: &str) -> Result<bool> {
    Ok(match s {
        "true" | "on" | "yes" => true,
        "false" | "off" | "no" => false,
        _ => bail!("invalid boolean {s:?} (expected true|false)"),
    })
}

/// A firewall blocklist entry: an IPv4 or IPv4 CIDR. Delegates to the config
/// validator so set-time feedback matches commit-time validation.
fn validate_block_entry(s: &str) -> Result<()> {
    crate::config::validate_cidr_or_ip(s)
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
        assert_eq!((vlan.parent.as_deref(), vlan.vlan), (Some("eth1"), Some(20)));
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
        assert_eq!((a.nat.source[0].name.as_str(), a.nat.source[0].zone.as_str()), ("wan-masq", "wan"));
        assert_eq!(a.nat.destination.len(), 1);
        let d = &a.nat.destination[0];
        assert_eq!((d.zone.as_str(), d.port, d.to.as_str()), ("wan", 443, "10.0.0.10:8443"));

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
    fn show_renders_partial_drafts() {
        let mut s = Session::empty();
        run(&mut s, "set system hostname fw1").unwrap();
        run(&mut s, "set interface wan0 zone wan").unwrap();
        let shown = s.show();
        assert!(shown.contains("hostname fw1"));
        assert!(shown.contains("interface wan0"));
        assert!(shown.contains("zone wan"));
    }
}
