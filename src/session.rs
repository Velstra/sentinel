//! An interactive configuration session — the VyOS/JunOS-style `configure`
//! context.
//!
//! You edit a **candidate** config with `set`/`delete`, `show` it, then `commit`
//! (validate + activate) and `save` (persist to disk). Because Sentinel's model
//! is declarative, the candidate is just a draft of the [`Appliance`] document;
//! fields can be set one at a time (so the draft holds optionals) and are
//! materialized into a validated [`Appliance`] at commit/save time.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::config::{Action, Appliance, Interface, Proto, Rule, System, Zone};

/// Default on-disk location of the active appliance config. Writable and
/// persistent (survives reboots); the flake reads it at rebuild time.
pub const DEFAULT_CONFIG: &str = "/var/lib/sentinel/appliance.toml";

/// A partially-specified interface (fields filled in incrementally).
#[derive(Debug, Clone, Default)]
struct IfaceDraft {
    role: Option<Zone>,
    address: Option<String>,
}

/// A partially-specified rule.
#[derive(Debug, Clone, Default)]
struct RuleDraft {
    from: Option<Zone>,
    to: Option<Zone>,
    action: Option<Action>,
    proto: Option<Proto>,
    port: Option<u16>,
}

/// The candidate config — a draft with optional fields, keyed by name so list
/// items (interfaces, rules) are addressable VyOS-"tag-node" style. Insertion
/// order is preserved for stable `show` output.
#[derive(Debug, Clone, Default)]
struct Draft {
    hostname: Option<String>,
    interfaces: Vec<(String, IfaceDraft)>,
    rules: Vec<(String, RuleDraft)>,
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

    fn from_appliance(a: &Appliance) -> Self {
        Draft {
            hostname: Some(a.system.hostname.clone()),
            interfaces: a
                .interfaces
                .iter()
                .map(|i| {
                    (
                        i.name.clone(),
                        IfaceDraft {
                            role: i.role,
                            address: i.address.clone(),
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
                            from: Some(r.from),
                            to: Some(r.to),
                            action: Some(r.action),
                            proto: r.proto,
                            port: r.port,
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

    /// `set <path...> <value>` — set one config node.
    pub fn set(&mut self, args: &[&str]) -> Result<()> {
        match args {
            ["system", "hostname", v] => self.draft.hostname = Some((*v).to_string()),
            ["interface", name, "role", v] => {
                self.draft.iface_mut(name).role = Some(parse_zone(v)?)
            }
            ["interface", name, "address", v] => {
                validate_address(v)?;
                self.draft.iface_mut(name).address = Some((*v).to_string());
            }
            ["rule", name, "from", v] => self.draft.rule_mut(name).from = Some(parse_zone(v)?),
            ["rule", name, "to", v] => self.draft.rule_mut(name).to = Some(parse_zone(v)?),
            ["rule", name, "action", v] => {
                self.draft.rule_mut(name).action = Some(parse_action(v)?)
            }
            ["rule", name, "proto", v] => self.draft.rule_mut(name).proto = Some(parse_proto(v)?),
            ["rule", name, "port", v] => {
                self.draft.rule_mut(name).port =
                    Some(v.parse().with_context(|| format!("invalid port {v:?}"))?);
            }
            _ => bail!(
                "unknown set path. Try:\n  \
                 set system hostname <name>\n  \
                 set interface <name> role <wan|lan|dmz>\n  \
                 set interface <name> address <dhcp|CIDR>\n  \
                 set rule <name> <from|to> <zone>\n  \
                 set rule <name> action <accept|drop|reject>\n  \
                 set rule <name> <proto tcp|udp | port <n>>"
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
            ["interface", name, "role"] => self.iface(name)?.role = None,
            ["rule", name] => {
                let before = self.draft.rules.len();
                self.draft.rules.retain(|(n, _)| n != name);
                if self.draft.rules.len() == before {
                    bail!("no rule {name:?}");
                }
            }
            ["rule", name, field] => {
                let r = self.rule(name)?;
                match *field {
                    "from" => r.from = None,
                    "to" => r.to = None,
                    "action" => r.action = None,
                    "proto" => r.proto = None,
                    "port" => r.port = None,
                    other => bail!("rule has no field {other:?}"),
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
                role: d.role,
                address: d.address.clone(),
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
                        .ok_or_else(|| anyhow::anyhow!("rule {name:?}: from not set"))?,
                    to: d
                        .to
                        .ok_or_else(|| anyhow::anyhow!("rule {name:?}: to not set"))?,
                    action: d
                        .action
                        .ok_or_else(|| anyhow::anyhow!("rule {name:?}: action not set"))?,
                    proto: d.proto,
                    port: d.port,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let appliance = Appliance {
            system: System { hostname },
            interfaces,
            rules,
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
    for (name, i) in &draft.interfaces {
        if skip_empty_ifaces && i.role.is_none() && i.address.is_none() {
            continue;
        }
        out.push_str(&format!("interface {name} {{\n"));
        if let Some(r) = i.role {
            out.push_str(&format!("    role {}\n", zone_str(r)));
        }
        if let Some(a) = &i.address {
            out.push_str(&format!("    address {a}\n"));
        }
        out.push_str("}\n");
    }
    for (name, r) in &draft.rules {
        out.push_str(&format!("rule {name} {{\n"));
        if let Some(z) = r.from {
            out.push_str(&format!("    from {}\n", zone_str(z)));
        }
        if let Some(z) = r.to {
            out.push_str(&format!("    to {}\n", zone_str(z)));
        }
        if let Some(a) = r.action {
            out.push_str(&format!("    action {}\n", action_str(a)));
        }
        if let Some(p) = r.proto {
            out.push_str(&format!("    proto {}\n", proto_str(p)));
        }
        if let Some(p) = r.port {
            out.push_str(&format!("    port {p}\n"));
        }
        out.push_str("}\n");
    }
    if out.is_empty() && !skip_empty_ifaces {
        out.push_str("(empty configuration)\n");
    }
    out
}

fn parse_zone(s: &str) -> Result<Zone> {
    Ok(match s {
        "wan" => Zone::Wan,
        "lan" => Zone::Lan,
        "dmz" => Zone::Dmz,
        _ => bail!("invalid zone {s:?} (expected wan|lan|dmz)"),
    })
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

fn zone_str(z: Zone) -> &'static str {
    match z {
        Zone::Wan => "wan",
        Zone::Lan => "lan",
        Zone::Dmz => "dmz",
    }
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
            "set interface wan0 role wan",
            "set interface wan0 address dhcp",
            "set interface lan0 role lan",
            "set interface lan0 address 10.0.0.1/24",
            "set rule lan-out from lan",
            "set rule lan-out to wan",
            "set rule lan-out action accept",
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
        run(&mut s, "set interface wan0 role wan").unwrap();
        // No hostname, and wan0 has no address yet.
        let err = s.commit().unwrap_err().to_string();
        assert!(err.contains("hostname"), "got: {err}");
    }

    #[test]
    fn delete_removes_nodes_and_fields() {
        let mut s = Session::empty();
        run(&mut s, "set system hostname fw1").unwrap();
        run(&mut s, "set interface wan0 role wan").unwrap();
        run(&mut s, "set interface wan0 address dhcp").unwrap();
        run(&mut s, "delete interface wan0 address").unwrap();
        assert!(s.commit().is_ok()); // address is optional (unconfigured NIC)
        run(&mut s, "delete interface wan0").unwrap();
        run(&mut s, "set system hostname fw1").unwrap();
        assert!(s.commit().is_ok()); // no interfaces, just a hostname
        // Deleting something absent is an error.
        assert!(run(&mut s, "delete rule nope").is_err());
    }

    #[test]
    fn rejects_invalid_values() {
        let mut s = Session::empty();
        assert!(run(&mut s, "set interface x role wifi").is_err());
        assert!(run(&mut s, "set interface x address 10.0.0.1/33").is_err());
        assert!(run(&mut s, "set rule r port 70000").is_err());
        assert!(run(&mut s, "set bogus path here").is_err());
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
    fn show_renders_partial_drafts() {
        let mut s = Session::empty();
        run(&mut s, "set system hostname fw1").unwrap();
        run(&mut s, "set interface wan0 role wan").unwrap();
        let shown = s.show();
        assert!(shown.contains("hostname fw1"));
        assert!(shown.contains("interface wan0"));
        assert!(shown.contains("role wan"));
    }
}
