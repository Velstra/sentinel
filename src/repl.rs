//! The interactive `configure` shell: command execution shared by the
//! interactive (rustyline, with tab-completion) and piped (plain stdin) paths.

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use rustyline::{
    Helper, completion::Completer, completion::Pair, highlight::Highlighter, hint::Hinter,
    validate::Validator,
};

use crate::{compile, session::Session, system};

/// Where the velstra agent reads its compiled config from (writable runtime
/// path, not the read-only image).
pub const DEFAULT_VELSTRA_OUT: &str = "/run/sentinel/velstra.toml";
/// The systemd unit running the data plane.
pub const DEFAULT_UNIT: &str = "velstra.service";

/// How `commit` applies the validated config to the running system.
pub struct Apply {
    /// Where to write the compiled velstra agent config.
    pub velstra_out: PathBuf,
    /// The systemd unit running the data plane (reloaded after writing).
    pub unit: String,
    /// Whether to actually touch the live system. Off-box / in tests this is
    /// false: `commit` validates + saves only.
    pub enabled: bool,
}

impl Apply {
    /// Apply disabled — validate + save only (used off-box and in tests).
    #[cfg(test)]
    pub fn off() -> Self {
        Self {
            velstra_out: PathBuf::from(DEFAULT_VELSTRA_OUT),
            unit: DEFAULT_UNIT.to_string(),
            enabled: false,
        }
    }
}

/// Run one command line against the session. Returns `true` when the session
/// should exit (`exit`/`quit`). Errors are printed, not propagated, so the shell
/// keeps running.
pub fn exec_line(session: &mut Session, act: &Apply, line: &str) -> bool {
    let args: Vec<&str> = line.split_whitespace().collect();
    let Some((&cmd, rest)) = args.split_first() else {
        return false; // blank line
    };

    let result: Result<()> = match cmd {
        "set" => session.set(rest),
        "delete" | "del" => session.delete(rest),
        "show" => {
            print!("{}", session.show());
            Ok(())
        }
        "compare" => session.compare().map(|d| {
            if d.is_empty() {
                eprintln!("no changes (candidate matches the saved config)");
            } else {
                print!("{d}");
            }
        }),
        "commit" => return commit(session, act),
        "save" => {
            let to = rest.first().map(Path::new);
            session
                .save(to)
                .map(|p| eprintln!("saved {} (persists across reboot)", p.display()))
        }
        "discard" => session.discard().map(|()| eprintln!("discarded edits")),
        "exit" | "quit" => {
            if session.dirty() {
                eprintln!("warning: uncommitted edits (use `commit`/`save`, or `discard`)");
            }
            return true;
        }
        "help" => {
            eprint!("{HELP}");
            Ok(())
        }
        other => Err(anyhow!("unknown command {other:?} (try `help`)")),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
    }
    false
}

/// `commit`: validate the candidate, persist it, then — if enabled — apply it to
/// the **running** system: recompile the firewall and reload the velstra data
/// plane, and set the hostname live. No rebuild, no reboot. Never exits the
/// shell. Returns `false`.
fn commit(session: &mut Session, act: &Apply) -> bool {
    let appliance = match session.commit() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            return false;
        }
    };
    let summary = format!(
        "{} interface(s), {} rule(s)",
        appliance.interfaces.len(),
        appliance.rules.len()
    );

    if !act.enabled {
        eprintln!("commit ok (validated): {summary}");
        eprintln!("note: live apply disabled (off-box or --no-apply)");
        return false;
    }

    // VyOS semantics: commit applies to the RUNNING system only. It does not
    // persist — `save` writes the boot config so a change survives reboot.
    let old_host = system::current_hostname();
    eprintln!("commit: {summary}; applying to the running system…");
    if let Err(e) = apply_live(&appliance, act) {
        eprintln!("error: applying config: {e}");
        return false;
    }
    if appliance.system.hostname != old_host {
        eprintln!("  hostname: {old_host} -> {}", appliance.system.hostname);
    }
    eprintln!("commit ok: applied live (not persisted — `save` to keep across reboot)");
    false
}

/// Apply a validated appliance config to the running system: compile + install
/// the firewall config and reload the agent, then set the hostname.
fn apply_live(appliance: &crate::config::Appliance, act: &Apply) -> Result<()> {
    // Firewall: compile -> atomically install -> reload the data plane.
    let rendered = compile::compile(appliance).to_toml()?;
    if let Some(parent) = act.velstra_out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = act.velstra_out.with_extension("toml.tmp");
    std::fs::write(&tmp, &rendered)?;
    std::fs::rename(&tmp, &act.velstra_out)?;
    system::reload_velstra(&act.unit)?;

    // Hostname: set it live.
    system::set_hostname(&appliance.system.hostname)?;
    // Interface addressing: render + apply networkd units live.
    crate::net::apply(appliance)?;
    Ok(())
}

pub const HELP: &str = "\
commands:
  set <path...> <value>   set a config node. The tree (Tab/`?` explores it):
                            system hostname <name>
                            interface <n> zone|address|parent|vlan …
                            firewall global  stateful|block-icmp|default-action|log|block …
                            firewall zone <z>  stateful|block-icmp|default-action|log|block …
                            firewall rule <r>  from|to|action|proto|port|log|source …
                            nat source <s>  zone …
                            nat destination <d>  zone|proto|port|to …
                          e.g.  set firewall rule web from wan
                                set nat source wan-masq zone wan
                                set nat destination web to 10.0.0.10:8443
  delete <path...>        remove a node or clear a field
  show                    show the candidate configuration
  compare                 diff the candidate against the saved config
  commit                  apply the candidate to the RUNNING system (live)
  save [path]             persist the config so it survives a reboot
  discard                 drop edits, reload from disk
  exit | quit             leave configuration mode (Ctrl-C cancels a line)
  (Tab or `?` lists commands, config keys, and value keywords.)
";

/// A completion candidate: the keyword to insert plus a short description shown
/// in the Tab/`?` listing (VyOS/vtysh style).
pub type Cand = (&'static str, &'static str);

const COMMANDS: &[Cand] = &[
    ("set", "set a configuration value"),
    ("delete", "remove a node or clear a field"),
    ("show", "show the candidate configuration"),
    ("compare", "diff the candidate against the saved config"),
    ("commit", "apply the candidate to the running system (live)"),
    ("save", "persist the configuration across reboot"),
    ("discard", "drop uncommitted edits"),
    ("exit", "leave configuration mode"),
    ("help", "show command help"),
];
// Top level: four nodes, each a clear domain — host settings, the NICs, the
// firewall (filtering), and NAT (address translation). NAT is deliberately NOT
// under firewall: filtering and translation are different things.
const TOP: &[Cand] = &[
    ("system", "host-wide settings (hostname, …)"),
    ("interface", "per-NIC zone, address, VLAN"),
    ("firewall", "packet filtering: global defaults, zones, rules"),
    ("nat", "address translation: source (masquerade), destination (port-forward)"),
];
// `firewall <Tab>` reveals the three firewall sub-trees (NAT lives at top level).
const FIREWALL_NODES: &[Cand] = &[
    ("global", "default posture inherited by every zone"),
    ("zone", "per-zone overrides (ICMP, stateful, default-action, …)"),
    ("rule", "zone-to-zone allow/deny rules"),
];
// `nat <Tab>` reveals the two NAT directions (VyOS-style).
const NAT_NODES: &[Cand] = &[
    ("source", "SNAT/masquerade a zone's outbound traffic"),
    ("destination", "inbound DNAT port-forward to an internal host"),
];
const SYSTEM_FIELDS: &[Cand] = &[("hostname", "the appliance hostname")];
const GLOBAL_FIELDS: &[Cand] = &[
    ("stateful", "track flows so return traffic is allowed (true|false)"),
    ("block-icmp", "drop inbound ICMP by default (true|false)"),
    ("default-action", "default ingress action (accept|drop|reject)"),
    ("log", "log matched traffic by default (true|false)"),
    ("block", "drop a source IP/CIDR everywhere"),
];
const ZONE_FIELDS: &[Cand] = &[
    ("stateful", "stateful inspection for this zone (true|false)"),
    ("block-icmp", "drop inbound ICMP on this zone (true|false)"),
    ("default-action", "ingress action for this zone (accept|drop|reject)"),
    ("log", "log this zone's traffic (true|false)"),
    ("block", "drop a source IP/CIDR on this zone"),
];
const NAT_SOURCE_FIELDS: &[Cand] = &[("zone", "egress (WAN) zone to masquerade")];
const NAT_DEST_FIELDS: &[Cand] = &[
    ("zone", "ingress zone (public side)"),
    ("proto", "tcp / udp"),
    ("port", "public destination port"),
    ("to", "internal target ip or ip:port"),
];
const BOOLS: &[Cand] = &[("true", "enabled"), ("false", "disabled")];
const ACTIONS: &[Cand] = &[
    ("accept", "allow matching traffic"),
    ("drop", "silently discard"),
    ("reject", "discard with an ICMP error"),
];
const PROTOS: &[Cand] = &[("tcp", "TCP"), ("udp", "UDP")];
const IFACE_FIELDS: &[Cand] = &[
    ("zone", "the zone this NIC belongs to"),
    ("address", "static CIDR or `dhcp`"),
    ("parent", "parent interface (for a VLAN subinterface)"),
    ("vlan", "802.1Q VLAN id 1–4094 (with `parent`)"),
];
const RULE_FIELDS: &[Cand] = &[
    ("from", "source zone"),
    ("to", "destination zone"),
    ("action", "accept / drop / reject"),
    ("proto", "tcp / udp"),
    ("port", "destination port or range (e.g. 443 or 8000-8100)"),
    ("log", "log packets matching this rule (true / false)"),
    ("source", "source address/CIDR (e.g. 10.0.0.0/24); default any"),
];

/// Static completion candidates for the token being typed, given the
/// already-complete `tokens` before it. The interface/rule/zone/nat **name**
/// positions and the zone-value positions are filled dynamically from the live
/// config — see [`dyn_candidates`].
fn candidates(tokens: &[&str]) -> &'static [Cand] {
    match tokens {
        [] => COMMANDS,
        ["set" | "delete"] => TOP,
        ["set" | "delete", "system"] => SYSTEM_FIELDS,
        // `set interface <name> <field>` — name is freeform, then fields.
        ["set" | "delete", "interface", _name] => IFACE_FIELDS,

        // The firewall sub-tree.
        ["set" | "delete", "firewall"] => FIREWALL_NODES,
        ["set" | "delete", "firewall", "global"] => GLOBAL_FIELDS,
        ["set", "firewall", "global", "stateful" | "block-icmp" | "log"] => BOOLS,
        ["set", "firewall", "global", "default-action"] => ACTIONS,
        ["set" | "delete", "firewall", "zone", _name] => ZONE_FIELDS,
        ["set", "firewall", "zone", _name, "stateful" | "block-icmp" | "log"] => BOOLS,
        ["set", "firewall", "zone", _name, "default-action"] => ACTIONS,
        ["set" | "delete", "firewall", "rule", _name] => RULE_FIELDS,
        ["set", "firewall", "rule", _name, "action"] => ACTIONS,
        ["set", "firewall", "rule", _name, "proto"] => PROTOS,
        ["set", "firewall", "rule", _name, "log"] => BOOLS,

        // The nat sub-tree (its own top-level node).
        ["set" | "delete", "nat"] => NAT_NODES,
        ["set" | "delete", "nat", "source", _name] => NAT_SOURCE_FIELDS,
        ["set" | "delete", "nat", "destination", _name] => NAT_DEST_FIELDS,
        ["set", "nat", "destination", _name, "proto"] => PROTOS,
        _ => &[],
    }
}

/// Live config names the completer offers for the name positions, refreshed
/// from the session after each command.
#[derive(Default)]
pub struct DynNames {
    pub interfaces: Vec<String>,
    pub rules: Vec<String>,
    pub zones: Vec<String>,
    pub nat_source: Vec<String>,
    pub nat_destination: Vec<String>,
}

/// Candidates for `tokens`, splicing in the live interface/rule/zone names at the
/// name + zone-value positions and falling back to the static grammar elsewhere.
/// Returns owned `(keyword, description)` pairs.
fn dyn_candidates(tokens: &[&str], names: &DynNames) -> Vec<(String, String)> {
    let own = |slice: &[Cand]| -> Vec<(String, String)> {
        slice.iter().map(|(k, d)| (k.to_string(), d.to_string())).collect()
    };
    let zones = |label: &'static str| -> Vec<(String, String)> {
        names.zones.iter().map(|z| (z.clone(), label.to_string())).collect()
    };
    match tokens {
        // `set interface <Tab>` → the NICs already present (system-discovered or
        // added), so you can pick one to keep configuring — VyOS-style.
        ["set" | "delete", "interface"] => names
            .interfaces
            .iter()
            .map(|n| (n.clone(), "interface".to_string()))
            .collect(),
        ["set" | "delete", "firewall", "rule"] => names
            .rules
            .iter()
            .map(|n| (n.clone(), "rule".to_string()))
            .collect(),
        ["set" | "delete", "nat", "source"] => names
            .nat_source
            .iter()
            .map(|n| (n.clone(), "nat source".to_string()))
            .collect(),
        ["set" | "delete", "nat", "destination"] => names
            .nat_destination
            .iter()
            .map(|n| (n.clone(), "nat destination".to_string()))
            .collect(),
        // Zone-name positions splice in the known zones.
        ["set" | "delete", "firewall", "zone"] => zones("zone"),
        ["set", "interface", _name, "zone"] => zones("zone"),
        ["set", "firewall", "rule", _name, "from" | "to"] => zones("zone"),
        ["set", "nat", "source", _name, "zone"] => zones("zone"),
        ["set", "nat", "destination", _name, "zone"] => zones("zone"),
        _ => own(candidates(tokens)),
    }
}

/// The terminal width (columns), so the completion menu can be laid out one
/// candidate per line. Falls back to 80 when it can't be queried.
fn term_width() -> usize {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0 {
            return ws.ws_col as usize;
        }
    }
    80
}

/// rustyline helper providing tab/`?` completion over the configure grammar,
/// including the live interface/rule names. The hint/highlight/validate traits
/// are no-ops; only completion is implemented.
pub struct ConfigCompleter {
    names: std::cell::RefCell<DynNames>,
}

impl ConfigCompleter {
    pub fn new() -> Self {
        Self {
            names: std::cell::RefCell::new(DynNames::default()),
        }
    }

    /// Refresh the interface/rule/zone names offered at the name + zone-value
    /// positions. Called from the configure loop after every command so new
    /// interfaces/rules/zones become completable immediately.
    pub fn set_names(
        &self,
        interfaces: Vec<String>,
        rules: Vec<String>,
        zones: Vec<String>,
        nat_source: Vec<String>,
        nat_destination: Vec<String>,
    ) {
        *self.names.borrow_mut() = DynNames {
            interfaces,
            rules,
            zones,
            nat_source,
            nat_destination,
        };
    }
}

impl Hinter for ConfigCompleter {
    type Hint = String;
}
impl Highlighter for ConfigCompleter {}
impl Validator for ConfigCompleter {}
impl Helper for ConfigCompleter {}

impl Completer for ConfigCompleter {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let head = &line[..pos];
        // The word under the cursor (empty if the line ends in whitespace) and
        // the complete tokens before it.
        let (prefix, start) = match head.rfind(char::is_whitespace) {
            Some(i) => (&head[i + 1..], i + 1),
            None => (head, 0),
        };
        let before: Vec<&str> = head[..start].split_whitespace().collect();

        let names = self.names.borrow();
        let all = dyn_candidates(&before, &names);
        let matched: Vec<&(String, String)> =
            all.iter().filter(|(kw, _)| kw.starts_with(prefix)).collect();

        // Align the keyword column, then pad each row out to the terminal width
        // so rustyline lists one candidate per line (keyword + description
        // stacked vertically), vtysh-style, instead of a packed grid.
        let kw_w = matched.iter().map(|(kw, _)| kw.len()).max().unwrap_or(0);
        let row_w = term_width().saturating_sub(1);
        let matches = matched
            .iter()
            .map(|(kw, desc)| {
                let body = if desc.is_empty() {
                    kw.clone()
                } else {
                    format!("{kw:<kw_w$}  {desc}")
                };
                Pair {
                    display: format!("{body:<row_w$}"),
                    replacement: format!("{kw} "),
                }
            })
            .collect();
        Ok((start, matches))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The keywords offered for a context (drops the descriptions).
    fn kw(tokens: &[&str]) -> Vec<&'static str> {
        candidates(tokens).iter().map(|(k, _)| *k).collect()
    }

    #[test]
    fn completion_grammar_is_context_aware() {
        assert_eq!(
            kw(&[]),
            ["set", "delete", "show", "compare", "commit", "save", "discard", "exit", "help"]
        );
        assert_eq!(kw(&["set"]), ["system", "interface", "firewall", "nat"]);
        assert_eq!(kw(&["set", "system"]), ["hostname"]);
        assert_eq!(
            kw(&["set", "interface", "wan0"]),
            ["zone", "address", "parent", "vlan"]
        );
        // The firewall sub-tree is discoverable level by level (NAT is separate).
        assert_eq!(kw(&["set", "firewall"]), ["global", "zone", "rule"]);
        assert_eq!(
            kw(&["set", "firewall", "global"]),
            ["stateful", "block-icmp", "default-action", "log", "block"]
        );
        assert_eq!(kw(&["set", "firewall", "global", "stateful"]), ["true", "false"]);
        assert_eq!(kw(&["set", "firewall", "global", "default-action"]), ["accept", "drop", "reject"]);
        assert_eq!(
            kw(&["set", "firewall", "zone", "wan"]),
            ["stateful", "block-icmp", "default-action", "log", "block"]
        );
        assert_eq!(kw(&["set", "firewall", "zone", "wan", "block-icmp"]), ["true", "false"]);
        assert_eq!(
            kw(&["set", "firewall", "rule", "web"]),
            ["from", "to", "action", "proto", "port", "log", "source"]
        );
        assert_eq!(kw(&["set", "firewall", "rule", "web", "log"]), ["true", "false"]);
        assert_eq!(kw(&["set", "firewall", "rule", "web", "action"]), ["accept", "drop", "reject"]);
        assert_eq!(kw(&["set", "firewall", "rule", "web", "proto"]), ["tcp", "udp"]);
        // The nat sub-tree: source (masquerade) + destination (port-forward).
        assert_eq!(kw(&["set", "nat"]), ["source", "destination"]);
        assert_eq!(kw(&["set", "nat", "source", "wan-masq"]), ["zone"]);
        assert_eq!(
            kw(&["set", "nat", "destination", "web"]),
            ["zone", "proto", "port", "to"]
        );
        assert_eq!(kw(&["set", "nat", "destination", "web", "proto"]), ["tcp", "udp"]);
        // zone-value positions are dynamic now (see dynamic_candidates test).
        assert!(kw(&["set", "firewall", "rule", "web", "from"]).is_empty());
        assert!(kw(&["set", "interface", "wan0", "zone"]).is_empty());
        // Unknown contexts complete nothing.
        assert!(candidates(&["bogus"]).is_empty());
    }

    #[test]
    fn dynamic_candidates_offer_live_names() {
        let names = DynNames {
            interfaces: vec!["eth0".into(), "eth1".into()],
            rules: vec!["web".into()],
            zones: vec!["lan".into(), "wan".into()],
            nat_source: vec!["wan-masq".into()],
            nat_destination: vec!["web-fwd".into()],
        };
        let kws = |toks: &[&str]| -> Vec<String> {
            dyn_candidates(toks, &names).into_iter().map(|(k, _)| k).collect()
        };
        // Name positions splice in the live interface/rule/zone/nat names.
        assert_eq!(kws(&["set", "interface"]), ["eth0", "eth1"]);
        assert_eq!(kws(&["delete", "firewall", "rule"]), ["web"]);
        assert_eq!(kws(&["set", "nat", "source"]), ["wan-masq"]);
        assert_eq!(kws(&["set", "nat", "destination"]), ["web-fwd"]);
        assert_eq!(kws(&["set", "firewall", "zone"]), ["lan", "wan"]);
        // Zone-value positions splice in the known zone names.
        assert_eq!(kws(&["set", "interface", "eth0", "zone"]), ["lan", "wan"]);
        assert_eq!(kws(&["set", "firewall", "rule", "web", "from"]), ["lan", "wan"]);
        assert_eq!(kws(&["set", "nat", "source", "wan-masq", "zone"]), ["lan", "wan"]);
        assert_eq!(kws(&["set", "nat", "destination", "web-fwd", "zone"]), ["lan", "wan"]);
        // Other positions fall back to the static grammar.
        assert_eq!(kws(&["set"]), ["system", "interface", "firewall", "nat"]);
        assert_eq!(
            kws(&["set", "interface", "eth0"]),
            ["zone", "address", "parent", "vlan"]
        );
    }

    #[test]
    fn exec_line_runs_commands_and_signals_exit() {
        // A throwaway session via a temp file so save/load work.
        let dir = std::env::temp_dir().join(format!("sentinel-repl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.toml");
        let mut s = Session::load(&path).unwrap();
        let act = Apply::off(); // no live apply in tests

        assert!(!exec_line(&mut s, &act, "set system hostname fw1"));
        assert!(!exec_line(&mut s, &act, "show"));
        // commit validates (apply off ⇒ no live changes) but does NOT persist.
        assert!(!exec_line(&mut s, &act, "commit"));
        assert!(!path.exists(), "commit must not persist (VyOS: that's `save`)");
        // save persists the config to disk.
        assert!(!exec_line(&mut s, &act, "save"));
        assert!(path.exists(), "save persisted the config");
        // exit returns true.
        assert!(exec_line(&mut s, &act, "exit"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
