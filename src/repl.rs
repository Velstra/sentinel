//! The interactive `configure` shell: command execution shared by the
//! interactive (rustyline, with tab-completion) and piped (plain stdin) paths.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
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
/// Where the Wren routing daemon reads its compiled config from.
pub const DEFAULT_WREN_OUT: &str = "/run/sentinel/wren.toml";
/// The systemd unit running the routing daemon.
pub const DEFAULT_WREN_UNIT: &str = "wren.service";

/// How `commit` applies the validated config to the running system.
pub struct Apply {
    /// Where to write the compiled velstra agent config.
    pub velstra_out: PathBuf,
    /// The systemd unit running the data plane (reloaded after writing).
    pub unit: String,
    /// Where to write the compiled Wren routing config.
    pub wren_out: PathBuf,
    /// The systemd unit running the routing daemon (reloaded after writing).
    pub wren_unit: String,
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
            wren_out: PathBuf::from(DEFAULT_WREN_OUT),
            wren_unit: DEFAULT_WREN_UNIT.to_string(),
            enabled: false,
        }
    }
}

/// Run one command line against the session. Returns `true` when the session
/// should exit (`exit`/`quit`). Errors are printed, not propagated, so the shell
/// keeps running.
pub fn exec_line(session: &mut Session, act: &Apply, ctx: &mut Vec<String>, line: &str) -> bool {
    let args: Vec<&str> = line.split_whitespace().collect();
    let Some((&cmd, rest)) = args.split_first() else {
        return false; // blank line
    };

    // The `edit` context is an implicit path prefix for set/delete/show
    // (VyOS-style): `edit firewall rule web` + `set action drop` ≡
    // `set firewall rule web action drop`.
    let with_ctx = |rest: &[&str]| -> Vec<String> {
        ctx.iter().cloned().chain(rest.iter().map(|s| s.to_string())).collect()
    };

    let result: Result<()> = match cmd {
        "set" => {
            let full = with_ctx(rest);
            let view: Vec<&str> = full.iter().map(String::as_str).collect();
            session.set(&view)
        }
        "delete" | "del" => {
            let full = with_ctx(rest);
            let view: Vec<&str> = full.iter().map(String::as_str).collect();
            session.delete(&view)
        }
        "show" => {
            let full = with_ctx(rest);
            match full.first() {
                None => print!("{}", session.show()),
                Some(section) => print!("{}", session.show_only(section)),
            }
            Ok(())
        }
        "edit" => {
            if rest.is_empty() {
                Err(anyhow!("edit needs a path, e.g. `edit firewall rule web`"))
            } else {
                let full = with_ctx(rest);
                if TOP.iter().any(|(k, _)| *k == full[0]) {
                    *ctx = full;
                    eprintln!("[edit {}]", ctx.join(" "));
                    Ok(())
                } else {
                    Err(anyhow!(
                        "unknown config node {:?} (system | interface | firewall | nat | protocols)",
                        full[0]
                    ))
                }
            }
        }
        "up" => {
            ctx.pop();
            match ctx.is_empty() {
                true => eprintln!("[edit]"),
                false => eprintln!("[edit {}]", ctx.join(" ")),
            }
            Ok(())
        }
        "top" => {
            ctx.clear();
            eprintln!("[edit]");
            Ok(())
        }
        // vtysh/VyOS: run an operational command without leaving config mode.
        "run" => match std::env::current_exe() {
            Ok(exe) => {
                let status = std::process::Command::new(exe).args(rest).status();
                match status {
                    Ok(_) => Ok(()),
                    Err(e) => Err(anyhow!("running operational command: {e}")),
                }
            }
            Err(e) => Err(anyhow!("resolving the sentinel binary: {e}")),
        },
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
            // VyOS: `exit` inside an edit context returns to the top of the
            // config tree; at the top it leaves configuration mode.
            if !ctx.is_empty() {
                ctx.clear();
                eprintln!("[edit]");
                return false;
            }
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

/// A stack of best-effort undo actions, run in reverse when a later apply stage
/// fails, so a partial `commit` never leaves the running system in a state
/// *worse* than "commit refused" (e.g. a new firewall live over stale routing).
/// A named best-effort undo action.
type UndoStep = (&'static str, Box<dyn FnOnce() -> Result<()>>);

struct Rollback {
    steps: Vec<UndoStep>,
}

impl Rollback {
    fn new() -> Self {
        Self { steps: Vec::new() }
    }

    fn push(&mut self, what: &'static str, undo: impl FnOnce() -> Result<()> + 'static) {
        self.steps.push((what, Box::new(undo)));
    }

    /// Run every recorded undo in reverse order. Returns the names of any that
    /// themselves failed, so the operator learns exactly what is left
    /// inconsistent (rather than a bare "commit failed").
    fn unwind(self) -> Vec<String> {
        let mut failures = Vec::new();
        for (what, undo) in self.steps.into_iter().rev() {
            if let Err(e) = undo() {
                failures.push(format!("{what} ({e})"));
            }
        }
        failures
    }
}

/// Write `bytes` to `path` via a temp file + rename, so a reader never sees a
/// half-written config.
fn atomic_install(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Restore a config file to a snapshot taken before the apply: rewrite the old
/// contents, or remove the file if there was none.
fn restore_file(path: &Path, prev: Option<&[u8]>) -> Result<()> {
    match prev {
        Some(bytes) => atomic_install(path, bytes),
        None => {
            let _ = std::fs::remove_file(path);
            Ok(())
        }
    }
}

/// Install a compiled config file and reload its unit as one unit of work. On
/// failure it restores the previous file (best-effort) and returns the error,
/// having made no lasting change. On success it returns an undo that restores
/// the previous file + reloads, so a *later* stage's failure can roll this back
/// too. Returns the undo boxed for the rollback stack.
fn apply_service(
    out: &Path,
    unit: &str,
    new: &[u8],
    prev: Option<&[u8]>,
) -> Result<Box<dyn FnOnce() -> Result<()>>> {
    atomic_install(out, new).with_context(|| format!("installing {}", out.display()))?;
    if let Err(e) = system::reload_velstra(unit) {
        // Reload failed: put the previous file back so we don't leave a new
        // config staged under a daemon still running the old one.
        let _ = restore_file(out, prev);
        return Err(e).with_context(|| format!("reloading {unit}"));
    }
    let out = out.to_path_buf();
    let unit = unit.to_string();
    let prev = prev.map(<[u8]>::to_vec);
    Ok(Box::new(move || {
        restore_file(&out, prev.as_deref())?;
        system::reload_velstra(&unit)
    }))
}

/// Combine the original stage error with the rollback outcome into one report.
fn unwind_err(rb: Rollback, cause: anyhow::Error, stage: &str) -> anyhow::Error {
    let failures = rb.unwind();
    if failures.is_empty() {
        anyhow!("applying {stage} failed: {cause}\n  rolled back to the previous running config")
    } else {
        anyhow!(
            "applying {stage} failed: {cause}\n  ROLLBACK INCOMPLETE — still inconsistent: {}",
            failures.join("; ")
        )
    }
}

/// Apply a validated appliance config to the running system atomically: compile
/// **everything** first (so a bad config is rejected before any live change),
/// then apply firewall, routing, hostname and addressing in order — each stage
/// recording how to undo itself. If a later stage fails, the completed stages
/// are rolled back in reverse and a report of what changed is returned.
fn apply_live(appliance: &crate::config::Appliance, act: &Apply) -> Result<()> {
    // ---- Phase 1: prepare (fallible, NO live side effects) ----
    let rendered = compile::compile(appliance)
        .to_toml()
        .context("compiling firewall config")?;
    let wren_rendered = crate::wren::compile_wren(appliance)
        .to_toml()
        .context("compiling routing config")?;
    // Snapshot the currently-installed configs so a later failure can restore
    // them (None ⇒ there was no file, so rollback removes ours).
    let velstra_prev = std::fs::read(&act.velstra_out).ok();
    let wren_prev = std::fs::read(&act.wren_out).ok();
    let old_host = system::current_hostname();

    // ---- Phase 2: apply, each stage undoable on a later failure ----
    let mut rb = Rollback::new();

    // Firewall: install + reload. If this first stage fails nothing else was
    // touched, so surface the error directly.
    let undo = apply_service(
        &act.velstra_out,
        &act.unit,
        rendered.as_bytes(),
        velstra_prev.as_deref(),
    )?;
    rb.push("firewall", undo);

    // Routing: install + reload the Wren daemon.
    match apply_service(
        &act.wren_out,
        &act.wren_unit,
        wren_rendered.as_bytes(),
        wren_prev.as_deref(),
    ) {
        Ok(undo) => rb.push("routing", undo),
        Err(e) => return Err(unwind_err(rb, e, "routing")),
    }

    // Hostname: set it live.
    if let Err(e) = system::set_hostname(&appliance.system.hostname) {
        return Err(unwind_err(rb, e, "hostname"));
    }
    rb.push("hostname", move || system::set_hostname(&old_host));

    // Interface addressing: render + apply networkd units live. Last stage, so
    // its own partial failure doesn't cascade; failure still rolls back the
    // firewall/routing/hostname above.
    if let Err(e) = crate::net::apply(appliance) {
        return Err(unwind_err(rb, e, "interface addressing"));
    }
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
  show [section]          show the candidate config (all, or one section:
                          system | interfaces | firewall | nat | protocols)
  edit <path...>          descend into a subtree; set/delete/show become
                          relative to it, e.g.  edit firewall rule web
  up | top                move one level up / back to the top of the tree
  run <op command>        run an operational command from config mode,
                          e.g.  run show ip route   run show ip bgp summary
  compare                 diff the candidate against the saved config
  commit                  apply the candidate to the RUNNING system (live)
  save [path]             persist the config so it survives a reboot
  discard                 drop edits, reload from disk
  exit | quit             leave the edit context / configuration mode
  (Tab or `?` lists commands, config keys, and value keywords.)
";

/// A completion candidate: the keyword to insert plus a short description shown
/// in the Tab/`?` listing (VyOS/vtysh style).
pub type Cand = (&'static str, &'static str);

const COMMANDS: &[Cand] = &[
    ("set", "set a configuration value"),
    ("delete", "remove a node or clear a field"),
    ("show", "show the candidate configuration (optionally a section)"),
    ("edit", "descend into a config subtree (VyOS-style context)"),
    ("up", "move one level up from the edit context"),
    ("top", "return to the top of the config tree"),
    ("run", "run an operational command (e.g. run show ip route)"),
    ("compare", "diff the candidate against the saved config"),
    ("commit", "apply the candidate to the running system (live)"),
    ("save", "persist the configuration across reboot"),
    ("discard", "drop uncommitted edits"),
    ("exit", "leave the edit context / configuration mode"),
    ("help", "show command help"),
];

// `run <Tab>` — the operational commands reachable from config mode.
const RUN_TOP: &[Cand] = &[("show", "operational show commands")];
const OP_SHOW_TOP: &[Cand] = &[
    ("interfaces", "live interfaces and addresses"),
    ("ip", "IPv4: route / bgp / ospf / rip"),
    ("ipv6", "IPv6: route / ospf3 / ripng"),
    ("isis", "IS-IS adjacencies / interfaces / database"),
    ("babel", "Babel neighbours / routes"),
    ("vrrp", "VRRP virtual-router state"),
    ("bfd", "BFD sessions"),
    ("firewall", "firewall summary / statistics / log"),
    ("nat", "NAT configuration summary"),
    ("configuration", "the saved configuration (config syntax)"),
    ("arp", "the ARP / neighbour table"),
    ("system", "hostname, services, interfaces"),
    ("log", "recent service log (velstra | wren)"),
    ("version", "software versions"),
];
const OP_IP: &[Cand] = &[
    ("route", "the routing table (via the wren RIB)"),
    ("bgp", "BGP routes / summary / neighbors"),
    ("ospf", "OSPF neighbors / interfaces / database"),
    ("rip", "RIP state"),
];
const OP_IPV6: &[Cand] = &[
    ("route", "the IPv6 routing table"),
    ("ospf3", "OSPFv3 neighbors / interfaces"),
    ("ripng", "RIPng state"),
];
// Top level: four nodes, each a clear domain — host settings, the NICs, the
// firewall (filtering), and NAT (address translation). NAT is deliberately NOT
// under firewall: filtering and translation are different things.
const TOP: &[Cand] = &[
    ("system", "host-wide settings (hostname, …)"),
    ("interface", "per-NIC zone, address, VLAN"),
    ("firewall", "packet filtering: global defaults, zones, rules"),
    ("nat", "address translation: source (masquerade), destination (port-forward)"),
    ("protocols", "dynamic routing: router-id, static routes, BGP"),
];
// `protocols <Tab>` reveals the routing sub-tree (compiled to the Wren daemon).
const PROTOCOLS_NODES: &[Cand] = &[
    ("router-id", "the 32-bit router id (an IPv4 address)"),
    ("static", "a static route (<prefix> via <ip> | dev <if>)"),
    ("ospf", "OSPFv2: interfaces, area, redistribution"),
    ("ospf3", "OSPFv3 (IPv6): interfaces, area, redistribution"),
    ("rip", "RIPv2 (IPv4): interfaces, redistribution"),
    ("ripng", "RIPng (IPv6): interfaces, redistribution"),
    ("babel", "Babel (dual-stack): interfaces, redistribution"),
    ("isis", "IS-IS: interfaces, system-id, area, level"),
    ("bgp", "BGP-4: local-as, networks, neighbors"),
    ("vrrp", "VRRP virtual router (first-hop redundancy)"),
];
const OSPF_FIELDS: &[Cand] = &[
    ("interface", "a NIC OSPF runs on"),
    ("area", "the OSPF area id (dotted quad, e.g. 0.0.0.0)"),
    ("cost", "output cost for these interfaces"),
    ("network-type", "broadcast / point-to-point"),
    ("redistribute", "inject a route source (static / connected / bgp)"),
];
const OSPF_NETWORK_TYPES: &[Cand] = &[
    ("broadcast", "elect a designated router"),
    ("point-to-point", "direct link, no DR"),
];
const RIP_FIELDS: &[Cand] = &[
    ("interface", "a NIC this protocol runs on"),
    ("redistribute", "inject a route source (static / connected / bgp)"),
    ("redistribute-metric", "metric for redistributed routes"),
];
const ISIS_FIELDS: &[Cand] = &[
    ("interface", "a NIC IS-IS runs on"),
    ("system-id", "the 6-byte system id (0000.0000.0001)"),
    ("area", "the area address (49.0001)"),
    ("level", "1 / 2 / 1-2"),
    ("network-type", "broadcast / point-to-point"),
    ("redistribute", "inject a route source"),
    ("redistribute-metric", "metric for redistributed routes"),
];
const ISIS_LEVELS: &[Cand] = &[("1", "level 1"), ("2", "level 2"), ("1-2", "both levels")];
const VRRP_FIELDS: &[Cand] = &[
    ("interface", "the NIC the virtual router runs on"),
    ("vrid", "virtual router id (1-255)"),
    ("priority", "election priority (higher wins)"),
    ("virtual-address", "the shared virtual IP"),
];
const STATIC_FIELDS: &[Cand] = &[
    ("via", "next-hop gateway IP"),
    ("dev", "outgoing interface (on-link route)"),
    ("metric", "route metric (lower wins)"),
];
const BGP_FIELDS: &[Cand] = &[
    ("local-as", "this router's AS number"),
    ("router-id", "BGP router-id (defaults to protocols router-id)"),
    ("network", "a prefix to originate/advertise"),
    ("redistribute", "inject a route source (static / connected)"),
    ("neighbor", "a BGP peer (<ip> remote-as <n>)"),
];
const REDIST: &[Cand] = &[
    ("static", "redistribute static routes"),
    ("connected", "redistribute connected (interface) routes"),
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
    ("private-key", "WireGuard private key (or `generate`)"),
    ("listen-port", "WireGuard UDP listen port"),
    ("peer", "WireGuard peer (by public key)"),
    ("dhcp-server", "serve DHCP from this NIC's static subnet"),
];
const DHCP_SERVER_FIELDS: &[Cand] = &[
    ("enable", "turn the DHCP server on"),
    ("disable", "turn the DHCP server off"),
    ("pool-offset", "first pool address offset within the subnet"),
    ("pool-size", "number of addresses in the pool"),
    ("dns", "DNS servers to advertise (comma-separated)"),
    ("lease-time", "default lease time in seconds"),
];
const WG_KEY_GEN: &[Cand] = &[("generate", "generate a fresh WireGuard keypair")];
const PEER_FIELDS: &[Cand] = &[
    ("allowed-ips", "CIDRs routed to this peer (comma-separated)"),
    ("endpoint", "peer's public host:port"),
    ("keepalive", "persistent-keepalive seconds"),
    ("preshared-key", "optional pre-shared key"),
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
        // WireGuard: `private-key` offers `generate`; a peer's fields follow its key.
        ["set", "interface", _name, "private-key"] => WG_KEY_GEN,
        ["set" | "delete", "interface", _name, "peer", _pk] => PEER_FIELDS,
        // The DHCP-server sub-tree of an interface.
        ["set" | "delete", "interface", _name, "dhcp-server"] => DHCP_SERVER_FIELDS,

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

        // The protocols (routing) sub-tree.
        ["set" | "delete", "protocols"] => PROTOCOLS_NODES,
        ["set" | "delete", "protocols", "static", _prefix] => STATIC_FIELDS,
        ["set" | "delete", "protocols", "bgp"] => BGP_FIELDS,
        ["set", "protocols", "bgp", "redistribute"] => REDIST,
        ["set" | "delete", "protocols", "ospf"] => OSPF_FIELDS,
        ["set", "protocols", "ospf", "redistribute"] => REDIST,
        ["set", "protocols", "ospf", "network-type"] => OSPF_NETWORK_TYPES,
        ["set" | "delete", "protocols", "ospf3"] => OSPF_FIELDS,
        ["set", "protocols", "ospf3", "redistribute"] => REDIST,
        ["set", "protocols", "ospf3", "network-type"] => OSPF_NETWORK_TYPES,
        ["set" | "delete", "protocols", "rip" | "ripng" | "babel"] => RIP_FIELDS,
        ["set", "protocols", "rip" | "ripng" | "babel", "redistribute"] => REDIST,
        ["set" | "delete", "protocols", "isis"] => ISIS_FIELDS,
        ["set", "protocols", "isis", "redistribute"] => REDIST,
        ["set", "protocols", "isis", "network-type"] => OSPF_NETWORK_TYPES,
        ["set", "protocols", "isis", "level"] => ISIS_LEVELS,
        ["set" | "delete", "protocols", "vrrp", _name] => VRRP_FIELDS,

        // `run` — operational commands from config mode (vtysh-style).
        ["run"] => RUN_TOP,
        ["run", "show"] => OP_SHOW_TOP,
        ["run", "show", "ip"] => OP_IP,
        ["run", "show", "ipv6"] => OP_IPV6,
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
/// The tokens candidate lookup should see for a line being completed: the
/// `edit` context is spliced in right after the command word for path commands,
/// and `edit` / scoped `show` complete like `set` paths (same tree).
fn effective_tokens(before: &[&str], ctx: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    match before.split_first() {
        Some((&cmd, rest)) if matches!(cmd, "set" | "delete" | "edit" | "show") => {
            out.push(if cmd == "edit" || cmd == "show" {
                "set".to_string()
            } else {
                cmd.to_string()
            });
            out.extend(ctx.iter().cloned());
            out.extend(rest.iter().map(|s| s.to_string()));
        }
        _ => out.extend(before.iter().map(|s| s.to_string())),
    }
    out
}

pub struct ConfigCompleter {
    names: std::cell::RefCell<DynNames>,
    /// The `edit` context: tokens implicitly prefixed to set/delete/show paths.
    context: std::cell::RefCell<Vec<String>>,
}

impl ConfigCompleter {
    pub fn new() -> Self {
        Self {
            names: std::cell::RefCell::new(DynNames::default()),
            context: std::cell::RefCell::new(Vec::new()),
        }
    }

    /// Refresh the `edit` context so completion offers candidates relative to
    /// it (`edit firewall` + `set <Tab>` lists the firewall sub-tree).
    pub fn set_context(&self, ctx: &[String]) {
        *self.context.borrow_mut() = ctx.to_vec();
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

        let ctx = self.context.borrow();
        let eff = effective_tokens(&before, &ctx);
        let eff_view: Vec<&str> = eff.iter().map(String::as_str).collect();
        let names = self.names.borrow();
        let all = dyn_candidates(&eff_view, &names);
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
            [
                "set", "delete", "show", "edit", "up", "top", "run", "compare", "commit", "save",
                "discard", "exit", "help"
            ]
        );
        assert_eq!(kw(&["set"]), ["system", "interface", "firewall", "nat", "protocols"]);
        assert_eq!(kw(&["set", "system"]), ["hostname"]);
        assert_eq!(
            kw(&["set", "interface", "wan0"]),
            [
                "zone",
                "address",
                "parent",
                "vlan",
                "private-key",
                "listen-port",
                "peer",
                "dhcp-server"
            ]
        );
        // The DHCP-server sub-tree of an interface is discoverable.
        assert_eq!(
            kw(&["set", "interface", "lan0", "dhcp-server"]),
            ["enable", "disable", "pool-offset", "pool-size", "dns", "lease-time"]
        );
        // WireGuard completion: `private-key` offers `generate`; a peer's fields
        // follow after its public key.
        assert_eq!(kw(&["set", "interface", "wg0", "private-key"]), ["generate"]);
        assert_eq!(
            kw(&["set", "interface", "wg0", "peer", "PUBKEY"]),
            ["allowed-ips", "endpoint", "keepalive", "preshared-key"]
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
        assert_eq!(kws(&["set"]), ["system", "interface", "firewall", "nat", "protocols"]);
        assert_eq!(
            kws(&["set", "interface", "eth0"]),
            [
                "zone",
                "address",
                "parent",
                "vlan",
                "private-key",
                "listen-port",
                "peer",
                "dhcp-server"
            ]
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

        let mut ctx = Vec::new();
        assert!(!exec_line(&mut s, &act, &mut ctx, "set system hostname fw1"));
        assert!(!exec_line(&mut s, &act, &mut ctx, "show"));
        // commit validates (apply off ⇒ no live changes) but does NOT persist.
        assert!(!exec_line(&mut s, &act, &mut ctx, "commit"));
        assert!(!path.exists(), "commit must not persist (VyOS: that's `save`)");
        // save persists the config to disk.
        assert!(!exec_line(&mut s, &act, &mut ctx, "save"));
        assert!(path.exists(), "save persisted the config");
        // exit returns true.
        assert!(exec_line(&mut s, &act, &mut ctx, "exit"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn edit_context_makes_paths_relative_vyos_style() {
        let dir = std::env::temp_dir().join(format!("sentinel-edit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.toml");
        let mut s = Session::load(&path).unwrap();
        let act = Apply::off();
        let mut ctx = Vec::new();

        // `edit protocols` + relative set ≡ `set protocols router-id …`.
        assert!(!exec_line(&mut s, &act, &mut ctx, "set system hostname r1"));
        assert!(!exec_line(&mut s, &act, &mut ctx, "edit protocols"));
        assert_eq!(ctx, vec!["protocols"]);
        assert!(!exec_line(&mut s, &act, &mut ctx, "set router-id 10.9.9.9"));
        // `edit` deeper from within the context appends.
        assert!(!exec_line(&mut s, &act, &mut ctx, "edit bgp"));
        assert_eq!(ctx, vec!["protocols", "bgp"]);
        assert!(!exec_line(&mut s, &act, &mut ctx, "set local-as 65001"));
        assert!(!exec_line(&mut s, &act, &mut ctx, "up"));
        assert_eq!(ctx, vec!["protocols"]);
        // `exit` inside a context returns to top — it does NOT leave the session.
        assert!(!exec_line(&mut s, &act, &mut ctx, "exit"));
        assert!(ctx.is_empty());
        // An unknown top-level node is rejected.
        assert!(!exec_line(&mut s, &act, &mut ctx, "edit bogus"));
        assert!(ctx.is_empty());

        // The relative sets landed on the real paths.
        let shown = s.show();
        assert!(shown.contains("router-id 10.9.9.9"), "{shown}");
        assert!(shown.contains("local-as 65001"), "{shown}");
        // Scoped show: only the protocols section.
        let scoped = s.show_only("protocols");
        assert!(scoped.contains("router-id 10.9.9.9"), "{scoped}");
        assert!(!scoped.contains("hostname"), "{scoped}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn completion_splices_the_edit_context() {
        // With ctx = [firewall], `set <Tab>` must offer the firewall sub-tree.
        let ctx = vec!["firewall".to_string()];
        let eff = effective_tokens(&["set"], &ctx);
        assert_eq!(eff, ["set", "firewall"]);
        // `edit` completes like `set` paths.
        let eff = effective_tokens(&["edit"], &[]);
        assert_eq!(eff, ["set"]);
        // Non-path commands pass through untouched.
        let eff = effective_tokens(&["run", "show"], &ctx);
        assert_eq!(eff, ["run", "show"]);
    }

    #[test]
    fn rollback_unwinds_in_reverse_and_reports_failures() {
        use std::cell::RefCell;
        use std::rc::Rc;

        // A shared log records the order undos run in.
        let order = Rc::new(RefCell::new(Vec::<&'static str>::new()));
        let mut rb = Rollback::new();
        for name in ["first", "second", "third"] {
            let order = order.clone();
            rb.push(name, move || {
                order.borrow_mut().push(name);
                // "second" fails to undo; the others succeed.
                if name == "second" {
                    Err(anyhow!("boom"))
                } else {
                    Ok(())
                }
            });
        }
        let failures = rb.unwind();
        // Undos run LIFO: third, second, first.
        assert_eq!(*order.borrow(), ["third", "second", "first"]);
        // Only the failing undo is reported, with its cause.
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("second"), "{:?}", failures);
        assert!(failures[0].contains("boom"), "{:?}", failures);
    }

    #[test]
    fn restore_file_rewrites_or_removes() {
        let dir = std::env::temp_dir().join(format!("sentinel-restore-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("velstra.toml");

        // Snapshot Some(old) restores the old contents even after an overwrite.
        std::fs::write(&path, b"new").unwrap();
        restore_file(&path, Some(b"old")).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"old");

        // Snapshot None (no file existed) removes the file we wrote.
        restore_file(&path, None).unwrap();
        assert!(!path.exists(), "restore of a None snapshot removes the file");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
