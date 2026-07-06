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
        ctx.iter()
            .cloned()
            .chain(rest.iter().map(|s| s.to_string()))
            .collect()
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
                // Deep validation: accept any path that names an interior node of
                // the grammar (an instance name is allowed even before it exists —
                // creation happens on the first `set` inside), reject garbage with
                // a hint listing what IS valid there.
                let full = with_ctx(rest);
                if is_interior_node(&full) {
                    *ctx = full;
                    eprintln!("[edit {}]", ctx.join(" "));
                    Ok(())
                } else {
                    Err(edit_error(&full))
                }
            }
        }
        // `no <path…>` — Cisco-style deletion relative to the context: `no bfd`.
        "no" => {
            if rest.is_empty() {
                Err(anyhow!(
                    "no needs a path, e.g. `no bfd` or `no neighbor 10.0.0.1`"
                ))
            } else {
                let full = with_ctx(rest);
                let view: Vec<&str> = full.iter().map(String::as_str).collect();
                match session.delete(&view) {
                    Ok(()) => Ok(()),
                    // Same absolute fallback as the implicit-set arm below:
                    // `no interface eth1 …` from inside another context deletes
                    // by the absolute path (Cisco mode-switch feel).
                    Err(del_err) if !ctx.is_empty() => {
                        let abs: Vec<&str> = rest.to_vec();
                        session.delete(&abs).map_err(|_| del_err)
                    }
                    Err(e) => Err(e),
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
        // `top` (VyOS) and `end` (Cisco) both jump straight to the top context.
        "top" | "end" => {
            ctx.clear();
            eprintln!("[edit]");
            Ok(())
        }
        // vtysh/VyOS `run` and Cisco `do`: run an operational command without
        // leaving config mode.
        "run" | "do" => match std::env::current_exe() {
            Ok(exe) => {
                let status = std::process::Command::new(exe).args(rest).status();
                match status {
                    Ok(_) => Ok(()),
                    Err(e) => Err(anyhow!("running operational command: {e}")),
                }
            }
            Err(e) => Err(anyhow!("resolving the sentinel binary: {e}")),
        },
        "compare" => do_compare(session, rest),
        "commit" => return commit(session, act),
        "commit-confirm" => return commit_confirm_line(session, act, rest),
        "confirm" => crate::confirm::confirm(act),
        "rollback" => return rollback_line(session, act, rest),
        "save" => {
            let to = rest.first().map(Path::new);
            session
                .save(to)
                .map(|p| eprintln!("saved {} (persists across reboot)", p.display()))
        }
        "discard" => session.discard().map(|()| eprintln!("discarded edits")),
        "exit" | "quit" => {
            // Cisco: `exit` pops ONE context level; only at the top does it leave
            // configuration mode. A level can span a keyword+instance pair
            // (`interface eth0`), so pop back to the next real interior node.
            if !ctx.is_empty() {
                pop_level(ctx);
                match ctx.is_empty() {
                    true => eprintln!("[edit]"),
                    false => eprintln!("[edit {}]", ctx.join(" ")),
                }
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
        // Not a known command. Cisco-style context feel: interpret the whole line
        // as either (b) a path to descend into, or (c) an implicit `set` relative
        // to the current context. Descend is tried BEFORE set so that entering
        // e.g. `neighbor 10.0.0.1` opens that context instead of only creating it.
        _ => {
            let full = with_ctx(&args);
            if is_interior_node(&full) {
                *ctx = full;
                eprintln!("[edit {}]", ctx.join(" "));
                Ok(())
            } else {
                let view: Vec<&str> = full.iter().map(String::as_str).collect();
                match session.set(&view) {
                    Ok(()) => Ok(()),
                    // Cisco mode-switch: a line that resolves to nothing inside
                    // the current context may be an ABSOLUTE path — on IOS,
                    // typing `interface eth1` from (config-if-eth0) switches
                    // contexts rather than erroring. Only tried with an active
                    // context; at the top, relative and absolute are the same.
                    Err(set_err) if !ctx.is_empty() => {
                        let abs: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
                        if is_interior_node(&abs) {
                            *ctx = abs;
                            eprintln!("[edit {}]", ctx.join(" "));
                            Ok(())
                        } else if session.set(&args).is_ok() {
                            Ok(())
                        } else {
                            Err(anyhow!(
                                "unknown command or config path {:?}: {set_err} \
                                 (Tab/? lists what's valid here)",
                                line.trim()
                            ))
                        }
                    }
                    Err(set_err) => Err(anyhow!(
                        "unknown command or config path {:?}: {set_err} \
                         (Tab/? lists what's valid here)",
                        line.trim()
                    )),
                }
            }
        }
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
    }
    false
}

/// The child keywords the grammar offers directly beneath `path` (an absolute
/// config path, i.e. relative to the top of the tree). Reuses the completion
/// tables so `edit`/context-entry validity stays in lockstep with Tab/`?`.
fn child_keywords(path: &[String]) -> Vec<&'static str> {
    let mut toks: Vec<&str> = Vec::with_capacity(path.len() + 1);
    toks.push("set");
    toks.extend(path.iter().map(String::as_str));
    candidates(&toks).iter().map(|(k, _)| *k).collect()
}

/// Whether `path` names an interior node we can descend into — used by `edit`
/// and by the Cisco-style context-entry shorthand. An instance-name position
/// (`firewall rule web`, `interface eth0`) counts as interior even before the
/// instance exists; creation happens on the first `set` inside.
fn is_interior_node(path: &[String]) -> bool {
    !path.is_empty() && !child_keywords(path).is_empty()
}

/// Pop one *level* off the edit context: drop the last token, then keep dropping
/// trailing tokens until the context is empty or again names a real interior
/// node. This steps `exit` up one Cisco-style level even when a level spans a
/// keyword+instance pair (`interface eth0`, `firewall rule web`, `… neighbor X`).
fn pop_level(ctx: &mut Vec<String>) {
    ctx.pop();
    while !ctx.is_empty() && !is_interior_node(ctx) {
        ctx.pop();
    }
}

/// The error for an `edit`/descend to an unknown path: point at the first bad
/// token and list what WOULD be valid at that level.
fn edit_error(full: &[String]) -> anyhow::Error {
    for cut in (0..full.len()).rev() {
        let kids = child_keywords(&full[..cut]);
        if !kids.is_empty() {
            return anyhow!(
                "unknown config node {:?} — valid here: {}",
                full[cut],
                kids.join(" | ")
            );
        }
    }
    anyhow!(
        "unknown config node {:?}",
        full.first().map(String::as_str).unwrap_or("")
    )
}

/// Render the edit context as a Cisco-style prompt fragment: `(config)` at the
/// top, `(config-if-eth0)` for an interface, `(config-router-bgp)` for BGP,
/// `(config-bgp-neighbor-10.0.0.1)` for a BGP neighbor, and generically
/// `(config-<last-two-tokens-joined-by-->)` for everything else. main.rs wraps
/// this in `user@host…# `.
pub fn prompt_context(ctx: &[String]) -> String {
    let t: Vec<&str> = ctx.iter().map(String::as_str).collect();
    match t.as_slice() {
        [] => "(config)".to_string(),
        ["interface", name] => format!("(config-if-{name})"),
        ["protocols", "bgp"] => "(config-router-bgp)".to_string(),
        ["protocols", "bgp", "neighbor", nbr] => format!("(config-bgp-neighbor-{nbr})"),
        rest => {
            let tail = &rest[rest.len().saturating_sub(2)..];
            format!("(config-{})", tail.join("-"))
        }
    }
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

/// `commit-confirm [minutes]`: apply live + arm the auto-rollback timer (roadmap
/// C21). Parses the optional window (default [`crate::confirm::
/// DEFAULT_CONFIRM_MINUTES`]) and never exits the shell. Returns `false`.
fn commit_confirm_line(session: &mut Session, act: &Apply, rest: &[&str]) -> bool {
    let minutes = match rest.first() {
        None => crate::confirm::DEFAULT_CONFIRM_MINUTES,
        Some(s) => match s.parse::<u32>() {
            Ok(m) if m >= 1 => m,
            _ => {
                eprintln!("error: commit-confirm <minutes> must be a positive integer");
                return false;
            }
        },
    };
    if let Err(e) = crate::confirm::commit_confirm(session, act, minutes) {
        eprintln!("error: {e}");
    }
    false
}

/// `compare [<N> [<M>]]`: diff the candidate against the saved config (no args),
/// against archived revision N (one arg), or revision N against revision M (two
/// args) — the VyOS `compare` spellings. Prints the diff or a "no differences"
/// note.
fn do_compare(session: &Session, rest: &[&str]) -> Result<()> {
    let rev = |s: &str| -> Result<usize> {
        s.parse::<usize>().map_err(|_| {
            anyhow!("compare: {s:?} is not a revision number (see `run show system commit`)")
        })
    };
    let diff = match rest {
        [] => session.compare()?,
        [n] => session.compare_revision(rev(n)?)?,
        [n, m] => session.compare_revisions(rev(n)?, rev(m)?)?,
        _ => {
            return Err(anyhow!(
                "compare [<rev> [<rev>]] — 0, 1 or 2 revision numbers"
            ));
        }
    };
    if diff.is_empty() {
        eprintln!("no differences");
    } else {
        print!("{diff}");
    }
    Ok(())
}

/// `rollback <N>`: revert the running system to archived revision N (0 = newest)
/// — the config-history counterpart to `commit-confirm` (roadmap C21). Never
/// exits the shell. Returns `false`.
fn rollback_line(session: &mut Session, act: &Apply, rest: &[&str]) -> bool {
    let Some(n) = rest.first().and_then(|s| s.parse::<usize>().ok()) else {
        eprintln!("error: rollback <N> needs a revision number (see `run show system commit`)");
        return false;
    };
    match crate::archive::rollback(session, act, n) {
        Ok(()) => eprintln!("rolled back to revision {n} (applied live + saved)."),
        Err(e) => eprintln!("error: {e}"),
    }
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
pub(crate) fn apply_live(appliance: &crate::config::Appliance, act: &Apply) -> Result<()> {
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
                            interface <n> zone|address|parent|vlan|type|qos|pppoe …
                            firewall global  stateful|block-icmp|default-action|log|block …
                            firewall zone <z>  stateful|block-icmp|default-action|log|block …
                            firewall rule <r>  from|to|action|proto|port|log|source|source-group|port-group …
                            firewall group  address-group <n> address <csv> | port-group <n> port <csv>
                            protocols bgp  local-as|router-id|hold-time|network|community|multipath|confederation|rpki|aggregate|roa|ebgp-require-policy …
                            protocols bgp neighbor <ip>  remote-as|passive|password|ttl-security|max-prefix|role|import|export|bfd …
                            protocols filter <name>  default accept|reject | rule <n> prefix|protocol|set-metric|set-community|action …
                            nat source <s>  zone …
                            nat destination <d>  zone|proto|port|to …
                            multiwan mode failover|load-balance
                            multiwan uplink <if>  priority|weight|table|gateway|check …
                            vpn ipsec <name>  local|remote|local-subnet|remote-subnet|psk|…
                          e.g.  set firewall rule web from wan
                                set nat source wan-masq zone wan
                                set nat destination web to 10.0.0.10:8443
  delete <path...>        remove a node or clear a field
  show [section]          show the candidate config (all, or one section:
                          system | interfaces | firewall | nat | protocols |
                          services | multiwan | vpn)
  edit <path...>          descend into a subtree (a context); set/delete/show
                          become relative to it, e.g.  edit firewall rule web
                          Any interior node works: edit interface eth0,
                          edit protocols bgp neighbor 10.0.0.1
  <path...>               context shorthand (Cisco-style): a bare path that
                          names a subtree descends into it — `interface eth0`,
                          and inside it `zone lan` — while a complete leaf path
                          is an implicit set — inside a rule, `action accept`
                          ≡ `set action accept`
  no <path...>            delete relative to the context (Cisco `no`), e.g.
                          `no action`  ≡  delete action
  exit                    pop one context level; at the top, leave config mode
  end | top               jump straight back to the top of the tree
  up                      move one token up from the edit context
  run <op command>        run an operational command from config mode,
                          e.g.  run show ip route   run show ip bgp summary
  do <op command>         Cisco alias for `run`, e.g.  do show ip route
  compare [<N> [<M>]]     diff the candidate vs the saved config (no args),
                          vs archived revision N, or revision N vs revision M
                          (list revisions with `run show system commit`)
  commit                  apply the candidate to the RUNNING system (live)
  commit-confirm [mins]   apply live, then auto-revert to the saved config after
                          `mins` (default 10) unless you `confirm` — the safety
                          net for editing a firewall over its own link
  confirm                 keep a commit-confirm change (cancel the auto-revert)
  save [path]             persist the config so it survives a reboot
  rollback <N>            revert to archived revision N (0 = newest); list them
                          with `run show system commit`
  discard                 drop edits, reload from disk
  quit                    alias for `exit`
  (Tab or `?` lists commands, config keys, and value keywords.
   examples:  edit interface eth0 → zone lan → address 10.0.0.1/24 → exit
              edit protocols bgp → local-as 65001 → neighbor 10.0.0.2 remote-as 65002)
";

/// A completion candidate: the keyword to insert plus a short description shown
/// in the Tab/`?` listing (VyOS/vtysh style).
pub type Cand = (&'static str, &'static str);

const COMMANDS: &[Cand] = &[
    ("set", "set a configuration value"),
    ("delete", "remove a node or clear a field"),
    (
        "show",
        "show the candidate configuration (optionally a section)",
    ),
    ("edit", "descend into a config subtree (VyOS-style context)"),
    ("up", "move one level up from the edit context"),
    ("top", "return to the top of the config tree"),
    ("run", "run an operational command (e.g. run show ip route)"),
    (
        "compare",
        "diff the candidate vs saved, or vs/between archived revisions",
    ),
    ("commit", "apply the candidate to the running system (live)"),
    (
        "commit-confirm",
        "apply live with an auto-rollback timer (default 10 min)",
    ),
    (
        "confirm",
        "keep a commit-confirm change (cancel the auto-rollback)",
    ),
    ("save", "persist the configuration across reboot"),
    (
        "rollback",
        "revert to an archived config revision (N; 0 = newest)",
    ),
    ("discard", "drop uncommitted edits"),
    ("exit", "leave the edit context / configuration mode"),
    ("help", "show command help"),
];

// Cisco-style extras offered at the first-token position alongside COMMANDS.
// Kept out of COMMANDS so the flat completion grammar (and its tests) is
// unchanged; they still work as typed commands everywhere.
const CONTEXT_COMMANDS: &[Cand] = &[
    ("end", "jump to the top of the config tree (Cisco `end`)"),
    ("no", "delete a node relative to the context (Cisco `no`)"),
    ("do", "run an operational command (Cisco `do show …`)"),
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
    ("vpn", "IPsec VPN: security associations / connections"),
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
const OP_VPN: &[Cand] = &[
    ("ipsec", "IPsec security associations (swanctl --list-sas)"),
    ("sas", "IPsec security associations"),
    (
        "connections",
        "loaded IPsec connections (swanctl --list-conns)",
    ),
];
// Top level: four nodes, each a clear domain — host settings, the NICs, the
// firewall (filtering), and NAT (address translation). NAT is deliberately NOT
// under firewall: filtering and translation are different things.
const TOP: &[Cand] = &[
    ("system", "host-wide settings (hostname, …)"),
    ("interface", "per-NIC zone, address, VLAN"),
    (
        "firewall",
        "packet filtering: global defaults, zones, rules",
    ),
    (
        "nat",
        "address translation: source (masquerade), destination (port-forward)",
    ),
    (
        "protocols",
        "dynamic routing: router-id, static routes, BGP",
    ),
    (
        "services",
        "box-wide services: DNS forwarder (NTP, … to come)",
    ),
    (
        "multiwan",
        "WAN uplinks: failover / load-balance + health checks",
    ),
    ("vpn", "site-to-site VPN: IKEv2 IPsec tunnels (strongSwan)"),
];
// `multiwan <Tab>` reveals the mode + the uplinks (each keyed by interface).
const MULTIWAN_NODES: &[Cand] = &[
    ("mode", "failover (primary/backup) or load-balance"),
    (
        "uplink",
        "a WAN uplink (by interface): priority, gateway, health-check",
    ),
];
const WAN_MODES: &[Cand] = &[
    (
        "failover",
        "one active uplink; fail over to the next on loss",
    ),
    (
        "load-balance",
        "spread flows across all healthy uplinks by weight",
    ),
];
// `multiwan uplink <if> <Tab>` reveals the per-uplink fields.
const UPLINK_FIELDS: &[Cand] = &[
    (
        "priority",
        "failover order (lower = preferred; default by config order)",
    ),
    ("weight", "load-balance share (default 1)"),
    ("table", "policy-routing table id (default 200 + index)"),
    (
        "gateway",
        "next-hop IPv4, or `dhcp` (resolve from the lease)",
    ),
    (
        "check",
        "health check: targets + interval/timeout/fail/rise",
    ),
];
// `multiwan uplink <if> check <Tab>` reveals the health-check fields.
const CHECK_FIELDS: &[Cand] = &[
    ("target", "an IPv4 to ping out this uplink (repeatable)"),
    ("interval", "seconds between probe rounds (default 5)"),
    ("timeout", "per-ping timeout seconds (default 2)"),
    ("fail", "consecutive losses to mark down (default 3)"),
    ("rise", "consecutive successes to mark up (default 3)"),
];
// `vpn <Tab>` reveals the VPN types (IPsec today; OpenVPN/road-warrior later).
const VPN_NODES: &[Cand] = &[("ipsec", "an IKEv2 site-to-site IPsec tunnel (by name)")];
// `vpn ipsec <name> <Tab>` reveals the per-connection fields.
const IPSEC_FIELDS: &[Cand] = &[
    ("local", "this box's IKE endpoint (IPv4)"),
    ("remote", "the peer's IKE endpoint (IPv4)"),
    ("local-subnet", "local protected subnet (IPv4 CIDR)"),
    ("remote-subnet", "remote protected subnet (IPv4 CIDR)"),
    ("psk", "pre-shared key (secret)"),
    ("ike-version", "IKE version 1 or 2 (default 2)"),
    (
        "ike-proposal",
        "IKE cipher proposal (default aes256-sha256-modp2048)",
    ),
    (
        "esp-proposal",
        "ESP cipher proposal (default aes256-sha256-modp2048)",
    ),
    ("local-id", "local IKE identity (default = local address)"),
    (
        "remote-id",
        "remote IKE identity (default = remote address)",
    ),
    ("start-action", "start | trap | none (default start)"),
];
// `vpn ipsec <name> start-action <Tab>` reveals the child-SA start actions.
const IPSEC_START_ACTIONS: &[Cand] = &[
    ("start", "initiate the tunnel as soon as the config loads"),
    (
        "trap",
        "install a policy; initiate on first matching packet",
    ),
    ("none", "wait for the peer to initiate (a responder)"),
];
// `services <Tab>` reveals the box-wide services (compiled to their daemons' config).
const SERVICES_NODES: &[Cand] = &[
    (
        "dns",
        "LAN DNS forwarder: upstreams + interfaces to serve on",
    ),
    (
        "ntp",
        "LAN NTP server: upstream sources + interfaces to serve on",
    ),
];
// `services ntp <Tab>` reveals the NTP-server fields (a chrony confdir drop-in).
const NTP_FIELDS: &[Cand] = &[
    (
        "upstream",
        "upstream NTP sources (comma-separated IPs/hostnames)",
    ),
    (
        "serve-on",
        "interfaces whose subnet may query us (comma-separated)",
    ),
];
// `services dns <Tab>` reveals the forwarder fields (a systemd-resolved drop-in).
const DNS_FIELDS: &[Cand] = &[
    (
        "upstream",
        "upstream resolvers to forward to (comma-separated IPs)",
    ),
    (
        "serve-on",
        "interfaces to listen on for LAN queries (comma-separated)",
    ),
    (
        "host-override",
        "a local DNS record: <name> <ip> (split-horizon)",
    ),
    (
        "blocklist",
        "sinkhole a domain (ad/tracker/malware blocking)",
    ),
    ("dnssec", "DNSSEC mode: yes / no / allow-downgrade"),
];
const DNSSEC_MODES: &[Cand] = &[
    ("yes", "validate"),
    ("no", "do not validate (appliance default)"),
    (
        "allow-downgrade",
        "validate, but tolerate non-DNSSEC upstreams",
    ),
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
    ("vrf", "a VRF (named isolated routing table)"),
    ("bfd", "global BFD timing / authentication defaults"),
    ("multicast", "IGMP/MLD querier + RFC 4605 proxy"),
    ("filter", "a named route filter (import/export policy)"),
    ("import", "per-protocol import filter (<proto> <filter>)"),
    ("export", "redistribution export filter (<proto> <filter>)"),
];
const OSPF_FIELDS: &[Cand] = &[
    (
        "interface",
        "a NIC OSPF runs on (add `area <id>` for its area)",
    ),
    ("area", "the OSPF area id (dotted quad, e.g. 0.0.0.0)"),
    ("router-priority", "DR-election priority (0 = never DR)"),
    ("cost", "output cost for these interfaces"),
    ("network-type", "broadcast / point-to-point"),
    (
        "passive-interface",
        "advertise the subnet, form no adjacency",
    ),
    (
        "redistribute",
        "inject a route source (static / connected / bgp)",
    ),
    ("redistribute-metric", "metric for redistributed routes"),
    ("stub-area", "an area with no AS-external LSAs"),
    ("stub-default-cost", "metric of the injected stub default"),
    ("nssa-area", "a not-so-stubby area (RFC 3101)"),
    ("totally-stubby-area", "a no-summary stub area"),
    ("totally-nssa-area", "a no-summary NSSA"),
    (
        "nssa-default-area",
        "an NSSA with an injected type-7 default",
    ),
    ("auth-type", "packet auth: none / text / md5"),
    ("auth-key", "the shared authentication key"),
    ("auth-key-id", "the MD5 key identifier"),
    ("auth-replay-protection", "MD5 anti-replay (true/false)"),
    ("hello-interval", "seconds between Hellos"),
    ("dead-interval", "seconds before a neighbour is dead"),
    (
        "graceful-restart",
        "act as a GR restarting router (true/false)",
    ),
    (
        "graceful-restart-period",
        "the advertised grace period (seconds)",
    ),
    ("bfd", "run a BFD session to each neighbour (true/false)"),
    ("vrf", "the VRF this instance runs in"),
];
const OSPF3_FIELDS: &[Cand] = &[
    ("interface", "a NIC OSPFv3 runs on (add `area <id>`)"),
    ("area", "the OSPFv3 area id (dotted quad)"),
    ("router-priority", "DR-election priority (0 = never DR)"),
    ("cost", "output cost for these interfaces"),
    ("network-type", "broadcast / point-to-point"),
    ("instance-id", "the OSPFv3 Instance ID"),
    ("redistribute", "inject a route source (static)"),
    ("redistribute-metric", "metric for redistributed routes"),
    ("bfd", "run a BFD session to each neighbour (true/false)"),
];
const OSPF_IFACE_FIELDS: &[Cand] = &[("area", "the area this interface belongs to (dotted quad)")];
const OSPF_NETWORK_TYPES: &[Cand] = &[
    ("broadcast", "elect a designated router"),
    ("point-to-point", "direct link, no DR"),
];
const OSPF_AUTH_TYPES: &[Cand] = &[
    ("none", "no authentication"),
    ("text", "cleartext password"),
    ("md5", "keyed-MD5 digest"),
];
const RIP_FIELDS: &[Cand] = &[
    ("interface", "a NIC this protocol runs on"),
    (
        "redistribute",
        "inject a route source (static / connected / bgp)",
    ),
    ("redistribute-metric", "metric for redistributed routes"),
    ("bfd", "run BFD to each neighbour (true/false)"),
    ("vrf", "the VRF this instance runs in"),
];
const RIPNG_FIELDS: &[Cand] = &[
    ("interface", "a NIC RIPng runs on"),
    ("redistribute", "inject a route source"),
    ("redistribute-metric", "metric for redistributed routes"),
];
const BABEL_FIELDS: &[Cand] = &[
    ("interface", "a NIC Babel runs on"),
    ("network", "a prefix to originate"),
    ("router-id", "the Babel Router-ID (dotted quad)"),
    ("redistribute", "inject a route source"),
    ("redistribute-metric", "metric for redistributed routes"),
    ("bfd", "run BFD to each neighbour (true/false)"),
    ("vrf", "the VRF this instance runs in"),
];
const ISIS_FIELDS: &[Cand] = &[
    ("interface", "a NIC IS-IS runs on"),
    ("system-id", "the 6-byte system id (0000.0000.0001)"),
    ("area", "the area address (49.0001)"),
    ("level", "1 / 2 / 1-2"),
    ("priority", "DIS-election priority (0-127)"),
    ("metric", "the metric advertised for each interface"),
    ("hello-interval", "HelloInterval in seconds"),
    ("network-type", "broadcast / point-to-point"),
    ("redistribute", "inject a route source"),
    ("redistribute-metric", "metric for redistributed routes"),
    ("l2-to-l1-leaking", "leak L2 prefixes into L1 (true/false)"),
    ("bfd", "run BFD to each neighbour (true/false)"),
    ("vrf", "the VRF this instance runs in"),
];
const ISIS_LEVELS: &[Cand] = &[("1", "level 1"), ("2", "level 2"), ("1-2", "both levels")];
const VRRP_FIELDS: &[Cand] = &[
    ("interface", "the NIC the virtual router runs on"),
    ("vrid", "virtual router id (1-255)"),
    ("priority", "election priority (higher wins)"),
    ("advert-interval", "advertisement interval (milliseconds)"),
    ("preempt", "preempt a lower-priority master (true/false)"),
    (
        "prefix-length",
        "the prefix length for each virtual address",
    ),
    ("track-interface", "track an interface; if down, demote"),
    (
        "priority-decrement",
        "priority drop while a tracked NIC is down",
    ),
    ("virtual-address", "the shared virtual IP"),
];
const BFD_FIELDS: &[Cand] = &[
    ("min-tx", "Desired Min TX Interval (ms)"),
    ("min-rx", "Required Min RX Interval (ms)"),
    ("detect-mult", "Detect Mult (missed intervals to fail)"),
    ("auth-type", "authentication type"),
    ("auth-key-id", "the wire key id"),
    ("auth-key", "the shared secret"),
    ("echo", "enable the Echo function (true/false)"),
    ("echo-interval", "interval between Echo packets (ms)"),
];
const MULTICAST_FIELDS: &[Cand] = &[
    ("enabled", "enable multicast IGMP/MLD (true/false)"),
    ("igmp", "run the IGMP querier/proxy (true/false)"),
    ("mld", "run the MLDv2 querier/proxy (true/false)"),
    ("igmp-version", "default IGMP version (2 or 3)"),
    ("robustness", "the Robustness Variable (QRV)"),
    ("query-interval", "the Query Interval (seconds)"),
    (
        "query-response-interval",
        "the Query Response Interval (seconds)",
    ),
    ("interface", "a NIC and its multicast role (<name> role …)"),
];
const MULTICAST_IFACE_FIELDS: &[Cand] = &[
    ("role", "querier / upstream / downstream"),
    ("igmp-version", "IGMP version for this interface (2 or 3)"),
];
const MULTICAST_ROLES: &[Cand] = &[
    ("querier", "act as the IGMP querier on this LAN"),
    ("upstream", "RFC 4605 proxy upstream (pull streams)"),
    ("downstream", "RFC 4605 proxy downstream (membership)"),
];
const VRF_FIELDS: &[Cand] = &[
    ("table", "the kernel routing table id"),
    ("rd", "the Route Distinguisher (e.g. 65000:1)"),
    ("interface", "an interface bound to this VRF"),
    ("import", "a filter applied to routes entering the VRF"),
    ("export", "a filter applied to routes leaving the VRF"),
];
const EXPORT_PROTOS: &[Cand] = &[
    ("kernel", "filter routes before the kernel FIB"),
    ("bgp", "filter routes redistributed into BGP"),
    ("ospf", "filter routes redistributed into OSPF"),
    ("rip", "filter routes redistributed into RIP"),
    ("ripng", "filter routes redistributed into RIPng"),
    ("babel", "filter routes redistributed into Babel"),
    ("isis", "filter routes redistributed into IS-IS"),
];
const IMPORT_PROTOS: &[Cand] = &[
    ("connected", "filter connected routes on import"),
    ("static", "filter static routes on import"),
    ("kernel", "filter kernel routes on import"),
    ("rip", "filter RIP routes on import"),
    ("ospf", "filter OSPF routes on import"),
    ("bgp", "filter BGP routes on import"),
    ("isis", "filter IS-IS routes on import"),
    ("babel", "filter Babel routes on import"),
];
const STATIC_FIELDS: &[Cand] = &[
    ("via", "next-hop gateway IP"),
    ("dev", "outgoing interface (on-link route)"),
    ("metric", "route metric (lower wins)"),
    ("vrf", "the VRF this route belongs to"),
];
const BGP_FIELDS: &[Cand] = &[
    ("local-as", "this router's AS number"),
    (
        "router-id",
        "BGP router-id (defaults to protocols router-id)",
    ),
    ("hold-time", "the OPEN Hold Time in seconds (default 180)"),
    ("cluster-id", "route-reflector CLUSTER_ID (dotted quad)"),
    ("network", "a prefix to originate/advertise"),
    ("redistribute", "inject a route source (static / connected)"),
    ("community", "a community attached to originated routes"),
    ("large-community", "a large community on originated routes"),
    ("ext-community", "an ext community on originated routes"),
    ("multipath", "max equal-cost paths (BGP multipath / ECMP)"),
    ("confederation", "confederation id / member (RFC 5065)"),
    ("aggregate", "a covering aggregate prefix (<prefix>)"),
    ("roa", "a static RPKI ROA (<prefix> origin-as <n>)"),
    ("rpki", "RPKI: reject-invalid, rtr cache"),
    ("ebgp-require-policy", "require a policy on every eBGP peer"),
    ("vrf", "the VRF this BGP instance runs in"),
    ("neighbor", "a BGP peer (<ip> remote-as <n> ...)"),
];
// A BGP neighbour's per-peer policy surface.
const NEIGHBOR_FIELDS: &[Cand] = &[
    ("remote-as", "the peer's AS number"),
    ("passive", "wait for the peer to connect"),
    ("route-reflector-client", "this iBGP peer is an RR client"),
    ("ttl-security", "GTSM max hops to the peer (1-254)"),
    ("password", "TCP-MD5 signature password"),
    ("ao-key", "TCP-AO master key"),
    ("ao-key-id", "TCP-AO key id (default 100)"),
    ("max-prefix", "tear down over this many prefixes"),
    ("default-originate", "advertise a default route to the peer"),
    ("add-path", "negotiate ADD-PATH (RFC 7911)"),
    ("extended-nexthop", "negotiate IPv4-over-IPv6 next hop"),
    ("evpn", "negotiate the EVPN address family"),
    ("flowspec", "negotiate the FlowSpec address family"),
    ("srpolicy", "negotiate the SR Policy address family"),
    ("link-state", "negotiate the BGP-LS address family"),
    ("import", "inbound route policy (a filter name)"),
    ("export", "outbound route policy (a filter name)"),
    ("role", "BGP Role toward the peer (RFC 9234)"),
    ("bfd", "run a BFD session to the peer"),
    ("bfd-auth-type", "per-neighbour BFD auth type"),
    ("bfd-auth-key-id", "BFD auth wire key id (default 1)"),
    ("bfd-auth-key", "BFD auth shared secret"),
];
// Values for `neighbor <ip> role`.
const BGP_ROLES: &[Cand] = &[
    ("provider", "transit provider (OTC applies)"),
    ("customer", "transit customer"),
    ("peer", "settlement-free peer"),
    ("rs-server", "route-server"),
    ("rs-client", "route-server client"),
];
// Values for `neighbor <ip> bfd-auth-type`.
const BFD_AUTH_TYPES: &[Cand] = &[
    ("simple", "simple password"),
    ("keyed-md5", "keyed MD5"),
    ("meticulous-md5", "meticulous keyed MD5"),
    ("keyed-sha1", "keyed SHA1"),
    ("meticulous-sha1", "meticulous keyed SHA1"),
];
const CONFEDERATION_FIELDS: &[Cand] = &[
    ("id", "the confederation identifier (AS shown externally)"),
    ("member", "a member-AS of this confederation"),
];
const RPKI_FIELDS: &[Cand] = &[
    ("reject-invalid", "drop RPKI-Invalid routes"),
    ("rtr", "RTR validating cache (host:port)"),
    ("rtr-refresh", "RTR refresh interval (seconds)"),
];
const AGGREGATE_FIELDS: &[Cand] = &[("summary-only", "advertise only the aggregate")];
const ROA_FIELDS: &[Cand] = &[
    ("origin-as", "the AS authorised to originate the prefix"),
    ("max-length", "the longest prefix length authorised"),
];
// A route filter's fields, and one rule's fields.
const FILTER_FIELDS: &[Cand] = &[
    ("default", "action when no rule matches (accept / reject)"),
    ("rule", "a rule, keyed by an integer index (<n>)"),
];
const FILTER_RULE_FIELDS: &[Cand] = &[
    ("prefix", "a prefix pattern to match (e.g. 10.0.0.0/8+)"),
    ("protocol", "match this route's protocol"),
    ("metric-le", "match metric ≤ this"),
    ("metric-ge", "match metric ≥ this"),
    ("set-metric", "set the matched route's metric"),
    ("add-metric", "add a signed delta to the metric"),
    ("set-preference", "set the administrative preference"),
    ("set-community", "replace communities"),
    ("add-community", "append a community"),
    ("set-large-community", "replace large communities"),
    ("add-large-community", "append a large community"),
    ("set-ext-community", "replace ext communities"),
    ("add-ext-community", "append an ext community"),
    ("action", "accept / reject a matching route"),
];
const ACCEPT_REJECT: &[Cand] = &[
    ("accept", "accept the route"),
    ("reject", "reject the route"),
];
const REDIST: &[Cand] = &[
    ("static", "redistribute static routes"),
    ("connected", "redistribute connected (interface) routes"),
];
// `firewall <Tab>` reveals the three firewall sub-trees (NAT lives at top level).
const FIREWALL_NODES: &[Cand] = &[
    ("global", "default posture inherited by every zone"),
    (
        "zone",
        "per-zone overrides (ICMP, stateful, default-action, …)",
    ),
    ("rule", "zone-to-zone allow/deny rules"),
    ("group", "named address/port aliases referenced by rules"),
];
// `firewall group <Tab>` reveals the alias kinds.
const GROUP_NODES: &[Cand] = &[
    (
        "address-group",
        "a reusable set of hosts/CIDRs (rule source-group)",
    ),
    (
        "port-group",
        "a reusable set of ports/ranges (rule port-group)",
    ),
];
const ADDRESS_GROUP_FIELDS: &[Cand] = &[(
    "address",
    "members: hosts/CIDRs, comma-separated (replaces the set)",
)];
const PORT_GROUP_FIELDS: &[Cand] = &[(
    "port",
    "members: ports/ranges, comma-separated (replaces the set)",
)];
// `nat <Tab>` reveals the two NAT directions (VyOS-style).
const NAT_NODES: &[Cand] = &[
    ("source", "SNAT/masquerade a zone's outbound traffic"),
    (
        "destination",
        "inbound DNAT port-forward to an internal host",
    ),
];
const SYSTEM_FIELDS: &[Cand] = &[("hostname", "the appliance hostname")];
const GLOBAL_FIELDS: &[Cand] = &[
    (
        "stateful",
        "track flows so return traffic is allowed (true|false)",
    ),
    ("block-icmp", "drop inbound ICMP by default (true|false)"),
    (
        "default-action",
        "default ingress action (accept|drop|reject)",
    ),
    ("log", "log matched traffic by default (true|false)"),
    ("block", "drop a source IP/CIDR everywhere"),
];
const ZONE_FIELDS: &[Cand] = &[
    ("stateful", "stateful inspection for this zone (true|false)"),
    ("block-icmp", "drop inbound ICMP on this zone (true|false)"),
    (
        "default-action",
        "ingress action for this zone (accept|drop|reject)",
    ),
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
    (
        "address6",
        "static IPv6 CIDR, `auto` (SLAAC) or `dhcp` (DHCPv6)",
    ),
    (
        "pd-from",
        "request a delegated IPv6 prefix from this uplink (DHCPv6-PD)",
    ),
    (
        "pd-subnet",
        "which /64 of the delegated prefix to use (0-255)",
    ),
    ("parent", "parent interface (for a VLAN subinterface)"),
    ("vlan", "802.1Q VLAN id 1–4094 (with `parent`)"),
    ("private-key", "WireGuard private key (or `generate`)"),
    ("listen-port", "WireGuard UDP listen port"),
    ("peer", "WireGuard peer (by public key)"),
    ("dhcp-server", "serve DHCP from this NIC's static subnet"),
    ("router-advert", "emit IPv6 Router Advertisements (SLAAC)"),
    (
        "type",
        "make this a bridge | bond | pppoe | gre | ipip | gretap interface",
    ),
    ("local", "tunnel local endpoint IP (type gre/ipip/gretap)"),
    ("remote", "tunnel remote endpoint IP (type gre/ipip/gretap)"),
    ("key", "GRE key (type gre/gretap) — demultiplexes tunnels"),
    ("ttl", "tunnel outer TTL 0–255 (0 = inherit inner)"),
    ("master", "enslave this NIC to a bridge/bond device"),
    ("bond-mode", "bonding mode (on a type=bond device)"),
    ("mtu", "link MTU in bytes (e.g. 1492 PPPoE, 9000 jumbo)"),
    (
        "mac",
        "override the link MAC (MAC cloning), e.g. 52:54:00:12:34:56",
    ),
    (
        "qos",
        "egress traffic shaping (cake / fq_codel — bufferbloat)",
    ),
    ("pppoe", "PPPoE client credentials (on a type=pppoe uplink)"),
];
const ADDRESS6_HINT: &[Cand] = &[
    ("auto", "accept Router Advertisements (SLAAC)"),
    (
        "dhcp",
        "DHCPv6 client (WAN uplink; may request a delegated prefix)",
    ),
];
const IFACE_TYPES: &[Cand] = &[
    ("bridge", "an L2 switch; enslave NICs with `master`"),
    ("bond", "link aggregation; enslave NICs with `master`"),
    (
        "pppoe",
        "a PPPoE client over a raw uplink NIC (VDSL/fibre WAN)",
    ),
    (
        "gre",
        "a GRE L3 tunnel (local/remote endpoints, optional key)",
    ),
    ("ipip", "an IPIP (IPv4-in-IPv4) L3 tunnel (no key)"),
    (
        "gretap",
        "a GRETAP L2 tunnel (GRE carrying Ethernet frames)",
    ),
];
const PPPOE_FIELDS: &[Cand] = &[
    ("username", "ISP login (PPPoE/PAP/CHAP username)"),
    (
        "password",
        "ISP password (stored 0600, rendered to chap/pap-secrets)",
    ),
    (
        "service-name",
        "optional PPPoE service name (rp_pppoe_service)",
    ),
    (
        "ac-name",
        "optional PPPoE access-concentrator name (rp_pppoe_ac)",
    ),
    ("mru", "PPP MRU in bytes (default = mtu or 1492)"),
];
const QOS_FIELDS: &[Cand] = &[
    ("discipline", "cake (shaper+AQM) or fq_codel (AQM only)"),
    (
        "bandwidth",
        "CAKE shaping rate, e.g. 100mbit (or `unlimited`)",
    ),
    (
        "rtt",
        "CAKE path RTT, a time (100ms) or keyword (internet/lan/…)",
    ),
    ("nat", "CAKE: per-host fairness through NAT (true / false)"),
    (
        "ack-filter",
        "CAKE: thin redundant ACKs on an asymmetric link (true/false)",
    ),
    (
        "diffserv",
        "CAKE tin mode (besteffort/diffserv3/diffserv4/diffserv8)",
    ),
    ("target", "fq_codel target delay, e.g. 5ms"),
    ("interval", "fq_codel interval, e.g. 100ms"),
    ("limit", "fq_codel backlog packet limit"),
];
const QOS_DISCIPLINES: &[Cand] = &[
    (
        "cake",
        "combined shaper + AQM + fairness (WAN uplink default)",
    ),
    ("fq_codel", "flow-queuing CoDel AQM (no built-in shaper)"),
];
const QOS_RTT: &[Cand] = &[
    ("datacentre", "~100us — same rack"),
    ("lan", "~1ms — local network"),
    ("metro", "~10ms — metropolitan"),
    ("regional", "~30ms"),
    ("internet", "~100ms — the default WAN preset"),
    ("oceanic", "~300ms"),
    ("satellite", "~1000ms"),
    ("interplanetary", "very high"),
];
const QOS_DIFFSERV: &[Cand] = &[
    ("besteffort", "one tin (no DSCP prioritisation)"),
    ("precedence", "legacy IP precedence"),
    ("diffserv3", "3 tins (bulk / best-effort / voice)"),
    ("diffserv4", "4 tins (bulk / best-effort / video / voice)"),
    ("diffserv8", "8 tins"),
];
const BOND_MODES: &[Cand] = &[
    (
        "active-backup",
        "one active link, the rest standby (no switch config)",
    ),
    ("802.3ad", "LACP link aggregation (needs switch support)"),
    ("balance-rr", "round-robin across links"),
    ("balance-xor", "hash-based load balancing"),
    ("broadcast", "transmit on all links"),
    ("balance-tlb", "adaptive transmit load balancing"),
    ("balance-alb", "adaptive load balancing (tx+rx)"),
];
const DHCP_SERVER_FIELDS: &[Cand] = &[
    ("enable", "turn the DHCP server on"),
    ("disable", "turn the DHCP server off"),
    ("pool-offset", "first pool address offset within the subnet"),
    ("pool-size", "number of addresses in the pool"),
    ("dns", "DNS servers to advertise (comma-separated)"),
    ("lease-time", "default lease time in seconds"),
];
const RA_FIELDS: &[Cand] = &[
    ("enable", "turn the RA sender on"),
    ("disable", "turn the RA sender off"),
    ("prefix", "IPv6 /64 prefixes to advertise (comma-separated)"),
    ("dns", "IPv6 DNS servers to advertise (comma-separated)"),
    ("managed", "set the Managed (M) flag (true / false)"),
    (
        "other-config",
        "set the Other-config (O) flag (true / false)",
    ),
    (
        "router-lifetime",
        "router lifetime seconds (0 = not a default router)",
    ),
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
    (
        "source",
        "source address/CIDR (e.g. 10.0.0.0/24); default any",
    ),
    (
        "source-group",
        "match an address-group (alias) as the source",
    ),
    (
        "port-group",
        "match a port-group (alias) instead of a single port",
    ),
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
        // `address6 auto` completes the SLAAC keyword.
        ["set", "interface", _name, "address6"] => ADDRESS6_HINT,
        // Bridge/bond value completions.
        ["set", "interface", _name, "type"] => IFACE_TYPES,
        ["set", "interface", _name, "bond-mode"] => BOND_MODES,
        // The PPPoE-client sub-tree of an interface.
        ["set" | "delete", "interface", _name, "pppoe"] => PPPOE_FIELDS,
        // The QoS / traffic-shaping sub-tree of an interface.
        ["set" | "delete", "interface", _name, "qos"] => QOS_FIELDS,
        ["set", "interface", _name, "qos", "discipline"] => QOS_DISCIPLINES,
        ["set", "interface", _name, "qos", "rtt"] => QOS_RTT,
        ["set", "interface", _name, "qos", "diffserv"] => QOS_DIFFSERV,
        ["set", "interface", _name, "qos", "nat" | "ack-filter"] => BOOLS,
        // The DHCP-server sub-tree of an interface.
        ["set" | "delete", "interface", _name, "dhcp-server"] => DHCP_SERVER_FIELDS,
        // The IPv6 Router-Advertisement sub-tree of an interface.
        ["set" | "delete", "interface", _name, "router-advert"] => RA_FIELDS,
        [
            "set",
            "interface",
            _name,
            "router-advert",
            "managed" | "other-config",
        ] => BOOLS,

        // The box-wide services sub-tree, and the DNS forwarder within it.
        ["set" | "delete", "services"] => SERVICES_NODES,
        ["set" | "delete", "services", "dns"] => DNS_FIELDS,
        ["set", "services", "dns", "dnssec"] => DNSSEC_MODES,
        ["set" | "delete", "services", "ntp"] => NTP_FIELDS,

        // The firewall sub-tree.
        ["set" | "delete", "firewall"] => FIREWALL_NODES,
        // firewall group: the alias kinds + their member fields.
        ["set" | "delete", "firewall", "group"] => GROUP_NODES,
        [
            "set" | "delete",
            "firewall",
            "group",
            "address-group",
            _name,
        ] => ADDRESS_GROUP_FIELDS,
        ["set" | "delete", "firewall", "group", "port-group", _name] => PORT_GROUP_FIELDS,
        ["set" | "delete", "firewall", "global"] => GLOBAL_FIELDS,
        [
            "set",
            "firewall",
            "global",
            "stateful" | "block-icmp" | "log",
        ] => BOOLS,
        ["set", "firewall", "global", "default-action"] => ACTIONS,
        ["set" | "delete", "firewall", "zone", _name] => ZONE_FIELDS,
        [
            "set",
            "firewall",
            "zone",
            _name,
            "stateful" | "block-icmp" | "log",
        ] => BOOLS,
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
        ["set", "protocols", "bgp", "ebgp-require-policy"] => BOOLS,
        ["set" | "delete", "protocols", "bgp", "confederation"] => CONFEDERATION_FIELDS,
        ["set" | "delete", "protocols", "bgp", "rpki"] => RPKI_FIELDS,
        ["set", "protocols", "bgp", "rpki", "reject-invalid"] => BOOLS,
        ["set" | "delete", "protocols", "bgp", "aggregate", _prefix] => AGGREGATE_FIELDS,
        [
            "set",
            "protocols",
            "bgp",
            "aggregate",
            _prefix,
            "summary-only",
        ] => BOOLS,
        ["set" | "delete", "protocols", "bgp", "roa", _prefix] => ROA_FIELDS,
        ["set" | "delete", "protocols", "bgp", "neighbor", _addr] => NEIGHBOR_FIELDS,
        ["set", "protocols", "bgp", "neighbor", _addr, "role"] => BGP_ROLES,
        [
            "set",
            "protocols",
            "bgp",
            "neighbor",
            _addr,
            "bfd-auth-type",
        ] => BFD_AUTH_TYPES,
        [
            "set",
            "protocols",
            "bgp",
            "neighbor",
            _addr,
            "passive"
            | "route-reflector-client"
            | "default-originate"
            | "add-path"
            | "extended-nexthop"
            | "evpn"
            | "flowspec"
            | "srpolicy"
            | "link-state"
            | "bfd",
        ] => BOOLS,
        ["set" | "delete", "protocols", "filter", _name] => FILTER_FIELDS,
        ["set", "protocols", "filter", _name, "default"] => ACCEPT_REJECT,
        ["set" | "delete", "protocols", "filter", _name, "rule", _n] => FILTER_RULE_FIELDS,
        ["set", "protocols", "filter", _name, "rule", _n, "action"] => ACCEPT_REJECT,
        ["set" | "delete", "protocols", "ospf"] => OSPF_FIELDS,
        ["set", "protocols", "ospf", "redistribute"] => REDIST,
        ["set", "protocols", "ospf", "network-type"] => OSPF_NETWORK_TYPES,
        ["set", "protocols", "ospf", "auth-type"] => OSPF_AUTH_TYPES,
        [
            "set",
            "protocols",
            "ospf",
            "auth-replay-protection" | "graceful-restart" | "bfd",
        ] => BOOLS,
        // A per-interface area: `ospf interface <name> area <id>`.
        [
            "set" | "delete",
            "protocols",
            "ospf" | "ospf3",
            "interface",
            _name,
        ] => OSPF_IFACE_FIELDS,
        ["set" | "delete", "protocols", "ospf3"] => OSPF3_FIELDS,
        ["set", "protocols", "ospf3", "redistribute"] => REDIST,
        ["set", "protocols", "ospf3", "network-type"] => OSPF_NETWORK_TYPES,
        ["set", "protocols", "ospf3", "bfd"] => BOOLS,
        ["set" | "delete", "protocols", "rip"] => RIP_FIELDS,
        ["set" | "delete", "protocols", "ripng"] => RIPNG_FIELDS,
        ["set" | "delete", "protocols", "babel"] => BABEL_FIELDS,
        [
            "set",
            "protocols",
            "rip" | "ripng" | "babel",
            "redistribute",
        ] => REDIST,
        ["set", "protocols", "rip" | "babel", "bfd"] => BOOLS,
        ["set" | "delete", "protocols", "isis"] => ISIS_FIELDS,
        ["set", "protocols", "isis", "redistribute"] => REDIST,
        ["set", "protocols", "isis", "network-type"] => OSPF_NETWORK_TYPES,
        ["set", "protocols", "isis", "level"] => ISIS_LEVELS,
        ["set", "protocols", "isis", "l2-to-l1-leaking" | "bfd"] => BOOLS,
        ["set" | "delete", "protocols", "vrrp", _name] => VRRP_FIELDS,
        ["set", "protocols", "vrrp", _name, "preempt"] => BOOLS,
        // Global BFD timing / authentication defaults.
        ["set" | "delete", "protocols", "bfd"] => BFD_FIELDS,
        ["set", "protocols", "bfd", "auth-type"] => BFD_AUTH_TYPES,
        ["set", "protocols", "bfd", "echo"] => BOOLS,
        // Multicast (IGMP/MLD querier + proxy).
        ["set" | "delete", "protocols", "multicast"] => MULTICAST_FIELDS,
        ["set", "protocols", "multicast", "enabled" | "igmp" | "mld"] => BOOLS,
        [
            "set" | "delete",
            "protocols",
            "multicast",
            "interface",
            _name,
        ] => MULTICAST_IFACE_FIELDS,
        ["set", "protocols", "multicast", "interface", _name, "role"] => MULTICAST_ROLES,
        // VRF instances.
        ["set" | "delete", "protocols", "vrf", _name] => VRF_FIELDS,
        // Global redistribution filters.
        ["set" | "delete", "protocols", "export"] => EXPORT_PROTOS,
        ["set" | "delete", "protocols", "import"] => IMPORT_PROTOS,

        // The multiwan (Multi-WAN failover / load-balance) sub-tree.
        ["set" | "delete", "multiwan"] => MULTIWAN_NODES,
        ["set", "multiwan", "mode"] => WAN_MODES,
        ["set" | "delete", "multiwan", "uplink", _iface] => UPLINK_FIELDS,
        ["set" | "delete", "multiwan", "uplink", _iface, "check"] => CHECK_FIELDS,

        // The vpn (IKEv2 site-to-site IPsec) sub-tree.
        ["set" | "delete", "vpn"] => VPN_NODES,
        ["set" | "delete", "vpn", "ipsec", _name] => IPSEC_FIELDS,
        ["set", "vpn", "ipsec", _name, "start-action"] => IPSEC_START_ACTIONS,

        // `run` — operational commands from config mode (vtysh-style).
        ["run"] => RUN_TOP,
        ["run", "show"] => OP_SHOW_TOP,
        ["run", "show", "ip"] => OP_IP,
        ["run", "show", "ipv6"] => OP_IPV6,
        ["run", "show", "vpn"] => OP_VPN,
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
    pub address_groups: Vec<String>,
    pub port_groups: Vec<String>,
}

/// Candidates for `tokens`, splicing in the live interface/rule/zone names at the
/// name + zone-value positions and falling back to the static grammar elsewhere.
/// Returns owned `(keyword, description)` pairs.
fn dyn_candidates(tokens: &[&str], names: &DynNames) -> Vec<(String, String)> {
    let own = |slice: &[Cand]| -> Vec<(String, String)> {
        slice
            .iter()
            .map(|(k, d)| (k.to_string(), d.to_string()))
            .collect()
    };
    let zones = |label: &'static str| -> Vec<(String, String)> {
        names
            .zones
            .iter()
            .map(|z| (z.clone(), label.to_string()))
            .collect()
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
        // `multiwan uplink <Tab>` → the NICs, so you pick one to make an uplink.
        ["set" | "delete", "multiwan", "uplink"] => names
            .interfaces
            .iter()
            .map(|n| (n.clone(), "interface".to_string()))
            .collect(),
        // Zone-name positions splice in the known zones.
        ["set" | "delete", "firewall", "zone"] => zones("zone"),
        ["set", "interface", _name, "zone"] => zones("zone"),
        ["set", "firewall", "rule", _name, "from" | "to"] => zones("zone"),
        ["set", "nat", "source", _name, "zone"] => zones("zone"),
        ["set", "nat", "destination", _name, "zone"] => zones("zone"),
        // Group-name positions splice in the declared alias names — both when
        // editing/deleting a group and when a rule references one.
        ["set" | "delete", "firewall", "group", "address-group"]
        | ["set", "firewall", "rule", _, "source-group"] => names
            .address_groups
            .iter()
            .map(|n| (n.clone(), "address-group".to_string()))
            .collect(),
        ["set" | "delete", "firewall", "group", "port-group"]
        | ["set", "firewall", "rule", _, "port-group"] => names
            .port_groups
            .iter()
            .map(|n| (n.clone(), "port-group".to_string()))
            .collect(),
        _ => own(candidates(tokens)),
    }
}

/// Candidates at the first-token (command) position, Cisco-aware: the flat
/// commands, plus the extra commands (end/no/do), plus the child keywords of the
/// current context — so an empty-line Tab/`?` inside a context lists both the
/// commands and the subtree you can descend into or implicitly `set`.
fn first_token_candidates(ctx: &[String], names: &DynNames) -> Vec<(String, String)> {
    let mut all = dyn_candidates(&[], names); // COMMANDS
    for (k, d) in CONTEXT_COMMANDS {
        if !all.iter().any(|(kw, _)| kw == k) {
            all.push((k.to_string(), d.to_string()));
        }
    }
    let mut child_toks: Vec<&str> = vec!["set"];
    child_toks.extend(ctx.iter().map(String::as_str));
    for c in dyn_candidates(&child_toks, names) {
        if !all.iter().any(|(kw, _)| *kw == c.0) {
            all.push(c);
        }
    }
    all
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
    #[allow(clippy::too_many_arguments)]
    pub fn set_names(
        &self,
        interfaces: Vec<String>,
        rules: Vec<String>,
        zones: Vec<String>,
        nat_source: Vec<String>,
        nat_destination: Vec<String>,
        address_groups: Vec<String>,
        port_groups: Vec<String>,
    ) {
        *self.names.borrow_mut() = DynNames {
            interfaces,
            rules,
            zones,
            nat_source,
            nat_destination,
            address_groups,
            port_groups,
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
        // First-token completion is Cisco-aware (see first_token_candidates);
        // deeper positions use the plain grammar.
        let all = if before.is_empty() {
            first_token_candidates(&ctx, &names)
        } else {
            dyn_candidates(&eff_view, &names)
        };
        let matched: Vec<&(String, String)> = all
            .iter()
            .filter(|(kw, _)| kw.starts_with(prefix))
            .collect();

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
                "set",
                "delete",
                "show",
                "edit",
                "up",
                "top",
                "run",
                "compare",
                "commit",
                "commit-confirm",
                "confirm",
                "save",
                "rollback",
                "discard",
                "exit",
                "help"
            ]
        );
        assert_eq!(
            kw(&["set"]),
            [
                "system",
                "interface",
                "firewall",
                "nat",
                "protocols",
                "services",
                "multiwan",
                "vpn"
            ]
        );
        assert_eq!(kw(&["set", "system"]), ["hostname"]);
        assert_eq!(
            kw(&["set", "interface", "wan0"]),
            [
                "zone",
                "address",
                "address6",
                "pd-from",
                "pd-subnet",
                "parent",
                "vlan",
                "private-key",
                "listen-port",
                "peer",
                "dhcp-server",
                "router-advert",
                "type",
                "local",
                "remote",
                "key",
                "ttl",
                "master",
                "bond-mode",
                "mtu",
                "mac",
                "qos",
                "pppoe"
            ]
        );
        // The QoS sub-tree of an interface is discoverable.
        assert_eq!(
            kw(&["set", "interface", "wan0", "qos"]),
            [
                "discipline",
                "bandwidth",
                "rtt",
                "nat",
                "ack-filter",
                "diffserv",
                "target",
                "interval",
                "limit"
            ]
        );
        assert_eq!(
            kw(&["set", "interface", "wan0", "qos", "discipline"]),
            ["cake", "fq_codel"]
        );
        // The DHCP-server sub-tree of an interface is discoverable.
        assert_eq!(
            kw(&["set", "interface", "lan0", "dhcp-server"]),
            [
                "enable",
                "disable",
                "pool-offset",
                "pool-size",
                "dns",
                "lease-time"
            ]
        );
        // The router-advert sub-tree of an interface is discoverable too.
        assert_eq!(
            kw(&["set", "interface", "lan0", "router-advert"]),
            [
                "enable",
                "disable",
                "prefix",
                "dns",
                "managed",
                "other-config",
                "router-lifetime"
            ]
        );
        // The PPPoE-client sub-tree of an interface is discoverable.
        assert_eq!(
            kw(&["set", "interface", "ppp0", "pppoe"]),
            ["username", "password", "service-name", "ac-name", "mru"]
        );
        // WireGuard completion: `private-key` offers `generate`; a peer's fields
        // follow after its public key.
        assert_eq!(
            kw(&["set", "interface", "wg0", "private-key"]),
            ["generate"]
        );
        assert_eq!(
            kw(&["set", "interface", "wg0", "peer", "PUBKEY"]),
            ["allowed-ips", "endpoint", "keepalive", "preshared-key"]
        );
        // The firewall sub-tree is discoverable level by level (NAT is separate).
        assert_eq!(
            kw(&["set", "firewall"]),
            ["global", "zone", "rule", "group"]
        );
        // The group sub-tree: alias kinds and their member fields.
        assert_eq!(
            kw(&["set", "firewall", "group"]),
            ["address-group", "port-group"]
        );
        assert_eq!(
            kw(&["set", "firewall", "group", "address-group", "mgmt"]),
            ["address"]
        );
        assert_eq!(
            kw(&["set", "firewall", "group", "port-group", "web"]),
            ["port"]
        );
        assert_eq!(
            kw(&["set", "firewall", "global"]),
            ["stateful", "block-icmp", "default-action", "log", "block"]
        );
        assert_eq!(
            kw(&["set", "firewall", "global", "stateful"]),
            ["true", "false"]
        );
        assert_eq!(
            kw(&["set", "firewall", "global", "default-action"]),
            ["accept", "drop", "reject"]
        );
        assert_eq!(
            kw(&["set", "firewall", "zone", "wan"]),
            ["stateful", "block-icmp", "default-action", "log", "block"]
        );
        assert_eq!(
            kw(&["set", "firewall", "zone", "wan", "block-icmp"]),
            ["true", "false"]
        );
        assert_eq!(
            kw(&["set", "firewall", "rule", "web"]),
            [
                "from",
                "to",
                "action",
                "proto",
                "port",
                "log",
                "source",
                "source-group",
                "port-group"
            ]
        );
        assert_eq!(
            kw(&["set", "firewall", "rule", "web", "log"]),
            ["true", "false"]
        );
        assert_eq!(
            kw(&["set", "firewall", "rule", "web", "action"]),
            ["accept", "drop", "reject"]
        );
        assert_eq!(
            kw(&["set", "firewall", "rule", "web", "proto"]),
            ["tcp", "udp"]
        );
        // The nat sub-tree: source (masquerade) + destination (port-forward).
        assert_eq!(kw(&["set", "nat"]), ["source", "destination"]);
        assert_eq!(kw(&["set", "nat", "source", "wan-masq"]), ["zone"]);
        assert_eq!(
            kw(&["set", "nat", "destination", "web"]),
            ["zone", "proto", "port", "to"]
        );
        assert_eq!(
            kw(&["set", "nat", "destination", "web", "proto"]),
            ["tcp", "udp"]
        );
        // zone-value positions are dynamic now (see dynamic_candidates test).
        assert!(kw(&["set", "firewall", "rule", "web", "from"]).is_empty());
        assert!(kw(&["set", "interface", "wan0", "zone"]).is_empty());
        // Unknown contexts complete nothing.
        assert!(candidates(&["bogus"]).is_empty());
    }

    #[test]
    fn bgp_and_filter_completion_is_discoverable() {
        // The protocols sub-tree now offers filters alongside bgp.
        assert!(kw(&["set", "protocols"]).contains(&"filter"));
        // The extended BGP field set.
        let bgp = kw(&["set", "protocols", "bgp"]);
        for f in [
            "hold-time",
            "confederation",
            "rpki",
            "aggregate",
            "roa",
            "neighbor",
        ] {
            assert!(bgp.contains(&f), "bgp fields missing {f:?}: {bgp:?}");
        }
        // A neighbour's full per-peer surface.
        let n = kw(&["set", "protocols", "bgp", "neighbor", "10.0.0.2"]);
        for f in [
            "remote-as",
            "passive",
            "role",
            "import",
            "export",
            "bfd-auth-type",
        ] {
            assert!(n.contains(&f), "neighbor fields missing {f:?}: {n:?}");
        }
        // Value-keyword lists.
        assert_eq!(
            kw(&["set", "protocols", "bgp", "neighbor", "10.0.0.2", "role"]),
            ["provider", "customer", "peer", "rs-server", "rs-client"]
        );
        assert_eq!(
            kw(&["set", "protocols", "bgp", "neighbor", "10.0.0.2", "passive"]),
            ["true", "false"]
        );
        assert_eq!(
            kw(&["set", "protocols", "bgp", "confederation"]),
            ["id", "member"]
        );
        assert_eq!(
            kw(&["set", "protocols", "bgp", "rpki"]),
            ["reject-invalid", "rtr", "rtr-refresh"]
        );
        assert_eq!(
            kw(&["set", "protocols", "bgp", "aggregate", "10.0.0.0/8"]),
            ["summary-only"]
        );
        assert_eq!(
            kw(&["set", "protocols", "bgp", "roa", "10.0.0.0/8"]),
            ["origin-as", "max-length"]
        );
        // The filter sub-tree: fields, default values, rule fields, rule action.
        assert_eq!(
            kw(&["set", "protocols", "filter", "f"]),
            ["default", "rule"]
        );
        assert_eq!(
            kw(&["set", "protocols", "filter", "f", "default"]),
            ["accept", "reject"]
        );
        assert!(kw(&["set", "protocols", "filter", "f", "rule", "10"]).contains(&"set-community"));
        assert_eq!(
            kw(&["set", "protocols", "filter", "f", "rule", "10", "action"]),
            ["accept", "reject"]
        );
    }

    #[test]
    fn dynamic_candidates_offer_live_names() {
        let names = DynNames {
            interfaces: vec!["eth0".into(), "eth1".into()],
            rules: vec!["web".into()],
            zones: vec!["lan".into(), "wan".into()],
            nat_source: vec!["wan-masq".into()],
            nat_destination: vec!["web-fwd".into()],
            address_groups: vec!["mgmt".into()],
            port_groups: vec!["webports".into()],
        };
        let kws = |toks: &[&str]| -> Vec<String> {
            dyn_candidates(toks, &names)
                .into_iter()
                .map(|(k, _)| k)
                .collect()
        };
        // Name positions splice in the live interface/rule/zone/nat names.
        assert_eq!(kws(&["set", "interface"]), ["eth0", "eth1"]);
        assert_eq!(kws(&["delete", "firewall", "rule"]), ["web"]);
        assert_eq!(kws(&["set", "nat", "source"]), ["wan-masq"]);
        assert_eq!(kws(&["set", "nat", "destination"]), ["web-fwd"]);
        assert_eq!(kws(&["set", "firewall", "zone"]), ["lan", "wan"]);
        // Zone-value positions splice in the known zone names.
        assert_eq!(kws(&["set", "interface", "eth0", "zone"]), ["lan", "wan"]);
        assert_eq!(
            kws(&["set", "firewall", "rule", "web", "from"]),
            ["lan", "wan"]
        );
        assert_eq!(
            kws(&["set", "nat", "source", "wan-masq", "zone"]),
            ["lan", "wan"]
        );
        assert_eq!(
            kws(&["set", "nat", "destination", "web-fwd", "zone"]),
            ["lan", "wan"]
        );
        // Group-name positions splice in the declared alias names (both when
        // editing a group and when a rule references one).
        assert_eq!(
            kws(&["set", "firewall", "group", "address-group"]),
            ["mgmt"]
        );
        assert_eq!(
            kws(&["set", "firewall", "group", "port-group"]),
            ["webports"]
        );
        assert_eq!(
            kws(&["set", "firewall", "rule", "web", "source-group"]),
            ["mgmt"]
        );
        assert_eq!(
            kws(&["set", "firewall", "rule", "web", "port-group"]),
            ["webports"]
        );
        // Other positions fall back to the static grammar.
        assert_eq!(
            kws(&["set"]),
            [
                "system",
                "interface",
                "firewall",
                "nat",
                "protocols",
                "services",
                "multiwan",
                "vpn"
            ]
        );
        assert_eq!(
            kws(&["set", "interface", "eth0"]),
            [
                "zone",
                "address",
                "address6",
                "pd-from",
                "pd-subnet",
                "parent",
                "vlan",
                "private-key",
                "listen-port",
                "peer",
                "dhcp-server",
                "router-advert",
                "type",
                "local",
                "remote",
                "key",
                "ttl",
                "master",
                "bond-mode",
                "mtu",
                "mac",
                "qos",
                "pppoe"
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
        assert!(!exec_line(
            &mut s,
            &act,
            &mut ctx,
            "set system hostname fw1"
        ));
        assert!(!exec_line(&mut s, &act, &mut ctx, "show"));
        // commit validates (apply off ⇒ no live changes) but does NOT persist.
        assert!(!exec_line(&mut s, &act, &mut ctx, "commit"));
        assert!(
            !path.exists(),
            "commit must not persist (VyOS: that's `save`)"
        );
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
    fn cisco_context_enters_new_protocol_subtrees_and_sets_fields() {
        let dir = std::env::temp_dir().join(format!("sentinel-ctx-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.toml");
        let mut s = Session::load(&path).unwrap();
        let act = Apply::off();
        let mut ctx = Vec::new();

        exec_line(&mut s, &act, &mut ctx, "set system hostname r1");
        // Cisco shorthand: a bare path descends into the OSPF context, then bare
        // fields set relative to it.
        exec_line(&mut s, &act, &mut ctx, "protocols ospf");
        assert_eq!(ctx, vec!["protocols", "ospf"]);
        exec_line(&mut s, &act, &mut ctx, "area 0.0.0.0");
        exec_line(&mut s, &act, &mut ctx, "hello-interval 5");
        exec_line(&mut s, &act, &mut ctx, "bfd true");
        exec_line(&mut s, &act, &mut ctx, "top");
        assert!(ctx.is_empty());
        // A named VRF context.
        exec_line(&mut s, &act, &mut ctx, "protocols vrf blue");
        assert_eq!(ctx, vec!["protocols", "vrf", "blue"]);
        exec_line(&mut s, &act, &mut ctx, "table 100");
        exec_line(&mut s, &act, &mut ctx, "top");
        // A multicast interface context (keyed node).
        exec_line(&mut s, &act, &mut ctx, "protocols multicast");
        exec_line(&mut s, &act, &mut ctx, "enabled true");
        exec_line(&mut s, &act, &mut ctx, "interface lan0");
        assert_eq!(ctx, vec!["protocols", "multicast", "interface", "lan0"]);
        exec_line(&mut s, &act, &mut ctx, "role querier");
        exec_line(&mut s, &act, &mut ctx, "top");

        let shown = s.show();
        assert!(shown.contains("hello-interval 5"), "{shown}");
        assert!(shown.contains("bfd true"), "{shown}");
        assert!(shown.contains("vrf blue {"), "{shown}");
        assert!(shown.contains("table 100"), "{shown}");
        assert!(shown.contains("multicast {"), "{shown}");
        assert!(shown.contains("role querier"), "{shown}");
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

    fn sv(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn prompt_context_renders_cisco_style() {
        assert_eq!(prompt_context(&[]), "(config)");
        assert_eq!(
            prompt_context(&sv(&["interface", "eth0"])),
            "(config-if-eth0)"
        );
        assert_eq!(
            prompt_context(&sv(&["protocols", "bgp"])),
            "(config-router-bgp)"
        );
        assert_eq!(
            prompt_context(&sv(&["protocols", "bgp", "neighbor", "10.0.0.1"])),
            "(config-bgp-neighbor-10.0.0.1)"
        );
        // Generic: the last (up to) two tokens joined by '-'.
        assert_eq!(
            prompt_context(&sv(&["firewall", "rule", "web"])),
            "(config-rule-web)"
        );
        assert_eq!(prompt_context(&sv(&["system"])), "(config-system)");
    }

    #[test]
    fn is_interior_node_accepts_nodes_and_instances_rejects_garbage() {
        assert!(is_interior_node(&sv(&["firewall"])));
        assert!(is_interior_node(&sv(&["firewall", "rule", "web"]))); // instance ok
        assert!(is_interior_node(&sv(&["interface", "eth0"])));
        assert!(is_interior_node(&sv(&["protocols", "bgp"])));
        assert!(!is_interior_node(&sv(&["bogus"])));
        assert!(!is_interior_node(&[])); // empty is not a node
        // A value-leaf path (past a value) is not descendable.
        assert!(!is_interior_node(&sv(&[
            "firewall", "rule", "web", "action", "drop"
        ])));
    }

    /// Build a throwaway session backed by a temp file.
    fn scratch_session(tag: &str) -> (Session, std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("sentinel-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.toml");
        let s = Session::load(&path).unwrap();
        (s, path, dir)
    }

    #[test]
    fn exit_pops_one_level_and_end_jumps_to_top() {
        let (mut s, _p, dir) = scratch_session("exit");
        let act = Apply::off();
        let mut ctx = Vec::new();

        // Descend two token-levels, then a keyword+instance level.
        exec_line(&mut s, &act, &mut ctx, "edit protocols bgp");
        assert_eq!(ctx, vec!["protocols", "bgp"]);
        // `exit` pops one level: bgp → protocols.
        exec_line(&mut s, &act, &mut ctx, "exit");
        assert_eq!(ctx, vec!["protocols"]);
        // `exit` again: protocols → top.
        exec_line(&mut s, &act, &mut ctx, "exit");
        assert!(ctx.is_empty());

        // A keyword+instance level (`interface eth0`) is popped as ONE level.
        exec_line(&mut s, &act, &mut ctx, "edit interface eth0");
        assert_eq!(ctx, vec!["interface", "eth0"]);
        exec_line(&mut s, &act, &mut ctx, "exit");
        assert!(ctx.is_empty(), "interface+name pops as one level");

        // `end` clears from any depth without leaving config mode.
        exec_line(&mut s, &act, &mut ctx, "edit firewall rule web");
        assert_eq!(ctx, vec!["firewall", "rule", "web"]);
        assert!(!exec_line(&mut s, &act, &mut ctx, "end"));
        assert!(ctx.is_empty());

        // At the top, `exit` leaves the session (returns true).
        assert!(exec_line(&mut s, &act, &mut ctx, "exit"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn context_shorthand_descends_and_implicit_set_mutates_draft() {
        let (mut s, _p, dir) = scratch_session("shorthand");
        let act = Apply::off();
        let mut ctx = Vec::new();

        // A bare path that names a subtree descends (context-entry shorthand).
        assert!(!exec_line(&mut s, &act, &mut ctx, "interface eth0"));
        assert_eq!(ctx, vec!["interface", "eth0"]);
        // Inside it, a complete leaf path is an implicit set.
        assert!(!exec_line(&mut s, &act, &mut ctx, "address 10.0.0.1/24"));
        assert!(!exec_line(&mut s, &act, &mut ctx, "zone lan"));

        // Descend a keyword+instance level, then implicit-set two leaves.
        exec_line(&mut s, &act, &mut ctx, "end");
        assert!(!exec_line(&mut s, &act, &mut ctx, "firewall rule web"));
        assert_eq!(ctx, vec!["firewall", "rule", "web"]);
        assert!(!exec_line(&mut s, &act, &mut ctx, "from lan"));
        assert!(!exec_line(&mut s, &act, &mut ctx, "action accept"));

        let shown = s.show();
        assert!(shown.contains("10.0.0.1/24"), "{shown}");
        assert!(shown.contains("web"), "{shown}");
        assert!(shown.contains("accept"), "{shown}");

        // Garbage that is neither a node nor a valid set errors (draft untouched).
        let before = s.show();
        assert!(!exec_line(&mut s, &act, &mut ctx, "totally bogus"));
        assert_eq!(s.show(), before, "a failed shorthand must not mutate");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_deletes_relative_to_context() {
        let (mut s, _p, dir) = scratch_session("no");
        let act = Apply::off();
        let mut ctx = Vec::new();

        exec_line(&mut s, &act, &mut ctx, "edit firewall rule web");
        exec_line(&mut s, &act, &mut ctx, "action accept");
        assert!(s.show().contains("accept"), "{}", s.show());
        // Cisco `no` deletes relative to the context.
        assert!(!exec_line(&mut s, &act, &mut ctx, "no action"));
        assert!(!s.show().contains("accept"), "{}", s.show());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn edit_rejects_garbage_with_a_helpful_error() {
        let (mut s, _p, dir) = scratch_session("editerr");
        let act = Apply::off();
        let mut ctx = Vec::new();
        // Deep validation still accepts a valid interior node.
        assert!(!exec_line(&mut s, &act, &mut ctx, "edit protocols bgp"));
        assert_eq!(ctx, vec!["protocols", "bgp"]);
        // The error helper points at the first bad token and lists valid children.
        let err = edit_error(&sv(&["firewall", "bogus"]));
        let msg = err.to_string();
        assert!(msg.contains("\"bogus\""), "{msg}");
        assert!(msg.contains("rule"), "{msg}"); // a real firewall child
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn first_token_completion_offers_context_children_and_extras() {
        let names = DynNames::default();
        // At the top: commands + Cisco extras + the top-level subtree keywords.
        let top: Vec<String> = first_token_candidates(&[], &names)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert!(top.contains(&"set".to_string()));
        assert!(top.contains(&"end".to_string()));
        assert!(top.contains(&"no".to_string()));
        assert!(top.contains(&"do".to_string()));
        assert!(top.contains(&"interface".to_string())); // a top subtree
        assert!(top.contains(&"protocols".to_string()));

        // Inside a context, the child keywords of that context are offered so a
        // bare Tab/`?` lists what you can descend into / implicitly set.
        let kids: Vec<String> = first_token_candidates(&sv(&["firewall", "rule", "web"]), &names)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert!(kids.contains(&"from".to_string()), "{kids:?}");
        assert!(kids.contains(&"action".to_string()), "{kids:?}");
        assert!(kids.contains(&"set".to_string()), "{kids:?}"); // commands still there
    }

    #[test]
    fn cisco_style_session_end_to_end() {
        let (mut s, _p, dir) = scratch_session("e2e");
        let act = Apply::off();
        let mut ctx = Vec::new();
        // A realistic Cisco-style session: descend, implicit-set, exit, descend a
        // keyword+instance level, end, descend routing, implicit-set a deep leaf.
        for line in [
            "interface eth0",
            "zone lan",
            "address 10.0.0.1/24",
            "exit",
            "firewall rule web",
            "from lan",
            "action accept",
            "end",
            "protocols bgp",
            "local-as 65001",
            "neighbor 10.0.0.2 remote-as 65002",
            "end",
        ] {
            assert!(!exec_line(&mut s, &act, &mut ctx, line), "line: {line}");
        }
        assert!(ctx.is_empty());
        let shown = s.show();
        for needle in ["eth0", "10.0.0.1/24", "web", "accept", "65001", "65002"] {
            assert!(shown.contains(needle), "missing {needle:?} in:\n{shown}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn absolute_path_mode_switches_from_inside_a_context() {
        let (mut s, _p, dir) = scratch_session("modeswitch");
        let act = Apply::off();
        let mut ctx = Vec::new();
        // IOS feel: from (config-if-eth0), an absolute `firewall rule web` line
        // switches contexts instead of erroring; an absolute set applies; and
        // `no` deletes by absolute path from an unrelated context.
        for line in [
            "interface eth0",
            "zone lan",
            "firewall rule web", // absolute — switches out of the interface ctx
            "from lan",
            "system hostname sw1", // absolute set from (config-firewall-rule-web)
            "no interface eth0 zone", // absolute delete from the same ctx
        ] {
            assert!(!exec_line(&mut s, &act, &mut ctx, line), "line: {line}");
        }
        assert_eq!(
            ctx,
            vec!["firewall".to_string(), "rule".into(), "web".into()]
        );
        let shown = s.show();
        assert!(shown.contains("from lan"), "{shown}");
        assert!(shown.contains("hostname sw1"), "{shown}");
        assert!(!shown.contains("zone lan"), "zone not deleted:\n{shown}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn flat_grammar_still_works_from_the_top() {
        // Regression: the flat grammar (no context) must behave exactly as before,
        // since piped scripts / nixosTests depend on it.
        let (mut s, _p, dir) = scratch_session("flat");
        let act = Apply::off();
        let mut ctx = Vec::new();
        assert!(!exec_line(
            &mut s,
            &act,
            &mut ctx,
            "set protocols bgp neighbor 1.2.3.4 remote-as 65001"
        ));
        assert!(ctx.is_empty(), "a flat `set` must not change the context");
        let shown = s.show();
        assert!(shown.contains("1.2.3.4"), "{shown}");
        assert!(shown.contains("65001"), "{shown}");
        let _ = std::fs::remove_dir_all(&dir);
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
        assert!(
            !path.exists(),
            "restore of a None snapshot removes the file"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
