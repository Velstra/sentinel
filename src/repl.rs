//! The interactive `configure` shell: command execution shared by the
//! interactive (rustyline, with tab-completion) and piped (plain stdin) paths.

use std::borrow::Cow;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use rustyline::{
    Helper, completion::Completer, completion::Pair, highlight::Highlighter, hint::Hinter,
    validate::Validator,
};

use crate::{compile, session::Session, system, ui};

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
                    announce_context(ctx);
                    Ok(())
                } else {
                    Err(edit_error(&full))
                }
            }
        }
        // `up` moves one level towards the top; a keyword+instance pair
        // (`interface eth0`) counts as ONE level.
        "up" => {
            pop_level(ctx);
            announce_context(ctx);
            Ok(())
        }
        "top" => {
            ctx.clear();
            announce_context(ctx);
            Ok(())
        }
        // VyOS `run`: run an operational command without leaving config mode.
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
        "compare" => do_compare(session, rest),
        "commit" => return commit(session, act),
        "commit-confirm" => return commit_confirm_line(session, act, rest),
        "confirm" => crate::confirm::confirm(act),
        "rollback" => return rollback_line(session, act, rest),
        "save" => {
            let to = rest.first().map(Path::new);
            session.save(to).map(|p| {
                eprintln!(
                    "{} saved {} (persists across reboot)",
                    ui::green("✔"),
                    p.display()
                )
            })
        }
        "discard" => session.discard().map(|()| eprintln!("discarded edits")),
        "exit" | "quit" => {
            // VyOS: inside an edit context, `exit` returns to the top of the
            // tree; only at the top does it leave configuration mode.
            if !ctx.is_empty() {
                ctx.clear();
                announce_context(ctx);
                return false;
            }
            if session.dirty() {
                eprintln!(
                    "{}",
                    ui::yellow("warning: uncommitted edits (use `commit`/`save`, or `discard`)")
                );
            }
            return true;
        }
        "help" => {
            match rest.first() {
                None => eprint!("{}", help_overview()),
                Some(name) => match help_command(name) {
                    Some(text) => eprint!("{text}"),
                    None => eprintln!("no help for {name:?} — `help` lists all commands"),
                },
            }
            Ok(())
        }
        // Anything else is not a command. The grammar is deliberately explicit
        // (pure VyOS): a bare config path is NOT a shorthand for set/edit, so
        // every line means exactly one thing. The error still points migrating
        // fingers in the right direction (renamed spellings, node hints, typos).
        _ => Err(unknown_command(cmd, rest, ctx)),
    };
    if let Err(e) = result {
        eprintln!("{} {e}", ui::red("error:"));
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
/// and by unknown_command's `edit` hint. An instance-name position
/// (`firewall rule web`, `interface eth0`) counts as interior even before the
/// instance exists; creation happens on the first `set` inside.
fn is_interior_node(path: &[String]) -> bool {
    !path.is_empty() && !child_keywords(path).is_empty()
}

/// Pop one *level* off the edit context: drop the last token, then keep dropping
/// trailing tokens until the context is empty or again names a real interior
/// node. This steps `up` one level even when a level spans a keyword+instance
/// pair (`interface eth0`, `firewall rule web`, `… neighbor X`).
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

/// Render the edit context as the VyOS/JunOS banner line: `[edit]` at the top,
/// `[edit firewall rule web]` inside a subtree. The interactive loop prints it
/// (dimmed) above the prompt while a context is active; command handlers print
/// it whenever the context changes.
pub fn edit_banner(ctx: &[String]) -> String {
    match ctx.is_empty() {
        true => "[edit]".to_string(),
        false => format!("[edit {}]", ctx.join(" ")),
    }
}

/// Print the context banner after a context change (`edit`/`up`/`top`/`exit`).
fn announce_context(ctx: &[String]) {
    eprintln!("{}", ui::cyan(&edit_banner(ctx)));
}

/// Edit distance for did-you-mean suggestions on mistyped commands.
fn levenshtein(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != *cb);
            cur.push((prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

/// The command closest to `word` (edit distance ≤ 2), if any.
fn closest_command(word: &str) -> Option<&'static str> {
    COMMANDS
        .iter()
        .map(|(k, _)| (levenshtein(word, k), *k))
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|(d, _)| *d)
        .map(|(_, k)| k)
}

/// The error for a first token that is not a command. Strict on grammar,
/// generous on guidance: retired spellings name their replacement, a config
/// node typed bare gets the explicit `set`/`edit` spellings, and a typo gets
/// the nearest command.
fn unknown_command(cmd: &str, rest: &[&str], ctx: &[String]) -> anyhow::Error {
    let renamed = match cmd {
        "no" => Some("delete"),
        "do" => Some("run"),
        "end" => Some("top"),
        _ => None,
    };
    if let Some(new) = renamed {
        return anyhow!("`{cmd}` is not a command here — use `{new}`");
    }
    // A config keyword typed bare (e.g. `interface eth0` or, inside a rule
    // context, `action accept`): show the explicit spellings.
    let mut toks: Vec<&str> = vec!["set"];
    toks.extend(ctx.iter().map(String::as_str));
    if candidates(&toks).iter().any(|(k, _)| *k == cmd) {
        let path = std::iter::once(cmd)
            .chain(rest.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        // Offer `edit` only when the path really names a subtree (context-
        // relative); a leaf like `action accept` gets just the `set` spelling.
        let full: Vec<String> = ctx
            .iter()
            .cloned()
            .chain(std::iter::once(cmd.to_string()))
            .chain(rest.iter().map(|s| (*s).to_string()))
            .collect();
        return match is_interior_node(&full) {
            true => anyhow!(
                "{cmd:?} is a config node, not a command — `set {path} …` sets a value, \
                 `edit {path}` enters the subtree"
            ),
            false => anyhow!("{cmd:?} is a config node, not a command — use `set {path}`"),
        };
    }
    match closest_command(cmd) {
        Some(s) => {
            anyhow!("unknown command {cmd:?} — did you mean `{s}`? (`help` lists all commands)")
        }
        None => anyhow!("unknown command {cmd:?} — `help` lists all commands"),
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
    for w in appliance.warnings() {
        eprintln!("{} {w}", ui::yellow("warning:"));
    }

    if !act.enabled {
        eprintln!("{} commit ok (validated): {summary}", ui::green("✔"));
        eprintln!(
            "{}",
            ui::dim("  note: live apply disabled (off-box or --no-apply)")
        );
        return false;
    }

    // VyOS semantics: commit applies to the RUNNING system only. It does not
    // persist — `save` writes the boot config so a change survives reboot.
    let old_host = system::current_hostname();
    eprintln!("commit: {summary}; applying to the running system…");
    if let Err(e) = apply_live(&appliance, act) {
        eprintln!("{} applying config: {e}", ui::red("error:"));
        return false;
    }
    if appliance.system.hostname != old_host {
        eprintln!("  hostname: {old_host} -> {}", appliance.system.hostname);
    }
    eprintln!(
        "{} commit ok: applied live {}",
        ui::green("✔"),
        ui::dim("(not persisted — `save` to keep across reboot)")
    );
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

/// One command's help. `usage` + `summary` drive the `help` overview; the
/// `detail` paragraph and `examples` complete `help <command>`.
struct CmdHelp {
    name: &'static str,
    usage: &'static str,
    summary: &'static str,
    detail: &'static str,
    examples: &'static [&'static str],
}

/// The `help` overview groups, in display order. Every name must exist in
/// `CMD_HELP` (enforced by a test).
const HELP_GROUPS: &[(&str, &[&str])] = &[
    (
        "Edit the candidate",
        &["set", "delete", "edit", "up", "top"],
    ),
    ("Inspect", &["show", "compare", "run"]),
    (
        "Apply and persist",
        &[
            "commit",
            "commit-confirm",
            "confirm",
            "save",
            "rollback",
            "discard",
        ],
    ),
    ("Session", &["exit", "help"]),
];

const CMD_HELP: &[CmdHelp] = &[
    CmdHelp {
        name: "set",
        usage: "set <path> <value>",
        summary: "set a configuration value",
        detail: "The configuration is a tree. <path> walks it from the top (or from the \
                 current edit context) down to a field; the last word(s) are the value. \
                 Tab or `?` lists what is valid at every step, so the whole tree is \
                 discoverable without documentation.",
        examples: &[
            "set system hostname fw1",
            "set interface eth0 address 10.0.0.1/24",
            "set firewall rule web action accept",
            "set protocols bgp neighbor 10.0.0.2 remote-as 65002",
        ],
    },
    CmdHelp {
        name: "delete",
        usage: "delete <path>",
        summary: "delete a node or reset a value",
        detail: "Removes the named node (an instance like a rule, or a single field). \
                 Deleting a field restores its default.",
        examples: &["delete firewall rule web", "delete interface eth0 address"],
    },
    CmdHelp {
        name: "edit",
        usage: "edit <path>",
        summary: "enter a subtree; paths become relative to it",
        detail: "Descends into any interior node of the tree — `set`, `delete` and \
                 `show` are then relative to it, and the prompt shows the position as \
                 `[edit <path>]`. Leave with `up` (one level), `top` or `exit` (back to \
                 the top).",
        examples: &[
            "edit firewall rule web",
            "set action accept        (= set firewall rule web action accept)",
            "edit protocols bgp neighbor 10.0.0.1",
        ],
    },
    CmdHelp {
        name: "up",
        usage: "up",
        summary: "go one level up from the edit context",
        detail: "A keyword+instance pair (`interface eth0`) counts as one level.",
        examples: &[],
    },
    CmdHelp {
        name: "top",
        usage: "top",
        summary: "return to the top of the tree",
        detail: "",
        examples: &[],
    },
    CmdHelp {
        name: "show",
        usage: "show [path]",
        summary: "show the candidate configuration",
        detail: "Without arguments the whole candidate config; with a section name \
                 (system, interfaces, firewall, nat, protocols, services, multiwan, \
                 vpn) just that part. Inside an edit context, `show` is relative to it.",
        examples: &["show", "show firewall"],
    },
    CmdHelp {
        name: "compare",
        usage: "compare [N [M]]",
        summary: "diff the candidate against saved or archived configs",
        detail: "No arguments: candidate vs the saved config. One argument: vs archived \
                 revision N. Two: revision N vs revision M. List the archive with \
                 `run show system commit`.",
        examples: &["compare", "compare 1", "compare 2 1"],
    },
    CmdHelp {
        name: "run",
        usage: "run <operational command>",
        summary: "run an operational command without leaving configure",
        detail: "",
        examples: &[
            "run show ip route",
            "run show ip bgp summary",
            "run show firewall log",
        ],
    },
    CmdHelp {
        name: "commit",
        usage: "commit",
        summary: "apply the candidate to the running system",
        detail: "Validates the candidate, then applies it live — no rebuild, no reboot. \
                 A commit does NOT persist across reboot; follow up with `save` once \
                 the change is proven good.",
        examples: &[],
    },
    CmdHelp {
        name: "commit-confirm",
        usage: "commit-confirm [minutes]",
        summary: "commit with an automatic revert unless confirmed",
        detail: "Applies the candidate live, then reverts to the saved config after \
                 <minutes> (default 10) unless you type `confirm` — the safety net for \
                 editing a firewall over the very link it filters.",
        examples: &["commit-confirm 5", "confirm"],
    },
    CmdHelp {
        name: "confirm",
        usage: "confirm",
        summary: "keep a commit-confirm change (cancel the revert)",
        detail: "",
        examples: &[],
    },
    CmdHelp {
        name: "save",
        usage: "save [path]",
        summary: "persist the configuration across reboot",
        detail: "Writes the committed config to the boot location (or to <path> for a \
                 backup copy).",
        examples: &[],
    },
    CmdHelp {
        name: "rollback",
        usage: "rollback <N>",
        summary: "revert to archived revision N (0 = newest)",
        detail: "Every save archives the previous config. List the revisions with \
                 `run show system commit`, inspect a diff first with `compare <N>`.",
        examples: &["rollback 0"],
    },
    CmdHelp {
        name: "discard",
        usage: "discard",
        summary: "drop all uncommitted edits",
        detail: "",
        examples: &[],
    },
    CmdHelp {
        name: "exit",
        usage: "exit",
        summary: "leave the edit context; at the top, leave configure",
        detail: "Inside an edit context, `exit` returns to the top of the tree. At the \
                 top it ends the session (warning if edits are uncommitted). `quit` is \
                 an alias.",
        examples: &[],
    },
    CmdHelp {
        name: "help",
        usage: "help [command]",
        summary: "this overview, or details on one command",
        detail: "",
        examples: &["help commit-confirm"],
    },
];

/// The grouped, aligned `help` overview.
pub fn help_overview() -> String {
    use std::fmt::Write;
    let w = CMD_HELP.iter().map(|c| c.usage.len()).max().unwrap_or(0);
    let mut out = String::new();
    let _ = writeln!(out, "{}", ui::bold("Sentinel configuration mode"));
    let _ = writeln!(
        out,
        "{}",
        ui::dim("  The configuration is a tree; every command names a path in it.")
    );
    for (title, names) in HELP_GROUPS {
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", ui::bold(title));
        for name in *names {
            let c = CMD_HELP
                .iter()
                .find(|c| c.name == *name)
                .expect("HELP_GROUPS names a known command");
            let padded = format!("{:<w$}", c.usage);
            let _ = writeln!(out, "  {}  {}", ui::cyan(&padded), c.summary);
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "{}",
        ui::dim(
            "  `help <command>` shows details and examples; Tab or `?` completes the next word."
        )
    );
    out
}

/// Detailed help for one command (`help <command>`), if it exists.
pub fn help_command(name: &str) -> Option<String> {
    use std::fmt::Write;
    let canonical = match name {
        "quit" => "exit",
        "del" => "delete",
        other => other,
    };
    let c = CMD_HELP.iter().find(|c| c.name == canonical)?;
    let mut out = String::new();
    let _ = writeln!(out, "{} {}", ui::bold("Usage:"), ui::cyan(c.usage));
    let _ = writeln!(out, "  {}", c.summary);
    if !c.detail.is_empty() {
        let _ = writeln!(out);
        for line in wrap(c.detail, 76) {
            let _ = writeln!(out, "  {line}");
        }
    }
    if !c.examples.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", ui::bold("Examples:"));
        for e in c.examples {
            let _ = writeln!(out, "  {}", ui::cyan(e));
        }
    }
    Some(out)
}

/// Greedy word-wrap for the `help <command>` detail paragraphs.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        if !cur.is_empty() && cur.len() + 1 + word.len() > width {
            lines.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(word);
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

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
    ("pki", "local CAs + issued certificates (expiry)"),
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
        "box-wide services: DNS, NTP, LLDP, SNMP, mDNS, dyndns, DHCP-relay",
    ),
    (
        "multiwan",
        "WAN uplinks: failover / load-balance + health checks",
    ),
    ("vpn", "site-to-site VPN: IKEv2 IPsec tunnels (strongSwan)"),
    (
        "pki",
        "certificates: local CA, issued certs, ACME (Let's Encrypt)",
    ),
    (
        "update",
        "signed update channel: URL + pinned release signing key",
    ),
];
// `update <Tab>` reveals the signed-update-channel fields (roadmap C13).
const UPDATE_FIELDS: &[Cand] = &[
    ("url", "channel base URL (holds manifest.json + images)"),
    (
        "public-key",
        "pinned Ed25519 signing key (PEM or file:<path>)",
    ),
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
const VPN_NODES: &[Cand] = &[
    ("ipsec", "an IKEv2 site-to-site IPsec tunnel (by name)"),
    (
        "wireguard",
        "a WireGuard tunnel's keys + peers (by interface name)",
    ),
    (
        "openconnect",
        "the OpenConnect (AnyConnect) road-warrior VPN server",
    ),
];
// `vpn openconnect <Tab>` reveals the road-warrior server fields (roadmap C17).
const OPENCONNECT_FIELDS: &[Cand] = &[
    (
        "certificate",
        "TLS server identity — a `pki certificate` name",
    ),
    ("port", "TCP/UDP listen port (default 443)"),
    ("pool", "client address pool (IPv4 CIDR, e.g. 10.99.0.0/24)"),
    ("dns", "DNS resolver(s) pushed to clients (repeatable)"),
    (
        "routes",
        "split-tunnel subnets pushed to clients (repeatable)",
    ),
    (
        "default-route",
        "full tunnel: push a default route (true|false)",
    ),
    ("zone", "firewall zone for the server's tun interface"),
    (
        "disabled",
        "administratively disable the server (true|false)",
    ),
    ("user", "a client login (by name) + password"),
];
const OPENCONNECT_USER_FIELDS: &[Cand] = &[("password", "the client account password (secret)")];
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
// `pki <Tab>` reveals the PKI object kinds (roadmap C19).
const PKI_NODES: &[Cand] = &[
    ("ca", "a local certificate authority (by name)"),
    ("certificate", "an issued leaf certificate (by name)"),
    ("acme", "the ACME account (Let's Encrypt) for public certs"),
];
// `pki ca <name> <Tab>` reveals the CA fields.
const PKI_CA_FIELDS: &[Cand] = &[
    ("common-name", "the CA subject common name (CN)"),
    ("organization", "the CA subject organization (O)"),
    ("key-type", "ec (P-256, default) or rsa (3072-bit)"),
    (
        "validity-days",
        "certificate lifetime in days (default 3650)",
    ),
];
// `pki certificate <name> <Tab>` reveals the leaf-cert fields.
const PKI_CERT_FIELDS: &[Cand] = &[
    ("ca", "the signing CA (a local CA name, or acme)"),
    ("common-name", "the subject common name (CN)"),
    ("subject-alt-name", "a SAN: DNS:<host> or IP:<addr>"),
    ("key-type", "ec (default) or rsa"),
    ("usage", "server (default) or client"),
    (
        "validity-days",
        "certificate lifetime in days (default 825)",
    ),
];
// `pki acme <Tab>` reveals the ACME-account fields.
const PKI_ACME_FIELDS: &[Cand] = &[
    (
        "email",
        "ACME contact email (registration + expiry notices)",
    ),
    (
        "directory-url",
        "ACME directory (default Let's Encrypt prod)",
    ),
    ("challenge", "http-01 (default) or dns-01"),
    (
        "agree-tos",
        "agree to the ACME terms of service (true/false)",
    ),
];
// `pki ca <name> key-type <Tab>` / `pki certificate <name> key-type <Tab>`.
const PKI_KEY_TYPES: &[Cand] = &[
    ("ec", "NIST P-256 elliptic-curve key (small, fast)"),
    ("rsa", "3072-bit RSA key"),
];
// `pki certificate <name> usage <Tab>`.
const PKI_USAGES: &[Cand] = &[
    ("server", "TLS/IKE server certificate (serverAuth)"),
    ("client", "client certificate (clientAuth)"),
];
// `pki acme challenge <Tab>`.
const PKI_CHALLENGES: &[Cand] = &[
    ("http-01", "HTTP-01 challenge (port 80 reachable)"),
    ("dns-01", "DNS-01 challenge (a TXT record, wildcards)"),
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
    ("lldp", "LLDP link-layer discovery (lldpd)"),
    ("snmp", "read-only SNMP agent (net-snmp)"),
    ("mdns", "mDNS reflector between segments (avahi)"),
    ("dyndns", "dynamic-DNS client (ddclient)"),
    (
        "dhcp-relay",
        "relay DHCP to an upstream server (isc dhcrelay)",
    ),
    (
        "reverse-proxy",
        "L7 reverse proxy / load balancer (haproxy, by name)",
    ),
];
// `services reverse-proxy <name> <Tab>` reveals the frontend fields (roadmap C22).
const REVERSE_PROXY_FIELDS: &[Cand] = &[
    ("port", "listen port (default 443)"),
    (
        "certificate",
        "TLS termination cert — a `pki certificate` name (omit ⇒ plain HTTP)",
    ),
    (
        "backends",
        "upstream host:port targets (round-robin; repeatable)",
    ),
    (
        "disabled",
        "administratively disable this frontend (true|false)",
    ),
];
// `services lldp <Tab>` reveals the LLDP fields.
const LLDP_FIELDS: &[Cand] = &[
    ("enable", "turn LLDP on (off by default)"),
    (
        "interface",
        "interfaces to run LLDP on (comma-separated; omit for all)",
    ),
];
// `services snmp <Tab>` reveals the read-only agent fields.
const SNMP_FIELDS: &[Cand] = &[
    ("community", "the v2c read-only community string (secret)"),
    ("listen", "agent listen address (net-snmp agentaddress)"),
    ("location", "advertised syslocation"),
    ("contact", "advertised syscontact"),
    (
        "allow",
        "source subnets allowed to poll (comma-separated CIDRs)",
    ),
];
// `services mdns <Tab>` reveals the reflector fields.
const MDNS_FIELDS: &[Cand] = &[(
    "interface",
    "interfaces to reflect mDNS between (comma-separated, ≥2)",
)];
// `services dyndns <Tab>` reveals the dynamic-DNS client fields.
const DYNDNS_FIELDS: &[Cand] = &[
    ("provider", "ddclient protocol (dyndns2/cloudflare/…)"),
    ("server", "the provider's update endpoint host"),
    ("hostname", "the FQDN to keep up to date"),
    ("login", "account login/username"),
    ("password", "account password / API token (secret)"),
    (
        "interface",
        "interface whose address to publish (else use=web)",
    ),
];
// `services dhcp-relay <Tab>` reveals the relay fields.
const DHCP_RELAY_FIELDS: &[Cand] = &[
    (
        "interface",
        "interfaces to relay on (comma-separated: client + upstream links)",
    ),
    (
        "server",
        "upstream DHCP server addresses (comma-separated IPv4)",
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
    ("cache-size", "max cached answers (dnsmasq cache-size)"),
    ("local-domain", "site local domain (local=/… + domain=)"),
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
    ("local-as", "override this speaker's AS for this session"),
    ("update-source", "source address for the outgoing session"),
    (
        "ebgp-multihop",
        "session TTL for a distant eBGP peer (1-255)",
    ),
    ("description", "free-form label for this neighbour"),
    ("shutdown", "administratively shut the session down"),
    ("hold-time", "per-session hold-time proposed in the OPEN"),
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
    ("bgp", "redistribute BGP routes"),
];
// `services dyndns provider <Tab>` — the ddclient protocols we render for.
const DYNDNS_PROVIDERS: &[Cand] = &[
    ("dyndns2", "the generic DynDNS v2 protocol (default)"),
    ("cloudflare", "Cloudflare DNS"),
    ("duckdns", "Duck DNS"),
    ("noip", "No-IP"),
];
// `protocols filter <name> rule <n> protocol <Tab>` — the route sources a filter
// rule can match on.
const FILTER_PROTOCOLS: &[Cand] = &[
    ("connected", "connected (interface) routes"),
    ("static", "static routes"),
    ("kernel", "kernel routes"),
    ("rip", "RIP routes"),
    ("ospf", "OSPF routes"),
    ("bgp", "BGP routes"),
    ("isis", "IS-IS routes"),
    ("babel", "Babel routes"),
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
// `nat <Tab>` reveals the NAT directions (VyOS-style) plus NAT64.
const NAT_NODES: &[Cand] = &[
    ("source", "SNAT/masquerade a zone's outbound traffic"),
    (
        "destination",
        "inbound DNAT port-forward to an internal host",
    ),
    (
        "nat64",
        "stateful IPv6→IPv4 translation (tayga) + DNS64 (unbound)",
    ),
];
// `nat nat64 <Tab>` reveals the NAT64 fields.
const NAT64_FIELDS: &[Cand] = &[
    ("enabled", "turn NAT64 on (off by default)"),
    ("prefix", "translation prefix /96 (default 64:ff9b::/96)"),
    ("pool", "IPv4 source pool for translated flows (a CIDR)"),
    (
        "interface",
        "the IPv6-only side (DNS64 binds its v6 address)",
    ),
    ("dns64", "synthesize AAAA for v4-only names (true|false)"),
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
    ("description", "free-text label for this zone"),
    ("stateful", "stateful inspection for this zone (true|false)"),
    ("block-icmp", "drop inbound ICMP on this zone (true|false)"),
    (
        "default-action",
        "ingress action for this zone (accept|drop|reject)",
    ),
    ("log", "log this zone's traffic (true|false)"),
    ("block", "drop a source IP/CIDR on this zone"),
];
const NAT_SOURCE_FIELDS: &[Cand] = &[
    ("zone", "egress (WAN) zone to masquerade"),
    ("description", "free-text label for this rule"),
    (
        "disabled",
        "administratively disable this rule (true|false)",
    ),
];
const NAT_DEST_FIELDS: &[Cand] = &[
    ("zone", "ingress zone (public side)"),
    ("proto", "tcp / udp"),
    ("port", "public destination port"),
    ("to", "internal target ip or ip:port"),
    ("description", "free-text label for this rule"),
    (
        "disabled",
        "administratively disable this rule (true|false)",
    ),
];
const BOOLS: &[Cand] = &[("true", "enabled"), ("false", "disabled")];
const ACTIONS: &[Cand] = &[
    ("accept", "allow matching traffic"),
    ("drop", "silently discard"),
    ("reject", "discard with an ICMP error"),
];
const PROTOS: &[Cand] = &[("tcp", "TCP"), ("udp", "UDP")];
const IFACE_FIELDS: &[Cand] = &[
    (
        "description",
        "free-text label (rendered as a unit comment)",
    ),
    ("disabled", "administratively disable this NIC (true|false)"),
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
    ("parent", "parent interface (VLAN subinterface or macvlan)"),
    ("vlan", "802.1Q VLAN id 1–4094 (with `parent`)"),
    (
        "vlan-protocol",
        "VLAN tag protocol: 802.1q (default) | 802.1ad (QinQ S-tag)",
    ),
    (
        "macvlan-mode",
        "MACVLAN mode: bridge | private | vepa | passthru (type=macvlan)",
    ),
    ("dhcp-server", "serve DHCP from this NIC's static subnet"),
    ("router-advert", "emit IPv6 Router Advertisements (SLAAC)"),
    (
        "type",
        "bridge | bond | wireguard | pppoe | gre | ipip | gretap | macvlan",
    ),
    ("local", "tunnel local endpoint IP (type gre/ipip/gretap)"),
    ("remote", "tunnel remote endpoint IP (type gre/ipip/gretap)"),
    ("key", "GRE key (type gre/gretap) — demultiplexes tunnels"),
    ("ttl", "tunnel outer TTL 0–255 (0 = inherit inner)"),
    (
        "member",
        "enslave a NIC to this bridge/bond device (repeatable)",
    ),
    ("bond-mode", "bonding mode (on a type=bond device)"),
    (
        "vlan-aware",
        "802.1Q VLAN filtering on this bridge (true|false)",
    ),
    (
        "vlan-tagged",
        "tagged VLAN ids on a vlan-aware bridge port (csv)",
    ),
    (
        "vlan-untagged",
        "untagged/PVID VLAN id on a vlan-aware bridge port",
    ),
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
    ("bridge", "an L2 switch; enslave NICs with `member`"),
    ("bond", "link aggregation; enslave NICs with `member`"),
    (
        "wireguard",
        "a WireGuard tunnel; keys/peers under `vpn wireguard`",
    ),
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
    (
        "macvlan",
        "a MACVLAN pseudo-NIC on a `parent` (own MAC; `macvlan-mode`)",
    ),
];
const MACVLAN_MODES: &[Cand] = &[
    ("bridge", "sub-interfaces can talk to each other (default)"),
    ("private", "sub-interfaces are isolated from each other"),
    ("vepa", "traffic goes out to an 802.1Qbg switch and back"),
    ("passthru", "one sub-interface gets the parent's queue"),
];
const VLAN_PROTOCOLS: &[Cand] = &[
    ("802.1q", "a C-VLAN customer tag (the default)"),
    ("802.1ad", "an S-VLAN service tag (QinQ outer tag)"),
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
    ("lease-time", "default lease time (12h, 1h30m, or seconds)"),
    (
        "default-router",
        "override the advertised gateway (option 3)",
    ),
    ("domain", "domain name to advertise (option 15)"),
    ("static-mapping", "a fixed lease: <name> mac <mac> ip <ip>"),
];
const STATIC_MAPPING_FIELDS: &[Cand] = &[
    ("mac", "the client MAC (52:54:00:12:34:56)"),
    ("ip", "the fixed address (inside the server subnet)"),
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
const WG_TUNNEL_FIELDS: &[Cand] = &[
    ("private-key", "WireGuard private key (or `generate`)"),
    ("listen-port", "WireGuard UDP listen port"),
    ("peer", "WireGuard peer (by public key)"),
];
const PEER_FIELDS: &[Cand] = &[
    ("allowed-ips", "CIDRs routed to this peer (comma-separated)"),
    ("endpoint", "peer's public host:port"),
    ("keepalive", "persistent-keepalive seconds"),
    ("preshared-key", "optional pre-shared key"),
];
const RULE_FIELDS: &[Cand] = &[
    ("description", "free-text label for this rule"),
    (
        "disabled",
        "administratively disable this rule (true|false)",
    ),
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

// ---- Display-only value placeholders (vtysh style) --------------------------
// A completion candidate whose keyword starts with '<' is a *hint* at a value
// position (`<A.B.C.D>`, `<1-65535>`, …). It is shown in the Tab/`?` list but
// never inserted — see [`is_placeholder`]/[`matches_for`], which give it a
// no-op replacement so it can never be typed literally. Defined once here and
// reused across every value position so the vocabulary stays consistent, and so
// new grammar entries can drop in the same shared consts.
const PH_IPV4: Cand = ("<A.B.C.D>", "an IPv4 address");
const PH_IPV6: Cand = ("<X:X::X:X>", "an IPv6 address");
const PH_IPV4_CIDR: Cand = ("<A.B.C.D/M>", "an IPv4 prefix (address/length)");
const PH_IPV6_CIDR: Cand = ("<X:X::X:X/M>", "an IPv6 prefix (address/length)");
const PH_IPV4_TO: Cand = ("<A.B.C.D:port>", "an internal target — ip or ip:port");
const PH_PORT: Cand = ("<1-65535>", "a TCP/UDP port");
const PH_PORT_RANGE: Cand = ("<port|lo-hi>", "a port or range (e.g. 443 or 8000-8100)");
const PH_ASN: Cand = ("<1-4294967295>", "an AS number");
const PH_VLAN: Cand = ("<1-4094>", "a VLAN id");
const PH_VLAN_CSV: Cand = ("<id,…>", "comma-separated VLAN ids");
const PH_PUBKEY: Cand = ("<pubkey>", "the peer's WireGuard public key");
const PH_U8: Cand = ("<0-255>", "a number 0-255");
const PH_SECONDS: Cand = ("<seconds>", "a duration in seconds");
const PH_NAME: Cand = ("<name>", "a name");
const PH_TEXT: Cand = ("<text>", "free-form text");
const PH_MAC: Cand = ("<xx:xx:xx:xx:xx:xx>", "a MAC address");
const PH_KEY: Cand = ("<key>", "a key / secret");
const PH_HOST_PORT: Cand = ("<host:port>", "a host and port");
const PH_URL: Cand = ("<url>", "a URL");
const PH_MTU: Cand = ("<68-9216>", "link MTU in bytes");
const PH_NUMBER: Cand = ("<number>", "a number");
const PH_DURATION: Cand = ("<12h|30m|3600>", "a duration (12h, 1h30m, or seconds)");

/// Whether a completion keyword is a display-only value placeholder (see the
/// `PH_*` consts) rather than a real, insertable keyword.
fn is_placeholder(keyword: &str) -> bool {
    keyword.starts_with('<')
}

/// Filter `all` candidates for the word the user has typed (`prefix`) and decide
/// what each inserts. Real keywords are prefix-filtered as usual; display-only
/// placeholders (`<…>`) always pass — even once the user has started typing a
/// value like `10.` — and insert the current word unchanged, i.e. a no-op, so a
/// literal `<A.B.C.D>` can never end up in the line. Returns, per surviving
/// candidate, `(keyword, description, replacement)`.
fn matches_for<'a>(all: &'a [(String, String)], prefix: &str) -> Vec<(&'a str, &'a str, String)> {
    all.iter()
        .filter(|(kw, _)| is_placeholder(kw) || kw.starts_with(prefix))
        .map(|(kw, desc)| {
            let replacement = if is_placeholder(kw) {
                prefix.to_string() // no-op: leave the typed word untouched
            } else {
                format!("{kw} ")
            };
            (kw.as_str(), desc.as_str(), replacement)
        })
        .collect()
}

/// Static completion candidates for the token being typed, given the
/// already-complete `tokens` before it. The interface/rule/zone/nat **name**
/// positions, the zone-value positions and every free-form **value** position
/// (which get `<…>` placeholders) are filled dynamically — see [`dyn_candidates`].
fn candidates(tokens: &[&str]) -> &'static [Cand] {
    match tokens {
        [] => COMMANDS,
        // `help <Tab>` completes the command names.
        ["help"] => COMMANDS,
        ["set" | "delete"] => TOP,
        ["set" | "delete", "system"] => SYSTEM_FIELDS,
        // `set interface <name> <field>` — name is freeform, then fields.
        ["set" | "delete", "interface", _name] => IFACE_FIELDS,
        ["set", "interface", _name, "vlan-aware"] => BOOLS,
        // WireGuard keys + peers live under `vpn wireguard <ifname>` (the
        // interface itself only carries `type wireguard` + address/zone).
        ["set" | "delete", "vpn", "wireguard", _name] => WG_TUNNEL_FIELDS,
        ["set", "vpn", "wireguard", _name, "private-key"] => WG_KEY_GEN,
        ["set" | "delete", "vpn", "wireguard", _name, "peer", _pk] => PEER_FIELDS,
        // OpenConnect road-warrior server (singleton): its fields, then a user.
        ["set" | "delete", "vpn", "openconnect"] => OPENCONNECT_FIELDS,
        ["set" | "delete", "vpn", "openconnect", "user", _u] => OPENCONNECT_USER_FIELDS,
        ["set", "vpn", "openconnect", "default-route" | "disabled"] => BOOLS,
        // `address6 auto` completes the SLAAC keyword.
        ["set", "interface", _name, "address6"] => ADDRESS6_HINT,
        // Bridge/bond value completions.
        ["set", "interface", _name, "type"] => IFACE_TYPES,
        ["set", "interface", _name, "bond-mode"] => BOND_MODES,
        ["set", "interface", _name, "macvlan-mode"] => MACVLAN_MODES,
        ["set", "interface", _name, "vlan-protocol"] => VLAN_PROTOCOLS,
        // The PPPoE-client sub-tree of an interface.
        ["set" | "delete", "interface", _name, "pppoe"] => PPPOE_FIELDS,
        // The QoS / traffic-shaping sub-tree of an interface.
        ["set" | "delete", "interface", _name, "qos"] => QOS_FIELDS,
        ["set", "interface", _name, "qos", "discipline"] => QOS_DISCIPLINES,
        ["set", "interface", _name, "qos", "rtt"] => QOS_RTT,
        ["set", "interface", _name, "qos", "diffserv"] => QOS_DIFFSERV,
        ["set", "interface", _name, "qos", "nat" | "ack-filter"] => BOOLS,
        // The DHCP-server sub-tree of an interface, incl. per-reservation fields.
        ["set" | "delete", "interface", _name, "dhcp-server"] => DHCP_SERVER_FIELDS,
        [
            "set" | "delete",
            "interface",
            _name,
            "dhcp-server",
            "static-mapping",
            _lname,
        ] => STATIC_MAPPING_FIELDS,
        ["set", "interface", _name, "disabled"] => BOOLS,
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
        ["set" | "delete", "services", "lldp"] => LLDP_FIELDS,
        ["set", "services", "lldp", "enable"] => BOOLS,
        ["set" | "delete", "services", "snmp"] => SNMP_FIELDS,
        ["set" | "delete", "services", "mdns"] => MDNS_FIELDS,
        ["set" | "delete", "services", "dyndns"] => DYNDNS_FIELDS,
        ["set", "services", "dyndns", "provider"] => DYNDNS_PROVIDERS,
        ["set" | "delete", "services", "dhcp-relay"] => DHCP_RELAY_FIELDS,
        ["set" | "delete", "services", "reverse-proxy", _name] => REVERSE_PROXY_FIELDS,
        ["set", "services", "reverse-proxy", _name, "disabled"] => BOOLS,

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
        ["set", "firewall", "rule", _name, "log" | "disabled"] => BOOLS,

        // The nat sub-tree (its own top-level node).
        ["set" | "delete", "nat"] => NAT_NODES,
        ["set" | "delete", "nat", "source", _name] => NAT_SOURCE_FIELDS,
        ["set", "nat", "source", _name, "disabled"] => BOOLS,
        ["set" | "delete", "nat", "destination", _name] => NAT_DEST_FIELDS,
        ["set", "nat", "destination", _name, "proto"] => PROTOS,
        ["set", "nat", "destination", _name, "disabled"] => BOOLS,
        ["set" | "delete", "nat", "nat64"] => NAT64_FIELDS,
        ["set", "nat", "nat64", "enabled" | "dns64"] => BOOLS,

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
            | "bfd"
            | "shutdown",
        ] => BOOLS,
        ["set" | "delete", "protocols", "filter", _name] => FILTER_FIELDS,
        ["set", "protocols", "filter", _name, "default"] => ACCEPT_REJECT,
        ["set" | "delete", "protocols", "filter", _name, "rule", _n] => FILTER_RULE_FIELDS,
        ["set", "protocols", "filter", _name, "rule", _n, "action"] => ACCEPT_REJECT,
        ["set", "protocols", "filter", _name, "rule", _n, "protocol"] => FILTER_PROTOCOLS,
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

        // The pki (certificate authority + ACME) sub-tree.
        ["set" | "delete", "pki"] => PKI_NODES,
        ["set" | "delete", "update"] => UPDATE_FIELDS,
        ["set" | "delete", "pki", "ca", _name] => PKI_CA_FIELDS,
        ["set", "pki", "ca", _name, "key-type"] => PKI_KEY_TYPES,
        ["set" | "delete", "pki", "certificate", _name] => PKI_CERT_FIELDS,
        ["set", "pki", "certificate", _name, "key-type"] => PKI_KEY_TYPES,
        ["set", "pki", "certificate", _name, "usage"] => PKI_USAGES,
        ["set" | "delete", "pki", "acme"] => PKI_ACME_FIELDS,
        ["set", "pki", "acme", "challenge"] => PKI_CHALLENGES,

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
    pub filters: Vec<String>,
    pub vrfs: Vec<String>,
    pub ipsec: Vec<String>,
    pub pki_cas: Vec<String>,
    pub pki_certificates: Vec<String>,
    pub wireguard: Vec<String>,
    pub reverse_proxy: Vec<String>,
}

/// Own a static `Cand` slice into `(keyword, description)` pairs — the bridge
/// from the static grammar / `PH_*` placeholders to the owned candidate list.
fn own_cands(slice: &[Cand]) -> Vec<(String, String)> {
    slice
        .iter()
        .map(|(k, d)| (k.to_string(), d.to_string()))
        .collect()
}

/// Candidates for `tokens`, splicing in the live interface/rule/zone names at the
/// name + zone-value positions, `<…>` value placeholders at every free-form value
/// leaf, and falling back to the static grammar elsewhere. Returns owned
/// `(keyword, description)` pairs. New grammar leaves adopt the same pattern:
/// add an arm returning `own_cands(&[PH_…])` (a value) or the live names plus a
/// `<name>` placeholder (a keyed instance).
fn dyn_candidates(tokens: &[&str], names: &DynNames) -> Vec<(String, String)> {
    // Reference an existing zone (a value position).
    let zones = |label: &'static str| -> Vec<(String, String)> {
        names
            .zones
            .iter()
            .map(|z| (z.clone(), label.to_string()))
            .collect()
    };
    // Pick a live NIC (a value position that names an interface).
    let nics = |label: &'static str| -> Vec<(String, String)> {
        names
            .interfaces
            .iter()
            .map(|n| (n.clone(), label.to_string()))
            .collect()
    };
    // A keyed-instance NAME position: the existing instances, then a `<name>`
    // placeholder inviting a fresh one (VyOS-style discovery).
    let named =
        |items: &[String], label: &'static str, hint: &'static str| -> Vec<(String, String)> {
            let mut v: Vec<(String, String)> = items
                .iter()
                .map(|n| (n.clone(), label.to_string()))
                .collect();
            v.push(("<name>".to_string(), hint.to_string()));
            v
        };
    match tokens {
        // ---- Keyed-instance NAME positions: live names + a `<name>` hint -----
        ["set" | "delete", "interface"] => named(
            &names.interfaces,
            "interface",
            "a new interface name (wg0, br0, …)",
        ),
        ["set" | "delete", "firewall", "rule"] => named(&names.rules, "rule", "a new rule name"),
        ["set" | "delete", "nat", "source"] => named(
            &names.nat_source,
            "nat source",
            "a new source-NAT rule name",
        ),
        ["set" | "delete", "nat", "destination"] => named(
            &names.nat_destination,
            "nat destination",
            "a new destination-NAT rule name",
        ),
        ["set" | "delete", "firewall", "zone"] => named(&names.zones, "zone", "a new zone name"),
        ["set" | "delete", "firewall", "group", "address-group"] => named(
            &names.address_groups,
            "address-group",
            "a new address-group name",
        ),
        ["set" | "delete", "firewall", "group", "port-group"] => {
            named(&names.port_groups, "port-group", "a new port-group name")
        }
        ["set" | "delete", "protocols", "vrrp"] => own_cands(&[PH_NAME]),
        ["set" | "delete", "vpn", "ipsec"] => {
            named(&names.ipsec, "IPsec connection", "a new connection name")
        }
        ["set" | "delete", "pki", "ca"] => named(&names.pki_cas, "CA", "a new CA name"),
        ["set" | "delete", "pki", "certificate"] => named(
            &names.pki_certificates,
            "certificate",
            "a new certificate name",
        ),
        ["set" | "delete", "protocols", "filter"] => {
            named(&names.filters, "route filter", "a new filter name")
        }
        ["set" | "delete", "protocols", "vrf"] => named(&names.vrfs, "VRF", "a new VRF name"),
        ["set" | "delete", "services", "reverse-proxy"] => named(
            &names.reverse_proxy,
            "reverse-proxy frontend",
            "a new reverse-proxy frontend name",
        ),
        [
            "set" | "delete",
            "interface",
            _name,
            "dhcp-server",
            "static-mapping",
        ] => own_cands(&[PH_NAME]),
        // Prefix / address instance positions.
        ["set" | "delete", "protocols", "static"] => own_cands(&[PH_IPV4_CIDR, PH_IPV6_CIDR]),
        ["set" | "delete", "protocols", "bgp", "aggregate" | "roa"] => {
            own_cands(&[PH_IPV4_CIDR, PH_IPV6_CIDR])
        }
        ["set" | "delete", "protocols", "bgp", "neighbor"] => own_cands(&[PH_IPV4, PH_IPV6]),
        ["set" | "delete", "protocols", "filter", _name, "rule"] => {
            own_cands(&[("<1-4294967295>", "a rule index (lower runs first)")])
        }

        // ---- NIC-picker sub-positions (choose a live interface) --------------
        ["set" | "delete", "multiwan", "uplink"] => nics("interface"),
        ["set", "nat", "nat64", "interface"] => nics("interface"),
        [
            "set" | "delete",
            "protocols",
            "ospf" | "ospf3" | "rip" | "ripng" | "babel" | "isis" | "multicast",
            "interface",
        ] => nics("interface"),
        ["set", "protocols", "vrrp", _name, "interface"] => nics("interface"),
        ["set", "protocols", "static", _pfx, "dev"] => nics("interface"),
        ["set", "interface", _name, "parent"] => nics("parent interface"),
        ["set", "interface", _name, "pd-from"] => nics("uplink interface"),
        ["set", "services", "dns" | "ntp", "serve-on"] => nics("interface"),
        [
            "set",
            "services",
            "lldp" | "mdns" | "dyndns" | "dhcp-relay",
            "interface",
        ] => nics("interface"),

        // ---- Zone-VALUE positions (reference an existing zone) ---------------
        ["set", "interface", _name, "zone"] => zones("zone"),
        ["set", "firewall", "rule", _name, "from" | "to"] => zones("zone"),
        ["set", "nat", "source", _name, "zone"] => zones("zone"),
        ["set", "nat", "destination", _name, "zone"] => zones("zone"),
        // Group-REFERENCE positions (an existing alias, no `<name>` invite).
        ["set", "firewall", "rule", _, "source-group"] => names
            .address_groups
            .iter()
            .map(|n| (n.clone(), "address-group".to_string()))
            .collect(),
        ["set", "firewall", "rule", _, "port-group"] => names
            .port_groups
            .iter()
            .map(|n| (n.clone(), "port-group".to_string()))
            .collect(),

        // ---- Interface value leaves ------------------------------------------
        ["set", "interface", _name, "address"] => {
            own_cands(&[PH_IPV4_CIDR, ("dhcp", "obtain the address via DHCP")])
        }
        ["set", "interface", _name, "address6"] => {
            let mut v = own_cands(&[PH_IPV6_CIDR]);
            v.extend(own_cands(ADDRESS6_HINT));
            v
        }
        ["set", "interface", _name, "vlan"] => own_cands(&[PH_VLAN]),
        ["set", "interface", _name, "pd-subnet" | "ttl"] => own_cands(&[PH_U8]),
        ["set", "interface", _name, "mtu"] => own_cands(&[PH_MTU]),
        ["set", "interface", _name, "mac"] => own_cands(&[PH_MAC]),
        // Bridge/bond membership + per-port VLAN filtering.
        ["set" | "delete", "interface", _name, "member"] => nics("member NIC"),
        ["set", "interface", _name, "vlan-untagged"] => own_cands(&[PH_VLAN]),
        ["set", "interface", _name, "vlan-tagged"] => own_cands(&[PH_VLAN_CSV]),
        // WireGuard tunnel config (under `vpn wireguard <ifname>`): offer the
        // declared type=wireguard interfaces first, all NICs as fallback.
        ["set" | "delete", "vpn", "wireguard"] => {
            let mut v: Vec<(String, String)> = names
                .wireguard
                .iter()
                .map(|n| (n.clone(), "a type=wireguard interface".to_string()))
                .collect();
            if v.is_empty() {
                v = nics("an interface (set `type wireguard` on it)");
            }
            v.push((PH_NAME.0.to_string(), PH_NAME.1.to_string()));
            v
        }
        // Filter-name reference positions: the declared route filters.
        ["set", "protocols", "import" | "export", _]
        | [
            "set",
            "protocols",
            "bgp",
            "neighbor",
            _,
            "import" | "export",
        ]
        | ["set", "protocols", "vrf", _, "import" | "export"] => {
            let mut v: Vec<(String, String)> = names
                .filters
                .iter()
                .map(|n| (n.clone(), "a declared route filter".to_string()))
                .collect();
            v.push((PH_NAME.0.to_string(), "a filter name".to_string()));
            v
        }
        // VRF-name reference positions: the declared VRFs.
        ["set", "protocols", "static", _, "vrf"]
        | [
            "set",
            "protocols",
            "bgp" | "ospf" | "ospf3" | "rip" | "ripng" | "babel" | "isis",
            "vrf",
        ] => {
            let mut v: Vec<(String, String)> = names
                .vrfs
                .iter()
                .map(|n| (n.clone(), "a declared VRF".to_string()))
                .collect();
            v.push((PH_NAME.0.to_string(), "a VRF name".to_string()));
            v
        }
        ["set" | "delete", "vpn", "wireguard", _name, "peer"] => own_cands(&[PH_PUBKEY]),
        ["set", "vpn", "wireguard", _name, "listen-port"] => own_cands(&[PH_PORT]),
        ["set", "vpn", "wireguard", _name, "private-key"] => {
            let mut v = own_cands(&[PH_KEY]);
            v.extend(own_cands(WG_KEY_GEN));
            v
        }
        ["set", "vpn", "wireguard", _name, "peer", _pk, "endpoint"] => own_cands(&[PH_HOST_PORT]),
        ["set", "vpn", "wireguard", _name, "peer", _pk, "allowed-ips"] => {
            own_cands(&[PH_IPV4_CIDR, PH_IPV6_CIDR])
        }
        ["set", "vpn", "wireguard", _name, "peer", _pk, "keepalive"] => own_cands(&[PH_SECONDS]),
        [
            "set",
            "vpn",
            "wireguard",
            _name,
            "peer",
            _pk,
            "preshared-key",
        ] => own_cands(&[PH_KEY]),
        ["set", "interface", _name, "local" | "remote"] => own_cands(&[PH_IPV4]),
        [
            "set",
            "interface",
            _name,
            "dhcp-server",
            "dns" | "default-router",
        ] => own_cands(&[PH_IPV4]),
        [
            "set",
            "interface",
            _name,
            "dhcp-server",
            "static-mapping",
            _l,
            "mac",
        ] => own_cands(&[PH_MAC]),
        [
            "set",
            "interface",
            _name,
            "dhcp-server",
            "static-mapping",
            _l,
            "ip",
        ] => own_cands(&[PH_IPV4]),
        ["set", "interface", _name, "router-advert", "prefix"] => own_cands(&[PH_IPV6_CIDR]),
        ["set", "interface", _name, "router-advert", "dns"] => own_cands(&[PH_IPV6]),
        [
            "set",
            "interface",
            _name,
            "router-advert",
            "router-lifetime",
        ] => own_cands(&[PH_SECONDS]),
        ["set", "interface", _name, "pppoe", "mru"] => own_cands(&[PH_MTU]),
        ["set", "interface", _name, "key"] => {
            own_cands(&[("<0-4294967295>", "a GRE key (demultiplexes tunnels)")])
        }
        [
            "set",
            "interface",
            _name,
            "dhcp-server",
            "pool-offset" | "pool-size",
        ] => own_cands(&[PH_NUMBER]),
        ["set", "interface", _name, "dhcp-server", "lease-time"] => own_cands(&[PH_DURATION]),
        ["set", "interface", _name, "qos", "limit"] => {
            own_cands(&[("<packets>", "fq_codel backlog packet limit")])
        }

        // ---- protocols value leaves ------------------------------------------
        ["set", "protocols", "router-id"] => own_cands(&[PH_IPV4]),
        ["set", "protocols", "static", _pfx, "via"] => own_cands(&[PH_IPV4, PH_IPV6]),
        ["set", "protocols", "babel", "router-id"] => own_cands(&[PH_IPV4]),
        ["set", "protocols", "bgp", "local-as"] => own_cands(&[PH_ASN]),
        ["set", "protocols", "bgp", "router-id"] => own_cands(&[PH_IPV4]),
        ["set", "protocols", "bgp", "hold-time"] => own_cands(&[PH_SECONDS]),
        ["set", "protocols", "bgp", "network"] => own_cands(&[PH_IPV4_CIDR, PH_IPV6_CIDR]),
        ["set", "protocols", "bgp", "confederation", "id" | "member"] => own_cands(&[PH_ASN]),
        ["set", "protocols", "bgp", "rpki", "rtr"] => own_cands(&[PH_HOST_PORT]),
        ["set", "protocols", "bgp", "rpki", "rtr-refresh"] => own_cands(&[PH_SECONDS]),
        ["set", "protocols", "bgp", "roa", _pfx, "origin-as"] => own_cands(&[PH_ASN]),
        [
            "set",
            "protocols",
            "bgp",
            "neighbor",
            _addr,
            "remote-as" | "local-as",
        ] => own_cands(&[PH_ASN]),
        ["set", "protocols", "bgp", "neighbor", _addr, "hold-time"] => own_cands(&[PH_SECONDS]),
        [
            "set",
            "protocols",
            "bgp",
            "neighbor",
            _addr,
            "update-source",
        ] => own_cands(&[PH_IPV4, PH_IPV6]),
        ["set", "protocols", "vrrp", _name, "virtual-address"] => own_cands(&[PH_IPV4, PH_IPV6]),

        // ---- firewall / nat value leaves -------------------------------------
        ["set", "firewall", "global", "block"] => own_cands(&[PH_IPV4_CIDR, PH_IPV6_CIDR]),
        ["set", "firewall", "zone", _name, "block"] => own_cands(&[PH_IPV4_CIDR, PH_IPV6_CIDR]),
        ["set", "firewall", "rule", _name, "source"] => own_cands(&[PH_IPV4_CIDR, PH_IPV6_CIDR]),
        ["set", "firewall", "rule", _name, "port"] => own_cands(&[PH_PORT_RANGE]),
        ["set", "nat", "destination", _name, "port"] => own_cands(&[PH_PORT]),
        ["set", "nat", "destination", _name, "to"] => own_cands(&[PH_IPV4_TO]),
        ["set", "nat", "nat64", "prefix"] => own_cands(&[PH_IPV6_CIDR]),
        ["set", "nat", "nat64", "pool"] => own_cands(&[PH_IPV4_CIDR]),

        // ---- services value leaves -------------------------------------------
        ["set", "services", "dns" | "ntp", "upstream"] => own_cands(&[PH_IPV4, PH_IPV6]),
        ["set", "services", "snmp", "listen"] => own_cands(&[PH_IPV4]),
        ["set", "services", "snmp", "community"] => own_cands(&[PH_KEY]),
        ["set", "services", "snmp", "location" | "contact"] => own_cands(&[PH_TEXT]),
        ["set", "services", "dhcp-relay", "server"] => own_cands(&[PH_IPV4]),
        ["set", "services", "dyndns", "hostname"] => {
            own_cands(&[("<fqdn>", "a fully-qualified domain name")])
        }
        ["set", "services", "dyndns", "server"] => own_cands(&[PH_HOST_PORT]),

        // ---- multiwan / vpn / pki value leaves -------------------------------
        ["set", "multiwan", "uplink", _if, "gateway"] => {
            own_cands(&[PH_IPV4, ("dhcp", "resolve from the DHCP lease")])
        }
        ["set", "multiwan", "uplink", _if, "check", "target"] => own_cands(&[PH_IPV4]),
        ["set", "vpn", "ipsec", _name, "local" | "remote"] => own_cands(&[PH_IPV4]),
        [
            "set",
            "vpn",
            "ipsec",
            _name,
            "local-subnet" | "remote-subnet",
        ] => own_cands(&[PH_IPV4_CIDR]),
        ["set", "vpn", "ipsec", _name, "psk"] => own_cands(&[PH_KEY]),
        // OpenConnect value positions.
        ["set", "vpn", "openconnect", "certificate"] => {
            let mut v: Vec<(String, String)> = names
                .pki_certificates
                .iter()
                .map(|n| (n.clone(), "a declared pki certificate".to_string()))
                .collect();
            v.push((
                "acme".to_string(),
                "an ACME-obtained certificate".to_string(),
            ));
            v
        }
        ["set", "vpn", "openconnect", "port"] => own_cands(&[PH_PORT]),
        ["set", "vpn", "openconnect", "pool"] => own_cands(&[PH_IPV4_CIDR]),
        // Reverse-proxy value positions (roadmap C22).
        ["set", "services", "reverse-proxy", _name, "certificate"] => {
            let mut v: Vec<(String, String)> = names
                .pki_certificates
                .iter()
                .map(|n| (n.clone(), "a declared pki certificate".to_string()))
                .collect();
            v.push((
                "acme".to_string(),
                "an ACME-obtained certificate".to_string(),
            ));
            v
        }
        ["set", "services", "reverse-proxy", _name, "port"] => own_cands(&[PH_PORT]),
        ["set", "services", "reverse-proxy", _name, "backends"] => own_cands(&[PH_HOST_PORT]),
        ["set", "vpn", "openconnect", "dns"] => own_cands(&[PH_IPV4, PH_IPV6]),
        ["set", "vpn", "openconnect", "routes"] => own_cands(&[PH_IPV4_CIDR, PH_IPV6_CIDR]),
        ["set", "vpn", "openconnect", "zone"] => zones("zone"),
        ["set" | "delete", "vpn", "openconnect", "user"] => own_cands(&[PH_NAME]),
        ["set", "vpn", "openconnect", "user", _u, "password"] => own_cands(&[PH_KEY]),
        ["set", "update", "url"] => own_cands(&[PH_URL]),
        ["set", "update", "public-key"] => {
            own_cands(&[("<pem|file:path>", "PEM key or file:<path>")])
        }
        ["set", "pki", "acme", "directory-url"] => own_cands(&[PH_URL]),
        ["set", "pki", "acme", "email"] => own_cands(&[("<email>", "a contact email address")]),

        // ---- Generic trailing hints (field names that mean the same anywhere) -
        ["set", .., "hostname"] => own_cands(&[PH_NAME]),
        [.., "password"] => own_cands(&[PH_KEY]),
        [.., "description"] => own_cands(&[PH_TEXT]),

        _ => own_cands(candidates(tokens)),
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

    /// Refresh the live instance names offered at the name + reference-value
    /// positions. Called from the configure loop after every command so new
    /// interfaces/rules/zones/filters/… become completable immediately.
    pub fn set_names(&self, names: DynNames) {
        *self.names.borrow_mut() = names;
    }
}

/// The commands the shell actually accepts, for first-word highlighting: the
/// completion table plus the two working aliases (`del`, `quit`). Retired Cisco
/// spellings (`no`/`do`/`end`) are deliberately absent — they render red.
fn is_known_command(word: &str) -> bool {
    COMMANDS.iter().any(|(k, _)| *k == word) || matches!(word, "del" | "quit")
}

/// A ghost hint that is displayed but never inserted: `completion()` returns
/// `None`, so right-arrow/End does nothing and a value placeholder like
/// `<A.B.C.D>` can never leak into the line (unlike the stock `String` hint).
pub struct ValueHint(String);
impl rustyline::hint::Hint for ValueHint {
    fn display(&self) -> &str {
        &self.0
    }
    fn completion(&self) -> Option<&str> {
        None
    }
}

impl Hinter for ConfigCompleter {
    type Hint = ValueHint;

    /// At a fresh word boundary (the line ends in a space) whose next token is a
    /// value position, show the `<…>` placeholder(s) as dimmed ghost text — so
    /// the box says *what to type* even where there is a single value and no
    /// keyword list to Tab through.
    fn hint(&self, line: &str, pos: usize, _ctx: &rustyline::Context<'_>) -> Option<ValueHint> {
        if pos != line.len() || !ui::enabled() || !line.ends_with(char::is_whitespace) {
            return None;
        }
        let before: Vec<&str> = line.split_whitespace().collect();
        if before.is_empty() {
            return None;
        }
        let ctx = self.context.borrow();
        let eff = effective_tokens(&before, &ctx);
        let eff_view: Vec<&str> = eff.iter().map(String::as_str).collect();
        let names = self.names.borrow();
        let hints: Vec<String> = dyn_candidates(&eff_view, &names)
            .into_iter()
            .map(|(k, _)| k)
            .filter(|k| is_placeholder(k))
            .collect();
        if hints.is_empty() {
            return None;
        }
        Some(ValueHint(ui::dim(&format!(" {}", hints.join(" | ")))))
    }
}

impl Highlighter for ConfigCompleter {
    /// Colour the first word once it is complete (a space follows it): bold green
    /// if it is a real command, bold red if not. The rest of the line is left
    /// untouched, and a half-typed command (no space yet) is not flagged.
    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> Cow<'l, str> {
        if !ui::enabled() {
            return Cow::Borrowed(line);
        }
        let lead = line.len() - line.trim_start().len();
        let rest = &line[lead..];
        let Some(word_len) = rest.find(char::is_whitespace) else {
            return Cow::Borrowed(line); // first word not finished yet
        };
        let word = &rest[..word_len];
        let coloured = if is_known_command(word) {
            ui::green_bold(word)
        } else {
            ui::red_bold(word)
        };
        Cow::Owned(format!("{}{coloured}{}", &line[..lead], &rest[word_len..]))
    }

    /// Bold the prompt. rustyline measures the *plain* prompt passed to
    /// `readline` for its width maths, so wrapping it in ANSI here is safe — the
    /// `*` dirty-marker stays part of that plain prompt.
    fn highlight_prompt<'b, 's: 'b, 'p: 'b>(
        &'s self,
        prompt: &'p str,
        _default: bool,
    ) -> Cow<'b, str> {
        if ui::enabled() {
            Cow::Owned(ui::bold(prompt))
        } else {
            Cow::Borrowed(prompt)
        }
    }

    /// Re-highlight once the first word is complete (a space is present): cheap,
    /// and enough to catch the word flipping known↔unknown as it is edited.
    fn highlight_char(&self, line: &str, _pos: usize, forced: bool) -> bool {
        forced || (ui::enabled() && line.contains(char::is_whitespace))
    }
}
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
        // Pure grammar everywhere: at the first token only the commands are
        // offered (a bare config path is not a command), deeper positions
        // complete the config tree.
        let all = dyn_candidates(&eff_view, &names);
        // Real keywords are prefix-filtered; `<…>` placeholders always show (and
        // insert nothing) — so a value position keeps hinting even mid-value.
        let matched = matches_for(&all, prefix);

        // Align the keyword column on VISIBLE width (the keywords carry no colour
        // yet), colour each piece, then pad each row out to the terminal width so
        // rustyline lists one candidate per line, vtysh-style, not a packed grid.
        let kw_w = matched.iter().map(|(kw, _, _)| kw.len()).max().unwrap_or(0);
        let row_w = term_width().saturating_sub(1);
        let matches = matched
            .iter()
            .map(|(kw, desc, repl)| {
                // Keyword column bold; a `<…>` placeholder italic+yellow; the
                // description column dimmed.
                let kw_col = if is_placeholder(kw) {
                    ui::italic(&ui::yellow(kw))
                } else {
                    ui::bold(kw)
                };
                // Compute the row's VISIBLE width from the plain pieces so the
                // padding is right despite the (zero-visible-width) colour codes.
                let (body, visible) = if desc.is_empty() {
                    (kw_col, kw.len())
                } else {
                    let gap = " ".repeat(kw_w.saturating_sub(kw.len()));
                    (
                        format!("{kw_col}{gap}  {}", ui::dim(desc)),
                        kw_w + 2 + desc.len(),
                    )
                };
                let pad = " ".repeat(row_w.saturating_sub(visible));
                Pair {
                    display: format!("{body}{pad}"),
                    replacement: repl.clone(),
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
                "vpn",
                "pki",
                "update"
            ]
        );
        assert_eq!(kw(&["set", "system"]), ["hostname"]);
        assert_eq!(
            kw(&["set", "interface", "wan0"]),
            [
                "description",
                "disabled",
                "zone",
                "address",
                "address6",
                "pd-from",
                "pd-subnet",
                "parent",
                "vlan",
                "vlan-protocol",
                "macvlan-mode",
                "dhcp-server",
                "router-advert",
                "type",
                "local",
                "remote",
                "key",
                "ttl",
                "member",
                "bond-mode",
                "vlan-aware",
                "vlan-tagged",
                "vlan-untagged",
                "mtu",
                "mac",
                "qos",
                "pppoe"
            ]
        );
        // WireGuard tunnel config is discoverable under `vpn wireguard`.
        assert_eq!(
            kw(&["set", "vpn", "wireguard", "wg0"]),
            ["private-key", "listen-port", "peer"]
        );
        assert_eq!(
            kw(&["set", "vpn", "wireguard", "wg0", "peer", "PUBKEY"]),
            ["allowed-ips", "endpoint", "keepalive", "preshared-key"]
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
                "lease-time",
                "default-router",
                "domain",
                "static-mapping"
            ]
        );
        // A per-reservation sub-context (mac / ip) is discoverable.
        assert_eq!(
            kw(&[
                "set",
                "interface",
                "lan0",
                "dhcp-server",
                "static-mapping",
                "printer"
            ]),
            ["mac", "ip"]
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
        // WireGuard keys/peers moved to `vpn wireguard` — the interface no
        // longer offers them (asserted via the exact IFACE_FIELDS list above).
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
            [
                "description",
                "stateful",
                "block-icmp",
                "default-action",
                "log",
                "block"
            ]
        );
        assert_eq!(
            kw(&["set", "firewall", "zone", "wan", "block-icmp"]),
            ["true", "false"]
        );
        assert_eq!(
            kw(&["set", "firewall", "rule", "web"]),
            [
                "description",
                "disabled",
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
        // The nat sub-tree: source (masquerade) + destination (port-forward) + nat64.
        assert_eq!(kw(&["set", "nat"]), ["source", "destination", "nat64"]);
        assert_eq!(
            kw(&["set", "nat", "nat64"]),
            ["enabled", "prefix", "pool", "interface", "dns64"]
        );
        assert_eq!(
            kw(&["set", "nat", "source", "wan-masq"]),
            ["zone", "description", "disabled"]
        );
        assert_eq!(
            kw(&["set", "nat", "destination", "web"]),
            ["zone", "proto", "port", "to", "description", "disabled"]
        );
        assert_eq!(
            kw(&["set", "nat", "destination", "web", "proto"]),
            ["tcp", "udp"]
        );
        // The box-services sub-tree is discoverable level by level — and because
        // contexts derive from these tables, each new leaf is an enterable context.
        assert_eq!(
            kw(&["set", "services"]),
            [
                "dns",
                "ntp",
                "lldp",
                "snmp",
                "mdns",
                "dyndns",
                "dhcp-relay",
                "reverse-proxy"
            ]
        );
        assert_eq!(kw(&["set", "services", "lldp"]), ["enable", "interface"]);
        assert_eq!(
            kw(&["set", "services", "lldp", "enable"]),
            ["true", "false"]
        );
        assert_eq!(
            kw(&["set", "services", "snmp"]),
            ["community", "listen", "location", "contact", "allow"]
        );
        assert_eq!(kw(&["set", "services", "mdns"]), ["interface"]);
        assert_eq!(
            kw(&["set", "services", "dyndns"]),
            [
                "provider",
                "server",
                "hostname",
                "login",
                "password",
                "interface"
            ]
        );
        assert_eq!(
            kw(&["set", "services", "dhcp-relay"]),
            ["interface", "server"]
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
            filters: vec!["from-peer".into()],
            vrfs: vec!["blue".into()],
            ipsec: vec!["hq".into()],
            pki_cas: vec!["root".into()],
            pki_certificates: vec!["api".into()],
            wireguard: vec!["wg0".into()],
            reverse_proxy: vec!["web".into()],
        };
        let kws = |toks: &[&str]| -> Vec<String> {
            dyn_candidates(toks, &names)
                .into_iter()
                .map(|(k, _)| k)
                .collect()
        };
        // Name positions splice in the live interface/rule/zone/nat names, then
        // a `<name>` placeholder inviting a fresh instance.
        assert_eq!(kws(&["set", "interface"]), ["eth0", "eth1", "<name>"]);
        assert_eq!(kws(&["delete", "firewall", "rule"]), ["web", "<name>"]);
        assert_eq!(kws(&["set", "nat", "source"]), ["wan-masq", "<name>"]);
        assert_eq!(kws(&["set", "nat", "destination"]), ["web-fwd", "<name>"]);
        assert_eq!(kws(&["set", "firewall", "zone"]), ["lan", "wan", "<name>"]);
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
        // Group-DEFINITION positions splice in the declared alias names, then a
        // `<name>` invite; group-REFERENCE positions (a rule) list only the
        // existing aliases.
        assert_eq!(
            kws(&["set", "firewall", "group", "address-group"]),
            ["mgmt", "<name>"]
        );
        assert_eq!(
            kws(&["set", "firewall", "group", "port-group"]),
            ["webports", "<name>"]
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
                "vpn",
                "pki",
                "update"
            ]
        );
        assert_eq!(
            kws(&["set", "interface", "eth0"]),
            [
                "description",
                "disabled",
                "zone",
                "address",
                "address6",
                "pd-from",
                "pd-subnet",
                "parent",
                "vlan",
                "vlan-protocol",
                "macvlan-mode",
                "dhcp-server",
                "router-advert",
                "type",
                "local",
                "remote",
                "key",
                "ttl",
                "member",
                "bond-mode",
                "vlan-aware",
                "vlan-tagged",
                "vlan-untagged",
                "mtu",
                "mac",
                "qos",
                "pppoe"
            ]
        );
        // WireGuard keys/peers live under `vpn wireguard <ifname>`, not on the
        // interface.
        assert_eq!(
            kws(&["set", "vpn", "wireguard", "wg0"]),
            ["private-key", "listen-port", "peer"]
        );
        assert_eq!(
            kws(&["set", "vpn", "wireguard", "wg0", "private-key"]),
            ["<key>", "generate"]
        );
    }

    #[test]
    fn value_positions_offer_display_only_placeholders() {
        let names = DynNames::default();
        let kws = |toks: &[&str]| -> Vec<String> {
            dyn_candidates(toks, &names)
                .into_iter()
                .map(|(k, _)| k)
                .collect()
        };
        // A BGP neighbour address position hints both address families.
        let n = kws(&["set", "protocols", "bgp", "neighbor"]);
        assert!(n.contains(&"<A.B.C.D>".to_string()), "{n:?}");
        assert!(n.contains(&"<X:X::X:X>".to_string()), "{n:?}");
        // remote-as / hold-time / interface address / nat to / firewall source /
        // rule port / mac / psk each get their vtysh-style value hint.
        assert_eq!(
            kws(&[
                "set",
                "protocols",
                "bgp",
                "neighbor",
                "10.0.0.2",
                "remote-as"
            ]),
            ["<1-4294967295>"]
        );
        assert_eq!(
            kws(&["set", "protocols", "bgp", "hold-time"]),
            ["<seconds>"]
        );
        assert_eq!(
            kws(&["set", "interface", "eth0", "address"]),
            ["<A.B.C.D/M>", "dhcp"]
        );
        assert_eq!(
            kws(&["set", "interface", "eth0", "address6"]),
            ["<X:X::X:X/M>", "auto", "dhcp"]
        );
        assert_eq!(kws(&["set", "interface", "eth0", "vlan"]), ["<1-4094>"]);
        assert_eq!(
            kws(&["set", "interface", "eth0", "mac"]),
            ["<xx:xx:xx:xx:xx:xx>"]
        );
        assert_eq!(
            kws(&["set", "nat", "destination", "web", "to"]),
            ["<A.B.C.D:port>"]
        );
        assert_eq!(
            kws(&["set", "firewall", "rule", "web", "source"]),
            ["<A.B.C.D/M>", "<X:X::X:X/M>"]
        );
        assert_eq!(
            kws(&["set", "firewall", "rule", "web", "port"]),
            ["<port|lo-hi>"]
        );
        assert_eq!(kws(&["set", "vpn", "ipsec", "t0", "psk"]), ["<key>"]);
        // Signed update channel value positions (roadmap C13).
        assert_eq!(kws(&["set", "update", "url"]), ["<url>"]);
        assert_eq!(kws(&["set", "update", "public-key"]), ["<pem|file:path>"]);
        // OpenConnect value positions get their vtysh-style hints, and the
        // certificate position offers the literal `acme` fallback.
        assert_eq!(kws(&["set", "vpn", "openconnect", "pool"]), ["<A.B.C.D/M>"]);
        assert_eq!(kws(&["set", "vpn", "openconnect", "port"]), ["<1-65535>"]);
        assert!(kws(&["set", "vpn", "openconnect", "certificate"]).contains(&"acme".to_string()));
        assert_eq!(kws(&["set", "vpn", "openconnect", "user"]), ["<name>"]);
        assert_eq!(
            kws(&["set", "vpn", "openconnect", "user", "alice", "password"]),
            ["<key>"]
        );
        // A description anywhere, and any password, get generic hints.
        assert_eq!(
            kws(&["set", "firewall", "rule", "web", "description"]),
            ["<text>"]
        );
        assert_eq!(kws(&["set", "system", "hostname"]), ["<name>"]);
        assert_eq!(
            kws(&["set", "interface", "ppp0", "pppoe", "password"]),
            ["<key>"]
        );
        // A fresh keyed-instance name position invites a `<name>`.
        assert_eq!(kws(&["set", "vpn", "ipsec"]), ["<name>"]);
        assert_eq!(kws(&["set", "pki", "ca"]), ["<name>"]);
    }

    #[test]
    fn matches_for_keeps_placeholders_and_makes_them_no_ops() {
        let all = vec![
            ("<A.B.C.D/M>".to_string(), "an IPv4 prefix".to_string()),
            ("dhcp".to_string(), "obtain via DHCP".to_string()),
        ];
        let names = |v: &[(&str, &str, String)]| -> Vec<String> {
            v.iter().map(|(k, _, _)| k.to_string()).collect()
        };
        // Empty prefix: both the placeholder and the real keyword show.
        let m = matches_for(&all, "");
        assert_eq!(names(&m), ["<A.B.C.D/M>", "dhcp"]);
        // A typed value prefix (`10.`) still lists the placeholder, but drops the
        // now-non-matching real keyword.
        let m = matches_for(&all, "10.");
        assert_eq!(names(&m), ["<A.B.C.D/M>"]);
        // The placeholder's replacement is a no-op: it re-inserts the typed word
        // unchanged, so a literal `<A.B.C.D/M>` is never entered.
        assert_eq!(m[0].2, "10.");
        // With prefix `d` both the (always-shown) placeholder and `dhcp` match;
        // the real keyword inserts itself plus a trailing space.
        let m = matches_for(&all, "d");
        assert_eq!(names(&m), ["<A.B.C.D/M>", "dhcp"]);
        let dhcp = m.iter().find(|(k, _, _)| *k == "dhcp").unwrap();
        assert_eq!(dhcp.2, "dhcp ");
    }

    #[test]
    fn followup_audit_positions_are_covered() {
        // Closed-enum tables (static grammar).
        assert!(kw(&["set", "protocols", "ospf", "redistribute"]).contains(&"bgp"));
        assert_eq!(
            kw(&["set", "services", "dyndns", "provider"]),
            ["dyndns2", "cloudflare", "duckdns", "noip"]
        );
        assert_eq!(
            kw(&["set", "protocols", "filter", "f", "rule", "10", "protocol"]),
            [
                "connected",
                "static",
                "kernel",
                "rip",
                "ospf",
                "bgp",
                "isis",
                "babel"
            ]
        );

        // Interface-name splices reuse the live NIC list.
        let names = DynNames {
            interfaces: vec!["eth0".into(), "eth1".into()],
            ..DynNames::default()
        };
        let kws = |toks: &[&str]| -> Vec<String> {
            dyn_candidates(toks, &names)
                .into_iter()
                .map(|(k, _)| k)
                .collect()
        };
        for toks in [
            vec!["set", "interface", "vlan10", "parent"],
            vec!["set", "interface", "lan0", "pd-from"],
            vec!["set", "services", "dns", "serve-on"],
            vec!["set", "services", "ntp", "serve-on"],
            vec!["set", "services", "lldp", "interface"],
            vec!["set", "services", "mdns", "interface"],
            vec!["set", "services", "dhcp-relay", "interface"],
            vec!["set", "protocols", "vrrp", "v1", "interface"],
            vec!["set", "protocols", "static", "10.0.0.0/8", "dev"],
            vec!["set", "protocols", "ospf", "interface"],
        ] {
            assert_eq!(
                kws(&toks),
                ["eth0", "eth1"],
                "NIC splice missing at {toks:?}"
            );
        }

        // Format-hint placeholders at the remaining value leaves.
        let ph = |toks: &[&str]| -> Vec<String> { kws(toks) };
        assert_eq!(ph(&["set", "interface", "eth0", "mtu"]), ["<68-9216>"]);
        assert_eq!(ph(&["set", "interface", "gre0", "key"]), ["<0-4294967295>"]);
        assert_eq!(
            ph(&["set", "interface", "lan0", "dhcp-server", "pool-offset"]),
            ["<number>"]
        );
        assert_eq!(
            ph(&["set", "interface", "lan0", "dhcp-server", "lease-time"]),
            ["<12h|30m|3600>"]
        );
        assert_eq!(
            ph(&[
                "set",
                "interface",
                "lan0",
                "router-advert",
                "router-lifetime"
            ]),
            ["<seconds>"]
        );
        assert_eq!(
            ph(&["set", "interface", "wan0", "qos", "limit"]),
            ["<packets>"]
        );
        // dhcp-relay server is an IP value, not a NIC.
        assert_eq!(
            ph(&["set", "services", "dhcp-relay", "server"]),
            ["<A.B.C.D>"]
        );
    }

    #[test]
    fn command_word_recognition_drives_highlighting() {
        // Real commands (and the working aliases) are known; retired spellings
        // and typos are not (they highlight red).
        for ok in ["set", "delete", "show", "commit", "del", "quit"] {
            assert!(is_known_command(ok), "{ok} should be known");
        }
        for bad in ["no", "do", "end", "interface", "shwo"] {
            assert!(!is_known_command(bad), "{bad} should be unknown");
        }
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
    fn edit_contexts_cover_protocol_subtrees_and_relative_sets() {
        let dir = std::env::temp_dir().join(format!("sentinel-ctx-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.toml");
        let mut s = Session::load(&path).unwrap();
        let act = Apply::off();
        let mut ctx = Vec::new();

        exec_line(&mut s, &act, &mut ctx, "set system hostname r1");
        // `edit` descends into the OSPF context; `set` is relative to it.
        exec_line(&mut s, &act, &mut ctx, "edit protocols ospf");
        assert_eq!(ctx, vec!["protocols", "ospf"]);
        exec_line(&mut s, &act, &mut ctx, "set area 0.0.0.0");
        exec_line(&mut s, &act, &mut ctx, "set hello-interval 5");
        exec_line(&mut s, &act, &mut ctx, "set bfd true");
        exec_line(&mut s, &act, &mut ctx, "top");
        assert!(ctx.is_empty());
        // A named VRF context.
        exec_line(&mut s, &act, &mut ctx, "edit protocols vrf blue");
        assert_eq!(ctx, vec!["protocols", "vrf", "blue"]);
        exec_line(&mut s, &act, &mut ctx, "set table 100");
        exec_line(&mut s, &act, &mut ctx, "top");
        // A multicast interface context (keyed node), entered stepwise.
        exec_line(&mut s, &act, &mut ctx, "edit protocols multicast");
        exec_line(&mut s, &act, &mut ctx, "set enabled true");
        exec_line(&mut s, &act, &mut ctx, "edit interface lan0");
        assert_eq!(ctx, vec!["protocols", "multicast", "interface", "lan0"]);
        exec_line(&mut s, &act, &mut ctx, "set role querier");
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
    fn edit_banner_renders_vyos_style() {
        assert_eq!(edit_banner(&[]), "[edit]");
        assert_eq!(
            edit_banner(&sv(&["firewall", "rule", "web"])),
            "[edit firewall rule web]"
        );
        assert_eq!(
            edit_banner(&sv(&["protocols", "bgp", "neighbor", "10.0.0.1"])),
            "[edit protocols bgp neighbor 10.0.0.1]"
        );
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
    fn exit_returns_to_top_and_up_pops_one_level() {
        let (mut s, _p, dir) = scratch_session("exit");
        let act = Apply::off();
        let mut ctx = Vec::new();

        // `up` pops one level: bgp → protocols → top.
        exec_line(&mut s, &act, &mut ctx, "edit protocols bgp");
        assert_eq!(ctx, vec!["protocols", "bgp"]);
        exec_line(&mut s, &act, &mut ctx, "up");
        assert_eq!(ctx, vec!["protocols"]);
        exec_line(&mut s, &act, &mut ctx, "up");
        assert!(ctx.is_empty());

        // A keyword+instance pair (`interface eth0`) pops as ONE level.
        exec_line(&mut s, &act, &mut ctx, "edit interface eth0");
        assert_eq!(ctx, vec!["interface", "eth0"]);
        exec_line(&mut s, &act, &mut ctx, "up");
        assert!(ctx.is_empty(), "interface+name pops as one level");

        // `exit` inside a context returns to the TOP (VyOS), not one level.
        exec_line(
            &mut s,
            &act,
            &mut ctx,
            "edit protocols bgp neighbor 10.0.0.1",
        );
        assert!(!exec_line(&mut s, &act, &mut ctx, "exit"));
        assert!(ctx.is_empty());

        // `top` clears from any depth.
        exec_line(&mut s, &act, &mut ctx, "edit firewall rule web");
        assert_eq!(ctx, vec!["firewall", "rule", "web"]);
        assert!(!exec_line(&mut s, &act, &mut ctx, "top"));
        assert!(ctx.is_empty());

        // At the top, `exit` leaves the session (returns true).
        assert!(exec_line(&mut s, &act, &mut ctx, "exit"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bare_paths_are_rejected_with_guidance_and_do_not_mutate() {
        let (mut s, _p, dir) = scratch_session("bare");
        let act = Apply::off();
        let mut ctx = Vec::new();

        // Pure grammar: a bare config path is NOT a command — it neither
        // descends nor sets, and the draft stays untouched.
        let before = s.show();
        assert!(!exec_line(&mut s, &act, &mut ctx, "interface eth0"));
        assert!(ctx.is_empty(), "a bare path must not change the context");
        assert!(!exec_line(&mut s, &act, &mut ctx, "totally bogus"));
        assert_eq!(s.show(), before, "a rejected line must not mutate");

        // The error text points at the explicit spellings.
        let err = unknown_command("interface", &["eth0"], &[]).to_string();
        assert!(err.contains("set interface eth0"), "{err}");
        assert!(err.contains("edit interface eth0"), "{err}");
        // Inside a context, a bare leaf gets the relative `set` hint.
        let rule_ctx = sv(&["firewall", "rule", "web"]);
        let err = unknown_command("action", &["accept"], &rule_ctx).to_string();
        assert!(err.contains("set action accept"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retired_spellings_and_typos_get_suggestions() {
        // The retired Cisco spellings name their replacement.
        for (old, new) in [("no", "delete"), ("do", "run"), ("end", "top")] {
            let err = unknown_command(old, &[], &[]).to_string();
            assert!(err.contains(&format!("`{new}`")), "{old}: {err}");
        }
        // A typo suggests the nearest command.
        let err = unknown_command("shwo", &[], &[]).to_string();
        assert!(err.contains("did you mean `show`"), "{err}");
        assert_eq!(closest_command("comit"), Some("commit"));
        assert_eq!(closest_command("xyzzy"), None);
    }

    #[test]
    fn delete_is_relative_to_the_edit_context() {
        let (mut s, _p, dir) = scratch_session("delrel");
        let act = Apply::off();
        let mut ctx = Vec::new();

        exec_line(&mut s, &act, &mut ctx, "edit firewall rule web");
        exec_line(&mut s, &act, &mut ctx, "set action accept");
        assert!(s.show().contains("accept"), "{}", s.show());
        // `delete` deletes relative to the context.
        assert!(!exec_line(&mut s, &act, &mut ctx, "delete action"));
        assert!(!s.show().contains("accept"), "{}", s.show());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn help_engine_is_complete_and_consistent() {
        // Every command in the completion table has help, and every help group
        // entry names a real command (the overview renderer asserts the
        // reverse direction via expect()).
        for (name, _) in COMMANDS {
            assert!(
                help_command(name).is_some(),
                "command {name:?} has no CMD_HELP entry"
            );
        }
        for (_, names) in HELP_GROUPS {
            for n in *names {
                assert!(
                    CMD_HELP.iter().any(|c| c.name == *n),
                    "HELP_GROUPS references unknown command {n:?}"
                );
            }
        }
        // The overview lists every grouped command's usage.
        let overview = help_overview();
        for c in CMD_HELP {
            assert!(overview.contains(c.usage), "overview misses {:?}", c.usage);
        }
        // Aliases resolve; garbage does not.
        assert!(help_command("quit").is_some());
        assert!(help_command("del").is_some());
        assert!(help_command("bogus").is_none());
        // Per-command help carries usage + examples.
        let cc = help_command("commit-confirm").unwrap();
        assert!(cc.contains("commit-confirm [minutes]"), "{cc}");
        assert!(cc.contains("confirm"), "{cc}");
    }

    #[test]
    fn wrap_breaks_lines_at_word_boundaries() {
        let lines = wrap("aa bb cc dd", 5);
        assert_eq!(lines, ["aa bb", "cc dd"]);
        assert!(wrap("", 10).is_empty());
        // A single overlong word is kept whole (never split mid-word).
        assert_eq!(wrap("supercalifragilistic", 5), ["supercalifragilistic"]);
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
    fn first_token_completion_offers_only_commands() {
        let names = DynNames::default();
        // At the first token only the commands are offered — a bare config
        // path is not a command, so the subtree keywords must NOT appear.
        let top: Vec<String> = dyn_candidates(&[], &names)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert!(top.contains(&"set".to_string()));
        assert!(top.contains(&"help".to_string()));
        assert!(!top.contains(&"end".to_string()));
        assert!(!top.contains(&"no".to_string()));
        assert!(!top.contains(&"do".to_string()));
        assert!(!top.contains(&"interface".to_string()));
        assert!(!top.contains(&"protocols".to_string()));

        // `help <Tab>` completes the command names.
        let help_args: Vec<String> = dyn_candidates(&["help"], &names)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert!(help_args.contains(&"commit".to_string()), "{help_args:?}");
    }

    #[test]
    fn vyos_style_session_end_to_end() {
        let (mut s, _p, dir) = scratch_session("e2e");
        let act = Apply::off();
        let mut ctx = Vec::new();
        // A realistic session: edit, relative sets, exit to top, flat sets, a
        // deeper context, and a relative delete.
        for line in [
            "edit interface eth0",
            "set zone lan",
            "set address 10.0.0.1/24",
            "exit",
            "edit firewall rule web",
            "set from lan",
            "set action accept",
            "top",
            "set protocols bgp local-as 65001",
            "edit protocols bgp neighbor 10.0.0.2",
            "set remote-as 65002",
            "delete remote-as",
            "set remote-as 65003",
            "exit",
        ] {
            assert!(!exec_line(&mut s, &act, &mut ctx, line), "line: {line}");
        }
        assert!(ctx.is_empty());
        let shown = s.show();
        for needle in ["eth0", "10.0.0.1/24", "web", "accept", "65001", "65003"] {
            assert!(shown.contains(needle), "missing {needle:?} in:\n{shown}");
        }
        assert!(!shown.contains("65002"), "deleted value survived:\n{shown}");
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
