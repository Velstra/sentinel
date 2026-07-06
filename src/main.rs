//! # Velstra Sentinel
//!
//! A standalone, **immutable** firewall/router appliance OS built on the Velstra
//! eBPF/XDP data plane. Velstra is the engine; Sentinel is the product on top.
//!
//! Unlike a mutable, log-in-and-tweak box (VyOS), a Sentinel appliance is
//! image-based and **declarative**: the whole box is described by one config
//! document that the system reconciles to atomically. This CLI is how you author
//! and apply that document — and, via [`velstra_proto`] (from crates.io), talk to
//! a running Velstra controller.

mod archive;
mod compile;
mod config;
mod confirm;
mod diff;
mod install;
mod ipsec;
mod net;
mod repl;
mod session;
mod system;
mod wgkey;
mod wren;

use std::{
    io::{BufRead, IsTerminal},
    path::PathBuf,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use crate::session::{DEFAULT_CONFIG, Session};
use velstra_proto::{ListPortsRequest, velstra_orchestrator_client::VelstraOrchestratorClient};

use crate::config::Appliance;

/// A config serialization format.
#[derive(Copy, Clone, Debug, ValueEnum)]
enum Format {
    Toml,
    Json,
}

/// RAID level for `sentinel install`.
#[derive(Copy, Clone, Debug, ValueEnum)]
enum RaidArg {
    /// Single disk, no array.
    None,
    /// RAID0 stripe (2+ disks, no redundancy).
    Stripe,
    /// RAID1 mirror (2+ disks).
    Mirror,
    /// RAID10 striped mirror (4+ disks).
    Mirror10,
}

impl From<RaidArg> for install::Raid {
    fn from(r: RaidArg) -> Self {
        match r {
            RaidArg::None => install::Raid::None,
            RaidArg::Stripe => install::Raid::Stripe,
            RaidArg::Mirror => install::Raid::Mirror,
            RaidArg::Mirror10 => install::Raid::Mirror10,
        }
    }
}

#[derive(Parser)]
#[command(name = "sentinel", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Enter an interactive configuration session (set/show/delete/commit/save).
    Configure {
        /// The appliance config to edit (loaded if it exists). `commit` writes
        /// here and applies it to the running system.
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
        /// Validate + save on commit, but don't apply to the running system
        /// (off-box editing).
        #[arg(long)]
        no_apply: bool,
    },
    /// Show live system state (operational mode), vtysh/VyOS-style paths:
    /// `show interfaces`, `show ip route [bgp|ospf|…]`, `show ip bgp summary`,
    /// `show ip ospf neighbors`, `show isis`, `show vrrp`, `show firewall
    /// statistics`, `show configuration`, `show log wren`, `show version`, …
    Show {
        /// The show path words (empty shows the system status).
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Author the declarative appliance config (file-based helpers).
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Compile the appliance config into a Velstra agent config (to stdout).
    Compile {
        /// Path to the appliance config (TOML or JSON).
        file: PathBuf,
    },
    /// Seed the running system from a config at boot: set the hostname and write
    /// the agent config (no reload — the agent starts after). Used by the
    /// sentinel-boot service.
    ApplyBoot {
        /// The active appliance config to apply.
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
        /// Where to write the compiled Velstra agent config.
        #[arg(long, default_value = repl::DEFAULT_VELSTRA_OUT)]
        out: PathBuf,
        /// Where to write the compiled Wren routing config.
        #[arg(long, default_value = repl::DEFAULT_WREN_OUT)]
        wren_out: PathBuf,
    },
    /// Compile + install the Velstra agent config, then reload the data plane.
    Apply {
        /// Path to the appliance config (TOML or JSON).
        file: PathBuf,
        /// Where to write the compiled Velstra agent config.
        #[arg(long, default_value = "/etc/sentinel/velstra.toml")]
        out: PathBuf,
        /// systemd unit to reload-or-restart after writing (skipped if unset).
        #[arg(long)]
        reload: Option<String>,
    },
    /// Install the appliance onto internal storage. With no target disk, lists
    /// candidate disks; with target(s), shows the install plan (dry-run unless
    /// `--commit`).
    Install {
        /// Target disk(s), e.g. `/dev/sda`. Two or more for a RAID array.
        targets: Vec<String>,
        /// RAID level for the writable data partition across the targets.
        #[arg(long, value_enum, default_value_t = RaidArg::None)]
        raid: RaidArg,
        /// Clone from this raw appliance image instead of the booted medium
        /// (the live-boot/ISO case). Defaults to $SENTINEL_INSTALL_SOURCE.
        #[arg(long)]
        source: Option<PathBuf>,
        /// Actually perform the (destructive) install instead of a dry-run.
        #[arg(long)]
        commit: bool,
    },
    /// A/B update: write a new appliance image into the inactive slot and boot
    /// it next (auto-rollback to the current slot if it fails).
    Update {
        /// The new appliance image (raw file) or a block device to re-seal from.
        image: PathBuf,
        /// Actually perform the (destructive-to-the-inactive-slot) update.
        #[arg(long)]
        commit: bool,
    },
    /// Revert the running system to the saved config. Invoked by the
    /// `commit-confirm` auto-rollback timer when its window expires; can also be
    /// run manually to drop an un-confirmed change immediately.
    ConfirmRollback {
        /// The saved config to revert to (the running/boot baseline).
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
    /// List the ports a Velstra controller currently knows about.
    Ports {
        /// The controller's orchestrator/admin endpoint.
        #[arg(long, default_value = "http://127.0.0.1:50052")]
        controller: String,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Print a commented starter config to stdout.
    Init,
    /// Parse and validate a config file (exit non-zero if invalid).
    Check {
        /// Path to the appliance config (TOML).
        file: PathBuf,
    },
    /// Parse a config file and print a normalized summary.
    Show {
        /// Path to the appliance config (TOML or JSON).
        file: PathBuf,
    },
    /// Convert a config between TOML and JSON (format in is by extension).
    Convert {
        /// Path to the appliance config (`.json` → JSON, else TOML).
        file: PathBuf,
        /// Output format.
        #[arg(long, value_enum)]
        to: Format,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Restore default SIGPIPE handling so `sentinel show … | head`/`grep -q`
    // exits quietly when the reader closes the pipe, instead of panicking on
    // EPIPE (Rust ignores SIGPIPE by default, turning a closed pipe into a
    // "failed printing to stdout" panic).
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    match Cli::parse().command {
        Command::Configure { config, no_apply } => configure(&config, no_apply),
        Command::Show { args } => show_op(&args),
        Command::Config { action } => config_cmd(action),
        Command::Compile { file } => {
            let appliance = Appliance::load(&file)?;
            print!("{}", compile::compile(&appliance).to_toml()?);
            Ok(())
        }
        Command::Install {
            targets,
            raid,
            source,
            commit,
        } => install_cmd(&targets, raid.into(), source, commit),
        Command::Update { image, commit } => install::update(&image, commit),
        Command::ApplyBoot {
            config,
            out,
            wren_out,
        } => apply_boot(&config, &out, &wren_out),
        Command::Apply { file, out, reload } => apply(&file, &out, reload.as_deref()),
        Command::ConfirmRollback { config } => confirm_rollback(&config),
        Command::Ports { controller } => ports(&controller).await,
    }
}

/// The live-apply target for `commit`/`commit-confirm`/`confirm-rollback`: the
/// runtime config paths + units. `enabled` off (off-box / `--no-apply`)
/// validates + saves only, touching no running service.
fn live_apply(enabled: bool) -> repl::Apply {
    repl::Apply {
        velstra_out: PathBuf::from(repl::DEFAULT_VELSTRA_OUT),
        unit: repl::DEFAULT_UNIT.to_string(),
        wren_out: PathBuf::from(repl::DEFAULT_WREN_OUT),
        wren_unit: repl::DEFAULT_WREN_UNIT.to_string(),
        enabled,
    }
}

/// `sentinel confirm-rollback`: revert the running system to the saved config.
/// The `commit-confirm` timer runs this when its window expires; an operator can
/// also run it (or `run confirm-rollback` from config mode) to drop an
/// un-confirmed change at once.
fn confirm_rollback(config: &std::path::Path) -> Result<()> {
    confirm::rollback(&live_apply(true), config)
}

/// The interactive configuration session — a VyOS/JunOS-style edit context.
/// On a terminal it uses rustyline (history + tab-completion); for piped input
/// (scripts/tests) it reads plain stdin lines. Both run `repl::exec_line`.
fn configure(config: &std::path::Path, no_apply: bool) -> Result<()> {
    let mut session = Session::load(config)?;
    // Surface the interfaces the system actually provides, so they appear in the
    // config (unassigned) ready to be given a zone/address — VyOS-style.
    session.merge_discovered(system::discover_interfaces());

    // Apply on commit unless told not to (off-box editing). The live apply uses
    // hostnamectl/systemctl, which only work on the box.
    let act = live_apply(!no_apply);

    if std::io::stdin().is_terminal() {
        eprintln!("Entering configuration mode. `help` for commands, `exit` to leave.");
        if !act.enabled {
            eprintln!("(commit will validate + save only; not applying)");
        }
        // `List` completion shows all candidates at once (like bash) instead of
        // cycling through them one Tab at a time.
        let cfg = rustyline::Config::builder()
            .completion_type(rustyline::CompletionType::List)
            .build();
        let mut rl = rustyline::Editor::<repl::ConfigCompleter, _>::with_config(cfg)
            .context("starting the line editor")?;
        rl.set_helper(Some(repl::ConfigCompleter::new()));
        // VyOS/vtysh `?`: list the candidates here without inserting a literal
        // `?`. Bound to the same completion the Tab key triggers.
        rl.bind_sequence(
            rustyline::KeyEvent(rustyline::KeyCode::Char('?'), rustyline::Modifiers::NONE),
            rustyline::Cmd::Complete,
        );
        let user = std::env::var("USER").unwrap_or_else(|_| "admin".into());
        let mut ctx: Vec<String> = Vec::new();
        loop {
            // Refresh the names the completer offers (interfaces/rules can change
            // with each command) so `set interface <Tab>` lists the current NICs,
            // and the edit context so completion is relative to it.
            if let Some(h) = rl.helper() {
                h.set_names(
                    session.interface_names(),
                    session.rule_names(),
                    session.zone_names(),
                    session.nat_source_names(),
                    session.nat_destination_names(),
                    session.address_group_names(),
                    session.port_group_names(),
                );
                h.set_context(&ctx);
            }
            // Cisco-style prompt, re-rendered each line: it reflects the LIVE
            // hostname (so a committed change shows immediately), marks
            // uncommitted edits with the leading `[edit] `, and renders the
            // context as `(config…)` (see repl::prompt_context).
            let edit = if session.dirty() { "[edit] " } else { "" };
            let prompt = format!(
                "{edit}{user}@{}{}# ",
                system::current_hostname(),
                repl::prompt_context(&ctx)
            );
            match rl.readline(&prompt) {
                Ok(line) => {
                    let _ = rl.add_history_entry(line.as_str());
                    if repl::exec_line(&mut session, &act, &mut ctx, &line) {
                        break;
                    }
                }
                // Ctrl-C cancels the current line (VyOS-style) — it does NOT
                // leave config mode. Use `exit` to leave.
                Err(rustyline::error::ReadlineError::Interrupted) => continue,
                // Ctrl-D leaves the session.
                Err(rustyline::error::ReadlineError::Eof) => break,
                Err(e) => return Err(e).context("reading input"),
            }
        }
    } else {
        let stdin = std::io::stdin();
        let mut ctx: Vec<String> = Vec::new();
        for line in stdin.lock().lines() {
            if repl::exec_line(
                &mut session,
                &act,
                &mut ctx,
                &line.context("reading stdin")?,
            ) {
                break;
            }
        }
    }
    Ok(())
}

/// Compile the appliance config, atomically install the Velstra agent config at
/// `out`, and (if given) reload the systemd `unit` running the data plane.
fn apply(file: &std::path::Path, out: &std::path::Path, reload: Option<&str>) -> Result<()> {
    let appliance = Appliance::load(file)?;
    let rendered = compile::compile(&appliance).to_toml()?;

    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    // Atomic: write a temp file then rename, so the agent never reads a half file.
    let tmp = out.with_extension("toml.tmp");
    std::fs::write(&tmp, &rendered).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, out).with_context(|| format!("installing {}", out.display()))?;
    println!("installed {}", out.display());

    if let Some(unit) = reload {
        // Use the pinned absolute path like the rest of the binary, so neither
        // the admin's $PATH nor sudo's secure_path can shadow or miss systemctl.
        let status = std::process::Command::new(system::bin("systemctl"))
            .args(["reload-or-restart", unit])
            .status()
            .with_context(|| format!("running systemctl reload-or-restart {unit}"))?;
        if !status.success() {
            anyhow::bail!("systemctl reload-or-restart {unit} failed");
        }
        println!("reloaded {unit}");
    }
    Ok(())
}

/// Seed the running system from the active config at boot: write the compiled
/// agent config (the agent starts after, so no reload) and set the hostname so
/// it persists across reboots.
fn apply_boot(
    config: &std::path::Path,
    out: &std::path::Path,
    wren_out: &std::path::Path,
) -> Result<()> {
    let appliance = Appliance::load(config)?;

    // Compile BOTH configs before writing either, so a compile error can't leave
    // a half-seeded system (velstra written, wren missing). Rendering is pure and
    // has no side effects, so this is the cheap point to fail atomically.
    let rendered = compile::compile(&appliance)
        .to_toml()
        .context("compiling firewall config")?;
    let wren_rendered = wren::compile_wren(&appliance)
        .to_toml()
        .context("compiling routing config")?;

    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(out, &rendered).with_context(|| format!("writing {}", out.display()))?;

    // Routing: seed the Wren config too (the daemon starts after, so no reload).
    if let Some(parent) = wren_out.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(wren_out, &wren_rendered)
        .with_context(|| format!("writing {}", wren_out.display()))?;

    system::set_hostname(&appliance.system.hostname)?;
    // Re-assert interface addressing from the saved config (networkd units),
    // so a reboot restores the live IPs the same way it restores the hostname.
    net::apply(&appliance)?;
    Ok(())
}

/// `sentinel install`: with no target on a terminal, run the interactive wizard
/// (pick mode + disks); with target(s), validate the selection and show the
/// plan. Destructive execution happens on `--commit` (or after the wizard's
/// confirmation).
fn install_cmd(
    targets: &[String],
    raid: install::Raid,
    source: Option<PathBuf>,
    commit: bool,
) -> Result<()> {
    // A bundled source image may come from the flag or the environment (the ISO
    // sets $SENTINEL_INSTALL_SOURCE).
    let source = source.or_else(|| std::env::var_os("SENTINEL_INSTALL_SOURCE").map(PathBuf::from));
    let disks = install::discover_disks()?;

    if targets.is_empty() {
        if std::io::stdin().is_terminal() {
            return interactive_install(&disks, source.as_deref());
        }
        // Non-interactive with no target: just list candidates.
        list_disks(&disks);
        return Ok(());
    }

    let chosen = install::plan_targets(&disks, targets, raid)?;
    print_plan(&chosen, raid);
    if !commit {
        println!("\n(dry-run — re-run with --commit to write. THIS ERASES THE TARGET DISK(S).)");
        return Ok(());
    }
    install::execute(&chosen, raid, source.as_deref())
}

/// Print the candidate disks as a numbered table.
fn list_disks(disks: &[install::Disk]) {
    if disks.is_empty() {
        println!("no disks found");
        return;
    }
    println!("Candidate install disks:");
    for (i, d) in disks.iter().enumerate() {
        println!(
            "  [{}] {:<12} {:>10}  {}{}",
            i + 1,
            d.dev_path(),
            install::human_size(d.size),
            if d.model.is_empty() {
                "(no model)"
            } else {
                &d.model
            },
            if d.removable { "  [removable]" } else { "" },
        );
    }
}

/// Print the resolved install plan.
fn print_plan(chosen: &[&install::Disk], raid: install::Raid) {
    println!("Install plan ({raid:?}):");
    for d in chosen {
        println!(
            "  target {} ({})",
            d.dev_path(),
            install::human_size(d.size)
        );
    }
    println!("  layout: ESP + dm-verity store (sealed, read-only) + data partition");
    if let Some(level) = raid.mdadm_level() {
        println!("  data partition as mdadm RAID{level} across the targets");
    }
}

/// The guided installer: choose a mode, pick the disks, confirm, install.
fn interactive_install(disks: &[install::Disk], source: Option<&std::path::Path>) -> Result<()> {
    list_disks(disks);
    if disks.is_empty() {
        return Ok(());
    }

    println!("\nInstall mode:");
    println!("  [1] single disk");
    println!("  [2] RAID0  (stripe — capacity, no redundancy, 2+ disks)");
    println!("  [3] RAID1  (mirror — redundancy, 2+ disks)");
    println!("  [4] RAID10 (striped mirror, 4+ disks)");
    let raid = match prompt("Mode [1-4]: ")?.trim() {
        "1" => install::Raid::None,
        "2" => install::Raid::Stripe,
        "3" => install::Raid::Mirror,
        "4" => install::Raid::Mirror10,
        other => anyhow::bail!("invalid mode {other:?}"),
    };

    let pick = prompt("Select disk number(s), space-separated: ")?;
    let targets = resolve_picks(disks, pick.trim())?;
    let chosen = install::plan_targets(disks, &targets, raid)?;

    println!();
    print_plan(&chosen, raid);
    let confirm = prompt("\nThis ERASES the selected disk(s). Type YES to proceed: ")?;
    if confirm.trim() != "YES" {
        println!("aborted.");
        return Ok(());
    }
    install::execute(&chosen, raid, source)
}

/// Map numbered picks (`"1 3"`) to `/dev` paths.
fn resolve_picks(disks: &[install::Disk], picks: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for tok in picks.split_whitespace() {
        let i: usize = tok
            .parse()
            .map_err(|_| anyhow::anyhow!("not a number: {tok:?}"))?;
        let d = disks
            .get(i.wrapping_sub(1))
            .ok_or_else(|| anyhow::anyhow!("no disk [{i}]"))?;
        out.push(d.dev_path());
    }
    if out.is_empty() {
        anyhow::bail!("no disks selected");
    }
    Ok(out)
}

/// Print a prompt and read one line from stdin.
fn prompt(msg: &str) -> Result<String> {
    use std::io::Write;
    print!("{msg}");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading input")?;
    Ok(line)
}

/// Operational-mode `show`: live system state, VyOS-style. `target` optionally
/// scopes interface/route/neighbor output to one NIC.
/// Operational-mode `show` — a vtysh/VyOS-style word tree. Routing state comes
/// from the Wren daemon's control socket (`wren show …`); interface/ARP state
/// from iproute2; firewall/agent state from the config + journal.
fn show_op(args: &[String]) -> Result<()> {
    let ip = system::bin("ip");
    let v: Vec<&str> = args.iter().map(String::as_str).collect();
    match v.as_slice() {
        // System status (the bare default).
        [] | ["system"] | ["status"] => {
            println!("hostname:   {}", system::current_hostname());
            print!("firewall:   ");
            run_show(&system::bin("systemctl"), &["is-active", "velstra.service"])?;
            print!("routing:    ");
            run_show(&system::bin("systemctl"), &["is-active", "wren.service"])?;
            println!("interfaces:");
            run_show(&ip, &["-brief", "address", "show"])
        }
        // Config revision history (roadmap C21): `show system commit` lists the
        // archived revisions; `show system commit <N>` shows one in config syntax.
        ["system", "commit"] => show_revisions(),
        ["system", "commit", n] => show_revision(n),
        ["interfaces", rest @ ..] => {
            let mut a = vec!["-brief", "address", "show"];
            a.extend(rest);
            run_show(&ip, &a)
        }
        ["arp", rest @ ..] | ["neighbors", rest @ ..] => {
            let mut a = vec!["neighbor", "show"];
            if let Some(dev) = rest.first() {
                a.extend(["dev", dev]);
            }
            run_show(&ip, &a)
        }

        // IPv4/IPv6 routing — served by Wren's RIB; the kernel FIB is the
        // fallback when the daemon isn't reachable.
        ["ip", "route"] => wren_show_or(&["routes"], &ip, &["route", "show"]),
        ["ip", "route", proto] => {
            wren_show_or(&["routes", proto], &ip, &["route", "show", "proto", proto])
        }
        ["ipv6", "route"] => run_show(&ip, &["-6", "route", "show"]),

        // BGP: vtysh-flavoured spellings on top of wren's tree.
        ["ip", "bgp"] | ["ip", "bgp", "routes"] => wren_show(&["bgp", "routes"]),
        ["ip", "bgp", "summary"] | ["ip", "bgp", "neighbors"] => wren_show(&["bgp", "neighbors"]),
        ["ip", "bgp", rest @ ..] => wren_show_words("bgp", rest),

        // IGPs — proxied to the wren control socket.
        ["ip", "ospf", rest @ ..] => wren_show_words("ospf", rest),
        ["ipv6", "ospf3", rest @ ..] | ["ip", "ospf3", rest @ ..] => wren_show_words("ospf3", rest),
        ["ip", "rip"] => wren_show(&["rip"]),
        ["ipv6", "ripng"] => wren_show(&["ripng"]),
        ["isis", rest @ ..] => wren_show_words("isis", rest),
        ["babel", rest @ ..] => wren_show_words("babel", rest),
        ["vrrp"] => wren_show(&["vrrp"]),
        ["bfd", rest @ ..] => wren_show_words("bfd", rest),

        // Firewall / NAT.
        ["firewall"] => {
            print!("agent:      ");
            run_show(&system::bin("systemctl"), &["is-active", "velstra.service"])?;
            let path = std::path::Path::new(DEFAULT_CONFIG);
            if path.exists() {
                print!("{}", Appliance::load(path)?.summary());
            }
            Ok(())
        }
        ["firewall", "statistics" | "stats"] => show_firewall_stats(),
        ["firewall", "log"] => run_show(
            &system::bin("journalctl"),
            &["-u", "velstra.service", "-n", "50", "--no-pager"],
        ),
        ["nat"] => show_nat(),

        // IPsec VPN (roadmap C2): the security-association / connection state,
        // proxied to strongSwan's swanctl (run privileged — charon's vici socket
        // is root-only).
        ["vpn"] | ["vpn", "ipsec"] | ["vpn", "ipsec", "sas"] | ["vpn", "sas"] => {
            print!("{}", system::swanctl_show(&["--list-sas"])?);
            Ok(())
        }
        ["vpn", "ipsec", "connections" | "conns"] | ["vpn", "connections" | "conns"] => {
            print!("{}", system::swanctl_show(&["--list-conns"])?);
            Ok(())
        }

        // Configuration views.
        ["configuration", ..] => {
            let path = std::path::Path::new(DEFAULT_CONFIG);
            if path.exists() {
                print!("{}", session::render_appliance(&Appliance::load(path)?));
            } else {
                println!("no saved config at {DEFAULT_CONFIG} (run `configure` + `save`)");
            }
            Ok(())
        }
        ["config"] => {
            let path = std::path::Path::new(DEFAULT_CONFIG);
            if path.exists() {
                print!("{}", Appliance::load(path)?.summary());
            } else {
                println!("no saved config at {DEFAULT_CONFIG} (run `configure` + `save`)");
            }
            Ok(())
        }

        // Logs + versions.
        ["log"] | ["log", "velstra"] => run_show(
            &system::bin("journalctl"),
            &["-u", "velstra.service", "-n", "50", "--no-pager"],
        ),
        ["log", "wren"] => run_show(
            &system::bin("journalctl"),
            &["-u", "wren.service", "-n", "50", "--no-pager"],
        ),
        ["version"] => {
            println!("sentinel:   {}", env!("CARGO_PKG_VERSION"));
            print!("wren:       ");
            if run_checked(&system::bin("wren"), &["--version"]).is_err() {
                println!("(not available)");
            }
            print!("kernel:     ");
            run_show(&system::bin("uname"), &["-sr"])
        }

        // Back-compat spellings.
        ["routes", rest @ ..] => {
            let mut a = vec!["route", "show"];
            if let Some(dev) = rest.first() {
                a.extend(["dev", dev]);
            }
            run_show(&ip, &a)
        }

        other => anyhow::bail!(
            "unknown show path {:?}. Available:\n  \
             show [system]                     hostname, services, interfaces\n  \
             show interfaces [<if>]            live interfaces and addresses\n  \
             show arp [<if>]                   the ARP / neighbour table\n  \
             show ip route [<protocol>]        the routing table (wren RIB)\n  \
             show ipv6 route                   the IPv6 routing table\n  \
             show ip bgp [summary|neighbors|routes]\n  \
             show ip ospf [neighbors|interfaces|database]\n  \
             show ipv6 ospf3 [neighbors|interfaces]\n  \
             show ip rip | show ipv6 ripng\n  \
             show isis [neighbors|interfaces|database]\n  \
             show babel [neighbors|routes]\n  \
             show vrrp | show bfd [sessions]\n  \
             show firewall [statistics|log]    firewall summary / counters / log\n  \
             show nat                          NAT configuration\n  \
             show configuration                the saved config (config syntax)\n  \
             show log [velstra|wren]           recent service log\n  \
             show version",
            other.join(" ")
        ),
    }
}

/// Run a command and fail (with its stderr) on a non-zero exit — unlike
/// [`run_show`], which is best-effort display only.
fn run_checked(cmd: &str, args: &[&str]) -> Result<()> {
    let out = std::process::Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("running {cmd}"))?;
    print!("{}", String::from_utf8_lossy(&out.stdout));
    if !out.status.success() {
        anyhow::bail!(
            "{cmd} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// `wren show <words>` against the routing daemon's control socket.
fn wren_show(words: &[&str]) -> Result<()> {
    let wren = system::bin("wren");
    let mut a = vec!["show"];
    a.extend(words);
    run_checked(&wren, &a)
}

/// `wren show <first> <rest…>` with vtysh-style plural aliases mapped onto
/// wren's singular words (`neighbors` → `neighbors` is already wren's own).
fn wren_show_words(first: &str, rest: &[&str]) -> Result<()> {
    let mut words = vec![first];
    words.extend(rest);
    wren_show(&words)
}

/// Try Wren first (the richer view: RIB with protocol/metric detail); fall back
/// to iproute2 when the daemon isn't reachable.
fn wren_show_or(words: &[&str], fallback_cmd: &str, fallback_args: &[&str]) -> Result<()> {
    if wren_show(words).is_err() {
        eprintln!("(wren not reachable; showing the kernel table)");
        run_show(fallback_cmd, fallback_args)?;
    }
    Ok(())
}

/// The latest counter table the velstra agent dumped to its journal — the
/// firewall's live statistics (rx/pass/drop/reject/NAT counters + drop rate).
fn show_firewall_stats() -> Result<()> {
    let out = std::process::Command::new(system::bin("journalctl"))
        .args([
            "-u",
            "velstra.service",
            "-n",
            "400",
            "--no-pager",
            "-o",
            "cat",
        ])
        .output()
        .context("running journalctl")?;
    let text = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = text.lines().collect();
    match lines.iter().rposition(|l| l.contains("rx_packets")) {
        Some(start) => {
            for l in &lines[start..] {
                println!("{l}");
                if l.contains("drop rate") {
                    break;
                }
            }
            Ok(())
        }
        None => {
            println!("no counter dump in the recent agent log yet");
            Ok(())
        }
    }
}

/// `show system commit`: the archived config revisions, newest first.
fn show_revisions() -> Result<()> {
    let revs = archive::list_revisions(std::path::Path::new(DEFAULT_CONFIG));
    if revs.is_empty() {
        println!("no archived revisions yet (a revision is saved on each `save`)");
        return Ok(());
    }
    println!("{:>3}  saved", "rev");
    for r in &revs {
        println!("{:>3}  {}", r.index, r.timestamp());
    }
    println!("\n`show system commit <rev>` shows one; `rollback <rev>` reverts to it.");
    Ok(())
}

/// `show system commit <N>`: revision N rendered in config syntax.
fn show_revision(n: &str) -> Result<()> {
    let n: usize = n
        .parse()
        .map_err(|_| anyhow::anyhow!("revision must be a number (see `show system commit`)"))?;
    let toml = archive::read_revision(std::path::Path::new(DEFAULT_CONFIG), n)?;
    let appliance = Appliance::from_toml(&toml)?;
    print!("{}", session::render_appliance(&appliance));
    Ok(())
}

/// The NAT section of the saved config, summarized.
fn show_nat() -> Result<()> {
    let path = std::path::Path::new(DEFAULT_CONFIG);
    if !path.exists() {
        println!("no saved config at {DEFAULT_CONFIG} (run `configure` + `save`)");
        return Ok(());
    }
    let a = Appliance::load(path)?;
    if a.nat.is_empty() {
        println!("no NAT configured");
        return Ok(());
    }
    for s in &a.nat.source {
        println!("source {}: masquerade zone {}", s.name, s.zone);
    }
    for d in &a.nat.destination {
        println!(
            "destination {}: {} {:?}/{} -> {}",
            d.name, d.zone, d.proto, d.port, d.to
        );
    }
    Ok(())
}

/// Run a command and print its stdout, ignoring the exit code (for read-only
/// `show` output — e.g. `systemctl is-active` exits non-zero when inactive).
fn run_show(cmd: &str, args: &[&str]) -> Result<()> {
    let out = std::process::Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("running {cmd}"))?;
    print!("{}", String::from_utf8_lossy(&out.stdout));
    Ok(())
}

fn config_cmd(action: ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Init => {
            print!("{}", config::EXAMPLE);
            Ok(())
        }
        ConfigAction::Check { file } => {
            Appliance::load(&file)?;
            println!("{} is valid", file.display());
            Ok(())
        }
        ConfigAction::Show { file } => {
            print!("{}", Appliance::load(&file)?.summary());
            Ok(())
        }
        ConfigAction::Convert { file, to } => {
            let appliance = Appliance::load(&file)?;
            let out = match to {
                Format::Toml => appliance.to_toml()?,
                Format::Json => appliance.to_json()?,
            };
            print!("{out}");
            Ok(())
        }
    }
}

/// Connect to a Velstra controller and print its ports — a working first use of
/// the shared `velstra-proto` wire types.
async fn ports(endpoint: &str) -> Result<()> {
    let mut client = VelstraOrchestratorClient::connect(endpoint.to_string())
        .await
        .with_context(|| format!("connecting to controller {endpoint}"))?;
    let resp = client
        .list_ports(ListPortsRequest {})
        .await
        .context("ListPorts RPC")?
        .into_inner();

    println!("{:<22} {:>6}  {:<15} host", "id", "vni", "ip");
    for p in resp.ports {
        println!("{:<22} {:>6}  {:<15} {}", p.id, p.vni, p.ip, p.host);
    }
    Ok(())
}
