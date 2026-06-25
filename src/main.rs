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

mod compile;
mod config;
mod diff;
mod net;
mod repl;
mod session;
mod system;

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

/// What `sentinel show` displays.
#[derive(Copy, Clone, Debug, ValueEnum)]
enum ShowKind {
    /// Hostname, firewall state, and interfaces (the default).
    Status,
    /// Live network interfaces and their addresses.
    Interfaces,
    /// The kernel routing table.
    Routes,
    /// The ARP / neighbor table.
    Neighbors,
    /// The saved appliance configuration.
    Config,
    /// Recent firewall (velstra) log lines.
    Log,
    /// Sentinel and kernel version.
    Version,
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
    /// Show live system state (operational mode): status, interfaces, or config.
    Show {
        #[arg(value_enum, default_value_t = ShowKind::Status)]
        what: ShowKind,
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
        Command::Show { what } => show_cmd(what),
        Command::Config { action } => config_cmd(action),
        Command::Compile { file } => {
            let appliance = Appliance::load(&file)?;
            print!("{}", compile::compile(&appliance).to_toml()?);
            Ok(())
        }
        Command::ApplyBoot { config, out } => apply_boot(&config, &out),
        Command::Apply { file, out, reload } => apply(&file, &out, reload.as_deref()),
        Command::Ports { controller } => ports(&controller).await,
    }
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
    let act = repl::Apply {
        velstra_out: PathBuf::from(repl::DEFAULT_VELSTRA_OUT),
        unit: repl::DEFAULT_UNIT.to_string(),
        enabled: !no_apply,
    };

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
        rl.set_helper(Some(repl::ConfigCompleter));
        // VyOS/vtysh `?`: list the candidates here without inserting a literal
        // `?`. Bound to the same completion the Tab key triggers.
        rl.bind_sequence(
            rustyline::KeyEvent(rustyline::KeyCode::Char('?'), rustyline::Modifiers::NONE),
            rustyline::Cmd::Complete,
        );
        let user = std::env::var("USER").unwrap_or_else(|_| "admin".into());
        loop {
            // VyOS-style prompt, re-rendered each line: it reflects the LIVE
            // hostname (so a committed change shows immediately) and marks
            // uncommitted edits.
            let edit = if session.dirty() { "[edit] " } else { "" };
            let prompt = format!("{edit}{user}@{}# ", system::current_hostname());
            match rl.readline(&prompt) {
                Ok(line) => {
                    let _ = rl.add_history_entry(line.as_str());
                    if repl::exec_line(&mut session, &act, &line) {
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
        for line in stdin.lock().lines() {
            if repl::exec_line(&mut session, &act, &line.context("reading stdin")?) {
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
        let status = std::process::Command::new("systemctl")
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
fn apply_boot(config: &std::path::Path, out: &std::path::Path) -> Result<()> {
    let appliance = Appliance::load(config)?;

    let rendered = compile::compile(&appliance).to_toml()?;
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(out, &rendered).with_context(|| format!("writing {}", out.display()))?;

    system::set_hostname(&appliance.system.hostname)?;
    // Re-assert interface addressing from the saved config (networkd units),
    // so a reboot restores the live IPs the same way it restores the hostname.
    net::apply(&appliance)?;
    Ok(())
}

/// Operational-mode `show`: live system state, VyOS-style.
fn show_cmd(what: ShowKind) -> Result<()> {
    match what {
        ShowKind::Interfaces => run_show("ip", &["-brief", "address", "show"]),
        ShowKind::Routes => run_show("ip", &["route", "show"]),
        ShowKind::Neighbors => run_show("ip", &["neighbor", "show"]),
        ShowKind::Log => run_show(
            "journalctl",
            &["-u", "velstra.service", "-n", "50", "--no-pager"],
        ),
        ShowKind::Version => {
            println!("sentinel:   {}", env!("CARGO_PKG_VERSION"));
            print!("kernel:     ");
            run_show("uname", &["-sr"])
        }
        ShowKind::Config => {
            let path = std::path::Path::new(DEFAULT_CONFIG);
            if path.exists() {
                print!("{}", Appliance::load(path)?.summary());
            } else {
                println!("no saved config at {DEFAULT_CONFIG} (run `configure` + `save`)");
            }
            Ok(())
        }
        ShowKind::Status => {
            println!("hostname:   {}", system::current_hostname());
            print!("firewall:   ");
            run_show("systemctl", &["is-active", "velstra.service"])?;
            println!("interfaces:");
            run_show("ip", &["-brief", "address", "show"])
        }
    }
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
