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

mod aaa;
mod acme;
mod alert;
mod api;
mod archive;
mod capture;
mod clock;
mod compile;
mod config;
mod confirm;
mod diff;
mod domain;
mod feed;
mod grammar_walk;
mod identity;
mod ids;
mod image;
mod install;
mod installer_tui;
mod ipsec;
mod lockout;
mod lookup;
mod metrics;
mod net;
mod openapi;
mod openconnect;
mod passwd;
mod pki;
mod portal;
mod portmap;
mod proxy;
mod relay;
mod repl;
mod session;
mod system;
mod trace;
mod ui;
mod unlock;
mod update;
mod velstra;
mod webui;
mod wgkey;
mod wireless;
mod wren;
mod wwan;

use std::{
    io::{BufRead, IsTerminal},
    path::PathBuf,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use crate::session::{DEFAULT_CONFIG, Session};

/// The saved configuration a `show` reads.
///
/// `$SENTINEL_CONFIG` wins over the built-in path. The API sets it when it
/// spawns a `show`, because the API can be pointed at a different file with
/// `--config` — and a console that serves one configuration while every `show`
/// beside it reads another is a console showing somebody else's firewall. On the
/// appliance the two are the same file and nothing changes.
fn saved_config_path() -> std::path::PathBuf {
    std::env::var_os("SENTINEL_CONFIG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(DEFAULT_CONFIG))
}
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
    /// Where would this packet go, and which rule decides it — answered from
    /// the configuration, without sending anything.
    ///
    ///   sentinel trace --in lan0 tcp 10.0.0.5 93.184.216.34 443
    Trace {
        /// The link the packet arrives on.
        #[arg(long = "in")]
        in_interface: String,
        /// tcp, udp, icmp, icmpv6, …
        proto: String,
        /// Source address.
        src: std::net::IpAddr,
        /// Destination address, as the packet carries it (before any NAT).
        dst: std::net::IpAddr,
        /// Destination port; omit for a protocol without ports.
        #[arg(default_value_t = 0)]
        port: u16,
        /// The sender's hardware address, to consult MAC-group rules.
        #[arg(long = "src-mac")]
        src_mac: Option<String>,
        /// The ICMP/ICMPv6 type, to consult typed rules.
        #[arg(long = "icmp-type")]
        icmp_type: Option<u8>,
        /// The configuration to walk (default: the saved one).
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
        /// Print the answer as JSON rather than as text.
        #[arg(long)]
        json: bool,
    },
    /// Take one round of history samples. Run by the `sentinel-metrics` timer
    /// once a minute; not something to type, but not hidden either — a timer
    /// whose command cannot be run by hand is a timer nobody can debug.
    RecordMetrics,
    /// Capture packets on an interface (bounded: never more than 500 packets
    /// or 60 seconds, and nothing is written to disk).
    Capture {
        /// Interface to listen on.
        interface: String,
        /// pcap filter expression, e.g. `tcp port 443`.
        #[arg(default_value = "")]
        filter: String,
        /// Stop after this many packets.
        #[arg(long, default_value_t = 50)]
        count: u32,
        /// Stop after this long.
        #[arg(long, default_value_t = 10)]
        seconds: u32,
    },
    /// Clear operational state (Cisco/VyOS-style): `clear ids block <ip>`,
    /// `clear ids blocks`.
    Clear {
        /// The clear path words.
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
        /// Print the routing daemon's configuration instead of the firewall's.
        ///
        /// A commit renders both and writes them to `/run/sentinel`, but only the
        /// firewall half could be produced on demand — so the routing half could
        /// not be looked at, diffed, or handed to `wren check` without applying
        /// it first. Anything generated for another program to read should be
        /// printable without running that program.
        #[arg(long)]
        routing: bool,
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
    /// Second boot stage (after networkd): re-apply the runtime-only network
    /// state a reboot wipes — tc qdiscs (QoS), Multi-WAN routes, IPsec SAs. Used
    /// by the sentinel-boot-late service.
    ApplyBootLate {
        /// The active appliance config to apply.
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
    /// Ask the data plane agent's query socket and print the reply.
    ///
    /// Internal: `show` re-invokes this under sudo when the socket is not
    /// readable, so the socket stays root-only while the diagnostics still work
    /// for an operator account.
    #[command(hide = true)]
    AgentQuery {
        /// The query the agent understands (`stats`, `flows`, `top`, …).
        command: String,
        /// Which agent socket to ask (the data plane's by default).
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Re-apply the console keyboard, locale and timezone from the saved config.
    ///
    /// Its own command because systemd owns the virtual console and re-runs
    /// `systemd-vconsole-setup` whenever one appears — which resets the keymap
    /// to the image's. This runs after it, and again whenever it runs, so the
    /// layout an operator chose is the one that survives.
    ApplyConsole {
        /// The active appliance config to read the settings from.
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
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
        /// Encrypt the writable data partition with LUKS2. The passphrase is read
        /// from $SENTINEL_LUKS_PASSPHRASE, or prompted for. The box asks for it at
        /// each boot (`sentinel unlock`) before mounting /var/lib/sentinel.
        #[arg(long)]
        encrypt: bool,
        /// Ask the questions one at a time instead of drawing the full-screen
        /// installer. Chosen automatically on a console it cannot be drawn on.
        #[arg(long)]
        text: bool,
    },
    /// A/B update: write a new appliance image into the inactive slot and boot
    /// it next (auto-rollback to the current slot if it fails).
    ///
    /// `<target>` is either a local image/block-device path (written directly —
    /// the trusted-image form), or one of the signed-channel keywords (roadmap
    /// C13, using the saved `[update]` channel):
    ///
    /// * `check` — fetch + verify the signed release manifest and print the
    ///   available version (needs neither root nor the disk);
    /// * `install` — re-verify, fetch the image, verify its SHA-256, then write
    ///   the inactive slot (`--commit`).
    Update {
        /// A local image/block-device path, or `check` / `install`.
        target: Option<String>,
        /// Actually perform the (destructive-to-the-inactive-slot) update.
        #[arg(long)]
        commit: bool,
        /// Write a LOCAL image WITHOUT verifying its signature — the trusted-image
        /// escape hatch (a re-seal from the booted medium, an air-gapped block
        /// device). Loud and logged. Ignored by `check`/`install`, which always
        /// verify the channel.
        #[arg(long)]
        allow_unsigned: bool,
        /// The pinned Ed25519 release public key to verify a local image against
        /// (a PEM file, or `file:<path>`). Defaults to the saved `[update]`
        /// channel's `public-key`, then to a key baked into the image.
        #[arg(long)]
        pubkey: Option<String>,
    },
    /// Unlock the encrypted data partition (LUKS2). Run by
    /// `sentinel-unlock.service` before `/var/lib/sentinel` is mounted, not by
    /// hand — it prompts for the passphrase, or does nothing on a box whose data
    /// partition is not encrypted.
    Unlock,
    /// Revert the running system to the saved config. Invoked by the
    /// `commit-confirm` auto-rollback timer when its window expires; can also be
    /// run manually to drop an un-confirmed change immediately.
    ConfirmRollback {
        /// The saved config to revert to (the running/boot baseline).
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
    /// Deliver an alert for a failed unit (roadmap C23). Invoked by systemd's
    /// `OnFailure=` on the units Sentinel owns, not by hand — it reads the saved
    /// config's `[services.alerts]` and notifies every configured target.
    Alert {
        /// The systemd unit that failed (systemd passes `%n`).
        unit: String,
        /// The saved config holding the alert targets.
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
    /// Serve NAT-PMP (roadmap C18). Run by `sentinel-portmap.service` from the
    /// settings an apply rendered, not by hand.
    PortMap {
        /// The resolved settings the last apply rendered.
        #[arg(long, default_value = portmap::STATE_FILE)]
        state: PathBuf,
    },
    /// Serve the captive portal (roadmap C20). Run by
    /// `sentinel-portal.service` from the saved config, not by hand: it binds
    /// the appliance's own address in the gated zone, and the address only
    /// exists once the network is up.
    Portal {
        /// The resolved portal settings the last apply rendered.
        #[arg(long, default_value = portal::STATE_FILE)]
        state: PathBuf,
    },
    /// Follow the detector's alerts and block what they name (roadmap C11).
    /// Run by `sentinel-ids-watch.service` while `block-on-alert` is set, not by
    /// hand. Every block it asks for expires, and none survive an agent restart.
    IdsWatch,
    /// Carry UDP broadcasts between segments (roadmap C18). Run by
    /// `sentinel-broadcast-relay.service` from the config an apply rendered, not
    /// by hand.
    BroadcastRelay,
    /// Obtain or renew the ACME certificates the config declares (roadmap C19).
    /// Run by `sentinel-acme.service` from its timer, not by hand.
    AcmeRenew,
    /// List the ports a Velstra controller currently knows about.
    Ports {
        /// The controller's orchestrator/admin endpoint.
        #[arg(long, default_value = "http://127.0.0.1:50052")]
        controller: String,
    },
    /// Serve the REST management API (roadmap C12) over the same config model the
    /// CLI edits: `GET/PUT /api/v1/config`, `GET /api/v1/status`,
    /// `GET /api/v1/show/*`. Bearer-token auth; binds localhost by default (widen
    /// with `--listen 0.0.0.0:<port>`). A `PUT` validates + applies live + saves
    /// through the exact same paths as a CLI `commit`+`save`.
    Api {
        /// Address to bind (host:port). Localhost by default — the API is not
        /// exposed off-box unless you widen this.
        #[arg(long, default_value = api::DEFAULT_LISTEN)]
        listen: String,
        /// The running/boot config a GET reads and a PUT writes.
        #[arg(long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
        /// Validate + save on PUT, but don't apply to the running system
        /// (off-box). Mirrors `configure --no-apply`.
        #[arg(long)]
        no_apply: bool,
        /// The bearer-token file (generated 0600 if absent; overridden by
        /// `$SENTINEL_API_TOKEN`).
        #[arg(long, default_value = api::DEFAULT_TOKEN_PATH)]
        token_file: PathBuf,
        /// Print the API as OpenAPI 3.1 and exit, serving nothing — the same
        /// document a running box answers at `/api/v1/openapi.json`.
        #[arg(long)]
        openapi: bool,
    },
    /// Wake a host on the LAN: send a Wake-on-LAN magic packet to a MAC address
    /// (an operational action, not persistent config). Broadcasts on the given
    /// interface's link, or on all interfaces when none is named.
    Wol {
        /// The target MAC address (`52:54:00:12:34:56`).
        mac: String,
        /// Interface to send the magic packet out (defaults to a global
        /// broadcast on every link).
        interface: Option<String>,
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
    //
    // **For the commands that print and exit only.** A server that carries this
    // setting dies the first time a client hangs up while it is writing: the
    // default action for SIGPIPE is to terminate, and systemd counts SIGPIPE as
    // a *clean* exit — so the unit reads "Deactivated successfully", nothing is
    // logged, and `Restart=on-failure` does not fire. That is how the
    // management API disappeared mid-request after a `curl … | grep -q`, which
    // closes the pipe on the first match and drops the connection under the
    // server's feet. The long-running commands below put it back.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    match Cli::parse().command {
        Command::Configure { config, no_apply } => configure(&config, no_apply),
        Command::Show { args } => show_op(&args),
        Command::Trace {
            in_interface,
            proto,
            src,
            dst,
            port,
            src_mac,
            icmp_type,
            config,
            json,
        } => {
            let appliance = Appliance::load(&config)?;
            let answer = trace::trace(
                &appliance,
                &trace::Query {
                    in_interface,
                    proto,
                    src,
                    dst,
                    port,
                    src_mac,
                    icmp_type,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&answer)?);
            } else {
                print!("{}", answer.render());
            }
            Ok(())
        }
        Command::RecordMetrics => {
            let root = crate::metrics::dir();
            let root = root.as_path();
            let n = crate::metrics::sample_once(root, crate::aaa::unix_now())?;
            // Quiet on success: this runs every minute, and a line a minute in
            // the journal is a log nobody reads and a disk that fills.
            if n == 0 {
                eprintln!("warning: no counters could be sampled");
            }
            Ok(())
        }
        Command::Capture {
            interface,
            filter,
            count,
            seconds,
        } => {
            let c = capture::Capture::new(&interface, &filter, count, seconds)?;
            print!("{}", capture::run(&c)?);
            Ok(())
        }
        Command::Clear { args } => clear_op(&args),
        Command::Config { action } => config_cmd(action),
        Command::Compile { file, routing } => {
            let appliance = Appliance::load(&file)?;
            if routing {
                print!("{}", wren::compile_wren(&appliance).to_toml()?);
            } else {
                print!("{}", compile::compile(&appliance).to_toml()?);
            }
            Ok(())
        }
        Command::Install {
            targets,
            raid,
            source,
            commit,
            encrypt,
            text,
        } => install_cmd(&targets, raid.into(), source, commit, encrypt, text),
        Command::Unlock => unlock::run(),
        Command::Update {
            target,
            commit,
            allow_unsigned,
            pubkey,
        } => update_cmd(target.as_deref(), commit, allow_unsigned, pubkey.as_deref()),
        Command::ApplyBoot {
            config,
            out,
            wren_out,
        } => apply_boot(&config, &out, &wren_out),
        Command::ApplyBootLate { config } => apply_boot_late(&config),
        Command::AgentQuery { command, socket } => {
            let path = socket.unwrap_or_else(|| PathBuf::from(velstra::SOCKET));
            print!("{}", velstra::query_at(&path, &command)?);
            Ok(())
        }
        Command::ApplyConsole { config } => net::apply_console_settings(&Appliance::load(&config)?),
        Command::Apply { file, out, reload } => apply(&file, &out, reload.as_deref()),
        Command::ConfirmRollback { config } => confirm_rollback(&config),
        Command::Alert { unit, config } => alert_unit(&unit, &config),
        Command::IdsWatch => {
            system::ignore_sigpipe();
            ids::watch()
        }
        Command::BroadcastRelay => {
            system::ignore_sigpipe();
            relay::run()
        }
        Command::Portal { state } => {
            system::ignore_sigpipe();
            serve_portal(&state).await
        }
        Command::PortMap { state } => serve_portmap(&state),
        Command::AcmeRenew => acme::run(),
        Command::Ports { controller } => ports(&controller).await,
        Command::Api {
            listen,
            config,
            no_apply,
            token_file,
            openapi,
        } => {
            if openapi {
                print!("{}", openapi::pretty());
                return Ok(());
            }
            api::serve(&listen, &config, live_apply(!no_apply), &token_file).await
        }
        Command::Wol { mac, interface } => wol(&mac, interface.as_deref()),
    }
}

/// `sentinel portal`: serve the captive portal the saved config describes.
///
/// A config with no portal is **not** an error — the unit is enabled from the
/// same config it reads, and a race between the two should not mark a service
/// failed on an appliance that simply has no guest zone.
async fn serve_portal(state: &std::path::Path) -> Result<()> {
    // A missing file is **not** an error: the unit and the file it reads are
    // installed by the same apply, and a race between the two should not mark a
    // service failed on an appliance that simply has no guest zone.
    if !state.exists() {
        eprintln!("no captive portal is configured; nothing to serve");
        return Ok(());
    }
    portal::serve(portal::load(state)?).await
}

/// `sentinel port-map`: serve NAT-PMP from the settings an apply rendered.
///
/// A missing file is not an error, for the same reason it is not one for the
/// portal: the unit and the file it reads are installed by the same apply.
fn serve_portmap(state: &std::path::Path) -> Result<()> {
    if !state.exists() {
        eprintln!("no port mapping is configured; nothing to serve");
        return Ok(());
    }
    portmap::serve(&portmap::load(state)?)
}

/// `sentinel wol <mac> [interface]`: send a Wake-on-LAN magic packet. The packet
/// is six `0xFF` bytes followed by the target MAC repeated 16 times (the standard
/// AMD magic-packet layout), broadcast to UDP port 9. With an interface given we
/// bind the socket to that link (`SO_BINDTODEVICE`) so the frame egresses there;
/// otherwise it goes out via the global broadcast route.
fn wol(mac: &str, interface: Option<&str>) -> Result<()> {
    use std::net::UdpSocket;

    // Parse the six hex octets (the same shape sentinel validates elsewhere).
    let octets: Vec<u8> = mac
        .split(':')
        .map(|o| u8::from_str_radix(o, 16))
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| anyhow::anyhow!("invalid MAC {mac:?}: expected six hex octets"))?;
    if octets.len() != 6 {
        anyhow::bail!("invalid MAC {mac:?}: expected six colon-separated hex octets");
    }

    // Magic packet: 6×0xFF sync stream, then the MAC repeated 16 times.
    let mut packet = vec![0xFFu8; 6];
    for _ in 0..16 {
        packet.extend_from_slice(&octets);
    }

    let sock = UdpSocket::bind("0.0.0.0:0").context("opening a UDP socket")?;
    sock.set_broadcast(true).context("enabling broadcast")?;
    if let Some(dev) = interface {
        bind_to_device(&sock, dev)?;
    }
    sock.send_to(&packet, "255.255.255.255:9")
        .context("sending the magic packet")?;
    match interface {
        Some(dev) => println!("sent Wake-on-LAN magic packet to {mac} on {dev}"),
        None => println!("sent Wake-on-LAN magic packet to {mac}"),
    }
    Ok(())
}

/// Pin a socket to a link with `SO_BINDTODEVICE` so a broadcast egresses exactly
/// that interface (needs CAP_NET_RAW/root — the appliance runs `wol` privileged).
#[cfg(target_os = "linux")]
fn bind_to_device(sock: &std::net::UdpSocket, dev: &str) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = sock.as_raw_fd();
    let cstr = std::ffi::CString::new(dev).context("interface name")?;
    // SAFETY: `setsockopt` reads `cstr.len()` bytes from a valid pointer into a
    // live socket fd; the buffer outlives the call.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            cstr.as_ptr() as *const libc::c_void,
            cstr.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("binding the Wake-on-LAN socket to {dev}"));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn bind_to_device(_sock: &std::net::UdpSocket, _dev: &str) -> Result<()> {
    anyhow::bail!("binding a Wake-on-LAN socket to an interface is only supported on Linux")
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
        eprintln!("{}", ui::bold("Sentinel configuration mode"));
        eprintln!(
            "{}",
            ui::dim(
                "  help: commands · Tab or ?: complete · commit: apply live · \
                 save: persist · exit: leave"
            )
        );
        if !act.enabled {
            eprintln!(
                "{}",
                ui::yellow("  (off-box: commit validates + saves only; not applying)")
            );
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
                h.set_names(repl::DynNames {
                    interfaces: session.interface_names(),
                    rules: session.rule_names(),
                    zones: session.zone_names(),
                    load_balancers: session.load_balancer_names(),
                    syslog_targets: session.syslog_target_names(),
                    nat_source: session.nat_source_names(),
                    nat_destination: session.nat_destination_names(),
                    nat_npt66: session.nat_npt66_names(),
                    address_groups: session.address_group_names(),
                    port_groups: session.port_group_names(),
                    domain_groups: session.domain_group_names(),
                    filters: session.filter_names(),
                    vrfs: session.vrf_names(),
                    ipsec: session.ipsec_names(),
                    pki_cas: session.pki_ca_names(),
                    pki_certificates: session.pki_certificate_names(),
                    wireguard: session.wireguard_names(),
                    reverse_proxy: session.reverse_proxy_names(),
                    broadcast_relay: session.broadcast_relay_names(),
                    prefix_lists: session.prefix_list_names(),
                    update_channels: session.update_channel_names(),
                });
                h.set_context(&ctx);
            }
            // VyOS/JunOS-style prompt, re-rendered each line: the edit context
            // appears as its own dimmed `[edit …]` banner line above the prompt
            // (so the prompt itself stays short at any depth), the hostname is
            // the LIVE one (a committed change shows immediately), and a `*`
            // marks uncommitted edits (Nokia SR-OS style).
            if !ctx.is_empty() {
                eprintln!("{}", ui::dim(&repl::edit_banner(&ctx)));
            }
            let dirty = if session.dirty() { "*" } else { "" };
            let prompt = format!("{user}@{}{dirty}# ", system::current_hostname());
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
        // Answer for what was refused. Scripts and the REST API judge by exit
        // status, and printing an error while exiting 0 told them a change had
        // been made that had not.
        let failed = repl::failed_lines();
        if failed > 0 {
            anyhow::bail!(
                "{failed} line(s) were refused — see the errors above; nothing they \
                 asked for was applied"
            );
        }
    }
    Ok(())
}

/// Compile the appliance config, atomically install the Velstra agent config at
/// `out`, and (if given) reload the systemd `unit` running the data plane.
fn apply(file: &std::path::Path, out: &std::path::Path, reload: Option<&str>) -> Result<()> {
    // Resolve domain groups before compiling: the compiler only knows addresses,
    // and this is also the periodic refresh — the timer re-runs exactly this.
    let appliance = identity::with_resolved(&feed::with_fetched(&domain::with_resolved(
        &Appliance::load(file)?,
    )));
    // This is the path `sentinel-fwsched.service` runs at every window
    // boundary, so it is where a schedule is decided by the clock. Saying so
    // here puts it in the journal beside the re-apply that acted on it, which
    // is where somebody asking "why did that port not open" will be looking.
    if let Some(w) = clock::schedule_warning(&appliance) {
        eprintln!("warning: {w}");
    }
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
    // Serialise against a `commit`/API `PUT` that lands mid-boot: this stage
    // stages through the same fixed temp names, so an interleaved writer could
    // corrupt a networkd unit or velstra.toml. Best-effort, held for the stage.
    let _lock = system::apply_lock();
    // load_lenient, not load: this is the boot-time apply of the saved config,
    // and the one place an unknown key must not keep the box from coming up. A
    // rollback to an older image whose saved config carries a newer field would
    // otherwise boot unconfigured. `config check` and every interactive path
    // stay strict — see Appliance::load_lenient.
    let appliance = identity::with_resolved(&feed::with_fetched(&domain::with_resolved(
        &Appliance::load_lenient(config)?,
    )));

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
    // Re-assert interface addressing from the saved config (networkd units) +
    // the co-service drop-ins, so a reboot restores the live config the same way
    // it restores the hostname. `ApplyMode::Boot` = render ONLY: this runs BEFORE
    // networkd, so it must not touch a single unit (networkd reads the units on
    // its own start; a `networkctl`/`systemctl restart` here would deadlock the
    // boot). The link-dependent runtime state (tc qdiscs, Multi-WAN routes, IPsec
    // SAs) — which a file can't express — is deferred to `apply-boot-late`, run
    // after networkd has brought the links up.
    net::apply_persistent(&appliance, net::ApplyMode::Boot)?;
    Ok(())
}

/// Second boot stage: after networkd has brought the links up, apply the
/// runtime-only network state that a reboot wipes and that could not be applied
/// before the links existed — tc egress qdiscs (QoS), the Multi-WAN policy
/// routes, and the IPsec SAs. Run by the `sentinel-boot-late` service.
fn apply_boot_late(config: &std::path::Path) -> Result<()> {
    // Lenient for the same reason as apply_boot: the second boot stage applies
    // the same saved config, and must survive an unknown key just the same.
    let _lock = system::apply_lock();
    let appliance = Appliance::load_lenient(config)?;
    net::apply_link_runtime(&appliance)
}

/// `sentinel install`: with no target on a terminal, run the interactive wizard
/// (pick mode + disks); with target(s), validate the selection and show the
/// plan. Destructive execution happens on `--commit` (or after the wizard's
/// confirmation).
/// Dispatch `sentinel update <target> [--commit]`. `target` is a local
/// image/block-device path (written directly by the existing slot-writer), or a
/// signed-channel keyword driving roadmap C13's authenticity gate against the
/// saved `[update]` channel.
fn update_cmd(
    target: Option<&str>,
    commit: bool,
    allow_unsigned: bool,
    pubkey: Option<&str>,
) -> Result<()> {
    match target {
        None => anyhow::bail!(
            "usage: sentinel update <image>|check|install [--commit] [--allow-unsigned]\n\
             (`check`/`install` use the saved [update] channel; a path writes that image directly)"
        ),
        Some("check") => {
            let chan = load_update_channel()?;
            // Every outcome is remembered, success and refusal alike — `show
            // subscription` reports the last contact as it happened, not as
            // one would hope it went.
            match update::check(&chan) {
                Ok(manifest) => {
                    update::record_status(
                        &chan,
                        &format!("release {} available", manifest.version),
                    );
                    println!(
                        "channel {:?}: update available: {} (image {}, sha256 {})",
                        chan.label(),
                        manifest.version,
                        manifest.image,
                        manifest.sha256
                    );
                    Ok(())
                }
                Err(e) => {
                    update::record_status(&chan, &format!("refused: {e:#}"));
                    Err(e)
                }
            }
        }
        Some("install") => {
            let chan = load_update_channel()?;
            match install::update_from_channel(&chan, commit) {
                Ok(()) => {
                    update::record_status(
                        &chan,
                        if commit {
                            "image verified and written to the inactive slot"
                        } else {
                            "image verified (dry-run; nothing written)"
                        },
                    );
                    Ok(())
                }
                Err(e) => {
                    update::record_status(&chan, &format!("refused: {e:#}"));
                    Err(e)
                }
            }
        }
        // Any other value is a local image/block-device path.
        Some(path) => update_local(path, commit, allow_unsigned, pubkey),
    }
}

/// Write a LOCAL image to the inactive slot, verifying its signature FIRST unless
/// the operator explicitly opts out.
///
/// Verification is now the default for a local image too — the local path used to
/// write anything given to it, which was the supply-chain hole. A detached
/// `<image>.sig` is checked against a pinned Ed25519 key (the `--pubkey` flag, the
/// saved channel's `public-key`, or a key baked into the image) before a single
/// byte reaches the slot-writer. `--allow-unsigned` keeps the old escape hatch for
/// a re-seal or an air-gapped block device — loud and logged, never silent.
fn update_local(
    path: &str,
    commit: bool,
    allow_unsigned: bool,
    pubkey: Option<&str>,
) -> Result<()> {
    let image = std::path::Path::new(path);
    if allow_unsigned {
        eprintln!(
            "warning: --allow-unsigned: writing {path} to the inactive slot WITHOUT signature \
             verification. A local image/device is trusted exactly as given; make sure you \
             trust its source."
        );
        return install::update(image, commit);
    }
    let key = local_update_pubkey(pubkey).ok_or_else(|| {
        anyhow::anyhow!(
            "refusing to write an unverified image: no release public key to verify against.\n\
             Pin one with --pubkey <pem|file:path>, set an [update] channel public-key and save, \
             or place the release key at {DEFAULT_RELEASE_KEY}. For a trusted local image/device, \
             pass --allow-unsigned."
        )
    })?;
    update::verify_local_image(image, &key)?;
    eprintln!("signature verified against the pinned release key");
    install::update(image, commit)
}

/// Where a local image's signing key is looked for, in order of precedence:
/// the explicit `--pubkey`, then the saved `[update]` channel's pinned key, then
/// a release key baked into the image at [`DEFAULT_RELEASE_KEY`].
fn local_update_pubkey(flag: Option<&str>) -> Option<String> {
    if let Some(k) = flag {
        return Some(k.to_string());
    }
    if let Ok(appliance) = Appliance::load(saved_config_path().as_path()) {
        // The ACTIVE channel's key, resolved the same way `update check` would
        // — a box subscribed to a channel verifies local images against that
        // channel's key, not against whichever entry happens to come first.
        if let Some(key) = appliance
            .update
            .and_then(|u| u.active().ok())
            .map(|c| c.public_key)
            .filter(|k| !k.trim().is_empty())
        {
            return Some(key);
        }
    }
    if std::path::Path::new(DEFAULT_RELEASE_KEY).exists() {
        return Some(format!("file:{DEFAULT_RELEASE_KEY}"));
    }
    None
}

/// The default on-image location of the release-signing public key, used to
/// verify a local image when no channel is pinned and no `--pubkey` is given.
const DEFAULT_RELEASE_KEY: &str = "/etc/sentinel/release.pem";

/// Load the saved appliance's ACTIVE `[update]` channel — the selected named
/// channel, or the legacy bare `url` as the unnamed default — or bail with what
/// exactly is missing.
fn load_update_channel() -> Result<config::UpdateChannel> {
    let saved = saved_config_path();
    let path = saved.as_path();
    let appliance = Appliance::load(path)?;
    appliance
        .update
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no [update] channel configured (set update url + public-key, then save)"
            )
        })?
        .active()
}

/// `show subscription` — the update channels and the entitlement state, as
/// facts. The key is masked to its tail (`…a1b2`) so two keys can be told apart
/// without either ever appearing; the last check is whatever `update
/// check`/`install` recorded, verbatim; and expiry is reported as not reported,
/// because the channel server has no contract for stating one yet — a date this
/// box computed itself would be a guess, and this view does not guess.
fn show_subscription() -> Result<()> {
    let saved = saved_config_path();
    let appliance = Appliance::load(saved.as_path())?;
    let Some(up) = &appliance.update else {
        println!(
            "no update channel configured — set update url <https-url> + public-key, or \
             define a named one: set update channel <name> url <https-url>"
        );
        return Ok(());
    };

    // Every channel this box knows, active one marked — the list is how an
    // operator sees what `set update channel <name>` could switch to.
    if !up.channels.is_empty() {
        println!("channels:");
        for c in &up.channels {
            let active = if up.channel.as_deref() == Some(c.name.as_str()) {
                " (active)"
            } else {
                ""
            };
            println!("  {}{active}", c.name);
        }
    }
    if let Some(url) = &up.url {
        let active = if up.channel.is_none() {
            " (active)"
        } else {
            ""
        };
        println!("default channel:{active} {url}");
    }

    match up.active() {
        Ok(chan) => {
            println!("active channel: {}", chan.label());
            println!("url:            {}", chan.url);
            match &chan.subscription_key {
                Some(key) => println!(
                    "subscription:   key configured (ends {})",
                    update::mask_key(key)
                ),
                None => println!("subscription:   no key configured"),
            }
            match update::read_status() {
                // Only a record about THIS channel is this channel's history —
                // a check against yesterday's channel says nothing about today's.
                Some(st) if st.channel == chan.label() => println!(
                    "last check:     {} — {}",
                    crate::archive::fmt_utc(st.checked),
                    st.outcome
                ),
                _ => println!("last check:     never (run `sentinel update check`)"),
            }
            if chan.subscription_key.is_some() {
                println!("expiry:         not reported by the channel server — nothing is assumed");
            }
        }
        Err(e) => println!("active channel: none — {e:#}"),
    }
    Ok(())
}

fn install_cmd(
    targets: &[String],
    raid: install::Raid,
    source: Option<PathBuf>,
    commit: bool,
    encrypt: bool,
    force_text: bool,
) -> Result<()> {
    // A bundled source image may come from the flag or the environment (the ISO
    // sets $SENTINEL_INSTALL_SOURCE).
    let source = source.or_else(|| std::env::var_os("SENTINEL_INSTALL_SOURCE").map(PathBuf::from));
    let disks = install::discover_disks()?;

    if targets.is_empty() {
        if std::io::stdin().is_terminal() {
            return interactive_install(&disks, source.as_deref(), force_text);
        }
        // Non-interactive with no target: just list candidates.
        list_disks(&disks);
        return Ok(());
    }

    let chosen = install::plan_targets(&disks, targets, raid)?;
    print_plan(&chosen, raid);
    if encrypt {
        println!("data partition: LUKS2 encrypted (unlocked at each boot)");
    }
    if !commit {
        println!("\n(dry-run — re-run with --commit to write. THIS ERASES THE TARGET DISK(S).)");
        return Ok(());
    }
    // Resolve the passphrase BEFORE erasing anything: a mistyped/absent one must
    // fail while the target disk is still intact, not after it has been wiped.
    let crypto = if encrypt {
        install::Crypto::Luks {
            passphrase: resolve_luks_passphrase()?,
        }
    } else {
        install::Crypto::None
    };
    install::execute(&chosen, raid, source.as_deref(), &crypto)
}

/// The LUKS passphrase for an encrypted install: from $SENTINEL_LUKS_PASSPHRASE
/// (scripted/automated installs), else prompted for twice on a terminal and
/// checked to match. Never defaulted — an encrypted volume with a guessable or
/// empty passphrase is worse than an honest plaintext one.
fn resolve_luks_passphrase() -> Result<String> {
    if let Some(p) = std::env::var_os("SENTINEL_LUKS_PASSPHRASE") {
        let p = p.to_string_lossy().into_owned();
        if p.is_empty() {
            anyhow::bail!("$SENTINEL_LUKS_PASSPHRASE is set but empty");
        }
        return Ok(p);
    }
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "--encrypt needs a passphrase: set $SENTINEL_LUKS_PASSPHRASE (no terminal to prompt on)"
        );
    }
    let first = prompt_secret("Passphrase for the encrypted data partition: ")?;
    if first.is_empty() {
        anyhow::bail!("an encrypted install needs a non-empty passphrase");
    }
    let again = prompt_secret("Repeat the passphrase: ")?;
    if first != again {
        anyhow::bail!("the passphrases did not match");
    }
    Ok(first)
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

/// Ask a question with a default; an empty answer takes the default.
fn ask(msg: &str, default: &str) -> Result<String> {
    let shown = if default.is_empty() {
        format!("{msg}: ")
    } else {
        format!("{msg} [{default}]: ")
    };
    let got = prompt(&shown)?;
    let got = got.trim();
    Ok(if got.is_empty() {
        default.to_string()
    } else {
        got.to_string()
    })
}

/// Ask for a secret: prompt, read one line, but do not echo what is typed.
///
/// An install is done over whatever console is at hand — a serial line, an IPMI
/// session, someone's laptop over a shoulder — and an echoed admin password
/// stays in that scrollback long after the install is finished. `getpass(3)`
/// behaviour, done by hand so it costs no dependency: drop `ECHO` for the read
/// and put the terminal back exactly as it was, including when the read fails.
fn prompt_secret(msg: &str) -> Result<String> {
    use std::io::Write;
    print!("{msg}");
    std::io::stdout().flush().ok();

    let fd = libc::STDIN_FILENO;
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    // Not a terminal (a piped answer file) — there is no echo to turn off.
    let is_term = unsafe { libc::tcgetattr(fd, &mut saved) } == 0;
    if is_term {
        let mut quiet = saved;
        quiet.c_lflag &= !libc::ECHO;
        // TCSANOW, not TCSAFLUSH: flushing would discard input that arrived
        // between the prompt and this call, which is precisely the answer.
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) };
    }

    let mut line = String::new();
    let read = std::io::stdin().read_line(&mut line);

    if is_term {
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved) };
        // The newline the user typed was swallowed with the echo; put it back so
        // the next prompt starts on its own line.
        println!();
    }
    read.context("reading input")?;
    Ok(line)
}

/// Ask a yes/no question.
fn ask_yes(msg: &str, default_yes: bool) -> Result<bool> {
    let d = if default_yes { "Y/n" } else { "y/N" };
    let got = prompt(&format!("{msg} [{d}]: "))?;
    Ok(match got.trim().to_ascii_lowercase().as_str() {
        "" => default_yes,
        "y" | "yes" | "j" | "ja" => true,
        _ => false,
    })
}

/// The first settings the wizard collects, as `set …` lines.
///
/// Built as CLI lines and replayed through the real command parser rather than
/// assembled into a document here. That is the whole reason this is safe to add:
/// every value the wizard collects is judged by the same grammar and the same
/// `validate()` an operator's own `configure` session goes through, so the
/// wizard cannot invent a configuration the appliance would refuse — and it
/// cannot drift from the CLI as either one changes.
///
/// Both front ends — the full-screen installer and the line-by-line one — end
/// here, so the two cannot produce different configurations from the same
/// answers.
fn wizard_lines_from(a: &installer_tui::Answers) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    out.push(format!("set system keyboard {}", a.keyboard));
    out.push(format!("set system locale {}", a.locale));
    out.push(format!("set system timezone {}", a.timezone));
    out.push(format!("set system hostname {}", a.hostname));
    out.push(format!(
        "set system login {} password {}",
        a.username, a.password
    ));
    if !a.ssh_key.is_empty() {
        out.push(format!(
            "set system login {} public-key {}",
            a.username, a.ssh_key
        ));
    }
    // Without a permission group the account can log in and can do nothing in
    // the web console — it is refused with "no management access". The installer
    // creates the box's only account; leaving it unable to manage the box is not
    // a decision anyone made on purpose.
    out.push("set system group operators permission read-write".into());
    out.push(format!("set system login {} group operators", a.username));
    out.push("set services ssh port 22".into());
    // The appliance is key-only by design, which is right — but the wizard asks
    // for a password and only *offers* a key. An operator who has no key to
    // paste at an install console (the common case: they are standing at the
    // machine) would get a box that refuses the very password it just made them
    // choose, and no way in but the console. So: a key was given, keep key-only;
    // no key, the password has to work or the account is decorative.
    if a.ssh_key.is_empty() {
        out.push("set services ssh password-authentication true".into());
    }

    // The network step is optional. Left alone, the installer writes no
    // interface at all and the box is set up from the console.
    let configured: Vec<&installer_tui::NicPlan> = a.nics.iter().filter(|n| n.configure).collect();
    for nic in &configured {
        out.push(format!("set interface {} zone {}", nic.name, nic.zone));
        out.push(format!(
            "set interface {} address {}",
            nic.name, nic.address
        ));
        if nic.address != "dhcp" && !nic.gateway.is_empty() {
            out.push(format!(
                "set protocols static 0.0.0.0/0 via {}",
                nic.gateway
            ));
        }
    }

    // The installer sets no firewall policy — that is the operator's to decide,
    // and a firewall appliance that ships wide open because of its own installer
    // would be the worst possible default. The one exception is asked for
    // explicitly: the appliance denies inbound by default, so an address
    // configured above would otherwise leave the box installed and unreachable.
    // One rule, one port, one zone.
    if a.permit_ssh {
        let mut zones: Vec<&str> = configured.iter().map(|n| n.zone.as_str()).collect();
        zones.sort_unstable();
        zones.dedup();
        for zone in zones {
            let rule = format!("install-ssh-{zone}");
            out.push(format!("set firewall rule {rule} from {zone}"));
            out.push(format!("set firewall rule {rule} proto tcp"));
            out.push(format!("set firewall rule {rule} port 22"));
            out.push(format!("set firewall rule {rule} action accept"));
        }
    }
    out
}

/// The line-by-line front end: the same questions, asked one at a time.
///
/// Kept for the consoles the full-screen installer cannot be drawn on — a
/// terminal too small, a dumb TTY, a serial line that mangles the alternate
/// screen — and reachable on purpose with `--text`.
fn collect_text(
    disks: &[install::Disk],
    nics: &[String],
) -> Result<Option<installer_tui::Answers>> {
    list_disks(disks);

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
    let picks = resolve_picks(disks, pick.trim())?;

    println!("\n── Console and locale ──");
    // Keyboard first, deliberately: everything typed from here on goes through
    // it, including the account password below.
    let keyboard = ask("Console keyboard layout", "us")?;
    let sample = prompt("Type `hello-123` to check the layout (or Enter to skip): ")?;
    let sample = sample.trim();
    if !sample.is_empty() && sample != "hello-123" {
        println!("  note: that came out as {sample:?} — the layout may not be what you expect.");
        if !ask_yes("Keep this layout anyway?", false)? {
            anyhow::bail!("aborted at the keyboard check");
        }
    }
    let locale = ask("Locale", "en_US.UTF-8")?;
    let timezone = ask("Timezone", "UTC")?;

    // Encryption comes after the keyboard check, deliberately: the passphrase is
    // typed here, and a passphrase entered on a layout nobody verified is a box
    // that cannot be unlocked.
    println!("\n── Disk encryption ──");
    println!("Only the writable data partition is encrypted; the read-only system store is");
    println!("already integrity-sealed. The box asks for the passphrase at every boot —");
    println!("there is no unattended unlock yet, so keep it somewhere you can reach.");
    let (encrypt, passphrase) = if ask_yes("Encrypt the data partition (LUKS2)?", false)? {
        let first = prompt_secret("Passphrase for the encrypted data partition: ")?;
        let first = first.trim_end_matches(['\n', '\r']).to_string();
        if first.is_empty() {
            anyhow::bail!("an encrypted install needs a non-empty passphrase");
        }
        let again = prompt_secret("Repeat the passphrase: ")?;
        let again = again.trim_end_matches(['\n', '\r']).to_string();
        if first != again {
            anyhow::bail!("the passphrases did not match");
        }
        (true, first)
    } else {
        (false, String::new())
    };

    println!("\n── Identity ──");
    let hostname = ask("Hostname", "sentinel")?;

    println!("\n── First account ──");
    let username = ask("Username", "admin")?;
    let password = prompt_secret("Password: ")?;
    let password = password.trim().to_string();
    if password.len() < 8 {
        anyhow::bail!("the password must be at least 8 characters");
    }
    let ssh_key = ask("SSH public key (Enter for none)", "")?;

    println!("\n── Network (optional) ──");
    println!("Only needed if the box should be reachable over SSH right after the");
    println!("reboot; otherwise skip this and set the network up from the console.");
    let mut plans: Vec<installer_tui::NicPlan> = Vec::new();
    let mut permit_ssh = false;
    let want_net = !nics.is_empty() && ask_yes("Configure an interface now?", false)?;
    for (i, nic) in nics.iter().enumerate() {
        let configure = want_net && ask_yes(&format!("Configure {nic}?"), i == 0)?;
        if !configure {
            plans.push(installer_tui::NicPlan {
                name: nic.clone(),
                configure: false,
                zone: "wan".into(),
                address: "dhcp".into(),
                gateway: String::new(),
            });
            continue;
        }
        let zone = ask(&format!("  {nic} zone"), "wan")?;
        let address = ask(&format!("  {nic} address (CIDR or `dhcp`)"), "dhcp")?;
        let gateway = if address == "dhcp" {
            String::new()
        } else {
            ask("  default gateway (Enter for none)", "")?
        };
        plans.push(installer_tui::NicPlan {
            name: nic.clone(),
            configure: true,
            zone,
            address,
            gateway,
        });
    }
    if plans.iter().any(|n| n.configure) {
        // Without this the box comes up installed and unreachable: the appliance
        // denies inbound by default, so the address just configured would buy
        // nothing. It is the only firewall setting the installer makes.
        permit_ssh = ask_yes("Permit SSH from that zone (one rule, port 22 only)?", true)?;
    }

    Ok(Some(installer_tui::Answers {
        raid,
        picks,
        keyboard,
        locale,
        timezone,
        hostname,
        username,
        password,
        ssh_key,
        encrypt,
        passphrase,
        nics: plans,
        permit_ssh,
    }))
}

/// Turn the collected lines into a validated appliance document.
fn wizard_config(lines: &[String]) -> Result<String> {
    let dir = std::env::temp_dir().join(format!("sentinel-wizard-{}", std::process::id()));
    std::fs::create_dir_all(&dir).context("creating the wizard scratch directory")?;
    let path = dir.join("appliance.toml");
    let _ = std::fs::remove_file(&path);
    let mut session = session::Session::load(&path)?;
    let act = repl::Apply::off();
    let mut ctx: Vec<String> = Vec::new();
    for line in lines {
        if repl::exec_line(&mut session, &act, &mut ctx, line) {
            anyhow::bail!("the wizard ended the session at {line:?}");
        }
    }
    // `commit` is what runs `validate()`. A wizard that wrote an invalid
    // document would produce a box that will not boot into its own config.
    let appliance = session.commit()?;
    let toml = appliance.to_toml()?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(toml)
}

/// The guided installer: collect the first settings, pick the disks, confirm,
/// install, and seed the configuration so the box comes up reachable.
///
/// Two front ends, one set of answers. The full-screen one is the default; the
/// line-by-line one takes over on a console it cannot be drawn on, so an install
/// is never blocked by the prettier of the two.
fn interactive_install(
    disks: &[install::Disk],
    source: Option<&std::path::Path>,
    force_text: bool,
) -> Result<()> {
    if disks.is_empty() {
        list_disks(disks);
        return Ok(());
    }
    let nics = system::discover_interfaces();

    // The full-screen installer confirms on its own review page; the
    // line-by-line one prints the plan and asks for YES below.
    // Say why, when it is not the operator's choice. A silent fallback looks
    // exactly like the full-screen installer being missing, which is a long way
    // from the truth and takes a long time to find out.
    let obstacle = if force_text {
        Some(String::new())
    } else {
        full_screen_obstacle()
    };
    let (answers, confirmed) = match &obstacle {
        Some(reason) => {
            if !reason.is_empty() {
                eprintln!(
                    "note: asking one question at a time because {reason}.\n      \
                     The full-screen installer needs a larger console."
                );
            }
            (collect_text(disks, &nics)?, false)
        }
        None => (installer_tui::run(disks, &nics)?, true),
    };
    let Some(answers) = answers else {
        println!("aborted — nothing was written.");
        return Ok(());
    };

    let targets: Vec<String> = answers
        .picks
        .iter()
        .filter_map(|i| disks.get(*i))
        .map(|d| d.dev_path())
        .collect();
    let chosen = install::plan_targets(disks, &targets, answers.raid)?;

    // Everything above chose *where* and *what*; this is the last point before
    // anything is erased.
    let lines = wizard_lines_from(&answers);
    let toml = wizard_config(&lines)?;

    println!();
    print_plan(&chosen, answers.raid);
    if answers.encrypt {
        println!("  data partition: LUKS2 encrypted (passphrase asked at each boot)");
    }
    println!("\nThe installed system will come up as:");
    for line in &lines {
        // The password is the one answer that must not be echoed back at the
        // end of an install, where it would sit in the scrollback of whatever
        // terminal or IPMI session did the install.
        if line.contains(" password ") {
            let redacted = line.rsplit_once(' ').map(|(head, _)| head).unwrap_or(line);
            println!("  {redacted} ********");
        } else {
            println!("  {line}");
        }
    }

    if !confirmed {
        let confirm = prompt("\nThis ERASES the selected disk(s). Type YES to proceed: ")?;
        if confirm.trim() != "YES" {
            println!("aborted.");
            return Ok(());
        }
    }
    // The encryption step (a wizard toggle + passphrase) drives the exact same
    // `install::Crypto::Luks` path `sentinel install --encrypt` uses — no second
    // installer, no second crypto. Off leaves a plaintext ext4, unchanged.
    let crypto = if answers.encrypt {
        install::Crypto::Luks {
            passphrase: answers.passphrase.clone(),
        }
    } else {
        install::Crypto::None
    };
    install::execute(&chosen, answers.raid, source, &crypto)?;
    // Seeded after the image is written, because the data partition it lands on
    // is created by the install.
    install::seed_config(&chosen, answers.raid, &toml, &crypto)?;
    println!("\nInstalled. Remove the medium and reboot; the box comes up configured.");
    Ok(())
}

/// Why the full-screen installer cannot be drawn here, if it cannot. A serial
/// console is 80×24 and fine; a terminal that reports smaller, or reports
/// nothing, gets the line-by-line front end instead of a scrambled screen.
fn full_screen_obstacle() -> Option<String> {
    if std::env::var("TERM").map(|t| t == "dumb").unwrap_or(false) {
        return Some("TERM=dumb".into());
    }
    match installer_tui::console_size() {
        Some((cols, rows))
            if cols >= installer_tui::MIN_COLS && rows >= installer_tui::MIN_ROWS =>
        {
            None
        }
        Some((cols, rows)) => Some(format!(
            "the console reports {cols}x{rows}, and {}x{} is the minimum",
            installer_tui::MIN_COLS,
            installer_tui::MIN_ROWS
        )),
        None => Some("the console size could not be read".into()),
    }
}

/// Map numbered picks (`"1 3"`) to `/dev` paths.
fn resolve_picks(disks: &[install::Disk], picks: &str) -> Result<Vec<usize>> {
    let mut out = Vec::new();
    for tok in picks.split_whitespace() {
        let i: usize = tok
            .parse()
            .map_err(|_| anyhow::anyhow!("not a number: {tok:?}"))?;
        let idx = i.wrapping_sub(1);
        if disks.get(idx).is_none() {
            anyhow::bail!("no disk [{i}]");
        }
        out.push(idx);
    }
    if out.is_empty() {
        anyhow::bail!("no disks selected");
    }
    Ok(out)
}

/// The XDP attachment mode of the link the data plane is on, as the kernel
/// reports it: `native` (driver hook), `generic` (software fallback) or
/// `offload` (on the NIC).
fn xdp_mode() -> Option<String> {
    let iface = std::fs::read_to_string("/run/sentinel/velstra.env")
        .ok()?
        .trim()
        .strip_prefix("VELSTRA_IFACE=")?
        .to_string();
    let out = std::process::Command::new(system::bin("ip"))
        .args(["-details", "link", "show", &iface])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mode = if text.contains("xdpoffload") {
        "offload"
    } else if text.contains("xdpgeneric") {
        "generic (software path — this NIC has no driver XDP hook)"
    } else if text.contains("xdp") {
        "native"
    } else {
        return None;
    };
    Some(format!("{mode} on {iface}"))
}

/// `show firewall zones` — the zones, their member interfaces, and the posture
/// each one ends up with.
fn show_zones() -> Result<()> {
    let saved = saved_config_path();
    if !saved.exists() {
        println!("no saved configuration");
        return Ok(());
    }
    let a = Appliance::load(&saved)?;

    // A zone exists because an interface names it. The posture block is
    // optional and may name a zone no interface is in — that block simply has
    // no effect, and saying so is more useful than hiding it.
    let mut names: Vec<String> = a.interfaces.iter().filter_map(|i| i.zone.clone()).collect();
    names.extend(a.firewall_zone_names());
    names.sort();
    names.dedup();

    if names.is_empty() {
        println!("no zones — a zone exists once an interface is given one:");
        println!("  set interface <name> zone <zone>");
        return Ok(());
    }

    for name in &names {
        let members: Vec<&str> = a
            .interfaces
            .iter()
            .filter(|i| i.zone.as_deref() == Some(name.as_str()))
            .map(|i| i.name.as_str())
            .collect();
        let p = a.zone_posture(name);
        let (action, source) = match p.default_action {
            Some(x) => (format!("{x:?}").to_lowercase(), "set on this zone"),
            None => (
                format!("{:?}", a.firewall.default_action).to_lowercase(),
                "inherited from firewall global",
            ),
        };
        println!("zone {name}");
        if members.is_empty() {
            println!("    interfaces  (none — this zone has a posture but no members,");
            println!("                 so nothing is in it and no rule may name it)");
        } else {
            println!("    interfaces  {}", members.join(", "));
        }
        println!("    default     {action}  ({source})");
        println!(
            "    stateful    {}   block-icmp {}   log {}",
            p.stateful, p.block_icmp, p.log
        );
        // The question this view exists to answer.
        let icmp = if p.block_icmp {
            "dropped (block-icmp is on)"
        } else if action == "accept" {
            "answered"
        } else {
            "dropped by the default action above. `block-icmp false` only means no \
             *extra* ICMP drop — to answer, permit it: `set firewall rule ping \
             from <zone>` + `proto icmp` + `action accept`"
        };
        println!("    ping        {icmp}");
        println!();
    }
    Ok(())
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
/// `show firewall hits` — the accept rules, and what each is currently carrying.
///
/// Attribution, not a hardware counter: the data plane counts globally, so this
/// asks it for the live flow table and works out which rule admitted each flow,
/// against the *compiled* rules so the ranking is the one the data plane
/// applies. What that buys is the question people actually have — which rules
/// are doing nothing.
fn show_rule_hits() -> Result<()> {
    let saved = saved_config_path();
    if !saved.exists() {
        println!("no saved configuration to attribute flows to");
        return Ok(());
    }
    let appliance = Appliance::load(&saved)?;
    let cfg = crate::compile::compile(&appliance);
    let table = velstra::query("flows --limit 0")
        .or_else(|_| velstra::query("flows"))
        .unwrap_or_default();
    if table.trim().is_empty() {
        println!("the data plane did not answer — is the agent running?");
        return Ok(());
    }
    let flows = crate::compile::parse_flows(&table);
    let hits = crate::compile::attribute(&cfg, &flows);
    if hits.is_empty() {
        println!("no accept rules are configured");
        return Ok(());
    }
    let total: u64 = hits.values().map(|h| h.flows).sum();
    let mut rows: Vec<(&String, &crate::compile::Hits)> = hits.iter().collect();
    // Busiest first: the interesting end of this list is both ends, and the
    // dead rules gather at the bottom where they read as a group.
    rows.sort_by(|a, b| b.1.flows.cmp(&a.1.flows).then(a.0.cmp(b.0)));
    println!("  {:<28} {:>8} {:>10}  share", "rule", "flows", "packets");
    for (name, h) in &rows {
        let share = if total > 0 {
            format!("{:.0} %", h.flows as f64 * 100.0 / total as f64)
        } else {
            "—".into()
        };
        let mark = if h.flows == 0 { "  ← nothing" } else { "" };
        println!(
            "  {name:<28} {:>8} {:>10}  {share}{mark}",
            h.flows, h.packets
        );
    }
    let dead = rows.iter().filter(|(_, h)| h.flows == 0).count();
    println!();
    println!(
        "{dead} of {} accept rules are carrying nothing right now, out of {} tracked flows.",
        rows.len(),
        flows.len()
    );
    // The one thing somebody must not conclude from a zero.
    println!(
        "Only accept rules appear here: a rule that drops leaves no flow behind, so it \
         cannot be counted this way."
    );
    Ok(())
}

/// `show vpn users` — who is connected, and the addresses a user group resolves
/// them to.
fn show_vpn_users() -> Result<()> {
    let live = crate::identity::connected();
    if live.is_empty() {
        println!("nobody is connected (or the VPN could not be asked)");
        return Ok(());
    }
    for (user, addrs) in &live {
        println!(
            "{user:<24} {}",
            addrs.iter().cloned().collect::<Vec<_>>().join(", ")
        );
    }
    Ok(())
}

/// `show history` — which series are being kept, and how far back.
fn show_history_list() -> Result<()> {
    let root = crate::metrics::dir();
    let root = root.as_path();
    let names = crate::metrics::series(root);
    if names.is_empty() {
        println!("no history is being kept (turn it on with `set system metrics enable true`)");
        return Ok(());
    }
    for name in names {
        let mut spans = Vec::new();
        for res in &crate::metrics::RESOLUTIONS {
            let n = crate::metrics::read(root, &name, res)
                .map(|s| s.len())
                .unwrap_or(0);
            if n > 0 {
                spans.push(format!("{n} at {}", res.name));
            }
        }
        println!("{name}  ({})", spans.join(", "));
    }
    Ok(())
}

/// `show history <series> [resolution]` — the samples themselves, as rates for
/// a counter and as values for a gauge.
fn show_history(series: &str, res_name: &str) -> Result<()> {
    let root = crate::metrics::dir();
    let root = root.as_path();
    let Some(res) = crate::metrics::resolution(res_name) else {
        anyhow::bail!(
            "no such resolution {res_name:?} — one of {}",
            crate::metrics::RESOLUTIONS
                .iter()
                .map(|r| r.name)
                .collect::<Vec<_>>()
                .join(", ")
        );
    };
    let samples = crate::metrics::read(root, series, res)?;
    if samples.is_empty() {
        println!("nothing recorded for {series} at {res_name} resolution");
        return Ok(());
    }
    // A gauge is a level and a counter is a total. Deriving a rate from a level
    // would draw the change in the number of sessions, which is not a thing
    // anybody wants to look at.
    if series.starts_with("gauge.") {
        for s in &samples {
            println!("{}  {}", stamp(s.at), s.value);
        }
        return Ok(());
    }
    let derived = crate::metrics::rates(&samples, res.step * 3);
    if derived.is_empty() {
        // One sample is a reading, not a rate. Printing nothing here reads as
        // "there is no history", which is a different and wrong answer.
        println!(
            "only one sample so far for {series} — a rate needs two, so give it {}s",
            res.step
        );
        return Ok(());
    }
    for (at, rate) in derived {
        match rate {
            Some(r) => println!("{}  {r:.0}/s", stamp(at)),
            None => println!("{}  (gap)", stamp(at)),
        }
    }
    Ok(())
}

/// A Unix time as something a person can read, without pulling in a date crate:
/// the appliance already prints revision timestamps this way.
fn stamp(at: u64) -> String {
    crate::archive::fmt_utc(at as i64)
}

/// `show multiwan` — the uplinks' measured quality and the steering decisions
/// that follow from it.
fn show_multiwan() -> Result<()> {
    let dir = std::path::Path::new("/run/sentinel/multiwan");
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap_or_default();

    let sla = read("sla");
    println!("uplinks:");
    if sla.trim().is_empty() {
        println!("  (the multi-WAN daemon has not reported a round yet)");
    } else {
        for line in sla.lines() {
            println!("  {line}");
        }
    }

    let steering = read("steering");
    if !steering.trim().is_empty() {
        println!("steering:");
        for line in steering.lines() {
            println!("  {line}");
        }
    }

    let active = read("active");
    if let Ok(idx) = active.trim().parse::<usize>() {
        println!("active uplink index: {idx}");
    }
    Ok(())
}

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
            // Which XDP mode the hook is in. `xdpgeneric` is the software path
            // — correct, and an order of magnitude slower than a driver hook —
            // and nothing said so, which is a poor way to learn why a firewall
            // is not reaching line rate.
            if let Some(mode) = xdp_mode() {
                println!("datapath:   {mode}");
            }
            // Only when it is wrong. A box whose clock is fine has nothing to
            // say here and status lines nobody needs are how the ones that
            // matter get skipped; a box whose clock nothing has ever set is
            // mis-stamping every log line and mis-timing every scheduled rule,
            // and that belongs on the screen an operator opens first.
            let time = clock::current();
            if time.synchronised == Some(false) {
                println!("clock:      {}", time.describe());
            }
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
        // The routing daemon knows which VRFs it is running; the kernel knows
        // which devices exist. Either answer is more use than none.
        ["vrf"] | ["vrfs"] => {
            wren_show_or(&["vrf"], &ip, &["-brief", "link", "show", "type", "vrf"])
        }
        // Multicast is programmed into the kernel's forwarding cache and the
        // daemon has no query of its own for it, so the cache *is* the state:
        // one line per (source, group) actually being forwarded.
        ["multicast"] => run_show(&ip, &["mroute", "show"]),
        // Policy routing: what the kernel is actually consulting, and in which
        // order. The configuration says what should be there; this says what is.
        ["policy", "route"] | ["policy-route"] => run_show(&ip, &["rule", "show"]),
        // Multi-WAN: what each uplink is measuring and where each steering
        // policy is currently sending its traffic. Both are written by the
        // daemon each round, so this is the state as of the last probe rather
        // than a fresh measurement — which is the honest thing to show, since a
        // fresh one would say nothing about the trend that moved the traffic.
        ["multiwan"] | ["wan"] => show_multiwan(),
        // The history. `show history` alone lists what is being kept; naming a
        // series prints it, newest last, at the resolution asked for.
        ["history"] => show_history_list(),
        ["history", series] => show_history(series, "minute"),
        ["history", series, res] => show_history(series, res),
        ["multicast", "groups"] => run_show(&ip, &["maddr", "show"]),
        ["bfd", rest @ ..] => wren_show_words("bfd", rest),

        // Firewall / NAT.
        ["firewall"] => {
            print!("agent:      ");
            run_show(&system::bin("systemctl"), &["is-active", "velstra.service"])?;
            let saved = saved_config_path();
            let path = saved.as_path();
            if path.exists() {
                print!("{}", Appliance::load(path)?.summary());
            }
            Ok(())
        }
        // What a zone actually is, in one place: which links are in it, and the
        // posture that results — inherited or set. Two different things are
        // called "zone" (an interface's membership, and an optional posture
        // block), and nothing brought them together, so a box could be filtering
        // exactly as configured and look misconfigured.
        ["firewall", "zones"] | ["zones"] => show_zones(),
        ["firewall", "statistics" | "stats"] => show_firewall_stats(),
        // Which rules are carrying traffic, and which are carrying none.
        ["firewall", "hits"] | ["firewall", "rules"] => show_rule_hits(),
        // C23 flow insight: the live state table, straight from the data plane.
        ["firewall", "flows"] | ["flows"] | ["connections"] | ["conntrack"] => {
            show_agent_query("flows", "flows")
        }
        // A3: what a BGP peer has asked this box to drop, and — just as
        // important — what it asked for that is not being enforced.
        ["firewall", "flowspec"] | ["flowspec"] => show_agent_query("flowspec", "flowspec rules"),
        ["firewall", "top-talkers" | "top"] | ["top-talkers"] => {
            show_agent_query("top", "top talkers")
        }
        ["firewall", "log"] => run_show(
            &system::bin("journalctl"),
            &["-u", "velstra.service", "-n", "50", "--no-pager"],
        ),
        ["nat"] => show_nat(),
        ["nat", "cgnat", addr] => show_cgnat(addr),

        // UDP broadcast relay (roadmap C18): what is carried, and whether the
        // daemon that carries it is up.
        ["broadcast-relay"] | ["broadcast-relay", "status"] => show_broadcast_relay(),

        // NAT-PMP (roadmap C18): what a host on the inside has opened.
        ["port-mapping"] | ["port-mapping", "status"] => show_portmap(),

        // Who may manage this appliance, and with what permission.
        ["users"] | ["system", "users"] => show_users(),

        // Captive portal (roadmap C20): who is on, and what holds the rest.
        ["portal"] | ["portal", "status"] => show_portal(),
        ["portal", "sessions"] => show_portal_sessions(),

        // Intrusion detection (roadmap C11): what is watched, and what fired.
        ["ids"] | ["ids", "status"] => show_ids(),
        // Asked of the agent, which owns the map and the deadlines — the CLI
        // keeping its own idea of what is blocked would be a second answer that
        // can disagree with what the data plane is doing.
        ["ids", "blocks"] => show_agent_query("blocks", "run-time blocks"),
        ["ids", "alerts"] => show_ids_alerts(DEFAULT_IDS_ALERTS),
        ["ids", "alerts", n] => show_ids_alerts(
            n.parse()
                .with_context(|| format!("{n:?} is not a number of alerts"))?,
        ),
        ["load-balancer"] => show_load_balancer(),

        // IPsec VPN (roadmap C2): the security-association / connection state,
        // proxied to strongSwan's swanctl (run privileged — charon's vici socket
        // is root-only).
        ["vpn"] | ["vpn", "ipsec"] | ["vpn", "ipsec", "sas"] | ["vpn", "sas"] => {
            print!("{}", system::swanctl_show(&["--list-sas"])?);
            Ok(())
        }
        // Who is on the road-warrior VPN, and on which address. This is the
        // appliance's only source of identity — the captive portal admits by
        // MAC and never learns a name — so it is also what a `user-group`
        // firewall rule resolves against.
        ["vpn", "users"] => show_vpn_users(),
        ["vpn", "ipsec", "connections" | "conns"] | ["vpn", "connections" | "conns"] => {
            print!("{}", system::swanctl_show(&["--list-conns"])?);
            Ok(())
        }

        // PKI (roadmap C19): the local CAs + issued certs, each annotated with
        // its on-disk expiry when generated.
        ["pki", ..] => show_pki(),

        // Configuration views.
        // VyOS `show configuration commands`: the running config as the flat
        // `set` lines that would recreate it — what you copy into a ticket, onto
        // a second appliance, or into a diff. The rule that produces it is
        // round-trip tested in `session`.
        ["configuration", "commands"] => {
            let saved = saved_config_path();
            let path = saved.as_path();
            if path.exists() {
                let rendered = session::render_appliance(&Appliance::load(path)?);
                for line in session::flatten_config(&rendered) {
                    println!("{line}");
                }
            } else {
                println!(
                    "no saved config at {} (run `configure` + `save`)",
                    path.display()
                );
            }
            Ok(())
        }
        ["configuration", ..] => {
            let saved = saved_config_path();
            let path = saved.as_path();
            if path.exists() {
                // The reading view: the subscription key is withheld. The
                // faithful document is one command away, at
                // `show configuration commands`, which is the form meant to
                // be copied and therefore the one that must carry it.
                print!(
                    "{}",
                    session::render_appliance_for_reading(&Appliance::load(path)?)
                );
            } else {
                println!(
                    "no saved config at {} (run `configure` + `save`)",
                    path.display()
                );
            }
            Ok(())
        }
        ["config"] => {
            let saved = saved_config_path();
            let path = saved.as_path();
            if path.exists() {
                print!("{}", Appliance::load(path)?.summary());
            } else {
                println!(
                    "no saved config at {} (run `configure` + `save`)",
                    path.display()
                );
            }
            Ok(())
        }

        // DHCP (roadmap C7). networkd's built-in server keeps its leases in the
        // per-interface state directory; dnsmasq (the DHCPv6 half) writes a
        // lease file of its own. Both are read here rather than in the console,
        // so the terminal and the browser report the same leases.
        ["dhcp"] | ["dhcp", "leases"] => {
            let mut found = false;
            for dir in ["/var/lib/systemd/network", "/run/systemd/netif/leases"] {
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        match std::fs::read_to_string(&path) {
                            Ok(body) if !body.trim().is_empty() => {
                                println!("{}:", path.display());
                                print!("{body}");
                                found = true;
                            }
                            _ => {}
                        }
                    }
                }
            }
            match std::fs::read_to_string("/run/sentinel/dhcp6/dhcp6.leases") {
                Ok(body) if !body.trim().is_empty() => {
                    println!("/run/sentinel/dhcp6/dhcp6.leases:");
                    print!("{body}");
                    found = true;
                }
                _ => {}
            }
            if !found {
                println!("no DHCP leases (no server configured, or nothing has asked yet)");
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
        // The subscription/update-channel state, as facts this box actually
        // holds: the active channel, whether a key is configured (masked — the
        // value never appears in show output), and the last contact with the
        // channel as it went. An unknown fact is printed as unknown; nothing
        // here is fetched, guessed or counted down.
        ["subscription"] => show_subscription(),
        ["version"] => {
            println!("sentinel:   {}", env!("CARGO_PKG_VERSION"));
            print!("wren:       ");
            if run_checked(&system::bin("wren"), &["--version"]).is_err() {
                println!("(not available)");
            }
            print!("kernel:     ");
            run_show(&system::bin("uname"), &["-sr"])?;
            // The version numbers above are hand-set and so cannot tell two
            // builds apart; these are derived from the running system and do.
            // On a box that updates A/B that is the whole question, so they
            // are printed every time rather than behind a flag.
            let id = image::current();
            println!("{:<12}{}", "image:", id.describe());
            println!("{:<12}{}", "binaries:", id.binaries_line());
            println!("{:<12}{}", "clock:", clock::current().describe());
            println!("{:<12}{}", "data:", crate::unlock::data_at_rest());
            Ok(())
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
             show flows [| top-talkers]        live state table / hosts by volume\n  \
             show nat                          NAT configuration\n  \
             show vpn [ipsec]                  IPsec security associations / connections\n  \
             show pki                          local CAs + issued certificates (expiry)\n  \
             show configuration                the saved config (config syntax)\n  \
             show log [velstra|wren]           recent service log\n  \
             show subscription                 update channels + entitlement state\n  \
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
    let mut a = vec!["show"];
    a.extend(words);
    // Escalated: wren's control socket is root-only, so every routing `show`
    // failed for the operator account the installer creates — with a raw
    // "Permission denied (os error 13)" and a store path, which reads like a
    // broken daemon rather than a missing privilege.
    let out = system::escalated_output("wren", &a)?;
    print!("{}", String::from_utf8_lossy(&out.stdout));
    if !out.status.success() {
        anyhow::bail!(
            "wren failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
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
/// Ask the agent's query socket and print its reply. A missing socket is reported
/// as such rather than as a failure: an agent started without `--query-socket`
/// (or an older one) is a normal state, and the operator needs to know *why* the
/// view is empty rather than see a stack of errors.
fn show_agent_query(command: &str, what: &str) -> Result<()> {
    match velstra::query(command) {
        Ok(reply) => {
            print!("{reply}");
            Ok(())
        }
        Err(e) => {
            println!("{what} unavailable: {e:#}");
            println!(
                "(the agent serves this on {}; check `systemctl status velstra.service`)",
                velstra::SOCKET
            );
            Ok(())
        }
    }
}

/// `show users`: the accounts, their management group and what it allows.
///
/// Read from the **saved** configuration rather than from the token directory:
/// the configuration is the authority on who may do what, and a token file is
/// only the secret. Listing the files instead would show an account as having
/// access after its group was taken away.
fn show_users() -> Result<()> {
    let appliance = Appliance::load(&saved_config_path())?;
    if appliance.system.logins.is_empty() {
        println!("no accounts configured");
        return Ok(());
    }
    println!(
        "{:<16} {:<14} {:<12} login",
        "account", "group", "permission"
    );
    for login in &appliance.system.logins {
        let permission = login
            .group
            .as_deref()
            .and_then(|g| appliance.system.groups.iter().find(|x| x.name == g))
            .map(|g| g.permission.as_str())
            .unwrap_or("—");
        let how = match (&login.hashed_password, login.ssh_keys.is_empty()) {
            (Some(_), false) => "password + key",
            (Some(_), true) => "password",
            (None, false) => "key only",
            (None, true) => "no credentials",
        };
        println!(
            "{:<16} {:<14} {:<12} {how}",
            login.username,
            login.group.as_deref().unwrap_or("—"),
            permission,
        );
    }
    Ok(())
}

/// `show port-mapping`: what is configured, and what hosts have opened.
///
/// The mappings come from the **agent**, which owns the table and the deadlines
/// — the same reason `show portal sessions` does. What is listed here is what
/// the data plane is actually forwarding, not a tally kept alongside it.
fn show_portmap() -> Result<()> {
    let Ok(state) = portmap::load(std::path::Path::new(portmap::STATE_FILE)) else {
        println!("no port mapping is configured");
        return Ok(());
    };
    println!("listening: {}", state.bind);
    println!("opens on:  policy {}", state.wan_policy);
    println!("external:  {}", state.external);
    println!("lifetime:  up to {}s", state.max_lifetime);
    println!(
        "below 1024: {}",
        if state.allow_privileged {
            "allowed"
        } else {
            "refused"
        }
    );
    println!(
        "service:   {}",
        if system::unit_active("sentinel-portmap.service") {
            "running"
        } else {
            "not running"
        }
    );
    println!();
    match velstra::query_at(std::path::Path::new(portmap::AGENT_SOCKET), "mappings") {
        Ok(reply) => print!("{reply}"),
        Err(e) => {
            println!("mappings unavailable: {e:#}");
            println!(
                "(the agent serves these on {}; check `systemctl status velstra.service`)",
                portmap::AGENT_SOCKET
            );
        }
    }
    Ok(())
}

/// `show portal`: what is configured, whether the page is up, and who is on.
///
/// The sessions come from the **agent**, which owns the map and the deadlines. A
/// second answer kept here could disagree with what the data plane is actually
/// letting through, which is the one thing this view exists to rule out.
fn show_portal() -> Result<()> {
    let Ok(state) = portal::load(std::path::Path::new(portal::STATE_FILE)) else {
        println!("no captive portal is configured");
        return Ok(());
    };
    println!("portal:   http://{}/", state.bind);
    println!("zone:     policy {}", state.policy);
    println!(
        "entry:    {}",
        if state.passphrase.is_some() {
            "passphrase"
        } else {
            "click-through"
        }
    );
    println!("session:  {}s", state.session_secs);
    println!(
        "service:  {}",
        if system::unit_active("sentinel-portal.service") {
            "running"
        } else {
            "not running"
        }
    );
    println!();
    show_portal_sessions()
}

/// `show portal sessions`: the devices currently admitted, from the agent.
fn show_portal_sessions() -> Result<()> {
    match velstra::query_at(std::path::Path::new(portal::AGENT_SOCKET), "sessions") {
        Ok(reply) => {
            print!("{reply}");
            Ok(())
        }
        Err(e) => {
            println!("portal sessions unavailable: {e:#}");
            println!(
                "(the agent serves these on {}; check `systemctl status velstra.service`)",
                portal::AGENT_SOCKET
            );
            Ok(())
        }
    }
}

fn show_firewall_stats() -> Result<()> {
    // Prefer the agent's live counters. The journal scrape below is the fallback
    // for an agent without a query socket: it only ever shows whatever the last
    // periodic dump happened to contain, so it is a poor substitute, not a peer.
    if let Ok(reply) = velstra::query("stats") {
        print!("{reply}");
        return Ok(());
    }
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
    let revs = archive::list_revisions(&saved_config_path());
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
    let toml = archive::read_revision(&saved_config_path(), n)?;
    let appliance = Appliance::from_toml(&toml)?;
    // A past revision is read, not replayed, so it is shown the same way the
    // running one is.
    print!("{}", session::render_appliance_for_reading(&appliance));
    Ok(())
}

/// The NAT section of the saved config, summarized.
fn show_nat() -> Result<()> {
    let saved = saved_config_path();
    let path = saved.as_path();
    if !path.exists() {
        println!(
            "no saved config at {} (run `configure` + `save`)",
            path.display()
        );
        return Ok(());
    }
    let a = Appliance::load(path)?;
    if a.nat.is_empty() {
        println!("no NAT configured");
        return Ok(());
    }
    for s in &a.nat.source {
        println!("source {}: masquerade zone {}", s.name, s.zone);
        if let Some(size) = s.cgnat_block_size {
            let base = s
                .cgnat_base_port
                .unwrap_or(crate::config::DEFAULT_CGNAT_BASE_PORT);
            // The configured shape. Which block a given address holds is the
            // agent's to answer — see `show nat cgnat <ip>`.
            println!("  cgnat: {size} ports per address from port {base}");
        }
    }
    for d in &a.nat.destination {
        println!(
            "destination {}: {} {:?}/{} -> {}",
            d.name, d.zone, d.proto, d.port, d.to
        );
    }
    Ok(())
}

/// Deliver an alert for a failed unit (roadmap C23).
///
/// Exits 0 even when nothing could be delivered: this runs as systemd's
/// `OnFailure=` handler, and a failing handler would add a second failed unit to
/// the incident — with its own OnFailure, if we ever wired one. What went wrong
/// goes to the journal instead.
fn alert_unit(unit: &str, config: &std::path::Path) -> Result<()> {
    if !config.exists() {
        eprintln!(
            "alert: no saved config at {} — nothing to notify",
            config.display()
        );
        return Ok(());
    }
    let a = match Appliance::load(config) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("alert: could not read {}: {e:#}", config.display());
            return Ok(());
        }
    };
    let alert = alert::Alert::unit_failure(unit);
    let n = alert::deliver(&a.services.alerts, &alert);
    if n == 0 && !a.services.alerts.is_empty() {
        eprintln!("alert: {unit} failed but no target accepted the notification");
    } else if n > 0 {
        println!("alert: notified {n} target(s) about {unit}");
    }
    Ok(())
}

/// The load-balanced services of the saved config (roadmap C22).
///
/// Names the two states the config alone reads past: a service that is
/// administratively disabled (the compiler drops it entirely), and one whose pool
/// is empty — legal, but it forwards nothing, which is worth saying out loud
/// rather than letting an operator read an empty column as "fine".
/// Report the WAN port block a given internal address is assigned.
///
/// Asked of the **agent**, not computed here: it holds the live layout and the
/// arithmetic the data plane hands ports out with. Sentinel cannot link
/// `velstra-common` yet (its aya dependency is a git one), and re-deriving the
/// blocks locally would eventually name a different subscriber than the ports
/// actually belonged to — which for the one question CGNAT exists to answer is
/// worse than no answer at all.
fn show_cgnat(addr: &str) -> Result<()> {
    addr.parse::<std::net::Ipv4Addr>()
        .with_context(|| format!("{addr:?} is not an IPv4 address"))?;
    show_agent_query(&format!("cgnat {addr}"), "cgnat port blocks")
}

/// Clear operational state. Only the data plane's run-time blocks so far — the
/// state a detector created and an operator may need to undo *now*.
///
/// Deliberately a separate verb from `show`: this changes what the box is doing,
/// and `show` must stay something an operator can run without thinking.
fn clear_op(args: &[String]) -> Result<()> {
    let path: Vec<&str> = args.iter().map(String::as_str).collect();
    match path.as_slice() {
        ["ids", "block", addr] => {
            addr.parse::<std::net::IpAddr>()
                .with_context(|| format!("{addr:?} is not an IP address"))?;
            show_agent_query(&format!("unblock {addr}"), "lifting the block")
        }
        // The false-positive case: a rule that was too broad blocked a dozen
        // sources, and lifting them one at a time is the wrong thing to be doing
        // while that is still happening.
        ["ids", "blocks"] => show_agent_query("unblock all", "lifting the blocks"),
        // C20: throw one device — or everybody — off the guest network without
        // waiting for a session to expire. Named by MAC because that is what a
        // session *is* and what `show portal sessions` lists.
        ["portal", "session", mac] => clear_portal(&format!("revoke {mac} any")),
        ["portal", "sessions"] => clear_portal("revoke all"),
        // C18: close every port a host on the inside opened. One at a time is
        // `clear port-mapping <tcp|udp> <port>` — but the case that actually
        // happens is wanting them all gone at once.
        ["port-mapping", "mappings"] | ["port-mapping"] => clear_mapping("unmap all"),
        ["port-mapping", proto, port] => {
            let Ok(state) = portmap::load(std::path::Path::new(portmap::STATE_FILE)) else {
                println!("no port mapping is configured");
                return Ok(());
            };
            clear_mapping(&format!("unmap {proto} {port} {}", state.wan_policy))
        }
        [] => {
            println!(
                "usage: clear ids block <ip> | clear ids blocks | \
                 clear portal session <mac> | clear portal sessions"
            );
            Ok(())
        }
        other => anyhow::bail!(
            "unknown clear path {other:?}; try: clear ids block <ip> | clear ids blocks | \
             clear portal session <mac> | clear portal sessions"
        ),
    }
}

/// Ask the agent's **portal** socket to end a session. Separate from
/// [`show_agent_query`] because the two sockets are separate — the diagnostics
/// one cannot touch a portal session, which is the point of it being a different
/// socket.
fn clear_portal(command: &str) -> Result<()> {
    match velstra::query_at(std::path::Path::new(portal::AGENT_SOCKET), command) {
        Ok(reply) => {
            print!("{reply}");
            Ok(())
        }
        Err(e) => {
            println!("ending that session failed: {e:#}");
            println!(
                "(the agent serves this on {}; check `systemctl status velstra.service`)",
                portal::AGENT_SOCKET
            );
            Ok(())
        }
    }
}

/// Ask the agent's **mapping** socket to close a mapping. A third socket and a
/// third helper, because they are three different amounts of trust.
fn clear_mapping(command: &str) -> Result<()> {
    match velstra::query_at(std::path::Path::new(portmap::AGENT_SOCKET), command) {
        Ok(reply) => {
            print!("{reply}");
            Ok(())
        }
        Err(e) => {
            println!("closing that mapping failed: {e:#}");
            Ok(())
        }
    }
}

/// How many alerts `show ids alerts` lists when the operator names no count.
const DEFAULT_IDS_ALERTS: usize = 20;

/// What the detector is watching, and whether it is actually doing so (roadmap
/// C11).
///
/// A ruleset file the operator named but that is not on the box is called out
/// here: the render skips it so the detector still starts with the rules that do
/// exist, and this is where that gap stops being silent.
fn show_broadcast_relay() -> Result<()> {
    let saved = saved_config_path();
    let path = saved.as_path();
    if !path.exists() {
        println!(
            "no saved config at {} (run `configure` + `save`)",
            path.display()
        );
        return Ok(());
    }
    let relays = Appliance::load(path)?.services.broadcast_relay;
    if relays.is_empty() {
        println!("no broadcast relay is configured");
        return Ok(());
    }
    let running = system::unit_active(relay::RELAY_UNIT);
    println!("relay: {}", if running { "running" } else { "NOT running" });
    for r in &relays {
        let state = if r.disabled { "  (disabled)" } else { "" };
        println!(
            "  {:<12} udp/{:<6} {}{state}",
            r.name,
            r.port,
            r.interface.join(" <-> "),
        );
    }
    // A relay whose port the firewall drops carries nothing while looking
    // perfectly configured, so the same advisory the commit prints is repeated
    // here — this is where someone looks when it is not working.
    let appliance = Appliance::load(path)?;
    for w in appliance.warnings() {
        if w.contains("broadcast-relay") {
            println!("warning: {w}");
        }
    }
    if !running && relays.iter().any(|r| !r.disabled) {
        println!("(`systemctl status {}` says why)", relay::RELAY_UNIT);
    }
    Ok(())
}

fn show_ids() -> Result<()> {
    let saved = saved_config_path();
    let path = saved.as_path();
    if !path.exists() {
        println!(
            "no saved config at {} (run `configure` + `save`)",
            path.display()
        );
        return Ok(());
    }
    let ids = Appliance::load(path)?.services.ids;
    if ids.is_empty() {
        println!("intrusion detection is off (no `services ids interface` is set)");
        return Ok(());
    }
    let running = system::unit_active(ids::SURICATA_UNIT);
    println!(
        "detector: {}",
        if running { "running" } else { "NOT running" }
    );
    println!("watching: {}", ids.interfaces.join(", "));
    // Where the detector sits, said once, here. The firewall runs in XDP and an
    // allowed packet ends on XDP_PASS, so AF_PACKET taps exactly what was
    // admitted — a rule written for a port the firewall drops can never fire,
    // and an operator waiting for that alert has no way to tell it apart from a
    // rule that does not match.
    println!(
        "sees:     traffic the firewall admitted (a dropped packet never reaches the detector)"
    );
    println!("home-net: {}", ids.home_net().join(", "));
    println!("rules from the configuration: {}", ids.rules.len());
    for path in &ids.rulesets {
        if std::path::Path::new(path).exists() {
            println!("ruleset: {path}");
        } else {
            println!("ruleset: {path}  — MISSING, its rules are not loaded");
        }
    }
    if !running {
        println!("(`systemctl status {}` says why)", ids::SURICATA_UNIT);
    }
    Ok(())
}

/// The most recent alerts, oldest first so the newest is next to the prompt.
fn show_ids_alerts(limit: usize) -> Result<()> {
    let alerts = ids::recent_alerts(limit)?;
    if alerts.is_empty() {
        println!("no alerts recorded");
        // An empty list means "nothing fired" only if something could have. The
        // difference matters: a quiet detector and an absent one look identical
        // here, and only one of them is good news.
        if !system::unit_active(ids::SURICATA_UNIT) {
            println!("(the detector is not running — see `show ids`)");
        }
        return Ok(());
    }
    for a in &alerts {
        println!(
            "{} [sev {}] {} — {} {} -> {}",
            a.timestamp, a.severity, a.signature, a.proto, a.src, a.dst
        );
    }
    Ok(())
}

fn show_load_balancer() -> Result<()> {
    let saved = saved_config_path();
    let path = saved.as_path();
    if !path.exists() {
        println!(
            "no saved config at {} (run `configure` + `save`)",
            path.display()
        );
        return Ok(());
    }
    let a = Appliance::load(path)?;
    if a.load_balancers.is_empty() {
        println!("no load-balanced services configured");
        return Ok(());
    }
    for lb in &a.load_balancers {
        let state = if lb.disabled { " (disabled)" } else { "" };
        println!(
            "{}: {} {:?}/{} vip {}{state}",
            lb.name, lb.zone, lb.proto, lb.port, lb.vip
        );
        if lb.backends.is_empty() {
            println!("    no backends — the pool is drained, traffic is passed through");
        }
        for b in &lb.backends {
            println!("    backend {b}");
        }
    }
    Ok(())
}

/// The PKI section of the saved config (roadmap C19): local CAs + issued certs,
/// each annotated with its on-disk status/expiry, plus the ACME account.
fn show_pki() -> Result<()> {
    let saved = saved_config_path();
    let path = saved.as_path();
    if !path.exists() {
        println!(
            "no saved config at {} (run `configure` + `save`)",
            path.display()
        );
        return Ok(());
    }
    let a = Appliance::load(path)?;
    if a.pki.is_empty() {
        println!("no PKI configured");
        return Ok(());
    }
    for ca in &a.pki.cas {
        let crt = format!("/var/lib/sentinel/pki/ca/{}/ca.crt", ca.name);
        println!(
            "ca {}: CN={} {}",
            ca.name,
            ca.common_name,
            cert_status(&crt)
        );
    }
    for cert in &a.pki.certificates {
        // An obtained certificate lands in the same store as a locally-signed
        // one, so the same status read works for both — which is the point.
        let status = cert_status(&format!(
            "/var/lib/sentinel/pki/certs/{}/cert.crt",
            cert.name
        ));
        println!(
            "certificate {}: CN={} ca={} {}",
            cert.name, cert.common_name, cert.ca, status
        );
    }
    if let Some(acme) = &a.pki.acme {
        println!(
            "acme: {} challenge={} email={}",
            acme.directory_url.as_deref().unwrap_or("letsencrypt-prod"),
            acme.challenge.as_deref().unwrap_or("http-01"),
            acme.email
        );
        // Whether renewal is actually scheduled. A certificate that shows a
        // healthy expiry today and has no timer behind it is the failure this
        // line exists to make visible.
        if a.pki.certificates.iter().any(|c| c.ca == "acme") {
            println!(
                "acme renewal: {}",
                if system::unit_active(acme::ACME_TIMER) {
                    "scheduled"
                } else {
                    "NOT scheduled — `systemctl status sentinel-acme` says why"
                }
            );
            for w in a.warnings() {
                if w.contains("pki acme") {
                    println!("warning: {w}");
                }
            }
        }
    }
    Ok(())
}

/// The generated-or-not / expiry annotation for a cert path — reads the on-disk
/// certificate's `notAfter` via openssl (a plain read; the cert is 0644).
fn cert_status(crt_path: &str) -> String {
    if !std::path::Path::new(crt_path).exists() {
        return "(not yet generated)".to_string();
    }
    let out = std::process::Command::new(system::bin("openssl"))
        .args(["x509", "-enddate", "-noout", "-in", crt_path])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let s = String::from_utf8_lossy(&o.stdout);
            // openssl prints `notAfter=Jun  1 12:00:00 2035 GMT`.
            match s.trim().strip_prefix("notAfter=") {
                Some(d) => format!("expires {}", d.trim()),
                None => "generated".to_string(),
            }
        }
        _ => "generated".to_string(),
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
