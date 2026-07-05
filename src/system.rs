//! Runtime application of the appliance config to the **live** system — no
//! rebuild, no reboot. This is the appliance model real firewall OSes use
//! (VyOS/OPNsense/Talos): a fixed, verified image, with config applied to
//! running services. Firewall changes reload the velstra data plane; the
//! hostname is set via `hostnamectl`. Only running services + persisted state
//! change; the root filesystem stays immutable. (OS *image* updates are a
//! separate A/B path.)

use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

/// The network interfaces the system provides — the real NICs — so they appear
/// in the config even before the operator assigns them (VyOS-like). Reads
/// `/sys/class/net`, skipping loopback and virtual interfaces (those without a
/// backing `device`). Names only for now; per-interface address discovery is a
/// later slice. Returns empty if the path is unreadable (e.g. off-box).
pub fn discover_interfaces() -> Vec<String> {
    let mut names = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return names;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        // Real NICs have a `device` symlink; lo and virtual ifaces (veth, bridges)
        // don't.
        if name != "lo" && entry.path().join("device").exists() {
            names.push(name);
        }
    }
    names.sort();
    names
}

/// The live kernel hostname. Reads `/proc/sys/kernel/hostname` each call, so a
/// committed change is reflected immediately (used by the prompt + commit
/// summary).
pub fn current_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "sentinel".into())
}

/// Set the system hostname live. NixOS blocks `hostnamectl` (the hostname is a
/// declarative setting), so set the live kernel hostname directly via the
/// `hostname` command (`sethostname(2)`). The boot service re-applies it each
/// boot, so it persists.
pub fn set_hostname(name: &str) -> Result<()> {
    run_priv("hostname", &[name])
}

/// Reload the velstra data plane so it picks up a freshly written config.
pub fn reload_velstra(unit: &str) -> Result<()> {
    run_priv("systemctl", &["reload-or-restart", unit])
}

/// Restart systemd-resolved so a freshly written drop-in takes effect. A plain
/// `restart` (not reload) is used deliberately: adding/removing a
/// `DNSStubListenerExtra=` listener requires resolved to re-bind its sockets,
/// which a reload (SIGHUP) does not do.
pub fn reload_resolved() -> Result<()> {
    run_priv("systemctl", &["restart", "systemd-resolved"])
}

/// Restart chrony so a freshly written confdir drop-in takes effect. A restart
/// (not reload) is used because chrony only reloads *sources* live; `server` /
/// `allow` directives in a confdir file are applied on start.
pub fn reload_chrony() -> Result<()> {
    run_priv("systemctl", &["restart", "chronyd"])
}

/// Restart dnsmasq so a freshly written conf-dir drop-in takes effect (new
/// `interface=`/`server=`/`address=` lines need a re-read + re-bind, which a
/// SIGHUP does not fully do for interface bindings).
pub fn reload_dnsmasq() -> Result<()> {
    run_priv("systemctl", &["restart", "dnsmasq"])
}

/// (Re)start the `sentinel-pppoe@<name>` templated unit that runs `pppd` for one
/// PPPoE session. A `restart` (re-dial) is used deliberately: it applies fresh
/// peer options / credentials by tearing the old `pppd` down and dialling again,
/// and starts the session if it wasn't running. Only sessions whose rendered
/// config actually changed are restarted (by [`crate::net`]), so an unrelated
/// commit never drops a live WAN link.
pub fn pppoe_restart(name: &str) -> Result<()> {
    run_priv("systemctl", &["restart", &format!("sentinel-pppoe@{name}.service")])
}

/// Stop and disband the `sentinel-pppoe@<name>` session (a PPPoE interface that
/// is no longer configured). Best-effort at the call site — a stop that fails
/// because the unit was never up must not abort the reconcile.
pub fn pppoe_stop(name: &str) -> Result<()> {
    run_priv("systemctl", &["stop", &format!("sentinel-pppoe@{name}.service")])
}

/// Load an nftables ruleset file into the running kernel (`nft -f <path>`). Used
/// for the PPPoE TCP-MSS-clamp table; the file's leading `table`/`delete table`
/// makes the load idempotent (it replaces our table wholesale each time).
pub fn nft_load(path: &Path) -> Result<()> {
    let Some(p) = path.to_str() else {
        bail!("non-UTF-8 path");
    };
    run_priv("nft", &["-f", p])
}

/// (Re)attach a root egress qdisc to `dev`: `tc qdisc replace dev <dev> root
/// <spec…>` (roadmap C8 traffic shaping). `replace` is idempotent — it installs
/// the qdisc if absent or swaps it in place without dropping the link, so a
/// re-apply of the same spec never blips a live queue.
pub fn tc_qdisc_replace(dev: &str, spec: &[&str]) -> Result<()> {
    let mut args: Vec<&str> = vec!["qdisc", "replace", "dev", dev, "root"];
    args.extend_from_slice(spec);
    run_priv("tc", &args)
}

/// Remove `dev`'s root qdisc, reverting it to the kernel default — used when an
/// interface no longer declares QoS. Best-effort at the call site.
pub fn tc_qdisc_del(dev: &str) -> Result<()> {
    run_priv("tc", &["qdisc", "del", "dev", dev, "root"])
}

/// The transient systemd unit base name for the `commit-confirm` auto-rollback.
/// `systemd-run --unit=<this>` creates `<this>.timer` + `<this>.service`.
pub const CONFIRM_UNIT: &str = "sentinel-confirm";

/// Arm the `commit-confirm` auto-rollback: a one-shot transient timer that runs
/// `sentinel confirm-rollback --config <cfg>` after `minutes`, reverting the box
/// to its saved config unless `confirm` disarms it first.
///
/// The timer runs the CURRENT binary (`current_exe`) with the whole `SENTINEL_*`
/// tool environment forwarded via `--setenv`, so the systemd-spawned process
/// resolves `systemctl`/`hostname`/`ip`/… to the exact store paths the
/// interactive session uses (the wrapper's env isn't inherited by a transient
/// unit otherwise). `--collect` GCs the unit after it fires, even on failure, so
/// re-arming later never trips over a lingering unit.
pub fn arm_confirm(minutes: u32, cfg: &Path) -> Result<()> {
    let exe = std::env::current_exe().context("resolving the sentinel binary")?;
    let (Some(exe_s), Some(cfg_s)) = (exe.to_str(), cfg.to_str()) else {
        bail!("non-UTF-8 path");
    };
    let mut args: Vec<String> = vec![
        format!("--unit={CONFIRM_UNIT}"),
        format!("--on-active={minutes}min"),
        "--timer-property=AccuracySec=1s".into(),
        "--collect".into(),
    ];
    for (k, v) in std::env::vars() {
        if k.starts_with("SENTINEL_") {
            args.push(format!("--setenv={k}={v}"));
        }
    }
    // Everything after the options is the command to run when the timer fires.
    args.push(exe_s.to_string());
    args.push("confirm-rollback".into());
    args.push("--config".into());
    args.push(cfg_s.to_string());
    let argref: Vec<&str> = args.iter().map(String::as_str).collect();
    run_priv("systemd-run", &argref)
}

/// Disarm the `commit-confirm` timer (best-effort). Only the **timer** is
/// stopped — never the `.service`, since a manual/auto `confirm-rollback` may be
/// the very unit calling this. `reset-failed` clears any leftover transient
/// state (it does not stop a running unit) so the next `arm_confirm` is clean.
pub fn disarm_confirm() {
    let timer = format!("{CONFIRM_UNIT}.timer");
    let service = format!("{CONFIRM_UNIT}.service");
    let _ = run_priv("systemctl", &["stop", &timer]);
    let _ = run_priv("systemctl", &["reset-failed", &timer, &service]);
}

/// Whether a `commit-confirm` window is currently pending (its timer armed).
/// `systemctl is-active` needs no privilege, so this is a plain read.
pub fn confirm_pending() -> bool {
    let out = Command::new(bin("systemctl"))
        .args(["is-active", &format!("{CONFIRM_UNIT}.timer")])
        .output();
    matches!(out, Ok(o) if String::from_utf8_lossy(&o.stdout).trim() == "active")
}

/// systemd-networkd's runtime drop-in dir (tmpfs, re-seeded each boot). We place
/// per-interface `.network` units here so addressing is applied live and is gone
/// on reboot unless re-asserted from the saved config by the boot service.
pub const NETWORKD_RUNTIME_DIR: &str = "/run/systemd/network";

/// Install file `contents` at a (root-owned) `path`. Tries a direct write first
/// (works as root, e.g. the boot service) and falls back to staging in a
/// wheel-writable temp and `sudo install`-ing it (the admin running `configure`).
pub fn install_file(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    if std::fs::write(path, contents).is_ok() {
        return Ok(());
    }
    // Fall back to sudo: stage in /run/sentinel (wheel-writable) then install.
    let tmp = Path::new("/run/sentinel").join(".net-unit.tmp");
    std::fs::write(&tmp, contents).with_context(|| format!("staging {}", tmp.display()))?;
    let (Some(tmp_s), Some(dst_s)) = (tmp.to_str(), path.to_str()) else {
        bail!("non-UTF-8 path");
    };
    sudo("install", &["-m", "0644", tmp_s, dst_s])
}

/// Install a secret file `contents` at a (root-owned) `path` readable by
/// systemd-networkd but no one else — mode **0640, group `systemd-network`**.
/// A WireGuard `.netdev` carries an inline `PrivateKey=`, so it must not be
/// world-readable; but systemd-networkd runs as the unprivileged
/// `systemd-network` user and must still open it, so 0600 root:root would give
/// it "Permission denied" and the link would never come up. We always route
/// through `install -m 0640 -g systemd-network` (via [`sudo`], which runs
/// directly when already root and via `sudo` otherwise) so the owning group is
/// set in one atomic step in both the boot-service (root) and `configure`
/// (admin) paths.
pub fn install_secret_file(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    // Stage in /run/sentinel (wheel-writable) then install with the right
    // mode+group. `install` resolves the group name and sets owner:group:mode
    // atomically, so there is never a window where the private key is world- or
    // wrong-group-readable.
    let tmp = Path::new("/run/sentinel").join(".net-secret.tmp");
    std::fs::write(&tmp, contents).with_context(|| format!("staging {}", tmp.display()))?;
    let (Some(tmp_s), Some(dst_s)) = (tmp.to_str(), path.to_str()) else {
        bail!("non-UTF-8 path");
    };
    sudo(
        "install",
        &["-m", "0640", "-g", "systemd-network", tmp_s, dst_s],
    )
}

/// Install a PPPoE credentials file (`chap-secrets`/`pap-secrets`) at a
/// root-owned `path`, mode **0600 root:root**. Unlike a WireGuard `.netdev`
/// (which an unprivileged `systemd-network` must read, hence 0640), `pppd` runs
/// as root, so the ISP password never needs to leave root — 0600 is the tightest
/// mode that still works. We stage in `/run/sentinel` (wheel-writable) then
/// `install -m 0600` atomically, so there is never a window where the password
/// is group- or world-readable, in both the boot-service (root) and `configure`
/// (admin) paths.
pub fn install_ppp_secret(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    let tmp = Path::new("/run/sentinel").join(".ppp-secret.tmp");
    std::fs::write(&tmp, contents).with_context(|| format!("staging {}", tmp.display()))?;
    let (Some(tmp_s), Some(dst_s)) = (tmp.to_str(), path.to_str()) else {
        bail!("non-UTF-8 path");
    };
    sudo("install", &["-m", "0600", tmp_s, dst_s])
}

/// Remove a (possibly root-owned) file, tolerating an already-absent path.
pub fn remove_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    if std::fs::remove_file(path).is_ok() {
        return Ok(());
    }
    let Some(p) = path.to_str() else {
        bail!("non-UTF-8 path");
    };
    sudo("rm", &["-f", p])
}

/// Ensure a directory exists, escalating to `sudo mkdir -p` if a direct create
/// is denied.
pub fn ensure_dir(dir: &Path) -> Result<()> {
    if dir.is_dir() || std::fs::create_dir_all(dir).is_ok() {
        return Ok(());
    }
    let Some(d) = dir.to_str() else {
        bail!("non-UTF-8 path");
    };
    sudo("mkdir", &["-p", d])
}

/// Tell systemd-networkd to re-read its unit files and re-apply them to the
/// given links — so a freshly written `.network` takes effect immediately.
/// Best-effort: at early boot networkd may not be up yet (it reads the files on
/// start anyway), so failures are reported by the caller, not fatal here.
pub fn networkctl_reload(ifaces: &[String]) -> Result<()> {
    run_priv("networkctl", &["reload"])?;
    for iface in ifaces {
        run_priv("networkctl", &["reconfigure", iface])?;
    }
    Ok(())
}

/// Resolve a logical tool name to an absolute path. The Nix wrapper injects
/// `SENTINEL_<TOOL>_BIN` env vars pointing at exact store paths, so neither the
/// admin's `$PATH` nor sudo's `secure_path` can shadow or miss a tool (the cause
/// of "Failed to execute /run/current-system/sw/..." on a `commit`). Off-box
/// (dev, tests) the vars are unset and we fall back to the bare name on `$PATH`.
pub fn bin(name: &str) -> String {
    let var = match name {
        "hostname" => "SENTINEL_HOSTNAME_BIN",
        "ip" => "SENTINEL_IP_BIN",
        "networkctl" => "SENTINEL_NETWORKCTL_BIN",
        "systemctl" => "SENTINEL_SYSTEMCTL_BIN",
        "systemd-run" => "SENTINEL_SYSTEMD_RUN_BIN",
        "journalctl" => "SENTINEL_JOURNALCTL_BIN",
        "wren" => "SENTINEL_WREN_BIN",
        "nft" => "SENTINEL_NFT_BIN",
        "tc" => "SENTINEL_TC_BIN",
        "lsblk" => "SENTINEL_LSBLK_BIN",
        "install" => "SENTINEL_INSTALL_BIN",
        "mkdir" => "SENTINEL_MKDIR_BIN",
        "rm" => "SENTINEL_RM_BIN",
        "uname" => "SENTINEL_UNAME_BIN",
        // installer tools
        "sgdisk" => "SENTINEL_SGDISK_BIN",
        "wipefs" => "SENTINEL_WIPEFS_BIN",
        "partprobe" => "SENTINEL_PARTPROBE_BIN",
        "udevadm" => "SENTINEL_UDEVADM_BIN",
        "dd" => "SENTINEL_DD_BIN",
        "mkfs.ext4" => "SENTINEL_MKFS_EXT4_BIN",
        "mdadm" => "SENTINEL_MDADM_BIN",
        "losetup" => "SENTINEL_LOSETUP_BIN",
        "mount" => "SENTINEL_MOUNT_BIN",
        "umount" => "SENTINEL_UMOUNT_BIN",
        "findmnt" => "SENTINEL_FINDMNT_BIN",
        _ => "",
    };
    if !var.is_empty() {
        if let Ok(path) = std::env::var(var) {
            if !path.is_empty() {
                return path;
            }
        }
    }
    name.to_string()
}

/// Run a command that needs root: when already root (e.g. the boot service) run
/// it directly; otherwise (the admin running `configure`) go straight to `sudo`.
///
/// We do **not** probe a direct non-root invocation first: a non-root
/// `systemctl`/`networkctl` would try to authorize via polkit, which spawns
/// `pkttyagent` on the controlling TTY. On the appliance that agent isn't
/// installed, so it prints "Failed to execute /run/current-system/sw/.../
/// pkttyagent: No such file or directory" straight to the terminal (bypassing
/// our stdio redirect, since it writes to the tty) and fails. Running via `sudo`
/// executes as root, which never touches polkit.
fn run_priv(cmd: &str, args: &[&str]) -> Result<()> {
    let is_root = unsafe { libc::geteuid() } == 0;
    if is_root {
        let direct = Command::new(bin(cmd))
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if matches!(direct, Ok(s) if s.success()) {
            return Ok(());
        }
    }
    sudo(cmd, args)
}

/// Run a privileged command via `sudo`, inheriting stdio. On the appliance the
/// admin is passwordless-wheel, so this is seamless; `sudo` is a transparent
/// passthrough when already root. The command itself is passed by absolute path
/// so sudo execs it directly, bypassing `secure_path` lookup entirely.
fn sudo(cmd: &str, args: &[&str]) -> Result<()> {
    let resolved = bin(cmd);
    let mut all = vec![resolved.as_str()];
    all.extend_from_slice(args);
    let status = Command::new("sudo")
        .args(&all)
        .status()
        .with_context(|| format!("running `sudo {}`", all.join(" ")))?;
    if !status.success() {
        bail!("`sudo {}` failed (exit {:?})", all.join(" "), status.code());
    }
    Ok(())
}
