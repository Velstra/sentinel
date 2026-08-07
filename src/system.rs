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

/// Set the console keyboard layout live (`loadkeys`), so it applies without a
/// reboot the way every other committed setting does.
pub fn load_keymap(name: &str) -> Result<()> {
    run_priv("loadkeys", &[name])
}

/// Set the system timezone (`timedatectl set-timezone`). Unlike the hostname,
/// NixOS does not block this one: the zone is a symlink `timedatectl` owns.
pub fn set_timezone(zone: &str) -> Result<()> {
    run_priv("timedatectl", &["set-timezone", zone])
}

/// Reload the velstra data plane so it picks up a freshly written config.
pub fn reload_velstra(unit: &str) -> Result<()> {
    run_priv("systemctl", &["reload-or-restart", unit])
}

/// Whether `unit` is currently running. `systemctl is-active` needs no
/// privilege, so this is a plain read.
pub fn unit_active(unit: &str) -> bool {
    let out = Command::new(bin("systemctl"))
        .args(["is-active", unit])
        .output();
    matches!(out, Ok(o) if String::from_utf8_lossy(&o.stdout).trim() == "active")
}

/// Restart `unit` to pick up a freshly written drop-in — but ONLY when it is
/// already running. These are always-enabled co-services (resolved/chrony/
/// dnsmasq): at boot the sentinel-boot service writes their drop-in and they
/// read it on their own (later) start, so no restart is needed there. And a
/// synchronous `systemctl restart` issued from the early sentinel-boot (which is
/// ordered Before systemd-networkd) would DEADLOCK — the restart job waits for
/// the network the service orders after, which waits for networkd, which waits
/// for sentinel-boot to finish. `commit` runs with the service up, so it
/// restarts live exactly as before.
fn restart_if_active(unit: &str) -> Result<()> {
    if !unit_active(unit) {
        return Ok(());
    }
    run_priv("systemctl", &["restart", unit])
}

/// Restart systemd-resolved so a freshly written drop-in takes effect. A plain
/// `restart` (not reload) is used deliberately: adding/removing a
/// `DNSStubListenerExtra=` listener requires resolved to re-bind its sockets,
/// which a reload (SIGHUP) does not do. Callers gate this to `ApplyMode::Live`
/// only — at boot the drop-in is written and resolved reads it on its own start
/// (a restart from the pre-networkd sentinel-boot would deadlock).
pub fn reload_resolved() -> Result<()> {
    restart_if_active("systemd-resolved.service")
}

/// Restart chrony so a freshly written confdir drop-in takes effect. A restart
/// (not reload) is used because chrony only reloads *sources* live; `server` /
/// `allow` directives in a confdir file are applied on start. Live-mode only
/// (see [`reload_resolved`]).
pub fn reload_chrony() -> Result<()> {
    restart_if_active("chronyd.service")
}

/// Restart dnsmasq so a freshly written conf-dir drop-in takes effect (new
/// `interface=`/`server=`/`address=` lines need a re-read + re-bind, which a
/// SIGHUP does not fully do for interface bindings). Live-mode only (see
/// [`reload_resolved`]).
pub fn reload_dnsmasq() -> Result<()> {
    restart_if_active("dnsmasq.service")
}

/// (Re)start the `sentinel-pppoe@<name>` templated unit that runs `pppd` for one
/// PPPoE session. A `restart` (re-dial) is used deliberately: it applies fresh
/// peer options / credentials by tearing the old `pppd` down and dialling again,
/// and starts the session if it wasn't running. Only sessions whose rendered
/// config actually changed are restarted (by [`crate::net`]), so an unrelated
/// commit never drops a live WAN link.
pub fn pppoe_restart(name: &str) -> Result<()> {
    run_priv(
        "systemctl",
        &["restart", &format!("sentinel-pppoe@{name}.service")],
    )
}

/// (Re)start a templated unit for one radio (`sentinel-hostapd@<if>` or
/// `sentinel-supplicant@<if>`). A restart rather than a reload: hostapd and
/// wpa_supplicant read their config once, at start.
pub fn radio_restart(unit: &str) -> Result<()> {
    run_priv("systemctl", &["restart", unit])
}

/// Stop a radio's daemon (its interface is no longer configured, or changed
/// role). Best-effort at the call site — a stop that fails because the unit was
/// never up must not abort the reconcile.
pub fn radio_stop(unit: &str) -> Result<()> {
    run_priv("systemctl", &["stop", unit])
}

/// Stop and disband the `sentinel-pppoe@<name>` session (a PPPoE interface that
/// is no longer configured). Best-effort at the call site — a stop that fails
/// because the unit was never up must not abort the reconcile.
pub fn pppoe_stop(name: &str) -> Result<()> {
    run_priv(
        "systemctl",
        &["stop", &format!("sentinel-pppoe@{name}.service")],
    )
}

/// Turn one offload feature on or off (`ethtool -K <dev> <feature> on|off`).
pub fn ethtool_offload(dev: &str, feature: &str, on: bool) -> Result<()> {
    run_priv(
        "ethtool",
        &["-K", dev, feature, if on { "on" } else { "off" }],
    )
}

/// Force a NIC's link speed and duplex (`ethtool -s <dev> speed N duplex D
/// autoneg off`). The two go together — a card handed one of them keeps
/// autonegotiating, and the link comes up at the wrong speed silently.
pub fn ethtool_link(dev: &str, speed: u32, duplex: &str) -> Result<()> {
    run_priv(
        "ethtool",
        &[
            "-s",
            dev,
            "speed",
            &speed.to_string(),
            "duplex",
            duplex,
            "autoneg",
            "off",
        ],
    )
}

/// Resize a NIC's ring buffers (`ethtool -G`). Either direction alone is valid.
pub fn ethtool_ring(dev: &str, rx: Option<u32>, tx: Option<u32>) -> Result<()> {
    let mut args: Vec<String> = vec!["-G".into(), dev.into()];
    if let Some(n) = rx {
        args.push("rx".into());
        args.push(n.to_string());
    }
    if let Some(n) = tx {
        args.push("tx".into());
        args.push(n.to_string());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_priv("ethtool", &refs)
}

/// Set a NIC's interrupt coalescing (`ethtool -C`).
pub fn ethtool_coalesce(dev: &str, params: &[(&str, String)]) -> Result<()> {
    let mut args: Vec<String> = vec!["-C".into(), dev.into()];
    for (k, v) in params {
        args.push((*k).into());
        args.push(v.clone());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_priv("ethtool", &refs)
}

/// Set one kernel parameter now (`sysctl -w name=value`).
///
/// Through `sysctl(8)` under `run_priv`, not a direct `/proc/sys` write. The
/// direct write is one fewer tool to pin, and it works — as root. `commit` is run
/// by the operator, who is not root, so every live apply failed with a warning
/// and the parameter took effect at the *next boot* instead, from the drop-in.
/// The doc on `apply_sysctl` claimed the apply is what makes `commit` mean now;
/// for anyone but the boot service it did not. Found by a VM check reading an ARP
/// switch back out of the running kernel.
///
/// `sysctl(8)` also handles the interface-name escaping natively — see
/// [`sysctl_iface_key`].
pub fn sysctl_write(key: &str, value: &str) -> Result<()> {
    run_priv("sysctl", &["-qw", &format!("{key}={value}")])
}

/// Set one *per-interface* kernel parameter now — `dir` is the sysctl directory
/// (`net.ipv4.conf`, `net.ipv6.conf`, `net.ipv4.neigh`), `iface` the link, `knob`
/// the leaf.
pub fn sysctl_write_iface(dir: &str, iface: &str, knob: &str, value: &str) -> Result<()> {
    sysctl_write(&sysctl_iface_key(dir, iface, knob), value)
}

/// The name of a per-interface parameter, as both `sysctl(8)` and a `sysctl.d`
/// file spell it.
///
/// The swap is the point. A VLAN subinterface is called `eth0.100`, and its
/// parameter is `net.ipv4.conf.eth0/100.arp_filter` — dot and slash trade places
/// so the name stays parseable. Spelling it the obvious way would address
/// `/proc/sys/net/ipv4/conf/eth0/100/arp_filter`, a path that does not exist, and
/// the setting would be silently absent on exactly the interfaces a firewall has
/// most of.
pub fn sysctl_iface_key(dir: &str, iface: &str, knob: &str) -> String {
    format!("{dir}.{}.{knob}", iface.replace('.', "/"))
}

/// Attach a `clsact` qdisc, which carries an ingress and an egress filter hook
/// without owning the root. `add` rather than `replace`, and the caller ignores
/// the failure: replacing it would take every filter — including the datapath's
/// own TC program — down with it, and an already-present clsact is the normal
/// case rather than an error.
pub fn tc_qdisc_add_clsact(dev: &str) -> Result<()> {
    run_priv("tc", &["qdisc", "add", "dev", dev, "clsact"])
}

/// Remove one of our filters by priority, so a changed mirror does not leave the
/// direction it used to point at still filtering.
pub fn tc_filter_del(dev: &str, dir: &str, prio: &str) -> Result<()> {
    run_priv("tc", &["filter", "del", "dev", dev, dir, "prio", prio])
}

/// Run an arbitrary `tc` invocation the caller has already assembled.
pub fn tc_run(args: &[&str]) -> Result<()> {
    run_priv("tc", args)
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

/// (Re)start the `sentinel-multiwan` daemon that health-checks the WAN uplinks
/// and programs the failover default route (roadmap C6). A `restart` re-reads the
/// freshly rendered health script and starts the daemon if it wasn't running;
/// only invoked (by [`crate::net`]) when the rendered config changed.
pub fn multiwan_restart() -> Result<()> {
    run_priv("systemctl", &["restart", "sentinel-multiwan.service"])
}

/// Stop the `sentinel-multiwan` daemon (no uplink configured any more).
/// Best-effort at the call site — a stop that fails because the unit was never up
/// must not abort the reconcile.
pub fn multiwan_stop() -> Result<()> {
    run_priv("systemctl", &["stop", "sentinel-multiwan.service"])
}

/// Flush a policy-routing table (`ip route flush table <n>`) — used to tear down
/// the routes a removed Multi-WAN uplink owned so no stale default lingers.
pub fn ip_route_flush_table(table: u32) -> Result<()> {
    run_priv("ip", &["route", "flush", "table", &table.to_string()])
}

/// The routing-policy rules the appliance owns, as `ip rule` prints them. Only
/// the priority band in [`crate::net::PBR_PRIORITY_BASE`] is ours; anything else
/// in the table belongs to the kernel or to somebody else and is left alone.
pub fn ip_rule_list() -> Result<String> {
    let is_root = unsafe { libc::geteuid() } == 0;
    let ip = bin("ip");
    let args = ["-o", "rule", "show"];
    let output = if is_root {
        Command::new(&ip).args(args).output()
    } else {
        let mut all = vec![ip.as_str()];
        all.extend_from_slice(&args);
        Command::new("sudo").args(&all).output()
    };
    let out = output.context("running ip rule show")?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Add or delete one routing-policy rule. The arguments are built by the caller
/// from the configuration; nothing here interprets them.
pub fn ip_rule(args: &[&str]) -> Result<()> {
    let mut all = vec!["rule"];
    all.extend_from_slice(args);
    run_priv("ip", &all)
}

/// Load a rendered strongSwan swanctl config into the running `charon` daemon
/// (roadmap C2 IPsec): `swanctl --load-all --file <path> --noprompt`. `--load-all`
/// reconciles connections, children and secrets to exactly what the file
/// declares (unloading anything removed), so a re-load after a config change
/// applies adds and removals in one step; `--noprompt` never blocks on a missing
/// credential. Only invoked (by [`crate::ipsec`]) when the rendered config
/// changed, or to (re)assert a tunnel at boot.
pub fn swanctl_load(path: &Path) -> Result<()> {
    let Some(p) = path.to_str() else {
        bail!("non-UTF-8 path");
    };
    run_priv("swanctl", &["--load-all", "--file", p, "--noprompt"])
}

/// Run a read-only `swanctl` query and return its stdout (for `show vpn` — the
/// SA / connection state). charon's vici control socket is root-only, so this
/// must run privileged: directly when already root, else via `sudo` (the admin
/// is passwordless-wheel on the appliance). The exit code is ignored, like the
/// other `show` paths, so an empty/inactive daemon still prints cleanly.
pub fn swanctl_show(args: &[&str]) -> Result<String> {
    let is_root = unsafe { libc::geteuid() } == 0;
    let swanctl = bin("swanctl");
    let output = if is_root {
        Command::new(&swanctl).args(args).output()
    } else {
        let mut all = vec![swanctl.as_str()];
        all.extend_from_slice(args);
        Command::new("sudo").args(&all).output()
    };
    let out = output.with_context(|| "running swanctl")?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Stage `contents` into `tmp` as a private **0600** file. `std::fs::write`
/// honours the process umask (typically 0644), which would leave the staged
/// secret world-readable in the wheel-writable, world-traversable `/run/sentinel`
/// until the next apply — `install` *copies* to the final owner/mode, so the temp
/// source is never removed by it. Creating the temp 0600 closes that window; the
/// final installed file still gets whatever mode the `install -m` call sets.
pub(crate) fn stage_private(tmp: &Path, contents: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(tmp)
        .with_context(|| format!("staging {}", tmp.display()))?;
    f.write_all(contents.as_bytes())
        .with_context(|| format!("staging {}", tmp.display()))
}

/// Install a strongSwan PSK secrets file at a root-owned `path`, mode **0600
/// root:root**. `charon` runs as root, so the pre-shared key never needs to leave
/// root — 0600 is the tightest mode that still works. Staged in `/run/sentinel`
/// (wheel-writable) then `install`-ed atomically, so there is never a window
/// where the key is group- or world-readable, in both the boot-service (root) and
/// `configure` (admin) paths.
pub fn install_ipsec_secret(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    let tmp = Path::new("/run/sentinel").join(".ipsec-secret.tmp");
    stage_private(&tmp, contents)?;
    let (Some(tmp_s), Some(dst_s)) = (tmp.to_str(), path.to_str()) else {
        bail!("non-UTF-8 path");
    };
    sudo("install", &["-m", "0600", tmp_s, dst_s])
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
    stage_private(&tmp, contents)?;
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
    stage_private(&tmp, contents)?;
    let (Some(tmp_s), Some(dst_s)) = (tmp.to_str(), path.to_str()) else {
        bail!("non-UTF-8 path");
    };
    sudo(
        "install",
        &["-m", "0640", "-g", "systemd-network", tmp_s, dst_s],
    )
}

/// Install a root-owned private file at `path`, mode **0600 root:root** —
/// staged in `/run/sentinel` (wheel-writable) and then `install`ed atomically, so
/// there is never a window where the contents are group- or world-readable.
///
/// Used for key material Sentinel receives rather than generates: an ACME
/// certificate's private key arrives as bytes from lego, so it cannot be created
/// in place inside an already-locked directory the way `pki` generates a leaf.
pub fn install_private_file(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    let tmp = Path::new("/run/sentinel").join(".private.tmp");
    stage_private(&tmp, contents)?;
    let (Some(tmp_s), Some(dst_s)) = (tmp.to_str(), path.to_str()) else {
        bail!("non-UTF-8 path");
    };
    sudo("install", &["-m", "0600", tmp_s, dst_s])
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
    stage_private(&tmp, contents)?;
    let (Some(tmp_s), Some(dst_s)) = (tmp.to_str(), path.to_str()) else {
        bail!("non-UTF-8 path");
    };
    sudo("install", &["-m", "0600", tmp_s, dst_s])
}

/// Install the alert-mail (msmtp) config at a root-owned `path`, mode **0600
/// root:root**. 0600 is not a preference here: msmtp **refuses to run** against a
/// config carrying a password that is group- or world-readable, so a looser mode
/// would turn into "alerts silently stopped working". Same stage-then-`install`
/// dance as the other secrets, so the password is never briefly readable.
pub fn install_alert_secret(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    let tmp = Path::new("/run/sentinel").join(".alert-secret.tmp");
    stage_private(&tmp, contents)?;
    let (Some(tmp_s), Some(dst_s)) = (tmp.to_str(), path.to_str()) else {
        bail!("non-UTF-8 path");
    };
    sudo("install", &["-m", "0600", tmp_s, dst_s])
}

/// Install a service secret (an SNMP community, a dyndns password) at a
/// root-owned `path`, mode **0640 root:root** — readable by root but never
/// world-readable. The consuming daemon (snmpd, ddclient) runs as root, so 0640
/// is ample; the group bit only matters if a monitoring group is later added.
/// Staged in `/run/sentinel` (wheel-writable) then `install`ed atomically, so
/// there is never a window where the secret is world-readable, in both the
/// boot-service (root) and `configure` (admin) paths.
pub fn install_service_secret(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    let tmp = Path::new("/run/sentinel").join(".svc-secret.tmp");
    stage_private(&tmp, contents)?;
    let (Some(tmp_s), Some(dst_s)) = (tmp.to_str(), path.to_str()) else {
        bail!("non-UTF-8 path");
    };
    sudo("install", &["-m", "0640", tmp_s, dst_s])
}

/// (Re)start a Sentinel-owned box service (`sentinel-snmpd`, `lldpd`, …) to pick
/// up freshly rendered config — a `restart` re-reads the config and starts it if
/// it wasn't running. Only invoked (by [`crate::net`]) when the rendered config
/// changed, or to (re)assert the service at boot-late (after networkd). Mirrors
/// [`multiwan_restart`], generalised over the unit name.
pub fn service_restart(unit: &str) -> Result<()> {
    run_priv("systemctl", &["restart", unit])
}

/// Stop a Sentinel-owned box service (its config was removed). Best-effort at the
/// call site — a stop that fails because the unit was never up must not abort the
/// reconcile. Mirrors [`multiwan_stop`], generalised over the unit name.
pub fn service_stop(unit: &str) -> Result<()> {
    run_priv("systemctl", &["stop", unit])
}

/// Ensure a service is running WITHOUT dropping existing connections — unlike
/// `restart`, `start` is a no-op when the unit is already up. Used to (re)assert
/// `sshd` after an `enable` toggle so a `commit` that only added a key doesn't cut
/// live admin sessions.
pub fn service_start(unit: &str) -> Result<()> {
    run_priv("systemctl", &["start", unit])
}

/// Ensure a local login account exists (roadmap C21, `[[system.login]]`). A no-op
/// when the user is already present (the built-in `admin`, or a prior commit's
/// account); otherwise `useradd -m -G wheel` creates it with a home, sudo/console
/// access via `wheel`, and the appliance login shell. Needs `mutableUsers` on.
pub fn ensure_login_account(user: &str) -> Result<()> {
    let present = Command::new(bin("id"))
        .arg("-u")
        .arg(user)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if present {
        return Ok(());
    }
    run_priv(
        "useradd",
        &[
            "-m",
            "-G",
            "wheel",
            "-s",
            "/run/current-system/sw/bin/bash",
            user,
        ],
    )
}

/// Set a login account's password to a pre-hashed crypt(3) value (`chpasswd`-style)
/// via `usermod -p`. The hash is passed as an argv element — never through a shell —
/// so its `$`-laden crypt form needs no escaping and cannot be expanded or logged by
/// a shell. Validation already guarantees it is a hash, not a plaintext password.
pub fn set_login_password(user: &str, hash: &str) -> Result<()> {
    run_priv("usermod", &["-p", hash, user])
}

/// Install the shared HA-sync bearer token at `path`, mode 0600 (root). Staged in
/// the wheel-writable `/run/sentinel` then `install`-ed, so it works both as the
/// admin (`configure`) and as root (boot) — mirrors [`install_secret_file`] but
/// 0600 root:root (the API reads it as root; no other reader needs it).
pub fn install_token(path: &Path, secret: &str) -> Result<()> {
    let tmp = Path::new("/run/sentinel").join(".api-token.tmp");
    std::fs::write(&tmp, secret).with_context(|| format!("staging {}", tmp.display()))?;
    let (Some(tmp_s), Some(dst_s)) = (tmp.to_str(), path.to_str()) else {
        bail!("non-UTF-8 path");
    };
    sudo("install", &["-m", "0600", tmp_s, dst_s])
}

/// PUT a config body (a file of JSON) to a peer's Sentinel API for HA config sync
/// (roadmap C21). Best-effort at the call site — a down peer must not fail the local
/// commit. The bearer token is an argv element (no shell), so it is never expanded
/// or logged; a short timeout keeps a commit from hanging on an unreachable peer.
/// `GET url` with a bearer token, returning the body.
///
/// The stack view's one way of reaching a peer. Deliberately the same tool the
/// config-sync push already uses rather than a second HTTP client in the
/// binary: one place to get TLS, timeouts and proxy behaviour wrong is enough.
/// The timeout is short — a peer that is down must make the console say so
/// quickly, not hang the page.
pub fn curl_get(url: &str, token: &str, timeout_secs: u32) -> Result<String> {
    let auth = format!("Authorization: Bearer {token}");
    let timeout = timeout_secs.to_string();
    let out = Command::new(bin("curl"))
        .args(["-sS", "-f", "--max-time", &timeout, "-H", &auth, url])
        .stderr(Stdio::null())
        .output()
        .with_context(|| format!("running curl to {url}"))?;
    if !out.status.success() {
        bail!("curl GET {url} failed");
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Ask the road-warrior VPN something, as JSON.
///
/// `occtl` talks to ocserv over a root-owned control socket, so this runs
/// privileged like the other operational queries. An error means the VPN could
/// not be asked — which the caller must not confuse with "nobody is connected".
pub fn occtl_json(args: &[&str]) -> Result<String> {
    let mut all = vec!["--json"];
    all.extend_from_slice(args);
    let is_root = unsafe { libc::geteuid() } == 0;
    let occtl = bin("occtl");
    let output = if is_root {
        Command::new(&occtl).args(&all).output()
    } else {
        // `-n`: never prompt. This runs on every commit that has a user group,
        // and a password prompt there would hang the commit on a box where the
        // operator is not sitting at the terminal — including the API's. If the
        // VPN cannot be asked without a password, it cannot be asked.
        let mut sudoed = vec!["-n", occtl.as_str()];
        sudoed.extend_from_slice(&all);
        Command::new("sudo").args(&sudoed).output()
    };
    let out = output.context("running occtl")?;
    if !out.status.success() {
        bail!("occtl did not answer");
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Bind to a directory as `dn`, with the password read from `secret_file`.
///
/// Returns the process's exit status for the caller to read as an answer — 0 is
/// a successful bind, 49 is invalid credentials, anything else means the
/// directory did not answer. `-x` is a simple bind (not SASL); `-ZZ` demands
/// StartTLS and fails rather than falling back to plaintext, which is the whole
/// point of asking for it.
pub fn ldapwhoami(
    uri: &str,
    dn: &str,
    secret_file: &Path,
    starttls: bool,
    timeout_secs: u32,
) -> Result<Option<i32>> {
    let Some(secret) = secret_file.to_str() else {
        bail!("non-UTF-8 path");
    };
    let timeout = timeout_secs.to_string();
    let mut args = vec!["-x", "-H", uri, "-D", dn, "-y", secret, "-o"];
    let net_timeout = format!("nettimeout={timeout}");
    args.push(&net_timeout);
    if starttls {
        args.push("-ZZ");
    }
    let out = Command::new(bin("ldapwhoami"))
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .with_context(|| format!("running ldapwhoami against {uri}"))?;
    Ok(out.status.code())
}

/// Fetch a URL with no credential attached — a published list, not an appliance
/// API. Separate from [`curl_get`] so a feed can never carry this box's token to
/// somebody else's web server.
pub fn curl_get_plain(url: &str, timeout_secs: u32) -> Result<String> {
    let timeout = timeout_secs.to_string();
    let out = Command::new(bin("curl"))
        .args(["-sS", "-f", "--max-time", &timeout, url])
        .stderr(Stdio::null())
        .output()
        .with_context(|| format!("running curl to {url}"))?;
    if !out.status.success() {
        bail!("fetching {url} failed");
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn curl_put_config(url: &str, token: &str, body_file: &Path) -> Result<()> {
    let auth = format!("Authorization: Bearer {token}");
    let data = format!("@{}", body_file.display());
    let status = Command::new(bin("curl"))
        .args([
            "-sS",
            "-f",
            "--max-time",
            "10",
            "-X",
            "PUT",
            "-H",
            "Content-Type: application/json",
            "-H",
            &auth,
            "--data-binary",
            &data,
            url,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("running curl to {url}"))?;
    if !status.success() {
        bail!("curl PUT {url} failed");
    }
    Ok(())
}

/// Make systemd re-read unit files after Sentinel wrote/removed one under
/// `/run/systemd/system` (e.g. the dynamic time-based-rules timer). Required
/// before starting a freshly written unit.
pub fn daemon_reload() -> Result<()> {
    run_priv("systemctl", &["daemon-reload"])
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

/// Ensure a directory exists with an explicit mode (privileged `mkdir -m <mode>
/// -p`). Used for the PKI store's per-CA/per-cert subdir, created **0700** so a
/// key generated inside it is never reachable through a world-readable parent
/// before its own mode is tightened. `-m` applies to the final component only,
/// so intermediate dirs keep the default mode; on an existing dir `mkdir -p` is
/// a no-op, so the mode is re-asserted with a `chmod` afterwards.
pub fn ensure_dir_mode(dir: &Path, mode: &str) -> Result<()> {
    let Some(d) = dir.to_str() else {
        bail!("non-UTF-8 path");
    };
    if dir.is_dir() {
        return set_mode(dir, mode);
    }
    run_priv("mkdir", &["-m", mode, "-p", d])
}

/// Set the mode of a (possibly root-owned) path, privileged (`chmod <mode>`).
/// Used by the PKI applier to lock a freshly generated key to 0600 and relax its
/// containing directory back to 0755 once the key material is in place.
pub fn set_mode(path: &Path, mode: &str) -> Result<()> {
    let Some(p) = path.to_str() else {
        bail!("non-UTF-8 path");
    };
    run_priv("chmod", &[mode, p])
}

/// Run `openssl` privileged (roadmap C19 PKI): generate a CA / leaf key +
/// certificate into the persistent store under `/var/lib/sentinel/pki`. Root is
/// used so a leaf can be signed with a 0600 CA key and every artifact is
/// consistently root-owned in both the boot-service (root) and `configure`
/// (admin, via `sudo`) paths. openssl reads no secret from `args` (only subject
/// / path arguments), so surfacing them on failure leaks nothing.
pub fn openssl(args: &[&str]) -> Result<()> {
    run_priv("openssl", args)
}

/// Tell systemd-networkd to re-read its unit files and re-apply them to the
/// given links — so a freshly written `.network` takes effect immediately.
/// Best-effort: at early boot networkd may not be up yet (it reads the files on
/// start anyway), so failures are reported by the caller, not fatal here.
pub fn networkctl_reload(ifaces: &[String]) -> Result<()> {
    // NOTE: this talks to networkd over D-Bus, which on-demand *activates* it if
    // down — fatal at early boot where sentinel-boot is ordered Before networkd
    // (the out-of-order activation deadlocks the boot). Callers therefore invoke
    // this only in `ApplyMode::Live` (networkd already up); at boot networkd
    // reads the freshly written `.network` units on its own start.
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
        "ldapwhoami" => "SENTINEL_LDAPWHOAMI_BIN",
        "occtl" => "SENTINEL_OCCTL_BIN",
        "ip" => "SENTINEL_IP_BIN",
        "networkctl" => "SENTINEL_NETWORKCTL_BIN",
        "systemctl" => "SENTINEL_SYSTEMCTL_BIN",
        "systemd-run" => "SENTINEL_SYSTEMD_RUN_BIN",
        "journalctl" => "SENTINEL_JOURNALCTL_BIN",
        "wren" => "SENTINEL_WREN_BIN",
        "tc" => "SENTINEL_TC_BIN",
        "loadkeys" => "SENTINEL_LOADKEYS_BIN",
        "timedatectl" => "SENTINEL_TIMEDATECTL_BIN",
        "sysctl" => "SENTINEL_SYSCTL_BIN",
        "swanctl" => "SENTINEL_SWANCTL_BIN",
        "openssl" => "SENTINEL_OPENSSL_BIN",
        "ethtool" => "SENTINEL_ETHTOOL_BIN",
        "lego" => "SENTINEL_LEGO_BIN",
        "lsblk" => "SENTINEL_LSBLK_BIN",
        "tcpdump" => "SENTINEL_TCPDUMP_BIN",
        "timeout" => "SENTINEL_TIMEOUT_BIN",
        "install" => "SENTINEL_INSTALL_BIN",
        "mkdir" => "SENTINEL_MKDIR_BIN",
        "chmod" => "SENTINEL_CHMOD_BIN",
        "rm" => "SENTINEL_RM_BIN",
        // local login accounts ([[system.login]], roadmap C21)
        "useradd" => "SENTINEL_USERADD_BIN",
        "usermod" => "SENTINEL_USERMOD_BIN",
        "id" => "SENTINEL_ID_BIN",
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
