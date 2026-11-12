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

/// The answers this system actually has for a setting whose values are a closed
/// set the appliance does not compile in.
///
/// The commit-time validator for a timezone deliberately checks against
/// `/usr/share/zoneinfo` rather than against a table in this binary, because
/// tzdata and the keymap package move independently of the appliance and a
/// table here would eventually refuse a zone that exists. A console offering a
/// picker built from a table would have the same bug one step earlier — it
/// would fail to *offer* a zone that exists — so the picker is built from the
/// same place the validator reads.
///
/// Never an error for the caller: a system with no zoneinfo (a container, a
/// workstation running the tests) has no answers, and the field is then an
/// ordinary box you type into. That is exactly what it was before.
pub fn choices(kind: &str) -> Result<Vec<String>> {
    let mut out = match kind {
        "timezone" => zone_names(),
        "keyboard" => keymap_names(),
        "locale" => locale_names(),
        other => bail!("unknown choices {other:?} (timezone | keyboard | locale)"),
    };
    out.sort();
    out.dedup();
    Ok(out)
}

/// Every zone under `/usr/share/zoneinfo`, named the way the setting is written.
///
/// `posix/` and `right/` are the same zones over again under two different leap
/// second models, and the tables next to them (`zone.tab`, `tzdata.zi`) are not
/// zones at all — a name with a dot in it never is.
fn zone_names() -> Vec<String> {
    let root = Path::new("/usr/share/zoneinfo");
    let mut out = Vec::new();
    walk_zones(root, root, &mut out, 0);
    out
}

fn walk_zones(root: &Path, dir: &Path, out: &mut Vec<String>, depth: usize) {
    // Three levels is every zone tzdata has (`America/Indiana/Knox`); a fourth
    // would only be a link loop.
    if depth > 3 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') || name.contains('.') {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            if depth == 0 && (name == "posix" || name == "right") {
                continue;
            }
            walk_zones(root, &path, out, depth + 1);
            continue;
        }
        // `localtime` and `posixrules` are this machine's own choices rather
        // than zones anybody would set.
        if name == "localtime" || name == "posixrules" {
            continue;
        }
        if let Ok(rel) = path.strip_prefix(root) {
            out.push(rel.to_string_lossy().into_owned());
        }
    }
}

/// Every console keymap this system carries, by the name `loadkeys` takes.
///
/// Two packages put them in two places — `kbd` under `/usr/share/kbd/keymaps`,
/// console-data under `/usr/share/keymaps` — and both are read, because which
/// one an image has is not something the console should have an opinion about.
fn keymap_names() -> Vec<String> {
    let mut out = Vec::new();
    for root in ["/usr/share/kbd/keymaps", "/usr/share/keymaps"] {
        walk_keymaps(Path::new(root), &mut out, 0);
    }
    out
}

fn walk_keymaps(dir: &Path, out: &mut Vec<String>, depth: usize) {
    if depth > 4 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_keymaps(&path, out, depth + 1);
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        // `de.map.gz` is loaded as `de`: the name before the first dot is what
        // the setting holds, and it is what the validator allows.
        let Some(stem) = name.split('.').next() else {
            continue;
        };
        if !name.contains(".map") || stem.is_empty() {
            continue;
        }
        if stem
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            out.push(stem.to_string());
        }
    }
}

/// The locales this system has built, from `locale -a`.
///
/// Asked of glibc rather than read off a path, because where the built locales
/// live is a glibc build option and `locale -a` is the one answer that is true
/// on every image. A box without the tool simply has nothing to offer.
fn locale_names() -> Vec<String> {
    let Ok(out) = Command::new("locale")
        .arg("-a")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        // The validator takes `xx_YY.CHARSET`, `C` and `POSIX` and nothing
        // else, so `locale -a`'s aliases (`german`, `en_US` without a charset)
        // are dropped rather than offered and then refused.
        .filter(|l| {
            *l == "C" || *l == "POSIX" || {
                let (lang, charset) = l.split_once('.').unwrap_or((l, ""));
                let (a, b) = lang.split_once('_').unwrap_or(("", ""));
                !charset.is_empty()
                    && a.len() == 2
                    && b.len() >= 2
                    && a.bytes().all(|c| c.is_ascii_lowercase())
                    && b.bytes().all(|c| c.is_ascii_uppercase())
            }
        })
        .map(str::to_string)
        .collect()
}

/// Reload the velstra data plane so it picks up a freshly written config.
pub fn reload_compiled(unit: &str, previous: Option<&[u8]>, next: &[u8]) -> Result<()> {
    let command = if unit == "velstra.service" && policy_identity_changed(previous, next) {
        // Conntrack keys contain the numeric policy ID. Reusing an ID for a
        // different zone must never inherit that zone's established sessions,
        // NAT mappings, counters or other policy-scoped runtime state.
        "reload-reset"
    } else {
        "reload"
    };
    reload_agent(unit, command)
}

fn policy_identity_changed(previous: Option<&[u8]>, next: &[u8]) -> bool {
    #[derive(serde::Deserialize)]
    struct Identities {
        #[serde(default)]
        policy: Vec<Identity>,
    }
    #[derive(serde::Deserialize)]
    struct Identity {
        id: u32,
        name: Option<String>,
    }
    let identities = |bytes: &[u8]| {
        let text = std::str::from_utf8(bytes).ok()?;
        let parsed: Identities = toml::from_str(text).ok()?;
        Some(
            parsed
                .policy
                .into_iter()
                .map(|p| (p.id, p.name))
                .collect::<std::collections::BTreeMap<_, _>>(),
        )
    };
    match (previous.and_then(identities), identities(next)) {
        (Some(old), Some(new)) => old.iter().any(|(id, name)| new.get(id) != Some(name)),
        _ => true,
    }
}

fn reload_agent(unit: &str, command: &str) -> Result<()> {
    if unit == "velstra.service" && unit_active(unit) {
        let reply = crate::velstra::query(command);
        if let Ok(reply) = reply {
            match reply.trim() {
                "ok" => return Ok(()),
                "restart-required" => return service_restart(unit),
                message if message.starts_with("error:") => bail!("{message}"),
                // Older agents have no reload verb. Restart once to upgrade.
                _ => {}
            }
        } else if Path::new(crate::velstra::SOCKET).exists() {
            return Err(reply.unwrap_err()).context("live data-plane reload failed");
        }
    }
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

/// Restart systemd-resolved so a freshly written drop-in takes effect. A plain
/// `restart` (not reload) is used deliberately: adding/removing a
/// `DNSStubListenerExtra=` listener requires resolved to re-bind its sockets,
/// which a reload (SIGHUP) does not do. Callers gate this to `ApplyMode::Live`
/// only — at boot the drop-in is written and resolved reads it on its own start
/// (a restart from the pre-networkd sentinel-boot would deadlock).
pub fn reload_resolved() -> Result<()> {
    service_restart("systemd-resolved.service")
}

/// Restart chrony so a freshly written confdir drop-in takes effect. A restart
/// (not reload) is used because chrony only reloads *sources* live; `server` /
/// `allow` directives in a confdir file are applied on start. Live-mode only
/// (see [`reload_resolved`]).
pub fn reload_chrony() -> Result<()> {
    service_restart("chronyd.service")
}

/// Restart dnsmasq so a freshly written conf-dir drop-in takes effect (new
/// `interface=`/`server=`/`address=` lines need a re-read + re-bind, which a
/// SIGHUP does not fully do for interface bindings). Live-mode only (see
/// [`reload_resolved`]).
pub fn reload_dnsmasq() -> Result<()> {
    service_restart("dnsmasq.service")
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
    let mut all = Vec::with_capacity(args.len() + 1);
    if let Some((&family @ ("-4" | "-6"), rest)) = args.split_first() {
        all.push(family);
        all.push("rule");
        all.extend_from_slice(rest);
    } else {
        all.push("rule");
        all.extend_from_slice(args);
    }
    run_priv("ip", &all)
}

/// Add, replace or delete one route. Like [`ip_rule`], the arguments are the
/// caller's — this only supplies the privilege.
pub fn ip_route(args: &[&str]) -> Result<()> {
    let mut all = vec!["route"];
    all.extend_from_slice(args);
    run_priv("ip", &all)
}

/// Add, delete or flush interface addresses. The arguments are the caller's.
pub fn ip_addr(args: &[&str]) -> Result<()> {
    let mut all = vec!["address"];
    all.extend_from_slice(args);
    run_priv("ip", &all)
}

/// Change a link's state. The arguments are the caller's.
pub fn ip_link(args: &[&str]) -> Result<()> {
    let mut all = vec!["link"];
    all.extend_from_slice(args);
    run_priv("ip", &all)
}

/// The addresses the box currently holds, as `ip -o addr show` prints them.
///
/// Read from the kernel rather than from the configuration on purpose: an
/// address can arrive from DHCP, from a peer, or from something outside
/// Sentinel entirely, and a caller asking "what am I actually reachable as"
/// wants the answer, not the intent.
pub fn ip_addr_list() -> Result<String> {
    let is_root = unsafe { libc::geteuid() } == 0;
    let ip = bin("ip");
    let args = ["-o", "addr", "show"];
    let output = if is_root {
        Command::new(&ip).args(args).output()
    } else {
        let mut all = vec![ip.as_str()];
        all.extend_from_slice(&args);
        Command::new("sudo").args(&all).output()
    };
    let out = output.context("running ip addr show")?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Load a rendered strongSwan swanctl config into the running `charon` daemon
/// (roadmap C2 IPsec): `swanctl --load-all --file <path> --noprompt`. `--load-all`
/// reloads definitions/credentials, NOT established start-action=none SAs.
/// [`crate::ipsec`] separately unloads and revokes removed/changed connections
/// before this call. `--noprompt` never waits for an interactive credential.
pub fn swanctl_load(path: &Path) -> Result<()> {
    let Some(p) = path.to_str() else {
        bail!("non-UTF-8 path");
    };
    run_priv("swanctl", &["--load-all", "--file", p, "--noprompt"])
}

/// Unload retired definitions before revoking their SAs, without reloading
/// credentials or touching unchanged connections' established associations.
pub fn swanctl_reload_connections(path: &Path) -> Result<()> {
    let p = path.to_str().context("non-UTF-8 IPsec config path")?;
    run_priv("swanctl", &["--load-conns", "--file", p])
        .context("unloading retired IPsec definitions")
}

/// Revoke all IKE/CHILD SAs for one proven-owned, already-unloaded connection.
/// Never flush the global XFRM table, restart charon or terminate another name.
/// Even a successful terminate response is not proof: wait for the actual
/// filtered daemon query to become empty before confidentiality guards retire.
pub fn swanctl_revoke(name: &str) -> Result<()> {
    let absent = || -> Result<bool> {
        let out = escalated_output("swanctl", &["--list-sas", "--ike", name])?;
        anyhow::ensure!(out.status.success(), "cannot inspect retired IPsec SAs");
        Ok(out.stdout.iter().all(u8::is_ascii_whitespace))
    };
    if absent()? {
        return Ok(());
    }
    // --force completes local teardown even when the removed peer is offline.
    // A race with a natural close may return a nonzero termination result;
    // only a subsequent successful empty query can make that harmless.
    let _result = escalated_output("swanctl", &["--terminate", "--ike", name, "--force"])?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if absent()? {
            return Ok(());
        }
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "retired IPsec connection still has active SAs; confidentiality guards retained"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
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

/// A reentrant, thread-bound cross-process configuration lock. Nested apply and
/// persist calls share the descriptor; the last guard releases the flock.
#[must_use = "the lock is released as soon as this guard is dropped"]
pub struct ApplyLock {
    _file: Option<std::rc::Rc<std::fs::File>>,
}

thread_local! {
    static APPLY_OWNERS: std::cell::RefCell<std::collections::BTreeMap<std::path::PathBuf,std::rc::Weak<std::fs::File>>> = const { std::cell::RefCell::new(std::collections::BTreeMap::new()) };
}

/// The single lockfile that serialises the apply/persist critical section.
const APPLY_LOCK_PATH: &str = "/run/sentinel/apply.lock";

/// Serialise the config apply/persist critical section across processes.
///
/// Staging always uses fixed temp filenames under `/run/sentinel`
/// (`.net-unit.tmp`, `.appliance.toml.tmp`, `.net-secret.tmp`, …), so a CLI
/// `commit` racing an API `PUT` — or either racing the boot-late reconcile —
/// could write the same temp out from under the other and install a spliced
/// networkd unit or a half-written `velstra.toml` / `appliance.toml`. An
/// exclusive advisory lock on one well-known lockfile makes those sections take
/// turns. It is advisory (`flock`), which is enough because every writer goes
/// through the same two chokepoints ([`crate::repl::apply_live`] and
/// [`crate::session::persist_appliance`]) and so cooperates on the one lock. The
/// call blocks until the lock is ours; the guard releases it on drop.
///
/// Off-box editing has no runtime directory. On an appliance, failure to lock
/// is an error before mutation, rather than permission to race another writer.
pub fn apply_lock() -> Result<ApplyLock> {
    if !Path::new("/run/sentinel").is_dir() {
        return Ok(ApplyLock { _file: None });
    }
    lock_config_at(Path::new(APPLY_LOCK_PATH))
}

pub(crate) fn lock_config_at(path: &Path) -> Result<ApplyLock> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::io::AsRawFd;
    if let Some(file) =
        APPLY_OWNERS.with(|owners| owners.borrow().get(path).and_then(std::rc::Weak::upgrade))
    {
        return Ok(ApplyLock { _file: Some(file) });
    }
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o660)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("opening configuration lock {}", path.display()))?;
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "configuration lock is not a regular file"
    );
    // The boot service creates the lock as root; interactive wheel sessions
    // must lock the same inode rather than silently skipping serialization.
    if unsafe { libc::geteuid() } == 0 {
        if let Some(gid) = wheel_gid() {
            anyhow::ensure!(
                unsafe { libc::fchown(file.as_raw_fd(), 0, gid) } == 0,
                "setting configuration lock group: {}",
                std::io::Error::last_os_error()
            );
        }
        file.set_permissions(std::fs::Permissions::from_mode(0o660))?;
    }
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            break;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("locking configuration transaction");
        }
    }
    let file = std::rc::Rc::new(file);
    APPLY_OWNERS.with(|owners| {
        let mut owners = owners.borrow_mut();
        owners.retain(|_, owner| owner.strong_count() > 0);
        owners.insert(path.to_path_buf(), std::rc::Rc::downgrade(&file));
    });
    Ok(ApplyLock { _file: Some(file) })
}

/// The numeric gid of the `wheel` group, if this system has one. Used to set the
/// saved config's group when writing it directly (as root), so it matches the
/// `install -g wheel` the escalating path uses. Best-effort — a system without a
/// `wheel` group simply leaves the file root-owned.
pub(crate) fn wheel_gid() -> Option<u32> {
    let name = std::ffi::CString::new("wheel").ok()?;
    // SAFETY: `getgrnam` returns a pointer into storage that a later call could
    // overwrite; we read `gr_gid` out immediately while the pointer is non-null
    // and keep nothing that outlives this call.
    let grp = unsafe { libc::getgrnam(name.as_ptr()) };
    if grp.is_null() {
        None
    } else {
        Some(unsafe { (*grp).gr_gid })
    }
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
    // The timer reverts its own change only (see `confirm::rollback`).
    args.push("--commit-confirm".into());
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

pub fn owned_file_exists(path: &Path) -> Result<bool> {
    owned_file_exists_with(path, is_root(), Path::try_exists, |path| {
        let path = path.to_str().context("non-UTF-8 config path")?;
        // The self command is never tried unprivileged, and sudo is always
        // noninteractive. Exit 1 from `sudo test -e` cannot prove absence: sudo
        // itself may have refused execution, or test may lack search access.
        escalated_output("sentinel-self", &["owned-file-probe", "--", path])
    })
}

fn owned_file_exists_with(
    path: &Path,
    root: bool,
    inspect: impl FnOnce(&Path) -> std::io::Result<bool>,
    probe: impl FnOnce(&Path) -> Result<std::process::Output>,
) -> Result<bool> {
    match inspect(path) {
        Ok(exists) => Ok(exists),
        Err(e) if !root && e.kind() == std::io::ErrorKind::PermissionDenied => {
            decode_owned_file_probe(probe(path)?)
                .with_context(|| format!("stat {}", path.display()))
        }
        Err(e) => Err(e).with_context(|| format!("stat {}", path.display())),
    }
}

fn decode_owned_file_probe(output: std::process::Output) -> Result<bool> {
    anyhow::ensure!(output.status.success(), "privileged metadata probe failed");
    // A successful child must attest presence OR verified absence. The entire
    // accepted frame is at most six bytes; never interpret status-only errors,
    // empty/extra output or a sudo diagnostic as an absent protected journal.
    // Do not include rejected output: this boundary must never disclose data.
    match output.stdout.as_slice() {
        b"true\n" => Ok(true),
        b"false\n" => Ok(false),
        _ => bail!("invalid privileged metadata probe response"),
    }
}

/// Internal root-only metadata protocol. This command never reads file contents
/// or escalates again: a metadata error must remain unknown, not become false.
pub fn owned_file_probe(path: &Path) -> Result<&'static str> {
    owned_file_probe_with(path, is_root(), Path::try_exists)
}

fn owned_file_probe_with(
    path: &Path,
    root: bool,
    inspect: impl FnOnce(&Path) -> std::io::Result<bool>,
) -> Result<&'static str> {
    anyhow::ensure!(root, "owned-file-probe requires root");
    let exists = inspect(path).with_context(|| format!("stat {}", path.display()))?;
    Ok(if exists { "true\n" } else { "false\n" })
}

/// Read a Sentinel-owned file, including a root/networkd-readable key file.
/// Never include its contents in an error or a command argument.
pub fn read_owned_file(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(body) => Ok(Some(body)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            if !owned_file_exists(path)? {
                return Ok(None);
            }
            let p = path.to_str().context("non-UTF-8 config path")?;
            let out = escalated_output("cat", &["--", p])?;
            anyhow::ensure!(out.status.success(), "reading {} failed", path.display());
            Ok(Some(
                String::from_utf8(out.stdout).context("non-UTF-8 config")?,
            ))
        }
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

const MAX_OWNED_READ: usize = 64 * 1024 * 1024;

/// Journals must not hold apply.lock while opening a FIFO or following a
/// replacement symlink. Preserve the existing noninteractive admin escalation,
/// but re-invoke a descriptor-validating reader, never an unbounded `cat`.
pub fn read_owned_regular(path: &Path, limit: usize) -> Result<Option<String>> {
    match read_regular(path, limit) {
        Err(error)
            if !is_root()
                && error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied) =>
        {
            let limit = limit.to_string();
            let path = path.to_str().context("non-UTF-8 journal path")?;
            let output = escalated_output(
                "sentinel-self",
                &["owned-file-read", "--max-bytes", &limit, "--", path],
            )?;
            anyhow::ensure!(
                output.status.success(),
                "reading protected regular journal failed"
            );
            serde_json::from_slice(&output.stdout).context("invalid protected journal read reply")
        }
        result => result,
    }
}

pub fn owned_file_read(path: &Path, limit: usize) -> Result<String> {
    anyhow::ensure!(is_root(), "owned-file-read requires root");
    serde_json::to_string(&read_regular(path, limit)?).map_err(Into::into)
}

fn read_regular(path: &Path, limit: usize) -> Result<Option<String>> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    anyhow::ensure!(
        (1..=MAX_OWNED_READ).contains(&limit),
        "invalid protected read bound"
    );
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("opening protected regular journal"),
    };
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.mode() & 0o022 == 0
            && (metadata.uid() == 0 || metadata.uid() == unsafe { libc::geteuid() })
            && metadata.len() <= limit as u64,
        "invalid protected regular journal"
    );
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= limit, "protected journal exceeds read bound");
    Ok(Some(
        String::from_utf8(bytes).context("journal is not UTF-8")?,
    ))
}

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

/// Install the appliance configuration at `path`, atomically, escalating when
/// the caller cannot write the directory itself.
///
/// `save` and `commit` are run by an operator account, not by root, and the
/// config lives in a root-owned directory — so a plain write fails with nothing
/// but "writing …/appliance.toml.tmp" to show for it. Try the direct atomic
/// write first (root, and the API service, take that path), then stage and
/// install under sudo.
///
/// Installed 0640 root:wheel: the file carries hashed passwords and VPN
/// secrets, and `wheel` is the group an operator account is in — the same
/// membership that lets them escalate here in the first place.
pub fn install_config_file(path: &Path, contents: &str) -> Result<()> {
    install_owned_atomic(path, contents, false)
}
/// Root-private atomic state for credentials and interrupted HA transactions.
pub fn install_ha_secret(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    install_owned_atomic(path, contents, true)
}
fn install_owned_atomic(path: &Path, contents: &str, private: bool) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::io::AsRawFd;
    let _transaction = apply_lock()?;
    if crate::mutation::intent_path(path) {
        crate::mutation::advance()?;
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    // A wheel-writable parent is still root-owned on the appliance. Creating
    // a sibling as the operator and renaming it would silently change file
    // ownership, and the API must reject such a machine credential. Only the
    // parent's owner may use the direct path; other callers install via sudo.
    use std::os::unix::fs::MetadataExt;
    if std::fs::metadata(parent)?.uid() == unsafe { libc::geteuid() } {
        match PrivateStage::create(parent, if private { 0o600 } else { 0o640 }) {
            Ok(mut stage) => {
                if let Some(gid) = (!private).then(wheel_gid).flatten() {
                    anyhow::ensure!(
                        unsafe { libc::fchown(stage.file.as_raw_fd(), !0, gid) } == 0,
                        std::io::Error::last_os_error()
                    );
                }
                // Creation mode is masked by umask. Set the final mode through
                // the private descriptor BEFORE writing any secret bytes.
                stage
                    .file
                    .set_permissions(std::fs::Permissions::from_mode(if private {
                        0o600
                    } else {
                        0o640
                    }))?;
                stage.file.write_all(contents.as_bytes())?;
                stage.file.sync_all()?;
                std::fs::rename(&stage.path, path)
                    .with_context(|| format!("atomically replacing {}", path.display()))?;
                std::fs::File::open(parent)?.sync_all()?;
                return Ok(());
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied) => {}
            Err(error) => return Err(error),
        }
    }
    // Escalation must preserve atomic replacement too: install into a sibling,
    // flush it, then rename. Installing over the live path exposes a truncated
    // document to the peer/API and leaves it truncated if install is interrupted.
    let mut staged = PrivateStage::create(Path::new("/run/sentinel"), 0o600)?;
    staged.file.write_all(contents.as_bytes())?;
    staged.file.sync_all()?;
    // The destination can itself be /run/sentinel (running.toml). A basename
    // copied from the source would ask install to copy a file onto itself,
    // preventing publication of the running snapshot before the outbox starts.
    let target = parent
        .join(staged.path.file_name().context("staging filename")?)
        .with_extension("install");
    let source = staged.path.to_str().context("non-UTF-8 staging path")?;
    let temporary = target.to_str().context("non-UTF-8 config directory")?;
    let destination = path.to_str().context("non-UTF-8 config path")?;
    let directory = parent.to_str().context("non-UTF-8 config directory")?;
    let result = (|| {
        if private {
            sudo("install", &["-m", "0600", source, temporary])?;
        } else {
            sudo("install", &["-m", "0640", "-g", "wheel", source, temporary])?;
        }
        sudo("sync", &["-f", temporary])?;
        sudo("mv", &["-fT", "--", temporary, destination])?;
        sudo("sync", &["-f", directory])
    })();
    if result.is_err() {
        let _ = sudo("rm", &["-f", "--", temporary]);
    }
    result.with_context(|| format!("atomically installing {}", path.display()))
}

/// Exclusively created, private staging file. Unpredictable names and O_EXCL
/// prevent following a pre-existing symlink or reusing another writer's file.
pub(crate) struct PrivateStage {
    pub(crate) path: std::path::PathBuf,
    pub(crate) file: std::fs::File,
}
impl PrivateStage {
    pub(crate) fn create(directory: &Path, mode: u32) -> Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random)
            .map_err(|error| anyhow::anyhow!("configuration staging entropy: {error}"))?;
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = directory.join(format!(".sentinel-config-{suffix}.tmp"));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        Ok(Self { path, file })
    }
}
impl Drop for PrivateStage {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
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
/// Go back to ignoring SIGPIPE, for a command that serves rather than prints.
///
/// `main` sets the default action so a `show` piped into `head` ends quietly.
/// A server must not carry that: the default action is to terminate, so one
/// client hanging up mid-write ends the whole service — and because systemd
/// counts SIGPIPE as a clean exit, it does so silently and without a restart.
/// Rust's own startup ignores SIGPIPE for exactly this reason; this puts it
/// back for the processes that need it.
pub fn ignore_sigpipe() {
    #[cfg(unix)]
    // SAFETY: setting a signal disposition to SIG_IGN is async-signal-safe and
    // is what the Rust runtime itself does before `main`.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

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
/// End the caller's own login session, so leaving the CLI leaves the box.
///
/// An operator who exits configuration mode should not be dropped at a shell
/// that the next person to walk up to the console inherits. Only meaningful
/// inside a real login session — `loginctl` is asked for the session by id, and
/// a caller that has none simply gets an error and stays put.
pub fn terminate_own_session() -> Result<()> {
    let id = std::env::var("XDG_SESSION_ID").context("not inside a login session")?;
    run_priv("loginctl", &["terminate-session", &id])
}

/// Enqueue a start for `unit` without waiting for the job to finish.
///
/// The boot-time reconcile runs *inside* `sentinel-boot.service`, and the units
/// it starts order themselves after that same service. A synchronous start
/// would deadlock: the job waits for a service that is waiting for the job.
pub fn service_start_nowait(unit: &str) -> Result<()> {
    run_priv("systemctl", &["--no-block", "start", unit])
}

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
    install_ha_secret(path, secret)
}

/// PUT a config body (a file of JSON) to a peer's Sentinel API for HA config sync
/// (roadmap C21). Best-effort at the call site — a down peer must not fail the local
/// commit. Bearer material travels through stdin; a short timeout bounds an unreachable peer.
/// `GET url` with a bearer token, returning the body.
///
/// The stack view's one way of reaching a peer. Deliberately the same tool the
/// config-sync push already uses rather than a second HTTP client in the
/// binary: one place to get TLS, timeouts and proxy behaviour wrong is enough.
/// The timeout is short — a peer that is down must make the console say so
/// quickly, not hang the page.
/// Bearer material is passed through a private stdin pipe, never process argv.
pub fn curl_request(
    url: &str,
    token: Option<&str>,
    method: &str,
    body: Option<&Path>,
    timeout_secs: u32,
    pin: Option<&str>,
) -> Result<String> {
    curl_request_with_header(url, token, method, body, None, timeout_secs, pin)
}

/// A management request the far end refused with an HTTP status, kept as a
/// value rather than a sentence so a caller can tell a refusal it must act on
/// (a `409 Conflict` from config-sync) from a peer that simply was not there.
#[derive(Debug)]
pub struct HttpStatus {
    pub status: u16,
    pub request: String,
}

impl std::fmt::Display for HttpStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "management request {} was refused (HTTP {})",
            self.request, self.status
        )
    }
}

impl std::error::Error for HttpStatus {}

/// The status curl's `-f` reports on stderr ("The requested URL returned
/// error: 409"), when that is why it failed.
fn curl_http_status(stderr: &str) -> Option<u16> {
    let rest = stderr.split("returned error: ").nth(1)?;
    rest.get(..3)?.parse().ok()
}

/// [`curl_request`] with one extra request header (`Name: value`). The header
/// goes through curl's private config on stdin like the bearer, never argv.
fn curl_request_with_header(
    url: &str,
    token: Option<&str>,
    method: &str,
    body: Option<&Path>,
    extra_header: Option<&str>,
    timeout_secs: u32,
    pin: Option<&str>,
) -> Result<String> {
    use std::io::Write;
    let mut args = vec![
        "-sS".to_string(),
        "-f".into(),
        "--max-time".into(),
        timeout_secs.to_string(),
        "--max-filesize".into(),
        "8388608".into(),
        "-X".into(),
        method.into(),
        "--config".into(),
        "-".into(),
    ];
    if let Some(body) = body {
        args.extend([
            "-H".into(),
            "Content-Type: application/json".into(),
            "--data-binary".into(),
            format!("@{}", body.display()),
        ]);
    }
    add_pin_args(&mut args, pin);
    args.push(url.into());
    let mut config = curl_auth_config(token)?;
    if let Some(extra) = extra_header {
        anyhow::ensure!(
            !extra
                .chars()
                .any(|c| c.is_control() || c == '"' || c == '\\'),
            "invalid request header"
        );
        config.push_str(&format!("header = \"{extra}\"\n"));
    }
    let mut child = curl_command()
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("starting management request")?;
    if let Err(error) = child
        .stdin
        .take()
        .context("curl stdin")?
        .write_all(config.as_bytes())
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error.into());
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        if let Some(status) = curl_http_status(&String::from_utf8_lossy(&out.stderr)) {
            return Err(HttpStatus {
                status,
                request: format!("{method} {url}"),
            }
            .into());
        }
        bail!("management request {method} {url} failed ({})", out.status);
    }
    String::from_utf8(out.stdout).context("non-UTF8 management response")
}
/// The pinned curl for a request that carries a credential or decides whom to
/// trust, with nothing of the caller's environment.
///
/// `--disable` (which only works as the FIRST argument) keeps `~/.curlrc` out,
/// but curl also reads its environment: `HTTPS_PROXY`/`ALL_PROXY` would route a
/// bearer token through somebody's proxy, `SSLKEYLOGFILE` would write the TLS
/// session keys to a file, `CURL_CA_BUNDLE`/`SSL_CERT_FILE` would swap the trust
/// store the certificate is checked against. A `sudo -E`, a service drop-in or a
/// login profile is enough to set any of them. None of them is a setting of
/// this appliance, so the child starts with an empty environment; only `PATH`
/// is carried, which curl never reads and the lookup of a bare `curl` (off the
/// appliance, where no pinned store path is set) needs. A proxy, if one is ever
/// wanted, belongs in explicit configuration.
pub fn curl_command() -> Command {
    curl_command_for(&bin("curl"))
}

pub fn curl_command_for(program: &str) -> Command {
    let mut command = Command::new(program);
    command.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    command.arg("--disable");
    command
}

fn curl_auth_config(token: Option<&str>) -> Result<String> {
    let Some(token) = token else {
        return Ok(String::new());
    };
    anyhow::ensure!(
        !token.is_empty() && !token.chars().any(|c| c.is_control()),
        "invalid bearer credential"
    );
    let escaped = token.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!("header = \"Authorization: Bearer {escaped}\"\n"))
}
pub fn curl_get(url: &str, token: &str, timeout_secs: u32, pin: Option<&str>) -> Result<String> {
    curl_request(url, Some(token), "GET", None, timeout_secs, pin)
}

/// [`curl_get`] with one extra request header (`Name: value`).
pub fn curl_get_with_header(
    url: &str,
    token: &str,
    header: &str,
    timeout_secs: u32,
    pin: Option<&str>,
) -> Result<String> {
    curl_request_with_header(
        url,
        Some(token),
        "GET",
        None,
        Some(header),
        timeout_secs,
        pin,
    )
}

/// Add curl's public-key pinning for a self-signed peer (H3): `--insecure` drops
/// CA and hostname verification (a self-signed peer certificate is vouched for by
/// no CA), and `--pinnedpubkey sha256//<pin>` re-adds verification against exactly
/// that public key — so the connection is both encrypted AND authenticated to the
/// pinned peer, without a shared CA. `None` leaves curl's normal CA verification
/// in place, for an operator-supplied certificate from a CA curl already trusts.
fn add_pin_args(args: &mut Vec<String>, pin: Option<&str>) {
    if let Some(pin) = pin {
        args.push("--insecure".into());
        args.push("--pinnedpubkey".into());
        args.push(format!("sha256//{pin}"));
    }
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

pub fn curl_put_config(url: &str, token: &str, body_file: &Path, pin: Option<&str>) -> Result<()> {
    curl_request(url, Some(token), "PUT", Some(body_file), 10, pin).map(|_| ())
}

/// Make systemd re-read unit files after Sentinel wrote/removed one under
/// `/run/systemd/system` (e.g. the dynamic time-based-rules timer). Required
/// before starting a freshly written unit.
pub fn daemon_reload() -> Result<()> {
    run_priv("systemctl", &["daemon-reload"])
}

/// Remove a (possibly root-owned) file, tolerating an already-absent path.
pub fn remove_file(path: &Path) -> Result<()> {
    let _lock = if crate::mutation::intent_path(path) {
        let lock = apply_lock()?;
        crate::mutation::advance()?;
        Some(lock)
    } else {
        None
    };
    if !owned_file_exists(path)? {
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
pub fn ha_guard(config: &Path) -> Result<()> {
    run_priv(
        "velstra",
        &["ha-guard", config.to_str().context("HA config path")?],
    )
}

pub fn openssl(args: &[&str]) -> Result<()> {
    run_priv("openssl", args)
}

/// Maintain the AUTOMATIC management certificate, never an explicit operator
/// certificate. Renew missing SANs or an expiring cert using the surviving key,
/// so config-sync's SPKI pin remains stable. A lost/mismatched key is an error,
/// not permission to silently replace the appliance's identity. Publish only a
/// fully verified certificate, atomically; private staging files are0600 from
/// creation, including during initial RSA generation.
pub fn ensure_self_signed_cert(cert: &Path, key: &Path, cn: &str, sans: &[String]) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let parent = cert
        .parent()
        .context("automatic TLS certificate directory")?;
    anyhow::ensure!(
        key.parent() == Some(parent) && cert != key,
        "automatic TLS key and certificate must be distinct siblings"
    );
    anyhow::ensure!(
        sans.len() <= 64
            && std::iter::once(cn)
                .chain(sans.iter().map(String::as_str))
                .all(valid_tls_name),
        "invalid automatic TLS name or address"
    );
    ensure_dir(parent)?;
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)?;
    let metadata = directory.metadata()?;
    anyhow::ensure!(
        metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o022 == 0,
        "automatic TLS directory must belong to its caller and not be group/world writable"
    );
    let _lock = lock_config_at(&parent.join(".certificate.lock"))?;
    let cert_file = automatic_tls_file(cert)?;
    let key_file = automatic_tls_file(key)?;
    anyhow::ensure!(
        cert_file.is_none() || key_file.is_some(),
        "automatic TLS private key is missing; restore the original key instead of rotating a pinned identity"
    );
    if let Some(file) = &key_file {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    let key_pin = key_file
        .as_ref()
        .map(|_| private_key_pubkey_pin(key))
        .transpose()?;
    if let Some(file) = &cert_file {
        let mode = file.metadata()?.permissions().mode() & 0o777 & !0o022;
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        anyhow::ensure!(
            Some(cert_pubkey_pin(cert)?) == key_pin,
            "automatic TLS certificate and key do not match; restore the pinned identity"
        );
        if automatic_tls_cert_ready(cert, cn, sans)? {
            return Ok(());
        }
    }
    let staged_cert = PrivateStage::create(parent, 0o600)?;
    let staged_key = if key_file.is_none() {
        Some(PrivateStage::create(parent, 0o600)?)
    } else {
        None
    };
    let certificate_path = staged_cert
        .path
        .to_str()
        .context("non-UTF-8 TLS staging path")?;
    let signing_key = staged_key.as_ref().map_or(key, |stage| &stage.path);
    let key_path = signing_key.to_str().context("non-UTF-8 TLS key path")?;
    let mut command = Command::new(bin("openssl"));
    command.args([
        "req",
        "-x509",
        "-sha256",
        "-days",
        "3650",
        "-out",
        certificate_path,
        "-subj",
        &format!("/CN={cn}"),
        "-addext",
        &build_san(cn, sans),
    ]);
    if staged_key.is_some() {
        command.args(["-newkey", "rsa:2048", "-nodes", "-keyout", key_path]);
    } else {
        command.args(["-key", key_path, "-passin", "pass:"]);
    }
    let out = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .context("running openssl to mint the management TLS certificate")?;
    anyhow::ensure!(
        out.status.success(),
        "openssl could not mint the automatic management TLS certificate; existing identity retained"
    );
    let expected_pin = private_key_pubkey_pin(signing_key)?;
    anyhow::ensure!(
        key_pin.as_ref().is_none_or(|pin| pin == &expected_pin)
            && cert_pubkey_pin(&staged_cert.path)? == expected_pin
            && automatic_tls_cert_ready(&staged_cert.path, cn, sans)?,
        "new automatic certificate failed identity/SAN/validity verification; existing certificate retained"
    );
    if let Some(stage) = &staged_key {
        stage
            .file
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        stage.file.sync_all()?;
        // No replace: never overwrite a key which appeared during generation.
        // If interrupted here, the surviving key is reused on the next start.
        use std::os::unix::ffi::OsStrExt;
        let source = std::ffi::CString::new(stage.path.as_os_str().as_bytes())?;
        let target = std::ffi::CString::new(key.as_os_str().as_bytes())?;
        // Atomic no-replace avoids the two-link crash window of link+unlink.
        // Linux appliances and their ext4 state filesystems support renameat2.
        if unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                source.as_ptr(),
                libc::AT_FDCWD,
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error())
                .context("publishing the new automatic TLS key without replacement");
        }
        directory.sync_all()?;
    }
    staged_cert
        .file
        .set_permissions(std::fs::Permissions::from_mode(0o644))?;
    staged_cert.file.sync_all()?;
    std::fs::rename(&staged_cert.path, cert)?;
    directory.sync_all()?;
    Ok(())
}

fn valid_tls_name(name: &str) -> bool {
    name.parse::<std::net::IpAddr>().is_ok()
        || (!name.is_empty()
            && name.len() <= 253
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)))
}

fn automatic_tls_file(path: &Path) -> Result<Option<std::fs::File>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).context("opening automatic TLS identity without following links");
        }
    };
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.nlink() == 1 && metadata.uid() == unsafe { libc::geteuid() },
        "automatic TLS identity must be a regular single-link file belonging to its caller"
    );
    Ok(Some(file))
}

fn private_key_pubkey_pin(key: &Path) -> Result<String> {
    use base64::Engine;
    let result = Command::new(bin("openssl"))
        .args([
            "pkey",
            "-in",
            key.to_str().context("TLS key path")?,
            "-passin",
            "pass:",
            "-pubout",
            "-outform",
            "DER",
        ])
        .stdin(Stdio::null())
        .output()
        .context("reading automatic TLS public identity")?;
    anyhow::ensure!(
        result.status.success(),
        "automatic TLS key is unreadable or encrypted; original identity retained"
    );
    Ok(base64::engine::general_purpose::STANDARD
        .encode(ring::digest::digest(&ring::digest::SHA256, &result.stdout)))
}

fn automatic_tls_cert_ready(cert: &Path, cn: &str, sans: &[String]) -> Result<bool> {
    let cert = cert.to_str().context("TLS certificate path")?;
    let check = |args: &[&str]| -> Result<bool> {
        Ok(Command::new(bin("openssl"))
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("checking automatic TLS certificate")?
            .success())
    };
    if !check(&["x509", "-in", cert, "-noout", "-checkend", "2592000"])?
        || !check(&["verify", "-CAfile", cert, cert])?
    {
        return Ok(false);
    }
    for name in std::iter::once(cn)
        .chain(std::iter::once("localhost"))
        .chain(sans.iter().map(String::as_str))
    {
        let option = if name.parse::<std::net::IpAddr>().is_ok() {
            "-checkip"
        } else {
            "-checkhost"
        };
        if !check(&["x509", "-in", cert, "-noout", option, name])? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Build an OpenSSL `subjectAltName` extension covering the CN plus each supplied
/// address/name, so a browser at the bound address is not warned about a name
/// mismatch (pinning ignores the name, but a person does not). Numeric entries
/// become `IP:`, everything else `DNS:`.
fn build_san(cn: &str, sans: &[String]) -> String {
    let mut parts = Vec::new();
    for s in std::iter::once(cn)
        .chain(std::iter::once("localhost"))
        .chain(sans.iter().map(String::as_str))
    {
        if s.parse::<std::net::IpAddr>().is_ok() {
            parts.push(format!("IP:{s}"));
        } else {
            parts.push(format!("DNS:{s}"));
        }
    }
    format!("subjectAltName={}", parts.join(","))
}

/// The curl `--pinnedpubkey sha256//<base64>` pin of a PEM certificate at `cert`:
/// the base64 of the SHA-256 of the certificate's DER SubjectPublicKeyInfo, i.e.
/// exactly what curl compares against. Derived with the pinned `openssl` so a box
/// can print its own management-cert pin for an operator to pin on a peer.
pub fn cert_pubkey_pin(cert: &Path) -> Result<String> {
    let pem = std::fs::read(cert).with_context(|| format!("reading {}", cert.display()))?;
    pubkey_pin_from_cert_pem(&pem)
}

/// Learn a peer's TLS public-key pin (H3 trust-on-first-use): connect once with
/// `openssl s_client` to read the peer's certificate — a public value, no secret
/// crosses the wire — and derive the same pin curl's `--pinnedpubkey` compares.
/// Used only when config sync has no pinned fingerprint in the config; the pin is
/// then stored and enforced on every later exchange, so this is the one contact
/// whose authenticity rests on the network rather than a pin.
pub fn learn_peer_pubkey_pin(authority: &str) -> Result<String> {
    let host = sni_host(authority);
    let out = Command::new(bin("timeout"))
        .arg("5s")
        .arg(bin("openssl"))
        .args(["s_client", "-connect", authority, "-servername", &host])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .with_context(|| format!("openssl s_client to {authority}"))?;
    if !out.status.success() {
        bail!("could not reach {authority} to read its TLS certificate");
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let cert_pem = first_pem_cert(&text)
        .ok_or_else(|| bail_str(format!("{authority} presented no certificate")))?;
    pubkey_pin_from_cert_pem(cert_pem.as_bytes())
}

/// A tiny helper so `ok_or_else` can carry a formatted message without a closure
/// that captures a temporary `String` by move into `anyhow!`.
fn bail_str(msg: String) -> anyhow::Error {
    anyhow::Error::msg(msg)
}

/// The SNI/host part of a config-sync authority: `host:port`, a bracketed
/// `[v6]:port`, or a bare host all reduce to the host for `-servername`.
fn sni_host(authority: &str) -> String {
    if let Some(rest) = authority.strip_prefix('[') {
        // [v6] or [v6]:port
        return rest.split(']').next().unwrap_or(rest).to_string();
    }
    // host or host:port (a bare IPv6 has >1 colon and no brackets — leave as is)
    if authority.matches(':').count() == 1 {
        authority.split(':').next().unwrap_or(authority).to_string()
    } else {
        authority.to_string()
    }
}

/// Extract the first `-----BEGIN CERTIFICATE----- … END` block from text (the
/// certificate `openssl s_client` prints among its diagnostics).
fn first_pem_cert(text: &str) -> Option<String> {
    const B: &str = "-----BEGIN CERTIFICATE-----";
    const E: &str = "-----END CERTIFICATE-----";
    let start = text.find(B)?;
    let end = text[start..].find(E)? + start + E.len();
    Some(text[start..end].to_string())
}

/// Derive curl's `sha256//<base64>` pin from a PEM certificate: cert → public key
/// → DER SubjectPublicKeyInfo (both via the pinned `openssl`), then SHA-256 and
/// base64. Kept in one place so the local-cert and peer-learn paths agree byte
/// for byte with what curl checks.
fn pubkey_pin_from_cert_pem(cert_pem: &[u8]) -> Result<String> {
    use base64::Engine;
    let pub_pem = openssl_filter(&["x509", "-pubkey", "-noout"], cert_pem)?;
    let spki_der = openssl_filter(&["pkey", "-pubin", "-outform", "der"], &pub_pem)?;
    let digest = openssl_filter(&["dgst", "-sha256", "-binary"], &spki_der)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(digest))
}

/// Run `openssl <args>` as a filter: write `input` to its stdin and return its
/// stdout. Used to chain cert → pubkey → DER → digest without a shell pipeline.
fn openssl_filter(args: &[&str], input: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write;
    let mut child = Command::new(bin("openssl"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("spawning openssl {}", args.join(" ")))?;
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| bail_str("openssl stdin unavailable".into()))?;
        stdin
            .write_all(input)
            .with_context(|| format!("feeding openssl {}", args.join(" ")))?;
        // `stdin` drops here, closing the pipe so openssl sees EOF and exits.
    }
    let out = child
        .wait_with_output()
        .with_context(|| format!("running openssl {}", args.join(" ")))?;
    if !out.status.success() {
        bail!("openssl {} failed", args.join(" "));
    }
    Ok(out.stdout)
}

/// Tell systemd-networkd to re-read its unit files. Reload automatically
/// reconfigures links whose network files changed; forcing another reconfigure
/// would discard DHCP leases again, including on unchanged links.
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
        // Netdev creation is asynchronous. In particular a new VLAN is not
        // necessarily present when `reload` returns. Never turn that race into
        // a successful commit with no configured interface.
        anyhow::ensure!(
            wait_for_link(iface, std::time::Duration::from_secs(10)),
            "network interface {iface} was not created"
        );
        run_priv("networkctl", &["reconfigure", iface])?;
    }
    Ok(())
}

/// Wait up to `timeout` for the kernel link `iface` to exist; whether it does.
pub fn wait_for_link(iface: &str, timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    let link = Path::new("/sys/class/net").join(iface);
    while !link.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    link.exists()
}

/// Make the live WireGuard device `iface` match the `wg`-format file at `path`
/// (key, port, peers), keeping the sessions of peers that did not change.
pub fn wg_syncconf(iface: &str, path: &Path) -> Result<()> {
    let Some(p) = path.to_str() else {
        bail!("non-UTF-8 path");
    };
    run_priv("wg", &["syncconf", iface, p])
}

/// Retire a device created by a Sentinel netdev. Physical NICs are never deleted.
pub fn delete_virtual_link(name: &str) -> Result<()> {
    if !Path::new("/sys/class/net").join(name).exists() {
        return Ok(());
    }
    let out = escalated_output("ip", &["-details", "-json", "link", "show", "dev", name])?;
    anyhow::ensure!(out.status.success(), "inspecting interface {name} failed");
    let links: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    anyhow::ensure!(
        links[0]["linkinfo"]["info_kind"].is_string(),
        "refusing to delete non-virtual interface {name}"
    );
    run_priv("ip", &["link", "delete", "dev", name])
}

/// Resolve a logical tool name to an absolute path. The Nix wrapper injects
/// `SENTINEL_<TOOL>_BIN` env vars pointing at exact store paths, so neither the
/// admin's `$PATH` nor sudo's `secure_path` can shadow or miss a tool (the cause
/// of "Failed to execute /run/current-system/sw/..." on a `commit`). Off-box
/// (dev, tests) the vars are unset and we fall back to the bare name on `$PATH`.
pub fn bin(name: &str) -> String {
    if name == "sentinel-self" {
        if let Ok(v) = std::env::var("SENTINEL_SELF_BIN") {
            return v;
        }
        if let Ok(exe) = std::env::current_exe() {
            return exe.to_string_lossy().into_owned();
        }
    }
    let var = match name {
        "hostname" => "SENTINEL_HOSTNAME_BIN",
        "ldapwhoami" => "SENTINEL_LDAPWHOAMI_BIN",
        "occtl" => "SENTINEL_OCCTL_BIN",
        "ip" => "SENTINEL_IP_BIN",
        "nft" => "SENTINEL_NFT_BIN",
        "networkctl" => "SENTINEL_NETWORKCTL_BIN",
        "cat" => "SENTINEL_CAT_BIN",
        "test" => "SENTINEL_TEST_BIN",
        "systemctl" => "SENTINEL_SYSTEMCTL_BIN",
        "systemd-run" => "SENTINEL_SYSTEMD_RUN_BIN",
        "bootctl" => "SENTINEL_BOOTCTL_BIN",
        "boot-health" => "SENTINEL_BOOT_HEALTH_BIN",
        "journalctl" => "SENTINEL_JOURNALCTL_BIN",
        // Our own path, so the escalated re-invocation runs this build and not
        // whatever `sentinel` a $PATH lookup under sudo might find.
        "sentinel-self" => "SENTINEL_SELF_BIN",
        "wren" => "SENTINEL_WREN_BIN",
        "velstra" => "SENTINEL_VELSTRA_BIN",
        "tc" => "SENTINEL_TC_BIN",
        "wg" => "SENTINEL_WG_BIN",
        "loadkeys" => "SENTINEL_LOADKEYS_BIN",
        "loginctl" => "SENTINEL_LOGINCTL_BIN",
        "timedatectl" => "SENTINEL_TIMEDATECTL_BIN",
        "sysctl" => "SENTINEL_SYSCTL_BIN",
        "swanctl" => "SENTINEL_SWANCTL_BIN",
        "openssl" => "SENTINEL_OPENSSL_BIN",
        "curl" => "SENTINEL_CURL_BIN",
        "ethtool" => "SENTINEL_ETHTOOL_BIN",
        "lego" => "SENTINEL_LEGO_BIN",
        "lsblk" => "SENTINEL_LSBLK_BIN",
        "tcpdump" => "SENTINEL_TCPDUMP_BIN",
        "timeout" => "SENTINEL_TIMEOUT_BIN",
        "install" => "SENTINEL_INSTALL_BIN",
        "mkdir" => "SENTINEL_MKDIR_BIN",
        "chmod" => "SENTINEL_CHMOD_BIN",
        "rm" => "SENTINEL_RM_BIN",
        "mv" => "SENTINEL_MV_BIN",
        "sync" => "SENTINEL_SYNC_BIN",
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
        // data-partition encryption (LUKS2): format/open at install, unlock at boot
        "cryptsetup" => "SENTINEL_CRYPTSETUP_BIN",
        "systemd-ask-password" => "SENTINEL_ASK_PASSWORD_BIN",
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
/// Run a read-only diagnostic under `sudo` when the caller is not root, with
/// the output going to the terminal.
///
/// The daemons' control sockets are root-only on purpose — the query socket can
/// add a drop, the portal one admits a device, the mapping one opens a port —
/// so widening them for the sake of `show` would trade a real boundary for
/// convenience. Escalating instead costs nothing here (an operator account is
/// in `wheel`, which already has passwordless sudo) and keeps the sockets shut.
pub fn escalated_output(cmd: &str, args: &[&str]) -> Result<std::process::Output> {
    let resolved = bin(cmd);
    let is_root = unsafe { libc::geteuid() } == 0;
    escalated_output_with(cmd, &resolved, args, is_root, |program, arguments| {
        Command::new(program).args(arguments).output()
    })
}

fn escalated_output_with(
    cmd: &str,
    resolved: &str,
    args: &[&str],
    is_root: bool,
    mut output: impl FnMut(&str, &[&str]) -> std::io::Result<std::process::Output>,
) -> Result<std::process::Output> {
    if is_root {
        return output(resolved, args).with_context(|| format!("running {resolved}"));
    }
    // Try it plainly first. Most of what this runs only needs a socket the
    // caller may already be allowed to open, and escalating regardless turns a
    // read into a privilege request for no reason.
    //
    // Never for a re-invocation of *this* binary, though: the only reason to run
    // ourselves again is to gain privilege, the caller has already made the
    // unprivileged attempt, and running it once more as the same user reproduces
    // the same failure — which escalates again, and again, one process deeper
    // each time. That is not hypothetical: `show flows` on a workstation with no
    // agent socket forked 1481 nested `sentinel agent-query` processes and
    // wedged the API that spawned the first one.
    let direct = if plain_attempt_is_useful(cmd) {
        output(resolved, args).ok()
    } else {
        None
    };
    if let Some(out) = direct.filter(|out| out.status.success()) {
        return Ok(out);
    }

    let mut all = vec!["-n", resolved];
    all.extend_from_slice(args);
    // `-n`: never prompt. Without it, a `sudo` configured to ask — for a
    // password, or on a workstation for a fingerprint — blocks until *its*
    // timeout, and every caller here is a read that something is waiting on.
    // A `show` that sat for thirty-two seconds before admitting it could not
    // escalate is how the console came to look like it had hung: the routing
    // section makes one such call per protocol.
    // A completed privileged invocation is authoritative even when nonzero.
    // For example, nft's exit 1/ENOENT proves a table is absent; replacing it
    // with the earlier unprivileged EPERM changes the caller's meaning. A sudo
    // refusal or signal also remains a failure, never a stale plain result.
    // Spawn/read/wait errors remain Err through the same contextual boundary.
    output("sudo", &all).with_context(|| format!("running `sudo {}`", all.join(" ")))
}

/// Whether running `cmd` unprivileged, before escalating, can tell us anything.
///
/// It can for a system tool: `ip`, `networkctl` and the rest answer plenty of
/// read-only questions as an ordinary user, and asking for privilege first would
/// turn every one of them into a privilege request.
///
/// It cannot for `sentinel-self`. A re-invocation of this binary exists *only*
/// to be root — the caller reached for it because its own unprivileged attempt
/// failed — so the plain attempt is that same failure, run again, in a child
/// that will escalate again when it fails.
fn plain_attempt_is_useful(cmd: &str) -> bool {
    cmd != "sentinel-self"
}

/// Whether this process is root, so a caller can say *why* it is escalating.
pub fn is_root() -> bool {
    (unsafe { libc::geteuid() }) == 0
}

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
pub(crate) fn sudo(cmd: &str, args: &[&str]) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_regular_reads_bound_bytes_and_preserve_missing_empty_and_invalid_states() {
        use std::os::unix::fs::PermissionsExt;
        let scratch = crate::update::Scratch::new().unwrap();
        let path = scratch.join("journal");
        assert!(read_owned_regular(&path, 8).unwrap().is_none());
        for body in [b"".as_slice(), b"12345678"] {
            std::fs::write(&path, body).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(
                read_owned_regular(&path, 8).unwrap().unwrap().as_bytes(),
                body
            );
        }
        std::fs::write(&path, b"123456789").unwrap();
        assert!(read_owned_regular(&path, 8).is_err());
        std::fs::write(&path, [0xff]).unwrap();
        assert!(read_owned_regular(&path, 8).is_err());
        assert!(read_owned_regular(&path, 0).is_err());
        assert!(read_owned_regular(&path, MAX_OWNED_READ + 1).is_err());
    }

    #[test]
    fn owned_regular_rejects_fifo_symlink_directory_hardlink_and_writable_journal() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let scratch = crate::update::Scratch::new().unwrap();
        let regular = scratch.join("regular");
        std::fs::write(&regular, "private journal").unwrap();
        std::fs::set_permissions(&regular, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = scratch.join("link");
        symlink(&regular, &link).unwrap();
        assert!(read_owned_regular(&link, 100).is_err());
        assert!(read_owned_regular(&scratch.join("."), 100).is_err());
        let fifo = scratch.join("fifo");
        let path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let start = std::time::Instant::now();
        assert!(read_owned_regular(&fifo, 100).is_err());
        assert!(start.elapsed() < std::time::Duration::from_millis(250));
        std::fs::hard_link(&regular, scratch.join("hardlink")).unwrap();
        assert!(read_owned_regular(&regular, 100).is_err());
        std::fs::remove_file(scratch.join("hardlink")).unwrap();
        std::fs::set_permissions(&regular, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_owned_regular(&regular, 100).is_err());
    }

    #[test]
    fn owned_regular_internal_wire_reply_is_optional_json_and_requires_root() {
        let scratch = crate::update::Scratch::new().unwrap();
        let absent = scratch.join("absent");
        if is_root() {
            assert_eq!(owned_file_read(&absent, 10).unwrap(), "null");
        } else {
            assert!(
                owned_file_read(&absent, 10)
                    .unwrap_err()
                    .to_string()
                    .contains("requires root")
            );
        }
    }

    fn owned_file_output(code: i32, stdout: &[u8], stderr: &[u8]) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt;
        std::process::Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        }
    }

    #[test]
    fn owned_file_direct_presence_and_absence_never_request_privilege() {
        for root in [false, true] {
            for exists in [false, true] {
                assert_eq!(
                    owned_file_exists_with(
                        Path::new("/metadata-only"),
                        root,
                        |_| Ok(exists),
                        |_| panic!("a known direct result must not escalate"),
                    )
                    .unwrap(),
                    exists
                );
            }
        }
    }

    #[test]
    fn owned_file_root_metadata_uncertainty_never_escalates_or_becomes_absence() {
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::Other,
        ] {
            assert!(
                owned_file_exists_with(
                    Path::new("/unknown-state"),
                    true,
                    |_| Err(std::io::Error::from(kind)),
                    |_| panic!("root has nobody left to ask"),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn owned_file_nonpermission_errors_do_not_escalate_or_become_absence() {
        assert!(
            owned_file_exists_with(
                Path::new("/unknown-state"),
                false,
                |_| Err(std::io::Error::other("metadata I/O failed")),
                |_| panic!("only non-root PermissionDenied may escalate"),
            )
            .is_err()
        );
    }

    #[test]
    fn owned_file_denied_nonroot_query_accepts_one_complete_boolean_proof() {
        use std::cell::Cell;
        let path = Path::new("-literal path 'quoted'\n$(not-a-command);*");
        for (frame, exists) in [(b"true\n".as_slice(), true), (b"false\n", false)] {
            let probes = Cell::new(0);
            let answer = owned_file_exists_with(
                path,
                false,
                |received| {
                    assert_eq!(received, path);
                    Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
                },
                |received| {
                    assert_eq!(received, path);
                    probes.set(probes.get() + 1);
                    Ok(owned_file_output(0, frame, b""))
                },
            )
            .unwrap();
            assert_eq!(answer, exists);
            assert_eq!(probes.get(), 1);
        }
    }

    #[test]
    fn owned_file_status_one_127_permission_failure_and_signals_are_unknown() {
        use std::os::unix::process::ExitStatusExt;
        for (code, stderr) in [
            (1, b"sudo: a password is required".as_slice()),
            (1, b"Operation not permitted"),
            (127, b"command not found"),
        ] {
            // Even a false-looking stdout must not attest absence on failure.
            assert!(decode_owned_file_probe(owned_file_output(code, b"false\n", stderr)).is_err());
        }
        let mut output = owned_file_output(0, b"false\n", b"");
        output.status = std::process::ExitStatus::from_raw(libc::SIGTERM);
        assert!(decode_owned_file_probe(output).is_err());
    }

    #[test]
    fn owned_file_probe_io_failure_is_not_absence_and_never_discloses_output() {
        let error = owned_file_exists_with(
            Path::new("/protected-state"),
            false,
            |_| Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            |_| Err(std::io::Error::from(std::io::ErrorKind::NotFound).into()),
        )
        .unwrap_err();
        assert!(error.downcast_ref::<std::io::Error>().is_some());
        let error = decode_owned_file_probe(owned_file_output(
            0,
            b"private-content-marker-not-an-actual-secret",
            b"another-private-content-marker",
        ))
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(!message.contains("private-content-marker"));
    }

    #[test]
    fn owned_file_probe_rejects_empty_extra_untyped_and_oversized_success_output() {
        for frame in [
            b"".as_slice(),
            b"false",
            b"true",
            b"\"false\"\n",
            b"{}\n",
            b"false\ntrue\n",
            b"false\n ",
            b" false\n",
            b"false\r\n",
            b"false\n\0",
        ] {
            assert!(decode_owned_file_probe(owned_file_output(0, frame, b"")).is_err());
        }
        assert!(decode_owned_file_probe(owned_file_output(0, &vec![b'x'; 65536], b"")).is_err());
    }

    #[test]
    fn owned_file_root_probe_denies_nonroot_without_touching_metadata() {
        assert!(
            owned_file_probe_with(Path::new("/must-not-be-inspected"), false, |_| {
                panic!("root-only probe must reject before querying metadata")
            })
            .is_err()
        );
    }

    #[test]
    fn owned_file_root_probe_errors_do_not_print_an_absence_frame() {
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::Other,
        ] {
            assert!(
                owned_file_probe_with(Path::new("/unknown-state"), true, |_| {
                    Err(std::io::Error::from(kind))
                })
                .is_err()
            );
        }
        for (exists, frame) in [(true, "true\n"), (false, "false\n")] {
            assert_eq!(
                owned_file_probe_with(Path::new("/metadata-only"), true, |_| Ok(exists)).unwrap(),
                frame
            );
        }
    }

    #[test]
    fn owned_file_unknown_state_never_reaches_an_absence_mutation_callback() {
        use std::cell::Cell;
        // This is the Result/? boundary shared by the actual callers. It does
        // not claim a live API/HA mutation test or a privileged filesystem test.
        for code in [1, 127] {
            let writes = Cell::new(0);
            let result = owned_file_exists_with(
                Path::new("/protected-pending-journal"),
                false,
                |_| Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
                |_| Ok(owned_file_output(code, b"false\n", b"")),
            )
            .and_then(|exists| {
                anyhow::ensure!(!exists, "pending transaction");
                writes.set(writes.get() + 1);
                Ok(())
            });
            assert!(result.is_err());
            assert_eq!(writes.get(), 0);
        }
    }

    #[test]
    fn owned_file_real_metadata_preserves_missing_and_symlink_semantics() {
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "sentinel-owned-metadata-{}-{:016x}",
            std::process::id(),
            u64::from_ne_bytes(random)
        ));
        std::fs::create_dir(&directory).unwrap();
        let present = directory.join("present");
        let missing = directory.join("missing");
        let link = directory.join("link");
        let broken = directory.join("broken");
        let cycle = directory.join("cycle");
        std::fs::write(&present, "public test fixture bytes\n").unwrap();
        std::os::unix::fs::symlink(&present, &link).unwrap();
        std::os::unix::fs::symlink(&missing, &broken).unwrap();
        std::os::unix::fs::symlink(&cycle, &cycle).unwrap();
        assert!(owned_file_exists(&present).unwrap());
        assert!(!owned_file_exists(&missing).unwrap());
        assert!(owned_file_exists(&link).unwrap());
        assert!(!owned_file_exists(&broken).unwrap());
        assert!(owned_file_exists(&cycle).is_err());
        assert_eq!(
            std::fs::read(&present).unwrap(),
            b"public test fixture bytes\n"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn atomic_config_modes_are_umask_independent_in_child_processes() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use std::os::unix::process::CommandExt;

        fn mask() -> u32 {
            let status = std::fs::read_to_string("/proc/self/status").unwrap();
            let value = status
                .lines()
                .find_map(|line| line.strip_prefix("Umask:"))
                .expect("Linux process umask observation");
            u32::from_str_radix(value.trim(), 8).unwrap()
        }

        let child_mask = match std::env::args().next().as_deref() {
            Some("sentinel-atomic-config-umask-child-022") => Some(0o022),
            Some("sentinel-atomic-config-umask-child-077") => Some(0o077),
            _ => None,
        };
        if let Some(expected) = child_mask {
            assert_eq!(
                mask(),
                expected,
                "the child must inherit the requested mask"
            );
            let directory = std::env::temp_dir().join(format!(
                "sentinel-atomic-mode-{}-{expected:03o}",
                std::process::id()
            ));
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let config = directory.join("appliance.toml");
            let private = directory.join("private-state");
            for _ in 0..2 {
                install_config_file(&config, "public permission regression fixture").unwrap();
                install_ha_secret(&private, "public private-mode regression fixture").unwrap();
                let configuration = std::fs::metadata(&config).unwrap();
                let secret = std::fs::metadata(&private).unwrap();
                assert_eq!(configuration.mode() & 0o7777, 0o640);
                assert_eq!(secret.mode() & 0o7777, 0o600);
                assert_eq!(configuration.uid(), unsafe { libc::geteuid() });
                assert_eq!(secret.uid(), configuration.uid());
                if let Some(wheel) = wheel_gid() {
                    assert_eq!(configuration.gid(), wheel);
                }
                assert_eq!(
                    std::fs::read_to_string(&config).unwrap(),
                    "public permission regression fixture"
                );
                assert_eq!(
                    std::fs::read_to_string(&private).unwrap(),
                    "public private-mode regression fixture"
                );
                assert!(!std::fs::read_dir(&directory).unwrap().any(|entry| {
                    entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".sentinel-config-")
                }));
                assert_eq!(mask(), expected, "installation must not change the umask");
            }
            std::fs::remove_dir_all(directory).unwrap();
            return;
        }

        let original_mask = mask();
        for (name, expected) in [
            ("sentinel-atomic-config-umask-child-022", 0o022),
            ("sentinel-atomic-config-umask-child-077", 0o077),
        ] {
            let mut child = Command::new(std::env::current_exe().unwrap());
            child.arg0(name).args([
                "--exact",
                "system::tests::atomic_config_modes_are_umask_independent_in_child_processes",
                "--nocapture",
                "--test-threads=1",
            ]);
            // SAFETY: after fork, change only the child's mask with one libc
            // call. No allocation, environment access or locks in this closure;
            // the parent test process and its concurrent tests are untouched.
            unsafe {
                child.pre_exec(move || {
                    libc::umask(expected);
                    Ok(())
                });
            }
            let output = child.output().unwrap();
            assert!(
                output.status.success(),
                "umask {expected:03o} child failed:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains("1 passed; 0 failed; 0 ignored"), "{stdout}");
            assert_eq!(mask(), original_mask, "child changed the parent mask");
        }
    }

    #[test]
    fn atomic_config_replacement_does_not_follow_the_old_predictable_temp_path() {
        use std::os::unix::fs::PermissionsExt;
        let directory =
            std::env::temp_dir().join(format!("sentinel-atomic-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let target = directory.join("appliance.toml");
        let victim = directory.join("unrelated");
        std::fs::write(&target, "previous").unwrap();
        std::fs::write(&victim, "preserved").unwrap();
        std::os::unix::fs::symlink(&victim, target.with_extension("toml.tmp")).unwrap();
        install_config_file(&target, "replacement").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "replacement");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "preserved");
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert!(!std::fs::read_dir(&directory).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".sentinel-config-")
        }));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn private_token_replacement_retains_the_parent_owner_and_private_mode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let directory =
            std::env::temp_dir().join(format!("sentinel-token-owner-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let token = directory.join("api-token");
        std::fs::write(&token, "previous").unwrap();
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o644)).unwrap();
        install_token(&token, "replacement").unwrap();
        let metadata = std::fs::metadata(&token).unwrap();
        assert_eq!(metadata.uid(), std::fs::metadata(&directory).unwrap().uid());
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&token).unwrap(), "replacement");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn configuration_transaction_is_reentrant_and_serializes_other_writers() {
        let directory = std::env::temp_dir().join(format!(
            "sentinel-lock-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("apply.lock");
        let outer = lock_config_at(&path).unwrap();
        let nested = lock_config_at(&path).unwrap();
        let (sent, received) = std::sync::mpsc::channel();
        let other_path = path.clone();
        let other = std::thread::spawn(move || {
            let _guard = lock_config_at(&other_path).unwrap();
            sent.send(()).unwrap();
        });
        assert!(
            received
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err()
        );
        drop(outer);
        assert!(
            received
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err()
        );
        drop(nested);
        received
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        other.join().unwrap();
        let target = directory.join("unrelated");
        std::fs::write(&target, "preserved").unwrap();
        let link = directory.join("symlink");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(lock_config_at(&link).is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "preserved");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn policy_id_reuse_or_removal_invalidates_sessions_but_rule_edits_do_not() {
        let old = b"[[policy]]\nid=1\nname='lan'\n[[policy]]\nid=2\nname='wan'\n";
        assert!(!policy_identity_changed(Some(old), old));
        let rules = [old.as_slice(), b"default_action='pass'\n"].concat();
        assert!(!policy_identity_changed(Some(old), &rules));
        let appended = [old.as_slice(), b"[[policy]]\nid=3\nname='vpn'\n"].concat();
        assert!(!policy_identity_changed(Some(old), &appended));
        let shifted = b"[[policy]]\nid=1\nname='aaa'\n[[policy]]\nid=2\nname='lan'\n[[policy]]\nid=3\nname='wan'\n";
        assert!(policy_identity_changed(Some(old), shifted));
        assert!(policy_identity_changed(
            Some(old),
            b"[[policy]]\nid=1\nname='lan'\n"
        ));
        assert!(policy_identity_changed(
            Some(old),
            b"[[policy]]\nid=1\nname='vpn'\n"
        ));
        assert!(policy_identity_changed(None, old));
        assert!(policy_identity_changed(Some(b"invalid TOML"), old));
    }

    fn openssl_available() -> bool {
        std::process::Command::new(bin("openssl"))
            .arg("version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[test]
    fn sni_host_extracts_the_host() {
        assert_eq!(sni_host("10.0.0.2:8080"), "10.0.0.2");
        assert_eq!(sni_host("fw.local:8080"), "fw.local");
        assert_eq!(sni_host("10.0.0.2"), "10.0.0.2");
        assert_eq!(sni_host("[2001:db8::1]:8080"), "2001:db8::1");
        assert_eq!(sni_host("[2001:db8::1]"), "2001:db8::1");
        // A bare IPv6 (no brackets, more than one colon) is left whole.
        assert_eq!(sni_host("2001:db8::1"), "2001:db8::1");
    }

    #[test]
    fn first_pem_cert_extracts_exactly_one_block() {
        let text = "noise\n-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n\
                    tail\n-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n";
        let got = first_pem_cert(text).expect("a cert block");
        assert!(got.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(got.ends_with("-----END CERTIFICATE-----"));
        assert!(
            got.contains("AAA") && !got.contains("BBB"),
            "only the first block"
        );
        assert!(first_pem_cert("no certificate here").is_none());
    }

    #[test]
    fn build_san_marks_ips_and_names() {
        let san = build_san("fw", &["127.0.0.1".to_string(), "mgmt.local".to_string()]);
        assert!(san.starts_with("subjectAltName="));
        assert!(san.contains("DNS:fw"));
        assert!(san.contains("DNS:localhost"));
        assert!(san.contains("IP:127.0.0.1"));
        assert!(san.contains("DNS:mgmt.local"));
    }

    #[test]
    fn self_signed_cert_pin_round_trips() {
        if !openssl_available() {
            eprintln!("skipping self_signed_cert_pin_round_trips: openssl not on PATH");
            return;
        }
        let dir = std::env::temp_dir().join(format!("sentinel-tls-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        ensure_self_signed_cert(&cert, &key, "fw", &["127.0.0.1".to_string()]).expect("mint cert");
        assert!(cert.exists() && key.exists());

        // The private key is not group/world readable.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key perms {mode:o}");

        // The pin curl would check is a valid, stable 44-char base64 SHA-256.
        let pin = cert_pubkey_pin(&cert).expect("pin");
        assert!(crate::config::is_valid_pinned_sha256(&pin), "pin {pin:?}");
        assert_eq!(cert_pubkey_pin(&cert).unwrap(), pin, "pin is stable");

        // An existing pair is never regenerated (stable across reboots for pinning).
        let key_before = std::fs::read(&key).unwrap();
        ensure_self_signed_cert(&cert, &key, "fw", &[]).unwrap();
        assert_eq!(
            std::fs::read(&key).unwrap(),
            key_before,
            "an existing certificate must not be regenerated"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn automatic_tls_rebind_renews_the_san_without_rotating_the_key() {
        assert!(openssl_available(), "run TLS tests with OpenSSL installed");
        let dir = std::env::temp_dir().join(format!("sentinel-tls-rebind-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        ensure_self_signed_cert(&cert, &key, "fw", &["127.0.0.1".into()]).unwrap();
        let key_before = std::fs::read(&key).unwrap();
        let old_cert = std::fs::read(&cert).unwrap();
        let pin = cert_pubkey_pin(&cert).unwrap();
        ensure_self_signed_cert(&cert, &key, "fw", &["127.0.0.1".into(), "127.0.0.2".into()])
            .unwrap();
        let verified = Command::new(bin("openssl"))
            .args([
                "verify",
                "-CAfile",
                cert.to_str().unwrap(),
                "-verify_ip",
                "127.0.0.2",
                cert.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            verified.status.success(),
            "new bind IP must pass strict certificate verification"
        );
        assert_eq!(std::fs::read(&key).unwrap(), key_before);
        assert_eq!(cert_pubkey_pin(&cert).unwrap(), pin);
        let renewed = std::fs::read(&cert).unwrap();
        assert_ne!(renewed, old_cert);
        ensure_self_signed_cert(&cert, &key, "fw", &["127.0.0.2".into()]).unwrap();
        assert_eq!(
            std::fs::read(&cert).unwrap(),
            renewed,
            "covered SANs must not renew every boot"
        );
        std::fs::remove_file(&cert).unwrap();
        ensure_self_signed_cert(&cert, &key, "fw", &["127.0.0.2".into()]).unwrap();
        assert_eq!(
            std::fs::read(&key).unwrap(),
            key_before,
            "a missing cert must reuse the surviving key"
        );
        assert_eq!(cert_pubkey_pin(&cert).unwrap(), pin);
        std::fs::remove_dir_all(dir).unwrap();
    }

    struct AutomaticTlsFixture(std::path::PathBuf);
    impl AutomaticTlsFixture {
        fn new() -> Self {
            use std::os::unix::fs::DirBuilderExt;
            let mut random = [0u8; 16];
            getrandom::getrandom(&mut random).unwrap();
            let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            let path = std::env::temp_dir().join(format!("sentinel-auto-tls-{suffix}"));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }
        fn cert(&self) -> std::path::PathBuf {
            self.0.join("cert.pem")
        }
        fn key(&self) -> std::path::PathBuf {
            self.0.join("key.pem")
        }
        fn mint(&self) {
            ensure_self_signed_cert(&self.cert(), &self.key(), "fw", &["127.0.0.1".into()])
                .unwrap();
        }
    }
    impl Drop for AutomaticTlsFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn automatic_tls_lost_or_mismatched_identity_fails_without_rotation() {
        let first = AutomaticTlsFixture::new();
        first.mint();
        let cert = std::fs::read(first.cert()).unwrap();
        std::fs::remove_file(first.key()).unwrap();
        assert!(ensure_self_signed_cert(&first.cert(), &first.key(), "fw", &[]).is_err());
        assert!(!first.key().exists());
        assert_eq!(std::fs::read(first.cert()).unwrap(), cert);
        let other = AutomaticTlsFixture::new();
        other.mint();
        std::fs::copy(other.key(), first.key()).unwrap();
        let wrong_key = std::fs::read(first.key()).unwrap();
        assert!(ensure_self_signed_cert(&first.cert(), &first.key(), "fw", &[]).is_err());
        assert_eq!(std::fs::read(first.key()).unwrap(), wrong_key);
        assert_eq!(std::fs::read(first.cert()).unwrap(), cert);
    }

    #[test]
    fn automatic_tls_corrupt_certificate_and_invalid_names_preserve_bytes() {
        let fixture = AutomaticTlsFixture::new();
        fixture.mint();
        let key = std::fs::read(fixture.key()).unwrap();
        let cert = std::fs::read(fixture.cert()).unwrap();
        for name in [
            "fw,DNS:foreign.example",
            "fw/CN=foreign",
            "fw\nDNS:foreign",
            "",
            "bad name",
        ] {
            assert!(ensure_self_signed_cert(&fixture.cert(), &fixture.key(), name, &[]).is_err());
            assert_eq!(std::fs::read(fixture.key()).unwrap(), key);
            assert_eq!(std::fs::read(fixture.cert()).unwrap(), cert);
        }
        assert!(
            ensure_self_signed_cert(
                &fixture.cert(),
                &fixture.key(),
                "fw",
                &["127.0.0.1,DNS:foreign".into()]
            )
            .is_err()
        );
        std::fs::write(fixture.cert(), b"invalid certificate").unwrap();
        assert!(ensure_self_signed_cert(&fixture.cert(), &fixture.key(), "fw", &[]).is_err());
        assert_eq!(
            std::fs::read(fixture.cert()).unwrap(),
            b"invalid certificate"
        );
        assert_eq!(std::fs::read(fixture.key()).unwrap(), key);
    }

    #[test]
    fn automatic_tls_refuses_linked_identity_without_chmodding_another_target() {
        use std::os::unix::fs::PermissionsExt;
        for hardlink in [false, true] {
            let fixture = AutomaticTlsFixture::new();
            let outside = AutomaticTlsFixture::new();
            let target = outside.0.join("unrelated-key");
            std::fs::write(&target, b"unrelated").unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
            if hardlink {
                std::fs::hard_link(&target, fixture.key()).unwrap();
            } else {
                std::os::unix::fs::symlink(&target, fixture.key()).unwrap();
            }
            assert!(ensure_self_signed_cert(&fixture.cert(), &fixture.key(), "fw", &[]).is_err());
            assert_eq!(std::fs::read(&target).unwrap(), b"unrelated");
            assert_eq!(
                std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o644
            );
            assert!(!fixture.cert().exists());
        }
    }

    #[test]
    fn automatic_tls_concurrent_bootstrap_has_one_stable_private_identity() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let fixture = AutomaticTlsFixture::new();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(6));
        let threads: Vec<_> = (0..6)
            .map(|_| {
                let cert = fixture.cert();
                let key = fixture.key();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    ensure_self_signed_cert(&cert, &key, "fw", &["127.0.0.1".into()]).unwrap();
                    cert_pubkey_pin(&cert).unwrap()
                })
            })
            .collect();
        let pins: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert!(pins.iter().all(|pin| pin == &pins[0]));
        let key = std::fs::metadata(fixture.key()).unwrap();
        assert_eq!(key.permissions().mode() & 0o777, 0o600);
        assert_eq!(key.nlink(), 1);
        assert!(std::fs::read_dir(&fixture.0).unwrap().all(|entry| {
            ["key.pem", "cert.pem", ".certificate.lock"]
                .contains(&entry.unwrap().file_name().to_str().unwrap())
        }));
    }

    #[test]
    fn automatic_tls_expiring_certificate_renews_with_the_original_key() {
        let fixture = AutomaticTlsFixture::new();
        fixture.mint();
        let key = std::fs::read(fixture.key()).unwrap();
        let pin = cert_pubkey_pin(&fixture.cert()).unwrap();
        // A one-day certificate is valid now, but inside the 30-day renewal
        // window. `req -days 0` is not supported by all OpenSSL versions.
        let expiring = Command::new(bin("openssl"))
            .args([
                "req",
                "-x509",
                "-key",
                fixture.key().to_str().unwrap(),
                "-days",
                "1",
                "-subj",
                "/CN=fw",
                "-out",
                fixture.cert().to_str().unwrap(),
                "-addext",
                "subjectAltName=DNS:fw,DNS:localhost,IP:127.0.0.1",
            ])
            .output()
            .unwrap();
        assert!(expiring.status.success(), "OpenSSL expiry fixture failed");
        let cert = std::fs::read(fixture.cert()).unwrap();
        ensure_self_signed_cert(&fixture.cert(), &fixture.key(), "fw", &["127.0.0.1".into()])
            .unwrap();
        assert_eq!(std::fs::read(fixture.key()).unwrap(), key);
        assert_eq!(cert_pubkey_pin(&fixture.cert()).unwrap(), pin);
        assert_ne!(std::fs::read(fixture.cert()).unwrap(), cert);
    }

    // A workstation with no agent socket once answered `show flows` with 1481
    // nested `sentinel agent-query` processes, and the API that spawned the
    // first one stopped answering anything at all. The cause was this one
    // decision: the escalation helper tried the command plainly before asking
    // for privilege, and for a re-invocation of ourselves "plainly" means the
    // failure that asked for the escalation, which asks again.
    #[test]
    fn a_self_reinvocation_is_never_tried_unprivileged_first() {
        assert!(!plain_attempt_is_useful("sentinel-self"));
        // System tools keep the cheap path: most of what they are asked is
        // readable without privilege, and escalating first would ask for root
        // to run `ip -brief address show`.
        for tool in ["ip", "networkctl", "systemctl", "journalctl"] {
            assert!(plain_attempt_is_useful(tool), "{tool}");
        }
    }

    fn process_output(raw_status: i32, stdout: &[u8], stderr: &[u8]) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt;
        std::process::Output {
            status: std::process::ExitStatus::from_raw(raw_status),
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        }
    }

    type Invocation = (String, Vec<String>);

    fn simulated_escalation(
        cmd: &str,
        root: bool,
        outcomes: Vec<std::io::Result<std::process::Output>>,
    ) -> (Result<std::process::Output>, Vec<Invocation>) {
        let mut outcomes = std::collections::VecDeque::from(outcomes);
        let mut invocations = Vec::new();
        let result = escalated_output_with(
            cmd,
            "/nix/store/qa-tool/bin/tool",
            &["-s", "literal spaces;$(never-a-shell)"],
            root,
            |program, arguments| {
                invocations.push((
                    program.to_owned(),
                    arguments.iter().map(|arg| (*arg).to_owned()).collect(),
                ));
                outcomes.pop_front().expect("unexpected extra invocation")
            },
        );
        assert!(outcomes.is_empty(), "an expected invocation did not occur");
        (result, invocations)
    }

    fn check_privileged_invocation(invocations: &[Invocation]) {
        assert_eq!(
            invocations.last().unwrap(),
            &(
                "sudo".into(),
                vec![
                    "-n".into(),
                    "/nix/store/qa-tool/bin/tool".into(),
                    "-s".into(),
                    "literal spaces;$(never-a-shell)".into(),
                ],
            )
        );
    }

    #[test]
    fn escalated_output_root_runs_once_and_retains_nonzero_output() {
        let (result, invocations) = simulated_escalation(
            "nft",
            true,
            vec![Ok(process_output(1 << 8, b"root stdout", b"root ENOENT"))],
        );
        let result = result.unwrap();
        assert_eq!(result.status.code(), Some(1));
        assert_eq!(result.stdout, b"root stdout");
        assert_eq!(result.stderr, b"root ENOENT");
        assert_eq!(
            invocations,
            vec![(
                "/nix/store/qa-tool/bin/tool".into(),
                vec!["-s".into(), "literal spaces;$(never-a-shell)".into()]
            )]
        );
    }

    #[test]
    fn escalated_output_root_spawn_error_is_not_retried_via_sudo() {
        let (result, invocations) = simulated_escalation(
            "nft",
            true,
            vec![Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "root executable absent",
            ))],
        );
        let error = result.unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::NotFound
        );
        assert_eq!(invocations.len(), 1);
        assert_ne!(invocations[0].0, "sudo");
    }

    #[test]
    fn escalated_output_plain_success_never_requests_privilege() {
        let (result, invocations) =
            simulated_escalation("ip", false, vec![Ok(process_output(0, b"public", b""))]);
        assert_eq!(result.unwrap().stdout, b"public");
        assert_eq!(invocations.len(), 1);
        assert_ne!(invocations[0].0, "sudo");
    }

    #[test]
    fn escalated_output_privileged_enoent_replaces_unprivileged_eperm() {
        let (result, invocations) = simulated_escalation(
            "nft",
            false,
            vec![
                Ok(process_output(1 << 8, b"", b"Operation not permitted")),
                Ok(process_output(
                    1 << 8,
                    b"privileged table lookup",
                    b"No such file or directory",
                )),
            ],
        );
        let result = result.unwrap();
        assert_eq!(result.status.code(), Some(1));
        assert_eq!(result.stdout, b"privileged table lookup");
        assert_eq!(result.stderr, b"No such file or directory");
        assert_eq!(invocations.len(), 2);
        check_privileged_invocation(&invocations);
    }

    #[test]
    fn escalated_output_privileged_success_preserves_binary_streams() {
        let (result, invocations) = simulated_escalation(
            "nft",
            false,
            vec![
                Ok(process_output(1 << 8, b"stale", b"EPERM")),
                Ok(process_output(0, &[0, 255, 1], &[255, 0])),
            ],
        );
        let result = result.unwrap();
        assert!(result.status.success());
        assert_eq!(result.stdout, [0, 255, 1]);
        assert_eq!(result.stderr, [255, 0]);
        check_privileged_invocation(&invocations);
    }

    #[test]
    fn escalated_output_genuine_privileged_permission_denial_remains_failure() {
        for (status, message) in [
            (1, "privileged operation denied"),
            (1, "sudo: a password is required"),
            (127, "sudo: tool: command not found"),
        ] {
            let (result, invocations) = simulated_escalation(
                "nft",
                false,
                vec![
                    Ok(process_output(1 << 8, b"stale", b"unprivileged EPERM")),
                    Ok(process_output(status << 8, b"", message.as_bytes())),
                ],
            );
            let result = result.unwrap();
            assert!(!result.status.success());
            assert_eq!(result.status.code(), Some(status));
            assert_eq!(result.stderr, message.as_bytes());
            assert_ne!(result.stderr, b"unprivileged EPERM");
            check_privileged_invocation(&invocations);
        }
    }

    #[test]
    fn escalated_output_signalled_privileged_result_is_not_replaced() {
        use std::os::unix::process::ExitStatusExt;
        let (result, invocations) = simulated_escalation(
            "nft",
            false,
            vec![
                Ok(process_output(1 << 8, b"", b"unprivileged EPERM")),
                Ok(process_output(9, b"partial", b"terminated")),
            ],
        );
        let result = result.unwrap();
        assert_eq!(result.status.signal(), Some(9));
        assert_eq!(result.status.code(), None);
        assert_eq!(result.stdout, b"partial");
        assert_eq!(result.stderr, b"terminated");
        check_privileged_invocation(&invocations);
    }

    #[test]
    fn escalated_output_sudo_io_failure_remains_error_not_stale_output() {
        for kind in [
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::BrokenPipe,
        ] {
            let (result, invocations) = simulated_escalation(
                "nft",
                false,
                vec![
                    Ok(process_output(1 << 8, b"", b"unprivileged EPERM")),
                    Err(std::io::Error::new(kind, "sudo spawn/read/wait failed")),
                ],
            );
            let error = result.unwrap_err();
            assert_eq!(error.downcast_ref::<std::io::Error>().unwrap().kind(), kind);
            assert!(format!("{error:#}").contains("sudo spawn/read/wait failed"));
            assert!(!format!("{error:#}").contains("unprivileged EPERM"));
            check_privileged_invocation(&invocations);
        }
    }

    #[test]
    fn escalated_output_plain_io_failure_still_allows_one_privileged_attempt() {
        let (result, invocations) = simulated_escalation(
            "nft",
            false,
            vec![
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "unprivileged cannot execute",
                )),
                Ok(process_output(0, b"privileged result", b"")),
            ],
        );
        assert_eq!(result.unwrap().stdout, b"privileged result");
        assert_eq!(invocations.len(), 2);
        check_privileged_invocation(&invocations);
    }

    #[test]
    fn escalated_output_self_never_recurses_plainly_even_when_sudo_fails() {
        let (result, invocations) = simulated_escalation(
            "sentinel-self",
            false,
            vec![Ok(process_output(1 << 8, b"", b"sudo refusal"))],
        );
        assert_eq!(result.unwrap().stderr, b"sudo refusal");
        assert_eq!(invocations.len(), 1);
        check_privileged_invocation(&invocations);
    }

    /// The picker only helps if what it offers is what the validator takes. A
    /// list containing `posix/Europe/Berlin` or `zone.tab` would be a set of
    /// choices half of which the appliance refuses at commit.
    #[test]
    fn every_timezone_offered_is_one_the_validator_would_take() {
        let zones = choices("timezone").expect("timezone");
        // A machine without tzdata has nothing to offer and that is a correct
        // answer, so the assertions are about what *is* there.
        for zone in &zones {
            assert!(!zone.contains(".."), "{zone}");
            assert!(!zone.starts_with('/'), "{zone}");
            assert!(
                !zone.contains('.'),
                "{zone}: not a zone, a table beside one"
            );
            assert!(
                !zone.starts_with("posix/") && !zone.starts_with("right/"),
                "{zone}: the same zone under another leap-second model"
            );
            assert!(
                std::path::Path::new("/usr/share/zoneinfo")
                    .join(zone)
                    .is_file(),
                "{zone}: offered but not installed"
            );
        }
        if std::path::Path::new("/usr/share/zoneinfo/Europe/Berlin").is_file() {
            assert!(zones.iter().any(|z| z == "Europe/Berlin"));
            assert!(zones.iter().any(|z| z == "UTC"));
        }
    }

    /// The same, for the keymaps: `de.map.gz` is offered as `de`, because `de`
    /// is what `loadkeys` takes and what `system keyboard` validates.
    #[test]
    fn a_keymap_is_offered_by_the_name_the_setting_holds() {
        for name in choices("keyboard").expect("keyboard") {
            assert!(!name.contains('.'), "{name}: still carries its extension");
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "{name}: the validator would refuse this"
            );
        }
    }

    /// Sorted and without repeats. Two packages install the same keymap under
    /// two roots, and a picker that lists `de` twice is a picker that looks
    /// broken in the one place its whole job is to look trustworthy.
    #[test]
    fn choices_come_back_sorted_and_once_each() {
        for kind in ["timezone", "keyboard", "locale"] {
            let got = choices(kind).expect(kind);
            let mut want = got.clone();
            want.sort();
            want.dedup();
            assert_eq!(got, want, "{kind}");
        }
        assert!(choices("nonsense").is_err());
    }

    /// A box that has none of these — a container, a workstation running the
    /// tests, an image built without the keymap package — answers with an empty
    /// list rather than failing. The console then leaves the field as the
    /// ordinary box you type into that it has always been, which is the right
    /// thing to degrade to: an appliance the console cannot enumerate is not an
    /// appliance whose timezone cannot be set.
    #[test]
    fn a_system_without_the_data_offers_nothing_rather_than_failing() {
        let nowhere = std::path::Path::new("/nonexistent/velstra/no-such-tree");
        let mut zones = Vec::new();
        walk_zones(nowhere, nowhere, &mut zones, 0);
        assert!(zones.is_empty());
        let mut keymaps = Vec::new();
        walk_keymaps(nowhere, &mut keymaps, 0);
        assert!(keymaps.is_empty());
        // And the caller still gets Ok: an empty answer is an answer.
        for kind in ["timezone", "keyboard", "locale"] {
            assert!(choices(kind).is_ok(), "{kind}");
        }
    }
}

#[cfg(test)]
mod ha_curl_tests {
    use super::*;
    /// A peer's refusal survives as a status a caller can act on: curl's `-f`
    /// says it only on stderr.
    #[test]
    fn an_http_refusal_is_read_off_curls_stderr() {
        assert_eq!(
            curl_http_status("curl: (22) The requested URL returned error: 409\n"),
            Some(409)
        );
        assert_eq!(
            curl_http_status("curl: (22) The requested URL returned error: 401 Unauthorized"),
            Some(401)
        );
        assert_eq!(curl_http_status("curl: (7) Failed to connect"), None);
    }
    #[test]
    fn bearer_config_escapes_and_rejects_injection() {
        assert_eq!(
            curl_auth_config(Some("a\\b\"c")).unwrap(),
            "header = \"Authorization: Bearer a\\\\b\\\"c\"\n"
        );
        assert_eq!(curl_auth_config(None).unwrap(), "");
        for bad in ["", "secret\nurl = https://attacker", "secret\r\n", "nul\0"] {
            assert!(curl_auth_config(Some(bad)).is_err());
        }
    }

    /// The credentialed curl sees none of the caller's environment — a proxy,
    /// a key log file or a CA override set around `sentinel` never reaches it —
    /// and `--disable` is its first argument, the only place curl honours it.
    #[test]
    fn credentialed_curl_runs_with_an_empty_environment_and_no_curlrc() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("sentinel-curl-env-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("curl");
        std::fs::write(&fake, "#!/bin/sh\nprintf 'first=%s\\n' \"$1\"\nenv\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        // SAFETY: test-only; nothing else in the test binary spawns curl, the
        // only reader of these two variables.
        unsafe {
            std::env::set_var("HTTPS_PROXY", "http://proxy.attacker.example:3128");
            std::env::set_var("SSLKEYLOGFILE", "/tmp/stolen-keys");
        }
        let out = curl_command_for(fake.to_str().unwrap())
            .arg("https://peer.example")
            .output()
            .unwrap();
        unsafe {
            std::env::remove_var("HTTPS_PROXY");
            std::env::remove_var("SSLKEYLOGFILE");
        }
        std::fs::remove_dir_all(&dir).unwrap();
        let text = String::from_utf8(out.stdout).unwrap();
        let mut lines = text.lines();
        assert_eq!(lines.next(), Some("first=--disable"), "{text}");
        // What a POSIX shell exports by itself (PWD, SHLVL, _) is the only
        // thing allowed beside PATH.
        // Names only: a failure must not print the environment's values.
        let leaked: Vec<_> = lines
            .filter_map(|l| l.split_once('=').map(|(name, _)| name))
            .filter(|name| !["PATH", "PWD", "SHLVL", "_"].contains(name))
            .collect();
        assert!(
            leaked.is_empty(),
            "ambient environment reached curl: {leaked:?}"
        );
    }
}
