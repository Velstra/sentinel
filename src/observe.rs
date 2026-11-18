//! Six local read capabilities. This is not a generic privileged command runner.
//! The sudoers rule names the exact unwrapped build and each literal operation.
//! Sudo supplies the original numeric UID; current account ownership and its
//! current configuration grant are checked before AND after collecting output.

use std::{
    io::Read,
    os::{fd::AsRawFd, unix::process::CommandExt},
    path::Path,
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::ValueEnum;

use crate::{api_session, config::Appliance, redact::Disclosure, session::DEFAULT_CONFIG, system};

const CHILD_ENV: &str = "SENTINEL_OBSERVE_CHILD";
const SUDO: &str = "/run/wrappers/bin/sudo";
const DEADLINE: Duration = Duration::from_secs(8);
const MAX_STDOUT: usize = 8 * 1024 * 1024;
const MAX_STDERR: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Operation {
    Configuration,
    ConfigurationCommands,
    BgpSummary,
    Flows,
    FirewallStatistics,
    FirewallCapacity,
}

impl Operation {
    pub fn name(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::ConfigurationCommands => "configuration-commands",
            Self::BgpSummary => "bgp-summary",
            Self::Flows => "flows",
            Self::FirewallStatistics => "firewall-statistics",
            Self::FirewallCapacity => "firewall-capacity",
        }
    }

    fn words(self) -> &'static [&'static str] {
        match self {
            Self::Configuration => &["configuration"],
            Self::ConfigurationCommands => &["configuration", "commands"],
            Self::BgpSummary => &["ip", "bgp", "summary"],
            Self::Flows => &["flows"],
            Self::FirewallStatistics => &["firewall", "statistics"],
            Self::FirewallCapacity => &["firewall", "capacity"],
        }
    }
}

pub fn operation_for_show(words: &[String]) -> Option<Operation> {
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["configuration"] => Some(Operation::Configuration),
        ["configuration", "commands"] => Some(Operation::ConfigurationCommands),
        ["ip", "bgp", "summary" | "neighbors"] => Some(Operation::BgpSummary),
        ["flows" | "connections" | "conntrack"] | ["firewall", "flows"] => Some(Operation::Flows),
        ["firewall", "statistics" | "stats"] => Some(Operation::FirewallStatistics),
        ["firewall", "capacity"] => Some(Operation::FirewallCapacity),
        _ => None,
    }
}

/// Off-box/custom-file shows keep their ordinary unprivileged behavior. Only
/// the installed appliance's protected default configuration uses a capability.
pub fn needs_capability(config: &Path) -> bool {
    !system::is_root()
        && config == Path::new(DEFAULT_CONFIG)
        && option_env!("SENTINEL_OBSERVE_HELPER_BIN").is_some()
        && !existing_administrator()
}

// This is routing, NOT a grant. Existing wheel accounts keep their existing
// ordinary file/sudo access, including the pre-provisioning recovery admin.
// A forged USER/LOGNAME/SUDO_USER cannot change kernel group membership. A
// non-wheel caller who bypasses this routing still cannot read protected files
// or reach the root-only sockets without passing the typed helper's grant.
fn existing_administrator() -> bool {
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count < 0 {
        return false;
    }
    let mut groups = vec![0; count as usize];
    if unsafe { libc::getgroups(count, groups.as_mut_ptr()) } != count {
        return false;
    }
    groups.push(unsafe { libc::getegid() });
    system::read_owned_regular(Path::new("/etc/group"), 4 * 1024 * 1024)
        .ok()
        .flatten()
        .is_some_and(|body| wheel_member(&body, &groups))
}

fn wheel_member(body: &str, groups: &[libc::gid_t]) -> bool {
    let mut wheel = None;
    for line in body.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.first() == Some(&"wheel") {
            if fields.len() != 4 || wheel.is_some() {
                return false;
            }
            let Ok(gid) = fields[2].parse::<libc::gid_t>() else {
                return false;
            };
            wheel = Some(gid);
        }
    }
    wheel.is_some_and(|gid| groups.contains(&gid))
}

pub fn strict_child() -> bool {
    system::is_root() && std::env::var_os(CHILD_ENV).as_deref() == Some(std::ffi::OsStr::new("1"))
}

fn store_binary(path: &str) -> Result<&str> {
    let path_ref = Path::new(path);
    ensure!(
        path_ref.starts_with("/nix/store")
            && path_ref.is_absolute()
            && path_ref.components().all(|part| matches!(
                part,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            ))
            && path_ref.file_name().is_some(),
        "observation capability has no immutable tool pin"
    );
    Ok(path)
}

/// No inherited config, socket, tool, redaction or sudo-origin variables. Sudo
/// creates its own authenticated SUDO_UID/SUDO_USER for the capability process.
pub fn request(operation: Operation) -> Result<()> {
    let helper = store_binary(
        option_env!("SENTINEL_OBSERVE_HELPER_BIN")
            .context("local observation capability is not installed")?,
    )?;
    let status = Command::new(SUDO)
        .args(["-n", "--", helper, "observe", operation.name()])
        .env_clear()
        .env("PATH", "/run/wrappers/bin")
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .status()
        .context("starting the local observation capability")?;
    ensure!(
        status.success(),
        "local observation was refused or unavailable"
    );
    Ok(())
}

fn sudo_uid(value: &str) -> Result<u32> {
    let uid: u32 = value.parse().context("invalid sudo origin UID")?;
    ensure!(
        value == uid.to_string() && system::managed_login_uid(uid),
        "observation requires a normal local sudo origin UID"
    );
    Ok(uid)
}

fn local_name(body: &str, uid: u32) -> Result<String> {
    let mut found = None;
    for line in body.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        ensure!(fields.len() == 7, "invalid local passwd inventory");
        let candidate: u32 = fields[2].parse().context("invalid local passwd UID")?;
        if candidate == uid {
            ensure!(found.is_none(), "ambiguous local observation identity");
            found = Some(fields[0].to_string());
        }
    }
    found.context("sudo origin is not a current local account")
}

#[derive(Debug, PartialEq, Eq)]
struct Grant {
    user: String,
    uid: u32,
    digest: String,
    disclosure: Disclosure,
}

fn appliance() -> Result<Appliance> {
    let body = match system::read_owned_regular(
        Path::new(crate::session::Session::RUNNING),
        2 * 1024 * 1024,
    )? {
        Some(body) => body,
        None => system::read_owned_regular(Path::new(DEFAULT_CONFIG), 2 * 1024 * 1024)?
            .context("no active appliance configuration")?,
    };
    Appliance::from_toml(&body).context("invalid active observation configuration")
}

fn grant(uid: u32, expected_name: &str) -> Result<(Grant, Appliance)> {
    let passwd = system::read_owned_regular(Path::new("/etc/passwd"), 4 * 1024 * 1024)?
        .context("local passwd inventory is unavailable")?;
    let user = local_name(&passwd, uid)?;
    ensure!(
        user == expected_name,
        "sudo origin name and numeric UID disagree"
    );
    crate::net::verify_observer_login(&user, uid)?;
    let appliance = appliance()?;
    Ok((account_grant(&appliance, &user, uid)?, appliance))
}

fn account_grant(appliance: &Appliance, user: &str, uid: u32) -> Result<Grant> {
    let (permission, digest) = api_session::grant(appliance, user, false)
        .context("the local account has no current observation grant")?;
    Ok(Grant {
        user: user.into(),
        uid,
        digest,
        disclosure: Disclosure::for_caller(Some(user), permission),
    })
}

/// Protected parser errors may contain the TOML/JSON source and secret values.
/// Do not attach their source chain before an authorization/redaction context
/// exists, or after that context was revoked while a collector was running.
fn authorization_failure(_: anyhow::Error) -> anyhow::Error {
    anyhow!("local observation authorization is unavailable or denied")
}

struct CollectorPermit {
    file: std::fs::File,
    owner: u32,
}

impl Drop for CollectorPermit {
    fn drop(&mut self) {
        // CLOEXEC closes a child's inherited descriptor only at exec. The
        // completed collector must release its permit even if an unrelated
        // fork still holds a duplicate of this open file description.
        // An inherited Rust guard must not unlock its parent's live collector
        // if a forked child drops it before exec.
        if self.owner == std::process::id() {
            unsafe {
                libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

fn permit_at(path: &Path, expected_uid: u32) -> Result<CollectorPermit> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .context("opening observation collector permit")?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == expected_uid
            && metadata.mode() & 0o077 == 0,
        "unsafe observation collector permit"
    );
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "another local observation is running; retry shortly"
    );
    Ok(CollectorPermit {
        file,
        owner: std::process::id(),
    })
}

fn child_command(exe: &Path, operation: Operation, disclosure: Disclosure) -> Result<Command> {
    // Every collector is a LEAF: Wren's fixed read client is invoked directly,
    // not via Sentinel -> Wren (parent-death signals do not survive fork).
    // The five Sentinel show paths below render config or query a fixed socket;
    // strict_child() forbids the historical journalctl statistics fallback.
    let mut command = if operation == Operation::BgpSummary {
        let mut command = Command::new(store_binary(
            option_env!("SENTINEL_OBSERVE_WREN_BIN")
                .context("routing observation has no immutable Wren pin")?,
        )?);
        command.args([
            "--socket",
            "/run/wren/wren.sock",
            "show",
            "bgp",
            "neighbors",
        ]);
        command
    } else {
        let mut command = Command::new(exe);
        command.args(["show"]).args(operation.words());
        command
    };
    command
        .env_clear()
        .env("PATH", "/no-observation-path")
        .env("LANG", "C.UTF-8")
        .env("HOME", "/")
        .env("SENTINEL_CONFIG", DEFAULT_CONFIG)
        .env(CHILD_ENV, "1")
        .env(
            crate::redact::ENV,
            disclosure
                .env_value()
                .context("observation may not disclose a full machine credential")?,
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    Ok(command)
}

fn nonblocking(stream: &impl AsRawFd) -> Result<()> {
    let fd = stream.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    ensure!(flags >= 0, "reading observation pipe flags failed");
    ensure!(
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0,
        "setting observation pipe flags failed"
    );
    Ok(())
}

fn drain(
    stream: &mut impl Read,
    output: &mut Vec<u8>,
    limit: usize,
    deadline: Instant,
) -> Result<bool> {
    let mut buffer = [0u8; 8192];
    loop {
        ensure!(Instant::now() < deadline, "observation deadline exceeded");
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(length) => {
                ensure!(
                    length <= limit.saturating_sub(output.len()),
                    "observation output limit exceeded"
                );
                output.extend_from_slice(&buffer[..length]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error).context("reading observation output"),
        }
    }
}

fn bounded(command: &mut Command, timeout: Duration, stdout_limit: usize) -> Result<Output> {
    let parent = unsafe { libc::getpid() };
    // Only async-signal-safe syscalls run between fork and exec. These fixed
    // non-setuid leaves never fork/change credentials. SIGKILL also covers
    // helper SIGTERM/SIGKILL; checking getppid closes the setup/death race.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
            }
            Ok(())
        });
    }
    let mut child = command.spawn().context("starting observation collector")?;
    let result = (|| {
        let mut stdout = child.stdout.take().context("observation stdout missing")?;
        let mut stderr = child.stderr.take().context("observation stderr missing")?;
        nonblocking(&stdout)?;
        nonblocking(&stderr)?;
        let deadline = Instant::now() + timeout;
        let mut output = Vec::new();
        let mut errors = Vec::new();
        loop {
            let out_done = drain(&mut stdout, &mut output, stdout_limit, deadline)?;
            let err_done = drain(&mut stderr, &mut errors, MAX_STDERR, deadline)?;
            if let Some(status) = child.try_wait()?
                && out_done
                && err_done
            {
                return Ok(Output {
                    status,
                    stdout: output,
                    stderr: errors,
                });
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })();
    if result.is_err() {
        // Leaf child only: std::Child tracks a reaped status, so unlike a raw
        // killpg this cannot target a newly reused PID after try_wait reaped it.
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

pub fn run(operation: Operation) -> Result<()> {
    ensure!(system::is_root(), "observation capability requires sudo");
    let uid =
        sudo_uid(&std::env::var("SUDO_UID").context("missing authenticated sudo origin UID")?)?;
    let name = std::env::var("SUDO_USER").context("missing authenticated sudo origin name")?;
    let (before, config) = grant(uid, &name).map_err(authorization_failure)?;
    let permit = permit_at(Path::new("/run/sentinel-observe.lock"), 0)?;
    let exe = std::env::current_exe().context("locating observation collector")?;
    let output = bounded(
        &mut child_command(&exe, operation, before.disclosure)?,
        DEADLINE,
        MAX_STDOUT,
    )?;
    let (after, current) = grant(uid, &name).map_err(authorization_failure)?;
    ensure!(
        before == after,
        "observation grant changed during collection"
    );
    let secrets = if before.disclosure == Disclosure::NoSecrets {
        let mut secrets = crate::redact::every_secret_value(&config);
        secrets.extend(crate::redact::every_secret_value(&current));
        secrets.sort_by_key(|value| std::cmp::Reverse(value.len()));
        secrets.dedup();
        secrets
    } else {
        // The rendered account-admin view already withholds machine credentials.
        // NoMachineCredential is never upgraded to Full by an environment flag.
        Vec::new()
    };
    if !output.status.success() {
        // A failed root collector could print a protected parse error with a
        // NEW secret absent from the before/after valid configurations. Never
        // forward that source excerpt, even through a known-secret scrubber.
        bail!(
            "{} observation unavailable (collector exit {:?}); check the relevant service or configuration",
            operation.name(),
            output.status.code()
        );
    }
    let text = crate::redact::scrub_text(
        std::str::from_utf8(&output.stdout).context("observation returned non-UTF-8 output")?,
        &secrets,
    );
    // A slow terminal may apply ordinary CLI backpressure; it must not retain
    // the privileged collector permit after collection/revalidation completes.
    drop(permit);
    print!("{text}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn capability_parser_has_only_six_literal_forms_and_no_path_or_control_escape() {
        for operation in Operation::value_variants() {
            assert!(crate::Cli::try_parse_from(["sentinel", "observe", operation.name()]).is_ok());
            for extra in [
                "reload",
                "--socket",
                "/etc/shadow",
                "--config",
                "--no-apply",
            ] {
                assert!(
                    crate::Cli::try_parse_from(["sentinel", "observe", operation.name(), extra])
                        .is_err()
                );
            }
        }
        assert_eq!(Operation::value_variants().len(), 6);
        for operation in [
            "show",
            "reload",
            "configuration\napply",
            "../configuration",
            "/etc/shadow",
            "flows 1",
            "",
        ] {
            assert!(crate::Cli::try_parse_from(["sentinel", "observe", operation]).is_err());
        }
    }

    #[test]
    fn aliases_resolve_to_fixed_requests_not_caller_arguments() {
        for words in [vec!["flows"], vec!["conntrack"], vec!["firewall", "flows"]] {
            assert_eq!(
                operation_for_show(&words.into_iter().map(str::to_string).collect::<Vec<_>>()),
                Some(Operation::Flows)
            );
        }
        for words in [
            vec!["flows", "reload"],
            vec!["configuration", "/etc/shadow"],
            vec!["ip", "bgp", "--config", "/etc/shadow"],
        ] {
            assert!(
                operation_for_show(&words.into_iter().map(str::to_string).collect::<Vec<_>>())
                    .is_none()
            );
        }
    }

    #[test]
    fn original_identity_is_numeric_unique_and_local_not_a_claimed_name() {
        let passwd = "root:x:0:0:root:/root:/bin/sh\nviewer:x:1234:100::/home/viewer:/bin/sh\n";
        assert_eq!(
            local_name(passwd, sudo_uid("1234").unwrap()).unwrap(),
            "viewer"
        );
        for uid in [
            "0",
            "999",
            "65534",
            "+1234",
            "01234",
            "1234\n",
            "-1",
            "4294967296",
        ] {
            assert!(sudo_uid(uid).is_err(), "{uid:?}");
        }
        assert!(local_name(passwd, 2345).is_err());
        assert!(
            local_name(
                &(passwd.to_string() + "other:x:1234:100::/:/bin/sh\n"),
                1234
            )
            .is_err()
        );
        assert!(local_name("malformed", 1234).is_err());
    }

    #[test]
    fn bootstrap_admin_routing_uses_kernel_groups_not_claimed_account_names() {
        let group = "root:x:0:\nwheel:x:10:admin,viewer\nusers:x:100:\n";
        assert!(wheel_member(group, &[100, 10]));
        // Even a name listed in /etc/group cannot grant the current process
        // wheel: only its actual effective/supplementary numeric GIDs count.
        assert!(!wheel_member(group, &[100]));
        assert!(!wheel_member("wheel:x:broken:admin\n", &[10]));
        assert!(!wheel_member(
            "wheel:x:10:admin\nwheel:x:100:viewer\n",
            &[10]
        ));
    }

    #[test]
    fn current_account_grant_is_required_and_viewer_disclosure_cannot_be_upgraded() {
        let text = "[system]\nhostname='observe-fixture'\n[[system.group]]\nname='viewers'\npermission='read-only'\n[[system.group]]\nname='operators'\npermission='read-write'\n[[system.login]]\nusername='viewer'\ngroup='viewers'\n[[system.login]]\nusername='operator'\ngroup='operators'\n[[system.login]]\nusername='ungrouped'\n[[system.login]]\nusername='admin'\n";
        let mut appliance = Appliance::from_toml(text).unwrap();
        assert_eq!(
            account_grant(&appliance, "viewer", 1234)
                .unwrap()
                .disclosure,
            Disclosure::NoSecrets
        );
        assert_eq!(
            account_grant(&appliance, "operator", 1235)
                .unwrap()
                .disclosure,
            Disclosure::NoMachineCredential
        );
        assert_eq!(
            account_grant(&appliance, "admin", 1236).unwrap().disclosure,
            Disclosure::NoMachineCredential
        );
        assert!(account_grant(&appliance, "ungrouped", 1237).is_err());
        assert!(account_grant(&appliance, "absent", 1238).is_err());
        let previous = account_grant(&appliance, "operator", 1235).unwrap();
        appliance.system.logins[1].group = Some("viewers".into());
        let demoted = account_grant(&appliance, "operator", 1235).unwrap();
        assert_ne!(previous, demoted);
        assert_eq!(demoted.disclosure, Disclosure::NoSecrets);
        appliance
            .system
            .logins
            .retain(|login| login.username != "operator");
        assert!(account_grant(&appliance, "operator", 1235).is_err());
    }

    #[test]
    fn protected_parse_errors_have_no_secret_source_chain_at_the_public_boundary() {
        let marker = "fixture-private-credential-do-not-disclose";
        let toml = Appliance::from_toml(&format!("[system]\nhostname='{marker}'\ninvalid = ["))
            .unwrap_err();
        let json =
            serde_json::from_str::<serde_json::Value>(&format!("{{\"secret\":\"{marker}\",broken"))
                .unwrap_err();
        for error in [toml, anyhow::Error::new(json)] {
            let shown = format!("{:#}", authorization_failure(error));
            assert_eq!(
                shown,
                "local observation authorization is unavailable or denied"
            );
            assert!(!shown.contains(marker));
        }
    }

    #[test]
    fn collector_permit_is_nonblocking_released_and_refuses_unsafe_files() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!(
            "sentinel-observe-permit-{}-{:?}",
            std::process::id(),
            Instant::now()
        ));
        let uid = unsafe { libc::geteuid() };
        let first = permit_at(&path, uid).unwrap();
        assert!(permit_at(&path, uid).is_err());
        drop(first);
        drop(permit_at(&path, uid).unwrap());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(permit_at(&path, uid).is_err());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn completed_collector_unlocks_despite_an_inherited_descriptor() {
        let path = std::env::temp_dir().join(format!(
            "sentinel-observe-inherited-permit-{}-{:?}",
            std::process::id(),
            Instant::now()
        ));
        let uid = unsafe { libc::geteuid() };
        let first = permit_at(&path, uid).unwrap();
        // dup and fork share the same open file description. Retaining a dup
        // reproduces the fork-before-exec lifetime without timing or a child.
        let inherited = first.file.try_clone().unwrap();
        let foreign_guard = CollectorPermit {
            file: first.file.try_clone().unwrap(),
            // A guard inherited from another process is not its lock owner.
            owner: 0,
        };
        drop(foreign_guard);
        assert!(permit_at(&path, uid).is_err());
        drop(first);
        let next = permit_at(&path, uid).unwrap();
        assert!(permit_at(&path, uid).is_err());
        drop(inherited);
        assert!(permit_at(&path, uid).is_err());
        drop(next);
        drop(permit_at(&path, uid).unwrap());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn collector_has_fixed_arguments_config_disclosure_and_no_inherited_environment() {
        let command = child_command(
            Path::new("/immutable/sentinel"),
            Operation::ConfigurationCommands,
            Disclosure::NoSecrets,
        )
        .unwrap();
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["show", "configuration", "commands"]
        );
        let env: std::collections::BTreeMap<_, _> = command.get_envs().collect();
        assert_eq!(
            env.get(std::ffi::OsStr::new("SENTINEL_CONFIG"))
                .unwrap()
                .unwrap(),
            DEFAULT_CONFIG
        );
        assert_eq!(
            env.get(std::ffi::OsStr::new(crate::redact::ENV))
                .unwrap()
                .unwrap(),
            "secrets"
        );
        assert_eq!(
            env.get(std::ffi::OsStr::new("PATH")).unwrap().unwrap(),
            "/no-observation-path"
        );
        assert!(!env.contains_key(std::ffi::OsStr::new("SUDO_UID")));
        assert!(
            child_command(
                Path::new("/sentinel"),
                Operation::Configuration,
                Disclosure::Full
            )
            .is_err()
        );
        for path in ["sentinel", "/tmp/evil", "/nix/store/../tmp/evil"] {
            assert!(store_binary(path).is_err());
        }
        match option_env!("SENTINEL_OBSERVE_WREN_BIN") {
            Some(pin) => {
                let bgp = child_command(
                    Path::new("/must-not-run-the-intermediate-sentinel"),
                    Operation::BgpSummary,
                    Disclosure::NoSecrets,
                )
                .unwrap();
                assert_eq!(bgp.get_program(), std::ffi::OsStr::new(pin));
                assert_eq!(
                    bgp.get_args().collect::<Vec<_>>(),
                    [
                        "--socket",
                        "/run/wren/wren.sock",
                        "show",
                        "bgp",
                        "neighbors"
                    ]
                );
            }
            None => assert!(
                child_command(
                    Path::new("/must-not-fallback"),
                    Operation::BgpSummary,
                    Disclosure::NoSecrets
                )
                .is_err()
            ),
        }
    }

    fn python(script: &str) -> Command {
        let mut command =
            Command::new(option_env!("SENTINEL_TEST_PYTHON_BIN").unwrap_or("/usr/bin/python3"));
        command
            .args(["-c", script])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    // This test-harness subprocess is used only by the parent-death regression.
    // It does not run a capability, read protected state or generate traffic.
    #[test]
    fn parent_death_child_harness() {
        let Some(path) = std::env::var_os("SENTINEL_TEST_PARENT_DEATH") else {
            return;
        };
        let script = format!(
            "import os,pathlib,time; p=pathlib.Path({:?}); t=p.with_name(p.name+'.tmp'); t.write_text(str(os.getpid())); t.replace(p); time.sleep(30)",
            path.to_str().unwrap()
        );
        let _ = bounded(&mut python(&script), Duration::from_secs(30), 1024);
        panic!("parent-death harness must be terminated by its test parent");
    }

    #[test]
    fn externally_killed_helper_cannot_leave_a_stalled_privileged_collector() {
        use std::os::unix::fs::DirBuilderExt;

        // Own both publication paths and the helper across every assertion. A
        // panic must not leave the helper alive or a partial PID file behind.
        struct Fixture {
            directory: std::path::PathBuf,
            helper: Option<std::process::Child>,
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                if let Some(helper) = self.helper.as_mut() {
                    let _ = helper.kill();
                    let _ = helper.wait();
                }
                for name in ["collector.pid", "collector.pid.tmp"] {
                    let _ = std::fs::remove_file(self.directory.join(name));
                }
                let _ = std::fs::remove_dir(&self.directory);
            }
        }

        let directory = std::env::temp_dir().join(format!(
            "sentinel-observe-parent-death-{}-{:?}",
            std::process::id(),
            Instant::now()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let mut fixture = Fixture {
            directory,
            helper: None,
        };
        let path = fixture.directory.join("collector.pid");
        fixture.helper = Some(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "observe::tests::parent_death_child_harness",
                    "--nocapture",
                ])
                .env("SENTINEL_TEST_PARENT_DEATH", &path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let helper = fixture.helper.as_mut().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        // The collector writes/closes a same-directory temporary file and
        // renames it into place. Existence now means a complete PID record,
        // not merely that write_text has opened its destination.
        while !path.exists() {
            if Instant::now() >= deadline {
                panic!("real collector did not publish its PID");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let pid: u32 = std::fs::read_to_string(&path).unwrap().parse().unwrap();
        assert!(std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok());
        helper.kill().unwrap();
        helper.wait().unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            // A dead reparented child may remain a zombie until init reaps it;
            // that is not a runnable collector or retained socket/permit owner.
            let live = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .is_some_and(|stat| !stat.rsplit_once(") ").unwrap().1.starts_with('Z'));
            if !live {
                break;
            }
            if Instant::now() >= deadline {
                unsafe {
                    libc::kill(pid as i32, libc::SIGKILL);
                }
                panic!("collector survived capability parent termination");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn actual_collection_preserves_success_failure_and_both_streams() {
        let output = bounded(
            &mut python(
                "import sys; print('live observation'); print('diagnostic',file=sys.stderr)",
            ),
            Duration::from_secs(3),
            1024,
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"live observation\n");
        assert_eq!(output.stderr, b"diagnostic\n");
        let output = bounded(
            &mut python("import sys; print('refused',file=sys.stderr); sys.exit(7)"),
            Duration::from_secs(3),
            1024,
        )
        .unwrap();
        assert_eq!(output.status.code(), Some(7));
    }

    #[test]
    fn actual_collection_is_deadline_and_output_bounded() {
        let start = Instant::now();
        assert!(
            bounded(
                &mut python("import time; time.sleep(10)"),
                Duration::from_millis(50),
                1024
            )
            .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(3));
        assert!(
            bounded(
                &mut python("print('x'*100000)"),
                Duration::from_secs(3),
                1024
            )
            .is_err()
        );
    }
}
