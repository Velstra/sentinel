//! Never boot dark because the data plane refuses the saved configuration.
//!
//! The DP-01 class: a configuration the agent will not load is cleanly rolled
//! back when it is committed live, but the same configuration SAVED makes the
//! agent crash-loop at boot. Its links stay held down (fail-closed), the
//! management NIC is zoned like any other, and the box is unreachable until
//! someone reaches its console. The triggers keep changing — an unknown
//! port-forward field, a protocol a port-forward cannot carry, more rules than
//! the agent's tries hold, a feed that grew past a cap — so this answers the
//! class rather than each trigger:
//!
//! 1. **Seed** (`sentinel-boot`, before the agent starts): ask the agent's own
//!    validator about the compiled saved config. If it refuses, boot the last
//!    configuration this box booted healthily with instead, and failing that a
//!    management-only policy derived from the saved one.
//! 2. **Verify** (`sentinel-boot-verify`, after the agent starts): a refusal
//!    the validator cannot see (a map that fills while loading) shows up as an
//!    agent that never becomes ready. Apply the same fallbacks live. When the
//!    agent is ready and nothing fell back, record the configuration as the
//!    new last-known-good.
//!
//! Either way the box says so: the journal and the console at boot, `show
//! system`, and the `configure` banner, until an operator saves a
//! configuration that works.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::config::{Action, Appliance};

/// Where a boot that fell back says so. Boot-local (tmpfs), like RUNNING.
pub const STATUS: &str = "/run/sentinel/config-fallback.json";

/// How long the verifier waits for the agent before judging it.
const READY_DEADLINE: Duration = Duration::from_secs(90);
/// How often one fallback is tried before the next one is.
const RESTORE_ATTEMPTS: u32 = 3;
/// The pause between those tries.
const RESTORE_RETRY_DELAY: Duration = Duration::from_secs(5);
/// Restarts after which a never-ready agent is judged without waiting longer.
const RESTARTS_BEFORE_JUDGING: u32 = 3;

/// The last configuration this box booted with a ready data plane.
pub(crate) fn last_good_path(config: &Path) -> PathBuf {
    config.with_file_name("last-good.toml")
}

/// What the box fell back to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Applied {
    /// The last configuration this box booted healthily with.
    LastKnownGood,
    /// The saved configuration reduced to what management needs.
    ManagementOnly,
    /// Nothing the agent accepts could be built; the box runs what it has.
    Nothing,
}

/// The record behind every report of a fallback.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Status {
    /// `seed` (before the agent started) or `verify` (after it failed to).
    pub stage: String,
    pub applied: Applied,
    /// Why the saved configuration was not used, scrubbed of secrets.
    pub reason: String,
}

impl Status {
    /// The operator-facing sentence.
    pub(crate) fn describe(&self) -> String {
        let what = match self.applied {
            Applied::LastKnownGood => "running the last configuration this box booted with",
            Applied::ManagementOnly => {
                "running a MANAGEMENT-ONLY policy (no forwarding rules, NAT or block lists)"
            }
            Applied::Nothing => "and no fallback configuration was accepted either",
        };
        format!(
            "CONFIGURATION FALLBACK: the data plane refused the saved configuration at boot \
             ({}); {what}. Fix the configuration, `commit` it, then `save` to clear this.",
            self.reason
        )
    }
}

/// The current boot's fallback, if it had one.
pub(crate) fn read_status() -> Option<Status> {
    read_status_at(Path::new(STATUS))
}

fn read_status_at(path: &Path) -> Option<Status> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

/// A working configuration was saved: the next boot will not fall back.
pub fn clear_status() {
    let path = Path::new(STATUS);
    if path.exists()
        && std::fs::remove_file(path).is_err()
        && let Some(text) = path.to_str()
    {
        let _ = crate::system::sudo("rm", &["-f", "--", text]);
    }
}

/// One line of an error, with parser excerpts dropped and secrets scrubbed.
fn reason(error: &anyhow::Error, configurations: &[&Appliance]) -> String {
    let text = format!("{error:#}");
    crate::agent_contract::summary(&text, configurations)
}

/// Pick the configuration the seed stage renders. `accepts` is the agent's
/// verdict on a configuration as it would be rendered at boot.
pub(crate) fn select_seed(
    saved: Result<Appliance>,
    last_good: Option<Appliance>,
    accepts: impl Fn(&Appliance) -> Result<()>,
) -> Result<(Appliance, Option<Status>)> {
    let refusal = match &saved {
        Ok(appliance) => match accepts(appliance) {
            Ok(()) => return Ok((appliance.clone(), None)),
            Err(error) => error,
        },
        Err(error) => anyhow!("{error:#}"),
    };
    let secrets: Vec<&Appliance> = saved.iter().chain(last_good.iter()).collect();
    let why = reason(&refusal, &secrets);
    let status = |applied| Status {
        stage: "seed".into(),
        applied,
        reason: why.clone(),
    };
    let refused = saved.as_ref().ok().and_then(|a| a.to_toml().ok());
    for (candidate, applied) in fallbacks(saved.as_ref().ok(), last_good.as_ref(), refused) {
        if accepts(&candidate).is_ok() {
            return Ok((candidate, Some(status(applied))));
        }
    }
    match saved {
        // Boot what there is: the agent will refuse it, but the rest of the box
        // (sshd, the console) still comes up and says why.
        Ok(appliance) => Ok((appliance, Some(status(Applied::Nothing)))),
        Err(error) => Err(error),
    }
}

/// The fallbacks, best first: the last-known-good configuration unless it is
/// the very one being refused, then the management-only reduction of the
/// newest intent available.
fn fallbacks(
    current: Option<&Appliance>,
    last_good: Option<&Appliance>,
    refused: Option<String>,
) -> Vec<(Appliance, Applied)> {
    let mut out = Vec::new();
    if let Some(good) = last_good
        && good.to_toml().ok() != refused
    {
        out.push((good.clone(), Applied::LastKnownGood));
    }
    if let Some(base) = current.or(last_good) {
        match management_only(base) {
            Ok(reduced) => out.push((reduced, Applied::ManagementOnly)),
            Err(error) => eprintln!("warning: no management-only fallback: {error:#}"),
        }
    }
    out
}

/// The configuration reduced to what reaching the box needs.
///
/// Kept: the system section (accounts, SSH, the console), interfaces, zones
/// and their posture, routing and VPNs — everything that decides whether an
/// administrator can get in. Kept from the policy: every enabled `accept`
/// rule that can carry a packet to this box on a management port (or on every
/// port), without its rate limit. Dropped: every other rule, every rule that
/// names a group, NAT, load balancers, block lists, GeoIP and SYN protection —
/// the parts whose size or shape the agent has refused before.
pub(crate) fn management_only(appliance: &Appliance) -> Result<Appliance> {
    let mut reduced = appliance.clone();
    let ports = crate::lockout::management_ports(appliance);
    reduced.rules.retain(|rule| {
        let reaches_box = match &rule.to {
            None => true,
            Some(zone) => appliance.zones.get(zone).is_some_and(|zone| zone.local),
        };
        let names_group = rule.source_group.is_some()
            || rule.destination_group.is_some()
            || rule.port_group.is_some()
            || rule.source_mac_group.is_some()
            || rule.interface_group.is_some();
        let on_management = rule.port.is_empty()
            || rule.port.iter().any(|spec| {
                ports
                    .iter()
                    .any(|&port| crate::lockout::covers(*spec, port))
            });
        !rule.disabled
            && rule.action == Action::Accept
            && reaches_box
            && !names_group
            && on_management
    });
    for rule in &mut reduced.rules {
        rule.limit = None;
        rule.burst = None;
    }
    reduced.nat = Default::default();
    reduced.load_balancers.clear();
    reduced.firewall.blocklist.clear();
    reduced.firewall.geoip_block.clear();
    reduced.firewall.syn_protect.clear();
    for zone in reduced.zones.values_mut() {
        zone.blocklist.clear();
        zone.geoip_block.clear();
    }
    // Through the full validator: a reduction that is not a valid
    // configuration is no fallback.
    Appliance::from_toml(&reduced.to_toml()?).context("validating the management-only policy")
}

/// The last-known-good configuration, if there is a usable one. Read leniently
/// for the same reason the saved file is at boot: it may have been written by
/// a newer image before an A/B rollback.
pub(crate) fn read_last_good(config: &Path) -> Option<Appliance> {
    let path = last_good_path(config);
    if !path.exists() {
        return None;
    }
    match Appliance::load_lenient(&path) {
        Ok(appliance) => Some(appliance),
        Err(error) => {
            eprintln!(
                "warning: ignoring {}: {}",
                path.display(),
                reason(&error, &[])
            );
            None
        }
    }
}

/// Make the fallback the running configuration and say so everywhere an
/// operator looks. RUNNING is what every later reader starts from — the next
/// `configure`, the refresh timers, boot-late, the held-link guard — so none of
/// them recompiles the refused configuration over the fallback.
pub(crate) fn publish(appliance: Option<&Appliance>, status: &Status) -> Result<()> {
    if let Some(appliance) = appliance {
        crate::system::install_config_file(
            Path::new(crate::session::Session::RUNNING),
            &appliance.to_toml()?,
        )
        .context("recording the fallback as the running configuration")?;
    }
    crate::system::install_file(Path::new(STATUS), &serde_json::to_string(status)?)
        .context("recording the configuration fallback")?;
    let message = status.describe();
    eprintln!("{message}");
    crate::journal::note(crate::journal::Severity::Error, "sentinel-boot", &message);
    Ok(())
}

/// `sentinel boot-verify`: the second half, after the agent has had its chance.
pub(crate) fn verify(config: &Path, act: &crate::repl::Apply) -> Result<()> {
    if let Some(status) = read_status() {
        // The seed stage already fell back; repeat it on the console, which is
        // where somebody standing at a dark box looks first.
        eprintln!("{}", status.describe());
    }
    let ready = wait_for_dataplane(READY_DEADLINE);
    match (ready, read_status()) {
        (Ok(()), None) => record_last_good(config),
        (Ok(()), Some(_)) => Ok(()),
        (Err(error), Some(status)) if status.stage == "verify" => {
            Err(error.context("the data plane is not ready on the fallback configuration either"))
        }
        (Err(error), _) => fall_back_live(config, act, &error),
    }
}

/// Wait until the agent answers Ready, or it has restarted enough times, or the
/// deadline passes.
fn wait_for_dataplane(deadline: Duration) -> Result<()> {
    let until = Instant::now() + deadline;
    loop {
        let error = match crate::repl::dataplane_ready() {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };
        if Instant::now() >= until || restarts() >= RESTARTS_BEFORE_JUDGING {
            return Err(error.context("the data plane did not become ready"));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn restarts() -> u32 {
    std::process::Command::new(crate::system::bin("systemctl"))
        .args(["show", "--property=NRestarts", "--value", "velstra.service"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
}

/// The agent is ready on what the box booted: remember it.
fn record_last_good(config: &Path) -> Result<()> {
    let active = Appliance::load_active(config)
        .or_else(|_| Appliance::load_lenient(config))
        .context("reading the configuration the data plane accepted")?;
    crate::system::install_config_file(&last_good_path(config), &active.to_toml()?)
        .context("recording the last-known-good configuration")
}

/// The agent never became ready on the configuration it was given: apply the
/// fallbacks live, through the same restore path commit-confirm uses.
fn fall_back_live(config: &Path, act: &crate::repl::Apply, cause: &anyhow::Error) -> Result<()> {
    crate::safe_apply::ensure_writable(config)
        .context("a management transaction is pending; not falling back")?;
    let active = Appliance::load_active(config)
        .or_else(|_| Appliance::load_lenient(config))
        .ok();
    let last_good = read_last_good(config);
    let secrets: Vec<&Appliance> = active.iter().chain(last_good.iter()).collect();
    let why = reason(cause, &secrets);
    let refused = active.as_ref().and_then(|a| a.to_toml().ok());
    for (candidate, applied) in fallbacks(active.as_ref(), last_good.as_ref(), refused) {
        if let Err(error) = crate::agent_contract::check(&candidate) {
            eprintln!("fallback {applied:?} refused by the data plane: {error:#}");
            continue;
        }
        if restore_with_retries(&candidate, act, applied) {
            let status = Status {
                stage: "verify".into(),
                applied,
                reason: why,
            };
            return publish(Some(&candidate), &status);
        }
    }
    let status = Status {
        stage: "verify".into(),
        applied: Applied::Nothing,
        reason: why,
    };
    publish(None, &status)?;
    Err(anyhow!("{}", status.describe()))
}

/// Apply one fallback, retrying a few times. At this point of the boot the
/// held links are coming up and addresses are being assigned, and the agent
/// refuses a reload whose host inventory changed underneath it; the VM check
/// saw exactly that transient refuse a perfectly good last-known-good once.
fn restore_with_retries(candidate: &Appliance, act: &crate::repl::Apply, applied: Applied) -> bool {
    for attempt in 1..=RESTORE_ATTEMPTS {
        match crate::repl::restore_live(candidate, act) {
            Ok(()) => return true,
            Err(error) => eprintln!(
                "fallback {applied:?} attempt {attempt} of {RESTORE_ATTEMPTS} could not be applied: {error:#}"
            ),
        }
        if attempt < RESTORE_ATTEMPTS {
            std::thread::sleep(RESTORE_RETRY_DELAY);
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAVED: &str = r#"
[system]
hostname = "fw"
[services.ssh]
enable = true
[zone.lan]
[zone.wan]
[zone.firewall]
local = true
[[interface]]
name = "lan0"
zone = "lan"
address = "192.0.2.1/24"
[[interface]]
name = "wan0"
zone = "wan"
address = "198.51.100.1/24"
[[rule]]
name = "ssh-from-lan"
from = "lan"
to = "firewall"
proto = "tcp"
port = 22
action = "accept"
limit = 10
[[rule]]
name = "web-out"
from = "lan"
to = "wan"
proto = "tcp"
port = 443
action = "accept"
[[rule]]
name = "drop-telnet"
from = "wan"
proto = "tcp"
port = 23
action = "drop"
[[nat.destination]]
name = "pf"
zone = "wan"
proto = "tcp"
port = 8080
to = "192.0.2.10:80"
"#;

    fn saved() -> Appliance {
        Appliance::from_toml(SAVED).unwrap()
    }

    fn good() -> Appliance {
        Appliance::from_toml("[system]\nhostname = \"last-good\"\n").unwrap()
    }

    #[test]
    fn an_accepted_saved_configuration_boots_as_it_is() {
        let (chosen, status) = select_seed(Ok(saved()), Some(good()), |_| Ok(())).unwrap();
        assert_eq!(chosen.system.hostname, "fw");
        assert!(status.is_none());
    }

    #[test]
    fn a_refused_saved_configuration_boots_the_last_known_good_and_says_why() {
        let (chosen, status) = select_seed(Ok(saved()), Some(good()), |candidate| {
            if candidate.nat.destination.is_empty() {
                Ok(())
            } else {
                anyhow::bail!(
                    "the data plane refuses this configuration: unknown field `local_destination`"
                )
            }
        })
        .unwrap();
        assert_eq!(chosen.system.hostname, "last-good");
        let status = status.unwrap();
        assert_eq!(status.applied, Applied::LastKnownGood);
        assert!(status.reason.contains("local_destination"), "{status:?}");
        assert!(status.describe().contains("CONFIGURATION FALLBACK"));
    }

    #[test]
    fn without_a_distinct_last_good_the_management_only_policy_keeps_the_way_in() {
        // The refused configuration is also the last-known-good (a feed grew,
        // a map filled): falling back to it would change nothing.
        let refused = saved();
        let (chosen, status) = select_seed(Ok(refused.clone()), Some(refused), |candidate| {
            if candidate.nat.destination.is_empty() && candidate.rules.len() < 3 {
                Ok(())
            } else {
                anyhow::bail!("refused")
            }
        })
        .unwrap();
        assert_eq!(status.unwrap().applied, Applied::ManagementOnly);
        let names: Vec<_> = chosen.rules.iter().map(|rule| rule.name.as_str()).collect();
        assert_eq!(
            names,
            ["ssh-from-lan"],
            "only the management accept survives"
        );
        assert_eq!(chosen.rules[0].limit, None);
        assert!(chosen.nat.destination.is_empty());
        assert_eq!(chosen.interfaces.len(), 2);
        assert!(chosen.services.ssh.enable);
    }

    #[test]
    fn an_unloadable_saved_configuration_still_boots_the_last_known_good() {
        let (chosen, status) = select_seed(
            Err(anyhow!(
                "TOML parse error at line 2\n2 | secret = \"x\"\n  | ^"
            )),
            Some(good()),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(chosen.system.hostname, "last-good");
        let status = status.unwrap();
        assert!(!status.reason.contains("secret ="), "{status:?}");
    }

    #[test]
    fn with_nothing_acceptable_the_box_boots_what_it_has_and_reports_it() {
        let (chosen, status) =
            select_seed(Ok(saved()), None, |_| anyhow::bail!("refused")).unwrap();
        assert_eq!(chosen.system.hostname, "fw");
        assert_eq!(status.unwrap().applied, Applied::Nothing);
        assert!(select_seed(Err(anyhow!("unreadable")), None, |_| Ok(())).is_err());
    }

    #[test]
    fn the_status_round_trips_through_its_file() {
        let dir = std::env::temp_dir().join(format!("sentinel-fallback-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("status.json");
        let status = Status {
            stage: "seed".into(),
            applied: Applied::ManagementOnly,
            reason: "refused".into(),
        };
        std::fs::write(&path, serde_json::to_string(&status).unwrap()).unwrap();
        assert_eq!(read_status_at(&path), Some(status));
        assert_eq!(read_status_at(&dir.join("missing.json")), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
