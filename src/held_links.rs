//! Zoned links held dark because the data plane has not hooked them.
//!
//! A zoned link comes up only once the agent has attached its packet hooks and
//! put the policy in force (see [`crate::net::held_until_attached`]). That is
//! the fail-closed half, and it has a cost: an agent that cannot start — a
//! datapath the kernel's verifier refuses, an object that does not match the
//! agent, a crash loop — or a NIC that cannot take XDP leaves those segments
//! dark, the console's LAN among them. Dark is the right state for a link
//! nobody can filter; a dark link nobody is told about is how an operator
//! spends an hour on the cabling. So this module makes the state loud: `show
//! interfaces` and the console name it, and a worker alerts when it outlasts a
//! normal start.
//!
//! Everything here reads the configuration and `/sys`, never the agent: the
//! case that matters most is the agent not answering at all.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{Duration, Instant},
};

use anyhow::Result;

use crate::config::Appliance;

/// What a held, dark link is called wherever it is shown.
pub const HELD_STATE: &str = "held: waiting for datapath";

/// How long a held link may stay dark before somebody is told. Long enough to
/// cover the agent's own start (load, verify, attach) after a boot or a
/// restart, short enough that the gap is not discovered by a user.
pub const HELD_ALERT_AFTER: Duration = Duration::from_secs(30);
const WATCH_INTERVAL: Duration = Duration::from_secs(2);

/// Whether `name` exists and is administratively down. Absent is not dark (it
/// is not there), and flags that cannot be read are not claimed down either.
pub fn link_down(name: &str) -> bool {
    std::fs::read_to_string(format!("/sys/class/net/{name}/flags"))
        .ok()
        .and_then(|flags| u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).ok())
        .is_some_and(|flags| flags & libc::IFF_UP as u32 == 0)
}

/// The links `appliance` holds for the data plane to raise.
pub fn held(appliance: &Appliance) -> BTreeSet<String> {
    appliance
        .interfaces
        .iter()
        .filter(|i| crate::net::held_until_attached(i))
        .map(|i| i.name.clone())
        .collect()
}

/// The held links that are down right now, by `down`.
pub fn dark(appliance: &Appliance, down: impl Fn(&str) -> bool) -> Vec<String> {
    held(appliance).into_iter().filter(|n| down(n)).collect()
}

/// The configuration the box is running: the last commit's snapshot, else the
/// saved document a boot applied. `None` when neither can be read, which a
/// caller showing state treats as "nothing to add", never as an error.
pub fn running_appliance() -> Option<Appliance> {
    crate::session::Session::running_snapshot()
        .and_then(|text| Appliance::from_toml(&text).ok())
        .or_else(|| Appliance::load(Path::new(crate::session::DEFAULT_CONFIG)).ok())
}

/// The lines `show interfaces` adds under the kernel's own listing: one per
/// held link that is dark, saying why and where to look. Empty when none is.
pub fn show_lines(dark: &[String]) -> String {
    dark.iter()
        .map(|name| {
            format!(
                "{name}: {HELD_STATE} (a zoned link stays down until the firewall has \
                 hooked it; see `show status`)\n"
            )
        })
        .collect()
}

/// Turns a stream of dark-link observations into at most one alert per link
/// and episode once it outlasts [`HELD_ALERT_AFTER`], and one when they are
/// all up again.
#[derive(Default)]
pub struct DarkLinkWatch {
    since: BTreeMap<String, Instant>,
    alerted: BTreeSet<String>,
}
impl DarkLinkWatch {
    /// `agent_running` only shapes the message: with the data plane down the
    /// cause is the agent, not the link, and the alert says where to look.
    pub fn observe(
        &mut self,
        dark: &[String],
        agent_running: bool,
        now: Instant,
    ) -> Option<crate::alert::Alert> {
        self.since.retain(|name, _| dark.contains(name));
        let cleared: Vec<String> = self
            .alerted
            .iter()
            .filter(|name| !dark.contains(name))
            .cloned()
            .collect();
        self.alerted.retain(|name| dark.contains(name));
        for name in dark {
            self.since.entry(name.clone()).or_insert(now);
        }
        let due: Vec<&String> = self
            .since
            .iter()
            .filter(|(name, since)| {
                !self.alerted.contains(*name)
                    && now.saturating_duration_since(**since) >= HELD_ALERT_AFTER
            })
            .map(|(name, _)| name)
            .collect();
        if due.is_empty() {
            return (!cleared.is_empty() && self.alerted.is_empty()).then(|| crate::alert::Alert {
                subject: "held links up again".into(),
                detail: "every zoned link this watch reported dark has been hooked by \
                             the data plane and is up again"
                    .into(),
            });
        }
        let names: Vec<String> = due.into_iter().cloned().collect();
        let cause = if agent_running {
            "the data plane is running but could not hook them (see `show interfaces` \
             and the velstra journal)"
        } else {
            "the data plane (velstra.service) is not running"
        };
        let detail = format!(
            "{} {} been down for over {} s: {cause}. They stay down rather than forward \
             unfiltered; anything reached through them, the web console included, is \
             unreachable until they come up.",
            names.join(", "),
            if names.len() == 1 { "has" } else { "have" },
            HELD_ALERT_AFTER.as_secs()
        );
        self.alerted.extend(names);
        Some(crate::alert::Alert {
            subject: "zoned links held down".into(),
            detail,
        })
    }
}

/// `sentinel link-watch`, run by systemd: the alert path for zoned links the
/// data plane has not raised. A dead agent fails its unit and alerts through
/// `OnFailure=`; a running agent that cannot hook one NIC fails nothing, and a
/// crash-looping one is easy to miss among its own restarts.
pub fn watch(config: &Path) -> Result<()> {
    let mut watch = DarkLinkWatch::default();
    loop {
        if let Some(appliance) = running_appliance() {
            let dark = dark(&appliance, link_down);
            let running = crate::system::unit_active("velstra.service");
            if let Some(alert) = watch.observe(&dark, running, Instant::now()) {
                eprintln!("{}: {}", alert.subject, alert.detail);
                match Appliance::load(config) {
                    Ok(a) => {
                        crate::alert::deliver(&a.services.alerts, &alert);
                    }
                    Err(error) => eprintln!("link watch: cannot read alert targets: {error:#}"),
                }
            }
        }
        std::thread::sleep(WATCH_INTERVAL);
    }
}

/// The held links an agent that stopped leaves open: those that are up.
///
/// An XDP program lives only as long as the process that attached it, so when
/// `velstra` exits — a crash, an OOM kill, a restart a commit asked for — every
/// zoned link it had raised keeps forwarding with nothing on it. The hold only
/// ever covered a link that was *created* while the agent was away; this is the
/// other half: a link the agent leaves behind is put back into the hold, and
/// the agent raises it again once its hooks are in place, exactly as at boot.
///
/// A link the HA guard fences is left alone. Its pinned TC guard outlives the
/// agent and drops every frame the moment the exit tracepoint clears the
/// owner, so it is already closed — and taking it down as well is not free:
/// `ip link set down` flushes its addresses, the shared VIPs and the neighbour
/// table, so a member that recovers and preempts comes back with established
/// flows stalled until all of that is relearned. A zoned link outside the HA
/// guard (on an HA box or not) has no other fence and is still held.
pub fn to_hold_down(appliance: &Appliance, up: impl Fn(&str) -> bool) -> Vec<String> {
    let fenced = crate::ha::guarded_interfaces(appliance);
    held(appliance)
        .into_iter()
        .filter(|n| !fenced.contains(n) && up(n))
        .collect()
}

/// Whether `name` exists and is administratively up.
fn link_up(name: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{name}")).exists() && !link_down(name)
}

/// `sentinel hold-links-down`, run as the agent unit's `ExecStopPost=`: put
/// every zoned link back into the hold. Each link is tried even if one fails,
/// and a failure fails the command, so the unit's `OnFailure=` alert names it.
pub fn hold_down(config: &Path) -> Result<()> {
    let appliance = running_appliance()
        .map(Ok)
        .unwrap_or_else(|| Appliance::load(config))?;
    let mut failed = Vec::new();
    for link in to_hold_down(&appliance, link_up) {
        match crate::system::ip_link(&["set", "dev", &link, "down"]) {
            Ok(()) => eprintln!("hold-links-down: {link} held until the data plane hooks it again"),
            Err(error) => {
                eprintln!("hold-links-down: {link}: {error:#}");
                failed.push(link);
            }
        }
    }
    anyhow::ensure!(
        failed.is_empty(),
        "zoned links left up without a data plane: {}",
        failed.join(", ")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn only_enabled_zoned_links_networkd_raises_are_held() {
        let appliance = Appliance::from_toml(
            r#"
[system]
hostname = "fw"
[zone.lan]
[[interface]]
name = "lan0"
zone = "lan"
[[interface]]
name = "mgmt0"
[[interface]]
name = "off0"
zone = "lan"
disabled = true
"#,
        )
        .unwrap();
        assert_eq!(held(&appliance), BTreeSet::from(["lan0".to_string()]));
        assert_eq!(dark(&appliance, |_| true), names(&["lan0"]));
        assert!(dark(&appliance, |_| false).is_empty());
    }

    #[test]
    fn show_interfaces_names_each_dark_link_and_why() {
        assert_eq!(show_lines(&[]), "");
        let text = show_lines(&names(&["lan0", "dmz0"]));
        assert_eq!(text.lines().count(), 2);
        assert!(
            text.starts_with("lan0: held: waiting for datapath"),
            "{text}"
        );
    }

    #[test]
    fn a_dark_link_alerts_once_after_the_threshold_and_once_when_up() {
        let mut watch = DarkLinkWatch::default();
        let start = Instant::now();
        let lan = names(&["lan0"]);
        assert!(watch.observe(&lan, false, start).is_none());
        assert!(
            watch
                .observe(
                    &lan,
                    false,
                    start + HELD_ALERT_AFTER - Duration::from_millis(1)
                )
                .is_none(),
            "an ordinary agent start must stay quiet"
        );
        let alert = watch
            .observe(&lan, false, start + HELD_ALERT_AFTER)
            .expect("past the threshold");
        assert_eq!(alert.subject, "zoned links held down");
        assert!(alert.detail.contains("lan0"), "{}", alert.detail);
        assert!(
            alert.detail.contains("velstra.service) is not running"),
            "{}",
            alert.detail
        );
        assert!(
            watch
                .observe(&lan, false, start + 10 * HELD_ALERT_AFTER)
                .is_none(),
            "one alert per episode"
        );
        // A second link going dark later is its own news.
        let both = names(&["lan0", "dmz0"]);
        let later = start + 11 * HELD_ALERT_AFTER;
        assert!(watch.observe(&both, true, later).is_none());
        let second = watch
            .observe(&both, true, later + HELD_ALERT_AFTER)
            .expect("dmz0 past its own threshold");
        assert!(second.detail.starts_with("dmz0 has"), "{}", second.detail);
        assert!(second.detail.contains("could not hook them"));
        // Recovery is reported once everything alerted on is up again.
        assert!(
            watch
                .observe(&names(&["dmz0"]), true, later + 2 * HELD_ALERT_AFTER)
                .is_none()
        );
        let up = watch
            .observe(&[], true, later + 3 * HELD_ALERT_AFTER)
            .expect("all up again");
        assert_eq!(up.subject, "held links up again");
        assert!(
            watch
                .observe(&[], true, later + 4 * HELD_ALERT_AFTER)
                .is_none()
        );
    }

    #[test]
    fn a_brief_dark_spell_stays_quiet_in_both_directions() {
        let mut watch = DarkLinkWatch::default();
        let start = Instant::now();
        assert!(watch.observe(&names(&["lan0"]), true, start).is_none());
        assert!(
            watch
                .observe(&[], true, start + Duration::from_secs(3))
                .is_none()
        );
    }

    #[test]
    fn a_stopped_agent_leaves_only_its_raised_zoned_links_to_hold() {
        let appliance = Appliance::from_toml(
            r#"
[system]
hostname = "fw"
[zone.lan]
[zone.wan]
[[interface]]
name = "eth1"
zone = "lan"
[[interface]]
name = "eth0"
zone = "wan"
[[interface]]
name = "eth2"
"#,
        )
        .unwrap();
        // eth0 is already down; eth2 is unzoned and never held.
        let up = |n: &str| n != "eth0";
        assert_eq!(to_hold_down(&appliance, up), vec!["eth1".to_string()]);
    }

    #[test]
    fn an_ha_member_leaves_guard_fenced_links_up_and_holds_the_rest() {
        let mut appliance = Appliance::from_toml(
            r#"
[system]
hostname = "fw"
[zone.lan]
[zone.sync]
[[interface]]
name = "lan0"
zone = "lan"
[[interface]]
name = "sync0"
zone = "sync"
"#,
        )
        .unwrap();
        // Pairing material is beside the point here; only the mapping from
        // `system.ha` to the guarded links matters.
        appliance.system.ha = Some(crate::config::Ha {
            enabled: true,
            witness: "192.0.2.10:5440".into(),
            sync_interface: "sync0".into(),
            ..Default::default()
        });
        assert!(crate::ha::guarded_interfaces(&appliance).contains("lan0"));
        assert!(!crate::ha::guarded_interfaces(&appliance).contains("sync0"));
        // lan0 is fenced by the pinned HA guard, which outlives the agent;
        // downing it would flush its addresses, VIPs and neighbours and stall
        // established flows after recovery. sync0 is zoned but outside the
        // guard, so nothing else closes it: it is still held.
        assert_eq!(
            to_hold_down(&appliance, |_| true),
            vec!["sync0".to_string()]
        );
    }
}
