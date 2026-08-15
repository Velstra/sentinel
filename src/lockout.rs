//! The warning a `commit` prints when it has just changed the way somebody
//! reaches this box, and that change has not been saved.
//!
//! `commit` applies to the running system; `save` writes the boot config. For
//! most settings the gap between the two is merely surprising — a reboot puts
//! back a DNS forwarder nobody noticed was gone. For the settings that govern
//! **management access** the gap is how an operator loses a remote box: install
//! a new SSH key, commit, do not save, reboot, and the appliance comes back
//! authenticating the key you replaced. The same holds for a login's password,
//! for the SSH daemon's port or listen address, and for any firewall decision on
//! the path to the socket you are typing into.
//!
//! So `commit` says so — a warning, never a refusal. Locking yourself out on
//! purpose is a legitimate thing to do on a lab box or in a scripted provision,
//! and an appliance that argues with its operator gets worked around.
//!
//! # Which paths count
//!
//! Not a list of path strings: a list is a thing somebody has to remember to
//! extend, and the setting that locks you out will be the one added after the
//! list was written. Instead the question is asked of the configuration model
//! twice — render the committed config, render a copy with the management-
//! governing parts *removed*, and the paths that disappeared are the management
//! paths. Anything added under those parts of the model later is covered on the
//! day it is added, because it is the renderer, not this file, that decides
//! which paths exist.
//!
//! What gets removed from the copy is three answers to one question — "could
//! this change stop me getting back in?":
//!
//! 1. **Who may authenticate**: the accounts (`system login`), the permission
//!    groups they point at, and the non-local authentication that stands in for
//!    them (`system aaa`).
//! 2. **Where the box answers**: the two services it runs for its own
//!    administration (`services ssh`, `services web`) and the serial console,
//!    which is the way back when the network is the thing that broke.
//! 3. **Whether a packet gets there**: global firewall posture and per-zone
//!    posture, which apply to every packet and therefore to management packets
//!    too; and the individual rules, port-forwards and load-balanced services
//!    that bear on a **management port**. That last one is decided by value
//!    rather than by name — a rule matching the port SSH listens on counts, a
//!    rule matching a web server's 443 does not — so a match keyword invented
//!    next year needs no change here either.
//!
//! The management ports are themselves read from the configuration — the ports
//! the SSH daemon and the web console are set to listen on, defaults applied —
//! plus, when this session arrived over the network, the port it actually came in
//! on: the most authoritative answer available to "which port must keep working".

use std::collections::BTreeSet;

use crate::config::{Appliance, Firewall, ZoneCfg};
use crate::session::{flatten_pairs, render_appliance};

/// How many paths the warning names before it stops listing them. Past a handful
/// the list is no longer telling an operator what happened, and the sentence that
/// matters — what the next boot will do — gets pushed off the screen.
const MAX_LISTED: usize = 6;

/// A commit that changed management access while the saved config still says
/// otherwise.
pub struct UnsavedAccess {
    /// Management paths this commit changed.
    changed: Vec<String>,
    /// Management paths an *earlier* commit had changed without saving and this
    /// one has just put back. Disjoint from `changed` by construction: a path
    /// this commit changed itself is reported once, as this commit's.
    replaced: Vec<String>,
}

/// Compare what was committed against what is on disk, and against what an
/// earlier commit left running, restricted to the paths that govern management
/// access.
///
/// `saved` is the config file `save` writes and the next boot reads — `None`
/// when the box has none yet, in which case everything management-related in the
/// commit is unsaved. `running_before` is what the *previous* commit applied, so
/// it must be read before this commit records its own snapshot.
///
/// `None` when there is nothing to say, which is the common case: either the
/// commit changed nothing about management access, or it matches what is saved
/// because the operator saved first.
pub fn unsaved_access(
    saved: Option<&Appliance>,
    running_before: Option<&Appliance>,
    committed: &Appliance,
) -> Option<UnsavedAccess> {
    let configs: Vec<&Appliance> = [saved, running_before, Some(committed)]
        .into_iter()
        .flatten()
        .collect();
    let scope = Scope::over(&configs);

    let changed = changed_paths(saved, Some(committed), &scope);
    // Where the running system already disagreed with the saved file before this
    // commit. With no running snapshot nothing has been committed since the box
    // booted, so the saved config *is* what is running and there is no drift.
    //
    // A path this commit changed itself needs no second mention — the sentence
    // above already covers where that setting now stands. What is left is drift
    // this commit did not repeat, and since a commit applies the whole candidate
    // and the candidate was loaded from the saved file, those settings have just
    // been put back to their saved values: the earlier change is gone from the
    // running system, which is worth hearing from whoever made it.
    let replaced: Vec<String> = match running_before {
        None => Vec::new(),
        Some(running) => changed_paths(saved, Some(running), &scope)
            .into_iter()
            .filter(|p| !changed.contains(p))
            .collect(),
    };
    if changed.is_empty() && replaced.is_empty() {
        return None;
    }
    Some(UnsavedAccess { changed, replaced })
}

impl UnsavedAccess {
    /// The warning, worded for somebody who may be typing over the very link it
    /// is about. It names the settings, says what the next boot does instead,
    /// and says which command changes that.
    pub fn message(&self) -> String {
        let mut out = String::new();
        if self.changed.is_empty() {
            // Nothing new is unsaved, but an unsaved change that *was* running
            // has just gone — and it may be the one the operator is using.
            out.push_str(&format!(
                "this commit undid an unsaved change to management access: {}.\n  \
                 An earlier commit applied {} and never saved {}, and this commit \
                 started\n  from the saved configuration — so the running system \
                 has the previous\n  {} again.\n",
                list(&self.replaced),
                plural(self.replaced.len(), "it", "them"),
                plural(self.replaced.len(), "it", "them"),
                plural(self.replaced.len(), "value", "values"),
            ));
            return out;
        }
        out.push_str(&format!(
            "this commit changed management access and has not been saved.\n  \
             changed: {}\n  \
             The next boot loads the saved configuration instead, where {} still {}\n  \
             the previous {} — if that is how you reach this box, the way in goes back\n  \
             with {}. `save` writes this configuration to disk, so what you just \
             committed\n  is what boots.\n",
            list(&self.changed),
            plural(self.changed.len(), "that setting", "those settings"),
            plural(self.changed.len(), "has", "have"),
            plural(self.changed.len(), "value", "values"),
            plural(self.changed.len(), "it", "them"),
        ));
        if !self.replaced.is_empty() {
            out.push_str(&format!(
                "  It also undid an unsaved change an earlier commit had applied ({}),\n  \
                 which is running the saved {} again.\n",
                list(&self.replaced),
                plural(self.replaced.len(), "value", "values"),
            ));
        }
        out
    }
}

/// Join paths for the message, cutting the list off before it buries the point.
fn list(paths: &[String]) -> String {
    let shown = paths
        .iter()
        .take(MAX_LISTED)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    match paths.len().checked_sub(MAX_LISTED) {
        Some(n) if n > 0 => format!("{shown} and {n} more"),
        _ => shown,
    }
}

fn plural<'a>(n: usize, one: &'a str, many: &'a str) -> &'a str {
    if n == 1 { one } else { many }
}

/// The management paths that differ between two configurations. A missing
/// configuration contributes nothing, so "no saved config at all" reads as
/// "everything in the commit is unsaved", which is exactly what it means.
fn changed_paths(
    before: Option<&Appliance>,
    after: Option<&Appliance>,
    scope: &Scope,
) -> Vec<String> {
    let a = before
        .map(|a| management_lines(a, scope))
        .unwrap_or_default();
    let b = after
        .map(|a| management_lines(a, scope))
        .unwrap_or_default();
    // A changed value shows up on both sides of the symmetric difference; the
    // set collapses it back to the one path an operator would type.
    a.symmetric_difference(&b)
        .map(|(path, _)| path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Every `(path, value)` this configuration renders that governs management
/// access — found by rendering it twice, with and without the parts of the model
/// that govern access, and keeping what only the full rendering produces.
fn management_lines(a: &Appliance, scope: &Scope) -> BTreeSet<(String, String)> {
    let full = pairs(a);
    let rest = pairs(&without_management(a, scope));
    full.difference(&rest).cloned().collect()
}

fn pairs(a: &Appliance) -> BTreeSet<(String, String)> {
    flatten_pairs(&render_appliance(a)).into_iter().collect()
}

/// Which ports management arrives on, and which named objects bear on them.
///
/// Held apart from any one configuration and computed over **all** the
/// configurations being compared, because relevance must not change halfway
/// through a diff: a rule that matched tcp/22 before the commit and tcp/2222
/// after it is one rule whose port was edited — the very edit that locks an
/// operator out — and judging each side separately would report every line of
/// that rule as changed instead of the one that was.
struct Scope {
    /// The ports management arrives on.
    ports: BTreeSet<u16>,
    /// Firewall rules that could decide the fate of a management packet.
    rules: BTreeSet<String>,
    /// Port-forwards that take a management port away from the box and hand it
    /// to a host behind it.
    forwards: BTreeSet<String>,
    /// Load-balanced services, which do the same thing to a pool of hosts.
    services: BTreeSet<String>,
}

impl Scope {
    fn over(configs: &[&Appliance]) -> Self {
        let mut ports: BTreeSet<u16> = configs.iter().flat_map(|a| management_ports(a)).collect();
        ports.extend(session_port());
        let mut scope = Scope {
            ports,
            rules: BTreeSet::new(),
            forwards: BTreeSet::new(),
            services: BTreeSet::new(),
        };
        for a in configs {
            for r in &a.rules {
                if scope.bears_on_management(a, r) {
                    scope.rules.insert(r.name.clone());
                }
            }
            for d in &a.nat.destination {
                if scope.ports.contains(&d.port) {
                    scope.forwards.insert(d.name.clone());
                }
            }
            for l in &a.load_balancers {
                if scope.ports.contains(&l.port) {
                    scope.services.insert(l.name.clone());
                }
            }
        }
        scope
    }

    /// Whether this rule could decide whether a management packet arrives.
    fn bears_on_management(&self, a: &Appliance, r: &crate::config::Rule) -> bool {
        // A rule aimed at another zone cannot govern traffic that terminates
        // here; one with no destination zone governs everything, this box
        // included.
        let could_reach_the_box = match &r.to {
            None => true,
            Some(z) => a.zones.get(z).map(|z| z.local).unwrap_or(false),
        };
        // No port match at all means every port, management included. A rule
        // pointing at a port group counts too: the group's membership lives
        // elsewhere in the config and may well name the management port.
        let unscoped = r.port.is_empty() && r.port_group.is_none();
        let matches_port = r.port_group.is_some()
            || r.port
                .iter()
                .any(|p| self.ports.iter().any(|&n| covers(*p, n)));
        could_reach_the_box && (unscoped || matches_port)
    }
}

/// A copy of the configuration with everything that governs management access
/// taken out of it. Never applied to anything — it exists only to be rendered,
/// so the difference against the real rendering names the management paths.
fn without_management(a: &Appliance, scope: &Scope) -> Appliance {
    let mut s = a.clone();
    // Who may authenticate.
    s.system.logins.clear();
    s.system.groups.clear();
    s.system.aaa = Default::default();
    s.system.console = Default::default();
    // Where the box answers for its own administration.
    s.services.ssh = Default::default();
    s.services.web = Default::default();
    // Global posture applies to every packet, so it applies to the management
    // packet. The named groups stay: a group is a definition, and it bites only
    // through the rule that references it — which is judged on its own below.
    let groups = std::mem::take(&mut s.firewall.group);
    s.firewall = Firewall {
        group: groups,
        ..Firewall::default()
    };
    // Zone posture is the same argument one scope down. The description is the
    // one leaf that admits nothing, so it survives and a documentation edit does
    // not raise a lockout warning.
    for z in s.zones.values_mut() {
        *z = ZoneCfg {
            description: z.description.take(),
            ..ZoneCfg::default()
        };
    }
    // Everything the scope decided bears on a management port. By name, so the
    // same objects are taken out of every configuration in one comparison.
    s.rules.retain(|r| !scope.rules.contains(&r.name));
    s.nat
        .destination
        .retain(|d| !scope.forwards.contains(&d.name));
    s.load_balancers
        .retain(|l| !scope.services.contains(&l.name));
    s
}

/// The ports management arrives on: what the administration services are
/// configured to listen on, defaults applied.
fn management_ports(a: &Appliance) -> BTreeSet<u16> {
    let mut ports = BTreeSet::new();
    if a.services.ssh.enable {
        ports.insert(a.services.ssh.port.unwrap_or(22));
    }
    if a.services.web.enable {
        ports.insert(a.services.web.port.unwrap_or(8080));
    }
    ports
}

/// The port this session is being administered over, when it came in over the
/// network. sshd states it in the environment as
/// `<client ip> <client port> <server ip> <server port>`; the last field is the
/// port that must keep answering for the operator to get back in, whatever the
/// configuration says about which service owns it.
fn session_port() -> Option<u16> {
    std::env::var("SSH_CONNECTION")
        .ok()?
        .split_whitespace()
        .nth(3)?
        .parse()
        .ok()
}

/// Whether a rule's port match covers `port`.
fn covers(spec: crate::config::PortSpec, port: u16) -> bool {
    let (lo, hi) = spec.bounds();
    (lo..=hi).contains(&port)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A box managed over SSH, with one account and a rule that lets the
    /// management network in. `edit` is applied as plain text so each test can
    /// state its change the way a config file would.
    const BASE: &str = r#"
[system]
hostname = "fw"
[[system.login]]
username = "admin"
ssh-key = ["ssh-ed25519 AAAAOLD admin@laptop"]
[[interface]]
name = "eth0"
zone = "lan"
address = "10.0.0.1/24"
[[interface]]
name = "eth1"
zone = "wan"
[zone.firewall]
local = true
[zone.wan]
default_action = "drop"
[[rule]]
name = "ssh-in"
from = "lan"
to = "firewall"
action = "accept"
proto = "tcp"
port = 22
[[rule]]
name = "web-in"
from = "wan"
to = "firewall"
action = "accept"
proto = "tcp"
port = 443
"#;

    fn cfg(toml: &str) -> Appliance {
        Appliance::from_toml(toml).expect("test config parses")
    }

    /// The base config with one substring replaced — the shortest way to write
    /// "the same box, except for this".
    fn edited(from: &str, to: &str) -> Appliance {
        assert!(
            BASE.contains(from),
            "the test's own anchor {from:?} is gone"
        );
        cfg(&BASE.replace(from, to))
    }

    fn warn(before: &Appliance, after: &Appliance) -> Option<String> {
        unsaved_access(Some(before), None, after).map(|u| u.message())
    }

    #[test]
    fn replacing_the_key_you_log_in_with_warns() {
        let saved = cfg(BASE);
        let committed = edited("AAAAOLD", "AAAANEW");
        let msg = warn(&saved, &committed).expect("a replaced SSH key must warn");
        assert!(msg.contains("system login admin ssh-key"), "{msg}");
        assert!(msg.contains("next boot"), "{msg}");
        assert!(msg.contains("`save`"), "{msg}");
    }

    #[test]
    fn a_saved_configuration_says_nothing() {
        let saved = cfg(BASE);
        assert!(warn(&saved, &saved).is_none());
    }

    #[test]
    fn a_change_that_cannot_lock_anybody_out_says_nothing() {
        let saved = cfg(BASE);
        let committed = edited(
            r#"address = "10.0.0.1/24""#,
            "address = \"10.0.0.1/24\"\ndescription = \"the office\"",
        );
        assert!(
            warn(&saved, &committed).is_none(),
            "an interface description is not management access"
        );
    }

    /// The point of deriving the paths instead of listing them: nothing in this
    /// file names `password-authentication`, and it is covered because it lives
    /// under the SSH service.
    #[test]
    fn a_setting_this_file_never_names_is_still_covered() {
        let saved = cfg(BASE);
        let committed = cfg(&format!(
            "{BASE}\n[services.ssh]\npassword-authentication = true\n"
        ));
        let msg = committed_warning(&saved, &committed);
        assert!(
            msg.contains("services ssh password-authentication"),
            "{msg}"
        );
    }

    fn committed_warning(before: &Appliance, after: &Appliance) -> String {
        warn(before, after).expect("this change must warn")
    }

    #[test]
    fn a_rule_on_the_management_port_warns_and_one_on_another_port_does_not() {
        let saved = cfg(BASE);

        let closed = edited(
            "name = \"ssh-in\"\nfrom = \"lan\"\nto = \"firewall\"\naction = \"accept\"",
            "name = \"ssh-in\"\nfrom = \"lan\"\nto = \"firewall\"\naction = \"drop\"",
        );
        let msg = committed_warning(&saved, &closed);
        assert!(msg.contains("firewall rule ssh-in action"), "{msg}");

        let web = edited(
            "name = \"web-in\"\nfrom = \"wan\"\nto = \"firewall\"\naction = \"accept\"",
            "name = \"web-in\"\nfrom = \"wan\"\nto = \"firewall\"\naction = \"drop\"",
        );
        assert!(
            warn(&saved, &web).is_none(),
            "a rule on tcp/443 is not the way in"
        );
    }

    /// Moving the management rule off the management port is *the* way to shut
    /// yourself out with one word. It must read as the one leaf that changed —
    /// not as a rule that vanished, which is what judging each side of the diff
    /// on its own port value would produce.
    #[test]
    fn moving_a_rule_off_the_management_port_names_the_port() {
        let saved = cfg(BASE);
        let committed = edited("port = 22", "port = 2222");
        let u = unsaved_access(Some(&saved), None, &committed).expect("this locks you out");
        assert_eq!(u.changed, vec!["firewall rule ssh-in port".to_string()]);
    }

    /// Relevance is decided by which ports a match covers, not by how it is
    /// written — a range that happens to swallow the console's port is as much a
    /// management rule as one that names it.
    #[test]
    fn a_port_range_that_swallows_the_console_counts() {
        let base = format!("{BASE}\n[services.web]\nenable = true\n");
        let rule = |action: &str| {
            cfg(&format!(
                "{base}\n[[rule]]\nname = \"range\"\nfrom = \"wan\"\nto = \"firewall\"\n\
                 action = \"{action}\"\nproto = \"tcp\"\nport = \"8000-8100\"\n"
            ))
        };
        let msg = committed_warning(&rule("accept"), &rule("drop"));
        assert!(msg.contains("firewall rule range action"), "{msg}");
    }

    #[test]
    fn a_zone_default_action_warns() {
        let saved = cfg(BASE);
        let committed = edited(
            "[zone.wan]\ndefault_action = \"drop\"",
            "[zone.wan]\ndefault_action = \"accept\"",
        );
        let msg = committed_warning(&saved, &committed);
        assert!(msg.contains("firewall zone wan default-action"), "{msg}");
    }

    #[test]
    fn a_port_forward_that_takes_the_ssh_port_warns() {
        let saved = cfg(BASE);
        let committed = cfg(&format!(
            "{BASE}\n[[nat.destination]]\nname = \"steal\"\nzone = \"wan\"\n\
             proto = \"tcp\"\nport = 22\nto = \"10.0.0.9\"\n"
        ));
        let msg = committed_warning(&saved, &committed);
        assert!(msg.contains("nat destination steal"), "{msg}");
    }

    #[test]
    fn moving_the_web_console_warns() {
        let saved = cfg(&format!(
            "{BASE}\n[services.web]\nenable = true\nlisten-address = \"10.0.0.1\"\n"
        ));
        let committed = cfg(&format!(
            "{BASE}\n[services.web]\nenable = true\nlisten-address = \"127.0.0.1\"\n"
        ));
        let msg = committed_warning(&saved, &committed);
        assert!(msg.contains("services web listen-address"), "{msg}");
    }

    #[test]
    fn nothing_saved_yet_makes_the_whole_commit_unsaved() {
        let committed = cfg(BASE);
        let u = unsaved_access(None, None, &committed).expect("a box with no saved config warns");
        assert!(
            u.changed
                .contains(&"system login admin ssh-key".to_string()),
            "{:?}",
            u.changed
        );
        // Every management path at once is more than a warning can usefully
        // read out, so the list stops and says how much it left.
        assert!(u.message().contains("more"), "{}", u.message());
    }

    /// A commit carries the whole configuration, so drift an earlier commit left
    /// behind and this one did not repeat is *undone* by this commit — which is
    /// worth saying, because the key the operator is holding may be the one that
    /// just went away.
    #[test]
    fn an_earlier_unsaved_commit_is_reported_alongside_this_one() {
        let saved = cfg(BASE);
        let running = edited(
            "action = \"accept\"\nproto = \"tcp\"\nport = 22",
            "action = \"drop\"\nproto = \"tcp\"\nport = 22",
        );
        let committed = edited("AAAAOLD", "AAAANEW");
        let msg = unsaved_access(Some(&saved), Some(&running), &committed)
            .expect("both the new change and the earlier one matter")
            .message();
        assert!(msg.contains("system login admin ssh-key"), "{msg}");
        assert!(msg.contains("It also undid"), "{msg}");
        assert!(msg.contains("firewall rule ssh-in action"), "{msg}");
    }

    /// The same path changed twice, never saved: the earlier commit is not worth
    /// a second sentence about the setting this one already named.
    #[test]
    fn a_path_changed_again_is_named_once() {
        let saved = cfg(BASE);
        let running = edited("AAAAOLD", "AAAAMIDDLE");
        let committed = edited("AAAAOLD", "AAAANEW");
        let msg = unsaved_access(Some(&saved), Some(&running), &committed)
            .expect("the key is still unsaved")
            .message();
        assert!(msg.contains("system login admin ssh-key"), "{msg}");
        assert!(!msg.contains("It also undid"), "{msg}");
    }

    /// A commit that changes nothing against the saved file, on a box whose
    /// running config differs: it has just taken the earlier change away.
    #[test]
    fn an_earlier_unsaved_commit_is_reported_on_its_own() {
        let saved = cfg(BASE);
        let running = edited("AAAAOLD", "AAAANEW");
        let msg = unsaved_access(Some(&saved), Some(&running), &saved)
            .expect("the running key is about to be replaced")
            .message();
        assert!(msg.contains("undid an unsaved change"), "{msg}");
        assert!(msg.contains("system login admin ssh-key"), "{msg}");
    }

    /// The wording itself, in full, for the case an operator is most likely to
    /// meet. A warning is only as good as the sentence it prints, and a sentence
    /// nobody asserts on is a sentence that decays into "check your
    /// configuration" one edit at a time.
    #[test]
    fn the_warning_reads_like_this() {
        let saved = cfg(BASE);
        let committed = edited("AAAAOLD", "AAAANEW");
        assert_eq!(
            committed_warning(&saved, &committed),
            "this commit changed management access and has not been saved.\n  \
             changed: system login admin ssh-key\n  \
             The next boot loads the saved configuration instead, where that setting still has\n  \
             the previous value — if that is how you reach this box, the way in goes back\n  \
             with it. `save` writes this configuration to disk, so what you just committed\n  \
             is what boots.\n"
        );
    }

    #[test]
    fn the_list_stops_before_it_buries_the_sentence() {
        let many: Vec<String> = (0..MAX_LISTED + 3).map(|n| format!("path {n}")).collect();
        let text = list(&many);
        assert!(text.ends_with("and 3 more"), "{text}");
    }
}
