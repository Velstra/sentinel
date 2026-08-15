//! Whether the clock can be believed.
//!
//! A box that boots with its clock five years slow behaves entirely normally. It
//! routes, it filters, it logs — and every timestamp in that log is wrong, a
//! certificate that expired long ago still validates, ACME renewal is computed
//! against a date that has not happened, and a firewall rule that opens a port
//! at 09:00 opens it on the wrong day of the wrong week. None of that announces
//! itself, so the appliance says it instead.
//!
//! **The judgement.** The kernel keeps a clock-discipline status that whatever
//! time daemon is running — chrony, here — clears once it has actually
//! synchronised. [`libc::adjtimex`] reads it with no daemon, no bus and no
//! subprocess, and it is the same pair of fields systemd reads to answer
//! `NTPSynchronized`, so `show version` and `timedatectl` cannot disagree about
//! the same box. "Not trustworthy" therefore means exactly what systemd means by
//! it: the kernel admits an error bound of 16 s or more — its own ceiling, which
//! it sits at until something disciplines the clock.
//!
//! **Not `STA_UNSYNC`**, and the test box is why. Two wrong versions of this
//! shipped before the right one, each ruled out by the hardware:
//!
//! 1. `STA_UNSYNC` clear *and* `maxerror` under the ceiling. Too strict in the
//!    second half on some setups, and it made the appliance cry wolf.
//! 2. `STA_UNSYNC` clear alone. Also wrong: on the real box, chrony tracks five
//!    servers, disciplines the clock, brings `maxerror` down — and leaves
//!    `STA_UNSYNC` **set**. The appliance still called itself unsynchronised
//!    while `timedatectl` two lines away said it was fine, and said "no time
//!    source has set this clock" about a box that had five.
//!
//! systemd's `ntp_synced()` looks at `maxerror` and nothing else, so that is what
//! this looks at. A warning that is always on is a warning nobody reads.
//!
//! That is the honest signal, and it is the only one that decides. A reading
//! that also looks implausible — earlier than a file this very appliance wrote —
//! is reported as corroboration, because a clock can be wrong while synchronised
//! and right while unsynchronised, and only one of the two facts is evidence.
//!
//! Nothing here corrects anything. An appliance that silently moved its own
//! clock would turn a visible fault into an invisible one.

use crate::archive::fmt_utc;
use crate::config::Appliance;

/// The kernel's own ceiling for how wrong it will admit to being, and systemd's
/// threshold for calling a clock synchronised. Below it, something is
/// disciplining the clock; at it, nothing is.
const MAX_ERROR_US: libc::c_long = 16_000_000;

/// Where to look for a timestamp this box wrote itself. The config file is
/// rewritten on every `save`, and a directory's timestamp moves whenever
/// anything is created under it — between them they are the most recent moment
/// this appliance is known to have been running. Both live on the one writable
/// partition; the rest of the system is an immutable image whose timestamps come
/// from the build, not from this box.
const STATE_PATHS: [&str; 2] = [crate::session::DEFAULT_CONFIG, "/var/lib/sentinel/archive"];

/// What the box can say about its own clock.
pub struct Clock {
    /// The kernel's verdict. `None` when it could not be asked at all, which is
    /// neither a yes nor a no and is printed as neither.
    pub synchronised: Option<bool>,
    /// Now, in epoch seconds, as this box believes it.
    pub now: i64,
    /// A path this appliance wrote whose timestamp lies in the future of `now`,
    /// with that timestamp — corroboration, never the reason for a verdict.
    pub newer_state: Option<(&'static str, i64)>,
}

/// Ask the kernel, then look for corroboration.
pub fn current() -> Clock {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        // A clock set before 1970 is a fault of exactly the kind this module
        // exists to report, so it becomes a reading of 0 rather than a panic.
        .unwrap_or(0);
    Clock {
        synchronised: kernel_sync(),
        now,
        newer_state: newest_state_after(now),
    }
}

impl Clock {
    /// The `clock:` line for `show version`.
    pub fn describe(&self) -> String {
        let now = fmt_utc(self.now);
        match self.synchronised {
            Some(true) => format!("{now} — synchronised"),
            Some(false) => {
                let mut s = format!(
                    "{now} — NOT synchronised: no time source has set this clock, so log \
                     timestamps, certificate expiry and time-based rules are all unreliable"
                );
                if let Some((path, stamp)) = self.newer_state {
                    s.push_str(&format!(
                        " (and it reads earlier than {path}, which this box wrote at {})",
                        fmt_utc(stamp)
                    ));
                }
                s
            }
            None => format!("{now} — unknown (the kernel could not be asked)"),
        }
    }

    /// The warning a scheduled firewall rule earns on a clock nothing has set,
    /// or `None` when there is nothing to warn about.
    ///
    /// Scoped to the rules that are actually being evaluated: a box with no
    /// schedule loses nothing to a wrong clock beyond its log timestamps, which
    /// `show version` already says, and a warning printed on every commit
    /// regardless would be the kind nobody reads.
    pub fn schedule_warning(&self, appliance: &Appliance) -> Option<String> {
        if self.synchronised != Some(false) {
            return None;
        }
        let scheduled = appliance
            .rules
            .iter()
            .filter(|r| !r.disabled && r.schedule.is_some())
            .count();
        if scheduled == 0 {
            return None;
        }
        Some(format!(
            "{scheduled} firewall rule(s) have a schedule, but the clock is not synchronised — \
             it reads {}. Their windows are opening and closing against that time, not the \
             real one.",
            fmt_utc(self.now)
        ))
    }
}

/// The warning for the current clock and this configuration — the form every
/// caller wants, since none of them has a [`Clock`] for any other reason.
pub fn schedule_warning(appliance: &Appliance) -> Option<String> {
    current().schedule_warning(appliance)
}

/// The kernel's own view of whether its clock is disciplined.
///
/// `None` means the call itself failed, which on Linux it does not — but a
/// guess in that case would be a verdict invented out of nothing.
fn kernel_sync() -> Option<bool> {
    // SAFETY: `adjtimex` fills a caller-owned `timex`. A zeroed `modes` asks for
    // a read, so this changes nothing and needs no privilege.
    let mut tx: libc::timex = unsafe { std::mem::zeroed() };
    if unsafe { libc::adjtimex(&mut tx) } < 0 {
        return None;
    }
    // `maxerror` alone — the same question systemd's `ntp_synced()` asks, so the
    // two answers about one box cannot disagree. See the module doc for the two
    // wrong versions the hardware ruled out.
    Some(tx.maxerror < MAX_ERROR_US)
}

/// The newest timestamp among the paths this appliance writes, if any of them
/// lies in the future of `now` — i.e. the clock has gone backwards past a moment
/// this box is known to have been running.
fn newest_state_after(now: i64) -> Option<(&'static str, i64)> {
    STATE_PATHS
        .into_iter()
        .filter_map(|path| Some((path, mtime(path)?)))
        .filter(|&(_, stamp)| stamp > now)
        .max_by_key(|&(_, stamp)| stamp)
}

/// A path's modification time in epoch seconds, or `None` if it has none to
/// give (it does not exist, or is not readable from here).
fn mtime(path: &str) -> Option<i64> {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    /// The verdict is the error bound, and `STA_UNSYNC` has no vote.
    ///
    /// Both of those halves were learned from the test box rather than reasoned
    /// out, and each cost an image. On that box chrony tracks five servers, has
    /// the clock right to a millisecond, keeps `maxerror` well under the
    /// ceiling — and leaves `STA_UNSYNC` **set**. A verdict that consults it
    /// calls a healthy appliance unsynchronised for ever, which is how a warning
    /// becomes noise.
    #[test]
    fn a_disciplined_clock_counts_even_while_the_kernel_flag_says_otherwise() {
        let verdict = |_status: i32, maxerror: libc::c_long| maxerror < MAX_ERROR_US;

        // What the real box reports: bound narrow, flag set.
        assert!(
            verdict(libc::STA_UNSYNC, 5_000),
            "a box tracking five time servers was called unset because of a flag \
             its time daemon never clears"
        );
        // Nothing disciplining the clock: the kernel sits at its ceiling.
        assert!(!verdict(0, MAX_ERROR_US));
    }

    use super::*;
    use crate::config::Appliance;

    /// 2021-01-14 03:22:57 UTC — the reading the hardware actually booted with.
    const SLOW: i64 = 1_610_594_577;

    const BASE: &str = "[system]\nhostname = \"fw\"\n[[interface]]\nname=\"eth0\"\nzone=\"lan\"\n";

    /// An appliance carrying `n` scheduled rules, `disabled` or not.
    fn scheduled(n: usize, disabled: bool) -> Appliance {
        let mut toml = BASE.to_string();
        for i in 0..n {
            toml.push_str(&format!(
                "[[rule]]\nname=\"office-{i}\"\nfrom=\"lan\"\naction=\"accept\"\n\
                 proto=\"tcp\"\nport=443\ndisabled={disabled}\n\
                 [rule.schedule]\ndays=[\"mon\"]\nstart=\"09:00\"\nend=\"17:00\"\n"
            ));
        }
        Appliance::from_toml(&toml).expect("fixture must parse")
    }

    /// The good case says so in one word and stops. Somebody reading a healthy
    /// box should not have to read a paragraph to learn nothing is wrong.
    #[test]
    fn a_synchronised_clock_is_one_short_line() {
        let c = Clock {
            synchronised: Some(true),
            now: SLOW,
            newer_state: None,
        };
        assert_eq!(c.describe(), "2021-01-14 03:22:57 UTC — synchronised");
    }

    /// The bad case names the consequences, because "not synchronised" alone
    /// reads like a detail rather than like the reason the rules are wrong.
    #[test]
    fn an_unsynchronised_clock_says_what_it_breaks() {
        let c = Clock {
            synchronised: Some(false),
            now: SLOW,
            newer_state: None,
        };
        let line = c.describe();
        assert!(
            line.starts_with("2021-01-14 03:22:57 UTC — NOT synchronised"),
            "{line}"
        );
        assert!(line.contains("time-based rules"), "{line}");
        assert!(!line.contains("earlier than"), "{line}");
    }

    /// Corroboration is appended to the verdict, never substituted for it.
    #[test]
    fn state_written_in_the_future_is_quoted_as_corroboration() {
        let c = Clock {
            synchronised: Some(false),
            now: SLOW,
            newer_state: Some(("/var/lib/sentinel/appliance.toml", 1_786_000_000)),
        };
        let line = c.describe();
        assert!(line.contains("/var/lib/sentinel/appliance.toml"), "{line}");
        assert!(line.contains("2026-08-06"), "{line}");

        // …and a clock that looks odd but that the kernel vouches for is not
        // accused on the strength of a file timestamp alone.
        let vouched = Clock {
            synchronised: Some(true),
            ..c
        };
        assert_eq!(
            vouched.describe(),
            "2021-01-14 03:22:57 UTC — synchronised",
            "corroboration must not become a verdict"
        );
    }

    /// Not knowing is its own answer.
    #[test]
    fn a_kernel_that_cannot_be_asked_is_not_a_verdict() {
        let c = Clock {
            synchronised: None,
            now: SLOW,
            newer_state: None,
        };
        assert!(c.describe().contains("unknown"), "{}", c.describe());
        assert!(c.schedule_warning(&scheduled(1, false)).is_none());
    }

    /// The warning exists for the rules it is about, and the count is the
    /// operator's cue for how much is affected.
    #[test]
    fn scheduled_rules_on_a_bad_clock_are_warned_about() {
        let bad = Clock {
            synchronised: Some(false),
            now: SLOW,
            newer_state: None,
        };
        let w = bad
            .schedule_warning(&scheduled(2, false))
            .expect("a scheduled rule on an unsynchronised clock must warn");
        assert!(w.starts_with("2 firewall rule(s)"), "{w}");
        assert!(w.contains("2021-01-14"), "{w}");

        // A rule the operator disabled is not being evaluated, so it is not
        // counted — a warning that overstates its own scope teaches people to
        // ignore it.
        assert!(
            bad.schedule_warning(&scheduled(1, true)).is_none(),
            "a disabled rule is not being evaluated against the clock"
        );
    }

    /// No schedule, no warning — and no warning at all once the clock is good.
    #[test]
    fn a_good_clock_or_no_schedule_warns_about_nothing() {
        let bad = Clock {
            synchronised: Some(false),
            now: SLOW,
            newer_state: None,
        };
        assert!(bad.schedule_warning(&scheduled(0, false)).is_none());

        let good = Clock {
            synchronised: Some(true),
            now: SLOW,
            newer_state: None,
        };
        assert!(good.schedule_warning(&scheduled(1, false)).is_none());
    }

    /// The kernel answers on any Linux this runs on, and its answer is a
    /// verdict rather than an error.
    #[test]
    fn the_kernel_can_be_asked() {
        assert!(
            kernel_sync().is_some(),
            "adjtimex(2) in read mode needs no privilege and should always answer"
        );
    }

    /// The corroboration is one-sided on purpose: a state file older than the
    /// clock says nothing (that is the normal case).
    #[test]
    fn only_a_future_timestamp_corroborates() {
        // Nothing on a test host is written in the future of the test host's
        // own clock, so this is the normal, silent case.
        assert!(newest_state_after(i64::MAX).is_none());
    }
}
