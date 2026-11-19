//! Brute-force budgets for the management API.
//!
//! Four doors take guesses: the sign-in form, every bearer-authenticated
//! endpoint, and the unauthenticated HA enrollment proof. Each has a budget
//! here, and all of them share one shape — [`Limiter`]: a bounded table of keys,
//! each counting attempts in a window and locked for a while once it exhausts
//! its budget.
//!
//! **A full table degrades, it does not slam shut.** Earlier a sign-in table
//! full of locked addresses refused every new address outright, so one IPv6
//! /48 (65 536 /64 sources) locked everybody out. Now a newcomer that finds no
//! room shares one small overflow budget with every other untracked source:
//! guessing from fresh addresses stays bounded globally, and an operator still
//! gets through once that budget refills.
//!
//! **Sign-in counts per account *and origin*.** The old cross-origin account
//! counter let anybody lock `admin` out by guessing its password thirty times
//! from anywhere. Now each (account, origin) pair has its own budget, and the
//! distributed budget — guesses at one account from many origins — applies only
//! to origins that have never signed that account in. An administrator at the
//! workstation they always use is not locked out by somebody else's botnet.
//!
//! Everything is in memory: a restart forgives, and an operator who locked
//! themselves out does not have to find a file to get back in.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

/// How a key is counted: attempts per window, and how long a key that used up
/// its window stays locked.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Budget {
    pub max: u32,
    pub window: Duration,
    pub lockout: Duration,
}

/// Why an attempt is refused, with the seconds until it may be retried.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// This key used its budget and is locked.
    Locked(u64),
    /// The table is full of locked keys and the overflow budget every untracked
    /// newcomer shares is used up for this window.
    Busy(u64),
}

impl Refusal {
    pub(crate) fn retry_after(&self) -> u64 {
        match self {
            Refusal::Locked(s) | Refusal::Busy(s) => *s,
        }
    }
}

#[derive(Clone, Copy)]
struct Record {
    window_started: Instant,
    count: u32,
    locked_until: Option<Instant>,
}

/// One shared budget for newcomers that find the table full.
struct Overflow {
    window_started: Instant,
    used: u32,
}

/// A bounded table of per-key attempt counters with lockout.
pub(crate) struct Limiter<K> {
    records: Mutex<HashMap<K, Record>>,
    overflow: Mutex<Overflow>,
    capacity: usize,
    budget: Budget,
    /// Attempts per window all untracked newcomers share once the table is
    /// full of locks.
    overflow_max: u32,
}

fn guard<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn seconds_until(until: Instant, now: Instant) -> u64 {
    until.saturating_duration_since(now).as_secs().max(1)
}

impl<K: Hash + Eq + Clone> Limiter<K> {
    pub(crate) fn new(capacity: usize, budget: Budget, overflow_max: u32) -> Self {
        Self {
            records: Mutex::default(),
            overflow: Mutex::new(Overflow {
                window_started: Instant::now(),
                used: 0,
            }),
            capacity,
            budget,
            overflow_max,
        }
    }

    /// Whether `key` may try now, without counting anything.
    pub(crate) fn check(&self, key: &K) -> Result<(), Refusal> {
        let now = Instant::now();
        let map = guard(&self.records);
        if let Some(until) = map.get(key).and_then(|r| r.locked_until)
            && until > now
        {
            return Err(Refusal::Locked(seconds_until(until, now)));
        }
        if !map.contains_key(key) && map.len() >= self.capacity && self.only_locks(&map, now) {
            return self.overflow_state(now, false);
        }
        Ok(())
    }

    /// Count one attempt for `key` now, returning how many it has made in the
    /// current window, or refuse it. Counted under the same lock as the check,
    /// so parallel attempts cannot all slip past a count that has not caught
    /// up: the budget is the most attempts one key can make per window.
    pub(crate) fn count(&self, key: &K) -> Result<u32, Refusal> {
        let now = Instant::now();
        let mut map = guard(&self.records);
        if let Some(until) = map.get(key).and_then(|r| r.locked_until) {
            if until > now {
                return Err(Refusal::Locked(seconds_until(until, now)));
            }
            map.remove(key);
        }
        if !map.contains_key(key) && map.len() >= self.capacity {
            self.make_room(&mut map, now);
            if map.len() >= self.capacity {
                // Nothing but live locks: never release one to make room (that
                // was a way to unlock yourself by spraying), and never refuse
                // everybody either. The newcomer goes untracked, on the shared
                // overflow budget.
                return self.overflow_state(now, true).map(|()| 1);
            }
        }
        let budget = self.budget;
        let record = map.entry(key.clone()).or_insert(Record {
            window_started: now,
            count: 0,
            locked_until: None,
        });
        if now.duration_since(record.window_started) > budget.window {
            *record = Record {
                window_started: now,
                count: 0,
                locked_until: None,
            };
        }
        record.count = record.count.saturating_add(1);
        if record.count >= budget.max {
            record.locked_until = Some(now + budget.lockout);
        }
        Ok(record.count)
    }

    /// Forget `key`: a good sign-in clears its own counter.
    pub(crate) fn forget(&self, key: &K) {
        guard(&self.records).remove(key);
    }

    /// Drop lapsed windows and expired locks, then the least-recently-active
    /// unlocked key. A live lock is never evicted.
    fn make_room(&self, map: &mut HashMap<K, Record>, now: Instant) {
        let window = self.budget.window;
        map.retain(|_, r| match r.locked_until {
            Some(until) => until > now,
            None => now.duration_since(r.window_started) <= window,
        });
        if map.len() < self.capacity {
            return;
        }
        let oldest = map
            .iter()
            .filter(|(_, r)| r.locked_until.is_none())
            .min_by_key(|(_, r)| r.window_started)
            .map(|(k, _)| k.clone());
        if let Some(oldest) = oldest {
            map.remove(&oldest);
        }
    }

    fn only_locks(&self, map: &HashMap<K, Record>, now: Instant) -> bool {
        map.values()
            .all(|r| r.locked_until.is_some_and(|until| until > now))
    }

    fn overflow_state(&self, now: Instant, consume: bool) -> Result<(), Refusal> {
        let mut overflow = guard(&self.overflow);
        if now.duration_since(overflow.window_started) > self.budget.window {
            overflow.window_started = now;
            overflow.used = 0;
        }
        if overflow.used >= self.overflow_max {
            return Err(Refusal::Busy(seconds_until(
                overflow.window_started + self.budget.window,
                now,
            )));
        }
        if consume {
            overflow.used += 1;
        }
        Ok(())
    }
}

/// Privacy addresses within one IPv6 /64 are one source for brute-force
/// protection, and a mapped IPv4 address is that IPv4 address, so neither buys
/// a second budget. Forwarding headers are never trusted.
pub(crate) fn source(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return IpAddr::V4(v4);
            }
            let mut bytes = v6.octets();
            bytes[8..].fill(0);
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        v4 => v4,
    }
}

/// The source a request without a peer address (an in-process caller) is
/// counted as.
pub(crate) const UNKNOWN_SOURCE: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// The most keys any one table tracks.
pub(crate) const MAX_TRACKED: usize = 4096;

/// Untracked newcomers share this many attempts per window once a table is
/// full of locks.
pub(crate) const OVERFLOW_ATTEMPTS: u32 = 20;

/// Sign-in attempts from one source, over all accounts: stops one source
/// spraying many accounts.
pub(crate) const SIGN_IN_PER_SOURCE: Budget = Budget {
    max: 10,
    window: Duration::from_secs(600),
    lockout: Duration::from_secs(900),
};

/// Sign-in attempts at one account from one origin.
pub(crate) const SIGN_IN_PER_ACCOUNT_ORIGIN: Budget = Budget {
    max: 10,
    window: Duration::from_secs(600),
    lockout: Duration::from_secs(900),
};

/// Sign-in attempts at one account from origins that never signed it in:
/// bounds a distributed guess without locking out known origins.
pub(crate) const SIGN_IN_PER_ACCOUNT_NEW_ORIGINS: Budget = Budget {
    max: 100,
    window: Duration::from_secs(600),
    lockout: Duration::from_secs(600),
};

/// Failed bearer authentications from one source. A console signs out on its
/// first 401, so an honest client spends a handful of these per expiry.
pub(crate) const BEARER_FAILURES: Budget = Budget {
    max: 30,
    window: Duration::from_secs(600),
    lockout: Duration::from_secs(300),
};

/// HA enrollment proofs per source. A pairing asks for one per attempt.
pub(crate) const HA_PROOFS: Budget = Budget {
    max: 10,
    window: Duration::from_secs(600),
    lockout: Duration::from_secs(900),
};

/// How long an origin that signed an account in is trusted for that account's
/// distributed budget.
const TRUSTED_ORIGIN: Duration = Duration::from_secs(30 * 24 * 3600);

/// Sign-in budgets: per (account, origin), and per account from new origins.
pub(crate) struct SignIn {
    pairs: Limiter<(String, IpAddr)>,
    accounts: Limiter<String>,
    trusted: Mutex<HashMap<(String, IpAddr), Instant>>,
}

/// Which sign-in budget refused an attempt.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SignInRefusal {
    /// This account from this origin.
    Origin(Refusal),
    /// This account from origins that never signed it in.
    NewOrigins(Refusal),
}

impl SignIn {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            pairs: Limiter::new(capacity, SIGN_IN_PER_ACCOUNT_ORIGIN, OVERFLOW_ATTEMPTS),
            accounts: Limiter::new(capacity, SIGN_IN_PER_ACCOUNT_NEW_ORIGINS, OVERFLOW_ATTEMPTS),
            trusted: Mutex::default(),
        }
    }

    /// Count one attempt at `account` from `origin`, returning the pair's count
    /// in its window (which paces the reply), or refuse it.
    pub(crate) fn begin(&self, account: &str, origin: IpAddr) -> Result<u32, SignInRefusal> {
        let key = (account.to_string(), source(origin));
        if !self.trusted_pair(&key) {
            // Checked before the pair is counted, counted after: a refusal by
            // the distributed budget must not also spend the pair's.
            self.accounts
                .check(&key.0)
                .map_err(SignInRefusal::NewOrigins)?;
        }
        let attempts = self.pairs.count(&key).map_err(SignInRefusal::Origin)?;
        if !self.trusted_pair(&key) {
            self.accounts
                .count(&key.0)
                .map_err(SignInRefusal::NewOrigins)?;
        }
        Ok(attempts)
    }

    /// A good sign-in: forgive the pair and trust the origin for this account.
    pub(crate) fn succeeded(&self, account: &str, origin: IpAddr) {
        let key = (account.to_string(), source(origin));
        self.pairs.forget(&key);
        let mut trusted = guard(&self.trusted);
        let now = Instant::now();
        if trusted.len() >= MAX_TRACKED && !trusted.contains_key(&key) {
            trusted.retain(|_, at| now.duration_since(*at) <= TRUSTED_ORIGIN);
            if trusted.len() >= MAX_TRACKED
                && let Some(oldest) = trusted
                    .iter()
                    .min_by_key(|(_, at)| **at)
                    .map(|(k, _)| k.clone())
            {
                trusted.remove(&oldest);
            }
        }
        trusted.insert(key, now);
    }

    /// Whether `origin` signed `account` in before (see [`TRUSTED_ORIGIN`]).
    pub(crate) fn is_trusted(&self, account: &str, origin: IpAddr) -> bool {
        self.trusted_pair(&(account.to_string(), source(origin)))
    }

    fn trusted_pair(&self, key: &(String, IpAddr)) -> bool {
        guard(&self.trusted)
            .get(key)
            .is_some_and(|at| at.elapsed() <= TRUSTED_ORIGIN)
    }
}

/// The process-wide tables the server uses.
pub(crate) struct Tables {
    pub sign_in_sources: Limiter<IpAddr>,
    pub sign_in: SignIn,
    pub bearer_failures: Limiter<IpAddr>,
    pub ha_proofs: Limiter<IpAddr>,
}

pub(crate) fn tables() -> &'static Tables {
    static TABLES: OnceLock<Tables> = OnceLock::new();
    TABLES.get_or_init(|| Tables {
        sign_in_sources: Limiter::new(MAX_TRACKED, SIGN_IN_PER_SOURCE, OVERFLOW_ATTEMPTS),
        sign_in: SignIn::new(MAX_TRACKED),
        bearer_failures: Limiter::new(MAX_TRACKED, BEARER_FAILURES, OVERFLOW_ATTEMPTS),
        ha_proofs: Limiter::new(MAX_TRACKED, HA_PROOFS, OVERFLOW_ATTEMPTS),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMALL: Budget = Budget {
        max: 3,
        window: Duration::from_secs(600),
        lockout: Duration::from_secs(900),
    };

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([198, 51, 100, n])
    }

    #[test]
    fn a_key_locks_at_its_budget_and_others_are_untouched() {
        let limiter = Limiter::new(16, SMALL, 2);
        for n in 1..=SMALL.max {
            assert_eq!(limiter.count(&ip(1)), Ok(n));
        }
        assert!(matches!(limiter.count(&ip(1)), Err(Refusal::Locked(s)) if s > 0 && s <= 900));
        assert!(matches!(limiter.check(&ip(1)), Err(Refusal::Locked(_))));
        assert_eq!(limiter.check(&ip(2)), Ok(()));
        limiter.forget(&ip(1));
        assert_eq!(limiter.count(&ip(1)), Ok(1));
    }

    /// CTRL-27: a table full of locks used to refuse every new address. Now a
    /// newcomer is admitted on the shared overflow budget, a lock is never
    /// released to make room, and the overflow itself is bounded.
    #[test]
    fn a_full_table_of_locks_degrades_to_the_overflow_budget() {
        let limiter = Limiter::new(2, SMALL, 2);
        for n in 1..=2u8 {
            for _ in 0..SMALL.max {
                limiter.count(&ip(n)).unwrap();
            }
        }
        assert_eq!(limiter.check(&ip(3)), Ok(()));
        assert_eq!(limiter.count(&ip(3)), Ok(1));
        assert_eq!(limiter.count(&ip(4)), Ok(1));
        assert!(matches!(limiter.count(&ip(5)), Err(Refusal::Busy(_))));
        assert!(matches!(limiter.check(&ip(6)), Err(Refusal::Busy(_))));
        assert!(matches!(limiter.count(&ip(1)), Err(Refusal::Locked(_))));
    }

    #[test]
    fn eviction_never_releases_a_lock() {
        let limiter = Limiter::new(4, SMALL, 2);
        for _ in 0..SMALL.max {
            limiter.count(&ip(1)).unwrap();
        }
        for n in 2..60u8 {
            assert_eq!(limiter.count(&ip(n)), Ok(1));
        }
        assert!(matches!(limiter.count(&ip(1)), Err(Refusal::Locked(_))));
    }

    #[test]
    fn ipv6_privacy_and_mapped_addresses_share_a_source() {
        let first: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let rotated: IpAddr = "2001:db8:1:2:abcd:1234:ffff:abcd".parse().unwrap();
        assert_eq!(source(first), source(rotated));
        assert_ne!(source(first), source("2001:db8:1:3::1".parse().unwrap()));
        assert_eq!(
            source("::ffff:192.0.2.1".parse().unwrap()),
            "192.0.2.1".parse::<IpAddr>().unwrap()
        );
    }

    /// CTRL-27: guessing `admin` from one origin locks that origin for that
    /// account only — the same account from another origin, and another
    /// account from the same origin, still sign in.
    #[test]
    fn an_account_is_locked_per_origin_not_everywhere() {
        let sign_in = SignIn::new(64);
        for _ in 0..SIGN_IN_PER_ACCOUNT_ORIGIN.max {
            sign_in.begin("admin", ip(1)).unwrap();
        }
        assert!(matches!(
            sign_in.begin("admin", ip(1)),
            Err(SignInRefusal::Origin(Refusal::Locked(_)))
        ));
        assert_eq!(sign_in.begin("admin", ip(2)), Ok(1));
        assert_eq!(sign_in.begin("operator", ip(1)), Ok(1));
    }

    /// A distributed guess exhausts the new-origins budget, which then refuses
    /// fresh origins — but an origin that signed the account in before keeps
    /// its own pair budget and gets through.
    #[test]
    fn a_distributed_guess_cannot_lock_out_a_known_origin() {
        let sign_in = SignIn::new(4096);
        let workstation = ip(200);
        sign_in.begin("admin", workstation).unwrap();
        sign_in.succeeded("admin", workstation);
        // The workstation's own first sign-in, from a then-new origin, spent
        // one attempt of the new-origins budget.
        for n in 1..SIGN_IN_PER_ACCOUNT_NEW_ORIGINS.max {
            let origin = IpAddr::from([203, 0, (n / 250) as u8, (n % 250) as u8 + 1]);
            sign_in.begin("admin", origin).unwrap();
        }
        assert!(matches!(
            sign_in.begin("admin", IpAddr::from([192, 0, 2, 1])),
            Err(SignInRefusal::NewOrigins(Refusal::Locked(_)))
        ));
        assert_eq!(sign_in.begin("admin", workstation), Ok(1));
        // Another account is not affected by the attack on this one.
        assert_eq!(
            sign_in.begin("operator", IpAddr::from([192, 0, 2, 1])),
            Ok(1)
        );
    }
}
