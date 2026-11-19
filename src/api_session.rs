//! Signed-in sessions for the management API.
//!
//! A sign-in used to hand back the account's one token — minted once, kept in
//! the clear beside the machine token, and valid until somebody deleted the
//! file. Nothing ended it: not a password reset, not an idle browser, not
//! closing the tab. And because the files were per *configured account*, a
//! directory login (no `[[system.login]]` entry) was handed a token that the
//! next request could not resolve.
//!
//! So a sign-in now opens a **session**: its own random bearer, valid for
//! [`IDLE`] without use and [`LIFETIME`] in all, and ended early by signing out
//! or by any change to what the account is. The session records the grant it
//! was opened under — the account's password hash, second factor, group and that
//! group's permission, folded into one digest — and every use recomputes that
//! digest from the running configuration. A password reset, a new TOTP secret,
//! a group change, a deleted account or a withdrawn `default-group` therefore
//! changes the digest, and every session opened before it stops resolving
//! without anybody having to remember to revoke it.
//!
//! **At rest a session is a digest, not a bearer.** The file is named by the
//! SHA-256 of the token and holds the same digest; the token itself exists only
//! in the reply to the sign-in. A backup of `/var/lib/sentinel`, or a read of
//! it, is not a way in. The token carries 256 random bits, so an unsalted digest
//! is enough: there is no dictionary to run against it.
//!
//! Sessions live on disk rather than in memory because the API is restarted by
//! the reconciler; a commit that touched the listener must not sign everybody
//! out. The machine token is not a session and is untouched by any of this.

use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::config::{Appliance, Permission};

/// How long a session may go unused. Thirty minutes: long enough to read a
/// ruleset without being signed out under the reader, short enough that a
/// console left open on a shared workstation is not an open door for the day.
pub const IDLE: u64 = 30 * 60;

/// How long a session lasts however busy it is: a working day. A bearer that
/// leaked into a proxy log or a screenshot stops working by tomorrow.
pub const LIFETIME: u64 = 12 * 60 * 60;

/// How stale `last_used` may get before a use rewrites it. The console polls
/// every few seconds and the telemetry stream checks its credential on every
/// event; recording each of those would be a disk write per event for a
/// timestamp nobody needs to the second.
const TOUCH_EVERY: u64 = 60;

/// How far into the future a session's timestamps may lie. A clock stepped
/// back by NTP, or a VM resumed from a snapshot, moves a little; a session
/// minted while the clock was hours ahead would otherwise read as brand new
/// until the clock caught up again, outliving both of its limits by the skew.
const CLOCK_SKEW: u64 = 5 * 60;

/// The most sessions one account keeps. A sign-in beyond it ends that
/// account's least recently used session: every sign-in is a file, and a
/// script that signs in on every run must not fill the state partition.
pub const MAX_SESSIONS_PER_ACCOUNT: usize = 16;

/// The most sessions the appliance keeps in all, for the same reason across
/// accounts (directory accounts are not listed anywhere to bound them by).
const MAX_SESSIONS: usize = 1024;

/// The largest session file read back. A record is a few hundred bytes; this
/// only bounds what a corrupted or planted file can make the server allocate.
const MAX_RECORD: u64 = 4096;

/// One open session, as stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Record {
    /// The SHA-256 of the bearer, hex — also the file's name.
    digest: String,
    user: String,
    permission: Permission,
    /// Whether a directory server, not the local password, accepted the
    /// sign-in. It decides whether removing every server ends the session.
    directory: bool,
    /// The digest of the grant the session was opened under (see [`grant`]).
    grant: String,
    created: u64,
    last_used: u64,
}

/// Session files are created, rewritten and removed by concurrent requests.
/// Without one lock a sign-out could land between a use reading the record and
/// the same use writing its refreshed timestamp back — and the rewrite would
/// bring the signed-out session back to life.
fn lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn sha256_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Whether a file name is a session's: 64 lowercase hex digits. Anything else
/// in the directory is not ours to honour — in particular the per-account
/// token files of the scheme this replaced, which are named by username (at
/// most 32 characters, so never mistaken for a digest).
fn is_session_name(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// What `user` may do according to `appliance`, and a digest of everything
/// that grant rests on — or `None` if it grants nothing.
///
/// The group is the account's own, else the directory `default-group`, exactly
/// as signing in decides it. The digest covers the account's password hash,
/// second factor and group, the effective group and its permission, and — for
/// a directory sign-in — whether any server is still configured. A change to
/// any of them is a different digest, which is what ends the session.
pub fn grant(appliance: &Appliance, user: &str, directory: bool) -> Option<(Permission, String)> {
    let login = appliance.system.logins.iter().find(|l| l.username == user);
    if !directory && login.is_none() {
        return None;
    }
    if directory && !appliance.system.aaa.has_servers() {
        return None;
    }
    // Match the existing Unix bootstrap exception, not a new grant: only a
    // configured builtin admin with no explicit group has administrator access.
    // An explicit read-only group still demotes it; a directory named admin or
    // an arbitrary ungrouped local login never inherits bootstrap privileges.
    let bootstrap = login.is_some_and(|l| l.username == "admin" && l.group.is_none());
    let group = login.and_then(|l| l.group.as_deref()).or_else(|| {
        directory
            .then_some(appliance.system.aaa.default_group.as_deref())
            .flatten()
    });
    let permission = if bootstrap {
        Permission::ReadWrite
    } else {
        appliance
            .system
            .groups
            .iter()
            .find(|g| Some(g.name.as_str()) == group)?
            .permission
    };
    let material = serde_json::json!({
        "user": user,
        "login": login.is_some(),
        "hashed-password": login.and_then(|l| l.hashed_password.as_deref()),
        "totp": login.and_then(|l| l.totp.as_deref()),
        "own-group": login.and_then(|l| l.group.as_deref()),
        "group": group,
        "permission": permission,
        "bootstrap-admin": bootstrap,
        // An endpoint/secret/TLS policy change withdraws sessions granted by
        // the old directory trust, not only removing the last server entirely.
        "directory-trust": directory.then_some(&appliance.system.aaa),
    });
    Some((permission, sha256_hex(material.to_string().as_bytes())))
}

/// Open a session for `user` with `permission`, under the grant digest
/// `grant`, and return its bearer. The directory is created 0700 and the
/// record 0600; the bearer is never written.
pub fn open(
    dir: &Path,
    user: &str,
    permission: Permission,
    directory: bool,
    grant: String,
    now: u64,
) -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| anyhow!("generating a session token: {e}"))?;
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let record = Record {
        digest: sha256_hex(token.as_bytes()),
        user: user.to_string(),
        permission,
        directory,
        grant,
        created: now,
        last_used: now,
    };
    let _guard = lock();
    ensure_dir(dir)?;
    make_room(dir, user, now);
    write_record(dir, &record, true)?;
    Ok(token)
}

/// Before a new session for `user` is written: drop every session past its
/// time limits, then that account's least recently used sessions beyond
/// [`MAX_SESSIONS_PER_ACCOUNT`] - 1, then the appliance's beyond
/// [`MAX_SESSIONS`] - 1. Best effort: a file that cannot be removed is not a
/// reason to refuse a sign-in. The caller holds [`lock`].
fn make_room(dir: &Path, user: &str, now: u64) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut live: Vec<Record> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(record) = read_record(dir, &name) else {
            continue;
        };
        if within_limits(&record, now) {
            live.push(record);
        } else {
            let _ = std::fs::remove_file(dir.join(&name));
        }
    }
    // Least recently used first.
    live.sort_by_key(|r| (r.last_used, r.created));
    let mine = live.iter().filter(|r| r.user == user).count();
    let mut excess_mine = (mine + 1).saturating_sub(MAX_SESSIONS_PER_ACCOUNT);
    let mut kept = Vec::with_capacity(live.len());
    for record in live {
        if excess_mine > 0 && record.user == user {
            excess_mine -= 1;
            let _ = std::fs::remove_file(dir.join(&record.digest));
        } else {
            kept.push(record);
        }
    }
    let excess = (kept.len() + 1).saturating_sub(MAX_SESSIONS);
    for record in kept.iter().take(excess) {
        let _ = std::fs::remove_file(dir.join(&record.digest));
    }
}

/// Who `presented` signs in as, and with what permission, at time `now` — or
/// `None`. An expired session, or one whose grant no longer matches the
/// configuration, is removed on the way out so it cannot come back.
pub fn resolve(
    dir: &Path,
    appliance: &Appliance,
    presented: &str,
    now: u64,
) -> Option<(String, Permission)> {
    let digest = sha256_hex(presented.as_bytes());
    let _guard = lock();
    let mut record = read_record(dir, &digest)?;
    // The name already selected this file by digest; the comparison is kept
    // constant-time anyway so a file that merely claims the name grants nothing.
    if !crate::api::ct_eq(record.digest.as_bytes(), digest.as_bytes()) {
        return None;
    }
    if !alive(&record, appliance, now) {
        let _ = std::fs::remove_file(dir.join(&digest));
        return None;
    }
    if now.saturating_sub(record.last_used) >= TOUCH_EVERY {
        record.last_used = now;
        if let Err(e) = write_record(dir, &record, false) {
            eprintln!("warning: could not record a session's use: {e:#}");
        }
    }
    Some((record.user, record.permission))
}

/// End the session `presented` names. `true` if there was one.
pub fn close(dir: &Path, presented: &str) -> bool {
    let digest = sha256_hex(presented.as_bytes());
    let _guard = lock();
    read_record(dir, &digest).is_some() && std::fs::remove_file(dir.join(&digest)).is_ok()
}

/// Remove every session that is expired or no longer granted, and anything in
/// the directory that is not a session at all — which includes the clear-text
/// per-account token files of the previous scheme. Those are deliberately
/// withdrawn rather than migrated: they never expired and were readable by
/// anybody who could read the state directory, so a client that held one signs
/// in again.
pub fn sweep(dir: &Path, appliance: &Appliance, now: u64) -> Result<()> {
    let _guard = lock();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    ensure_dir(dir)?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let keep = is_session_name(&name)
            && read_record(dir, &name).is_some_and(|r| alive(&r, appliance, now));
        if !keep {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    Ok(())
}

/// Whether `record` is inside both of its time limits and still describes what
/// the configuration grants. The comparison is on the grant digest *and* the
/// permission, so even a digest collision could not carry a session across a
/// change of permission.
fn alive(record: &Record, appliance: &Appliance, now: u64) -> bool {
    if !within_limits(record, now) {
        return false;
    }
    match grant(appliance, &record.user, record.directory) {
        Some((permission, digest)) => {
            permission == record.permission
                && crate::api::ct_eq(digest.as_bytes(), record.grant.as_bytes())
        }
        None => false,
    }
}

/// Whether `record` is inside both of its time limits at `now`.
///
/// A record stamped more than [`CLOCK_SKEW`] in the future was written while
/// the clock was wrong, and is not trusted: `saturating_sub` used to read it
/// as zero seconds old, so a session minted with the clock a day ahead stayed
/// alive for a day after the clock was corrected (CTRL-29).
fn within_limits(record: &Record, now: u64) -> bool {
    let horizon = now.saturating_add(CLOCK_SKEW);
    record.created <= horizon
        && record.last_used <= horizon
        && now.saturating_sub(record.last_used) <= IDLE
        && now.saturating_sub(record.created) <= LIFETIME
}

fn ensure_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    if !dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
    }
    // The directory of the previous scheme was made with the default mode. The
    // records are 0600 either way, but who has signed in, and when, is nobody
    // else's business either.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("restricting {}", dir.display()))
}

fn read_record(dir: &Path, digest: &str) -> Option<Record> {
    use std::io::Read;
    if !is_session_name(digest) {
        return None;
    }
    let file = std::fs::File::open(dir.join(digest)).ok()?;
    let mut text = String::new();
    file.take(MAX_RECORD).read_to_string(&mut text).ok()?;
    serde_json::from_str(&text).ok()
}

/// Write `record` under its digest. A new session is created exclusively, so a
/// (vanishingly unlikely) colliding token can never overwrite another's record;
/// a refresh goes through a temporary file and a rename, so a reader never sees
/// half a record.
fn write_record(dir: &Path, record: &Record, create: bool) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let body = serde_json::to_vec(record)?;
    let path = dir.join(&record.digest);
    let target = if create {
        path.clone()
    } else {
        dir.join(format!(".{}.tmp", record.digest))
    };
    let mut options = std::fs::OpenOptions::new();
    options.write(true).mode(0o600);
    if create {
        options.create_new(true);
    } else {
        options.create(true).truncate(true);
    }
    let mut file = options
        .open(&target)
        .with_context(|| format!("writing {}", target.display()))?;
    file.write_all(&body)
        .with_context(|| format!("writing {}", target.display()))?;
    if !create {
        std::fs::rename(&target, &path).with_context(|| format!("replacing {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configured() -> Appliance {
        Appliance::from_toml(
            "[system]\nhostname='grant-test'\n\
             [[system.group]]\nname='viewers'\npermission='read-only'\n\
             [[system.group]]\nname='operators'\npermission='read-write'\n\
             [[system.login]]\nusername='admin'\n\
             [[system.login]]\nusername='shell-user'\n\
             [system.aaa]\ndefault-group='operators'\n\
             [[system.aaa.radius]]\nserver='192.0.2.9'\nsecret='directory-secret'\n",
        )
        .unwrap()
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sentinel-session-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn admin_session(dir: &Path, appliance: &Appliance, now: u64) -> String {
        let (permission, digest) = grant(appliance, "admin", false).unwrap();
        open(dir, "admin", permission, false, digest, now).unwrap()
    }

    /// CTRL-29: a session minted while the clock was a day ahead used to read
    /// as zero seconds old once the clock was corrected (`saturating_sub`), so
    /// it outlived its idle limit by the whole skew. A record from the future
    /// beyond a small skew is not trusted at all.
    #[test]
    fn a_session_from_a_clock_that_ran_ahead_is_not_trusted_after_correction() {
        let appliance = configured();
        let dir = scratch("clock-ahead");
        let corrected = 1_800_000_000;
        let ahead = corrected + 24 * 60 * 60;
        let token = admin_session(&dir, &appliance, ahead);
        assert!(resolve(&dir, &appliance, &token, ahead).is_some());
        assert!(
            resolve(&dir, &appliance, &token, corrected + IDLE + 1).is_none(),
            "a session from a day-ahead clock survived past its idle limit after correction"
        );
        // A small backwards step (NTP slew, a VM resumed) is tolerated.
        let dir = scratch("clock-skew");
        let token = admin_session(&dir, &appliance, corrected + 30);
        assert!(resolve(&dir, &appliance, &token, corrected).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CTRL-29: every successful sign-in wrote one more session file, without
    /// bound. One account keeps its newest sessions only.
    #[test]
    fn repeated_sign_ins_keep_a_bounded_number_of_sessions() {
        let appliance = configured();
        let dir = scratch("bounded");
        let now = 1_800_000_000;
        let tokens: Vec<String> = (0..(MAX_SESSIONS_PER_ACCOUNT as u64 + 24))
            .map(|n| admin_session(&dir, &appliance, now + n))
            .collect();
        let files = std::fs::read_dir(&dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .is_ok_and(|e| is_session_name(&e.file_name().to_string_lossy()))
            })
            .count();
        assert!(
            files <= MAX_SESSIONS_PER_ACCOUNT,
            "{files} session files for one account"
        );
        let later = now + tokens.len() as u64;
        assert!(resolve(&dir, &appliance, tokens.last().unwrap(), later).is_some());
        assert!(resolve(&dir, &appliance, &tokens[0], later).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bootstrap_admin_matches_unix_grant_but_explicit_groups_can_demote_it() {
        let mut appliance = configured();
        assert_eq!(
            grant(&appliance, "admin", false).unwrap().0,
            Permission::ReadWrite
        );
        assert!(grant(&appliance, "shell-user", false).is_none());
        assert!(grant(&appliance, "not-configured", false).is_none());
        let original = grant(&appliance, "admin", false).unwrap().1;
        appliance.system.logins[0].group = Some("viewers".into());
        let demoted = grant(&appliance, "admin", false).unwrap();
        assert_eq!(demoted.0, Permission::ReadOnly);
        assert_ne!(original, demoted.1);
        appliance.system.logins.remove(0);
        assert!(grant(&appliance, "admin", false).is_none());
        // A directory account named admin gets only the explicit default-group,
        // not the deleted local account's bootstrap grant.
        appliance.system.aaa.default_group = Some("viewers".into());
        assert_eq!(
            grant(&appliance, "admin", true).unwrap().0,
            Permission::ReadOnly
        );
        appliance.system.aaa.default_group = None;
        assert!(grant(&appliance, "admin", true).is_none());
    }

    #[test]
    fn directory_trust_changes_revoke_grants_but_do_not_revoke_local_password_sessions() {
        let mut appliance = configured();
        let directory = grant(&appliance, "directory-user", true).unwrap().1;
        let local = grant(&appliance, "admin", false).unwrap().1;
        appliance.system.aaa.radius[0].secret = "replacement-secret".into();
        assert_ne!(
            directory,
            grant(&appliance, "directory-user", true).unwrap().1
        );
        assert_eq!(local, grant(&appliance, "admin", false).unwrap().1);
        let changed_secret = grant(&appliance, "directory-user", true).unwrap().1;
        appliance.system.aaa.radius[0].server = "192.0.2.10".into();
        assert_ne!(
            changed_secret,
            grant(&appliance, "directory-user", true).unwrap().1
        );
        appliance.system.aaa.radius.clear();
        assert!(grant(&appliance, "directory-user", true).is_none());
        assert!(grant(&appliance, "admin", true).is_none());
    }
}
