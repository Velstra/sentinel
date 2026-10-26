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
    let group =
        login
            .and_then(|l| l.group.as_deref())
            .or(appliance.system.aaa.default_group.as_deref())?;
    let permission = appliance
        .system
        .groups
        .iter()
        .find(|g| g.name == group)?
        .permission;
    let material = serde_json::json!({
        "user": user,
        "login": login.is_some(),
        "hashed-password": login.and_then(|l| l.hashed_password.as_deref()),
        "totp": login.and_then(|l| l.totp.as_deref()),
        "own-group": login.and_then(|l| l.group.as_deref()),
        "group": group,
        "permission": permission,
        "directory": directory && appliance.system.aaa.has_servers(),
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
    write_record(dir, &record, true)?;
    Ok(token)
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
    // A clock that has gone backwards past the sign-in is not a reason to trust
    // a session longer; `saturating_sub` reads it as zero elapsed, and the
    // lifetime still runs from `created` once time moves forward again.
    if now.saturating_sub(record.last_used) > IDLE || now.saturating_sub(record.created) > LIFETIME
    {
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
