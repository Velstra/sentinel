//! Durable commit-confirm for management writes. The recovery timer is a
//! separate systemd service: killing/restarting the HTTP server cannot cancel
//! it. An unconfirmed revision is also recovered before boot reconciliation.
use std::{
    cell::Cell,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    config::Appliance,
    repl::{self, Apply},
    session, system,
};

thread_local! { static INTERNAL: Cell<bool> = const { Cell::new(false) }; }

fn internal<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            INTERNAL.with(|v| v.set(self.0));
        }
    }
    let _reset = Reset(INTERNAL.with(|v| v.replace(true)));
    f()
}

fn journal(path: &Path) -> PathBuf {
    path.with_file_name(format!(
        ".{}.pending.json",
        path.file_name().unwrap_or_default().to_string_lossy()
    ))
}

#[derive(Serialize, Deserialize)]
struct Pending {
    version: u32,
    id: String,
    boot: String,
    deadline_ms: u64,
    saved: String,
    running: String,
    candidate_revision: String,
    candidate: String,
    timeout_seconds: u32,
    ready: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum OutcomeKind {
    Confirmed,
    Reverted,
    ApplyFailed,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Outcome {
    id: String,
    revision: String,
    outcome: OutcomeKind,
    at: u64,
}
fn outcome_path(path: &Path) -> PathBuf {
    path.with_file_name(format!(
        ".{}.result.json",
        path.file_name().unwrap_or_default().to_string_lossy()
    ))
}
fn last_outcome(path: &Path) -> Option<Outcome> {
    system::read_owned_file(&outcome_path(path))
        .ok()
        .flatten()
        .and_then(|text| serde_json::from_str(&text).ok())
}
fn record_outcome(path: &Path, pending: &Pending, outcome: OutcomeKind) {
    let receipt = Outcome {
        id: pending.id.clone(),
        revision: pending.candidate_revision.clone(),
        outcome,
        at: crate::aaa::unix_now(),
    };
    // Receipt failure must never undo a completed confirmation or recovery.
    if let Err(error) = serde_json::to_string(&receipt)
        .map_err(anyhow::Error::from)
        .and_then(|text| system::install_ha_secret(&outcome_path(path), &text))
    {
        eprintln!("warning: recording configuration outcome: {error:#}");
    }
}

fn boot() -> Result<String> {
    Ok(std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .into())
}
fn now_ms() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // CLOCK_BOOTTIME counts suspend and cannot be moved by NTP or an operator.
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) },
        0
    );
    ts.tv_sec as u64 * 1000 + ts.tv_nsec as u64 / 1_000_000
}

fn read(path: &Path) -> Result<Option<Pending>> {
    let Some(text) = system::read_owned_file(&journal(path))? else {
        return Ok(None);
    };
    let pending: Pending =
        serde_json::from_str(&text).context("reading pending configuration transaction")?;
    ensure!(
        pending.version == 1,
        "unsupported pending configuration journal"
    );
    Ok(Some(pending))
}
fn write(path: &Path, pending: &Pending) -> Result<()> {
    system::install_ha_secret(&journal(path), &serde_json::to_string(pending)?)
}
fn clear(path: &Path) -> Result<()> {
    system::remove_file(&journal(path))?;
    std::fs::File::open(
        path.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()?;
    Ok(())
}

/// Every CLI/API writer cooperates; a save must never replace the rollback
/// target, nor may a concurrent commit silently invalidate its confirmation.
pub fn ensure_writable(path: &Path) -> Result<()> {
    if !INTERNAL.with(Cell::get) {
        ensure!(
            read(path)?.is_none(),
            "configuration confirmation pending; confirm or revert it before another write"
        );
    }
    Ok(())
}

fn public(p: &Pending) -> Value {
    json!({"id":p.id,"revision":p.candidate_revision,"ready":p.ready,
        "reverting":p.deadline_ms==0,"timeout_seconds":p.timeout_seconds,"remaining_seconds":p.deadline_ms.saturating_sub(now_ms()).div_ceil(1000)})
}

pub fn status(path: &Path) -> Result<Value> {
    // Journal replacement is atomic. Reading it must not wait for an apply's
    // lock: the replacement API needs to report progress while the worker owns
    // network reconciliation.
    Ok(json!({"pending":read(path)?.as_ref().map(public),"last_result":last_outcome(path)}))
}

/// Snapshot and journal BEFORE applying. Recovery is armed before any network
/// mutation, and the final confirmation window starts after reconciliation.
pub fn begin(path: &Path, candidate: &Appliance, act: &Apply, seconds: u32) -> Result<Value> {
    begin_with(path, candidate, act, seconds, |next, previous| {
        if act.enabled {
            repl::apply_live(next, act, previous)?;
        }
        Ok(())
    })
}

fn begin_with(
    path: &Path,
    candidate: &Appliance,
    act: &Apply,
    seconds: u32,
    apply: impl FnOnce(&Appliance, Option<&Appliance>) -> Result<()>,
) -> Result<Value> {
    ensure!(
        (1..=3600).contains(&seconds),
        "confirmation timeout must be 1–3600 seconds"
    );
    candidate.validate()?;
    let _lock = system::apply_lock()?;
    let _file = system::lock_config_at(&path.with_extension("transaction.lock"))?;
    ensure_writable(path)?;
    let saved = system::read_owned_file(path)?.context("safe apply requires a saved baseline")?;
    Appliance::from_toml(&saved).context("validating the rollback baseline")?;
    let running = if act.enabled {
        session::Session::running_snapshot().unwrap_or_else(|| saved.clone())
    } else {
        saved.clone()
    };
    let previous = Appliance::from_toml(&running)?;
    if act.enabled {
        let out = std::process::Command::new(system::bin("systemctl"))
            .args(["is-active", "sentinel-apply-recovery.timer"])
            .output()?;
        ensure!(
            out.status.success(),
            "independent configuration recovery timer is not active; refusing unsafe apply"
        );
    }
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).map_err(|e| anyhow::anyhow!("transaction identity: {e}"))?;
    let mut pending = Pending {
        version: 1,
        id: nonce.iter().map(|b| format!("{b:02x}")).collect(),
        boot: boot()?,
        deadline_ms: now_ms()
            + if act.enabled {
                180_000
            } else {
                u64::from(seconds) * 1000
            },
        saved,
        running,
        candidate_revision: crate::ha::revision(candidate)?,
        candidate: candidate.to_toml()?,
        timeout_seconds: seconds,
        ready: false,
    };
    write(path, &pending)?;
    if act.enabled {
        // The API can restart itself (port/TLS changes) without terminating the
        // operation. Only the independent unit may mark the revision ready.
        if let Err(error) = launch_worker(path, &pending.id) {
            recover(path, &Apply::off(), true, true)?;
            return Err(error);
        }
        return Ok(
            json!({"accepted":true,"applied":false,"saved":false,"pending":public(&pending)}),
        );
    }
    complete_with(path, &mut pending, candidate, act, |next| {
        apply(next, Some(&previous))
    })?;
    Ok(json!({"applied":false,"saved":true,"pending":public(&pending)}))
}

fn launch_worker(path: &Path, id: &str) -> Result<()> {
    let mut args = vec![
        format!("--unit=sentinel-provisional-{}", &id[..16]),
        "--collect".into(),
        "--property=Type=exec".into(),
        "--property=RuntimeMaxSec=180s".into(),
        "--property=KillMode=control-group".into(),
    ];
    if let Some(path) = std::env::var_os("PATH") {
        args.push(format!("--setenv=PATH={}", path.to_string_lossy()));
    }
    for (key, value) in
        std::env::vars().filter(|(key, _)| key.starts_with("SENTINEL_") && key.ends_with("_BIN"))
    {
        args.push(format!("--setenv={key}={value}"));
    }
    args.extend([
        system::bin("sentinel-self"),
        "apply-pending".into(),
        "--config".into(),
        path.to_str().context("non-UTF-8 config path")?.into(),
        "--id".into(),
        id.into(),
    ]);
    let refs: Vec<_> = args.iter().map(String::as_str).collect();
    let output = system::escalated_output("systemd-run", &refs)?;
    ensure!(
        output.status.success(),
        "starting independent configuration worker: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn complete_with(
    path: &Path,
    pending: &mut Pending,
    candidate: &Appliance,
    act: &Apply,
    apply: impl FnOnce(&Appliance) -> Result<()>,
) -> Result<()> {
    internal(|| {
        // Services restarted by reconciliation must read the proposed desired
        // document, including its new TLS settings. The journal protects the
        // exact saved bytes throughout this provisional publication.
        session::persist_appliance(candidate, path, false)?;
        apply(candidate).context("applying the provisional configuration")?;
        if act.enabled {
            system::install_config_file(
                Path::new(session::Session::RUNNING),
                &candidate.to_toml()?,
            )?;
        }
        pending.deadline_ms = now_ms() + u64::from(pending.timeout_seconds) * 1000;
        pending.ready = true;
        write(path, pending)
    })
}

pub fn apply_pending(path: &Path, id: &str, act: &Apply) -> Result<()> {
    let _lock = system::apply_lock()?;
    let _file = system::lock_config_at(&path.with_extension("transaction.lock"))?;
    let mut pending = read(path)?.context("provisional configuration no longer pending")?;
    ensure!(
        pending.id == id
            && !pending.ready
            && pending.boot == boot()?
            && now_ms() < pending.deadline_ms,
        "stale or expired provisional worker"
    );
    let candidate = Appliance::from_toml(&pending.candidate)?;
    ensure!(
        crate::ha::revision(&candidate)? == pending.candidate_revision,
        "provisional journal revision mismatch"
    );
    let previous = Appliance::from_toml(&pending.running)?;
    if let Err(error) = complete_with(path, &mut pending, &candidate, act, |next| {
        repl::apply_live(next, act, Some(&previous))
    }) {
        pending.deadline_ms = 0;
        let _ = write(path, &pending);
        record_outcome(path, &pending, OutcomeKind::ApplyFailed);
        return match recover(path, act, true, false) {
            Ok(_) => Err(error)
                .context("provisional apply failed; previous working configuration restored"),
            Err(recovery) => Err(error).context(format!(
                "provisional apply failed and recovery requires retry: {recovery:#}"
            )),
        };
    }
    Ok(())
}

pub fn confirm(path: &Path, id: &str, act: &Apply) -> Result<Value> {
    let _lock = system::apply_lock()?;
    let _file = system::lock_config_at(&path.with_extension("transaction.lock"))?;
    let pending = match read(path)? {
        Some(pending) => pending,
        None => {
            if let Some(receipt) = last_outcome(path)
                .filter(|receipt| receipt.id == id && receipt.outcome == OutcomeKind::Confirmed)
            {
                ensure!(
                    crate::ha::revision(&Appliance::load(path)?)? == receipt.revision,
                    "the confirmed revision has been superseded"
                );
                return Ok(json!({"confirmed":true,"revision":receipt.revision}));
            }
            anyhow::bail!("no configuration confirmation is pending");
        }
    };
    ensure!(pending.id == id, "stale configuration confirmation");
    ensure!(
        pending.ready && pending.boot == boot()? && now_ms() < pending.deadline_ms,
        "configuration confirmation expired or apply has not completed"
    );
    let candidate = Appliance::load(path)?;
    ensure!(
        crate::ha::revision(&candidate)? == pending.candidate_revision,
        "configuration changed outside the pending transaction"
    );
    let previous = Appliance::from_toml(&pending.saved)?;
    // Queue the durable HA outbox before removing recovery protection. The
    // worker shares apply.lock, so it cannot publish until this commit returns.
    if act.enabled {
        crate::configsync::enqueue(&candidate, Some(&previous))?;
    }
    clear(path)?;
    record_outcome(path, &pending, OutcomeKind::Confirmed);
    let keep = candidate
        .system
        .commit_revisions
        .map(|n| n as usize)
        .unwrap_or(crate::archive::ARCHIVE_KEEP);
    if let Err(error) = crate::archive::archive_config(path, &candidate.to_toml()?, keep) {
        eprintln!("warning: archiving confirmed revision: {error:#}");
    }
    Ok(json!({"confirmed":true,"revision":pending.candidate_revision}))
}

pub fn revert(path: &Path, id: &str, act: &Apply) -> Result<bool> {
    let _lock = system::apply_lock()?;
    let _file = system::lock_config_at(&path.with_extension("transaction.lock"))?;
    let mut pending = match read(path)? {
        Some(pending) => pending,
        None => {
            ensure!(
                last_outcome(path).is_some_and(
                    |receipt| receipt.id == id && receipt.outcome != OutcomeKind::Confirmed
                ),
                "stale configuration transaction"
            );
            return Ok(true);
        }
    };
    ensure!(pending.id == id, "stale configuration transaction");
    if act.enabled {
        // A reverse port/TLS change can terminate this API too. Persist the
        // request, then let the independent recovery unit finish it.
        pending.deadline_ms = 0;
        pending.ready = false;
        write(path, &pending)?;
        return Ok(false);
    }
    recover(path, act, true, false)
}

/// On boot, restore the canonical saved document before any service renders
/// it. During normal operation reconcile the exact previous running snapshot.
pub fn recover(path: &Path, act: &Apply, force: bool, booting: bool) -> Result<bool> {
    recover_with(path, act, force, booting, |next| {
        if act.enabled {
            repl::apply_live(next, act, None)?;
        }
        Ok(())
    })
}
fn recover_with(
    path: &Path,
    act: &Apply,
    force: bool,
    booting: bool,
    apply: impl FnOnce(&Appliance) -> Result<()>,
) -> Result<bool> {
    let _lock = system::apply_lock()?;
    let _file = system::lock_config_at(&path.with_extension("transaction.lock"))?;
    let Some(pending) = read(path)? else {
        return Ok(false);
    };
    if !force && !booting && pending.boot == boot()? && now_ms() < pending.deadline_ms {
        return Ok(false);
    }
    internal(|| {
        system::install_config_file(path, &pending.saved)?;
        if !booting {
            let previous = Appliance::from_toml(&pending.running)?;
            apply(&previous).context("restoring the previous working network configuration")?;
            if act.enabled {
                system::install_config_file(
                    Path::new(session::Session::RUNNING),
                    &pending.running,
                )?;
            }
        }
        clear(path)
    })?;
    if !last_outcome(path).is_some_and(|receipt| {
        receipt.id == pending.id && receipt.outcome == OutcomeKind::ApplyFailed
    }) {
        record_outcome(path, &pending, OutcomeKind::Reverted);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn fixture() -> PathBuf {
        let mut nonce = [0u8; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "sentinel-safe-{}-{:x}",
            std::process::id(),
            u64::from_ne_bytes(nonce)
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("appliance.toml");
        std::fs::write(
            &path,
            "# working baseline\n[system]\nhostname = \"working\"\n",
        )
        .unwrap();
        path
    }
    fn next() -> Appliance {
        Appliance::from_toml("[system]\nhostname=\"provisional\"\n").unwrap()
    }
    #[test]
    fn unconfirmed_revision_restores_exact_saved_bytes_and_runtime() {
        let path = fixture();
        let original = std::fs::read(&path).unwrap();
        begin(&path, &next(), &Apply::off(), 60).unwrap();
        assert!(ensure_writable(&path).is_err());
        assert!(session::persist_appliance(&next(), &path, false).is_err());
        assert_eq!(
            std::fs::metadata(journal(&path))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(!recover(&path, &Apply::off(), false, false).unwrap());
        let mut p = read(&path).unwrap().unwrap();
        p.deadline_ms = 0;
        write(&path, &p).unwrap();
        let mut restored = false;
        assert!(
            recover_with(&path, &Apply::off(), false, false, |a| {
                assert_eq!(a.system.hostname, "working");
                restored = true;
                Ok(())
            })
            .unwrap()
        );
        assert!(restored);
        assert_eq!(status(&path).unwrap()["last_result"]["outcome"], "reverted");
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(ensure_writable(&path).is_ok());
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
    #[test]
    fn confirmation_is_bound_to_the_revision_and_deadline() {
        let path = fixture();
        let r = begin(&path, &next(), &Apply::off(), 60).unwrap();
        assert!(confirm(&path, "stale", &Apply::off()).is_err());
        assert!(begin(&path, &next(), &Apply::off(), 60).is_err());
        let id = r["pending"]["id"].as_str().unwrap();
        confirm(&path, id, &Apply::off()).unwrap();
        assert_eq!(
            status(&path).unwrap()["last_result"]["outcome"],
            "confirmed"
        );
        confirm(&path, id, &Apply::off()).unwrap();
        assert!(!recover(&path, &Apply::off(), true, false).unwrap());
        assert_eq!(
            Appliance::load(&path).unwrap().system.hostname,
            "provisional"
        );
        let r = begin(&path, &next(), &Apply::off(), 60).unwrap();
        let mut p = read(&path).unwrap().unwrap();
        p.deadline_ms = 0;
        write(&path, &p).unwrap();
        assert!(confirm(&path, r["pending"]["id"].as_str().unwrap(), &Apply::off()).is_err());
        recover(&path, &Apply::off(), true, false).unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
    #[test]
    fn failed_apply_and_failed_recovery_retain_durable_protection() {
        let path = fixture();
        assert!(
            begin_with(&path, &next(), &Apply::off(), 60, |_, _| anyhow::bail!(
                "failed network apply"
            ))
            .is_err()
        );
        assert!(read(&path).unwrap().is_some());
        assert!(
            recover_with(&path, &Apply::off(), true, false, |_| anyhow::bail!(
                "retry me"
            ))
            .is_err()
        );
        assert!(read(&path).unwrap().is_some());
        recover(&path, &Apply::off(), true, false).unwrap();
        assert_eq!(Appliance::load(&path).unwrap().system.hostname, "working");
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
    #[test]
    fn reboot_never_boots_an_unconfirmed_revision() {
        let path = fixture();
        begin(&path, &next(), &Apply::off(), 3600).unwrap();
        assert!(
            recover_with(&path, &Apply::off(), false, true, |_| panic!(
                "boot must render after recovery, never apply live here"
            ))
            .unwrap()
        );
        assert_eq!(Appliance::load(&path).unwrap().system.hostname, "working");
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
