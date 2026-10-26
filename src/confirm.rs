//! `commit-confirm` (roadmap C21): apply a config live, but arm an auto-rollback
//! timer so a change that locks you out of a remote box reverts itself unless you
//! `confirm` it in time. This is the single most important safety net for
//! administering a firewall over the very link it filters.
//!
//! The model fits Sentinel's immutable, daemon-less CLI: each `sentinel`
//! invocation is a fresh process, so the timer can't live inside the shell. It is
//! a **transient systemd timer** (`systemd-run --on-active=<N>min`) that fires
//! `sentinel confirm-rollback`, which re-applies the last *saved* config live.
//!
//! - **rollback target** is the saved config on disk (`DEFAULT_CONFIG` — the
//!   running/boot config), not a fresh snapshot: the new config is applied
//!   *live only* (like a plain `commit`), so the saved file still holds the
//!   previous known-good config until the operator `save`s. Reverting to it is
//!   therefore correct, and — crucially — puts no secret-bearing config copy in
//!   the world-readable runtime tree.
//! - **pending state** is the timer itself (`sentinel-confirm.timer`), so there
//!   is no marker file to leak or get out of sync.

use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::config::Appliance;
use crate::repl::{Apply, apply_live, restore_live};
use crate::session::Session;
use crate::system;

/// The default confirmation window (minutes), matching VyOS's `commit-confirm`.
pub const DEFAULT_CONFIRM_MINUTES: u32 = 10;

/// Apply the candidate live, then arm an auto-rollback timer. The candidate is
/// validated + activated exactly like `commit` (running-only, not persisted);
/// the difference is the armed timer that reverts to the saved config after
/// `minutes` unless [`confirm`] cancels it.
pub fn commit_confirm(session: &mut Session, act: &Apply, minutes: u32) -> Result<()> {
    // Held from the check until the timer is armed. The management transaction
    // (`safe_apply::begin`) takes the same lock and refuses while this timer
    // exists, so the two kinds of provisional change can never be pending at
    // once — otherwise one's rollback would revert the other's change, and
    // one's `confirm` would keep a change its author never verified.
    let _lock = system::apply_lock()?;
    if act.enabled {
        refuse_over_management(Path::new(crate::session::DEFAULT_CONFIG))?;
    }
    let appliance = session.commit()?;
    let summary = format!(
        "{} interface(s), {} rule(s)",
        appliance.interfaces.len(),
        appliance.rules.len()
    );

    if !act.enabled {
        eprintln!("commit-confirm ok (validated): {summary}");
        eprintln!("note: live apply disabled (off-box or --no-apply); no timer armed");
        return Ok(());
    }

    // The revert target is the saved config — the box's current known-good
    // baseline. Without one there is nothing safe to fall back to, so refuse
    // rather than arm a timer that would revert to nothing.
    let cfg_path = session.config_path().to_path_buf();
    if !cfg_path.exists() {
        bail!(
            "commit-confirm needs a saved baseline to revert to — run `save` first, \
             then `commit-confirm`"
        );
    }

    // Clear any prior pending timer so re-arming is clean, then apply live.
    // apply_live rolls its own partial failure back, so on error nothing armed
    // and the previous running config stands.
    system::disarm_confirm();
    // The saved baseline (guaranteed present above) is the last-good target a
    // failed broad apply reconciles back to — the same config the timer reverts
    // to. Loading it can fail for reasons applying it will not (a race on the
    // file); a `None` target just means a partial failure reports mixed-state
    // rather than rolling back, so fall back rather than refusing the commit.
    let last_good = Appliance::load(&cfg_path).ok();
    apply_live(&appliance, act, last_good.as_ref()).context("applying the candidate")?;

    // Arm the auto-rollback. If arming fails we must NOT leave the new config
    // live without protection — revert immediately and surface the failure.
    if let Err(e) = system::arm_confirm(minutes, &cfg_path) {
        // A revert: no last-good to reconcile to (reconciling back to the
        // un-confirmed candidate would defeat it), and a held link that stays
        // dark is reported rather than failing it: `restore_live`.
        let revert = Appliance::load(&cfg_path).and_then(|prev| restore_live(&prev, act));
        return match revert {
            Ok(()) => {
                Err(e).context("arming the rollback timer failed; reverted to the saved config")
            }
            Err(re) => Err(e).context(format!(
                "arming the rollback timer failed AND the immediate revert failed ({re}) \
                 — the box may be on the un-confirmed config with no timer"
            )),
        };
    }

    eprintln!("commit-confirm: {summary}; applied live.");
    eprintln!(
        "  auto-revert to the saved config in {minutes} min — run `confirm` to keep the change \
         (then `save` to persist across reboot)."
    );
    Ok(())
}

/// Refuse a `commit-confirm` while a management (API/console/fleet)
/// transaction is pending, naming it so the operator knows whose it is.
fn refuse_over_management(path: &Path) -> Result<()> {
    if let Some(id) = crate::safe_apply::status(path)?["pending"]["id"].as_str() {
        bail!(
            "management transaction {id} (started from the API or console) is pending; \
             confirm or revert it before `commit-confirm`"
        );
    }
    Ok(())
}

/// Which provisional change a `confirm [id]` keeps.
#[derive(Debug, PartialEq, Eq)]
enum ConfirmTarget {
    /// This shell's own `commit-confirm`.
    CommitConfirm,
    /// The management transaction the operator named.
    Management(String),
    Nothing,
}

/// A bare `confirm` keeps only a `commit-confirm`; a management transaction is
/// kept only when named by its id. Confirming "whatever is pending" would let
/// an SSH operator keep a console change nobody verified, and the transaction
/// id is what the console and `GET /api/v1/config/transaction` show.
fn confirm_target(
    id: Option<&str>,
    commit_confirm_pending: bool,
    management: Option<&str>,
) -> Result<ConfirmTarget> {
    match (id, management) {
        (Some(id), Some(pending)) if id == pending => Ok(ConfirmTarget::Management(id.into())),
        (Some(id), _) => bail!("no management transaction {id} is pending"),
        (None, _) if commit_confirm_pending => Ok(ConfirmTarget::CommitConfirm),
        (None, Some(pending)) => bail!(
            "no commit-confirm is pending; management transaction {pending} was started \
             from the API or console — `confirm {pending}` keeps it"
        ),
        (None, None) => Ok(ConfirmTarget::Nothing),
    }
}

/// Cancel a pending auto-rollback: the live config stays as committed. The
/// operator still needs `save` to persist it across a reboot (VyOS semantics).
/// `confirm <id>` keeps the named management transaction instead.
pub fn confirm(act: &Apply, id: Option<&str>) -> Result<()> {
    let path = Path::new(crate::session::DEFAULT_CONFIG);
    let status = if act.enabled {
        crate::safe_apply::status(path)?
    } else {
        serde_json::Value::Null
    };
    match confirm_target(
        id,
        system::confirm_pending(),
        status["pending"]["id"].as_str(),
    )? {
        ConfirmTarget::Management(id) => {
            crate::safe_apply::confirm(path, &id, act)?;
            eprintln!("confirmed management revision — applied and saved.");
        }
        ConfirmTarget::CommitConfirm => {
            system::disarm_confirm();
            eprintln!("confirmed — change kept (run `save` to persist across reboot).");
        }
        ConfirmTarget::Nothing => eprintln!("no pending commit-confirm (nothing to confirm)."),
    }
    Ok(())
}

/// Revert the running system to the saved config. Run by the auto-rollback timer
/// when a `commit-confirm` window expires, and available manually
/// (`sentinel confirm-rollback` / `run confirm-rollback`) to drop an
/// un-confirmed change immediately. Idempotent: re-applying the saved config
/// live is always safe.
///
/// `from_timer` marks the `commit-confirm` timer's own invocation. It reverts
/// only that change: a management transaction is never its to undo, even if
/// one slipped in while the timer's service was already starting. An operator
/// running it by hand is making an explicit choice and may revert either.
pub fn rollback(act: &Apply, cfg_path: &Path, from_timer: bool) -> Result<()> {
    let _lock = system::apply_lock()?;
    if crate::safe_apply::status(cfg_path)?["pending"].is_object() {
        if from_timer {
            refuse_over_management(cfg_path)
                .context("the commit-confirm window expired, but it cannot be reverted")?;
        }
        crate::safe_apply::recover(cfg_path, act, true, false)?;
        eprintln!("reverted the provisional management revision.");
        return Ok(());
    }
    if !cfg_path.exists() {
        eprintln!(
            "no saved config at {} — nothing to revert to.",
            cfg_path.display()
        );
        return Ok(());
    }
    let appliance = Appliance::load(cfg_path)
        .with_context(|| format!("loading the saved config {}", cfg_path.display()))?;
    // Stop the timer first (it may be the very unit running us) so a revert
    // that itself races a second firing can't loop.
    system::disarm_confirm();
    // A revert to saved: there is no last-good to reconcile a partial failure
    // to (reconciling back to the un-confirmed config would defeat the revert),
    // so a failure here reports mixed-state honestly. A restore, so a held link
    // that stays dark is reported rather than failing the revert.
    restore_live(&appliance, act).context("reverting to the saved config")?;
    eprintln!("reverted the running system to the saved config.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_confirm_never_keeps_a_management_transaction() {
        assert_eq!(
            confirm_target(None, true, None).unwrap(),
            ConfirmTarget::CommitConfirm
        );
        let refused = confirm_target(None, false, Some("abc")).unwrap_err();
        assert!(refused.to_string().contains("confirm abc"), "{refused}");
        assert_eq!(
            confirm_target(Some("abc"), false, Some("abc")).unwrap(),
            ConfirmTarget::Management("abc".into())
        );
        assert!(confirm_target(Some("stale"), false, Some("abc")).is_err());
        assert!(confirm_target(Some("abc"), true, None).is_err());
        assert_eq!(
            confirm_target(None, false, None).unwrap(),
            ConfirmTarget::Nothing
        );
    }

    #[test]
    fn the_commit_confirm_timer_never_reverts_a_management_transaction() {
        let mut nonce = [0u8; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "sentinel-confirm-{}-{:x}",
            std::process::id(),
            u64::from_ne_bytes(nonce)
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("appliance.toml");
        std::fs::write(&path, "[system]\nhostname = \"working\"\n").unwrap();
        let candidate = Appliance::from_toml("[system]\nhostname=\"api\"\n").unwrap();
        crate::safe_apply::begin(&path, &candidate, &Apply::off(), 60).unwrap();
        // Refused before it touches systemd or the journal.
        let refused = rollback(&Apply::off(), &path, true).unwrap_err();
        assert!(
            format!("{refused:#}").contains("management transaction"),
            "{refused:#}"
        );
        assert!(crate::safe_apply::status(&path).unwrap()["pending"].is_object());
        assert_eq!(Appliance::load(&path).unwrap().system.hostname, "api");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
