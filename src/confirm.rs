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
use crate::repl::{Apply, apply_live};
use crate::session::Session;
use crate::system;

/// The default confirmation window (minutes), matching VyOS's `commit-confirm`.
pub const DEFAULT_CONFIRM_MINUTES: u32 = 10;

/// Apply the candidate live, then arm an auto-rollback timer. The candidate is
/// validated + activated exactly like `commit` (running-only, not persisted);
/// the difference is the armed timer that reverts to the saved config after
/// `minutes` unless [`confirm`] cancels it.
pub fn commit_confirm(session: &mut Session, act: &Apply, minutes: u32) -> Result<()> {
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
    apply_live(&appliance, act).context("applying the candidate")?;

    // Arm the auto-rollback. If arming fails we must NOT leave the new config
    // live without protection — revert immediately and surface the failure.
    if let Err(e) = system::arm_confirm(minutes, &cfg_path) {
        let revert = Appliance::load(&cfg_path).and_then(|prev| apply_live(&prev, act));
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

/// Cancel a pending auto-rollback: the live config stays as committed. The
/// operator still needs `save` to persist it across a reboot (VyOS semantics).
pub fn confirm(_act: &Apply) -> Result<()> {
    if !system::confirm_pending() {
        eprintln!("no pending commit-confirm (nothing to confirm).");
        return Ok(());
    }
    system::disarm_confirm();
    eprintln!("confirmed — change kept (run `save` to persist across reboot).");
    Ok(())
}

/// Revert the running system to the saved config. Run by the auto-rollback timer
/// when a `commit-confirm` window expires, and available manually
/// (`sentinel confirm-rollback` / `run confirm-rollback`) to drop an
/// un-confirmed change immediately. Idempotent: re-applying the saved config
/// live is always safe.
pub fn rollback(act: &Apply, cfg_path: &Path) -> Result<()> {
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
    apply_live(&appliance, act).context("reverting to the saved config")?;
    eprintln!("reverted the running system to the saved config.");
    Ok(())
}
