//! `commit-confirm` (roadmap C21): apply a config live, but arm an auto-rollback
//! timer so a change that locks you out of a remote box reverts itself unless you
//! `confirm` it in time. This is the single most important safety net for
//! administering a firewall over the very link it filters.
//!
//! The model fits Sentinel's immutable, daemon-less CLI: each `sentinel`
//! invocation is a fresh process, so the timer can't live inside the shell. It is
//! a **transient systemd timer**, armed BEFORE live mutation. It restores a
//! root-private, atomically persisted snapshot of the previous active intent,
//! including unsaved commits. The saved boot configuration is not changed.
//! This closes the apply-before-arm crash window, but is not the API's durable
//! transaction journal: reboot still restores the saved boot configuration.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};

use crate::config::Appliance;
use crate::repl::{Apply, apply_live, restore_live};
use crate::session::Session;
use crate::system;

/// The default confirmation window (minutes), matching VyOS's `commit-confirm`.
pub const DEFAULT_CONFIRM_MINUTES: u32 = 10;
const FAILED_RECOVERY: &str = "commit-confirm recovery failed; run `sentinel confirm-rollback` to retry the retained rollback service, or reboot to apply the saved configuration";

/// Arm protection, then apply the candidate live. The candidate is
/// validated + activated exactly like `commit` (running-only, not persisted);
/// the difference is the armed timer that reverts to the previous active intent after
/// `minutes` unless [`confirm`] cancels it.
pub fn commit_confirm(session: &mut Session, act: &Apply, minutes: u32) -> Result<()> {
    ensure!(
        minutes > 0,
        "commit-confirm needs a positive confirmation window"
    );
    // Held from the check until the timer is armed. The management transaction
    // (`safe_apply::begin`) takes the same lock and refuses while this timer
    // exists, so the two kinds of provisional change can never be pending at
    // once — otherwise one's rollback would revert the other's change, and
    // one's `confirm` would keep a change its author never verified.
    let _lock = system::apply_lock()?;
    if act.enabled {
        session.ensure_current()?;
        refuse_over_management(Path::new(crate::session::DEFAULT_CONFIG))?;
        let state = confirmation_state()?;
        ensure!(state != ConfirmationState::Failed, FAILED_RECOVERY);
        ensure!(
            state == ConfirmationState::Idle,
            "a commit-confirm or its rollback is already pending; confirm or revert it before another commit-confirm"
        );
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

    let cfg_path = session
        .config_path()
        .canonicalize()
        .context("resolving the saved configuration for independent rollback")?;
    refuse_over_management(&cfg_path)?;
    // Both baselines must be readable and valid BEFORE mutation: saved bytes
    // remain the boot fallback, while unsaved running intent is the live undo.
    let previous = previous_active(&cfg_path, Path::new(Session::RUNNING))?;
    // Recheck the exact protected undo baseline before writing its snapshot,
    // advancing the mutation epoch, or arming a timer. Session admission also
    // covers the validation-only branch above.
    crate::admission::check(Some(&previous), &appliance)?;
    let rollback_path = snapshot_path(&cfg_path);
    let previous_toml = previous.to_toml()?;
    crate::mutation::advance()?;
    protected_apply(
        || system::install_ha_secret(&rollback_path, &previous_toml),
        || {
            system::arm_confirm(minutes, &rollback_path, &cfg_path)?;
            ensure!(
                confirmation_state()? == ConfirmationState::Armed,
                "independent rollback timer is not armed"
            );
            Ok(())
        },
        || apply_live(&appliance, act, Some(&previous)),
        || session.note_committed(&appliance.to_toml()?),
    )?;

    eprintln!("commit-confirm: {summary}; applied live.");
    eprintln!(
        "  auto-revert to the previous active config within {minutes} min of starting apply — run `confirm` to keep the change \
         (then `save` to persist across reboot)."
    );
    Ok(())
}

fn snapshot_path(config: &Path) -> PathBuf {
    config.with_file_name(format!(
        ".{}.commit-confirm.toml",
        config.file_name().unwrap_or_default().to_string_lossy()
    ))
}

fn previous_active(saved: &Path, running: &Path) -> Result<Appliance> {
    let baseline = system::read_owned_regular(saved, 64 * 1024 * 1024)?
        .context("commit-confirm needs a valid saved boot baseline; run `save` first")?;
    // Read as boot reads it (CTRL-08): a value a later update refuses must not
    // block the commit that fixes it; reverting restores this file, which boots.
    let saved =
        Appliance::saved_lenient(saved, &baseline).context("validating the saved boot baseline")?;
    match Session::read_running_at(running)? {
        Some(text) => {
            Appliance::from_toml(&text).context("validating the previous active configuration")
        }
        None => Ok(saved),
    }
}

/// No cleanup on failure: once armed, independent recovery remains responsible
/// even if apply partly fails, publication fails, or the caller is killed.
fn protected_apply(
    snapshot: impl FnOnce() -> Result<()>,
    arm: impl FnOnce() -> Result<()>,
    apply: impl FnOnce() -> Result<()>,
    publish: impl FnOnce() -> Result<()>,
) -> Result<()> {
    snapshot().context("saving the private rollback baseline; candidate not applied")?;
    arm().context("arming independent rollback failed; candidate not applied")?;
    apply().context("applying the candidate failed; rollback protection remains armed")?;
    publish().context("candidate applied and rollback armed, but recording active intent failed")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConfirmationState {
    Idle,
    Armed,
    Reverting,
    Failed,
}

fn decode_confirmation_state(output: &str) -> Result<ConfirmationState> {
    let states: Vec<_> = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    ensure!(
        states.len() == 2,
        "cannot determine commit-confirm timer and rollback state"
    );
    for state in &states {
        ensure!(
            [
                "active",
                "activating",
                "deactivating",
                "reloading",
                "inactive",
                "failed"
            ]
            .contains(state),
            "unrecognized commit-confirm unit state"
        );
    }
    let active = |state: &str| !matches!(state, "inactive" | "failed");
    Ok(if active(states[1]) {
        ConfirmationState::Reverting
    } else if states.contains(&"failed") {
        ConfirmationState::Failed
    } else if active(states[0]) {
        ConfirmationState::Armed
    } else {
        ConfirmationState::Idle
    })
}

fn confirmation_state() -> Result<ConfirmationState> {
    let output = std::process::Command::new(system::bin("systemctl"))
        .args([
            "show",
            "--property=ActiveState",
            "--value",
            &format!("{}.timer", system::CONFIRM_UNIT),
            &format!("{}.service", system::CONFIRM_UNIT),
        ])
        .output()
        .context("reading commit-confirm unit state")?;
    ensure!(
        output.status.success(),
        "cannot inspect commit-confirm unit state"
    );
    decode_confirmation_state(std::str::from_utf8(&output.stdout)?)
}

fn require_worker_pid(value: &str, current: u32) -> Result<()> {
    let pid = value
        .trim()
        .parse::<u32>()
        .context("invalid rollback service MainPID")?;
    ensure!(
        pid != 0 && pid == current,
        "--commit-confirm is reserved for the systemd-owned rollback worker; use confirm-rollback without that flag"
    );
    Ok(())
}

fn require_rollback_worker() -> Result<()> {
    // arm_confirm starts the executable directly with Type=exec. MainPID is
    // supplied by PID1, unlike caller-controlled flags or INVOCATION_ID.
    let output = std::process::Command::new(system::bin("systemctl"))
        .args([
            "show",
            "--property=MainPID",
            "--value",
            &format!("{}.service", system::CONFIRM_UNIT),
        ])
        .output()
        .context("reading rollback service ownership")?;
    ensure!(
        output.status.success(),
        "cannot verify rollback service ownership"
    );
    require_worker_pid(std::str::from_utf8(&output.stdout)?, std::process::id())
}

/// An automatic console refresh may defer a recognized trial/recovery without
/// creating a failing service loop. Unknown PID1 state remains an error; it is
/// never evidence that protected intent can safely be replayed.
pub(crate) fn automatic_reapply_pending() -> Result<bool> {
    Ok(confirmation_state()? != ConfirmationState::Idle)
}

/// Schedule/feed enforcement may legitimately refresh a still-armed candidate.
/// A restoring or failed rollback instead means actual live state may differ
/// from RUNNING; it must not be overwritten by an unattended candidate replay.
pub(crate) fn automatic_firewall_refresh_blocked() -> Result<bool> {
    firewall_refresh_blocked_with(confirmation_state)
}

fn firewall_refresh_blocked_with(
    state: impl FnOnce() -> Result<ConfirmationState>,
) -> Result<bool> {
    Ok(matches!(
        state()?,
        ConfirmationState::Reverting | ConfirmationState::Failed
    ))
}

/// Caller holds apply.lock. Offline editing without an appliance runtime does
/// not require PID 1; on an appliance even --no-apply save must preserve trial
/// protection. No ordinary write implicitly confirms another operation.
pub(crate) fn ensure_idle_for_write(live: bool) -> Result<()> {
    admit_write(
        live,
        Path::new("/run/sentinel").is_dir(),
        confirmation_state,
    )
}

fn admit_write(
    live: bool,
    appliance: bool,
    state: impl FnOnce() -> Result<ConfirmationState>,
) -> Result<()> {
    if live || appliance {
        let state = state()?;
        ensure!(state != ConfirmationState::Failed, FAILED_RECOVERY);
        ensure!(
            state == ConfirmationState::Idle,
            "commit-confirm or its rollback is pending; explicitly confirm or revert it before another write"
        );
    }
    Ok(())
}

fn original_configuration(
    config: &Path,
    from_timer: bool,
    original: Option<&Path>,
) -> Result<PathBuf> {
    let Some(original) = original else {
        // Old timers pass the original configuration, whose legitimate name
        // can itself look like a snapshot. Never infer metadata from a name.
        return Ok(config.to_path_buf());
    };
    ensure!(
        from_timer
            && original.is_absolute()
            && config.is_absolute()
            && snapshot_path(original) == config,
        "invalid commit-confirm original configuration metadata"
    );
    Ok(original.to_path_buf())
}

fn cancel_confirmation(
    disarm: impl FnOnce(),
    state: impl FnOnce() -> Result<ConfirmationState>,
) -> Result<()> {
    disarm();
    let state = state()?;
    ensure!(state != ConfirmationState::Failed, FAILED_RECOVERY);
    ensure!(
        state == ConfirmationState::Idle,
        "commit-confirm could not be cancelled or rollback is already running; change was not confirmed"
    );
    Ok(())
}

fn schedule_rollback(
    start: impl FnOnce() -> Result<()>,
    state: impl FnOnce() -> Result<ConfirmationState>,
    disarm_timer: impl FnOnce(),
) -> Result<()> {
    // A Type=exec service acknowledges start before taking apply.lock. The
    // caller releases that lock only after verifying that recovery is queued;
    // this is not a claim that restoration has already completed.
    start().context("starting the bound rollback service; protection remains")?;
    ensure!(
        state()? == ConfirmationState::Reverting,
        "bound rollback did not enter recovery; protection remains"
    );
    // The recovery child cannot take apply.lock until our caller releases it.
    // Do not stop the timer before both start acknowledgement and the active
    // service check: a launch failure must leave the original deadline armed.
    disarm_timer();
    Ok(())
}

fn finish_restore(
    restore: impl FnOnce() -> Result<()>,
    publish: impl FnOnce() -> Result<()>,
    disarm: impl FnOnce(),
) -> Result<()> {
    restore()?;
    publish()?;
    disarm();
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
    let _lock = system::apply_lock()?;
    if !act.enabled {
        // Portable confirmation is a no-op, not a way to hide a failed or
        // pending appliance trial by passing --no-apply.
        ensure_idle_for_write(false)?;
    }
    let path = Path::new(crate::session::DEFAULT_CONFIG);
    let status = if act.enabled {
        crate::safe_apply::status(path)?
    } else {
        serde_json::Value::Null
    };
    let state = if act.enabled {
        confirmation_state()?
    } else {
        ConfirmationState::Idle
    };
    ensure!(state != ConfirmationState::Failed, FAILED_RECOVERY);
    ensure!(
        state != ConfirmationState::Reverting,
        "commit-confirm rollback is already running; the change cannot be confirmed"
    );
    match confirm_target(
        id,
        state == ConfirmationState::Armed,
        status["pending"]["id"].as_str(),
    )? {
        ConfirmTarget::Management(id) => {
            crate::safe_apply::confirm(path, &id, act)?;
            eprintln!("confirmed management revision — applied and saved.");
        }
        ConfirmTarget::CommitConfirm => {
            if act.enabled {
                crate::mutation::advance()?;
            }
            cancel_confirmation(system::disarm_confirm, confirmation_state)?;
            eprintln!("confirmed — change kept (run `save` to persist across reboot).");
        }
        ConfirmTarget::Nothing => eprintln!("no pending commit-confirm (nothing to confirm)."),
    }
    Ok(())
}

/// Revert the running system to its rollback baseline. Run by the auto-rollback timer
/// when a `commit-confirm` window expires, and available manually
/// (`sentinel confirm-rollback` / `run confirm-rollback`) to drop an
/// un-confirmed change immediately. A pending CLI trial schedules its exact
/// bound service; the queued message does not claim restoration has completed.
/// With no trial, manually restore the selected saved configuration instead.
///
/// `from_timer` marks the `commit-confirm` timer's own invocation. It reverts
/// only that change: a management transaction is never its to undo, even if
/// one slipped in while the timer's service was already starting. An operator
/// running it by hand is making an explicit choice and may revert either.
pub fn rollback(
    act: &Apply,
    cfg_path: &Path,
    from_timer: bool,
    original: Option<&Path>,
) -> Result<()> {
    let _lock = system::apply_lock()?;
    let original = original_configuration(cfg_path, from_timer, original)?;
    // New timers receive a snapshot path, but an independent management
    // journal belongs to the ORIGINAL configuration. Also protect the product
    // default when a custom path targets the same running appliance.
    if from_timer && original != Path::new(crate::session::DEFAULT_CONFIG) {
        refuse_over_management(Path::new(crate::session::DEFAULT_CONFIG))?;
    }
    if crate::safe_apply::status(&original)?["pending"].is_object() {
        if from_timer {
            refuse_over_management(&original)
                .context("the commit-confirm window expired, but it cannot be reverted")?;
        }
        crate::safe_apply::recover(&original, act, true, false)?;
        eprintln!("reverted the provisional management revision.");
        return Ok(());
    }
    // A pending trial belongs to the retained service's exact ExecStart, not
    // the manual caller's --config (which may be the unrelated default). New
    // timers name their private snapshot directly; old timers retain their
    // original saved-path interpretation. Never guess from leftover snapshots.
    let state = if !from_timer && act.enabled {
        confirmation_state()?
    } else {
        ConfirmationState::Idle
    };
    ensure!(
        state != ConfirmationState::Reverting,
        "commit-confirm rollback is already running; wait for restoration to finish"
    );
    if matches!(state, ConfirmationState::Armed | ConfirmationState::Failed) {
        schedule_rollback(
            || system::service_start(&format!("{}.service", system::CONFIRM_UNIT)),
            confirmation_state,
            system::disarm_confirm,
        )?;
        let operation = if state == ConfirmationState::Failed {
            "failed rollback retry"
        } else {
            "rollback"
        };
        eprintln!("{operation} scheduled; writes stay blocked until restoration succeeds.");
        return Ok(());
    }
    if from_timer {
        require_rollback_worker()?;
    }
    let text = system::read_owned_regular(cfg_path, 64 * 1024 * 1024)?;
    let Some(text) = text else {
        eprintln!(
            "no saved config at {} — nothing to revert to.",
            cfg_path.display()
        );
        return Ok(());
    };
    let appliance = Appliance::from_toml(&text)
        .with_context(|| format!("loading the saved config {}", cfg_path.display()))?;
    if !from_timer {
        // With no protected trial, --config selects a new policy, not an
        // owned rollback baseline. Never grandfather it against itself.
        crate::admission::check_saved(
            Path::new(crate::session::DEFAULT_CONFIG),
            act.enabled,
            &appliance,
        )?;
    }
    if act.enabled {
        crate::mutation::advance()?;
    }
    // A revert to saved: there is no last-good to reconcile a partial failure
    // to (reconciling back to the un-confirmed config would defeat the revert),
    // so a failure here reports mixed-state honestly. A restore, so a held link
    // that stays dark is reported rather than failing the revert.
    // Do not cancel protection before a successful restore and publication.
    // If this is the timer's own service, disarm stops only its timer.
    finish_restore(
        || restore_live(&appliance, act).context("reverting to the rollback baseline"),
        || record_restored(&appliance, act),
        system::disarm_confirm,
    )?;
    eprintln!("reverted the running system to the rollback baseline.");
    Ok(())
}

/// A successful restore must replace any earlier unsaved running snapshot.
/// Otherwise the delayed boot stage can reconcile back to the very candidate
/// the timer just reverted. Never publish intent for off-box validation.
fn record_restored(appliance: &Appliance, act: &Apply) -> Result<()> {
    if act.enabled {
        system::install_config_file(Path::new(Session::RUNNING), &appliance.to_toml()?).context(
            "saved configuration restored, but recording the running configuration failed",
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn rollback_worker_authority_requires_the_exact_live_main_pid() {
        assert!(super::require_worker_pid("1234\n", 1234).is_ok());
        for value in [
            "0",
            "1235",
            "",
            "MainPID=1234",
            "1234\n1234",
            "-1",
            "garbage",
        ] {
            assert!(super::require_worker_pid(value, 1234).is_err(), "{value:?}");
        }
        assert!(super::require_worker_pid("0", 0).is_err());
    }

    use super::*;

    #[test]
    fn manual_rollback_without_a_trial_cannot_adopt_legacy_from_a_selected_file() {
        let dir = fixture();
        let selected = dir.join("selected.toml");
        let content = r#"
[system]
hostname = "selected"
[zone.lan]
[zone.wan]
[[interface]]
name = "lan0"
zone = "lan"
address = "192.0.2.1/24"
[[interface]]
name = "wan0"
zone = "wan"
address = "198.51.100.1/24"
[[rule]]
name = "manual-rollback-new-deny"
from = "lan"
to = "wan"
action = "drop"
proto = "tcp"
port = 443
"#;
        Appliance::from_toml(content).unwrap();
        std::fs::write(&selected, content).unwrap();
        let mut act = Apply::off();
        act.velstra_out = dir.join("velstra.toml");
        act.wren_out = dir.join("wren.toml");
        let error = rollback(&act, &selected, false, None).unwrap_err();
        assert!(
            format!("{error:#}").contains("destination-zone admission"),
            "{error:#}"
        );
        assert_eq!(std::fs::read_to_string(&selected).unwrap(), content);
        assert!(!act.velstra_out.exists());
        assert!(!act.wren_out.exists());
        assert!(!snapshot_path(&selected).exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn fixture() -> PathBuf {
        let mut nonce = [0u8; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "sentinel-confirm-baseline-{}-{:x}",
            std::process::id(),
            u64::from_ne_bytes(nonce)
        ));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn snapshot_and_arm_are_required_before_apply_and_protection_survives_every_failure() {
        use std::cell::{Cell, RefCell};
        for failure in 0..=4 {
            let calls = RefCell::new(Vec::new());
            let armed = Cell::new(false);
            let step = |index| {
                calls.borrow_mut().push(index);
                ensure!(index != failure, "injected failure");
                Ok(())
            };
            let result = protected_apply(
                || step(0),
                || {
                    step(1)?;
                    armed.set(true);
                    Ok(())
                },
                || {
                    assert!(armed.get());
                    step(2)
                },
                || {
                    assert!(armed.get());
                    step(3)
                },
            );
            assert_eq!(result.is_ok(), failure == 4);
            assert_eq!(*calls.borrow(), (0..=failure.min(3)).collect::<Vec<_>>());
            assert_eq!(armed.get(), failure >= 2);
        }
    }

    #[test]
    fn unwinding_an_interrupted_apply_does_not_cancel_independent_protection() {
        let armed = std::cell::Cell::new(false);
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            protected_apply(
                || Ok(()),
                || {
                    armed.set(true);
                    Ok(())
                },
                || panic!("simulated caller interruption"),
                || panic!("must not publish"),
            )
        }));
        assert!(interrupted.is_err());
        assert!(armed.get());
        // This is a callback-order proof, not a SIGKILL/systemd VM receipt.
    }

    #[test]
    fn active_unsaved_intent_is_the_live_baseline_but_saved_boot_bytes_are_unchanged() {
        use std::os::unix::fs::PermissionsExt;
        let dir = fixture();
        let saved = dir.join("appliance.toml");
        let running = dir.join("running.toml");
        let bytes = "# exact boot bytes\n[system]\nhostname='saved'\n";
        std::fs::write(&saved, bytes).unwrap();
        std::fs::write(&running, "[system]\nhostname='unsaved-active'\n").unwrap();
        let previous = previous_active(&saved, &running).unwrap();
        assert_eq!(previous.system.hostname, "unsaved-active");
        let snapshot = snapshot_path(&saved);
        system::install_ha_secret(&snapshot, &previous.to_toml().unwrap()).unwrap();
        assert_eq!(
            std::fs::metadata(&snapshot).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            Appliance::load(&snapshot).unwrap().system.hostname,
            "unsaved-active"
        );
        assert_eq!(std::fs::read_to_string(&saved).unwrap(), bytes);
        std::fs::remove_file(&running).unwrap();
        assert_eq!(
            previous_active(&saved, &running).unwrap().system.hostname,
            "saved"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn invalid_or_nonregular_active_and_missing_or_invalid_boot_baselines_fail_closed() {
        let dir = fixture();
        let saved = dir.join("appliance.toml");
        let running = dir.join("running.toml");
        std::fs::write(&saved, "[system]\nhostname='saved'\n").unwrap();
        std::fs::write(&running, "not valid TOML!").unwrap();
        assert!(previous_active(&saved, &running).is_err());
        std::fs::remove_file(&running).unwrap();
        std::os::unix::fs::symlink(&saved, &running).unwrap();
        assert!(previous_active(&saved, &running).is_err());
        std::fs::remove_file(&running).unwrap();
        std::fs::write(&running, "[system]\nhostname='running'\n").unwrap();
        std::fs::remove_file(&saved).unwrap();
        assert!(previous_active(&saved, &running).is_err());
        std::fs::write(&saved, "not valid TOML!").unwrap();
        assert!(previous_active(&saved, &running).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rollback_service_state_wins_over_the_timer_and_unknown_state_is_not_idle() {
        for state in ["active", "activating", "reloading", "deactivating"] {
            assert_eq!(
                decode_confirmation_state(&format!("inactive\n\n{state}\n")).unwrap(),
                ConfirmationState::Reverting
            );
            assert_eq!(
                decode_confirmation_state(&format!("active\n\n{state}\n")).unwrap(),
                ConfirmationState::Reverting
            );
        }
        assert_eq!(
            decode_confirmation_state("active\n\ninactive\n").unwrap(),
            ConfirmationState::Armed
        );
        assert_eq!(
            decode_confirmation_state("inactive\n\nfailed\n").unwrap(),
            ConfirmationState::Failed
        );
        for output in ["", "active", "active\ninactive\nextra", "unknown\ninactive"] {
            assert!(decode_confirmation_state(output).is_err());
        }
    }

    #[test]
    fn ordinary_writes_refuse_pending_or_unreadable_state_but_offline_editing_needs_no_pid1() {
        admit_write(false, false, || {
            panic!("portable editing must not query PID1")
        })
        .unwrap();
        for (live, appliance) in [(true, false), (true, true), (false, true)] {
            admit_write(live, appliance, || Ok(ConfirmationState::Idle)).unwrap();
            for state in [ConfirmationState::Armed, ConfirmationState::Reverting] {
                let refusal = admit_write(live, appliance, || Ok(state)).unwrap_err();
                assert!(refusal.to_string().contains("explicitly confirm or revert"));
            }
            assert!(admit_write(live, appliance, || bail!("PID1 unavailable")).is_err());
            assert!(
                admit_write(live, appliance, || Ok(ConfirmationState::Failed))
                    .unwrap_err()
                    .to_string()
                    .contains("recovery failed")
            );
            assert!(admit_write(live, appliance, || decode_confirmation_state("active")).is_err());
        }
    }

    #[test]
    fn periodic_policy_refresh_preserves_trials_but_defers_unknown_live_recovery() {
        for state in [ConfirmationState::Idle, ConfirmationState::Armed] {
            assert!(!firewall_refresh_blocked_with(|| Ok(state)).unwrap());
        }
        for state in [ConfirmationState::Reverting, ConfirmationState::Failed] {
            assert!(firewall_refresh_blocked_with(|| Ok(state)).unwrap());
        }
        assert!(firewall_refresh_blocked_with(|| bail!("PID1 lookup failed")).is_err());
        assert!(
            firewall_refresh_blocked_with(|| decode_confirmation_state("unknown\ninactive"))
                .is_err()
        );
        assert!(firewall_refresh_blocked_with(|| decode_confirmation_state("inactive")).is_err());
    }

    #[test]
    fn explicit_original_metadata_is_bound_to_the_snapshot_and_never_guessed_from_names() {
        let original = Path::new("/var/lib/sentinel/custom.toml");
        let snapshot = snapshot_path(original);
        assert_eq!(
            original_configuration(&snapshot, true, Some(original)).unwrap(),
            original
        );
        assert_eq!(
            original_configuration(&snapshot, true, None).unwrap(),
            snapshot
        );
        for (config, from_timer, original) in [
            (snapshot.as_path(), false, original),
            (Path::new("relative.toml"), true, original),
            (snapshot.as_path(), true, Path::new("relative.toml")),
            (Path::new("/var/lib/sentinel/other.toml"), true, original),
            (
                snapshot.as_path(),
                true,
                Path::new("/var/lib/sentinel/other.toml"),
            ),
        ] {
            assert!(original_configuration(config, from_timer, Some(original)).is_err());
        }
    }

    #[test]
    fn a_failed_stop_or_racing_rollback_is_never_reported_as_confirmed() {
        for state in [
            ConfirmationState::Armed,
            ConfirmationState::Reverting,
            ConfirmationState::Failed,
            ConfirmationState::Idle,
        ] {
            let stopped = std::cell::Cell::new(false);
            let result = cancel_confirmation(|| stopped.set(true), || Ok(state));
            assert!(stopped.get());
            assert_eq!(result.is_ok(), state == ConfirmationState::Idle);
        }
        assert!(cancel_confirmation(|| (), || bail!("state query failed")).is_err());
    }

    #[test]
    fn rollback_launch_preserves_timer_until_bound_recovery_is_proven_and_never_claims_restored() {
        assert!(
            schedule_rollback(
                || bail!("start refused"),
                || panic!("no successful start"),
                || panic!("a launch failure must keep the timer")
            )
            .is_err()
        );
        for state in [
            ConfirmationState::Idle,
            ConfirmationState::Armed,
            ConfirmationState::Failed,
        ] {
            assert!(
                schedule_rollback(
                    || Ok(()),
                    || Ok(state),
                    || panic!("unproven recovery must keep the timer")
                )
                .is_err()
            );
        }
        assert!(
            schedule_rollback(
                || Ok(()),
                || bail!("state query failed"),
                || panic!("unreadable recovery must keep the timer")
            )
            .is_err()
        );
        let calls = std::cell::RefCell::new(Vec::new());
        schedule_rollback(
            || {
                calls.borrow_mut().push("start");
                Ok(())
            },
            || {
                calls.borrow_mut().push("verify");
                Ok(ConfirmationState::Reverting)
            },
            || calls.borrow_mut().push("stop-timer"),
        )
        .unwrap();
        assert_eq!(*calls.borrow(), ["start", "verify", "stop-timer"]);
    }

    #[test]
    fn failed_restore_or_intent_publication_cannot_disarm_remaining_protection() {
        for failure in 0..=2 {
            let disarmed = std::cell::Cell::new(false);
            let result = finish_restore(
                || {
                    ensure!(failure != 0, "restore failed");
                    Ok(())
                },
                || {
                    ensure!(failure != 1, "publication failed");
                    Ok(())
                },
                || disarmed.set(true),
            );
            assert_eq!(result.is_ok(), failure == 2);
            assert_eq!(disarmed.get(), failure == 2);
        }
    }

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
        let refused = rollback(&Apply::off(), &path, true, None).unwrap_err();
        assert!(
            format!("{refused:#}").contains("management transaction"),
            "{refused:#}"
        );
        assert!(crate::safe_apply::status(&path).unwrap()["pending"].is_object());
        assert_eq!(Appliance::load(&path).unwrap().system.hostname, "api");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_snapshot_timer_checks_the_original_configuration_management_journal() {
        let dir = fixture();
        let original = dir.join("custom.toml");
        let snapshot = snapshot_path(&original);
        std::fs::write(&original, "[system]\nhostname='working'\n").unwrap();
        std::fs::write(&snapshot, "[system]\nhostname='previous-active'\n").unwrap();
        let candidate = Appliance::from_toml("[system]\nhostname='api'\n").unwrap();
        crate::safe_apply::begin(&original, &candidate, &Apply::off(), 60).unwrap();
        let before = crate::safe_apply::status(&original).unwrap();
        let refusal = rollback(&Apply::off(), &snapshot, true, Some(&original)).unwrap_err();
        assert!(format!("{refusal:#}").contains("management transaction"));
        assert_eq!(
            crate::safe_apply::status(&original).unwrap()["pending"]["id"],
            before["pending"]["id"]
        );
        assert_eq!(Appliance::load(&original).unwrap().system.hostname, "api");
        assert_eq!(
            Appliance::load(&snapshot).unwrap().system.hostname,
            "previous-active"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
