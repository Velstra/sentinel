//! Durable receive authorization, published BEFORE any live or saved change.
//!
//! The journal is never cleared: even an interrupted first synchronization has
//! participated. An unchanged baseline may retry exactly its authorized policy,
//! but never a different stale push or an undelivered local edit. A separate
//! completion write would add a failure boundary without strengthening CAS;
//! holding the desired revision already makes repeated delivery idempotent.
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::{config::Appliance, system};

#[derive(Debug)]
pub(crate) struct Conflict;

impl std::fmt::Display for Conflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "this member's configuration changed since the sender last synchronized it; \
             roll back the member whose change should be discarded",
        )
    }
}

impl std::error::Error for Conflict {}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fence {
    version: u32,
    /// Full local document, not just shared policy: local identity edits also
    /// invalidate an interrupted first-sync exemption.
    baseline: String,
    desired: String,
}

fn revision(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Caller holds the common apply lock AND this document's transaction lock
/// from loading `local` until live apply/persistence finish. Reusing only the
/// global lock would not serialize off-box API/CLI edits to the same file.
pub(crate) fn prepare(
    marker: &Path,
    local: &Appliance,
    desired: &Appliance,
    bases: Option<&str>,
    local_pending: bool,
) -> Result<()> {
    prepare_with(marker, local, desired, bases, local_pending, |text| {
        system::install_ha_secret(marker, text)
    })
}

fn prepare_with(
    marker: &Path,
    local: &Appliance,
    desired: &Appliance,
    bases: Option<&str>,
    local_pending: bool,
    persist: impl FnOnce(&str) -> Result<()>,
) -> Result<()> {
    let held = super::shared_revision(local)?;
    let arriving = super::shared_revision(desired)?;
    let baseline = crate::ha::revision(local)?;
    let previous = system::read_owned_regular(marker, 1024)?;
    let interrupted = match previous.as_deref() {
        None => false,
        // Upgrade an existing successful legacy receipt. Its value never
        // grants an interrupted first-sync retry; it only proves participation.
        Some(text) if revision(text.trim_end_matches('\n')) => false,
        Some(text) => {
            let fence: Fence = serde_json::from_str(text)
                .context("reading config-sync receive authorization; refusing unsafe recovery")?;
            ensure!(
                fence.version == 1 && revision(&fence.baseline) && revision(&fence.desired),
                "invalid config-sync receive authorization; refusing unsafe recovery"
            );
            fence.baseline == baseline && fence.desired == arriving && !local_pending
        }
    };
    let based_on_held = bases.is_some_and(|bases| bases.split(',').any(|base| base == held));
    let first = previous.is_none() && !local_pending;
    if held != arriving && !based_on_held && !first && !interrupted {
        return Err(Conflict.into());
    }
    let fence = Fence {
        version: 1,
        baseline,
        desired: arriving,
    };
    // Includes file fsync, atomic rename and parent-directory fsync. Any error
    // (including uncertain durability AFTER rename) refuses apply/acknowledge.
    // A later retry republishes and syncs the exact fence before proceeding.
    persist(&serde_json::to_string(&fence)?)
        .context("cannot durably authorize config-sync; no policy was applied")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;

    struct Fixture {
        directory: PathBuf,
        marker: PathBuf,
        local: Appliance,
        desired: Appliance,
    }

    impl Fixture {
        fn new() -> Self {
            static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let directory = std::env::temp_dir().join(format!(
                "sentinel-receive-fence-{}-{}",
                std::process::id(),
                N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir(&directory).unwrap();
            let local = Appliance::from_toml(crate::config::EXAMPLE).unwrap();
            let mut desired = local.clone();
            desired.interfaces[0].mtu = Some(1400);
            Self {
                marker: directory.join("received"),
                directory,
                local,
                desired,
            }
        }

        fn prepare(&self, local: &Appliance, desired: &Appliance, pending: bool) -> Result<()> {
            prepare(&self.marker, local, desired, None, pending)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.directory).unwrap();
        }
    }

    #[test]
    fn interrupted_first_apply_retries_only_exact_policy_on_exact_baseline() {
        let fixture = Fixture::new();
        fixture
            .prepare(&fixture.local, &fixture.desired, false)
            .unwrap();
        assert_eq!(
            std::fs::metadata(&fixture.marker)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        // Simulate failed live apply or save: the saved baseline stays local.
        // A fresh read (including after a process restart) retains the fence.
        let mut different = fixture.desired.clone();
        different.system.timezone = Some("UTC".into());
        assert!(
            fixture
                .prepare(&fixture.local, &different, false)
                .unwrap_err()
                .is::<Conflict>()
        );
        assert!(
            fixture
                .prepare(&fixture.local, &fixture.desired, true)
                .unwrap_err()
                .is::<Conflict>()
        );
        let mut local_edit = fixture.local.clone();
        local_edit.system.hostname = "operator-local-identity-edit".into();
        assert_eq!(
            super::super::shared_revision(&local_edit).unwrap(),
            super::super::shared_revision(&fixture.local).unwrap()
        );
        assert!(
            fixture
                .prepare(&local_edit, &fixture.desired, false)
                .unwrap_err()
                .is::<Conflict>()
        );
        fixture
            .prepare(&fixture.local, &fixture.desired, false)
            .unwrap();
        // After save/ack loss, holding the policy is an idempotent retry.
        fixture
            .prepare(&fixture.desired, &fixture.desired, false)
            .unwrap();
    }

    #[test]
    fn persistence_failure_before_publication_never_consumes_or_acknowledges_apply() {
        let fixture = Fixture::new();
        let error = prepare_with(
            &fixture.marker,
            &fixture.local,
            &fixture.desired,
            None,
            false,
            |_| Err(std::io::Error::from_raw_os_error(libc::ENOSPC).into()),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("no policy was applied"));
        assert!(!fixture.marker.exists());
        fixture
            .prepare(&fixture.local, &fixture.desired, false)
            .unwrap();
    }

    #[test]
    fn uncertain_directory_sync_after_rename_never_reopens_first_sync() {
        let fixture = Fixture::new();
        let error = prepare_with(
            &fixture.marker,
            &fixture.local,
            &fixture.desired,
            None,
            false,
            |text| {
                system::install_ha_secret(&fixture.marker, text)?;
                Err(std::io::Error::from_raw_os_error(libc::EIO).into())
            },
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("no policy was applied"));
        let mut stale = fixture.desired.clone();
        stale.interfaces[0].mtu = Some(1300);
        assert!(
            fixture
                .prepare(&fixture.local, &stale, false)
                .unwrap_err()
                .is::<Conflict>()
        );
        fixture
            .prepare(&fixture.local, &fixture.desired, false)
            .unwrap();
    }

    #[test]
    fn legacy_receipts_enforce_cas_and_upgrade_only_authorized_changes() {
        let fixture = Fixture::new();
        let held = super::super::shared_revision(&fixture.local).unwrap();
        std::fs::write(&fixture.marker, format!("{held}\n")).unwrap();
        assert!(
            fixture
                .prepare(&fixture.local, &fixture.desired, false)
                .unwrap_err()
                .is::<Conflict>()
        );
        prepare(
            &fixture.marker,
            &fixture.local,
            &fixture.desired,
            Some(&held),
            true,
        )
        .unwrap();
        let fence: Fence =
            serde_json::from_str(&std::fs::read_to_string(&fixture.marker).unwrap()).unwrap();
        assert_eq!(fence.version, 1);
        assert_eq!(fence.baseline, crate::ha::revision(&fixture.local).unwrap());
    }

    #[test]
    fn malformed_unknown_or_nonregular_receipts_refuse_even_an_explicit_base() {
        let fixture = Fixture::new();
        let held = super::super::shared_revision(&fixture.local).unwrap();
        let valid = serde_json::json!({"version":1,"baseline":held,"desired":held});
        for text in [
            "".to_string(),
            "{}".into(),
            "{".into(),
            "x".repeat(1025),
            valid.to_string().replace("\"version\":1", "\"version\":2"),
            valid
                .to_string()
                .replace("\"version\":1", "\"version\":1,\"extra\":true"),
            valid
                .to_string()
                .replace("\"version\":1", "\"version\":1,\"version\":1"),
            valid.to_string().replace(&held, "bad"),
        ] {
            std::fs::write(&fixture.marker, text).unwrap();
            assert!(
                prepare(
                    &fixture.marker,
                    &fixture.local,
                    &fixture.desired,
                    Some(&held),
                    false
                )
                .is_err()
            );
        }
        std::fs::remove_file(&fixture.marker).unwrap();
        symlink(fixture.directory.join("missing"), &fixture.marker).unwrap();
        assert!(
            fixture
                .prepare(&fixture.local, &fixture.desired, false)
                .is_err()
        );
        std::fs::remove_file(&fixture.marker).unwrap();
        std::fs::create_dir(&fixture.marker).unwrap();
        assert!(
            fixture
                .prepare(&fixture.local, &fixture.desired, false)
                .is_err()
        );
    }

    #[test]
    fn an_undelivered_local_commit_blocks_first_sync_but_not_matching_cas() {
        let fixture = Fixture::new();
        assert!(
            fixture
                .prepare(&fixture.local, &fixture.desired, true)
                .unwrap_err()
                .is::<Conflict>()
        );
        assert!(!fixture.marker.exists());
        let held = super::super::shared_revision(&fixture.local).unwrap();
        prepare(
            &fixture.marker,
            &fixture.local,
            &fixture.desired,
            Some(&held),
            true,
        )
        .unwrap();
    }
}
