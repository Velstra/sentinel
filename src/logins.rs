//! Ownership of local credentials reconciled from `system.login`.
//!
//! Keep account IDs and homes when a grant disappears, but revoke its password
//! and generated SSH keys. The private journal records ownership, never desired
//! credentials: only the current appliance document can grant access. Write the
//! union before side effects so a partial apply cannot orphan a newly created
//! credential; narrow it only after revocation succeeds. The caller holds the
//! shared apply lock across this whole transaction, including boot and rollback.

use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use crate::config::{Login, valid_login_username};
use crate::system;

const OWNERSHIP_FILE: &str = "/var/lib/sentinel/managed-logins.json";
const KEY_PREFIX: &str = "authorized_keys.";

pub struct Ownership {
    previous: BTreeSet<String>,
    desired: BTreeSet<String>,
}

fn checked_names(names: BTreeSet<String>) -> Result<BTreeSet<String>> {
    ensure!(
        names.iter().all(|name| valid_login_username(name)),
        "managed login ownership contains an invalid account name"
    );
    Ok(names)
}

fn parse_ownership(contents: &str) -> Result<BTreeSet<String>> {
    checked_names(serde_json::from_str(contents).context("decoding managed login ownership")?)
}

fn load_ownership() -> Result<BTreeSet<String>> {
    match std::fs::symlink_metadata(OWNERSHIP_FILE) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(error) => return Err(error).context("reading managed login ownership metadata"),
        Ok(metadata) => ensure!(
            metadata.is_file(),
            "managed login ownership is not a regular file"
        ),
    }
    let contents = system::read_private_file(Path::new(OWNERSHIP_FILE))
        .context("reading managed login ownership")?;
    parse_ownership(&contents)
}

fn save_ownership(names: &BTreeSet<String>) -> Result<()> {
    let contents = serde_json::to_string(names)? + "\n";
    system::install_config_file(Path::new(OWNERSHIP_FILE), contents.as_bytes())
        .context("persisting managed login ownership")
}

fn key_path(directory: &Path, user: &str) -> PathBuf {
    directory.join(format!("{KEY_PREFIX}{user}"))
}

/// Adopt legacy generated key files as evidence of prior management. Never
/// enumerate or revoke unrelated accounts from the operating-system database.
pub fn begin(logins: &[Login], keys_dir: &Path) -> Result<Ownership> {
    let desired = checked_names(logins.iter().map(|login| login.username.clone()).collect())?;
    let mut previous = load_ownership()?;
    let entries = match std::fs::read_dir(keys_dir) {
        Ok(entries) => Some(entries),
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("examining managed SSH keys"),
    };
    if let Some(entries) = entries {
        for entry in entries {
            let entry = entry.context("reading managed SSH key entry")?;
            let name = entry.file_name();
            if let Some(user) = name.to_str().and_then(|name| name.strip_prefix(KEY_PREFIX)) {
                ensure!(
                    valid_login_username(user),
                    "invalid managed SSH key account name"
                );
                previous.insert(user.to_owned());
            }
        }
    }
    let pending = previous.union(&desired).cloned().collect();
    save_ownership(&pending)?;
    Ok(Ownership { previous, desired })
}

fn local_account_exists(passwd: &str, user: &str) -> bool {
    passwd
        .lines()
        .any(|line| line.split_once(':').is_some_and(|(name, _)| name == user))
}

impl Ownership {
    pub fn finish(self, keys_dir: &Path) -> Result<()> {
        let mut removed = false;
        for user in self.previous.difference(&self.desired) {
            removed = true;
            system::remove_file(&key_path(keys_dir, user))
                .with_context(|| format!("revoking SSH keys for {user}"))?;
            // A user may already have been removed outside Sentinel. Account
            // absence is converged; an unreadable local database is an error.
            let passwd =
                std::fs::read_to_string("/etc/passwd").context("examining local login accounts")?;
            if local_account_exists(&passwd, user) {
                system::set_login_password(user, system::DISABLED_LOGIN_PASSWORD)
                    .with_context(|| format!("revoking the password for {user}"))?;
            }
        }
        if removed {
            // Do not forget ownership while the old shadow password could
            // still return after a crash. The pending journal remains on error.
            system::sync_login_database()?;
        }
        save_ownership(&self.desired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ownership_is_a_deterministic_set_of_safe_account_names() {
        let names = parse_ownership(r#"["ops", "alice", "ops"]"#).unwrap();
        assert_eq!(names.into_iter().collect::<Vec<_>>(), ["alice", "ops"]);
    }

    #[test]
    fn ownership_cannot_supply_paths_or_command_options() {
        for name in [
            "",
            "--root",
            "../root",
            "ops/other",
            "ops\nroot",
            "x:y",
            "1ops",
        ] {
            let contents = serde_json::to_string(&[name]).unwrap();
            assert!(parse_ownership(&contents).is_err(), "{name:?}");
        }
    }

    #[test]
    fn invalid_ownership_is_not_an_empty_successful_reconcile() {
        for contents in ["", "null", "{}", "[1]", "[\"ops\""] {
            assert!(parse_ownership(contents).is_err(), "{contents}");
        }
    }

    #[test]
    fn local_account_matching_is_exact() {
        let passwd = "root:x:0:0::/root:/bin/sh\nops-other:x:1000:100::/home/ops:/bin/sh\n";
        assert!(!local_account_exists(passwd, "ops"));
        assert!(local_account_exists(passwd, "root"));
        assert!(local_account_exists(passwd, "ops-other"));
        assert!(!local_account_exists("", "root"));
    }
}
