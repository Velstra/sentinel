//! Durable latest-desired-state outbox. A received configuration never queues
//! another push. Only one delivery worker runs at a time; an old acknowledgement
//! cannot erase a newer local commit. Peers that failed remain pending.
use crate::{config::Appliance, system};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const DIRECTORY: &str = "/var/lib/sentinel/configsync";
const PENDING: &str = "/var/lib/sentinel/configsync/pending.json";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    version: u32,
    appliance: Appliance,
    peers: Vec<String>,
}

pub fn enqueue(appliance: &Appliance) -> Result<()> {
    let _transaction = system::apply_lock()?;
    if appliance.system.config_sync.peers.is_empty() {
        system::remove_file(Path::new(PENDING))?;
        return stop_when_empty();
    }
    system::ensure_dir_mode(Path::new(DIRECTORY), "0750")?;
    enqueue_at(Path::new(PENDING), appliance)?;
    // The timer also retries after reboot or a temporarily unavailable peer.
    system::service_start_nowait("sentinel-configsync.timer")?;
    system::service_start_nowait("sentinel-configsync.service")
}

fn enqueue_at(path: &Path, appliance: &Appliance) -> Result<()> {
    let _transaction = system::apply_lock()?;
    let pending = Pending {
        version: 1,
        appliance: appliance.clone(),
        peers: appliance.system.config_sync.peers.clone(),
    };
    system::install_config_file(path, &serde_json::to_string(&pending)?)
}

pub fn flush() -> Result<()> {
    let path = Path::new(PENDING);
    if !system::owned_file_exists(path)? {
        return stop_when_empty();
    }
    // After a reboot, an unsaved CLI commit is no longer desired state. Never
    // send its persisted outbox over the configuration this boot actually uses.
    let current = [
        PathBuf::from(crate::session::DEFAULT_CONFIG),
        PathBuf::from(crate::session::Session::RUNNING),
    ];
    flush_at(path, Some(&current), crate::net::push_config_peer)?;
    stop_when_empty()
}

fn stop_when_empty() -> Result<()> {
    // Serialize the check and stop with enqueue's write and timer start. A
    // successful older worker must not disable retries for a newer commit.
    let _transaction = system::apply_lock()?;
    if !system::owned_file_exists(Path::new(PENDING))? {
        system::service_stop("sentinel-configsync.timer")?;
    }
    Ok(())
}

fn flush_at(
    path: &Path,
    current: Option<&[PathBuf]>,
    mut deliver: impl FnMut(&Appliance, &str) -> Result<()>,
) -> Result<usize> {
    let parent = path.parent().context("outbox parent")?;
    let _delivery = system::lock_config_at(&parent.join("delivery.lock"))?;
    let original = {
        let _transaction = system::apply_lock()?;
        system::read_owned_file(path)?
    };
    let Some(original) = original else {
        return Ok(0);
    };
    let mut pending: Pending =
        serde_json::from_str(&original).context("reading pending HA configuration")?;
    ensure!(pending.version == 1, "unsupported HA outbox version");
    pending.appliance.validate()?;
    if let Some(current) = current {
        let desired = pending.appliance.to_toml()?;
        if !current.iter().any(|file| {
            Appliance::load(file)
                .and_then(|a| a.to_toml())
                .is_ok_and(|text| text == desired)
        }) {
            let _transaction = system::apply_lock()?;
            if system::read_owned_file(path)?.as_deref() == Some(&original) {
                system::remove_file(path)?;
                std::fs::File::open(parent)?.sync_all()?;
            }
            return Ok(0);
        }
    }
    let mut failed = Vec::new();
    let mut delivered = 0;
    for peer in &pending.peers {
        match deliver(&pending.appliance, peer) {
            Ok(()) => delivered += 1,
            Err(error) => {
                eprintln!("config-sync to {peer} remains pending: {error:#}");
                failed.push(peer.clone());
            }
        }
    }
    let _transaction = system::apply_lock()?;
    if system::read_owned_file(path)?.as_deref() == Some(&original) {
        if failed.is_empty() {
            system::remove_file(path)?;
            std::fs::File::open(parent)?.sync_all()?;
        } else {
            pending.peers = failed.clone();
            system::install_config_file(path, &serde_json::to_string(&pending)?)?;
        }
    }
    ensure!(
        failed.is_empty(),
        "{} HA peer(s) awaiting configuration delivery",
        failed.len()
    );
    Ok(delivered)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn outbox_retries_only_failed_peers_and_never_loses_a_newer_commit() {
        let directory =
            std::env::temp_dir().join(format!("sentinel-outbox-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("pending.json");
        let mut appliance = Appliance::from_toml(crate::config::EXAMPLE).unwrap();
        appliance.system.config_sync.peers = vec!["10.0.0.1".into(), "10.0.0.2".into()];
        appliance.system.config_sync.secret = Some("test credential".into());
        enqueue_at(&path, &appliance).unwrap();
        assert!(
            flush_at(&path, None, |_, peer| {
                ensure!(peer == "10.0.0.1", "peer unavailable");
                Ok(())
            })
            .is_err()
        );
        let pending: Pending =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(pending.peers, vec!["10.0.0.2"]);
        let mut newer = appliance.clone();
        newer.system.hostname = "newer".into();
        assert_eq!(
            flush_at(&path, None, |_, _| enqueue_at(&path, &newer)).unwrap(),
            1
        );
        let pending: Pending =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(pending.appliance.system.hostname, "newer");
        assert_eq!(flush_at(&path, None, |_, _| Ok(())).unwrap(), 2);
        assert!(!path.exists());
        enqueue_at(&path, &appliance).unwrap();
        let current = directory.join("appliance.toml");
        std::fs::write(&current, newer.to_toml().unwrap()).unwrap();
        assert_eq!(
            flush_at(&path, Some(&[current]), |_, _| panic!(
                "obsolete unsaved commit sent"
            ))
            .unwrap(),
            0
        );
        assert!(!path.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }
}
