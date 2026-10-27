//! Durable latest-desired-state outbox. A received configuration never queues
//! another push. Only one delivery worker runs at a time; an old acknowledgement
//! cannot erase a newer local commit. Peers that failed remain pending.
//!
//! Every push names the shared revision it was made *on top of* — the
//! [`shared_revision`] the peer last received from this member — and the peer
//! applies it only if that is still what it has (or if it already has exactly
//! what arrives). Without that, two members committing at once each applied
//! the other's push, each then discarded its own outbox as superseded by what
//! it had just received, and the pair ended up permanently swapped: A running
//! B's change and B running A's. Now both pushes are refused with a conflict,
//! both stay pending and say so, and nothing is lost: the operator rolls back
//! the member whose change should be discarded, after which the other's held
//! push applies there and the rolled-back member's own outbox is dropped as
//! superseded.
use crate::{config::Appliance, system};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const DIRECTORY: &str = "/var/lib/sentinel/configsync";
const PENDING: &str = "/var/lib/sentinel/configsync/pending.json";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    version: u32,
    #[serde(default)]
    prior_secrets: Vec<String>,
    appliance: Appliance,
    peers: Vec<String>,
    /// Per peer, the shared revisions this push may be based on: what that
    /// peer last received from here, plus every revision this member has since
    /// tried to deliver to it. An acknowledgement can be lost after the peer
    /// applied a push, so the peer may hold any of them; it applies the new
    /// push only if it holds one. Absent for an outbox written before
    /// revisions were carried; such a push only applies where it changes
    /// nothing.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    bases: BTreeMap<String, Vec<String>>,
    /// Peers that refused this push because they changed in the meantime.
    /// Persisted so the conflict is still visible after the worker that met it
    /// has exited (see [`peer_states`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    conflicts: Vec<String>,
}

/// The query parameter a push carries its base revisions in, comma-separated.
pub const BASE_PARAMETER: &str = "base";

/// How many base revisions a push carries at most: the oldest (what the peer
/// had before this member's undelivered commits began) and the most recent
/// ones. A peer that is away for longer than this many commits and *also*
/// lost an acknowledgement in the middle of them reports a conflict instead.
const MAX_BASES: usize = 32;

/// The revision of the part of `a` that config-sync converges: the same on
/// both members of a pair that are in sync, whichever member computes it.
///
/// Member-local facts differ by design and are taken out first — the exact
/// set the receiver keeps when it merges a push (`api::merge_synced_config`).
/// For a paired HA member that set is everything [`crate::ha::materialize_peer`]
/// rewrites, so rather than re-listing it the shared view *is* node 1's
/// document, normalised by one round trip through the peer's view: node 2
/// computes it as `m(m(m(self)))`, node 1 as `m(m(self))`, and since node 2's
/// document is node 1's materialised (or the other way round), both arrive at
/// the same text. Legacy config-sync blanks the fields its merge preserves.
pub fn shared_revision(a: &Appliance) -> Result<String> {
    let mut a = a.clone();
    // Never pushed, always the receiver's own.
    a.fleet = None;
    let view = match a.system.ha.as_ref() {
        Some(ha) if ha.peer_identity.is_some() => {
            let node1 = if ha.node() == 1 {
                a
            } else {
                crate::ha::materialize_peer(a)?
            };
            crate::ha::materialize_peer(crate::ha::materialize_peer(node1)?)?
        }
        _ => {
            a.system.hostname = String::new();
            a.system.config_sync = Default::default();
            a.system.conntrack_sync = Default::default();
            a.protocols.router_id = None;
            for interface in &mut a.interfaces {
                interface.address = None;
                interface.address6 = None;
                interface.local = None;
            }
            for router in &mut a.protocols.vrrp {
                router.priority = None;
            }
            a
        }
    };
    crate::ha::revision(&view)
}

/// Whether this member holds a commit it has not delivered to every peer yet.
pub fn has_pending() -> Result<bool> {
    system::owned_file_exists(Path::new(PENDING))
}

/// What the outbox says about each peer it still holds a push for:
/// `"conflict"` when the peer refused it because it changed in the meantime,
/// `"pending"` when it simply has not been delivered yet. A peer absent from
/// the map has everything this member committed.
pub fn peer_states() -> Result<BTreeMap<String, &'static str>> {
    peer_states_at(Path::new(PENDING))
}

fn peer_states_at(path: &Path) -> Result<BTreeMap<String, &'static str>> {
    let Some(text) = system::read_owned_file(path)? else {
        return Ok(BTreeMap::new());
    };
    let pending: Pending = serde_json::from_str(&text)?;
    Ok(pending
        .peers
        .iter()
        .map(|peer| {
            let state = if pending.conflicts.contains(peer) {
                "conflict"
            } else {
                "pending"
            };
            (peer.clone(), state)
        })
        .collect())
}

pub fn enqueue(appliance: &Appliance, previous: Option<&Appliance>) -> Result<()> {
    let _transaction = system::apply_lock()?;
    if appliance.system.config_sync.peers.is_empty() {
        system::remove_file(Path::new(PENDING))?;
        return stop_when_empty();
    }
    system::ensure_dir_mode(Path::new(DIRECTORY), "0750")?;
    enqueue_previous_at(Path::new(PENDING), appliance, previous)?;
    // The timer also retries after reboot or a temporarily unavailable peer.
    system::service_start_nowait("sentinel-configsync.timer")?;
    system::service_start_nowait("sentinel-configsync.service")
}

#[cfg(test)]
fn enqueue_at(path: &Path, appliance: &Appliance) -> Result<()> {
    enqueue_previous_at(path, appliance, None)
}
fn enqueue_previous_at(
    path: &Path,
    appliance: &Appliance,
    previous: Option<&Appliance>,
) -> Result<()> {
    let _transaction = system::apply_lock()?;
    // Preserve credentials for revisions a disconnected peer has not received,
    // including an ambiguously acknowledged in-flight revision. A later MTU
    // change must not erase the credential needed to deliver an earlier rotation.
    let mut prior_secrets = Vec::new();
    // What each peer has: the previous configuration, if it received it, or
    // still the base of the push it has not received yet.
    let delivered_base = match previous.map(shared_revision).transpose() {
        Ok(base) => base,
        Err(error) => {
            eprintln!("config-sync: cannot compute the shared revision: {error:#}");
            None
        }
    };
    let mut bases: BTreeMap<String, Vec<String>> = appliance
        .system
        .config_sync
        .peers
        .iter()
        .filter_map(|p| Some((p.clone(), vec![delivered_base.clone()?])))
        .collect();
    if let Some(text) = system::read_owned_file(path)? {
        let previous_pending: Pending = serde_json::from_str(&text)?;
        for peer in &previous_pending.peers {
            if !appliance.system.config_sync.peers.contains(peer) {
                continue;
            }
            // Not delivered: the peer still has one of the earlier bases, or
            // the revision that was in flight (the previous configuration).
            match previous_pending.bases.get(peer) {
                Some(earlier) => {
                    let mut chain = earlier.clone();
                    chain.extend(delivered_base.clone());
                    chain.dedup();
                    if chain.len() > MAX_BASES {
                        chain.drain(1..chain.len() - (MAX_BASES - 1));
                    }
                    bases.insert(peer.clone(), chain);
                }
                None => {
                    bases.remove(peer);
                }
            }
        }
        if previous_pending
            .peers
            .iter()
            .any(|p| appliance.system.config_sync.peers.contains(p))
        {
            prior_secrets = previous_pending.prior_secrets;
            if let Some(secret) = previous_pending.appliance.system.config_sync.secret {
                prior_secrets.push(secret);
            }
        }
    }
    if let Some(secret) = previous.and_then(|a| a.system.config_sync.secret.clone()) {
        prior_secrets.push(secret);
    }
    prior_secrets.retain(|s| Some(s) != appliance.system.config_sync.secret.as_ref());
    prior_secrets.sort();
    prior_secrets.dedup();
    let pending = Pending {
        version: 1,
        prior_secrets,
        appliance: appliance.clone(),
        peers: appliance.system.config_sync.peers.clone(),
        bases,
        conflicts: Vec::new(),
    };
    system::install_ha_secret(path, &serde_json::to_string(&pending)?)
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
    flush_at(path, Some(&current), |appliance, peer, previous, bases| {
        match crate::net::push_config_peer(appliance, peer, bases) {
            Ok(()) => Ok(()),
            // Authenticated and refused: another credential will not change
            // the peer's mind, and the refusal is what has to be reported.
            Err(error) if is_conflict(&error) => Err(error),
            Err(error) => {
                for credential in previous.iter().rev() {
                    match crate::net::push_config_peer_with_secret(
                        appliance, peer, credential, bases,
                    ) {
                        Ok(()) => return Ok(()),
                        Err(refused) if is_conflict(&refused) => return Err(refused),
                        Err(_) => {}
                    }
                }
                Err(error).context("current and retained HA delivery credentials failed")
            }
        }
    })?;
    stop_when_empty()
}

/// Whether a delivery failed because the peer refused it as a conflict.
fn is_conflict(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<system::HttpStatus>()
        .is_some_and(|e| e.status == 409)
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
    mut deliver: impl FnMut(&Appliance, &str, &[String], &[String]) -> Result<()>,
) -> Result<usize> {
    let parent = path.parent().context("outbox parent")?;
    let _delivery = system::lock_config_at(&parent.join("delivery.lock"))?;
    let original = {
        let _transaction = system::apply_lock()?;
        if let Some(current) = current {
            for config in current {
                crate::safe_apply::ensure_writable(config)?;
            }
        }
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
    let mut conflicts = Vec::new();
    let mut delivered = 0;
    for peer in &pending.peers {
        let bases = pending
            .bases
            .get(peer)
            .map(Vec::as_slice)
            .unwrap_or_default();
        match deliver(&pending.appliance, peer, &pending.prior_secrets, bases) {
            Ok(()) => delivered += 1,
            Err(error) if is_conflict(&error) => {
                // Not a peer that is away: one that will refuse this push
                // every time until somebody decides which change wins. Kept,
                // never dropped, and worded so the journal says what to do.
                eprintln!(
                    "config-sync to {peer} CONFLICT: {peer} changed its configuration since it \
                     last received this member's, so this commit is held, not applied there. \
                     Roll back the member whose change should be discarded; the other's held \
                     push then applies."
                );
                conflicts.push(peer.clone());
                failed.push(peer.clone());
            }
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
            pending.bases.retain(|peer, _| failed.contains(peer));
            pending.peers = failed.clone();
            pending.conflicts = conflicts.clone();
            system::install_ha_secret(path, &serde_json::to_string(&pending)?)?;
        }
    }
    ensure!(
        conflicts.is_empty(),
        "{} HA peer(s) refused this member's configuration as a conflict",
        conflicts.len()
    );
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
    fn pending_secret_rotations_survive_following_edits_and_ambiguous_acknowledgements() {
        use std::os::unix::fs::PermissionsExt;
        let directory =
            std::env::temp_dir().join(format!("sentinel-outbox-rotation-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("pending.json");
        let mut old = Appliance::from_toml(crate::config::EXAMPLE).unwrap();
        old.system.config_sync.peers = vec!["10.0.0.2".into()];
        old.system.config_sync.secret = Some("old-credential".into());
        enqueue_previous_at(&path, &old, None).unwrap();
        let mut rotated = old.clone();
        rotated.system.config_sync.secret = Some("new-credential".into());
        enqueue_previous_at(&path, &rotated, Some(&old)).unwrap();
        let mut edited = rotated.clone();
        edited.system.hostname = "after-rotation".into();
        enqueue_previous_at(&path, &edited, Some(&rotated)).unwrap();
        let pending: Pending =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(pending.prior_secrets, vec!["old-credential"]);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let mut twice = edited.clone();
        twice.system.config_sync.secret = Some("third-credential".into());
        enqueue_previous_at(&path, &twice, Some(&edited)).unwrap();
        assert_eq!(
            flush_at(&path, None, |appliance, _, credentials, _| {
                assert_eq!(
                    appliance.system.config_sync.secret.as_deref(),
                    Some("third-credential")
                );
                assert!(credentials.iter().any(|s| s == "old-credential"));
                assert!(credentials.iter().any(|s| s == "new-credential"));
                Ok(())
            })
            .unwrap(),
            1
        );
        assert!(!path.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }
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
            flush_at(&path, None, |_, peer, _, _| {
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
            flush_at(&path, None, |_, _, _, _| enqueue_at(&path, &newer)).unwrap(),
            1
        );
        let pending: Pending =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(pending.appliance.system.hostname, "newer");
        assert_eq!(flush_at(&path, None, |_, _, _, _| Ok(())).unwrap(), 2);
        assert!(!path.exists());
        enqueue_at(&path, &appliance).unwrap();
        let current = directory.join("appliance.toml");
        std::fs::write(&current, newer.to_toml().unwrap()).unwrap();
        assert_eq!(
            flush_at(&path, Some(&[current]), |_, _, _, _| panic!(
                "obsolete unsaved commit sent"
            ))
            .unwrap(),
            0
        );
        assert!(!path.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn conflict() -> anyhow::Error {
        system::HttpStatus {
            status: 409,
            request: "PUT https://peer/api/v1/config-sync".into(),
        }
        .into()
    }

    /// A push carries what the peer last received, and keeps carrying it —
    /// plus every revision since tried — for as long as the peer has not
    /// acknowledged one; once delivered, the next push starts from the
    /// delivered configuration.
    #[test]
    fn a_push_names_every_base_the_peer_may_hold() {
        let directory =
            std::env::temp_dir().join(format!("sentinel-outbox-bases-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("pending.json");
        let mut s0 = Appliance::from_toml(crate::config::EXAMPLE).unwrap();
        s0.system.config_sync.peers = vec!["10.0.0.2".into()];
        s0.system.config_sync.secret = Some("test credential".into());
        // Shared settings: a hostname is member-local and would not count.
        let mut s1 = s0.clone();
        s1.system.timezone = Some("UTC".into());
        let mut s2 = s1.clone();
        s2.system.timezone = Some("Europe/Berlin".into());
        let r = |a: &Appliance| shared_revision(a).unwrap();
        enqueue_previous_at(&path, &s1, Some(&s0)).unwrap();
        // Not delivered (the acknowledgement may have been lost): s2 is based
        // on s0, or on s1 if s1 did land.
        assert!(flush_at(&path, None, |_, _, _, _| anyhow::bail!("timeout")).is_err());
        enqueue_previous_at(&path, &s2, Some(&s1)).unwrap();
        let mut seen = Vec::new();
        flush_at(&path, None, |_, _, _, bases| {
            seen = bases.to_vec();
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, vec![r(&s0), r(&s1)]);
        // Delivered: the next one is based on s2 alone.
        let mut s3 = s2.clone();
        s3.system.timezone = Some("Asia/Tokyo".into());
        enqueue_previous_at(&path, &s3, Some(&s2)).unwrap();
        flush_at(&path, None, |_, _, _, bases| {
            seen = bases.to_vec();
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, vec![r(&s2)]);
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// A peer that refuses a push as a conflict keeps it pending, marked as a
    /// conflict where status can see it, and the worker fails saying so — it
    /// is neither retried into silence nor dropped.
    #[test]
    fn a_refused_push_is_kept_and_reported_as_a_conflict() {
        let directory =
            std::env::temp_dir().join(format!("sentinel-outbox-conflict-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("pending.json");
        let mut appliance = Appliance::from_toml(crate::config::EXAMPLE).unwrap();
        appliance.system.config_sync.peers = vec!["10.0.0.1".into(), "10.0.0.2".into()];
        appliance.system.config_sync.secret = Some("test credential".into());
        enqueue_at(&path, &appliance).unwrap();
        let error = flush_at(&path, None, |_, peer, _, _| {
            if peer == "10.0.0.2" {
                Err(conflict())
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("conflict"), "{error:#}");
        let states = peer_states_at(&path).unwrap();
        assert_eq!(states.get("10.0.0.2"), Some(&"conflict"));
        assert_eq!(states.get("10.0.0.1"), None, "the other peer took it");
        // Once the conflict is resolved on the peer, the held push lands.
        assert_eq!(flush_at(&path, None, |_, _, _, _| Ok(())).unwrap(), 1);
        assert!(peer_states_at(&path).unwrap().is_empty());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_conflict_is_told_apart_from_an_absent_peer() {
        assert!(is_conflict(&conflict()));
        assert!(!is_conflict(&anyhow::anyhow!("connection refused")));
        let unauthorised: anyhow::Error = system::HttpStatus {
            status: 401,
            request: "x".into(),
        }
        .into();
        assert!(!is_conflict(&unauthorised));
        assert!(is_conflict(&conflict().context("delivering")));
    }
}
