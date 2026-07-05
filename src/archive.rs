//! Config archive & revision rollback (roadmap C21): every `save` snapshots the
//! persisted config into a timestamped archive, so an operator can list past
//! revisions and `rollback <N>` to one — the companion to `commit-confirm`
//! ([[crate::confirm]]) for recovering from a bad-but-committed change.
//!
//! The archive lives next to the saved config (`<config-dir>/archive/`), one
//! file per revision named `config-<epoch-nanos>.toml` so the directory sorts
//! chronologically by name. Revisions are numbered newest-first: **0 is the most
//! recent**, matching VyOS's `show system commit`. The archive is pruned to the
//! last [`ARCHIVE_KEEP`] revisions.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use crate::config::Appliance;
use crate::repl::Apply;
use crate::session::Session;

/// Archive subdirectory, relative to the saved config's directory.
const ARCHIVE_SUBDIR: &str = "archive";
/// Revision filename prefix; the rest is the zero-padded epoch-nanos + `.toml`.
const ARCHIVE_PREFIX: &str = "config-";
const ARCHIVE_SUFFIX: &str = ".toml";
/// How many revisions to keep (older ones are pruned on each new archive).
pub const ARCHIVE_KEEP: usize = 50;

/// One archived revision.
pub struct Revision {
    /// Recency index — 0 is the newest.
    pub index: usize,
    /// Epoch nanoseconds the revision was archived at (from the filename).
    pub nanos: u128,
    /// The revision file.
    pub path: PathBuf,
}

impl Revision {
    /// A human-readable UTC timestamp for the revision.
    pub fn timestamp(&self) -> String {
        fmt_utc((self.nanos / 1_000_000_000) as i64)
    }
}

/// The archive directory for a given saved-config path.
fn archive_dir(config_path: &Path) -> PathBuf {
    let parent = config_path.parent().unwrap_or(Path::new("."));
    parent.join(ARCHIVE_SUBDIR)
}

/// Snapshot `contents` (the just-saved config TOML) as a new revision, then prune
/// to the most recent [`ARCHIVE_KEEP`]. Best-effort by design: a failure to
/// archive must never fail the `save` itself, so callers log rather than
/// propagate. The archive dir sits under `/var/lib/sentinel` (wheel-writable), so
/// no privilege escalation is needed.
pub fn archive_config(config_path: &Path, contents: &str) -> Result<()> {
    let dir = archive_dir(config_path);
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // Zero-pad so lexical order == chronological order for the foreseeable range.
    let name = format!("{ARCHIVE_PREFIX}{nanos:020}{ARCHIVE_SUFFIX}");
    let path = dir.join(&name);
    // Atomic: temp + rename, so a reader never sees a half-written revision.
    let tmp = dir.join(format!(".{name}.tmp"));
    std::fs::write(&tmp, contents).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("installing {}", path.display()))?;

    prune(&dir);
    Ok(())
}

/// Remove all but the newest [`ARCHIVE_KEEP`] revisions (best-effort).
fn prune(dir: &Path) {
    let mut files = revision_files(dir);
    // Newest first; drop everything past the keep window.
    files.sort_by_key(|f| std::cmp::Reverse(f.1));
    for (path, _) in files.into_iter().skip(ARCHIVE_KEEP) {
        let _ = std::fs::remove_file(path);
    }
}

/// The revision files in `dir` as `(path, nanos)`, unsorted. Non-matching names
/// are ignored.
fn revision_files(dir: &Path) -> Vec<(PathBuf, u128)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some(nanos) = parse_revision_nanos(name) {
            out.push((entry.path(), nanos));
        }
    }
    out
}

/// Parse `config-<nanos>.toml` → the epoch-nanos, or `None` if the name doesn't
/// match (so temp files and stray entries are skipped).
fn parse_revision_nanos(name: &str) -> Option<u128> {
    name.strip_prefix(ARCHIVE_PREFIX)?
        .strip_suffix(ARCHIVE_SUFFIX)?
        .parse()
        .ok()
}

/// List the archived revisions for `config_path`, newest first (index 0 = most
/// recent).
pub fn list_revisions(config_path: &Path) -> Vec<Revision> {
    let mut files = revision_files(&archive_dir(config_path));
    files.sort_by_key(|f| std::cmp::Reverse(f.1));
    files
        .into_iter()
        .enumerate()
        .map(|(index, (path, nanos))| Revision { index, nanos, path })
        .collect()
}

/// The TOML content of revision `n` (0 = newest).
pub fn read_revision(config_path: &Path, n: usize) -> Result<String> {
    let revs = list_revisions(config_path);
    let rev = revs
        .get(n)
        .ok_or_else(|| anyhow::anyhow!("no revision {n} (have {})", revs.len()))?;
    std::fs::read_to_string(&rev.path).with_context(|| format!("reading {}", rev.path.display()))
}

/// Revert the running system to archived revision `n`: apply it live (when
/// enabled), persist it as the saved config (which archives it as a fresh
/// revision), and reset the session's candidate to it. Idempotent — the revision
/// is a full, already-validated config.
pub fn rollback(session: &mut Session, act: &Apply, n: usize) -> Result<()> {
    let cfg = session.config_path().to_path_buf();
    let content = read_revision(&cfg, n)?;
    // Parse + validate before touching anything live.
    let appliance = Appliance::from_toml(&content).context("the archived revision is invalid")?;

    if act.enabled {
        crate::repl::apply_live(&appliance, act).context("applying the revision")?;
    }

    // Persist it as the current saved config (atomic) and archive the rollback
    // as a new revision, then reload the candidate so `show` reflects it.
    if let Some(parent) = cfg.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = cfg.with_extension("toml.tmp");
    std::fs::write(&tmp, &content).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &cfg).with_context(|| format!("installing {}", cfg.display()))?;
    archive_config(&cfg, &content)?;
    session
        .discard()
        .context("reloading the rolled-back config")?;
    Ok(())
}

/// Format epoch seconds as `YYYY-MM-DD HH:MM:SS UTC`, dependency-free.
fn fmt_utc(epoch_secs: i64) -> String {
    let days = epoch_secs.div_euclid(86_400);
    let secs = epoch_secs.rem_euclid(86_400);
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
}

/// Days-since-epoch → (year, month, day), Howard Hinnant's `civil_from_days`
/// (proleptic Gregorian, exact for the full range).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_from_days_matches_known_dates() {
        // Epoch day 0 is 1970-01-01.
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // A leap-day and a known modern date.
        assert_eq!(civil_from_days(59), (1970, 3, 1)); // 1970 not a leap year
        assert_eq!(civil_from_days(20_454), (2026, 1, 1));
    }

    #[test]
    fn fmt_utc_formats_a_known_instant() {
        // 2021-01-01 00:00:00 UTC = 1609459200.
        assert_eq!(fmt_utc(1_609_459_200), "2021-01-01 00:00:00 UTC");
    }

    #[test]
    fn parse_revision_nanos_accepts_only_our_names() {
        assert_eq!(
            parse_revision_nanos("config-00000000000001700000000.toml"),
            Some(1_700_000_000)
        );
        assert!(parse_revision_nanos("config-.toml").is_none());
        assert!(parse_revision_nanos("appliance.toml").is_none());
        assert!(parse_revision_nanos(".config-123.toml.tmp").is_none());
    }

    #[test]
    fn archive_snapshots_and_lists_newest_first() {
        let dir = std::env::temp_dir().join(format!("sentinel-archive-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("appliance.toml");

        // Two archived revisions with distinct, ordered names (the real path uses
        // the clock; here we drive the naming directly to stay deterministic).
        let adir = archive_dir(&cfg);
        std::fs::create_dir_all(&adir).unwrap();
        std::fs::write(
            adir.join("config-00000000000000000000001.toml"),
            "hostname = \"old\"",
        )
        .unwrap();
        std::fs::write(
            adir.join("config-00000000000000000000002.toml"),
            "hostname = \"new\"",
        )
        .unwrap();

        let revs = list_revisions(&cfg);
        assert_eq!(revs.len(), 2);
        assert_eq!(revs[0].index, 0);
        // Newest (higher nanos) first.
        assert_eq!(read_revision(&cfg, 0).unwrap(), "hostname = \"new\"");
        assert_eq!(read_revision(&cfg, 1).unwrap(), "hostname = \"old\"");
        assert!(read_revision(&cfg, 2).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn archive_config_prunes_to_keep_window() {
        let dir = std::env::temp_dir().join(format!("sentinel-prune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("appliance.toml");

        // Archiving is clock-driven; force ordering by pre-seeding beyond the keep
        // window, then one real archive, and assert the count is capped.
        let adir = archive_dir(&cfg);
        std::fs::create_dir_all(&adir).unwrap();
        for i in 0..(ARCHIVE_KEEP + 5) {
            std::fs::write(adir.join(format!("config-{i:020}.toml")), "x").unwrap();
        }
        archive_config(&cfg, "newest").unwrap();
        assert_eq!(list_revisions(&cfg).len(), ARCHIVE_KEEP);
        // The just-archived one is the newest.
        assert_eq!(read_revision(&cfg, 0).unwrap(), "newest");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
