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

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
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
/// How many revisions to keep when the configuration does not say (older ones
/// are pruned on each new archive).
pub const ARCHIVE_KEEP: usize = 50;

/// One archived revision.
pub struct Revision {
    /// Recency index — 0 is the newest.
    pub index: usize,
    /// Epoch nanoseconds the revision was archived at (from the filename).
    pub nanos: u128,
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

fn open_directory(dir: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir)
}

/// Resolve children relative to the already-open directory, not a pathname
/// that could have been replaced since the no-follow check. Linux appliances
/// mount procfs; this descriptor is never handed to a child process.
fn descriptor_path(directory: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
}

fn permissions(file: &File, uid: u32, gid: u32, mode: u32) -> Result<()> {
    let metadata = file.metadata()?;
    if metadata.uid() != uid || metadata.gid() != gid {
        // Use the descriptor throughout: chown(path) would follow a substituted
        // symlink. Keep an already-correct uid unchanged for unprivileged saves.
        let owner = if metadata.uid() == uid { !0 } else { uid };
        anyhow::ensure!(
            unsafe { libc::fchown(file.as_raw_fd(), owner, gid) } == 0,
            std::io::Error::last_os_error()
        );
    }
    if metadata.mode() & 0o7777 != mode {
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

/// Restrict historical copies as well as new ones. This runs before logins and
/// management services at boot and on every archive write. Do not follow links
/// or chmod a hard-linked file outside this dedicated directory. A malformed
/// archive fails closed and needs an administrator, never a recursive chmod.
fn protect_local(config_path: &Path, create: bool) -> Result<Option<File>> {
    let dir = archive_dir(config_path);
    if create {
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("creating private configuration archive"),
        }
    }
    let directory = match open_directory(&dir) {
        Ok(directory) => directory,
        Err(error) if !create && error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).context("opening configuration archive without following links");
        }
    };
    let parent = dir
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let owner = std::fs::metadata(parent)?;
    let gid = crate::system::wheel_gid().unwrap_or(owner.gid());
    // Remove public traversal FIRST, including on legacy 0755 directories.
    // Keep wheel access (like the saved config), but no group write permission.
    permissions(&directory, owner.uid(), gid, 0o750)?;
    let stable = descriptor_path(&directory);
    for entry in std::fs::read_dir(&stable)? {
        let entry = entry?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(entry.path())
            .context("opening historical configuration archive without following links")?;
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file() && metadata.nlink() == 1,
            "configuration archive contains a non-regular or multiply-linked entry"
        );
        permissions(&file, owner.uid(), gid, 0o640)?;
    }
    directory.sync_all()?;
    Ok(Some(directory))
}

/// Boot-time permission migration, intentionally independent of config parsing
/// and the apply lock: even an invalid saved config must not expose old secrets.
/// The privileged re-invocation must not deadlock its parent's held apply lock.
pub fn protect_archives(config_path: &Path, create: bool) -> Result<()> {
    protect_local(config_path, create).map(|_| ())
}

fn prepare_archive(config_path: &Path) -> Result<File> {
    match protect_local(config_path, true) {
        Ok(Some(directory)) => Ok(directory),
        Ok(None) => unreachable!("creation requested"),
        Err(error)
            if !crate::system::is_root()
                && error.chain().any(|cause| {
                    cause
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied)
                }) =>
        {
            let absolute = std::path::absolute(config_path)?;
            crate::system::sudo(
                "sentinel-self",
                &[
                    "protect-archives",
                    "--create",
                    "--config",
                    absolute.to_str().context("non-UTF-8 config path")?,
                ],
            )?;
            open_directory(&archive_dir(config_path))
                .context("opening protected configuration archive")
        }
        Err(error) => Err(error),
    }
}

/// Snapshot `contents` (the just-saved config TOML) as a new revision, then prune
/// to the most recent [`ARCHIVE_KEEP`]. Best-effort by design: a failure to
/// archive must never fail the `save` itself, so callers log rather than
/// propagate. Revisions carry the SAME secrets as the saved config: 0640 with
/// wheel read access in a 0750 directory. Operators escalate through the shared
/// atomic installer when the directory is root-owned.
pub fn archive_config(config_path: &Path, contents: &str, keep: usize) -> Result<()> {
    let _transaction = crate::system::apply_lock()?;
    let dir = archive_dir(config_path);
    let _directory = prepare_archive(config_path)?;

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // Zero-pad so lexical order == chronological order for the foreseeable range.
    let name = format!("{ARCHIVE_PREFIX}{nanos:020}{ARCHIVE_SUFFIX}");
    let path = dir.join(&name);

    crate::system::install_config_file(&path, contents)?;
    prune(&dir, keep);
    Ok(())
}

/// Remove all but the newest `keep` revisions (best-effort).
fn prune(dir: &Path, keep: usize) {
    let mut files = revision_files(dir);
    // Newest first; drop everything past the keep window.
    files.sort_by_key(|f| std::cmp::Reverse(f.1));
    for (path, _) in files.into_iter().skip(keep.max(1)) {
        if std::fs::remove_file(&path).is_ok() {
            continue;
        }
        // A revision written through the escalating path above is root-owned, so
        // an operator cannot unlink it directly. Without this the window an
        // operator set would be the one number in `system commit-revisions` that
        // did nothing.
        if let Some(p) = path.to_str() {
            let _ = crate::system::sudo("rm", &["-f", p]);
        }
    }
}

/// The revision files in `dir` as `(path, nanos)`, unsorted. Non-matching names
/// are ignored.
fn revision_files(dir: &Path) -> Vec<(PathBuf, u128)> {
    let Ok(directory) = open_directory(dir) else {
        return Vec::new();
    };
    revision_files_in(&directory, dir)
}

fn revision_files_in(directory: &File, dir: &Path) -> Vec<(PathBuf, u128)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(descriptor_path(directory)) else {
        return out;
    };
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some(nanos) = parse_revision_nanos(name) {
            out.push((dir.join(name), nanos));
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
        .map(|(index, (_, nanos))| Revision { index, nanos })
        .collect()
}

/// The TOML content of revision `n` (0 = newest).
pub fn read_revision(config_path: &Path, n: usize) -> Result<String> {
    let dir = archive_dir(config_path);
    let directory =
        open_directory(&dir).context("opening configuration archive without following links")?;
    let mut revs = revision_files_in(&directory, &dir);
    revs.sort_by_key(|f| std::cmp::Reverse(f.1));
    let (path, _) = revs
        .get(n)
        .ok_or_else(|| anyhow::anyhow!("no revision {n} (have {})", revs.len()))?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(descriptor_path(&directory).join(path.file_name().context("revision filename")?))?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.nlink() == 1,
        "revision is not a private regular file"
    );
    let mut content = String::new();
    file.read_to_string(&mut content)
        .context("reading configuration revision")?;
    Ok(content)
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
        // A revert to an archived revision: `None`, so a partial broad-apply
        // failure reports mixed-state rather than reconciling back to the
        // config the operator explicitly asked to leave.
        crate::repl::apply_live(&appliance, act, None).context("applying the revision")?;
    }

    // Persist it as the current saved config and archive the rollback as a new
    // revision, then reload the candidate so `show` reflects it.
    //
    // Through the same installer `save` uses, rather than writing the file
    // here: the saved config is root-owned, so an operator's rollback wrote
    // nothing and said "Permission denied" — while the commit that followed it
    // succeeded, which made the failure look like noise.
    if let Some(parent) = cfg.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    crate::system::install_config_file(&cfg, &content)?;
    archive_config(&cfg, &content, ARCHIVE_KEEP)?;
    session
        .discard()
        .context("reloading the rolled-back config")?;
    Ok(())
}

/// Format epoch seconds as `YYYY-MM-DD HH:MM:SS UTC`, dependency-free.
pub(crate) fn fmt_utc(epoch_secs: i64) -> String {
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

    struct Directory(PathBuf);
    impl Directory {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("sentinel-archive-{name}-{}", std::process::id()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn config(&self) -> PathBuf {
            self.0.join("appliance.toml")
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn new_and_historical_archives_match_the_saved_config_access_boundary() {
        let dir = Directory::new("privacy");
        let config = dir.config();
        let archive = archive_dir(&config);
        std::fs::create_dir(&archive).unwrap();
        std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Legacy revision and an interrupted old predictable temporary copy.
        for name in ["config-00000000000000000001.toml", ".config-2.toml.tmp"] {
            let path = archive.join(name);
            std::fs::write(&path, "test credential, never a real secret").unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        archive_config(&config, "new test credential", 10).unwrap();
        let metadata = std::fs::metadata(&archive).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o750);
        assert_eq!(metadata.uid(), std::fs::metadata(&dir.0).unwrap().uid());
        for entry in std::fs::read_dir(&archive).unwrap() {
            let file = entry.unwrap().metadata().unwrap();
            assert_eq!(file.mode() & 0o7777, 0o640);
            assert_eq!(file.uid(), metadata.uid());
            assert_eq!(file.gid(), metadata.gid());
        }
        assert_eq!(read_revision(&config, 0).unwrap(), "new test credential");
        protect_archives(&config, false).unwrap(); // repeat migration is harmless
        assert_eq!(list_revisions(&config).len(), 2);
    }

    #[test]
    fn missing_history_is_not_created_by_boot_migration() {
        let dir = Directory::new("missing");
        protect_archives(&dir.config(), false).unwrap();
        assert!(!archive_dir(&dir.config()).exists());
    }

    #[test]
    fn linked_archive_directory_is_refused_without_touching_its_target() {
        let dir = Directory::new("linked-directory");
        let outside = dir.0.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o755)).unwrap();
        let victim = outside.join("config-9999999999999999999.toml");
        std::fs::write(&victim, "unrelated content").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(&outside, archive_dir(&dir.config())).unwrap();
        assert!(archive_config(&dir.config(), "never write", 10).is_err());
        assert!(read_revision(&dir.config(), 0).is_err());
        assert!(list_revisions(&dir.config()).is_empty());
        assert_eq!(std::fs::metadata(&outside).unwrap().mode() & 0o7777, 0o755);
        assert_eq!(std::fs::metadata(&victim).unwrap().mode() & 0o7777, 0o644);
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "unrelated content"
        );
    }

    #[test]
    fn linked_revision_is_not_read_or_chmodded() {
        for hard in [false, true] {
            let dir = Directory::new(if hard { "hardlink" } else { "symlink" });
            let victim = dir.0.join("outside.toml");
            std::fs::write(&victim, "unrelated content").unwrap();
            std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
            let archive = archive_dir(&dir.config());
            std::fs::create_dir(&archive).unwrap();
            let linked = archive.join("config-9999999999999999999.toml");
            if hard {
                std::fs::hard_link(&victim, &linked).unwrap();
            } else {
                std::os::unix::fs::symlink(&victim, &linked).unwrap();
            }
            assert!(archive_config(&dir.config(), "never write", 10).is_err());
            assert!(read_revision(&dir.config(), 0).is_err());
            assert_eq!(std::fs::metadata(&victim).unwrap().mode() & 0o7777, 0o644);
            assert_eq!(
                std::fs::read_to_string(&victim).unwrap(),
                "unrelated content"
            );
            assert_eq!(std::fs::metadata(&archive).unwrap().mode() & 0o7777, 0o750);
        }
    }

    #[test]
    fn non_regular_revision_cannot_block_a_reader_or_permission_migration() {
        let dir = Directory::new("fifo");
        let archive = archive_dir(&dir.config());
        std::fs::create_dir(&archive).unwrap();
        let fifo = archive.join("config-9999999999999999999.toml");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(list_revisions(&dir.config()).is_empty());
        assert!(read_revision(&dir.config(), 0).is_err());
        assert!(protect_archives(&dir.config(), false).is_err());
    }

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
        archive_config(&cfg, "newest", ARCHIVE_KEEP).unwrap();
        assert_eq!(list_revisions(&cfg).len(), ARCHIVE_KEEP);
        // The just-archived one is the newest.
        assert_eq!(read_revision(&cfg, 0).unwrap(), "newest");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
