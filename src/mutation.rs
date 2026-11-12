//! Boot-bound configuration mutation generations and short OTA checkpoints.
//!
//! Writers advance BEFORE their first possible side effect while holding the
//! common apply lock. Readers never initialize a missing generation. Expensive
//! parsing, hashing, probes and networking run outside the final checkpoint;
//! only nonblocking flock and descriptor/path metadata comparisons run inside.
use std::fs::{File, Metadata, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};

const EPOCH: &str = "/run/sentinel/mutation.json";
const LOCK: &str = "/run/sentinel/apply.lock";
const BOOT: &str = "/proc/sys/kernel/random/boot_id";
const PENDING: &str = "/var/lib/sentinel/.appliance.toml.pending.json";
const OUTBOX: &str = "/var/lib/sentinel/configsync/pending.json";

fn paths_idle(paths: &[PathBuf]) -> Result<bool> {
    for path in paths {
        match path.symlink_metadata() {
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(true)
}

/// OTA needs absence, not the contents of a provisional journal or delivery
/// outbox. Never read an untrusted FIFO, symlink target or oversized JSON here.
pub fn idle() -> Result<bool> {
    paths_idle(&[PathBuf::from(PENDING), PathBuf::from(OUTBOX)])
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Epoch {
    boot: String,
    nonce: String,
}

fn fresh(boot: String) -> Result<Epoch> {
    let mut bytes = [0; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("generating configuration mutation nonce"))?;
    Ok(Epoch {
        boot,
        nonce: bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
    })
}

fn read_epoch(token: &Token, boot: &str) -> Result<Epoch> {
    let mut bytes = Vec::new();
    token
        .file
        .as_ref()
        .context("mutation generation missing")?
        .take(1025)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 1024, "mutation generation oversized");
    let epoch: Epoch = serde_json::from_slice(&bytes)?;
    ensure!(
        epoch.boot == boot
            && epoch.nonce.len() == 64
            && epoch
                .nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid or previous-boot mutation generation"
    );
    Ok(epoch)
}

/// Called ONLY by the real boot apply, under the common lock. Restarting that
/// service in the same boot must not reset the mutation history.
pub fn initialize_boot() -> Result<()> {
    let _lock = crate::system::apply_lock()?;
    let boot = std::fs::read_to_string(BOOT)?.trim().to_string();
    match Token::open(Path::new(EPOCH), false, false, 0) {
        Ok(token) => {
            read_epoch(&token, &boot)?;
            token.check()?;
        }
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            crate::system::install_config_file(
                Path::new(EPOCH),
                &serde_json::to_string(&fresh(boot)?)?,
            )?;
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

/// No runtime directory is the existing off-box editing mode, not an OTA
/// appliance. A live appliance with a missing/corrupt epoch fails before writes.
pub fn advance() -> Result<()> {
    if !Path::new("/run/sentinel").is_dir() {
        return Ok(());
    }
    let _lock = crate::system::apply_lock()?;
    let token = Token::open(Path::new(EPOCH), false, false, 0)?;
    let boot = std::fs::read_to_string(BOOT)?.trim().to_string();
    let old = read_epoch(&token, &boot)?;
    token.check()?;
    let next = fresh(boot)?;
    ensure!(old.nonce != next.nonce, "mutation nonce repeated");
    crate::system::install_config_file(Path::new(EPOCH), &serde_json::to_string(&next)?)
}

/// Atomic publishers are shared by CLI save, live snapshots and safe-apply's
/// journal. Other secrets, timer refreshes and outbox acknowledgements are NOT
/// configuration intent and must not invalidate every reviewed offer.
pub fn intent_path(path: &Path) -> bool {
    [
        crate::session::DEFAULT_CONFIG,
        crate::session::Session::RUNNING,
        PENDING,
    ]
    .into_iter()
    .any(|value| path == Path::new(value))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    size: u64,
    links: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
impl From<&Metadata> for Stamp {
    fn from(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            size: m.size(),
            links: m.nlink(),
            mode: m.mode(),
            uid: m.uid(),
            gid: m.gid(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        }
    }
}

struct Token {
    path: PathBuf,
    follow: bool,
    file: Option<File>,
    stamp: Option<Stamp>,
    link: Option<Stamp>,
}
impl Token {
    fn open(path: &Path, optional: bool, follow: bool, owner: u32) -> Result<Self> {
        let flags = libc::O_CLOEXEC | libc::O_NONBLOCK | if follow { 0 } else { libc::O_NOFOLLOW };
        let file = match OpenOptions::new().read(true).custom_flags(flags).open(path) {
            Ok(file) => file,
            Err(error) if optional && error.kind() == std::io::ErrorKind::NotFound => {
                // A dangling link is not legitimate optional absence.
                ensure!(
                    matches!(path.symlink_metadata(), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
                    "protected path is a dangling link"
                );
                return Ok(Self {
                    path: path.into(),
                    follow,
                    file: None,
                    stamp: None,
                    link: None,
                });
            }
            Err(error) => return Err(error).context("opening protected update context"),
        };
        let m = file.metadata()?;
        ensure!(
            m.is_file() && m.uid() == owner && m.mode() & 0o022 == 0 && (follow || m.nlink() == 1),
            "protected update context must be an owner-controlled regular file"
        );
        Ok(Self {
            path: path.into(),
            follow,
            stamp: Some(Stamp::from(&m)),
            file: Some(file),
            link: follow
                .then(|| path.symlink_metadata().map(|m| Stamp::from(&m)))
                .transpose()?,
        })
    }
    fn check(&self) -> Result<()> {
        if let Some(link) = &self.link {
            ensure!(
                &Stamp::from(&self.path.symlink_metadata()?) == link,
                "protected symlink changed"
            );
        }
        if let Some(file) = &self.file {
            ensure!(
                Some(Stamp::from(&file.metadata()?)) == self.stamp,
                "protected descriptor changed"
            );
        }
        // Always lstat absence, even for a path where legitimate symlinks may
        // be followed. A newly-created dangling symlink is not absence.
        let metadata = if self.follow && self.file.is_some() {
            self.path.metadata()
        } else {
            self.path.symlink_metadata()
        };
        match metadata {
            Ok(m) => ensure!(
                Some(Stamp::from(&m)) == self.stamp,
                "protected pathname changed"
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                ensure!(self.stamp.is_none(), "protected pathname removed")
            }
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }
}

pub struct Observation {
    lock: File,
    lock_path: PathBuf,
    lock_identity: (u64, u64),
    owner: u32,
    // One borrowed checkpoint cannot be shared across concurrent flock calls
    // on the same open-file description (which would not exclude each other).
    not_sync: std::marker::PhantomData<std::cell::Cell<()>>,
    tokens: Vec<Token>,
    absent: [PathBuf; 2],
    pub nonce: String,
}
#[derive(Debug)]
pub struct Busy;
impl std::fmt::Display for Busy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("configuration writer is busy")
    }
}
impl std::error::Error for Busy {}

impl Observation {
    pub fn begin(config: &Path) -> Result<Self> {
        let boot = std::fs::read_to_string(BOOT)?.trim().to_string();
        let mut result = Self::at(
            Path::new(LOCK),
            Path::new(EPOCH),
            &boot,
            0,
            [PathBuf::from(PENDING), PathBuf::from(OUTBOX)],
        )?;
        result.add(config, false, false)?;
        result.add(Path::new(crate::session::Session::RUNNING), true, false)?;
        result.add(Path::new("/boot/loader/loader.conf"), true, false)?;
        for name in ["LoaderEntryDefault", "LoaderEntryOneShot"] {
            result.add(
                &Path::new("/sys/firmware/efi/efivars")
                    .join(format!("{name}-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f")),
                true,
                false,
            )?;
        }
        result.check(false)?;
        Ok(result)
    }

    fn at(
        lock_path: &Path,
        epoch: &Path,
        boot: &str,
        owner: u32,
        absent: [PathBuf; 2],
    ) -> Result<Self> {
        // Open existing lock only. No creation, chmod/chown, NSS lookup or
        // content reads are allowed inside the final critical section.
        let lock = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(lock_path)?;
        let m = lock.metadata()?;
        ensure!(
            m.is_file() && m.uid() == owner && m.nlink() == 1 && m.mode() & 0o007 == 0,
            "untrusted configuration lock"
        );
        let token = Token::open(epoch, false, false, owner)?;
        let epoch = read_epoch(&token, boot)?;
        Ok(Self {
            lock,
            lock_path: lock_path.into(),
            lock_identity: (m.dev(), m.ino()),
            owner,
            not_sync: std::marker::PhantomData,
            tokens: vec![token],
            absent,
            nonce: epoch.nonce,
        })
    }

    pub fn add(&mut self, path: &Path, optional: bool, follow: bool) -> Result<()> {
        self.tokens.push(Token::open(path, optional, follow, 0)?);
        Ok(())
    }

    /// Linearization point. No blocking lock wait, subprocess, hashing,
    /// configuration parse, content I/O, directory enumeration or publication.
    pub fn check(&self, require_idle: bool) -> Result<()> {
        if unsafe { libc::flock(self.lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                return Err(Busy.into());
            }
            return Err(error.into());
        }
        struct Unlock<'a>(&'a File);
        impl Drop for Unlock<'_> {
            fn drop(&mut self) {
                let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
            }
        }
        let _unlock = Unlock(&self.lock);
        let m = self.lock_path.symlink_metadata()?;
        ensure!(
            m.is_file()
                && (m.dev(), m.ino()) == self.lock_identity
                && m.uid() == self.owner
                && m.nlink() == 1
                && m.mode() & 0o007 == 0,
            "configuration lock replaced"
        );
        for token in &self.tokens {
            token.check()?;
        }
        if require_idle {
            ensure!(
                paths_idle(&self.absent)?,
                "configuration confirmation or config-sync delivery is pending"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    const BOOT_ID: &str = "12345678-1234-1234-1234-123456789abc";

    fn fixture() -> (crate::update::Scratch, Observation) {
        let scratch = crate::update::Scratch::new().unwrap();
        let lock = scratch.join("apply.lock");
        std::fs::write(&lock, b"").unwrap();
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o660)).unwrap();
        std::fs::write(
            scratch.join("epoch"),
            serde_json::to_vec(&fresh(BOOT_ID.into()).unwrap()).unwrap(),
        )
        .unwrap();
        let observation = Observation::at(
            &lock,
            &scratch.join("epoch"),
            BOOT_ID,
            unsafe { libc::geteuid() },
            [scratch.join("journal"), scratch.join("outbox")],
        )
        .unwrap();
        (scratch, observation)
    }

    #[test]
    fn mutation_epoch_is_boot_bound_strict_bounded_and_missing_is_not_initialized() {
        let (scratch, observation) = fixture();
        observation.check(true).unwrap();
        let path = scratch.join("epoch");
        let owner = unsafe { libc::geteuid() };
        for bytes in [
            b"{}".to_vec(),
            serde_json::to_vec(&fresh("previous boot".into()).unwrap()).unwrap(),
            format!(
                "{{\"boot\":\"{BOOT_ID}\",\"nonce\":\"{}\",\"nonce\":\"{}\"}}",
                "a".repeat(64),
                "b".repeat(64)
            )
            .into_bytes(),
            vec![b' '; 1025],
        ] {
            std::fs::write(&path, bytes).unwrap();
            let token = Token::open(&path, false, false, owner).unwrap();
            assert!(read_epoch(&token, BOOT_ID).is_err());
        }
        std::fs::remove_file(&path).unwrap();
        assert!(Token::open(&path, false, false, owner).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn mutation_checkpoint_refuses_busy_without_waiting_and_never_unlinks_lock() {
        let (scratch, observation) = fixture();
        let path = scratch.join("apply.lock");
        let identity = path.metadata().unwrap().ino();
        let (ready, started) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _lock = crate::system::lock_config_at(&path).unwrap();
            ready.send(()).unwrap();
            wait.recv_timeout(Duration::from_secs(5)).unwrap();
        });
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        let now = Instant::now();
        assert!(observation.check(true).unwrap_err().is::<Busy>());
        assert!(now.elapsed() < Duration::from_millis(250));
        release.send(()).unwrap();
        worker.join().unwrap();
        observation.check(true).unwrap();
        assert_eq!(
            scratch.join("apply.lock").metadata().unwrap().ino(),
            identity
        );
    }

    #[test]
    fn mutation_slow_observation_does_not_hold_apply_lock_and_aba_invalidates_it() {
        let (scratch, observation) = fixture();
        let config = scratch.join("config");
        std::fs::write(&config, "unchanged saved bytes").unwrap();
        let before = std::fs::read(&config).unwrap();
        let lock = scratch.join("apply.lock");
        let epoch = scratch.join("epoch");
        let worker = std::thread::spawn(move || {
            let _lock = crate::system::lock_config_at(&lock).unwrap();
            let next = epoch.with_extension("next");
            std::fs::write(
                &next,
                serde_json::to_vec(&fresh(BOOT_ID.into()).unwrap()).unwrap(),
            )
            .unwrap();
            std::fs::rename(next, epoch).unwrap();
        });
        worker.join().unwrap();
        assert_eq!(std::fs::read(&config).unwrap(), before);
        assert!(observation.check(true).is_err());
    }

    #[test]
    fn mutation_protected_tokens_detect_replacement_rewrite_removal_and_permissions() {
        let owner = unsafe { libc::geteuid() };
        for operation in 0..4 {
            let (scratch, mut observation) = fixture();
            let path = scratch.join("config");
            std::fs::write(&path, "same bytes").unwrap();
            observation
                .tokens
                .push(Token::open(&path, false, false, owner).unwrap());
            observation.check(true).unwrap();
            match operation {
                0 => {
                    let next = scratch.join("next");
                    std::fs::write(&next, "same bytes").unwrap();
                    std::fs::rename(next, &path).unwrap();
                }
                1 => {
                    std::fs::write(&path, "different bytes").unwrap();
                    std::fs::write(&path, "same bytes").unwrap();
                }
                2 => std::fs::remove_file(&path).unwrap(),
                _ => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap()
                }
            }
            assert!(observation.check(true).is_err(), "operation {operation}");
        }
    }

    #[test]
    fn mutation_pending_unknown_or_dangling_journal_and_outbox_fail_closed() {
        for name in ["journal", "outbox"] {
            for directory in [false, true] {
                let (scratch, observation) = fixture();
                let path = scratch.join(name);
                if directory {
                    std::fs::create_dir(&path).unwrap();
                } else {
                    symlink(scratch.join("absent"), &path).unwrap();
                }
                assert!(observation.check(true).is_err());
                // Read-only identity observation is still possible; absence
                // is a write-admission policy, not evidence of peer health.
                observation.check(false).unwrap();
            }
        }
    }

    #[test]
    fn mutation_idle_never_opens_fifo_journal_and_preserves_unknown_errors() {
        let (scratch, observation) = fixture();
        assert!(paths_idle(&observation.absent).unwrap());
        let path = scratch.join("journal");
        let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let start = Instant::now();
        assert!(!paths_idle(&observation.absent).unwrap());
        assert!(start.elapsed() < Duration::from_millis(250));
        let parent = scratch.join("not-directory");
        std::fs::write(&parent, "regular file").unwrap();
        assert!(paths_idle(&[parent.join("journal")]).is_err());
    }

    #[test]
    fn mutation_tokens_allow_public_pin_symlinks_but_refuse_fifo_and_config_symlink() {
        let (scratch, _) = fixture();
        let owner = unsafe { libc::geteuid() };
        let file = scratch.join("regular");
        std::fs::write(&file, "public pin").unwrap();
        let link = scratch.join("link");
        symlink(&file, &link).unwrap();
        Token::open(&link, false, true, owner)
            .unwrap()
            .check()
            .unwrap();
        assert!(Token::open(&link, false, false, owner).is_err());
        let fifo = scratch.join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let start = Instant::now();
        assert!(Token::open(&fifo, false, false, owner).is_err());
        assert!(start.elapsed() < Duration::from_millis(250));
        assert!(Token::open(&file, false, false, owner ^ 1).is_err());
    }

    #[test]
    fn mutation_epoch_and_lock_replacement_cannot_authorize_writes() {
        let (scratch, observation) = fixture();
        let next = scratch.join("other.lock");
        std::fs::write(&next, b"").unwrap();
        std::fs::rename(next, scratch.join("apply.lock")).unwrap();
        assert!(observation.check(true).is_err());
    }

    #[test]
    fn mutation_intent_publishers_exclude_refresh_and_delivery_bookkeeping() {
        for path in [
            crate::session::DEFAULT_CONFIG,
            crate::session::Session::RUNNING,
            PENDING,
        ] {
            assert!(intent_path(Path::new(path)));
        }
        for path in [
            EPOCH,
            OUTBOX,
            "/etc/velstra/velstra.toml",
            "/tmp/appliance.toml",
        ] {
            assert!(!intent_path(Path::new(path)));
        }
    }
}
