//! Bounded, signed online-metadata freshness. This is not a TUF root/key-rotation
//! protocol and deliberately does not govern offline media or boot fallback.

use std::collections::BTreeMap;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

const DIRECTORY: &str = "/var/lib/sentinel/update-trust";
pub(super) const MAX_INTEGER: u64 = (1 << 53) - 1;
pub(super) const MAX_LIFETIME: u64 = 14 * 86400;
pub(super) const CLOCK_SKEW: u64 = 300;
// An unset RTC is not evidence that an otherwise expired signature is current.
pub(super) const MIN_CLOCK: u64 = 1704067200; // 2024-01-01 UTC; not a release timestamp.
const MAX_STATE: u64 = 1024 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Freshness {
    pub schema: u32,
    pub channel: String,
    pub arch: String,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
}

fn label_valid(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 64
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

impl Freshness {
    /// The manifest's own lifetime alone, without any channel timestamp.
    #[cfg(test)]
    pub(super) fn validate(&self, channel: &str, now: u64) -> Result<()> {
        self.validate_extended(channel, now, None)
    }

    /// Whether this metadata fails [`Self::validate`] ONLY because its own
    /// lifetime has ended: the one case a channel timestamp may cover.
    pub(super) fn expired_only(&self, channel: &str, now: u64) -> bool {
        now >= self.expires_at && self.validate_extended(channel, now, Some(u64::MAX)).is_ok()
    }

    /// [`Self::validate`], where `extended` is the expiry of a channel
    /// timestamp already verified to bind exactly this manifest
    /// ([`super::timestamp::extension`]). It can only lengthen the lifetime
    /// of metadata that is otherwise valid; every other check is unchanged.
    pub(super) fn validate_extended(
        &self,
        channel: &str,
        now: u64,
        extended: Option<u64>,
    ) -> Result<()> {
        ensure!(
            self.schema == 1
                && label_valid(channel)
                && self.channel == channel
                && self.arch == std::env::consts::ARCH,
            "signed update scope does not match the configured channel and architecture"
        );
        ensure!(
            self.sequence > 0
                && self.sequence <= MAX_INTEGER
                && self.issued_at >= MIN_CLOCK
                && self.issued_at <= MAX_INTEGER
                && self.expires_at > self.issued_at
                && self.expires_at <= MAX_INTEGER
                && self.expires_at - self.issued_at <= MAX_LIFETIME,
            "signed update freshness fields are invalid (maximum lifetime: 14 days)"
        );
        ensure!(
            (MIN_CLOCK..=MAX_INTEGER).contains(&now),
            "system clock is not usable for secure updates; configure time synchronization"
        );
        ensure!(
            self.issued_at <= now.saturating_add(CLOCK_SKEW),
            "signed update metadata is not yet valid; check time synchronization"
        );
        if now < self.expires_at {
            return Ok(());
        }
        let Some(until) = extended else {
            bail!("signed update metadata expired; request a fresh release");
        };
        ensure!(
            now < until,
            "signed update metadata expired and its channel timestamp expired too; \
             request a fresh release"
        );
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    channel: String,
    arch: String,
    public_key_sha256: String,
    sequence: u64,
    manifest_sha256: String,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    schema: u32,
    max_time: u64,
    #[serde(deserialize_with = "unique_scopes")]
    scopes: BTreeMap<String, Record>,
}
fn unique_scopes<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<BTreeMap<String, Record>, D::Error> {
    struct Unique;
    impl<'de> serde::de::Visitor<'de> for Unique {
        type Value = BTreeMap<String, Record>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("an object with unique update trust scopes")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut m: M,
        ) -> std::result::Result<Self::Value, M::Error> {
            let mut out = BTreeMap::new();
            while let Some((key, record)) = m.next_entry::<String, Record>()? {
                if out.insert(key, record).is_some() {
                    return Err(serde::de::Error::custom("duplicate update trust scope"));
                }
            }
            Ok(out)
        }
    }
    d.deserialize_map(Unique)
}
fn scope(channel: &str, arch: &str) -> String {
    super::digest_hex(format!("{}\n{channel}\n{arch}", super::PRODUCT).as_bytes())
}
fn hash_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Ledger {
    fn validate(&self) -> bool {
        self.schema == 1
            && (MIN_CLOCK..=MAX_INTEGER).contains(&self.max_time)
            && !self.scopes.is_empty()
            && self.scopes.len() <= 1024
            && self.scopes.iter().all(|(key, r)| {
                label_valid(&r.channel)
                    && r.arch == std::env::consts::ARCH
                    && *key == scope(&r.channel, &r.arch)
                    && hash_valid(&r.public_key_sha256)
                    && hash_valid(&r.manifest_sha256)
                    && r.sequence > 0
                    && r.sequence <= MAX_INTEGER
            })
    }
    fn observe(
        &mut self,
        f: &Freshness,
        channel: &str,
        manifest: &str,
        key: &str,
        now: u64,
        extended: Option<u64>,
    ) -> Result<()> {
        f.validate_extended(channel, now, extended)?;
        ensure!(
            hash_valid(manifest) && hash_valid(key),
            "invalid signed offer fingerprint"
        );
        ensure!(
            now.saturating_add(CLOCK_SKEW) >= self.max_time,
            "system clock moved behind the trusted update ledger; repair time synchronization"
        );
        f.validate_extended(channel, now.max(self.max_time), extended)?;
        let id = scope(channel, &f.arch);
        if let Some(old) = self.scopes.get(&id) {
            ensure!(
                old.public_key_sha256 == key,
                "update signing key changed without an authorized key rotation"
            );
        } else {
            // A channel label is configuration, not a trust boundary: whoever
            // may rename the channel must not thereby enrol a new signer
            // (CTRL-24). A first-ever check pins its key; later labels inherit.
            let mut pinned = self.scopes.values().filter(|r| r.arch == f.arch).peekable();
            ensure!(
                pinned.peek().is_none() || pinned.any(|r| r.public_key_sha256 == key),
                "update signing key differs from every key this appliance has pinned; a new \
                 channel cannot introduce a signer without an authorized key rotation"
            );
            ensure!(
                self.scopes.len() < 1024,
                "trusted update scope limit reached"
            );
        }
        // One signer, one sequence space: the floor is the highest sequence
        // this key has been seen at under ANY label, so a renamed or newly
        // selected channel cannot reopen metadata the signer has moved past.
        let signed: Vec<&Record> = self
            .scopes
            .values()
            .filter(|r| r.arch == f.arch && r.public_key_sha256 == key)
            .collect();
        if let Some(floor) = signed.iter().map(|r| r.sequence).max() {
            ensure!(
                f.sequence >= floor,
                "signed update metadata rollback refused"
            );
            ensure!(
                f.sequence != floor
                    || signed
                        .iter()
                        .filter(|r| r.sequence == floor)
                        .all(|r| r.manifest_sha256 == manifest),
                "signed update metadata sequence was reused for different bytes"
            );
        }
        self.max_time = now.max(self.max_time);
        self.scopes.insert(
            id,
            Record {
                channel: channel.to_owned(),
                arch: f.arch.clone(),
                public_key_sha256: key.to_owned(),
                sequence: f.sequence,
                manifest_sha256: manifest.to_owned(),
            },
        );
        Ok(())
    }
}

fn owned_file(dir: &File, name: &std::ffi::CStr, flags: i32, owner: u32) -> Result<File> {
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let st = file.metadata()?;
    ensure!(
        st.is_file() && st.uid() == owner && st.mode() & 0o7777 == 0o600 && st.nlink() == 1,
        "update trust file must be an owned mode-0600 regular file"
    );
    Ok(file)
}

/// Written once a ledger has been published, so a later missing ledger is
/// recognisably lost state rather than an initialization that never finished.
const PUBLISHED: &std::ffi::CStr = c"published";

/// Whether a trust directory holding no ledger is merely an interrupted first
/// initialization (CTRL-23): nothing in it but the lock and staged ledgers the
/// first check could have left behind, and no record that a ledger was ever
/// published. Anything else stays a refusal: a reset of an existing ledger
/// must never read as a fresh start.
fn never_published(dir: &File) -> Result<bool> {
    let listing = std::path::PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
    let mut staged = Vec::new();
    for entry in std::fs::read_dir(&listing).context("listing update trust directory")? {
        let name = entry?.file_name();
        let Some(name) = name.to_str() else {
            return Ok(false);
        };
        let is_staged = name
            .strip_prefix("ledger-")
            .and_then(|rest| rest.strip_suffix(".tmp"))
            .is_some_and(hash_valid);
        if is_staged {
            staged.push(std::ffi::CString::new(name)?);
        } else if name != "lock" {
            // Includes PUBLISHED: a published ledger that is now missing.
            return Ok(false);
        }
    }
    for name in staged {
        // An abandoned transaction is never read; removing it keeps the
        // directory in the shape this check recognises.
        unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) };
    }
    Ok(true)
}

/// Record durably that this directory has held a published ledger.
fn mark_published(dir: &File, owner: u32) -> Result<()> {
    let marker = owned_file(dir, PUBLISHED, libc::O_WRONLY | libc::O_CREAT, owner)
        .context("recording the published update trust ledger")?;
    marker.sync_all()?;
    dir.sync_all()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn observe_at(
    directory: &Path,
    owner: u32,
    f: &Freshness,
    channel: &str,
    manifest: &str,
    key: &str,
    now: u64,
    extended: Option<u64>,
) -> Result<()> {
    f.validate_extended(channel, now, extended)?;
    ensure!(
        unsafe { libc::geteuid() } == owner,
        "secure update check requires root to persist rollback protection"
    );
    let created = match DirBuilder::new().mode(0o700).create(directory) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(e) => return Err(e).context("creating persistent update trust directory"),
    };
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory)?;
    let st = dir.metadata()?;
    ensure!(
        st.is_dir() && st.uid() == owner && st.mode() & 0o7777 == 0o700,
        "update trust directory must be root-owned mode 0700"
    );
    let lock = owned_file(&dir, c"lock", libc::O_RDWR | libc::O_CREAT, owner)?;
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } == 0,
        "cannot lock persistent update trust ledger"
    );
    let mut ledger = match owned_file(&dir, c"ledger.json", libc::O_RDONLY, owner) {
        Ok(file) => {
            ensure!(
                file.metadata()?.len() <= MAX_STATE,
                "oversized update trust ledger"
            );
            let mut bytes = Vec::new();
            file.take(MAX_STATE + 1).read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 <= MAX_STATE,
                "oversized update trust ledger"
            );
            let state: Ledger = serde_json::from_slice(&bytes)
                .context("corrupt update trust ledger; refusing updates")?;
            ensure!(
                state.validate(),
                "invalid update trust ledger; refusing updates"
            );
            state
        }
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                && (created || never_published(&dir)?) =>
        {
            Ledger {
                schema: 1,
                max_time: now,
                scopes: BTreeMap::new(),
            }
        }
        Err(e) => {
            return Err(e)
                .context("update trust ledger unavailable; refusing to reset rollback protection");
        }
    };
    ledger.observe(f, channel, manifest, key, now, extended)?;
    let bytes = serde_json::to_vec(&ledger)?;
    ensure!(
        bytes.len() as u64 <= MAX_STATE,
        "oversized update trust ledger"
    );
    let mut random = [0u8; 16];
    getrandom::getrandom(&mut random)
        .map_err(|_| anyhow::anyhow!("cannot name trust ledger transaction"))?;
    let name = std::ffi::CString::new(format!("ledger-{}.tmp", super::digest_hex(&random)))?;
    let mut output = owned_file(
        &dir,
        &name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        owner,
    )?;
    let result = (|| {
        output.write_all(&bytes)?;
        output.sync_all()?;
        ensure!(
            unsafe {
                libc::renameat(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    dir.as_raw_fd(),
                    c"ledger.json".as_ptr(),
                )
            } == 0,
            "cannot publish durable update trust ledger"
        );
        dir.sync_all()?;
        mark_published(&dir, owner)?;
        if created {
            File::open(
                directory
                    .parent()
                    .context("trust directory has no parent")?,
            )?
            .sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) };
    }
    result
}

pub(super) fn observe(
    chan: &crate::config::UpdateChannel,
    offer: &super::VerifiedOffer,
) -> Result<()> {
    observe_with(
        chan,
        offer,
        Path::new(DIRECTORY),
        0,
        Path::new(super::timestamp::KEY_PATH),
    )
}

/// The one observation path: the release check, the pre-write recheck and the
/// tests all come through here, so a channel timestamp is judged identically
/// at the first disk write and at the offer.
fn observe_with(
    chan: &crate::config::UpdateChannel,
    offer: &super::VerifiedOffer,
    directory: &Path,
    owner: u32,
    timestamp_key: &Path,
) -> Result<()> {
    let f = offer.manifest.freshness.as_ref().context(
        "signed update metadata has no freshness policy; request a current signed release",
    )?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes Unix epoch")?
        .as_secs();
    let extended = super::timestamp::extension(chan, offer, f, timestamp_key, now)?;
    observe_at(
        directory,
        owner,
        f,
        chan.label(),
        &offer.manifest_sha256,
        &offer.public_key_sha256,
        now,
        extended,
    )
}

#[cfg(test)]
pub(super) fn observe_test(
    chan: &crate::config::UpdateChannel,
    offer: &super::VerifiedOffer,
    directory: &Path,
) -> Result<()> {
    observe_test_with_key(
        chan,
        offer,
        directory,
        &directory.join("no-timestamp-key.pem"),
    )
}

#[cfg(test)]
pub(super) fn observe_test_with_key(
    chan: &crate::config::UpdateChannel,
    offer: &super::VerifiedOffer,
    directory: &Path,
    timestamp_key: &Path,
) -> Result<()> {
    observe_with(
        chan,
        offer,
        directory,
        unsafe { libc::geteuid() },
        timestamp_key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fresh() -> Freshness {
        Freshness {
            schema: 1,
            channel: "enterprise".into(),
            arch: std::env::consts::ARCH.into(),
            sequence: 1,
            issued_at: MIN_CLOCK,
            expires_at: MIN_CLOCK + 3600,
        }
    }
    #[test]
    fn durable_floor_rejects_rollback_equivocation_key_change_and_bad_clock() {
        let parent = super::super::Scratch::new().unwrap();
        let directory = parent.join("trust");
        let owner = unsafe { libc::geteuid() };
        let write = |f: &Freshness, hash: &str, key: &str, time| {
            observe_at(&directory, owner, f, "enterprise", hash, key, time, None)
        };
        let mut f = fresh();
        write(&f, &"a".repeat(64), &"b".repeat(64), MIN_CLOCK + 301).unwrap();
        write(&f, &"a".repeat(64), &"b".repeat(64), MIN_CLOCK + 301).unwrap();
        assert!(write(&f, &"c".repeat(64), &"b".repeat(64), MIN_CLOCK + 301).is_err());
        assert!(write(&f, &"a".repeat(64), &"c".repeat(64), MIN_CLOCK + 301).is_err());
        assert!(write(&f, &"a".repeat(64), &"b".repeat(64), MIN_CLOCK).is_err());
        f.sequence = 2;
        write(&f, &"c".repeat(64), &"b".repeat(64), MIN_CLOCK + 302).unwrap();
        f.sequence = 1;
        assert!(write(&f, &"a".repeat(64), &"b".repeat(64), MIN_CLOCK + 303).is_err());
        let original = std::fs::read_to_string(directory.join("ledger.json")).unwrap();
        let id = scope("enterprise", std::env::consts::ARCH);
        let parsed: Ledger = serde_json::from_str(&original).unwrap();
        let record = serde_json::to_string(parsed.scopes.get(&id).unwrap()).unwrap();
        let duplicate = format!(
            r#"{{"schema":1,"max_time":{},"scopes":{{"{id}":{record},"{id}":{record}}}}}"#,
            MIN_CLOCK + 302
        );
        std::fs::write(directory.join("ledger.json"), duplicate).unwrap();
        assert!(write(&f, &"a".repeat(64), &"b".repeat(64), MIN_CLOCK + 303).is_err());
        std::fs::write(directory.join("ledger.json"), b"{}").unwrap();
        f.sequence = 3;
        assert!(write(&f, &"d".repeat(64), &"b".repeat(64), MIN_CLOCK + 304).is_err());
        std::fs::remove_file(directory.join("ledger.json")).unwrap();
        assert!(write(&f, &"d".repeat(64), &"b".repeat(64), MIN_CLOCK + 304).is_err());
    }
    #[test]
    fn an_interrupted_first_initialization_does_not_refuse_updates_forever() {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        let parent = super::super::Scratch::new().unwrap();
        let directory = parent.join("trust");
        let owner = unsafe { libc::geteuid() };
        // The state a crash or ENOSPC leaves behind during the very first
        // check: the directory and its lock exist, a staged ledger may exist,
        // but no ledger was ever published.
        DirBuilder::new().mode(0o700).create(&directory).unwrap();
        for name in [
            "lock",
            "ledger-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.tmp",
        ] {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(directory.join(name))
                .unwrap();
        }
        let write = |f: &Freshness, time| {
            observe_at(
                &directory,
                owner,
                f,
                "enterprise",
                &"a".repeat(64),
                &"b".repeat(64),
                time,
                None,
            )
        };
        write(&fresh(), MIN_CLOCK + 1).unwrap();
        assert!(directory.join("ledger.json").exists());
        // Once a ledger has been published, losing it is NOT a fresh start.
        std::fs::remove_file(directory.join("ledger.json")).unwrap();
        assert!(write(&fresh(), MIN_CLOCK + 2).is_err());
        // Unknown state beside a missing ledger is never read as "empty".
        let other = parent.join("other");
        DirBuilder::new().mode(0o700).create(&other).unwrap();
        std::fs::write(other.join("unexpected"), b"x").unwrap();
        assert!(
            observe_at(
                &other,
                owner,
                &fresh(),
                "enterprise",
                &"a".repeat(64),
                &"b".repeat(64),
                MIN_CLOCK + 1,
                None,
            )
            .is_err()
        );
    }
    #[test]
    fn a_new_channel_label_inherits_the_key_pin_and_sequence_floor() {
        let parent = super::super::Scratch::new().unwrap();
        let directory = parent.join("trust");
        let owner = unsafe { libc::geteuid() };
        let write = |label: &str, sequence, manifest: &str, key: &str| {
            let mut f = fresh();
            f.channel = label.into();
            f.sequence = sequence;
            observe_at(
                &directory,
                owner,
                &f,
                label,
                manifest,
                key,
                MIN_CLOCK + 1,
                None,
            )
        };
        write("enterprise", 50, &"a".repeat(64), &"b".repeat(64)).unwrap();
        // Renaming the channel must not let a different signer in.
        assert!(write("renamed", 60, &"c".repeat(64), &"d".repeat(64)).is_err());
        // Nor reopen sequences the pinned signer has already moved past.
        assert!(write("renamed", 49, &"c".repeat(64), &"b".repeat(64)).is_err());
        // The same signer at or above its floor may serve a new label.
        write("renamed", 50, &"a".repeat(64), &"b".repeat(64)).unwrap();
        write("renamed", 51, &"e".repeat(64), &"b".repeat(64)).unwrap();
        // And the floor it reached there binds the original label too.
        assert!(write("enterprise", 50, &"a".repeat(64), &"b".repeat(64)).is_err());
    }
    #[test]
    fn expiry_scope_future_ttl_and_unset_clock_fail_closed() {
        let f = fresh();
        f.validate("enterprise", MIN_CLOCK).unwrap();
        assert!(f.validate("enterprise", MIN_CLOCK + 3600).is_err());
        assert!(f.validate("community", MIN_CLOCK).is_err());
        assert!(f.validate("enterprise", 0).is_err());
        for (field, value) in [
            ("sequence", 0),
            ("sequence", MAX_INTEGER + 1),
            ("issued_at", MIN_CLOCK + 301),
            ("expires_at", MIN_CLOCK + MAX_LIFETIME + 1),
        ] {
            let mut json = serde_json::to_value(&f).unwrap();
            json[field] = value.into();
            let altered: Freshness = serde_json::from_value(json).unwrap();
            assert!(
                altered.validate("enterprise", MIN_CLOCK).is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn unsafe_files_and_symlinked_state_are_never_followed() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let parent = super::super::Scratch::new().unwrap();
        let directory = parent.join("trust");
        let owner = unsafe { libc::geteuid() };
        observe_at(
            &directory,
            owner,
            &fresh(),
            "enterprise",
            &"a".repeat(64),
            &"b".repeat(64),
            MIN_CLOCK,
            None,
        )
        .unwrap();
        std::fs::set_permissions(
            directory.join("ledger.json"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(
            observe_at(
                &directory,
                owner,
                &fresh(),
                "enterprise",
                &"a".repeat(64),
                &"b".repeat(64),
                MIN_CLOCK,
                None,
            )
            .is_err()
        );
        let link = parent.join("link");
        symlink(&directory, &link).unwrap();
        assert!(
            observe_at(
                &link,
                owner,
                &fresh(),
                "enterprise",
                &"a".repeat(64),
                &"b".repeat(64),
                MIN_CLOCK,
                None,
            )
            .is_err()
        );
    }
}
