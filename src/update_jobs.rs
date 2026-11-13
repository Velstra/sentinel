//! Durable local Check/Stage jobs. No reboot, remote member, unsigned source,
//! downgrade override, shell command or request-owned update process exists.
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

use crate::{config::Appliance, install, system, update};

const DIRECTORY: &str = "/var/lib/sentinel/update-jobs";
const MAX_STATE: usize = 32 * 1024;
// The design's 16 KiB per-record bound remains enforced. The one atomic
// registry holds eight retained records plus one running record, so it has a
// separate 32 KiB aggregate ceiling (not nine times the record ceiling).
const MAX_JOB: usize = 16 * 1024;
const HISTORY: usize = 8;
const CHECK_SECONDS: u64 = 240;
const STAGE_SECONDS: u64 = 8 * 60 * 60;
const PROBE_BYTES: usize = 65536;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Code {
    InvalidRequest,
    UnsupportedRuntime,
    UnstableBoot,
    Conflict,
    Busy,
    NotFound,
    StateUnavailable,
    WorkerUnavailable,
    MetadataRefused,
    DownloadRefused,
    StageRefused,
    Interrupted,
    WriteOutcomeUnknown,
}
impl Code {
    pub fn message(self) -> &'static str {
        match self {
            Self::InvalidRequest => "Malformed local update request.",
            Self::UnsupportedRuntime => {
                "Updates require the live root-owned A/B appliance and canonical saved configuration; off-box and no-apply servers cannot run updates."
            }
            Self::UnstableBoot => {
                "The current image must be permanently assessed, healthy and the next default before staging an update."
            }
            Self::Conflict => {
                "Configuration, signing key, boot identity or reviewed release changed; check and review again."
            }
            Self::Busy => {
                "A configuration writer or update operation is busy; no new slot write was authorized."
            }
            Self::NotFound => "That update job is not retained on this appliance.",
            Self::StateUnavailable => {
                "Protected update state is unavailable or invalid; no new update was authorized."
            }
            Self::WorkerUnavailable => {
                "Worker launch was not acknowledged. Refresh this job and inspect appliance services; do not blindly resubmit it."
            }
            Self::MetadataRefused => {
                "The saved channel could not provide an eligible release verified by its pinned key. The appliance keeps running unchanged."
            }
            Self::DownloadRefused => {
                "Image transfer or verification failed before slot writing. Check channel access and persistent update capacity."
            }
            Self::StageRefused => {
                "The update was refused before slot writing; review boot, configuration and image compatibility."
            }
            Self::Interrupted => {
                "The update worker was interrupted; it will not resume or retry automatically."
            }
            Self::WriteOutcomeUnknown => {
                "The writer was interrupted or could not confirm publication. The inactive slot or next boot may have changed; inspect boot selection before rebooting."
            }
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Error(pub Code);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.message())
    }
}
impl std::error::Error for Error {}
type JobResult<T> = std::result::Result<T, Error>;
fn unavailable(_: impl std::fmt::Debug) -> Error {
    Error(Code::StateUnavailable)
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    Check,
    Stage,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    Accepted,
    Metadata,
    Downloading,
    Verifying,
    Preflight,
    Writing,
    Publishing,
    Checked,
    Staged,
    Failed,
    Interrupted,
}
impl Phase {
    fn terminal(self) -> bool {
        matches!(
            self,
            Self::Checked | Self::Staged | Self::Failed | Self::Interrupted
        )
    }
    fn may_have_written(self) -> bool {
        matches!(self, Self::Writing | Self::Publishing)
    }
    fn permits(self, next: Self) -> bool {
        // Worker admission/terminal results are separate journal operations.
        // Engine observations may repeat but never skip prewrite assessment
        // or erase an acknowledged Writing/Publishing uncertainty boundary.
        matches!(
            (self, next),
            (Self::Metadata, Self::Metadata | Self::Downloading)
                | (Self::Downloading, Self::Downloading | Self::Verifying)
                | (Self::Verifying, Self::Verifying | Self::Preflight)
                | (Self::Preflight, Self::Preflight | Self::Writing)
                | (Self::Writing, Self::Writing | Self::Publishing)
                | (Self::Publishing, Self::Publishing)
        )
    }
}
impl From<install::UpdatePhase> for Phase {
    fn from(value: install::UpdatePhase) -> Self {
        match value {
            install::UpdatePhase::Metadata => Self::Metadata,
            install::UpdatePhase::Downloading => Self::Downloading,
            install::UpdatePhase::Verifying => Self::Verifying,
            install::UpdatePhase::Preflight => Self::Preflight,
            install::UpdatePhase::Writing => Self::Writing,
            install::UpdatePhase::Publishing => Self::Publishing,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub boot_id: String,
    pub mutation_epoch: String,
    pub config_revision: String,
    pub public_key_sha256: String,
    pub release: String,
    pub slot: String,
    pub verity: String,
    pub selected_entry: String,
    pub next_entry: String,
    pub uki_sha256: String,
    pub verity_guid: String,
    pub store_guid: String,
    pub permanent: bool,
}
impl Snapshot {
    fn stable(&self) -> bool {
        self.permanent && self.selected_entry == self.next_entry
    }
    fn validate(&self) -> bool {
        self.validate_with(crate::boot_entry::native_enabled())
    }
    fn validate_with(&self, native: bool) -> bool {
        is_boot_id(&self.boot_id)
            && [
                &self.mutation_epoch,
                &self.config_revision,
                &self.public_key_sha256,
                &self.verity,
                &self.uki_sha256,
            ]
            .into_iter()
            .all(|s| is_id(s))
            && matches!(self.slot.as_str(), "sentinel-a" | "sentinel-b")
            && !self.release.is_empty()
            && self.release.len() <= 128
            && crate::boot_entry::Entry::parse(&self.selected_entry, native).is_some_and(|entry| {
                entry.matches_running(&self.slot, &self.release)
                    && self.permanent == entry.permanent_for(&self.slot, &self.release)
            })
            && crate::boot_entry::Entry::parse(&self.next_entry, native).is_some()
            && is_boot_id(&self.verity_guid)
            && is_boot_id(&self.store_guid)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    pub id: String,
    pub verified: update::VerifiedOffer,
    pub snapshot: Snapshot,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub id: String,
    request_id: String,
    request_digest: String,
    pub action: Action,
    pub phase: Phase,
    pub started_utc: u64,
    started_ms: u64,
    deadline_ms: u64,
    pub expected: Snapshot,
    offer: Option<Offer>,
    pub error: Option<Code>,
    pub staged: Option<install::StagedImage>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    schema: u32,
    generation: String,
    jobs: Vec<Job>,
    offer: Option<Offer>,
}
impl Registry {
    fn empty() -> JobResult<Self> {
        Ok(Self {
            schema: 1,
            generation: "0".repeat(64),
            jobs: Vec::new(),
            offer: None,
        })
    }
    fn validate(&self) -> bool {
        self.schema == 1
            && is_id(&self.generation)
            && self.jobs.len() <= HISTORY + 1
            && self
                .jobs
                .iter()
                .map(|j| &j.id)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == self.jobs.len()
            && self
                .jobs
                .iter()
                .map(|j| &j.request_id)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == self.jobs.len()
            && self.jobs.iter().filter(|j| !j.phase.terminal()).count() <= 1
            && self.jobs.iter().filter(|j| j.phase.terminal()).count() <= HISTORY
            && self.jobs.iter().all(|j| {
                is_id(&j.id)
                    && is_id(&j.request_id)
                    && is_id(&j.request_digest)
                    && j.expected.validate()
                    && j.deadline_ms > j.started_ms
                    && j.deadline_ms - j.started_ms
                        == (if j.action == Action::Check {
                            CHECK_SECONDS
                        } else {
                            STAGE_SECONDS
                        }) * 1000
                    && (j.phase != Phase::Checked || j.action == Action::Check)
                    && (j.phase != Phase::Staged || j.action == Action::Stage)
                    && (j.staged.is_some() == (j.phase == Phase::Staged))
                    && j.staged.as_ref().is_none_or(|staged| {
                        j.error.is_none()
                            && j.offer.as_ref().is_some_and(|offer| {
                                valid_staged(
                                    staged,
                                    &j.expected,
                                    &offer.verified,
                                    crate::boot_entry::native_enabled(),
                                )
                            })
                    })
                    && (j.action != Action::Stage || j.offer.is_some())
                    && serde_json::to_vec(j).is_ok_and(|bytes| bytes.len() <= MAX_JOB)
                    && j.offer
                        .as_ref()
                        .is_none_or(|offer| valid_offer(offer) && offer.snapshot == j.expected)
            })
            && self.offer.as_ref().is_none_or(valid_offer)
    }
}
fn valid_offer(offer: &Offer) -> bool {
    let m = &offer.verified.manifest;
    is_id(&offer.id)
        && offer.snapshot.validate()
        && is_id(&offer.verified.manifest_sha256)
        && is_id(&offer.verified.public_key_sha256)
        && m.version.len() <= 128
        && offer.verified.public_key_sha256 == offer.snapshot.public_key_sha256
        && !m.version.is_empty()
        && m.image.len() <= 255
        && !m.image.chars().any(char::is_control)
        && update::valid_image_name(&m.image)
        && is_id(
            m.sha256
                .strip_prefix("sha256:")
                .unwrap_or(&m.sha256)
                .to_ascii_lowercase()
                .as_str(),
        )
        && m.product.as_deref().is_none_or(|p| p == update::PRODUCT)
}

pub(crate) fn is_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn is_boot_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn valid_staged(
    staged: &install::StagedImage,
    expected: &Snapshot,
    offer: &update::VerifiedOffer,
    native: bool,
) -> bool {
    // sgdisk's real writer readback uses uppercase hex; native resources and
    // snapshots use lowercase. Preserve historical journal bytes but compare
    // partition identities canonically, never as case-sensitive strings.
    let verity_guid = staged.verity_guid.to_ascii_lowercase();
    let store_guid = staged.store_guid.to_ascii_lowercase();
    let Some(entry) = crate::boot_entry::Entry::parse(&staged.boot_entry, native) else {
        return false;
    };
    let initial_entry = match entry.image {
        crate::boot_entry::Image::Slot(slot) => format!("{slot}+3.efi"),
        crate::boot_entry::Image::Release(version) => format!("sentinel_{version}+3-0.efi"),
    };
    staged.active_slot == expected.slot
        && matches!(
            (staged.active_slot.as_str(), staged.staged_slot.as_str()),
            ("sentinel-a", "sentinel-b") | ("sentinel-b", "sentinel-a")
        )
        && entry.matches_running(&staged.staged_slot, &offer.manifest.version)
        && staged.boot_entry == initial_entry
        && is_id(&staged.uki_sha256)
        && is_boot_id(&verity_guid)
        && is_boot_id(&store_guid)
        && verity_guid != store_guid
        && [&verity_guid, &store_guid].into_iter().all(|guid| {
            guid != "00000000-0000-0000-0000-000000000000"
                && !guid.eq_ignore_ascii_case(&expected.verity_guid)
                && !guid.eq_ignore_ascii_case(&expected.store_guid)
        })
}
fn random_id() -> JobResult<String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(unavailable)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn digest(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn boot_id() -> JobResult<String> {
    let value = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(unavailable)?
        .trim()
        .to_string();
    if !is_boot_id(&value) {
        return Err(Error(Code::StateUnavailable));
    }
    Ok(value)
}
fn boot_ms() -> JobResult<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) } != 0
        || ts.tv_sec < 0
        || ts.tv_nsec < 0
    {
        return Err(Error(Code::StateUnavailable));
    }
    Ok((ts.tv_sec as u64)
        .saturating_mul(1000)
        .saturating_add(ts.tv_nsec as u64 / 1_000_000))
}

/// Every byte is read/written relative to a validated private directory FD.
struct Store {
    directory: File,
    owner: u32,
}
struct Guard(File);
impl Drop for Guard {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
impl Store {
    fn production(create: bool) -> JobResult<Option<Self>> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(Error(Code::UnsupportedRuntime));
        }
        Self::open(Path::new(DIRECTORY), 0, create)
    }
    fn open(path: &Path, owner: u32, create: bool) -> JobResult<Option<Self>> {
        if create {
            match std::fs::DirBuilder::new().mode(0o700).create(path) {
                Ok(()) => {
                    File::open(path.parent().ok_or(Error(Code::StateUnavailable))?)
                        .map_err(unavailable)?
                        .sync_all()
                        .map_err(unavailable)?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(unavailable(e)),
            }
        }
        let directory = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(file) => file,
            Err(e) if !create && e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(unavailable(e)),
        };
        let meta = directory.metadata().map_err(unavailable)?;
        if meta.uid() != owner || meta.mode() & 0o777 != 0o700 {
            return Err(Error(Code::StateUnavailable));
        }
        Ok(Some(Self { directory, owner }))
    }
    fn file(&self, name: &std::ffi::CStr, flags: i32) -> JobResult<Option<File>> {
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                0o600,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            return if error.kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(unavailable(error))
            };
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let meta = file.metadata().map_err(unavailable)?;
        if !meta.is_file()
            || meta.uid() != self.owner
            || meta.nlink() != 1
            || meta.mode() & 0o777 != 0o600
        {
            return Err(Error(Code::StateUnavailable));
        }
        Ok(Some(file))
    }
    fn lock(&self) -> JobResult<Guard> {
        let file = self
            .file(c"registry.lock", libc::O_RDWR | libc::O_CREAT)?
            .ok_or(Error(Code::StateUnavailable))?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Error(Code::Busy));
        }
        let guard = Guard(file);
        self.recover_temporaries()?;
        Ok(guard)
    }
    fn recover_temporaries(&self) -> JobResult<()> {
        // A writer can die between exclusive staging creation and rename.
        // The registry flock has already excluded every cooperating writer.
        // Inspect at most18 regular private entries; never recurse or follow
        // an arbitrary pathname. Unknown inventory is an error, not trash.
        let directory = format!("/proc/self/fd/{}", self.directory.as_raw_fd());
        let mut orphaned = Vec::new();
        for (index, entry) in std::fs::read_dir(directory)
            .map_err(unavailable)?
            .enumerate()
        {
            if index >= 18 {
                return Err(Error(Code::StateUnavailable));
            }
            let entry = entry.map_err(unavailable)?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(Error(Code::StateUnavailable))?;
            let orphan = name.strip_prefix(".state-").is_some_and(is_id);
            if !orphan && !matches!(name, "state.json" | "registry.lock") {
                return Err(Error(Code::StateUnavailable));
            }
            let name = CString::new(name).map_err(unavailable)?;
            let file = self
                .file(&name, libc::O_RDONLY)?
                .ok_or(Error(Code::StateUnavailable))?;
            if file.metadata().map_err(unavailable)?.len() > MAX_STATE as u64 {
                return Err(Error(Code::StateUnavailable));
            }
            if orphan {
                orphaned.push((name, file));
            }
        }
        // Validate the WHOLE inventory before removing even one owned orphan.
        for (name, file) in &orphaned {
            let mut named: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::fstatat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    &mut named,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(Error(Code::StateUnavailable));
            }
            let open = file.metadata().map_err(unavailable)?;
            if named.st_ino != open.ino() || named.st_dev != open.dev() {
                return Err(Error(Code::StateUnavailable));
            }
        }
        for (name, _) in &orphaned {
            if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err(Error(Code::StateUnavailable));
            }
        }
        if !orphaned.is_empty() {
            self.directory.sync_all().map_err(unavailable)?;
        }
        Ok(())
    }
    fn read(&self) -> JobResult<Option<Registry>> {
        let Some(file) = self.file(c"state.json", libc::O_RDONLY)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.take(MAX_STATE as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(unavailable)?;
        if bytes.len() > MAX_STATE {
            return Err(Error(Code::StateUnavailable));
        }
        let registry: Registry = serde_json::from_slice(&bytes).map_err(unavailable)?;
        if !registry.validate() {
            return Err(Error(Code::StateUnavailable));
        }
        Ok(Some(registry))
    }
    fn write(&self, registry: &Registry) -> JobResult<()> {
        if !registry.validate() {
            return Err(Error(Code::StateUnavailable));
        }
        let bytes = serde_json::to_vec(registry).map_err(unavailable)?;
        if bytes.len() > MAX_STATE {
            return Err(Error(Code::StateUnavailable));
        }
        let name = CString::new(format!(".state-{}", random_id()?)).map_err(unavailable)?;
        let mut file = self
            .file(&name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)?
            .ok_or(Error(Code::StateUnavailable))?;
        let outcome = (|| {
            file.write_all(&bytes).map_err(unavailable)?;
            file.sync_all().map_err(unavailable)?;
            if unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    self.directory.as_raw_fd(),
                    c"state.json".as_ptr(),
                )
            } != 0
            {
                return Err(Error(Code::StateUnavailable));
            }
            self.directory.sync_all().map_err(unavailable)
        })();
        if outcome.is_err() {
            unsafe {
                libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0);
            }
        }
        outcome
    }
    fn change<T>(&self, mutate: impl FnOnce(&mut Registry) -> JobResult<T>) -> JobResult<T> {
        let _lock = self.lock()?;
        let mut registry = self.read()?.unwrap_or(Registry::empty()?);
        let result = mutate(&mut registry)?;
        self.write(&registry)?;
        Ok(result)
    }
    fn phase(&self, id: &str, phase: Phase) -> JobResult<()> {
        self.change(|r| {
            let job = r
                .jobs
                .iter_mut()
                .find(|j| j.id == id)
                .ok_or(Error(Code::NotFound))?;
            if job.phase.terminal()
                || !job.phase.permits(phase)
                || job.expected.boot_id != boot_id()?
                || boot_ms()? > job.deadline_ms
            {
                return Err(Error(Code::Conflict));
            }
            job.phase = phase;
            Ok(())
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub request_id: String,
    pub expected_generation: String,
    pub expected: Snapshot,
    #[serde(default)]
    pub offer_id: Option<String>,
}
#[derive(Clone, Serialize)]
pub struct Status {
    pub schema: u32,
    pub generation: Option<String>,
    pub current: Option<CurrentImage>,
    /// A full config revision is a write-context token, not a read-only
    /// disclosure of a hash covering the unredacted configuration/secrets.
    pub mutation_context: Option<Snapshot>,
    pub offer: Option<OfferView>,
    pub jobs: Vec<JobView>,
    pub can_check: bool,
    pub can_stage: bool,
    pub unavailable: Option<Code>,
}

#[derive(Clone, Serialize)]
pub struct CurrentImage {
    pub boot_id: String,
    pub release: String,
    pub slot: String,
    pub verity: String,
    pub selected_entry: String,
    pub next_entry: String,
    pub permanent: bool,
    pub uki_sha256: String,
}
impl From<&Snapshot> for CurrentImage {
    fn from(s: &Snapshot) -> Self {
        Self {
            boot_id: s.boot_id.clone(),
            release: s.release.clone(),
            slot: s.slot.clone(),
            verity: s.verity.clone(),
            selected_entry: s.selected_entry.clone(),
            next_entry: s.next_entry.clone(),
            permanent: s.permanent,
            uki_sha256: s.uki_sha256.clone(),
        }
    }
}
#[derive(Clone, Serialize)]
pub struct OfferView {
    pub id: String,
    pub verified: update::VerifiedOffer,
}
impl From<Offer> for OfferView {
    fn from(o: Offer) -> Self {
        Self {
            id: o.id,
            verified: o.verified,
        }
    }
}
#[derive(Clone, Serialize)]
pub struct JobView {
    pub id: String,
    pub request_id: String,
    pub action: Action,
    pub phase: Phase,
    pub started_utc: u64,
    pub boot_id: String,
    pub error: Option<Code>,
    pub message: Option<&'static str>,
    pub staged: Option<install::StagedImage>,
    pub offer: Option<OfferView>,
}
impl From<Job> for JobView {
    fn from(j: Job) -> Self {
        Self {
            id: j.id,
            request_id: j.request_id,
            action: j.action,
            phase: j.phase,
            started_utc: j.started_utc,
            boot_id: j.expected.boot_id,
            message: j.error.map(Code::message),
            error: j.error,
            staged: j.staged,
            offer: j.offer.map(Into::into),
        }
    }
}

fn runtime(config: &Path, apply: bool) -> JobResult<()> {
    if !apply
        || unsafe { libc::geteuid() } != 0
        || config != Path::new(crate::session::DEFAULT_CONFIG)
        || config
            .symlink_metadata()
            .map_err(unavailable)?
            .file_type()
            .is_symlink()
        || !Path::new("/sys/firmware/efi/efivars").is_dir()
    {
        return Err(Error(Code::UnsupportedRuntime));
    }
    let metadata = config.metadata().map_err(unavailable)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
    {
        return Err(Error(Code::UnsupportedRuntime));
    }
    let identity = crate::image::current();
    if identity.slot.is_none() || identity.verity.as_ref().is_none_or(|v| !is_id(v)) {
        return Err(Error(Code::UnsupportedRuntime));
    }
    Ok(())
}

/// Bounded child observation preserves nonzero exit separately from IO failure.
/// Raw output remains private and is never placed in a public job error.
struct ProbeChild {
    child: Child,
    reaped: bool,
}
impl ProbeChild {
    fn exited(&self) -> JobResult<bool> {
        // Observe without reaping: the owned leader keeps its PID reserved
        // until group cleanup, so a recycled PID can never name another group.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(unavailable(error));
        }
        Ok(unsafe { info.si_pid() } != 0)
    }

    fn finish(&mut self) -> std::io::Result<ExitStatus> {
        if !self.reaped {
            // Every spawned probe is its own group leader. Kill descendants
            // even when the wrapper already exited but they retained stdout.
            unsafe {
                libc::kill(-(self.child.id() as i32), libc::SIGKILL);
            }
        }
        let result = self.child.wait();
        if result.is_ok() {
            self.reaped = true;
        }
        result
    }
}
impl Drop for ProbeChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.finish();
        }
    }
}

pub(crate) fn probe(
    program: &str,
    args: &[&str],
    seconds: u64,
) -> JobResult<(ExitStatus, Vec<u8>)> {
    use std::os::unix::process::CommandExt;
    let mut disposition: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut disposition) } != 0
        || disposition.sa_sigaction != libc::SIG_DFL
        || disposition.sa_flags & libc::SA_NOCLDWAIT != 0
    {
        // An external reaper/ignored SIGCHLD would invalidate PID ownership.
        // Refuse before spawning rather than signal an uncertain process group.
        return Err(Error(Code::StateUnavailable));
    }
    let child = Command::new(program)
        .args(args)
        .process_group(0)
        .env_clear()
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env("SYSTEMD_PAGER", "")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(unavailable)?;
    let mut child = ProbeChild {
        child,
        reaped: false,
    };
    let result = (|| {
        let mut pipe = child
            .child
            .stdout
            .take()
            .ok_or(Error(Code::StateUnavailable))?;
        let fd = pipe.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(Error(Code::StateUnavailable));
        }
        let started = Instant::now();
        let mut bytes = Vec::new();
        let mut exited = false;
        loop {
            let mut buffer = [0u8; 4096];
            loop {
                if started.elapsed() > Duration::from_secs(seconds) {
                    return Err(Error(Code::StateUnavailable));
                }
                match pipe.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) if bytes.len() + n <= PROBE_BYTES => {
                        bytes.extend_from_slice(&buffer[..n])
                    }
                    Ok(_) => return Err(Error(Code::StateUnavailable)),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(unavailable(e)),
                }
            }
            if exited {
                return Ok(bytes);
            }
            exited = child.exited()?;
            if !exited {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    })();
    let status = child.finish().map_err(unavailable)?;
    result.map(|bytes| (status, bytes))
}

fn boot_entry(
    bytes: &[u8],
    slot: &str,
    version: &str,
    verity: &str,
) -> JobResult<(String, String, bool)> {
    boot_entry_with_policy(
        bytes,
        slot,
        version,
        verity,
        crate::boot_entry::native_enabled(),
    )
}

fn observed_boot_entry(
    row: &serde_json::Value,
    native: bool,
) -> JobResult<(&str, crate::boot_entry::Entry<'_>)> {
    let refused = || Error(Code::UnstableBoot);
    let id = row["id"].as_str().ok_or_else(refused)?;
    let name = row["path"]
        .as_str()
        .and_then(|p| p.strip_prefix("/boot/EFI/Linux/"))
        .ok_or_else(refused)?;
    let entry = crate::boot_entry::Entry::parse(name, native).ok_or_else(refused)?;
    let stable = name
        .split_once('+')
        .map_or_else(|| name.to_owned(), |(base, _)| format!("{base}.efi"));
    if (id != name && id != stable)
        || row["type"] != "type2"
        || row["source"] != "esp"
        || row["root"] != "/boot"
        || row["linux"] != format!("/EFI/Linux/{name}")
    {
        return Err(refused());
    }
    let left = row.get("triesLeft").filter(|v| !v.is_null());
    let done = row.get("triesDone").filter(|v| !v.is_null());
    if let Some((_, suffix)) = name.strip_suffix(".efi").and_then(|s| s.split_once('+')) {
        let (expected_left, expected_done) = suffix.split_once('-').unwrap_or((suffix, "0"));
        let expected_left = expected_left.parse::<u64>().map_err(|_| refused())?;
        let expected_done = expected_done.parse::<u64>().map_err(|_| refused())?;
        match (left, done) {
            (Some(left), Some(done))
                if left.as_u64() == Some(expected_left) && done.as_u64() == Some(expected_done) => {
            }
            // systemd 260 omits triesDone when the filename is +N, not +N-M.
            // Its implicit zero never makes that real counted inode permanent.
            (Some(left), None) if !suffix.contains('-') && left.as_u64() == Some(expected_left) => {
            }
            // Older inventory used the full counted filename as ID without
            // separate counters. A normalized ID needs every encoded counter;
            // it must never stand in for a permanent filename.
            (None, None) if id == name => {}
            _ => return Err(refused()),
        }
    } else if left.is_some() || done.is_some() {
        return Err(refused());
    }
    if let crate::boot_entry::Image::Release(version) = entry.image {
        if row["version"] != version {
            return Err(refused());
        }
    }
    let hashes: Vec<_> = row["cmdline"]
        .as_str()
        .ok_or_else(refused)?
        .split_ascii_whitespace()
        .filter_map(|part| part.strip_prefix("usrhash="))
        .collect();
    if hashes.len() != 1 || !is_id(hashes[0]) {
        return Err(refused());
    }
    Ok((name, entry))
}

fn boot_entry_with_policy(
    bytes: &[u8],
    slot: &str,
    version: &str,
    verity: &str,
    native: bool,
) -> JobResult<(String, String, bool)> {
    let entries: Vec<serde_json::Value> = serde_json::from_slice(bytes).map_err(unavailable)?;
    let selected: Vec<_> = entries.iter().filter(|e| e["isSelected"] == true).collect();
    let defaults: Vec<_> = entries.iter().filter(|e| e["isDefault"] == true).collect();
    if selected.len() != 1 || defaults.len() != 1 {
        return Err(Error(Code::UnstableBoot));
    }
    let row = selected[0];
    // systemd's logical ID omits the boot counter; path/linux name the actual
    // inode. Authorization and permanent/trial assessment use that filename,
    // with strict ID/counter reconciliation on BOTH selected/default entries.
    let (name, entry) = observed_boot_entry(row, native)?;
    let (next, _) = observed_boot_entry(defaults[0], native)?;
    let cmdline = row["cmdline"].as_str().ok_or(Error(Code::UnstableBoot))?;
    let hashes: Vec<_> = cmdline
        .split_ascii_whitespace()
        .filter_map(|part| part.strip_prefix("usrhash="))
        .collect();
    if !entry.matches_running(slot, version)
        || row["version"] != version
        || hashes != [verity]
        || (row["id"] == defaults[0]["id"] && row != defaults[0])
    {
        return Err(Error(Code::UnstableBoot));
    }
    Ok((name.into(), next.into(), entry.permanent_for(slot, version)))
}

fn active_guids(slot: &str) -> JobResult<(String, String)> {
    let mapper = std::fs::canonicalize("/dev/mapper/usr").map_err(unavailable)?;
    let mapper = mapper
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or(Error(Code::UnsupportedRuntime))?;
    let slaves = Path::new("/sys/class/block").join(mapper).join("slaves");
    let expected = if slot == "sentinel-a" {
        [2u32, 3]
    } else if slot == "sentinel-b" {
        [4u32, 5]
    } else {
        return Err(Error(Code::UnsupportedRuntime));
    };
    let mut found = std::collections::BTreeMap::new();
    for entry in std::fs::read_dir(slaves).map_err(unavailable)? {
        let path = entry.map_err(unavailable)?.path();
        let target = path.canonicalize().map_err(unavailable)?;
        let number: u32 = std::fs::read_to_string(target.join("partition"))
            .map_err(unavailable)?
            .trim()
            .parse()
            .map_err(unavailable)?;
        let disk = target
            .parent()
            .and_then(Path::file_name)
            .and_then(|s| s.to_str())
            .ok_or(Error(Code::UnsupportedRuntime))?;
        if !expected.contains(&number)
            || disk.is_empty()
            || disk.len() > 128
            || !disk
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || found.insert(number, disk.to_string()).is_some()
        {
            return Err(Error(Code::UnsupportedRuntime));
        }
    }
    if found.len() != 2 || found.get(&expected[0]) != found.get(&expected[1]) {
        return Err(Error(Code::UnsupportedRuntime));
    }
    let disk = format!(
        "/dev/{}",
        found
            .get(&expected[0])
            .ok_or(Error(Code::UnsupportedRuntime))?
    );
    let mut guids = Vec::new();
    for number in expected {
        let argument = format!("--info={number}");
        let (code, bytes) = probe(&system::bin("sgdisk"), &[&argument, &disk], 5)?;
        if !code.success() {
            return Err(Error(Code::StateUnavailable));
        }
        let text = std::str::from_utf8(&bytes).map_err(unavailable)?;
        let values: Vec<_> = text
            .lines()
            .filter_map(|l| l.strip_prefix("Partition unique GUID: "))
            .collect();
        if values.len() != 1 {
            return Err(Error(Code::StateUnavailable));
        }
        let guid = values[0].trim().to_ascii_lowercase();
        if !is_boot_id(&guid) {
            return Err(Error(Code::StateUnavailable));
        }
        guids.push(guid);
    }
    Ok((guids.remove(0), guids.remove(0)))
}

fn snapshot(config: &Path) -> JobResult<(Snapshot, crate::config::UpdateChannel)> {
    let (snapshot, channel, fence) = observe_snapshot(config)?;
    fence.check(false).map_err(fence_error)?;
    Ok((snapshot, channel))
}

fn fence_error(error: anyhow::Error) -> Error {
    if error.is::<crate::mutation::Busy>() {
        Error(Code::Busy)
    } else {
        Error(Code::StateUnavailable)
    }
}

fn observe_snapshot(
    config: &Path,
) -> JobResult<(
    Snapshot,
    crate::config::UpdateChannel,
    crate::mutation::Observation,
)> {
    let mut fence = crate::mutation::Observation::begin(config).map_err(fence_error)?;
    let appliance = Appliance::load(config).map_err(unavailable)?;
    let channel = appliance
        .update
        .as_ref()
        .ok_or(Error(Code::MetadataRefused))?
        .active()
        .map_err(|_| Error(Code::MetadataRefused))?;
    if let Some(path) = channel.public_key.strip_prefix("file:") {
        // /etc public pins legitimately point into the immutable Nix store.
        // Unlike config/running files they may be symlinks, but the opened
        // descriptor and resolved file identity must survive the checkpoint.
        fence
            .add(Path::new(path), false, true)
            .map_err(fence_error)?;
    }
    let identity = crate::image::current();
    let slot = identity.slot.ok_or(Error(Code::UnsupportedRuntime))?;
    let verity = identity.verity.ok_or(Error(Code::UnsupportedRuntime))?;
    let release = update::running_version().map_err(|_| Error(Code::UnsupportedRuntime))?;
    let (code, bytes) = probe(&system::bin("bootctl"), &["list", "--json=short"], 5)?;
    if !code.success() {
        return Err(Error(Code::UnstableBoot));
    }
    let (selected_entry, next_entry, permanent) = boot_entry(&bytes, slot, &release, &verity)?;
    fence
        .add(
            &Path::new("/boot/EFI/Linux").join(&selected_entry),
            false,
            false,
        )
        .map_err(fence_error)?;
    let (verity_guid, store_guid) = active_guids(slot)?;
    let result = Snapshot {
        boot_id: boot_id()?,
        mutation_epoch: fence.nonce.clone(),
        config_revision: crate::ha::revision(&appliance).map_err(unavailable)?,
        public_key_sha256: update::public_key_fingerprint(&channel)
            .map_err(|_| Error(Code::MetadataRefused))?,
        release,
        slot: slot.into(),
        verity,
        uki_sha256: install::hash_uki(&Path::new("/boot/EFI/Linux").join(&selected_entry))
            .map_err(unavailable)?,
        selected_entry,
        next_entry,
        permanent,
        verity_guid,
        store_guid,
    };
    if !result.validate() {
        return Err(Error(Code::StateUnavailable));
    }
    Ok((result, channel, fence))
}

/// An expired timer is not proof that its rollback service has finished. Query
/// both units by typed properties, never infer safety from `is-active`'s exit
/// code or a missing/failed command. Normal `--collect` must remove both units
/// before HTTP update admission is available again.
fn confirmation_idle_with(
    mut observe: impl FnMut(&str) -> JobResult<(ExitStatus, Vec<u8>)>,
) -> JobResult<()> {
    let mut blocked = false;
    for unit in ["sentinel-confirm.timer", "sentinel-confirm.service"] {
        let (status, bytes) = observe(unit)?;
        blocked |= !confirmation_unit_absent(status, &bytes)?;
    }
    if blocked {
        Err(Error(Code::Conflict))
    } else {
        Ok(())
    }
}

fn confirmation_unit_absent(status: ExitStatus, bytes: &[u8]) -> JobResult<bool> {
    if !status.success() || bytes.len() > 1024 {
        return Err(Error(Code::StateUnavailable));
    }
    let text = std::str::from_utf8(bytes).map_err(unavailable)?;
    let mut values = std::collections::BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once('=').ok_or(Error(Code::StateUnavailable))?;
        if !matches!(key, "LoadState" | "ActiveState" | "SubState")
            || values.insert(key, value).is_some()
        {
            return Err(Error(Code::StateUnavailable));
        }
    }
    if values.len() != 3 {
        return Err(Error(Code::StateUnavailable));
    }
    match (
        values["LoadState"],
        values["ActiveState"],
        values["SubState"],
    ) {
        ("not-found", "inactive", "dead") => Ok(true),
        // Even an inactive loaded unit is conservative refusal: require the
        // real transient-unit lifecycle to finish, not a test-only reset.
        (
            "loaded",
            "active" | "inactive" | "failed" | "activating" | "deactivating" | "reloading"
            | "refreshing",
            sub,
        ) if !sub.is_empty() => Ok(false),
        _ => Err(Error(Code::StateUnavailable)),
    }
}

fn confirmation_idle() -> JobResult<()> {
    confirmation_idle_with(|unit| {
        probe(
            &system::bin("systemctl"),
            &["show", "--property=LoadState,ActiveState,SubState", unit],
            5,
        )
    })
}

fn admission_guard(config: &Path) -> JobResult<()> {
    if config != Path::new(crate::session::DEFAULT_CONFIG) {
        return Err(Error(Code::UnsupportedRuntime));
    }
    if !crate::mutation::idle().map_err(unavailable)? {
        return Err(Error(Code::Conflict));
    }
    confirmation_idle()
}
fn compare_snapshot(expected: &Snapshot, actual: &Snapshot, stable: bool) -> JobResult<()> {
    if actual != expected {
        return Err(Error(Code::Conflict));
    }
    if stable && !actual.stable() {
        return Err(Error(Code::UnstableBoot));
    }
    Ok(())
}
fn check_snapshot(
    config: &Path,
    expected: &Snapshot,
    stable: bool,
) -> JobResult<crate::config::UpdateChannel> {
    let (actual, channel, fence) = observe_snapshot(config)?;
    compare_snapshot(expected, &actual, stable)?;
    // Health, signatures, probes, journal parsing and channel requests are
    // OUTSIDE the common lock. Cooperating writes advance the epoch before
    // effects, so same-bytes ABA cannot pass the final metadata-only CAS.
    admission_guard(config)?;
    fence.check(true).map_err(fence_error)?;
    Ok(channel)
}
fn readiness() -> JobResult<()> {
    // This pinned wrapper invokes ONLY the existing read-only product checker;
    // it neither starts assessment units nor blesses/reboots any image.
    // The existing package wrapper restores its immutable executable pins for
    // config check/compile. Do not ask an env-cleared naked core to find tools
    // through a mutable/missing PATH, and do not inherit credentials instead.
    let this = std::env::var("SENTINEL_PAIR_SELF_BIN").map_err(unavailable)?;
    if !this.starts_with("/nix/store/") || this.chars().any(char::is_control) {
        return Err(Error(Code::UnsupportedRuntime));
    }
    let (status, _) = probe(
        &system::bin("boot-health"),
        &["--sentinel", &this, "--timeout", "60"],
        100,
    )?;
    if !status.success() {
        return Err(Error(Code::UnstableBoot));
    }
    Ok(())
}

fn unit_name(id: &str) -> JobResult<String> {
    if !is_id(id) {
        return Err(Error(Code::InvalidRequest));
    }
    Ok(format!("sentinel-update-{id}.service"))
}
fn unit_alive(id: &str) -> JobResult<bool> {
    let name = unit_name(id)?;
    let (status, bytes) = probe(
        &system::bin("systemctl"),
        &["show", "--property=LoadState,ActiveState", &name],
        5,
    )?;
    parse_unit(status, &bytes)
}
fn parse_unit(status: ExitStatus, bytes: &[u8]) -> JobResult<bool> {
    let text = std::str::from_utf8(bytes).map_err(unavailable)?;
    let mut values = std::collections::HashMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once('=').ok_or(Error(Code::StateUnavailable))?;
        if !matches!(key, "LoadState" | "ActiveState") || values.insert(key, value).is_some() {
            return Err(Error(Code::StateUnavailable));
        }
    }
    if values.len() != 2 {
        return Err(Error(Code::StateUnavailable));
    }
    match (
        values.get("LoadState").copied(),
        values.get("ActiveState").copied(),
    ) {
        (Some("not-found"), Some("inactive")) if status.success() => Ok(false),
        (Some("loaded"), Some("active" | "activating" | "deactivating" | "reloading"))
            if status.success() =>
        {
            Ok(true)
        }
        (Some("loaded"), Some("inactive" | "failed")) if status.success() => Ok(false),
        _ => Err(Error(Code::StateUnavailable)),
    }
}
fn mark_interrupted(job: &mut Job) {
    if !job.phase.terminal() {
        job.error = Some(if job.phase.may_have_written() {
            Code::WriteOutcomeUnknown
        } else {
            Code::Interrupted
        });
        job.phase = Phase::Interrupted;
    }
}
fn recover(store: &Store) -> JobResult<()> {
    let Some(registry) = store.read()? else {
        return Ok(());
    };
    let Some(job) = registry.jobs.iter().find(|j| !j.phase.terminal()) else {
        return Ok(());
    };
    let now = boot_ms()?;
    let same_boot = job.expected.boot_id == boot_id()?;
    if same_boot && now.saturating_sub(job.started_ms) < 5000 {
        return Ok(());
    }
    if same_boot && unit_alive(&job.id)? {
        return Ok(());
    }
    let id = job.id.clone();
    store.change(|r| {
        let job = r
            .jobs
            .iter_mut()
            .find(|j| j.id == id)
            .ok_or(Error(Code::NotFound))?;
        mark_interrupted(job);
        while r.jobs.len() > HISTORY {
            r.jobs.remove(0);
        }
        Ok(())
    })
}

fn worker_arguments(
    job: &Job,
    this: &str,
    pins: impl IntoIterator<Item = (String, String)>,
) -> JobResult<Vec<String>> {
    if !this.starts_with("/nix/store/") {
        return Err(Error(Code::UnsupportedRuntime));
    }
    let seconds = if job.action == Action::Check {
        CHECK_SECONDS
    } else {
        STAGE_SECONDS
    };
    let mut args = vec![
        format!("--unit={}", unit_name(&job.id)?),
        "--collect".into(),
        "--property=Type=exec".into(),
        "--property=User=root".into(),
        "--property=UMask=0077".into(),
        "--property=KillMode=control-group".into(),
        "--property=TimeoutStartSec=10s".into(),
        "--property=TimeoutStopSec=15s".into(),
        format!("--property=RuntimeMaxSec={seconds}s"),
        "--property=Restart=no".into(),
    ];
    // Existing immutable executable pins are not credentials. Never forward
    // API tokens, channel config, PATH or the arbitrary caller environment.
    for (key, value) in pins
        .into_iter()
        .filter(|(key, _)| key.starts_with("SENTINEL_") && key.ends_with("_BIN"))
    {
        if !key
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            || !value.starts_with("/nix/store/")
            || value.chars().any(char::is_control)
        {
            return Err(Error(Code::WorkerUnavailable));
        }
        args.push(format!("--setenv={key}={value}"));
    }
    args.extend([this.into(), "update-job".into(), job.id.clone()]);
    Ok(args)
}
fn launch(job: &Job) -> JobResult<()> {
    let this = std::env::current_exe().map_err(unavailable)?;
    let this = this.to_str().ok_or(Error(Code::WorkerUnavailable))?;
    let args = worker_arguments(job, this, std::env::vars())?;
    let refs: Vec<_> = args.iter().map(String::as_str).collect();
    let (status, _) = probe(&system::bin("systemd-run"), &refs, 10)
        .map_err(|_| Error(Code::WorkerUnavailable))?;
    if !status.success() {
        return Err(Error(Code::WorkerUnavailable));
    }
    Ok(())
}

pub(crate) fn unavailable_status(code: Code) -> Status {
    Status {
        schema: 1,
        generation: None,
        current: None,
        mutation_context: None,
        offer: None,
        jobs: Vec::new(),
        can_check: false,
        can_stage: false,
        unavailable: Some(code),
    }
}

pub fn status(config: &Path, apply: bool, write_access: bool) -> JobResult<Status> {
    let unsupported = runtime(config, apply).err().map(|e| e.0);
    if let Some(code) = unsupported {
        return Ok(unavailable_status(code));
    }
    let (current, _) = snapshot(config)?;
    let registry = match Store::production(false)? {
        Some(store) => {
            recover(&store)?;
            store.read()?
        }
        None => None,
    };
    let busy = registry
        .as_ref()
        .is_some_and(|r| r.jobs.iter().any(|j| !j.phase.terminal()));
    let refusal = admission_guard(config).err().map(|e| e.0);
    let free = !busy && refusal.is_none();
    let offer = registry
        .as_ref()
        .and_then(|r| r.offer.as_ref())
        .filter(|o| o.snapshot == current)
        .cloned();
    Ok(Status {
        schema: 1,
        generation: Some(
            registry
                .as_ref()
                .map_or_else(|| "0".repeat(64), |r| r.generation.clone()),
        ),
        can_check: write_access && free,
        can_stage: write_access && free && current.stable() && offer.is_some(),
        current: Some((&current).into()),
        mutation_context: write_access.then_some(current),
        offer: offer.map(Into::into),
        jobs: registry.map_or_else(Vec::new, |r| r.jobs.into_iter().map(Into::into).collect()),
        unavailable: if busy { Some(Code::Busy) } else { refusal },
    })
}

pub(crate) fn validate_request(action: Action, request: &Request) -> JobResult<()> {
    if !is_id(&request.request_id)
        || !is_id(&request.expected_generation)
        || !request.expected.validate()
        || (action == Action::Check && request.offer_id.is_some())
        || (action == Action::Stage && request.offer_id.as_ref().is_none_or(|id| !is_id(id)))
    {
        return Err(Error(Code::InvalidRequest));
    }
    Ok(())
}

fn admit(
    registry: &mut Registry,
    action: Action,
    request: &Request,
    current: &Snapshot,
    now: u64,
) -> JobResult<(Job, bool)> {
    validate_request(action, request)?;
    let request_digest = digest(&serde_json::to_vec(&(action, request)).map_err(unavailable)?);
    if let Some(previous) = registry
        .jobs
        .iter()
        .find(|j| j.request_id == request.request_id)
    {
        return if previous.request_digest == request_digest {
            Ok((previous.clone(), false))
        } else {
            Err(Error(Code::Conflict))
        };
    }
    if registry.jobs.iter().any(|j| !j.phase.terminal()) {
        return Err(Error(Code::Busy));
    }
    if registry.generation != request.expected_generation || &request.expected != current {
        return Err(Error(Code::Conflict));
    }
    let offer = if action == Action::Stage {
        if !current.stable() {
            return Err(Error(Code::UnstableBoot));
        }
        let offer = registry
            .offer
            .as_ref()
            .filter(|o| Some(&o.id) == request.offer_id.as_ref() && &o.snapshot == current)
            .ok_or(Error(Code::Conflict))?;
        Some(offer.clone())
    } else {
        None
    };
    let seconds = if action == Action::Check {
        CHECK_SECONDS
    } else {
        STAGE_SECONDS
    };
    let job = Job {
        id: random_id()?,
        request_id: request.request_id.clone(),
        request_digest,
        action,
        phase: Phase::Accepted,
        started_utc: crate::aaa::unix_now(),
        started_ms: now,
        deadline_ms: now
            .checked_add(seconds * 1000)
            .ok_or(Error(Code::StateUnavailable))?,
        expected: current.clone(),
        offer,
        error: None,
        staged: None,
    };
    registry.generation = random_id()?;
    while registry.jobs.len() > HISTORY {
        registry.jobs.remove(0);
    }
    registry.jobs.push(job.clone());
    Ok((job, true))
}

pub fn submit(config: &Path, apply: bool, action: Action, request: &Request) -> JobResult<JobView> {
    runtime(config, apply)?;
    let (current, _) = snapshot(config)?;
    admission_guard(config)?;
    let store = Store::production(true)?.ok_or(Error(Code::StateUnavailable))?;
    recover(&store)?;
    let (job, created) = store.change(|r| admit(r, action, request, &current, boot_ms()?))?;
    if created && launch(&job).is_err() {
        // Launch may have succeeded before its reply was lost. Never declare
        // failure/retry over a possibly running worker: status reconciles it.
        store.change(|r| {
            let job = r
                .jobs
                .iter_mut()
                .find(|j| j.id == job.id)
                .ok_or(Error(Code::NotFound))?;
            if job.phase == Phase::Accepted {
                job.error = Some(Code::WorkerUnavailable);
            }
            Ok(())
        })?;
    }
    Ok(store
        .read()?
        .and_then(|r| r.jobs.into_iter().find(|j| j.id == job.id))
        .ok_or(Error(Code::NotFound))?
        .into())
}

pub fn run_worker(id: &str) -> JobResult<()> {
    let config = Path::new(crate::session::DEFAULT_CONFIG);
    runtime(config, true)?;
    if !is_id(id) {
        return Err(Error(Code::InvalidRequest));
    }
    let store = Store::production(false)?.ok_or(Error(Code::StateUnavailable))?;
    let job = store.change(|r| claim_worker(r, id, &boot_id()?, boot_ms()?))?;
    // Keep the successfully acknowledged first-write boundary even when the
    // registry later becomes unreadable or its final fsync fails. A journal
    // failure is never proof that target writes did not happen.
    let mut last_phase = Phase::Metadata;
    let result = (|| -> Result<Option<install::StagedImage>> {
        let channel = check_snapshot(config, &job.expected, job.action == Action::Stage)?;
        if job.action == Action::Check {
            let verified = update::check_offer(&channel)?;
            update::refuse_downgrade(&verified.manifest.version, false)?;
            check_snapshot(config, &job.expected, false)?;
            let offer = Offer {
                id: random_id()?,
                verified,
                snapshot: job.expected.clone(),
            };
            if !valid_offer(&offer) {
                return Err(Error(Code::MetadataRefused).into());
            }
            store.change(|r| {
                let job = r
                    .jobs
                    .iter_mut()
                    .find(|j| j.id == id)
                    .ok_or(Error(Code::NotFound))?;
                if job.phase != Phase::Metadata {
                    return Err(Error(Code::Conflict));
                }
                job.offer = Some(offer.clone());
                r.offer = Some(offer);
                Ok(())
            })?;
            Ok(None)
        } else {
            readiness()?;
            let offer = job.offer.as_ref().ok_or(Error(Code::Conflict))?;
            let mut phase = |phase: install::UpdatePhase| -> Result<()> {
                let phase = phase.into();
                store.phase(id, phase)?;
                last_phase = phase;
                Ok(())
            };
            let mut before_write = || -> Result<()> {
                readiness()?;
                let current_channel = check_snapshot(config, &job.expected, true)?;
                // A slow transfer must not silently authorize metadata that
                // the reviewed channel has since replaced. No signature,
                // config, pin or boot observation from admission is reused as
                // permission to cross the first-write boundary.
                let current_offer = update::check_offer(&current_channel)
                    .map_err(|_| Error(Code::MetadataRefused))?;
                ensure!(current_offer == offer.verified, Error(Code::Conflict));
                // Metadata/network work above is OUTSIDE the apply lock. Now
                // take one final saved-config/file-pin/boot/safe-apply CAS;
                // this is the first-write authorization linearization point.
                check_snapshot(config, &job.expected, true)?;
                Ok(())
            };
            let staged = install::update_from_channel_guarded(
                &channel,
                &offer.verified,
                install::UpdateHooks {
                    phase: &mut phase,
                    before_write: &mut before_write,
                },
            )?;
            if crate::boot_entry::native_enabled() {
                // Independently verify the bootloader's real selected/default
                // entries and the saved-config/active-image fence after native
                // staging; a provider's success frame alone is never enough.
                let mut expected = job.expected.clone();
                expected.next_entry = staged.boot_entry.clone();
                let (actual, _) = snapshot(config)?;
                compare_snapshot(&expected, &actual, false)?;
            }
            Ok(Some(staged))
        }
    })();
    finish_worker(&store, id, last_phase, &result)
}

fn finish_worker(
    store: &Store,
    id: &str,
    last_phase: Phase,
    result: &Result<Option<install::StagedImage>>,
) -> JobResult<()> {
    let mut may_have_written = last_phase.may_have_written();
    let completion = store.change(|r| {
        let job = r
            .jobs
            .iter_mut()
            .find(|j| j.id == id)
            .ok_or(Error(Code::NotFound))?;
        may_have_written |= job.phase.may_have_written();
        if job.phase.terminal() {
            return Err(Error(Code::Conflict));
        }
        let code = match result {
            Ok(staged) => {
                let valid = match (job.action, staged) {
                    (Action::Check, None) => {
                        job.phase == Phase::Metadata && last_phase == Phase::Metadata
                    }
                    (Action::Stage, Some(staged)) => {
                        job.phase == Phase::Publishing
                            && last_phase == Phase::Publishing
                            && job.offer.as_ref().is_some_and(|offer| {
                                valid_staged(
                                    staged,
                                    &job.expected,
                                    &offer.verified,
                                    crate::boot_entry::native_enabled(),
                                )
                            })
                    }
                    _ => false,
                };
                if !valid {
                    let code = if may_have_written {
                        Code::WriteOutcomeUnknown
                    } else {
                        Code::StateUnavailable
                    };
                    job.error = Some(code);
                    job.staged = None;
                    job.phase = Phase::Failed;
                    return Ok(Some(code));
                }
                job.staged = staged.clone();
                job.phase = if job.action == Action::Check {
                    Phase::Checked
                } else {
                    Phase::Staged
                };
                None
            }
            Err(error) => {
                let code = if may_have_written {
                    Code::WriteOutcomeUnknown
                } else {
                    failure_code(job.phase, error)
                };
                job.error = Some(code);
                job.phase = Phase::Failed;
                Some(code)
            }
        };
        while r.jobs.len() > HISTORY {
            r.jobs.remove(0);
        }
        Ok(code)
    });
    match completion {
        Ok(None) => Ok(()),
        Ok(Some(code)) => Err(Error(code)),
        Err(_) if may_have_written => Err(Error(Code::WriteOutcomeUnknown)),
        Err(error) => Err(error),
    }
}

fn claim_worker(registry: &mut Registry, id: &str, current_boot: &str, now: u64) -> JobResult<Job> {
    if !is_id(id) {
        return Err(Error(Code::InvalidRequest));
    }
    let job = registry
        .jobs
        .iter_mut()
        .find(|j| j.id == id)
        .ok_or(Error(Code::NotFound))?;
    if job.phase != Phase::Accepted || job.expected.boot_id != current_boot || now > job.deadline_ms
    {
        return Err(Error(Code::Conflict));
    }
    job.phase = Phase::Metadata;
    job.error = None;
    Ok(job.clone())
}

fn failure_code(phase: Phase, error: &anyhow::Error) -> Code {
    if phase.may_have_written() {
        Code::WriteOutcomeUnknown
    } else if let Some(error) = error.downcast_ref::<Error>() {
        error.0
    } else if error
        .downcast_ref::<crate::update_stage::UpdateBusy>()
        .is_some()
    {
        Code::Busy
    } else {
        match phase {
            Phase::Metadata => Code::MetadataRefused,
            Phase::Downloading | Phase::Verifying => Code::DownloadRefused,
            _ => Code::StageRefused,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn fixture() -> (update::Scratch, Store) {
        let scratch = update::Scratch::new().unwrap();
        let store = Store::open(&scratch.join("jobs"), unsafe { libc::geteuid() }, true)
            .unwrap()
            .unwrap();
        (scratch, store)
    }
    fn sample() -> Snapshot {
        Snapshot {
            boot_id: "12345678-1234-1234-1234-123456789abc".into(),
            mutation_epoch: "9".repeat(64),
            config_revision: "a".repeat(64),
            public_key_sha256: "b".repeat(64),
            release: "2.0.1".into(),
            slot: "sentinel-b".into(),
            verity: "c".repeat(64),
            selected_entry: "sentinel-b.efi".into(),
            next_entry: "sentinel-b.efi".into(),
            uki_sha256: "d".repeat(64),
            permanent: true,
            verity_guid: "22222222-2222-2222-2222-222222222222".into(),
            store_guid: "33333333-3333-3333-3333-333333333333".into(),
        }
    }
    fn request(r: &Registry) -> Request {
        Request {
            request_id: "e".repeat(64),
            expected_generation: r.generation.clone(),
            expected: sample(),
            offer_id: None,
        }
    }
    fn offer() -> Offer {
        Offer {
            id: "f".repeat(64),
            snapshot: sample(),
            verified: update::VerifiedOffer {
                manifest: update::Manifest {
                    version: "2.1.0".into(),
                    image: "sentinel_2.1.0+build.raw".into(),
                    sha256: "1".repeat(64),
                    product: Some(update::PRODUCT.into()),
                },
                manifest_sha256: "2".repeat(64),
                public_key_sha256: sample().public_key_sha256,
            },
        }
    }
    fn finished() -> Registry {
        let mut r = Registry::empty().unwrap();
        let req = request(&r);
        let (mut j, _) = admit(&mut r, Action::Check, &req, &sample(), 1000).unwrap();
        j.phase = Phase::Checked;
        r.jobs = vec![j];
        r
    }
    fn assert_code<T>(result: JobResult<T>, code: Code) {
        assert!(matches!(result, Err(Error(actual)) if actual == code));
    }

    #[test]
    fn update_jobs_initial_generation_is_readable_without_creating_state() {
        let (_scratch, store) = fixture();
        assert!(store.read().unwrap().is_none());
        assert_eq!(Registry::empty().unwrap().generation, "0".repeat(64));
    }
    #[test]
    fn update_jobs_private_atomic_roundtrip_retains_regular_inode_and_modes() {
        let (scratch, store) = fixture();
        store.change(|_| Ok(())).unwrap();
        let path = scratch.join("jobs/state.json");
        let first = path.metadata().unwrap().ino();
        let generation = store.read().unwrap().unwrap().generation;
        store
            .change(|r| {
                r.generation = "9".repeat(64);
                Ok(())
            })
            .unwrap();
        assert_ne!(path.metadata().unwrap().ino(), first);
        assert_eq!(path.metadata().unwrap().mode() & 0o777, 0o600);
        assert_eq!(path.metadata().unwrap().nlink(), 1);
        assert_ne!(store.read().unwrap().unwrap().generation, generation);
        assert_eq!(std::fs::read_dir(scratch.join("jobs")).unwrap().count(), 2);
    }
    #[test]
    fn update_jobs_directory_permissions_owner_and_symlinks_are_not_trusted() {
        let (scratch, store) = fixture();
        drop(store);
        let path = scratch.join("jobs");
        assert_code(
            Store::open(&path, unsafe { libc::geteuid() } ^ 1, false),
            Code::StateUnavailable,
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert_code(
            Store::open(&path, unsafe { libc::geteuid() }, false),
            Code::StateUnavailable,
        );
        symlink(&path, scratch.join("alias")).unwrap();
        assert_code(
            Store::open(&scratch.join("alias"), unsafe { libc::geteuid() }, false),
            Code::StateUnavailable,
        );
    }
    #[test]
    fn update_jobs_foreign_mode_state_is_unknown_not_empty() {
        let (scratch, store) = fixture();
        store.change(|_| Ok(())).unwrap();
        std::fs::set_permissions(
            scratch.join("jobs/state.json"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert_code(store.read(), Code::StateUnavailable);
    }
    #[test]
    fn update_jobs_symlink_state_does_not_follow_or_become_absence() {
        let (scratch, store) = fixture();
        scratch
            .create_private("target")
            .unwrap()
            .write_all(b"sensitive-fixture")
            .unwrap();
        symlink(scratch.join("target"), scratch.join("jobs/state.json")).unwrap();
        assert_code(store.read(), Code::StateUnavailable);
        assert_eq!(
            std::fs::read(scratch.join("target")).unwrap(),
            b"sensitive-fixture"
        );
    }
    #[test]
    fn update_jobs_hardlinked_state_is_rejected() {
        let (scratch, store) = fixture();
        store.change(|_| Ok(())).unwrap();
        std::fs::hard_link(scratch.join("jobs/state.json"), scratch.join("alias")).unwrap();
        assert_code(store.read(), Code::StateUnavailable);
    }
    #[test]
    fn update_jobs_fifo_is_rejected_without_blocking() {
        let (scratch, store) = fixture();
        let path = CString::new(scratch.join("jobs/state.json").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let begin = Instant::now();
        assert_code(store.read(), Code::StateUnavailable);
        assert!(begin.elapsed() < Duration::from_secs(1));
    }
    #[test]
    fn update_jobs_corrupt_oversized_and_unknown_schema_state_fails_closed() {
        let (scratch, store) = fixture();
        let path = scratch.join("jobs/state.json");
        for bytes in [
            b"not-json".to_vec(),
            vec![b'x'; MAX_STATE + 1],
            b"{\"schema\":99}".to_vec(),
        ] {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            file.write_all(&bytes).unwrap();
            assert_code(store.read(), Code::StateUnavailable);
        }
    }
    #[test]
    fn update_jobs_registry_lock_is_nonblocking_and_same_inode() {
        let (scratch, store) = fixture();
        let lock = store.lock().unwrap();
        let ino = scratch.join("jobs/registry.lock").metadata().unwrap().ino();
        assert_code(store.lock(), Code::Busy);
        drop(lock);
        let _next = store.lock().unwrap();
        assert_eq!(
            scratch.join("jobs/registry.lock").metadata().unwrap().ino(),
            ino
        );
    }
    #[test]
    fn update_jobs_crash_orphans_are_exact_private_bounded_and_recovered_under_lock() {
        let (scratch, store) = fixture();
        store.change(|_| Ok(())).unwrap();
        let name = format!(".state-{}", "a".repeat(64));
        let path = scratch.join(&format!("jobs/{name}"));
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap()
            .write_all(b"interrupted-private-record")
            .unwrap();
        let state = std::fs::read(scratch.join("jobs/state.json")).unwrap();
        let _guard = store.lock().unwrap();
        assert!(!path.exists());
        assert_eq!(
            std::fs::read(scratch.join("jobs/state.json")).unwrap(),
            state
        );
        assert_eq!(std::fs::read_dir(scratch.join("jobs")).unwrap().count(), 2);
    }
    #[test]
    fn update_jobs_unknown_or_unsafe_orphan_inventory_is_preserved_not_cleaned() {
        for unsafe_name in ["operator-notes", ".state-not-an-id"] {
            let (scratch, store) = fixture();
            let safe = scratch.join(&format!("jobs/.state-{}", "a".repeat(64)));
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&safe)
                .unwrap();
            let unknown = scratch.join(&format!("jobs/{unsafe_name}"));
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&unknown)
                .unwrap();
            assert_code(store.lock(), Code::StateUnavailable);
            assert!(safe.exists() && unknown.exists());
        }
        let (scratch, store) = fixture();
        let name = scratch.join(&format!("jobs/.state-{}", "b".repeat(64)));
        symlink(scratch.join("outside"), &name).unwrap();
        assert_code(store.lock(), Code::StateUnavailable);
        assert!(name.symlink_metadata().unwrap().file_type().is_symlink());
    }
    #[test]
    fn update_jobs_orphan_scan_refuses_unbounded_private_inventory_without_removing_it() {
        let (scratch, store) = fixture();
        for i in 0..18 {
            let path = scratch.join(&format!("jobs/.state-{i:064x}"));
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .unwrap();
        }
        assert_code(store.lock(), Code::StateUnavailable);
        assert_eq!(std::fs::read_dir(scratch.join("jobs")).unwrap().count(), 19);
    }
    #[test]
    fn update_jobs_mutation_generation_rejects_same_config_aba() {
        let before = sample();
        let mut after = before.clone();
        after.mutation_epoch = "8".repeat(64);
        assert_eq!(after.config_revision, before.config_revision);
        assert_code(compare_snapshot(&before, &after, false), Code::Conflict);
        assert_code(compare_snapshot(&before, &after, true), Code::Conflict);
    }
    #[test]
    fn update_jobs_admission_is_durable_idempotent_and_never_launches_twice() {
        let (_scratch, store) = fixture();
        let r = Registry::empty().unwrap();
        let req = request(&r);
        let (first, created) = store
            .change(|r| admit(r, Action::Check, &req, &sample(), 1000))
            .unwrap();
        assert!(created);
        let (second, created) = store
            .change(|r| admit(r, Action::Check, &req, &sample(), 1000))
            .unwrap();
        assert!(!created);
        assert_eq!(first.id, second.id);
        assert_eq!(store.read().unwrap().unwrap().jobs.len(), 1);
    }
    #[test]
    fn update_jobs_reused_id_with_different_request_is_a_conflict() {
        let mut r = Registry::empty().unwrap();
        let mut req = request(&r);
        admit(&mut r, Action::Check, &req, &sample(), 1000).unwrap();
        req.expected.release = "9.0.0".into();
        assert_code(
            admit(&mut r, Action::Check, &req, &sample(), 1000),
            Code::Conflict,
        );
    }
    #[test]
    fn update_jobs_busy_other_id_never_admits_parallel_work() {
        let mut r = Registry::empty().unwrap();
        let mut req = request(&r);
        admit(&mut r, Action::Check, &req, &sample(), 1000).unwrap();
        req.request_id = "3".repeat(64);
        assert_code(
            admit(&mut r, Action::Check, &req, &sample(), 1000),
            Code::Busy,
        );
    }
    #[test]
    fn update_jobs_worker_claim_is_exact_opaque_id_boot_deadline_and_once_only() {
        let mut registry = Registry::empty().unwrap();
        let req = request(&registry);
        let (job, _) = admit(&mut registry, Action::Check, &req, &sample(), 1000).unwrap();
        for id in ["../outside", "", "update-job --reboot"] {
            assert_code(
                claim_worker(&mut registry.clone(), id, &sample().boot_id, 1001),
                Code::InvalidRequest,
            );
        }
        assert_code(
            claim_worker(
                &mut registry.clone(),
                &"7".repeat(64),
                &sample().boot_id,
                1001,
            ),
            Code::NotFound,
        );
        assert_code(
            claim_worker(&mut registry.clone(), &job.id, "different-boot", 1001),
            Code::Conflict,
        );
        assert_code(
            claim_worker(
                &mut registry.clone(),
                &job.id,
                &sample().boot_id,
                job.deadline_ms + 1,
            ),
            Code::Conflict,
        );
        let claimed = claim_worker(&mut registry, &job.id, &sample().boot_id, 1001).unwrap();
        assert_eq!(claimed.id, job.id);
        assert_eq!(claimed.phase, Phase::Metadata);
        assert_code(
            claim_worker(&mut registry, &job.id, &sample().boot_id, 1001),
            Code::Conflict,
        );
    }
    #[test]
    fn update_jobs_worker_arguments_never_forward_tokens_channel_or_arbitrary_commands() {
        let mut registry = Registry::empty().unwrap();
        let req = request(&registry);
        let (job, _) = admit(&mut registry, Action::Check, &req, &sample(), 1000).unwrap();
        let args = worker_arguments(
            &job,
            "/nix/store/public-sentinel/bin/sentinel",
            [
                (
                    "SENTINEL_SELF_BIN".into(),
                    "/nix/store/public-sentinel/bin/sentinel".into(),
                ),
                ("SENTINEL_API_TOKEN".into(), "PRIVATE".into()),
                ("PATH".into(), "/mutable/bin".into()),
                ("LICENSE_KEY".into(), "SECRET".into()),
            ],
        )
        .unwrap();
        assert_eq!(
            &args[args.len() - 3..],
            [
                "/nix/store/public-sentinel/bin/sentinel",
                "update-job",
                &job.id
            ]
        );
        assert!(args.iter().any(|a| a == "--property=RuntimeMaxSec=240s"));
        assert!(args.iter().any(|a| a == "--property=Restart=no"));
        assert!(args.iter().any(|a| a == "--property=TimeoutStartSec=10s"));
        assert!(args.iter().any(|a| a == "--property=TimeoutStopSec=15s"));
        assert!(!args.iter().any(|a| {
            ["PRIVATE", "SECRET", "/mutable/bin"]
                .iter()
                .any(|secret| a.contains(secret))
        }));
        assert_code(
            worker_arguments(&job, "/tmp/sentinel", []),
            Code::UnsupportedRuntime,
        );
        for value in ["/tmp/replaced", "/nix/store/line\nsecret"] {
            assert_code(
                worker_arguments(
                    &job,
                    "/nix/store/public/bin/sentinel",
                    [("SENTINEL_SELF_BIN".into(), value.into())],
                ),
                Code::WorkerUnavailable,
            );
        }
        for name in ["SENTINEL_a_BIN", "SENTINEL_A=B_BIN", "SENTINEL_A\nB_BIN"] {
            assert_code(
                worker_arguments(
                    &job,
                    "/nix/store/public/bin/sentinel",
                    [(name.into(), "/nix/store/public/bin/tool".into())],
                ),
                Code::WorkerUnavailable,
            );
        }
    }

    #[test]
    fn update_jobs_worker_accepts_every_actual_nix_wrapper_pin_including_ext4() {
        let source;
        let pins = match option_env!("SENTINEL_TEST_TOOL_PINS") {
            Some(pins) => pins,
            None => {
                source = std::fs::read_to_string(
                    Path::new(env!("CARGO_MANIFEST_DIR")).join("flake.nix"),
                )
                .expect("local Cargo tests require the repository's actual wrapper definitions");
                &source
            }
        };
        let names: std::collections::BTreeSet<_> = pins
            .split_whitespace()
            .filter(|word| word.starts_with("SENTINEL_") && word.ends_with("_BIN"))
            .collect();
        assert!(names.contains("SENTINEL_MKFS_EXT4_BIN"));
        assert!(names.len() >= 50);
        let job = finished().jobs.remove(0);
        let args = worker_arguments(
            &job,
            "/nix/store/fixture/bin/sentinel",
            names
                .iter()
                .map(|name| (name.to_string(), "/nix/store/fixture/bin/tool".into())),
        )
        .expect("every image-owned immutable executable pin must reach the worker");
        for name in names {
            assert!(args.contains(&format!("--setenv={name}=/nix/store/fixture/bin/tool")));
        }
    }
    #[test]
    fn update_jobs_stale_generation_cannot_replay_after_history_pruning() {
        let mut r = finished();
        let mut req = request(&r);
        req.request_id = "5".repeat(64);
        req.expected_generation = "0".repeat(64);
        assert_code(
            admit(&mut r, Action::Check, &req, &sample(), 1000),
            Code::Conflict,
        );
    }
    #[test]
    fn update_jobs_every_snapshot_identity_field_is_in_the_prewrite_cas() {
        let expected = sample();
        let value = serde_json::to_value(&expected).unwrap();
        for name in value.as_object().unwrap().keys() {
            let mut changed = value.clone();
            if name == "permanent" {
                changed[name] = false.into();
            } else {
                changed[name] = format!("different-{name}").into();
            }
            let actual: Snapshot = serde_json::from_value(changed).unwrap();
            assert_code(compare_snapshot(&expected, &actual, true), Code::Conflict);
        }
        compare_snapshot(&expected, &expected, true).unwrap();
    }
    #[test]
    fn update_jobs_stage_requires_exact_offer_and_stable_boot_not_opposite_slot() {
        let mut r = Registry::empty().unwrap();
        let mut req = request(&r);
        req.offer_id = Some(offer().id);
        assert_code(
            admit(&mut r, Action::Stage, &req, &sample(), 1000),
            Code::Conflict,
        );
        r.offer = Some(offer());
        let (job, _) = admit(&mut r, Action::Stage, &req, &sample(), 1000).unwrap();
        assert_eq!(job.action, Action::Stage);
        let mut trial = sample();
        trial.selected_entry = "sentinel-b+2-1.efi".into();
        trial.permanent = false;
        assert_code(compare_snapshot(&trial, &trial, true), Code::UnstableBoot);
        let mut staged_next = sample();
        staged_next.next_entry = "sentinel-a+3.efi".into();
        assert_code(
            compare_snapshot(&staged_next, &staged_next, true),
            Code::UnstableBoot,
        );
    }
    #[test]
    fn update_jobs_file_pin_must_match_the_key_that_verified_the_offer() {
        let mut o = offer();
        assert!(valid_offer(&o));
        o.verified.public_key_sha256 = "9".repeat(64);
        assert!(!valid_offer(&o));
    }
    #[test]
    fn update_jobs_bad_ids_and_hidden_unsigned_flags_are_refused() {
        let r = Registry::empty().unwrap();
        for bad in ["../outside", "", "UPPER", "a/b", "x\n"] {
            let mut req = request(&r);
            req.request_id = bad.into();
            assert_code(
                admit(&mut r.clone(), Action::Check, &req, &sample(), 1000),
                Code::InvalidRequest,
            );
            assert!(unit_name(bad).is_err());
        }
        let mut value = serde_json::to_value(request(&r)).unwrap();
        for key in [
            "member",
            "url",
            "disk",
            "allow_unsigned",
            "allow_downgrade",
            "reboot",
        ] {
            value[key] = true.into();
            assert!(serde_json::from_value::<Request>(value.clone()).is_err());
            value.as_object_mut().unwrap().remove(key);
        }
    }
    #[test]
    fn update_jobs_invalid_registry_never_creates_unbounded_history() {
        let mut r = finished();
        r.jobs = vec![r.jobs[0].clone(); HISTORY + 1];
        for (i, j) in r.jobs.iter_mut().enumerate() {
            j.id = format!("{i:064x}");
            j.request_id = format!("{:064x}", i + 100);
        }
        assert!(!r.validate());
        r.jobs.truncate(HISTORY);
        assert!(r.validate());
    }
    #[test]
    fn update_jobs_public_job_view_exposes_signed_offer_without_config_context() {
        let mut r = finished();
        r.jobs[0].offer = Some(offer());
        let view = serde_json::to_value(JobView::from(r.jobs[0].clone())).unwrap();
        for absent in [
            "expected",
            "request_digest",
            "config_revision",
            "public_key_sha256",
        ] {
            assert!(view.get(absent).is_none());
        }
        assert_eq!(view["offer"]["id"], offer().id);
        assert_eq!(
            view["offer"]["verified"]["manifest_sha256"],
            offer().verified.manifest_sha256
        );
        assert!(view["offer"].get("snapshot").is_none());
        assert!(!view.to_string().contains(&sample().config_revision));
    }
    #[test]
    fn update_jobs_offbox_noapply_status_never_initializes_machine_or_state() {
        let scratch = update::Scratch::new().unwrap();
        let path = scratch.join("not-the-appliance.toml");
        let value = status(&path, false, true).unwrap();
        assert!(!value.can_check && !value.can_stage && value.current.is_none());
        assert_eq!(value.unavailable, Some(Code::UnsupportedRuntime));
        assert_eq!(std::fs::read_dir(scratch.join(".")).unwrap().count(), 0);
    }

    #[test]
    fn update_jobs_confirmation_requires_successful_typed_absence_of_both_units() {
        use std::os::unix::process::ExitStatusExt;
        let mut seen = Vec::new();
        confirmation_idle_with(|unit| {
            seen.push(unit.to_owned());
            Ok((
                ExitStatus::from_raw(0),
                b"SubState=dead\nLoadState=not-found\nActiveState=inactive\n".to_vec(),
            ))
        })
        .unwrap();
        assert_eq!(seen, ["sentinel-confirm.timer", "sentinel-confirm.service"]);
    }

    #[test]
    fn update_jobs_confirmation_refuses_timer_or_rollback_service_even_if_other_is_absent() {
        use std::os::unix::process::ExitStatusExt;
        for blocked_unit in ["sentinel-confirm.timer", "sentinel-confirm.service"] {
            for active in [
                "active",
                "activating",
                "deactivating",
                "reloading",
                "refreshing",
                "failed",
                "inactive",
            ] {
                let mut seen = Vec::new();
                assert_code(
                    confirmation_idle_with(|unit| {
                        seen.push(unit.to_owned());
                        let text = if unit == blocked_unit {
                            format!(
                                "LoadState=loaded\nActiveState={active}\nSubState=fixture-state\n"
                            )
                        } else {
                            "LoadState=not-found\nActiveState=inactive\nSubState=dead\n".into()
                        };
                        Ok((ExitStatus::from_raw(0), text.into_bytes()))
                    }),
                    Code::Conflict,
                );
                assert_eq!(
                    seen.len(),
                    2,
                    "both units must be observed: {blocked_unit}/{active}"
                );
            }
        }
    }

    #[test]
    fn update_jobs_confirmation_never_infers_absence_from_failure_or_partial_output() {
        use std::os::unix::process::ExitStatusExt;
        let absent = b"LoadState=not-found\nActiveState=inactive\nSubState=dead\n";
        for raw in [1 << 8, 3 << 8, 9] {
            assert_code(
                confirmation_unit_absent(ExitStatus::from_raw(raw), absent),
                Code::StateUnavailable,
            );
        }
        for bytes in [
            &b""[..],
            &b"inactive\n"[..],
            &b"LoadState=not-found\nActiveState=inactive\n"[..],
            &b"LoadState=not-found\nActiveState=inactive\nSubState=dead\nSubState=dead\n"[..],
            &b"LoadState=not-found\nActiveState=inactive\nSubState=dead\nUnexpected=yes\n"[..],
            &b"LoadState=not-found\nActiveState=active\nSubState=dead\n"[..],
            &b"LoadState=error\nActiveState=inactive\nSubState=dead\n"[..],
            &b"LoadState=loaded\nActiveState=future-state\nSubState=dead\n"[..],
            &b"LoadState=loaded\nActiveState=inactive\nSubState=\n"[..],
            &b"LoadState=not-found\nActiveState=inactive\nSubState=\xff\n"[..],
            &vec![b'x'; 1025],
        ] {
            assert_code(
                confirmation_unit_absent(ExitStatus::from_raw(0), bytes),
                Code::StateUnavailable,
            );
        }
        assert_code(
            confirmation_idle_with(|_| Err(Error(Code::StateUnavailable))),
            Code::StateUnavailable,
        );
    }

    #[test]
    fn update_jobs_bounded_probe_preserves_authoritative_nonzero_output() {
        let (status, bytes) =
            probe("/bin/sh", &["-c", "printf public-fixture; exit 7"], 2).unwrap();
        assert_eq!(status.code(), Some(7));
        assert_eq!(bytes, b"public-fixture");
    }
    #[test]
    fn update_jobs_probe_timeout_and_output_limits_are_real_and_reaped() {
        let started = Instant::now();
        assert_code(
            probe("/bin/sh", &["-c", "exec sleep 30"], 0),
            Code::StateUnavailable,
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_code(
            probe(
                "/bin/sh",
                &["-c", "while :; do printf 'public-fixture'; done"],
                2,
            ),
            Code::StateUnavailable,
        );
    }

    fn process_identity(stat: &str) -> (char, u64) {
        // comm may itself contain spaces or parentheses. Field 22 is the
        // start time, counted from state (field 3) after the final ") ".
        let fields: Vec<_> = stat
            .rsplit_once(") ")
            .unwrap()
            .1
            .split_whitespace()
            .collect();
        (
            fields[0].chars().next().unwrap(),
            fields[19].parse().unwrap(),
        )
    }

    struct FixtureProcess(std::fs::File);
    impl Drop for FixtureProcess {
        fn drop(&mut self) {
            // Test failure must not leave the deliberately busy descendant.
            // A pidfd, never a recycled numeric PID, identifies that process.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.0.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
        }
    }

    fn fixture_process_gone(error: &std::io::Error) -> bool {
        // Linux procfs can lose a task between open and read: the already-open
        // descriptor then returns ESRCH rather than pathname ENOENT. Neither
        // result names a live replacement process; all other errors stay fatal.
        error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
    }

    #[test]
    fn update_jobs_owned_fixture_accepts_only_authoritative_process_absence_errors() {
        for (errno, gone) in [
            (libc::ENOENT, true),
            (libc::ESRCH, true),
            (libc::EACCES, false),
            (libc::EPERM, false),
            (libc::EIO, false),
            (libc::EINTR, false),
        ] {
            assert_eq!(
                fixture_process_gone(&std::io::Error::from_raw_os_error(errno)),
                gone
            );
        }
    }

    fn descendant_probe(trailer: &str, seconds: u64, success: bool) {
        let scratch = update::Scratch::new().unwrap();
        let proof = scratch.join("owned-descendant");
        let script = format!(
            "(while :; do :; done) &\n\
             pid=$!\n\
             IFS= read -r stat < /proc/$pid/stat\n\
             printf '%s\\n%s\\n' \"$pid\" \"$stat\" > \"$1\"\n\
             printf public-fixture\n{trailer}"
        );
        let started = Instant::now();
        let result = probe(
            "/bin/sh",
            &[
                "-c",
                &script,
                "sentinel-owned-fixture",
                proof.to_str().unwrap(),
            ],
            seconds,
        );
        let elapsed = started.elapsed();
        let proof = std::fs::read_to_string(proof).unwrap();
        let (pid, stat) = proof.split_once('\n').unwrap();
        let pid: i32 = pid.parse().unwrap();
        assert!(pid > 1);
        let expected_start = process_identity(stat).1;
        let proc_stat = format!("/proc/{pid}/stat");

        let mut cleanup = None;
        if let Ok(current) = std::fs::read_to_string(&proc_stat) {
            if process_identity(&current).1 == expected_start {
                let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
                if fd >= 0 {
                    let file = unsafe { std::fs::File::from_raw_fd(fd as i32) };
                    // Check identity again after pinning the fd. If the old
                    // process vanished/reused its PID, do not signal this fd.
                    if std::fs::read_to_string(&proc_stat)
                        .is_ok_and(|now| process_identity(&now).1 == expected_start)
                    {
                        cleanup = Some(FixtureProcess(file));
                    }
                }
            }
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        let not_running = loop {
            match std::fs::read_to_string(&proc_stat) {
                Err(error) if fixture_process_gone(&error) => break true,
                Ok(current) => {
                    let (state, start) = process_identity(&current);
                    if start != expected_start || matches!(state, 'Z' | 'X') {
                        break true;
                    }
                }
                Err(error) => panic!("unable to inspect owned fixture: {error}"),
            }
            if Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert!(not_running, "probe left its descendant running");
        assert!(elapsed < Duration::from_secs(seconds + 2));
        if success {
            let (status, bytes) = result.unwrap();
            assert_eq!(status.code(), Some(7));
            assert_eq!(bytes, b"public-fixture");
        } else {
            assert_code(result, Code::StateUnavailable);
        }
        drop(cleanup);
    }

    #[test]
    fn update_jobs_probe_cleans_descendant_after_wrapper_exits_with_open_stdout() {
        descendant_probe("exit 7", 2, true);
    }

    #[test]
    fn update_jobs_probe_cleans_descendant_after_timeout() {
        descendant_probe("wait", 1, false);
    }

    #[test]
    fn update_jobs_probe_cleans_descendant_after_output_overflow() {
        descendant_probe("while :; do printf public-fixture; done", 2, false);
    }
    fn entries() -> Vec<serde_json::Value> {
        vec![
            serde_json::json!({"type":"type2","source":"esp","id":"sentinel-b.efi", "root":"/boot", "path":"/boot/EFI/Linux/sentinel-b.efi",
            "linux":"/EFI/Linux/sentinel-b.efi","version":"2.0.1","cmdline":format!("init=/nix/store/public/init usrhash={}", sample().verity),"isSelected":true,"isDefault":true}),
        ]
    }
    fn parse_entries(rows: &[serde_json::Value]) -> JobResult<(String, String, bool)> {
        boot_entry(
            &serde_json::to_vec(rows).unwrap(),
            "sentinel-b",
            "2.0.1",
            &sample().verity,
        )
    }
    #[test]
    fn update_jobs_bootctl_uses_actual_source_esp_path_schema() {
        assert_eq!(
            parse_entries(&entries()).unwrap(),
            ("sentinel-b.efi".into(), "sentinel-b.efi".into(), true)
        );
        let mut rows = entries();
        rows[0]["source"] = "/boot/EFI/Linux/sentinel-b.efi".into();
        assert_code(parse_entries(&rows), Code::UnstableBoot);
    }
    #[test]
    fn update_jobs_bootctl_duplicate_selected_or_wrong_guid_path_is_not_healthy() {
        let mut rows = entries();
        rows.push(rows[0].clone());
        assert_code(parse_entries(&rows), Code::UnstableBoot);
        for (key, wrong) in [
            ("path", "/elsewhere/sentinel-b.efi"),
            ("version", "0.0.0"),
            ("cmdline", "usrhash=wrong"),
            ("root", "/wrong"),
        ] {
            let mut rows = entries();
            rows[0][key] = wrong.into();
            assert_code(parse_entries(&rows), Code::UnstableBoot);
        }
    }
    #[test]
    fn update_jobs_counted_boot_is_observed_but_never_classed_permanent() {
        let mut rows = entries();
        rows[0]["id"] = "sentinel-b+2-1.efi".into();
        rows[0]["path"] = "/boot/EFI/Linux/sentinel-b+2-1.efi".into();
        rows[0]["linux"] = "/EFI/Linux/sentinel-b+2-1.efi".into();
        assert!(!parse_entries(&rows).unwrap().2);
    }
    #[test]
    fn update_jobs_recovery_never_interprets_unknown_systemctl_failure_as_dead() {
        use std::os::unix::process::ExitStatusExt;
        let active = b"LoadState=loaded\nActiveState=active\n";
        assert!(parse_unit(ExitStatus::from_raw(0), active).unwrap());
        assert!(
            !parse_unit(
                ExitStatus::from_raw(0),
                b"LoadState=loaded\nActiveState=failed\n"
            )
            .unwrap()
        );
        assert!(
            !parse_unit(
                ExitStatus::from_raw(0),
                b"LoadState=not-found\nActiveState=inactive\n"
            )
            .unwrap()
        );
        for (status, bytes) in [
            (1 << 8, &b""[..]),
            (127 << 8, active),
            (15, active),
            (0, &b"malformed\n"[..]),
            (1 << 8, &b"LoadState=not-found\nActiveState=inactive\n"[..]),
            (4 << 8, &b"LoadState=not-found\nActiveState=inactive\n"[..]),
            (
                0,
                &b"LoadState=loaded\nLoadState=not-found\nActiveState=inactive\n"[..],
            ),
            (
                0,
                &b"LoadState=loaded\nActiveState=inactive\nUnknown=value\n"[..],
            ),
            (
                0,
                &b"LoadState=loaded\nActiveState=inactive\nmalformed\n"[..],
            ),
        ] {
            assert_code(
                parse_unit(ExitStatus::from_raw(status), bytes),
                Code::StateUnavailable,
            );
        }
    }
    #[test]
    fn update_jobs_recovery_is_interruption_not_automatic_retry_or_success() {
        let mut r = Registry::empty().unwrap();
        let req = request(&r);
        let (base, _) = admit(&mut r, Action::Check, &req, &sample(), 1000).unwrap();
        for phase in [
            Phase::Accepted,
            Phase::Metadata,
            Phase::Downloading,
            Phase::Verifying,
            Phase::Preflight,
            Phase::Writing,
            Phase::Publishing,
        ] {
            let mut job = base.clone();
            job.phase = phase;
            mark_interrupted(&mut job);
            assert_eq!(job.phase, Phase::Interrupted);
            assert_eq!(
                job.error,
                Some(if phase.may_have_written() {
                    Code::WriteOutcomeUnknown
                } else {
                    Code::Interrupted
                })
            );
            assert!(job.staged.is_none());
        }
        let mut completed = finished().jobs.remove(0);
        mark_interrupted(&mut completed);
        assert_eq!(completed.phase, Phase::Checked);
    }
    #[test]
    fn update_jobs_write_uncertainty_overrides_a_later_stale_config_error() {
        let error: anyhow::Error = Error(Code::Conflict).into();
        assert_eq!(failure_code(Phase::Preflight, &error), Code::Conflict);
        assert_eq!(
            failure_code(Phase::Writing, &error),
            Code::WriteOutcomeUnknown
        );
        assert_eq!(
            failure_code(Phase::Publishing, &error),
            Code::WriteOutcomeUnknown
        );
    }
    fn running_stage(store: &Store, phase: Phase) -> String {
        store
            .change(|r| {
                r.offer = Some(offer());
                let mut req = request(r);
                req.offer_id = Some(offer().id);
                let (job, _) = admit(r, Action::Stage, &req, &sample(), 1000)?;
                r.jobs.last_mut().unwrap().phase = phase;
                Ok(job.id)
            })
            .unwrap()
    }
    fn staged_image() -> install::StagedImage {
        install::StagedImage {
            active_slot: "sentinel-b".into(),
            staged_slot: "sentinel-a".into(),
            verity_guid: "44444444-4444-4444-4444-444444444444".into(),
            store_guid: "55555555-5555-5555-5555-555555555555".into(),
            boot_entry: "sentinel-a+3.efi".into(),
            uki_sha256: "6".repeat(64),
        }
    }
    #[test]
    fn update_jobs_worker_exit_and_durable_failure_use_the_same_typed_code() {
        for phase in [
            Phase::Metadata,
            Phase::Downloading,
            Phase::Verifying,
            Phase::Preflight,
            Phase::Writing,
            Phase::Publishing,
        ] {
            for error in [
                anyhow::anyhow!("raw upstream PRIVATE credential details"),
                Error(Code::Conflict).into(),
                crate::update_stage::UpdateBusy.into(),
            ] {
                let (_scratch, store) = fixture();
                let id = running_stage(&store, phase);
                let expected = failure_code(phase, &error);
                assert_code(finish_worker(&store, &id, phase, &Err(error)), expected);
                let registry = store.read().unwrap().unwrap();
                let job = &registry.jobs[0];
                assert_eq!(job.phase, Phase::Failed);
                assert_eq!(job.error, Some(expected));
                assert!(job.staged.is_none());
                assert!(!expected.message().contains("PRIVATE"));
                if phase.may_have_written() {
                    assert!(!expected.message().contains("before slot writing"));
                    assert!(!expected.message().contains("unchanged"));
                }
            }
        }
    }
    #[test]
    fn update_jobs_completion_cannot_erase_durable_or_local_write_uncertainty() {
        for (durable, local) in [
            (Phase::Writing, Phase::Preflight),
            (Phase::Preflight, Phase::Writing),
            (Phase::Publishing, Phase::Writing),
        ] {
            let (_scratch, store) = fixture();
            let id = running_stage(&store, durable);
            assert_code(
                finish_worker(&store, &id, local, &Err(Error(Code::Conflict).into())),
                Code::WriteOutcomeUnknown,
            );
            assert_eq!(
                store.read().unwrap().unwrap().jobs[0].error,
                Some(Code::WriteOutcomeUnknown)
            );
        }
    }
    #[test]
    fn update_jobs_final_registry_failure_after_writes_never_claims_prewrite_refusal() {
        for phase in [Phase::Writing, Phase::Publishing] {
            for success in [false, true] {
                for corruption in ["locked", "invalid-state", "unsafe-inventory"] {
                    let (scratch, store) = fixture();
                    let id = running_stage(&store, phase);
                    let guard = if corruption == "locked" {
                        Some(store.lock().unwrap())
                    } else {
                        if corruption == "invalid-state" {
                            std::fs::write(scratch.join("jobs/state.json"), b"not-json").unwrap();
                        } else {
                            std::fs::write(scratch.join("jobs/unowned-file"), b"do-not-delete")
                                .unwrap();
                        }
                        None
                    };
                    let result = if success {
                        Ok(Some(staged_image()))
                    } else {
                        Err(Error(Code::Conflict).into())
                    };
                    assert_code(
                        finish_worker(&store, &id, phase, &result),
                        Code::WriteOutcomeUnknown,
                    );
                    drop(guard);
                    if corruption == "locked" {
                        let registry = store.read().unwrap().unwrap();
                        assert_eq!(registry.jobs[0].phase, phase);
                        assert!(registry.jobs[0].staged.is_none());
                    } else if corruption == "unsafe-inventory" {
                        assert_eq!(
                            std::fs::read(scratch.join("jobs/unowned-file")).unwrap(),
                            b"do-not-delete"
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn update_jobs_completion_does_not_overwrite_a_recovered_terminal_job() {
        let (_scratch, store) = fixture();
        let id = running_stage(&store, Phase::Publishing);
        store
            .change(|r| {
                mark_interrupted(&mut r.jobs[0]);
                Ok(())
            })
            .unwrap();
        assert_code(
            finish_worker(&store, &id, Phase::Publishing, &Ok(Some(staged_image()))),
            Code::WriteOutcomeUnknown,
        );
        let registry = store.read().unwrap().unwrap();
        assert_eq!(registry.jobs[0].phase, Phase::Interrupted);
        assert_eq!(registry.jobs[0].error, Some(Code::WriteOutcomeUnknown));
        assert!(registry.jobs[0].staged.is_none());
    }
    #[test]
    fn update_jobs_completed_check_and_stage_still_publish_their_real_result() {
        for action in [Action::Check, Action::Stage] {
            let (_scratch, store) = fixture();
            let phase = if action == Action::Stage {
                Phase::Publishing
            } else {
                Phase::Metadata
            };
            let id = if action == Action::Stage {
                running_stage(&store, phase)
            } else {
                store
                    .change(|r| {
                        let req = request(r);
                        let (job, _) = admit(r, action, &req, &sample(), 1000)?;
                        r.jobs.last_mut().unwrap().phase = phase;
                        Ok(job.id)
                    })
                    .unwrap()
            };
            let result = (action == Action::Stage).then(staged_image);
            finish_worker(&store, &id, phase, &Ok(result.clone())).unwrap();
            let registry = store.read().unwrap().unwrap();
            let job = &registry.jobs[0];
            assert_eq!(
                job.phase,
                if action == Action::Stage {
                    Phase::Staged
                } else {
                    Phase::Checked
                }
            );
            assert_eq!(job.error, None);
            assert_eq!(job.staged, result);
        }
    }
    #[test]
    fn update_jobs_raw_upstream_credential_errors_are_never_public_messages() {
        let error = anyhow::anyhow!(
            "https://user:SECRET@channel/?license=PRIVATE HTTP401 raw upstream data"
        );
        for phase in [
            Phase::Metadata,
            Phase::Downloading,
            Phase::Verifying,
            Phase::Preflight,
            Phase::Writing,
            Phase::Publishing,
        ] {
            let code = failure_code(phase, &error);
            assert!(
                !code.message().contains("SECRET")
                    && !code.message().contains("PRIVATE")
                    && !code.message().contains("https")
            );
            assert_ne!(code, Code::InvalidRequest);
        }
    }
    #[test]
    fn update_jobs_invalid_state_write_preserves_prior_durable_bytes() {
        let (scratch, store) = fixture();
        store.change(|_| Ok(())).unwrap();
        let path = scratch.join("jobs/state.json");
        let before = std::fs::read(&path).unwrap();
        assert_code(
            store.change(|r| {
                r.schema = 999;
                Ok(())
            }),
            Code::StateUnavailable,
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn update_jobs_native_snapshot_binds_release_and_requires_actual_blessing() {
        for slot in ["sentinel-a", "sentinel-b"] {
            let mut snapshot = sample();
            snapshot.slot = slot.into();
            snapshot.release = "v1.2.3-lts".into();
            snapshot.selected_entry = "sentinel_v1.2.3-lts.efi".into();
            snapshot.next_entry = snapshot.selected_entry.clone();
            assert!(snapshot.validate_with(true));
            assert!(snapshot.stable());
            assert!(!snapshot.validate_with(false));
            let mut wrong = snapshot.clone();
            wrong.release = "v1.2.4-lts".into();
            assert!(!wrong.validate_with(true));
            for counted in ["+3", "+3-0", "+0-3"] {
                let mut pending = snapshot.clone();
                pending.selected_entry = format!("sentinel_v1.2.3-lts{counted}.efi");
                pending.next_entry = pending.selected_entry.clone();
                assert!(!pending.validate_with(true)); // A boolean cannot bless a counted file.
                pending.permanent = false;
                assert!(pending.validate_with(true));
                assert!(!pending.stable());
            }
            snapshot.next_entry = "sentinel_v1.2.4-lts+3-0.efi".into();
            assert!(snapshot.validate_with(true));
            assert!(!snapshot.stable());
        }
        let mut wrong_slot = sample();
        wrong_slot.selected_entry = "sentinel-a.efi".into();
        assert!(!wrong_slot.validate_with(false));
    }

    #[test]
    fn update_jobs_native_bootctl_observation_keeps_source_hash_and_release_checks() {
        for counted in ["", "+3-0", "+0-3"] {
            let id = format!("sentinel_v1.2.3-lts{counted}.efi");
            let mut rows = entries();
            rows[0]["id"] = id.clone().into();
            rows[0]["path"] = format!("/boot/EFI/Linux/{id}").into();
            rows[0]["linux"] = format!("/EFI/Linux/{id}").into();
            rows[0]["version"] = "v1.2.3-lts".into();
            let parse = |rows: &[serde_json::Value], version: &str, native| {
                boot_entry_with_policy(
                    &serde_json::to_vec(rows).unwrap(),
                    "sentinel-b",
                    version,
                    &sample().verity,
                    native,
                )
            };
            assert_eq!(
                parse(&rows, "v1.2.3-lts", true).unwrap(),
                (id.clone(), id, counted.is_empty())
            );
            assert_code(parse(&rows, "v1.2.3-lts", false), Code::UnstableBoot);
            assert_code(parse(&rows, "v1.2.4-lts", true), Code::UnstableBoot);
            for (key, value) in [
                ("source", "xbootldr"),
                ("type", "type1"),
                ("root", "/other"),
                ("path", "/boot/EFI/Linux/sentinel-b.efi"),
                ("cmdline", "usrhash=wrong"),
            ] {
                let mut wrong = rows.clone();
                wrong[0][key] = value.into();
                assert_code(parse(&wrong, "v1.2.3-lts", true), Code::UnstableBoot);
            }
        }
    }

    fn actual_native_boot_rows() -> Vec<serde_json::Value> {
        let mut selected = entries()[0].clone();
        selected["id"] = "sentinel_v1.2.3-lts.efi".into();
        selected["path"] = "/boot/EFI/Linux/sentinel_v1.2.3-lts.efi".into();
        selected["linux"] = "/EFI/Linux/sentinel_v1.2.3-lts.efi".into();
        selected["version"] = "v1.2.3-lts".into();
        selected["isDefault"] = false.into();
        let mut pending = selected.clone();
        pending["id"] = "sentinel_v1.2.4-lts.efi".into();
        pending["path"] = "/boot/EFI/Linux/sentinel_v1.2.4-lts+3-0.efi".into();
        pending["linux"] = "/EFI/Linux/sentinel_v1.2.4-lts+3-0.efi".into();
        pending["version"] = "v1.2.4-lts".into();
        pending["isDefault"] = true.into();
        pending["isSelected"] = false.into();
        pending["triesLeft"] = 3.into();
        pending["triesDone"] = 0.into();
        vec![selected, pending]
    }

    fn parse_actual_native_rows(rows: &[serde_json::Value]) -> JobResult<(String, String, bool)> {
        boot_entry_with_policy(
            &serde_json::to_vec(rows).unwrap(),
            "sentinel-b",
            "v1.2.3-lts",
            &sample().verity,
            true,
        )
    }

    #[test]
    fn update_jobs_real_bootctl_normalized_id_retains_the_actual_counted_next_filename() {
        // Reproduces systemd 260's actual native Stage readback: the ID is
        // stable, but path/linux and tries metadata describe a trial inode.
        assert_eq!(
            parse_actual_native_rows(&actual_native_boot_rows()).unwrap(),
            (
                "sentinel_v1.2.3-lts.efi".into(),
                "sentinel_v1.2.4-lts+3-0.efi".into(),
                true
            )
        );
    }

    #[test]
    fn update_jobs_normalized_selected_trial_can_never_be_mistaken_for_permanent() {
        let mut row = actual_native_boot_rows().remove(1);
        row["isSelected"] = true.into();
        for (left, done) in [(3, 0), (2, 1), (0, 3)] {
            let name = format!("sentinel_v1.2.4-lts+{left}-{done}.efi");
            row["path"] = format!("/boot/EFI/Linux/{name}").into();
            row["linux"] = format!("/EFI/Linux/{name}").into();
            row["triesLeft"] = left.into();
            row["triesDone"] = done.into();
            assert_eq!(
                boot_entry_with_policy(
                    &serde_json::to_vec(&[&row]).unwrap(),
                    "sentinel-b",
                    "v1.2.4-lts",
                    &sample().verity,
                    true,
                )
                .unwrap(),
                (name.clone(), name, false)
            );
        }
    }

    #[test]
    fn update_jobs_default_entry_identity_and_counter_metadata_are_not_trusted_by_id_alone() {
        for (key, invalid) in [
            ("id", serde_json::json!("sentinel_v1.2.5-lts.efi")),
            (
                "path",
                serde_json::json!("/elsewhere/sentinel_v1.2.4-lts+3-0.efi"),
            ),
            (
                "path",
                serde_json::json!("/boot/EFI/Linux/../sentinel_v1.2.4-lts+3-0.efi"),
            ),
            (
                "linux",
                serde_json::json!("/EFI/Linux/sentinel_v1.2.4-lts.efi"),
            ),
            ("source", serde_json::json!("xbootldr")),
            ("root", serde_json::json!("/other")),
            ("type", serde_json::json!("type1")),
            ("version", serde_json::json!("v1.2.5-lts")),
            ("triesLeft", serde_json::json!(2)),
            ("triesDone", serde_json::json!(1)),
            ("triesDone", serde_json::json!(-1)),
            ("triesLeft", serde_json::json!(true)),
            ("triesDone", serde_json::Value::Null),
            ("cmdline", serde_json::json!("usrhash=wrong")),
        ] {
            let mut rows = actual_native_boot_rows();
            rows[1][key] = invalid;
            assert_code(parse_actual_native_rows(&rows), Code::UnstableBoot);
        }
        let mut rows = actual_native_boot_rows();
        rows[0]["triesLeft"] = 0.into();
        rows[0]["triesDone"] = 0.into();
        assert_code(parse_actual_native_rows(&rows), Code::UnstableBoot);
    }

    fn actual_community_single_counter_rows() -> Vec<serde_json::Value> {
        let mut selected = entries().remove(0);
        selected["isDefault"] = false.into();
        let mut pending = selected.clone();
        pending["id"] = "sentinel-a.efi".into();
        pending["path"] = "/boot/EFI/Linux/sentinel-a+3.efi".into();
        pending["linux"] = "/EFI/Linux/sentinel-a+3.efi".into();
        pending["version"] = "3.0.0".into();
        pending["cmdline"] = format!("usrhash={}", "b".repeat(64)).into();
        pending["isDefault"] = true.into();
        pending["isSelected"] = false.into();
        pending["triesLeft"] = 3.into();
        // systemd 260 emits triesDone only if the filename actually has -N.
        vec![selected, pending]
    }

    #[test]
    fn update_jobs_actual_single_counter_schema_keeps_an_omitted_done_counter_unassessed() {
        let rows = actual_community_single_counter_rows();
        assert_eq!(
            parse_entries(&rows).unwrap(),
            ("sentinel-b.efi".into(), "sentinel-a+3.efi".into(), true)
        );
        let mut trial = rows[1].clone();
        trial["isSelected"] = true.into();
        assert_eq!(
            boot_entry_with_policy(
                &serde_json::to_vec(&[trial]).unwrap(),
                "sentinel-a",
                "3.0.0",
                &"b".repeat(64),
                false,
            )
            .unwrap(),
            ("sentinel-a+3.efi".into(), "sentinel-a+3.efi".into(), false)
        );
    }

    #[test]
    fn update_jobs_single_counter_schema_still_requires_matching_left_and_implicit_zero_done() {
        for (field, invalid) in [
            ("triesLeft", serde_json::json!(2)),
            ("triesLeft", serde_json::json!(true)),
            ("triesLeft", serde_json::Value::Null),
            ("triesDone", serde_json::json!(1)),
            ("triesDone", serde_json::json!(-1)),
            ("triesDone", serde_json::json!("0")),
        ] {
            let mut rows = actual_community_single_counter_rows();
            rows[1][field] = invalid;
            assert_code(parse_entries(&rows), Code::UnstableBoot);
        }
        let mut rows = actual_community_single_counter_rows();
        rows[1]["triesDone"] = 0.into();
        parse_entries(&rows).unwrap();
    }

    #[test]
    fn update_jobs_legacy_full_counted_id_requires_consistent_metadata_when_present() {
        let mut rows = actual_native_boot_rows();
        rows[1]["id"] = "sentinel_v1.2.4-lts+3-0.efi".into();
        parse_actual_native_rows(&rows).unwrap();
        rows[1]["triesDone"] = 1.into();
        assert_code(parse_actual_native_rows(&rows), Code::UnstableBoot);
        rows[1].as_object_mut().unwrap().remove("triesLeft");
        rows[1].as_object_mut().unwrap().remove("triesDone");
        parse_actual_native_rows(&rows).unwrap();
        rows[1]["id"] = "sentinel_v1.2.4-lts.efi".into();
        assert_code(parse_actual_native_rows(&rows), Code::UnstableBoot);
    }

    #[test]
    fn update_jobs_staged_identity_must_be_an_initial_counted_opposite_slot() {
        let expected = sample();
        let offer = offer().verified;
        let original = staged_image();
        assert!(valid_staged(&original, &expected, &offer, false));
        let serialized = serde_json::to_value(&original).unwrap();
        for (field, invalid) in [
            ("active_slot", "sentinel-a"),
            ("staged_slot", "sentinel-b"),
            ("staged_slot", "unknown"),
            ("boot_entry", "sentinel-a.efi"),
            ("boot_entry", "sentinel-b+3.efi"),
            ("boot_entry", "../sentinel-a+3.efi"),
            ("boot_entry", "sentinel-a+0-3.efi"),
            ("boot_entry", "sentinel-a+2-1.efi"),
            ("boot_entry", "sentinel-a+3-0.efi"),
            ("uki_sha256", "invalid"),
            ("store_guid", "invalid"),
            ("verity_guid", "00000000-0000-0000-0000-000000000000"),
            ("verity_guid", "44444444-4444-4444-4444-444444444444A"),
            ("store_guid", "44444444-4444-4444-4444-444444444444"),
            ("store_guid", "22222222-2222-2222-2222-222222222222"),
            ("verity_guid", "33333333-3333-3333-3333-333333333333"),
        ] {
            let mut value = serialized.clone();
            value[field] = invalid.into();
            let stage = serde_json::from_value(value).unwrap();
            assert!(
                !valid_staged(&stage, &expected, &offer, false),
                "{field}: {invalid}"
            );
        }
    }

    #[test]
    fn update_jobs_native_staged_identity_binds_the_exact_reviewed_release() {
        let mut offer = offer().verified;
        offer.manifest.version = "v1.2.3-lts".into();
        let mut staged = staged_image();
        staged.boot_entry = "sentinel_v1.2.3-lts+3-0.efi".into();
        assert!(valid_staged(&staged, &sample(), &offer, true));
        assert!(!valid_staged(&staged, &sample(), &offer, false));
        offer.manifest.version = "v1.2.4-lts".into();
        assert!(!valid_staged(&staged, &sample(), &offer, true));
        offer.manifest.version = "v1.2.3-lts".into();
        for entry in [
            "sentinel_v1.2.3-lts.efi",
            "sentinel_v1.2.3-lts+3.efi",
            "sentinel_v1.2.3-lts+0-3.efi",
            "sentinel_v1.2.3-lts+2-1.efi",
        ] {
            staged.boot_entry = entry.into();
            assert!(!valid_staged(&staged, &sample(), &offer, true), "{entry}");
        }
    }

    #[test]
    fn update_jobs_sgdisk_and_native_uuid_case_are_the_same_partition_identity() {
        let mut stage = staged_image();
        stage.verity_guid = "abcdef01-abcd-abcd-abcd-abcdef012345".into();
        stage.store_guid = "fedcba01-abcd-abcd-abcd-abcdef012345".into();
        assert!(valid_staged(&stage, &sample(), &offer().verified, false));
        stage.verity_guid.make_ascii_uppercase();
        stage.store_guid.make_ascii_uppercase();
        assert!(valid_staged(&stage, &sample(), &offer().verified, false));
        let mut expected = sample();
        expected.store_guid = stage.verity_guid.to_ascii_lowercase();
        assert!(!valid_staged(&stage, &expected, &offer().verified, false));
        stage.store_guid = stage.verity_guid.to_ascii_lowercase();
        assert!(!valid_staged(&stage, &sample(), &offer().verified, false));
    }

    #[test]
    fn update_jobs_journal_refuses_corrupt_staged_results_without_rewriting_evidence() {
        let (scratch, store) = fixture();
        let id = running_stage(&store, Phase::Publishing);
        finish_worker(&store, &id, Phase::Publishing, &Ok(Some(staged_image()))).unwrap();
        let path = scratch.join("jobs/state.json");
        let original: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        for (field, invalid) in [
            ("active_slot", "sentinel-a"),
            ("boot_entry", "sentinel-a.efi"),
            ("uki_sha256", "not-a-hash"),
            ("store_guid", "not-a-guid"),
        ] {
            let mut value = original.clone();
            value["jobs"][0]["staged"][field] = invalid.into();
            let corrupt = serde_json::to_vec(&value).unwrap();
            std::fs::write(&path, &corrupt).unwrap();
            assert_code(store.read(), Code::StateUnavailable);
            assert_eq!(std::fs::read(&path).unwrap(), corrupt);
        }
        for edit in ["missing-offer", "different-snapshot", "success-with-error"] {
            let mut value = original.clone();
            match edit {
                "missing-offer" => value["jobs"][0]["offer"] = serde_json::Value::Null,
                "different-snapshot" => {
                    value["jobs"][0]["offer"]["snapshot"]["mutation_epoch"] = "1".repeat(64).into()
                }
                "success-with-error" => value["jobs"][0]["error"] = "write-outcome-unknown".into(),
                _ => unreachable!(),
            }
            let corrupt = serde_json::to_vec(&value).unwrap();
            std::fs::write(&path, &corrupt).unwrap();
            assert_code(store.read(), Code::StateUnavailable);
            assert_eq!(std::fs::read(&path).unwrap(), corrupt);
        }
    }

    #[test]
    fn update_jobs_success_requires_the_typed_result_and_both_publication_observations() {
        for phase in [Phase::Metadata, Phase::Writing, Phase::Publishing] {
            for result in [
                None,
                Some(install::StagedImage {
                    boot_entry: "sentinel-a.efi".into(),
                    ..staged_image()
                }),
            ] {
                let (_scratch, store) = fixture();
                let id = running_stage(&store, phase);
                let expected = if phase.may_have_written() {
                    Code::WriteOutcomeUnknown
                } else {
                    Code::StateUnavailable
                };
                assert_code(finish_worker(&store, &id, phase, &Ok(result)), expected);
                let registry = store.read().unwrap().unwrap();
                assert_eq!(registry.jobs[0].phase, Phase::Failed);
                assert_eq!(registry.jobs[0].error, Some(expected));
                assert!(registry.jobs[0].staged.is_none());
            }
        }
        for (durable, local) in [
            (Phase::Writing, Phase::Publishing),
            (Phase::Publishing, Phase::Writing),
        ] {
            let (_scratch, store) = fixture();
            let id = running_stage(&store, durable);
            assert_code(
                finish_worker(&store, &id, local, &Ok(Some(staged_image()))),
                Code::WriteOutcomeUnknown,
            );
            assert_eq!(store.read().unwrap().unwrap().jobs[0].phase, Phase::Failed);
        }
    }

    #[test]
    fn update_jobs_engine_phase_matrix_cannot_skip_or_erase_the_write_boundary() {
        let engine = [
            Phase::Metadata,
            Phase::Downloading,
            Phase::Verifying,
            Phase::Preflight,
            Phase::Writing,
            Phase::Publishing,
        ];
        let other = [
            Phase::Accepted,
            Phase::Checked,
            Phase::Staged,
            Phase::Failed,
            Phase::Interrupted,
        ];
        for (from_index, from) in engine.iter().enumerate() {
            for (to_index, to) in engine.iter().enumerate() {
                assert_eq!(
                    from.permits(*to),
                    to_index == from_index || to_index == from_index + 1,
                    "{from:?} -> {to:?}"
                );
            }
            for state in other {
                assert!(!from.permits(state));
                assert!(!state.permits(*from));
            }
        }
    }

    #[test]
    fn update_jobs_check_cannot_publish_an_image_result_as_a_metadata_success() {
        let (_scratch, store) = fixture();
        let id = store
            .change(|r| {
                let req = request(r);
                let (job, _) = admit(r, Action::Check, &req, &sample(), 1000)?;
                r.jobs.last_mut().unwrap().phase = Phase::Metadata;
                Ok(job.id)
            })
            .unwrap();
        assert_code(
            finish_worker(&store, &id, Phase::Metadata, &Ok(Some(staged_image()))),
            Code::StateUnavailable,
        );
        let registry = store.read().unwrap().unwrap();
        assert_eq!(registry.jobs[0].phase, Phase::Failed);
        assert!(registry.jobs[0].staged.is_none());
    }
}
