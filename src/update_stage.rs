//! Bounded, anonymous persistent staging for signed channel RAW images.
//!
//! A RAW's logical length includes unused slots and zero-filled partitions. A
//! dense `/tmp` download consumes RAM and may not fit even when the actual
//! payload fits persistent state. Keep every logical byte and its signed hash,
//! but allocate only nonzero blocks on the mounted ext4 state filesystem.

use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Output, Stdio};

use anyhow::{Context, Result, ensure};
use ring::digest;

const STATE: &str = "/var/lib/sentinel";
const LOCK_DIRECTORY: &str = "/run/sentinel-update";
const CHUNK: usize = 4 * 1024 * 1024;
const RESERVE: u64 = 512 * 1024 * 1024;
const METADATA_HEADROOM: u64 = 8 * 1024 * 1024;
const STDERR_TAIL: usize = 4096;
const STATUS_MARKER: &str = "SENTINEL_HTTP_STATUS:";

/// The same nonblocking lock protects all local and remote slot writers. It is
/// deliberately separate from the config apply lock: a stalled download must
/// never block an emergency configuration commit.
pub struct UpdateLock(File);

#[derive(Debug)]
pub struct UpdateBusy;
impl std::fmt::Display for UpdateBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("another update is in progress; nothing was changed")
    }
}
impl std::error::Error for UpdateBusy {}

impl UpdateLock {
    pub fn acquire() -> Result<Self> {
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "update must run as root (try `sudo sentinel update …`)"
        );
        let path = Path::new(LOCK_DIRECTORY);
        match std::fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("creating private update lock directory"),
        }
        Self::at(path)
    }

    fn at(path: &Path) -> Result<Self> {
        let directory = open_directory(path)?;
        let metadata = directory.metadata()?;
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o777 == 0o700,
            "update lock directory must be caller-owned0700"
        );
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                c"install.lock".as_ptr(),
                libc::O_RDWR
                    | libc::O_CREAT
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
                0o600,
            )
        };
        let file = owned_fd(fd).context("opening update transaction lock")?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o777 == 0o600
                && metadata.nlink() == 1,
            "update transaction lock is not a private regular file"
        );
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                return Err(UpdateBusy.into());
            }
            return Err(error).context("locking update transaction");
        }
        Ok(Self(file))
    }
}

impl Drop for UpdateLock {
    fn drop(&mut self) {
        // Never unlink a lock inode: a second process must lock the same inode.
        // Explicit unlock also releases a transient fork inheritance before an
        // unrelated child has exec'ed and closed its CLOEXEC descriptor.
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn owned_fd(fd: libc::c_int) -> std::io::Result<File> {
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: this successful open returned a fresh descriptor we own.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn open_directory(path: &Path) -> Result<File> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("opening update storage directory {}", path.display()))
}

#[derive(Clone, Copy, Debug)]
struct Space {
    available: u64,
    total: u64,
    block: u64,
}

fn space(file: &File) -> Result<Space> {
    let mut value = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::fstatvfs(file.as_raw_fd(), value.as_mut_ptr()) } == 0,
        "inspecting update staging capacity: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: successful fstatvfs initialized the complete value.
    let value = unsafe { value.assume_init() };
    ensure!(
        value.f_flag & libc::ST_RDONLY == 0,
        "update state is read-only"
    );
    let block = value.f_frsize;
    ensure!(
        (512..=65536).contains(&block) && block.is_power_of_two(),
        "unsupported update storage allocation block size"
    );
    Ok(Space {
        // Do not consume ext4's root-reserved blocks, even though we are root.
        available: value
            .f_bavail
            .checked_mul(block)
            .context("update available-capacity overflow")?,
        total: value
            .f_blocks
            .checked_mul(block)
            .context("update total-capacity overflow")?,
        block,
    })
}

fn reserve(space: Space) -> u64 {
    RESERVE.max(space.total / 20)
}

fn allocation_size(bytes: u64, block: u64) -> Result<u64> {
    ensure!(
        block > 0 && block.is_power_of_two(),
        "invalid allocation block size"
    );
    bytes
        .checked_add(block - 1)
        .map(|value| value / block * block)
        .context("update allocation-size overflow")
}

fn allow_allocation(available: u64, bytes: u64, reserve: u64) -> Result<()> {
    let need = bytes
        .checked_add(reserve)
        .and_then(|value| value.checked_add(METADATA_HEADROOM))
        .context("update capacity calculation overflow")?;
    ensure!(
        available >= need,
        "insufficient persistent update staging capacity: {available} bytes available, \
         {bytes} bytes needed for the next payload extent plus {reserve} bytes reserve \
         and {METADATA_HEADROOM} bytes metadata headroom; nothing was written to a slot"
    );
    Ok(())
}

/// Private and unlinked from creation. A wheel-writable state parent cannot
/// rename or replace this inode; process death also reclaims it automatically.
pub struct ImageStage {
    file: File,
    block: usize,
    reserve: u64,
    budget: u64,
    allocated: u64,
}

impl ImageStage {
    pub fn new() -> Result<Self> {
        Self::at(Path::new(STATE))
    }

    fn at(path: &Path) -> Result<Self> {
        let directory = open_directory(path)?;
        let metadata = directory.metadata()?;
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() },
            "update state must belong to its caller"
        );
        let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
        ensure!(
            unsafe { libc::fstatfs(directory.as_raw_fd(), fs.as_mut_ptr()) } == 0,
            "inspecting update state filesystem"
        );
        let fs = unsafe { fs.assume_init() };
        ensure!(
            fs.f_type == libc::EXT4_SUPER_MAGIC,
            "persistent update state is not mounted ext4; refusing volatile or unsupported staging"
        );
        let parent = owned_fd(unsafe {
            libc::openat(
                directory.as_raw_fd(),
                c"..".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        })?;
        ensure!(
            metadata.dev() != parent.metadata()?.dev(),
            "persistent update state is not a separate mounted filesystem"
        );
        Self::in_directory(&directory)
    }

    fn in_directory(directory: &File) -> Result<Self> {
        let snapshot = space(directory)?;
        let reserve = reserve(snapshot);
        allow_allocation(snapshot.available, 0, reserve)?;
        let file = owned_fd(unsafe {
            libc::openat(
                directory.as_raw_fd(),
                c".".as_ptr(),
                libc::O_TMPFILE | libc::O_EXCL | libc::O_RDWR | libc::O_CLOEXEC,
                0o600,
            )
        })
        .context("creating anonymous persistent update file (no volatile fallback)")?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o777 == 0o600
                && metadata.nlink() == 0
                && metadata.dev() == directory.metadata()?.dev(),
            "update stage is not the private anonymous inode just created"
        );
        Ok(Self {
            file,
            block: snapshot.block as usize,
            reserve,
            budget: snapshot.available - reserve - METADATA_HEADROOM,
            allocated: 0,
        })
    }
}

trait SparseSink {
    fn block(&self) -> usize;
    fn write_extent(&mut self, bytes: &[u8], offset: u64) -> Result<()>;
    fn finish(&mut self, bytes: u64) -> Result<()>;
}

impl SparseSink for ImageStage {
    fn block(&self) -> usize {
        self.block
    }

    fn write_extent(&mut self, bytes: &[u8], offset: u64) -> Result<()> {
        let allocated = allocation_size(bytes.len() as u64, self.block as u64)?;
        let next = self
            .allocated
            .checked_add(allocated)
            .context("update allocation accounting overflow")?;
        ensure!(
            next <= self.budget,
            "update payload exceeds its persistent staging budget"
        );
        allow_allocation(space(&self.file)?.available, allocated, self.reserve)?;
        // Allocate ONLY this nonzero extent, not the logical RAW. This also
        // avoids delayed allocation hiding the updater's admitted disk usage.
        ensure!(
            unsafe {
                libc::fallocate(
                    self.file.as_raw_fd(),
                    libc::FALLOC_FL_KEEP_SIZE,
                    offset.try_into()?,
                    allocated.try_into()?,
                )
            } == 0,
            "allocating update payload extent: {}; no slot was changed",
            std::io::Error::last_os_error()
        );
        self.file
            .write_all_at(bytes, offset)
            .context("writing persistent update extent; no slot was changed")?;
        self.allocated = next;
        Ok(())
    }

    fn finish(&mut self, bytes: u64) -> Result<()> {
        // A final zero block still contributes to the EXACT signed byte stream.
        self.file.set_len(bytes)?;
        self.file
            .sync_all()
            .context("syncing staged update before verification")
    }
}

fn copy_sparse_bounded(
    reader: &mut impl Read,
    sink: &mut impl SparseSink,
    maximum: u64,
) -> Result<String> {
    let block = sink.block();
    ensure!(block > 0 && CHUNK % block == 0, "invalid sparse block size");
    let mut buffer = vec![0u8; CHUNK];
    let mut total = 0u64;
    let mut hash = digest::Context::new(&digest::SHA256);
    loop {
        let mut filled = 0;
        while filled < buffer.len() {
            match reader.read(&mut buffer[filled..]) {
                Ok(0) => break,
                Ok(count) => {
                    filled += count;
                    ensure!(
                        total
                            .checked_add(filled as u64)
                            .is_some_and(|value| value <= maximum),
                        "update download exceeds its {maximum} byte logical limit"
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error).context("reading update download"),
            }
        }
        if filled == 0 {
            break;
        }
        let bytes = &buffer[..filled];
        hash.update(bytes);
        let mut at = 0;
        while at < filled {
            let end = (at + block).min(filled);
            if bytes[at..end].iter().all(|byte| *byte == 0) {
                at = end;
                continue;
            }
            let start = at;
            at = end;
            while at < filled {
                let end = (at + block).min(filled);
                if bytes[at..end].iter().all(|byte| *byte == 0) {
                    break;
                }
                at = end;
            }
            sink.write_extent(&bytes[start..at], total + start as u64)?;
        }
        total += filled as u64;
    }
    sink.finish(total)?;
    Ok(hash
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Explicit process ownership is mandatory: dropping Child does not reap it.
struct DownloadChild(Child);

impl Drop for DownloadChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn drain_tail(mut reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut tail = Vec::with_capacity(STDERR_TAIL);
    let mut buffer = [0u8; STDERR_TAIL];
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(0) => return Ok(tail),
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        let excess = (tail.len() + count).saturating_sub(STDERR_TAIL);
        tail.drain(..excess);
        tail.extend_from_slice(&buffer[..count]);
    }
}

fn http_status(tail: &[u8]) -> Vec<u8> {
    String::from_utf8_lossy(tail)
        .lines()
        .rev()
        .find_map(|line| {
            let code = line.strip_prefix(STATUS_MARKER)?;
            (code.len() == 3 && code.bytes().all(|byte| byte.is_ascii_digit()))
                .then(|| code.as_bytes().to_vec())
        })
        .unwrap_or_default()
}

/// Body and status have separate pipes. Error text is drained, bounded and
/// never emitted (it may contain external content); only framed status survives.
pub fn download(mut command: Command, maximum: u64) -> Result<(File, String, Output)> {
    download_into(&mut command, ImageStage::new()?, maximum)
}

fn download_into(
    command: &mut Command,
    mut stage: ImageStage,
    maximum: u64,
) -> Result<(File, String, Output)> {
    let mut child = DownloadChild(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("starting bounded sparse image transfer")?,
    );
    let mut stdout = child
        .0
        .stdout
        .take()
        .context("download stdout pipe missing")?;
    let stderr = child
        .0
        .stderr
        .take()
        .context("download stderr pipe missing")?;
    let reader = std::thread::spawn(move || drain_tail(stderr));
    let result = copy_sparse_bounded(&mut stdout, &mut stage, maximum);
    drop(stdout);
    let status: Result<ExitStatus> = if result.is_err() {
        let _ = child.0.kill();
        child.0.wait().context("reaping refused update transfer")
    } else {
        child.0.wait().context("waiting for image transfer")
    };
    let tail = reader
        .join()
        .map_err(|_| anyhow::anyhow!("download status reader failed"))?;
    let hash = result?;
    Ok((
        stage.file,
        hash,
        Output {
            status: status?,
            stdout: http_status(&tail?),
            stderr: Vec::new(),
        },
    ))
}

#[cfg(test)]
pub(crate) fn test_download_in(
    mut command: Command,
    directory: &Path,
    maximum: u64,
) -> Result<(File, String, Output)> {
    // Host integration tests exercise the exact stream/file/process code on
    // their owned scratch FS, not the appliance-only mounted-ext4 guard.
    download_into(
        &mut command,
        ImageStage::in_directory(&open_directory(directory)?)?,
        maximum,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use std::os::unix::fs::PermissionsExt;

    struct MemorySink {
        bytes: Vec<u8>,
        extents: Vec<(u64, usize)>,
        fail_write: bool,
        fail_finish: bool,
    }

    impl MemorySink {
        fn new() -> Self {
            Self {
                bytes: Vec::new(),
                extents: Vec::new(),
                fail_write: false,
                fail_finish: false,
            }
        }
    }

    impl SparseSink for MemorySink {
        fn block(&self) -> usize {
            4096
        }
        fn write_extent(&mut self, bytes: &[u8], offset: u64) -> Result<()> {
            ensure!(!self.fail_write, "injected sink write failure");
            let end = offset as usize + bytes.len();
            self.bytes.resize(self.bytes.len().max(end), 0);
            self.bytes[offset as usize..end].copy_from_slice(bytes);
            self.extents.push((offset, bytes.len()));
            Ok(())
        }
        fn finish(&mut self, bytes: u64) -> Result<()> {
            ensure!(!self.fail_finish, "injected sink finish failure");
            self.bytes.resize(bytes as usize, 0);
            Ok(())
        }
    }

    fn hex(bytes: &[u8]) -> String {
        digest::digest(&digest::SHA256, bytes)
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn descriptor_refers_to_inode(
        descriptor: libc::c_int,
        original: &std::fs::Metadata,
    ) -> std::io::Result<bool> {
        match std::fs::metadata(format!("/proc/self/fd/{descriptor}")) {
            Ok(current) => Ok(current.dev() == original.dev() && current.ino() == original.ino()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    #[test]
    fn fd_identity_oracle_distinguishes_live_original_and_unrelated_files() {
        let scratch = crate::update::Scratch::new().unwrap();
        let stage = ImageStage::in_directory(&open_directory(&scratch.join(".")).unwrap()).unwrap();
        let witness = stage.file.try_clone().unwrap();
        let original = witness.metadata().unwrap();
        let unrelated = scratch.create_private("unrelated").unwrap();
        assert!(descriptor_refers_to_inode(stage.file.as_raw_fd(), &original).unwrap());
        assert!(descriptor_refers_to_inode(witness.as_raw_fd(), &original).unwrap());
        // An open FD belonging to another file is a deterministic boundary for
        // legitimate FD-number reuse. Never dup2 over a parallel test's FD.
        assert!(!descriptor_refers_to_inode(unrelated.as_raw_fd(), &original).unwrap());
    }

    struct Fragmented<'a> {
        bytes: &'a [u8],
        count: usize,
    }
    impl Read for Fragmented<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let count = out.len().min(self.count).min(self.bytes.len());
            out[..count].copy_from_slice(&self.bytes[..count]);
            self.bytes = &self.bytes[count..];
            Ok(count)
        }
    }

    #[test]
    fn fragmented_streams_preserve_every_zero_and_nonzero_byte_and_exact_hash() {
        for size in [0, 1, 4095, 4096, 4097, CHUNK - 1, CHUNK, CHUNK + 1] {
            let mut bytes = vec![0u8; size];
            for (index, byte) in bytes.iter_mut().enumerate() {
                if index / 4096 % 3 == 1 {
                    *byte = (index % 255 + 1) as u8;
                }
            }
            for count in [1, 4093, CHUNK + 7] {
                let mut sink = MemorySink::new();
                let hash = copy_sparse_bounded(
                    &mut Fragmented {
                        bytes: &bytes,
                        count,
                    },
                    &mut sink,
                    size as u64,
                )
                .unwrap();
                assert_eq!(sink.bytes, bytes);
                assert_eq!(hash, hex(&bytes));
                assert!(sink.extents.iter().all(|(offset, _)| offset % 4096 == 0));
                assert!(sink.extents.iter().map(|(_, size)| size).sum::<usize>() <= size);
            }
        }
    }

    #[test]
    fn zero_stream_is_bounded_even_though_it_allocates_no_payload() {
        let mut sink = MemorySink::new();
        copy_sparse_bounded(
            &mut Cursor::new(vec![0u8; CHUNK + 3]),
            &mut sink,
            (CHUNK + 3) as u64,
        )
        .unwrap();
        assert_eq!(sink.bytes.len(), CHUNK + 3);
        assert!(sink.extents.is_empty());
        let error =
            copy_sparse_bounded(&mut Cursor::new(vec![0u8; 65]), &mut MemorySink::new(), 64)
                .unwrap_err();
        assert!(error.to_string().contains("logical limit"));
    }

    #[test]
    fn read_write_finish_and_allocation_errors_never_return_a_digest() {
        struct BadReader;
        impl Read for BadReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("injected read error"))
            }
        }
        assert!(copy_sparse_bounded(&mut BadReader, &mut MemorySink::new(), 100).is_err());
        let mut sink = MemorySink::new();
        sink.fail_write = true;
        assert!(copy_sparse_bounded(&mut Cursor::new(b"data"), &mut sink, 100).is_err());
        let mut sink = MemorySink::new();
        sink.fail_finish = true;
        assert!(copy_sparse_bounded(&mut Cursor::new(b"data"), &mut sink, 100).is_err());
        assert!(allocation_size(u64::MAX, 4096).is_err());
        assert!(allocation_size(1, 0).is_err());
        assert!(allocation_size(1, 3).is_err());
        assert_eq!(allocation_size(4097, 4096).unwrap(), 8192);
        assert!(allow_allocation(u64::MAX, u64::MAX, 1).is_err());
        let exact = RESERVE + METADATA_HEADROOM + 4096;
        assert!(allow_allocation(exact, 4096, RESERVE).is_ok());
        assert!(allow_allocation(exact - 1, 4096, RESERVE).is_err());
        assert_eq!(
            reserve(Space {
                available: 0,
                total: 100 * RESERVE,
                block: 4096
            }),
            5 * RESERVE
        );
    }

    #[test]
    fn anonymous_sparse_file_remains_exact_and_private_when_its_parent_is_renamed() {
        let scratch = crate::update::Scratch::new().unwrap();
        let path = scratch.join("parent");
        std::fs::create_dir(&path).unwrap();
        let directory = open_directory(&path).unwrap();
        let mut stage = ImageStage::in_directory(&directory).unwrap();
        let renamed = scratch.join("renamed");
        std::fs::rename(&path, &renamed).unwrap();
        std::os::unix::fs::symlink("/does-not-exist", &path).unwrap();
        let mut bytes = vec![0u8; 9 * 1024 * 1024 + 17];
        bytes[2 * 1024 * 1024..2 * 1024 * 1024 + 4096].fill(0x45);
        let hash =
            copy_sparse_bounded(&mut Cursor::new(&bytes), &mut stage, bytes.len() as u64).unwrap();
        assert_eq!(hash, hex(&bytes));
        let metadata = stage.file.metadata().unwrap();
        assert_eq!(metadata.len(), bytes.len() as u64);
        assert_eq!(metadata.nlink(), 0);
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert!(
            metadata.blocks() * 512 < 1024 * 1024,
            "file must really be sparse"
        );
        let mut actual = vec![0; bytes.len()];
        stage.file.read_exact_at(&mut actual, 0).unwrap();
        assert_eq!(actual, bytes);
        assert_eq!(std::fs::read_dir(&renamed).unwrap().count(), 0);
        let descriptor = stage.file.as_raw_fd();
        // Keep the original anonymous inode alive while checking retirement:
        // another test may legitimately reuse the numeric FD after close, but
        // cannot reallocate this inode while the witness still holds it.
        let witness = stage.file.try_clone().unwrap();
        assert!(descriptor_refers_to_inode(descriptor, &metadata).unwrap());
        drop(stage);
        assert!(!descriptor_refers_to_inode(descriptor, &metadata).unwrap());
        assert!(descriptor_refers_to_inode(witness.as_raw_fd(), &metadata).unwrap());
        actual.fill(0);
        witness.read_exact_at(&mut actual, 0).unwrap();
        assert_eq!(actual, bytes);
    }

    #[test]
    fn stage_budget_fails_without_consuming_the_filesystem() {
        let scratch = crate::update::Scratch::new().unwrap();
        let mut stage =
            ImageStage::in_directory(&open_directory(&scratch.join(".")).unwrap()).unwrap();
        stage.budget = 4096;
        assert!(copy_sparse_bounded(&mut Cursor::new(vec![1u8; 8192]), &mut stage, 8192).is_err());
        assert_eq!(stage.file.metadata().unwrap().blocks(), 0);
        let mut stage =
            ImageStage::in_directory(&open_directory(&scratch.join(".")).unwrap()).unwrap();
        stage.reserve = space(&stage.file).unwrap().available;
        let error =
            copy_sparse_bounded(&mut Cursor::new(vec![1u8; 4096]), &mut stage, 4096).unwrap_err();
        assert!(error.to_string().contains("capacity"));
        assert_eq!(stage.file.metadata().unwrap().blocks(), 0);
        assert!(ImageStage::at(&scratch.join("missing")).is_err());
        let link = scratch.join("link");
        std::os::unix::fs::symlink(scratch.join("."), &link).unwrap();
        assert!(ImageStage::at(&link).is_err());
    }

    #[test]
    fn locks_refuse_concurrency_bad_permissions_symlinks_and_nonregular_inodes() {
        let scratch = crate::update::Scratch::new().unwrap();
        let path = scratch.join("locks");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        let first = UpdateLock::at(&path).unwrap();
        assert!(
            UpdateLock::at(&path)
                .err()
                .unwrap()
                .to_string()
                .contains("in progress")
        );
        drop(first);
        drop(UpdateLock::at(&path).unwrap());
        let duplicate = scratch.join("duplicate-lock");
        std::fs::hard_link(path.join("install.lock"), &duplicate).unwrap();
        assert!(
            UpdateLock::at(&path).is_err(),
            "multiply linked lock refused"
        );
        std::fs::remove_file(duplicate).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(UpdateLock::at(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_file(path.join("install.lock")).unwrap();
        std::os::unix::fs::symlink(scratch.join("outside"), path.join("install.lock")).unwrap();
        assert!(UpdateLock::at(&path).is_err());
        std::fs::remove_file(path.join("install.lock")).unwrap();
        std::fs::create_dir(path.join("install.lock")).unwrap();
        assert!(UpdateLock::at(&path).is_err());
    }

    fn shell(script: &str) -> Command {
        let mut command = Command::new("sh");
        command.args(["-c", script]);
        command
    }

    #[test]
    fn status_is_separate_and_large_stderr_is_drained_with_constant_memory() {
        let scratch = crate::update::Scratch::new().unwrap();
        let command = shell(
            r"i=0; while test $i -lt 10000; do printf xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx >&2; i=$((i+1)); done; printf '\001\000\002'; printf '\nSENTINEL_HTTP_STATUS:200\n' >&2",
        );
        let (file, hash, output) = test_download_in(command, &scratch.join("."), 1024).unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"200");
        assert!(output.stderr.is_empty());
        let mut bytes = [0u8; 3];
        file.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(bytes, [1, 0, 2]);
        assert_eq!(hash, hex(&bytes));
        let tail = drain_tail(Cursor::new(vec![7u8; STDERR_TAIL * 100])).unwrap();
        assert_eq!(tail.len(), STDERR_TAIL);
        assert!(http_status(b"body200\nSENTINEL_HTTP_STATUS:20\n").is_empty());
    }

    #[test]
    fn complete_body_with_http_refusal_is_never_a_successful_transfer() {
        let scratch = crate::update::Scratch::new().unwrap();
        let (_, hash, output) = test_download_in(
            shell("printf data; printf '\nSENTINEL_HTTP_STATUS:403\n' >&2; exit 22"),
            &scratch.join("."),
            1024,
        )
        .unwrap();
        assert!(!output.status.success());
        assert_eq!(output.stdout, b"403");
        assert_eq!(hash, hex(b"data"));
    }

    #[test]
    fn failing_stream_kills_and_reaps_the_actual_child_promptly() {
        let scratch = crate::update::Scratch::new().unwrap();
        let started = std::time::Instant::now();
        let command = shell("printf 123456789; exec sleep 30");
        let error = test_download_in(command, &scratch.join("."), 8)
            .err()
            .unwrap();
        assert!(error.to_string().contains("logical limit"), "{error:#}");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        // waitpid on a child already waited by the guard must report ECHILD;
        // use a separately owned actual child to verify the guard contract.
        let child = shell("exec sleep 30").spawn().unwrap();
        let pid = child.id() as libc::pid_t;
        drop(DownloadChild(child));
        assert_eq!(
            unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn actual_curl_binary_does_not_append_http_status_to_the_raw() {
        let scratch = crate::update::Scratch::new().unwrap();
        let bytes = [0u8, 1, 0, 255, b'2', b'0', b'0', 0];
        let source = scratch.join("source.raw");
        let mut file = scratch.create_private("source.raw").unwrap();
        file.write_all(&bytes).unwrap();
        let mut command = crate::system::curl_command();
        command.args([
            "-fsSL",
            "--proto",
            "=file",
            "-o",
            "-",
            "-w",
            "%{stderr}\nSENTINEL_HTTP_STATUS:%{http_code}\n",
        ]);
        command.arg(format!("file://{}", source.display()));
        let (file, hash, output) = test_download_in(command, &scratch.join("."), 4096).unwrap();
        assert!(output.status.success());
        assert_eq!(file.metadata().unwrap().len(), bytes.len() as u64);
        assert_eq!(hash, hex(&bytes));
        assert_eq!(output.stdout, b"000");
    }
}
