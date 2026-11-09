//! The appliance installer: write the running verified-boot image onto a target
//! disk (or a RAID array) so the box boots from internal storage.
//!
//! Sentinel ships as an immutable dm-verity image (see `nix/image.nix`). The
//! same image doubles as the installer: you boot it from USB, pick a target
//! device, and it lays down the appliance — ESP + dm-verity store + a fresh
//! persistent data partition — onto that device. The store is integrity-sealed,
//! so what lands on disk is the exact verified image.
//!
//! This module owns the *pure* parts — discovering candidate disks and
//! computing the install plan — so they are unit-tested without touching real
//! hardware. Executing the plan (the destructive writes) is gated behind an
//! explicit confirmation.

use std::process::Command;

use anyhow::{Context, Result, bail, ensure};

use crate::config::UpdateChannel;
use crate::system;
use crate::update;
use crate::verified_image::VerifiedImage;

/// A candidate target block device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disk {
    /// Kernel name, e.g. `sda`, `nvme0n1`.
    pub name: String,
    /// Capacity in bytes.
    pub size: u64,
    /// Model string (may be empty).
    pub model: String,
    /// Whether the kernel marks it removable (a USB stick — usually the
    /// installer medium, not a target).
    pub removable: bool,
}

impl Disk {
    /// The `/dev` path of the whole disk.
    pub fn dev_path(&self) -> String {
        format!("/dev/{}", self.name)
    }
}

/// A RAID level for the data (state) array. The dm-verity store is read-only and
/// identical on every member, so only the writable data partition is mirrored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Raid {
    /// No array — a single target disk.
    None,
    /// Stripe across 2+ disks: capacity sum, NO redundancy (RAID0).
    Stripe,
    /// Mirror across 2+ disks (survives losing all but one) (RAID1).
    Mirror,
    /// Striped mirror across 4+ disks: capacity + redundancy (RAID10).
    Mirror10,
}

impl Raid {
    /// The minimum number of member disks this level needs.
    pub fn min_disks(self) -> usize {
        match self {
            Raid::None => 1,
            Raid::Stripe | Raid::Mirror => 2,
            Raid::Mirror10 => 4,
        }
    }

    /// The `mdadm --level` value, if this level uses an array.
    pub fn mdadm_level(self) -> Option<&'static str> {
        match self {
            Raid::None => None,
            Raid::Stripe => Some("0"),
            Raid::Mirror => Some("1"),
            Raid::Mirror10 => Some("10"),
        }
    }
}

/// Discover whole disks that could be install targets. Reads `lsblk` (JSON-free,
/// stable columns): name, size in bytes, type, removable flag, model. Only
/// `type == "disk"` entries are returned.
pub fn discover_disks() -> Result<Vec<Disk>> {
    let out = Command::new(system::bin("lsblk"))
        .args(["-dnb", "-o", "NAME,SIZE,TYPE,RM,MODEL"])
        .output()
        .context("running lsblk")?;
    if !out.status.success() {
        bail!("lsblk failed (exit {:?})", out.status.code());
    }
    Ok(parse_lsblk(&String::from_utf8_lossy(&out.stdout)))
}

/// Parse `lsblk -dnb -o NAME,SIZE,TYPE,RM,MODEL` output into disks. Kept pure for
/// testing. Lines that aren't `type == disk` (partitions, loop, rom) are skipped;
/// the model is whatever remains after the first four whitespace-split fields.
fn parse_lsblk(text: &str) -> Vec<Disk> {
    let mut disks = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // NAME SIZE TYPE RM [MODEL...] — columns are space-padded, so collapse
        // runs of whitespace; the model is whatever remains after the 4 fixed
        // fields (and may itself contain spaces).
        let parts: Vec<&str> = line.split_whitespace().collect();
        let [name, size, kind, rm, model @ ..] = parts.as_slice() else {
            continue;
        };
        // Only real disks: lsblk types out loop/rom, but zram (compressed RAM
        // swap) and md/dm virtual devices still report as "disk" — never install
        // targets.
        if *kind != "disk"
            || name.starts_with("zram")
            || name.starts_with("md")
            || name.starts_with("dm-")
        {
            continue;
        }
        let Ok(size) = size.parse::<u64>() else {
            continue;
        };
        disks.push(Disk {
            name: (*name).to_string(),
            size,
            model: model.join(" "),
            removable: *rm == "1",
        });
    }
    disks
}

/// Render a byte count as a short human-readable size (binary units).
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// A floor below which no build of the appliance could ever fit — enough to
/// reject an obviously wrong disk without reading anything.
///
/// It is deliberately NOT the real requirement: that is the source medium's
/// protected layout plus fresh data, prepared by [`InstallLayout`] before a
/// single byte is erased. The source's disposable grown data is not cloned. That
/// per-source check is the authority and it runs pre-erase, so a disk that
/// clears this floor but is still too small is rejected before any wipe. The
/// floor stays a coarse sanity gate, but no lower than it needs to be: the real
/// layout is ~5.7 GiB today, so 5 GiB rejects the obviously-too-small disks
/// without ever exceeding (and so wrongly rejecting) a disk the real check would
/// have accepted.
pub const MIN_TARGET_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// The number of bytes a target must have for the source layout to be written
/// onto it: the end of the source's last partition, plus the 33 sectors the
/// backup GPT header occupies at the very end of the disk.
///
/// Parsed from `sgdisk -p` output — pure, so the arithmetic is testable without
/// a disk. Returns `None` if the listing carries no partition rows at all.
fn parse_layout_bytes(sgdisk_print: &str) -> Option<u64> {
    let sector = printed_sector_size(sgdisk_print).unwrap_or(512);
    // Partition rows begin with the partition number; every other line either
    // has a non-numeric first field or too few fields to be one.
    let last_end = sgdisk_print
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let [num, _start, end, ..] = f.as_slice() else {
                return None;
            };
            num.parse::<u32>().ok()?;
            end.parse::<u64>().ok()
        })
        .max()?;
    // The backup GPT sits in the last 33 sectors; `sgdisk --move-second-header`
    // has to have somewhere to put it.
    last_end.checked_add(34)?.checked_mul(sector)
}

fn printed_sector_size(text: &str) -> Option<u64> {
    let bytes = text
        .lines()
        .find_map(|line| {
            line.split_once("Sector size (logical/physical):")
                .or_else(|| line.split_once("Sector size (logical):"))
        })?
        .1
        .trim()
        .split(['/', ' '])
        .next()?
        .parse()
        .ok()?;
    matches!(bytes, 512 | 1024 | 2048 | 4096).then_some(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InstallGeometry {
    sector: u64,
    parts: Vec<(u32, u64, u64)>,
}

impl InstallGeometry {
    fn parse(text: &str) -> Result<Self> {
        let sector =
            printed_sector_size(text).context("missing/invalid GPT logical sector size")?;
        let parts: Vec<_> = text
            .lines()
            .filter_map(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                let [number, start, end, ..] = fields.as_slice() else {
                    return None;
                };
                Some((
                    number.parse::<u32>().ok()?,
                    start.parse::<u64>().ok()?,
                    end.parse::<u64>().ok()?,
                ))
            })
            .collect();
        ensure!(
            parts.len() == 6,
            "install requires the six-partition factory layout"
        );
        let mut previous_end = 0;
        for (index, &(number, start, end)) in parts.iter().enumerate() {
            ensure!(
                number as usize == index + 1 && start > previous_end && end >= start,
                "factory partitions are missing, reordered or overlapping"
            );
            ensure!(
                start.checked_mul(sector).is_some_and(|n| n >= 1024 * 1024),
                "factory partition overlaps the GPT prefix"
            );
            end.checked_add(34)
                .and_then(|n| n.checked_mul(sector))
                .context("factory geometry overflows byte capacity")?;
            previous_end = end;
        }
        Ok(Self { sector, parts })
    }

    fn fresh_data(&self) -> Self {
        let mut result = self.clone();
        let (_, start, end) = result.parts[5];
        // Match the factory's normal128MiB floor, never enlarge a smaller
        // explicitly built floor. Installed/grown state is recreated, not copied.
        let sectors = (end - start + 1).min(128 * 1024 * 1024 / self.sector);
        result.parts[5].2 = start + sectors - 1;
        result
    }

    /// GPT uses logical sectors; Linux sysfs always reports 512-byte sectors.
    /// A successful disk write is not enough if the kernel still exposes old
    /// partition extents. Never format or clone through stale device nodes.
    fn require_kernel_view(&self, target: &str) -> Result<()> {
        for &(number, start, end) in &self.parts {
            let device = part_path(target, number);
            let canonical = std::fs::canonicalize(&device)
                .with_context(|| format!("installed partition is unavailable: {device}"))?;
            let name = canonical
                .file_name()
                .context("partition has no kernel name")?;
            let sysfs = std::path::Path::new("/sys/class/block").join(name);
            let read = |field: &str| -> Result<u64> {
                std::fs::read_to_string(sysfs.join(field))?
                    .trim()
                    .parse()
                    .with_context(|| format!("invalid kernel {field} for {device}"))
            };
            let expected_start = start
                .checked_mul(self.sector / 512)
                .context("partition start overflows kernel sectors")?;
            let expected_size = (end - start + 1)
                .checked_mul(self.sector / 512)
                .context("partition size overflows kernel sectors")?;
            ensure!(
                read("start")? == expected_start && read("size")? == expected_size,
                "kernel partition view does not match the installed GPT for {device}; refusing to clone or format stale extents"
            );
        }
        Ok(())
    }
}

fn inspect_layout(args: &[&str]) -> Result<String> {
    let out = Command::new(system::bin("sgdisk"))
        .args(args)
        .env_clear()
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C")
        .output()
        .context("preparing the private install GPT layout")?;
    ensure!(
        out.status.success(),
        "install GPT preflight refused: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    ensure!(
        out.stdout.len() <= 64 * 1024,
        "oversized install GPT inspection"
    );
    String::from_utf8(out.stdout).context("non-UTF-8 install GPT inspection")
}

/// A small private GPT backup, NOT another appliance image. The protected
/// entries retain their identities; source data is replaced IN MEMORY ONLY.
/// All tools inspecting the source/targets use --pretend before the erase gate.
struct InstallLayout {
    _scratch: update::Scratch,
    backup: std::path::PathBuf,
    geometry: InstallGeometry,
    bytes: u64,
}

impl InstallLayout {
    fn new(source: &str) -> Result<Self> {
        let original = inspect_layout(&["--pretend", "--print", source])?;
        let geometry = InstallGeometry::parse(&original)?.fresh_data();
        let scratch = update::Scratch::new()?;
        drop(scratch.create_private("install-layout.gpt")?);
        let backup = scratch.join("install-layout.gpt");
        let filename = backup
            .to_str()
            .context("non-UTF-8 private GPT backup path")?;
        let (_, start, end) = geometry.parts[5];
        let text = inspect_layout(&[
            "--pretend",
            "--set-alignment=1",
            "--delete=6",
            &format!("--new=6:{start}:{end}"),
            "--typecode=6:8300",
            "--change-name=6:data",
            &format!("--backup={filename}"),
            "--print",
            source,
        ])?;
        ensure!(
            InstallGeometry::parse(&text)? == geometry,
            "private install template changed protected partition geometry"
        );
        let bytes = parse_layout_bytes(&text).context("private GPT has no measurable layout")?;
        let size = std::fs::metadata(&backup)?.len();
        ensure!(
            size > 0 && size <= 1024 * 1024,
            "invalid private install GPT backup size"
        );
        Ok(Self {
            _scratch: scratch,
            backup,
            geometry,
            bytes,
        })
    }

    fn validate_target(&self, target: &str) -> Result<()> {
        let filename = self
            .backup
            .to_str()
            .context("non-UTF-8 private GPT backup path")?;
        let text = inspect_layout(&[
            "--pretend",
            &format!("--load-backup={filename}"),
            "--move-second-header",
            "--print",
            target,
        ])?;
        ensure!(
            InstallGeometry::parse(&text)? == self.geometry,
            "target logical sectors or protected GPT layout do not match the source; nothing erased"
        );
        Ok(())
    }
}

/// Validate a target selection against a RAID level: enough disks, each big
/// enough, none removable. Returns the chosen disks in order, or an error
/// describing what's wrong. Pure — the caller has already discovered the disks.
pub fn plan_targets<'a>(
    available: &'a [Disk],
    targets: &[String],
    raid: Raid,
) -> Result<Vec<&'a Disk>> {
    if targets.len() < raid.min_disks() {
        bail!(
            "{:?} needs at least {} disk(s), got {}",
            raid,
            raid.min_disks(),
            targets.len()
        );
    }
    if raid == Raid::None && targets.len() != 1 {
        bail!("a non-RAID install takes exactly one target disk");
    }
    let mut chosen = Vec::new();
    for t in targets {
        let want = t.trim_start_matches("/dev/");
        let disk = available
            .iter()
            .find(|d| d.name == want)
            .ok_or_else(|| anyhow::anyhow!("no such disk {t:?} (see `sentinel install`)"))?;
        if disk.size < MIN_TARGET_BYTES {
            bail!(
                "disk {} is {} — below the {} minimum",
                disk.dev_path(),
                human_size(disk.size),
                human_size(MIN_TARGET_BYTES)
            );
        }
        if disk.removable {
            bail!(
                "disk {} is removable (the installer medium?) — refusing to install \
                 onto it. There is no override; install to a non-removable disk.",
                disk.dev_path()
            );
        }
        chosen.push(disk);
    }
    Ok(chosen)
}

/// How the writable data partition is protected at rest.
///
/// The A/B root is dm-verity and read-only, so there is nothing on it worth
/// encrypting — its integrity, not its secrecy, is what matters. The secrets live
/// on the ONE writable partition: the TLS key and cert, config-sync pins and
/// tokens, per-account password hashes, WireGuard/IPsec keys. That is what LUKS
/// protects here, and nothing else needs to.
#[derive(Debug, Clone)]
pub enum Crypto {
    /// Plaintext ext4 — the historical (and still default) behaviour.
    None,
    /// LUKS2 over the data partition, unlocked at boot with this passphrase.
    Luks { passphrase: String },
}

/// The device-mapper name the unlocked data volume is opened as, both at install
/// time and at boot (`sentinel unlock`). The ext4 filesystem — LABEL=data — lives
/// *inside* it, so the appliance's existing `/dev/disk/by-label/data` mount finds
/// it unchanged once the volume is open.
pub const DATA_MAPPER: &str = "data";

/// The `/dev/mapper` path of the unlocked data volume.
pub fn data_mapper_path() -> String {
    format!("/dev/mapper/{DATA_MAPPER}")
}

/// The A/B GPT layout: 1=ESP, 2=store-verity-A, 3=store-A, 4=store-verity-B,
/// 5=store-B, 6=data. Data is last so it can grow to fill the disk.
pub const DATA_PART: u32 = 6;
/// Partitions cloned block-for-block on install: the ESP and slot A's verity
/// hash + store. Slot B (4,5) is reserved empty space — its GPT entries are
/// retained in the private install template, and a later update fills it.
// ESP selects a UKI from either slot after a real A/B update. Copy BOTH pairs,
// including an empty factory B, so no copied boot entry points at missing bytes.
// The writable data partition is always freshly created and never cloned.
pub const SEALED_PARTS: std::ops::RangeInclusive<u32> = 1..=5;

/// The partition device path for partition `n` on `disk` — `nvme0n1` →
/// `nvme0n1p2`, `sda`/`vda` → `sda2`. (A trailing digit needs the `p`.)
pub fn part_path(disk: &str, n: u32) -> String {
    let bare = disk.trim_start_matches("/dev/");
    let sep = if bare.chars().last().is_some_and(|c| c.is_ascii_digit()) {
        "p"
    } else {
        ""
    };
    format!("/dev/{bare}{sep}{n}")
}

/// Run an external tool (resolved to its absolute path), inheriting stdio,
/// failing on a non-zero exit.
/// The GPT unique GUID of one partition, as `sgdisk` reports it.
///
/// Needed because a verity slot is not identified by where it sits on the disk
/// but by this GUID: systemd derives the pair it looks for from the image's
/// root hash, so the partitions carrying an image must carry the GUIDs that
/// hash produces. Cloning the bytes without them yields a slot whose contents
/// are right and which nothing can find.
fn partition_guid(disk: &str, part: u32) -> Result<String> {
    let out = Command::new(system::bin("sgdisk"))
        .args([&format!("-i{part}"), disk])
        .output()
        .with_context(|| format!("reading the GUID of {disk} partition {part}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find_map(|l| l.split_once("Partition unique GUID: "))
        .map(|(_, guid)| guid.trim().to_string())
        .ok_or_else(|| anyhow::anyhow!("no unique GUID for {disk} partition {part}"))
}

fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(system::bin(cmd))
        .args(args)
        .status()
        .with_context(|| format!("running {cmd}"))?;
    if !status.success() {
        bail!(
            "`{cmd} {}` failed (exit {:?})",
            args.join(" "),
            status.code()
        );
    }
    Ok(())
}

/// Run an external tool feeding `input` on stdin — used to hand a LUKS passphrase
/// to `cryptsetup` without ever putting it on the command line (where it would
/// show in `ps` and the install log). stdout/stderr are inherited so the tool's
/// own errors still reach the operator.
fn run_stdin(cmd: &str, args: &[&str], input: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut child = Command::new(system::bin(cmd))
        .args(args)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("running {cmd}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("no stdin for {cmd}"))?
        .write_all(input)
        .with_context(|| format!("feeding the passphrase to {cmd}"))?;
    let status = child.wait().with_context(|| format!("waiting for {cmd}"))?;
    if !status.success() {
        bail!(
            "`{cmd} {}` failed (exit {:?})",
            args.join(" "),
            status.code()
        );
    }
    Ok(())
}

/// Format `dev` as a fresh LUKS2 container and open it as [`DATA_MAPPER`], with
/// the passphrase fed on stdin (never on argv). LUKS2 is the modern default:
/// Argon2id key derivation, a resilient on-disk header. The mapped device that
/// comes back is where the data filesystem is then made.
///
/// TPM2-backed unattended unlock is a deliberate follow-up, not wired here: it
/// needs `systemd-cryptenroll` against real hardware to test, and a half-wired
/// TPM path is worse than an honest passphrase one. The on-disk format is
/// standard LUKS2, so a later `sentinel` can enrol a TPM2 token onto the very
/// same volume without reformatting.
fn luks_format_open(dev: &str, passphrase: &str) -> Result<()> {
    if passphrase.is_empty() {
        bail!("refusing to create an encrypted volume with an empty passphrase");
    }
    // `--key-file -` reads the passphrase from stdin; `--batch-mode` skips the
    // interactive "type uppercase YES" confirmation (we already confirmed the
    // erase). luksFormat then luksOpen, both fed the same passphrase.
    run_stdin(
        "cryptsetup",
        &[
            "luksFormat",
            "--type",
            "luks2",
            "--batch-mode",
            "--key-file",
            "-",
            dev,
        ],
        passphrase.as_bytes(),
    )
    .with_context(|| format!("creating the LUKS2 volume on {dev}"))?;
    luks_open(dev, passphrase)
}

/// Open an existing LUKS2 volume on `dev` as [`DATA_MAPPER`], passphrase on stdin.
fn luks_open(dev: &str, passphrase: &str) -> Result<()> {
    run_stdin(
        "cryptsetup",
        &["open", "--key-file", "-", dev, DATA_MAPPER],
        passphrase.as_bytes(),
    )
    .with_context(|| format!("opening the LUKS2 volume on {dev}"))
}

/// Close the [`DATA_MAPPER`] device when dropped, so an encrypted install leaves
/// nothing unlocked behind it however it returns.
struct CryptGuard;
impl Drop for CryptGuard {
    fn drop(&mut self) {
        let _ = Command::new(system::bin("cryptsetup"))
            .args(["close", DATA_MAPPER])
            .status();
    }
}

/// The whole disk holding the running, sealed verity store — i.e. the install
/// medium we clone from. Follows the **active** dm-verity device
/// (`/dev/mapper/usr`) down to its backing disk; a partlabel would be ambiguous
/// once a target has been installed (it copies the same labels).
pub(crate) fn find_source_disk() -> Result<String> {
    // `-s` walks the dependency tree downward; `-r` (raw) avoids tree-drawing
    // characters in the NAME column. Pick the entry whose TYPE is `disk`.
    let out = Command::new(system::bin("lsblk"))
        .args(["-nsro", "NAME,TYPE", "/dev/mapper/usr"])
        .output()
        .context("locating the source disk")?;
    let text = String::from_utf8_lossy(&out.stdout);
    let name = text
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let (name, kind) = (f.next()?, f.next()?);
            (kind == "disk").then(|| name.to_string())
        })
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve the source disk from /dev/mapper/usr"))?;
    Ok(format!("/dev/{name}"))
}

/// Detaches a loop device when dropped, so a `--source` image install cleans up
/// even on error.
struct LoopGuard(String);
impl Drop for LoopGuard {
    fn drop(&mut self) {
        let _ = Command::new(system::bin("losetup"))
            .args(["-d", &self.0])
            .status();
    }
}

/// Attach a raw image file as a partitioned loop device, returning its path.
fn losetup_attach(image: &std::path::Path) -> Result<String> {
    let img = image
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF-8 image path"))?;
    let out = Command::new(system::bin("losetup"))
        .args(["-P", "-f", "--show", img])
        .output()
        .context("attaching the source image via losetup")?;
    if !out.status.success() {
        bail!("losetup failed (exit {:?})", out.status.code());
    }
    let dev = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if dev.is_empty() {
        bail!("losetup returned no device for {img}");
    }
    Ok(dev)
}

/// Execute the validated install onto `targets`: partition each disk like the
/// sealed source image, clone the ESP + dm-verity partitions onto it, then make
/// the data filesystem (a plain ext4, or an mdadm array for RAID). DESTRUCTIVE.
///
/// `source_image` is a raw appliance image to clone from (the ISO/live-boot
/// case); when `None`, the source is the booted verity medium itself.
pub fn execute(
    targets: &[&Disk],
    raid: Raid,
    source_image: Option<&std::path::Path>,
    crypto: &Crypto,
) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("install must run as root (try `sudo sentinel install …`)");
    }
    // The source is either a loop device over the bundled image, or the booted
    // medium's own disk. The guard detaches the loop device on return.
    let (source, _loop) = match source_image {
        Some(img) => {
            let dev = losetup_attach(img)?;
            (dev.clone(), Some(LoopGuard(dev)))
        }
        None => (find_source_disk()?, None),
    };
    eprintln!("source (install medium): {source}");

    // Pre-flight: reject any target that collides with the source medium BEFORE
    // erasing anything. This check used to live inside the prepare loop, so with
    // two targets disk 1 could be wiped before disk 2 was found to be the source
    // — leaving a blank disk and no install (H8).
    for t in targets {
        let dev = t.dev_path();
        if dev == source {
            bail!("refusing to install onto the source medium {dev}");
        }
    }

    // Pre-flight ALL targets against the prepared factory layout. The source's
    // grown writable state is never cloned, so must not raise the hardware floor.
    // No target/source GPT write is permitted during these --pretend inspections.
    let layout = InstallLayout::new(&source)?;
    let need = layout.bytes;
    for t in targets {
        if t.size < need {
            bail!(
                "disk {} is {} — the appliance layout on {source} needs {}",
                t.dev_path(),
                human_size(t.size),
                human_size(need)
            );
        }
        layout.validate_target(&t.dev_path())?;
    }

    // From here on disks are being erased. Track which, so a mid-way failure
    // reports exactly which disks are left blank (none are recoverable once
    // wipefs has run — but the operator must know which to re-install).
    let mut erased: Vec<String> = Vec::new();
    for t in targets {
        let dev = t.dev_path();
        eprintln!("preparing {dev} (ERASING) …");
        erased.push(dev.clone());
        if let Err(e) = prepare_disk(&source, &dev, raid, &layout) {
            return Err(partial_install_error(e, &erased));
        }
    }

    let data_parts: Vec<String> = targets
        .iter()
        .map(|t| part_path(&t.dev_path(), DATA_PART))
        .collect();
    // Build the data filesystem (or RAID array, optionally LUKS-wrapped). A
    // failure here leaves every erased disk partitioned but without a bootable
    // system — report which.
    let fs_result: Result<()> = (|| {
        // The block device the data filesystem sits on: the single data
        // partition, or the assembled array across all of them.
        let base = build_data_base(&data_parts, raid)?;
        // Optionally wrap that device in LUKS2. The ext4 (LABEL=data) is then made
        // *inside* the opened volume, so at rest the partition is a LUKS container
        // and nothing readable. The volume is opened only for the mkfs and closed
        // again here, so the install ends in a clean, LOCKED state — the box (or
        // `seed_config`) unlocks it fresh with the passphrase.
        match crypto {
            Crypto::None => {
                run("mkfs.ext4", &["-q", "-F", "-L", "data", &base])?;
            }
            Crypto::Luks { passphrase } => {
                eprintln!("encrypting the data partition (LUKS2) …");
                luks_format_open(&base, passphrase)?;
                let guard = CryptGuard;
                run("udevadm", &["settle"]).ok();
                run(
                    "mkfs.ext4",
                    &["-q", "-F", "-L", "data", &data_mapper_path()],
                )?;
                drop(guard); // close the volume now, not at end of scope
            }
        }
        Ok(())
    })();
    if let Err(e) = fs_result {
        return Err(partial_install_error(e, &erased));
    }
    eprintln!("install complete — remove the medium and reboot.");
    Ok(())
}

/// The block device the data filesystem sits on: the single data partition, or
/// the freshly-assembled RAID array across all of them. For the RAID case this
/// *creates* the array (as `/dev/md/sentinel-data`), so it is called exactly once
/// per install.
fn build_data_base(data_parts: &[String], raid: Raid) -> Result<String> {
    match raid.mdadm_level() {
        None => Ok(data_parts[0].clone()),
        Some(level) => {
            run("udevadm", &["settle"]).ok();
            let n = data_parts.len().to_string();
            let mut args = vec![
                "--create",
                "/dev/md/sentinel-data",
                "--level",
                level,
                "--raid-devices",
                &n,
                "--metadata=1.2",
                "--run",
                "--force",
            ];
            args.extend(data_parts.iter().map(String::as_str));
            eprintln!("creating RAID{level} across {} disk(s) …", data_parts.len());
            run("mdadm", &args)?;
            Ok("/dev/md/sentinel-data".to_string())
        }
    }
}

/// The already-assembled data base device to seed into, WITHOUT recreating a RAID
/// array (which `execute` has already built in this same installer session).
fn existing_data_base(targets: &[&Disk], raid: Raid) -> String {
    match raid.mdadm_level() {
        Some(_) => "/dev/md/sentinel-data".to_string(),
        None => part_path(&targets[0].dev_path(), DATA_PART),
    }
}

/// Wrap a destructive-phase failure with the list of disks already erased, so
/// the operator knows exactly which disks are left blank. Disk contents are gone
/// (wipefs ran) — this is a clear report, not a recovery: re-running the install
/// finishes the job, since every listed disk is an intended target anyway.
fn partial_install_error(cause: anyhow::Error, erased: &[String]) -> anyhow::Error {
    anyhow::anyhow!(
        "install failed after starting to erase {}: {cause}\n\
         these disk(s) are now BLANK (partitioned but WITHOUT a complete, bootable \
         system); re-run the install to finish, or restore them from backup. No \
         disk outside this list was touched.",
        erased.join(", ")
    )
}

/// Take down whatever is holding `target` open, so it can be erased.
///
/// Scoped to this disk on purpose. A volume group that also has a physical
/// volume on another disk is left alone and named instead: deactivating it
/// would take down storage the operator did not offer to this installer, and
/// "it erased the disk I did not pick" is not a failure anybody recovers from.
///
/// Every step is best-effort and in the order the holders stack — swap and
/// mounts sit on top of dm and md, which sit on the partitions. What is left
/// after this is reported by [`holders_of`], which is what makes the refusal
/// name a cause instead of an errno.
fn release_holders(target: &str) -> Result<()> {
    let kernel = target.trim_start_matches("/dev/");

    // Swap first: a swap partition is an open holder and `swapoff` is the only
    // thing that closes it.
    if let Ok(swaps) = std::fs::read_to_string("/proc/swaps") {
        for line in swaps.lines().skip(1) {
            let Some(dev) = line.split_whitespace().next() else {
                continue;
            };
            if disk_path_matches(dev, target) {
                eprintln!("  swapoff {dev}");
                let _ = run("swapoff", &[dev]);
            }
        }
    }

    // Then mounts, deepest first: /var before /, or the shallower umount
    // fails on a busy subtree.
    let mut mounts: Vec<(String, String)> = Vec::new();
    if let Ok(mi) = std::fs::read_to_string("/proc/self/mountinfo") {
        for line in mi.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            let Some(sep) = f.iter().position(|x| *x == "-") else {
                continue;
            };
            let (Some(point), Some(dev)) = (f.get(4), f.get(sep + 2)) else {
                continue;
            };
            if disk_path_matches(dev, target) {
                mounts.push(((*point).to_string(), (*dev).to_string()));
            }
        }
    }
    mounts.sort_by_key(|(point, _)| std::cmp::Reverse(point.matches('/').count()));
    for (point, dev) in mounts {
        eprintln!("  umount {point} ({dev})");
        let _ = run("umount", &[&point]);
    }

    // Device-mapper and md, from `/sys/class/block/<part>/holders`. That
    // directory is the kernel's own answer to "who has this open", so it needs
    // no guessing about naming and covers LUKS, LVM and md alike.
    for part in std::iter::once(kernel.to_string()).chain(partitions_of(kernel)) {
        for holder in holders_named(&part) {
            if !holder_is_confined(&holder, kernel, &|name| {
                let entries = std::fs::read_dir(format!("/sys/class/block/{name}/slaves")).ok()?;
                entries
                    .map(|entry| entry.ok()?.file_name().into_string().ok())
                    .collect()
            }) {
                eprintln!(
                    "  leaving {holder} alone: its dependencies are shared with another disk or could not be verified"
                );
                continue;
            }
            if holder.starts_with("dm-") {
                let name = std::fs::read_to_string(format!("/sys/class/block/{holder}/dm/name"))
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                eprintln!("  dmsetup remove {name}");
                let _ = run("dmsetup", &["remove", "--retry", &name]);
            } else if holder.starts_with("md") {
                eprintln!("  mdadm --stop /dev/{holder}");
                let _ = run("mdadm", &["--stop", &format!("/dev/{holder}")]);
            }
        }
    }

    // The kernel needs a moment to notice; `wipefs` right after a `dmsetup
    // remove` can still see the old holder.
    let _ = run("udevadm", &["settle"]);

    let left = holders_of(kernel);
    if !left.is_empty() {
        bail!(
            "{target} is still held by {} — nothing has been written. \
             Take it down and run the installer again, or pick another disk. \
             `lsblk {target}` shows what is on it",
            left.join(", ")
        );
    }
    Ok(())
}

/// The partition kernel names of a whole disk, `nvme0n1p1`, `sda1`.
fn partitions_of(kernel: &str) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(format!("/sys/class/block/{kernel}")) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| disk_node_matches(n, kernel) && n != kernel)
        .collect()
}

/// What the kernel says currently holds a block device open.
fn holders_named(kernel: &str) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(format!("/sys/class/block/{kernel}/holders")) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect()
}

/// Everything still holding the disk or any of its partitions, for a refusal
/// that names a cause. Device-mapper devices are reported by their real name
/// (`vg0-root`) rather than `dm-3`, because that is what an operator can act on.
fn holders_of(kernel: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut parts = vec![kernel.to_string()];
    parts.extend(partitions_of(kernel));
    for part in parts {
        for holder in holders_named(&part) {
            let named = std::fs::read_to_string(format!("/sys/class/block/{holder}/dm/name"))
                .ok()
                .map(|n| n.trim().to_string())
                .filter(|n| !n.is_empty())
                .unwrap_or(holder);
            if !out.contains(&named) {
                out.push(named);
            }
        }
    }
    out
}

/// Match a disk and its partitions without confusing sda with sdaa, or
/// nvme0n1 with nvme0n10. The kernel separates digit-ending disk names with p.
fn disk_node_matches(node: &str, disk: &str) -> bool {
    if node == disk {
        return true;
    }
    let Some(suffix) = node.strip_prefix(disk) else {
        return false;
    };
    let suffix = if disk.ends_with(|c: char| c.is_ascii_digit()) {
        let Some(part) = suffix.strip_prefix('p') else {
            return false;
        };
        part
    } else {
        suffix
    };
    !suffix.is_empty() && suffix.bytes().all(|c| c.is_ascii_digit())
}

fn disk_path_matches(device: &str, target: &str) -> bool {
    let device = std::fs::canonicalize(device).unwrap_or_else(|_| device.into());
    let target = std::fs::canonicalize(target).unwrap_or_else(|_| target.into());
    device.parent() == target.parent()
        && device
            .file_name()
            .zip(target.file_name())
            .is_some_and(|(node, disk)| {
                disk_node_matches(&node.to_string_lossy(), &disk.to_string_lossy())
            })
}

/// Follow the kernel dependency graph, including md and stacked dm devices.
/// Unknown dependencies fail closed; a shared volume must never be stopped.
fn holder_is_confined(
    holder: &str,
    disk: &str,
    slaves: &impl Fn(&str) -> Option<Vec<String>>,
) -> bool {
    fn visit(
        node: &str,
        disk: &str,
        slaves: &impl Fn(&str) -> Option<Vec<String>>,
        seen: &mut std::collections::BTreeSet<String>,
    ) -> bool {
        if seen.len() >= 64 || !seen.insert(node.into()) {
            return false;
        }
        let Some(children) = slaves(node) else {
            return false;
        };
        let safe = if children.is_empty() {
            disk_node_matches(node, disk)
        } else {
            children
                .iter()
                .all(|child| visit(child, disk, slaves, seen))
        };
        seen.remove(node);
        safe
    }
    visit(holder, disk, slaves, &mut std::collections::BTreeSet::new())
}

/// One ordered GPT transaction, retaining the signed store pair's UUIDs.
fn install_gpt_args(backup: &str, target: &str, raid: Raid, data_start: u64) -> Vec<String> {
    let typecode = if raid.mdadm_level().is_some() {
        "FD00"
    } else {
        "8300"
    };
    vec![
        format!("--load-backup={backup}"),
        "--move-second-header".into(),
        "--disk-guid=R".into(),
        "--set-alignment=1".into(),
        format!("--delete={DATA_PART}"),
        format!("--new={DATA_PART}:{data_start}:0"),
        format!("--typecode={DATA_PART}:{typecode}"),
        format!("--change-name={DATA_PART}:data"),
        target.into(),
    ]
}

/// Clone the sealed layout and create a fresh full-sized data partition.
fn prepare_disk(source: &str, target: &str, raid: Raid, layout: &InstallLayout) -> Result<()> {
    // Everything the kernel is still holding this disk open with, taken down
    // first. Without it `wipefs` fails with `probing initialization failed:
    // Device or resource busy` and the install stops before it has written
    // anything — on any machine that already carries an installation, which is
    // every machine being *re*-installed.
    //
    // A live medium assembles what it finds: an existing LUKS volume becomes a
    // `/dev/mapper/…`, an LVM volume group is activated, an md array is
    // started, a swap partition may be switched on. Each of those is an open
    // holder of the whole-disk device, and none of them is visible in the
    // candidate listing — so the operator sees a disk offered, picks it, says
    // YES, and is told the device is busy with no indication of what by.
    release_holders(target)?;
    run("wipefs", &["-a", target])?;
    // Load the already checked private template, not the source's full grown
    // data entry. It fits smaller targets too; no live source GPT is modified.
    let backup = layout
        .backup
        .to_str()
        .context("non-UTF-8 private GPT backup path")?;
    // Give the disk a fresh **disk** GUID so it doesn't collide with the source
    // medium — but do NOT randomize the *partition* GUIDs. The dm-verity store
    // relies on the systemd Discoverable Partitions convention: the verity and
    // store partition UUIDs are derived from the roothash the UKI carries as
    // `usrhash=`, so systemd auto-binds `/dev/mapper/usr` by matching them at
    // boot — it never needs to be told which partitions to use, and that is why
    // the GUIDs are load-bearing. `sgdisk --randomize-guids` would overwrite those
    // roothash-derived UUIDs, so the installed system could never activate the
    // verity device — it would time out waiting for `/dev/mapper/usr` and drop to
    // emergency mode (while a directly-booted image, with the UUIDs intact, works
    // fine). `--disk-guid=R` randomizes only the disk GUID and leaves every
    // partition UUID as replicated. The data partition below is recreated and so
    // gets its own fresh UUID regardless.
    // Commit ONE complete GPT. Publishing an intermediate clone and then
    // deleting/recreating its partitions lets duplicate PARTUUID device events
    // stop the live source's systemd-veritysetup@usr.service. Never reset that
    // failure or weaken verity binding to hide it. sgdisk itself notifies the
    // kernel after its final write; a second destructive reread is unnecessary.
    let args = install_gpt_args(backup, target, raid, layout.geometry.parts[5].1);
    run(
        "sgdisk",
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    )?;
    run("udevadm", &["settle"])?;
    let actual = InstallGeometry::parse(&inspect_layout(&["--pretend", "--print", target])?)?;
    ensure!(
        actual.sector == layout.geometry.sector
            && actual.parts[..5] == layout.geometry.parts[..5]
            && actual.parts[5].1 == layout.geometry.parts[5].1
            && actual.parts[5].2 >= layout.geometry.parts[5].2,
        "installed GPT changed protected geometry or truncated the fresh data partition"
    );
    actual.require_kernel_view(target)?;
    // Clone every bootable payload represented by the copied ESP. A booted,
    // updated source can have active B and a still-valid fallback A: copying
    // only A would silently install stale bytes and leave B's selected UKI
    // pointing at an empty verity pair. Preserve both slots without rewriting
    // signed UKIs, renumbering hash-derived UUIDs or changing boot preference.
    for n in SEALED_PARTS {
        run(
            "dd",
            &[
                &format!("if={}", part_path(source, n)),
                &format!("of={}", part_path(target, n)),
                "bs=4M",
                "conv=fsync",
            ],
        )?;
    }
    Ok(())
}

// ---- A/B updates ----------------------------------------------------------

/// A store slot: its verity-hash + store partition numbers, and the systemd-boot
/// entry name its UKI is filed under in /EFI/Linux.
///
/// Visible to the crate because the slot layout is also what tells `show
/// version` which half of the disk the running image came from — see
/// [`crate::image`]. One definition, so the updater and the report can never
/// disagree about which partition is which.
pub struct Slot {
    pub name: &'static str,
    pub verity_part: u32,
    pub store_part: u32,
}
pub const SLOT_A: Slot = Slot {
    name: "sentinel-a",
    verity_part: 2,
    store_part: 3,
};
pub const SLOT_B: Slot = Slot {
    name: "sentinel-b",
    verity_part: 4,
    store_part: 5,
};

// systemd GPT type GUIDs for the verity store pair (x86-64) — used to re-type
// slot B (reserved generic at build) once it holds a real verity image.
const USR_TYPE: &str = "8484680C-9521-48C6-9C11-B0720656F69E";
const USR_VERITY_TYPE: &str = "77FF5F63-E7B6-4633-ACF4-1565B864C0E6";

/// The slot whose store currently backs the running `/dev/mapper/usr`.
fn active_slot(disk: &str) -> Result<&'static Slot> {
    let bare = disk.trim_start_matches("/dev/");
    let out = Command::new(system::bin("lsblk"))
        .args(["-nsro", "NAME,TYPE", "/dev/mapper/usr"])
        .output()
        .context("inspecting the active verity device")?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let mut f = line.split_whitespace();
        let (name, kind) = (f.next().unwrap_or(""), f.next().unwrap_or(""));
        if kind != "part" {
            continue;
        }
        if let Some(rest) = name.strip_prefix(bare) {
            let num: u32 = rest.trim_start_matches('p').parse().unwrap_or(0);
            if num == SLOT_A.store_part {
                return Ok(&SLOT_A);
            }
            if num == SLOT_B.store_part {
                return Ok(&SLOT_B);
            }
        }
    }
    bail!("could not determine the active slot from /dev/mapper/usr");
}

/// Unmounts a path when dropped.
struct MountGuard(std::path::PathBuf);
impl Drop for MountGuard {
    fn drop(&mut self) {
        let _ = Command::new(system::bin("umount")).arg(&self.0).status();
    }
}

/// Write a freshly built appliance configuration onto the installed system's
/// data partition, so the box comes up configured instead of empty.
///
/// This is what makes the wizard worth having. Without it the operator installs,
/// reboots into a box with no address and no account, and has to do the whole
/// thing again at the console — which is exactly the step a guided installer
/// exists to remove.
///
/// The mount is a guard: it comes off however this returns, including on the
/// error paths, so a failed seed does not leave the installed filesystem
/// mounted under the live medium.
pub fn seed_config(targets: &[&Disk], raid: Raid, toml: &str, crypto: &Crypto) -> Result<()> {
    // On an encrypted install `execute` has left the data partition a closed LUKS
    // volume, so re-open it with the passphrase to write the seed, and close it
    // again afterwards so the freshly installed box unlocks it fresh on its first
    // boot. Both guards run however this returns, error paths included; the mount
    // guard is declared *after* the crypt guard so it drops first (unmount before
    // close). A plaintext install writes the base device directly, unchanged.
    let (dev, _crypt_guard) = match crypto {
        Crypto::None => (existing_data_base(targets, raid), None),
        Crypto::Luks { passphrase } => {
            luks_open(&existing_data_base(targets, raid), passphrase)?;
            (data_mapper_path(), Some(CryptGuard))
        }
    };
    let mnt = std::path::Path::new("/run/sentinel-seed");
    std::fs::create_dir_all(mnt).context("creating the seed mountpoint")?;
    // execute() always creates ext4 here, including inside LUKS. Do not let
    // mount's image-specific auto-detection/helper order guess EROFS for fresh
    // data: that fails seeding after the destructive copy already completed.
    run("mount", &["-t", "ext4", &dev, mnt.to_str().unwrap()])?;
    let _guard = MountGuard(mnt.to_path_buf());

    // The data partition IS /var/lib/sentinel on the installed system — it is
    // mounted there, so the config belongs at the partition's root. Writing
    // `lib/sentinel/` under it put the operator's answers at
    // /var/lib/sentinel/lib/sentinel/appliance.toml, where nothing looks: the
    // box booted, found no config, copied the factory default over the top, and
    // every answer given during the install — password, keymap, hostname,
    // network — was gone by the first login prompt.
    let path = mnt.join("appliance.toml");
    std::fs::write(&path, toml).with_context(|| format!("writing {}", path.display()))?;
    eprintln!("seeded {} ({} bytes)", path.display(), toml.len());
    Ok(())
}

/// A/B update: write `image`'s sealed store into the INACTIVE slot, then make
/// systemd-boot try it next (it rolls back to the current slot if the new one
/// fails 3 boots). `image` may be a raw image file (loop-mounted) or a block
/// device (used directly — e.g. the booted medium, for a re-seal). DESTRUCTIVE
/// to the inactive slot only; the running slot is untouched.
pub fn update(image: &std::path::Path, commit: bool) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;

    let (disk, active, inactive) = update_target()?;
    if !commit {
        eprintln!(
            "(dry-run — re-run with --commit to write slot {} and switch the boot default)",
            inactive.name
        );
        return Ok(());
    }

    // Boot selection is part of the safety gate, even for a deliberately
    // unsigned local image. Refuse unsafe firmware state before any slot write.
    preflight_boot_selection()?;

    // Resolve the source to a partitioned block device.
    let is_block = std::fs::metadata(image)
        .map(|m| m.file_type().is_block_device())
        .unwrap_or(false);
    let (srcdev, _loop) = if is_block {
        (image.to_string_lossy().into_owned(), None)
    } else {
        let dev = losetup_attach(image)?;
        (dev.clone(), Some(LoopGuard(dev)))
    };

    // The slot's identity (its partition GUIDs) is checked before any write;
    // see [`refuse_identical_image`] for why an identical image must be refused.
    let src_verity = partition_guid(&srcdev, SLOT_A.verity_part)?;
    let src_store = partition_guid(&srcdev, SLOT_A.store_part)?;
    refuse_identical_image(&disk, active, inactive, &src_verity, &src_store)?;

    // Clone the source's slot-A store + verity hash into our inactive slot.
    eprintln!("writing slot {} from {srcdev} …", inactive.name);
    let clone = |from: u32, to: u32| -> Result<()> {
        run(
            "dd",
            &[
                &format!("if={}", part_path(&srcdev, from)),
                &format!("of={}", part_path(&disk, to)),
                "bs=4M",
                "conv=fsync",
            ],
        )
    };
    clone(SLOT_A.verity_part, inactive.verity_part)?;
    clone(SLOT_A.store_part, inactive.store_part)?;
    // Re-type the inactive (reserved-generic) partitions to the verity GUIDs so
    // the initrd's veritysetup considers them, and give them the source's
    // unique GUIDs so it can identify which image they hold.
    run(
        "sgdisk",
        &[
            &format!("--typecode={}:{USR_VERITY_TYPE}", inactive.verity_part),
            &format!("--typecode={}:{USR_TYPE}", inactive.store_part),
            &format!("--partition-guid={}:{src_verity}", inactive.verity_part),
            &format!("--partition-guid={}:{src_store}", inactive.store_part),
            &disk,
        ],
    )?;
    run("partprobe", &[&disk]).ok();
    run("udevadm", &["settle"]).ok();

    switch_boot(&disk, UkiSource::Device(&srcdev), active, inactive)?;
    eprintln!(
        "update complete — reboot to boot slot {} (auto-rolls back to {} if it fails 3×)",
        inactive.name, active.name
    );
    // The slot was just given the source's partition GUIDs — that is how the
    // initrd finds it. A medium that stays attached across the reboot answers
    // to the same GUIDs, and systemd mounts whichever it meets first: /usr then
    // comes up from the stick, and pulling the stick later takes /usr with it.
    // (checks.update reproduced exactly that with the medium left in.)
    if is_block {
        eprintln!(
            "note: {srcdev} carries the same verity/store partition GUIDs as slot {} now. \
             Unplug it before rebooting — while it is attached, the initrd may mount /usr \
             from the medium instead of the slot.",
            inactive.name
        );
    }
    Ok(())
}

/// The slot an update writes: the running disk, its active slot, and the
/// inactive one that receives the image. Root only.
fn update_target() -> Result<(String, &'static Slot, &'static Slot)> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("update must run as root (try `sudo sentinel update …`)");
    }
    let disk = find_source_disk()?;
    let active = active_slot(&disk)?;
    let inactive = if active.name == SLOT_A.name {
        &SLOT_B
    } else {
        &SLOT_A
    };
    eprintln!(
        "active slot: {} — updating inactive slot {} on {disk}",
        active.name, inactive.name
    );
    Ok((disk, active, inactive))
}

/// The *identity* of the slot, not only its contents, and it is checked
/// BEFORE any destructive write. systemd finds a verity pair by partition
/// GUID -- the two halves of the image's root hash -- so a slot holding the
/// new image while keeping the old slot's randomly assigned GUIDs is a slot
/// the initrd cannot find. It then waits for a device that will never appear:
/// the box hangs rather than failing, so it never resets, so the boot counter
/// never decrements and the automatic rollback never fires. That is exactly
/// how an updated appliance went dark on the bench.
///
/// The same mechanism bites the *identical-image* case: if this image is
/// byte-for-byte the one already running, its slot-A verity/store GUIDs ARE
/// the active slot's GUIDs, and stamping them onto the inactive slot leaves
/// two partitions sharing one PARTUUID — which the initrd cannot tell apart,
/// so it hangs exactly as above. The GUIDs cannot be randomised away (verity
/// derives them from the root hash the UKI expects), so the only safe answer
/// is to refuse up front, before the inactive slot is touched.
fn refuse_identical_image(
    disk: &str,
    active: &Slot,
    inactive: &Slot,
    src_verity: &str,
    src_store: &str,
) -> Result<()> {
    let active_verity = partition_guid(disk, active.verity_part)?;
    let active_store = partition_guid(disk, active.store_part)?;
    if src_verity.eq_ignore_ascii_case(&active_verity)
        || src_store.eq_ignore_ascii_case(&active_store)
    {
        bail!(
            "this image is identical to the running slot {active} (its verity/store \
             partitions carry the same GUIDs): writing it to slot {inactive} would \
             leave two partitions with the same PARTUUID, which the initrd cannot \
             tell apart — the box would hang at boot instead of auto-rolling-back. \
             Nothing was changed. Update to a freshly built image, which carries its \
             own verity GUIDs.",
            active = active.name,
            inactive = inactive.name,
        );
    }
    Ok(())
}

/// A/B update from an image that must hash to `sha256` — the signed path, for
/// a local image, a USB stick or a channel download alike.
///
/// Unlike [`update`], nothing here looks at the source twice by name: the image
/// is opened once ([`VerifiedImage`]), hashed in full against the signed digest
/// before anything is written, and then only the verified partitions are copied
/// from that same open file — each re-hashed on the way, so a source that
/// changes underneath (a rewritten file, a swapped stick) is refused before the
/// slot is re-typed or the boot default moves. The GUIDs stamped on the slot
/// and the UKI installed come from those verified bytes too; the UKI is read
/// from a private copy of the image's ESP, not from a mount of the source.
pub fn update_verified(source: &std::path::Path, sha256: &str, commit: bool) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;

    let (disk, active, inactive) = update_target()?;
    // Not a let-chain: the appliance's pinned compiler predates them.
    let same_disk = matches!(
        (source.canonicalize(), std::path::Path::new(&disk).canonicalize()),
        (Ok(src), Ok(running)) if src == running
    );
    if same_disk {
        bail!(
            "{} is the disk this box runs from; re-sealing the booted medium is the trusted \
             path (--allow-unsigned), not a signed update",
            source.display()
        );
    }
    let image = VerifiedImage::open(source, sha256)?;
    eprintln!("image SHA-256 verified against its signed digest");
    if !commit {
        eprintln!(
            "(dry-run — re-run with --commit to write slot {} and switch the boot default)",
            inactive.name
        );
        return Ok(());
    }
    preflight_boot_selection()?;
    refuse_identical_image(
        &disk,
        active,
        inactive,
        image.guid(SLOT_A.verity_part),
        image.guid(SLOT_A.store_part),
    )?;
    let target = |part: u32, from: u32| -> Result<std::fs::File> {
        use std::io::{Seek, SeekFrom};
        let path = part_path(&disk, part);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .with_context(|| format!("opening {path}"))?;
        let room = file.seek(SeekFrom::End(0))?;
        file.seek(SeekFrom::Start(0))?;
        ensure!(
            image.len(from) <= room,
            "image partition {from} ({} bytes) does not fit slot partition {path} ({room} bytes)",
            image.len(from)
        );
        Ok(file)
    };
    // Size checks for both before either is written.
    let mut verity = target(inactive.verity_part, SLOT_A.verity_part)?;
    let mut store = target(inactive.store_part, SLOT_A.store_part)?;
    let esp_copy = update::Scratch::new()?;
    let mut esp = esp_copy.create_private("esp.img")?;
    eprintln!("writing slot {} from {} …", inactive.name, source.display());
    let written = image
        .copy_partition(SLOT_A.verity_part, &mut verity)
        .and_then(|()| image.copy_partition(SLOT_A.store_part, &mut store))
        .and_then(|()| image.copy_partition(1, &mut esp));
    if let Err(error) = written {
        bail!(
            "{error:#}\nslot {} may hold a partial copy and was NOT activated: its partition \
             types and the boot default are unchanged, the running slot {} is untouched.",
            inactive.name,
            active.name
        );
    }
    run(
        "sgdisk",
        &[
            &format!("--typecode={}:{USR_VERITY_TYPE}", inactive.verity_part),
            &format!("--typecode={}:{USR_TYPE}", inactive.store_part),
            &format!(
                "--partition-guid={}:{}",
                inactive.verity_part,
                image.guid(SLOT_A.verity_part)
            ),
            &format!(
                "--partition-guid={}:{}",
                inactive.store_part,
                image.guid(SLOT_A.store_part)
            ),
            &disk,
        ],
    )?;
    run("partprobe", &[&disk]).ok();
    run("udevadm", &["settle"]).ok();
    switch_boot(
        &disk,
        UkiSource::EspImage(&esp_copy.join("esp.img")),
        active,
        inactive,
    )?;
    eprintln!(
        "update complete — reboot to boot slot {} (auto-rolls back to {} if it fails 3×)",
        inactive.name, active.name
    );
    if std::fs::metadata(source).is_ok_and(|m| m.file_type().is_block_device()) {
        eprintln!(
            "note: {} carries the same verity/store partition GUIDs as slot {} now. \
             Unplug it before rebooting — while it is attached, the initrd may mount /usr \
             from the medium instead of the slot.",
            source.display(),
            inactive.name
        );
    }
    Ok(())
}

/// Signed-channel update (roadmap C13): verify the channel's signed release
/// manifest against the pinned key, refuse a release older than the running one
/// unless `allow_downgrade`, fetch the image it names and verify its SHA-256,
/// then hand that image to [`update_verified`] with the manifest's digest — so
/// the bytes written are hashed once more as they are read for the slot. This
/// is the ONLY path from a remote channel to the slot-write, and it is
/// fail-closed: an unsigned, wrong-key, stale or digest-mismatched release can
/// never be written.
pub fn update_from_channel(
    chan: &UpdateChannel,
    commit: bool,
    allow_downgrade: bool,
) -> Result<()> {
    let manifest = update::check(chan)?;
    eprintln!(
        "verified release {} (image {}) — signed by the pinned update key",
        manifest.version, manifest.image
    );
    update::refuse_downgrade(&manifest.version, allow_downgrade)?;

    // Stage the verified image in a self-cleaning scratch dir that outlives the
    // slot-write below (it drops — and deletes the image — when this fn returns).
    let scratch = update::Scratch::new()?;
    let image = scratch.join("image.img");
    update::fetch_verified_image(chan, &manifest, &image)?;
    eprintln!("image SHA-256 verified against the signed manifest");

    // Only now, past both crypto gates, does the image reach the slot-writer.
    update_verified(&image, &manifest.sha256, commit)
}

/// The mountpoint of a block device, if it's currently mounted.
fn mountpoint_of(dev: &str) -> Option<String> {
    let out = Command::new(system::bin("findmnt"))
        .args(["-nro", "TARGET", "-S", dev])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
}

/// Where the new slot's UKI comes from: the ESP of a source device (the
/// trusted `--allow-unsigned` path, which may be the booted disk itself), or a
/// private copy of a verified image's ESP.
enum UkiSource<'a> {
    Device(&'a str),
    EspImage(&'a std::path::Path),
}

const LOADER_VENDOR_GUID: &str = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f";
const MAX_EFI_VARIABLE_BYTES: usize = 4096;

/// Read an efivarfs payload without trusting its reported file size. Missing
/// optional variables are normal; unreadable, oversized or malformed ones are
/// not permission to stage a candidate whose fallback policy is unknown.
fn read_bounded(path: &std::path::Path, maximum: usize) -> Result<Option<Vec<u8>>> {
    use std::io::Read;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= maximum, "{} is oversized", path.display());
    Ok(Some(bytes))
}

fn decode_loader_variable(bytes: &[u8]) -> Result<String> {
    ensure!(
        (4..=MAX_EFI_VARIABLE_BYTES).contains(&bytes.len()) && (bytes.len() - 4) % 2 == 0,
        "malformed efivarfs UTF-16 payload"
    );
    let attributes = u32::from_le_bytes(bytes[..4].try_into().expect("four attributes bytes"));
    // Loader variables are boot-service/runtime variables, either volatile
    // (6) or nonvolatile (7), not authenticated-key or append-write payloads.
    ensure!(
        matches!(attributes, 6 | 7),
        "unexpected EFI loader-variable attributes"
    );
    let words: Vec<_> = bytes[4..]
        .chunks_exact(2)
        .map(|word| u16::from_le_bytes([word[0], word[1]]))
        .collect();
    let end = words
        .iter()
        .position(|word| *word == 0)
        .unwrap_or(words.len());
    ensure!(
        words[end..].iter().all(|word| *word == 0),
        "data after EFI loader-variable string terminator"
    );
    String::from_utf16(&words[..end]).context("invalid EFI loader-variable UTF-16")
}

fn validate_boot_selection(loader: Option<&str>, overrides: &[(&str, &str)]) -> Result<()> {
    let version = loader
        .and_then(|value| value.strip_prefix("systemd-boot "))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.split(['.', '~', '-', '+']).next())
        .and_then(|value| value.parse::<u32>().ok());
    ensure!(
        version.is_some_and(|version| version >= 260),
        "safe A/B updates require the running UEFI systemd-boot version 260 or newer; \
         LoaderInfo is missing, unsupported or too old. Review bootloader maintenance \
         before retrying; no slot write was authorized"
    );
    for (name, value) in overrides {
        let command = match *name {
            "LoaderEntryDefault" => "set-default",
            "LoaderEntryPreferred" => "set-preferred",
            "LoaderEntryOneShot" => "set-oneshot",
            _ => bail!("unexpected EFI boot-selection override"),
        };
        ensure!(
            value.is_empty(),
            "UEFI {name} overrides appliance A/B selection; review it and explicitly \
             clear it with `bootctl {command} ''` before retrying. Sentinel does not \
             clear firmware variables automatically"
        );
    }
    Ok(())
}

fn preflight_boot_selection() -> Result<()> {
    let directory = std::path::Path::new("/sys/firmware/efi/efivars");
    let read = |name: &str| -> Result<Option<String>> {
        let path = directory.join(format!("{name}-{LOADER_VENDOR_GUID}"));
        read_bounded(&path, MAX_EFI_VARIABLE_BYTES)?
            .map(|bytes| decode_loader_variable(&bytes))
            .transpose()
            .with_context(|| format!("validating EFI {name}"))
    };
    let loader = read("LoaderInfo")?;
    let names = [
        "LoaderEntryDefault",
        "LoaderEntryPreferred",
        "LoaderEntryOneShot",
    ];
    let overrides: Vec<_> = names
        .into_iter()
        .map(|name| Ok((name, read(name)?.unwrap_or_default())))
        .collect::<Result<_>>()?;
    let borrowed: Vec<_> = overrides
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    validate_boot_selection(loader.as_deref(), &borrowed)
}

/// A preferred pattern honors boot assessment; a hard per-slot default does
/// not (systemd-boot 260). The broad fallback still matches the retained good
/// slot, sorted ahead of an exhausted candidate. Remove ALL old exact keys,
/// including duplicate directives, without eating comments or unrelated keys.
fn render_loader_selection(previous: &str, slot: &Slot) -> String {
    let mut output = String::new();
    for line in previous.lines() {
        if matches!(
            line.split_whitespace().next(),
            Some("default" | "preferred")
        ) {
            continue;
        }
        output.push_str(line);
        output.push('\n');
    }
    output.push_str(&format!("preferred {}*\ndefault sentinel-*\n", slot.name));
    output
}

/// Install the source image's UKI onto the running ESP as the inactive slot's
/// boot-counted entry (`<slot>+3.efi`) and prefer it without forcing an exhausted
/// entry ahead of the healthy fallback.
fn switch_boot(disk: &str, source: UkiSource, active: &Slot, inactive: &Slot) -> Result<()> {
    // Recheck immediately before ESP mutation as well as before partition
    // writes. A newly introduced firmware override must not be hidden by a
    // successful copy of the inactive slot.
    preflight_boot_selection()?;
    let self_reseal = matches!(source, UkiSource::Device(dev) if dev == disk);
    // The running ESP is already mounted (systemd-gpt-auto puts it on /boot,
    // read-only). Reuse that mountpoint and flip it writable rather than mounting
    // the device a second time. If somehow unmounted, mount it ourselves.
    let disk_esp = part_path(disk, 1);
    let (dst, _dg): (std::path::PathBuf, Option<MountGuard>) = match mountpoint_of(&disk_esp) {
        Some(mp) => {
            run("mount", &["-o", "remount,rw", &mp])?;
            (std::path::PathBuf::from(mp), None)
        }
        None => {
            let p = std::path::PathBuf::from("/run/sentinel/upd-dst");
            std::fs::create_dir_all(&p)?;
            run("mount", &[&disk_esp, p.to_str().unwrap()])?;
            (p.clone(), Some(MountGuard(p)))
        }
    };

    // Source ESP: a self-reseal from the same disk shares the dest ESP; a
    // separate image gets its ESP mounted read-only at a temp path.
    let (src, _sg): (std::path::PathBuf, Option<MountGuard>) = if self_reseal {
        (dst.clone(), None)
    } else {
        let p = std::path::PathBuf::from("/run/sentinel/upd-src");
        std::fs::create_dir_all(&p)?;
        let (options, device) = match source {
            UkiSource::Device(dev) => ("ro", part_path(dev, 1)),
            UkiSource::EspImage(file) => ("ro,loop", file.to_string_lossy().into_owned()),
        };
        run("mount", &["-o", options, &device, p.to_str().unwrap()])?;
        (p.clone(), Some(MountGuard(p)))
    };

    // The source UKI: for a self-reseal pick the active slot's entry; for a
    // separate image there's exactly one UKI in its /EFI/Linux.
    let want = if self_reseal { Some(active.name) } else { None };
    let uki = std::fs::read_dir(src.join("EFI/Linux"))?
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            p.extension().is_some_and(|x| x == "efi")
                && want.is_none_or(|n| {
                    p.file_name()
                        .is_some_and(|f| f.to_string_lossy().starts_with(n))
                })
        })
        .ok_or_else(|| anyhow::anyhow!("no UKI in the source ESP"))?;

    let lin = dst.join("EFI/Linux");
    let conf = dst.join("loader/loader.conf");
    let previous = read_bounded(&conf, 65_536)?.unwrap_or_default();
    let previous = String::from_utf8(previous).context("loader.conf is not valid UTF-8")?;
    let selection = render_loader_selection(&previous, inactive);
    std::fs::create_dir_all(&lin)?;
    // Replace any prior entry for this slot, then install the new one with 3 tries.
    for e in std::fs::read_dir(&lin)?.flatten() {
        if e.file_name().to_string_lossy().starts_with(inactive.name) {
            std::fs::remove_file(e.path())?;
        }
    }
    std::fs::copy(&uki, lin.join(format!("{}+3.efi", inactive.name)))?;

    // Globs survive the successful bless removing +N, but only `preferred`
    // checks tries_left. The broad default permits assessment-based fallback.
    std::fs::create_dir_all(dst.join("loader"))?;
    std::fs::write(&conf, selection)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn installation_copies_both_sealed_slots_but_never_persistent_data() {
        assert_eq!(super::SEALED_PARTS.collect::<Vec<_>>(), [1, 2, 3, 4, 5]);
    }
    use super::*;

    fn loader_variable(attributes: u32, value: &str) -> Vec<u8> {
        let mut bytes = attributes.to_le_bytes().to_vec();
        for word in value.encode_utf16().chain([0]) {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn loader_variables_decode_attributes_utf16_and_empty_values() {
        for attributes in [6, 7] {
            assert_eq!(
                decode_loader_variable(&loader_variable(attributes, "systemd-boot 260.5")).unwrap(),
                "systemd-boot 260.5"
            );
            assert_eq!(
                decode_loader_variable(&attributes.to_le_bytes()).unwrap(),
                ""
            );
            assert_eq!(
                decode_loader_variable(&loader_variable(attributes, "")).unwrap(),
                ""
            );
        }
        assert_eq!(
            decode_loader_variable(&loader_variable(7, "é-fixture")).unwrap(),
            "é-fixture"
        );
        let mut padded = loader_variable(6, "systemd-boot 260.5");
        padded.extend_from_slice(&[0, 0]);
        assert_eq!(
            decode_loader_variable(&padded).unwrap(),
            "systemd-boot 260.5"
        );
    }

    #[test]
    fn malformed_loader_variables_are_not_treated_as_absent_overrides() {
        for bytes in [
            vec![],
            vec![0; 3],
            vec![0; 5],
            vec![0; MAX_EFI_VARIABLE_BYTES + 2],
        ] {
            assert!(decode_loader_variable(&bytes).is_err());
        }
        for attributes in [0, 1, 2, 3, 4, 8, 0x27, u32::MAX] {
            assert!(decode_loader_variable(&loader_variable(attributes, "sentinel-a*")).is_err());
        }
        let mut surrogate = 6u32.to_le_bytes().to_vec();
        surrogate.extend_from_slice(&0xd800u16.to_le_bytes());
        assert!(decode_loader_variable(&surrogate).is_err());
        assert!(decode_loader_variable(&loader_variable(6, "sentinel-a*\0sentinel-b*")).is_err());
    }

    #[test]
    fn only_supported_running_systemd_boot_can_stage_a_candidate() {
        for version in [
            "systemd-boot 260",
            "systemd-boot 260.5",
            "systemd-boot 261~rc1",
            "systemd-boot 262+nixos",
        ] {
            validate_boot_selection(Some(version), &[]).unwrap();
        }
        for loader in [
            None,
            Some(""),
            Some("GRUB 260"),
            Some("systemd-boot 259.99"),
            Some("systemd-boot 260garbage"),
            Some("systemd-boot unknown"),
        ] {
            assert!(
                validate_boot_selection(loader, &[]).is_err(),
                "accepted {loader:?}"
            );
        }
    }

    #[test]
    fn efi_selection_overrides_require_explicit_operator_review() {
        for (name, command) in [
            ("LoaderEntryDefault", "set-default"),
            ("LoaderEntryPreferred", "set-preferred"),
            ("LoaderEntryOneShot", "set-oneshot"),
        ] {
            validate_boot_selection(Some("systemd-boot 260.5"), &[(name, "")]).unwrap();
            for value in [
                "sentinel-a*",
                "sentinel-*",
                "@saved",
                " ",
                "unrelated-os.conf",
            ] {
                let error = validate_boot_selection(Some("systemd-boot 260.5"), &[(name, value)])
                    .unwrap_err();
                let message = error.to_string();
                assert!(
                    message.contains(name) && message.contains(command),
                    "{message}"
                );
            }
        }
        assert!(validate_boot_selection(Some("systemd-boot 260.5"), &[("unknown", "")]).is_err());
    }

    #[test]
    fn loader_selection_migrates_all_hard_defaults_without_eating_other_options() {
        let previous = "# default sentinel-a*\ntimeout 3\n default\tsentinel-a*\npreferred sentinel-a*\ndefault sentinel-b*\neditor no\ndefault-timeout 4\n# preferred keep-comment\n";
        let rendered = render_loader_selection(previous, &SLOT_B);
        assert_eq!(
            rendered,
            "# default sentinel-a*\ntimeout 3\neditor no\ndefault-timeout 4\n# preferred keep-comment\npreferred sentinel-b*\ndefault sentinel-*\n"
        );
        assert_eq!(render_loader_selection(&rendered, &SLOT_B), rendered);
        let reversed = render_loader_selection(&rendered, &SLOT_A);
        assert!(reversed.ends_with("preferred sentinel-a*\ndefault sentinel-*\n"));
        assert_eq!(
            reversed
                .lines()
                .filter(|line| line.starts_with("default "))
                .count(),
            1
        );
        assert_eq!(
            reversed
                .lines()
                .filter(|line| line.starts_with("preferred "))
                .count(),
            1
        );
        assert_eq!(
            render_loader_selection("", &SLOT_A),
            "preferred sentinel-a*\ndefault sentinel-*\n"
        );
    }

    #[test]
    fn bounded_boot_policy_reads_do_not_accept_truncation_or_hide_io_failures() {
        use std::io::Write;
        let mut stage = system::PrivateStage::create(&std::env::temp_dir(), 0o600).unwrap();
        stage.file.write_all(b"12345678").unwrap();
        assert_eq!(read_bounded(&stage.path, 8).unwrap().unwrap(), b"12345678");
        assert!(read_bounded(&stage.path, 7).is_err());
        assert!(read_bounded(&std::env::temp_dir(), 8).is_err());
        let absent = stage.path.with_extension("missing");
        assert!(read_bounded(&absent, 8).unwrap().is_none());
        assert!(std::fs::read(stage.path.clone()).unwrap() == b"12345678");
    }

    #[test]
    fn active_and_inactive_slots_are_distinct() {
        assert_ne!(SLOT_A.name, SLOT_B.name);
        assert_eq!((SLOT_A.verity_part, SLOT_A.store_part), (2, 3));
        assert_eq!((SLOT_B.verity_part, SLOT_B.store_part), (4, 5));
    }

    #[test]
    fn the_unlocked_data_volume_has_a_stable_name() {
        assert_eq!(data_mapper_path(), "/dev/mapper/data");
        assert_eq!(DATA_MAPPER, "data");
    }

    #[test]
    fn the_seed_target_is_the_array_or_the_partition() {
        let sda = disk("sda", 500, false);
        let sdb = disk("sdb", 500, false);
        // Single disk: the raw data partition.
        assert_eq!(existing_data_base(&[&sda], Raid::None), "/dev/sda6");
        // RAID: the assembled array node execute created.
        assert_eq!(
            existing_data_base(&[&sda, &sdb], Raid::Mirror),
            "/dev/md/sentinel-data"
        );
    }

    #[test]
    fn an_empty_luks_passphrase_is_refused_before_touching_the_disk() {
        // Fails on the empty-passphrase guard, before any cryptsetup spawn — so
        // this runs without cryptsetup present.
        let err = luks_format_open("/dev/does-not-matter", "").unwrap_err();
        assert!(format!("{err}").contains("empty passphrase"), "{err}");
    }

    #[test]
    fn part_path_handles_nvme_and_sata() {
        assert_eq!(part_path("/dev/sda", 1), "/dev/sda1");
        assert_eq!(part_path("vdb", 4), "/dev/vdb4");
        assert_eq!(part_path("/dev/nvme0n1", 3), "/dev/nvme0n1p3");
        assert_eq!(part_path("/dev/mmcblk0", 2), "/dev/mmcblk0p2");
    }

    #[test]
    fn raid_levels_map_to_mdadm() {
        assert_eq!(Raid::None.mdadm_level(), None);
        assert_eq!(Raid::Stripe.mdadm_level(), Some("0"));
        assert_eq!(Raid::Mirror.mdadm_level(), Some("1"));
        assert_eq!(Raid::Mirror10.mdadm_level(), Some("10"));
        assert_eq!(Raid::Stripe.min_disks(), 2);
    }

    #[test]
    fn parses_lsblk_disks_and_skips_non_disks() {
        let text = "\
sda    500107862016 disk 0 Samsung SSD 860
sda1     1048576000 part 0
nvme0n1 1000204886016 disk 0 WD_BLACK SN770
sdb       8000000000 disk 1 SanDisk Cruzer
sr0       1073741824 rom  1
";
        let disks = parse_lsblk(text);
        assert_eq!(disks.len(), 3);
        assert_eq!(disks[0].name, "sda");
        assert_eq!(disks[0].model, "Samsung SSD 860");
        assert!(!disks[0].removable);
        assert_eq!(disks[1].name, "nvme0n1");
        assert_eq!(disks[2].name, "sdb");
        assert!(disks[2].removable, "RM=1 → removable");
    }

    #[test]
    fn human_size_is_readable() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(500_107_862_016), "465.8 GiB");
    }

    #[test]
    fn partial_install_error_names_the_erased_disks() {
        let e = partial_install_error(
            anyhow::anyhow!("mkfs failed"),
            &["/dev/sda".into(), "/dev/sdb".into()],
        );
        let msg = format!("{e}");
        // Names every erased disk and its underlying cause.
        assert!(msg.contains("/dev/sda"), "{msg}");
        assert!(msg.contains("/dev/sdb"), "{msg}");
        assert!(msg.contains("mkfs failed"), "{msg}");
        // Makes the blank/not-bootable state unambiguous.
        assert!(msg.contains("BLANK"), "{msg}");
    }

    #[test]
    fn layout_bytes_measures_the_end_of_the_last_partition() {
        // Abridged `sgdisk -p` of an appliance medium: an ESP, both verity
        // slots, and the data partition last.
        let printed = "\
Disk /dev/vda: 12582912 sectors, 6.0 GiB
Sector size (logical/physical): 512/512 bytes
Disk identifier (GUID): 2E4C1F0A-0000-4000-8000-000000000001
Partition table holds up to 128 entries
First usable sector is 34, last usable sector is 12582878

Number  Start (sector)    End (sector)  Size       Code  Name
   1            2048          264191   128.0 MiB   EF00  esp
   2          264192          657407   192.0 MiB   8300  store-verity-a
   3          657408         5900799   2.5 GiB     8300  store-a
   6        11534336        11796479   128.0 MiB   8300  data
";
        // The last partition ends at 11796479, and the backup GPT needs the 33
        // sectors after it.
        let want = (11_796_479u64 + 1 + 33) * 512;
        assert_eq!(parse_layout_bytes(printed), Some(want));
        // Which is more than the hand-kept floor — the very reason the floor is
        // not the check that guards the erase.
        assert!(want > MIN_TARGET_BYTES);
    }

    #[test]
    fn layout_bytes_ignores_a_listing_without_partitions() {
        assert_eq!(
            parse_layout_bytes("Disk /dev/vdb: 100 sectors\nNumber  Start (sector)\n"),
            None
        );
    }

    #[test]
    fn layout_bytes_honours_a_4k_sector_size() {
        let printed = "\
Sector size (logical/physical): 4096/4096 bytes
Number  Start (sector)    End (sector)  Size       Code  Name
   1            2048          264191   1.0 GiB     EF00  esp
";
        assert_eq!(parse_layout_bytes(printed), Some((264_191u64 + 34) * 4096));
    }

    fn factory_geometry(data_sectors: u64) -> String {
        let mut text =
            "Sector size (logical): 512 bytes\nNumber Start End Size Code Name\n".to_string();
        let mut start = 2048;
        for number in 1..=6 {
            let sectors = if number == 6 { data_sectors } else { 8192 };
            text.push_str(&format!(
                "{number} {start} {} 4 MiB 8300 p{number}\n",
                start + sectors - 1
            ));
            start += sectors;
        }
        text
    }

    #[test]
    fn install_gpt_is_one_ordered_complete_transaction() {
        assert_eq!(
            install_gpt_args(
                "/private/install-layout.gpt",
                "/dev/nvme0n1",
                Raid::None,
                11536384
            ),
            [
                "--load-backup=/private/install-layout.gpt",
                "--move-second-header",
                "--disk-guid=R",
                "--set-alignment=1",
                "--delete=6",
                "--new=6:11536384:0",
                "--typecode=6:8300",
                "--change-name=6:data",
                "/dev/nvme0n1",
            ]
        );
    }

    #[test]
    fn install_gpt_raid_only_changes_the_fresh_data_type() {
        for raid in [Raid::Stripe, Raid::Mirror, Raid::Mirror10] {
            let args = install_gpt_args("/private/layout.gpt", "/dev/vdb", raid, 11536384);
            assert!(args.iter().any(|arg| arg == "--typecode=6:FD00"));
            assert_eq!(
                args.iter()
                    .filter(|arg| arg.starts_with("--delete="))
                    .count(),
                1
            );
            assert!(
                !args
                    .iter()
                    .any(|arg| arg.contains("randomize-guids")
                        || arg.starts_with("--partition-guid="))
            );
            assert_eq!(args.last().unwrap(), "/dev/vdb");
        }
    }

    #[test]
    fn fresh_install_layout_does_not_clone_grown_source_data_capacity() {
        let source = InstallGeometry::parse(&factory_geometry(16 * 1024 * 1024)).unwrap();
        let prepared = source.fresh_data();
        assert_eq!(prepared.parts[..5], source.parts[..5]);
        assert_eq!(prepared.parts[5].1, source.parts[5].1);
        assert_eq!(
            (prepared.parts[5].2 - prepared.parts[5].1 + 1) * prepared.sector,
            128 * 1024 * 1024
        );
        assert!(prepared.parts[5].2 < source.parts[5].2);
    }

    #[test]
    fn fresh_install_layout_never_enlarges_an_explicit_smaller_factory_floor() {
        let source = InstallGeometry::parse(&factory_geometry(8192)).unwrap();
        assert_eq!(source.fresh_data(), source);
    }

    #[test]
    fn install_geometry_reads_actual_modern_and_legacy_sector_headers() {
        let modern = factory_geometry(1024 * 1024).replace("512 bytes", "4096 bytes");
        let legacy = modern.replace("(logical): 4096", "(logical/physical): 4096/4096");
        let parsed = InstallGeometry::parse(&modern).unwrap();
        assert_eq!(parsed.sector, 4096);
        assert_eq!(InstallGeometry::parse(&legacy).unwrap(), parsed);
        let fresh = parsed.fresh_data();
        assert_eq!(
            (fresh.parts[5].2 - fresh.parts[5].1 + 1) * 4096,
            128 * 1024 * 1024
        );
        assert_eq!(
            parse_layout_bytes("Sector size (logical): 4096 bytes\n1 2048 264191 x\n"),
            Some((264_191 + 34) * 4096)
        );
    }

    #[test]
    fn install_geometry_refuses_missing_duplicate_overlapping_and_overflow_rows() {
        let source = factory_geometry(8192);
        for text in [
            source.replace("512 bytes", "8192 bytes"),
            source
                .lines()
                .filter(|l| !l.starts_with("6 "))
                .collect::<Vec<_>>()
                .join("\n"),
            source.replace("4 26624", "3 26624"),
            source.replace("2 10240", "2 2048"),
            source.replace("1 2048", "1 1"),
            source.replace("51199", "18446744073709551615"),
        ] {
            assert!(
                InstallGeometry::parse(&text).is_err(),
                "accepted invalid geometry: {text}"
            );
        }
    }

    #[test]
    fn install_layout_capacity_arithmetic_never_wraps() {
        assert_eq!(parse_layout_bytes("1 2048 18446744073709551615 x\n"), None);
        assert_eq!(
            parse_layout_bytes("Sector size (logical): 4096 bytes\n1 2048 4503599627370496 x\n"),
            None
        );
    }

    fn disk(name: &str, gib: u64, removable: bool) -> Disk {
        Disk {
            name: name.into(),
            size: gib * 1024 * 1024 * 1024,
            model: String::new(),
            removable,
        }
    }

    #[test]
    fn plan_targets_enforces_count_size_and_removable() {
        let avail = vec![
            disk("sda", 500, false),
            disk("sdb", 500, false),
            disk("usb0", 16, true),
            disk("tiny", 2, false),
        ];
        // Single-disk happy path.
        let p = plan_targets(&avail, &["/dev/sda".into()], Raid::None).unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].name, "sda");
        // Mirror needs 2.
        assert!(plan_targets(&avail, &["sda".into()], Raid::Mirror).is_err());
        let p = plan_targets(&avail, &["sda".into(), "sdb".into()], Raid::Mirror).unwrap();
        assert_eq!(p.len(), 2);
        // Too small / removable / unknown are rejected.
        assert!(plan_targets(&avail, &["tiny".into()], Raid::None).is_err());
        assert!(plan_targets(&avail, &["usb0".into()], Raid::None).is_err());
        assert!(plan_targets(&avail, &["nope".into()], Raid::None).is_err());
        // Non-RAID rejects multiple targets.
        assert!(plan_targets(&avail, &["sda".into(), "sdb".into()], Raid::None).is_err());
    }
}

#[cfg(test)]
mod holder_scope_tests {
    use super::*;
    #[test]
    fn disk_partition_matching_excludes_similarly_named_disks() {
        for (disk, yes, no) in [
            ("sda", "sda12", "sdaa1"),
            ("nvme0n1", "nvme0n1p2", "nvme0n10p2"),
            ("mmcblk0", "mmcblk0p1", "mmcblk01p1"),
        ] {
            assert!(disk_node_matches(disk, disk));
            assert!(disk_node_matches(yes, disk));
            assert!(!disk_node_matches(no, disk));
        }
        assert!(!disk_node_matches("sda", ""));
        assert!(!disk_path_matches("/dev/sdaa1", "/dev/sda"));
        assert!(!disk_path_matches("/different/sda1", "/dev/sda"));
    }
    #[test]
    fn shared_unknown_and_cyclic_holders_are_never_released() {
        let mut graph = std::collections::BTreeMap::from([
            ("sda1", vec![]),
            ("sdb1", vec![]),
            ("dm-local", vec!["sda1"]),
            ("md-shared", vec!["sda1", "sdb1"]),
            ("dm-stack", vec!["dm-local"]),
            ("dm-shared", vec!["md-shared"]),
            ("dm-cycle", vec!["dm-cycle"]),
        ]);
        let query = |name: &str| {
            graph
                .get(name)
                .map(|nodes| nodes.iter().map(|s| (*s).into()).collect())
        };
        assert!(holder_is_confined("dm-local", "sda", &query));
        assert!(holder_is_confined("dm-stack", "sda", &query));
        for name in ["md-shared", "dm-shared", "dm-cycle", "missing"] {
            assert!(!holder_is_confined(name, "sda", &query));
        }
        graph.remove("sda1");
        assert!(!holder_is_confined("dm-local", "sda", &|name| graph
            .get(name)
            .map(|nodes| nodes.iter().map(|s| (*s).into()).collect())));
    }
}
