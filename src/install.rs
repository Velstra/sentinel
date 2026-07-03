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

use anyhow::{Context, Result, bail};

use crate::system;

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

/// The minimum disk size we'll install onto: the sealed store (~1.3 GiB) plus
/// ESP, verity hash, and a usable data partition, with slack.
pub const MIN_TARGET_BYTES: u64 = 4 * 1024 * 1024 * 1024;

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
                "disk {} is removable (the installer medium?) — refusing; \
                 pass it explicitly only if you're sure",
                disk.dev_path()
            );
        }
        chosen.push(disk);
    }
    Ok(chosen)
}

/// The A/B GPT layout: 1=ESP, 2=store-verity-A, 3=store-A, 4=store-verity-B,
/// 5=store-B, 6=data. Data is last so it can grow to fill the disk.
pub const DATA_PART: u32 = 6;
/// Partitions cloned block-for-block on install: the ESP and slot A's verity
/// hash + store. Slot B (4,5) is reserved empty space — its GPT entries are
/// cloned by `--replicate`, and a later `sentinel update` fills it.
pub const SEALED_PARTS: std::ops::RangeInclusive<u32> = 1..=3;

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
fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(system::bin(cmd))
        .args(args)
        .status()
        .with_context(|| format!("running {cmd}"))?;
    if !status.success() {
        bail!("`{cmd} {}` failed (exit {:?})", args.join(" "), status.code());
    }
    Ok(())
}

/// The whole disk holding the running, sealed verity store — i.e. the install
/// medium we clone from. Follows the **active** dm-verity device
/// (`/dev/mapper/usr`) down to its backing disk; a partlabel would be ambiguous
/// once a target has been installed (it copies the same labels).
fn find_source_disk() -> Result<String> {
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
        let _ = Command::new(system::bin("losetup")).args(["-d", &self.0]).status();
    }
}

/// Attach a raw image file as a partitioned loop device, returning its path.
fn losetup_attach(image: &std::path::Path) -> Result<String> {
    let img = image.to_str().ok_or_else(|| anyhow::anyhow!("non-UTF-8 image path"))?;
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
pub fn execute(targets: &[&Disk], raid: Raid, source_image: Option<&std::path::Path>) -> Result<()> {
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

    // From here on disks are being erased. Track which, so a mid-way failure
    // reports exactly which disks are left blank (none are recoverable once
    // wipefs has run — but the operator must know which to re-install).
    let mut erased: Vec<String> = Vec::new();
    for t in targets {
        let dev = t.dev_path();
        eprintln!("preparing {dev} (ERASING) …");
        erased.push(dev.clone());
        if let Err(e) = prepare_disk(&source, &dev, raid) {
            return Err(partial_install_error(e, &erased));
        }
    }

    let data_parts: Vec<String> =
        targets.iter().map(|t| part_path(&t.dev_path(), DATA_PART)).collect();
    // Build the data filesystem (or RAID array). A failure here leaves every
    // erased disk partitioned but without a bootable system — report which.
    let fs_result: Result<()> = (|| {
        match raid.mdadm_level() {
            None => {
                run("mkfs.ext4", &["-q", "-F", "-L", "data", &data_parts[0]])?;
            }
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
                run("mkfs.ext4", &["-q", "-F", "-L", "data", "/dev/md/sentinel-data"])?;
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

/// Lay the image's A/B partition layout onto `target` and clone the sealed
/// partitions block-for-block from `source`. The data partition (the last one)
/// is recreated to fill the target, typed for a filesystem or a RAID member.
fn prepare_disk(source: &str, target: &str, raid: Raid) -> Result<()> {
    run("wipefs", &["-a", target])?;
    // Replicate the source GPT onto the target (`--replicate=<dest>` takes the
    // DESTINATION; the source is the positional device), then move the backup
    // header to the end of the (larger) target. This also lays down the (empty)
    // slot-B partition entries for later updates.
    run("sgdisk", &[&format!("--replicate={target}"), source])?;
    run("sgdisk", &["--move-second-header", target])?;
    // Give the disk a fresh **disk** GUID so it doesn't collide with the source
    // medium — but do NOT randomize the *partition* GUIDs. The dm-verity store
    // relies on the systemd Discoverable Partitions convention: the verity and
    // store partition UUIDs are derived from the roothash (no explicit
    // `usrhash=` on the kernel cmdline), so systemd auto-binds `/dev/mapper/usr`
    // by matching them at boot. `sgdisk --randomize-guids` would overwrite those
    // roothash-derived UUIDs, so the installed system could never activate the
    // verity device — it would time out waiting for `/dev/mapper/usr` and drop to
    // emergency mode (while a directly-booted image, with the UUIDs intact, works
    // fine). `--disk-guid=R` randomizes only the disk GUID and leaves every
    // partition UUID as replicated. The data partition below is recreated and so
    // gets its own fresh UUID regardless.
    run("sgdisk", &["--disk-guid=R", target])?;
    // Recreate the data partition to fill the disk, typed for the install mode.
    let typecode = if raid.mdadm_level().is_some() {
        "FD00" // Linux RAID
    } else {
        "8300" // Linux filesystem
    };
    run("sgdisk", &[&format!("--delete={DATA_PART}"), target])?;
    run(
        "sgdisk",
        &[
            &format!("--new={DATA_PART}:0:0"),
            &format!("--typecode={DATA_PART}:{typecode}"),
            &format!("--change-name={DATA_PART}:data"),
            target,
        ],
    )?;
    run("partprobe", &[target]).ok();
    run("udevadm", &["settle"]).ok();
    // Clone the sealed partitions (ESP/UKI + slot A's verity hash + store).
    // Slot B (the reserved generic partitions) is left empty for a future update.
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
struct Slot {
    name: &'static str,
    verity_part: u32,
    store_part: u32,
}
const SLOT_A: Slot = Slot { name: "sentinel-a", verity_part: 2, store_part: 3 };
const SLOT_B: Slot = Slot { name: "sentinel-b", verity_part: 4, store_part: 5 };

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

/// A/B update: write `image`'s sealed store into the INACTIVE slot, then make
/// systemd-boot try it next (it rolls back to the current slot if the new one
/// fails 3 boots). `image` may be a raw image file (loop-mounted) or a block
/// device (used directly — e.g. the booted medium, for a re-seal). DESTRUCTIVE
/// to the inactive slot only; the running slot is untouched.
pub fn update(image: &std::path::Path, commit: bool) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;

    if unsafe { libc::geteuid() } != 0 {
        bail!("update must run as root (try `sudo sentinel update …`)");
    }
    let disk = find_source_disk()?;
    let active = active_slot(&disk)?;
    let inactive = if active.name == SLOT_A.name { &SLOT_B } else { &SLOT_A };
    eprintln!(
        "active slot: {} — updating inactive slot {} on {disk}",
        active.name, inactive.name
    );
    if !commit {
        eprintln!(
            "(dry-run — re-run with --commit to write slot {} and switch the boot default)",
            inactive.name
        );
        return Ok(());
    }

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
    // the initrd's veritysetup considers them.
    run(
        "sgdisk",
        &[
            &format!("--typecode={}:{USR_VERITY_TYPE}", inactive.verity_part),
            &format!("--typecode={}:{USR_TYPE}", inactive.store_part),
            &disk,
        ],
    )?;
    run("partprobe", &[&disk]).ok();
    run("udevadm", &["settle"]).ok();

    switch_boot(&disk, &srcdev, active, inactive)?;
    eprintln!(
        "update complete — reboot to boot slot {} (auto-rolls back to {} if it fails 3×)",
        inactive.name, active.name
    );
    Ok(())
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

/// Install the source image's UKI onto the running ESP as the inactive slot's
/// boot-counted entry (`<slot>+3.efi`) and point loader.conf's default at it.
fn switch_boot(disk: &str, srcdev: &str, active: &Slot, inactive: &Slot) -> Result<()> {
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
    let (src, _sg): (std::path::PathBuf, Option<MountGuard>) = if srcdev == disk {
        (dst.clone(), None)
    } else {
        let p = std::path::PathBuf::from("/run/sentinel/upd-src");
        std::fs::create_dir_all(&p)?;
        run("mount", &["-o", "ro", &part_path(srcdev, 1), p.to_str().unwrap()])?;
        (p.clone(), Some(MountGuard(p)))
    };

    // The source UKI: for a self-reseal pick the active slot's entry; for a
    // separate image there's exactly one UKI in its /EFI/Linux.
    let want = if srcdev == disk { Some(active.name) } else { None };
    let uki = std::fs::read_dir(src.join("EFI/Linux"))?
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            p.extension().is_some_and(|x| x == "efi")
                && want.is_none_or(|n| {
                    p.file_name().is_some_and(|f| f.to_string_lossy().starts_with(n))
                })
        })
        .ok_or_else(|| anyhow::anyhow!("no UKI in the source ESP"))?;

    let lin = dst.join("EFI/Linux");
    std::fs::create_dir_all(&lin)?;
    // Replace any prior entry for this slot, then install the new one with 3 tries.
    for e in std::fs::read_dir(&lin)?.flatten() {
        if e.file_name().to_string_lossy().starts_with(inactive.name) {
            std::fs::remove_file(e.path())?;
        }
    }
    std::fs::copy(&uki, lin.join(format!("{}+3.efi", inactive.name)))?;

    // Point the boot default at the new slot (a glob, so it keeps matching after
    // a successful boot blesses the entry and strips the `+N` counter).
    let conf = dst.join("loader/loader.conf");
    let mut out = String::new();
    let mut replaced = false;
    for line in std::fs::read_to_string(&conf).unwrap_or_default().lines() {
        if line.trim_start().starts_with("default") {
            out.push_str(&format!("default {}*\n", inactive.name));
            replaced = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !replaced {
        out.push_str(&format!("default {}*\n", inactive.name));
    }
    std::fs::write(&conf, out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_and_inactive_slots_are_distinct() {
        assert_ne!(SLOT_A.name, SLOT_B.name);
        assert_eq!((SLOT_A.verity_part, SLOT_A.store_part), (2, 3));
        assert_eq!((SLOT_B.verity_part, SLOT_B.store_part), (4, 5));
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
