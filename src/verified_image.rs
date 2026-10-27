//! An update image that is trusted only in the bytes this process read.
//!
//! The local update path used to verify an image by path and then hand the same
//! path to `losetup`, `dd` and `mount`, each of which opened it again. Whatever
//! sat at that path in between — a file rewritten by its owner, a USB stick
//! swapped in the port — was what got written to the slot, verified or not.
//!
//! Here the image is opened once. A first pass hashes every byte against the
//! signed digest and, from the same bytes, reads the GPT: where the ESP and the
//! slot-A verity/store partitions are and which GUIDs they carry. Nothing is
//! written until that pass has matched. The second pass copies only those three
//! partitions, from the same open file, hashing each again and comparing with
//! what the first pass saw — so a source that changes after it was verified is
//! caught before the slot is re-typed or the boot default moves. The GUIDs the
//! slot is stamped with come from the verified first pass, never from a second
//! look at the source.
//!
//! A block device has no length of its own that means anything: a stick is
//! larger than the image `dd`'d onto it. The image's own primary GPT header
//! names its last sector (the backup header's LBA), which is exactly the length
//! of the raw image file; that header is untrusted until the hash matches, but
//! a header that lies about the length simply produces a different digest.

use std::fs::File;
use std::os::unix::fs::{FileExt, FileTypeExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use ring::digest;

/// The appliance image's logical sector size (`image.repart.sectorSize`).
const SECTOR: u64 = 512;
/// How much of the start of the image the partition table must fit in.
const HEAD: u64 = 1 << 20;
/// Read/write granularity.
const CHUNK: usize = 4 << 20;
/// The partitions an update takes from the image: the ESP (for its UKI) and
/// slot A's verity hash and store (see `install::SLOT_A`).
const USED: [u32; 3] = [1, 2, 3];

/// One partition of the verified image.
struct Part {
    number: u32,
    offset: u64,
    len: u64,
    guid: String,
    sha256: Vec<u8>,
}

/// An opened, hashed, digest-matched image.
pub struct VerifiedImage {
    file: File,
    path: PathBuf,
    parts: Vec<Part>,
}

impl VerifiedImage {
    /// Open `path` and accept it only if its bytes hash to `sha256` (hex).
    pub fn open(path: &Path, sha256: &str) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let is_block = file.metadata()?.file_type().is_block_device();
        let size = if is_block {
            use std::io::{Seek, SeekFrom};
            (&file).seek(SeekFrom::End(0))?
        } else {
            file.metadata()?.len()
        };
        let mut head = vec![0u8; HEAD.min(size) as usize];
        file.read_exact_at(&mut head, 0)
            .with_context(|| format!("reading {}", path.display()))?;
        let (last_lba, table) = parse_gpt(&head)?;
        let len = image_len(is_block, size, last_lba)
            .with_context(|| format!("sizing the image on {}", path.display()))?;
        let mut parts = Vec::new();
        for number in USED {
            let (offset, end, guid) = table
                .iter()
                .find(|(n, ..)| *n == number)
                .map(|(_, first, last, guid)| (*first * SECTOR, (*last + 1) * SECTOR, guid))
                .with_context(|| format!("the image has no partition {number}"))?;
            ensure!(
                offset < end && end <= len,
                "image partition {number} lies outside the image"
            );
            parts.push(Part {
                number,
                offset,
                len: end - offset,
                guid: guid.clone(),
                sha256: Vec::new(),
            });
        }

        // Pass 1: the whole image, and each used partition's share of it.
        let mut whole = digest::Context::new(&digest::SHA256);
        let mut each: Vec<_> = parts
            .iter()
            .map(|_| digest::Context::new(&digest::SHA256))
            .collect();
        let mut buf = vec![0u8; CHUNK];
        let mut at = 0u64;
        while at < len {
            let n = (len - at).min(CHUNK as u64) as usize;
            file.read_exact_at(&mut buf[..n], at)
                .with_context(|| format!("reading {} at byte {at}", path.display()))?;
            whole.update(&buf[..n]);
            for (part, ctx) in parts.iter().zip(each.iter_mut()) {
                let from = part.offset.max(at);
                let to = (part.offset + part.len).min(at + n as u64);
                if from < to {
                    ctx.update(&buf[(from - at) as usize..(to - at) as usize]);
                }
            }
            at += n as u64;
        }
        let got = hex(whole.finish().as_ref());
        if !got.eq_ignore_ascii_case(sha256.trim()) {
            bail!(
                "image does not match its signed SHA-256 digest (signed {}, image {got}) — \
                 refusing the update; nothing was written",
                sha256.trim()
            );
        }
        for (part, ctx) in parts.iter_mut().zip(each) {
            part.sha256 = ctx.finish().as_ref().to_vec();
        }
        Ok(Self {
            file,
            path: path.to_path_buf(),
            parts,
        })
    }

    fn part(&self, number: u32) -> &Part {
        self.parts
            .iter()
            .find(|p| p.number == number)
            .expect("only the partitions in USED are asked for")
    }

    /// The verified GPT unique GUID of partition `number` (upper-case, as
    /// `sgdisk` prints it).
    pub fn guid(&self, number: u32) -> &str {
        &self.part(number).guid
    }

    /// The size in bytes of partition `number`.
    pub fn len(&self, number: u32) -> u64 {
        self.part(number).len
    }

    /// Pass 2: copy partition `number` into `dest` from the same open file,
    /// and refuse if the bytes are not the ones pass 1 hashed.
    pub fn copy_partition(&self, number: u32, dest: &mut File) -> Result<()> {
        use std::io::Write;
        let part = self.part(number);
        let mut ctx = digest::Context::new(&digest::SHA256);
        let mut buf = vec![0u8; CHUNK];
        let mut done = 0u64;
        while done < part.len {
            let n = (part.len - done).min(CHUNK as u64) as usize;
            self.file
                .read_exact_at(&mut buf[..n], part.offset + done)
                .with_context(|| format!("reading {}", self.path.display()))?;
            ctx.update(&buf[..n]);
            dest.write_all(&buf[..n])?;
            done += n as u64;
        }
        dest.sync_all()?;
        ensure!(
            ctx.finish().as_ref() == part.sha256.as_slice(),
            "{} changed after it was verified (partition {number} no longer matches) — \
             refusing to activate what was copied",
            self.path.display()
        );
        Ok(())
    }
}

/// How many bytes of the source are the image: all of a regular file (the
/// signed digest covers the file as published), and of a block device the
/// span its own GPT describes, up to and including the backup header.
fn image_len(is_block: bool, size: u64, last_lba: u64) -> Result<u64> {
    let len = if is_block {
        last_lba
            .checked_add(1)
            .and_then(|n| n.checked_mul(SECTOR))
            .context("the image GPT names an impossible length")?
    } else {
        size
    };
    ensure!(
        len <= size,
        "the source is shorter than the image its partition table describes"
    );
    Ok(len)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

/// A GPT GUID in its text form: the first three fields are stored
/// little-endian, the last two as bytes.
fn guid_text(b: &[u8]) -> String {
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{}",
        le32(b, 0),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8],
        b[9],
        b[10..16]
            .iter()
            .map(|x| format!("{x:02X}"))
            .collect::<String>()
    )
}

/// Parse the primary GPT from the start of an image: the backup header's LBA
/// (the image's last sector) and each used entry as (number, first LBA, last
/// LBA, unique GUID). Bounds are checked; integrity is not — the caller trusts
/// none of this until the whole image has matched its signed digest.
#[allow(clippy::type_complexity)]
fn parse_gpt(head: &[u8]) -> Result<(u64, Vec<(u32, u64, u64, String)>)> {
    let h = SECTOR as usize;
    ensure!(
        head.len() >= 2 * h && &head[h..h + 8] == b"EFI PART",
        "not a GPT disk image (no EFI PART header at sector 1)"
    );
    let last_lba = le64(head, h + 32);
    let entries_lba = le64(head, h + 72);
    let count = le32(head, h + 80) as u64;
    let size = le32(head, h + 84) as u64;
    ensure!(
        size >= 128 && count <= 1024,
        "implausible GPT partition entry array"
    );
    let start = entries_lba
        .checked_mul(SECTOR)
        .context("implausible GPT entry location")?;
    let end = start
        .checked_add(count * size)
        .filter(|end| *end <= head.len() as u64)
        .context("the GPT partition entries are not at the start of the image")?;
    let mut parts = Vec::new();
    for (index, entry) in head[start as usize..end as usize]
        .chunks_exact(size as usize)
        .enumerate()
    {
        if entry[..16].iter().all(|b| *b == 0) {
            continue;
        }
        let (first, last) = (le64(entry, 32), le64(entry, 40));
        ensure!(first <= last, "GPT entry {} is inverted", index + 1);
        parts.push((index as u32 + 1, first, last, guid_text(&entry[16..32])));
    }
    Ok((last_lba, parts))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny GPT image: header at LBA 1, entries at LBA 2, three partitions
    /// of `sectors` each starting at LBA 34, backup header at the last LBA.
    fn image(sectors: u64) -> Vec<u8> {
        let last = 34 + 3 * sectors + 33;
        let mut img = vec![0u8; ((last + 1) * SECTOR) as usize];
        let h = SECTOR as usize;
        img[h..h + 8].copy_from_slice(b"EFI PART");
        img[h + 32..h + 40].copy_from_slice(&last.to_le_bytes());
        img[h + 72..h + 80].copy_from_slice(&2u64.to_le_bytes());
        img[h + 80..h + 84].copy_from_slice(&128u32.to_le_bytes());
        img[h + 84..h + 88].copy_from_slice(&128u32.to_le_bytes());
        for i in 0..3u64 {
            let e = (2 * SECTOR + i * 128) as usize;
            img[e] = 0xAF; // any non-zero type GUID marks the entry used
            for (k, b) in img[e + 16..e + 32].iter_mut().enumerate() {
                *b = (i as u8 + 1) * 0x10 + k as u8;
            }
            let first = 34 + i * sectors;
            img[e + 32..e + 40].copy_from_slice(&first.to_le_bytes());
            img[e + 40..e + 48].copy_from_slice(&(first + sectors - 1).to_le_bytes());
            let data = (first * SECTOR) as usize..((first + sectors) * SECTOR) as usize;
            img[data].fill(b'a' + i as u8);
        }
        img
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex(digest::digest(&digest::SHA256, bytes).as_ref())
    }

    fn scratch() -> crate::update::Scratch {
        crate::update::Scratch::new().unwrap()
    }

    /// A stick is bigger than the image on it: a device is read up to the
    /// image's own backup header, a file in full, and a table that claims more
    /// than the source holds is refused.
    #[test]
    fn a_device_is_read_to_the_end_of_its_image_not_of_the_stick() {
        assert_eq!(image_len(true, 32 << 30, 99).unwrap(), 100 * SECTOR);
        assert_eq!(image_len(false, 12345, 99).unwrap(), 12345);
        assert!(image_len(true, 50 * SECTOR, 99).is_err());
        assert!(image_len(true, u64::MAX, u64::MAX).is_err());
    }

    #[test]
    fn gpt_guids_are_rendered_mixed_endian_like_sgdisk() {
        let raw: Vec<u8> = (0u8..16).collect();
        assert_eq!(guid_text(&raw), "03020100-0504-0706-0809-0A0B0C0D0E0F");
    }

    #[test]
    fn a_matching_image_yields_its_partitions_and_copies_them_exactly() {
        let dir = scratch();
        let path = dir.join("image.raw");
        let bytes = image(8);
        std::fs::write(&path, &bytes).unwrap();
        let verified = VerifiedImage::open(&path, &sha256_hex(&bytes)).unwrap();
        assert_eq!(verified.len(3), 8 * SECTOR);
        assert_eq!(verified.guid(2), "23222120-2524-2726-2829-2A2B2C2D2E2F");
        let out_path = dir.join("store");
        let mut out = dir.create_private("store").unwrap();
        verified.copy_partition(3, &mut out).unwrap();
        assert_eq!(std::fs::read(out_path).unwrap(), vec![b'c'; 8 * 512]);
    }

    #[test]
    fn a_mismatched_image_is_refused_before_anything_is_copied() {
        let dir = scratch();
        let path = dir.join("image.raw");
        let mut bytes = image(8);
        let signed = sha256_hex(&bytes);
        let last = bytes.len() - 1;
        bytes[last] ^= 1; // outside every partition: the whole image is signed
        std::fs::write(&path, &bytes).unwrap();
        let error = VerifiedImage::open(&path, &signed).err().unwrap();
        assert!(error.to_string().contains("does not match"), "{error:#}");
        std::fs::write(&path, b"no partition table at all").unwrap();
        assert!(VerifiedImage::open(&path, &signed).is_err());
    }

    /// The TOCTOU this module exists for: the source is rewritten after it was
    /// verified. The copy is refused, because the bytes it read are not the
    /// bytes the signature vouched for.
    #[test]
    fn a_source_rewritten_after_verification_is_refused() {
        let dir = scratch();
        let path = dir.join("image.raw");
        let bytes = image(8);
        std::fs::write(&path, &bytes).unwrap();
        let verified = VerifiedImage::open(&path, &sha256_hex(&bytes)).unwrap();
        let swapped = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        swapped
            .write_all_at(b"evil", 34 * SECTOR + 8 * SECTOR)
            .unwrap();
        let mut out = dir.create_private("verity").unwrap();
        let error = verified.copy_partition(2, &mut out).unwrap_err();
        assert!(
            error.to_string().contains("changed after it was verified"),
            "{error:#}"
        );
        // Partitions that were not touched still copy.
        let mut esp = dir.create_private("esp").unwrap();
        verified.copy_partition(1, &mut esp).unwrap();
    }
}
