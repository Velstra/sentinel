//! Resolve persistent state through the running verified store, never a label
//! shared by an attached installer or update image.

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;

use crate::{install, system};

pub const DEVICE_LINK: &str = "/run/sentinel-data/device";

#[derive(Debug, PartialEq, Eq)]
pub struct Volume {
    pub base: String,
    pub encrypted: bool,
    pub ready: Option<String>,
}

#[derive(Deserialize)]
struct Devices {
    blockdevices: Vec<Device>,
}

#[derive(Deserialize)]
struct Device {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    fstype: Option<String>,
    #[serde(default)]
    children: Vec<Device>,
}

#[derive(Debug)]
struct WaitingForRaid;

impl std::fmt::Display for WaitingForRaid {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the boot disk's data RAID array has not assembled")
    }
}

impl std::error::Error for WaitingForRaid {}

/// udev/mdadm can still be assembling an owned array during early boot. Only
/// that explicit transient state is retried, with a bounded deadline; other
/// failures never turn into a search for an unrelated labelled volume.
pub fn wait_for_boot_volume() -> Result<Volume> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match boot_volume() {
            Ok(volume) => return Ok(volume),
            Err(error) if error.is::<WaitingForRaid>() && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(150));
            }
            Err(error) => return Err(error),
        }
    }
}

/// The data partition on the disk actually backing /dev/mapper/usr. The
/// forward dependency tree also identifies an assembled RAID array and an
/// already-open LUKS mapping belonging to that partition.
pub fn boot_volume() -> Result<Volume> {
    let disk = install::find_source_disk()?;
    let partition = install::part_path(&disk, install::DATA_PART);
    let out = Command::new(system::bin("lsblk"))
        .args(["--json", "--paths", "--output", "NAME,TYPE", &partition])
        .output()
        .context("examining the boot disk's data partition")?;
    ensure!(
        out.status.success(),
        "could not examine data partition {partition}"
    );
    let mut devices: Devices = serde_json::from_slice(&out.stdout)
        .context("decoding the boot disk's data-device topology")?;
    let [device] = devices.blockdevices.as_mut_slice() else {
        bail!("the boot disk must have exactly one data-partition root");
    };
    probe_types(device)?;
    resolve(device)
}

/// Early boot can precede udev's filesystem-property cache. Probe the selected
/// devices directly instead of mistaking an unpopulated cache for blank state.
fn probe_types(device: &mut Device) -> Result<()> {
    let out = system::escalated_output(
        "blkid",
        &[
            "--probe",
            "--match-tag",
            "TYPE",
            "--output",
            "value",
            "--",
            &device.name,
        ],
    )
    .with_context(|| format!("probing data device {}", device.name))?;
    device.fstype = if out.status.success() {
        let kind = String::from_utf8(out.stdout).context("data filesystem type is not UTF-8")?;
        let kind = kind.trim();
        ensure!(
            !kind.is_empty(),
            "data-device probe returned no filesystem type"
        );
        Some(kind.to_owned())
    } else if out.status.code() == Some(2) && out.stderr.is_empty() {
        None
    } else {
        bail!(
            "cannot probe data device {} (exit {:?})",
            device.name,
            out.status.code()
        );
    };
    for child in &mut device.children {
        probe_types(child)?;
    }
    Ok(())
}

fn resolve(device: &Device) -> Result<Volume> {
    ensure!(
        Path::new(&device.name).starts_with("/dev"),
        "data device is not an absolute device path"
    );
    match device.fstype.as_deref() {
        Some("ext4") => Ok(Volume {
            base: device.name.clone(),
            encrypted: false,
            ready: Some(device.name.clone()),
        }),
        Some("crypto_LUKS") => {
            let mappings: Vec<_> = device
                .children
                .iter()
                .filter(|d| d.kind == "crypt")
                .collect();
            let ready = match mappings.as_slice() {
                [] => None,
                [mapping] => {
                    ensure!(
                        mapping.fstype.as_deref() == Some("ext4"),
                        "unlocked data volume is not ext4"
                    );
                    Some(mapping.name.clone())
                }
                _ => bail!("the boot disk's data volume has multiple unlocked mappings"),
            };
            Ok(Volume {
                base: device.name.clone(),
                encrypted: true,
                ready,
            })
        }
        Some("linux_raid_member") => {
            let arrays: Vec<_> = device
                .children
                .iter()
                .filter(|d| d.kind.starts_with("raid"))
                .collect();
            let array = match arrays.as_slice() {
                [] => return Err(WaitingForRaid.into()),
                [array] => array,
                _ => bail!("the boot disk's data RAID array is ambiguous"),
            };
            resolve(array)
        }
        _ => bail!(
            "data device {} has no supported filesystem or assembled array",
            device.name
        ),
    }
}

/// Publish only after selecting/unlocking the boot-owned volume. Keep the
/// staging directory root-private and replace the link atomically.
pub fn publish(device: &str) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, symlink};

    ensure!(
        std::fs::metadata(device)?.file_type().is_block_device(),
        "data target is not a block device"
    );
    let parent = Path::new(DEVICE_LINK)
        .parent()
        .expect("fixed device-link parent");
    match std::fs::DirBuilder::new().mode(0o700).create(parent) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).context("creating private data-device directory"),
    }
    let metadata = std::fs::symlink_metadata(parent)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "data-device directory is not a protected root-owned directory"
    );
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| anyhow::anyhow!("creating data-device nonce: {error}"))?;
    let temp = parent.join(format!(".device-{:032x}", u128::from_ne_bytes(nonce)));
    symlink(device, &temp).context("staging boot-owned data device")?;
    if let Err(error) = std::fs::rename(&temp, DEVICE_LINK) {
        let _ = std::fs::remove_file(&temp);
        return Err(error).context("publishing boot-owned data device");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn volume(json: &str) -> Result<Volume> {
        resolve(&serde_json::from_str::<Device>(json).unwrap())
    }

    #[test]
    fn plaintext_state_uses_the_boot_partition_directly() {
        assert_eq!(
            volume(r#"{"name":"/dev/vda6","type":"part","fstype":"ext4"}"#).unwrap(),
            Volume {
                base: "/dev/vda6".into(),
                encrypted: false,
                ready: Some("/dev/vda6".into())
            }
        );
    }

    #[test]
    fn locked_state_keeps_its_own_container_identity() {
        assert_eq!(
            volume(r#"{"name":"/dev/nvme0n1p6","type":"part","fstype":"crypto_LUKS"}"#).unwrap(),
            Volume {
                base: "/dev/nvme0n1p6".into(),
                encrypted: true,
                ready: None
            }
        );
    }

    #[test]
    fn already_open_state_is_taken_only_from_the_owned_container() {
        let result = volume(r#"{"name":"/dev/vda6","type":"part","fstype":"crypto_LUKS","children":[{"name":"/dev/mapper/data","type":"crypt","fstype":"ext4"}]}"#).unwrap();
        assert_eq!(result.ready.as_deref(), Some("/dev/mapper/data"));
        assert!(result.encrypted);
    }

    #[test]
    fn raid_state_follows_the_boot_disks_assembled_array() {
        let result = volume(r#"{"name":"/dev/vda6","type":"part","fstype":"linux_raid_member","children":[{"name":"/dev/md127","type":"raid1","fstype":"ext4"}]}"#).unwrap();
        assert_eq!(result.ready.as_deref(), Some("/dev/md127"));
    }

    #[test]
    fn encrypted_raid_keeps_the_array_as_its_container() {
        let result = volume(r#"{"name":"/dev/vda6","type":"part","fstype":"linux_raid_member","children":[{"name":"/dev/md127","type":"raid10","fstype":"crypto_LUKS"}]}"#).unwrap();
        assert_eq!(result.base, "/dev/md127");
        assert!(result.encrypted);
        assert_eq!(result.ready, None);
    }

    #[test]
    fn missing_or_ambiguous_arrays_fail_without_label_fallback() {
        for json in [
            r#"{"name":"/dev/vda6","type":"part","fstype":"linux_raid_member"}"#,
            r#"{"name":"/dev/vda6","type":"part","fstype":"linux_raid_member","children":[{"name":"/dev/md1","type":"raid1","fstype":"ext4"},{"name":"/dev/md2","type":"raid1","fstype":"ext4"}]}"#,
            r#"{"name":"/dev/vda6","type":"part","fstype":null}"#,
            r#"{"name":"relative","type":"part","fstype":"ext4"}"#,
        ] {
            assert!(volume(json).is_err(), "{json}");
        }
    }

    #[test]
    fn only_an_unassembled_owned_array_is_transient() {
        let absent = volume(r#"{"name":"/dev/vda6","type":"part","fstype":"linux_raid_member"}"#)
            .unwrap_err();
        assert!(absent.is::<WaitingForRaid>());
        let unknown = volume(r#"{"name":"/dev/vda6","type":"part","fstype":null}"#).unwrap_err();
        assert!(!unknown.is::<WaitingForRaid>());
    }
}
