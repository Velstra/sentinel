//! Unlocking the encrypted data partition at boot.
//!
//! An encrypted install (`sentinel install --encrypt`) lays the data filesystem
//! inside a LUKS2 volume (see [`crate::install::Crypto`]). Everything writable —
//! the TLS key, config-sync tokens, account hashes, VPN keys — lives there, so
//! the box cannot mount `/var/lib/sentinel` until the volume is open. This is the
//! command a boot-time unit runs, ordered before that mount, to open it.
//!
//! It is deliberately conditional: the SAME image serves encrypted and plaintext
//! installs, so a static "always unlock" would break every unencrypted box. So it
//! looks at what is actually on the disk and does the right thing —
//!
//!   * the data volume is already open → nothing to do;
//!   * there is no LUKS data volume (a plaintext install) → nothing to do, and
//!     the ordinary `/dev/disk/by-label/data` mount takes it from here;
//!   * there IS a locked LUKS data volume → prompt for the passphrase (via
//!     `systemd-ask-password`, so a console operator or a remote
//!     `systemd-tty-ask-password-agent` can answer) and open it.
//!
//! Passphrase-based only, for now: TPM2 unattended unlock is a documented
//! follow-up (`systemd-cryptenroll`), and the on-disk format is standard LUKS2 so
//! a TPM2 token can be enrolled onto the same volume later without reformatting.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::install::{DATA_MAPPER, data_mapper_path};
use crate::system;

/// The filesystem type `lsblk`/`blkid` report for a LUKS container.
const LUKS_FSTYPE: &str = "crypto_LUKS";

/// How many times to re-prompt for a wrong passphrase before giving up. A boot
/// prompt an operator fat-fingers should not drop them straight to a rescue
/// shell, but an endless loop is its own denial of service.
const MAX_ATTEMPTS: u32 = 3;

/// Open the encrypted data volume, prompting for its passphrase — or do nothing
/// if there is no encrypted volume (or it is already open).
///
/// Run by `sentinel-unlock.service` before `/var/lib/sentinel` is mounted, not by
/// hand. Needs root (it drives `cryptsetup`).
pub fn run() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("unlock must run as root (it opens a LUKS volume)");
    }
    if Path::new(&data_mapper_path()).exists() {
        eprintln!("data volume already unlocked");
        return Ok(());
    }
    let Some(dev) = find_luks_data()? else {
        // A plaintext install: the by-label/data mount handles it. Say so plainly
        // rather than looking like a failure.
        eprintln!("no encrypted data volume found — nothing to unlock");
        return Ok(());
    };
    eprintln!("unlocking the encrypted data volume on {dev} …");
    for attempt in 1..=MAX_ATTEMPTS {
        let passphrase = ask_passphrase()?;
        match open(&dev, &passphrase) {
            Ok(()) => {
                eprintln!("data volume unlocked");
                return Ok(());
            }
            Err(e) => eprintln!("attempt {attempt}/{MAX_ATTEMPTS} failed: {e}"),
        }
    }
    bail!("could not unlock the data volume after {MAX_ATTEMPTS} attempts")
}

/// How the data volume is protected at rest, as one line for `show version`.
///
/// The box can be installed either way, and nothing else on the appliance says
/// which — an operator looking at a console could not tell whether the keys,
/// account hashes and TLS material on this machine survive its theft. The
/// answer is derived from the disk every time rather than remembered from the
/// config, because the config is not what decides it: the installer is.
pub fn data_at_rest() -> String {
    match find_luks_data() {
        // The device is present and still a raw crypto_LUKS container, which is
        // what an unlocked volume looks like from the outside: the mapper device
        // is what carries the filesystem, and the container keeps its type.
        Ok(Some(dev)) => format!("LUKS2 encrypted ({dev}) — passphrase asked at boot"),
        Ok(None) => "not encrypted — an install without --encrypt".to_string(),
        // Never guess. Claiming "not encrypted" because lsblk failed would be
        // the more alarming of the two possible lies.
        Err(e) => format!("unknown — {e}"),
    }
}

/// Inspect only the boot disk's data partition and its assembled descendants.
/// Read signatures directly: udev's FSTYPE property may still be absent when
/// the unlock unit starts, even though the LUKS header is already readable.
fn find_luks_data() -> Result<Option<String>> {
    // Ordinary non-image NixOS installations have no appliance data partition.
    // Do not scan or unlock unrelated customer/USB volumes on those hosts.
    if !Path::new("/dev/mapper/usr").exists() {
        return Ok(None);
    }
    let disk = crate::install::find_source_disk()?;
    let partition = crate::install::part_path(&disk, crate::install::DATA_PART);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let out = Command::new(system::bin("lsblk"))
            .args([
                "--properties-by=blkid",
                "--json",
                "--list",
                "--paths",
                "--output",
                "NAME,FSTYPE,TYPE",
                &partition,
            ])
            .output()
            .context("probing the boot disk's data volume")?;
        if !out.status.success() {
            bail!("data volume probe failed (exit {:?})", out.status.code());
        }
        match classify_data_tree(&partition, &out.stdout)? {
            DataVolume::Plain => return Ok(None),
            DataVolume::Encrypted(device) => return Ok(Some(device)),
            DataVolume::AwaitArray if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(200));
            }
            DataVolume::AwaitArray => bail!("boot data RAID array did not assemble within 30s"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum DataVolume {
    Plain,
    Encrypted(String),
    AwaitArray,
}

#[derive(serde::Deserialize)]
struct BlockTree {
    blockdevices: Vec<BlockDevice>,
}

#[derive(serde::Deserialize, PartialEq, Eq)]
struct BlockDevice {
    name: String,
    fstype: Option<String>,
    #[serde(rename = "type")]
    kind: String,
}

fn classify_data_tree(partition: &str, output: &[u8]) -> Result<DataVolume> {
    let tree: BlockTree = serde_json::from_slice(output).context("invalid data volume probe")?;
    let mut devices = BTreeMap::new();
    for device in tree.blockdevices {
        if let Some(previous) = devices.insert(device.name.clone(), device)
            && devices.get(&previous.name) != Some(&previous)
        {
            bail!("inconsistent duplicate data device");
        }
    }
    let root = devices
        .get(partition)
        .ok_or_else(|| anyhow::anyhow!("boot data partition is absent from probe"))?;
    if root.kind != "part" {
        bail!("boot data device is not a partition");
    }
    match root.fstype.as_deref() {
        Some(LUKS_FSTYPE) => return Ok(DataVolume::Encrypted(partition.to_string())),
        Some("ext4") => return Ok(DataVolume::Plain),
        Some("linux_raid_member") => {}
        _ => bail!("boot data partition has no recognized filesystem signature"),
    }
    let arrays: Vec<_> = devices
        .values()
        .filter(|device| matches!(device.kind.as_str(), "raid0" | "raid1" | "raid10"))
        .collect();
    match arrays.as_slice() {
        [] => Ok(DataVolume::AwaitArray),
        [array] => match array.fstype.as_deref() {
            Some(LUKS_FSTYPE) => Ok(DataVolume::Encrypted(array.name.clone())),
            Some("ext4") => Ok(DataVolume::Plain),
            None => Ok(DataVolume::AwaitArray),
            _ => bail!("boot data RAID array has an unsupported filesystem"),
        },
        _ => bail!("multiple arrays depend on the boot data partition"),
    }
}

/// Ask the operator for the passphrase via `systemd-ask-password`, which reaches
/// the console AND any waiting `systemd-tty-ask-password-agent`, so an unattended
/// box can be unlocked over an already-open channel too. Returns the entered
/// passphrase (systemd prints it to stdout).
fn ask_passphrase() -> Result<String> {
    let out = Command::new(system::bin("systemd-ask-password"))
        .args(["--timeout=0", "Unlock the Sentinel data volume:"])
        .output()
        .context("prompting for the LUKS passphrase")?;
    if !out.status.success() {
        bail!("systemd-ask-password failed (exit {:?})", out.status.code());
    }
    // Only the trailing newline is stripped: a passphrase may legitimately begin
    // or end with a space, so nothing else is trimmed.
    let mut pass = String::from_utf8_lossy(&out.stdout).into_owned();
    if pass.ends_with('\n') {
        pass.pop();
        if pass.ends_with('\r') {
            pass.pop();
        }
    }
    Ok(pass)
}

/// `cryptsetup open <dev> data`, passphrase on stdin (never on argv).
fn open(dev: &str, passphrase: &str) -> Result<()> {
    use std::io::Write;
    let mut child = Command::new(system::bin("cryptsetup"))
        .args(["open", "--key-file", "-", dev, DATA_MAPPER])
        .stdin(Stdio::piped())
        .spawn()
        .context("running cryptsetup open")?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("no stdin for cryptsetup"))?
        .write_all(passphrase.as_bytes())
        .context("feeding the passphrase to cryptsetup")?;
    let status = child.wait().context("waiting for cryptsetup")?;
    if !status.success() {
        bail!(
            "cryptsetup open refused the passphrase (exit {:?})",
            status.code()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(rows: serde_json::Value) -> Result<DataVolume> {
        classify_data_tree(
            "/dev/vda6",
            &serde_json::to_vec(&serde_json::json!({"blockdevices":rows})).unwrap(),
        )
    }

    #[test]
    fn direct_boot_partition_signature_does_not_need_a_udev_label() {
        assert_eq!(
            probe(serde_json::json!([{"name":"/dev/vda6","fstype":"crypto_LUKS","type":"part"}]))
                .unwrap(),
            DataVolume::Encrypted("/dev/vda6".into())
        );
    }

    #[test]
    fn plaintext_data_is_not_misreported_as_encrypted_by_another_volume() {
        assert_eq!(
            probe(serde_json::json!([
                {"name":"/dev/vda6","fstype":"ext4","type":"part"},
                {"name":"/dev/foreign","fstype":"crypto_LUKS","type":"crypt"}
            ]))
            .unwrap(),
            DataVolume::Plain
        );
    }

    #[test]
    fn encrypted_assembled_array_is_discovered_and_duplicate_rows_are_deduplicated() {
        assert_eq!(
            probe(serde_json::json!([
                {"name":"/dev/vda6","fstype":"linux_raid_member","type":"part"},
                {"name":"/dev/md127","fstype":"crypto_LUKS","type":"raid1"},
                {"name":"/dev/md127","fstype":"crypto_LUKS","type":"raid1"}
            ]))
            .unwrap(),
            DataVolume::Encrypted("/dev/md127".into())
        );
    }

    #[test]
    fn plaintext_assembled_array_is_recognized() {
        assert_eq!(
            probe(serde_json::json!([
                {"name":"/dev/vda6","fstype":"linux_raid_member","type":"part"},
                {"name":"/dev/md127","fstype":"ext4","type":"raid1"}
            ]))
            .unwrap(),
            DataVolume::Plain
        );
    }

    #[test]
    fn raid_member_without_assembled_filesystem_waits_instead_of_claiming_plaintext() {
        for extra in [
            serde_json::json!([]),
            serde_json::json!([
                {"name":"/dev/md127","fstype":null,"type":"raid1"}
            ]),
        ] {
            let mut rows = vec![
                serde_json::json!({"name":"/dev/vda6","fstype":"linux_raid_member","type":"part"}),
            ];
            rows.extend(extra.as_array().unwrap().iter().cloned());
            assert_eq!(
                probe(serde_json::json!(rows)).unwrap(),
                DataVolume::AwaitArray
            );
        }
    }

    #[test]
    fn absent_or_unreadable_root_signature_never_claims_plaintext() {
        assert!(probe(serde_json::json!([])).is_err());
        assert!(
            probe(serde_json::json!([{"name":"/dev/vda6","fstype":null,"type":"part"}])).is_err()
        );
        assert!(
            probe(serde_json::json!([{"name":"/dev/vda6","fstype":"crypto_LUKS","type":"disk"}]))
                .is_err()
        );
        assert!(classify_data_tree("/dev/vda6", b"not JSON").is_err());
    }

    #[test]
    fn conflicting_signatures_and_multiple_arrays_fail_closed() {
        assert!(
            probe(serde_json::json!([
                {"name":"/dev/vda6","fstype":"ext4","type":"part"},
                {"name":"/dev/vda6","fstype":"crypto_LUKS","type":"part"}
            ]))
            .is_err()
        );
        assert!(
            probe(serde_json::json!([
                {"name":"/dev/vda6","fstype":"linux_raid_member","type":"part"},
                {"name":"/dev/md126","fstype":"ext4","type":"raid1"},
                {"name":"/dev/md127","fstype":"crypto_LUKS","type":"raid1"}
            ]))
            .is_err()
        );
    }
}
