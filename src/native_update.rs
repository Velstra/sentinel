//! Native provider dispatch and independent readback. No Community RAW fallback.
//! The immutable provider pin selects this engine, never a request or URL.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use anyhow::{Result, ensure};
use serde_json::Value;

use crate::{config::UpdateChannel, install, system, update, update_jobs};

const USR: &str = "8484680c-9521-48c6-9c11-b0720656f69e";
const VERITY: &str = "77ff5f63-e7b6-4633-acf4-1565b864c0e6";

pub(crate) fn stage(
    channel: &UpdateChannel,
    offer: &update::VerifiedOffer,
    hooks: install::UpdateHooks<'_>,
) -> Result<install::StagedImage> {
    let program = option_env!("VELSTRA_ENTERPRISE_UPDATE_BIN")
        .filter(|s| s.starts_with("/nix/store/") && !s.chars().any(char::is_control))
        .ok_or_else(|| anyhow::anyhow!("immutable native update provider unavailable"))?;
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "native updates require root"
    );
    let current = crate::image::current();
    let slot = current
        .slot
        .ok_or_else(|| anyhow::anyhow!("running slot unavailable"))?;
    let version = update::running_version()?;
    update::refuse_downgrade(&offer.manifest.version, false)?;
    let disk = disk()?;
    let before = table(&disk)?;
    validate_table(&before, &disk, slot, &version)?;
    let mut command = Command::new(program);
    command.arg("install-guarded");
    let staged = crate::native_update_protocol::run(command, channel, offer, hooks)?;
    // A terminal provider frame is not independent evidence of disk contents.
    // Re-observe using the parent's pinned tools and read the actual UKI inode.
    ensure!(
        disk == self::disk()?
            && current.slot == crate::image::current().slot
            && current.verity == crate::image::current().verity
            && version == update::running_version()?,
        "running image changed during native staging"
    );
    let after = table(&disk)?;
    validate_readback(&before, &after, slot, &offer.manifest.version, &staged)?;
    let path = Path::new("/boot/EFI/Linux").join(&staged.boot_entry);
    ensure!(
        install::hash_uki(&path)? == staged.uki_sha256,
        "native staged UKI bytes do not match the provider result"
    );
    Ok(staged)
}

fn output(program: &str, args: &[&str]) -> Result<Vec<u8>> {
    let (status, bytes) = update_jobs::probe(program, args, 5)
        .map_err(|_| anyhow::anyhow!("native readback unavailable"))?;
    ensure!(status.success(), "native readback command refused");
    Ok(bytes)
}

fn disk() -> Result<String> {
    let bytes = output(
        &system::bin("lsblk"),
        &["-snpro", "NAME,TYPE", "/dev/mapper/usr"],
    )?;
    let text = std::str::from_utf8(&bytes)?;
    let disks: BTreeSet<_> = text
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.next()?;
            (fields.next()? == "disk" && fields.next().is_none()).then_some(name)
        })
        .collect();
    ensure!(disks.len() == 1, "native boot disk is ambiguous");
    let path = disks.into_iter().next().expect("one disk");
    ensure!(
        path.starts_with("/dev/")
            && path.len() <= 128
            && path[5..]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "invalid native boot disk identity"
    );
    Ok(path.to_string())
}

fn table(disk: &str) -> Result<Value> {
    let bytes = output(&system::bin("sfdisk"), &["--json", disk])?;
    let value: Value = serde_json::from_slice(&bytes)?;
    value
        .get("partitiontable")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("missing native GPT"))
}

fn rows(table: &Value) -> Result<&Vec<Value>> {
    let rows = table
        .get("partitions")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("missing native GPT partitions"))?;
    ensure!(rows.len() == 6, "native GPT must have six partitions");
    Ok(rows)
}

fn pair(slot: &str) -> Result<(usize, usize)> {
    match slot {
        "sentinel-a" => Ok((1, 2)),
        "sentinel-b" => Ok((3, 4)),
        _ => anyhow::bail!("invalid native physical slot"),
    }
}

fn guid(value: &Value) -> Result<String> {
    let guid = value.as_str().unwrap_or("").to_ascii_lowercase();
    ensure!(
        guid.len() == 36
            && guid != "00000000-0000-0000-0000-000000000000"
            && guid
                .bytes()
                .enumerate()
                .all(|(i, b)| if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                }),
        "invalid native partition GUID"
    );
    Ok(guid)
}

fn validate_table(table: &Value, disk: &str, slot: &str, version: &str) -> Result<()> {
    ensure!(
        table["label"] == "gpt" && table["device"] == disk && table["unit"] == "sectors",
        "unsupported native GPT identity"
    );
    let parts = rows(table)?;
    let mut identities = BTreeSet::new();
    for (index, part) in parts.iter().enumerate() {
        let separator = if disk.ends_with(|c: char| c.is_ascii_digit()) {
            "p"
        } else {
            ""
        };
        let expected = format!("{disk}{separator}{}", index + 1);
        ensure!(
            part["node"] == expected
                && part["start"].as_u64().is_some_and(|x| x > 0)
                && part["size"].as_u64().is_some_and(|x| x > 0)
                && identities.insert(guid(&part["uuid"])?),
            "ambiguous native GPT partition"
        );
    }
    for (index, kind) in [(1, VERITY), (2, USR), (3, VERITY), (4, USR)] {
        ensure!(
            parts[index]["type"]
                .as_str()
                .unwrap_or("")
                .eq_ignore_ascii_case(kind),
            "native GPT partition type mismatch"
        );
    }
    let (verity, store) = pair(slot)?;
    ensure!(
        parts[verity]["name"] == format!("sentinel_{version}_verity")
            && parts[store]["name"] == format!("sentinel_{version}"),
        "native GPT running slot mismatch"
    );
    Ok(())
}

fn validate_readback(
    before: &Value,
    after: &Value,
    slot: &str,
    version: &str,
    staged: &install::StagedImage,
) -> Result<()> {
    let inactive = if slot == "sentinel-a" {
        "sentinel-b"
    } else {
        "sentinel-a"
    };
    let (verity, store) = pair(inactive)?;
    ensure!(
        staged.active_slot == slot
            && staged.staged_slot == inactive
            && crate::boot_entry::native_version(version)
            && staged.boot_entry == format!("sentinel_{version}+3-0.efi")
            && update_jobs::is_id(&staged.uki_sha256),
        "invalid native staged identity"
    );
    let mut header_before = before.clone();
    let mut header_after = after.clone();
    header_before
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("invalid GPT header"))?
        .remove("partitions");
    header_after
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("invalid GPT header"))?
        .remove("partitions");
    ensure!(
        header_before == header_after,
        "native update changed the protected GPT header"
    );
    let old = rows(before)?;
    let new = rows(after)?;
    let mut unique = BTreeSet::new();
    for index in 0..6 {
        ensure!(
            unique.insert(guid(&new[index]["uuid"])?),
            "duplicate native partition identity"
        );
        if ![verity, store].contains(&index) {
            ensure!(
                old[index] == new[index],
                "native update changed a protected partition"
            );
        } else {
            let mut protected_before = old[index].clone();
            let mut protected_after = new[index].clone();
            for key in ["uuid", "name", "attrs"] {
                protected_before
                    .as_object_mut()
                    .ok_or_else(|| anyhow::anyhow!("invalid GPT row"))?
                    .remove(key);
                protected_after
                    .as_object_mut()
                    .ok_or_else(|| anyhow::anyhow!("invalid GPT row"))?
                    .remove(key);
            }
            ensure!(
                protected_before == protected_after,
                "native update changed a partition boundary/type"
            );
        }
    }
    let vg = guid(&serde_json::json!(staged.verity_guid))?;
    let sg = guid(&serde_json::json!(staged.store_guid))?;
    let existing = old
        .iter()
        .map(|p| guid(&p["uuid"]))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        !existing.contains(&vg)
            && !existing.contains(&sg)
            && guid(&new[verity]["uuid"])? == vg
            && guid(&new[store]["uuid"])? == sg
            && new[verity]["name"] == format!("sentinel_{version}_verity")
            && new[store]["name"] == format!("sentinel_{version}"),
        "native target readback mismatch"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
