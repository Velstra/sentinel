//! Which image is running.
//!
//! `show version` printed a hand-set number, and a hand-set number does not move
//! when the inputs do. An A/B update that demonstrably replaced the running
//! system — a different slot, a different dm-verity root hash, different store
//! paths for every binary — printed the identical two lines before and after. On
//! a box that updates A/B, "which image am I running?" is the one question that
//! command exists to answer, so the number is now printed beside something
//! derived from the running system itself.
//!
//! Two sources, in descending order of strength:
//!
//!   * The **dm-verity root hash** of `/usr`, which the UKI puts on the kernel
//!     command line as `usrhash=`. The kernel refuses to mount the store unless
//!     every block under it hashes back to that value, so it is image identity
//!     in the strongest sense available here: it changes if and only if a byte
//!     of the image changes. With the slot the store is mounted from, that is
//!     the whole answer.
//!   * The **Nix store path hashes** of the running binaries, for the boots that
//!     have no verity at all — a VM test, the installer medium, a dev build. A
//!     store path hash is a hash of a derivation's inputs, so two builds from
//!     different sources land on different paths. But it identifies those
//!     binaries and not the image around them (a new kernel or a new dnsmasq
//!     moves neither), which is why it is printed as a second, separate line
//!     rather than dressed up as the answer.
//!
//! Everything degrades to "unavailable, and here is why" rather than to a blank
//! or to a plausible-looking default. An identity that quietly prints something
//! wrong is worse than one that admits it does not know: the whole point is that
//! two different images never read the same.

use crate::{install, system};

/// How much of the verity root hash to print. Twelve hex characters is 48 bits
/// — far past any chance of two of this appliance's images colliding — and
/// short enough to read down a phone line as three groups of four. The full
/// hash stays on the kernel command line for anyone comparing byte for byte.
const SHORT_HEX: usize = 12;

/// How much of a Nix store path hash to print. Eight base-32 characters is 40
/// bits, and these are only ever compared against each other on one box.
const SHORT_STORE: usize = 8;

/// The kernel command line, which the UKI stamps with `usrhash=<roothash>`.
const CMDLINE: &str = "/proc/cmdline";

/// The device-mapper node the verity-protected store is mounted from.
const USR_DM: &str = "/dev/mapper/usr";

/// The Nix store path hash is 32 characters of Nix's own base-32 alphabet —
/// `e`, `o`, `t` and `u` are absent so no word forms by accident.
const NIX_BASE32: &str = "0123456789abcdfghijklmnpqrsvwxyz";

/// The identity of the running image, as far as the box can tell.
pub struct Identity {
    /// The dm-verity root hash of `/usr`, lowercase hex, on a verity boot.
    pub verity: Option<String>,
    /// The boot entry name of the slot backing `/usr` (`sentinel-a` /
    /// `sentinel-b`) — the same word systemd-boot shows and `sentinel update`
    /// writes as its default.
    pub slot: Option<&'static str>,
    /// The running binaries and their store path hashes. `None` where a binary
    /// is not a store path (a dev build) or could not be located at all.
    pub binaries: Vec<(&'static str, Option<String>)>,
}

/// Everything the running system will say about which image it is.
pub fn current() -> Identity {
    let cmdline = std::fs::read_to_string(CMDLINE).unwrap_or_default();
    let sentinel = std::env::current_exe()
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    Identity {
        verity: usrhash(&cmdline),
        slot: active_slot(),
        binaries: vec![
            ("sentinel", sentinel.as_deref().and_then(store_hash)),
            ("wren", store_hash(&system::bin("wren"))),
            ("velstra", velstra_exe().as_deref().and_then(store_hash)),
        ],
    }
}

impl Identity {
    /// The `image:` line — what identifies the running image, or why nothing
    /// does.
    pub fn describe(&self) -> String {
        let Some(hash) = &self.verity else {
            return "unidentified — no usrhash= on the kernel command line, so this is not a \
                    verity boot; the binaries below identify themselves, not the image"
                .to_string();
        };
        let slot = match self.slot {
            Some(name) => format!("slot {name}"),
            // The hash still answers "which image"; only "which half of the
            // disk it came from" is missing, and saying which part is unknown
            // beats leaving the reader to guess what the omission meant.
            None => "slot unknown".to_string(),
        };
        format!("{} (dm-verity /usr, {slot})", short(hash, SHORT_HEX))
    }

    /// The `binaries:` line — one store path hash per binary, in a fixed order.
    pub fn binaries_line(&self) -> String {
        self.binaries
            .iter()
            .map(|(name, hash)| match hash {
                Some(h) => format!("{name} {}", short(h, SHORT_STORE)),
                None => format!("{name} (no store path)"),
            })
            .collect::<Vec<_>>()
            .join("  ")
    }
}

/// A hash prefix, or the whole thing when it is already shorter than `n`.
fn short(hash: &str, n: usize) -> String {
    hash.chars().take(n).collect()
}

/// The `usrhash=` value on a kernel command line.
///
/// Validated rather than taken on trust: the command line is a flat string
/// anything can add a word to, and a value that is not a hash at all would be
/// printed as an identity nothing can be compared against. Hex, and at least 32
/// characters — the SHA-256 root hash systemd uses is 64, and a shorter digest
/// would still be a real one.
fn usrhash(cmdline: &str) -> Option<String> {
    let value = cmdline
        .split_ascii_whitespace()
        .find_map(|token| token.strip_prefix("usrhash="))?;
    let plausible = value.len() >= 32 && value.chars().all(|c| c.is_ascii_hexdigit());
    plausible.then(|| value.to_ascii_lowercase())
}

/// The hash component of a Nix store path, given any path inside it.
fn store_hash(path: &str) -> Option<String> {
    let name = path.strip_prefix("/nix/store/")?.split('/').next()?;
    let hash = name.get(..32)?;
    // `-` after the hash is what separates it from the derivation name; without
    // it this is some other 32-character directory that merely lives there.
    if name.as_bytes().get(32) != Some(&b'-') || !hash.chars().all(|c| NIX_BASE32.contains(c)) {
        return None;
    }
    Some(hash.to_string())
}

/// The partition number at the end of a kernel block-device name. `vda3`, `sda3`
/// and `nvme0n1p3` all end in the partition number, whatever precedes it.
fn partition_number(name: &str) -> Option<u32> {
    let digits: Vec<char> = name
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.iter().rev().collect::<String>().parse().ok()
}

/// Which slot a partition number belongs to — either half of the pair, since the
/// verity device is built from the hash partition *and* the store.
fn slot_of_partition(part: u32) -> Option<&'static str> {
    [&install::SLOT_A, &install::SLOT_B]
        .into_iter()
        .find(|slot| part == slot.store_part || part == slot.verity_part)
        .map(|slot| slot.name)
}

/// The slot backing the running `/usr`.
///
/// Walks sysfs rather than running `lsblk` (as [`crate::install`] does, where a
/// tool is already being driven): `show version` has to answer for an operator
/// who is not root and on a box where nothing else has been set up, so it must
/// not depend on a subprocess or on a tool being resolvable. `/dev/mapper/usr`
/// is a symlink to the `dm-N` node, and that node's `slaves` are the partitions
/// the verity device was built from.
fn active_slot() -> Option<&'static str> {
    let node = std::fs::read_link(USR_DM).ok()?;
    let node = node.file_name()?.to_str()?.to_string();
    let slaves = std::fs::read_dir(format!("/sys/class/block/{node}/slaves")).ok()?;
    slaves
        .flatten()
        .filter_map(|e| partition_number(&e.file_name().to_string_lossy()))
        .find_map(slot_of_partition)
}

/// The `velstra` binary the running data plane was started from.
///
/// It has no `SENTINEL_*_BIN` of its own: the agent is started by systemd from
/// the unit's `ExecStart`, so the unit is where its path is written down. That
/// is also the better source — it describes the process that is *running*,
/// rather than one this binary would start if it were asked to.
fn velstra_exe() -> Option<String> {
    let out = std::process::Command::new(system::bin("systemctl"))
        .args(["show", "-p", "ExecStart", "--value", "velstra.service"])
        .output()
        .ok()?;
    exec_start_path(&String::from_utf8_lossy(&out.stdout)).map(str::to_string)
}

/// The executable out of a systemd `ExecStart` property, which systemd prints as
/// `{ path=/nix/store/…/bin/velstra ; argv[]=… ; ignore_errors=no }`.
fn exec_start_path(value: &str) -> Option<&str> {
    value
        .split_whitespace()
        .find_map(|token| token.strip_prefix("path="))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one source that is proof rather than inference, and the shapes that
    /// are not it. A command line is a flat string; `usrhash` has to be the
    /// whole token, not a suffix of somebody else's.
    #[test]
    fn usrhash_is_taken_only_from_a_plausible_token() {
        let hash = "a".repeat(64);
        assert_eq!(
            usrhash(&format!("initrd=\\initrd usrhash={hash} quiet")),
            Some(hash.clone())
        );
        // Upper case is normalised, so the same image never reads two ways.
        assert_eq!(
            usrhash(&format!("usrhash={}", hash.to_uppercase())),
            Some(hash)
        );

        assert_eq!(usrhash("quiet loglevel=4"), None);
        assert_eq!(usrhash("usrhash="), None);
        assert_eq!(usrhash("usrhash=short"), None);
        assert_eq!(usrhash(&format!("usrhash={}", "z".repeat(64))), None);
        // A different option that merely ends in the same letters is not it.
        assert_eq!(usrhash(&format!("myusrhash={}", "a".repeat(64))), None);
    }

    /// The fallback identity: the hash Nix derives from a build's inputs.
    #[test]
    fn store_hash_reads_the_input_hash_and_nothing_else() {
        assert_eq!(
            store_hash("/nix/store/1qxk9v2m3p4r5s6d7f8g9h0j1k2l3m4n-sentinel-0.4.2/bin/sentinel")
                .as_deref(),
            Some("1qxk9v2m3p4r5s6d7f8g9h0j1k2l3m4n")
        );
        // `t` and `u` are not in Nix's alphabet, so a 32-character directory
        // containing them is some other directory that happens to live there.
        assert_eq!(
            store_hash("/nix/store/1qxk9v2m3p4r5s6t7u8v9w0x1y2z3a4b-sentinel-0.4.2/bin/sentinel"),
            None
        );
        // Not a store path at all: an unresolved bare name, or a dev build.
        assert_eq!(store_hash("wren"), None);
        assert_eq!(store_hash("/home/me/target/debug/sentinel"), None);
        // The hash must be followed by the `-name` separator.
        assert_eq!(
            store_hash("/nix/store/1qxk9v2m3p4r5s6d7f8g9h0j1k2l3m4n/bin/x"),
            None
        );
    }

    /// Every disk naming convention the appliance can be installed on ends in
    /// the partition number, and both halves of a slot identify that slot.
    #[test]
    fn a_partition_names_its_slot() {
        assert_eq!(partition_number("vda3"), Some(3));
        assert_eq!(partition_number("sda5"), Some(5));
        assert_eq!(partition_number("nvme0n1p5"), Some(5));
        assert_eq!(partition_number("dm-0"), Some(0));
        assert_eq!(partition_number("loop"), None);

        assert_eq!(slot_of_partition(2), Some("sentinel-a"));
        assert_eq!(slot_of_partition(3), Some("sentinel-a"));
        assert_eq!(slot_of_partition(4), Some("sentinel-b"));
        assert_eq!(slot_of_partition(5), Some("sentinel-b"));
        // The ESP and the data partition belong to neither slot.
        assert_eq!(slot_of_partition(1), None);
        assert_eq!(slot_of_partition(6), None);
    }

    #[test]
    fn exec_start_path_is_the_executable_not_the_arguments() {
        let value = "{ path=/nix/store/aaaa-velstra/bin/velstra ; argv[]=/nix/store/aaaa-velstra/bin/velstra run --iface eth0 ; ignore_errors=no }";
        assert_eq!(
            exec_start_path(value),
            Some("/nix/store/aaaa-velstra/bin/velstra")
        );
        assert_eq!(exec_start_path(""), None);
    }

    /// The line an operator reads aloud: short, and different for different
    /// images.
    #[test]
    fn the_image_line_names_the_hash_and_the_slot() {
        let id = Identity {
            verity: Some("3f8a1c92e7b40d15".repeat(4)),
            slot: Some("sentinel-b"),
            binaries: Vec::new(),
        };
        assert_eq!(
            id.describe(),
            "3f8a1c92e7b4 (dm-verity /usr, slot sentinel-b)"
        );

        // Two images differ in the printed prefix, not only in the full hash.
        let other = Identity {
            verity: Some("00000000000000000000000000000000".to_string()),
            slot: Some("sentinel-b"),
            binaries: Vec::new(),
        };
        assert_ne!(id.describe(), other.describe());

        let no_slot = Identity {
            slot: None,
            ..other
        };
        assert!(
            no_slot.describe().contains("slot unknown"),
            "{}",
            no_slot.describe()
        );
    }

    /// No verity means the box says so, rather than printing a number that
    /// looks like an answer.
    #[test]
    fn without_verity_the_image_line_admits_it() {
        let id = Identity {
            verity: None,
            slot: None,
            binaries: vec![
                (
                    "sentinel",
                    Some("1qxk9v2m3p4r5s6d7f8g9h0j1k2l3m4n".to_string()),
                ),
                ("wren", None),
            ],
        };
        let line = id.describe();
        assert!(line.starts_with("unidentified"), "{line}");
        assert!(line.contains("usrhash="), "{line}");
        assert_eq!(
            id.binaries_line(),
            "sentinel 1qxk9v2m  wren (no store path)"
        );
    }
}
