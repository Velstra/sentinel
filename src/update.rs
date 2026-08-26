//! Signed update channel (roadmap C13): the authenticity gate that sits in front
//! of the existing A/B slot-writer ([`crate::install::update`]).
//!
//! `sentinel update <image>` writes ANY image into the inactive slot with no
//! signature check — that is the supply-chain hole this module closes. Before an
//! image from a remote channel is ever handed to the slot-writer, we:
//!
//!   1. fetch a signed release **manifest** (`manifest.json`) plus its detached
//!      signature (`manifest.json.sig`),
//!   2. verify that signature is a valid Ed25519 signature over the *exact* bytes
//!      of `manifest.json` under the operator-**pinned** public key, and only
//!      then trust the version + image name + digest the manifest carries,
//!   3. fetch the named image and verify its SHA-256 equals the digest the (now
//!      trusted) manifest names.
//!
//! Every step FAILS CLOSED: any fetch error, missing/short/garbled file, wrong
//! key, bad signature, or digest mismatch returns `Err`, and the slot-write is
//! never reached — see [`crate::install::update_from_channel`], where the call to
//! the writer sits strictly *after* both [`check`] and [`fetch_verified_image`]
//! have returned `Ok`.
//!
//! Crypto is done by the pinned `openssl` (the same binary [`crate::pki`] uses,
//! resolved via [`crate::system::bin`]): Ed25519 `pkeyutl -verify -rawin` and
//! `dgst -sha256`. Fetching is `curl -fsSL` — `-f` turns an HTTP 404 (or a
//! missing `file://` path) into a non-zero exit, i.e. a refusal. No untrusted
//! manifest field is ever interpolated into a URL path beyond a validated image
//! basename.

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::config::UpdateChannel;
use crate::system;

/// A signed release manifest: the small JSON document, signed by the pinned key,
/// that names the release and the exact image to write. Unknown fields are
/// ignored so the manifest can gain fields without breaking older appliances.
#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    /// Human-readable release version, e.g. `"0.3.0"` — shown to the operator.
    pub version: String,
    /// The image file's basename within the channel directory (never a path).
    pub image: String,
    /// Lowercase hex SHA-256 of the image file (an optional `sha256:` prefix is
    /// tolerated). The fetched image must hash to exactly this.
    pub sha256: String,
}

// ---- scratch storage ------------------------------------------------------

static SCRATCH_SEQ: AtomicU64 = AtomicU64::new(0);

/// A private temp directory that removes itself (and everything under it) on
/// drop. Used to stage the fetched manifest/signature/pinned-key and, for a
/// channel install, the verified image. Public so [`crate::install`] can own the
/// image's scratch dir for the lifetime of the slot-write.
pub struct Scratch(std::path::PathBuf);

impl Scratch {
    /// Create a fresh, uniquely-named scratch dir under the system temp dir.
    pub fn new() -> Result<Self> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "sentinel-update-{}-{nanos}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&p).with_context(|| format!("creating {}", p.display()))?;
        Ok(Self(p))
    }

    /// A path to `name` inside this scratch dir.
    pub fn join(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---- helpers --------------------------------------------------------------

/// The channel base URL with any trailing slash removed, so known filenames can
/// be appended with a single `/`.
fn base_url(chan: &UpdateChannel) -> &str {
    chan.url.trim_end_matches('/')
}

/// A manifest-named image must be a plain basename living directly in the channel
/// directory — never a path that could climb out of it or point elsewhere. This
/// is the one untrusted field we append to a URL, so it is validated hard.
fn valid_image_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains("..")
}

/// Normalise a digest for comparison: strip an optional `sha256:` prefix and
/// lowercase it. (The comparison itself is an exact hex-string match.)
fn norm_digest(d: &str) -> String {
    d.trim()
        .trim_start_matches("sha256:")
        .trim()
        .to_ascii_lowercase()
}

/// A UTF-8 view of a path for passing to an external tool (our scratch paths are
/// always UTF-8; a non-UTF-8 path is a hard error rather than lossy).
fn s(p: &Path) -> Result<&str> {
    p.to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF-8 path {}", p.display()))
}

/// The pinned `curl`: the Nix wrapper sets `SENTINEL_CURL_BIN` to an absolute
/// store path (so neither `$PATH` nor sudo's `secure_path` can shadow it);
/// off-box (dev/tests) it falls back to the bare name.
fn curl_bin() -> String {
    std::env::var("SENTINEL_CURL_BIN")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "curl".to_string())
}

/// The pinned `openssl` (same resolution as the PKI path).
fn openssl_bin() -> String {
    system::bin("openssl")
}

/// Fetch `url` to `dest` with `curl -fsSL`. `-f` makes an HTTP error (or a
/// missing `file://` path) a non-zero exit; `--proto =https,file` refuses any
/// other scheme even across a redirect. Any failure bails — fetch is fail-closed.
///
/// A channel with a `subscription-key` sends it as `Authorization: Bearer` on
/// every request. The header travels via a 0600 file (`-H @file`), never on the
/// command line — argv is world-readable through /proc for as long as curl
/// runs, and a secret must not be.
fn fetch(chan: &UpdateChannel, url: &str, dest: &Path) -> Result<()> {
    let scratch = Scratch::new()?;
    let mut cmd = Command::new(curl_bin());
    cmd.args([
        "-fsSL",
        "--proto",
        "=https,file",
        "--proto-redir",
        "=https,file",
        // The HTTP status, on stdout after the (empty, `-o`-redirected) body —
        // it is what tells an entitlement refusal apart from a broken mirror.
        "-w",
        "%{http_code}",
        "-o",
        s(dest)?,
        url,
    ]);
    if let Some(key) = &chan.subscription_key {
        let hdr = scratch.join("auth-header");
        std::fs::write(&hdr, format!("Authorization: Bearer {key}\n"))
            .context("staging the subscription header")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&hdr, std::fs::Permissions::from_mode(0o600))
                .context("tightening the subscription header file")?;
        }
        cmd.args(["-H", &format!("@{}", s(&hdr)?)]);
    }
    let out = cmd
        .output()
        .with_context(|| format!("running curl for {url}"))?;
    if out.status.success() {
        return Ok(());
    }
    let code: Option<u32> = String::from_utf8_lossy(&out.stdout)
        .trim()
        .rsplit(|c: char| !c.is_ascii_digit())
        .next()
        .and_then(|t| t.parse().ok())
        .filter(|c| *c >= 100);
    // PRODUCT COMMITMENT, not an implementation detail: an expired or rejected
    // subscription must never brick, degrade or nag-block the appliance. This
    // function only ever *reads*; on any refusal the box keeps routing, keeps
    // filtering, keeps its configuration — the one and only consequence is that
    // new images from this channel are unavailable, and the error says so. No
    // retry timer, no phone-home, nothing on the box is disabled.
    if let Some(code @ (401 | 403)) = code {
        let name = chan.label();
        if chan.subscription_key.is_some() {
            bail!(
                "channel {name:?}: this subscription is not valid for this channel \
                 (HTTP {code}). The appliance keeps running unchanged — only new images \
                 from this channel are unavailable. Renew the subscription with your \
                 vendor, or correct the key (set update channel {name} subscription-key \
                 <key>, commit, save) and run `sentinel update check` again."
            );
        }
        // The unnamed default channel cannot carry a key — the fix there is to
        // move onto a named channel, and saying `set update channel default …`
        // would name a command that does not exist.
        let fix = match &chan.name {
            Some(n) => format!(
                "Add the key with `set update channel {n} subscription-key <key>`"
            ),
            None => "Define a named channel carrying the key (set update channel <name> \
                     url/public-key/subscription-key …) and select it"
                .to_string(),
        };
        bail!(
            "channel {name:?} requires a subscription (HTTP {code}) and none is \
             configured. The appliance keeps running unchanged — only new images from \
             this channel are unavailable. {fix}, commit, save, then run \
             `sentinel update check`."
        );
    }
    bail!(
        "fetch of {url} failed (curl exit {:?}{})",
        out.status.code(),
        code.map(|c| format!(", HTTP {c}")).unwrap_or_default()
    );
}

/// Resolve the pinned public key to a PEM file on disk: a `file:<path>` value is
/// read from that path, an inline value is the PEM itself. Either way it is
/// re-staged into `scratch` (and sanity-checked to be a PEM public key) so the
/// verify call has a single, known input.
fn resolve_pubkey(chan: &UpdateChannel, scratch: &Scratch) -> Result<std::path::PathBuf> {
    resolve_pubkey_pem(&chan.public_key, scratch)
}

/// The value-level form of [`resolve_pubkey`]: stage `public_key` (a `file:<path>`
/// reference or an inline PEM) as a PEM file in `scratch`. Shared by the channel
/// path and the local-image path so both accept a pinned key the same way.
pub fn resolve_pubkey_pem(public_key: &str, scratch: &Scratch) -> Result<std::path::PathBuf> {
    let pem = if let Some(path) = public_key.strip_prefix("file:") {
        std::fs::read_to_string(path)
            .with_context(|| format!("reading pinned update public key from {path}"))?
    } else {
        public_key.to_string()
    };
    if !pem.contains("BEGIN PUBLIC KEY") {
        bail!("pinned update public-key is not a PEM public key (-----BEGIN PUBLIC KEY-----)");
    }
    let dst = scratch.join("pinned-pub.pem");
    std::fs::write(&dst, pem).context("staging the pinned public key")?;
    Ok(dst)
}

/// Verify the detached Ed25519 signature `sig` over `manifest` under `pubkey`.
/// Ed25519 signs the raw message (no pre-hash), so `-rawin` is required (openssl
/// 3.x). Exit 0 == verified; anything else is a refusal.
pub fn verify_signature(pubkey: &Path, manifest: &Path, sig: &Path) -> Result<()> {
    let ok = Command::new(openssl_bin())
        .args([
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            s(pubkey)?,
            "-rawin",
            "-in",
            s(manifest)?,
            "-sigfile",
            s(sig)?,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("running openssl pkeyutl -verify")?
        .success();
    if !ok {
        bail!(
            "manifest signature verification FAILED — the release manifest is not signed by the \
             pinned update key; refusing the update"
        );
    }
    Ok(())
}

/// Compute the lowercase hex SHA-256 of `file` via `openssl dgst -sha256`. The
/// digest is the last whitespace-delimited token of openssl's output
/// (`SHA2-256(<path>)= <hex>`); it is validated to be 64 hex chars.
fn sha256_hex(file: &Path) -> Result<String> {
    let out = Command::new(openssl_bin())
        .args(["dgst", "-sha256", s(file)?])
        .output()
        .context("running openssl dgst -sha256")?;
    if !out.status.success() {
        bail!(
            "computing the image SHA-256 failed (openssl exit {:?})",
            out.status.code()
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let hex = text
        .split_whitespace()
        .last()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("could not parse a SHA-256 from openssl output: {text:?}");
    }
    Ok(hex)
}

// ---- public API -----------------------------------------------------------

/// Fetch and cryptographically verify the channel's release manifest, returning
/// the parsed [`Manifest`] on success. This needs neither root nor the disk — it
/// only proves *which* release the pinned key is currently vouching for.
///
/// Fails closed: a fetch error, a signature that does not verify under the pinned
/// key, or a manifest naming an unsafe image path all return `Err`.
pub fn check(chan: &UpdateChannel) -> Result<Manifest> {
    let base = base_url(chan);
    let scratch = Scratch::new()?;
    let manifest_path = scratch.join("manifest.json");
    let sig_path = scratch.join("manifest.json.sig");

    fetch(chan, &format!("{base}/manifest.json"), &manifest_path)?;
    fetch(chan, &format!("{base}/manifest.json.sig"), &sig_path)?;

    // Verify the signature BEFORE parsing/trusting any manifest field.
    let pubkey = resolve_pubkey(chan, &scratch)?;
    verify_signature(&pubkey, &manifest_path, &sig_path)?;

    let bytes = std::fs::read(&manifest_path).context("reading the verified manifest")?;
    let manifest: Manifest =
        serde_json::from_slice(&bytes).context("parsing the (verified) release manifest")?;

    if !valid_image_name(&manifest.image) {
        bail!(
            "manifest names an unsafe image path {:?} (must be a plain file name)",
            manifest.image
        );
    }
    if norm_digest(&manifest.sha256).len() != 64 {
        bail!(
            "manifest sha256 {:?} is not a 64-hex-char SHA-256",
            manifest.sha256
        );
    }
    Ok(manifest)
}

/// Fetch the image named by a verified `manifest` into `dest` and verify its
/// SHA-256 equals the manifest's digest. On mismatch the unverified file is
/// removed and the call bails — so a caller can only ever hand a digest-matched
/// image to the slot-writer.
///
/// `manifest` must be one returned by [`check`] (so its signature was verified);
/// the image-name is re-validated here as belt-and-braces.
pub fn fetch_verified_image(chan: &UpdateChannel, manifest: &Manifest, dest: &Path) -> Result<()> {
    if !valid_image_name(&manifest.image) {
        bail!("refusing to fetch unsafe image path {:?}", manifest.image);
    }
    let url = format!("{}/{}", base_url(chan), manifest.image);
    fetch(chan, &url, dest)?;

    let got = sha256_hex(dest)?;
    let want = norm_digest(&manifest.sha256);
    if got != want {
        // Don't leave an unverified image lying around to be picked up by mistake.
        let _ = std::fs::remove_file(dest);
        bail!(
            "image SHA-256 mismatch — refusing the update: manifest names {want}, fetched image \
             is {got}"
        );
    }
    Ok(())
}

/// The detached-signature path for a local image: `<image>.sig`, the same
/// convention the channel uses for `manifest.json.sig`.
pub fn signature_path(image: &Path) -> std::path::PathBuf {
    let mut name = image.as_os_str().to_os_string();
    name.push(".sig");
    std::path::PathBuf::from(name)
}

/// Verify an operator-supplied **local** image against a pinned key before it is
/// written to a slot — the local counterpart of the channel's manifest check,
/// closing the same supply-chain hole for `sentinel update <image>`.
///
/// Reuses the channel's signing infra exactly: an Ed25519 detached signature
/// (`<image>.sig`) over the image's *own bytes*, verified under `public_key` (a
/// `file:<path>` reference or an inline PEM). Fails closed — a missing signature,
/// an unreadable/…invalid key, or a signature that does not verify all return
/// `Err`, and the caller never reaches the slot-writer.
///
/// The image is signed directly rather than through a manifest because a local
/// file needs no fetch step: there is no version/name/digest to fetch and trust,
/// only the bytes in front of the operator, so signing those bytes is the whole
/// proof.
pub fn verify_local_image(image: &Path, public_key: &str) -> Result<()> {
    let sig = signature_path(image);
    if !sig.exists() {
        bail!(
            "no detached signature next to the image: expected {} — refusing to write an \
             unverified image. Sign it with the release key (openssl pkeyutl -sign -rawin), or, \
             for a trusted local image/device, pass --allow-unsigned.",
            sig.display()
        );
    }
    let scratch = Scratch::new()?;
    let pubkey = resolve_pubkey_pem(public_key, &scratch)?;
    verify_signature(&pubkey, image, &sig)
}

// ---- subscription state, visible ------------------------------------------

/// A secret shown as its tail: `…a1b2`, never the value. Enough to tell two
/// keys apart over a support call, useless to replay. A key too short to spare
/// four characters shows none of them.
pub fn mask_key(key: &str) -> String {
    let chars: Vec<char> = key.chars().collect();
    if chars.len() < 8 {
        return "…".to_string();
    }
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("…{tail}")
}

/// Where the outcome of the last channel check is remembered, so `show
/// subscription` reports what actually happened rather than re-fetching (a
/// `show` must never be the thing that talks to the internet).
const STATUS_PATH: &str = "/var/lib/sentinel/update-status.json";

/// The last channel contact: which channel, when, and how it went. Written by
/// `update check`/`install`, read by `show subscription`. Deliberately WITHOUT
/// an expiry field: the channel server has no contract for reporting one yet,
/// and a date this box computed itself would be a guess dressed as a fact —
/// the display says "not reported" instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    /// The channel's label (its name, or "default" for the unnamed channel).
    pub channel: String,
    /// When the contact happened, epoch seconds.
    pub checked: i64,
    /// What came of it, in the words the operator saw.
    pub outcome: String,
}

/// Remember `outcome` for `show subscription`. Best-effort on purpose: the
/// check itself needs neither root nor the disk, and a status file that cannot
/// be written must not turn a successful check into a failure — the check's
/// own output already told the operator everything this file remembers.
pub fn record_status(chan: &UpdateChannel, outcome: &str) {
    let status = Status {
        channel: chan.label().to_string(),
        checked: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        outcome: outcome.to_string(),
    };
    if let Ok(body) = serde_json::to_vec_pretty(&status) {
        let _ = std::fs::write(status_path(), body);
    }
}

/// The last recorded contact, or `None` when there has never been one (or the
/// file is unreadable/garbled — reported as "never checked", which is the
/// honest reading of a record that cannot be read).
pub fn read_status() -> Option<Status> {
    let bytes = std::fs::read(status_path()).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The status file path, overridable for tests (`SENTINEL_UPDATE_STATUS`).
fn status_path() -> std::path::PathBuf {
    std::env::var("SENTINEL_UPDATE_STATUS")
        .ok()
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(STATUS_PATH))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- pure tests (no openssl/curl, always run) ----

    #[test]
    fn rejects_unsafe_image_names() {
        assert!(valid_image_name("sentinel-0.3.0.img"));
        assert!(valid_image_name("img_2026-07-08.raw"));
        assert!(!valid_image_name(""));
        assert!(!valid_image_name("../etc/passwd"));
        assert!(!valid_image_name("a/b.img"));
        assert!(!valid_image_name("foo/../bar"));
        assert!(!valid_image_name(".hidden"));
        assert!(!valid_image_name("a\\b"));
    }

    #[test]
    fn normalises_digests() {
        let bare = "ABCDEF0123456789";
        assert_eq!(norm_digest(bare), "abcdef0123456789");
        assert_eq!(norm_digest("  sha256:ABCD  "), "abcd");
        assert_eq!(norm_digest("sha256:beef"), "beef");
    }

    #[test]
    fn trims_trailing_slashes_in_base_url() {
        let chan = UpdateChannel {
            name: None,
            url: "https://example.test/chan/".to_string(),
            public_key: "x".to_string(),
            subscription_key: None,
        };
        assert_eq!(base_url(&chan), "https://example.test/chan");
    }

    /// The mask shows a tail to recognise a key by, never the key — and a key
    /// too short to spare four characters shows nothing at all.
    #[test]
    fn a_masked_key_shows_only_its_tail() {
        assert_eq!(mask_key("velstra-enterprise-a1b2"), "…a1b2");
        assert_eq!(mask_key("abcdefgh"), "…efgh");
        assert_eq!(mask_key("short"), "…");
        assert_eq!(mask_key(""), "…");
        assert!(!mask_key("velstra-enterprise-a1b2").contains("enterprise"));
    }

    /// A recorded outcome reads back exactly, and an absent/garbled file reads
    /// as "never checked" rather than an error.
    #[test]
    fn status_round_trips_and_fails_soft() {
        let dir = Scratch::new().unwrap();
        let file = dir.join("status.json");
        // SAFETY: test-only env mutation; the var name is unique to this test
        // binary and reset below.
        unsafe { std::env::set_var("SENTINEL_UPDATE_STATUS", &file) };
        let chan = UpdateChannel {
            name: Some("enterprise".into()),
            url: "https://updates.example.test/ent".into(),
            public_key: "file:/etc/sentinel/ent.pem".into(),
            subscription_key: Some("velstra-enterprise-a1b2".into()),
        };
        assert!(read_status().is_none(), "no file yet reads as never");
        record_status(&chan, "release 0.4.0 available");
        let st = read_status().expect("recorded");
        assert_eq!(st.channel, "enterprise");
        assert_eq!(st.outcome, "release 0.4.0 available");
        assert!(st.checked > 0);
        // The status file must never carry the subscription key.
        let body = std::fs::read_to_string(&file).unwrap();
        assert!(!body.contains("a1b2"), "no secret in the status file");
        std::fs::write(&file, b"not json").unwrap();
        assert!(read_status().is_none(), "garbage reads as never, not error");
        unsafe { std::env::remove_var("SENTINEL_UPDATE_STATUS") };
    }

    #[test]
    fn parses_a_manifest() {
        let m: Manifest = serde_json::from_str(
            r#"{"version":"0.3.0","image":"sentinel-0.3.0.img","sha256":"deadbeef","extra":1}"#,
        )
        .unwrap();
        assert_eq!(m.version, "0.3.0");
        assert_eq!(m.image, "sentinel-0.3.0.img");
        assert_eq!(m.sha256, "deadbeef");
    }

    // ---- openssl-backed tests (SKIP when openssl isn't spawnable) ----
    //
    // The Nix cargo-test sandbox has no openssl on PATH, so these must self-skip
    // there rather than fail the package build. Real crypto coverage lives in the
    // `checks.updatechannel` nixosTest.

    fn openssl_available() -> bool {
        Command::new(openssl_bin())
            .arg("version")
            .status()
            .map(|st| st.success())
            .unwrap_or(false)
    }

    #[test]
    fn ed25519_signature_roundtrip() {
        if !openssl_available() {
            return;
        }
        let dir = Scratch::new().unwrap();
        let priv_pem = dir.join("priv.pem");
        let pub_pem = dir.join("pub.pem");
        let manifest = dir.join("manifest.json");
        let sig = dir.join("manifest.json.sig");

        let ob = openssl_bin();
        assert!(
            Command::new(&ob)
                .args([
                    "genpkey",
                    "-algorithm",
                    "ed25519",
                    "-out",
                    priv_pem.to_str().unwrap()
                ])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new(&ob)
                .args([
                    "pkey",
                    "-in",
                    priv_pem.to_str().unwrap(),
                    "-pubout",
                    "-out",
                    pub_pem.to_str().unwrap(),
                ])
                .status()
                .unwrap()
                .success()
        );
        std::fs::write(
            &manifest,
            br#"{"version":"9.9.9","image":"x.img","sha256":"ab"}"#,
        )
        .unwrap();
        assert!(
            Command::new(&ob)
                .args([
                    "pkeyutl",
                    "-sign",
                    "-inkey",
                    priv_pem.to_str().unwrap(),
                    "-rawin",
                    "-in",
                    manifest.to_str().unwrap(),
                    "-out",
                    sig.to_str().unwrap(),
                ])
                .status()
                .unwrap()
                .success()
        );

        // Good signature verifies.
        verify_signature(&pub_pem, &manifest, &sig).unwrap();

        // Tampering the manifest breaks verification (fail closed).
        std::fs::write(&manifest, b"tampered").unwrap();
        assert!(verify_signature(&pub_pem, &manifest, &sig).is_err());
    }

    #[test]
    fn sha256_hex_is_64_hex_chars() {
        if !openssl_available() {
            return;
        }
        let dir = Scratch::new().unwrap();
        let blob = dir.join("blob");
        std::fs::write(&blob, b"hello velstra").unwrap();
        let h = sha256_hex(&blob).unwrap();
        assert_eq!(h.len(), 64);
        assert!(h.bytes().all(|b| b.is_ascii_hexdigit()));
        // Deterministic: hashing the same bytes again matches.
        assert_eq!(h, sha256_hex(&blob).unwrap());
    }

    #[test]
    fn the_signature_path_sits_beside_the_image() {
        assert_eq!(
            signature_path(Path::new("/tmp/sentinel-0.4.raw")),
            Path::new("/tmp/sentinel-0.4.raw.sig")
        );
        assert_eq!(
            signature_path(Path::new("image")),
            Path::new("image.sig")
        );
    }

    /// A missing signature is refused without needing any crypto at all — the
    /// default-secure behaviour a plain `sentinel update <image>` now gets.
    #[test]
    fn a_local_image_without_a_signature_is_refused() {
        let dir = Scratch::new().unwrap();
        let img = dir.join("image.raw");
        std::fs::write(&img, b"pretend image").unwrap();
        // No image.raw.sig beside it.
        let err = verify_local_image(&img, "does-not-matter").unwrap_err();
        assert!(
            format!("{err}").contains("no detached signature"),
            "{err}"
        );
    }

    /// The local path reuses the channel's Ed25519 infra: a detached signature
    /// over the image bytes, verified under the pinned key. A good signature
    /// passes; tampering the image afterwards fails closed.
    #[test]
    fn a_signed_local_image_verifies_and_tampering_fails() {
        if !openssl_available() {
            return;
        }
        let dir = Scratch::new().unwrap();
        let priv_pem = dir.join("priv.pem");
        let pub_pem = dir.join("pub.pem");
        let img = dir.join("image.raw");
        let sig = signature_path(&img);
        std::fs::write(&img, b"a whole appliance image, pretend").unwrap();

        let ob = openssl_bin();
        assert!(
            Command::new(&ob)
                .args(["genpkey", "-algorithm", "ed25519", "-out", priv_pem.to_str().unwrap()])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new(&ob)
                .args([
                    "pkey",
                    "-in",
                    priv_pem.to_str().unwrap(),
                    "-pubout",
                    "-out",
                    pub_pem.to_str().unwrap(),
                ])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new(&ob)
                .args([
                    "pkeyutl",
                    "-sign",
                    "-inkey",
                    priv_pem.to_str().unwrap(),
                    "-rawin",
                    "-in",
                    img.to_str().unwrap(),
                    "-out",
                    sig.to_str().unwrap(),
                ])
                .status()
                .unwrap()
                .success()
        );

        // Pinned by inline PEM and by `file:` reference — both accepted.
        let pem = std::fs::read_to_string(&pub_pem).unwrap();
        verify_local_image(&img, &pem).expect("a correctly signed image must verify");
        verify_local_image(&img, &format!("file:{}", pub_pem.to_str().unwrap()))
            .expect("a file: pinned key must verify too");

        // Tamper the image: the signature no longer covers these bytes.
        std::fs::write(&img, b"a whole appliance image, TAMPERED").unwrap();
        assert!(
            verify_local_image(&img, &pem).is_err(),
            "a tampered image must fail closed"
        );
    }
}
