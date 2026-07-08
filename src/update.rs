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
use serde::Deserialize;

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
fn fetch(url: &str, dest: &Path) -> Result<()> {
    let status = Command::new(curl_bin())
        .args([
            "-fsSL",
            "--proto",
            "=https,file",
            "--proto-redir",
            "=https,file",
            "-o",
            s(dest)?,
            url,
        ])
        .status()
        .with_context(|| format!("running curl for {url}"))?;
    if !status.success() {
        bail!("fetch of {url} failed (curl exit {:?})", status.code());
    }
    Ok(())
}

/// Resolve the pinned public key to a PEM file on disk: a `file:<path>` value is
/// read from that path, an inline value is the PEM itself. Either way it is
/// re-staged into `scratch` (and sanity-checked to be a PEM public key) so the
/// verify call has a single, known input.
fn resolve_pubkey(chan: &UpdateChannel, scratch: &Scratch) -> Result<std::path::PathBuf> {
    let pem = if let Some(path) = chan.public_key.strip_prefix("file:") {
        std::fs::read_to_string(path)
            .with_context(|| format!("reading pinned update public key from {path}"))?
    } else {
        chan.public_key.clone()
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
fn verify_signature(pubkey: &Path, manifest: &Path, sig: &Path) -> Result<()> {
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

    fetch(&format!("{base}/manifest.json"), &manifest_path)?;
    fetch(&format!("{base}/manifest.json.sig"), &sig_path)?;

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
    fetch(&url, dest)?;

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
            url: "https://example.test/chan/".to_string(),
            public_key: "x".to_string(),
        };
        assert_eq!(base_url(&chan), "https://example.test/chan");
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
}
