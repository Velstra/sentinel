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

use std::path::{Path, PathBuf};
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
    /// The release version, e.g. `"1.2.0"`. Compared against the running
    /// version before anything is installed ([`refuse_downgrade`]).
    pub version: String,
    /// The image file's basename within the channel directory (never a path).
    pub image: String,
    /// Lowercase hex SHA-256 of the image file (an optional `sha256:` prefix is
    /// tolerated). The fetched image must hash to exactly this.
    pub sha256: String,
    /// What the release is for — [`PRODUCT`]. Optional so that manifests signed
    /// before the field existed still verify; when present it must match, so a
    /// manifest for another product signed by a shared key is refused.
    #[serde(default)]
    pub product: Option<String>,
}

/// The product a manifest's `product` field must name.
pub const PRODUCT: &str = "velstra-sentinel";

/// The version of the running image: the one `show version` prints, which the
/// release process bumps with every tagged release.
pub const RUNNING_VERSION: &str = env!("CARGO_PKG_VERSION");

// ---- scratch storage ------------------------------------------------------

static SCRATCH_SEQ: AtomicU64 = AtomicU64::new(0);

/// A private temp directory that removes itself (and everything under it) on
/// drop. Used to stage the fetched manifest/signature/pinned-key and, for a
/// channel install, the verified image. Public so [`crate::install`] can own the
/// image's scratch dir for the lifetime of the slot-write.
///
/// Private from the first instant, not after a chmod: the directory is created
/// 0700 in one call, and it must be one this process just made. `/tmp` is
/// shared, so a directory already sitting at the name — another user's, or a
/// symlink planted there — is refused rather than reused, and the name carries
/// random bits so it cannot be predicted to plant one in the first place.
pub struct Scratch(std::path::PathBuf);

impl Scratch {
    /// Create a fresh, uniquely-named, 0700 scratch dir under the system temp dir.
    pub fn new() -> Result<Self> {
        Self::new_in(&std::env::temp_dir())
    }

    fn new_in(parent: &Path) -> Result<Self> {
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random)
            .map_err(|_| anyhow::anyhow!("scratch name randomness unavailable"))?;
        let random: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let seq = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
        let p = parent.join(format!(
            "sentinel-update-{}-{seq}-{random}",
            std::process::id()
        ));
        Self::claim(p)
    }

    /// Create `p` as this process's private directory, or refuse.
    fn claim(p: PathBuf) -> Result<Self> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&p)
            .with_context(|| {
                format!(
                    "creating private scratch {} (refusing an existing one)",
                    p.display()
                )
            })?;
        // The umask can only remove bits, never add them, but the ownership and
        // type are re-read rather than assumed: whatever is at the path now is
        // what every staged file will be written into.
        let meta = std::fs::symlink_metadata(&p)?;
        if !meta.is_dir()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.permissions().mode() & 0o077 != 0
        {
            bail!(
                "scratch {} is not a private directory owned by this user",
                p.display()
            );
        }
        Ok(Self(p))
    }

    /// A path to `name` inside this scratch dir.
    pub fn join(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }

    /// Create `name` in this scratch dir, 0600 from the moment it exists and
    /// never a file that was already there.
    pub fn create_private(&self, name: &str) -> Result<std::fs::File> {
        use std::os::unix::fs::OpenOptionsExt;
        let path = self.join(name);
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .with_context(|| format!("creating {}", path.display()))
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

/// The pinned `openssl` (same resolution as the PKI path).
fn openssl_bin() -> String {
    system::bin("openssl")
}

/// Fetch `url` to `dest` with `curl -fsSL`. `-f` makes an HTTP error (or a
/// missing `file://` path) a non-zero exit; `--proto =https,file` refuses any
/// other scheme even across a redirect. Any failure bails — fetch is fail-closed.
///
/// A channel with a `subscription-key` sends it as `Authorization: Bearer` on
/// every request. The header travels via a file that is 0600 from its creation,
/// inside a 0700 directory (`-H @file`), never on the
/// command line — argv is world-readable through /proc for as long as curl
/// runs, and a secret must not be.
fn fetch(chan: &UpdateChannel, url: &str, dest: &Path) -> Result<()> {
    let scratch = Scratch::new()?;
    let header = match &chan.subscription_key {
        Some(key) => {
            use std::io::Write;
            scratch
                .create_private("auth-header")?
                .write_all(format!("Authorization: Bearer {key}\n").as_bytes())
                .context("staging the subscription header")?;
            Some(scratch.join("auth-header"))
        }
        None => None,
    };
    let out = fetch_command(url, dest, header.as_deref())?
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
            Some(n) => format!("Add the key with `set update channel {n} subscription-key <key>`"),
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

/// The fetch itself. The pinned curl comes from [`system::curl_command`]:
/// `--disable` first and an empty environment, so neither a `~/.curlrc` nor an
/// ambient proxy, key-log or CA variable decides where a subscription key goes
/// or which certificates a channel is checked against — the system trust store
/// is. `-f` makes an HTTP error (or a missing `file://` path) a non-zero exit;
/// `--proto =https,file` refuses any other scheme even across a redirect.
fn fetch_command(url: &str, dest: &Path, auth_header: Option<&Path>) -> Result<Command> {
    let mut cmd = system::curl_command();
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
    if let Some(header) = auth_header {
        cmd.args(["-H", &format!("@{}", s(header)?)]);
    }
    Ok(cmd)
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
    check_manifest_fields(&manifest)?;
    Ok(manifest)
}

/// The checks every verified manifest gets, from a channel or from a medium.
fn check_manifest_fields(manifest: &Manifest) -> Result<()> {
    let digest = norm_digest(&manifest.sha256);
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!(
            "manifest sha256 {:?} is not a 64-hex-char SHA-256",
            manifest.sha256
        );
    }
    if let Some(product) = manifest.product.as_ref().filter(|p| *p != PRODUCT) {
        bail!("the signed manifest is for {product:?}, not {PRODUCT:?} — refusing the update");
    }
    Ok(())
}

/// Refuse to install a release older than the one running, unless the operator
/// asked for exactly that.
///
/// A signature says a release is genuine, not that it is current: every old
/// release stays validly signed forever, so a mirror (or anybody in the path)
/// serving yesterday's manifest could put a box back onto a release with known
/// holes. The same version again is allowed — that is a re-install, not a step
/// back. A version that cannot be compared is refused too: "cannot tell" must
/// not read as "newer".
pub fn refuse_downgrade(offered: &str, allow_downgrade: bool) -> Result<()> {
    let verdict = compare_versions(offered, RUNNING_VERSION);
    if matches!(
        verdict,
        Some(std::cmp::Ordering::Equal | std::cmp::Ordering::Greater)
    ) {
        return Ok(());
    }
    let what = match verdict {
        Some(_) => format!("release {offered} is OLDER than the running {RUNNING_VERSION}"),
        None => format!(
            "release version {offered:?} cannot be compared with the running {RUNNING_VERSION}"
        ),
    };
    if allow_downgrade {
        eprintln!("warning: --allow-downgrade: {what}; installing it as asked");
        return Ok(());
    }
    bail!(
        "{what} — refusing a downgrade. An old release stays validly signed forever, so this \
         is how a box is put back onto known holes. If going back is what you mean, pass \
         --allow-downgrade."
    )
}

/// Order two versions the way semantic versioning does: numeric dot-separated
/// core (a leading `v` and `+build` metadata ignored, missing components read as
/// zero), and a `-pre.release` sorting before the release it precedes —
/// numeric identifiers numerically and below alphanumeric ones. `None` when
/// either side is not a version at all.
pub fn compare_versions(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    use std::cmp::Ordering;
    fn parse(v: &str) -> Option<(Vec<u64>, Vec<&str>)> {
        let v = v.trim();
        let v = v.strip_prefix('v').unwrap_or(v);
        let v = v.split_once('+').map_or(v, |(core, _)| core);
        let (core, pre) = match v.split_once('-') {
            Some((core, pre)) => (core, pre.split('.').collect()),
            None => (v, Vec::new()),
        };
        let mut numbers = core
            .split('.')
            .map(|n| {
                (!n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                    .then(|| n.parse().ok())
                    .flatten()
            })
            .collect::<Option<Vec<u64>>>()?;
        if numbers.is_empty() || numbers.len() > 4 || pre.iter().any(|p: &&str| p.is_empty()) {
            return None;
        }
        numbers.resize(4, 0);
        Some((numbers, pre))
    }
    let (a_core, a_pre) = parse(a)?;
    let (b_core, b_pre) = parse(b)?;
    let core = a_core.cmp(&b_core);
    if core != Ordering::Equal {
        return Some(core);
    }
    Some(match (a_pre.is_empty(), b_pre.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => {
            for (x, y) in a_pre.iter().zip(&b_pre) {
                let order = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(x), Ok(y)) => x.cmp(&y),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => x.cmp(y),
                };
                if order != Ordering::Equal {
                    return Some(order);
                }
            }
            a_pre.len().cmp(&b_pre.len())
        }
    })
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

/// What a verified local proof vouches for: the SHA-256 the image must hash to,
/// the release version when the proof states one, and which file to install —
/// the image itself, or (for a raw signature) the private copy that was
/// verified. Holding the copy's scratch keeps it alive until the install ends.
pub struct LocalProof {
    pub sha256: String,
    pub version: Option<String>,
    pub source: PathBuf,
    _copy: Option<Scratch>,
}

/// Read a small proof file (a digest or a manifest) once, bounded.
fn read_small(path: &Path, limit: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .with_context(|| format!("reading {}", path.display()))?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("{} is too large to be a signed proof", path.display());
    }
    Ok(bytes)
}

/// Verify `signature` over `bytes` already held in memory. The bytes are staged
/// privately and openssl verifies that copy, so what was verified is what the
/// caller goes on to trust — never the file at the original path, read again.
fn verify_bytes(public_key: &str, bytes: &[u8], signature: &Path) -> Result<()> {
    use std::io::Write;
    let scratch = Scratch::new()?;
    let pubkey = resolve_pubkey_pem(public_key, &scratch)?;
    scratch.create_private("signed")?.write_all(bytes)?;
    verify_signature(&pubkey, &scratch.join("signed"), signature)
}

/// Verify an operator-supplied **local** image (a file or a block device)
/// against a pinned key before it is written to a slot — the local counterpart
/// of the channel's manifest check, closing the same supply-chain hole for
/// `sentinel update <image>`.
///
/// Three proofs, all Ed25519 under `public_key` (a `file:<path>` reference or an
/// inline PEM), named by `signature` or found beside the image:
///
/// * a signed **release manifest** (`--signature …/manifest.json.sig`): the
///   channel's own `manifest.json`, copied to a medium. It names the image's
///   SHA-256 and the release version, so the downgrade check applies.
/// * a signed **digest** (`<image>.sha256` + `<image>.sha256.sig`): one hex
///   SHA-256 of the image file. OpenSSL's Ed25519 buffers its whole input, so
///   this is the form for a multi-GiB appliance image.
/// * a raw signature over the image bytes (`<image>.sig`), for small images.
///   The image is copied privately first and the copy is what is verified and
///   installed. A block device cannot be proven this way: nothing in a raw
///   signature says where the image ends on a larger stick.
///
/// A supplied digest takes precedence over a raw signature beside the image,
/// and a bad proof never falls back to another one. The image itself is not
/// hashed here: [`crate::verified_image::VerifiedImage`] hashes it while
/// reading it for the install, so it is read for trust exactly once.
pub fn verify_local_image(
    image: &Path,
    signature: Option<&Path>,
    public_key: &str,
) -> Result<LocalProof> {
    use std::os::unix::fs::FileTypeExt;
    let is_block = std::fs::metadata(image)
        .with_context(|| format!("reading {}", image.display()))?
        .file_type()
        .is_block_device();
    let (signed, sig) = match signature {
        Some(sig) => {
            let Some(signed) = sig.to_str().and_then(|s| s.strip_suffix(".sig")) else {
                bail!(
                    "--signature {} must name a detached signature file ending in .sig",
                    sig.display()
                );
            };
            (PathBuf::from(signed), sig.to_path_buf())
        }
        None => {
            let mut digest = image.as_os_str().to_os_string();
            digest.push(".sha256");
            let digest = PathBuf::from(digest);
            if digest.exists() {
                let sig = signature_path(&digest);
                (digest, sig)
            } else {
                (image.to_path_buf(), signature_path(image))
            }
        }
    };
    let name = signed.to_string_lossy();
    if name.ends_with(".json") {
        let bytes = read_small(&signed, 65536)?;
        verify_bytes(public_key, &bytes, &sig)?;
        let manifest: Manifest =
            serde_json::from_slice(&bytes).context("parsing the (verified) release manifest")?;
        check_manifest_fields(&manifest)?;
        return Ok(LocalProof {
            sha256: norm_digest(&manifest.sha256),
            version: Some(manifest.version),
            source: image.to_path_buf(),
            _copy: None,
        });
    }
    if name.ends_with(".sha256") {
        let bytes = read_small(&signed, 128)?;
        let digest = std::str::from_utf8(&bytes)?.trim();
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("signed image digest must contain one SHA-256 hex value");
        }
        verify_bytes(public_key, &bytes, &sig)?;
        return Ok(LocalProof {
            sha256: digest.to_ascii_lowercase(),
            version: None,
            source: image.to_path_buf(),
            _copy: None,
        });
    }
    if is_block {
        bail!(
            "{} is a block device: a raw signature cannot say where the image ends on it. \
             Pass --signature with the release's signed digest (<image>.sha256.sig) or signed \
             manifest (manifest.json.sig); for a trusted device, --allow-unsigned.",
            image.display()
        );
    }
    let same = |a: &Path, b: &Path| {
        a == b || matches!((a.canonicalize(), b.canonicalize()), (Ok(x), Ok(y)) if x == y)
    };
    if !same(&signed, image) {
        bail!(
            "--signature {} signs {}, which is neither this image, a .sha256 digest nor a \
             release manifest",
            sig.display(),
            signed.display()
        );
    }
    if !sig.exists() {
        bail!(
            "no detached signature next to the image: expected {} — refusing to write an \
             unverified image. Sign it with the release key (openssl pkeyutl -sign -rawin), pass \
             --signature <file>, or, for a trusted local image/device, pass --allow-unsigned.",
            sig.display()
        );
    }
    // Raw form: copy first, verify the copy, install the copy.
    let copy = Scratch::new()?;
    let source = copy.join("image.raw");
    std::io::copy(
        &mut std::fs::File::open(image)?,
        &mut copy.create_private("image.raw")?,
    )
    .context("staging the image privately")?;
    let pubkey = resolve_pubkey_pem(public_key, &copy)?;
    verify_signature(&pubkey, &source, &sig)?;
    let sha256 = sha256_hex(&source)?;
    Ok(LocalProof {
        sha256,
        version: None,
        source,
        _copy: Some(copy),
    })
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
        assert_eq!(signature_path(Path::new("image")), Path::new("image.sig"));
    }

    /// A missing signature is refused without needing any crypto at all — the
    /// default-secure behaviour a plain `sentinel update <image>` now gets.
    #[test]
    fn a_local_image_without_a_signature_is_refused() {
        let dir = Scratch::new().unwrap();
        let img = dir.join("image.raw");
        std::fs::write(&img, b"pretend image").unwrap();
        // No image.raw.sig beside it.
        let err = verify_local_image(&img, None, "does-not-matter")
            .err()
            .unwrap();
        assert!(format!("{err}").contains("no detached signature"), "{err}");
    }

    #[test]
    fn a_large_local_image_uses_a_signed_digest_and_rejects_tampering() {
        if !openssl_available() {
            return;
        }
        let dir = Scratch::new().unwrap();
        let private = dir.join("private.pem");
        let public = dir.join("public.pem");
        let image = dir.join("large.raw");
        let digest = dir.join("large.raw.sha256");
        let signature = signature_path(&digest);
        // Sparse, larger than OpenSSL's direct-signing limit; no large RAM buffer.
        let file = std::fs::File::create(&image).unwrap();
        file.set_len((1_u64 << 31) + 1).unwrap();
        let ob = openssl_bin();
        for args in [
            vec![
                "genpkey",
                "-algorithm",
                "ed25519",
                "-out",
                private.to_str().unwrap(),
            ],
            vec![
                "pkey",
                "-in",
                private.to_str().unwrap(),
                "-pubout",
                "-out",
                public.to_str().unwrap(),
            ],
        ] {
            assert!(Command::new(&ob).args(args).status().unwrap().success());
        }
        std::fs::write(&digest, format!("{}\n", sha256_hex(&image).unwrap())).unwrap();
        assert!(
            Command::new(&ob)
                .args([
                    "pkeyutl",
                    "-sign",
                    "-rawin",
                    "-inkey",
                    private.to_str().unwrap(),
                    "-in",
                    digest.to_str().unwrap(),
                    "-out",
                    signature.to_str().unwrap()
                ])
                .status()
                .unwrap()
                .success()
        );
        let key = format!("file:{}", public.display());
        let proof = verify_local_image(&image, None, &key).unwrap();
        assert_eq!(proof.sha256, sha256_hex(&image).unwrap());
        assert_eq!(
            proof.source, image,
            "a digest proof installs the image itself"
        );
        assert!(proof.version.is_none());
        // The same proof named explicitly, from another directory — a USB
        // stick's proof lives on some other medium.
        let elsewhere = Scratch::new().unwrap();
        let moved = elsewhere.join("velstra-sentinel.raw.sha256");
        std::fs::copy(&digest, &moved).unwrap();
        std::fs::copy(&signature, signature_path(&moved)).unwrap();
        let named = verify_local_image(&image, Some(&signature_path(&moved)), &key).unwrap();
        assert_eq!(named.sha256, proof.sha256);
        // A malformed supplied digest never falls back to another signature.
        std::fs::write(&digest, b"not a digest").unwrap();
        assert!(verify_local_image(&image, None, &key).is_err());
        std::fs::write(&digest, [b'a'; 129]).unwrap();
        assert!(
            verify_local_image(&image, None, &key)
                .err()
                .unwrap()
                .to_string()
                .contains("too large")
        );
        // A digest that is not the one signed is refused before the image is
        // ever read.
        std::fs::write(&digest, format!("{}\n", "0".repeat(64))).unwrap();
        assert!(verify_local_image(&image, None, &key).is_err());
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
        let proof =
            verify_local_image(&img, None, &pem).expect("a correctly signed image must verify");
        verify_local_image(&img, None, &format!("file:{}", pub_pem.to_str().unwrap()))
            .expect("a file: pinned key must verify too");

        // What gets installed is the private copy that was verified, so
        // rewriting the original afterwards changes nothing that is written.
        assert_ne!(proof.source, img);
        std::fs::write(&img, b"a whole appliance image, TAMPERED").unwrap();
        assert_eq!(
            std::fs::read(&proof.source).unwrap(),
            b"a whole appliance image, pretend"
        );
        assert_eq!(proof.sha256, sha256_hex(&proof.source).unwrap());

        // Tamper the image: the signature no longer covers these bytes.
        assert!(
            verify_local_image(&img, None, &pem).is_err(),
            "a tampered image must fail closed"
        );
        // A --signature naming some other file's raw signature is refused.
        let other = dir.join("other.raw");
        std::fs::write(&other, b"other").unwrap();
        assert!(
            verify_local_image(&img, Some(&signature_path(&other)), &pem)
                .err()
                .unwrap()
                .to_string()
                .contains("neither this image")
        );
    }

    /// A signed manifest copied to a medium proves an image and states its
    /// version — the form that brings downgrade protection to a USB install.
    #[test]
    fn a_signed_manifest_proves_a_local_image_and_its_version() {
        if !openssl_available() {
            return;
        }
        let dir = Scratch::new().unwrap();
        let private = dir.join("private.pem");
        let public = dir.join("public.pem");
        let ob = openssl_bin();
        let sh = |args: &[&str]| assert!(Command::new(&ob).args(args).status().unwrap().success());
        sh(&[
            "genpkey",
            "-algorithm",
            "ed25519",
            "-out",
            s(&private).unwrap(),
        ]);
        sh(&[
            "pkey",
            "-in",
            s(&private).unwrap(),
            "-pubout",
            "-out",
            s(&public).unwrap(),
        ]);
        let image = dir.join("velstra-sentinel.raw");
        std::fs::write(&image, b"pretend appliance image").unwrap();
        let manifest = dir.join("manifest.json");
        let sign = |body: String| {
            std::fs::write(&manifest, body).unwrap();
            sh(&[
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                s(&private).unwrap(),
                "-in",
                s(&manifest).unwrap(),
                "-out",
                s(&signature_path(&manifest)).unwrap(),
            ]);
        };
        let digest = sha256_hex(&image).unwrap();
        sign(format!(
            r#"{{"version":"9.1.0","image":"velstra-sentinel.raw","sha256":"{digest}","product":"velstra-sentinel"}}"#
        ));
        let key = format!("file:{}", public.display());
        let proof = verify_local_image(&image, Some(&signature_path(&manifest)), &key).unwrap();
        assert_eq!(proof.version.as_deref(), Some("9.1.0"));
        assert_eq!(proof.sha256, digest);
        // Signed for another product: refused.
        sign(format!(
            r#"{{"version":"9.1.0","image":"x.raw","sha256":"{digest}","product":"velstra-cloud"}}"#
        ));
        assert!(
            verify_local_image(&image, Some(&signature_path(&manifest)), &key)
                .err()
                .unwrap()
                .to_string()
                .contains("velstra-cloud")
        );
        // A manifest changed after signing: refused.
        std::fs::write(&manifest, b"{\"version\":\"9.9.9\"}").unwrap();
        assert!(verify_local_image(&image, Some(&signature_path(&manifest)), &key).is_err());
    }

    #[test]
    fn versions_order_like_semver() {
        use std::cmp::Ordering::*;
        for (a, b, want) in [
            ("1.0.0", "1.0.0", Equal),
            ("v1.0", "1.0.0", Equal),
            ("1.0.0+build.7", "1.0.0", Equal),
            ("1.0.1", "1.0.0", Greater),
            ("1.10.0", "1.9.0", Greater),
            ("0.3.0", "1.0.0", Less),
            ("2", "1.99.99", Greater),
            ("1.0.0-rc.1", "1.0.0", Less),
            ("1.0.0-rc.2", "1.0.0-rc.10", Less),
            ("1.0.0-alpha", "1.0.0-1", Greater),
            ("1.0.0-alpha", "1.0.0-alpha.1", Less),
        ] {
            assert_eq!(compare_versions(a, b), Some(want), "{a} vs {b}");
        }
        for bad in ["", "latest", "1..0", "1.0.0-", "1.x", "1.2.3.4.5"] {
            assert_eq!(compare_versions(bad, "1.0.0"), None, "{bad:?}");
        }
    }

    /// An older signed release is refused unless asked for; the same or a
    /// newer one passes; an uncomparable version is not read as newer.
    #[test]
    fn a_downgrade_is_refused_unless_explicitly_allowed() {
        let error = refuse_downgrade("0.3.0", false).unwrap_err().to_string();
        assert!(
            error.contains("OLDER") && error.contains("--allow-downgrade"),
            "{error}"
        );
        refuse_downgrade("0.3.0", true).unwrap();
        refuse_downgrade(RUNNING_VERSION, false).unwrap();
        refuse_downgrade("99.0.0", false).unwrap();
        assert!(refuse_downgrade("nightly", false).is_err());
        refuse_downgrade("nightly", true).unwrap();
    }

    /// Manifests signed before `product` existed still parse and pass; one
    /// naming another product does not.
    #[test]
    fn a_manifest_bound_to_another_product_is_refused() {
        let digest = "ab".repeat(32);
        let old: Manifest = serde_json::from_str(&format!(
            r#"{{"version":"1.0.0","image":"a.img","sha256":"{digest}"}}"#
        ))
        .unwrap();
        check_manifest_fields(&old).unwrap();
        let other: Manifest = serde_json::from_str(&format!(
            r#"{{"version":"1.0.0","image":"a.img","sha256":"{digest}","product":"velstra-cloud"}}"#
        ))
        .unwrap();
        assert!(check_manifest_fields(&other).is_err());
        let bad: Manifest = serde_json::from_str(&format!(
            r#"{{"version":"1.0.0","image":"a.img","sha256":"{}"}}"#,
            "zz".repeat(32)
        ))
        .unwrap();
        assert!(check_manifest_fields(&bad).is_err());
    }

    /// The scratch directory is private from creation, refuses a directory
    /// that already exists at its name, and its files are 0600 at open.
    #[test]
    fn scratch_is_private_from_creation_and_refuses_an_existing_directory() {
        use std::os::unix::fs::PermissionsExt;
        let parent = Scratch::new().unwrap();
        let scratch = Scratch::new_in(&parent.0).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&scratch.0), 0o700);
        scratch.create_private("auth-header").unwrap();
        assert_eq!(mode(&scratch.join("auth-header")), 0o600);
        assert!(
            scratch.create_private("auth-header").is_err(),
            "never reuses a file"
        );
        // Somebody else's directory (or a planted one) at the name is refused.
        let planted = parent.join("planted");
        std::fs::create_dir(&planted).unwrap();
        std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(Scratch::claim(planted.clone()).is_err());
        std::os::unix::fs::symlink(&planted, parent.join("link")).unwrap();
        assert!(Scratch::claim(parent.join("link")).is_err());
    }

    /// The channel fetch runs curl with `--disable` first and nothing of the
    /// caller's environment, and the subscription header stays off argv.
    #[test]
    fn the_channel_fetch_ignores_curlrc_and_the_ambient_environment() {
        let cmd = fetch_command(
            "https://updates.example.test/manifest.json",
            Path::new("/tmp/x/manifest.json"),
            Some(Path::new("/tmp/x/auth-header")),
        )
        .unwrap();
        let args: Vec<_> = cmd.get_args().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(args.first(), Some(&"--disable"), "{args:?}");
        assert!(args.contains(&"@/tmp/x/auth-header"));
        let envs: Vec<_> = cmd.get_envs().map(|(k, _)| k.to_str().unwrap()).collect();
        assert!(envs.iter().all(|k| *k == "PATH"), "{envs:?}");
    }
}
