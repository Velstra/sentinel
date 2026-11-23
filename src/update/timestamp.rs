//! Channel timestamp role (reader side): a second, low-privilege Ed25519 key
//! may keep the CURRENT signed manifest installable after the manifest's own
//! `freshness.expires_at` has passed, for at most 14 days per signature and
//! never later than 90 days after the manifest was issued.
//!
//! The timestamp key cannot authorize an image, change a sequence or point at
//! other bytes: its document binds the exact manifest SHA-256, channel, arch
//! and sequence the release key already signed. The anti-rollback ledger is
//! untouched; only the effective expiry of an otherwise valid manifest moves.
//!
//! An appliance without the pinned key ([`KEY_PATH`]) behaves exactly as
//! before. The wire format and rules mirror the channel publisher's reference
//! implementation (`channel_timestamp.py verify`).

use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;

use super::freshness::{CLOCK_SKEW, Freshness, MAX_INTEGER, MAX_LIFETIME, MIN_CLOCK};
use super::{Scratch, VerifiedOffer};
use crate::config::UpdateChannel;

/// The pinned timestamp public key an image ships when its channel publishes
/// timestamps. Absent: manifests expire at their own `expires_at`.
pub(super) const KEY_PATH: &str = "/etc/sentinel/update-timestamp.pem";
/// Hard ceiling after the manifest's own `issued_at`; then a human must sign
/// a new release.
pub(super) const MAX_EXTENSION: u64 = 90 * 86400;
const ROLE: &str = "timestamp";
const MAX_DOCUMENT: usize = 4096;
pub(super) const FETCH: super::FetchPolicy = super::FetchPolicy {
    max_bytes: 8192,
    ..super::MANIFEST_FETCH
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: u32,
    timestamp: String,
    signature: String,
}

/// Exactly the published fields: `deny_unknown_fields` plus no defaults means
/// a missing, extra or duplicated field is a refusal, as is a wrong type.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema: u32,
    role: String,
    channel: String,
    arch: String,
    manifest_sha256: String,
    sequence: u64,
    issued_at: u64,
    expires_at: u64,
}

/// Split an envelope into the exact signed document bytes and the signature.
fn decode(envelope: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    use base64::Engine;
    ensure!(
        envelope.len() as u64 <= FETCH.max_bytes,
        "oversized channel timestamp"
    );
    let envelope: Envelope =
        serde_json::from_slice(envelope).context("malformed channel timestamp envelope")?;
    ensure!(envelope.schema == 1, "unsupported channel timestamp schema");
    let engine = base64::engine::general_purpose::STANDARD;
    let document = engine
        .decode(&envelope.timestamp)
        .context("malformed channel timestamp document")?;
    let signature = engine
        .decode(&envelope.signature)
        .context("malformed channel timestamp signature")?;
    ensure!(
        !document.is_empty() && document.len() <= MAX_DOCUMENT && signature.len() == 64,
        "invalid channel timestamp lengths"
    );
    Ok((document, signature))
}

/// The binding and validity rules for an already signature-checked document.
/// Returns the timestamp's `expires_at`, the manifest's effective expiry.
pub(super) fn window(
    document: &[u8],
    manifest: &Freshness,
    manifest_sha256: &str,
    channel: &str,
    now: u64,
) -> Result<u64> {
    let value: Document =
        serde_json::from_slice(document).context("malformed channel timestamp document")?;
    ensure!(
        value.schema == 1 && value.role == ROLE,
        "unknown channel timestamp document schema"
    );
    ensure!(
        value.channel == channel
            && manifest.channel == channel
            && value.arch == manifest.arch
            && manifest.arch == std::env::consts::ARCH,
        "channel timestamp scope differs from the configured channel and architecture"
    );
    ensure!(
        value.manifest_sha256 == manifest_sha256 && value.sequence == manifest.sequence,
        "channel timestamp does not bind the current signed manifest"
    );
    let (issued, expires) = (value.issued_at, value.expires_at);
    ensure!(
        manifest.issued_at <= issued
            && issued < expires
            && expires <= MAX_INTEGER
            && expires - issued <= MAX_LIFETIME
            && expires <= manifest.issued_at.saturating_add(MAX_EXTENSION),
        "channel timestamp has an invalid validity window (14 days each, 90 days after the release)"
    );
    ensure!(
        (MIN_CLOCK..=MAX_INTEGER).contains(&now),
        "system clock is not usable for secure updates; configure time synchronization"
    );
    ensure!(
        issued <= now.saturating_add(CLOCK_SKEW),
        "channel timestamp is not yet valid; check time synchronization"
    );
    ensure!(now < expires, "channel timestamp expired");
    Ok(expires)
}

/// Verify `envelope` under the pinned timestamp key `key_pem` for `offer`.
fn verify(
    envelope: &[u8],
    key_pem: &str,
    offer: &VerifiedOffer,
    manifest: &Freshness,
    channel: &str,
    now: u64,
) -> Result<u64> {
    use std::io::Write;
    let key = crate::update_key::canonical_pem(key_pem)
        .context("the pinned channel timestamp key is not an Ed25519 public key")?;
    // The offer's key fingerprint is the digest of the canonical release key
    // its manifest verified under: one key must never hold both roles.
    ensure!(
        super::digest_hex(key.as_bytes()) != offer.public_key_sha256,
        "the channel timestamp key must differ from the release signing key"
    );
    let (document, signature) = decode(envelope)?;
    let scratch = Scratch::new()?;
    scratch.create_private("timestamp")?.write_all(&document)?;
    scratch
        .create_private("timestamp.sig")?
        .write_all(&signature)?;
    let pinned = super::resolve_pubkey_pem(&key, &scratch)?;
    super::verify_signature(
        &pinned,
        &scratch.join("timestamp"),
        &scratch.join("timestamp.sig"),
    )
    .map_err(|_| anyhow::anyhow!("channel timestamp signature does not match the pinned key"))?;
    window(&document, manifest, &offer.manifest_sha256, channel, now)
}

/// The pinned timestamp key, or `None` when the image pins none. Opened
/// non-blocking and accepted only as a bounded regular file, so a FIFO or a
/// device at the path refuses instead of hanging the update check.
fn read_pinned_key(path: &Path) -> Result<Option<String>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).context("reading the pinned channel timestamp key");
        }
    };
    ensure!(
        file.metadata()
            .context("reading the pinned channel timestamp key")?
            .is_file(),
        "the pinned channel timestamp key must be a regular file"
    );
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .context("reading the pinned channel timestamp key")?;
    ensure!(
        bytes.len() <= 4096,
        "the pinned channel timestamp key is oversized"
    );
    String::from_utf8(bytes)
        .context("the pinned channel timestamp key is not text")
        .map(Some)
}

/// The verified timestamp expiry that extends `offer`, if one is needed and
/// the image pins a timestamp key at `key_path`. `Ok(None)` means the
/// manifest's own freshness decides (current, not merely expired, or no key).
/// A needed but refused timestamp is an error naming both reasons.
pub(super) fn extension(
    chan: &UpdateChannel,
    offer: &VerifiedOffer,
    manifest: &Freshness,
    key_path: &Path,
    now: u64,
) -> Result<Option<u64>> {
    if !manifest.expired_only(chan.label(), now) {
        return Ok(None);
    }
    let Some(key) = read_pinned_key(key_path)? else {
        return Ok(None);
    };
    let refused = |error: anyhow::Error| {
        error.context("signed update metadata expired and its channel timestamp was refused")
    };
    let scratch = Scratch::new()?;
    let path = scratch.join("timestamp.json");
    let url = format!("{}/timestamp.json", super::base_url(chan));
    if let Err(error) = super::fetch(chan, &url, &path, FETCH) {
        if error.downcast_ref::<super::MetadataNotFound>().is_some() {
            bail!("signed update metadata expired; the channel publishes no timestamp");
        }
        return Err(refused(error));
    }
    let envelope = super::read_small(&path, FETCH.max_bytes).map_err(refused)?;
    verify(&envelope, &key, offer, manifest, chan.label(), now)
        .map(Some)
        .map_err(refused)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "ab";

    fn manifest() -> Freshness {
        Freshness {
            schema: 1,
            channel: "enterprise".into(),
            arch: std::env::consts::ARCH.into(),
            sequence: 7,
            issued_at: MIN_CLOCK,
            expires_at: MIN_CLOCK + MAX_LIFETIME,
        }
    }

    fn document(change: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
        let mut value = serde_json::json!({
            "schema": 1, "role": "timestamp", "channel": "enterprise",
            "arch": std::env::consts::ARCH, "manifest_sha256": DIGEST.repeat(32),
            "sequence": 7, "issued_at": MIN_CLOCK + MAX_LIFETIME - 60,
            "expires_at": MIN_CLOCK + 2 * MAX_LIFETIME - 60,
        });
        change(&mut value);
        serde_json::to_vec(&value).unwrap()
    }

    fn check(bytes: &[u8], now: u64) -> Result<u64> {
        window(bytes, &manifest(), &DIGEST.repeat(32), "enterprise", now)
    }

    #[test]
    fn a_bound_fresh_timestamp_moves_only_the_effective_expiry() {
        let now = MIN_CLOCK + MAX_LIFETIME + 10;
        assert_eq!(
            check(&document(|_| {}), now).unwrap(),
            MIN_CLOCK + 2 * MAX_LIFETIME - 60
        );
    }

    #[test]
    fn every_binding_and_window_violation_is_refused() {
        let now = MIN_CLOCK + MAX_LIFETIME + 10;
        type Change = fn(&mut serde_json::Value);
        let cases: &[(&str, Change)] = &[
            ("wrong digest", |v| {
                v["manifest_sha256"] = "cd".repeat(32).into()
            }),
            ("older sequence", |v| v["sequence"] = 6.into()),
            ("newer sequence", |v| v["sequence"] = 8.into()),
            ("swapped channel", |v| v["channel"] = "community".into()),
            ("other arch", |v| v["arch"] = "aarch64".into()),
            ("other role", |v| v["role"] = "release".into()),
            ("schema 2", |v| v["schema"] = 2.into()),
            ("float sequence", |v| v["sequence"] = 7.0.into()),
            ("string time", |v| v["issued_at"] = "now".into()),
            ("extra field", |v| v["note"] = "x".into()),
            ("missing field", |v| {
                v.as_object_mut().unwrap().remove("arch");
            }),
            ("issued before manifest", |v| {
                v["issued_at"] = (MIN_CLOCK - 1).into()
            }),
            ("empty window", |v| v["expires_at"] = v["issued_at"].clone()),
            ("over 14 days", |v| {
                v["expires_at"] = (MIN_CLOCK + 2 * MAX_LIFETIME - 59).into()
            }),
            ("not yet valid", |v| {
                v["issued_at"] = (MIN_CLOCK + MAX_LIFETIME + 10 + CLOCK_SKEW + 1).into();
                v["expires_at"] = (MIN_CLOCK + 2 * MAX_LIFETIME).into();
            }),
            ("expired timestamp", |v| {
                v["issued_at"] = (MIN_CLOCK + 20).into();
                v["expires_at"] = (MIN_CLOCK + MAX_LIFETIME + 10).into();
            }),
        ];
        for (name, change) in cases {
            assert!(check(&document(change), now).is_err(), "{name}");
        }
        let mut duplicated = String::from_utf8(document(|_| {})).unwrap();
        duplicated.insert_str(1, r#""sequence":7,"#);
        assert!(
            check(duplicated.as_bytes(), now).is_err(),
            "duplicate field"
        );
        assert!(check(&document(|_| {}), 0).is_err(), "unset clock");
        let mut other = manifest();
        other.channel = "community".into();
        assert!(
            window(
                &document(|_| {}),
                &other,
                &DIGEST.repeat(32),
                "enterprise",
                now
            )
            .is_err(),
            "manifest of another channel"
        );
    }

    #[test]
    fn the_ninety_day_ceiling_after_the_release_is_exact() {
        // Inside the timestamp's own window, so only the ceiling can refuse.
        let ceiling = MIN_CLOCK + MAX_EXTENSION;
        let now = ceiling - 100;
        let at = |expires: u64| {
            document(|v| {
                v["issued_at"] = (now - 60).into();
                v["expires_at"] = expires.into();
            })
        };
        assert_eq!(check(&at(ceiling), now).unwrap(), ceiling);
        let error = check(&at(ceiling + 1), now).unwrap_err().to_string();
        assert!(error.contains("90 days"), "{error}");
    }

    #[test]
    fn the_pinned_key_must_be_a_regular_file_and_never_blocks() {
        let dir = Scratch::new().unwrap();
        assert!(read_pinned_key(&dir.join("absent.pem")).unwrap().is_none());
        let fifo = dir.join("fifo.pem");
        let name = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        // A FIFO with no writer would block a plain open forever.
        let (done, wait) = std::sync::mpsc::channel();
        let path = fifo.clone();
        std::thread::spawn(move || done.send(read_pinned_key(&path).is_err()).unwrap());
        assert!(
            wait.recv_timeout(std::time::Duration::from_secs(5))
                .expect("reading a FIFO key blocked"),
            "a FIFO is not a pinned key"
        );
        assert!(
            read_pinned_key(&dir.0).is_err(),
            "a directory is not a pinned key"
        );
        std::fs::write(dir.join("big.pem"), vec![b'x'; 4097]).unwrap();
        assert!(read_pinned_key(&dir.join("big.pem")).is_err());
        std::fs::write(dir.join("key.pem"), b"pem").unwrap();
        assert_eq!(
            read_pinned_key(&dir.join("key.pem")).unwrap().as_deref(),
            Some("pem")
        );
    }

    #[test]
    fn malformed_envelopes_are_refused_before_any_signature_check() {
        use base64::Engine;
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let good =
            serde_json::json!({"schema":1,"timestamp":b64(b"{}"),"signature":b64(&[0u8; 64])});
        assert!(decode(&serde_json::to_vec(&good).unwrap()).is_ok());
        for bad in [
            serde_json::json!({"schema":2,"timestamp":b64(b"{}"),"signature":b64(&[0u8; 64])}),
            serde_json::json!({"schema":1,"timestamp":b64(b"{}"),"signature":b64(&[0u8; 63])}),
            serde_json::json!({"schema":1,"timestamp":"","signature":b64(&[0u8; 64])}),
            serde_json::json!({"schema":1,"timestamp":"!!","signature":b64(&[0u8; 64])}),
            serde_json::json!({"schema":1,"timestamp":b64(&[b'x'; 4097]),"signature":b64(&[0u8; 64])}),
            serde_json::json!({"schema":1,"timestamp":b64(b"{}"),"signature":b64(&[0u8; 64]),"x":1}),
            serde_json::json!({"schema":1,"timestamp":b64(b"{}")}),
        ] {
            assert!(decode(&serde_json::to_vec(&bad).unwrap()).is_err(), "{bad}");
        }
        assert!(decode(&vec![b' '; 8193]).is_err());
    }
}
