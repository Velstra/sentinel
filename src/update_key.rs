//! Release-key representation, shared by configuration and the verifier.
//! This validates an Ed25519 SubjectPublicKeyInfo, not a signature or trust.
use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};

const BEGIN: &str = "-----BEGIN PUBLIC KEY-----";
const END: &str = "-----END PUBLIC KEY-----";
// RFC8410 sections3/4: Ed25519 OID1.3.101.112, absent parameters, and a
// 32-byte public key in an octet-aligned BIT STRING. No private-key decoding.
const ED25519_SPKI: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0,
];

/// One replayable CLI value. Quotes preserve filenames containing whitespace,
/// quotes or backslashes; public PEM line breaks are representation only.
pub fn cli_value(value: &str) -> String {
    let flat = value.replace(['\r', '\n'], " ");
    if flat
        .chars()
        .any(|c| c.is_whitespace() || matches!(c, '"' | '\\' | '\''))
    {
        serde_json::to_string(&flat).expect("serializable public key")
    } else {
        flat
    }
}

/// Accept the original file reference without resolving it on the config host,
/// or canonicalize public PEM. Never trim/change a referenced pathname.
pub fn reference_or_pem(value: &str) -> Result<String> {
    if let Some(path) = value.strip_prefix("file:") {
        if path.is_empty() || path.len() > 4096 || path.chars().any(char::is_control) {
            bail!(
                "update public-key file reference needs a nonempty path without control characters"
            );
        }
        return Ok(value.to_string());
    }
    canonical_pem(value)
}

/// Whitespace is representation, not key material. In particular, repair the
/// old one-line form/export representation without changing its public bytes.
/// The complete DER length/prefix rejects foreign algorithms, NULL parameters,
/// concatenated keys and trailing ASN.1. OpenSSL still owns signature checking.
pub fn canonical_pem(value: &str) -> Result<String> {
    if value.len() > 4096 {
        bail!("update public-key PEM exceeds 4096 bytes");
    }
    let body = value.trim().strip_prefix(BEGIN).and_then(|v| v.strip_suffix(END))
        .context("update public-key must be an Ed25519 PUBLIC KEY PEM, not a private key, or a file:<path> reference")?;
    let compact: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let der = STANDARD
        .decode(&compact)
        .context("update public-key has invalid base64 encoding")?;
    if der.len() != ED25519_SPKI.len() + 32 || !der.starts_with(&ED25519_SPKI) {
        bail!("update public-key must contain exactly one Ed25519 SubjectPublicKeyInfo (RFC8410)");
    }
    Ok(format!("{BEGIN}\n{}\n{END}\n", STANDARD.encode(der)))
}

#[cfg(test)]
mod tests {
    use super::*;
    // Public example in https://www.rfc-editor.org/rfc/rfc8410#section-4.
    const PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----\n";

    #[test]
    fn canonical_crlf_spaced_and_legacy_flattened_keys_keep_identical_public_bytes() {
        for value in [
            PEM.into(),
            PEM.replace('\n', "\r\n"),
            PEM.replace('\n', " "),
            PEM.replace('\n', ""),
        ] {
            assert_eq!(canonical_pem(&value).unwrap(), PEM);
        }
    }

    #[test]
    fn file_references_are_not_read_or_silently_retargeted() {
        for value in [
            "file:/not-present/release.pem",
            "file:relative key.pem",
            "file:/key ending in a space ",
            "file:/etc/sentinel/releases/clé publique.pem ",
        ] {
            assert_eq!(reference_or_pem(value).unwrap(), value);
        }
        for value in ["file:", "file:/key\nother", "file:/key\0other"] {
            assert!(reference_or_pem(value).is_err());
        }
    }

    #[test]
    fn wrong_algorithm_parameters_lengths_and_trailing_bytes_fail_closed() {
        let original = STANDARD.decode(PEM.lines().nth(1).unwrap()).unwrap();
        let mut wrong_oid = original.clone();
        wrong_oid[8] = 0x6e; // X25519 is not a signing key.
        let mut wrong_unused_bits = original.clone();
        wrong_unused_bits[11] = 1;
        let mut trailing = original.clone();
        trailing.push(0);
        let mut parameters = original.clone();
        parameters.splice(9..9, [5, 0]);
        for der in [
            wrong_oid,
            wrong_unused_bits,
            trailing,
            parameters,
            original[..43].to_vec(),
        ] {
            let input = format!("{BEGIN}\n{}\n{END}", STANDARD.encode(der));
            assert!(canonical_pem(&input).is_err());
        }
    }

    #[test]
    fn malformed_duplicate_private_and_oversized_values_are_not_echoed() {
        for value in [
            "not a key".into(),
            "-----BEGIN PRIVATE KEY-----\nPRIVATE_MARKER\n-----END PRIVATE KEY-----".into(),
            PEM.replace("MCow", "%%%%"),
            format!("{PEM}{PEM}"),
            "x".repeat(4097),
        ] {
            let error = canonical_pem(&value).unwrap_err().to_string();
            assert!(!error.contains("PRIVATE_MARKER"));
        }
    }
}
