//! WireGuard Curve25519 key helpers: derive the public key from a private key,
//! and generate a fresh keypair. Keys are the standard base64 encoding of 32 raw
//! bytes (the `wg` tool's format).
use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use x25519_dalek::{PublicKey, StaticSecret};

pub fn decode_key(s: &str) -> Result<[u8; 32]> {
    let raw = STANDARD.decode(s).context("key is not valid base64")?;
    let arr: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("key must be 32 bytes"))?;
    Ok(arr)
}

pub fn public_from_private(private_b64: &str) -> Result<String> {
    let secret = StaticSecret::from(decode_key(private_b64)?);
    Ok(STANDARD.encode(PublicKey::from(&secret).as_bytes()))
}

/// (private_b64, public_b64)
pub fn generate_keypair() -> Result<(String, String)> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).context("getrandom")?;
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    Ok((
        STANDARD.encode(secret.to_bytes()),
        STANDARD.encode(public.as_bytes()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_roundtrips_private_to_public() {
        // A freshly generated keypair's public key is exactly what deriving from
        // the private key yields — the `wg pubkey` relationship.
        let (private, public) = generate_keypair().expect("generate");
        assert_eq!(public_from_private(&private).expect("derive"), public);
    }

    #[test]
    fn known_vector_derives_expected_public() {
        // Vector produced with the real `wg` tool: `wg genkey | wg pubkey`.
        let private = "ICOioMTTlfQE/2NndOoEntortz+0tZ5Hll0AEM7tdmE=";
        let public = "6gUqcU72dUQr2VqzOWxiON1qzkzIOQD7SkZjPjPFWXs=";
        assert_eq!(public_from_private(private).expect("derive"), public);
    }

    #[test]
    fn decode_key_rejects_wrong_length() {
        // 16 bytes of base64 ("AAAA..." decodes to fewer than 32 bytes).
        let short = STANDARD.encode([0u8; 16]);
        assert!(decode_key(&short).is_err());
        // Not base64 at all.
        assert!(decode_key("not valid base64 !!!").is_err());
        // Exactly 32 bytes is accepted.
        let ok = STANDARD.encode([7u8; 32]);
        assert!(decode_key(&ok).is_ok());
    }
}
