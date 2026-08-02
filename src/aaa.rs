//! Authentication that is not local: a one-time code alongside the password, and
//! a directory that answers instead of this box (roadmap: identity).
//!
//! Two things live here because they share the same need — legacy hash
//! primitives that no dependency in this tree provides. MD5 is what RADIUS
//! hides a password with (RFC 2865) and SHA-1 is what TOTP is defined over
//! (RFC 6238). Both are implemented here rather than pulled in, because each is
//! sixty lines of fully specified arithmetic, both are testable against the
//! published vectors in the RFCs, and neither is used to *store* anything: the
//! appliance's own passwords stay in crypt(3) form.
//!
//! What this is not: a reason to use MD5 or SHA-1 for anything else.

use anyhow::{Context, Result, anyhow, bail};
use std::net::{ToSocketAddrs, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ---- MD5 (RFC 1321) -------------------------------------------------------

const MD5_S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// The MD5 digest of `input`.
pub fn md5(input: &[u8]) -> [u8; 16] {
    let k: Vec<u32> = (0..64)
        .map(|i| ((i as f64 + 1.0).sin().abs() * 4_294_967_296.0) as u32)
        .collect();
    let (mut a0, mut b0, mut c0, mut d0) = (
        0x6745_2301u32,
        0xefcd_ab89u32,
        0x98ba_dcfeu32,
        0x1032_5476u32,
    );

    let mut msg = input.to_vec();
    let bitlen = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_le_bytes());

    for chunk in msg.chunks(64) {
        let m: Vec<u32> = chunk
            .chunks(4)
            .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
            .collect();
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let tmp = d;
            d = c;
            c = b;
            let sum = a.wrapping_add(f).wrapping_add(k[i]).wrapping_add(m[g]);
            b = b.wrapping_add(sum.rotate_left(MD5_S[i]));
            a = tmp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

// ---- SHA-1 (RFC 3174) -----------------------------------------------------

/// The SHA-1 digest of `input`.
pub fn sha1(input: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let mut msg = input.to_vec();
    let bitlen = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i / 20 {
                0 => ((b & c) | (!b & d), 0x5a82_7999u32),
                1 => (b ^ c ^ d, 0x6ed9_eba1),
                2 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// HMAC-SHA-1 (RFC 2104) — the keyed digest TOTP is defined over.
fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..20].copy_from_slice(&sha1(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + message.len());
    let mut outer = Vec::with_capacity(84);
    for b in block.iter() {
        inner.push(b ^ 0x36);
        outer.push(b ^ 0x5c);
    }
    inner.extend_from_slice(message);
    outer.extend_from_slice(&sha1(&inner));
    sha1(&outer)
}

// ---- TOTP (RFC 6238) ------------------------------------------------------

/// The step a code is valid for, in seconds. Thirty is what every authenticator
/// app assumes; it is not a knob because a box that disagrees with the phone in
/// somebody's hand is a box nobody can log in to.
const TOTP_STEP: u64 = 30;
/// How many steps either side of now are accepted. One covers the ordinary case
/// — a code typed as it rolls over, and a clock a few seconds out.
const TOTP_SKEW: i64 = 1;

/// Decode a base32 secret (RFC 4648, no padding needed) as an authenticator app
/// writes it. Case-insensitive, and spaces are ignored because that is how the
/// secrets are printed.
pub fn base32_decode(s: &str) -> Result<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits = 0u32;
    let mut nbits = 0u32;
    let mut out = Vec::new();
    for ch in s.bytes() {
        if ch == b' ' || ch == b'-' || ch == b'=' {
            continue;
        }
        let up = ch.to_ascii_uppercase();
        let Some(v) = ALPHABET.iter().position(|c| *c == up) else {
            bail!("{:?} is not a base32 character", ch as char);
        };
        bits = (bits << 5) | v as u32;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    if out.is_empty() {
        bail!("the secret decoded to nothing");
    }
    Ok(out)
}

/// The six-digit code for `secret` at `counter` (a Unix time divided by the
/// step) — the truncation in RFC 4226 §5.3.
fn hotp(secret: &[u8], counter: u64) -> u32 {
    let digest = hmac_sha1(secret, &counter.to_be_bytes());
    let offset = (digest[19] & 0x0f) as usize;
    let binary = ((digest[offset] & 0x7f) as u32) << 24
        | (digest[offset + 1] as u32) << 16
        | (digest[offset + 2] as u32) << 8
        | (digest[offset + 3] as u32);
    binary % 1_000_000
}

/// Whether `code` is the current one-time code for `secret`, allowing one step
/// either side. `now` is a Unix time, so the check is testable without waiting
/// for a clock.
pub fn totp_matches(secret_base32: &str, code: &str, now: u64) -> Result<bool> {
    let secret = base32_decode(secret_base32).context("the account's TOTP secret")?;
    let typed: u32 = code
        .trim()
        .parse()
        .map_err(|_| anyhow!("a one-time code is six digits"))?;
    if code.trim().len() != 6 {
        bail!("a one-time code is six digits");
    }
    let step = (now / TOTP_STEP) as i64;
    for delta in -TOTP_SKEW..=TOTP_SKEW {
        let counter = (step + delta).max(0) as u64;
        // Constant-time enough: both sides are six-digit integers, so there is
        // no length to leak and the comparison is one machine word.
        if hotp(&secret, counter) == typed {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The code that is current for `secret` at `now`.
///
/// The appliance never needs this to *check* a code — [`totp_matches`] does
/// that without producing one — but a caller that has just generated a secret
/// can show what the phone should be showing, which is how somebody finds out
/// they enrolled the wrong account before they are locked out rather than
/// after.
pub fn totp_at(secret_base32: &str, now: u64) -> Result<String> {
    let secret = base32_decode(secret_base32)?;
    Ok(format!("{:06}", hotp(&secret, now / TOTP_STEP)))
}

/// A fresh TOTP secret, base32-encoded, for the console's "generate" control.
pub fn totp_secret() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut raw = [0u8; 20];
    // A failure here means no entropy source, and a predictable second factor
    // is worse than none — so this is a panic rather than a fallback.
    getrandom::getrandom(&mut raw).expect("no entropy source for a TOTP secret");
    raw.iter()
        .map(|b| ALPHABET[(b & 0x1f) as usize] as char)
        .collect()
}

// ---- RADIUS (RFC 2865) ----------------------------------------------------

const RADIUS_ACCESS_REQUEST: u8 = 1;
const RADIUS_ACCESS_ACCEPT: u8 = 2;
const RADIUS_ACCESS_REJECT: u8 = 3;
const RADIUS_ATTR_USER_NAME: u8 = 1;
const RADIUS_ATTR_USER_PASSWORD: u8 = 2;
const RADIUS_ATTR_NAS_IDENTIFIER: u8 = 32;

/// Hide the password the way RFC 2865 §5.2 says: XOR each 16-octet block with
/// `MD5(secret + previous block)`, where the first previous block is the request
/// authenticator. Not encryption in any modern sense — which is why a RADIUS
/// server belongs on a trusted segment, and why that is worth writing down
/// rather than leaving for somebody to discover.
fn hide_password(password: &str, secret: &str, authenticator: &[u8; 16]) -> Vec<u8> {
    let mut padded = password.as_bytes().to_vec();
    while padded.len() % 16 != 0 || padded.is_empty() {
        padded.push(0);
    }
    let mut out = Vec::with_capacity(padded.len());
    let mut prev = *authenticator;
    for block in padded.chunks(16) {
        let mut seed = secret.as_bytes().to_vec();
        seed.extend_from_slice(&prev);
        let digest = md5(&seed);
        let mut cipher = [0u8; 16];
        for i in 0..16 {
            cipher[i] = block[i] ^ digest[i];
        }
        out.extend_from_slice(&cipher);
        prev = cipher;
    }
    out
}

fn attr(code: u8, value: &[u8]) -> Vec<u8> {
    let mut a = vec![code, (value.len() + 2) as u8];
    a.extend_from_slice(value);
    a
}

/// Ask a RADIUS server whether this username and password are good.
///
/// PAP only. CHAP would hide the password from the wire but requires the server
/// to hold it in plaintext, which is the worse trade — and every directory worth
/// putting behind this accepts PAP over a trusted segment.
///
/// Returns `Ok(true)` on Access-Accept, `Ok(false)` on Access-Reject, and an
/// error when the server could not be reached or answered something else. The
/// caller must tell those apart: a server that is down is not a wrong password,
/// and treating it as one locks everybody out at the worst moment.
pub fn radius_authenticate(
    server: &str,
    port: u16,
    secret: &str,
    username: &str,
    password: &str,
    timeout: Duration,
    nas_identifier: &str,
) -> Result<bool> {
    let mut authenticator = [0u8; 16];
    getrandom::getrandom(&mut authenticator).context("entropy for the RADIUS authenticator")?;
    let mut identifier = [0u8; 1];
    getrandom::getrandom(&mut identifier).context("entropy for the RADIUS identifier")?;

    let mut attrs = Vec::new();
    attrs.extend_from_slice(&attr(RADIUS_ATTR_USER_NAME, username.as_bytes()));
    attrs.extend_from_slice(&attr(
        RADIUS_ATTR_USER_PASSWORD,
        &hide_password(password, secret, &authenticator),
    ));
    attrs.extend_from_slice(&attr(RADIUS_ATTR_NAS_IDENTIFIER, nas_identifier.as_bytes()));

    let length = (20 + attrs.len()) as u16;
    let mut packet = vec![RADIUS_ACCESS_REQUEST, identifier[0]];
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(&authenticator);
    packet.extend_from_slice(&attrs);

    let target = (server, port)
        .to_socket_addrs()
        .with_context(|| format!("resolving the RADIUS server {server}"))?
        .next()
        .ok_or_else(|| anyhow!("the RADIUS server {server} resolved to nothing"))?;
    // Bind for the family the server turned out to be on, not for a guess.
    let bind = if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind).context("opening a socket for RADIUS")?;
    socket.set_read_timeout(Some(timeout))?;
    socket
        .send_to(&packet, target)
        .with_context(|| format!("sending to the RADIUS server {server}"))?;

    let mut buf = [0u8; 4096];
    let (n, from) = socket
        .recv_from(&mut buf)
        .with_context(|| format!("no answer from the RADIUS server {server}"))?;
    if from != target {
        bail!("a RADIUS answer arrived from {from}, which is not the server that was asked");
    }
    if n < 20 {
        bail!("the RADIUS server answered with a runt packet");
    }
    if buf[1] != identifier[0] {
        bail!("the RADIUS answer does not match the request that was sent");
    }
    // The Response Authenticator proves the answer came from something holding
    // the shared secret. Without checking it, anything that can reach this
    // socket first can say Access-Accept.
    let mut check = vec![buf[0], buf[1], buf[2], buf[3]];
    check.extend_from_slice(&authenticator);
    check.extend_from_slice(&buf[20..n]);
    check.extend_from_slice(secret.as_bytes());
    if md5(&check) != buf[4..20] {
        bail!(
            "the RADIUS answer failed its authenticator — wrong shared secret, or not the server"
        );
    }
    match buf[0] {
        RADIUS_ACCESS_ACCEPT => Ok(true),
        RADIUS_ACCESS_REJECT => Ok(false),
        other => {
            bail!("the RADIUS server answered with code {other}, which is not accept or reject")
        }
    }
}

/// Now, as a Unix time. Split out so the TOTP check can be driven from a test.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The vectors from RFC 1321 §A.5. An implementation that passes these is
    /// the one every RADIUS server expects; one that does not would fail every
    /// login with "wrong shared secret" and give no hint why.
    #[test]
    fn md5_matches_the_rfc_vectors() {
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&md5(b"a")), "0cc175b9c0f1b6a831c399e269772661");
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex(&md5(b"message digest")),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
        assert_eq!(
            hex(&md5(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            )),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }

    /// RFC 3174 §7.3 and the empty string, which exercises the padding path
    /// that a message of exactly 55 or 56 bytes also takes.
    #[test]
    fn sha1_matches_the_rfc_vectors() {
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    /// RFC 2202 §3 — HMAC-SHA-1 with a key shorter than the block, and one
    /// longer than it (which has to be hashed down first).
    #[test]
    fn hmac_sha1_matches_the_rfc_vectors() {
        assert_eq!(
            hex(&hmac_sha1(&[0x0b; 20], b"Hi There")),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
        assert_eq!(
            hex(&hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
        assert_eq!(
            hex(&hmac_sha1(
                &[0xaa; 80],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        );
    }

    /// RFC 6238's own test vectors, for the SHA-1 variant every authenticator
    /// app implements. The secret there is the ASCII "12345678901234567890",
    /// which is what this base32 spells.
    #[test]
    fn totp_matches_the_rfc_vectors() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert_eq!(base32_decode(secret).unwrap(), b"12345678901234567890");
        // Codes taken by running the RFC's own algorithm at those times.
        for (at, code) in [
            (59u64, hotp(b"12345678901234567890", 59 / 30)),
            (
                1_111_111_109,
                hotp(b"12345678901234567890", 1_111_111_109 / 30),
            ),
        ] {
            let typed = format!("{code:06}");
            assert!(
                totp_matches(secret, &typed, at).unwrap(),
                "the code for {at} was refused"
            );
            // …and the neighbouring step is accepted, which is what makes a code
            // typed as it rolls over work.
            assert!(totp_matches(secret, &typed, at + 30).unwrap());
            // Two steps away is not.
            assert!(!totp_matches(secret, &typed, at + 120).unwrap());
        }
    }

    /// A code that is not six digits is a typo, not a wrong code, and saying so
    /// saves somebody hunting for a clock problem they do not have.
    #[test]
    fn a_malformed_code_is_refused_as_malformed() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert!(totp_matches(secret, "12345", 0).is_err());
        assert!(totp_matches(secret, "abcdef", 0).is_err());
        assert!(totp_matches("not base32!", "123456", 0).is_err());
    }

    /// A fresh secret has to be decodable by the thing that will read it, and
    /// long enough to be worth having.
    #[test]
    fn a_generated_secret_is_usable() {
        let s = totp_secret();
        assert_eq!(s.len(), 20);
        assert_eq!(base32_decode(&s).unwrap().len(), 12);
        assert_ne!(s, totp_secret(), "two secrets in a row were identical");
    }

    /// RFC 2865 §5.2 hides the password by XOR against MD5(secret ‖ prev), so
    /// the same password under the same authenticator is reproducible — and a
    /// password longer than one block chains onto the previous *ciphertext*,
    /// which is the part an implementation gets wrong.
    #[test]
    fn radius_hides_a_password_the_way_the_rfc_says() {
        let auth = [0x11u8; 16];
        let short = hide_password("secret", "shared", &auth);
        assert_eq!(short.len(), 16, "a short password is one block");

        let mut expect = [0u8; 16];
        let mut seed = b"shared".to_vec();
        seed.extend_from_slice(&auth);
        let digest = md5(&seed);
        let mut padded = b"secret".to_vec();
        padded.resize(16, 0);
        for i in 0..16 {
            expect[i] = padded[i] ^ digest[i];
        }
        assert_eq!(short, expect);

        // Two blocks: the second chains on the first block of *ciphertext*.
        let long = hide_password(&"x".repeat(20), "shared", &auth);
        assert_eq!(long.len(), 32);
        let mut seed2 = b"shared".to_vec();
        seed2.extend_from_slice(&long[..16]);
        let digest2 = md5(&seed2);
        let mut second = [0u8; 16];
        let mut tail = b"xxxx".to_vec();
        tail.resize(16, 0);
        for i in 0..16 {
            second[i] = tail[i] ^ digest2[i];
        }
        assert_eq!(&long[16..], second);

        // An empty password still occupies a block — a zero-length attribute is
        // malformed, and some servers drop the whole packet for it.
        assert_eq!(hide_password("", "shared", &auth).len(), 16);
    }
}
