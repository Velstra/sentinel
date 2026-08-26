//! Authentication that is not local: a one-time code alongside the password, and
//! a directory that answers instead of this box (roadmap: identity).
//!
//! Two things live here because they share the same need — legacy hash
//! primitives that no dependency in this tree provides. MD5 is what RADIUS
//! hides a password with (RFC 2865) and what TACACS+ builds its body pad from
//! (RFC 8907); SHA-1 is what TOTP is defined over
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

/// Encode one RADIUS attribute (RFC 2865 §5): `type`, then `length` (the whole
/// TLV, i.e. value + 2), then the value. `length` is a single octet, so a value
/// longer than 253 bytes cannot be represented — truncating it (`as u8`
/// wrapping) would declare a short length and leave the tail to be parsed as a
/// forged next attribute (attribute injection via, e.g., an over-long username).
/// Reject it instead.
fn attr(code: u8, value: &[u8]) -> Result<Vec<u8>> {
    if value.len() > 253 {
        bail!(
            "RADIUS attribute {code} is {} bytes; the per-attribute maximum is 253",
            value.len()
        );
    }
    let mut a = vec![code, (value.len() + 2) as u8];
    a.extend_from_slice(value);
    Ok(a)
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
    attrs.extend_from_slice(&attr(RADIUS_ATTR_USER_NAME, username.as_bytes())?);
    attrs.extend_from_slice(&attr(
        RADIUS_ATTR_USER_PASSWORD,
        &hide_password(password, secret, &authenticator),
    )?);
    attrs.extend_from_slice(&attr(RADIUS_ATTR_NAS_IDENTIFIER, nas_identifier.as_bytes())?);

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

// ---- LDAP (RFC 4511 simple bind, via ldapwhoami) --------------------------

/// Escape a value for use inside a DN (RFC 4514 §2.4).
///
/// The username goes into `uid=<here>,ou=…`, so a username containing a comma
/// would not be a username any more — it would be a different DN, chosen by
/// whoever typed it. That is the LDAP shape of an injection, and it is why this
/// exists rather than a format string.
pub fn dn_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    for (i, ch) in value.chars().enumerate() {
        let special = matches!(ch, ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=');
        // A space or `#` is only special at the start; a space also at the end.
        let edge =
            (i == 0 && (ch == ' ' || ch == '#')) || (i + ch.len_utf8() == bytes.len() && ch == ' ');
        if special || edge {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// What a directory said about a username and password.
#[derive(Debug, PartialEq, Eq)]
pub enum Directory {
    /// The bind succeeded.
    Accepted,
    /// The directory answered, and the answer was no.
    Rejected,
}

/// `ldapwhoami`'s exit status, read as an answer.
///
/// 0 is a successful bind. **49** is `LDAP_INVALID_CREDENTIALS` — a real answer
/// from a reachable directory, which must not be confused with the directory
/// being unreachable: treating an outage as a wrong password locks everybody out
/// at the moment the network is already broken.
pub fn directory_from_exit(code: Option<i32>) -> Result<Directory> {
    match code {
        Some(0) => Ok(Directory::Accepted),
        Some(49) => Ok(Directory::Rejected),
        Some(other) => bail!("the directory did not answer (ldap exit {other})"),
        None => bail!("the directory query was killed before it answered"),
    }
}

/// The URI and bind DN a query would use. Split out from the query itself so
/// both can be checked without a directory to talk to.
pub fn ldap_target(
    server: &str,
    port: Option<u16>,
    tls: &str,
    base_dn: &str,
    user_attribute: &str,
    username: &str,
) -> (String, String) {
    let scheme = if tls == "ldaps" { "ldaps" } else { "ldap" };
    let port = port.unwrap_or(if scheme == "ldaps" { 636 } else { 389 });
    // A literal IPv6 address needs brackets in a URI, or the colons in it read
    // as the port separator.
    let host = if server.contains(':') && !server.starts_with('[') {
        format!("[{server}]")
    } else {
        server.to_string()
    };
    (
        format!("{scheme}://{host}:{port}"),
        format!("{user_attribute}={},{base_dn}", dn_escape(username)),
    )
}

/// Ask a directory whether this username and password are good, by binding as
/// that user.
///
/// The password goes in a **file**, not on the command line: `/proc` is
/// world-readable, so `-w <password>` would show it to every local user for as
/// long as the call takes.
#[allow(clippy::too_many_arguments)]
pub fn ldap_authenticate(
    server: &str,
    port: Option<u16>,
    tls: &str,
    base_dn: &str,
    user_attribute: &str,
    username: &str,
    password: &str,
    timeout: u32,
) -> Result<Directory> {
    let (uri, dn) = ldap_target(server, port, tls, base_dn, user_attribute, username);
    let dir = std::path::Path::new("/run/sentinel");
    std::fs::create_dir_all(dir).ok();
    let secret = dir.join(format!("ldap-bind.{}", std::process::id()));
    crate::system::stage_private(&secret, password).context("staging the bind password")?;
    let out = crate::system::ldapwhoami(&uri, &dn, &secret, tls == "starttls", timeout);
    let _ = std::fs::remove_file(&secret);
    directory_from_exit(out?)
}

// ---- TACACS+ (RFC 8907) ---------------------------------------------------
//
// The third of the trio a network operator expects beside RADIUS and LDAP.
// Only the authentication part of the protocol is spoken here — an appliance
// login needs a yes or a no, not command authorization or accounting — and
// only the ASCII flow, which every TACACS+ server supports: the client STARTs
// a session naming the user, the server asks for the password (GETPASS), the
// client CONTINUEs with it, and the server answers PASS or FAIL.

/// TACACS+ runs over TCP, on 49 unless the configuration says otherwise.
pub const TACACS_DEFAULT_PORT: u16 = 49;

/// `major_version` 0xc, `minor_version` 0 — the version the ASCII flow speaks
/// (RFC 8907 §4.1; minor 1 is for PAP/CHAP, which this client does not use).
const TACACS_VERSION: u8 = 0xc0;
/// Packet type: authentication (§4.1). Authorization (2) and accounting (3)
/// are deliberately not implemented.
const TACACS_TYPE_AUTHEN: u8 = 0x01;
/// Header flag: the body is NOT obfuscated. This client never sets it, and a
/// server answering with it has no shared secret configured for us — a
/// misconfiguration to report, not an answer to trust.
const TACACS_FLAG_UNENCRYPTED: u8 = 0x01;

/// START: action LOGIN, at the user privilege level, ASCII, login service
/// (§5.1). One combination, spelled out, because it is the only one sent.
const TACACS_AUTHEN_LOGIN: u8 = 0x01;
const TACACS_PRIV_LVL_USER: u8 = 0x01;
const TACACS_AUTHEN_TYPE_ASCII: u8 = 0x01;
const TACACS_AUTHEN_SVC_LOGIN: u8 = 0x01;

/// REPLY statuses (§5.2). GETDATA/RESTART/FOLLOW exist in the RFC; a server
/// answering one of those wants a conversation this client does not have
/// (a password change, a redirect), and saying so beats pretending.
const TACACS_STATUS_PASS: u8 = 0x01;
const TACACS_STATUS_FAIL: u8 = 0x02;
const TACACS_STATUS_GETUSER: u8 = 0x04;
const TACACS_STATUS_GETPASS: u8 = 0x05;
const TACACS_STATUS_ERROR: u8 = 0x07;

/// The body cap accepted from a server. A REPLY is a status and a prompt; a
/// length claiming megabytes is not a reply, it is an attempt to make this
/// client allocate one.
const TACACS_MAX_REPLY: u32 = 65536;

/// The pseudo-pad of RFC 8907 §4.5: MD5 blocks chained over the header fields
/// and the shared secret, truncated to the body length.
///
///   pad_1 = MD5(session_id ‖ secret ‖ version ‖ seq_no)
///   pad_n = MD5(session_id ‖ secret ‖ version ‖ seq_no ‖ pad_{n-1})
///
/// The body is XORed with this pad. That is **obfuscation, not encryption** —
/// the RFC itself says so (§10.3): anyone holding the shared secret, or able
/// to guess it offline, reads every packet. A TACACS+ server belongs on a
/// segment you already trust, exactly like a RADIUS server.
fn tacacs_pad(session_id: &[u8; 4], secret: &str, seq_no: u8, len: usize) -> Vec<u8> {
    let mut pad = Vec::with_capacity(len.next_multiple_of(16));
    let mut prev: Option<[u8; 16]> = None;
    while pad.len() < len {
        let mut seed = session_id.to_vec();
        seed.extend_from_slice(secret.as_bytes());
        seed.push(TACACS_VERSION);
        seed.push(seq_no);
        if let Some(p) = prev {
            seed.extend_from_slice(&p);
        }
        let digest = md5(&seed);
        pad.extend_from_slice(&digest);
        prev = Some(digest);
    }
    pad.truncate(len);
    pad
}

/// A complete packet: the 12-byte header (§4.1) followed by the body XORed
/// with the pseudo-pad. `seq_no` is odd for the client (1, 3, …), even for
/// the server.
fn tacacs_packet(session_id: &[u8; 4], secret: &str, seq_no: u8, body: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(12 + body.len());
    packet.push(TACACS_VERSION);
    packet.push(TACACS_TYPE_AUTHEN);
    packet.push(seq_no);
    packet.push(0); // flags: obfuscated body, single session
    packet.extend_from_slice(session_id);
    packet.extend_from_slice(&(body.len() as u32).to_be_bytes());
    let pad = tacacs_pad(session_id, secret, seq_no, body.len());
    packet.extend(body.iter().zip(&pad).map(|(b, p)| b ^ p));
    packet
}

/// The START body (§5.1) that opens an ASCII login for `username`. The `port`
/// and `rem_addr` fields describe the line the user is on; this client reports
/// where the login arrived so the server's accounting names something real.
fn tacacs_start_body(username: &str, port: &str, rem_addr: &str) -> Result<Vec<u8>> {
    // Each length is one octet, and like the RADIUS attribute cap, truncating
    // (`as u8` wrapping) would declare a short length and let the tail be
    // parsed as some other field. Refuse instead.
    for (what, v) in [("username", username), ("port", port), ("rem_addr", rem_addr)] {
        if v.len() > 255 {
            bail!("TACACS+ {what} is {} bytes; the field maximum is 255", v.len());
        }
    }
    let mut body = vec![
        TACACS_AUTHEN_LOGIN,
        TACACS_PRIV_LVL_USER,
        TACACS_AUTHEN_TYPE_ASCII,
        TACACS_AUTHEN_SVC_LOGIN,
        username.len() as u8,
        port.len() as u8,
        rem_addr.len() as u8,
        0, // data_len: the ASCII flow sends nothing in START's data field
    ];
    body.extend_from_slice(username.as_bytes());
    body.extend_from_slice(port.as_bytes());
    body.extend_from_slice(rem_addr.as_bytes());
    Ok(body)
}

/// The CONTINUE body (§5.3) answering a server prompt — for this client,
/// always the password after a GETPASS (or the username after a GETUSER from
/// a server that ignored the one in START).
fn tacacs_continue_body(user_msg: &str) -> Result<Vec<u8>> {
    if user_msg.len() > u16::MAX as usize {
        bail!(
            "a TACACS+ answer of {} bytes does not fit its 16-bit length field",
            user_msg.len()
        );
    }
    let mut body = Vec::with_capacity(5 + user_msg.len());
    body.extend_from_slice(&(user_msg.len() as u16).to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes()); // data_len
    body.push(0); // flags
    body.extend_from_slice(user_msg.as_bytes());
    Ok(body)
}

/// A REPLY body (§5.2), decoded: the status octet and the server's message
/// (which a FAIL or ERROR often uses to say why).
fn tacacs_parse_reply(clear: &[u8]) -> Result<(u8, String)> {
    if clear.len() < 6 {
        bail!("the TACACS+ reply body is {} bytes; the fixed part alone is 6", clear.len());
    }
    let status = clear[0];
    let server_msg_len = u16::from_be_bytes([clear[2], clear[3]]) as usize;
    let data_len = u16::from_be_bytes([clear[4], clear[5]]) as usize;
    // A reply whose declared lengths overrun the body it arrived in is not a
    // reply that got shortened; it is a length field lying about the bytes
    // that follow, and reading past them would read the pad.
    if 6 + server_msg_len + data_len > clear.len() {
        bail!(
            "the TACACS+ reply declares {server_msg_len}+{data_len} bytes of text in a \
             {}-byte body",
            clear.len()
        );
    }
    let server_msg = String::from_utf8_lossy(&clear[6..6 + server_msg_len]).into_owned();
    Ok((status, server_msg))
}

/// Read one server packet for `session_id`, expecting `seq_no`, and return the
/// de-obfuscated body.
fn tacacs_read_reply(
    stream: &mut std::net::TcpStream,
    session_id: &[u8; 4],
    secret: &str,
    seq_no: u8,
) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut header = [0u8; 12];
    stream
        .read_exact(&mut header)
        .context("no answer from the TACACS+ server")?;
    if header[0] != TACACS_VERSION {
        bail!(
            "the TACACS+ server answered with version {:#04x}, not the {TACACS_VERSION:#04x} \
             this client speaks",
            header[0]
        );
    }
    if header[1] != TACACS_TYPE_AUTHEN {
        bail!("the TACACS+ server answered with packet type {}, not authentication", header[1]);
    }
    if header[2] != seq_no {
        bail!("the TACACS+ server answered out of sequence ({} where {seq_no} was next)", header[2]);
    }
    if header[3] & TACACS_FLAG_UNENCRYPTED != 0 {
        // The server is answering in the clear, which means it has no shared
        // secret configured for this client. Its answer may even be readable —
        // but trusting an unobfuscated PASS would let anything on the path
        // mint one.
        bail!(
            "the TACACS+ server answered unobfuscated — it has no shared secret configured \
             for this box; configure the same secret on both ends"
        );
    }
    if header[4..8] != session_id[..] {
        bail!("the TACACS+ answer belongs to a different session than the one opened");
    }
    let len = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
    if len > TACACS_MAX_REPLY {
        bail!("the TACACS+ server declared a {len}-byte reply, which is not a plausible reply");
    }
    let mut body = vec![0u8; len as usize];
    stream
        .read_exact(&mut body)
        .context("the TACACS+ reply ended before its declared length")?;
    let pad = tacacs_pad(session_id, secret, seq_no, body.len());
    for (b, p) in body.iter_mut().zip(&pad) {
        *b ^= p;
    }
    Ok(body)
}

/// Ask a TACACS+ server whether this username and password are good, over the
/// ASCII authentication flow of RFC 8907.
///
/// Returns [`Directory::Accepted`] on PASS, [`Directory::Rejected`] on FAIL,
/// and an error when the server could not be reached or the conversation went
/// somewhere this client does not follow. The caller must keep those apart for
/// the same reason as with RADIUS and LDAP: a server that is down is not a
/// wrong password, and treating it as one locks everybody out at the worst
/// moment.
pub fn tacacs_authenticate(
    server: &str,
    port: u16,
    secret: &str,
    username: &str,
    password: &str,
    timeout: Duration,
) -> Result<Directory> {
    use std::io::Write;
    let target = (server, port)
        .to_socket_addrs()
        .with_context(|| format!("resolving the TACACS+ server {server}"))?
        .next()
        .ok_or_else(|| anyhow!("the TACACS+ server {server} resolved to nothing"))?;
    let mut stream = std::net::TcpStream::connect_timeout(&target, timeout)
        .with_context(|| format!("connecting to the TACACS+ server {server}"))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let mut session_id = [0u8; 4];
    getrandom::getrandom(&mut session_id).context("entropy for the TACACS+ session id")?;

    // Where this login arrived, for the server's own log line.
    let start = tacacs_start_body(username, "api", "")?;
    stream
        .write_all(&tacacs_packet(&session_id, secret, 1, &start))
        .with_context(|| format!("sending to the TACACS+ server {server}"))?;

    // START is seq 1; the server's replies are even, ours odd. The password
    // goes over the wire once: a server that asks again after receiving it is
    // off-script, and the loop ends rather than repeating a credential.
    let mut seq = 2u8;
    let mut sent_password = false;
    loop {
        let body = tacacs_read_reply(&mut stream, &session_id, secret, seq)?;
        let (status, server_msg) = tacacs_parse_reply(&body)?;
        let answer = match status {
            TACACS_STATUS_PASS => return Ok(Directory::Accepted),
            TACACS_STATUS_FAIL => return Ok(Directory::Rejected),
            // A server may ask for the username even though START carried it.
            TACACS_STATUS_GETUSER => username,
            TACACS_STATUS_GETPASS if !sent_password => {
                sent_password = true;
                password
            }
            TACACS_STATUS_GETPASS => {
                bail!("the TACACS+ server asked for the password twice; not repeating it")
            }
            TACACS_STATUS_ERROR => bail!(
                "the TACACS+ server reported an error{}",
                if server_msg.is_empty() {
                    String::new()
                } else {
                    format!(": {server_msg}")
                }
            ),
            other => bail!(
                "the TACACS+ server answered status {other}, which the ASCII login flow \
                 does not use"
            ),
        };
        seq = seq
            .checked_add(1)
            .ok_or_else(|| anyhow!("the TACACS+ conversation ran past 255 packets"))?;
        stream
            .write_all(&tacacs_packet(&session_id, secret, seq, &tacacs_continue_body(answer)?))
            .with_context(|| format!("sending to the TACACS+ server {server}"))?;
        seq = seq
            .checked_add(1)
            .ok_or_else(|| anyhow!("the TACACS+ conversation ran past 255 packets"))?;
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

    /// The username goes into `uid=<here>,ou=…`, so a username with a comma in
    /// it would not be a username any more — it would be a different DN, chosen
    /// by whoever typed it. That is the LDAP shape of an injection.
    #[test]
    fn a_username_cannot_rewrite_the_dn_it_goes_into() {
        assert_eq!(dn_escape("alice"), "alice");
        // The classic: end the RDN early and append another.
        assert_eq!(
            dn_escape("alice,ou=admins,dc=example,dc=com"),
            "alice\\,ou\\=admins\\,dc\\=example\\,dc\\=com"
        );
        assert_eq!(dn_escape("a+b"), "a\\+b");
        assert_eq!(dn_escape("a\\b"), "a\\\\b");
        // Space and `#` are special only where they can be mistaken for syntax.
        assert_eq!(dn_escape(" leading"), "\\ leading");
        assert_eq!(dn_escape("trailing "), "trailing\\ ");
        assert_eq!(dn_escape("mid dle"), "mid dle");
        assert_eq!(dn_escape("#hash"), "\\#hash");
        assert_eq!(dn_escape("no#hash"), "no#hash");
    }

    /// The URI and the DN are what the query is; both are built here so both can
    /// be checked without a directory to talk to.
    #[test]
    fn the_bind_target_is_built_from_the_configuration() {
        let (uri, dn) = ldap_target(
            "ldap.example.com",
            None,
            "ldaps",
            "ou=people,dc=example,dc=com",
            "uid",
            "alice",
        );
        assert_eq!(uri, "ldaps://ldap.example.com:636");
        assert_eq!(dn, "uid=alice,ou=people,dc=example,dc=com");

        // StartTLS runs on the plain port…
        let (uri, _) = ldap_target("dir", None, "starttls", "dc=x", "uid", "a");
        assert_eq!(uri, "ldap://dir:389");
        // …and an explicit port wins over both defaults.
        let (uri, _) = ldap_target("dir", Some(1636), "ldaps", "dc=x", "uid", "a");
        assert_eq!(uri, "ldaps://dir:1636");

        // A literal IPv6 address needs brackets, or its colons read as the port
        // separator and the query goes somewhere else entirely.
        let (uri, _) = ldap_target("2001:db8::5", None, "ldaps", "dc=x", "uid", "a");
        assert_eq!(uri, "ldaps://[2001:db8::5]:636");

        // Active Directory names accounts differently, and the DN follows.
        let (_, dn) = ldap_target("d", None, "ldaps", "dc=x", "sAMAccountName", "alice");
        assert_eq!(dn, "sAMAccountName=alice,dc=x");
    }

    /// 49 is `LDAP_INVALID_CREDENTIALS` — a real answer from a reachable
    /// directory. Confusing it with an unreachable one is what locks everybody
    /// out at the moment the network is already broken.
    #[test]
    fn a_rejection_and_an_outage_are_different_answers() {
        assert_eq!(directory_from_exit(Some(0)).unwrap(), Directory::Accepted);
        assert_eq!(directory_from_exit(Some(49)).unwrap(), Directory::Rejected);
        // Anything else is "could not ask", not "wrong password".
        assert!(directory_from_exit(Some(255)).is_err());
        assert!(directory_from_exit(Some(1)).is_err());
        assert!(directory_from_exit(None).is_err());
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

    /// The START body, pinned octet by octet against RFC 8907 §5.1 — written
    /// out by hand from the RFC's field layout, not produced by the encoder
    /// under test. A codec that only agrees with itself has been wrong here
    /// before (the OSPF flag byte), and a TACACS+ server would answer such a
    /// packet with silence.
    #[test]
    fn tacacs_start_is_the_rfc_wire_layout() {
        let body = tacacs_start_body("alice", "api", "").unwrap();
        let expected: &[u8] = &[
            0x01, // action: LOGIN
            0x01, // priv_lvl: user
            0x01, // authen_type: ASCII
            0x01, // authen_service: login
            0x05, // user_len:      "alice"
            0x03, // port_len:      "api"
            0x00, // rem_addr_len
            0x00, // data_len
            b'a', b'l', b'i', b'c', b'e', b'a', b'p', b'i',
        ];
        assert_eq!(body, expected);

        // A name that does not fit its one-octet length field is refused, not
        // truncated — a wrapped length would declare a short field and leave
        // the tail to be misparsed as the ones after it.
        assert!(tacacs_start_body(&"x".repeat(256), "api", "").is_err());
    }

    /// The CONTINUE body (§5.3), likewise pinned by hand: two 16-bit
    /// big-endian lengths, a flag octet, then the text.
    #[test]
    fn tacacs_continue_is_the_rfc_wire_layout() {
        let body = tacacs_continue_body("hunter2").unwrap();
        let expected: &[u8] = &[
            0x00, 0x07, // user_msg_len
            0x00, 0x00, // data_len
            0x00, // flags
            b'h', b'u', b'n', b't', b'e', b'r', b'2',
        ];
        assert_eq!(body, expected);
    }

    /// The 12-byte header (§4.1), pinned by hand around a body of known
    /// length: version 0xc0, type authentication, the sequence number, a zero
    /// flag octet (obfuscated), the session id, and a 32-bit big-endian body
    /// length.
    #[test]
    fn tacacs_header_is_the_rfc_wire_layout() {
        let session = [0x01u8, 0x02, 0x03, 0x04];
        let packet = tacacs_packet(&session, "s3cret", 1, &[0u8; 20]);
        assert_eq!(
            &packet[..12],
            &[0xc0, 0x01, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x14],
        );
        assert_eq!(packet.len(), 12 + 20);
    }

    /// The §4.5 pseudo-pad, checked against the RFC's formula computed
    /// longhand: MD5(session_id ‖ secret ‖ version ‖ seq), then each further
    /// block re-including the previous digest. The chaining is the part an
    /// implementation gets wrong — a pad that repeats its first block XORs the
    /// second body block against the wrong bytes, and every login fails with
    /// no hint why. (MD5 itself is pinned against RFC 1321 above.)
    #[test]
    fn tacacs_pad_chains_the_way_the_rfc_says() {
        let session = [0xde, 0xad, 0xbe, 0xef];
        let pad = tacacs_pad(&session, "shared", 3, 20);

        let mut seed = session.to_vec();
        seed.extend_from_slice(b"shared");
        seed.push(0xc0); // version
        seed.push(3); // seq_no
        let first = md5(&seed);
        assert_eq!(&pad[..16], &first);

        let mut seed2 = seed.clone();
        seed2.extend_from_slice(&first);
        assert_eq!(&pad[16..20], &md5(&seed2)[..4]);

        // A pad for a different sequence number is a different pad — reusing
        // one across packets would make the XOR trivially strippable.
        assert_ne!(tacacs_pad(&session, "shared", 1, 16), pad[..16].to_vec());
    }

    /// Obfuscation is XOR against the pad and nothing else, so applying it
    /// twice returns the body — which is also how a reply is read.
    #[test]
    fn tacacs_obfuscation_is_an_involution() {
        let session = [7u8, 7, 7, 7];
        let body = tacacs_start_body("bob", "api", "").unwrap();
        let packet = tacacs_packet(&session, "key", 1, &body);
        let pad = tacacs_pad(&session, "key", 1, body.len());
        let clear: Vec<u8> = packet[12..].iter().zip(&pad).map(|(b, p)| b ^ p).collect();
        assert_eq!(clear, body);
        // …and without the pad, the password-carrying bytes are not on the
        // wire in the clear.
        assert_ne!(&packet[12..], &body[..]);
    }

    /// A REPLY body parsed from hand-written bytes (§5.2): status, flags, two
    /// big-endian lengths, then the server's message.
    #[test]
    fn tacacs_reply_parses_from_raw_bytes() {
        // A GETPASS with the classic prompt.
        let mut reply = vec![0x05, 0x00, 0x00, 0x0a, 0x00, 0x00];
        reply.extend_from_slice(b"Password: ");
        assert_eq!(tacacs_parse_reply(&reply).unwrap(), (5, "Password: ".to_string()));

        // A bare PASS and a bare FAIL.
        assert_eq!(tacacs_parse_reply(&[0x01, 0, 0, 0, 0, 0]).unwrap().0, 1);
        assert_eq!(tacacs_parse_reply(&[0x02, 0, 0, 0, 0, 0]).unwrap().0, 2);

        // A reply whose declared lengths overrun the bytes that actually
        // arrived is refused — reading on would read the pseudo-pad as text.
        assert!(tacacs_parse_reply(&[0x01, 0x00, 0xff, 0xff, 0x00, 0x00]).is_err());
        // And a runt shorter than the fixed part is not a reply at all.
        assert!(tacacs_parse_reply(&[0x01, 0x00]).is_err());
    }

    /// Nobody is listening on a closed port, and that must come back as an
    /// error — the "could not ask" that keeps the login moving to the local
    /// account — never as a rejection.
    #[test]
    fn an_unreachable_tacacs_server_is_an_error_not_a_rejection() {
        // A TEST-NET-1 address with a tiny timeout: nothing routable answers.
        let out = tacacs_authenticate(
            "192.0.2.1",
            49,
            "secret",
            "alice",
            "pw",
            Duration::from_millis(50),
        );
        assert!(out.is_err(), "an unreachable server must be an error");
    }
}
