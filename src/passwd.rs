//! Passwords: hashing one, and checking one.
//!
//! An account could only ever be given a `hashed-password` — a `$6$…` string
//! from `mkpasswd`. That is the right thing to *store*, and the wrong thing to
//! *ask for*: nobody types a crypt hash into a web form, so from the console an
//! administrator account could not be created at all, and there was nothing to
//! log in with even if it had been.
//!
//! So the appliance hashes. `set system login alice password …` takes what a
//! person can type, hashes it here, and keeps only the hash — the plaintext is
//! never written to the configuration, never rendered by `show`, and never
//! reaches the archive.
//!
//! `openssl passwd` does the work, for the same reason the PKI path uses
//! openssl: it is already in the image, it is the same binary the rest of the
//! appliance trusts, and it keeps a password-hashing implementation out of this
//! crate. SHA-512-crypt (`-6`) is what is generated; verification also accepts
//! the other schemes openssl can compute, because an operator may have set a
//! hash by hand.

use std::io::Write as _;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

/// The scheme new hashes are made with. SHA-512-crypt: what `mkpasswd -m sha-512`
/// produces, what a NixOS `hashedPassword` expects, and what every login path on
/// the appliance already understands.
const SCHEME: &str = "-6";

/// The shortest password this appliance will accept.
///
/// Not a policy engine — one number, and it is about the failure mode that
/// actually happens: an account made in a hurry with `admin`, reachable from a
/// zone somebody later opens.
pub const MIN_LENGTH: usize = 8;

/// Hash a password for storage.
pub fn hash(plaintext: &str) -> Result<String> {
    if plaintext.len() < MIN_LENGTH {
        bail!("a password must be at least {MIN_LENGTH} characters");
    }
    if plaintext.contains(['\n', '\r', '\0']) {
        bail!("a password may not contain a line break");
    }
    run_openssl(&[SCHEME, "-stdin"], plaintext)
}

/// Does `plaintext` produce `stored`?
///
/// A crypt hash carries its own salt (`$scheme$salt$digest`), so verifying is
/// hashing again with that salt and comparing. The comparison is
/// constant-time — a password check that returns faster for a wrong first
/// character is a password check that can be read one character at a time.
pub fn verify(plaintext: &str, stored: &str) -> Result<bool> {
    // No password is not a password. Asked to hash nothing, openssl answers
    // with something that is not a hash — which would surface here as "this
    // appliance cannot check that hash" rather than as the plain refusal it is.
    if plaintext.is_empty() {
        return Ok(false);
    }
    let (scheme, salt) = split_hash(stored)?;
    let again = run_openssl(&[scheme, "-salt", &salt, "-stdin"], plaintext)?;
    Ok(constant_time_eq(again.as_bytes(), stored.as_bytes()))
}

/// The scheme flag and salt of a stored hash.
///
/// Only the schemes openssl can recompute are accepted. A `$y$` (yescrypt) hash
/// — what some distributions now write — cannot be checked here, and saying so
/// is better than answering "wrong password" to a password that is right.
fn split_hash(stored: &str) -> Result<(&'static str, String)> {
    let parts: Vec<&str> = stored.split('$').collect();
    // "$6$salt$digest" splits to ["", "6", "salt", "digest"].
    if parts.len() < 4 || !stored.starts_with('$') {
        bail!("this account's password hash is not one this appliance can check");
    }
    let scheme = match parts[1] {
        "1" => "-1",
        "5" => "-5",
        "6" => "-6",
        other => bail!(
            "this account's password hash uses scheme ${other}$, which this \
             appliance cannot check — sign in with the management token and set \
             a new password"
        ),
    };
    // A rounds= parameter sits between the scheme and the salt.
    let salt = if parts[2].starts_with("rounds=") {
        format!("{}${}", parts[2], parts.get(3).copied().unwrap_or_default())
    } else {
        parts[2].to_string()
    };
    Ok((scheme, salt))
}

/// Run `openssl passwd` with the password on stdin.
///
/// On stdin and never on the command line: an argument is visible in `ps` to
/// every process on the box for as long as the command runs.
fn run_openssl(args: &[&str], plaintext: &str) -> Result<String> {
    let mut child = Command::new(crate::system::bin("openssl"))
        .arg("passwd")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running openssl passwd")?;
    child
        .stdin
        .as_mut()
        .context("openssl passwd took no stdin")?
        .write_all(format!("{plaintext}\n").as_bytes())
        .context("writing the password to openssl")?;
    let out = child.wait_with_output().context("openssl passwd")?;
    if !out.status.success() {
        bail!(
            "openssl passwd failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let hash = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !hash.starts_with('$') {
        bail!("openssl passwd produced something that is not a crypt hash");
    }
    Ok(hash)
}

/// Compare without leaking where two byte strings first differ.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hash_verifies_against_the_password_that_made_it() {
        let stored = hash("correct horse battery").unwrap();
        assert!(stored.starts_with("$6$"), "{stored}");
        assert!(verify("correct horse battery", &stored).unwrap());
        assert!(!verify("correct horse batteru", &stored).unwrap());
        assert!(!verify("", &stored).unwrap());
    }

    /// The plaintext must never be recoverable from what is stored, which is
    /// the whole reason this module exists — a config file is copied, synced to
    /// peers and archived on every commit.
    #[test]
    fn the_stored_form_does_not_contain_the_password() {
        let stored = hash("hunter2hunter2").unwrap();
        assert!(!stored.contains("hunter2"));
    }

    #[test]
    fn a_short_password_is_refused_rather_than_hashed() {
        assert!(hash("short").is_err());
        assert!(hash("with\na break in it").is_err());
    }

    /// Two hashes of the same password differ, because the salt does. A store
    /// where they matched would let anyone see which accounts share a password.
    #[test]
    fn the_same_password_hashes_differently_each_time() {
        let a = hash("the same password").unwrap();
        let b = hash("the same password").unwrap();
        assert_ne!(a, b);
        assert!(verify("the same password", &a).unwrap());
        assert!(verify("the same password", &b).unwrap());
    }

    /// A scheme this appliance cannot recompute has to say so. Answering
    /// "wrong password" to a password that is right is how an operator ends up
    /// locked out of a box that is working perfectly.
    #[test]
    fn an_uncheckable_hash_is_an_error_not_a_refusal() {
        let err = verify("anything at all", "$y$j9T$salt$digest").unwrap_err();
        assert!(format!("{err}").contains("cannot check"), "{err}");
        assert!(verify("anything at all", "not-a-hash").is_err());
    }
}
