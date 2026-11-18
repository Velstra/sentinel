//! Local Unix/API password hashing through the pinned libxcrypt mkpasswd tool.
//!
//! New hashes use yescrypt cost 5 (16 MiB), with the helper's OS-random salt.
//! Existing MD5/SHA-256/SHA-512 crypt hashes remain verifiable; they are never
//! generated for new credentials. The OpenConnect renderer uses the same
//! memory-hard helper while retaining its existing nonempty-password policy.

use std::io::Write as _;
use std::process::{Command, Stdio};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

pub const MIN_LENGTH: usize = 8;
// libxcrypt's CRYPT_MAX_PASSPHRASE_SIZE=512 includes the terminating NUL.
const MAX_LENGTH: usize = 511;
const MAX_HASH_LENGTH: usize = 256;
const MAX_SHA_ROUNDS: u32 = 1_000_000;
const WORKERS: usize = 4;
const HELPER_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound memory-hard work in each API/CLI process, including queueing. Separate
/// operating-system processes have independent budgets, not a host-wide quota.
struct HashWorker;

static HASH_WORKERS: (Mutex<usize>, Condvar) = (Mutex::new(0), Condvar::new());

impl HashWorker {
    fn acquire() -> Result<Self> {
        let started = Instant::now();
        let (mutex, ready) = &HASH_WORKERS;
        let mut active = mutex.lock().unwrap_or_else(|p| p.into_inner());
        while *active >= WORKERS {
            let remaining = HELPER_TIMEOUT.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                bail!("password hashing is busy; retry shortly");
            }
            let (guard, timeout) = ready
                .wait_timeout(active, remaining)
                .unwrap_or_else(|p| p.into_inner());
            active = guard;
            if timeout.timed_out() && *active >= WORKERS {
                bail!("password hashing is busy; retry shortly");
            }
        }
        *active += 1;
        Ok(Self)
    }
}

impl Drop for HashWorker {
    fn drop(&mut self) {
        let (mutex, ready) = &HASH_WORKERS;
        let mut active = mutex.lock().unwrap_or_else(|p| p.into_inner());
        *active -= 1;
        ready.notify_one();
    }
}

fn valid_plaintext(plaintext: &str) -> bool {
    plaintext.len() <= MAX_LENGTH && !plaintext.contains(['\n', '\r', '\0'])
}

pub fn hash(plaintext: &str) -> Result<String> {
    if plaintext.len() < MIN_LENGTH {
        bail!("a password must be at least {MIN_LENGTH} characters");
    }
    hash_nonempty(plaintext)
}

/// Upgrade already-configured VPN credentials without imposing the local
/// account creation minimum on imported OpenConnect configurations.
pub(crate) fn hash_nonempty(plaintext: &str) -> Result<String> {
    anyhow::ensure!(!plaintext.is_empty(), "a password must not be empty");
    if !valid_plaintext(plaintext) {
        bail!("a password must be at most {MAX_LENGTH} bytes and contain no line break or NUL");
    }
    let hashed = run_mkpasswd(&["--method=yescrypt", "--rounds=5", "--stdin"], plaintext)?;
    let _ = hash_setting(&hashed)?;
    anyhow::ensure!(
        hashed.starts_with("$y$j9T$"),
        "password helper did not produce the required yescrypt cost"
    );
    Ok(hashed)
}

pub(crate) fn validate_hash(stored: &str) -> Result<()> {
    hash_setting(stored).map(|_| ())
}

pub fn verify(plaintext: &str, stored: &str) -> Result<bool> {
    if plaintext.is_empty() || !valid_plaintext(plaintext) {
        return Ok(false);
    }
    // Passing a stored digest as part of mkpasswd's salt makes that helper
    // report wrong passwords as unsupported-method errors. Supply only the
    // complete setting, then compare the computed result in constant time.
    let setting = hash_setting(stored)?;
    let again = run_mkpasswd(&["--stdin", "--salt", setting], plaintext)?;
    Ok(constant_time_eq(again.as_bytes(), stored.as_bytes()))
}

fn crypt_base64(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'/'))
}

fn legacy_salt(value: &str, max: usize) -> bool {
    (1..=max).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'$' | b':' | b';' | b'\\' | b'!' | b'*'))
}

/// Validate structure/cost BEFORE expensive work; return setting without digest.
fn hash_setting(stored: &str) -> Result<&str> {
    anyhow::ensure!(
        stored.len() <= MAX_HASH_LENGTH && stored.is_ascii(),
        "cannot check an oversized or non-ASCII password hash"
    );
    let fields: Vec<&str> = stored.split('$').collect();
    anyhow::ensure!(
        fields.first() == Some(&""),
        "this account's password hash is not one this appliance can check"
    );
    match fields.get(1).copied() {
        Some("y") => {
            anyhow::ensure!(fields.len() == 5, "cannot check malformed yescrypt hash");
            // libxcrypt's default p=1 profiles, cost1..6: at most32MiB/helper.
            // Arbitrary work/memory/parallelism encodings are not imported.
            anyhow::ensure!(
                ["j75", "j85", "j7T", "j8T", "j9T", "jAT"].contains(&fields[2]),
                "cannot check unsupported or excessive-cost yescrypt settings"
            );
            anyhow::ensure!(
                (22..=86).contains(&fields[3].len())
                    && crypt_base64(fields[3])
                    && fields[4].len() == 43
                    && crypt_base64(fields[4]),
                "cannot check malformed yescrypt salt or digest"
            );
        }
        Some("1") => {
            anyhow::ensure!(
                fields.len() == 4
                    && legacy_salt(fields[2], 8)
                    && fields[3].len() == 22
                    && crypt_base64(fields[3]),
                "cannot check malformed MD5-crypt hash"
            );
        }
        Some(method @ ("5" | "6")) => {
            let index = if fields
                .get(2)
                .is_some_and(|field| field.starts_with("rounds="))
            {
                anyhow::ensure!(fields.len() == 5, "cannot check malformed SHA-crypt rounds");
                let number = &fields[2]["rounds=".len()..];
                anyhow::ensure!(
                    !number.is_empty()
                        && !number.starts_with('0')
                        && number.bytes().all(|b| b.is_ascii_digit()),
                    "cannot check malformed SHA-crypt rounds"
                );
                let rounds: u32 = number
                    .parse()
                    .context("cannot check overflowing SHA-crypt rounds")?;
                anyhow::ensure!(
                    (1000..=MAX_SHA_ROUNDS).contains(&rounds),
                    "cannot check unsupported or excessive-cost SHA-crypt rounds"
                );
                3
            } else {
                anyhow::ensure!(fields.len() == 4, "cannot check malformed SHA-crypt hash");
                2
            };
            let digest_len = if method == "6" { 86 } else { 43 };
            anyhow::ensure!(
                legacy_salt(fields[index], 16)
                    && fields[index + 1].len() == digest_len
                    && crypt_base64(fields[index + 1]),
                "cannot check malformed SHA-crypt salt or digest"
            );
        }
        _ => bail!(
            "this account's password hash uses a scheme this appliance cannot check — use the management token to set a new password"
        ),
    }
    Ok(&stored[..stored.rfind('$').context("password hash has no setting")? + 1])
}

fn run_mkpasswd(args: &[&str], plaintext: &str) -> Result<String> {
    let _worker = HashWorker::acquire()?;
    let binary = if cfg!(test) {
        option_env!("SENTINEL_TEST_MKPASSWD_BIN")
            .map(str::to_string)
            .unwrap_or_else(|| crate::system::bin("mkpasswd"))
    } else {
        crate::system::bin("mkpasswd")
    };
    run_helper(&binary, args, plaintext, HELPER_TIMEOUT)
}

fn run_helper(binary: &str, args: &[&str], plaintext: &str, timeout: Duration) -> Result<String> {
    let mut child = Command::new(binary)
        .args(args)
        // mkpasswd prepends MKPASSWD_OPTIONS to argv. The caller's environment
        // (including dynamic-loader settings) must not override our policy.
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running the pinned password hashing helper")?;
    let input = child
        .stdin
        .take()
        .context("password helper took no stdin")?
        .write_all(format!("{plaintext}\n").as_bytes());
    if let Err(error) = input {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error).context("writing the password to the hashing helper");
    }
    let started = Instant::now();
    loop {
        if child
            .try_wait()
            .context("checking the password hashing helper")?
            .is_some()
        {
            break;
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            bail!("password hashing helper exceeded its deadline");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let output = child
        .wait_with_output()
        .context("reading the password hashing helper")?;
    anyhow::ensure!(
        output.status.success(),
        "password hashing helper failed; check its installation and hash policy"
    );
    anyhow::ensure!(
        output.stdout.len() <= MAX_HASH_LENGTH + 1,
        "password helper returned an oversized hash"
    );
    let hash = String::from_utf8(output.stdout).context("password helper returned non-UTF-8")?;
    let hash = hash.strip_suffix('\n').unwrap_or(&hash);
    let _ = hash_setting(hash).context("password helper returned an invalid hash")?;
    Ok(hash.to_string())
}

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
        assert!(stored.starts_with("$y$j9T$"), "{stored}");
        assert!(verify("correct horse battery", &stored).unwrap());
        assert!(!verify("correct horse batteru", &stored).unwrap());
        assert!(!verify("", &stored).unwrap());
    }

    #[test]
    fn the_stored_form_does_not_contain_the_password() {
        assert!(!hash("hunter2hunter2").unwrap().contains("hunter2"));
    }

    #[test]
    fn short_oversized_or_multiline_passwords_are_refused() {
        for invalid in [
            "short".to_string(),
            "p".repeat(512),
            "with\na break in it".into(),
            "with\0nul in it".into(),
        ] {
            assert!(hash(&invalid).is_err());
        }
        let full = "p".repeat(MAX_LENGTH);
        assert!(verify(&full, &hash(&full).unwrap()).unwrap());
    }

    #[test]
    fn the_same_password_hashes_differently_each_time() {
        let a = hash("the same password").unwrap();
        let b = hash("the same password").unwrap();
        assert_ne!(a, b);
        assert!(verify("the same password", &a).unwrap());
        assert!(verify("the same password", &b).unwrap());
    }

    #[test]
    fn legacy_hashes_match_independently_generated_openssl_vectors() {
        // Generated independently by openssl passwd, not by this helper.
        for stored in [
            "$1$salt1234$Wf.nqwASZ/FlosX3JiWwn1",
            "$5$salt123456789012$46s4249.s4ZRpbNtgdkvjvoVha8c02t7F7e0Y7EhpK3",
            "$6$salt123456789012$mrQIS8eBOuKvq23qeHhMYQGqzyaljxGgVQih9JxYJi7aMYM4TCNknwxRRFgrzIi20LVUXbUyY.j.yJDZCzyaC/",
            "$6$rounds=10000$roundssalt123456$5cSUgK06b0pS3KiK585T5lrZX0iAOud2KghDBdNjDP9p9BAdsFs9lACaunaoDbiJ7Q1IPKN2x3EiPHEqYdHdO.",
        ] {
            assert!(
                verify("fixture-known-password", stored).unwrap(),
                "{}",
                &stored[..3]
            );
            assert!(!verify("a wrong password", stored).unwrap());
        }
    }

    #[test]
    fn malformed_and_excessive_cost_hashes_are_refused_before_a_helper_can_run() {
        for stored in [
            "not-a-hash".into(),
            "$y$j9T$salt$digest".into(),
            format!("$y$jBT${}${}", "s".repeat(22), "h".repeat(43)),
            format!("$y$j9Textra${}${}", "s".repeat(22), "h".repeat(43)),
            format!("$6$rounds=999999999$salt${}", "h".repeat(86)),
            format!("$6$rounds=999999999999999999999$salt${}", "h".repeat(86)),
            format!("$6$rounds=0005000$salt${}", "h".repeat(86)),
            format!("$6$salt${}:injection", "h".repeat(86)),
            "$2b$12$unsupported".into(),
            "x".repeat(1024),
        ] {
            assert!(hash_setting(&stored).is_err(), "{stored}");
            assert!(verify("anything at all", &stored).is_err());
        }
    }

    #[test]
    fn a_new_hash_is_accepted_by_the_independent_system_libcrypt_verifier() {
        let stored = hash("independent-verifier-password").unwrap();
        let python = option_env!("SENTINEL_TEST_PYTHON_BIN").unwrap_or("/usr/bin/python3");
        let library = option_env!("SENTINEL_TEST_CRYPT_LIB").unwrap_or("");
        let mut verifier = Command::new(python)
            .args([
                "-c",
                r#"
import ctypes, ctypes.util, hmac, sys
path = sys.argv[1] or ctypes.util.find_library('crypt')
assert path, 'libxcrypt is required for this independent verification'
library = ctypes.CDLL(path, use_errno=True)
library.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
library.crypt.restype = ctypes.c_char_p
password = sys.stdin.buffer.readline().rstrip(b'\n')
stored = sys.argv[2].encode('ascii')
actual = library.crypt(password, stored)
assert actual and hmac.compare_digest(actual, stored)
wrong = library.crypt(b'wrong-password', stored)
assert wrong and not hmac.compare_digest(wrong, stored)
"#,
                library,
                &stored,
            ])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        verifier
            .stdin
            .take()
            .unwrap()
            .write_all(b"independent-verifier-password\n")
            .unwrap();
        assert!(verifier.wait().unwrap().success());
    }

    #[test]
    fn a_stalled_password_helper_is_killed_at_its_deadline() {
        let python = option_env!("SENTINEL_TEST_PYTHON_BIN").unwrap_or("/usr/bin/python3");
        let started = Instant::now();
        let error = run_helper(
            python,
            &["-c", "import time; time.sleep(60)"],
            "public-test-password",
            Duration::from_millis(50),
        )
        .unwrap_err();
        assert!(error.to_string().contains("deadline"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
