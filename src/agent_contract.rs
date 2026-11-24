//! The data plane's own verdict on a compiled configuration.
//!
//! Sentinel's validation and the agent's parser are two different programs,
//! and every member of the DP-01 class lives in the gap between them: a
//! port-forward field the pinned agent did not know, a protocol a port-forward
//! cannot carry, more rate-limited rules than the agent holds. Each passed
//! `config check` and `save`, was refused only when the agent read it, and —
//! read at boot — left every zoned link held down. The cure that does not
//! depend on finding the next such gap first is to ask the agent: the image
//! ships it, and `velstra validate <file>` parses and resolves a config without
//! touching the kernel. Commit, save, `config check` and the boot seed all ask
//! through [`check_rendered`], so they cannot disagree about what is loadable.
//!
//! What this cannot see is a refusal that only happens while loading into the
//! kernel (a map that fills up, DP-17). The boot verifier in
//! [`crate::boot_fallback`] covers that one by watching the agent come up.

use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::config::Appliance;

/// How long the validator may take. Parsing a ten-thousand-rule config takes
/// well under a second; anything near this is a wedged process.
const VALIDATE_DEADLINE: Duration = Duration::from_secs(60);
/// How much of the validator's stderr is read. Its diagnostics are short.
const STDERR_LIMIT: u64 = 64 * 1024;
/// How many diagnostic lines reach the operator.
const SUMMARY_LINES: usize = 4;

/// Whether the agent was asked.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The agent's validator accepts the compiled configuration.
    Accepted,
    /// There is no agent on this host (off-box editing): nothing was checked.
    Unavailable,
}

/// The validator the image ships, if this is an appliance. The Nix wrapper sets
/// `SENTINEL_VELSTRA_BIN` to the exact store path of the agent the image runs,
/// so the check is made by the same parser that will read the file. Off-box the
/// variable is unset and there is nothing to ask.
fn validator() -> Option<PathBuf> {
    std::env::var_os("SENTINEL_VELSTRA_BIN").map(PathBuf::from)
}

/// Compile `appliance` as it is written (no feed or name resolution) and ask the
/// agent whether it would load it.
pub(crate) fn check(appliance: &Appliance) -> Result<Verdict> {
    let rendered = crate::compile::compile(appliance)
        .to_toml()
        .context("compiling firewall config")?;
    check_rendered(&rendered, &[appliance])
}

/// Ask the agent about an already compiled configuration. `configurations` are
/// the appliance documents whose secrets must not appear in a diagnostic.
/// `Err` means the agent refused it, or that an appliance could not run its own
/// validator, which is no better.
pub(crate) fn check_rendered(rendered: &str, configurations: &[&Appliance]) -> Result<Verdict> {
    match validator() {
        None => Ok(Verdict::Unavailable),
        Some(binary) => {
            validate_with(&binary, rendered, configurations)?;
            Ok(Verdict::Accepted)
        }
    }
}

/// A private directory for the compiled file: it carries the same credentials
/// as the agent's own copy (HA sync secrets, portal keys), so it is created
/// 0700 with an unpredictable name and removed on every path out.
struct PrivateDir(PathBuf);

impl PrivateDir {
    fn create() -> Result<Self> {
        let mut random = [0u8; 12];
        getrandom::getrandom(&mut random)
            .map_err(|error| anyhow::anyhow!("validator staging entropy: {error}"))?;
        let name: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = std::env::temp_dir().join(format!("sentinel-validate-{name}"));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .with_context(|| format!("creating {}", path.display()))?;
        Ok(Self(path))
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run `<binary> validate <file>` on `rendered`.
pub(crate) fn validate_with(
    binary: &Path,
    rendered: &str,
    configurations: &[&Appliance],
) -> Result<()> {
    let dir = PrivateDir::create()?;
    let file = dir.0.join("velstra.toml");
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&file)
        .context("staging the compiled configuration for validation")?;
    out.write_all(rendered.as_bytes())?;
    drop(out);
    let mut child = Command::new(binary)
        .arg("validate")
        .arg(&file)
        .stdin(Stdio::null())
        // The validator echoes the whole resolved ruleset on success; only its
        // verdict and its diagnostic matter here.
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("running the data-plane validator {}", binary.display()))?;
    let mut stderr = child.stderr.take().context("validator stderr")?;
    let reader = std::thread::spawn(move || {
        let mut text = Vec::new();
        let _ = (&mut stderr).take(STDERR_LIMIT).read_to_end(&mut text);
        // Drain the rest so a chatty validator cannot block on a full pipe.
        let _ = std::io::copy(&mut stderr, &mut std::io::sink());
        text
    });
    let deadline = Instant::now() + VALIDATE_DEADLINE;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "the data-plane validator did not answer within {}s",
                VALIDATE_DEADLINE.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let stderr = reader.join().unwrap_or_default();
    if status.success() {
        return Ok(());
    }
    // The private staging path means nothing to the reader.
    let stderr = String::from_utf8_lossy(&stderr)
        .replace(&*file.to_string_lossy(), "the compiled configuration");
    bail!(
        "the data plane refuses this configuration: {}",
        summary(&stderr, configurations)
    )
}

/// The validator's diagnostic, reduced to what an operator (or an API client)
/// may see: parser source excerpts (`227 | key = …`) are dropped because they
/// quote the compiled file, every configured secret is scrubbed from what is
/// left, and control characters are escaped.
pub(crate) fn summary(stderr: &str, configurations: &[&Appliance]) -> String {
    let excerpt = |line: &str| {
        let trimmed = line.trim_start();
        let digits = trimmed.trim_start_matches(|c: char| c.is_ascii_digit());
        digits.trim_start().starts_with('|') || trimmed.starts_with('^')
    };
    let lines: Vec<&str> = stderr
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && *line != "Caused by:" && !excerpt(line))
        .map(|line| line.strip_prefix("Error: ").unwrap_or(line))
        .take(SUMMARY_LINES)
        .collect();
    if lines.is_empty() {
        return "no diagnostic".to_string();
    }
    let joined = lines.join("; ");
    crate::repl::apply_error_message(&anyhow::anyhow!(joined), configurations.iter().copied())
        .replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in validator with the agent's refusal shape: an anyhow chain with
    /// a TOML source excerpt that quotes the offending line, and a cause line
    /// that echoes a configured credential.
    fn fake_validator(dir: &Path) -> PathBuf {
        let path = dir.join("velstra");
        crate::test_exec::write_executable(
            &path,
            "#!/bin/sh\n\
             [ \"$1\" = validate ] || exit 64\n\
             if grep -q local_destination \"$2\"; then\n\
             echo \"Error: parsing config $2\" >&2\n\
             echo 'Caused by:' >&2\n\
             echo 'TOML parse error at line 3, column 1' >&2\n\
             echo '  |' >&2\n\
             echo \"3 | $(grep source-quote \"$2\")\" >&2\n\
             echo '  | ^^^^^' >&2\n\
             echo 'unknown field `local_destination` near sync-credential-1234' >&2\n\
             exit 1\n\
             fi\n\
             echo 'Configuration is valid:'\n",
            0o700,
        );
        path
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sentinel-agent-contract-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn the_agents_refusal_is_reported_without_source_excerpts_or_secrets() {
        let dir = scratch("refused");
        let validator = fake_validator(&dir);
        let mut appliance = Appliance::from_toml("[system]\nhostname = \"fw\"\n").unwrap();
        appliance.system.config_sync.secret = Some("sync-credential-1234".into());
        let rendered = "[x]\nname = \"source-quote\"\nlocal_destination = true\n";
        let error = validate_with(&validator, rendered, &[&appliance])
            .unwrap_err()
            .to_string();
        assert!(error.contains("data plane refuses"), "{error}");
        assert!(error.contains("TOML parse error at line 3"), "{error}");
        assert!(
            error.contains("unknown field `local_destination`"),
            "{error}"
        );
        assert!(
            !error.contains("source-quote"),
            "source excerpt leaked: {error}"
        );
        assert!(
            !error.contains("sync-credential-1234"),
            "secret leaked: {error}"
        );
        assert!(!error.contains('\n'), "{error}");
        assert!(
            !error.contains("sentinel-validate-"),
            "staging path leaked: {error}"
        );
        assert!(!error.contains("Caused by"), "{error}");
        assert!(
            error.contains("parsing config the compiled configuration"),
            "{error}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_accepted_configuration_passes() {
        let dir = scratch("accepted");
        let validator = fake_validator(&dir);
        validate_with(&validator, "[x]\nname = \"ok\"\n", &[]).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_staged_copy_is_private_and_removed() {
        use std::os::unix::fs::PermissionsExt;
        let staged = PrivateDir::create().unwrap();
        let path = staged.0.clone();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        drop(staged);
        assert!(!path.exists());
    }

    #[test]
    fn a_validator_that_cannot_run_is_an_error_not_an_acceptance() {
        let error = validate_with(Path::new("/nonexistent/velstra"), "[x]\n", &[]).unwrap_err();
        assert!(
            format!("{error:#}").contains("data-plane validator"),
            "{error:#}"
        );
    }
}
