//! Which source revision this binary was built from (STATIC-04).
//!
//! `sentinel --version` said only `sentinel 1.0.0`, so a shipped binary could
//! not be traced to a commit. The Nix wrapper sets `SENTINEL_GIT_REVISION` to
//! the flake's revision; it is read at run time rather than compiled in, so a
//! documentation-only commit does not rebuild and retest an identical binary.
//! Off Nix, or from an unversioned (`path:`) source, the revision is
//! `unknown` — never a guess.

use std::sync::OnceLock;

pub const UNKNOWN: &str = "unknown";
const VARIABLE: &str = "SENTINEL_GIT_REVISION";

/// A git revision as Nix reports it: 7-40 lowercase hex digits, optionally
/// followed by `-dirty`. Anything else is reported as unknown.
pub fn parse_revision(value: Option<&str>) -> &str {
    let Some(value) = value else { return UNKNOWN };
    let hex = value.strip_suffix("-dirty").unwrap_or(value);
    let valid = (7..=40).contains(&hex.len())
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if valid { value } else { UNKNOWN }
}

/// The revision this binary reports.
pub fn revision() -> &'static str {
    static REVISION: OnceLock<String> = OnceLock::new();
    REVISION.get_or_init(|| {
        let runtime = std::env::var(VARIABLE).ok();
        parse_revision(runtime.as_deref().or(option_env!("SENTINEL_GIT_REVISION"))).to_string()
    })
}

/// `--version` text: the package version and the source revision.
pub fn version() -> &'static str {
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION.get_or_init(|| format!("{} (revision {})", env!("CARGO_PKG_VERSION"), revision()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_git_revision_is_reported() {
        let full = "04d4145a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e";
        assert_eq!(parse_revision(Some(full)), full);
        assert_eq!(parse_revision(Some("04d4145")), "04d4145");
        assert_eq!(parse_revision(Some("04d4145-dirty")), "04d4145-dirty");
        for bad in [
            "",
            "04d414",
            "04D4145",
            "main",
            "04d4145; rm -rf /",
            "\u{1b}[31m04d4145",
        ] {
            assert_eq!(parse_revision(Some(bad)), UNKNOWN, "{bad:?}");
        }
        assert_eq!(parse_revision(None), UNKNOWN);
    }

    #[test]
    fn version_names_package_and_revision() {
        assert!(version().starts_with(env!("CARGO_PKG_VERSION")));
        assert!(version().contains("(revision "));
    }
}
