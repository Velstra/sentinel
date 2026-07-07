//! Terminal presentation helpers for the CLI: ANSI colour that automatically
//! degrades to plain text when the output is not a terminal (piped configs,
//! tests, logs) or when the user sets `NO_COLOR`.

use std::io::IsTerminal;
use std::sync::OnceLock;

/// Whether colour should be emitted at all. Decided once per process: stderr
/// must be a terminal (the shell prints all feedback on stderr, keeping stdout
/// clean for `show` output that may be piped) and `NO_COLOR` must be unset
/// (https://no-color.org).
pub fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED
        .get_or_init(|| std::env::var_os("NO_COLOR").is_none() && std::io::stderr().is_terminal())
}

fn paint(code: &str, s: &str) -> String {
    paint_if(enabled(), code, s)
}

fn paint_if(on: bool, code: &str, s: &str) -> String {
    if on {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

pub fn bold(s: &str) -> String {
    paint("1", s)
}
pub fn dim(s: &str) -> String {
    paint("2", s)
}
pub fn red(s: &str) -> String {
    paint("31", s)
}
pub fn green(s: &str) -> String {
    paint("32", s)
}
pub fn yellow(s: &str) -> String {
    paint("33", s)
}
pub fn cyan(s: &str) -> String {
    paint("36", s)
}

#[cfg(test)]
mod tests {
    // Whether stderr is a terminal depends on the harness (nix gives builders
    // a pty!), so the tests pin the flag instead of probing the environment.
    #[test]
    fn paint_wraps_when_on_and_passes_through_when_off() {
        assert_eq!(super::paint_if(false, "1", "x"), "x");
        assert_eq!(super::paint_if(false, "31", ""), "");
        assert_eq!(super::paint_if(true, "31", "err"), "\x1b[31merr\x1b[0m");
    }
}
