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
pub fn italic(s: &str) -> String {
    paint("3", s)
}
/// Bold + green, in one SGR sequence (used for a recognised command word).
pub fn green_bold(s: &str) -> String {
    paint("1;32", s)
}
/// Bold + red, in one SGR sequence (used for an unrecognised command word).
pub fn red_bold(s: &str) -> String {
    paint("1;31", s)
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

    #[test]
    fn typography_codes_are_the_ones_the_cli_uses() {
        // italic, and the combined bold+colour sequences for the command word.
        assert_eq!(super::paint_if(true, "3", "x"), "\x1b[3mx\x1b[0m");
        assert_eq!(super::paint_if(true, "1;32", "set"), "\x1b[1;32mset\x1b[0m");
        assert_eq!(super::paint_if(true, "1;31", "wat"), "\x1b[1;31mwat\x1b[0m");
        // All still degrade to plain when colour is off.
        assert_eq!(super::paint_if(false, "3", "x"), "x");
        assert_eq!(super::paint_if(false, "1;32", "set"), "set");
    }
}
