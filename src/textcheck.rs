//! One rule for every string in the configuration: no line breaks and no other
//! control characters (audit 8b6181, CTRL-08).
//!
//! Almost everything this appliance generates is line-oriented — networkd and
//! systemd units, `sshd_config`, `hostapd.conf`, `chrony.conf`, ddclient, pppd
//! secrets, sysctl drop-ins, HTTP headers — and in every one of them a line break
//! inside a value is the start of a directive nobody configured. systemd's parser
//! also takes a lone CR as a line break, and some readers stop at NUL or treat
//! U+2028/U+2029/U+0085 as line ends. A per-field check for each of the several
//! hundred string settings was tried and is how CTRL-02/03/12/13/16/17/18 came
//! about: each was a field somebody forgot. So the rule is applied generically,
//! by walking the serialized document, and a field added next year is covered
//! without anybody remembering it.
//!
//! The walk sees what serde sees. Two inputs are walked, because a section whose
//! `skip_serializing_if` predicate forgets one of its fields hides that field
//! from a walk over the *serialized* appliance while the renderer still reads
//! it: [`check_appliance`] covers in-memory candidates (the CLI draft, merged
//! sync documents) and [`screen_toml`]/[`screen_json`] cover every document as
//! it was received.
//!
//! The only exceptions are the reviewed [`MULTILINE`] fields, whose values are
//! documents by nature (a PEM key), and even they may carry nothing but `\n` and
//! `\r` — each is parsed strictly elsewhere before use.

use anyhow::{Result, bail};
use serde_json::Value;

use crate::config::Appliance;

/// Whether `c` may never appear in a configuration string: every Unicode
/// control character (U+0000–U+001F, U+007F–U+009F, which includes NEL
/// U+0085) and the two Unicode line/paragraph separators.
pub(crate) fn is_forbidden(c: char) -> bool {
    c.is_control() || matches!(c, '\u{2028}' | '\u{2029}')
}

/// Settings whose value legitimately spans lines, and the only control
/// characters each may hold. Paths are serde paths with array indices written
/// `[]`. Reviewed list — adding to it needs a reason the value cannot be a
/// single line *and* a strict parser for it before it reaches any file:
///
/// * `update.public-key`, `update.channels[].public-key`: an Ed25519 PEM,
///   canonicalised by `update_key::reference_or_pem` (base64 between the PEM
///   armour lines, nothing else) before it is used.
pub(crate) const MULTILINE: &[(&str, &[char])] = &[
    ("update.public-key", &['\n', '\r']),
    ("update.channels[].public-key", &['\n', '\r']),
];

/// One string (or map key) that breaks the rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Finding {
    /// Where, spelt the way the CLI spells it (`services ssh loglevel`,
    /// `interface[0] dhcp user-class`); a key holding the bad character is
    /// shown escaped.
    pub path: String,
    /// The first offending character.
    pub ch: char,
    /// Whether the offending string is the map *key* at `path`.
    pub in_key: bool,
}

impl std::fmt::Display for Finding {
    // The value is never printed: the field may be a password or a key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let what = if self.in_key { "the name" } else { "the value" };
        write!(
            f,
            "setting `{}`: {what} contains the control character U+{:04X}; line breaks and \
             other control characters are refused in every setting, because the files the \
             appliance generates from them are line-oriented",
            self.path, self.ch as u32
        )
    }
}

/// A position in the document, in two spellings: `pattern` is what
/// [`MULTILINE`] is written in (`update.channels[].public-key`), `words` is
/// what an operator reads (`update channels[2] public-key`).
#[derive(Clone, Default)]
struct Path {
    pattern: String,
    words: String,
}

impl Path {
    fn key(&self, key: &str) -> Path {
        let shown = if key.chars().any(is_forbidden) || key.contains(' ') {
            format!("{key:?}")
        } else {
            key.to_string()
        };
        if self.pattern.is_empty() {
            return Path {
                pattern: key.to_string(),
                words: shown,
            };
        }
        Path {
            pattern: format!("{}.{key}", self.pattern),
            words: format!("{} {shown}", self.words),
        }
    }

    fn index(&self, i: usize) -> Path {
        Path {
            pattern: format!("{}[]", self.pattern),
            words: format!("{}[{i}]", self.words),
        }
    }

    /// The characters this position may hold beyond the rule.
    fn allowed(&self) -> &'static [char] {
        MULTILINE
            .iter()
            .find(|(p, _)| *p == self.pattern)
            .map_or(&[], |(_, allowed)| *allowed)
    }

    fn bad_char(&self, s: &str) -> Option<char> {
        let allowed = self.allowed();
        s.chars().find(|c| is_forbidden(*c) && !allowed.contains(c))
    }

    fn finding(&self, ch: char, in_key: bool) -> Finding {
        Finding {
            path: self.words.clone(),
            ch,
            in_key,
        }
    }
}

/// Every string and map key in `value` that breaks the rule.
pub(crate) fn scan(value: &Value) -> Vec<Finding> {
    let mut out = Vec::new();
    walk(value, &Path::default(), &mut out);
    out
}

fn walk(value: &Value, path: &Path, out: &mut Vec<Finding>) {
    match value {
        Value::String(s) => out.extend(path.bad_char(s).map(|ch| path.finding(ch, false))),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                walk(item, &path.index(i), out);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                let here = path.key(key);
                if let Some(ch) = key.chars().find(|c| is_forbidden(*c)) {
                    out.push(here.finding(ch, true));
                }
                walk(item, &here, out);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// `s` with every character the rule forbids at `allowed` replaced by a space.
fn spaced(s: &str, allowed: &[char]) -> String {
    s.chars()
        .map(|c| {
            if is_forbidden(c) && !allowed.contains(&c) {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// Replace every forbidden character with a space, in values and keys alike,
/// recording what was changed. Used only to bring up a saved configuration that
/// predates the rule — see [`screen_toml`].
fn sanitize(value: &mut Value, path: &Path, changed: &mut Vec<Finding>) {
    match value {
        Value::String(s) => {
            if let Some(ch) = path.bad_char(s) {
                changed.push(path.finding(ch, false));
                *s = spaced(s, path.allowed());
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter_mut().enumerate() {
                sanitize(item, &path.index(i), changed);
            }
        }
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in keys {
                let Some(mut item) = map.remove(&key) else {
                    continue;
                };
                let clean_key = match key.chars().find(|c| is_forbidden(*c)) {
                    Some(ch) => {
                        changed.push(path.key(&key).finding(ch, true));
                        spaced(&key, &[])
                    }
                    None => key,
                };
                sanitize(&mut item, &path.key(&clean_key), changed);
                map.insert(clean_key, item);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Refuse an in-memory candidate holding a forbidden character anywhere.
/// Called by [`Appliance::validate`], so every path to `commit` passes it.
pub(crate) fn check_appliance(appliance: &Appliance) -> Result<()> {
    let value = serde_json::to_value(appliance)?;
    match scan(&value).first() {
        Some(finding) => bail!("{finding}"),
        None => Ok(()),
    }
}

/// What to do with a received document that breaks the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Screen {
    /// Refuse it (`config check`, commit, the API, config-sync, fleet).
    Refuse,
    /// Neutralise it and say so loudly: the boot-time apply of a saved
    /// configuration, which must come up rather than go dark.
    Neutralise,
}

/// Screen a received TOML document. `Ok(None)`: nothing to do, parse the text
/// as it is. `Ok(Some(json))`: the document as JSON with every forbidden
/// character replaced by a space (only with [`Screen::Neutralise`]). A text that
/// is not TOML at all is left to the real parser, which says why far better.
pub(crate) fn screen_toml(text: &str, mode: Screen) -> Result<Option<String>> {
    let Ok(doc) = toml::from_str::<toml::Value>(text) else {
        return Ok(None);
    };
    screen_value(serde_json::to_value(doc)?, mode)
}

/// [`screen_toml`] for a JSON document.
pub(crate) fn screen_json(text: &str, mode: Screen) -> Result<Option<String>> {
    let Ok(doc) = serde_json::from_str::<Value>(text) else {
        return Ok(None);
    };
    screen_value(doc, mode)
}

fn screen_value(mut doc: Value, mode: Screen) -> Result<Option<String>> {
    let findings = scan(&doc);
    let Some(first) = findings.first() else {
        return Ok(None);
    };
    if mode == Screen::Refuse {
        bail!("{first}");
    }
    let mut changed = Vec::new();
    sanitize(&mut doc, &Path::default(), &mut changed);
    for finding in &changed {
        eprintln!(
            "error: {finding}. The saved configuration predates this rule; each such \
             character was replaced by a space so the appliance still comes up and can be \
             configured. The next commit saves the replacement; `config check` refuses the \
             saved file until then."
        );
    }
    Ok(Some(serde_json::to_string(&doc)?))
}

/// Render-time guard: refuse to write `value` into a generated file when it
/// holds a forbidden character or one of the format's own metacharacters
/// (`extra`: a quote it is wrapped in, a separator it is split on).
///
/// Defence in depth behind [`check_appliance`]: validation should already have
/// refused the value, but a hostile one must never reach a daemon's config
/// intact, and failing loudly beats silently mangling it. `field` names the
/// setting so the error is actionable; the value is never printed.
pub(crate) fn reject_unsafe(field: &str, value: &str, extra: &[char]) -> Result<()> {
    if let Some(c) = value
        .chars()
        .find(|c| is_forbidden(*c) || extra.contains(c))
    {
        bail!(
            "{field} contains an unsafe character U+{:04X} that could corrupt the generated \
             daemon config; remove it",
            c as u32
        );
    }
    Ok(())
}

/// Render-time guard over a whole configuration object: refuse when any string
/// in `value` (at any depth, keys included) holds a forbidden character. The
/// generic counterpart of [`reject_unsafe`], for a generator that interpolates
/// many fields of one object (an interface into its networkd units).
pub(crate) fn reject_unsafe_in<T: serde::Serialize>(what: &str, value: &T) -> Result<()> {
    let value = serde_json::to_value(value)?;
    match scan(&value).first() {
        Some(finding) => bail!("refusing to render {what}: {finding}"),
        None => Ok(()),
    }
}

/// Render-time guard for a whole generated text whose lines are separated by
/// `\n` and nothing else: refuse any other control character (a CR that systemd
/// would read as a second line, a NUL that truncates it) and the Unicode line
/// separators. Tabs are allowed — several formats use them as field separators.
pub(crate) fn reject_unsafe_text(what: &str, text: &str) -> Result<()> {
    if let Some(c) = text
        .chars()
        .find(|c| *c != '\n' && *c != '\t' && is_forbidden(*c))
    {
        bail!(
            "refusing to write {what}: it would contain the control character U+{:04X}",
            c as u32
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_line_break_and_control_character_is_forbidden() {
        for c in [
            '\n', '\r', '\0', '\t', '\u{0b}', '\u{0c}', '\u{1b}', '\u{7f}', '\u{85}', '\u{9f}',
            '\u{2028}', '\u{2029}',
        ] {
            assert!(is_forbidden(c), "U+{:04X}", c as u32);
        }
        for c in ['a', ' ', '"', '\\', 'é', '\u{a0}', '\u{fffd}'] {
            assert!(!is_forbidden(c), "U+{:04X}", c as u32);
        }
    }

    #[test]
    fn the_walk_reaches_nested_values_array_elements_and_map_keys() {
        let doc = json!({
            "services": {"ssh": {"loglevel": "INFO\nX"}},
            "interface": [{"name": "a"}, {"dhcp": {"user-class": "x\ry"}}],
            "system": {"sysctl": {"net.a\nkernel.b": "1"}},
        });
        let paths: Vec<_> = scan(&doc).into_iter().map(|f| f.path).collect();
        assert!(
            paths.contains(&"services ssh loglevel".to_string()),
            "{paths:?}"
        );
        assert!(
            paths.contains(&"interface[1] dhcp user-class".to_string()),
            "{paths:?}"
        );
        assert!(
            paths.contains(&"system sysctl \"net.a\\nkernel.b\"".to_string()),
            "{paths:?}"
        );
        assert_eq!(paths.len(), 3, "{paths:?}");
    }

    #[test]
    fn only_the_reviewed_multiline_fields_may_hold_a_newline_and_only_a_newline() {
        let pem = "-----BEGIN PUBLIC KEY-----\nAAAA\r\n-----END PUBLIC KEY-----\n";
        let ok = json!({"update": {"public-key": pem, "channels": [{"public-key": pem}]}});
        assert!(scan(&ok).is_empty());
        let nul = json!({"update": {"channels": [{"public-key": "x\0y"}]}});
        assert_eq!(scan(&nul).len(), 1);
        let elsewhere = json!({"update": {"url": "https://x\n"}});
        assert_eq!(scan(&elsewhere).len(), 1);
    }

    #[test]
    fn findings_never_print_the_value() {
        let doc = json!({"vpn": {"ipsec": [{"psk": "hunter2\nsecret"}]}});
        let message = scan(&doc)[0].to_string();
        assert!(message.contains("vpn ipsec[0] psk"), "{message}");
        assert!(!message.contains("hunter2"), "{message}");
    }

    #[test]
    fn refuse_mode_refuses_and_neutralise_mode_replaces_with_spaces() {
        let text = "[services.ssh]\nloglevel = \"INFO\\nAuthorizedKeysCommand x\"\n";
        assert!(screen_toml(text, Screen::Refuse).is_err());
        let fixed = screen_toml(text, Screen::Neutralise).unwrap().unwrap();
        let doc: Value = serde_json::from_str(&fixed).unwrap();
        assert_eq!(
            doc["services"]["ssh"]["loglevel"],
            "INFO AuthorizedKeysCommand x"
        );
        assert!(scan(&doc).is_empty());
        // A clean document is passed through untouched in either mode.
        let clean = "[system]\nhostname = \"a\"\n";
        assert_eq!(screen_toml(clean, Screen::Refuse).unwrap(), None);
        assert_eq!(screen_toml(clean, Screen::Neutralise).unwrap(), None);
        // Not TOML at all: left to the real parser.
        assert_eq!(screen_toml("[system", Screen::Refuse).unwrap(), None);
    }

    #[test]
    fn render_guards_refuse_line_breaks_and_named_metacharacters() {
        assert!(reject_unsafe("f", "plain value", &[]).is_ok());
        assert!(reject_unsafe("f", "a\nb", &[]).is_err());
        assert!(reject_unsafe("f", "a\u{2028}b", &[]).is_err());
        assert!(reject_unsafe("f", "a'b", &['\'']).is_err());
        assert!(reject_unsafe_text("unit", "[A]\nB=c\td\n").is_ok());
        assert!(reject_unsafe_text("unit", "[A]\nB=c\r[Match]\n").is_err());
    }
}
