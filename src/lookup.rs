//! Answers about a value an operator is typing, asked of the world.
//!
//! Configuring a BGP neighbour means typing an AS number, and an AS number is
//! the one field in this whole console where the operator cannot check their
//! own work: 65010 and 65001 look alike, and getting it wrong means a session
//! that never comes up for a reason nothing on the page explains. So the
//! appliance looks it up and says whose it is.
//!
//! **The console never reaches outside itself.** The page asks *this* appliance
//! and the appliance asks the registry — which is the same shape as every other
//! thing the console shows, and the reason a page served on an isolated network
//! still renders and works. When the box has no route to the internet the answer
//! is simply "not known", never an error and never a delay: every lookup here is
//! short-timeout, best-effort, and cached.
//!
//! `curl` is the fetcher for the same reason the update path uses it — one
//! pinned binary, TLS from the image, no HTTP client in the dependency tree.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};

/// How long an answer is kept. An AS's holder changes on the scale of years;
/// re-asking within a session is pure noise on somebody's registry.
const TTL: Duration = Duration::from_secs(6 * 3600);

/// How long a *failure* is kept, which is a different question entirely. One
/// slow registry, or a link that came up a second later, must not blind the
/// hint for six hours — that is a feature that "works sometimes" for reasons
/// nobody can see.
const TTL_UNKNOWN: Duration = Duration::from_secs(60);

/// How long the appliance is willing to wait. A field hint that arrives after
/// the operator has moved on is worse than none, and a management plane must
/// never block on somebody else's server. Long enough for a cold DNS lookup
/// and two TLS handshakes (rdap.org redirects to the holding registry), short
/// enough that nobody watches a spinner.
const TIMEOUT_SECS: u32 = 8;

/// What was learned and when. `None` is a remembered *failure*, kept so a dead
/// link does not turn every field hint into a fresh eight-second wait.
type Answer = (Instant, Option<String>);

fn cache() -> &'static Mutex<HashMap<String, Answer>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Answer>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn curl_bin() -> String {
    std::env::var("SENTINEL_CURL_BIN")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "curl".to_string())
}

/// Look something up. `kind` is `asn` or `ptr`; the answer is a short line of
/// prose, or `None` when nothing is known — which includes "this appliance has
/// no internet", and is not an error.
pub fn lookup(kind: &str, value: &str) -> Result<Option<String>> {
    let key = format!("{kind}/{value}");
    if let Some((at, answer)) = cache().lock().unwrap().get(&key) {
        let ttl = if answer.is_some() { TTL } else { TTL_UNKNOWN };
        if at.elapsed() < ttl {
            return Ok(answer.clone());
        }
    }
    let answer = match kind {
        "asn" => asn(value)?,
        "ptr" => ptr(value)?,
        other => bail!("unknown lookup {other:?} (asn | ptr)"),
    };
    cache()
        .lock()
        .unwrap()
        .insert(key, (Instant::now(), answer.clone()));
    Ok(answer)
}

/// Who holds an AS number, from RDAP.
///
/// Private and documentation ranges are answered from here rather than from the
/// registry: they have no holder, and "not known" would read as a failed lookup
/// when it is in fact the correct and complete answer.
fn asn(value: &str) -> Result<Option<String>> {
    let n: u32 = match value.parse() {
        Ok(n) => n,
        Err(_) => bail!("not an AS number: {value:?}"),
    };
    if let Some(reserved) = reserved_asn(n) {
        return Ok(Some(reserved.to_string()));
    }
    // rdap.org redirects to whichever registry holds the number, so one URL
    // covers all five.
    let out = std::process::Command::new(curl_bin())
        .args([
            "-fsSL",
            "--max-time",
            &TIMEOUT_SECS.to_string(),
            "-H",
            "Accept: application/rdap+json",
            &format!("https://rdap.org/autnum/{n}"),
        ])
        .output();
    let Ok(out) = out else { return Ok(None) };
    if !out.status.success() {
        return Ok(None);
    }
    let body: serde_json::Value = match serde_json::from_slice(&out.stdout) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    // Two names, and both are worth having: `name` is the network handle an
    // operator sees in a routing table (CLOUDFLARENET), the registrant's vCard
    // is the company behind it (Cloudflare, Inc.). Whoever is reading is
    // checking one or the other.
    let handle = body
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let org = registrant_name(&body);
    let country = body.get("country").and_then(|v| v.as_str());
    let mut answer = match (handle, org) {
        (Some(handle), Some(org)) if !org.eq_ignore_ascii_case(&handle) => {
            format!("{handle} — {org}")
        }
        (Some(handle), _) => handle,
        (None, Some(org)) => org,
        (None, None) => return Ok(None),
    };
    if let Some(cc) = country {
        answer.push_str(&format!(" ({cc})"));
    }
    Ok(Some(answer))
}

/// The organisation behind an RDAP object: the `fn` line of the registrant's
/// vCard. RDAP nests this three levels deep in an array-of-arrays, which is why
/// it is worth a named function rather than a chain of `get`s in the caller.
fn registrant_name(body: &serde_json::Value) -> Option<String> {
    let entities = body.get("entities")?.as_array()?;
    let pick = entities
        .iter()
        .find(|e| {
            e.get("roles")
                .and_then(|r| r.as_array())
                .map(|roles| roles.iter().any(|r| r.as_str() == Some("registrant")))
                .unwrap_or(false)
        })
        .or_else(|| entities.first())?;
    let card = pick.get("vcardArray")?.as_array()?.get(1)?.as_array()?;
    card.iter().find_map(|entry| {
        let entry = entry.as_array()?;
        (entry.first()?.as_str()? == "fn")
            .then(|| entry.get(3)?.as_str().map(str::to_string))
            .flatten()
    })
}

/// The names IANA has already given a range, so the appliance does not ask a
/// registry a question it can answer itself.
fn reserved_asn(n: u32) -> Option<&'static str> {
    match n {
        0 => Some("reserved (AS 0 must not be used)"),
        23456 => Some("AS_TRANS — a 4-byte AS seen by a 2-byte speaker"),
        64496..=64511 | 65536..=65551 => Some("reserved for documentation (RFC 5398)"),
        64512..=65534 | 4200000000..=4294967294 => Some("private use (RFC 6996)"),
        65535 | 4294967295 => Some("reserved (last of its range)"),
        _ => None,
    }
}

/// The name behind an address, from whatever resolver this appliance uses.
///
/// `getent` rather than a DNS library: it goes through the box's own resolution
/// path, so the answer is the one the appliance itself would get — including
/// `/etc/hosts` and a local resolver an operator has configured.
fn ptr(value: &str) -> Result<Option<String>> {
    if value.parse::<std::net::IpAddr>().is_err() {
        bail!("not an address: {value:?}");
    }
    let out = std::process::Command::new(crate::system::bin("getent"))
        .args(["hosts", value])
        .output();
    let Ok(out) = out else { return Ok(None) };
    if !out.status.success() {
        return Ok(None);
    }
    let line = String::from_utf8_lossy(&out.stdout);
    Ok(line
        .split_whitespace()
        .nth(1)
        .filter(|name| *name != value)
        .map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ranges with no holder are answered here, not by asking a registry
    /// about a number it has never heard of.
    #[test]
    fn reserved_ranges_answer_without_the_network() {
        assert!(asn("65001").unwrap().unwrap().contains("private"));
        assert!(asn("64500").unwrap().unwrap().contains("documentation"));
        assert!(asn("4200000001").unwrap().unwrap().contains("private"));
        assert!(asn("23456").unwrap().unwrap().contains("AS_TRANS"));
    }

    /// A lookup of something that is not the kind it claims to be is an error,
    /// not a silent "not known" — the caller has a bug, and hiding it would
    /// make the field hint quietly stop working.
    #[test]
    fn a_malformed_value_is_refused_rather_than_looked_up() {
        assert!(asn("sixty-five thousand").is_err());
        assert!(ptr("not-an-address").is_err());
        assert!(lookup("weather", "tomorrow").is_err());
    }

    /// Nothing here may panic or hang on an appliance with no route out: an
    /// unknown answer is a normal answer.
    #[test]
    fn an_unresolvable_name_is_not_an_error() {
        // 192.0.2.0/24 is TEST-NET-1: it resolves nowhere, by design.
        assert_eq!(ptr("192.0.2.77").unwrap(), None);
    }
}
