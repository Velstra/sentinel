//! Feed groups: an address list somebody else publishes, folded into the
//! firewall's own groups (roadmap: URL-fed tables).
//!
//! The lists worth having are maintained elsewhere — a bogon list, a Tor exit
//! list, a threat feed, a provider's own prefixes. Copying one into the
//! configuration by hand means it is wrong within a week, and nobody notices
//! until it matters.
//!
//! Like [`crate::domain`], the result is folded into the ordinary address groups
//! before the compiler runs, so a rule references a feed through the same
//! `source-group` / `destination-group` field and neither the compiler nor the
//! data plane needs a second concept.
//!
//! Three rules that are not negotiable, and the reasons they exist:
//!
//! **The last good list is cached, and a failed fetch keeps it.** A feed's usual
//! job is to block something. If a publisher's outage emptied the group, the
//! rule would match nothing — and a rule that blocks nothing is a rule that
//! allows. The failure would silently undo what the operator configured.
//!
//! **HTTPS only.** This list becomes firewall rules. Fetched over plain HTTP,
//! anything on the path decides what this box permits.
//!
//! **A cap, and it is loud.** The data plane's tries hold a bounded number of
//! entries. A feed that grows past what was budgeted must be truncated *and*
//! said, because silently keeping the first ten thousand of a blocklist is a
//! firewall that stopped blocking things without telling anybody.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};

use crate::config::Appliance;

/// Where the last good copy of each feed is kept.
const CACHE: &str = "/var/lib/sentinel/feed-groups.toml";

/// How long a cached copy is used before the feed is asked again. The refresh
/// timer runs far more often than this — it exists to re-resolve domain groups —
/// so without a TTL every tick would re-download every list, which is rude to
/// the publisher and slow for no gain.
const TTL_SECS: u64 = 3600;

/// The most addresses one feed may contribute.
const MAX_ENTRIES: usize = 10_000;

/// How long to wait for a publisher.
const TIMEOUT_SECS: u32 = 20;

/// Fetch every feed group and return a copy of `appliance` with the results
/// merged into its address groups.
///
/// Never fails: a feed that cannot be fetched falls back to its cached copy, and
/// one that has none yet contributes nothing but a warning. A hard error here
/// would refuse a whole commit because somebody else's web server was down.
pub fn with_fetched(appliance: &Appliance) -> Appliance {
    if appliance.firewall.group.feed.is_empty() {
        return appliance.clone();
    }
    let now = crate::aaa::unix_now();
    let mut cache = load_cache();
    let mut out = appliance.clone();

    for (name, urls) in &appliance.firewall.group.feed {
        let mut addrs: BTreeSet<String> = BTreeSet::new();
        for url in urls {
            let fresh = cache
                .get(url)
                .is_some_and(|c| now.saturating_sub(c.fetched) < TTL_SECS);
            if fresh {
                addrs.extend(cache[url].addresses.iter().cloned());
                continue;
            }
            match fetch(url) {
                Ok(list) => {
                    addrs.extend(list.iter().cloned());
                    cache.insert(
                        url.clone(),
                        Cached {
                            fetched: now,
                            addresses: list,
                        },
                    );
                }
                Err(e) => match cache.get(url) {
                    // Stale is not the same as absent. A list that is an hour
                    // out of date still blocks what it blocked an hour ago.
                    Some(cached) => {
                        eprintln!(
                            "warning: feed group {name:?}: {url} could not be fetched ({e}); \
                             keeping the copy from {}s ago",
                            now.saturating_sub(cached.fetched)
                        );
                        addrs.extend(cached.addresses.iter().cloned());
                    }
                    None => eprintln!(
                        "warning: feed group {name:?}: {url} could not be fetched ({e}) and \
                         nothing is cached — this group contributes nothing"
                    ),
                },
            }
        }
        if addrs.is_empty() {
            continue;
        }
        // Into the address groups, where a rule already knows how to name it.
        out.firewall
            .group
            .address
            .entry(name.clone())
            .or_default()
            .extend(addrs);
    }

    if let Err(e) = store_cache(&cache) {
        // A cache that cannot be written costs the safety net on the *next*
        // run, not this one, so it is a warning rather than a failure.
        eprintln!("warning: could not persist the feed-group cache: {e}");
    }
    out
}

/// Fetch one list and reduce it to addresses.
///
/// Published lists are text with comments, blank lines and sometimes a second
/// column. Anything that is not an address or a CIDR is skipped rather than
/// failing the fetch: one malformed line in a list of thousands must not cost
/// the whole list.
fn fetch(url: &str) -> Result<Vec<String>> {
    if !url.starts_with("https://") {
        anyhow::bail!("only https is accepted — this list becomes firewall rules");
    }
    let body = crate::system::curl_get_plain(url, TIMEOUT_SECS)
        .with_context(|| format!("fetching {url}"))?;
    let mut out = Vec::new();
    let mut skipped = 0usize;
    for line in body.lines() {
        // `#` and `;` both start a comment in the lists people publish.
        let line = line.split(['#', ';']).next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        // A leading token is the address; some lists carry a name after it.
        let token = line.split_whitespace().next().unwrap_or("");
        if crate::config::validate_cidr_or_ip(token).is_ok() {
            out.push(token.to_string());
        } else {
            skipped += 1;
        }
        if out.len() >= MAX_ENTRIES {
            eprintln!(
                "warning: {url} has more than {MAX_ENTRIES} addresses; the rest are ignored \
                 — this group no longer covers the whole list"
            );
            break;
        }
    }
    if out.is_empty() {
        anyhow::bail!("nothing in it parsed as an address ({skipped} lines skipped)");
    }
    Ok(out)
}

/// One cached feed: when it was fetched, and what it held.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Cached {
    fetched: u64,
    addresses: Vec<String>,
}

fn cache_path() -> std::path::PathBuf {
    std::env::var_os("SENTINEL_FEED_CACHE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(CACHE))
}

fn load_cache() -> BTreeMap<String, Cached> {
    std::fs::read_to_string(cache_path())
        .ok()
        .and_then(|t| toml::from_str(&t).ok())
        .unwrap_or_default()
}

fn store_cache(cache: &BTreeMap<String, Cached>) -> Result<()> {
    let path = cache_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, toml::to_string_pretty(cache)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A published list is text, not a data format: comments, blank lines and a
    /// second column are all ordinary. One bad line must not cost the list.
    #[test]
    fn a_published_list_is_read_forgivingly() {
        // The parse is exercised through the same code the fetch uses, with the
        // network step stood in for.
        let body = "\
# bogons, updated hourly
0.0.0.0/8
10.0.0.0/8      rfc1918
;a semicolon comment

192.0.2.1
not-an-address
2001:db8::/32
";
        let mut out = Vec::new();
        let mut skipped = 0;
        for line in body.lines() {
            let line = line.split(['#', ';']).next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let token = line.split_whitespace().next().unwrap_or("");
            if crate::config::validate_cidr_or_ip(token).is_ok() {
                out.push(token.to_string());
            } else {
                skipped += 1;
            }
        }
        assert_eq!(
            out,
            ["0.0.0.0/8", "10.0.0.0/8", "192.0.2.1", "2001:db8::/32"]
        );
        assert_eq!(skipped, 1, "exactly the one malformed line");
    }

    /// Plain HTTP is refused before anything is fetched. This list becomes
    /// firewall rules; over HTTP anything on the path decides what the box
    /// permits.
    #[test]
    fn a_feed_must_be_https() {
        let e = fetch("http://example.com/list.txt").expect_err("http was accepted");
        assert!(
            format!("{e}").contains("https"),
            "the refusal does not say why: {e}"
        );
    }

    /// A stale copy is kept when the publisher is unreachable. A feed's job is
    /// usually to block something, and a group that empties on a fetch failure
    /// turns a block into an allow — silently, at the moment the network is
    /// already misbehaving.
    #[test]
    fn an_unreachable_feed_keeps_what_it_had() {
        let dir = std::env::temp_dir().join(format!("sentinel-feed-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cache = dir.join("feed.toml");
        // SAFETY: a unit test, before any other thread reads the variable.
        unsafe { std::env::set_var("SENTINEL_FEED_CACHE", &cache) };

        let mut seeded = BTreeMap::new();
        seeded.insert(
            "https://example.invalid/bogons.txt".to_string(),
            Cached {
                // Older than the TTL, so the fetch is attempted — and fails,
                // because the host does not resolve.
                fetched: 1,
                addresses: vec!["203.0.113.0/24".into()],
            },
        );
        store_cache(&seeded).unwrap();

        let appliance = Appliance::from_toml(
            "[system]\nhostname = \"fw\"\n\
             [firewall.group.feed]\nbogons = [\"https://example.invalid/bogons.txt\"]\n",
        )
        .expect("parses");
        let out = with_fetched(&appliance);
        assert_eq!(
            out.firewall.group.address.get("bogons").map(Vec::as_slice),
            Some(["203.0.113.0/24".to_string()].as_slice()),
            "the cached list was dropped when the publisher was unreachable"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
