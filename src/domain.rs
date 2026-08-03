//! Domain groups (roadmap C15): DNS names resolved to addresses the firewall can
//! match on.
//!
//! The data plane matches addresses by longest prefix and knows nothing about
//! names, so a domain group is resolved in user space and folded into the address
//! groups before the compiler runs. A rule therefore references a domain group
//! through the same `source-group` / `destination-group` field as an address
//! group, and neither the compiler nor the data plane needs a second concept.
//!
//! **The last good answer is cached on disk, and a failed lookup keeps it.** That
//! is the whole reason this file has state. A domain group's usual job is to block
//! something; if a transient DNS failure emptied the group, the rule would match
//! nothing — and a rule that blocks nothing is a rule that allows. The outage
//! would silently undo exactly what the operator configured, at the moment the
//! network is already misbehaving.

use std::collections::{BTreeMap, BTreeSet};
use std::net::ToSocketAddrs;

use anyhow::{Context, Result};

use crate::config::Appliance;

/// Where the last successful resolution of each domain is kept.
const CACHE: &str = "/var/lib/sentinel/domain-groups.toml";

/// Resolve every domain group and return a copy of `appliance` with the results
/// merged into its address groups.
///
/// Never fails on a lookup: a domain that will not resolve falls back to its
/// cached addresses, and one that has none yet contributes nothing but a warning.
/// A hard error here would refuse a whole commit because a name server blinked.
pub fn with_resolved(appliance: &Appliance) -> Appliance {
    if appliance.firewall.group.domain.is_empty() {
        return appliance.clone();
    }
    let mut cache = load_cache();
    let mut out = appliance.clone();
    for (name, domains) in &appliance.firewall.group.domain {
        let mut addrs: BTreeSet<String> = BTreeSet::new();
        for domain in domains {
            match resolve_one(domain) {
                Ok(found) if !found.is_empty() => {
                    cache.insert(domain.clone(), found.clone());
                    addrs.extend(found);
                }
                // Resolved to nothing usable (v6-only, say) or failed outright:
                // either way the cached answer is better than none.
                other => {
                    if let Err(e) = other {
                        eprintln!("warning: domain-group {name}: resolving {domain} failed: {e}");
                    }
                    match cache.get(domain) {
                        Some(cached) => addrs.extend(cached.iter().cloned()),
                        None => eprintln!(
                            "warning: domain-group {name}: {domain} has never \
                             resolved; it contributes no addresses"
                        ),
                    }
                }
            }
        }
        if addrs.is_empty() {
            eprintln!(
                "warning: domain-group {name}: resolved to no addresses; \
                 rules using it match nothing"
            );
        }
        out.firewall
            .group
            .address
            .insert(name.clone(), addrs.into_iter().collect());
    }
    if let Err(e) = store_cache(&cache) {
        // A cache that cannot be written costs the safety net on the *next* run,
        // not this one, so it must not fail the apply.
        eprintln!("warning: could not persist the domain-group cache: {e}");
    }
    out
}

/// The IPv4 addresses a name resolves to. Port 0 is a placeholder — the resolver
/// wants a socket address and only the IP is kept.
///
/// **Both families.** IPv6 answers used to be dropped, because the rule tries
/// matched IPv4 only — they no longer do. Keeping only the A records made a
/// domain group half a group: the usual job of one is to *block* something, and
/// a name that also has AAAA records was reachable over IPv6 the whole time,
/// silently, which is the worst way for a block to be incomplete.
fn resolve_one(domain: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for addr in (domain, 0u16)
        .to_socket_addrs()
        .with_context(|| format!("resolving {domain}"))?
    {
        let cidr = match addr.ip() {
            std::net::IpAddr::V4(v4) => format!("{v4}/32"),
            std::net::IpAddr::V6(v6) => format!("{v6}/128"),
        };
        if !out.contains(&cidr) {
            out.push(cidr);
        }
    }
    Ok(out)
}

/// The on-disk cache: `domain = ["1.2.3.4/32", …]`. A missing or unreadable file
/// is an empty cache, not an error — the first run has none.
fn load_cache() -> BTreeMap<String, Vec<String>> {
    std::fs::read_to_string(CACHE)
        .ok()
        .and_then(|raw| toml::from_str(&raw).ok())
        .unwrap_or_default()
}

fn store_cache(cache: &BTreeMap<String, Vec<String>>) -> Result<()> {
    let path = std::path::Path::new(CACHE);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let body = toml::to_string_pretty(cache).context("serializing the domain-group cache")?;
    crate::system::install_file(path, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A box with no domain groups must not touch the cache or the address groups.
    #[test]
    fn without_domain_groups_the_appliance_is_unchanged() {
        let toml = r#"
[system]
hostname = "fw"
[firewall.group.address]
admins = ["10.0.0.10/32"]
"#;
        let a = Appliance::from_toml(toml).unwrap();
        let out = with_resolved(&a);
        assert_eq!(out.firewall.group.address, a.firewall.group.address);
    }

    /// `localhost` is the one name every machine resolves without a network, so it
    /// is what proves the merge lands where the compiler will look for it.
    #[test]
    fn a_resolved_group_becomes_an_address_group() {
        let toml = r#"
[system]
hostname = "fw"
[firewall.group.domain]
loop = ["localhost.localdomain"]
"#;
        let a = Appliance::from_toml(toml).unwrap();
        // Resolution may legitimately fail in a sandbox with no resolver at all;
        // what must hold either way is that the group exists after the merge, so a
        // rule referencing it compiles instead of dangling.
        let out = with_resolved(&a);
        assert!(
            out.firewall.group.address.contains_key("loop"),
            "the domain group must appear among the address groups"
        );
    }

    /// Every answer is kept, as a host prefix in its own family. A bare address
    /// would not parse where the compiler expects a host or CIDR, and dropping
    /// the AAAA records — which this used to do — left a blocking group that did
    /// not block over IPv6.
    #[test]
    fn resolution_yields_host_prefixes_in_both_families() {
        let answers = resolve_one("localhost").unwrap_or_default();
        for cidr in &answers {
            let (addr, len) = cidr.split_once('/').expect("a host prefix");
            match addr.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(_)) => assert_eq!(len, "32", "{cidr}"),
                Ok(std::net::IpAddr::V6(_)) => assert_eq!(len, "128", "{cidr}"),
                Err(e) => panic!("{cidr} is not an address: {e}"),
            }
        }
        // localhost resolves to at least one of the two on every sane box.
        assert!(!answers.is_empty(), "localhost resolved to nothing");
    }
}
