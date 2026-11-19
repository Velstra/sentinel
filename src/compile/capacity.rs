//! Does the compiled policy fit the data plane's maps?
//!
//! Every eBPF map is a fixed size, and nothing upstream of the agent used to
//! count against those sizes: 9,000 single-port rules passed `config check`
//! and the agent refused them with a raw `ENOSPC` after closing the datapath
//! gate; the same configuration saved and rebooted brought the box up with
//! every zoned link held down. A global blocklist is copied into every zone's
//! policy, so 100k entries on a three-zone box are 400k entries in the map,
//! and only the agent noticed.
//!
//! This counts what the agent will write — per map, from the compiled output,
//! with every scheduled rule included — and names the map, the count, the
//! limit and the rules that contribute most. The limits mirror the data
//! plane's map definitions (fabric `velstra-ebpf/src/main.rs` and
//! `velstra-common/src/policy.rs`); Sentinel does not link the data-plane
//! crates, and finding the ceiling as a half-programmed firewall is worse
//! than keeping two numbers in step.

use std::collections::BTreeMap;

use super::{PortRule, Schedules, VelstraConfig, compile_with};
use crate::config::Appliance;

/// `PORT_RULES`, `DST_RULES`, `PORT_RULES6`, `DST_RULES6`: 8192 entries each.
const RULE_TRIE: usize = 8192;
/// `MAC_RULES`.
const MAC_RULES: usize = 4096;
/// `MAX_RULE_LIMITS`: rate-limited rules across all policies.
const RULE_LIMITS: usize = 127;
/// `MAX_BLOCKLIST`, per address family, across all policies.
const BLOCKLIST: usize = 262_144;
/// `PORT_FORWARDS`.
const PORT_FORWARDS: usize = 1024;
/// `SERVICES`.
const SERVICES: usize = 1024;
/// `BACKENDS`: one flat pool shared by every service.
const BACKENDS: usize = 4096;
/// `SYNPROXY`.
const SYNPROXY: usize = 256;

/// Which rule trie a compiled port rule lands in — the agent's own split:
/// an IPv6 source or destination has its own trie, a v4 destination (or a
/// local one) the destination trie, a v4 source the IPv4 source trie, and a
/// rule naming no address at all BOTH source tries (one entry in each, unless
/// `family` scopes it to one), because the IPv6 datapath never consults the
/// IPv4 tries (fabric DP-11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Trie {
    Source4,
    Destination4,
    Source6,
    Destination6,
}

impl Trie {
    fn map(self) -> &'static str {
        match self {
            Trie::Source4 => "PORT_RULES (IPv4 source / address-less rules)",
            Trie::Destination4 => "DST_RULES (IPv4 destination rules)",
            Trie::Source6 => "PORT_RULES6 (IPv6 source / address-less rules)",
            Trie::Destination6 => "DST_RULES6 (IPv6 destination rules)",
        }
    }
}

/// How many box addresses of each family a `dst-local` rule will expand to
/// on the agent. Only an estimate is possible offline: the configured
/// addresses, plus one lease per DHCP interface and a link-local and an
/// autoconfigured address per IPv6-capable interface.
fn local_estimate(appliance: &Appliance) -> (usize, usize) {
    let configured = super::configured_local_addresses(appliance);
    let enabled: Vec<_> = appliance
        .interfaces
        .iter()
        .filter(|i| !i.disabled)
        .collect();
    let v4 = configured.iter().filter(|a| a.is_ipv4()).count()
        + enabled
            .iter()
            .filter(|i| i.address.as_deref() == Some("dhcp"))
            .count();
    let v6 = configured.iter().filter(|a| a.is_ipv6()).count() + 2 * enabled.len();
    (v4.max(1), v6.max(1))
}

/// Every trie entry one compiled rule becomes, as `(trie, entries)` pairs.
fn trie_entries(rule: &PortRule, local: (usize, usize)) -> Vec<(Trie, usize)> {
    if rule.src_mac.is_some() {
        return Vec::new();
    }
    let v6 = |cidr: &String| cidr.contains(':');
    if rule.dst_local {
        let mut out = Vec::new();
        if rule.family.as_deref() != Some("ipv6") {
            out.push((Trie::Destination4, local.0));
        }
        if rule.family.as_deref() != Some("ipv4") {
            out.push((Trie::Destination6, local.1));
        }
        return out;
    }
    let trie = match (&rule.src, &rule.dst) {
        (Some(s), _) if v6(s) => Trie::Source6,
        (_, Some(d)) if v6(d) => Trie::Destination6,
        (_, Some(_)) => Trie::Destination4,
        (Some(_), None) => Trie::Source4,
        (None, None) => {
            let mut out = Vec::new();
            if rule.family.as_deref() != Some("ipv6") {
                out.push((Trie::Source4, 1));
            }
            if rule.family.as_deref() != Some("ipv4") {
                out.push((Trie::Source6, 1));
            }
            return out;
        }
    };
    vec![(trie, 1)]
}

/// Rate-limit slots one compiled rule takes on the agent: one per rule it
/// writes, however many tries that rule lands in. A `dst-local` rule is
/// written as one rule per local address.
fn limit_slots(rule: &PortRule, entries: &[(Trie, usize)]) -> usize {
    if rule.dst_local {
        entries.iter().map(|(_, n)| n).sum()
    } else {
        usize::from(!entries.is_empty())
    }
}

/// One map over its limit, with what fills it.
fn over(map: &str, used: usize, limit: usize, top: &BTreeMap<String, usize>, why: &str) -> String {
    let mut ranked: Vec<(&String, &usize)> = top.iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    let largest = ranked
        .iter()
        .take(3)
        .map(|(name, n)| format!("{name} ({n})"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut out = format!("data-plane capacity: {map} needs {used} entries, its limit is {limit}");
    if !largest.is_empty() {
        out.push_str(&format!("; largest: {largest}"));
    }
    if !why.is_empty() {
        out.push_str(&format!(". {why}"));
    }
    out
}

fn rule_maps(cfg: &VelstraConfig, local: (usize, usize), errors: &mut Vec<String>) {
    let mut tries: BTreeMap<Trie, (usize, BTreeMap<String, usize>)> = BTreeMap::new();
    let mut macs = (0usize, BTreeMap::<String, usize>::new());
    let mut limits = (0usize, BTreeMap::<String, usize>::new());
    for policy in &cfg.policies {
        for rule in &policy.port_rules {
            let label = format!("rule {:?} in zone {}", rule.name, policy.name);
            if rule.src_mac.is_some() {
                macs.0 += 1;
                *macs.1.entry(label.clone()).or_default() += 1;
            }
            let entries = trie_entries(rule, local);
            for &(trie, n) in &entries {
                let slot = tries.entry(trie).or_default();
                slot.0 += n;
                *slot.1.entry(label.clone()).or_default() += n;
            }
            if rule.limit.is_some() {
                let n = limit_slots(rule, &entries);
                limits.0 += n;
                *limits.1.entry(label).or_default() += n;
            }
        }
    }
    for (trie, (used, top)) in &tries {
        if *used > RULE_TRIE {
            errors.push(over(
                trie.map(),
                *used,
                RULE_TRIE,
                top,
                "Every port of a range, every member of a group and each protocol of tcp_udp \
                 is its own entry; use fewer or narrower ranges and groups",
            ));
        }
    }
    if macs.0 > MAC_RULES {
        errors.push(over("MAC_RULES", macs.0, MAC_RULES, &macs.1, ""));
    }
    if limits.0 > RULE_LIMITS {
        errors.push(over(
            "RULE_LIMITS (rate-limited rules)",
            limits.0,
            RULE_LIMITS,
            &limits.1,
            "Each port of a rate-limited range and each member of its groups needs its own \
             limit slot",
        ));
    }
}

fn blocklists(cfg: &VelstraConfig, errors: &mut Vec<String>) {
    // The top-level list is the default policy's; every zone's policy carries
    // the global list and GeoIP countries again, because the data plane looks
    // a blocklist up under the arriving packet's policy only.
    let lists = std::iter::once(("the default policy".to_string(), &cfg.blocklist)).chain(
        cfg.policies
            .iter()
            .map(|p| (format!("zone {}", p.name), &p.blocklist)),
    );
    let mut v4 = (0usize, BTreeMap::<String, usize>::new());
    let mut v6 = (0usize, BTreeMap::<String, usize>::new());
    for (owner, list) in lists {
        let six = list.iter().filter(|e| e.contains(':')).count();
        let four = list.len() - six;
        v4.0 += four;
        v6.0 += six;
        v4.1.insert(owner.clone(), four);
        v6.1.insert(owner, six);
    }
    let why = format!(
        "Each of the {} zone policies and the default policy holds its own copy of the global \
         blocklist and GeoIP countries, so a global entry costs {} entries; block fewer \
         prefixes or countries, or move them to the zones that need them",
        cfg.policies.len(),
        cfg.policies.len() + 1
    );
    for (family, (used, top)) in [("IPv4", v4), ("IPv6", v6)] {
        if used > BLOCKLIST {
            errors.push(over(
                &format!("BLOCKLIST ({family})"),
                used,
                BLOCKLIST,
                &top,
                &why,
            ));
        }
    }
}

fn services(cfg: &VelstraConfig, errors: &mut Vec<String>) {
    let none = BTreeMap::new();
    if cfg.port_forwards.len() > PORT_FORWARDS {
        errors.push(over(
            "PORT_FORWARDS (port-forwards and hairpin reflections)",
            cfg.port_forwards.len(),
            PORT_FORWARDS,
            &none,
            "A hairpin forward adds one reflection per other zone",
        ));
    }
    if cfg.services.len() > SERVICES {
        errors.push(over("SERVICES", cfg.services.len(), SERVICES, &none, ""));
    }
    let backends: usize = cfg.services.iter().map(|s| s.backends.len()).sum();
    if backends > BACKENDS {
        errors.push(over("BACKENDS", backends, BACKENDS, &none, ""));
    }
    if cfg.synproxy.len() > SYNPROXY {
        errors.push(over("SYNPROXY", cfg.synproxy.len(), SYNPROXY, &none, ""));
    }
}

/// Every map the compiled policy would overflow, as a sentence each. Empty
/// when it fits. Compiles with every scheduled rule in force.
///
/// Call this on the appliance the agent will actually be given — after feed,
/// domain and identity groups have been merged in — not only on the
/// operator's file, whose groups may still be empty.
pub(crate) fn capacity_errors(appliance: &Appliance) -> Vec<String> {
    let cfg = compile_with(appliance, Schedules::All);
    let mut errors = Vec::new();
    rule_maps(&cfg, local_estimate(appliance), &mut errors);
    blocklists(&cfg, &mut errors);
    services(&cfg, &mut errors);
    errors
}
