//! Two compiled rules on the same data-plane key.
//!
//! The data plane holds **one** verdict per `(zone, protocol, ICMP type, port,
//! interface, address)`: its rule tries are keyed on exactly that, and the
//! agent writes rules in order, so a second rule on a key silently replaces the
//! first. Before this, the emitted order decided — `block-85` (drop) followed by
//! `web-range` (accept 80-90) left port 85 *open* — while `sentinel trace` and
//! `attribute` ranked the pair by strictness and reported the drop. The firewall
//! and the tool that explains it disagreed about the same packet.
//!
//! The compiler now resolves every such pair itself, with the tie-break the
//! trace has always documented: the stricter action wins (`reject` > `drop` >
//! `pass`), and between equally strict rules the one written first. Only the
//! winner is emitted, so the data plane, the trace and the attribution all read
//! the same single entry. Where the winner's family/direction scope does not
//! cover the loser's, part of what the losing rule said is not enforced at all,
//! and [`resolve`] says so in a note that `config check` and `commit` print.

use std::collections::BTreeMap;

use super::PortRule;

/// Which address end a compiled rule is keyed on.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum End {
    Any,
    Source(String),
    Destination(String),
    Local,
    Mac(String),
}

/// The part of a compiled rule the data plane keys its map entry on.
type Key = (&'static str, Option<u8>, u16, Option<String>, End);

fn key(r: &PortRule) -> Key {
    let end = if let Some(mac) = &r.src_mac {
        End::Mac(mac.to_ascii_lowercase())
    } else if let Some(src) = &r.src {
        End::Source(normalized(src))
    } else if let Some(dst) = &r.dst {
        End::Destination(normalized(dst))
    } else if r.dst_local {
        End::Local
    } else {
        End::Any
    };
    // A typed ICMP rule is keyed at port 0 by the agent, whatever port field
    // it carries.
    let port = if r.icmp_type.is_some() { 0 } else { r.port };
    (r.proto, r.icmp_type, port, r.in_interface.clone(), end)
}

/// A CIDR in the form the agent's trie stores it: host bits cleared and an
/// explicit prefix length, so `10.0.0.5/24`, `10.0.0.0/24` and a bare host
/// compare the way the map does.
fn normalized(cidr: &str) -> String {
    let (addr, bits) = match cidr.split_once('/') {
        Some((a, b)) => (a, b.parse::<u32>().ok()),
        None => (cidr, None),
    };
    match addr.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            let bits = bits.unwrap_or(32).min(32);
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            format!("{}/{bits}", std::net::Ipv4Addr::from(u32::from(ip) & mask))
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            let bits = bits.unwrap_or(128).min(128);
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            format!("{}/{bits}", std::net::Ipv6Addr::from(u128::from(ip) & mask))
        }
        Err(_) => cidr.to_string(),
    }
}

/// `reject` > `drop` > `pass` — the order `sentinel trace` ranks equal
/// prefixes by.
pub(crate) fn strictness(action: &str) -> u8 {
    match action {
        "reject" => 2,
        "drop" => 1,
        _ => 0,
    }
}

/// The family a rule is really scoped to. An ICMP or ICMPv6 rule can only ever
/// match its own family, so a `family` written on it changes nothing in the data
/// plane and must not make two otherwise identical entries look different.
fn family(r: &PortRule) -> Option<&str> {
    match r.proto {
        "icmp" => Some("ipv4"),
        "icmpv6" => Some("ipv6"),
        _ => r.family.as_deref(),
    }
}

/// action, log, limit, burst, family scope, direction.
type Verdict<'a> = (
    &'static str,
    bool,
    Option<u32>,
    Option<u32>,
    Option<&'a str>,
    &'a Option<String>,
);

/// Everything but the key: two entries that agree on all of it are the same
/// entry written twice (overlapping groups do this), not a conflict.
fn verdict(r: &PortRule) -> Verdict<'_> {
    (r.action, r.log, r.limit, r.burst, family(r), &r.direction)
}

/// Two entries that differ only in being the `in` and the `out` half.
fn mirrored(a: &PortRule, b: &PortRule) -> bool {
    let halves = matches!(
        (a.direction.as_deref(), b.direction.as_deref()),
        (Some("in"), Some("out")) | (Some("out"), Some("in"))
    );
    halves
        && (a.action, a.log, a.limit, a.burst, family(a))
            == (b.action, b.log, b.limit, b.burst, family(b))
}

/// Whether `outer`'s family/direction scope covers everything `inner`'s does.
fn covers(outer: &PortRule, inner: &PortRule) -> bool {
    let family = family(outer).is_none() || family(outer) == family(inner);
    let direction = outer.direction.is_none() || outer.direction == inner.direction;
    family && direction
}

fn describe(r: &PortRule) -> String {
    let scope = [r.family.as_deref(), r.direction.as_deref()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    if scope.is_empty() {
        format!("{:?} ({})", r.name, r.action)
    } else {
        format!("{:?} ({}, {})", r.name, r.action, scope.join(" "))
    }
}

fn what(r: &PortRule) -> String {
    if let Some(mac) = &r.src_mac {
        return format!("sender {mac}");
    }
    let mut out = if r.port != 0 && r.icmp_type.is_none() {
        format!("{}/{}", r.proto, r.port)
    } else {
        r.proto.to_string()
    };
    if let Some(s) = &r.src {
        out.push_str(&format!(" from {s}"));
    }
    if let Some(d) = &r.dst {
        out.push_str(&format!(" to {d}"));
    }
    if r.dst_local {
        out.push_str(" to this box");
    }
    if let Some(i) = &r.in_interface {
        out.push_str(&format!(" on {i}"));
    }
    out
}

/// Keep one rule per data-plane key, the stricter one; append a note to
/// `notes` for every pair whose loser had a scope the winner does not cover.
///
/// The winner takes the position of the key's first occurrence, so the
/// emitted order stays the configured order.
pub(crate) fn resolve(rules: Vec<PortRule>, zone: &str, notes: &mut Vec<String>) -> Vec<PortRule> {
    let mut slot_of: BTreeMap<Key, usize> = BTreeMap::new();
    let mut kept: Vec<PortRule> = Vec::with_capacity(rules.len());
    for rule in rules {
        let k = key(&rule);
        let Some(&slot) = slot_of.get(&k) else {
            slot_of.insert(k, kept.len());
            kept.push(rule);
            continue;
        };
        let current = &kept[slot];
        if verdict(current) == verdict(&rule) {
            continue;
        }
        // The same verdict for `in` and for `out` is one entry for both
        // directions — the data plane's "no direction" — not a conflict.
        if mirrored(current, &rule) {
            kept[slot].direction = None;
            continue;
        }
        let replace = strictness(rule.action) > strictness(current.action);
        let (winner, loser) = if replace {
            (&rule, current)
        } else {
            (current, &rule)
        };
        // A stricter winner whose scope covers the loser's is the documented
        // tie-break doing its job (an exception carved out of a range): quiet.
        // Anything else loses something the operator wrote.
        let equally_strict = strictness(winner.action) == strictness(loser.action);
        let loses_limit = equally_strict && winner.limit != loser.limit;
        if winner.name != loser.name && (!covers(winner, loser) || loses_limit) {
            notes.push(format!(
                "zone {zone:?}: rules {} and {} both match {}; the data plane holds one \
                 verdict per zone, protocol, port and address, so {} decides it and the \
                 part of {} outside its scope falls to the zone default. Give the rules \
                 different ports or addresses, or the same family/direction scope.",
                describe(winner),
                describe(loser),
                what(winner),
                describe(winner),
                describe(loser),
            ));
        }
        if replace {
            kept[slot] = rule;
        }
    }
    kept
}
