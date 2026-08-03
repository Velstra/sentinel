//! User groups: a firewall rule that names people instead of addresses
//! (roadmap: identity-based policy).
//!
//! A rule saying `10.9.0.0/24` says where somebody was, not who they are. When
//! addresses come from a pool, the two drift apart the moment anybody
//! reconnects — and the rule then describes whoever holds that address now.
//!
//! Like [`crate::domain`] and [`crate::feed`], the result is folded into the
//! ordinary address groups before the compiler runs, so a rule references a user
//! group through the same `source-group` / `destination-group` field and neither
//! the compiler nor the data plane needs a second concept.
//!
//! **Where identity comes from, and where it does not.** The only place this
//! appliance learns that an address belongs to a *person* is the road-warrior
//! VPN: a client authenticates with a username and is handed an address. The
//! captive portal admits by MAC and never learns a name; a host on the LAN has
//! no identity here at all. So a user group is a group of **VPN users**, and
//! saying that plainly is better than a feature that silently covers a third of
//! what its name suggests.
//!
//! **There is no cache, and that is the opposite of the feed groups on
//! purpose.** A feed's job is to block, so a stale copy is safer than an empty
//! one. A user group's job is usually to *allow*, so a stale copy would keep
//! somebody's access alive after they disconnected and their address went to
//! the next person in the pool. When the VPN cannot be asked, the group is empty
//! and says so.

use std::collections::{BTreeMap, BTreeSet};

use crate::config::Appliance;

/// Who is connected, and on which address.
///
/// Parses `occtl --json show users`. The JSON is read with the appliance's own
/// serde rather than by hand because the fields that matter — `Username` and
/// `IPv4`/`IPv6` — sit among two dozen others that change between releases.
pub fn connected() -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let Ok(text) = crate::system::occtl_json(&["show", "users"]) else {
        return out;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return out;
    };
    let Some(rows) = value.as_array() else {
        return out;
    };
    for row in rows {
        let Some(user) = row.get("Username").and_then(|v| v.as_str()) else {
            continue;
        };
        if user.is_empty() {
            continue;
        }
        for key in ["IPv4", "IPv6"] {
            if let Some(addr) = row.get(key).and_then(|v| v.as_str()) {
                // occtl prints an empty string for the family a session does
                // not have, and the appliance's validators would refuse it.
                if crate::config::validate_cidr_or_ip(addr).is_ok() {
                    out.entry(user.to_string())
                        .or_default()
                        .insert(host_prefix(addr));
                }
            }
        }
    }
    out
}

/// One address as a single-host prefix, which is what an address group holds.
fn host_prefix(addr: &str) -> String {
    if addr.contains('/') {
        return addr.to_string();
    }
    if addr.contains(':') {
        format!("{addr}/128")
    } else {
        format!("{addr}/32")
    }
}

/// Resolve every user group and return a copy of `appliance` with the results
/// merged into its address groups.
///
/// Never fails: a VPN that cannot be asked leaves its groups empty, with a
/// warning. An empty group matches nothing, which for an allow rule means the
/// access is not granted — the safe direction when identity is unknown.
pub fn with_resolved(appliance: &Appliance) -> Appliance {
    if appliance.firewall.group.user.is_empty() {
        return appliance.clone();
    }
    let live = connected();
    let mut out = appliance.clone();
    for (name, users) in &appliance.firewall.group.user {
        let mut addrs: BTreeSet<String> = BTreeSet::new();
        let mut absent = Vec::new();
        for user in users {
            match live.get(user) {
                Some(found) => addrs.extend(found.iter().cloned()),
                None => absent.push(user.as_str()),
            }
        }
        if !absent.is_empty() {
            // Not a warning about a mistake: somebody being disconnected is the
            // ordinary case. It is said because a rule that suddenly matches
            // nothing otherwise looks like a firewall fault.
            eprintln!(
                "note: user group {name:?}: not connected right now — {}",
                absent.join(", ")
            );
        }
        if addrs.is_empty() {
            continue;
        }
        out.firewall
            .group
            .address
            .entry(name.clone())
            .or_default()
            .extend(addrs);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A session has one family or both, and occtl prints an empty string for
    /// the one it does not have. Letting that through would put `""` into an
    /// address group, where it becomes a rule that matches nothing and cannot be
    /// explained by looking at the configuration.
    #[test]
    fn an_address_becomes_a_single_host_prefix() {
        assert_eq!(host_prefix("10.9.0.7"), "10.9.0.7/32");
        assert_eq!(host_prefix("fd00::7"), "fd00::7/128");
        // Already a prefix: left alone.
        assert_eq!(host_prefix("10.9.0.0/24"), "10.9.0.0/24");
    }

    /// A user group whose members are all disconnected contributes nothing — and
    /// nothing is the right answer. Carrying yesterday's addresses would keep
    /// access alive for whoever holds them now.
    #[test]
    fn a_group_of_nobody_contributes_nothing() {
        let appliance = Appliance::from_toml(
            "[system]\nhostname = \"fw\"\n\
             [firewall.group.user]\nadmins = [\"alice\"]\n",
        )
        .expect("parses");
        // No VPN is running in a unit test, so `connected()` is empty.
        let out = with_resolved(&appliance);
        assert!(
            !out.firewall.group.address.contains_key("admins"),
            "a group of disconnected users must not appear as an address group"
        );
    }

    /// A configuration with no user group is returned untouched — the resolver
    /// must not cost anything on a box that does not use it.
    #[test]
    fn a_box_without_user_groups_is_left_alone() {
        let appliance = Appliance::from_toml("[system]\nhostname = \"fw\"\n").expect("parses");
        let out = with_resolved(&appliance);
        assert!(out.firewall.group.address.is_empty());
    }
}
