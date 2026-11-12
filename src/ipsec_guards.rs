//! Daemon-independent confidentiality shunts for policy IPsec (OSQA-040).
//!
//! Charon's UPDPOLICY replaces same-selector XFRM block policies. Instead,
//! enforce encryption at Netfilter before TC SNAT. The eBPF agent still owns
//! firewall policy; these narrow rules only reject protected selectors without
//! outbound XFRM or inbound IPsec provenance. Never flush a global ruleset.

use crate::{config::Appliance, system};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::Path;

const STATE: &str = "/run/sentinel/ipsec-guards.json";
const RULES: &str = "/run/sentinel/ipsec-guards.nft";
const TABLE: &str = "sentinel_ipsec_shunt";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
enum Direction {
    In,
    Out,
    Fwd,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Guard {
    src: String,
    dst: String,
    direction: Direction,
    local: Ipv4Addr,
    remote: Ipv4Addr,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: u32,
    guards: Vec<Guard>,
    // Entire stateless numerical table, not just rule comments. An interrupted
    // transaction without a saved fingerprint fails closed on the next apply.
    snapshot: Option<String>,
}

fn selector(value: &str) -> Result<String> {
    let (address, prefix) = value.split_once('/').unwrap_or((value, "32"));
    let address = address
        .parse::<Ipv4Addr>()
        .context("invalid protected IPv4 address")?;
    let prefix = prefix
        .parse::<u32>()
        .context("invalid protected prefix length")?;
    ensure!(prefix <= 32, "invalid protected prefix length");
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ok(format!(
        "{}/{}",
        Ipv4Addr::from(u32::from(address) & mask),
        prefix
    ))
}

fn validate(rows: Vec<Guard>) -> Result<Vec<Guard>> {
    let mut result = BTreeSet::new();
    for guard in rows {
        ensure!(
            selector(&guard.src)? == guard.src && selector(&guard.dst)? == guard.dst,
            "noncanonical IPsec guard state"
        );
        result.insert(guard);
    }
    Ok(result.into_iter().collect())
}

fn wanted(appliance: &Appliance) -> Result<Vec<Guard>> {
    let mut rows = Vec::new();
    for conn in &appliance.vpn.ipsec {
        // A route-based 0/0 selector must NOT become a global policy shunt.
        if conn.vti.is_some() {
            continue;
        }
        let local = selector(
            conn.local_subnet
                .as_deref()
                .context("policy IPsec requires a local subnet")?,
        )?;
        let remote = selector(
            conn.remote_subnet
                .as_deref()
                .context("policy IPsec requires a remote subnet")?,
        )?;
        let local_endpoint = conn.local.parse().context("invalid local IKE endpoint")?;
        let remote_endpoint = conn.remote.parse().context("invalid remote IKE endpoint")?;
        rows.push(Guard {
            src: local.clone(),
            dst: remote.clone(),
            direction: Direction::Out,
            local: local_endpoint,
            remote: remote_endpoint,
        });
        for direction in [Direction::In, Direction::Fwd] {
            rows.push(Guard {
                src: remote.clone(),
                dst: local.clone(),
                direction,
                local: local_endpoint,
                remote: remote_endpoint,
            });
        }
    }
    validate(rows)
}

fn previous() -> Result<Option<Journal>> {
    let Some(body) = system::read_owned_file(Path::new(STATE))? else {
        return Ok(None);
    };
    let mut journal: Journal =
        serde_json::from_str(&body).context("invalid IPsec shunt journal")?;
    ensure!(journal.schema == 2, "unknown IPsec shunt journal schema");
    journal.guards = validate(journal.guards)?;
    if let Some(hash) = &journal.snapshot {
        ensure!(
            hash.len() == 64 && hash.bytes().all(|c| c.is_ascii_hexdigit()),
            "invalid shunt fingerprint"
        );
    }
    Ok(Some(journal))
}

fn record(journal: &Journal) -> Result<()> {
    system::install_config_file(Path::new(STATE), &(serde_json::to_string(journal)? + "\n"))
}

fn fingerprint(body: &str) -> String {
    // nft -s omits packet/byte counters; handles are not requested.
    let canonical = body.split_whitespace().collect::<Vec<_>>().join(" ");
    ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn query() -> Result<Option<String>> {
    let output = system::escalated_output("nft", &["-s", "-nn", "list", "table", "inet", TABLE])?;
    if output.status.success() {
        return Ok(Some(
            String::from_utf8(output.stdout).context("non-UTF8 IPsec shunt table")?,
        ));
    }
    let error = String::from_utf8_lossy(&output.stderr);
    if output.status.code() == Some(1) && error.contains("No such file or directory") {
        return Ok(None);
    }
    bail!("cannot inspect IPsec shunt table: {}", error.trim())
}

fn owned(journal: Option<&Journal>, body: Option<&str>) -> bool {
    match (journal, body) {
        (_, None) => true,
        (Some(journal), Some(body)) => journal.snapshot.as_ref() == Some(&fingerprint(body)),
        (None, Some(_)) => false,
    }
}

fn render(rows: &[Guard], replace: bool) -> String {
    let mut text = String::new();
    if replace {
        text.push_str(&format!("delete table inet {TABLE}\n"));
    }
    if rows.is_empty() {
        return text;
    }
    text.push_str(&format!(
        "table inet {TABLE} {{\n comment \"Sentinel policy-IPsec confidentiality shunts\"\n"
    ));
    for (name, direction) in [
        ("input", Direction::In),
        ("output", Direction::Out),
        ("forward", Direction::Fwd),
    ] {
        text.push_str(&format!(
            " chain {name} {{\n  type filter hook {name} priority -150; policy accept;\n"
        ));
        // Full policy selectors can cover the IKE/ESP endpoints themselves.
        // Charon's socket XFRM bypass does not bypass this separate nft hook.
        // Exempt ONLY the configured endpoint transport on host input/output;
        // never create a forwarded UDP/ESP plaintext escape. Outgoing IKE must
        // originate from a root-owned daemon socket on its actual IKE ports.
        if direction != Direction::Fwd {
            let endpoints: BTreeSet<_> = rows.iter().map(|g| (g.local, g.remote)).collect();
            for (local, remote) in endpoints {
                let (src, dst, ike) = if direction == Direction::Out {
                    (local, remote, "meta skuid 0 udp sport { 500, 4500 }")
                } else {
                    (remote, local, "udp dport { 500, 4500 }")
                };
                text.push_str(&format!(
                    "  ip saddr {src} ip daddr {dst} {ike} counter accept\n"
                ));
                text.push_str(&format!(
                    "  ip saddr {src} ip daddr {dst} meta l4proto esp counter accept\n"
                ));
            }
        }
        for guard in rows {
            let check = match (direction, guard.direction) {
                (Direction::Out | Direction::Fwd, Direction::Out) => "rt ipsec missing",
                (Direction::In, Direction::In) | (Direction::Fwd, Direction::Fwd) => {
                    "meta ipsec missing"
                }
                _ => continue,
            };
            text.push_str(&format!(
                "  ip saddr {} ip daddr {} {check} counter drop\n",
                guard.src, guard.dst
            ));
        }
        text.push_str(" }\n");
    }
    text.push_str("}\n");
    text
}

fn reconcile(rows: &[Guard]) -> Result<()> {
    let old = previous()?;
    let actual = query()?;
    ensure!(
        owned(old.as_ref(), actual.as_deref()),
        "foreign, altered or incompletely journalled IPsec shunt table; refusing mutation"
    );
    if actual.is_some() && old.as_ref().is_some_and(|j| j.guards == rows) {
        return Ok(());
    }
    if actual.is_none() && rows.is_empty() {
        if old.is_some() {
            system::remove_file(Path::new(STATE))?;
        }
        return Ok(());
    }
    // Retain the old complete journal until the atomic kernel transaction
    // succeeds. First creation records pending ownership BEFORE mutation.
    if old.is_none() && !rows.is_empty() {
        record(&Journal {
            schema: 2,
            guards: rows.to_vec(),
            snapshot: None,
        })?;
    }
    system::install_config_file(Path::new(RULES), &render(rows, actual.is_some()))?;
    let output = system::escalated_output("nft", &["--file", RULES])?;
    ensure!(
        output.status.success(),
        "IPsec shunt transaction failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    if rows.is_empty() {
        ensure!(
            query()?.is_none(),
            "removed IPsec shunt table remains present"
        );
        system::remove_file(Path::new(STATE))?;
    } else {
        let body = query()?.context("new IPsec shunt table is absent")?;
        record(&Journal {
            schema: 2,
            guards: rows.to_vec(),
            snapshot: Some(fingerprint(&body)),
        })?;
    }
    Ok(())
}

/// Protect the union of old/new selectors BEFORE interfaces/routes change.
pub(crate) fn prepare(appliance: &Appliance) -> Result<Vec<Guard>> {
    let desired = wanted(appliance)?;
    let old = previous()?.map(|j| j.guards).unwrap_or_default();
    let union = validate(old.into_iter().chain(desired.iter().cloned()).collect())?;
    if !union.is_empty() {
        reconcile(&union)?;
    }
    Ok(desired)
}

/// Prune obsolete selectors only AFTER old routes/config are reconciled.
pub(crate) fn finish(desired: &[Guard]) -> Result<()> {
    if !desired.is_empty() || previous()?.is_some() {
        reconcile(desired)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn guards() -> Vec<Guard> {
        vec![
            Guard {
                src: "198.18.20.0/24".into(),
                dst: "198.19.210.0/24".into(),
                direction: Direction::Out,
                local: "198.18.10.100".parse().unwrap(),
                remote: "198.18.10.254".parse().unwrap(),
            },
            Guard {
                src: "198.19.210.0/24".into(),
                dst: "198.18.20.0/24".into(),
                direction: Direction::In,
                local: "198.18.10.100".parse().unwrap(),
                remote: "198.18.10.254".parse().unwrap(),
            },
            Guard {
                src: "198.19.210.0/24".into(),
                dst: "198.18.20.0/24".into(),
                direction: Direction::Fwd,
                local: "198.18.10.100".parse().unwrap(),
                remote: "198.18.10.254".parse().unwrap(),
            },
        ]
    }
    #[test]
    fn selectors_are_canonical_and_bounded() {
        assert_eq!(selector("198.18.20.19/24").unwrap(), "198.18.20.0/24");
        assert_eq!(selector("198.18.20.19").unwrap(), "198.18.20.19/32");
        assert_eq!(selector("198.18.20.19/0").unwrap(), "0.0.0.0/0");
        for bad in [
            "::/0",
            "198.18.20.1/33",
            "198.18.20.1/-1",
            "198.18.20.1/24/24",
            "x",
            "",
        ] {
            assert!(selector(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn duplicate_selectors_are_stable_but_noncanonical_journals_are_refused() {
        let rows = guards();
        assert_eq!(
            validate(rows.iter().cloned().chain(rows.clone()).collect())
                .unwrap()
                .len(),
            3
        );
        let mut invalid = rows;
        invalid[0].src = "198.18.20.5/24".into();
        assert!(validate(invalid).is_err());
    }
    #[test]
    fn all_packet_directions_require_encryption_or_provenance() {
        let body = render(&guards(), false);
        assert_eq!(body.matches("counter drop").count(), 4);
        assert_eq!(body.matches("rt ipsec missing").count(), 2);
        assert_eq!(body.matches("meta ipsec missing").count(), 2);
        for hook in ["input", "output", "forward"] {
            assert!(body.contains(&format!("hook {hook} priority -150; policy accept")));
        }
    }
    #[test]
    fn rules_are_not_a_destination_blackhole_or_a_global_firewall() {
        let body = render(&guards(), false);
        assert_eq!(
            body.matches("ip saddr 198.18.20.0/24 ip daddr 198.19.210.0/24")
                .count(),
            2
        );
        for forbidden in ["policy drop", "flush ruleset", "xfrm policy", "tcp"] {
            assert!(!body.contains(forbidden));
        }
    }
    #[test]
    fn replacement_is_one_table_scoped_atomic_transaction() {
        assert!(render(&guards(), true).starts_with(
            "delete table inet sentinel_ipsec_shunt\ntable inet sentinel_ipsec_shunt"
        ));
        assert_eq!(
            render(&[], true),
            "delete table inet sentinel_ipsec_shunt\n"
        );
        assert!(render(&[], false).is_empty());
    }
    #[test]
    fn identical_foreign_or_modified_tables_are_never_adopted() {
        let body = render(&guards(), false);
        let journal = Journal {
            schema: 2,
            guards: guards(),
            snapshot: Some(fingerprint(&body)),
        };
        assert!(!owned(None, Some(&body)));
        assert!(owned(Some(&journal), Some(&body)));
        assert!(!owned(
            Some(&journal),
            Some(&body.replace("counter drop", "counter accept"))
        ));
        assert!(!owned(
            Some(&Journal {
                snapshot: None,
                ..journal
            }),
            Some(&body)
        ));
    }
    #[test]
    fn full_fingerprint_ignores_only_whitespace_not_foreign_objects() {
        assert_eq!(fingerprint("a b\n c"), fingerprint("a\t b c"));
        assert_ne!(fingerprint("a b"), fingerprint("a b foreign rule"));
    }
    #[test]
    fn endpoint_transport_is_narrow_and_never_exempts_forwarded_plaintext() {
        let body = render(&guards(), false);
        assert_eq!(body.matches("counter accept").count(), 4);
        assert!(body.contains("ip saddr 198.18.10.100 ip daddr 198.18.10.254 meta skuid 0 udp sport { 500, 4500 } counter accept"));
        assert!(body.contains(
            "ip saddr 198.18.10.254 ip daddr 198.18.10.100 udp dport { 500, 4500 } counter accept"
        ));
        let forward = body.split(" chain forward {").nth(1).unwrap();
        assert!(!forward.contains("counter accept"));
        assert!(!forward.contains("udp"));
        assert_eq!(forward.matches("counter drop").count(), 2);
    }
    #[test]
    fn identical_selectors_preserve_distinct_peers_and_deduplicate_transport() {
        let mut other = guards();
        for g in &mut other {
            g.remote = "198.18.10.253".parse().unwrap();
        }
        let rows = validate(guards().into_iter().chain(other).collect()).unwrap();
        assert_eq!(rows.len(), 6);
        let body = render(&rows, false);
        assert_eq!(body.matches("counter accept").count(), 8);
        for peer in ["198.18.10.253", "198.18.10.254"] {
            assert_eq!(
                body.matches(&format!("ip daddr {peer} meta skuid 0"))
                    .count(),
                1
            );
        }
    }
    #[test]
    fn start_trap_and_responder_modes_get_the_same_shunts() {
        for action in ["start", "trap", "none"] {
            let appliance = Appliance::from_toml(&format!(
                r#"
[system]
hostname="fw"
[[vpn.ipsec]]
name="site"
local="198.18.10.100"
remote="198.18.10.254"
local-subnet="198.18.20.0/24"
remote-subnet="198.19.210.0/24"
psk="public-unit-test-only"
start-action="{action}"
"#
            ))
            .unwrap();
            assert_eq!(wanted(&appliance).unwrap(), validate(guards()).unwrap());
        }
    }
    fn default_policy(local: &str, remote: &str, extra: &str) -> String {
        format!(
            r#"
[system]
hostname="fw"
[[vpn.ipsec]]
name="site"
local="198.18.10.100"
remote="198.18.10.254"
local-subnet="{local}"
remote-subnet="{remote}"
psk="public-validation-fixture-only"
{extra}
"#
        )
    }
    #[test]
    fn policy_defaults_on_both_sides_are_refused_before_apply_including_aliases() {
        for (local, remote) in [
            ("0.0.0.0/0", "0.0.0.0/0"),
            ("198.18.20.1/0", "198.19.210.9/0"),
        ] {
            let error = Appliance::from_toml(&default_policy(local, remote, "")).unwrap_err();
            assert!(error.to_string().contains("/0 on both sides"), "{error}");
            assert!(error.to_string().contains("`vti`"), "{error}");
        }
    }
    #[test]
    fn a_policy_remote_default_with_bounded_local_selector_remains_valid() {
        for local in ["198.18.20.0/24", "198.18.0.0/16"] {
            let appliance = Appliance::from_toml(&default_policy(local, "0.0.0.0/0", "")).unwrap();
            assert_eq!(wanted(&appliance).unwrap().len(), 3);
        }
    }
    #[test]
    fn route_based_both_default_selectors_remain_valid_and_do_not_get_global_shunts() {
        let text = default_policy(
            "0.0.0.0/0",
            "0.0.0.0/0",
            r#"vti="vti0"
[[interface]]
name="vti0"
type="vti"
vti-key=42
address="10.255.0.1/30""#,
        );
        let appliance = Appliance::from_toml(&text).unwrap();
        assert!(wanted(&appliance).unwrap().is_empty());
    }
}
