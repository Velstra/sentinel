//! Regression tests for the compiler contract findings of release audit
//! 8b6181 (DP-13 … DP-43, HA-01, PROV-03, PERF-03, IMG-09/10).
//!
//! They judge the **emitted agent TOML** — the artifact the data plane
//! actually loads — rather than the compiler's internal structs, so a change
//! that left the structs right and the wire format wrong would still fail.

use crate::config::Appliance;

fn emitted(appliance: &Appliance) -> toml::Value {
    let text = super::compile(appliance).to_toml().expect("renders");
    toml::from_str(&text).expect("the emitted agent config parses back")
}

fn policy<'a>(cfg: &'a toml::Value, zone: &str) -> &'a toml::Value {
    cfg["policy"]
        .as_array()
        .expect("policies")
        .iter()
        .find(|p| p["name"].as_str() == Some(zone))
        .unwrap_or_else(|| panic!("no policy for zone {zone}"))
}

fn rules<'a>(cfg: &'a toml::Value, zone: &str) -> Vec<&'a toml::Value> {
    policy(cfg, zone)
        .get("port_rule")
        .and_then(toml::Value::as_array)
        .map(|a| a.iter().collect())
        .unwrap_or_default()
}

fn on_port<'a>(cfg: &'a toml::Value, zone: &str, port: i64) -> Vec<&'a toml::Value> {
    rules(cfg, zone)
        .into_iter()
        .filter(|r| r["port"].as_integer() == Some(port))
        .collect()
}

const BASE: &str = r#"
[system]
hostname = "fw"
[[interface]]
name = "eth0"
zone = "wan"
address = "198.51.100.2/24"
[[interface]]
name = "eth1"
zone = "lan"
address = "192.168.50.1/24"
[zone.wan]
default_action = "drop"
[zone.lan]
default_action = "accept"
"#;

fn with(extra: &str) -> String {
    format!("{BASE}{extra}")
}

// ---- DP-15: direction-less rules are ingress rules --------------------------

#[test]
fn dp15_a_directionless_rule_is_emitted_as_an_ingress_rule() {
    let a = Appliance::from_toml(&with(
        r#"
[[rule]]
name = "no-smtp-in"
from = "wan"
proto = "tcp"
port = 25
action = "drop"
[[rule]]
name = "out-dns"
from = "wan"
proto = "udp"
port = 53
action = "accept"
direction = "out"
"#,
    ))
    .unwrap();
    let cfg = emitted(&a);
    let smtp = on_port(&cfg, "wan", 25);
    assert_eq!(smtp.len(), 1, "{smtp:?}");
    // Absent means "both" to the agent, whose egress hook then applies the
    // rule under the zone a packet LEAVES through: LAN→WAN:25 was dropped.
    assert_eq!(
        smtp[0].get("direction").and_then(toml::Value::as_str),
        Some("in"),
        "a `from wan` rule must not also be enforced on traffic leaving through wan: {smtp:?}"
    );
    let dns = on_port(&cfg, "wan", 53);
    assert_eq!(
        dns[0].get("direction").and_then(toml::Value::as_str),
        Some("out"),
        "an explicit direction is kept"
    );
}

// ---- DP-16 / HA-01 / PROV-03: `to <local zone>` is this box, live ----------

const LOCAL: &str = r#"
[system]
hostname = "fw"
[[interface]]
name = "mgmt0"
zone = "mgmt"
address = "dhcp"
[[interface]]
name = "lan0"
zone = "lan"
address = "LANADDR"
[zone.mgmt]
default_action = "drop"
[zone.lan]
default_action = "drop"
[zone.firewall]
local = true
[[rule]]
name = "mgmt-ssh"
from = "mgmt"
to = "firewall"
proto = "tcp"
port = 22
action = "accept"
"#;

#[test]
fn dp16_a_local_destination_is_resolved_by_the_agent_not_from_static_addresses() {
    let a = Appliance::from_toml(&LOCAL.replace("LANADDR", "10.84.1.254/24")).unwrap();
    let cfg = emitted(&a);
    let ssh = on_port(&cfg, "mgmt", 22);
    assert_eq!(
        ssh.len(),
        1,
        "one symbolic rule, not one per static address: {ssh:?}"
    );
    let rule = ssh[0];
    // The DHCP management address is unknown at compile time; a static
    // resolution held only 10.84.1.254 and locked management out.
    assert_eq!(
        rule.get("dst-local").and_then(toml::Value::as_bool),
        Some(true),
        "{rule:?}"
    );
    assert!(
        rule.get("dst").is_none(),
        "no static address may stand in for the box: {rule:?}"
    );
}

#[test]
fn dp16_an_all_dhcp_box_never_widens_a_local_rule_to_any_destination() {
    let a = Appliance::from_toml(&LOCAL.replace("LANADDR", "dhcp")).unwrap();
    let cfg = emitted(&a);
    let rule = on_port(&cfg, "mgmt", 22)[0];
    // With no static address the old compiler emitted no `dst` at all, which
    // the agent reads as "to any destination": SSH to every routed host.
    assert_eq!(
        rule.get("dst-local").and_then(toml::Value::as_bool),
        Some(true),
        "{rule:?}"
    );
}

#[test]
fn dp16_ha_members_with_different_addresses_compile_the_same_local_rules() {
    // HA-02's root: the readiness digest covers the compiled policy, and the
    // per-member resolved addresses made it differ between members.
    let a = emitted(&Appliance::from_toml(&LOCAL.replace("LANADDR", "10.92.0.2/24")).unwrap());
    let b = emitted(&Appliance::from_toml(&LOCAL.replace("LANADDR", "10.92.0.3/24")).unwrap());
    assert_eq!(rules(&a, "mgmt"), rules(&b, "mgmt"));
}

// ---- DP-13: zone ids do not move when another zone appears ------------------

#[test]
fn dp13_adding_a_zone_keeps_every_other_zones_policy_id() {
    let before = Appliance::from_toml(BASE).unwrap();
    let after = Appliance::from_toml(&with(
        r#"
[[interface]]
name = "eth2"
zone = "aaa"
address = "172.16.0.1/24"
"#,
    ))
    .unwrap();
    let old = super::zone_policy_ids(&before);
    let new = super::zone_policy_ids(&after);
    // "aaa" sorts first; with rank-based ids it shifted lan and wan, and the
    // commit reset every connection on the box.
    for zone in ["lan", "wan"] {
        assert_eq!(old[zone], new[zone], "zone {zone} was renumbered");
    }
    for id in new.values() {
        assert!((1..=0x00FF_FFFF).contains(id), "id {id} outside 1..=2^24-1");
    }
    let distinct: std::collections::BTreeSet<_> = new.values().collect();
    assert_eq!(distinct.len(), new.len());
}

// ---- DP-30: one verdict per key, the same one trace reports ------------------

fn overlap(first_drop: bool) -> Appliance {
    let drop = r#"
[[rule]]
name = "block-85"
from = "wan"
proto = "tcp"
port = 85
action = "drop"
"#;
    let range = r#"
[[rule]]
name = "web-range"
from = "wan"
proto = "tcp"
port = "80-90"
action = "accept"
"#;
    let body = if first_drop {
        format!("{drop}{range}")
    } else {
        format!("{range}{drop}")
    };
    Appliance::from_toml(&with(&body)).unwrap()
}

#[test]
fn dp30_the_stricter_of_two_rules_on_one_key_is_the_only_one_emitted() {
    for first_drop in [true, false] {
        let a = overlap(first_drop);
        let cfg = emitted(&a);
        let p85 = on_port(&cfg, "wan", 85);
        assert_eq!(p85.len(), 1, "the agent keeps the last of two: {p85:?}");
        assert_eq!(p85[0]["action"].as_str(), Some("drop"), "{p85:?}");
        // …and `trace` says the same thing the data plane will do.
        let t = crate::trace::trace(
            &a,
            &crate::trace::Query {
                in_interface: "eth0".into(),
                proto: "tcp".into(),
                src: "203.0.113.9".parse().unwrap(),
                dst: "198.51.100.2".parse().unwrap(),
                port: 85,
                src_mac: None,
                icmp_type: None,
            },
        )
        .unwrap();
        assert_eq!(t.verdict, "drop");
        assert_eq!(t.decided_by, "block-85");
    }
}

/// An ICMPv6 rule can only match IPv6, so `family = "ipv6"` on it is no scope
/// at all: an `in` echo-reply drop and an `out` one that also says
/// `family ipv6` are the two halves of one entry, not a conflict the first
/// rule wins (which left outgoing echo replies unblocked; checks.icmptype).
#[test]
fn dp30_an_icmp_family_scope_does_not_split_an_in_out_pair() {
    let a = Appliance::from_toml(&with(
        r#"
[[rule]]
name = "no-ping6"
from = "wan"
proto = "icmpv6"
direction = "in"
icmp-type = "echo-reply"
action = "drop"
[[rule]]
name = "no-replies6"
from = "wan"
proto = "icmpv6"
family = "ipv6"
direction = "out"
icmp-type = "echo-reply"
action = "drop"
"#,
    ))
    .unwrap();
    let cfg = emitted(&a);
    let typed: Vec<_> = rules(&cfg, "wan")
        .into_iter()
        .filter(|r| r["proto"].as_str() == Some("icmpv6"))
        .collect();
    assert_eq!(typed.len(), 1, "{typed:?}");
    assert!(
        typed[0].get("direction").is_none(),
        "both directions: {typed:?}"
    );
    assert_eq!(typed[0]["action"].as_str(), Some("drop"), "{typed:?}");
}

// ---- DP-18: forwards and services carry only protocols with ports -----------

#[test]
fn dp18_tcp_udp_forward_and_service_compile_to_one_entry_per_protocol() {
    let a = Appliance::from_toml(&with(
        r#"
[[nat.destination]]
name = "game"
zone = "wan"
proto = "tcp_udp"
port = 27015
to = "192.168.50.10:27015"
[[load-balancer]]
name = "dns"
zone = "wan"
vip = "198.51.100.53"
proto = "tcp_udp"
port = 53
backends = ["192.168.50.11"]
"#,
    ))
    .unwrap();
    let text = super::compile(&a).to_toml().unwrap();
    assert!(
        !text.contains("tcp_udp"),
        "the agent has no protocol named tcp_udp:\n{text}"
    );
    let cfg: toml::Value = toml::from_str(&text).unwrap();
    let protos = |table: &str| -> Vec<String> {
        let mut out: Vec<String> = cfg[table]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["proto"].as_str().unwrap().to_string())
            .collect();
        out.sort();
        out
    };
    assert_eq!(protos("port_forward"), ["tcp", "udp"]);
    assert_eq!(protos("service"), ["tcp", "udp"]);
}

#[test]
fn dp18_a_forward_or_service_without_ports_is_refused() {
    for proto in ["icmp", "esp", "gre"] {
        let fwd = with(&format!(
            "[[nat.destination]]\nname = \"x\"\nzone = \"wan\"\nproto = \"{proto}\"\nport = 80\nto = \"192.168.50.10:80\"\n"
        ));
        assert!(
            Appliance::from_toml(&fwd).is_err(),
            "forward on {proto} accepted"
        );
        let lb = with(&format!(
            "[[load-balancer]]\nname = \"x\"\nzone = \"wan\"\nvip = \"198.51.100.9\"\nproto = \"{proto}\"\nport = 80\nbackends = [\"192.168.50.11\"]\n"
        ));
        assert!(
            Appliance::from_toml(&lb).is_err(),
            "service on {proto} accepted"
        );
    }
}

// ---- DP-14: a broad accept cannot carry what it would ignore -----------------

#[test]
fn dp14_a_broad_accept_with_a_qualifier_is_refused() {
    let base = r#"
[system]
hostname = "fw"
[[interface]]
name = "eth1"
zone = "lan"
address = "192.168.50.1/24"
[[interface]]
name = "eth0"
zone = "wan"
address = "198.51.100.2/24"
[firewall]
default_action = "drop"
[firewall.group.address]
admins = ["192.168.50.5"]
"#;
    for qualifier in [
        "source = \"192.168.50.5\"",
        "destination = \"198.51.100.0/24\"",
        "source-group = \"admins\"",
        "family = \"ipv6\"",
        "direction = \"out\"",
        "log = true",
    ] {
        let text = format!(
            "{base}[[rule]]\nname = \"admin\"\nfrom = \"lan\"\naction = \"accept\"\n{qualifier}\n"
        );
        let err = Appliance::from_toml(&text)
            .err()
            .unwrap_or_else(|| panic!("`{qualifier}` on a broad accept was accepted"));
        assert!(format!("{err:#}").contains("proto"), "{err:#}");
    }
    // The bare posture rule is still the way to let a zone initiate.
    let plain =
        format!("{base}[[rule]]\nname = \"lan-out\"\nfrom = \"lan\"\naction = \"accept\"\n");
    assert!(Appliance::from_toml(&plain).is_ok());
}

#[test]
fn dp14_a_broad_accept_overridden_by_an_explicit_zone_default_is_refused() {
    let text = with(
        r#"
[[rule]]
name = "wan-open"
from = "wan"
action = "accept"
"#,
    );
    let err = Appliance::from_toml(&text).expect_err("an inert broad accept was accepted");
    assert!(format!("{err:#}").contains("no effect"), "{err:#}");
}

// ---- DP-17 / DP-29 / PERF-03: the compiled policy has to fit -----------------

#[test]
fn dp29_more_rate_limited_entries_than_the_agent_has_slots_are_refused() {
    let text = with(
        r#"
[[rule]]
name = "lim"
from = "wan"
proto = "tcp"
port = "1000-1199"
action = "accept"
limit = 10
"#,
    );
    let err = super::check_capacity(&Appliance::from_toml(&text).unwrap())
        .expect_err("200 limited entries > 127 slots");
    let msg = format!("{err:#}");
    assert!(msg.contains("RULE_LIMITS") && msg.contains("127"), "{msg}");
}

#[test]
fn dp17_rules_beyond_a_trie_are_refused_with_the_map_and_its_limit() {
    let mut text = with("");
    for i in 0..9 {
        let lo = 1000 + i * 1000;
        text.push_str(&format!(
            "[[rule]]\nname = \"r{i}\"\nfrom = \"wan\"\nproto = \"tcp\"\nport = \"{lo}-{}\"\naction = \"accept\"\n",
            lo + 999
        ));
    }
    let err = super::check_capacity(&Appliance::from_toml(&text).unwrap())
        .expect_err("9000 entries > 8192");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("PORT_RULES") && msg.contains("9000") && msg.contains("8192"),
        "{msg}"
    );
}

/// An address-less rule is one entry in EACH source trie on the agent (fabric
/// DP-11), so 5,000 of them fit both tries and 9,000 overflow both; a family
/// scope keeps a rule out of the other family's trie.
#[test]
fn dp17_an_address_less_rule_counts_in_both_source_tries() {
    let rules = |n: usize, family: &str| {
        let mut text = with("");
        for i in 0..n.div_ceil(1000) {
            let lo = 1000 + i * 1000;
            let hi = lo + (n - i * 1000).min(1000) - 1;
            text.push_str(&format!(
                "[[rule]]\nname = \"r{i}\"\nfrom = \"wan\"\nproto = \"tcp\"\nport = \"{lo}-{hi}\"\naction = \"accept\"\n{family}"
            ));
        }
        text
    };
    let msg = format!(
        "{:#}",
        super::check_capacity(&Appliance::from_toml(&rules(9000, "")).unwrap())
            .expect_err("9000 address-less entries overflow both source tries")
    );
    assert!(
        msg.contains("PORT_RULES (") && msg.contains("PORT_RULES6 ("),
        "{msg}"
    );
    let v4 = format!(
        "{:#}",
        super::check_capacity(&Appliance::from_toml(&rules(9000, "family = \"ipv4\"\n")).unwrap())
            .expect_err("9000 IPv4-only entries overflow the IPv4 source trie")
    );
    assert!(
        v4.contains("PORT_RULES (") && !v4.contains("PORT_RULES6"),
        "{v4}"
    );
    assert!(super::check_capacity(&Appliance::from_toml(&rules(5000, "")).unwrap()).is_ok());
}

#[test]
fn perf03_a_global_blocklist_is_counted_once_per_zone_policy() {
    // 70,000 × (2 zones + the default policy) = 210,000 fits; a third zone
    // makes it 280,000, over the 262,144 the agent holds per family.
    let list: Vec<String> = (0..70_000u32)
        .map(|i| format!("\"10.{}.{}.0/24\"", (i >> 8) & 0xff, i & 0xff))
        .collect();
    let blocklist = format!("[firewall]\nblocklist = [{}]\n", list.join(","));
    let two = format!("{}{blocklist}", BASE);
    assert!(super::check_capacity(&Appliance::from_toml(&two).unwrap()).is_ok());
    let three = format!(
        "{BASE}[[interface]]\nname = \"eth2\"\nzone = \"dmz\"\naddress = \"172.16.0.1/24\"\n{blocklist}"
    );
    let err = super::check_capacity(&Appliance::from_toml(&three).unwrap())
        .expect_err("280,000 entries > 262,144");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("BLOCKLIST (IPv4)") && msg.contains("280000"),
        "{msg}"
    );
}

// ---- advisories --------------------------------------------------------------

fn warnings(text: &str) -> String {
    Appliance::from_toml(text).unwrap().warnings().join("\n")
}

#[test]
fn img09_a_console_bound_to_loopback_only_says_so() {
    let w = warnings(&with("[services.web]\nenable = true\n"));
    assert!(w.contains("listen-address"), "{w}");
}

#[test]
fn dp39_hairpin_on_a_dhcp_uplink_says_it_reflects_nothing() {
    let text = r#"
[system]
hostname = "fw"
[[interface]]
name = "eth0"
zone = "wan"
address = "dhcp"
[[interface]]
name = "eth1"
zone = "lan"
address = "192.168.50.1/24"
[[nat.destination]]
name = "web"
zone = "wan"
proto = "tcp"
port = 443
to = "192.168.50.10:443"
hairpin = true
"#;
    let w = warnings(text);
    assert!(w.contains("hairpin"), "{w}");
}

// ---- DP-31: the SYN proxy is scoped to the zones that admit the port --------

fn synproxy(cfg: &toml::Value) -> Vec<&toml::Value> {
    cfg.get("synproxy")
        .and_then(toml::Value::as_array)
        .map(|a| a.iter().collect())
        .unwrap_or_default()
}

fn policy_id(cfg: &toml::Value, zone: &str) -> i64 {
    policy(cfg, zone)["id"].as_integer().expect("policy id")
}

const WEB_FORWARD: &str = r#"
[[nat.destination]]
name = "web"
zone = "wan"
proto = "tcp"
port = 443
to = "192.168.50.10:443"
"#;

#[test]
fn dp31_a_forwarded_port_is_proxied_for_the_forwarding_zone_only() {
    let text = with(&format!(
        "{WEB_FORWARD}[[firewall.syn-protect]]\nport = 443\n"
    ));
    let cfg = emitted(&Appliance::from_toml(&text).unwrap());
    let entries = synproxy(&cfg);
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0]["port"].as_integer(), Some(443));
    assert_eq!(
        entries[0].get("policy").and_then(toml::Value::as_integer),
        Some(policy_id(&cfg, "wan")),
        "{cfg:?}"
    );
    let w = warnings(&text);
    assert!(w.contains("arriving on zone wan"), "{w}");
}

#[test]
fn dp31_a_port_opened_by_a_rule_is_proxied_for_that_zone() {
    let text = with(
        r#"
[[rule]]
name = "web-in"
from = "wan"
proto = "tcp"
port = 443
action = "accept"
[[firewall.syn-protect]]
port = 443
mss = 1400
"#,
    );
    let cfg = emitted(&Appliance::from_toml(&text).unwrap());
    let entries = synproxy(&cfg);
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(
        entries[0].get("policy").and_then(toml::Value::as_integer),
        Some(policy_id(&cfg, "wan")),
        "{cfg:?}"
    );
    assert_eq!(entries[0]["mss"].as_integer(), Some(1400));
}

/// A LAN client dialling the public address through a hairpin is an inside
/// client: its zone's reflection entry must not make the proxy answer every
/// LAN SYN to that port.
#[test]
fn dp31_a_hairpin_reflection_does_not_proxy_the_inside() {
    let text = with(&format!(
        "{WEB_FORWARD}hairpin = true\n[[firewall.syn-protect]]\nport = 443\n"
    ));
    let cfg = emitted(&Appliance::from_toml(&text).unwrap());
    let lan = policy_id(&cfg, "lan");
    let entries = synproxy(&cfg);
    assert!(!entries.is_empty());
    assert!(
        entries
            .iter()
            .all(|e| e.get("policy").and_then(toml::Value::as_integer) != Some(lan)),
        "{entries:?}"
    );
}

/// Nothing admits the port explicitly (a default-accept zone serves it): the
/// proxy stays on for every zone rather than silently protecting nothing, and
/// says what that costs.
#[test]
fn dp31_a_port_no_zone_admits_is_proxied_everywhere_and_says_so() {
    let text = with("[[firewall.syn-protect]]\nport = 443\n");
    let cfg = emitted(&Appliance::from_toml(&text).unwrap());
    let entries = synproxy(&cfg);
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert!(entries[0].get("policy").is_none(), "{entries:?}");
    let w = warnings(&text);
    assert!(w.contains("syn-protect") && w.contains("any zone"), "{w}");
}

// ---- DP-35: the SYN proxy is IPv4 only, and says so where it matters --------

fn with_v6_wan(extra: &str) -> String {
    with(extra).replace(
        "address = \"198.51.100.2/24\"\n",
        "address = \"198.51.100.2/24\"\naddress6 = \"2001:db8:51::2/64\"\n",
    )
}

const WEB_RULE: &str = r#"
[[rule]]
name = "web-in"
from = "wan"
proto = "tcp"
port = 443
action = "accept"
[[firewall.syn-protect]]
port = 443
"#;

#[test]
fn dp35_a_protected_port_reachable_over_ipv6_says_ipv6_is_not_proxied() {
    let text = with_v6_wan(WEB_RULE);
    assert!(
        text.contains("address6"),
        "the fixture gained its IPv6 address"
    );
    let w = warnings(&text);
    assert!(
        w.contains("syn-protect 443: TCP 443 is reachable over IPv6 on zone wan")
            && w.contains("IPv6 SYNs to it are not proxied"),
        "{w}"
    );
}

#[test]
fn dp35_no_ipv6_note_where_the_port_cannot_be_reached_over_ipv6() {
    // The zone has no IPv6 address.
    let w = warnings(&with(WEB_RULE));
    assert!(w.contains("syn-protect 443"), "{w}");
    assert!(!w.contains("over IPv6"), "{w}");
    // The zone has one, but the only rule admitting 443 is IPv4-only.
    let v4_only = WEB_RULE.replace(
        "action = \"accept\"\n",
        "action = \"accept\"\nfamily = \"ipv4\"\n",
    );
    let w = warnings(&with_v6_wan(&v4_only));
    assert!(!w.contains("over IPv6"), "{w}");
}

#[test]
fn dp35_a_port_proxied_everywhere_names_the_ipv6_zones() {
    let w = warnings(&with_v6_wan("[[firewall.syn-protect]]\nport = 443\n"));
    assert!(w.contains("reachable over IPv6 on zone wan"), "{w}");
}

// ---- DP-15: blocklists and GeoIP name sources only -------------------------

#[test]
fn dp15_a_zone_blocklist_is_emitted_as_source_only() {
    let text = with("").replace(
        "[zone.wan]\ndefault_action = \"drop\"\n",
        "[zone.wan]\ndefault_action = \"drop\"\nblocklist = [\"203.0.113.0/24\"]\n",
    );
    assert!(
        text.contains("blocklist"),
        "the fixture gained its blocklist"
    );
    let cfg = emitted(&Appliance::from_toml(&text).unwrap());
    let wan = policy(&cfg, "wan");
    assert_eq!(
        wan.get("blocklist_ingress_only")
            .and_then(toml::Value::as_bool),
        Some(true),
        "{wan:?}"
    );
    // A policy without a blocklist has nothing to scope and carries no key, so
    // an unchanged configuration's emitted policy is unchanged.
    assert!(policy(&cfg, "lan").get("blocklist_ingress_only").is_none());
}

#[test]
fn dp15_the_global_blocklist_is_source_only_for_every_policy() {
    let text = format!("[firewall]\nblocklist = [\"203.0.113.7\"]\n{}", with(""));
    let cfg = emitted(&Appliance::from_toml(&text).unwrap());
    assert_eq!(
        cfg.get("blocklist_ingress_only")
            .and_then(toml::Value::as_bool),
        Some(true),
        "{cfg:?}"
    );
    for zone in ["wan", "lan"] {
        assert_eq!(
            policy(&cfg, zone)
                .get("blocklist_ingress_only")
                .and_then(toml::Value::as_bool),
            Some(true),
            "{zone}"
        );
    }
}

#[test]
fn img10_to_an_undeclared_firewall_zone_explains_local() {
    let text = with(
        "[[rule]]\nname = \"mgmt-ssh\"\nfrom = \"lan\"\nto = \"firewall\"\nproto = \"tcp\"\nport = 22\naction = \"accept\"\n",
    );
    let err = Appliance::from_toml(&text).expect_err("no such zone");
    assert!(format!("{err:#}").contains("local true"), "{err:#}");
}

#[test]
fn dp43_trace_names_the_whole_port_range_it_passed_over() {
    let a = Appliance::from_toml(&with(
        "[[rule]]\nname = \"web-range\"\nfrom = \"wan\"\nproto = \"tcp\"\nport = \"80-90\"\naction = \"accept\"\n",
    ))
    .unwrap();
    let t = crate::trace::trace(
        &a,
        &crate::trace::Query {
            in_interface: "eth0".into(),
            proto: "tcp".into(),
            src: "203.0.113.9".parse().unwrap(),
            dst: "198.51.100.2".parse().unwrap(),
            port: 22,
            src_mac: None,
            icmp_type: None,
        },
    )
    .unwrap();
    let rendered = t.render();
    assert!(rendered.contains("80-90"), "{rendered}");
}

// ---- DP-15: every rule shape, its emitted direction ---------------------------

/// The direction each shape of operator rule is emitted with. A shape that
/// silently kept "both" would still be enforced on traffic leaving through
/// its `from` zone; one that turned `out` into `in` would stop guarding what
/// the box sends.
#[test]
fn dp15_every_rule_shape_has_the_direction_it_was_written_with() {
    let text = with(
        r#"
[[interface]]
name = "eth2"
zone = "dmz"
address = "172.16.0.1/24"
[zone.firewall]
local = true
[firewall.group.address]
peers = ["203.0.113.0/24"]
[firewall.group.interface]
uplinks = ["eth0"]
[firewall.group.mac]
printers = ["aa:bb:cc:dd:ee:ff"]
[[load-balancer]]
name = "vip"
zone = "wan"
vip = "198.51.100.80"
proto = "tcp"
port = 8443
backends = ["172.16.0.10"]
[[rule]]
name = "plain"
from = "wan"
proto = "tcp"
port = 1001
action = "drop"
[[rule]]
name = "source"
from = "wan"
source = "203.0.113.9"
proto = "tcp"
port = 1002
action = "drop"
[[rule]]
name = "destination"
from = "wan"
destination = "172.16.0.10"
proto = "tcp"
port = 1003
action = "accept"
[[rule]]
name = "to-zone"
from = "wan"
to = "dmz"
proto = "tcp"
port = 1004
action = "accept"
[[rule]]
name = "to-local"
from = "wan"
to = "firewall"
proto = "tcp"
port = 1005
action = "accept"
[[rule]]
name = "groups"
from = "wan"
source-group = "peers"
interface-group = "uplinks"
proto = "udp"
port = 1006
action = "accept"
[[rule]]
name = "family"
from = "wan"
family = "ipv6"
proto = "tcp"
port = 1007
action = "drop"
[[rule]]
name = "typed"
from = "wan"
proto = "icmp"
icmp-type = "echo-request"
action = "accept"
[[rule]]
name = "both-protos"
from = "wan"
proto = "tcp_udp"
port = 1008
action = "accept"
[[rule]]
name = "portless"
from = "wan"
proto = "gre"
action = "accept"
[[rule]]
name = "limited"
from = "wan"
proto = "tcp"
port = 1009
action = "accept"
limit = 5
[[rule]]
name = "explicit-in"
from = "wan"
proto = "tcp"
port = 1010
action = "drop"
direction = "in"
[[rule]]
name = "explicit-out"
from = "wan"
proto = "tcp"
port = 1011
action = "drop"
direction = "out"
[[rule]]
name = "explicit-both"
from = "wan"
proto = "tcp"
port = 1012
action = "drop"
direction = "both"
[[rule]]
name = "half-in"
from = "wan"
proto = "tcp"
port = 1013
action = "drop"
direction = "in"
[[rule]]
name = "half-out"
from = "wan"
proto = "tcp"
port = 1013
action = "drop"
direction = "out"
[[rule]]
name = "no-printers"
from = "lan"
source-mac-group = "printers"
action = "drop"
"#,
    );
    let a = Appliance::from_toml(&text).unwrap();
    let cfg = emitted(&a);
    let all: Vec<&toml::Value> = ["wan", "lan", "dmz"]
        .iter()
        .flat_map(|z| rules(&cfg, z))
        .collect();
    let directions = |name: &str| -> Vec<Option<String>> {
        let found: Vec<Option<String>> = all
            .iter()
            .filter(|r| r["name"].as_str() == Some(name))
            .map(|r| {
                r.get("direction")
                    .and_then(toml::Value::as_str)
                    .map(str::to_string)
            })
            .collect();
        assert!(!found.is_empty(), "rule {name} was not emitted");
        found
    };
    let ingress = Some("in".to_string());
    for name in [
        "plain",
        "source",
        "destination",
        "to-zone",
        "to-local",
        "groups",
        "family",
        "typed",
        "both-protos",
        "portless",
        "limited",
        "explicit-in",
        "(load-balancer vip)",
    ] {
        assert!(
            directions(name).iter().all(|d| *d == ingress),
            "{name}: {:?}",
            directions(name)
        );
    }
    assert_eq!(directions("both-protos").len(), 2);
    assert_eq!(directions("explicit-out"), [Some("out".to_string())]);
    // `both` is the agent's default: no direction on the wire.
    assert_eq!(directions("explicit-both"), [None]);
    // An `in` and an `out` rule with one verdict are one entry for both.
    let halves: Vec<_> = on_port(&cfg, "wan", 1013);
    assert_eq!(halves.len(), 1, "{halves:?}");
    assert!(halves[0].get("direction").is_none(), "{halves:?}");
    // A MAC verdict is consulted once, from the Ethernet header.
    assert_eq!(directions("no-printers"), [None]);
}

/// The capacity refusal must not run inside `validate`: the boot-time load
/// runs `validate`, and a configuration that no longer fits has to reach the
/// boot fallback instead of failing before it (audit P0 class).
#[test]
fn dp17_capacity_is_not_part_of_validate_so_boot_can_fall_back() {
    let mut text = with("");
    for i in 0..9 {
        let lo = 1000 + i * 1000;
        text.push_str(&format!(
            "[[rule]]\nname = \"r{i}\"\nfrom = \"wan\"\nproto = \"tcp\"\nport = \"{lo}-{}\"\naction = \"accept\"\n",
            lo + 999
        ));
    }
    let path = std::env::temp_dir().join(format!("sentinel-dp17-boot-{}.toml", std::process::id()));
    std::fs::write(&path, &text).unwrap();
    let booted = Appliance::load_lenient(&path);
    let _ = std::fs::remove_file(&path);
    let booted = booted.expect("an over-capacity saved config still loads for the boot fallback");
    assert!(
        super::check_capacity(&booted).is_err(),
        "…and the explicit check still refuses it"
    );
}
