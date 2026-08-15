//! A walk of the entire `set` grammar, driven through a real session.
//!
//! Every other test in this crate picks a feature and proves that feature. This
//! one asks the opposite question: is there anywhere in the configuration tree
//! that the completion offers a setting the session then refuses, silently
//! drops, cannot save, or cannot delete? A path like that is invisible to
//! feature tests — nobody writes a test for a setting they never knew existed —
//! and it is exactly what an operator finds by typing `?` and following it.
//!
//! The tree is not a list kept beside the grammar; it *is* the grammar. The walk
//! asks [`dyn_candidates`] for the children of a path, the same function Tab
//! and `?` ask, so a setting that gains a field gains a test the same day.
//!
//! For every leaf the walk finds a value the CLI accepts and puts the line
//! through four gates:
//!
//! 1. **accepted** — some value is accepted at all;
//! 2. **shown** — it then appears in `show configuration`, so it was stored
//!    rather than parsed and thrown away;
//! 3. **persisted** — it survives a commit, a save and a re-load;
//! 4. **deletable** — the matching `delete` removes it again.
//!
//! A commit that is refused is recorded separately: a setting may legitimately
//! depend on another one, and the message says which.

#![cfg(test)]

use std::collections::BTreeSet;
use std::io::Write;

use crate::repl::{DynNames, dyn_candidates};
use crate::session::Session;

/// The names the completion knows about while walking. Seeded to match
/// [`BASE`], so a position that references an existing object (a zone, a
/// prefix-list) offers a name that really is there — a walk against an empty
/// box would test every reference against a dangling one.
fn seeded_names() -> DynNames {
    DynNames {
        interfaces: vec!["eth0".into()],
        rules: vec!["r1".into()],
        zones: vec!["lan".into()],
        load_balancers: vec!["lb1".into()],
        syslog_targets: vec!["10.9.9.9".into()],
        nat_source: vec!["s1".into()],
        nat_destination: vec!["d1".into()],
        nat_npt66: vec!["n1".into()],
        address_groups: vec!["ag1".into()],
        port_groups: vec!["pg1".into()],
        domain_groups: vec!["dg1".into()],
        filters: vec!["rm1".into()],
        vrfs: vec!["blue".into()],
        ipsec: vec!["tun1".into()],
        pki_cas: vec!["ca1".into()],
        pki_certificates: vec!["crt1".into()],
        wireguard: vec!["wg0".into()],
        reverse_proxy: vec!["fe1".into()],
        broadcast_relay: vec!["br1".into()],
        prefix_lists: vec!["pl1".into()],
    }
}

/// The configuration the walk starts from: one of every object the grammar
/// lets other settings point at. Without it a third of the tree fails for the
/// one uninteresting reason that its target does not exist.
const BASE: &[&str] = &[
    "set system hostname walker",
    "set interface eth0 zone lan",
    "set interface eth0 address 10.0.0.1/24",
    "set interface eth1 zone wan",
    "set interface eth1 address 198.51.100.2/24",
    "set firewall zone lan default-action accept",
    "set firewall zone wan default-action drop",
    "set firewall rule r1 from lan",
    "set firewall rule r1 action accept",
    "set firewall group address-group ag1 address 10.0.0.0/8",
    "set firewall group port-group pg1 port 443",
    "set firewall group domain-group dg1 domain example.com",
    "set policy prefix-list pl1 rule 10 prefix 10.0.0.0/8",
    "set policy route-map rm1 rule 10 action permit",
    "set protocols vrf blue table 100",
    "set pki ca ca1 common-name test-ca",
    "set pki certificate crt1 ca ca1",
    "set pki certificate crt1 common-name host.example.com",
    "set nat source s1 zone wan",
    "set nat destination d1 zone wan",
    "set nat destination d1 proto tcp",
    "set nat destination d1 port 443",
    "set nat destination d1 to 10.0.0.9:443",
];

/// Settings that only mean something beside another setting. The model is
/// right to refuse them on their own; the walk supplies the company they need
/// so the setting itself gets tested rather than its precondition.
///
/// Keyed on a path prefix; every matching entry's lines are applied, in order,
/// on top of [`BASE`].
const CONTEXT: &[(&str, &[&str])] = &[
    (
        "protocols bgp",
        &[
            "set protocols bgp local-as 65001",
            "set protocols bgp router-id 10.0.0.1",
        ],
    ),
    (
        "evpn",
        &[
            "set protocols bgp local-as 65001",
            "set protocols bgp neighbor 10.0.0.2 remote-as 65001",
            "set protocols bgp neighbor 10.0.0.2 evpn true",
            "set evpn vtep-ip 10.0.0.1",
            "set evpn underlay-interface eth1",
        ],
    ),
    (
        "interface eth0 qos",
        &["set interface eth0 qos discipline cake"],
    ),
    ("interface eth0 bond", &["set interface eth0 type bond"]),
    ("interface eth0 member", &["set interface eth0 type bond"]),
    (
        "interface eth0 bond-mode",
        &["set interface eth0 type bond"],
    ),
    ("interface eth0 bridge", &["set interface eth0 type bridge"]),
    (
        "interface eth0 vlan-aware",
        &["set interface eth0 type bridge"],
    ),
    (
        "interface eth0 wireless",
        &[
            "set interface eth0 type wireless",
            "set interface eth0 wireless mode access-point",
            "set interface eth0 wireless ssid velstra",
            "set interface eth0 wireless wpa passphrase velstra-secret",
            "set interface eth0 wireless country DE",
        ],
    ),
    (
        "interface eth0 wwan",
        &[
            "set interface eth0 type wwan",
            "set interface eth0 wwan apn internet",
            "delete interface eth0 address",
            "set interface eth0 address dhcp",
        ],
    ),
    (
        "interface eth0 dhcp ",
        &[
            "delete interface eth0 address",
            "set interface eth0 address dhcp",
        ],
    ),
    (
        "interface eth0 dhcpv6",
        &["set interface eth0 address6 fd00:a::1/64"],
    ),
    (
        "interface eth0 macsec",
        &[
            "set interface eth0 type macsec",
            "set interface eth0 parent eth1",
            "set interface eth1 mac 02:00:00:00:00:11",
            "set interface eth0 macsec-key 0123456789abcdef0123456789abcdef",
            "set interface eth0 macsec-peer 02:00:00:00:00:22",
        ],
    ),
    (
        "firewall rule r1 icmp-type",
        &["set firewall rule r1 proto icmp"],
    ),
    (
        "vpn ipsec tun1",
        &[
            "set vpn ipsec tun1 local 198.51.100.2",
            "set vpn ipsec tun1 remote 198.51.100.9",
            "set vpn ipsec tun1 psk shared-secret",
            "set vpn ipsec tun1 local-subnet 10.0.0.0/24",
            "set vpn ipsec tun1 remote-subnet 10.9.0.0/24",
        ],
    ),
    (
        "vpn openconnect",
        &[
            "set vpn openconnect pool 10.99.0.0/24",
            "set vpn openconnect certificate crt1",
            "set vpn openconnect user alice password s3cret",
        ],
    ),
    (
        "vpn wireguard wg0",
        &[
            "set interface wg0 type wireguard",
            "set interface wg0 zone lan",
            "set vpn wireguard wg0 private-key generate",
        ],
    ),
    (
        "protocols vrrp t1",
        &[
            "set protocols vrrp t1 interface eth0",
            "set protocols vrrp t1 vrid 10",
            "set protocols vrrp t1 virtual-address 10.0.0.250",
        ],
    ),
    (
        "load-balancer lb1",
        &[
            "set load-balancer lb1 zone lan",
            "set load-balancer lb1 vip 10.0.0.200",
            "set load-balancer lb1 proto tcp",
            "set load-balancer lb1 port 80",
            "set load-balancer lb1 backend 10.0.0.11:80",
        ],
    ),
    (
        "services dyndns",
        &["set services dyndns hostname h.example.com"],
    ),
    (
        "services reverse-proxy fe1",
        &["set services reverse-proxy fe1 backends 10.0.0.11:80"],
    ),
    (
        "services alerts mail",
        &[
            "set services alerts mail to ops@example.com",
            "set services alerts mail relay 10.0.0.25",
        ],
    ),
    (
        "nat nat64",
        &[
            "set nat nat64 prefix 64:ff9b::/96",
            "set nat nat64 pool 10.64.0.0/24",
        ],
    ),
    ("services portal", &["set services portal zone lan"]),
    (
        "services port-mapping",
        &[
            "set services port-mapping zone lan",
            "set services port-mapping wan-zone wan",
        ],
    ),
    (
        "services broadcast-relay br1",
        &[
            "set services broadcast-relay br1 interface eth0",
            "set services broadcast-relay br1 interface eth1",
            "set services broadcast-relay br1 port 6000",
        ],
    ),
    (
        "protocols bgp neighbor",
        &[
            "set protocols bgp neighbor 10.20.30.40 remote-as 65002",
            "set protocols bgp neighbor fd00:20::1 remote-as 65002",
        ],
    ),
    ("policy route", &["set policy route x1 table 100"]),
    ("multiwan policy", &["set multiwan policy x1 uplink eth0"]),
    ("evpn instance", &["set evpn instance x1 vni 100"]),
    (
        "evpn ip-vrf",
        &[
            "set protocols vrf x1 table 200",
            "set evpn ip-vrf x1 l3-vni 200",
        ],
    ),
    (
        "protocols static",
        &[
            "set protocols static 10.20.30.0/24 via 10.0.0.9",
            "set protocols static fd00:20::/64 via fd00:a::9",
        ],
    ),
    ("services snmp", &["set services snmp community public"]),
    ("pki acme", &["set pki acme email ops@example.com"]),
    (
        "services dhcp-relay",
        &[
            "set services dhcp-relay interface eth0",
            "set services dhcp-relay interface eth1",
            "set services dhcp-relay server 10.0.0.53",
        ],
    ),
    (
        "multiwan",
        &[
            "set multiwan uplink eth0 priority 1",
            "set multiwan uplink eth1 priority 2",
        ],
    ),
    (
        "nat npt66 n1",
        &[
            "set nat npt66 n1 interface eth1",
            "set nat npt66 n1 internal fd00:1::/48",
            "set nat npt66 n1 external 2001:db8:1::/48",
        ],
    ),
];

/// A leaf of the configuration tree: the path, and the type the completion
/// declares for its value — `None` where the completion declares nothing, which
/// is a finding in its own right.
struct Leaf {
    path: Vec<String>,
    hint: Option<String>,
}

fn is_ph(k: &str) -> bool {
    k.starts_with('<')
}

/// A value for a `<…>` placeholder — the type the completion itself declares.
fn from_hint(ph: &str) -> &'static str {
    match ph {
        "<A.B.C.D>" => "10.20.30.40",
        "<A.B.C.D/M>" => "10.20.30.0/24",
        "<X:X::X:X>" => "fd00:20::1",
        "<X:X::X:X/M>" => "fd00:20::/64",
        "<A.B.C.D:port>" => "10.20.30.40:8080",
        "<1-65535>" | "<port|lo-hi>" => "8080",
        "<1-4294967295>" => "65001",
        "<0-4294967295>" => "100",
        "<1-4094>" => "100",
        "<id,…>" => "100,200",
        "<0-255>" => "10",
        "<0-128>" => "64",
        "<68-9216>" => "1400",
        "<seconds>" | "<number>" | "<packets>" | "<seq>" => "10",
        "<12h|30m|3600>" => "30m",
        "<asn:value>" => "65001:100",
        "<CC>" => "DE",
        "<email>" => "ops@example.com",
        "<fqdn>" => "host.example.com",
        "<url>" => "https://example.com/hook",
        "<host:port>" => "10.20.30.40:514",
        "<key>" => "sample-secret",
        "<text>" => "sample",
        "<name>" => "t1",
        "<xx:xx:xx:xx:xx:xx>" => "02:00:00:00:00:01",
        "<pubkey>" => "d0JCPLcS8bXlwuA6xdaHrqLdEeQz9M+xUsHhVJnEbn0=",
        "<pem|file:path>" => "file:/tmp/walker.pem",
        _ => "sample",
    }
}

/// Values tried, in order, at a position the completion says nothing about.
/// The first the session accepts is the one the line is built with — so the
/// walk never has to know a field's type, only that *some* value works.
const PROBE: &[&str] = &[
    "10",
    "true",
    "10.20.30.40",
    "10.20.30.0/24",
    "fd00:20::1",
    "fd00:20::/64",
    "02:00:00:00:00:01",
    "08:00",
    "mon",
    "eth0",
    "lan",
    "permit",
    "tcp",
    "example.com",
    "DE",
    "1",
    "2",
    "info",
    "local0",
    "DNS:host.example.com",
    "wpa2",
    "1000",
    "https://feed.example.com/list",
    "d0JCPLcS8bXlwuA6xdaHrqLdEeQz9M+xUsHhVJnEbn0=",
    // Positions whose value is more than one word. The completion says nothing
    // at any of them, which is why they have to be spelled out here.
    "h.example.com 10.0.0.5",
    "x.example.com hello",
    "alert tcp any any -> any any (msg:\"t\"; sid:1000001; rev:1;)",
    "sample",
];

/// Every leaf the grammar can reach.
fn walk_leaves() -> Vec<Leaf> {
    let names = seeded_names();
    let mut out: Vec<Leaf> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    walk(&mut vec!["set".to_string()], &names, &mut out, &mut seen);
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out.dedup_by(|a, b| a.path == b.path);
    out
}

/// A token to descend an unhinted interior position with. Any token does — the
/// grammar matches these positions with a wildcard — but a plausible one keeps
/// the emitted lines readable.
fn descend_token(field: &str) -> &'static str {
    match field {
        "syn-protect" => "443",
        _ => "x1",
    }
}

fn walk(
    path: &mut Vec<String>,
    names: &DynNames,
    out: &mut Vec<Leaf>,
    seen: &mut BTreeSet<String>,
) {
    if path.len() > 14 || !seen.insert(path.join(" ")) {
        return;
    }
    let view: Vec<&str> = path.iter().map(String::as_str).collect();
    let kids = dyn_candidates(&view, names);

    if kids.is_empty() {
        // Nothing is offered here. Either the path ends (a value goes here, and
        // the completion declares no type for it), or it is an interior
        // position the grammar matches with a wildcard — `firewall syn-protect
        // <port>` has fields below it but no hint at the port.
        let field = path.last().cloned().unwrap_or_default();
        path.push(descend_token(&field).to_string());
        let v: Vec<&str> = path.iter().map(String::as_str).collect();
        let interior = !dyn_candidates(&v, names).is_empty();
        if interior {
            walk(path, names, out, seen);
            path.pop();
        } else {
            path.pop();
            out.push(Leaf {
                path: path.clone(),
                hint: None,
            });
        }
        return;
    }

    let plain: Vec<String> = kids
        .iter()
        .map(|(k, _)| k.clone())
        .filter(|k| !is_ph(k))
        .collect();
    let phs: Vec<String> = kids
        .iter()
        .map(|(k, _)| k.clone())
        .filter(|k| is_ph(k))
        .collect();

    // A keyed-instance NAME position offers the objects that exist plus a
    // `<name>` inviting a new one. Both lead to the same fields, so the walk
    // takes the existing object only — a second pass under a fresh name would
    // duplicate every field below it.
    let name_position = phs.iter().any(|p| p == "<name>") && !plain.is_empty() && {
        path.push(plain[0].clone());
        let v: Vec<&str> = path.iter().map(String::as_str).collect();
        let has = !dyn_candidates(&v, names).is_empty();
        path.pop();
        has
    };
    if name_position {
        path.push(plain[0].clone());
        walk(path, names, out, seen);
        path.pop();
        return;
    }

    // A keyword child is followed unconditionally: whether it ends the line
    // (`action accept`), takes a value the grammar says nothing about
    // (`bridge priority <?>`), or opens a wildcard level (`syn-protect
    // <port> mss`) is decided one level down, by the branch above.
    for k in &plain {
        path.push(k.clone());
        walk(path, names, out, seen);
        path.pop();
    }
    for p in &phs {
        let tok = from_hint(p).to_string();
        path.push(tok);
        let v: Vec<&str> = path.iter().map(String::as_str).collect();
        if dyn_candidates(&v, names).is_empty() {
            let mut l = path.clone();
            l.pop();
            out.push(Leaf {
                path: l,
                hint: Some(p.clone()),
            });
            path.pop();
        } else {
            walk(path, names, out, seen);
            path.pop();
        }
    }
}

/// The prerequisite lines this leaf needs, from [`CONTEXT`].
fn context_for(path: &[String]) -> Vec<&'static str> {
    let printed = format!("{} ", path[1..].join(" "));
    let mut out: Vec<&'static str> = Vec::new();
    for (prefix, lines) in CONTEXT {
        if printed.starts_with(prefix) {
            for l in *lines {
                if !out.contains(l) {
                    out.push(l);
                }
            }
        }
    }
    out
}

/// A saved configuration holding [`BASE`] plus `extra`, and what it reads back
/// as. Both are needed: a setting the file keeps but `show configuration`
/// never prints is configured, applied — and invisible.
struct Ground {
    path: std::path::PathBuf,
    toml: String,
    show: String,
}

fn ground(dir: &std::path::Path, key: usize, extra: &[&str]) -> Ground {
    let path = dir.join(format!("base-{key}.toml"));
    let _ = std::fs::remove_file(&path);
    let mut s = Session::load(&path).expect("empty session");
    for line in BASE.iter().chain(extra.iter()) {
        let mut toks: Vec<&str> = line.split_whitespace().collect();
        let cmd = toks.remove(0);
        let r = if cmd == "delete" {
            s.delete(&toks)
        } else {
            s.set(&toks)
        };
        r.unwrap_or_else(|e| panic!("context line {line:?}: {e}"));
    }
    s.save(Some(&path)).expect("save ground");
    Ground {
        toml: std::fs::read_to_string(&path).unwrap(),
        show: Session::load(&path).unwrap().show(),
        path,
    }
}

struct Outcome {
    line: String,
    stage: &'static str,
    detail: String,
}

/// Find a value this leaf accepts, and return the whole line.
fn accepted_line(leaf: &Leaf, base: &std::path::Path) -> Result<Vec<String>, String> {
    let try_line = |toks: &[String]| -> Result<(), String> {
        let mut s = Session::load(base).map_err(|e| e.to_string())?;
        let view: Vec<&str> = toks.iter().map(String::as_str).collect();
        s.set(&view).map_err(|e| e.to_string())
    };
    let body: Vec<String> = leaf.path.iter().skip(1).cloned().collect();

    let mut first_err = String::new();
    let mut candidates: Vec<String> = Vec::new();
    match &leaf.hint {
        Some(h) => {
            candidates.push(from_hint(h).to_string());
            candidates.extend(PROBE.iter().map(|s| s.to_string()));
        }
        // The grammar says nothing here. The line may already be complete (a
        // permitted value, a switch), so the empty value is tried first.
        None => {
            candidates.push(String::new());
            candidates.extend(PROBE.iter().map(|s| s.to_string()));
        }
    }
    for c in candidates {
        // `false` is every switch's default, and a switch left at its default
        // cannot be told from one that was never set. Try the other side first.
        let c = if c == "false" { "true".to_string() } else { c };
        let mut toks = body.clone();
        if !c.is_empty() {
            toks.extend(c.split_whitespace().map(str::to_string));
        }
        match try_line(&toks) {
            Ok(()) => return Ok(toks),
            Err(e) => {
                if first_err.is_empty() {
                    first_err = e;
                }
            }
        }
    }
    Err(first_err)
}

#[test]
fn every_settable_path_is_accepted_shown_persisted_and_deletable() {
    let leaves = walk_leaves();
    assert!(
        leaves.len() > 700,
        "the walk found only {} leaves — the grammar cannot have shrunk that far, \
         so the walker itself is broken",
        leaves.len()
    );

    let dir = std::env::temp_dir().join(format!("sentinel-walk-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // One ground configuration per distinct set of prerequisites, built once.
    let mut grounds: Vec<(Vec<&'static str>, Ground)> = Vec::new();

    let mut bad: Vec<Outcome> = Vec::new();
    let mut unhinted: Vec<String> = Vec::new();
    let mut noop: Vec<String> = Vec::new();
    let mut refused: Vec<String> = Vec::new();
    let mut needs_company: Vec<String> = Vec::new();
    let mut ok = 0usize;

    for leaf in &leaves {
        let extra = context_for(&leaf.path);
        let idx = match grounds.iter().position(|(k, _)| *k == extra) {
            Some(i) => i,
            None => {
                let g = ground(&dir, grounds.len(), &extra);
                grounds.push((extra.clone(), g));
                grounds.len() - 1
            }
        };
        let base_path = grounds[idx].1.path.clone();
        let base_toml = grounds[idx].1.toml.clone();
        let base_show = grounds[idx].1.show.clone();

        let printed = leaf.path.join(" ");
        let toks = match accepted_line(leaf, &base_path) {
            Ok(t) => t,
            Err(e) => {
                bad.push(Outcome {
                    line: printed,
                    stage: "accepted",
                    detail: e,
                });
                continue;
            }
        };
        let line = format!("set {}", toks.join(" "));
        let view: Vec<&str> = toks.iter().map(String::as_str).collect();
        // A value had to be supplied, and the completion declared no type for
        // it: `?` at this position shows nothing, so the only way to learn what
        // goes here is to guess or read the source.
        if leaf.hint.is_none() && toks.len() > leaf.path.len() - 1 {
            unhinted.push(line.clone());
        }

        let p = dir.join("one.toml");
        let _ = std::fs::remove_file(&p);
        std::fs::copy(&base_path, &p).unwrap();
        let mut s = Session::load(&p).unwrap();
        s.set(&view).unwrap();
        let after_show = s.show();
        // A commit failure is usually the configuration model doing its job —
        // a setting that only makes sense beside another one. Recorded, then
        // reviewed by reading the message.
        if let Err(e) = s.commit() {
            needs_company.push(format!("{line} — {e}"));
            continue;
        }
        s.save(Some(&p)).expect("save");
        let after_toml = std::fs::read_to_string(&p).unwrap();

        // The two ways a setting can fail to register, told apart: the file
        // kept it but `show` will not print it (invisible), or nothing changed
        // anywhere (the set did nothing — usually because the value already
        // was the value, which is fine, and listed rather than failed).
        if after_toml == base_toml {
            if after_show == base_show {
                noop.push(line);
            } else {
                bad.push(Outcome {
                    line,
                    stage: "unsaved",
                    detail: "shown in the candidate but absent from the saved file".into(),
                });
            }
            continue;
        }
        if after_show == base_show {
            bad.push(Outcome {
                line,
                stage: "shown",
                detail: "saved, but `show configuration` never prints it".into(),
            });
            continue;
        }
        if Session::load(&p).unwrap().show() != after_show {
            bad.push(Outcome {
                line,
                stage: "persisted",
                detail: "the saved configuration reads back differently".into(),
            });
            continue;
        }

        // Deletable: VyOS-style, either naming the value or not. Judged on the
        // saved file, not on `show`, because a secret is deliberately absent
        // from `show` and removing one changes nothing visible.
        //
        // Three outcomes are told apart. A delete the grammar does not know is
        // a hole. A delete that works but leaves a configuration the model then
        // refuses is the model doing its job — the field was required — and is
        // recorded, not failed. Anything else removed the setting.
        let del = dir.join("del.toml");
        let attempt = |args: &[&str]| -> Result<bool, String> {
            let mut s3 = Session::load(&p).unwrap();
            s3.delete(args).map_err(|e| e.to_string())?;
            let _ = std::fs::remove_file(&del);
            match s3.save(Some(&del)) {
                // Removed, and the result is still a valid configuration.
                Ok(_) => Ok(
                    std::fs::read_to_string(&del).unwrap_or_default() != after_toml
                        || s3.show() != after_show,
                ),
                // Removed, and now something else is missing. Correct.
                Err(_) => Ok(true),
            }
        };
        let without: Vec<&str> = view[..view.len().saturating_sub(1)].to_vec();
        let with_err = attempt(&view);
        let plain_err = if without.is_empty() || without == view {
            Err(String::new())
        } else {
            attempt(&without)
        };
        match (&with_err, &plain_err) {
            (Ok(true), _) | (_, Ok(true)) => ok += 1,
            // Removing a switch that is already off changes nothing, and
            // should not: `false` is what "not set" means.
            (Ok(false), _) | (_, Ok(false)) => {
                if view.last() == Some(&"false") {
                    noop.push(line);
                } else {
                    bad.push(Outcome {
                        line,
                        stage: "deletable",
                        detail: "delete left the configuration unchanged".into(),
                    });
                }
            }
            (Err(a), Err(b)) => {
                let msg = if b.is_empty() { a.clone() } else { b.clone() };
                // A refusal the grammar never heard of is a hole. A refusal
                // that explains itself — "required, delete the whole object" —
                // is a decision, and is recorded rather than failed.
                let hole = msg.contains("unknown delete path") || msg.contains("has no field");
                if hole {
                    bad.push(Outcome {
                        line,
                        stage: "deletable",
                        detail: msg,
                    });
                } else {
                    refused.push(format!("{line} — {msg}"));
                }
            }
        }
    }

    let report = std::path::PathBuf::from("target/grammar-walk.txt");
    let mut f = std::fs::File::create(&report).unwrap();
    writeln!(
        f,
        "leaves: {}  clean: {}  failing: {}  unhinted: {}  no-op: {}  \
         delete-refused: {}  needs-company: {}",
        leaves.len(),
        ok,
        bad.len(),
        unhinted.len(),
        noop.len(),
        refused.len(),
        needs_company.len()
    )
    .unwrap();
    for b in &bad {
        // One finding per line: an error message that wraps would otherwise
        // read as a dozen findings.
        let d: String = b
            .detail
            .replace(['\n', '\t'], " ")
            .chars()
            .take(160)
            .collect();
        writeln!(f, "{}\t{}\t{}", b.stage, b.line, d).unwrap();
    }
    for u in &unhinted {
        writeln!(f, "unhinted\t{u}\t").unwrap();
    }
    for n in &noop {
        writeln!(f, "no-op\t{n}\t").unwrap();
    }
    for r in &refused {
        writeln!(f, "delete-refused\t{r}\t").unwrap();
    }
    for c in &needs_company {
        let c: String = c.replace(['\n', '\t'], " ").chars().take(200).collect();
        writeln!(f, "needs-company\t{c}\t").unwrap();
    }
    eprintln!("grammar walk report: {}", report.display());

    assert!(
        bad.is_empty(),
        "{} of {} configuration paths do not work (report: {}):\n{}",
        bad.len(),
        leaves.len(),
        report.display(),
        bad.iter()
            .take(40)
            .map(|b| format!("  [{}] {} — {}", b.stage, b.line, b.detail))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Every top-level section can be cleared in one line — or says why not.
///
/// The tree's thirteen sections were split eight-to-five on this, for no reason
/// an operator could see: `delete protocols` worked, `delete firewall` came back
/// "unknown delete path". Starting a part of a configuration over means emptying
/// that part, not hunting its fields one at a time, and a refusal is only an
/// answer if it explains itself.
#[test]
fn every_top_level_section_can_be_cleared_or_says_why_not() {
    let names = seeded_names();
    let sections: Vec<String> = dyn_candidates(&["set"], &names)
        .into_iter()
        .map(|(k, _)| k)
        .filter(|k| !is_ph(k))
        .collect();
    assert!(
        sections.len() > 8,
        "only {} top-level sections?",
        sections.len()
    );

    let dir = std::env::temp_dir().join(format!("sentinel-walk-top-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let g = ground(&dir, 0, &[]);

    let mut bad: Vec<String> = Vec::new();
    for section in &sections {
        let mut s = Session::load(&g.path).unwrap();
        if let Err(e) = s.delete(&[section.as_str()]) {
            let msg = e.to_string();
            if msg.contains("unknown delete path") || msg.contains("has no field") {
                bad.push(format!("delete {section} — {msg}"));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "a section that cannot be cleared and cannot say why:\n  {}",
        bad.join("\n  ")
    );
}

/// The positions whose children are a vocabulary rather than settings.
///
/// `action` offers `accept`, `drop` and `reject`; `zone` offers the zones that
/// exist — sometimes only one, since a vocabulary drawn from the configuration
/// is as long as the configuration makes it. Both look exactly like a field
/// with sub-fields from the outside, and the difference is visible only in the
/// shape underneath: every child ends the line and none of them takes a value.
/// A bare flag (`disable`) fails that test on its siblings — it sits under an
/// object that also has keyword children that go deeper, like `static-mapping`.
///
/// A `<value>` sibling does **not** disqualify a position: `redistribute` offers
/// `connected`, `static` and `bgp` *and* a comma-separated list to type instead,
/// and `address` takes an address or the word `dhcp`. Those words are still the
/// vocabulary of one setting, and reading them as settings of their own put
/// `protocols connected` and `interface dhcp` in the inventory — pairs no
/// interface can be measured against.
fn value_enumerations(leaves: &[Leaf]) -> BTreeSet<Vec<String>> {
    let mut terminal: std::collections::BTreeMap<Vec<String>, usize> =
        std::collections::BTreeMap::new();
    let mut has_other: BTreeSet<Vec<String>> = BTreeSet::new();
    for leaf in leaves {
        if leaf.path.len() < 2 {
            continue;
        }
        let parent = leaf.path[..leaf.path.len() - 1].to_vec();
        if leaf.hint.is_none() {
            *terminal.entry(parent).or_default() += 1;
        }
        // Anything further above has a child that leads deeper than one word.
        for n in 1..leaf.path.len().saturating_sub(1) {
            has_other.insert(leaf.path[..n].to_vec());
        }
    }
    terminal
        .into_iter()
        .filter(|(path, n)| *n >= 1 && !has_other.contains(path))
        .map(|(path, _)| path)
        .collect()
}

/// The inventory the web console is measured against, as a committed file.
///
/// The console's own coverage pass (`tests/console/coverage.mjs`) can report
/// what it is able to write, but it has nothing to compare that with — and a
/// coverage figure computed against a list somebody typed by hand measures the
/// list. So the CLI half comes from the same walk as everything else here.
///
/// Recorded as `<section> <field>` rather than as whole paths on purpose: the
/// two sides name objects differently (the walk uses seeded names like `eth0`,
/// the console a placeholder), and a comparison that has to reconcile those
/// mostly measures the reconciliation. What a section can express is the
/// question worth asking, and it survives both spellings.
///
/// Golden, not generated on the fly: `UPDATE_CLI_FIELDS=1 cargo test` rewrites
/// it, and any other run fails on a difference. Silent drift here would move
/// the console's coverage number without anyone deciding to.
#[test]
fn the_cli_field_inventory_is_current() {
    let leaves = walk_leaves();
    let enumerations = value_enumerations(&leaves);
    let mut fields: BTreeSet<String> = BTreeSet::new();
    for leaf in &leaves {
        // `set <section> … <field>` — drop `set`, keep the section and the leaf.
        // Except where the leaf is one of a position's *values* rather than a
        // setting of its own: `action accept` configures `action`, and counting
        // `accept`, `drop` and `reject` as three separate things a section can
        // express is how a coverage figure ends up measuring vocabularies.
        let end = leaf.path.len() - 1;
        let field_at =
            if leaf.hint.is_none() && end >= 2 && enumerations.contains(&leaf.path[..end]) {
                end - 1
            } else {
                end
            };
        let (Some(section), Some(field)) = (leaf.path.get(1), leaf.path.get(field_at)) else {
            continue;
        };
        if field_at < 1 || is_ph(section) || is_ph(field) {
            continue;
        }
        fields.insert(format!("{section} {field}"));
    }
    assert!(
        fields.len() > 400,
        "only {} section/field pairs — the grammar cannot have shrunk that far",
        fields.len()
    );

    let path = std::path::Path::new("tests/console/cli-fields.txt");
    let body = fields.into_iter().collect::<Vec<_>>().join("\n") + "\n";
    if std::env::var_os("UPDATE_CLI_FIELDS").is_some() {
        std::fs::write(path, &body).unwrap();
        return;
    }
    let Ok(have) = std::fs::read_to_string(path) else {
        // A build from the git tree only carries tracked files, so an inventory
        // that exists on disk and not in the index is simply absent here — and
        // "the inventory has moved" would be a confusing way to say that.
        panic!(
            "{} is missing — generate it with UPDATE_CLI_FIELDS=1 and `git add` it",
            path.display()
        );
    };
    if have == body {
        return;
    }
    let old: BTreeSet<&str> = have.lines().collect();
    let new: BTreeSet<&str> = body.lines().collect();
    let added: Vec<&&str> = new.difference(&old).take(10).collect();
    let gone: Vec<&&str> = old.difference(&new).take(10).collect();
    panic!(
        "the CLI field inventory has moved — re-run with UPDATE_CLI_FIELDS=1 \
         and look at what the console coverage does in response.\n  \
         added: {added:?}\n  gone:  {gone:?}"
    );
}
