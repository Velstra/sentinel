//! Per-field shape checks for settings that reach a daemon's config file
//! verbatim (audit 8b6181, CTRL-02/03/08/13/16/17/18/29).
//!
//! These used to live in the CLI's `set` handlers only, so the API document
//! path, config-sync, fleet push and archive rollback — which run
//! `Appliance::validate()` and nothing else — never saw them. Each check is now
//! one function, called by `validate()` (through [`validate`]) *and* by the
//! `set` handler, so the two cannot drift apart again.
//!
//! Every rule also names what the **boot-time** apply does when a saved
//! configuration from before the rule breaks it ([`quarantine`]): the affected
//! setting or service is switched off with a loud error, and the rest of the
//! configuration still comes up. `config check`, `commit`, the API and sync stay
//! strict; only `Appliance::load_lenient` quarantines.

use std::net::Ipv4Addr;

use anyhow::{Context, Result, bail};

use crate::config::{Appliance, Dyndns, PppoeUser};

/// The levels sshd's `LogLevel` takes (case-insensitively; `DEBUG` is an alias
/// of `DEBUG1`).
pub(crate) const SSH_LOG_LEVELS: [&str; 9] = [
    "QUIET", "FATAL", "ERROR", "INFO", "VERBOSE", "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3",
];

/// networkd's `TransmitHashPolicy=` values.
pub(crate) const BOND_HASH_POLICIES: [&str; 6] = [
    "layer2",
    "layer2+3",
    "layer3+4",
    "encap2+3",
    "encap3+4",
    "vlan+srcmac",
];

/// networkd's `LACPTransmitRate=` values.
pub(crate) const BOND_LACP_RATES: [&str; 2] = ["slow", "fast"];

/// `services ssh loglevel`: rendered as `LogLevel <v>` into the sshd drop-in, so
/// anything but a level name is a second sshd directive (CTRL-03).
pub(crate) fn ssh_loglevel(v: &str) -> Result<()> {
    if !SSH_LOG_LEVELS.iter().any(|l| l.eq_ignore_ascii_case(v)) {
        bail!(
            "services ssh loglevel {v:?}: expected one of {}",
            SSH_LOG_LEVELS.join(", ")
        );
    }
    Ok(())
}

/// `interface … dhcp host-name`: DHCP option 12, a hostname or a fully
/// qualified name (networkd's `Hostname=`).
pub(crate) fn dhcp_host_name(v: &str) -> Result<()> {
    crate::config::validate_hostname(v)
        .or_else(|_| crate::config::validate_domain_name(v))
        .with_context(|| format!("dhcp host-name {v:?}: a hostname or a DNS name"))
}

/// `interface … bond hash-policy`.
pub(crate) fn bond_hash_policy(v: &str) -> Result<()> {
    if !BOND_HASH_POLICIES.contains(&v) {
        bail!(
            "bond hash-policy {v:?}: expected one of {}",
            BOND_HASH_POLICIES.join(" | ")
        );
    }
    Ok(())
}

/// `interface … bond lacp-rate`.
pub(crate) fn bond_lacp_rate(v: &str) -> Result<()> {
    if !BOND_LACP_RATES.contains(&v) {
        bail!("bond lacp-rate {v:?}: slow | fast");
    }
    Ok(())
}

/// `services dyndns login`: one plain token. ddclient splits a config line on
/// unquoted whitespace and commas into *several* options, so
/// `user usev4=cmdv4 cmdv4="…"` set a command it runs as root (CTRL-02).
pub(crate) fn dyndns_login(v: &str) -> Result<()> {
    let plain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '+' | '-');
    if v.is_empty() || v.len() > 128 || !v.chars().all(plain) {
        bail!(
            "services dyndns login: 1-128 of letters, digits and @ . _ + - (ddclient would read \
             anything else as further options)"
        );
    }
    Ok(())
}

/// `services dyndns password`: rendered single-quoted, and ddclient takes a
/// backslash as an escape — so neither a quote nor a backslash may appear.
pub(crate) fn dyndns_password(v: &str) -> Result<()> {
    if v.contains(['\'', '\\']) {
        bail!("services dyndns password: must not contain a single quote or a backslash");
    }
    Ok(())
}

/// `services ntp allow-from`: a network, written as an address or a prefix.
/// Rendered as `allow <v>` into chrony.conf (CTRL-16).
pub(crate) fn ntp_allow_from(v: &str) -> Result<()> {
    crate::config::validate_cidr_or_ip(v)
        .with_context(|| format!("services ntp allow-from {v:?}: an address or prefix"))
}

/// A word of a pppd `chap-secrets` row: rendered inside double quotes, where a
/// quote ends the word and a backslash escapes the next character (CTRL-18).
fn chap_word(field: &str, v: &str) -> Result<()> {
    if v.is_empty() || v.contains(['"', '\\']) {
        bail!("services pppoe-server {field}: must be non-empty, without a quote or backslash");
    }
    Ok(())
}

/// `services pppoe-server user <name>`: one subscriber row. A name of `*` is
/// pppd's wildcard (every client), and a secret starting with `@` makes pppd
/// read the secret from the file it names.
pub(crate) fn pppoe_subscriber(u: &PppoeUser) -> Result<()> {
    chap_word("user name", &u.name)?;
    if u.name == "*" {
        bail!("services pppoe-server user name `*`: that is pppd's wildcard for every client");
    }
    pppoe_subscriber_password(&u.name, &u.password)?;
    if let Some(a) = &u.address {
        a.parse::<Ipv4Addr>().with_context(|| {
            format!(
                "services pppoe-server user {:?} address: an IPv4 address",
                u.name
            )
        })?;
    }
    Ok(())
}

/// The secret half of [`pppoe_subscriber`], for the CLI's `set … password`.
pub(crate) fn pppoe_subscriber_password(name: &str, password: &str) -> Result<()> {
    chap_word("user password", password)
        .with_context(|| format!("services pppoe-server user {name:?}"))?;
    if password.starts_with('@') {
        bail!(
            "services pppoe-server user {name:?} password: must not start with `@`, which makes \
             pppd read the secret from a file"
        );
    }
    Ok(())
}

/// `update channel … subscription-key`: sent as `Authorization: Bearer <key>`,
/// so it must be an RFC 6750 `b64token` — anything else is header syntax.
pub(crate) fn subscription_key(v: &str) -> Result<()> {
    let body = v.trim_end_matches('=');
    let token =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~' | '+' | '/');
    if body.is_empty() || v.len() > 4096 || !body.chars().all(token) {
        bail!(
            "update subscription-key: 1-4096 characters of letters, digits and - . _ ~ + / \
             (optionally ending in =)"
        );
    }
    Ok(())
}

/// `system sysctl <key>`: a dotted kernel parameter name. The drop-in is
/// `key = value` lines, so a space or `=` in the name is a different line.
pub(crate) fn sysctl_key(v: &str) -> Result<()> {
    let name = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
    if v.is_empty() || !v.chars().all(name) {
        bail!("system sysctl {v:?}: a parameter name is letters, digits and . _ -");
    }
    Ok(())
}

/// `services dns txt-record <name> <text>`: rendered `txt-record=name,"text"`
/// for dnsmasq, which ends the string at a quote and escapes with a backslash.
pub(crate) fn dns_txt(v: &str) -> Result<()> {
    if v.contains(['"', '\\']) {
        bail!("services dns txt-record: the text must not contain a double quote or backslash");
    }
    Ok(())
}

/// One rule over the whole appliance.
struct Rule {
    /// What the boot-time apply does instead, when a saved value breaks it.
    fallback: &'static str,
    /// Every breach, as a message (never including a secret value).
    find: fn(&Appliance) -> Vec<String>,
    /// Neutralise every breach of this rule. Must leave nothing `find` reports.
    neutralise: fn(&mut Appliance),
}

fn errors<I: IntoIterator<Item = Result<()>>>(checks: I) -> Vec<String> {
    checks
        .into_iter()
        .filter_map(|r| r.err().map(|e| format!("{e:#}")))
        .collect()
}

fn is_bad<T>(value: &Option<T>, check: impl Fn(&T) -> Result<()>) -> bool {
    value.as_ref().is_some_and(|v| check(v).is_err())
}

fn dyndns_ok(d: &Dyndns) -> Result<()> {
    if let Some(l) = &d.login {
        dyndns_login(l)?;
    }
    if let Some(p) = &d.password {
        dyndns_password(p)?;
    }
    Ok(())
}

const RULES: &[Rule] = &[
    Rule {
        fallback: "sshd keeps its default LogLevel",
        find: |a| errors(a.services.ssh.loglevel.as_deref().map(ssh_loglevel)),
        neutralise: |a| {
            if is_bad(&a.services.ssh.loglevel, |v| ssh_loglevel(v)) {
                a.services.ssh.loglevel = None;
            }
        },
    },
    Rule {
        fallback: "that DHCP client sends no host name",
        find: |a| {
            errors(a.interfaces.iter().filter_map(|i| {
                let h = i.dhcp.host_name.as_deref()?;
                Some(dhcp_host_name(h).with_context(|| format!("interface {:?}", i.name)))
            }))
        },
        neutralise: |a| {
            for i in &mut a.interfaces {
                if is_bad(&i.dhcp.host_name, |v| dhcp_host_name(v)) {
                    i.dhcp.host_name = None;
                }
            }
        },
    },
    Rule {
        fallback: "that bond uses the kernel's default",
        find: |a| {
            errors(a.interfaces.iter().flat_map(|i| {
                [
                    i.bond.hash_policy.as_deref().map(bond_hash_policy),
                    i.bond.lacp_rate.as_deref().map(bond_lacp_rate),
                ]
                .into_iter()
                .flatten()
                .map(move |r| r.with_context(|| format!("interface {:?}", i.name)))
            }))
        },
        neutralise: |a| {
            for i in &mut a.interfaces {
                if is_bad(&i.bond.hash_policy, |v| bond_hash_policy(v)) {
                    i.bond.hash_policy = None;
                }
                if is_bad(&i.bond.lacp_rate, |v| bond_lacp_rate(v)) {
                    i.bond.lacp_rate = None;
                }
            }
        },
    },
    Rule {
        fallback: "dynamic DNS is disabled",
        find: |a| errors([dyndns_ok(&a.services.dyndns)]),
        neutralise: |a| {
            if dyndns_ok(&a.services.dyndns).is_err() {
                a.services.dyndns = Dyndns::default();
            }
        },
    },
    Rule {
        fallback: "that network is not served time",
        find: |a| errors(a.services.ntp.allow_from.iter().map(|n| ntp_allow_from(n))),
        neutralise: |a| {
            a.services
                .ntp
                .allow_from
                .retain(|n| ntp_allow_from(n).is_ok())
        },
    },
    Rule {
        fallback: "that subscriber is not accepted",
        find: |a| errors(a.services.pppoe_server.users.iter().map(pppoe_subscriber)),
        neutralise: |a| {
            a.services
                .pppoe_server
                .users
                .retain(|u| pppoe_subscriber(u).is_ok());
        },
    },
    Rule {
        fallback: "updates from that channel are unavailable",
        find: |a| {
            errors(a.update.iter().flat_map(|u| &u.channels).filter_map(|c| {
                let key = c.subscription_key.as_deref()?;
                Some(subscription_key(key).with_context(|| format!("update channel {:?}", c.name)))
            }))
        },
        neutralise: |a| {
            for c in a.update.iter_mut().flat_map(|u| &mut u.channels) {
                if is_bad(&c.subscription_key, |v| subscription_key(v)) {
                    c.subscription_key = None;
                }
            }
        },
    },
    Rule {
        fallback: "that kernel parameter is not set",
        find: |a| errors(a.system.sysctl.keys().map(|k| sysctl_key(k))),
        neutralise: |a| a.system.sysctl.retain(|k, _| sysctl_key(k).is_ok()),
    },
    Rule {
        fallback: "that TXT record is not served",
        find: |a| {
            errors(
                a.services.dns.txt_record.iter().map(|(name, text)| {
                    dns_txt(text).with_context(|| format!("txt-record {name:?}"))
                }),
            )
        },
        neutralise: |a| {
            a.services
                .dns
                .txt_record
                .retain(|_, text| dns_txt(text).is_ok());
        },
    },
];

/// Refuse the first breach of any rule. Part of `Appliance::validate`.
pub(crate) fn validate(appliance: &Appliance) -> Result<()> {
    for rule in RULES {
        if let Some(message) = (rule.find)(appliance).into_iter().next() {
            bail!("{message}");
        }
    }
    Ok(())
}

/// Boot-time only: switch off whatever a saved configuration from before these
/// rules breaks, loudly, so the appliance comes up with the rest of it instead
/// of with nothing. Returns the messages it printed (for tests).
pub(crate) fn quarantine(appliance: &mut Appliance) -> Vec<String> {
    let mut printed = Vec::new();
    for rule in RULES {
        let found = (rule.find)(appliance);
        if found.is_empty() {
            continue;
        }
        for message in found {
            let line = format!(
                "error: {message}. The saved configuration predates this check; at boot {}. \
                 Fix the setting and commit: `config check` refuses it until then.",
                rule.fallback
            );
            eprintln!("{line}");
            printed.push(line);
        }
        (rule.neutralise)(appliance);
    }
    printed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_levels_are_case_insensitive_and_closed() {
        for ok in ["INFO", "verbose", "DEBUG", "debug3"] {
            assert!(ssh_loglevel(ok).is_ok(), "{ok}");
        }
        for bad in ["", "LOUD", "INFO\nX", "INFO X"] {
            assert!(ssh_loglevel(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_dyndns_login_is_one_token() {
        for ok in ["user", "me@example.com", "a.b_c+d-e"] {
            assert!(dyndns_login(ok).is_ok(), "{ok}");
        }
        for bad in ["", "a b", "a,b", "a=b", "a'b", "a\"b", "a#b", "a\\b"] {
            assert!(dyndns_login(bad).is_err(), "{bad:?}");
        }
        assert!(dyndns_password("p@ss w0rd!").is_ok());
        assert!(dyndns_password("x\\").is_err());
    }

    #[test]
    fn a_subscriber_cannot_be_a_wildcard_a_file_or_a_second_row() {
        let user = |name: &str, password: &str, address: Option<&str>| PppoeUser {
            name: name.into(),
            password: password.into(),
            address: address.map(str::to_string),
        };
        assert!(pppoe_subscriber(&user("alice", "pw with space", Some("10.0.0.5"))).is_ok());
        for bad in [
            user("*", "pw", None),
            user("a\"b", "pw", None),
            user("alice", "@/etc/shadow", None),
            user("alice", "pw\\", None),
            user("alice", "pw", Some("*")),
            user("alice", "pw", Some("10.0.0.5 extra")),
        ] {
            assert!(pppoe_subscriber(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_subscription_key_is_a_bearer_token() {
        assert!(subscription_key("abc.DEF-123_~+/==").is_ok());
        for bad in ["", "=", "a b", "a\nb", "a:b", "a=b"] {
            assert!(subscription_key(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn every_rule_neutralises_everything_it_finds() {
        let mut a = Appliance::from_toml("[system]\nhostname = \"edge\"\n").unwrap();
        a.services.ssh.loglevel = Some("LOUD".into());
        a.services.ntp.allow_from = vec!["10.0.0.0/8".into(), "cmdallow all".into()];
        a.services.dyndns.hostname = Some("h.example.com".into());
        a.services.dyndns.login = Some("a b".into());
        a.system.sysctl.insert("net.a = 1 b".into(), "1".into());
        a.services
            .dns
            .txt_record
            .insert("x.lan".into(), "a\"b".into());
        assert!(validate(&a).is_err());
        let printed = quarantine(&mut a);
        assert_eq!(printed.len(), 5, "{printed:#?}");
        assert!(validate(&a).is_ok());
        assert_eq!(a.services.ssh.loglevel, None);
        assert_eq!(a.services.ntp.allow_from, ["10.0.0.0/8"]);
        assert!(
            a.services.dyndns.hostname.is_none(),
            "dyndns must be off, not half-on"
        );
        for rule in RULES {
            assert!((rule.find)(&a).is_empty(), "{}", rule.fallback);
        }
    }
}
