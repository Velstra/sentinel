//! Admission of a new configuration, distinct from parsing stored intent.
//!
//! `to <zone>` is not route-selected egress matching. Until that dataplane
//! contract exists, a newly introduced deny must not promise that protection.
//! Boot, timer reapplication and owned recovery deliberately do not use this
//! gate: refusing an already installed policy there can lock out the appliance.

use crate::config::{Action, Appliance};
use anyhow::{Context, Result, bail};
use std::path::Path;

/// Check a transition against authoritative, pre-change intent. Callers hold
/// apply.lock through admission and the subsequent mutation. Never pass the
/// candidate itself as a fallback baseline.
pub(crate) fn check(previous: Option<&Appliance>, candidate: &Appliance) -> Result<()> {
    let mut candidate = candidate.clone();
    candidate.normalize();
    let previous = previous.map(|value| {
        let mut value = value.clone();
        value.normalize();
        value
    });
    // Deliberately conservative: interface membership/addressing, zone
    // posture, other rules and all named firewall groups affect enforcement. A change
    // to these requires migrating legacy denies first, not silently retaining
    // their grandfathered status. Hostname/services/HA identity edits do not.
    let context = |value: &Appliance| {
        serde_json::to_value((
            &value.firewall,
            &value.zones,
            &value.interfaces,
            &value.rules,
        ))
    };
    let same_context = previous
        .as_ref()
        .map(|old| Ok::<_, anyhow::Error>(context(old)? == context(&candidate)?))
        .transpose()?
        .unwrap_or(false);
    let mut refused = Vec::new();
    for (index, rule) in candidate.rules.iter().enumerate() {
        let Some(zone) = rule.to.as_deref() else {
            continue;
        };
        if rule.disabled
            || rule.action == Action::Accept
            || candidate.zones.get(zone).is_some_and(|zone| zone.local)
        {
            continue;
        }
        let unchanged = same_context
            && previous
                .as_ref()
                .and_then(|old| old.rules.get(index))
                .map(|old| {
                    Ok::<_, anyhow::Error>(
                        serde_json::to_value(old)? == serde_json::to_value(rule)?,
                    )
                })
                .transpose()?
                .unwrap_or(false);
        if !unchanged {
            // JSON quoting keeps hostile/control-containing names single-line.
            refused.push(serde_json::to_string(&rule.name)?);
        }
    }
    if !refused.is_empty() {
        // A name can duplicate a credential. Diagnostics are public operator
        // guidance, not a secret export; scrub names, including JSON escaping,
        // without corrupting the fixed remediation text for short secrets.
        let mut secrets = crate::redact::every_secret_value(&candidate);
        if let Some(previous) = &previous {
            secrets.extend(crate::redact::every_secret_value(previous));
        }
        for secret in secrets.clone() {
            let encoded = serde_json::to_string(&secret)?;
            secrets.push(encoded[1..encoded.len() - 1].to_string());
        }
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        secrets.dedup();
        let scrubbed = crate::redact::scrub_text(&refused.join(", "), &secrets);
        let mut names = String::new();
        for character in scrubbed.chars() {
            if character.is_control() {
                names.extend(character.escape_debug());
            } else {
                names.push(character);
            }
        }
        bail!(
            "destination-zone admission refused for rule(s) {}: drop/reject with a non-local `to` zone does not match the routed egress interface. Use an explicit destination/destination-group for the intended networks; remove `to` only if every destination is intended. Unchanged legacy policies may be reapplied, but changes to rules, firewall, zones or interfaces require migrating all legacy destination-zone denies first",
            names
        );
    }
    // CTRL-01: a weak config-sync secret is an offline-guessable credential.
    // Refused for every admitted change, not grandfathered: the box still
    // boots and pairs with it (boot does not use this gate), but no change is
    // accepted until it is rotated.
    candidate.refuse_weak_sync_secret()?;
    Ok(())
}

/// Strict baseline selection shared by interactive/API mutations. An invalid,
/// inaccessible or non-regular active file is an error, never saved fallback.
/// Missing intent is allowed only as a genuinely initial configuration.
pub(crate) fn check_saved(path: &Path, live: bool, candidate: &Appliance) -> Result<()> {
    let _lock = crate::system::apply_lock()?;
    let previous = baseline(
        path,
        live.then_some(Path::new(crate::session::Session::RUNNING)),
    )?;
    check(previous.as_ref(), candidate)
}

fn baseline(saved: &Path, running: Option<&Path>) -> Result<Option<Appliance>> {
    const LIMIT: usize = 64 * 1024 * 1024;
    if let Some(running) = running
        && let Some(text) = crate::system::read_owned_regular(running, LIMIT)
            .context("reading admission active intent")?
    {
        return Appliance::from_toml(&text)
            // Parser error chains can include credential-bearing source lines.
            // The caller may publish this error through a redacted API surface.
            .map_err(|_| anyhow::anyhow!("admission active intent is invalid; inspect the protected running configuration locally"))
            .map(Some);
    }
    let Some(text) = crate::system::read_owned_regular(saved, LIMIT)
        .context("reading admission saved intent")?
    else {
        return Ok(None);
    };
    if saved.extension().and_then(|value| value.to_str()) == Some("json") {
        Appliance::from_json(&text)
    } else {
        Appliance::from_toml(&text)
    }
    .map_err(|_| {
        anyhow::anyhow!(
            "admission saved intent is invalid; inspect the protected saved configuration locally"
        )
    })
    .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy() -> Appliance {
        Appliance::from_toml(
            r#"[system]
hostname = "fw"
[[interface]]
name = "lan0"
zone = "lan"
address = "192.0.2.1/24"
[[interface]]
name = "wan0"
zone = "wan"
address = "198.51.100.1/24"
[[rule]]
name = "deny-telnet"
from = "lan"
to = "wan"
action = "reject"
proto = "tcp"
port = 23
"#,
        )
        .unwrap()
    }

    #[test]
    fn parsing_and_compiling_legacy_intent_remain_available() {
        let old = legacy();
        assert!(crate::compile::compile(&old).to_toml().is_ok());
        assert!(check(Some(&old), &old).is_ok());
        assert!(check(None, &old).is_err());
        let mut changed = old.clone();
        changed.system.hostname = "renamed".into();
        assert!(check(Some(&old), &changed).is_ok());
    }

    #[test]
    fn changed_rules_and_enforcement_context_cannot_inherit_legacy_status() {
        let old = legacy();
        let mut cases = Vec::new();
        let mut value = old.clone();
        value.rules[0].action = Action::Drop;
        cases.push(value);
        let mut value = old.clone();
        value.rules[0].name = "renamed".into();
        cases.push(value);
        let mut value = old.clone();
        value.rules[0].source = Some("192.0.2.9/32".into());
        cases.push(value);
        let mut value = old.clone();
        value.interfaces[1].address = Some("203.0.113.1/24".into());
        cases.push(value);
        let mut value = old.clone();
        value.firewall.default_action = Action::Accept;
        cases.push(value);
        let mut value = old.clone();
        value.zones.insert("wan".into(), Default::default());
        cases.push(value);
        let mut value = old.clone();
        let mut extra = value.rules[0].clone();
        extra.name = "allow".into();
        extra.action = Action::Accept;
        value.rules.insert(0, extra);
        cases.push(value);
        for candidate in cases {
            assert!(check(Some(&old), &candidate).is_err());
        }
    }

    #[test]
    fn disabled_local_and_accept_exemptions_do_not_authorize_enabling_a_deny() {
        let old = legacy();
        let mut previous = old.clone();
        previous.rules[0].disabled = true;
        assert!(check(None, &previous).is_ok());
        assert!(check(Some(&previous), &old).is_err());
        let mut accept = old.clone();
        accept.rules[0].action = Action::Accept;
        assert!(check(None, &accept).is_ok());
        assert!(check(Some(&accept), &old).is_err());
        let mut local = old.clone();
        local.zones.entry("wan".into()).or_default().local = true;
        assert!(check(None, &local).is_ok());
        assert!(check(Some(&local), &old).is_err());
        let mut explicit = old.clone();
        explicit.rules[0].to = None;
        explicit.rules[0].destination = Some("203.0.113.0/24".into());
        assert!(check(None, &explicit).is_ok());
        assert!(check(Some(&old), &explicit).is_ok());
    }

    #[test]
    fn baseline_is_strict_and_prefers_running_over_saved() {
        let dir = std::env::temp_dir().join(format!("sentinel-admission-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let saved = dir.join("saved.toml");
        let running = dir.join("running.toml");
        assert!(baseline(&saved, Some(&running)).unwrap().is_none());
        let old = legacy();
        std::fs::write(&saved, old.to_toml().unwrap()).unwrap();
        assert!(baseline(&saved, Some(&running)).unwrap().is_some());
        let mut active = old.clone();
        active.system.hostname = "active".into();
        std::fs::write(&running, active.to_toml().unwrap()).unwrap();
        assert_eq!(
            baseline(&saved, Some(&running))
                .unwrap()
                .unwrap()
                .system
                .hostname,
            "active"
        );
        let secret = "private-baseline-marker";
        std::fs::write(
            &running,
            format!("[system]\nhostname=\"{secret}\"\nbroken=["),
        )
        .unwrap();
        let failure = baseline(&saved, Some(&running)).unwrap_err();
        assert!(!format!("{failure:#}").contains(secret));
        std::fs::remove_file(&running).unwrap();
        std::os::unix::fs::symlink(&saved, &running).unwrap();
        assert!(baseline(&saved, Some(&running)).is_err());
        std::fs::remove_file(&running).unwrap();
        std::fs::create_dir(&running).unwrap();
        assert!(baseline(&saved, Some(&running)).is_err());
        std::fs::write(&saved, "bad saved intent").unwrap();
        assert!(baseline(&saved, None).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn another_rule_cannot_change_posture_around_an_unchanged_legacy_deny() {
        let mut old = legacy();
        let mut broad = old.rules[0].clone();
        broad.name = "broad".into();
        broad.to = None;
        broad.proto = None;
        broad.port.clear();
        broad.action = Action::Drop;
        old.rules.push(broad);
        let mut candidate = old.clone();
        candidate.rules[1].action = Action::Accept;
        assert!(check(Some(&old), &candidate).is_err());
    }

    #[test]
    fn diagnostic_names_are_single_line_and_do_not_export_credentials() {
        let mut candidate = legacy();
        for secret in ["x", "secret-\"quoted\\value\nend"] {
            candidate.system.config_sync.secret = Some(secret.into());
            candidate.rules[0].name = format!("label-{secret}\u{85}\u{7f}");
            let message = check(None, &candidate).unwrap_err().to_string();
            let quoted = serde_json::to_string(secret).unwrap();
            assert!(!message.contains(&format!("label-{}", &quoted[1..quoted.len() - 1])));
            assert!(!message.chars().any(char::is_control));
            assert!(message.contains(crate::redact::REDACTED));
            assert!(message.contains("explicit destination"));
        }
    }
}
