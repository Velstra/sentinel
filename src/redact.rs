//! Keeping secrets out of what is read back.
//!
//! The appliance stores its secrets in its own configuration — a PSK, a
//! WireGuard private key, a RADIUS secret, the config-sync credential — and the
//! configuration is read back through more than one door: `GET /config`, the
//! full document the console edits, every `show` that renders it, and a peer's
//! `show` proxied through the stack view. One list of what is secret, used by
//! all of them, is the only way the doors stay in step: a second list is how
//! `/config` came to redact a BGP password while `show configuration commands`
//! printed it, and how both forgot the OSPF key.
//!
//! What a caller may see is a [`Disclosure`], decided from who is asking:
//!
//! - the **machine credential** (no account behind it — a peer firewall, or the
//!   operator holding the 0600 token file) sees everything;
//! - a **read-write account** sees every secret except the machine credential.
//!   It could set any of the others anyway, so hiding them protects nothing,
//!   while the machine credential is the one thing an account must not be able
//!   to turn into: it is the peer's full-access token, it has no account to
//!   withdraw, and it is what lets a request skip the account's own limits;
//! - a **read-only account** sees no secret at all — "may read everything" is
//!   about the configuration's shape, never about the keys inside it.

use std::ffi::OsStr;

use anyhow::{Context, Result};
use serde_json::Value;

use crate::config::{Appliance, Permission};

/// Serialised-config field names that carry secret material. Redaction is by
/// name and by type, and it fails closed: any string value under one of these
/// keys is replaced, so a future secret field that uses one of these
/// conventional names is redacted the moment it exists, and a genuinely new
/// secret name is a one-line addition here. The guard test below reads the
/// configuration model's field names and fails on any secret-looking name that
/// is neither listed here nor explicitly argued to be harmless.
///
/// Type matters for `community`: the SNMP read community is a secret *string*,
/// while a BGP `community` is a *list* of route tags that is not secret — so only
/// string-valued occurrences are redacted, which leaves the BGP list alone. The
/// GRE tunnel `key` is a `u32`, so it is likewise never touched (and not listed).
pub const SECRET_FIELDS: &[&str] = &[
    "secret",
    "password",
    "passphrase",
    "psk",
    "preshared-key",
    "private-key",
    "hashed-password",
    "totp",
    "community",
    "ao-key",
    "pin",
    // The routing protocols' shared keys: OSPF and IS-IS authentication, the
    // global BFD key and the per-neighbour BFD key. Anyone holding one can
    // inject routes or tear sessions down — exactly what a read-only view of a
    // router must not hand out.
    "auth-key",
    "bfd-auth-key",
    // The MACsec connectivity association key: the link's whole encryption.
    "macsec-key",
    // The update channel's entitlement (`[[update.channels]] subscription-key`):
    // a bearer token that buys tested images — anyone holding it can consume
    // the subscription, so it never leaves through the read API.
    "subscription-key",
    "enrollment-token",
    // The HA witness key (`[system.ha-witness] key`): it cannot sign in to a
    // member, but whoever holds it can impersonate the witness to both and
    // decide which of them forwards. The only other `key` in the model is the
    // GRE tunnel key, a `u32`, which the string-only rule leaves alone.
    "key",
];

/// Where the machine credential lives in a serialised [`Appliance`]: the
/// config-sync secret (which is written to this box's API token file, so it
/// *is* the full-access token) and the HA witness secret (the same pairing
/// credential, by the HA setup's own instruction). Paths, not names: a field
/// called `secret` elsewhere — a RADIUS secret — is an ordinary secret.
pub const MACHINE_CREDENTIALS: &[&[&str]] = &[
    &["system", "config-sync", "secret"],
    &["system", "ha-witness", "secret"],
];

/// What a redacted secret reads as — a marker, not an empty string, so a reader
/// can tell "a secret is set but hidden" apart from "unset". Every door uses the
/// same marker, so a document read back through one and written back through
/// another can recognise what it was not shown.
pub const REDACTED: &str = "__redacted__";

/// The environment variable through which the API tells the `show` it runs how
/// much to disclose. It can only ever *add* redaction: unset means the full
/// view (the CLI on the box, where whoever runs it can read the file anyway),
/// and a value this binary does not recognise means the strictest view.
pub const ENV: &str = "SENTINEL_REDACT";

/// How much of the configuration's secret material a reader is shown. Ordered
/// from most to least disclosed, so combining two requests is a `max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Disclosure {
    /// Everything, the machine credential included.
    Full,
    /// Every secret except the machine credential.
    NoMachineCredential,
    /// No secret at all.
    NoSecrets,
}

impl Disclosure {
    /// What an authenticated caller may see: `user` is `None` for the machine
    /// credential, which has no account behind it.
    pub fn for_caller(user: Option<&str>, permission: Permission) -> Self {
        match (user, permission.may_write()) {
            (_, false) => Disclosure::NoSecrets,
            (Some(_), true) => Disclosure::NoMachineCredential,
            (None, true) => Disclosure::Full,
        }
    }

    /// The value [`ENV`] carries for this level, or `None` for [`Self::Full`],
    /// which is what an unset variable already means.
    pub fn env_value(self) -> Option<&'static str> {
        match self {
            Disclosure::Full => None,
            Disclosure::NoMachineCredential => Some("machine-credential"),
            Disclosure::NoSecrets => Some("secrets"),
        }
    }

    /// Read a level back from [`ENV`]'s value. Fails closed: anything but the
    /// two spellings [`Self::env_value`] writes is the strictest level, so a
    /// typo or a newer caller's word can never widen what is shown.
    pub fn from_env_value(value: Option<&OsStr>) -> Self {
        match value.map(|v| v.to_str()) {
            None => Disclosure::Full,
            Some(Some("machine-credential")) => Disclosure::NoMachineCredential,
            Some(_) => Disclosure::NoSecrets,
        }
    }

    /// The level this process was asked to show at.
    pub fn from_env() -> Self {
        Self::from_env_value(std::env::var_os(ENV).as_deref())
    }
}

/// Walk a serialised [`Appliance`] and replace every secret string in place.
/// Recurses through objects and arrays; only string values under a
/// [`SECRET_FIELDS`] key are touched, which is what leaves the BGP `community`
/// list and the numeric GRE `key` alone.
pub fn redact_secrets(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if v.is_string() && SECRET_FIELDS.contains(&k.as_str()) {
                    *v = Value::String(REDACTED.to_string());
                } else {
                    redact_secrets(v);
                }
            }
        }
        Value::Array(items) => {
            for v in items.iter_mut() {
                redact_secrets(v);
            }
        }
        _ => {}
    }
}

/// Replace only the machine credential(s) in a serialised [`Appliance`].
pub fn redact_machine_credential(value: &mut Value) {
    for path in MACHINE_CREDENTIALS {
        if let Some(slot) = pointer_mut(value, path).filter(|v| v.is_string()) {
            *slot = Value::String(REDACTED.to_string());
        }
    }
}

/// Redact a serialised [`Appliance`] down to `level`.
pub fn redact_value(value: &mut Value, level: Disclosure) {
    match level {
        Disclosure::Full => {}
        Disclosure::NoMachineCredential => redact_machine_credential(value),
        Disclosure::NoSecrets => redact_secrets(value),
    }
}

/// The same [`Appliance`] with its secrets replaced down to `level`.
///
/// Through JSON and back without validation: a redacted WireGuard key is not a
/// key, so the result would not validate — and it is never meant to. It exists
/// to be *rendered*, by the same renderers the full document goes through, so
/// every view that prints the configuration prints the marker in the same
/// place, rather than each renderer learning which of its lines are secret.
pub fn appliance(a: &Appliance, level: Disclosure) -> Result<Appliance> {
    if level == Disclosure::Full {
        return Ok(a.clone());
    }
    let mut value = serde_json::to_value(a).context("serialising the configuration")?;
    redact_value(&mut value, level);
    serde_json::from_value(value).context("re-reading the redacted configuration")
}

/// Put back the machine credential a reader was not shown.
///
/// A read-write account edits the full document with the machine credential
/// replaced by [`REDACTED`]; when that document comes back, the marker means
/// "unchanged", not "set the credential to this word". Any other value is a
/// deliberate change and is kept.
pub fn restore_machine_credential(candidate: &mut Value, current: &Value) {
    for path in MACHINE_CREDENTIALS {
        let Some(slot) = pointer_mut(candidate, path) else {
            continue;
        };
        if slot.as_str() != Some(REDACTED) {
            continue;
        }
        match pointer(current, path) {
            Some(original) => *slot = original.clone(),
            // There was no credential to keep, and the marker is not one
            // either: the field goes, as if it had never been written.
            None => {
                let (field, parent) = path.split_last().expect("a non-empty path");
                if let Some(Value::Object(map)) = pointer_mut(candidate, parent) {
                    map.remove(*field);
                }
            }
        }
    }
}

/// Every secret string in `a`, longest first — what [`scrub_text`] looks for in
/// text that did not come through a renderer this module controls.
pub fn secret_values(a: &Appliance) -> Vec<String> {
    let mut out = every_secret_value(a);
    // Short values are left alone: a five-digit SIM PIN would otherwise turn
    // every matching number in a counter column into the marker, and a short
    // secret is not what this net is for — it catches the long shared
    // credentials.
    out.retain(|s| s.len() >= SCRUB_MIN_LEN);
    out
}

/// Every secret string in `a`, however short, longest first.
pub(crate) fn every_secret_value(a: &Appliance) -> Vec<String> {
    fn collect(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (k, v) in map {
                    match v {
                        Value::String(s) if SECRET_FIELDS.contains(&k.as_str()) => {
                            out.push(s.clone())
                        }
                        _ => collect(v, out),
                    }
                }
            }
            Value::Array(items) => items.iter().for_each(|v| collect(v, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    if let Ok(value) = serde_json::to_value(a) {
        collect(&value, &mut out);
    }
    out.retain(|s| !s.is_empty() && s != REDACTED);
    out.sort_by_key(|s| std::cmp::Reverse(s.len()));
    out.dedup();
    out
}

/// The shortest secret [`scrub_text`] will look for.
const SCRUB_MIN_LEN: usize = 8;

/// Replace every occurrence of any of `secrets` in `text` with [`REDACTED`].
///
/// A second net for text this appliance did not render — a peer's `show`
/// output. An HA pair shares most of its secrets, the config-sync credential
/// first among them, so scrubbing a peer's answer of *this* box's secrets
/// catches what a peer too old to honour the redaction request would print.
pub fn scrub_text(text: &str, secrets: &[String]) -> String {
    let mut out = text.to_string();
    for secret in secrets {
        if out.contains(secret.as_str()) {
            out = out.replace(secret.as_str(), REDACTED);
        }
    }
    out
}

fn pointer<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(value, |v, key| v.get(*key))
}

fn pointer_mut<'a>(value: &'a mut Value, path: &[&str]) -> Option<&'a mut Value> {
    path.iter().try_fold(value, |v, key| v.get_mut(*key))
}

/// A saved configuration with a distinct, recognisable value in every
/// secret-bearing field the model has — built through the CLI grammar, so it is
/// a configuration an operator could really have, and validated by the save.
#[cfg(test)]
pub(crate) fn every_secret_fixture(path: &std::path::Path) -> Appliance {
    let _ = std::fs::remove_file(path);
    let mut session = crate::session::Session::load(path).expect("empty session");
    for line in EVERY_SECRET {
        let words: Vec<&str> = line.split_whitespace().collect();
        session
            .set(&words)
            .unwrap_or_else(|e| panic!("fixture line {line:?}: {e:#}"));
    }
    session.save(Some(path)).expect("the fixture validates");
    Appliance::load(path).expect("the fixture loads")
}

/// The lines [`every_secret_fixture`] is built from. Every secret value is its
/// own and appears nowhere else in the configuration, so a test can look for
/// each one in output and name the field that leaked.
#[cfg(test)]
const EVERY_SECRET: &[&str] = &[
    "system hostname fixture",
    "interface eth0 zone lan",
    "interface eth0 address 10.0.0.1/24",
    "interface eth1 zone wan",
    "interface eth1 address 198.51.100.2/24",
    "firewall zone lan default-action accept",
    "firewall zone wan default-action drop",
    // Accounts.
    "system group ops permission read-write",
    "system login vera group ops",
    "system group viewers permission read-only",
    "system login viewer group viewers",
    "system login vera hashed-password $6$zqsaltzq$zqHashedPasswordValueThatIsLongEnoughzq",
    "system login vera totp GEZDGNBVGY3TQOJQZQZQGEZDGNBVGY3T",
    "system aaa radius 10.0.0.9 secret zq-radius-secret",
    "system aaa tacacs 10.0.0.10 secret zq-tacacs-secret",
    // The machine credential, twice over.
    "system config-sync peer 10.0.0.2",
    "system config-sync secret zq-machine-credential-0123456789abcdef",
    "system ha-witness listen 10.0.0.3:5440",
    "system ha-witness secret zq-witness-credential-0123456789abcdefghij",
    // Fleet and update entitlements.
    "fleet controller-url https://fleet.example",
    "fleet node-id sentinel-test",
    "fleet enrollment-token zq-fleet-enrollment",
    "fleet ca-certificate /etc/fleet/ca.pem",
    "fleet client-certificate /etc/fleet/client.pem",
    "fleet client-key /etc/fleet/client.key",
    "fleet signing-key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "update channel t1 url https://updates.example.test/chan",
    "update channel t1 public-key file:/tmp/zq-walker.pem",
    "update channel t1 subscription-key zq-subscription-key",
    // Services.
    "services snmp community zq-snmp-community",
    "services dyndns hostname h.example.com",
    "services dyndns password zq-dyndns-password",
    "services portal zone lan",
    "services portal passphrase zq-portal-passphrase",
    "services alerts mail to ops@example.com",
    "services alerts mail relay 10.0.0.25",
    "services alerts mail user alerts",
    "services alerts mail password zq-mail-password",
    "services pppoe-server user dialin password zq-pppoe-server-password",
    // Routing.
    "protocols ospf auth-key zq-ospf",
    "protocols isis auth-key zq-isis-key",
    "protocols bfd auth-key zq-bfd-key",
    "protocols bgp local-as 65001",
    "protocols bgp router-id 10.0.0.1",
    "protocols bgp neighbor 10.0.0.20 remote-as 65002",
    "protocols bgp neighbor 10.0.0.20 password zq-bgp-md5",
    "protocols bgp neighbor 10.0.0.20 bfd-auth-key zq-bgp-bfd",
    "protocols bgp neighbor 10.0.0.21 remote-as 65002",
    "protocols bgp neighbor 10.0.0.21 ao-key zq-bgp-ao-key",
    // Links.
    "interface eth2 type macsec",
    "interface eth2 parent eth1",
    "interface eth1 mac 02:00:00:00:00:11",
    "interface eth2 macsec-key 5ec2e75ec2e75ec2e75ec2e75ec2e7ab",
    "interface eth2 macsec-peer 02:00:00:00:00:22",
    "interface eth3 type wwan",
    "interface eth3 wwan apn internet",
    "interface eth3 address dhcp",
    "interface eth3 wwan username mobile",
    "interface eth3 wwan password zq-wwan-password",
    "interface eth3 wwan pin 97531",
    "interface eth4 type wireless",
    "interface eth4 wireless mode access-point",
    "interface eth4 wireless ssid velstra",
    "interface eth4 wireless wpa passphrase zq-wifi-passphrase",
    "interface eth4 wireless country DE",
    "interface eth6 zone wan",
    "interface ppp0 type pppoe",
    "interface ppp0 parent eth6",
    "interface ppp0 pppoe username isp",
    "interface ppp0 pppoe password zq-pppoe-password",
    // VPNs.
    "vpn ipsec tun1 local 198.51.100.2",
    "vpn ipsec tun1 remote 198.51.100.9",
    "vpn ipsec tun1 psk zq-ipsec-psk",
    "vpn ipsec tun1 local-subnet 10.0.0.0/24",
    "vpn ipsec tun1 remote-subnet 10.9.0.0/24",
    "interface wg0 type wireguard",
    "interface wg0 zone lan",
    "vpn wireguard wg0 private-key zqzqzqzqzqzqzqzqzqzqzqzqzqzqzqzqzqzqzqzqzqw=",
    "vpn wireguard wg0 peer d0JCPLcS8bXlwuA6xdaHrqLdEeQz9M+xUsHhVJnEbn0= allowed-ips 10.8.0.2/32",
    "vpn wireguard wg0 peer d0JCPLcS8bXlwuA6xdaHrqLdEeQz9M+xUsHhVJnEbn0= preshared-key ZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQZQw=",
    "pki ca ca1 common-name test-ca",
    "pki certificate crt1 ca ca1",
    "pki certificate crt1 common-name host.example.com",
    "vpn openconnect pool 10.99.0.0/24",
    "vpn openconnect certificate crt1",
    "vpn openconnect user alice password zq-openconnect-password",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Which of `secrets` appear in `text`.
    fn leaked(text: &str, secrets: &[String]) -> Vec<String> {
        secrets
            .iter()
            .filter(|s| text.contains(s.as_str()))
            .cloned()
            .collect()
    }

    #[test]
    fn a_disclosure_from_the_environment_fails_closed() {
        assert_eq!(Disclosure::from_env_value(None), Disclosure::Full);
        for level in [Disclosure::NoMachineCredential, Disclosure::NoSecrets] {
            let v = level.env_value().map(OsStr::new);
            assert_eq!(Disclosure::from_env_value(v), level);
        }
        for odd in ["", "none", "full", "Secrets", "machine-credential "] {
            assert_eq!(
                Disclosure::from_env_value(Some(OsStr::new(odd))),
                Disclosure::NoSecrets,
                "{odd:?} widened what is shown"
            );
        }
    }

    #[test]
    fn who_is_asking_decides_what_is_disclosed() {
        use Permission::*;
        assert_eq!(Disclosure::for_caller(None, ReadWrite), Disclosure::Full);
        assert_eq!(
            Disclosure::for_caller(Some("vera"), ReadWrite),
            Disclosure::NoMachineCredential
        );
        assert_eq!(
            Disclosure::for_caller(Some("viewer"), ReadOnly),
            Disclosure::NoSecrets
        );
    }

    /// The fixture really does reach every secret field the model has: every
    /// name in [`SECRET_FIELDS`] that the configuration uses appears in it with
    /// a value. A new secret field fails here until the fixture sets it, which
    /// is what keeps the redaction tests below honest.
    #[test]
    fn the_fixture_sets_every_secret_field_the_model_has() {
        let dir = std::env::temp_dir().join(format!("sentinel-redact-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = every_secret_fixture(&dir.join("fixture.toml"));
        let value = serde_json::to_value(&a).unwrap();
        let mut seen = std::collections::BTreeSet::new();
        fn names(value: &Value, seen: &mut std::collections::BTreeSet<String>) {
            match value {
                Value::Object(map) => {
                    for (k, v) in map {
                        if v.is_string() && SECRET_FIELDS.contains(&k.as_str()) {
                            seen.insert(k.clone());
                        }
                        names(v, seen);
                    }
                }
                Value::Array(items) => items.iter().for_each(|v| names(v, seen)),
                _ => {}
            }
        }
        names(&value, &mut seen);
        // The witness `key` and the legacy witness `secret` are mutually
        // exclusive (`ha::validate`), and the fixture keeps the `secret`
        // because it is a machine credential; the key has its own test,
        // `a_witness_key_is_a_secret_but_not_a_machine_credential`.
        for field in model_secret_fields().into_iter().filter(|f| f != "key") {
            assert!(
                seen.contains(&field),
                "the fixture sets no {field:?}; add it so its redaction is tested"
            );
        }
        // Every value is its own, so a leak names exactly one field.
        let secrets = every_secret_value(&a);
        let distinct: std::collections::BTreeSet<_> = secrets.iter().collect();
        assert_eq!(distinct.len(), secrets.len(), "{secrets:?}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Every view `show` renders the configuration through, at the read-only
    /// level, carries none of the fixture's secrets — and at the read-write
    /// account level carries all of them except the machine credential.
    #[test]
    fn every_rendered_view_withholds_what_the_caller_may_not_see() {
        let dir =
            std::env::temp_dir().join(format!("sentinel-redact-views-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = every_secret_fixture(&dir.join("fixture.toml"));
        let secrets = every_secret_value(&a);
        assert!(secrets.len() >= 25, "{secrets:?}");
        let views = |a: &Appliance| {
            let mut all = String::new();
            all.push_str(&crate::session::render_appliance(a));
            for line in crate::session::flatten_config(&crate::session::render_appliance(a)) {
                all.push_str(&line);
                all.push('\n');
            }
            all.push_str(&crate::session::render_appliance_for_reading(a));
            all.push_str(&a.summary());
            all
        };
        // The unredacted views do print them — otherwise this proves nothing.
        let full = views(&appliance(&a, Disclosure::Full).unwrap());
        let unprinted: Vec<_> = secrets
            .iter()
            .filter(|s| !full.contains(s.as_str()))
            .collect();
        assert!(
            unprinted.is_empty(),
            "the full view should print every secret: {unprinted:?}"
        );

        let read_only = views(&appliance(&a, Disclosure::NoSecrets).unwrap());
        assert_eq!(leaked(&read_only, &secrets), Vec::<String>::new());
        assert!(read_only.contains(REDACTED));

        let account = views(&appliance(&a, Disclosure::NoMachineCredential).unwrap());
        let shown = leaked(&account, &secrets);
        for credential in [
            "zq-machine-credential-0123456789abcdef",
            "zq-witness-credential-0123456789abcdefghij",
        ] {
            assert!(!shown.iter().any(|s| s == credential), "{credential} shown");
        }
        assert!(shown.iter().any(|s| s == "zq-ipsec-psk"), "{shown:?}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_redacted_machine_credential_written_back_means_unchanged() {
        let current = serde_json::json!({"system":{"config-sync":{"secret":"real"}}});
        let mut same = serde_json::json!({"system":{"config-sync":{"secret":REDACTED}}});
        restore_machine_credential(&mut same, &current);
        assert_eq!(same["system"]["config-sync"]["secret"], "real");
        let mut changed = serde_json::json!({"system":{"config-sync":{"secret":"new"}}});
        restore_machine_credential(&mut changed, &current);
        assert_eq!(changed["system"]["config-sync"]["secret"], "new");
        let mut invented = serde_json::json!({"system":{"ha-witness":{"secret":REDACTED}}});
        restore_machine_credential(&mut invented, &current);
        assert_eq!(invented, serde_json::json!({"system":{"ha-witness":{}}}));
    }

    #[test]
    fn scrubbing_replaces_long_secrets_and_leaves_short_ones() {
        let secrets = vec!["shared-credential-xyz".to_string()];
        assert_eq!(
            scrub_text("token shared-credential-xyz end", &secrets),
            format!("token {REDACTED} end")
        );
        let a = Appliance::from_toml(
            "[system]\nhostname=\"x\"\n[system.config-sync]\npeer=[\"10.0.0.2\"]\nsecret=\"shared-credential-xyz\"\n",
        )
        .unwrap();
        assert_eq!(secret_values(&a), secrets);
    }

    /// Field names in the configuration model that look like secrets but are
    /// not, each with the reason. Everything else that looks like a secret must
    /// be in [`SECRET_FIELDS`].
    const NOT_SECRET: &[(&str, &str)] = &[
        ("public-key", "a public key is published by definition"),
        ("ssh-key", "an authorized SSH *public* key"),
        ("signing-key", "the fleet controller's Ed25519 *public* key"),
        (
            "client-key",
            "a file path; the key itself stays in the file",
        ),
        ("tls-key", "a file path; the key itself stays in the file"),
        ("key-type", "the algorithm name (ec/rsa)"),
        ("auth-key-id", "a numeric key identifier, not the key"),
        ("ao-key-id", "a numeric key identifier, not the key"),
        ("bfd-auth-key-id", "a numeric key identifier, not the key"),
        ("tunnel-key", "the GRE key's Rust name; serialised as `key`"),
        ("vti-key", "the VTI mark: a u32 demultiplexer, not a secret"),
        (
            "password-authentication",
            "a switch: whether SSH accepts passwords",
        ),
        ("large-community", "BGP route tags"),
        ("ext-community", "BGP route tags"),
        ("set-community", "BGP route tags"),
        ("add-community", "BGP route tags"),
        ("set-large-community", "BGP route tags"),
        ("add-large-community", "BGP route tags"),
        ("set-ext-community", "BGP route tags"),
        ("add-ext-community", "BGP route tags"),
        ("auth-type", "the algorithm name, not the key"),
        ("bfd-auth-type", "the algorithm name, not the key"),
        ("auth-replay-protection", "a switch"),
        ("keyboard", "a keymap name"),
    ];

    fn looks_secret(name: &str) -> bool {
        const WORDS: &[&str] = &[
            "key",
            "secret",
            "password",
            "passphrase",
            "psk",
            "token",
            "totp",
            "community",
            "pin",
            "auth",
            "credential",
        ];
        name.split('-').any(|part| WORDS.contains(&part)) || name.starts_with("key")
    }

    /// The serialised name of every field in the configuration model, read off
    /// the model's source: an explicit `rename = "…"` where there is one, the
    /// kebab-case spelling of the field otherwise. An over-approximation (it
    /// also lists fields of types that are never serialised), which is the safe
    /// direction for a guard.
    fn model_field_names() -> std::collections::BTreeSet<String> {
        let source = include_str!("config.rs");
        let mut names = std::collections::BTreeSet::new();
        for line in source.lines() {
            let line = line.trim();
            if let Some(rest) = line.split("rename = \"").nth(1) {
                if let Some(name) = rest.split('"').next() {
                    names.insert(name.to_string());
                }
            }
            if let Some(field) = line
                .strip_prefix("pub ")
                .and_then(|r| r.split_once(':'))
                .map(|(f, _)| f.trim())
                .filter(|f| {
                    f.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                })
                .filter(|f| !f.is_empty())
            {
                names.insert(field.replace('_', "-"));
            }
        }
        names
    }

    /// The model's secret-looking field names that are not argued away in
    /// [`NOT_SECRET`] — what the fixture must populate.
    fn model_secret_fields() -> Vec<String> {
        model_field_names()
            .into_iter()
            .filter(|n| looks_secret(n))
            .filter(|n| !NOT_SECRET.iter().any(|(k, _)| k == n))
            .collect()
    }

    /// The guard that would have caught `auth-key`, `bfd-auth-key` and
    /// `macsec-key` going out through `/config` in clear: every field the model
    /// has whose name says "secret" is either redacted or on [`NOT_SECRET`]
    /// with a reason.
    #[test]
    fn every_secret_looking_field_is_redacted_or_argued_harmless() {
        let names = model_field_names();
        assert!(names.contains("hashed-password") && names.contains("macsec-key"));
        let unguarded: Vec<String> = model_secret_fields()
            .into_iter()
            .filter(|n| !SECRET_FIELDS.contains(&n.as_str()))
            .collect();
        assert!(
            unguarded.is_empty(),
            "secret-looking config fields neither redacted nor allow-listed: {unguarded:?}"
        );
        // And the allow-list carries nothing stale that hides a real secret.
        for (name, _) in NOT_SECRET {
            assert!(
                !SECRET_FIELDS.contains(name),
                "{name} is both redacted and allow-listed"
            );
        }
    }

    #[test]
    fn a_witness_key_is_a_secret_but_not_a_machine_credential() {
        let key = "f00dfeed".repeat(8);
        let mut value = serde_json::json!({
            "system": {"ha-witness": {"key": key, "cluster": "c-0123456789"}},
            "tunnel": [{"key": 7}],
        });
        let mut account = value.clone();
        redact_value(&mut account, Disclosure::NoMachineCredential);
        assert_eq!(account["system"]["ha-witness"]["key"], key.as_str());
        redact_value(&mut value, Disclosure::NoSecrets);
        assert_eq!(value["system"]["ha-witness"]["key"], REDACTED);
        // The numeric GRE key shares the name and is no secret.
        assert_eq!(value["tunnel"][0]["key"], 7);
    }
}
