//! C19 — **ACME issuance**: turning the `[pki.acme]` account descriptor into
//! certificates a browser will actually accept.
//!
//! The local CA ([`crate::pki`]) is right for a VPN, where both ends are ours.
//! It is useless for anything a person points a browser at — the management API,
//! the reverse proxy — because nothing trusts it. That is what ACME is for, and
//! until now Sentinel rendered the account and stopped.
//!
//! ## Issuance is a job, not part of a commit
//!
//! Obtaining a certificate talks to a server, waits for it to call back, and can
//! fail for reasons that have nothing to do with the config (DNS not pointing
//! here yet, port 80 unreachable, the directory down). Doing that inside `commit`
//! would make a commit slow, occasionally fail for external reasons, and offer no
//! way to retry. So the commit renders what is needed and the work happens in
//! `sentinel-acme.service`, run by a timer — which is also what renewal is, so
//! issuance and renewal are the same code path rather than two.
//!
//! ## It ends up indistinguishable from a local cert
//!
//! An obtained certificate is installed into the same `certs/<name>/` store as a
//! CA-signed one, under the same filenames. Everything downstream — the reverse
//! proxy, the OpenConnect server, `show pki` — therefore never learns where a
//! certificate came from, which is the only way `ca = "acme"` can be a one-word
//! change in the config.
//!
//! The ACME protocol itself is [`lego`]'s job, pinned in the image like every
//! other daemon Sentinel drives. Writing an RFC 8555 client here would be a
//! second implementation of something already solved, with worse crypto review.
//!
//! [`lego`]: https://go-acme.github.io/lego/

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::config::{ACME_CA, Appliance, Pki};
use crate::system;

/// What the renewal job needs, rendered at apply time.
///
/// Rendered rather than read back from the saved appliance config for the reason
/// [`crate::ids`] documents: `commit` applies *before* `save` writes, and a
/// `commit` without a `save` never writes at all, so the job would work from the
/// previous configuration.
pub const ACME_CONF: &str = "/run/sentinel/acme.toml";

/// The unit that performs issuance and renewal.
pub const ACME_UNIT: &str = "sentinel-acme.service";
/// The timer that runs it.
pub const ACME_TIMER: &str = "sentinel-acme.timer";

/// lego's own state — the account key, its registration, and the certificates it
/// obtained. On the persistent partition: losing the account key means
/// re-registering, and losing the certificates means asking a rate-limited
/// service for them again.
const ACME_STATE: &str = "/var/lib/sentinel/pki/acme/lego";

/// Renew this many days before expiry. 30 is the interval Let's Encrypt's own
/// guidance assumes, and it leaves room for a fortnight of failures before
/// anything is actually at risk.
const RENEW_BEFORE_DAYS: u32 = 30;

/// One certificate to obtain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcmeCert {
    /// The store name — `certs/<name>/`, where the result is installed.
    pub name: String,
    /// The names to certify: the common name first, then any subject-alt-names.
    pub domains: Vec<String>,
}

/// The renewal job's whole configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcmeConfig {
    pub directory_url: String,
    pub email: String,
    #[serde(default, rename = "certificate")]
    pub certificates: Vec<AcmeCert>,
}

/// The DNS names a certificate covers: its common name, plus every `DNS:` entry
/// in its subject-alt-names.
///
/// `IP:` entries are dropped rather than passed on: a public CA cannot certify an
/// address over HTTP-01, and handing lego one would fail the whole order —
/// including the names that were fine.
fn domains(cert: &crate::config::Certificate) -> Vec<String> {
    let mut out = vec![cert.common_name.clone()];
    for san in &cert.subject_alt_names {
        if let Some(name) = san.strip_prefix("DNS:") {
            if !out.iter().any(|d| d == name) {
                out.push(name.to_string());
            }
        }
    }
    out
}

/// Render the renewal job's config, or `None` when no ACME certificate is
/// declared (the timer is then stopped rather than run with nothing to obtain).
pub fn conf_body(pki: &Pki) -> Option<String> {
    let acme = pki.acme.as_ref()?;
    let certificates: Vec<AcmeCert> = pki
        .certificates
        .iter()
        .filter(|c| c.ca == ACME_CA)
        .map(|c| AcmeCert {
            name: c.name.clone(),
            domains: domains(c),
        })
        .collect();
    if certificates.is_empty() {
        return None;
    }
    let cfg = AcmeConfig {
        directory_url: acme
            .directory_url
            .clone()
            .unwrap_or_else(|| crate::config::DEFAULT_ACME_DIRECTORY.to_string()),
        email: acme.email.clone(),
        certificates,
    };
    let mut body = String::from("# rendered by sentinel — ACME issuance (do not edit)\n");
    body.push_str(&toml::to_string_pretty(&cfg).ok()?);
    Some(body)
}

/// Refuse an ACME setup that is well-formed but could never obtain a certificate.
///
/// The account's own shape — the address, the directory URL, a challenge name the
/// schema knows — is checked by `config::validate` before this runs. What is left
/// here is what *issuance* needs, and each of these would otherwise fail hours
/// later inside a timer, where nobody is looking.
///
/// All of it is conditional on a certificate actually asking for ACME: an account
/// declared ahead of the certificates that will use it is a reasonable state.
pub fn validate(pki: &Pki) -> Result<()> {
    let wants_acme = pki.certificates.iter().any(|c| c.ca == ACME_CA);
    let Some(acme) = &pki.acme else {
        return Ok(());
    };
    if !wants_acme {
        return Ok(());
    }
    // The protocol has no way to obtain a certificate without accepting the
    // terms; lego would refuse, in a timer, with nobody watching.
    if acme.agree_tos != Some(true) {
        bail!(
            "pki acme: issuance requires accepting the directory's terms of service \
             (`set pki acme agree-tos true`)"
        );
    }
    let challenge = acme.challenge.as_deref().unwrap_or("http-01");
    if challenge != "http-01" {
        bail!(
            "pki acme: challenge {challenge:?} cannot be used to issue — dns-01 needs \
             provider credentials Sentinel does not model, so accepting it here would \
             mean failing at renewal instead of now"
        );
    }
    for cert in pki.certificates.iter().filter(|c| c.ca == ACME_CA) {
        // An HTTP-01 challenge is fetched over a name. A public CA will not
        // certify an address, and the order would fail as a whole.
        if cert.common_name.parse::<std::net::IpAddr>().is_ok() {
            bail!(
                "pki certificate {:?}: {:?} is an address — an ACME certificate is issued \
                 for DNS names, which is what the http-01 challenge is fetched over",
                cert.name,
                cert.common_name
            );
        }
        if domains(cert).is_empty() {
            bail!("pki certificate {:?}: no DNS name to certify", cert.name);
        }
    }
    Ok(())
}

/// Render the config and bring the renewal timer into line with it.
pub fn apply(appliance: &Appliance) -> Result<()> {
    let path = Path::new(ACME_CONF);
    match conf_body(&appliance.pki) {
        Some(body) => {
            system::install_file(path, &body)?;
            // Start the timer, then ask for one run now: waiting for the timer's
            // first tick would mean a fresh box has no certificate for a day
            // while everything reports success.
            if let Err(e) = system::service_restart(ACME_TIMER) {
                eprintln!("warning: (re)starting {ACME_TIMER} failed: {e}");
            }
            if let Err(e) = system::service_start(ACME_UNIT) {
                eprintln!("warning: starting {ACME_UNIT} failed: {e}");
            }
        }
        None => {
            if system::unit_active(ACME_TIMER) {
                if let Err(e) = system::service_stop(ACME_TIMER) {
                    eprintln!("warning: stopping {ACME_TIMER}: {e}");
                }
            }
            if path.exists() {
                system::remove_file(path)?;
            }
        }
    }
    Ok(())
}

/// lego's output path for `domain`'s certificate and key.
fn lego_output(domain: &str) -> (PathBuf, PathBuf) {
    let dir = Path::new(ACME_STATE).join("certificates");
    // lego sanitises a wildcard into `_`; nothing else in a DNS name is touched.
    let stem = domain.replace('*', "_");
    (
        dir.join(format!("{stem}.crt")),
        dir.join(format!("{stem}.key")),
    )
}

/// Obtain or renew every declared certificate.
///
/// Each certificate is independent: one failing (a name that does not resolve
/// here yet, a directory that is down) must not stop the others, because the
/// common case for a partial failure is exactly one misconfigured name among
/// several working ones. Failures are reported and the job exits non-zero, so the
/// unit is failed and — like every other Sentinel unit — that is what raises an
/// alert.
pub fn run() -> Result<()> {
    let text =
        std::fs::read_to_string(ACME_CONF).with_context(|| format!("reading {ACME_CONF}"))?;
    let cfg: AcmeConfig = toml::from_str(&text).with_context(|| format!("parsing {ACME_CONF}"))?;
    if cfg.certificates.is_empty() {
        return Ok(());
    }
    // lego keeps the account key here, so the directory must not be readable by
    // anyone who is not root.
    system::ensure_dir_mode(Path::new(ACME_STATE), "0700")?;

    let mut failed = Vec::new();
    for cert in &cfg.certificates {
        if let Err(e) = obtain(&cfg, cert) {
            eprintln!("acme: {}: {e:#}", cert.name);
            failed.push(cert.name.clone());
        }
    }
    if !failed.is_empty() {
        bail!("could not obtain: {}", failed.join(", "));
    }
    Ok(())
}

/// Obtain (or renew) one certificate and install it into the PKI store.
fn obtain(cfg: &AcmeConfig, cert: &AcmeCert) -> Result<()> {
    let (out_crt, out_key) = lego_output(&cert.domains[0]);
    let mut args: Vec<String> = vec![
        "--accept-tos".into(),
        "--server".into(),
        cfg.directory_url.clone(),
        "--email".into(),
        cfg.email.clone(),
        "--path".into(),
        ACME_STATE.into(),
        // lego serves the challenge itself on :80. The alternative is writing
        // into somebody else's webroot, which means Sentinel would have to own a
        // web server just to hold a file for ten seconds.
        "--http".into(),
        "--http.port".into(),
        ":80".into(),
    ];
    for domain in &cert.domains {
        args.push("--domains".into());
        args.push(domain.clone());
    }
    // `renew` on an existing certificate and `run` on a new one. lego treats the
    // wrong one as an error rather than doing the obvious thing, so the choice is
    // made from what is on disk.
    if out_crt.exists() {
        args.push("renew".into());
        args.push("--days".into());
        args.push(RENEW_BEFORE_DAYS.to_string());
    } else {
        args.push("run".into());
    }

    let out = std::process::Command::new(system::bin("lego"))
        .args(&args)
        .output()
        .context("running lego")?;
    if !out.status.success() {
        // lego says why on stderr; passing it through is the difference between
        // "renewal failed" and knowing that a name does not resolve here.
        bail!(
            "lego {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    if !out_crt.exists() {
        bail!(
            "lego reported success but wrote no certificate at {}",
            out_crt.display()
        );
    }
    install(cert, &out_crt, &out_key)
}

/// Copy an obtained certificate into `certs/<name>/`, where everything else
/// already looks for a certificate — the key at 0600, the certificate readable.
fn install(cert: &AcmeCert, crt: &Path, key: &Path) -> Result<()> {
    let (dst_crt, dst_key) = crate::pki::leaf_paths(&cert.name);
    let dir = dst_crt
        .parent()
        .context("certificate store path has no parent")?;
    system::ensure_dir_mode(dir, "0700")?;
    let crt_body =
        std::fs::read_to_string(crt).with_context(|| format!("reading {}", crt.display()))?;
    let key_body =
        std::fs::read_to_string(key).with_context(|| format!("reading {}", key.display()))?;
    // The key goes down first and stays 0600; the certificate is public, and the
    // directory relaxes only once the key inside it is locked — the same order
    // `pki::generate_leaf` uses, for the same reason.
    system::install_private_file(&dst_key, &key_body)?;
    system::install_file(&dst_crt, &crt_body)?;
    system::ensure_dir_mode(dir, "0755")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Acme, Certificate};

    fn cert(name: &str, ca: &str, cn: &str, sans: &[&str]) -> Certificate {
        Certificate {
            name: name.into(),
            ca: ca.into(),
            common_name: cn.into(),
            subject_alt_names: sans.iter().map(|s| s.to_string()).collect(),
            key_type: None,
            usage: None,
            validity_days: None,
        }
    }

    /// A `Pki` with an account and the given certificates.
    fn pki(acme: Option<Acme>, certs: Vec<Certificate>) -> Pki {
        Pki {
            acme,
            certificates: certs,
            ..Default::default()
        }
    }

    fn account() -> Acme {
        Acme {
            email: "admin@example.com".into(),
            directory_url: None,
            challenge: None,
            agree_tos: Some(true),
        }
    }

    #[test]
    fn nothing_is_rendered_without_an_acme_certificate() {
        assert!(
            conf_body(&pki(Some(account()), vec![])).is_none(),
            "an account alone has nothing to obtain"
        );
        let local = pki(
            Some(account()),
            vec![cert("vpn", "corp-ca", "vpn.example.com", &[])],
        );
        assert!(
            conf_body(&local).is_none(),
            "a locally-signed certificate is not an ACME one"
        );
    }

    #[test]
    fn the_job_is_told_every_name_the_certificate_covers() {
        let p = pki(
            Some(account()),
            vec![cert(
                "web",
                ACME_CA,
                "fw.example.com",
                &["DNS:vpn.example.com", "IP:10.0.0.1"],
            )],
        );
        let cfg: AcmeConfig = toml::from_str(&conf_body(&p).unwrap()).unwrap();
        assert_eq!(cfg.certificates.len(), 1);
        // The address is dropped: a public CA will not certify one over http-01,
        // and passing it would fail the order including the names that were fine.
        assert_eq!(
            cfg.certificates[0].domains,
            ["fw.example.com", "vpn.example.com"]
        );
        assert_eq!(cfg.directory_url, crate::config::DEFAULT_ACME_DIRECTORY);
    }

    #[test]
    fn an_account_declared_before_its_certificates_is_fine() {
        // Setting up the account first and adding certificates later is an
        // ordinary way to work; nothing here should object to it.
        let acme = Acme {
            agree_tos: None,
            ..account()
        };
        validate(&pki(Some(acme), vec![])).unwrap();
    }

    #[test]
    fn issuance_without_agreeing_to_the_terms_is_refused_now_not_later() {
        let acme = Acme {
            agree_tos: None,
            ..account()
        };
        let p = pki(
            Some(acme),
            vec![cert("web", ACME_CA, "fw.example.com", &[])],
        );
        let err = validate(&p).unwrap_err();
        assert!(err.to_string().contains("terms of service"), "{err}");
    }

    #[test]
    fn an_unsupported_challenge_is_refused_rather_than_failing_in_a_timer() {
        let acme = Acme {
            challenge: Some("dns-01".into()),
            ..account()
        };
        let p = pki(
            Some(acme),
            vec![cert("web", ACME_CA, "fw.example.com", &[])],
        );
        let err = validate(&p).unwrap_err();
        assert!(err.to_string().contains("dns-01"), "{err}");
    }

    #[test]
    fn an_address_cannot_be_certified() {
        let p = pki(Some(account()), vec![cert("web", ACME_CA, "10.0.0.1", &[])]);
        let err = validate(&p).unwrap_err();
        assert!(err.to_string().contains("is an address"), "{err}");
    }

    #[test]
    fn a_purely_local_pki_is_left_alone() {
        validate(&pki(None, vec![cert("vpn", "corp-ca", "vpn.lan", &[])])).unwrap();
    }

    #[test]
    fn a_wildcard_maps_to_legos_filename() {
        let (crt, key) = lego_output("*.example.com");
        assert!(crt.ends_with("_.example.com.crt"), "{}", crt.display());
        assert!(key.ends_with("_.example.com.key"), "{}", key.display());
    }
}
