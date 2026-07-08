//! Built-in public-key infrastructure (roadmap C19).
//!
//! Two capabilities, one config tree (`[pki]`):
//!   * a local **certificate authority** (`[[pki.ca]]`) — self-signed, used to
//!     issue certs for the VPN / management plane; and
//!   * **issued leaf certificates** (`[[pki.certificate]]`) — signed either by a
//!     local CA or (`ca = "acme"`) obtained from an ACME directory (`[pki.acme]`).
//!
//! On an immutable appliance, key material is not part of the image: it is a
//! **runtime action** that writes to the persistent `/var/lib/sentinel/pki`
//! store (the same discipline the WireGuard key derivation uses — see
//! [`crate::wgkey`]). Generation shells out to the pinned `openssl` (via
//! [`crate::system::openssl`], run privileged so a leaf can be signed with a
//! 0600 CA key). It is **idempotent**: an existing CA/cert is never regenerated,
//! so its serial and fingerprint are stable across commits and reboots.
//!
//! Live ACME issuance needs external reachability (an HTTP-01 / DNS-01 challenge)
//! and is deferred to hardware; here the account descriptor is rendered so the
//! config round-trips and the wiring is in place.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::config::{
    ACME_CA, Acme, Appliance, Ca, Certificate, DEFAULT_ACME_DIRECTORY, DEFAULT_CA_VALIDITY_DAYS,
    DEFAULT_CERT_VALIDITY_DAYS, DEFAULT_PKI_KEY_TYPE, Pki,
};
use crate::net::ApplyMode;
use crate::system;

/// The persistent PKI store — CAs under `ca/<name>/`, leaf certs under
/// `certs/<name>/`, the ACME descriptor under `acme/`.
const PKI_DIR: &str = "/var/lib/sentinel/pki";
/// tmpfs scratch for the non-secret CSR + extension file used while signing a
/// leaf (re-created each apply, cleaned up after).
const PKI_STAGE_DIR: &str = "/run/sentinel/pki-stage";
/// The CA key / cert filenames within `ca/<name>/`.
const CA_KEY: &str = "ca.key";
const CA_CRT: &str = "ca.crt";
/// The leaf key / cert filenames within `certs/<name>/`.
const CERT_KEY: &str = "cert.key";
const CERT_CRT: &str = "cert.crt";

/// The store directory for the local CA `name`.
fn ca_dir(name: &str) -> PathBuf {
    Path::new(PKI_DIR).join("ca").join(name)
}

/// The store directory for the leaf certificate `name`.
fn cert_dir(name: &str) -> PathBuf {
    Path::new(PKI_DIR).join("certs").join(name)
}

/// The on-disk `(certificate, private-key)` paths for the issued leaf `name` —
/// the TLS identity another daemon (e.g. the OpenConnect server) serves. The
/// files are written by [`apply`]; the caller must handle their possible
/// absence (a not-yet-issued cert) rather than assume they exist.
pub fn leaf_paths(name: &str) -> (PathBuf, PathBuf) {
    let dir = cert_dir(name);
    (dir.join(CERT_CRT), dir.join(CERT_KEY))
}

/// A path as `&str`, or a clear error for a non-UTF-8 path (never expected for
/// our fixed store layout, but openssl args must be UTF-8).
fn p(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("non-UTF-8 path {}", path.display()))
}

/// Reconcile the PKI store to `appliance.pki`. The ACME account descriptor is a
/// pure file render (no key material, no network), safe in both `Boot` and
/// `Live`. CA / leaf **generation** happens on a live commit only: the material
/// is durable state on the persistent partition (it survives reboot), and
/// generation is privileged, which `ApplyMode::Boot` forbids. Generation is
/// idempotent — an existing CA/cert is never regenerated.
pub fn apply(appliance: &Appliance, mode: ApplyMode) -> Result<()> {
    let pki = &appliance.pki;
    render_acme(pki)?;
    if mode == ApplyMode::Live {
        for ca in &pki.cas {
            generate_ca(ca)?;
        }
        for cert in &pki.certificates {
            if cert.ca != ACME_CA {
                generate_leaf(cert)?;
            }
        }
    }
    Ok(())
}

/// Generate a self-signed CA into `ca/<name>/` if it does not already exist. The
/// key is written into a **0700** directory (no world-readable window), then
/// locked to 0600 while the cert becomes 0644 and the directory relaxes to 0755
/// (so a later commit can stat the cert for the idempotency check).
fn generate_ca(ca: &Ca) -> Result<()> {
    let dir = ca_dir(&ca.name);
    let crt = dir.join(CA_CRT);
    if crt.exists() {
        // Never regenerate an existing CA — its serial/fingerprint stays stable.
        return Ok(());
    }
    system::ensure_dir_mode(&dir, "0700")?;
    let key = dir.join(CA_KEY);
    gen_key(&key, ca.key_type.as_deref())?;
    let days = ca
        .validity_days
        .unwrap_or(DEFAULT_CA_VALIDITY_DAYS)
        .to_string();
    let subj = subject(&ca.common_name, ca.organization.as_deref());
    system::openssl(&[
        "req",
        "-x509",
        "-new",
        "-key",
        p(&key)?,
        "-sha256",
        "-days",
        &days,
        "-subj",
        &subj,
        "-out",
        p(&crt)?,
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    ])?;
    finalize(&dir, &key, &crt)
}

/// Generate a CA-signed leaf into `certs/<name>/` if it does not already exist.
/// The CSR + extension file are staged on tmpfs; the leaf is signed with the
/// referenced CA's key (which validation guarantees is a declared local CA, and
/// which `apply` generates before any leaf).
fn generate_leaf(cert: &Certificate) -> Result<()> {
    let dir = cert_dir(&cert.name);
    let crt = dir.join(CERT_CRT);
    if crt.exists() {
        return Ok(());
    }
    let cadir = ca_dir(&cert.ca);
    let ca_crt = cadir.join(CA_CRT);
    let ca_key = cadir.join(CA_KEY);
    if !ca_crt.exists() {
        bail!(
            "pki certificate {:?}: signing CA {:?} has not been generated",
            cert.name,
            cert.ca
        );
    }
    system::ensure_dir_mode(&dir, "0700")?;
    let key = dir.join(CERT_KEY);
    gen_key(&key, cert.key_type.as_deref())?;

    let stage = Path::new(PKI_STAGE_DIR);
    system::ensure_dir(stage)?;
    let csr = stage.join(format!("{}.csr", cert.name));
    let ext = stage.join(format!("{}.ext", cert.name));
    system::install_file(&ext, &extfile_body(cert))?;
    let subj = subject(&cert.common_name, None);
    system::openssl(&[
        "req",
        "-new",
        "-key",
        p(&key)?,
        "-sha256",
        "-subj",
        &subj,
        "-out",
        p(&csr)?,
    ])?;
    let days = cert
        .validity_days
        .unwrap_or(DEFAULT_CERT_VALIDITY_DAYS)
        .to_string();
    let srl = cadir.join("ca.srl");
    system::openssl(&[
        "x509",
        "-req",
        "-in",
        p(&csr)?,
        "-CA",
        p(&ca_crt)?,
        "-CAkey",
        p(&ca_key)?,
        "-CAcreateserial",
        "-CAserial",
        p(&srl)?,
        "-sha256",
        "-days",
        &days,
        "-out",
        p(&crt)?,
        "-extfile",
        p(&ext)?,
    ])?;
    system::remove_file(&csr)?;
    system::remove_file(&ext)?;
    finalize(&dir, &key, &crt)
}

/// Generate a private key of the requested type (`ec` P-256 by default, or
/// `rsa` 3072-bit) at `path`.
fn gen_key(path: &Path, key_type: Option<&str>) -> Result<()> {
    match key_type.unwrap_or(DEFAULT_PKI_KEY_TYPE) {
        "rsa" => system::openssl(&[
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:3072",
            "-out",
            p(path)?,
        ]),
        // ec (default) and any already-validated value fall here.
        _ => system::openssl(&[
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            p(path)?,
        ]),
    }
}

/// Lock a freshly generated pair down: key 0600, cert 0644, and relax the
/// containing directory to 0755 so the cert is statable for future idempotency
/// checks (the key stays 0600, so it is never readable).
fn finalize(dir: &Path, key: &Path, crt: &Path) -> Result<()> {
    system::set_mode(key, "0600")?;
    system::set_mode(crt, "0644")?;
    system::set_mode(dir, "0755")?;
    Ok(())
}

/// The openssl `-subj` for a certificate: `/CN=<cn>` plus `/O=<org>` when an
/// organization is given. Every component has passed
/// [`crate::config::validate_subject_component`], so the string is injection-safe.
fn subject(cn: &str, org: Option<&str>) -> String {
    match org {
        Some(o) => format!("/CN={cn}/O={o}"),
        None => format!("/CN={cn}"),
    }
}

/// The x509 v3 extension file for a leaf: a non-CA cert with the usage-derived
/// extended key usage and the subject alternative names. Each SAN has passed
/// [`crate::config::validate_san`], so it is already a safe `DNS:`/`IP:` token.
fn extfile_body(cert: &Certificate) -> String {
    let eku = match cert.usage.as_deref() {
        Some("client") => "clientAuth",
        _ => "serverAuth",
    };
    let mut s =
        String::from("# rendered by sentinel — leaf certificate extensions (roadmap C19)\n");
    s.push_str("basicConstraints = CA:FALSE\n");
    s.push_str("keyUsage = critical, digitalSignature, keyEncipherment\n");
    s.push_str(&format!("extendedKeyUsage = {eku}\n"));
    if !cert.subject_alt_names.is_empty() {
        s.push_str(&format!(
            "subjectAltName = {}\n",
            cert.subject_alt_names.join(", ")
        ));
    }
    s
}

/// Render the ACME account descriptor to `acme/account.conf` when an account is
/// configured (removing a stale one otherwise). This is the deferred-to-hardware
/// wiring point: it records the directory / email / challenge and the
/// certificates to obtain, without hitting the ACME server.
fn render_acme(pki: &Pki) -> Result<()> {
    let path = Path::new(PKI_DIR).join("acme").join("account.conf");
    match &pki.acme {
        Some(acme) => {
            if let Some(parent) = path.parent() {
                system::ensure_dir(parent)?;
            }
            system::install_file(&path, &acme_descriptor(pki, acme))?;
        }
        None => system::remove_file(&path)?,
    }
    Ok(())
}

/// The body of the ACME account descriptor.
fn acme_descriptor(pki: &Pki, acme: &Acme) -> String {
    let mut s = String::from("# rendered by sentinel — ACME account (roadmap C19)\n");
    s.push_str("# Live issuance runs on hardware (needs external reachability); this\n");
    s.push_str("# descriptor records the account and the certificates to obtain.\n");
    s.push_str(&format!(
        "directory-url = {}\n",
        acme.directory_url
            .as_deref()
            .unwrap_or(DEFAULT_ACME_DIRECTORY)
    ));
    s.push_str(&format!("email = {}\n", acme.email));
    s.push_str(&format!(
        "challenge = {}\n",
        acme.challenge.as_deref().unwrap_or("http-01")
    ));
    s.push_str(&format!(
        "agree-tos = {}\n",
        acme.agree_tos.unwrap_or(false)
    ));
    for cert in &pki.certificates {
        if cert.ca == ACME_CA {
            let sans = if cert.subject_alt_names.is_empty() {
                String::new()
            } else {
                format!(" [{}]", cert.subject_alt_names.join(", "))
            };
            s.push_str(&format!(
                "certificate {} = {}{}\n",
                cert.name, cert.common_name, sans
            ));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(usage: Option<&str>, sans: &[&str]) -> Certificate {
        Certificate {
            name: "vpn".into(),
            ca: "corp".into(),
            common_name: "vpn.example.com".into(),
            subject_alt_names: sans.iter().map(|s| (*s).to_string()).collect(),
            key_type: None,
            usage: usage.map(str::to_string),
            validity_days: None,
        }
    }

    #[test]
    fn subject_includes_org_only_when_present() {
        assert_eq!(subject("host.example", None), "/CN=host.example");
        assert_eq!(
            subject("host.example", Some("Example Inc")),
            "/CN=host.example/O=Example Inc"
        );
    }

    #[test]
    fn extfile_defaults_to_server_auth_with_sans() {
        let body = extfile_body(&cert(None, &["DNS:vpn.example.com", "IP:10.0.0.1"]));
        assert!(body.contains("basicConstraints = CA:FALSE"), "{body}");
        assert!(body.contains("extendedKeyUsage = serverAuth"), "{body}");
        assert!(
            body.contains("subjectAltName = DNS:vpn.example.com, IP:10.0.0.1"),
            "{body}"
        );
    }

    #[test]
    fn extfile_client_usage_and_no_sans() {
        let body = extfile_body(&cert(Some("client"), &[]));
        assert!(body.contains("extendedKeyUsage = clientAuth"), "{body}");
        assert!(!body.contains("subjectAltName"), "{body}");
    }

    #[test]
    fn acme_descriptor_carries_account_and_acme_certs() {
        let pki = Pki {
            cas: vec![],
            certificates: vec![Certificate {
                ca: ACME_CA.into(),
                ..cert(None, &["DNS:www.example.com"])
            }],
            acme: Some(Acme {
                email: "admin@example.com".into(),
                directory_url: None,
                challenge: Some("http-01".into()),
                agree_tos: Some(true),
            }),
        };
        let body = acme_descriptor(&pki, pki.acme.as_ref().unwrap());
        assert!(body.contains("email = admin@example.com"), "{body}");
        assert!(body.contains("challenge = http-01"), "{body}");
        // Defaults to the Let's Encrypt production directory.
        assert!(body.contains(DEFAULT_ACME_DIRECTORY), "{body}");
        assert!(
            body.contains("certificate vpn = vpn.example.com [DNS:www.example.com]"),
            "{body}"
        );
    }

    #[test]
    fn store_paths_are_under_the_persistent_root() {
        assert_eq!(ca_dir("corp"), Path::new("/var/lib/sentinel/pki/ca/corp"));
        assert_eq!(
            cert_dir("vpn-server"),
            Path::new("/var/lib/sentinel/pki/certs/vpn-server")
        );
    }
}
