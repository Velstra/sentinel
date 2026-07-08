//! L7 reverse proxy / load balancer via HAProxy (roadmap C22).
//!
//! A `[[services.reverse-proxy]]` frontend terminates a listen port — optionally
//! with TLS from the on-box PKI ([`crate::pki`]) — and forwards to one or more
//! backends round-robin. Sentinel renders HAProxy's config to
//! `/run/sentinel/haproxy/haproxy.cfg` and, for each TLS frontend, a combined
//! cert+key PEM bundle to a 0600 file under `certs/`, then (re)starts the
//! `haproxy` systemd unit. This follows the same render + change-detect + reload
//! model the IPsec / OpenConnect / box-service appliers use: the config lives on
//! tmpfs, is re-seeded from the saved config each boot, and the daemon is only
//! (re)started when the rendered config changed — so an unrelated commit never
//! disturbs a live proxy. HAProxy's own `-c` check gates the reload, so a config
//! it would reject never replaces a working one.
//!
//! The XDP L4 load-balancer (fabric) is the separate high-throughput path; this
//! is the L7 tier that does TLS termination + HTTP-aware forwarding.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;

use crate::config::{Appliance, ReverseProxy};
use crate::system;

/// Runtime dir for the rendered HAProxy config + the per-frontend TLS bundles
/// (tmpfs; re-seeded each boot). Mode 0750 — the 0600 cert bundles (which hold
/// private keys) live under `certs/`.
const HAPROXY_RUNTIME_DIR: &str = "/run/sentinel/haproxy";
/// The rendered `haproxy.cfg`, read by the `haproxy` unit's `-f`.
const HAPROXY_CFG: &str = "/run/sentinel/haproxy/haproxy.cfg";
/// The subdir holding one `<name>.pem` cert+key bundle per TLS frontend (0600).
const HAPROXY_CERTS_DIR: &str = "/run/sentinel/haproxy/certs";
/// The systemd unit that runs `haproxy` from the rendered config. Present but idle
/// (`wantedBy = []`) until Sentinel (re)starts it here.
const HAPROXY_UNIT: &str = "haproxy.service";

/// Whether writing `body` to `path` would change what is already there (or the
/// file is absent) — the same change-detect the other appliers use.
fn file_changed(path: &Path, body: &str) -> bool {
    std::fs::read_to_string(path)
        .map(|c| c != body)
        .unwrap_or(true)
}

/// The on-disk bundle path (`certs/<name>.pem`) for the TLS frontend `name`. The
/// name has passed validation (`[A-Za-z0-9_-]`), so it never escapes the dir.
fn cert_bundle_path(name: &str) -> PathBuf {
    Path::new(HAPROXY_CERTS_DIR).join(format!("{name}.pem"))
}

/// Render a bootable `haproxy.cfg` for `proxies`. Every value has already passed
/// validation (safe name, `host:port` backends, valid port), so nothing needs
/// escaping. A frontend whose `certificate` is set binds `ssl crt <bundle>`
/// (TLS-terminated); one without binds plain HTTP. A `disabled` frontend is
/// omitted entirely. Each backend load-balances `roundrobin` with one checked
/// `server` line per upstream.
///
/// The caller ([`apply`]) has already cleared `certificate` on any frontend whose
/// PKI leaf is not yet on disk, so a `crt` line here always names a bundle that
/// exists — a not-yet-issued cert degrades to plain HTTP rather than a config
/// HAProxy would reject.
fn haproxy_cfg_body(proxies: &[ReverseProxy]) -> String {
    let mut s = String::from("# rendered by sentinel — L7 reverse proxy (HAProxy), roadmap C22\n");
    // Master-worker mode (`-W`) keeps the master in the foreground for systemd, so
    // NO `daemon` here. The log target is best-effort (a missing /dev/log only
    // warns), the rest are conservative L7 defaults.
    s.push_str("global\n");
    s.push_str("    log /dev/log local0\n");
    s.push_str("    maxconn 4096\n\n");
    s.push_str("defaults\n");
    s.push_str("    mode http\n");
    s.push_str("    log global\n");
    s.push_str("    option httplog\n");
    s.push_str("    option dontlognull\n");
    s.push_str("    option forwardfor\n");
    s.push_str("    timeout connect 5s\n");
    s.push_str("    timeout client 30s\n");
    s.push_str("    timeout server 30s\n");

    for p in proxies.iter().filter(|p| !p.disabled) {
        let port = p.port();
        s.push_str(&format!("\nfrontend {}\n", p.name));
        match &p.certificate {
            Some(_) => s.push_str(&format!(
                "    bind *:{port} ssl crt {}\n",
                cert_bundle_path(&p.name).display()
            )),
            None => s.push_str(&format!("    bind *:{port}\n")),
        }
        s.push_str(&format!("    default_backend {}\n", p.name));

        s.push_str(&format!("\nbackend {}\n", p.name));
        s.push_str("    balance roundrobin\n");
        for (i, backend) in p.backends.iter().enumerate() {
            s.push_str(&format!("    server s{i} {backend} check\n"));
        }
    }
    s
}

/// Assemble the combined cert+key PEM bundle HAProxy's `crt` wants for the TLS
/// frontend `name`: read the PKI leaf's `cert.crt` and `cert.key`, concatenate
/// (cert then key), and install it 0600 (it holds the private key) via the same
/// installer the IPsec/OpenConnect secrets use. Returns `Ok(None)` when the
/// leaf's files are not on disk yet (a not-yet-issued cert) — the caller then
/// degrades that frontend to plain HTTP rather than failing the whole apply.
/// `Ok(Some(changed))` reports whether the bundle differed from what was there.
fn write_cert_bundle(name: &str, cert_ref: &str) -> Result<Option<bool>> {
    let (crt, key) = crate::pki::leaf_paths(cert_ref);
    let (Ok(crt_pem), Ok(key_pem)) = (std::fs::read_to_string(&crt), std::fs::read_to_string(&key))
    else {
        eprintln!(
            "warning: reverse-proxy frontend {name:?}: certificate {cert_ref:?} is not issued \
             yet ({} / {} missing) — serving plain HTTP until it is",
            crt.display(),
            key.display()
        );
        return Ok(None);
    };
    // HAProxy reads one PEM with the cert (chain) first, then the private key.
    let bundle = format!("{crt_pem}{key_pem}");
    let path = cert_bundle_path(name);
    let changed = file_changed(&path, &bundle);
    system::install_ipsec_secret(&path, &bundle)?;
    Ok(Some(changed))
}

/// Remove any stale `certs/<name>.pem` bundle no longer in `keep` (a frontend was
/// removed, disabled, or lost its TLS). Best-effort: a dir that doesn't exist yet
/// (no TLS frontend ever rendered) is simply nothing to clean.
fn prune_cert_bundles(keep: &HashSet<String>) -> Result<()> {
    let Ok(entries) = std::fs::read_dir(HAPROXY_CERTS_DIR) else {
        return Ok(());
    };
    for e in entries.flatten() {
        let file = e.file_name();
        let name = file.to_string_lossy();
        let stem = name.strip_suffix(".pem").unwrap_or(&name);
        if !keep.contains(stem) {
            system::remove_file(&e.path())?;
        }
    }
    Ok(())
}

/// Run HAProxy's own config check (`haproxy -c -f <cfg>`) before a reload, so a
/// config it would reject never replaces a working one. `Some(true)` = valid,
/// `Some(false)` = HAProxy rejected it, `None` = the check could not run (e.g.
/// `haproxy` not on PATH off-box) — the caller treats `None` as "proceed", since
/// the render is trusted and the unit's own start would surface a real problem.
fn config_is_valid(cfg: &Path) -> Option<bool> {
    let Some(cfg_s) = cfg.to_str() else {
        return Some(false);
    };
    Command::new(system::bin("haproxy"))
        .args(["-c", "-f", cfg_s])
        .output()
        .ok()
        .map(|o| o.status.success())
}

/// Reconcile the reverse proxy to `appliance.services.reverse_proxy`: render
/// `haproxy.cfg` + a 0600 cert bundle per TLS frontend, then (re)start the
/// `haproxy` unit when the rendered config changed (a fresh boot always counts as
/// changed, since the tmpfs files are gone, so the daemon is re-asserted then
/// too). When nothing is configured — or every frontend is `disabled` — stop the
/// unit and drop the runtime artifacts. The restart is best-effort: at early boot
/// the unit's dependencies may not be ready, in which case the config applies on
/// the next commit/boot.
pub fn apply(appliance: &Appliance) -> Result<()> {
    let proxies = &appliance.services.reverse_proxy;
    let cfg_path = Path::new(HAPROXY_CFG);

    // Nothing configured, or every frontend parked: tear down. Stop the daemon
    // (best-effort — it may never have been up) and remove the rendered files.
    let any_active = proxies.iter().any(|p| !p.disabled);
    if !any_active {
        if cfg_path.exists() {
            if let Err(e) = system::service_stop(HAPROXY_UNIT) {
                eprintln!("warning: stopping haproxy failed: {e}");
            }
            system::remove_file(cfg_path)?;
            prune_cert_bundles(&HashSet::new())?;
        }
        return Ok(());
    }

    system::ensure_dir(Path::new(HAPROXY_CERTS_DIR))?;

    // Render each TLS frontend's bundle first. A frontend whose leaf is not yet
    // issued has its `certificate` cleared on the working copy, so the config
    // renderer emits a plain `bind` for it (degrade, don't fail). `bundles_changed`
    // rolls into the change-detect so a rotated cert triggers a reload.
    let mut effective: Vec<ReverseProxy> = Vec::with_capacity(proxies.len());
    let mut keep: HashSet<String> = HashSet::new();
    let mut bundles_changed = false;
    for p in proxies {
        let mut p = p.clone();
        if !p.disabled {
            if let Some(cert_ref) = p.certificate.clone() {
                match write_cert_bundle(&p.name, &cert_ref)? {
                    Some(changed) => {
                        keep.insert(p.name.clone());
                        bundles_changed |= changed;
                    }
                    // Not issued yet: serve plain until it is.
                    None => p.certificate = None,
                }
            }
        }
        effective.push(p);
    }
    // Drop bundles for frontends that no longer terminate TLS (removed/disabled).
    prune_cert_bundles(&keep)?;

    system::ensure_dir(Path::new(HAPROXY_RUNTIME_DIR))?;
    let cfg = haproxy_cfg_body(&effective);
    let changed = file_changed(cfg_path, &cfg) || bundles_changed;
    system::install_file(cfg_path, &cfg)?;

    // Gate the reload on HAProxy's own check: never replace a running proxy with a
    // config it would reject. An un-runnable check (off-box) is treated as "go".
    if config_is_valid(cfg_path) == Some(false) {
        eprintln!(
            "warning: rendered haproxy.cfg failed `haproxy -c` — leaving the running proxy \
             untouched; fix the config and re-commit"
        );
        return Ok(());
    }

    if changed {
        if let Err(e) = system::service_restart(HAPROXY_UNIT) {
            eprintln!("warning: (re)starting haproxy failed (applies on next commit/boot): {e}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy(name: &str) -> ReverseProxy {
        ReverseProxy {
            name: name.into(),
            disabled: false,
            port: None,
            certificate: None,
            backends: vec!["10.0.0.10:8080".into()],
        }
    }

    #[test]
    fn renders_global_and_defaults_once() {
        let body = haproxy_cfg_body(&[proxy("web")]);
        // The `global` + `defaults` skeleton is present exactly once, ahead of the
        // per-frontend sections.
        assert_eq!(body.matches("\nglobal\n").count(), 1, "{body}");
        assert_eq!(body.matches("\ndefaults\n").count(), 1, "{body}");
        assert_eq!(body.matches("mode http").count(), 1, "{body}");
    }

    #[test]
    fn plain_frontend_binds_without_ssl() {
        let body = haproxy_cfg_body(&[proxy("web")]);
        // A frontend + its backend, bound plain on the default 443, one checked
        // server per backend.
        assert!(body.contains("frontend web\n"), "{body}");
        assert!(body.contains("    bind *:443\n"), "{body}");
        assert!(!body.contains("ssl crt"), "no TLS without a cert: {body}");
        assert!(body.contains("    default_backend web\n"), "{body}");
        assert!(body.contains("backend web\n"), "{body}");
        assert!(
            body.contains("    server s0 10.0.0.10:8080 check\n"),
            "{body}"
        );
    }

    #[test]
    fn explicit_port_overrides_default() {
        let p = ReverseProxy {
            port: Some(8443),
            ..proxy("web")
        };
        let body = haproxy_cfg_body(&[p]);
        assert!(body.contains("    bind *:8443\n"), "{body}");
    }

    #[test]
    fn tls_frontend_emits_ssl_crt_bundle() {
        let p = ReverseProxy {
            certificate: Some("web-cert".into()),
            ..proxy("web")
        };
        let body = haproxy_cfg_body(&[p]);
        // The bundle is keyed by the FRONTEND name (so two frontends sharing a cert
        // never collide on one file), not by the certificate name.
        assert!(
            body.contains("    bind *:443 ssl crt /run/sentinel/haproxy/certs/web.pem\n"),
            "{body}"
        );
    }

    #[test]
    fn disabled_frontend_is_omitted() {
        let p = ReverseProxy {
            disabled: true,
            ..proxy("web")
        };
        let body = haproxy_cfg_body(&[p]);
        assert!(!body.contains("frontend web"), "{body}");
        assert!(!body.contains("backend web"), "{body}");
        // The skeleton still renders (so a torn-down proxy is a valid empty cfg).
        assert!(body.contains("mode http"), "{body}");
    }

    #[test]
    fn two_frontends_each_get_a_frontend_and_backend() {
        let a = proxy("web");
        let b = ReverseProxy {
            port: Some(8080),
            ..proxy("api")
        };
        let body = haproxy_cfg_body(&[a, b]);
        assert!(body.contains("frontend web\n"), "{body}");
        assert!(body.contains("frontend api\n"), "{body}");
        assert!(body.contains("backend web\n"), "{body}");
        assert!(body.contains("backend api\n"), "{body}");
    }

    #[test]
    fn round_robin_emits_one_server_per_backend() {
        let p = ReverseProxy {
            backends: vec!["10.0.0.10:8080".into(), "10.0.0.11:8080".into()],
            ..proxy("web")
        };
        let body = haproxy_cfg_body(&[p]);
        assert!(body.contains("    balance roundrobin\n"), "{body}");
        assert!(
            body.contains("    server s0 10.0.0.10:8080 check\n"),
            "{body}"
        );
        assert!(
            body.contains("    server s1 10.0.0.11:8080 check\n"),
            "{body}"
        );
    }

    #[test]
    fn cert_bundle_path_is_under_the_certs_dir() {
        assert_eq!(
            cert_bundle_path("web-cert"),
            Path::new("/run/sentinel/haproxy/certs/web-cert.pem")
        );
    }
}
