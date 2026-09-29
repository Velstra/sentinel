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
/// (TLS-terminated); one without forwards HTTP or a TCP stream. A `disabled` frontend is
/// omitted entirely. Each backend load-balances `roundrobin` with one checked
/// `server` line per upstream.
///
/// The caller ([`apply`]) refuses a configured TLS frontend whose certificate
/// is unavailable, so a `crt` line always names a complete bundle.
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
    s.push_str("    timeout connect 5s\n");
    s.push_str("    timeout client 30s\n");
    s.push_str("    timeout server 30s\n");

    for p in proxies.iter().filter(|p| !p.disabled) {
        let port = p.port();
        s.push_str(&format!("\nfrontend fe_{}\n", p.name));
        if p.mode == crate::config::ProxyMode::Tcp {
            s.push_str("    mode tcp\n    option tcplog\n    timeout client 1h\n");
        }
        match &p.certificate {
            Some(_) => s.push_str(&format!(
                "    bind *:{port} ssl crt {}\n",
                cert_bundle_path(&p.name).display()
            )),
            None => s.push_str(&format!("    bind *:{port}\n")),
        }
        s.push_str(&format!("    default_backend be_{}\n", p.name));

        s.push_str(&format!("\nbackend be_{}\n", p.name));
        if p.mode == crate::config::ProxyMode::Tcp {
            s.push_str("    mode tcp\n    timeout server 1h\n");
        } else {
            s.push_str("    option forwardfor\n");
        }
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
/// installer the IPsec/OpenConnect secrets use. Missing certificate material
/// is an error: an encrypted listener must never degrade to plaintext. The
/// result reports whether the installed bundle changed.
fn write_cert_bundle(name: &str, cert_ref: &str) -> Result<bool> {
    let (crt, key) = crate::pki::leaf_paths(cert_ref);
    let (Ok(crt_pem), Ok(key_pem)) = (std::fs::read_to_string(&crt), std::fs::read_to_string(&key))
    else {
        anyhow::bail!(
            "reverse-proxy frontend {name:?}: TLS certificate {cert_ref:?} is not available; refusing plaintext fallback"
        );
    };
    // HAProxy reads one PEM with the cert (chain) first, then the private key.
    let bundle = format!("{crt_pem}{key_pem}");
    let path = cert_bundle_path(name);
    let changed = file_changed(&path, &bundle);
    system::install_ipsec_secret(&path, &bundle)?;
    Ok(changed)
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
/// unit and drop the runtime artifacts. Invalid configurations and failed
/// restarts fail the apply so callers never report an inactive proxy as ready.
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

    // Render TLS bundles before touching the listener configuration. A missing
    // certificate aborts the update; rotation participates in change detection.
    let mut keep: HashSet<String> = HashSet::new();
    let mut bundles_changed = false;
    for p in proxies.iter().filter(|p| !p.disabled) {
        if let Some(cert_ref) = &p.certificate {
            bundles_changed |= write_cert_bundle(&p.name, cert_ref)?;
            keep.insert(p.name.clone());
        }
    }
    // Drop bundles for frontends that no longer terminate TLS (removed/disabled).
    prune_cert_bundles(&keep)?;

    system::ensure_dir(Path::new(HAPROXY_RUNTIME_DIR))?;
    let cfg = haproxy_cfg_body(proxies);
    let changed = file_changed(cfg_path, &cfg) || bundles_changed;
    let staged_path = Path::new("/run/sentinel/haproxy/.candidate.cfg");
    system::install_file(staged_path, &cfg)?;

    // Gate the reload on HAProxy's own check: never replace a running proxy with a
    // config it would reject. An un-runnable check (off-box) is treated as "go".
    if config_is_valid(staged_path) == Some(false) {
        let _ = system::remove_file(staged_path);
        anyhow::bail!(
            "rendered haproxy.cfg failed `haproxy -c` — leaving the running proxy \
             untouched; fix the config and re-commit"
        );
    }
    system::install_file(cfg_path, &cfg)?;
    system::remove_file(staged_path)?;

    if changed {
        system::service_restart(HAPROXY_UNIT)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy(name: &str) -> ReverseProxy {
        ReverseProxy {
            mode: crate::config::ProxyMode::Http,
            name: name.into(),
            disabled: false,
            port: None,
            certificate: None,
            backends: vec!["10.0.0.10:8080".into()],
        }
    }

    #[test]
    fn tcp_passthrough_keeps_streams_and_backend_checks() {
        let mut p = proxy("cloud");
        p.mode = crate::config::ProxyMode::Tcp;
        let body = haproxy_cfg_body(&[proxy("web"), p]);
        assert_eq!(body.matches("mode tcp").count(), 2, "{body}");
        assert!(body.contains("option tcplog"));
        assert!(!body.contains("no option forwardfor"));
        assert_eq!(body.matches("option forwardfor").count(), 1);
        assert!(body.contains("timeout client 1h"));
        assert!(body.contains("server s0 10.0.0.10:8080 check"));
        assert!(!body.contains("bind *:443 ssl"));
    }

    #[test]
    fn missing_tls_material_never_falls_back_to_plaintext() {
        let why = write_cert_bundle("test-unissued-safety", "test-unissued-safety").unwrap_err();
        assert!(why.to_string().contains("refusing plaintext fallback"));
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
        assert!(body.contains("frontend fe_web\n"), "{body}");
        assert!(body.contains("    bind *:443\n"), "{body}");
        assert!(!body.contains("ssl crt"), "no TLS without a cert: {body}");
        assert!(body.contains("    default_backend be_web\n"), "{body}");
        assert!(body.contains("backend be_web\n"), "{body}");
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
        assert!(!body.contains("frontend fe_web"), "{body}");
        assert!(!body.contains("backend be_web"), "{body}");
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
        assert!(body.contains("frontend fe_web\n"), "{body}");
        assert!(body.contains("frontend fe_api\n"), "{body}");
        assert!(body.contains("backend be_web\n"), "{body}");
        assert!(body.contains("backend be_api\n"), "{body}");
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
