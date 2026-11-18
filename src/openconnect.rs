//! OpenConnect (AnyConnect-compatible) TLS road-warrior VPN via `ocserv`
//! (roadmap C17).
//!
//! A single `[vpn.openconnect]` server terminates client devices over TLS,
//! complementing the site-to-site IPsec ([`crate::ipsec`]) and peer-to-peer
//! WireGuard tracks. Sentinel renders `ocserv`'s config to
//! `/run/sentinel/ocserv/ocserv.conf` and the user credentials into a separate
//! 0600 `ocpasswd` file, then (re)starts the `ocserv` systemd unit. This follows
//! the same render + change-detect + reload model the IPsec / PPPoE / Multi-WAN
//! appliers use: the config lives on tmpfs, is re-seeded from the saved config
//! each boot, and the daemon is only (re)started when the rendered config changed
//! (or a server exists on a fresh boot), so an unrelated commit never disturbs a
//! live session.
//!
//! The server's TLS identity is a leaf issued by the on-box PKI ([`crate::pki`]),
//! resolved through [`crate::pki::leaf_paths`]. The per-user passwords are hashed
//! with the same random-salted yescrypt cost5 helper as local logins. `ocserv`'s
//! `plain` backend verifies crypt(3) hashes through libxcrypt. Valid existing
//! hashes are reused when the password is unchanged, preserving live sessions
//! during unrelated applies without deterministic salts or a fast password
//! fingerprint. The ephemeral credential file is recreated after boot.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, ensure};

use crate::config::{Appliance, OpenConnectServer};
use crate::system;

/// Runtime dir for the rendered ocserv config (tmpfs; re-seeded each boot). Mode
/// 0750 — the 0600 password file lives here.
const OCSERV_RUNTIME_DIR: &str = "/run/sentinel/ocserv";
/// The rendered `ocserv.conf`, read by the `ocserv` unit's `--config`.
const OCSERV_CONF: &str = "/run/sentinel/ocserv/ocserv.conf";
/// The rendered `ocpasswd` credential file (0600 root:root — `ocserv` runs as
/// root, so the hashes never need to leave root). `auth = plain[passwd=…]` reads
/// it.
const OCPASSWD: &str = "/run/sentinel/ocserv/ocpasswd";
/// The systemd unit that runs `ocserv` from the rendered config. Present but idle
/// (`wantedBy = []`) until Sentinel (re)starts it here.
const OCSERV_UNIT: &str = "ocserv.service";
const MAX_CREDENTIAL_FILE: usize = 1024 * 1024;

/// Split a validated IPv4 CIDR pool (`10.99.0.0/24`) into its network address and
/// dotted netmask, the pair `ocserv` wants as `ipv4-network` + `ipv4-netmask`.
/// Validation guarantees the `/prefix` form, so the fallbacks here never fire on a
/// committed config — they only keep the renderer total.
fn pool_network_netmask(pool: &str) -> (String, String) {
    let (net, prefix) = pool.split_once('/').unwrap_or((pool, "24"));
    let prefix: u8 = prefix.parse().unwrap_or(24);
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix.min(32)))
    };
    let netmask = format!(
        "{}.{}.{}.{}",
        (mask >> 24) & 0xff,
        (mask >> 16) & 0xff,
        (mask >> 8) & 0xff,
        mask & 0xff
    );
    (net.to_string(), netmask)
}

/// An `ocserv` split-tunnel route line value: a CIDR is kept verbatim, a bare host
/// address is widened to `/32` (both forms pass `validate_cidr_or_ip`).
fn route_cidr(route: &str) -> String {
    if route.contains('/') {
        route.to_string()
    } else {
        format!("{route}/32")
    }
}

/// Render a bootable `ocserv.conf` for `oc`. Every value has already passed
/// validation (safe charset, IP/CIDR forms), so there is nothing to escape here.
/// Full vs split tunnel follows `ocserv`'s own default: NO `route` lines means the
/// client sends everything over the VPN, so `default-route` (full tunnel) emits no
/// routes and turns on `tunnel-all-dns`, while a split config emits one `route`
/// line per pushed CIDR.
fn ocserv_conf_body(oc: &OpenConnectServer) -> String {
    let port = oc.port();
    let (cert, key) = crate::pki::leaf_paths(&oc.certificate);
    let (network, netmask) = pool_network_netmask(&oc.pool);

    let mut s = String::from("# rendered by sentinel — OpenConnect (ocserv), roadmap C17\n");
    // Plain (username/password) auth against the 0600 hash file rendered alongside.
    s.push_str(&format!("auth = \"plain[passwd={OCPASSWD}]\"\n"));
    s.push_str(&format!("tcp-port = {port}\n"));
    s.push_str(&format!("udp-port = {port}\n"));
    // ocserv runs as root under systemd; it never needs to drop to another user for
    // this appliance, and staying root keeps /dev/net/tun + the socket accessible
    // in the CI sandbox.
    s.push_str("run-as-user = root\n");
    s.push_str("run-as-group = root\n");
    s.push_str("socket-file = /run/sentinel/ocserv/ocserv.sock\n");
    s.push_str(&format!("server-cert = {}\n", cert.display()));
    s.push_str(&format!("server-key = {}\n", key.display()));
    // Don't seccomp-isolate the worker processes — the sandbox VM's restricted
    // syscall surface otherwise trips the isolation and ocserv fails to serve.
    s.push_str("isolate-workers = false\n");
    s.push_str("max-clients = 128\n");
    s.push_str("max-same-clients = 2\n");
    // Banning off: during a commit/boot the client may retry auth a few times while
    // the server settles; a ban would then lock it out for the rest of the window.
    s.push_str("max-ban-score = 0\n");
    s.push_str("ban-reset-time = 300\n");
    s.push_str("keepalive = 300\n");
    s.push_str("dpd = 60\n");
    s.push_str("mobile-dpd = 300\n");
    s.push_str("switch-to-tcp-timeout = 25\n");
    s.push_str("try-mtu-discovery = true\n");
    // The DN field ocserv maps to the connecting user's certificate identity; the
    // stock value for TLS-cert auth (unused here, but ocserv wants it defined).
    s.push_str("cert-user-oid = 0.9.2342.19200300.100.1.1\n");
    s.push_str("tls-priorities = \"NORMAL:%SERVER_PRECEDENCE:%COMPAT\"\n");
    s.push_str("auth-timeout = 240\n");
    s.push_str("idle-timeout = 1200\n");
    s.push_str("mobile-idle-timeout = 1800\n");
    s.push_str("cookie-timeout = 300\n");
    s.push_str("deny-roaming = false\n");
    s.push_str("rekey-time = 172800\n");
    s.push_str("rekey-method = ssl\n");
    // The control socket is what lets the appliance ask who is connected — for
    // `show vpn users` and for the user groups a firewall rule can name. It is
    // root-owned in /run, so enabling it widens nothing that root could not
    // already do; leaving it off simply made occtl (which the image ships)
    // useless.
    s.push_str("use-occtl = true\n");
    s.push_str("pid-file = /run/sentinel/ocserv/ocserv.pid\n");
    s.push_str("device = vpn0\n");
    s.push_str("predictable-ips = true\n");
    s.push_str(&format!("ipv4-network = {network}\n"));
    s.push_str(&format!("ipv4-netmask = {netmask}\n"));
    s.push_str("cisco-client-compat = true\n");
    s.push_str("dtls-legacy = true\n");
    for d in &oc.dns {
        s.push_str(&format!("dns = {d}\n"));
    }
    // Full tunnel ⇒ tell the client to send even its DNS over the VPN; split tunnel
    // ⇒ leave the client's own resolver in place for non-pushed destinations.
    s.push_str(&format!("tunnel-all-dns = {}\n", oc.default_route));
    if !oc.default_route {
        for r in &oc.routes {
            s.push_str(&format!("route = {}\n", route_cidr(r)));
        }
    }
    s
}

/// Parse only Sentinel's root-private credential file format. Corrupt or
/// ambiguous state is an error, never a reason to silently regenerate secrets.
fn cached_hashes(body: Option<&str>) -> Result<BTreeMap<String, String>> {
    let mut hashes = BTreeMap::new();
    let Some(body) = body else { return Ok(hashes) };
    ensure!(
        body.len() <= MAX_CREDENTIAL_FILE,
        "OpenConnect credential cache exceeds read bound"
    );
    for line in body.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        ensure!(
            fields.len() == 3 && fields[1] == "*",
            "invalid OpenConnect credential cache entry"
        );
        let name = fields[0];
        ensure!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')),
            "invalid OpenConnect credential cache identity"
        );
        crate::passwd::validate_hash(fields[2])
            .context("invalid OpenConnect cached password hash")?;
        ensure!(
            hashes
                .insert(name.to_string(), fields[2].to_string())
                .is_none(),
            "duplicate OpenConnect credential cache identity"
        );
    }
    ensure!(
        !hashes.is_empty(),
        "an existing OpenConnect credential cache must contain an account"
    );
    Ok(hashes)
}

/// Assemble one `ocpasswd` line from a name and a pre-computed hash: the
/// `username:groupname:hash` form the `plain` backend parses. The group is `*`
/// (no group restriction).
fn ocpasswd_line(name: &str, hash: &str) -> String {
    format!("{name}:*:{hash}")
}

/// Render the `ocpasswd` credential file (0600) for `oc` — one hashed line per
/// user. The passwords are hashed here, never emitted in clear, and never land in
/// `ocserv.conf`.
fn ocpasswd_body(oc: &OpenConnectServer, previous: Option<&str>) -> Result<String> {
    let hashes = cached_hashes(previous)?;
    let mut s = String::from("# rendered by sentinel — OpenConnect credentials (0600)\n");
    for u in &oc.users {
        let previous = hashes.get(&u.name);
        let hash = match previous {
            Some(hash)
                if hash.starts_with("$y$j9T$") && crate::passwd::verify(&u.password, hash)? =>
            {
                hash.clone()
            }
            _ => crate::passwd::hash_nonempty(&u.password)?,
        };
        s.push_str(&ocpasswd_line(&u.name, &hash));
        s.push('\n');
    }
    Ok(s)
}

/// Reconcile the OpenConnect server to `appliance.vpn.openconnect`: render
/// `ocserv.conf` + the 0600 `ocpasswd`, then (re)start the `ocserv` unit when the
/// rendered config changed (a fresh boot always counts as changed, since the tmpfs
/// files are gone, so the daemon is re-asserted then too). When no server is
/// configured — or it is administratively `disabled` — stop the unit and drop the
/// runtime artifacts. The restart is best-effort: at early boot the unit's
/// dependencies may not be ready, in which case the config applies on the next
/// commit/boot.
pub fn apply(appliance: &Appliance) -> Result<()> {
    let _transaction = system::apply_lock()?;
    let conf_path = Path::new(OCSERV_CONF);
    let passwd_path = Path::new(OCPASSWD);

    // No server, or parked: tear down. Stop the daemon (best-effort — it may never
    // have been up) and remove the rendered files so nothing lingers.
    let oc = match &appliance.vpn.openconnect {
        Some(oc) if !oc.disabled => oc,
        _ => {
            if conf_path.exists() {
                if let Err(e) = system::service_stop(OCSERV_UNIT) {
                    eprintln!("warning: stopping ocserv failed: {e}");
                }
                system::remove_file(conf_path)?;
                system::remove_file(passwd_path)?;
            }
            return Ok(());
        }
    };

    system::ensure_dir(Path::new(OCSERV_RUNTIME_DIR))?;
    let previous = system::read_owned_private(passwd_path, MAX_CREDENTIAL_FILE)?;
    let conf = ocserv_conf_body(oc);
    let passwd = ocpasswd_body(oc, previous.as_deref())?;
    let conf_changed =
        system::read_owned_regular(conf_path, MAX_CREDENTIAL_FILE)?.as_deref() != Some(&conf);
    let passwd_changed = previous.as_deref() != Some(&passwd);
    let changed = conf_changed || passwd_changed;
    if conf_changed {
        system::install_file(conf_path, &conf)?;
    }
    if passwd_changed {
        system::install_ha_secret(passwd_path, &passwd)?;
    }
    if changed && let Err(e) = system::service_restart(OCSERV_UNIT) {
        eprintln!("warning: (re)starting ocserv failed (applies on next commit/boot): {e}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{OpenConnectServer, OpenConnectUser};

    fn server() -> OpenConnectServer {
        OpenConnectServer {
            disabled: false,
            port: None,
            certificate: "vpn-server".into(),
            pool: "10.99.0.0/24".into(),
            dns: vec!["10.99.0.1".into()],
            routes: vec!["10.100.0.0/24".into()],
            default_route: false,
            zone: None,
            users: vec![OpenConnectUser {
                name: "alice".into(),
                password: "s3cr3t".into(),
            }],
        }
    }

    #[test]
    fn conf_renders_port_cert_pool_and_split_routes() {
        let body = ocserv_conf_body(&server());
        // Default port is 443 on both transports.
        assert!(body.contains("tcp-port = 443"), "{body}");
        assert!(body.contains("udp-port = 443"), "{body}");
        // TLS identity resolves to the PKI leaf's store paths.
        assert!(
            body.contains("server-cert = /var/lib/sentinel/pki/certs/vpn-server/cert.crt"),
            "{body}"
        );
        assert!(
            body.contains("server-key = /var/lib/sentinel/pki/certs/vpn-server/cert.key"),
            "{body}"
        );
        // Pool split into network + dotted netmask.
        assert!(body.contains("ipv4-network = 10.99.0.0"), "{body}");
        assert!(body.contains("ipv4-netmask = 255.255.255.0"), "{body}");
        // DNS pushed, tun device fixed, plain auth points at the 0600 file.
        assert!(body.contains("dns = 10.99.0.1"), "{body}");
        assert!(body.contains("device = vpn0"), "{body}");
        assert!(
            body.contains("auth = \"plain[passwd=/run/sentinel/ocserv/ocpasswd]\""),
            "{body}"
        );
        // Split tunnel: one route line for the pushed CIDR, DNS not forced.
        assert!(body.contains("route = 10.100.0.0/24"), "{body}");
        assert!(body.contains("tunnel-all-dns = false"), "{body}");
    }

    #[test]
    fn explicit_port_overrides_default() {
        let oc = OpenConnectServer {
            port: Some(8443),
            ..server()
        };
        let body = ocserv_conf_body(&oc);
        assert!(body.contains("tcp-port = 8443"), "{body}");
        assert!(body.contains("udp-port = 8443"), "{body}");
    }

    #[test]
    fn default_route_emits_full_tunnel_no_routes() {
        let oc = OpenConnectServer {
            routes: vec![],
            default_route: true,
            ..server()
        };
        let body = ocserv_conf_body(&oc);
        // Full tunnel: DNS forced, and NO route lines at all (ocserv's own default
        // when no routes are pushed).
        assert!(body.contains("tunnel-all-dns = true"), "{body}");
        assert!(!body.contains("route = "), "no split routes: {body}");
    }

    #[test]
    fn bare_host_route_is_widened_to_slash_32() {
        let oc = OpenConnectServer {
            routes: vec!["198.51.100.7".into()],
            ..server()
        };
        let body = ocserv_conf_body(&oc);
        assert!(body.contains("route = 198.51.100.7/32"), "{body}");
    }

    #[test]
    fn pool_splits_network_and_netmask() {
        assert_eq!(
            pool_network_netmask("10.99.0.0/24"),
            ("10.99.0.0".into(), "255.255.255.0".into())
        );
        assert_eq!(
            pool_network_netmask("172.16.0.0/16"),
            ("172.16.0.0".into(), "255.255.0.0".into())
        );
        assert_eq!(
            pool_network_netmask("10.0.0.0/8"),
            ("10.0.0.0".into(), "255.0.0.0".into())
        );
    }

    #[test]
    fn cached_credentials_refuse_malformed_duplicate_or_excessive_cost_state() {
        let valid = "$6$salt123456789012$mrQIS8eBOuKvq23qeHhMYQGqzyaljxGgVQih9JxYJi7aMYM4TCNknwxRRFgrzIi20LVUXbUyY.j.yJDZCzyaC/";
        assert!(cached_hashes(None).unwrap().is_empty());
        assert!(cached_hashes(Some("# existing comment\n")).is_err());
        assert!(cached_hashes(Some(&format!("alice:*:{valid}\n"))).is_ok());
        for body in [
            String::new(),
            "# incomplete cache\n".to_string(),
            "alice:*:not-a-hash".to_string(),
            format!("alice:*:{valid}\nalice:*:{valid}\n"),
            format!("alice:unexpected-group:{valid}\n"),
            format!("a b:*:{valid}\n"),
            format!("alice:*:{valid}:extra\n"),
            format!("alice:*:$y$jBT${}${}\n", "s".repeat(22), "h".repeat(43)),
            "x".repeat(MAX_CREDENTIAL_FILE + 1),
        ] {
            assert!(cached_hashes(Some(&body)).is_err());
            assert!(ocpasswd_body(&server(), Some(&body)).is_err());
        }
    }

    #[test]
    fn ocpasswd_line_is_user_star_hash() {
        assert_eq!(
            ocpasswd_line("alice", "$6$alice$abc"),
            "alice:*:$6$alice$abc"
        );
    }

    #[test]
    fn ocpasswd_body_hashes_each_user() {
        // The real pinned libxcrypt helper is required; failures cannot turn
        // into a silently skipped green test.
        let body = ocpasswd_body(&server(), None).unwrap();
        assert!(body.contains("alice:*:$y$j9T$"), "{body}");
        assert!(!body.contains("s3cr3t"), "plaintext must not leak: {body}");
        let hash = &cached_hashes(Some(&body)).unwrap()["alice"];
        assert!(
            hash.len() < 128,
            "ocserv1.4.0 cpass buffer must fit the hash"
        );
        assert!(crate::passwd::verify("s3cr3t", hash).unwrap());
        assert!(!crate::passwd::verify("wrong", hash).unwrap());
        assert_eq!(ocpasswd_body(&server(), Some(&body)).unwrap(), body);
        // A fresh boot gets a fresh random salt, not a username-derived one.
        assert_ne!(ocpasswd_body(&server(), None).unwrap(), body);
        // The shared compatibility entry point must not relax local creation.
        assert!(crate::passwd::hash("s3cr3t").is_err());
    }

    #[test]
    fn credentials_rotate_on_password_change_and_removed_users_do_not_linger() {
        let original = ocpasswd_body(&server(), None).unwrap();
        let mut oc = server();
        oc.users[0].password = "new public fixture password".into();
        oc.users.push(OpenConnectUser {
            name: "bob".into(),
            password: "new public fixture password".into(),
        });
        let changed = ocpasswd_body(&oc, Some(&original)).unwrap();
        let hashes = cached_hashes(Some(&changed)).unwrap();
        assert!(!crate::passwd::verify("s3cr3t", &hashes["alice"]).unwrap());
        assert!(crate::passwd::verify(&oc.users[0].password, &hashes["alice"]).unwrap());
        assert_ne!(
            hashes["alice"], hashes["bob"],
            "separate identities need independent salts"
        );
        oc.users.remove(0);
        let removed = ocpasswd_body(&oc, Some(&changed)).unwrap();
        assert!(!cached_hashes(Some(&removed)).unwrap().contains_key("alice"));
        assert_eq!(cached_hashes(Some(&removed)).unwrap()["bob"], hashes["bob"]);
    }

    #[test]
    fn legacy_hash_is_migrated_once_without_breaking_existing_short_vpn_passwords() {
        let legacy = "alice:*:$6$salt123456789012$mrQIS8eBOuKvq23qeHhMYQGqzyaljxGgVQih9JxYJi7aMYM4TCNknwxRRFgrzIi20LVUXbUyY.j.yJDZCzyaC/\n";
        let body = ocpasswd_body(&server(), Some(legacy)).unwrap();
        assert!(body.contains("alice:*:$y$j9T$"));
        assert!(!body.contains("$6$"));
        assert_eq!(ocpasswd_body(&server(), Some(&body)).unwrap(), body);
        for password in [String::new(), "p".repeat(512), "bad\npassword".into()] {
            let mut oc = server();
            oc.users[0].password = password;
            assert!(ocpasswd_body(&oc, Some(&body)).is_err());
        }
    }
}
