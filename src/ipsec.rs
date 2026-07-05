//! IKEv2 site-to-site IPsec via strongSwan (roadmap C2).
//!
//! A `[[vpn.ipsec]]` connection is a policy-based tunnel between two endpoints,
//! authenticated with a pre-shared key. Sentinel renders the strongSwan
//! **swanctl.conf** (`connections`/`children`) to `/run/sentinel/swanctl/` and
//! the PSK into a separate 0600 `secrets.conf`, then loads them into the running
//! `charon` daemon with `swanctl --load-all`. This follows the same render +
//! change-detect + reload model the PPPoE / Multi-WAN appliers use: the config
//! lives on tmpfs, is re-seeded from the saved config each boot, and the daemon
//! is only (re)loaded when the rendered config changed (or a tunnel exists on a
//! fresh boot), so an unrelated commit never disturbs a live SA.
//!
//! Route-based (XFRM-interface) mode with a firewall zone, road-warrior
//! responders and certificate authentication are follow-ups; this module
//! implements the policy-based, PSK, site-to-site core.

use std::path::Path;

use anyhow::Result;

use crate::config::{
    Appliance, DEFAULT_ESP_PROPOSAL, DEFAULT_IKE_PROPOSAL, DEFAULT_IPSEC_START_ACTION,
    IpsecConnection,
};
use crate::system;

/// Runtime dir for the rendered swanctl config (tmpfs; re-seeded each boot). Mode
/// 0700 — the secrets file lives here.
const SWANCTL_RUNTIME_DIR: &str = "/run/sentinel/swanctl";
/// The rendered swanctl `connections` file, loaded with `swanctl --load-all`. It
/// `include`s the secrets file (absolute path) so the PSKs load in the same pass.
const SWANCTL_CONF: &str = "/run/sentinel/swanctl/swanctl.conf";
/// The rendered `secrets` file (PSKs). 0600 root:root — charon runs as root, so
/// the key never needs to leave root.
const SWANCTL_SECRETS: &str = "/run/sentinel/swanctl/secrets.conf";

/// Whether writing `body` to `path` would change what is already there (or the
/// file is absent) — the same change-detect the other appliers use.
fn file_changed(path: &Path, body: &str) -> bool {
    std::fs::read_to_string(path)
        .map(|c| c != body)
        .unwrap_or(true)
}

/// The local IKE identity for `c` (its `local-id`, else the `local` address).
fn local_id(c: &IpsecConnection) -> &str {
    c.local_id.as_deref().unwrap_or(&c.local)
}

/// The remote IKE identity for `c` (its `remote-id`, else the `remote` address).
fn remote_id(c: &IpsecConnection) -> &str {
    c.remote_id.as_deref().unwrap_or(&c.remote)
}

/// Render the swanctl `connections { … }` block for `conns` (+ the trailing
/// `include` of the secrets file). Every value has already passed validation, so
/// it carries only the safe charset — there is nothing to escape here.
fn swanctl_conf_body(conns: &[IpsecConnection]) -> String {
    let mut s = String::from("# rendered by sentinel — IPsec (strongSwan swanctl), roadmap C2\n");
    s.push_str("connections {\n");
    for c in conns {
        let version = c.ike_version.unwrap_or(2);
        let ike = c.ike_proposal.as_deref().unwrap_or(DEFAULT_IKE_PROPOSAL);
        let esp = c.esp_proposal.as_deref().unwrap_or(DEFAULT_ESP_PROPOSAL);
        let start = c
            .start_action
            .as_deref()
            .unwrap_or(DEFAULT_IPSEC_START_ACTION);
        s.push_str(&format!("    conn-{} {{\n", c.name));
        s.push_str(&format!("        version = {version}\n"));
        s.push_str(&format!("        local_addrs = {}\n", c.local));
        s.push_str(&format!("        remote_addrs = {}\n", c.remote));
        s.push_str(&format!("        proposals = {ike}\n"));
        s.push_str("        local {\n");
        s.push_str("            auth = psk\n");
        s.push_str(&format!("            id = {}\n", local_id(c)));
        s.push_str("        }\n");
        s.push_str("        remote {\n");
        s.push_str("            auth = psk\n");
        s.push_str(&format!("            id = {}\n", remote_id(c)));
        s.push_str("        }\n");
        s.push_str("        children {\n");
        s.push_str(&format!("            {} {{\n", c.name));
        s.push_str(&format!("                local_ts = {}\n", c.local_subnet));
        s.push_str(&format!(
            "                remote_ts = {}\n",
            c.remote_subnet
        ));
        s.push_str(&format!("                esp_proposals = {esp}\n"));
        s.push_str("                mode = tunnel\n");
        s.push_str(&format!("                start_action = {start}\n"));
        s.push_str("            }\n");
        s.push_str("        }\n");
        s.push_str("    }\n");
    }
    s.push_str("}\n");
    // Load the PSKs in the same pass. An absolute include path is unambiguous
    // regardless of charon's working directory.
    s.push_str(&format!("include {SWANCTL_SECRETS}\n"));
    s
}

/// Render the swanctl `secrets { … }` block (the PSKs). Written 0600 — never
/// world-readable. Each connection contributes one `ike-<name>` entry listing the
/// two acceptable identities and the shared key.
fn swanctl_secrets_body(conns: &[IpsecConnection]) -> String {
    let mut s = String::from("# rendered by sentinel — IPsec pre-shared keys (0600)\n");
    s.push_str("secrets {\n");
    for c in conns {
        s.push_str(&format!("    ike-{} {{\n", c.name));
        s.push_str(&format!("        id-local = {}\n", local_id(c)));
        s.push_str(&format!("        id-remote = {}\n", remote_id(c)));
        s.push_str(&format!("        secret = \"{}\"\n", c.psk));
        s.push_str("    }\n");
    }
    s.push_str("}\n");
    s
}

/// Reconcile the IPsec tunnels to `appliance.vpn.ipsec`: render the swanctl
/// connections + the 0600 secrets, then `swanctl --load-all` into the running
/// charon when the rendered config changed (or a tunnel exists on a fresh boot,
/// so the daemon is re-seeded even if the tmpfs file happens to match). When no
/// connection is configured, clear any previously-loaded config and drop the
/// runtime artifacts. The load is best-effort: charon may not be up yet at early
/// boot, in which case the config applies on the next commit/boot.
pub fn apply(appliance: &Appliance) -> Result<()> {
    let conns = &appliance.vpn.ipsec;
    let conf_path = Path::new(SWANCTL_CONF);
    let secrets_path = Path::new(SWANCTL_SECRETS);

    if conns.is_empty() {
        // Nothing configured. If a previous apply wrote a config, load an empty
        // one to unload the connections from charon, then remove the artifacts.
        if conf_path.exists() {
            system::ensure_dir(Path::new(SWANCTL_RUNTIME_DIR))?;
            system::install_file(conf_path, &swanctl_conf_body(&[]))?;
            system::install_ipsec_secret(secrets_path, &swanctl_secrets_body(&[]))?;
            if let Err(e) = system::swanctl_load(conf_path) {
                eprintln!("warning: clearing swanctl config failed: {e}");
            }
            system::remove_file(conf_path)?;
            system::remove_file(secrets_path)?;
        }
        return Ok(());
    }

    system::ensure_dir(Path::new(SWANCTL_RUNTIME_DIR))?;
    let conf = swanctl_conf_body(conns);
    let secrets = swanctl_secrets_body(conns);
    let changed = file_changed(conf_path, &conf) || file_changed(secrets_path, &secrets);
    system::install_file(conf_path, &conf)?;
    system::install_ipsec_secret(secrets_path, &secrets)?;
    // Load when the rendered config changed, or unconditionally when a tunnel is
    // configured (a fresh boot re-asserts charon's state even if the tmpfs file
    // matches what a previous run wrote).
    if changed || !conns.is_empty() {
        if let Err(e) = system::swanctl_load(conf_path) {
            eprintln!("warning: loading swanctl config failed (applies on next commit/boot): {e}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IpsecConnection;

    fn conn() -> IpsecConnection {
        IpsecConnection {
            name: "site-a".into(),
            local: "203.0.113.1".into(),
            remote: "198.51.100.1".into(),
            local_subnet: "10.0.0.0/24".into(),
            remote_subnet: "10.1.0.0/24".into(),
            psk: "topsecret".into(),
            ike_version: None,
            ike_proposal: None,
            esp_proposal: None,
            local_id: None,
            remote_id: None,
            start_action: None,
        }
    }

    #[test]
    fn conf_renders_connection_children_and_defaults() {
        let body = swanctl_conf_body(&[conn()]);
        assert!(body.contains("conn-site-a {"), "{body}");
        assert!(body.contains("version = 2"), "{body}");
        assert!(body.contains("local_addrs = 203.0.113.1"), "{body}");
        assert!(body.contains("remote_addrs = 198.51.100.1"), "{body}");
        // Defaults filled in for proposals + start action.
        assert!(
            body.contains("proposals = aes256-sha256-modp2048"),
            "{body}"
        );
        assert!(
            body.contains("esp_proposals = aes256-sha256-modp2048"),
            "{body}"
        );
        assert!(body.contains("local_ts = 10.0.0.0/24"), "{body}");
        assert!(body.contains("remote_ts = 10.1.0.0/24"), "{body}");
        assert!(body.contains("start_action = start"), "{body}");
        // The secrets file is included, and no PSK leaks into swanctl.conf.
        assert!(
            body.contains("include /run/sentinel/swanctl/secrets.conf"),
            "{body}"
        );
        assert!(
            !body.contains("topsecret"),
            "psk must not be in conf: {body}"
        );
        // Identities default to the endpoint addresses.
        assert!(body.contains("id = 203.0.113.1"), "{body}");
        assert!(body.contains("id = 198.51.100.1"), "{body}");
    }

    #[test]
    fn secrets_carry_psk_and_identities() {
        let body = swanctl_secrets_body(&[conn()]);
        assert!(body.contains("ike-site-a {"), "{body}");
        assert!(body.contains("id-local = 203.0.113.1"), "{body}");
        assert!(body.contains("id-remote = 198.51.100.1"), "{body}");
        assert!(body.contains("secret = \"topsecret\""), "{body}");
    }

    #[test]
    fn overrides_win_over_defaults() {
        let c = IpsecConnection {
            ike_version: Some(1),
            ike_proposal: Some("aes128-sha256-modp2048".into()),
            esp_proposal: Some("aes128gcm16-modp2048".into()),
            local_id: Some("gw-a.example.com".into()),
            remote_id: Some("gw-b.example.com".into()),
            start_action: Some("trap".into()),
            ..conn()
        };
        let body = swanctl_conf_body(&[c]);
        assert!(body.contains("version = 1"), "{body}");
        assert!(
            body.contains("proposals = aes128-sha256-modp2048"),
            "{body}"
        );
        assert!(
            body.contains("esp_proposals = aes128gcm16-modp2048"),
            "{body}"
        );
        assert!(body.contains("id = gw-a.example.com"), "{body}");
        assert!(body.contains("id = gw-b.example.com"), "{body}");
        assert!(body.contains("start_action = trap"), "{body}");
    }

    #[test]
    fn empty_connections_render_an_empty_block() {
        let body = swanctl_conf_body(&[]);
        assert!(body.contains("connections {"), "{body}");
        assert!(!body.contains("conn-"), "{body}");
    }
}
