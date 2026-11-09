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

use std::{collections::BTreeMap, path::Path};

use anyhow::{Context, Result, ensure};

use crate::config::{
    Appliance, DEFAULT_ESP_PROPOSAL, DEFAULT_IKE_PROPOSAL, DEFAULT_IPSEC_START_ACTION, Interface,
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
/// The routes [`tunnel_routes`] last installed, one `<subnet> <peer>` per line.
///
/// Needed because a removed tunnel must take its route with it: a route to the
/// far subnet that outlives the policy sends that traffic to the peer's WAN
/// address **in the clear**. Kept on tmpfs deliberately — after a reboot the
/// routes are gone too, so an empty file and an empty routing table agree.
///
/// Beside the swanctl directory rather than inside it: that one is 0700 root
/// (it holds the PSKs) and `commit` runs as the admin, which cannot traverse
/// it — so the list read back empty and a removed tunnel kept its route.
const ROUTES_STATE: &str = "/run/sentinel/ipsec-routes";
// Private auxiliary routes must coexist with Wren/operator routes, not replace
// them at metric zero. Both tags are also required on every owned deletion.
const ROUTE_PROTOCOL: &str = "201";
const ROUTE_METRIC: &str = "42760";

/// Extract only our canonical top-level connection/secret sections. The files
/// are root-private; never include their contents (or PSKs) in diagnostics.
fn rendered_sections(body: &str, prefix: &str) -> Result<BTreeMap<String, String>> {
    ensure!(
        body.starts_with("# rendered by sentinel"),
        "unowned IPsec runtime configuration"
    );
    let mut sections = BTreeMap::new();
    let mut current: Option<(String, String)> = None;
    for line in body.lines() {
        if let Some((_, section)) = current.as_mut() {
            section.push_str(line);
            section.push('\n');
            if line == "    }" {
                let (name, section) = current.take().expect("section is present");
                ensure!(
                    sections.insert(name, section).is_none(),
                    "duplicate IPsec runtime section"
                );
            }
        } else if let Some(name) = line.strip_prefix(prefix).and_then(|s| s.strip_suffix(" {")) {
            ensure!(
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "invalid IPsec runtime connection name"
            );
            current = Some((name.to_owned(), format!("{line}\n")));
        }
    }
    ensure!(current.is_none(), "incomplete IPsec runtime section");
    Ok(sections)
}

/// Match by name and effective rendered settings, including PSKs and XFRM IDs.
/// Reordering connections or editing an unrelated feature must not restart SAs.
fn retired_connections(
    previous_conf: &str,
    previous_secrets: &str,
    conf: &str,
    secrets: &str,
) -> Result<Vec<String>> {
    let previous = rendered_sections(previous_conf, "    conn-")?;
    let old_keys = rendered_sections(previous_secrets, "    ike-")?;
    let wanted = rendered_sections(conf, "    conn-")?;
    let keys = rendered_sections(secrets, "    ike-")?;
    let mut retired = Vec::new();
    for (name, section) in previous {
        let old_key = old_keys
            .get(&name)
            .context("missing IPsec runtime credential section")?;
        if wanted.get(&name) != Some(&section) || keys.get(&name) != Some(old_key) {
            retired.push(name);
        }
    }
    Ok(retired)
}

fn without_connections(conf: &str, retired: &[String]) -> Result<String> {
    let mut result = String::from("# rendered by sentinel — IPsec transition\nconnections {\n");
    for (name, section) in rendered_sections(conf, "    conn-")? {
        if !retired.contains(&name) {
            result.push_str(&section);
        }
    }
    result.push_str(&format!("}}\ninclude {SWANCTL_SECRETS}\n"));
    Ok(result)
}

/// The routes a set of connections needs, as `ip route` argument lists.
///
/// charon is told **not** to install routes (`install_routes = no` in the
/// appliance's `strongswan.conf`): Sentinel owns the routing table, and a
/// route-based tunnel's selectors are `0.0.0.0/0`, so charon's own route would
/// be a default route quietly outranking the box's. The consequence is that
/// nothing else installed them either, and a policy-based tunnel came up
/// perfectly — SAs established, selectors correct — while carrying nothing: a
/// packet with no route is never offered to the XFRM policy at all.
///
/// Two deliberate limits:
///
/// * **Policy-based only.** A route-based tunnel (`vti`) is reached through its
///   own interface and the operator's own routes; the objection above stands.
/// * **`src` is required.** Without it the kernel sources a locally-generated
///   packet from the outgoing (WAN) address, which does not match `local_ts` —
///   so it would leave the box **unencrypted** rather than through the tunnel.
///   A route that turns a failure into a plaintext leak is worse than no route,
///   so a connection whose local subnet the box holds no address in gets none.
///   Traffic *forwarded* from behind the firewall already carries a matching
///   source and is what a site-to-site tunnel is for.
fn tunnel_routes(conns: &[IpsecConnection], addrs: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for c in conns {
        if c.vti.is_some() {
            continue;
        }
        let (Some(remote_net), Some(local_net)) = (&c.remote_subnet, &c.local_subnet) else {
            continue;
        };
        // A default route through a tunnel is the case the objection above is
        // about — never install one from here.
        if remote_net == "0.0.0.0/0" || remote_net == "::/0" {
            continue;
        }
        let Some(src) = local_address_in(addrs, local_net) else {
            continue;
        };
        out.push(vec![
            "replace".into(),
            remote_net.clone(),
            "via".into(),
            c.remote.clone(),
            "src".into(),
            src,
            "proto".into(),
            ROUTE_PROTOCOL.into(),
            "metric".into(),
            ROUTE_METRIC.into(),
        ]);
    }
    out
}

/// Only replace a route if both its reserved tags and the previous journal
/// prove ownership. `add` is atomic when absent, so a concurrent foreign route
/// at this metric is never overwritten by a blind `replace`.
fn route_operation(
    journal: &str,
    route: &[String],
    observed: &[serde_json::Value],
) -> Result<&'static str> {
    let matches: Vec<_> = observed
        .iter()
        .filter(|r| r["metric"].as_u64() == Some(42760))
        .collect();
    if matches.is_empty() {
        return Ok("add");
    }
    let expected = format!("{} {}", route[1], route[3]);
    ensure!(
        matches.len() == 1
            && journal.lines().any(|l| l == expected)
            && (matches[0]["protocol"].as_u64() == Some(201)
                || matches[0]["protocol"].as_str() == Some(ROUTE_PROTOCOL))
            && matches[0]["gateway"].as_str() == Some(route[3].as_str()),
        "foreign or unjournalled route occupies the protected IPsec metric for {}; refusing replacement",
        route[1]
    );
    Ok("replace")
}

/// Reconcile only journalled, protocol/metric-tagged auxiliary routes. Missing
/// old routes are harmless; inspection/install failures are not silent success.
fn reconcile_routes(wanted: &[Vec<String>]) -> Result<()> {
    let previous = std::fs::read_to_string(ROUTES_STATE).unwrap_or_default();
    // `<subnet> <peer>` is enough to delete a route; the source address is not
    // part of a route's identity.
    let keep: Vec<String> = wanted
        .iter()
        .map(|r| format!("{} {}", r[1], r[3]))
        .collect();
    for line in previous.lines().filter(|l| !l.trim().is_empty()) {
        if keep.iter().any(|k| k == line) {
            continue;
        }
        let mut f = line.split_whitespace();
        if let (Some(net), Some(peer)) = (f.next(), f.next()) {
            if let Err(e) = system::ip_route(&[
                "del",
                net,
                "via",
                peer,
                "proto",
                ROUTE_PROTOCOL,
                "metric",
                ROUTE_METRIC,
            ]) {
                eprintln!("warning: removing the route to {net} failed: {e}");
            }
        }
    }
    for r in wanted {
        let observed = system::escalated_output(
            "ip",
            &["-j", "-4", "route", "show", "table", "main", "exact", &r[1]],
        )?;
        ensure!(
            observed.status.success(),
            "cannot inspect the protected IPsec route"
        );
        let observed: Vec<serde_json::Value> =
            serde_json::from_slice(&observed.stdout).context("invalid kernel route inspection")?;
        let operation = route_operation(&previous, r, &observed)?;
        let mut args: Vec<&str> = r.iter().map(String::as_str).collect();
        args[0] = operation;
        system::ip_route(&args).with_context(|| format!("installing protected route {}", r[1]))?;
    }
    let state = keep.join("\n");
    if state.is_empty() {
        system::remove_file(Path::new(ROUTES_STATE))?;
    } else {
        system::install_file(Path::new(ROUTES_STATE), &format!("{state}\n"))?;
    }
    Ok(())
}

/// An address the box holds inside `subnet`, from `ip -o addr show` output.
///
/// Pure so the parsing and the containment arithmetic are testable without a
/// kernel. IPv4 only, which is what the policy-based tunnel surface accepts.
fn local_address_in(addrs: &str, subnet: &str) -> Option<String> {
    let (net, bits) = subnet.split_once('/')?;
    let bits: u32 = bits.parse().ok()?;
    let net: std::net::Ipv4Addr = net.parse().ok()?;
    // `/0` would shift by 32, which is undefined for u32; it also cannot be a
    // tunnel's local subnet in any useful sense.
    if bits == 0 || bits > 32 {
        return None;
    }
    let mask = u32::MAX << (32 - bits);
    let want = u32::from(net) & mask;
    addrs.lines().find_map(|l| {
        // `2: eth1    inet 10.0.0.1/24 brd … scope global eth1\…`
        let mut f = l.split_whitespace();
        let cidr = loop {
            if f.next()? == "inet" {
                break f.next()?;
            }
        };
        let addr: std::net::Ipv4Addr = cidr.split('/').next()?.parse().ok()?;
        (u32::from(addr) & mask == want).then(|| addr.to_string())
    })
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
fn swanctl_conf_body(conns: &[IpsecConnection], ifaces: &[Interface]) -> String {
    // A route-based tunnel names its link; the child SA needs that link's id.
    // Resolved here, once, from the same list validation checked against — so a
    // name that got through cannot fail to resolve.
    let vti_id = |c: &IpsecConnection| -> Option<u32> {
        let name = c.vti.as_deref()?;
        ifaces
            .iter()
            .find(|i| i.name == name)
            .and_then(|i| i.vti_key)
    };
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
        let vti_id = vti_id(c);
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
        // On a route-based tunnel the routing table decides what is encrypted, so
        // the selectors open to everything and narrowing them is optional. On a
        // policy-based one they are the whole reach, and validation has already
        // insisted on them.
        let any = if c.vti.is_some() { "0.0.0.0/0" } else { "" };
        let local_ts = c.local_subnet.as_deref().unwrap_or(any);
        let remote_ts = c.remote_subnet.as_deref().unwrap_or(any);
        s.push_str(&format!("                local_ts = {local_ts}\n"));
        s.push_str(&format!("                remote_ts = {remote_ts}\n"));
        s.push_str(&format!("                esp_proposals = {esp}\n"));
        s.push_str("                mode = tunnel\n");
        // Route-based: both directions carry the bound link's id, so the kernel
        // knows which interface a decrypted packet arrived on and which SA an
        // outbound one belongs to. One id for both because a single link is both
        // ends of the same tunnel here; separate ids exist for the case where the
        // two directions are different interfaces, which this does not offer.
        if let Some(id) = vti_id {
            s.push_str(&format!("                if_id_in = {id}\n"));
            s.push_str(&format!("                if_id_out = {id}\n"));
        }
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
    let guards = crate::ipsec_guards::prepare(appliance)?;
    let conns = &appliance.vpn.ipsec;
    let conf_path = Path::new(SWANCTL_CONF);
    let secrets_path = Path::new(SWANCTL_SECRETS);
    let conf = swanctl_conf_body(conns, &appliance.interfaces);
    let secrets = swanctl_secrets_body(conns);
    // The CLI runs as admin and cannot traverse this root-only directory.
    // Permission denied must never masquerade as an absent previous config.
    let previous_conf = system::read_owned_file(conf_path)?;
    if let Some(previous) = &previous_conf {
        let previous_secrets =
            system::read_owned_file(secrets_path)?.context("missing IPsec runtime credentials")?;
        let retired = retired_connections(previous, &previous_secrets, &conf, &secrets)?;
        if !retired.is_empty() {
            // First unload ONLY removed/changed definitions, retaining every
            // unchanged connection. This prevents new handshakes using revoked
            // settings while established IKE/CHILD SAs are being terminated.
            // load-conns does not reload credentials or flush kernel state.
            system::install_file(conf_path, &without_connections(previous, &retired)?)?;
            system::swanctl_reload_connections(conf_path)?;
            for name in retired {
                system::swanctl_revoke(&format!("conn-{name}"))?;
            }
        }
    }

    if conns.is_empty() {
        // Nothing configured. If a previous apply wrote a config, load an empty
        // one to unload the connections from charon, then remove the artifacts.
        if previous_conf.is_some() {
            system::remove_file(conf_path)?;
            system::remove_file(secrets_path)?;
        }
        // Unconditionally: the routes outlive the config file they came from,
        // and leaving them is the plaintext case [`ROUTES_STATE`] describes.
        reconcile_routes(&[])?;
        crate::ipsec_guards::finish(&guards)?;
        return Ok(());
    }

    system::ensure_dir(Path::new(SWANCTL_RUNTIME_DIR))?;
    system::install_file(conf_path, &conf)?;
    system::install_ipsec_secret(secrets_path, &secrets)?;
    // Load when the rendered config changed, or unconditionally when a tunnel is
    // configured (a fresh boot re-asserts charon's state even if the tmpfs file
    // matches what a previous run wrote).
    if let Err(e) = system::swanctl_load(conf_path) {
        eprintln!("warning: loading swanctl config failed (applies on next commit/boot): {e}");
    }
    // And the routes that make the loaded policy reachable. Read the addresses
    // from the kernel rather than the configuration: the address inside a
    // protected subnet may have come from DHCP or from a link Sentinel does not
    // own, and what matters is the one the box actually holds.
    let addrs = system::ip_addr_list().unwrap_or_default();
    reconcile_routes(&tunnel_routes(conns, &addrs))?;
    crate::ipsec_guards::finish(&guards)?;
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
            local_subnet: Some("10.0.0.0/24".into()),
            remote_subnet: Some("10.1.0.0/24".into()),
            vti: None,
            psk: "topsecret".into(),
            ike_version: None,
            ike_proposal: None,
            esp_proposal: None,
            local_id: None,
            remote_id: None,
            start_action: None,
        }
    }

    fn retired(old: &[IpsecConnection], wanted: &[IpsecConnection]) -> Vec<String> {
        retired_connections(
            &swanctl_conf_body(old, &[]),
            &swanctl_secrets_body(old),
            &swanctl_conf_body(wanted, &[]),
            &swanctl_secrets_body(wanted),
        )
        .unwrap()
    }

    #[test]
    fn removed_and_changed_connections_revoke_only_their_own_sas() {
        let first = conn();
        let mut other = conn();
        other.name = "site-b".into();
        let previous = [first.clone(), other.clone()];
        assert_eq!(retired(&previous, std::slice::from_ref(&other)), ["site-a"]);
        let mut changed = first;
        changed.psk = "replacement-private-key".into();
        assert_eq!(
            retired(&previous, &[changed.clone(), other.clone()]),
            ["site-a"]
        );
        changed = previous[0].clone();
        changed.remote_subnet = Some("10.2.0.0/24".into());
        assert_eq!(retired(&previous, &[changed, other]), ["site-a"]);
    }

    #[test]
    fn unchanged_and_reordered_connections_preserve_live_sas() {
        let first = conn();
        let mut other = conn();
        other.name = "site-b".into();
        assert!(retired(&[first.clone(), other.clone()], &[other, first]).is_empty());
    }

    #[test]
    fn effective_defaults_do_not_restart_a_tunnel() {
        let previous = conn();
        let mut explicit = previous.clone();
        explicit.ike_version = Some(2);
        explicit.ike_proposal = Some(DEFAULT_IKE_PROPOSAL.into());
        explicit.esp_proposal = Some(DEFAULT_ESP_PROPOSAL.into());
        explicit.start_action = Some(DEFAULT_IPSEC_START_ACTION.into());
        assert!(retired(&[previous], &[explicit]).is_empty());
    }

    #[test]
    fn transition_unloads_revoked_definitions_but_keeps_other_sections_exact() {
        let mut keep = conn();
        keep.name = "keep".into();
        let conf = swanctl_conf_body(&[conn(), keep.clone()], &[]);
        let intermediate = without_connections(&conf, &["site-a".into()]).unwrap();
        let parsed = rendered_sections(&intermediate, "    conn-").unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed,
            rendered_sections(&swanctl_conf_body(&[keep], &[]), "    conn-").unwrap()
        );
        assert!(intermediate.ends_with(&format!("include {SWANCTL_SECRETS}\n")));
    }

    #[test]
    fn malformed_runtime_sections_fail_closed_without_exposing_secrets() {
        for invalid in [
            "connections {\n}",
            "# rendered by sentinel\n    conn-unsafe/name {\n    }\n",
            "# rendered by sentinel\n    conn-open {\n",
            "# rendered by sentinel\n    conn-duplicate {\n    }\n    conn-duplicate {\n    }\n",
        ] {
            assert!(rendered_sections(invalid, "    conn-").is_err());
        }
        let error = retired_connections(
            &swanctl_conf_body(&[conn()], &[]),
            &swanctl_secrets_body(&[]),
            &swanctl_conf_body(&[], &[]),
            &swanctl_secrets_body(&[]),
        )
        .unwrap_err();
        assert!(!error.to_string().contains("topsecret"));
    }

    /// `ip -o addr show` as the kernel prints it, abridged.
    const ADDRS: &str = "\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever
2: eth1    inet 203.0.113.1/24 brd 203.0.113.255 scope global eth1\\       valid_lft forever
3: proto0    inet 10.0.0.1/24 brd 10.0.0.255 scope global proto0\\       valid_lft forever
";

    #[test]
    fn a_policy_based_tunnel_gets_a_route_sourced_from_its_own_subnet() {
        let routes = tunnel_routes(&[conn()], ADDRS);
        assert_eq!(
            routes,
            vec![vec![
                "replace".to_string(),
                "10.1.0.0/24".into(),
                "via".into(),
                "198.51.100.1".into(),
                // Not the WAN address: sourced from the WAN the packet would
                // miss its own out policy and leave unencrypted.
                "src".into(),
                "10.0.0.1".into(),
                "proto".into(),
                ROUTE_PROTOCOL.into(),
                "metric".into(),
                ROUTE_METRIC.into(),
            ]]
        );
    }

    #[test]
    fn auxiliary_route_does_not_replace_an_operator_route_at_another_metric() {
        let route = &tunnel_routes(&[conn()], ADDRS)[0];
        let operator = serde_json::json!({"protocol":"static", "gateway":"198.51.100.1"});
        assert_eq!(route_operation("", route, &[operator]).unwrap(), "add");
    }

    #[test]
    fn auxiliary_route_replacement_requires_both_actual_tags_and_journal() {
        let route = &tunnel_routes(&[conn()], ADDRS)[0];
        let journal = "10.1.0.0/24 198.51.100.1\n";
        let owned = serde_json::json!({"protocol":201,"metric":42760,"gateway":"198.51.100.1"});
        assert_eq!(
            route_operation(journal, route, std::slice::from_ref(&owned)).unwrap(),
            "replace"
        );
        assert!(route_operation("", route, &[owned]).is_err());
        for foreign in [
            serde_json::json!({"protocol":"static","metric":42760,"gateway":"198.51.100.1"}),
            serde_json::json!({"protocol":201,"metric":42760,"gateway":"198.51.100.2"}),
        ] {
            assert!(route_operation(journal, route, &[foreign]).is_err());
        }
    }

    #[test]
    fn no_address_in_the_local_subnet_means_no_route() {
        // The box holds nothing in 192.168.9.0/24, so a locally-generated
        // packet could only be sourced from the WAN — which the tunnel's own
        // selectors would not match. Refusing the route keeps that traffic
        // failing instead of leaving in the clear.
        let mut c = conn();
        c.local_subnet = Some("192.168.9.0/24".into());
        assert!(tunnel_routes(&[c], ADDRS).is_empty());
    }

    #[test]
    fn a_route_based_tunnel_and_a_default_selector_get_no_route() {
        let mut vti = conn();
        vti.vti = Some("vti0".into());
        assert!(tunnel_routes(&[vti], ADDRS).is_empty());

        let mut all = conn();
        all.remote_subnet = Some("0.0.0.0/0".into());
        assert!(tunnel_routes(&[all], ADDRS).is_empty());
    }

    #[test]
    fn local_address_lookup_respects_the_mask() {
        assert_eq!(
            local_address_in(ADDRS, "10.0.0.0/24").as_deref(),
            Some("10.0.0.1")
        );
        // A /16 that contains it, and a /24 next door that does not.
        assert_eq!(
            local_address_in(ADDRS, "10.0.0.0/16").as_deref(),
            Some("10.0.0.1")
        );
        assert_eq!(local_address_in(ADDRS, "10.0.1.0/24"), None);
        // `/0` matches everything and so identifies nothing.
        assert_eq!(local_address_in(ADDRS, "0.0.0.0/0"), None);
        assert_eq!(local_address_in(ADDRS, "nonsense"), None);
    }

    #[test]
    fn conf_renders_connection_children_and_defaults() {
        let body = swanctl_conf_body(&[conn()], &[]);
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
        let body = swanctl_conf_body(&[c], &[]);
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

    /// A tunnel bound to a link is route-based: both directions carry the link's
    /// id, and the selectors open to everything because the routing table is what
    /// decides.
    #[test]
    fn a_bound_tunnel_is_route_based() {
        // Built from TOML rather than a struct literal: the point of the test is
        // that a configuration an operator could write renders as route-based,
        // and `Interface` has no Default to fake one with.
        let a = Appliance::from_toml(
            r#"
[system]
hostname = "fw"
[[interface]]
name = "vti0"
type = "vti"
vti-key = 42
address = "10.255.0.1/30"
"#,
        )
        .unwrap();
        let link = a.interfaces.clone();
        let c = IpsecConnection {
            vti: Some("vti0".into()),
            local_subnet: None,
            remote_subnet: None,
            ..conn()
        };
        let body = swanctl_conf_body(&[c], &link);
        assert!(body.contains("if_id_in = 42"), "{body}");
        assert!(body.contains("if_id_out = 42"), "{body}");
        assert!(body.contains("local_ts = 0.0.0.0/0"), "{body}");
        assert!(body.contains("remote_ts = 0.0.0.0/0"), "{body}");

        // Narrowing is still allowed — a route-based tunnel may refuse to carry
        // what its routes would otherwise hand it.
        let narrowed = IpsecConnection {
            vti: Some("vti0".into()),
            local_subnet: Some("10.0.0.0/24".into()),
            remote_subnet: None,
            ..conn()
        };
        let body = swanctl_conf_body(&[narrowed], &link);
        assert!(body.contains("local_ts = 10.0.0.0/24"), "{body}");
        assert!(body.contains("remote_ts = 0.0.0.0/0"), "{body}");
    }

    /// An unbound tunnel is policy-based and carries no interface id at all — a
    /// stray `if_id` would bind it to a link that does not exist.
    #[test]
    fn an_unbound_tunnel_carries_no_interface_id() {
        let body = swanctl_conf_body(&[conn()], &[]);
        assert!(!body.contains("if_id"), "{body}");
    }

    #[test]
    fn empty_connections_render_an_empty_block() {
        let body = swanctl_conf_body(&[], &[]);
        assert!(body.contains("connections {"), "{body}");
        assert!(!body.contains("conn-"), "{body}");
    }
}
