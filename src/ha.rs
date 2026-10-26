//! Declarative member identities, witness configuration and kernel-guard intent.
use crate::{
    config::{Appliance, HaIdentity, HaInterfaceIdentity},
    system,
};
use anyhow::{Context, Result, ensure};
use ring::{digest, hmac};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    path::Path,
};

pub const WITNESS_CONFIG: &str = "/run/sentinel/witness.json";
#[derive(Debug, Serialize)]
pub struct DataplaneHa {
    enabled: bool,
    cluster: String,
    node: u8,
    interfaces: Vec<String>,
    disabled: Vec<String>,
    wireguard_ports: Vec<u16>,
    wireguard: Vec<String>,
    wireguard_policy: String,
}
#[derive(Serialize)]
pub struct RoutingHa {
    cluster: String,
    node: u8,
    witness: String,
    secret: String,
    priority: u8,
    preempt: bool,
    wireguard: Vec<String>,
    wireguard_policy: String,
}
impl std::fmt::Debug for RoutingHa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutingHa")
            .field("cluster", &self.cluster)
            .field("node", &self.node)
            .field("witness", &self.witness)
            .field("secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}
pub fn derive(token: &str, label: &[u8], cluster: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, token.as_bytes());
    let mut context = hmac::Context::with_key(&key);
    context.update(label);
    context.update(cluster.as_bytes());
    context
        .sign()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub fn cluster_id(token: &str) -> String {
    derive(token, b"Velstra Sentinel HA cluster v1\0", "")[..32].into()
}
fn valid_cluster(cluster: &str) -> bool {
    (16..=128).contains(&cluster.len())
        && cluster
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
}
fn numeric_endpoint(value: &str) -> Result<SocketAddr> {
    let endpoint: SocketAddr = value
        .parse()
        .context("HA endpoint must be a numeric IP:port (bracket IPv6)")?;
    ensure!(endpoint.port() > 0, "HA endpoint port must be nonzero");
    Ok(endpoint)
}
/// Guard every declared data link and its L2 ancestry. A dedicated
/// control interface and its underlay cannot be shared with this closure.
pub fn guarded_interfaces(a: &Appliance) -> BTreeSet<String> {
    let Some(ha) = &a.system.ha else {
        return BTreeSet::new();
    };
    let control =
        control_interfaces(a).unwrap_or_else(|_| [ha.sync_interface.clone()].into_iter().collect());
    let mut names: BTreeSet<_> = if ha.enabled || !ha.sync_interface.is_empty() {
        a.interfaces
            .iter()
            .filter(|i| !control.contains(&i.name))
            .map(|i| i.name.clone())
            .collect()
    } else {
        BTreeSet::new()
    };
    names.extend(
        a.protocols
            .vrrp
            .iter()
            .map(|v| v.address_interface.as_ref().unwrap_or(&v.interface).clone()),
    );
    names.extend(
        a.vpn
            .wireguard
            .iter()
            .filter(|w| w.name != ha.sync_interface)
            .map(|w| w.name.clone()),
    );
    loop {
        let before = names.len();
        for i in &a.interfaces {
            if names.contains(&i.name) {
                names.extend(i.parent.iter().cloned());
                names.extend(i.members.iter().cloned());
            }
        }
        if names.len() == before {
            break;
        }
    }
    names
}
pub fn dataplane(a: &Appliance) -> Option<DataplaneHa> {
    let ha = a.system.ha.as_ref()?;
    let interfaces: Vec<_> = guarded_interfaces(a).into_iter().collect();
    if interfaces.is_empty() {
        return None;
    }
    Some(DataplaneHa {
        enabled: ha.enabled,
        cluster: ha.cluster.clone(),
        node: ha.node(),
        disabled: a
            .interfaces
            .iter()
            .filter(|i| i.disabled && interfaces.contains(&i.name))
            .map(|i| i.name.clone())
            .collect(),
        interfaces,
        wireguard_policy: wireguard_policy(a),
        wireguard: a
            .vpn
            .wireguard
            .iter()
            .filter(|w| w.name != ha.sync_interface)
            .map(|w| w.name.clone())
            .collect(),
        wireguard_ports: a
            .vpn
            .wireguard
            .iter()
            .filter(|w| w.name != ha.sync_interface)
            .filter_map(|w| w.listen_port)
            .collect(),
    })
}
pub fn routing(a: &Appliance) -> Option<RoutingHa> {
    let ha = a.system.ha.as_ref().filter(|h| h.enabled)?;
    Some(RoutingHa {
        cluster: ha.cluster.clone(),
        node: ha.node(),
        witness: ha.witness.clone(),
        secret: derive(
            a.system.config_sync.secret.as_deref().unwrap_or_default(),
            b"Velstra Sentinel witness key v1\0",
            &ha.cluster,
        ),
        priority: ha.priority(),
        preempt: ha.preempt,
        wireguard_policy: wireguard_policy(a),
        wireguard: a
            .vpn
            .wireguard
            .iter()
            .filter(|w| w.name != ha.sync_interface)
            .map(|w| w.name.clone())
            .collect(),
    })
}
fn interface_address(a: &Appliance, name: &str, address: IpAddr) -> bool {
    a.interfaces
        .iter()
        .find(|i| i.name == name)
        .is_some_and(|i| {
            [i.address.as_deref(), i.address6.as_deref()]
                .into_iter()
                .flatten()
                .any(|s| {
                    s.split('/').next().and_then(|v| v.parse::<IpAddr>().ok()) == Some(address)
                })
        })
}
pub fn validate(a: &Appliance) -> Result<()> {
    ensure!(
        a.system.ha.is_none() || a.system.ha_witness.is_none(),
        "a witness must be independent of either HA member"
    );
    if let Some(w) = &a.system.ha_witness {
        numeric_endpoint(&w.listen)?;
        ensure!(
            (32..=1024).contains(&w.secret.len()),
            "HA witness secret must contain 32..1024 bytes"
        );
        ensure!(
            w.cluster.is_empty() || valid_cluster(&w.cluster),
            "invalid HA witness cluster identifier"
        );
    }
    let Some(ha) = &a.system.ha else {
        return Ok(());
    };
    let witness = numeric_endpoint(&ha.witness)?;
    ensure!(
        !witness.ip().is_unspecified(),
        "HA witness must name an independent endpoint"
    );
    ensure!(
        (1..=2).contains(&ha.node()) && ha.priority() > 0,
        "HA node must be 1 or 2; priority must be nonzero"
    );
    ensure!(
        ha.cluster.is_empty() || valid_cluster(&ha.cluster),
        "invalid HA cluster identifier"
    );
    if !ha.enabled {
        return Ok(());
    }
    ensure!(
        valid_cluster(&ha.cluster),
        "enabled HA requires a stable cluster identifier"
    );
    ensure!(
        a.system
            .config_sync
            .secret
            .as_ref()
            .is_some_and(|s| (32..=1024).contains(&s.len())),
        "HA needs a 32..1024 byte enrollment credential"
    );
    ensure!(
        a.system.config_sync.peers.len() == 1 && a.system.conntrack_sync.peers.len() == 1,
        "HA needs exactly one configuration and state peer"
    );
    ensure!(
        a.system.conntrack_sync.interval.is_none(),
        "leased HA uses 50ms state sync; omit the legacy interval in seconds"
    );
    let listen = numeric_endpoint(
        a.system
            .conntrack_sync
            .listen
            .as_deref()
            .context("HA needs an explicit state-sync listen IP:port")?,
    )?;
    let peer = numeric_endpoint(&a.system.conntrack_sync.peer_endpoints()[0])?;
    ensure!(
        !listen.ip().is_unspecified() && listen.ip() != peer.ip(),
        "HA members need distinct explicit state-sync addresses"
    );
    ensure!(
        interface_address(a, &ha.sync_interface, listen.ip()),
        "HA state-sync listen address must belong to the declared sync-interface"
    );
    ensure!(
        !a.protocols.vrrp.is_empty(),
        "HA needs declared virtual addresses"
    );
    let guarded = guarded_interfaces(a);
    ensure!(
        guarded.len() <= 128,
        "HA supports at most 128 guarded data links"
    );
    let control = control_interfaces(a)?;
    ensure!(
        guarded.is_disjoint(&control),
        "HA control underlay cannot carry fenced data/VIPs"
    );
    for source in a
        .nat
        .source
        .iter()
        .filter(|s| !s.disabled && s.to.is_none())
    {
        for interface in a
            .interfaces
            .iter()
            .filter(|i| !i.disabled && i.zone.as_deref() == Some(&source.zone))
        {
            ensure!(
                shared_v4(a, &interface.name).len() == 1,
                "HA masquerade on {} requires exactly one shared IPv4 VIP or an explicit nat.source.to address",
                interface.name
            );
        }
    }

    ensure!(
        !guarded.contains(&ha.sync_interface),
        "HA control traffic needs a dedicated interface outside the fenced dataplane"
    );
    for name in &guarded {
        ensure!(
            a.interfaces.iter().any(|i| &i.name == name),
            "HA guarded link {name} must be explicitly declared"
        );
    }
    for w in &a.vpn.wireguard {
        if w.name != ha.sync_interface {
            ensure!(
                w.listen_port.is_some_and(|p| p > 0),
                "HA WireGuard data VPNs need an explicit listen-port"
            );
        }
    }
    for v in &a.protocols.vrrp {
        ensure!(
            v.priority.is_none_or(|p| p == ha.priority()),
            "all HA VIPs must use the member's HA priority"
        );
        ensure!(
            v.preempt.is_none_or(|p| p == ha.preempt),
            "all HA VIPs must share HA preempt policy"
        );
    }
    if let Some(pin) = &ha.management_fingerprint {
        ensure!(
            crate::config::is_valid_pinned_sha256(pin),
            "invalid HA management fingerprint"
        );
    }
    if let Some(identity) = &ha.peer_identity {
        ensure!(
            identity.node == 3 - ha.node() && identity.priority > 0,
            "peer identity names the wrong HA member"
        );
        ensure!(
            crate::config::is_valid_pinned_sha256(&identity.management_fingerprint),
            "invalid HA peer TLS fingerprint"
        );
        ensure!(
            ha.management_fingerprint.is_some(),
            "paired HA needs this member's management fingerprint"
        );
        numeric_endpoint(&identity.management_endpoint)?;
        numeric_endpoint(&identity.state_listen)?;
        for i in &a.interfaces {
            let node_specific = i.address.as_deref().is_some_and(|s| s != "dhcp")
                || i.address6
                    .as_deref()
                    .is_some_and(|s| !matches!(s, "auto" | "dhcp"))
                || i.local.is_some();
            ensure!(
                !node_specific || identity.interfaces.contains_key(&i.name),
                "new interface {} needs its peer-specific identity in system.ha.peer-identity",
                i.name
            );
        }
        // Validate the materialized peer through the ordinary complete schema,
        // with reverse-profile recursion disabled for this one validation pass.
        let mut peer = materialize_peer(a.clone())?;
        ensure!(
            guarded_interfaces(a) == guarded_interfaces(&peer),
            "HA members must have the same logical dedicated control underlay"
        );
        peer.system.ha.as_mut().expect("HA retained").peer_identity = None;
        peer.validate()
            .context("peer-adjusted appliance is invalid")?;
    }
    Ok(())
}
fn management_endpoint(a: &Appliance) -> Result<String> {
    let state = numeric_endpoint(
        a.system
            .conntrack_sync
            .listen
            .as_deref()
            .context("HA state endpoint missing")?,
    )?;
    let ip = a
        .services
        .web
        .listen_address
        .as_deref()
        .filter(|s| !matches!(*s, "0.0.0.0" | "::" | "127.0.0.1" | "::1"))
        .map(str::parse::<IpAddr>)
        .transpose()?
        .unwrap_or(state.ip());
    Ok(SocketAddr::new(
        ip,
        if a.services.web.enable {
            a.services.web.port.unwrap_or(8080)
        } else {
            8080
        },
    )
    .to_string())
}
pub fn capture(a: &Appliance) -> Result<HaIdentity> {
    let ha = a.system.ha.as_ref().context("HA member identity missing")?;
    Ok(HaIdentity {
        node: ha.node(),
        hostname: a.system.hostname.clone(),
        router_id: a.protocols.router_id.clone(),
        management_endpoint: management_endpoint(a)?,
        management_fingerprint: ha
            .management_fingerprint
            .clone()
            .context("HA TLS identity missing")?,
        management_web: Some(a.services.web.clone()),
        state_listen: a
            .system
            .conntrack_sync
            .listen
            .clone()
            .context("HA state endpoint missing")?,
        priority: ha.priority(),
        interfaces: a
            .interfaces
            .iter()
            .map(|i| {
                (
                    i.name.clone(),
                    HaInterfaceIdentity {
                        address: i.address.clone(),
                        address6: i.address6.clone(),
                        local: i.local.clone(),
                    },
                )
            })
            .collect(),
        control_wireguard: a
            .vpn
            .wireguard
            .iter()
            .find(|w| w.name == ha.sync_interface)
            .cloned(),
    })
}
/// Swap node-specific facts while retaining the complete shared desired policy.
/// Applying the reverse swap produces the original primary document again.
pub fn materialize_peer(mut a: Appliance) -> Result<Appliance> {
    let source = capture(&a)?;
    let target = a
        .system
        .ha
        .as_ref()
        .and_then(|h| h.peer_identity.clone())
        .context("peer identity missing")?;
    let ha = a.system.ha.as_mut().context("HA missing")?;
    ensure!(target.node == 3 - ha.node(), "HA peer node mismatch");
    ha.node = Some(target.node);
    ha.priority = Some(target.priority);
    ha.management_fingerprint = Some(target.management_fingerprint.clone());
    ha.peer_identity = Some(source.clone());
    a.system.hostname = target.hostname;
    if let Some(web) = target.management_web {
        a.services.web = web;
    }
    a.protocols.router_id = target.router_id;
    a.system.config_sync.peers = vec![source.management_endpoint];
    a.system.config_sync.peer_fingerprint = Some(source.management_fingerprint);
    a.system.conntrack_sync.listen = Some(target.state_listen);
    a.system.conntrack_sync.peers = vec![source.state_listen];
    for i in &mut a.interfaces {
        if let Some(facts) = target.interfaces.get(&i.name) {
            i.address = facts.address.clone();
            i.address6 = facts.address6.clone();
            i.local = facts.local.clone();
        } else {
            ensure!(
                i.address.as_deref().is_none_or(|s| s == "dhcp")
                    && i.address6
                        .as_deref()
                        .is_none_or(|s| matches!(s, "auto" | "dhcp"))
                    && i.local.is_none(),
                "interface {} lacks peer addressing",
                i.name
            );
        }
    }
    if let Some(control) = target.control_wireguard {
        let wireguard = &mut a.vpn.wireguard;
        if let Some(existing) = wireguard.iter_mut().find(|w| w.name == control.name) {
            *existing = control;
        } else {
            wireguard.push(control);
        }
    }
    for v in &mut a.protocols.vrrp {
        v.priority = Some(target.priority);
        v.preempt = Some(ha.preempt);
    }
    Ok(a)
}

#[derive(Serialize)]
struct WitnessRuntime {
    cluster: String,
    secret: String,
    listen: String,
    state: &'static str,
}
pub fn apply_witness(a: &Appliance, live: bool) -> Result<()> {
    let path = Path::new(WITNESS_CONFIG);
    if let Some(w) = &a.system.ha_witness {
        let cluster = if w.cluster.is_empty() {
            cluster_id(&w.secret)
        } else {
            w.cluster.clone()
        };
        let runtime = WitnessRuntime {
            secret: derive(&w.secret, b"Velstra Sentinel witness key v1\0", &cluster),
            cluster,
            listen: w.listen.clone(),
            state: "/var/lib/sentinel/witness/state.json",
        };
        let text = serde_json::to_string(&runtime)?;
        let changed = system::read_owned_file(path)?.as_deref() != Some(&text);
        system::install_ha_secret(path, &text)?;
        if live {
            if changed {
                system::service_restart("sentinel-witness.service")?;
            } else {
                system::service_start("sentinel-witness.service")?;
            }
        }
    } else if system::owned_file_exists(path)? {
        system::remove_file(path)?;
        if live {
            system::service_stop("sentinel-witness.service")?;
        }
    }
    Ok(())
}
/// Hashes used for compare-and-apply enrollment are over canonical validated
/// TOML, not map order or JSON formatting.
pub fn revision(a: &Appliance) -> Result<String> {
    Ok(digest::digest(&digest::SHA256, a.to_toml()?.as_bytes())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// Proof is bound to both a fresh client nonce and the actual management SPKI.
/// It cannot authorize a different TLS endpoint and never sends the bearer.
pub fn enrollment_proof(token: &str, nonce: &str, pin: &str) -> Result<String> {
    ensure!(
        nonce.len() == 64 && nonce.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid enrollment nonce"
    );
    let key = hmac::Key::new(hmac::HMAC_SHA256, token.as_bytes());
    let mut message = hmac::Context::with_key(&key);
    message.update(b"Velstra Sentinel enrollment proof v1\0");
    message.update(nonce.as_bytes());
    message.update(pin.as_bytes());
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(message.sign().as_ref()))
}

pub fn authenticate_peer(authority: &str, token: &str) -> Result<String> {
    let pin = system::learn_peer_pubkey_pin(authority)?;
    let mut random = [0u8; 32];
    getrandom::getrandom(&mut random).map_err(|e| anyhow::anyhow!("enrollment randomness: {e}"))?;
    let nonce: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let response = system::curl_request(
        &format!("https://{authority}/api/v1/ha/proof/{nonce}"),
        None,
        "GET",
        None,
        5,
        Some(&pin),
    )?;
    let response: serde_json::Value = serde_json::from_str(&response)?;
    let proof = response
        .get("proof")
        .and_then(|v| v.as_str())
        .context("peer omitted credential proof")?;
    let expected = enrollment_proof(token, &nonce, &pin)?;
    use base64::Engine;
    let supplied = base64::engine::general_purpose::STANDARD.decode(proof)?;
    let expected = base64::engine::general_purpose::STANDARD.decode(expected)?;
    ensure!(
        crate::api::ct_eq(&supplied, &expected),
        "peer failed TLS-bound enrollment authentication"
    );
    Ok(pin)
}

#[derive(serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    appliance: Appliance,
    revision: String,
}
#[derive(serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PairPlan {
    peer: String,
    pin: String,
    previous: String,
    appliance: Appliance,
    request: crate::api::PairRequest,
}

fn state_address(a: &Appliance, remote: IpAddr) -> Result<(String, String)> {
    let bind = if remote.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = std::net::UdpSocket::bind(bind)?;
    socket.connect(SocketAddr::new(remote, 5429))?;
    let local = socket.local_addr()?.ip();
    let interface = a
        .interfaces
        .iter()
        .find(|i| interface_address(a, &i.name, local))
        .context("route to peer does not use an explicitly addressed control interface")?;
    Ok((
        interface.name.clone(),
        SocketAddr::new(local, 5429).to_string(),
    ))
}

pub fn pair(
    peer: &str,
    secret: &str,
    config: &Path,
    witness: Option<&str>,
    identity: Option<&Path>,
) -> Result<()> {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    ensure!(
        (32..=1024).contains(&secret.len()) && !secret.chars().any(|c| c.is_control()),
        "HA secret must contain 32..1024 non-control bytes"
    );
    let peer = numeric_endpoint(peer)?.to_string();
    if unsafe { libc::geteuid() } != 0 {
        // The already-authorized admin sudo policy is used without copying a
        // credential into sudo's command line or audit log.
        let mut command = Command::new(system::bin("sudo"));
        command
            .arg("-n")
            .arg(
                std::env::var_os("SENTINEL_PAIR_SELF_BIN")
                    .map(std::path::PathBuf::from)
                    .unwrap_or(std::env::current_exe()?),
            )
            .args(["ha", "pair", &peer, "--secret-stdin", "--config"])
            .arg(config);
        if let Some(w) = witness {
            command.args(["--witness", w]);
        }
        if let Some(i) = identity {
            command.arg("--peer-identity").arg(i);
        }
        let mut child = command.stdin(Stdio::piped()).spawn()?;
        if let Err(e) = child
            .stdin
            .take()
            .context("pair stdin")?
            .write_all(secret.as_bytes())
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e.into());
        }
        ensure!(
            child.wait()?.success(),
            "privileged HA enrollment failed; inspect the preceding diagnostic"
        );
        return Ok(());
    }
    // Bound a complete attempt; every transport operation has its own timeout.
    // A private durable plan makes interrupted/ambiguous peer acknowledgements
    // retryable without reconstructing a different desired revision.
    let plan_path = Path::new("/var/lib/sentinel/ha-pair.json");
    let _transaction = system::apply_lock()?;
    let current = Appliance::load(config)?;
    let current_revision = revision(&current)?;
    let plan: PairPlan = if let Some(text) = system::read_owned_file(plan_path)? {
        let saved: PairPlan = serde_json::from_str(&text)?;
        ensure!(
            saved.peer == peer
                && saved
                    .appliance
                    .system
                    .config_sync
                    .secret
                    .as_deref()
                    .is_some_and(|s| crate::api::ct_eq(s.as_bytes(), secret.as_bytes())),
            "another interrupted HA pairing is pending; resume its endpoint and credential"
        );
        ensure!(
            current_revision == saved.previous || current_revision == revision(&saved.appliance)?,
            "local configuration changed during interrupted pairing; review the private pairing plan before retrying"
        );
        saved
    } else {
        let pin = authenticate_peer(&peer, secret)?;
        let remote: Enrollment = serde_json::from_str(&system::curl_get(
            &format!("https://{peer}/api/v1/ha/enrollment"),
            secret,
            5,
            Some(&pin),
        )?)?;
        ensure!(
            revision(&remote.appliance)? == remote.revision,
            "inconsistent peer enrollment revision"
        );
        let mut local = current.clone();
        let mut secondary = remote.appliance;
        let witness = witness.map(str::to_owned).or_else(|| local.system.ha.as_ref().map(|h|h.witness.clone())).context("configure system.ha.witness or pass --witness with an independent witness endpoint")?;
        numeric_endpoint(&witness)?;
        let cluster = local
            .system
            .ha
            .as_ref()
            .map(|h| h.cluster.clone())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| cluster_id(secret));
        ensure!(
            local
                .system
                .ha
                .as_ref()
                .is_none_or(|h| !h.enabled || (h.node() == 1 && h.cluster == cluster)),
            "primary already has a different active HA identity"
        );
        ensure!(
            secondary
                .system
                .ha
                .as_ref()
                .is_none_or(|h| !h.enabled || (h.node() == 2 && h.cluster == cluster)),
            "peer already belongs to another active HA identity"
        );
        let remote_ip = numeric_endpoint(&peer)?.ip();
        let (local_interface, local_state) = state_address(&local, remote_ip)?;
        let local_ip = numeric_endpoint(&local_state)?.ip();
        // The peer's declared facts, rather than a guessed address increment,
        // determine its dedicated control interface.
        let remote_interface = secondary
            .interfaces
            .iter()
            .find(|i| interface_address(&secondary, &i.name, remote_ip))
            .context("peer management IP must belong to its declared dedicated control interface")?
            .name
            .clone();
        ensure!(
            local_interface == remote_interface,
            "pair members must use the same logical control interface name"
        );
        local.system.ha = Some(crate::config::Ha {
            enabled: true,
            cluster: cluster.clone(),
            node: Some(1),
            witness: witness.clone(),
            sync_interface: local_interface.clone(),
            priority: Some(200),
            preempt: local.system.ha.as_ref().is_some_and(|h| h.preempt),
            ..Default::default()
        });
        secondary.system.ha = Some(crate::config::Ha {
            enabled: true,
            cluster,
            node: Some(2),
            witness,
            sync_interface: remote_interface,
            priority: Some(100),
            ..Default::default()
        });
        for (a, listen, other) in [
            (
                &mut local,
                local_state.clone(),
                SocketAddr::new(remote_ip, 5429).to_string(),
            ),
            (
                &mut secondary,
                SocketAddr::new(remote_ip, 5429).to_string(),
                local_state,
            ),
        ] {
            a.system.conntrack_sync.listen = Some(listen);
            a.system.conntrack_sync.peers = vec![other];
            a.system.conntrack_sync.interval = None;
            a.system.config_sync.secret = Some(secret.into());
            for v in &mut a.protocols.vrrp {
                v.priority = Some(a.system.ha.as_ref().expect("member").priority());
                v.preempt = Some(a.system.ha.as_ref().expect("member").preempt);
            }
        }
        local.system.config_sync.peers = vec![peer.clone()];
        local.system.config_sync.peer_fingerprint = Some(pin.clone());
        secondary.system.config_sync.peers =
            vec![SocketAddr::new(local_ip, local.services.web.port.unwrap_or(8080)).to_string()];
        secondary
            .system
            .ha
            .as_mut()
            .expect("member")
            .management_fingerprint = Some(pin.clone());
        // Generate/preflight the SAME persistent TLS identity the local API uses.
        let mut staged = system::PrivateStage::create(Path::new("/run/sentinel"), 0o600)?;
        staged.file.write_all(local.to_toml()?.as_bytes())?;
        let listen = SocketAddr::new(local_ip, local.services.web.port.unwrap_or(8080));
        let (cert, _) = crate::api::resolve_web_tls(
            &staged.path,
            Path::new(crate::api::DEFAULT_TOKEN_PATH),
            &listen,
        )?
        .context("HA pairing requires local TLS")?;
        let local_pin = system::cert_pubkey_pin(&cert)?;
        local
            .system
            .ha
            .as_mut()
            .expect("member")
            .management_fingerprint = Some(local_pin);
        let mut facts = if let Some(path) = identity {
            serde_json::from_str::<HaIdentity>(&std::fs::read_to_string(path)?)?
        } else {
            capture(&secondary)?
        };
        facts.node = 2;
        facts.management_endpoint = peer.clone();
        facts.management_fingerprint = pin.clone();
        facts.priority = 100;
        local.system.ha.as_mut().expect("member").peer_identity = Some(facts);
        local.validate()?;
        let adjusted = materialize_peer(local.clone())?;
        adjusted.validate()?;
        let plan = PairPlan {
            peer: peer.clone(),
            pin,
            previous: current_revision.clone(),
            appliance: local,
            request: crate::api::PairRequest {
                expected_revision: remote.revision,
                appliance: adjusted,
            },
        };
        system::install_ha_secret(plan_path, &serde_json::to_string(&plan)?)?;
        plan
    };
    let mut staged = system::PrivateStage::create(Path::new("/run/sentinel"), 0o600)?;
    staged
        .file
        .write_all(serde_json::to_string(&plan.request)?.as_bytes())?;
    system::curl_request(
        &format!("https://{peer}/api/v1/ha/pair"),
        Some(secret),
        "POST",
        Some(&staged.path),
        10,
        Some(&plan.pin),
    )
    .context(
        "peer pairing did not acknowledge; the private plan is retained for an identical retry",
    )?;
    if current_revision != revision(&plan.appliance)? {
        let mut apply = crate::repl::Apply::off();
        apply.enabled = true;
        crate::repl::apply_live(&plan.appliance,&apply,Some(&current)).context("peer accepted; local apply failed; retry the same pair command to complete the retained plan")?;
        crate::session::persist_appliance(&plan.appliance, config, true)?;
        system::install_config_file(
            Path::new(crate::session::Session::RUNNING),
            &plan.appliance.to_toml()?,
        )?;
    }
    system::remove_file(plan_path)?;
    println!(
        "HA pair configured: node 1 + node 2 at {peer}; authority is granted by the independent witness."
    );
    Ok(())
}

fn wireguard_policy(a: &Appliance) -> String {
    let sync = a.system.ha.as_ref().map(|h| h.sync_interface.as_str());
    let tunnels: Vec<_> = a
        .vpn
        .wireguard
        .iter()
        .filter(|w| Some(w.name.as_str()) != sync)
        .collect();
    let bytes = serde_json::to_vec(&tunnels).expect("WireGuard configuration serializes");
    digest::digest(&digest::SHA256, &bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// New fencing must precede replacing a currently unfenced firewall process.
pub fn needs_guard_preparation(a: &Appliance, previous: Option<&Appliance>) -> bool {
    let desired = guarded_interfaces(a);
    !desired.is_empty()
        && (previous.is_none_or(|p| !desired.is_subset(&guarded_interfaces(p)))
            || !Path::new("/sys/fs/bpf/velstra-ha/deadline").exists())
}
pub fn prepare_guard(rendered: &str) -> Result<()> {
    use std::io::Write;
    let mut stage = system::PrivateStage::create(Path::new("/run/sentinel"), 0o600)?;
    stage.file.write_all(rendered.as_bytes())?;
    system::ha_guard(&stage.path)
}

fn network_contains(cidr: &str, ip: IpAddr) -> Option<u8> {
    let (network, prefix) = cidr.split_once('/')?;
    let network: IpAddr = network.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    let (network, ip, width) = match (network, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => (u32::from(n) as u128, u32::from(i) as u128, 32),
        (IpAddr::V6(n), IpAddr::V6(i)) => (u128::from(n), u128::from(i), 128),
        _ => return None,
    };
    if prefix > width {
        return None;
    }
    let shift = width - prefix;
    (prefix == 0 || network.checked_shr(shift as u32) == ip.checked_shr(shift as u32))
        .then_some(prefix)
}
fn control_interfaces(a: &Appliance) -> Result<BTreeSet<String>> {
    let Some(ha) = &a.system.ha else {
        return Ok(BTreeSet::new());
    };
    let mut control: BTreeSet<_> = [ha.sync_interface.clone()].into_iter().collect();
    if let Some(tunnel) = a.vpn.wireguard.iter().find(|w| w.name == ha.sync_interface) {
        for peer in &tunnel.peers {
            let endpoint = numeric_endpoint(
                peer.endpoint
                    .as_deref()
                    .context("HA control WireGuard needs explicit numeric peer endpoints")?,
            )?;
            let mut connected: Vec<_> = a
                .interfaces
                .iter()
                .filter(|i| i.name != ha.sync_interface)
                .filter_map(|i| {
                    [i.address.as_deref(), i.address6.as_deref()]
                        .into_iter()
                        .flatten()
                        .filter_map(|c| network_contains(c, endpoint.ip()))
                        .max()
                        .map(|prefix| (prefix, &i.name))
                })
                .collect();
            connected.sort();
            let best = connected.last().context(
                "HA control WireGuard endpoint needs a declared dedicated connected underlay",
            )?;
            ensure!(
                connected.iter().filter(|v| v.0 == best.0).count() == 1,
                "ambiguous HA control WireGuard underlay"
            );
            control.insert(best.1.clone());
        }
    }
    loop {
        let before = control.len();
        for i in &a.interfaces {
            if control.contains(&i.name) {
                control.extend(i.parent.iter().cloned());
                control.extend(i.members.iter().cloned());
            }
        }
        if before == control.len() {
            break;
        }
    }
    Ok(control)
}
fn shared_v4(a: &Appliance, interface: &str) -> BTreeSet<std::net::Ipv4Addr> {
    a.protocols
        .vrrp
        .iter()
        .filter(|v| v.address_interface.as_deref().unwrap_or(&v.interface) == interface)
        .flat_map(|v| v.virtual_address.iter())
        .filter_map(|ip| ip.parse().ok())
        .collect()
}
pub fn masquerade_address(a: &Appliance, interface: &str) -> Option<String> {
    if a.system.ha.as_ref().is_none_or(|ha| !ha.enabled) {
        return None;
    }
    let addresses = shared_v4(a, interface);
    (addresses.len() == 1).then(|| addresses.first().expect("one VIP").to_string())
}

#[cfg(test)]
pub(crate) fn paired_fixture() -> Appliance {
    let mut primary = Appliance::from_toml(
        r#"
[system]
hostname="primary"
[system.config-sync]
peer=["10.20.0.2:8080"]
secret="abcdefghijklmnopqrstuvwxyz0123456789"
[system.conntrack-sync]
listen="10.20.0.1:5429"
peer=["10.20.0.2:5429"]
[system.ha]
enabled=true
cluster="test-cluster-0123456789"
node=1
priority=200
witness="10.20.0.3:5440"
sync-interface="sync0"
[[interface]]
name="wan0"
address="10.10.0.1/24"
[[interface]]
name="sync0"
address="10.20.0.1/24"
[protocols]
router-id="10.20.0.1"
[[protocols.vrrp]]
name="wan"
interface="wan0"
vrid=42
priority=200
preempt=false
virtual-address=["10.10.0.254"]
"#,
    )
    .unwrap();
    use base64::Engine;
    let pin = base64::engine::general_purpose::STANDARD.encode([1; 32]);
    primary.system.config_sync.peer_fingerprint = Some(pin.clone());
    primary.system.ha.as_mut().unwrap().management_fingerprint = Some(pin.clone());
    let mut facts = capture(&primary).unwrap();
    facts.node = 2;
    facts.priority = 100;
    facts.hostname = "secondary".into();
    facts.router_id = Some("10.20.0.2".into());
    facts.management_endpoint = "10.20.0.2:8080".into();
    facts.state_listen = "10.20.0.2:5429".into();
    facts.management_fingerprint = pin;
    facts.interfaces.get_mut("sync0").unwrap().address = Some("10.20.0.2/24".into());
    facts.interfaces.get_mut("wan0").unwrap().address = Some("10.10.0.2/24".into());
    primary.system.ha.as_mut().unwrap().peer_identity = Some(facts);
    primary.validate().unwrap();
    primary
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_swap_is_reversible_and_preserves_shared_intent() {
        let primary = paired_fixture();
        let peer = materialize_peer(primary.clone()).unwrap();
        peer.validate().unwrap();
        assert_eq!(peer.system.hostname, "secondary");
        assert_eq!(peer.interfaces[0].address.as_deref(), Some("10.10.0.2/24"));
        assert_eq!(peer.system.config_sync.peers, vec!["10.20.0.1:8080"]);
        assert_eq!(peer.protocols.vrrp[0].priority, Some(100));
        assert_eq!(
            revision(&materialize_peer(peer).unwrap()).unwrap(),
            revision(&primary).unwrap()
        );
    }
    #[test]
    fn new_static_links_require_explicit_peer_facts() {
        let mut a = paired_fixture();
        let mut link = a.interfaces[0].clone();
        link.name = "new0".into();
        link.address = Some("192.0.2.1/30".into());
        a.interfaces.push(link);
        assert!(
            a.validate()
                .unwrap_err()
                .to_string()
                .contains("peer-specific identity")
        );
        a.system
            .ha
            .as_mut()
            .unwrap()
            .peer_identity
            .as_mut()
            .unwrap()
            .interfaces
            .insert(
                "new0".into(),
                HaInterfaceIdentity {
                    address: Some("192.0.2.2/30".into()),
                    ..Default::default()
                },
            );
        a.validate().unwrap();
        assert_eq!(
            materialize_peer(a).unwrap().interfaces[2]
                .address
                .as_deref(),
            Some("192.0.2.2/30")
        );
    }
    #[test]
    fn control_link_cannot_be_in_guarded_ancestry() {
        let mut a = paired_fixture();
        a.interfaces[0].parent = Some("sync0".into());
        assert!(validate(&a).unwrap_err().to_string().contains("control"));
    }
    #[test]
    fn all_data_links_are_fenced_including_links_without_vips() {
        let mut a = paired_fixture();
        let mut extra = a.interfaces[0].clone();
        extra.name = "dmz0".into();
        extra.address = None;
        a.interfaces.push(extra);
        assert_eq!(
            guarded_interfaces(&a),
            ["dmz0".to_string(), "wan0".to_string()]
                .into_iter()
                .collect()
        );
        assert!(!guarded_interfaces(&a).contains("sync0"));
    }
    #[test]
    fn masquerade_uses_shared_vip_and_refuses_ambiguous_identity() {
        let mut a = paired_fixture();
        a.interfaces[0].zone = Some("wan".into());
        a.nat
            .source
            .push(serde_json::from_value(serde_json::json!({"name":"wan","zone":"wan"})).unwrap());
        a.validate().unwrap();
        let compiled = crate::compile::compile(&a);
        assert_eq!(
            compiled
                .interfaces
                .iter()
                .find(|i| i.name == "wan0")
                .unwrap()
                .snat_address
                .as_deref(),
            Some("10.10.0.254")
        );
        a.protocols.vrrp[0]
            .virtual_address
            .push("10.10.0.253".into());
        assert!(
            a.validate()
                .unwrap_err()
                .to_string()
                .contains("exactly one shared IPv4")
        );
        a.nat.source[0].to = Some("10.10.0.254".into());
        a.validate().unwrap();
    }
    #[test]
    fn control_tunnel_must_have_an_independent_declared_underlay() {
        let mut a = paired_fixture();
        let mut control = a.interfaces[1].clone();
        control.name = "wg-control".into();
        control.if_type = Some(crate::config::IfaceType::Wireguard);
        control.address = Some("172.16.0.1/30".into());
        a.interfaces.push(control);
        let mut underlay = a.interfaces[1].clone();
        underlay.name = "underlay0".into();
        underlay.address = Some("192.0.2.1/24".into());
        a.interfaces.push(underlay);
        a.system.ha.as_mut().unwrap().sync_interface = "wg-control".into();
        a.vpn.wireguard.push(serde_json::from_value(serde_json::json!({"name":"wg-control","private-key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","peer":[{"public-key":"d0JCPLcS8bXlwuA6xdaHrqLdEeQz9M+xUsHhVJnEbn0=","allowed-ips":["172.16.0.2/32"],"endpoint":"192.0.2.2:51820"}]})).unwrap());
        assert!(!guarded_interfaces(&a).contains("underlay0"));
        assert!(control_interfaces(&a).unwrap().contains("underlay0"));
        a.vpn.wireguard[0].peers[0].endpoint = Some("10.10.0.2:51820".into());
        let guarded = guarded_interfaces(&a);
        assert!(
            !guarded.is_disjoint(&control_interfaces(&a).unwrap()),
            "a shared data/WAN control underlay must be rejected"
        );
    }
    #[test]
    fn explicit_peer_profile_with_spaces_survives_cli_command_replay() {
        let mut a = paired_fixture();
        let web = a
            .system
            .ha
            .as_mut()
            .unwrap()
            .peer_identity
            .as_mut()
            .unwrap()
            .management_web
            .as_mut()
            .unwrap();
        web.tls_cert = Some("/var/lib/sentinel/peer cert.pem".into());
        web.tls_key = Some("/var/lib/sentinel/peer key.pem".into());
        a.validate().unwrap();
        let directory =
            std::env::temp_dir().join(format!("sentinel-peer-command-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let mut session = crate::session::Session::load(&directory.join("empty.toml")).unwrap();
        for command in crate::session::flatten_config(&crate::session::render_appliance(&a)) {
            let args = crate::repl::split_line(&command);
            let words: Vec<_> = args.iter().skip(1).map(String::as_str).collect();
            session
                .set(&words)
                .unwrap_or_else(|e| panic!("{command}: {e}"));
        }
        assert_eq!(
            revision(&session.commit().unwrap()).unwrap(),
            revision(&a).unwrap()
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn proof_binds_nonce_secret_and_tls_identity() {
        let a = enrollment_proof("secret", &"a".repeat(64), "pin").unwrap();
        for (secret, nonce, pin) in [
            ("other", "a", "pin"),
            ("secret", "b", "pin"),
            ("secret", "a", "other"),
        ] {
            assert_ne!(a, enrollment_proof(secret, &nonce.repeat(64), pin).unwrap());
        }
        assert!(enrollment_proof("secret", "short", "pin").is_err());
        assert!(enrollment_proof("secret", &"z".repeat(64), "pin").is_err());
    }
    #[test]
    fn introducing_ha_requires_fencing_before_service_replacement() {
        let active = paired_fixture();
        let mut previous = active.clone();
        previous.system.ha = None;
        assert!(needs_guard_preparation(&active, Some(&previous)));
        assert!(!needs_guard_preparation(&previous, Some(&active)));
    }
    #[test]
    fn disabled_pair_cannot_fall_back_to_unfenced_vrrp() {
        let mut a = paired_fixture();
        a.system.ha.as_mut().unwrap().enabled = false;
        let routing = crate::wren::compile_wren(&a).to_toml().unwrap();
        assert!(!routing.contains("[[vrrp]]"));
        assert!(dataplane(&a).is_some());
    }
}
