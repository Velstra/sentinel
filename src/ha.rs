//! Declarative member identities, witness configuration and kernel-guard intent.
use crate::{
    config::{
        Appliance, HaControlIdentity, HaControlInterface, HaIdentity, HaInterfaceIdentity,
        HaInterfaceLinkIdentity, HaMode,
    },
    system,
};
use anyhow::{Context, Result, ensure};
use ring::{digest, hmac};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    path::Path,
    time::{Duration, Instant},
};

pub const WITNESS_CONFIG: &str = "/run/sentinel/witness.json";
const WITNESS_KEY_LABEL: &[u8] = b"Velstra Sentinel witness key v1\0";

// The witness timing budget. Wren re-checks the same relation when its
// coordinator starts; refusing it here turns a pair that would never hold
// authority into a commit error instead of an outage.
//
// A member's lease runs from the instant it started connecting, so round trips
// are spent out of the lease. One exchange is about three round trips and is
// abandoned after the I/O budget; the lease must outlast one abandoned exchange,
// the coordinator's poll and the safety margin.
pub const LEASE_MS: u64 = 250;
pub const IO_MS: u64 = 80;
const POLL_MS: u64 = 25;
const MARGIN_MS: u64 = 20;
const MAX_LEASE_MS: u64 = 10_000;
pub const PEER_SILENCE_MS: u64 = 10_000;
pub const PEER_TIMEOUT_MS: u64 = 1_000;
pub const STARTUP_DELAY_MS: u64 = 3_000;
pub fn check_budget(lease_ms: u64, io_ms: u64) -> Result<()> {
    ensure!(
        (1..=MAX_LEASE_MS).contains(&lease_ms) && io_ms > 0,
        "HA lease-ms must be 1..={MAX_LEASE_MS} and io-timeout-ms nonzero"
    );
    ensure!(
        2 * io_ms + POLL_MS + MARGIN_MS <= lease_ms,
        "HA io-timeout-ms {io_ms} does not fit lease-ms {lease_ms}: 2 x io-timeout-ms + \
         {POLL_MS} ms poll + {MARGIN_MS} ms margin must not exceed the lease (set lease-ms \
         to at least {} here and on the witness)",
        2 * io_ms + POLL_MS + MARGIN_MS
    );
    Ok(())
}
/// The coordinator rewrites its role once per exchange, so the agent must
/// accept a role as old as one I/O budget plus the poll on either side of it.
/// Staleness only says the coordinator is gone; the lease deadline inside the
/// role, enforced by the kernel, is what fences forwarding.
fn role_fresh_ms(io_ms: u64) -> u64 {
    (io_ms + 2 * POLL_MS).max(100)
}
/// Three round trips must fit in three quarters of the I/O budget, leaving the
/// rest for the witness's own work and an occasional retransmission.
pub fn check_witness_rtt(rtt: Duration, io_ms: u64) -> Result<()> {
    let rtt_ms = u64::try_from(rtt.as_millis()).unwrap_or(u64::MAX);
    ensure!(
        rtt_ms.saturating_mul(4) <= io_ms,
        "witness round trip {rtt_ms} ms does not fit io-timeout-ms {io_ms}: set \
         system ha io-timeout-ms to at least {} and lease-ms (on both members and the \
         witness) to at least {}, or move the witness closer",
        rtt_ms.saturating_mul(4),
        rtt_ms.saturating_mul(8) + POLL_MS + MARGIN_MS
    );
    Ok(())
}
/// The best of a few TCP handshakes: one round trip, without credentials. A
/// witness that is unreachable from the primary would leave the pair fenced.
fn witness_rtt(witness: &str) -> Result<Duration> {
    let endpoint = numeric_endpoint(witness)?;
    let mut best: Option<Duration> = None;
    let mut last = None;
    for _ in 0..3 {
        let started = Instant::now();
        match std::net::TcpStream::connect_timeout(&endpoint, Duration::from_secs(1)) {
            Ok(_) => best = Some(best.map_or(started.elapsed(), |b| b.min(started.elapsed()))),
            Err(error) => last = Some(error),
        }
    }
    best.with_context(|| {
        format!(
            "witness {witness} is unreachable from this member ({}); the pair would stay fenced",
            last.map_or_else(String::new, |e| e.to_string())
        )
    })
}
pub fn witness_key(token: &str, cluster: &str) -> String {
    derive(token, WITNESS_KEY_LABEL, cluster)
}
#[derive(Debug, Serialize)]
pub struct DataplaneHa {
    enabled: bool,
    cluster: String,
    node: u8,
    interfaces: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    control_interfaces: Vec<String>,
    disabled: Vec<String>,
    wireguard_ports: Vec<u16>,
    wireguard: Vec<String>,
    wireguard_policy: String,
    role_fresh_ms: u64,
}
#[derive(Serialize)]
pub struct RoutingHa {
    cluster: String,
    node: u8,
    mode: HaMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    witness: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    two_node: Option<RoutingTwoNode>,
    secret: String,
    priority: u8,
    preempt: bool,
    wireguard: Vec<String>,
    wireguard_policy: String,
    lease_ms: u64,
    io_ms: u64,
}
#[derive(Debug, Serialize)]
pub struct RoutingTwoNode {
    listen: Vec<String>,
    peers: Vec<String>,
    peer_timeout_ms: u64,
    startup_delay_ms: u64,
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
fn heartbeat_endpoint(value: &str) -> Result<SocketAddr> {
    let endpoint = numeric_endpoint(value)?;
    let ip = endpoint.ip();
    ensure!(
        !ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback(),
        "HA heartbeat requires a unicast non-loopback endpoint"
    );
    ensure!(
        ip != IpAddr::V4(std::net::Ipv4Addr::BROADCAST),
        "HA heartbeat must not use broadcast"
    );
    Ok(endpoint)
}
fn heartbeat_interface(a: &Appliance, address: IpAddr) -> Result<&str> {
    let matches: Vec<_> = a
        .interfaces
        .iter()
        .filter(|i| !i.disabled && interface_address(a, &i.name, address))
        .collect();
    ensure!(
        matches.len() == 1,
        "HA heartbeat listen address must belong to exactly one enabled declared static interface"
    );
    Ok(&matches[0].name)
}
fn validate_two_node(a: &Appliance, ha: &crate::config::Ha) -> Result<()> {
    if !ha.enabled && ha.heartbeat_listen.is_empty() && ha.heartbeat_peer.is_empty() {
        return Ok(());
    }
    ensure!(
        (1..=4).contains(&ha.heartbeat_listen.len())
            && ha.heartbeat_listen.len() == ha.heartbeat_peer.len(),
        "two-node HA needs 1..4 matching heartbeat-listen and heartbeat-peer paths"
    );
    let listens: Vec<_> = ha
        .heartbeat_listen
        .iter()
        .map(|s| heartbeat_endpoint(s))
        .collect::<Result<_>>()?;
    let peers: Vec<_> = ha
        .heartbeat_peer
        .iter()
        .map(|s| heartbeat_endpoint(s))
        .collect::<Result<_>>()?;
    ensure!(
        listens.iter().collect::<BTreeSet<_>>().len() == listens.len()
            && peers.iter().collect::<BTreeSet<_>>().len() == peers.len(),
        "HA heartbeat paths must not contain duplicate endpoints"
    );
    for (listen, peer) in listens.iter().zip(&peers) {
        ensure!(
            listen.is_ipv4() == peer.is_ipv4() && listen.ip() != peer.ip(),
            "HA heartbeat path needs matching address families and distinct member addresses"
        );
        heartbeat_interface(a, listen.ip())?;
        ensure!(
            !a.interfaces
                .iter()
                .any(|i| interface_address(a, &i.name, peer.ip())),
            "HA heartbeat peer must not name a local interface"
        );
    }
    let timeout = ha.peer_timeout_ms.unwrap_or(PEER_TIMEOUT_MS);
    let delay = ha.startup_delay_ms.unwrap_or(STARTUP_DELAY_MS);
    ensure!(
        (750..=1200).contains(&timeout)
            && timeout >= ha.lease_ms.unwrap_or(LEASE_MS).saturating_mul(4),
        "two-node HA peer-timeout-ms must be 750..1200 and at least four lease periods"
    );
    ensure!(
        timeout + ha.io_timeout_ms.unwrap_or(IO_MS) + POLL_MS + MARGIN_MS < 1500,
        "two-node HA decision must fit the dataplane's 1500ms complete-state freshness budget"
    );
    ensure!(
        delay >= timeout.saturating_mul(2) && delay <= 120_000,
        "two-node HA startup-delay-ms must be at least twice peer-timeout-ms and at most 120000"
    );
    Ok(())
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
            .filter(|w| !control.contains(&w.name))
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
        control_interfaces: if ha.enabled {
            let control = control_interfaces(a).unwrap_or_default();
            a.interfaces
                .iter()
                .filter(|i| !i.disabled && i.zone.is_some() && control.contains(&i.name))
                .map(|i| i.name.clone())
                .collect()
        } else {
            Vec::new()
        },
        role_fresh_ms: role_fresh_ms(ha.io_timeout_ms.unwrap_or(IO_MS)),
        wireguard_policy: wireguard_policy(a),
        wireguard: a
            .vpn
            .wireguard
            .iter()
            .filter(|w| !control_interfaces(a).unwrap_or_default().contains(&w.name))
            .map(|w| w.name.clone())
            .collect(),
        wireguard_ports: a
            .vpn
            .wireguard
            .iter()
            .filter(|w| !control_interfaces(a).unwrap_or_default().contains(&w.name))
            .filter_map(|w| w.listen_port)
            .collect(),
    })
}
pub fn routing(a: &Appliance) -> Option<RoutingHa> {
    let ha = a.system.ha.as_ref().filter(|h| h.enabled)?;
    Some(RoutingHa {
        cluster: ha.cluster.clone(),
        node: ha.node(),
        mode: ha.mode,
        witness: (ha.mode == HaMode::Witness).then(|| ha.witness.clone()),
        two_node: (ha.mode == HaMode::TwoNode).then(|| RoutingTwoNode {
            listen: ha.heartbeat_listen.clone(),
            peers: ha.heartbeat_peer.clone(),
            peer_timeout_ms: ha.peer_timeout_ms.unwrap_or(PEER_TIMEOUT_MS),
            startup_delay_ms: ha.startup_delay_ms.unwrap_or(STARTUP_DELAY_MS),
        }),
        secret: witness_key(
            a.system.config_sync.secret.as_deref().unwrap_or_default(),
            &ha.cluster,
        ),
        lease_ms: ha.lease_ms.unwrap_or(LEASE_MS),
        io_ms: ha.io_timeout_ms.unwrap_or(IO_MS),
        priority: ha.priority(),
        preempt: ha.preempt,
        wireguard_policy: wireguard_policy(a),
        wireguard: a
            .vpn
            .wireguard
            .iter()
            .filter(|w| !control_interfaces(a).unwrap_or_default().contains(&w.name))
            .map(|w| w.name.clone())
            .collect(),
    })
}
fn validate_witness(w: &crate::config::HaWitness) -> Result<()> {
    numeric_endpoint(&w.listen)?;
    ensure!(
        w.key.is_empty() != w.secret.is_empty(),
        "HA witness needs exactly one of key (derived, from `sentinel ha witness-key`) or the deprecated secret"
    );
    if w.key.is_empty() {
        ensure!(
            (32..=1024).contains(&w.secret.len()),
            "HA witness secret must contain 32..1024 bytes"
        );
    } else {
        ensure!(
            w.key.len() == 64 && w.key.bytes().all(|b| b.is_ascii_hexdigit()),
            "HA witness key must be the 64 hex digits `sentinel ha witness-key` prints"
        );
        // The cluster is derived from the credential, which a key-only
        // witness deliberately does not hold.
        ensure!(
            !w.cluster.is_empty(),
            "a witness configured with a key needs its explicit cluster identifier"
        );
    }
    ensure!(
        w.cluster.is_empty() || valid_cluster(&w.cluster),
        "invalid HA witness cluster identifier"
    );
    // Compared in the witness's own form: it maps an IPv4-mapped IPv6 member
    // (`::ffff:10.0.0.1`) to plain IPv4 before checking the two differ, so a
    // pair that differs only in that spelling would pass here and leave a
    // witness that refuses to start.
    let members = witness_members(w)?;
    ensure!(
        members.is_empty()
            || members.len() == 2
                && members[0] != members[1]
                && members.iter().all(|m| !m.is_unspecified()),
        "HA witness needs the two distinct member addresses"
    );
    let lease = w.lease_ms.unwrap_or(LEASE_MS);
    ensure!(
        lease > MARGIN_MS && lease <= MAX_LEASE_MS,
        "HA witness lease-ms must be {}..={MAX_LEASE_MS}",
        MARGIN_MS + 1
    );
    let silence = w.peer_silence_ms.unwrap_or(PEER_SILENCE_MS);
    ensure!(
        silence >= 1_000 && silence >= 4 * lease,
        "HA witness peer-silence-ms must be at least 1000 and four leases"
    );
    Ok(())
}
/// Commit-time advisories. Neither blocks a commit: refusing a witness that
/// boots from an older document would take its pair's authority down with it.
pub fn witness_warnings(a: &Appliance) -> Vec<String> {
    if a.system
        .ha
        .as_ref()
        .is_some_and(|h| h.mode == HaMode::TwoNode)
    {
        return vec!["two-node HA has no external arbiter: a total heartbeat partition can promote both members; configure independent control paths or use witness mode when split-brain exclusion is required".into()];
    }
    let Some(w) = &a.system.ha_witness else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if !w.secret.is_empty() {
        out.push(
            "system ha-witness secret is the members' enrollment credential and API machine \
             token; replace it with the derived key from `sentinel ha witness-key`"
                .into(),
        );
    }
    if w.members.is_empty() {
        out.push(format!(
            "system ha-witness has no member addresses: any host that reaches {} can hold \
             the sessions both members need to renew their leases",
            w.listen
        ));
    }
    out
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
        validate_witness(w)?;
    }
    let Some(ha) = &a.system.ha else {
        return Ok(());
    };
    check_budget(
        ha.lease_ms.unwrap_or(LEASE_MS),
        ha.io_timeout_ms.unwrap_or(IO_MS),
    )?;
    match ha.mode {
        HaMode::Witness => {
            let witness = numeric_endpoint(&ha.witness)?;
            ensure!(
                !witness.ip().is_unspecified(),
                "HA witness must name an independent endpoint"
            );
            ensure!(
                ha.heartbeat_listen.is_empty()
                    && ha.heartbeat_peer.is_empty()
                    && ha.peer_timeout_ms.is_none()
                    && ha.startup_delay_ms.is_none(),
                "witness HA cannot configure two-node heartbeat fields"
            );
        }
        HaMode::TwoNode => {
            ensure!(
                ha.witness.is_empty(),
                "two-node HA must not configure a witness"
            );
            validate_two_node(a, ha)?;
        }
    }
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
        if !control.contains(&w.name) {
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
        if ha.mode == HaMode::TwoNode {
            ensure!(
                identity.heartbeat_listen == ha.heartbeat_peer
                    && identity.heartbeat_peer == ha.heartbeat_listen,
                "paired two-node heartbeat paths must be reciprocal member-local endpoints"
            );
        }
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
                !node_specific
                    || identity.interfaces.contains_key(&i.name)
                    || identity.control.is_some() && control.contains(&i.name),
                "new interface {} needs its peer-specific identity in system.ha.peer-identity",
                i.name
            );
        }
        // Validate the materialized peer through the ordinary complete schema,
        // with reverse-profile recursion disabled for this one validation pass.
        let mut peer = materialize_peer(a.clone())?;
        ensure!(
            guarded_interfaces(a) == guarded_interfaces(&peer),
            "HA members must retain the same logical fenced data links"
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
    let control = control_interfaces(a)?;
    ensure!(
        control
            .iter()
            .all(|name| a.interfaces.iter().any(|i| &i.name == name)),
        "HA member identity requires every dedicated control ancestor to be declared"
    );
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
        heartbeat_listen: ha.heartbeat_listen.clone(),
        heartbeat_peer: ha.heartbeat_peer.clone(),
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
                        link: Some(HaInterfaceLinkIdentity {
                            hw_id: i.hw_id.clone(),
                            remote: i.remote.clone(),
                        }),
                    },
                )
            })
            .collect(),
        control: Some(HaControlIdentity {
            sync_interface: ha.sync_interface.clone(),
            interfaces: a
                .interfaces
                .iter()
                .enumerate()
                .filter(|(_, interface)| control.contains(&interface.name))
                .map(|(position, interface)| HaControlInterface {
                    position,
                    configuration: interface.clone(),
                })
                .collect(),
        }),
        control_wireguard: a
            .vpn
            .wireguard
            .iter()
            .find(|w| w.name == ha.sync_interface)
            .cloned(),
        control_wireguards: a
            .vpn
            .wireguard
            .iter()
            .filter(|w| control.contains(&w.name) && w.name != ha.sync_interface)
            .cloned()
            .collect(),
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
    // Capture and validate the source closure before replacing anything. A
    // data link whose ancestry uses it is never exempted from fencing.
    let source_control = control_interfaces(&a)?;
    let source_guarded = guarded_interfaces(&a);
    ensure!(
        source_guarded.is_disjoint(&source_control),
        "HA control underlay cannot carry fenced data/VIPs"
    );
    if let Some(control) = &target.control {
        crate::config::validate_iface_name(&control.sync_interface)?;
        ensure!(
            !control.interfaces.is_empty() && control.interfaces.len() <= 128,
            "peer control profile must contain 1..128 declared links"
        );
        let names: BTreeSet<_> = control
            .interfaces
            .iter()
            .map(|i| i.configuration.name.clone())
            .collect();
        let positions: BTreeSet<_> = control.interfaces.iter().map(|i| i.position).collect();
        ensure!(
            names.len() == control.interfaces.len()
                && positions.len() == control.interfaces.len()
                && names.contains(&control.sync_interface),
            "peer control profile has duplicate links/positions or lacks its sync interface"
        );
        ensure!(
            !a.interfaces
                .iter()
                .any(|i| !source_control.contains(&i.name) && names.contains(&i.name)),
            "peer control link collides with a shared data interface"
        );
        ensure!(
            !a.vpn.wireguard.iter().any(
                |tunnel| !source_control.contains(&tunnel.name) && names.contains(&tunnel.name)
            ),
            "peer control link collides with a shared data WireGuard tunnel"
        );
        a.vpn
            .wireguard
            .retain(|tunnel| !source_control.contains(&tunnel.name));
        a.interfaces.retain(|i| !source_control.contains(&i.name));
        let mut links = control.interfaces.clone();
        links.sort_by_key(|i| i.position);
        for entry in links {
            let position = entry.position.min(a.interfaces.len());
            a.interfaces.insert(position, entry.configuration);
        }
        for v in &mut a.protocols.vrrp {
            if v.interface
                == source
                    .control
                    .as_ref()
                    .expect("captured control")
                    .sync_interface
            {
                // Only the heartbeat binding is member-local. The VIP's
                // address-interface stays shared and guarded.
                v.interface = control.sync_interface.clone();
            }
        }
        // Service policy is shared, but a binding to the selected dedicated
        // control link names a member-local interface. Translate only that
        // proven correspondence; arbitrary ancestors (especially bridge
        // members) have no unambiguous peer mapping and must fail validation
        // rather than silently serving on a guessed link.
        let source_sync = &source
            .control
            .as_ref()
            .expect("captured control")
            .sync_interface;
        for bindings in [&mut a.services.ntp.serve_on, &mut a.services.dns.serve_on] {
            for binding in bindings {
                if binding == source_sync {
                    *binding = control.sync_interface.clone();
                }
            }
        }
        a.system.ha.as_mut().context("HA missing")?.sync_interface = control.sync_interface.clone();
    }
    let ha = a.system.ha.as_mut().context("HA missing")?;
    ensure!(target.node == 3 - ha.node(), "HA peer node mismatch");
    ha.node = Some(target.node);
    ha.heartbeat_listen = target.heartbeat_listen;
    ha.heartbeat_peer = target.heartbeat_peer;
    ha.priority = Some(target.priority);
    ha.management_fingerprint = Some(target.management_fingerprint.clone());
    ha.peer_identity = Some(source.clone());
    let preempt = ha.preempt;
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
            if let Some(link) = &facts.link {
                i.hw_id = link.hw_id.clone();
                i.remote = link.remote.clone();
            }
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
    for control in target
        .control_wireguard
        .into_iter()
        .chain(target.control_wireguards)
    {
        let wireguard = &mut a.vpn.wireguard;
        if let Some(existing) = wireguard.iter_mut().find(|w| w.name == control.name) {
            *existing = control;
        } else {
            wireguard.push(control);
        }
    }
    if let Some(control) = &target.control {
        let declared: BTreeSet<_> = control
            .interfaces
            .iter()
            .map(|i| i.configuration.name.clone())
            .collect();
        ensure!(
            control_interfaces(&a)? == declared,
            "peer control profile must describe exactly its dedicated control ancestry"
        );
    }
    for v in &mut a.protocols.vrrp {
        v.priority = Some(target.priority);
        v.preempt = Some(preempt);
    }
    ensure!(
        guarded_interfaces(&a) == source_guarded,
        "peer control profile must preserve the complete fenced data-link set"
    );
    Ok(a)
}

/// The witness's member addresses as the witness compares them: numeric, and
/// with an IPv4-mapped IPv6 address taken as the IPv4 address it carries — an
/// IPv4 member reaching a dual-stack listener arrives mapped.
fn witness_members(w: &crate::config::HaWitness) -> Result<Vec<IpAddr>> {
    w.members
        .iter()
        .map(|m| {
            m.parse::<IpAddr>()
                .map(|ip| ip.to_canonical())
                .with_context(|| format!("HA witness member {m:?} must be a numeric IP address"))
        })
        .collect()
}
#[derive(Serialize)]
struct WitnessRuntime {
    cluster: String,
    /// The derived witness key the members also derive; the handshake is
    /// keyed by exactly these bytes, whichever way the witness obtained them.
    secret: String,
    listen: String,
    state: &'static str,
    members: Vec<IpAddr>,
    lease_ms: u64,
    peer_silence_ms: u64,
}
fn witness_runtime(w: &crate::config::HaWitness) -> Result<WitnessRuntime> {
    let cluster = if !w.cluster.is_empty() {
        w.cluster.clone()
    } else {
        cluster_id(&w.secret)
    };
    let secret = if w.key.is_empty() {
        witness_key(&w.secret, &cluster)
    } else {
        w.key.to_ascii_lowercase()
    };
    Ok(WitnessRuntime {
        secret,
        cluster,
        listen: w.listen.clone(),
        state: "/var/lib/sentinel/witness/state.json",
        members: witness_members(w)?,
        lease_ms: w.lease_ms.unwrap_or(LEASE_MS),
        peer_silence_ms: w.peer_silence_ms.unwrap_or(PEER_SILENCE_MS),
    })
}
pub fn apply_witness(a: &Appliance, live: bool) -> Result<()> {
    let path = Path::new(WITNESS_CONFIG);
    if let Some(w) = &a.system.ha_witness {
        let runtime = witness_runtime(w)?;
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

/// How long the primary waits for the peer to apply and acknowledge pairing.
const PAIR_ACK_SECS: u32 = 25;

pub fn pair(
    peer: &str,
    secret: &str,
    config: &Path,
    witness: Option<&str>,
    identity: Option<&Path>,
    mode: Option<HaMode>,
) -> Result<()> {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    ensure!(
        (32..=1024).contains(&secret.len()) && !secret.chars().any(|c| c.is_control()),
        "HA secret must contain 32..1024 non-control bytes"
    );
    ensure!(
        mode != Some(HaMode::TwoNode) || witness.is_none(),
        "--mode two-node conflicts with --witness"
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
        if let Some(mode) = mode {
            command.args(["--mode", mode.as_str()]);
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
                && mode.is_none_or(|m| saved
                    .appliance
                    .system
                    .ha
                    .as_ref()
                    .is_some_and(|h| h.mode == m))
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
        let selected_mode =
            mode.unwrap_or_else(|| local.system.ha.as_ref().map_or(HaMode::Witness, |h| h.mode));
        ensure!(
            selected_mode != HaMode::TwoNode || witness.is_none(),
            "--mode two-node conflicts with --witness"
        );
        let witness = if selected_mode == HaMode::Witness {
            let witness = witness.map(str::to_owned).or_else(|| local.system.ha.as_ref().map(|h|h.witness.clone())).filter(|w| !w.is_empty()).context("configure system.ha.witness or pass --witness with an independent witness endpoint")?;
            numeric_endpoint(&witness)?;
            witness
        } else {
            ensure!(
                local
                    .system
                    .ha
                    .as_ref()
                    .is_none_or(|h| h.witness.is_empty()),
                "remove system.ha.witness before selecting two-node mode"
            );
            eprintln!(
                "WARNING: witnessless two-node HA cannot prevent dual promotion during a total peer partition; use independent heartbeat paths or an external witness."
            );
            String::new()
        };
        // Timing prepared on the primary applies to both members; check that
        // this witness can answer inside it before either document changes.
        let (lease_ms, io_timeout_ms) = local
            .system
            .ha
            .as_ref()
            .map_or((None, None), |h| (h.lease_ms, h.io_timeout_ms));
        let io = io_timeout_ms.unwrap_or(IO_MS);
        check_budget(lease_ms.unwrap_or(LEASE_MS), io)?;
        if selected_mode == HaMode::Witness {
            check_witness_rtt(witness_rtt(&witness)?, io)?;
        }
        let prepared = local.system.ha.clone().unwrap_or_default();
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
        let (heartbeat_listen, heartbeat_peer) = if selected_mode == HaMode::TwoNode {
            let paths =
                if prepared.heartbeat_listen.is_empty() && prepared.heartbeat_peer.is_empty() {
                    (
                        vec![SocketAddr::new(local_ip, 5441).to_string()],
                        vec![SocketAddr::new(remote_ip, 5441).to_string()],
                    )
                } else {
                    (
                        prepared.heartbeat_listen.clone(),
                        prepared.heartbeat_peer.clone(),
                    )
                };
            if let Some(remote) = secondary
                .system
                .ha
                .as_ref()
                .filter(|h| !h.heartbeat_listen.is_empty() || !h.heartbeat_peer.is_empty())
            {
                ensure!(
                    remote.mode == HaMode::TwoNode
                        && remote.heartbeat_listen == paths.1
                        && remote.heartbeat_peer == paths.0,
                    "prepared peer heartbeat paths conflict with primary's reciprocal paths"
                );
            }
            paths
        } else {
            (Vec::new(), Vec::new())
        };
        // The peer's declared facts, rather than a guessed address increment,
        // determine its dedicated control interface.
        let remote_interface = secondary
            .interfaces
            .iter()
            .find(|i| interface_address(&secondary, &i.name, remote_ip))
            .context("peer management IP must belong to its declared dedicated control interface")?
            .name
            .clone();
        local.system.ha = Some(crate::config::Ha {
            enabled: true,
            cluster: cluster.clone(),
            node: Some(1),
            witness: witness.clone(),
            mode: selected_mode,
            sync_interface: local_interface.clone(),
            priority: Some(200),
            preempt: local.system.ha.as_ref().is_some_and(|h| h.preempt),
            lease_ms,
            io_timeout_ms,
            peer_timeout_ms: prepared.peer_timeout_ms,
            startup_delay_ms: prepared.startup_delay_ms,
            ..Default::default()
        });
        secondary.system.ha = Some(crate::config::Ha {
            enabled: true,
            cluster,
            node: Some(2),
            witness,
            mode: selected_mode,
            sync_interface: remote_interface,
            priority: Some(100),
            lease_ms,
            io_timeout_ms,
            peer_timeout_ms: prepared.peer_timeout_ms,
            startup_delay_ms: prepared.startup_delay_ms,
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
            if selected_mode == HaMode::TwoNode {
                let primary = numeric_endpoint(&listen)?.ip() == local_ip;
                let ha = a.system.ha.as_mut().expect("member");
                ha.heartbeat_listen = if primary {
                    heartbeat_listen.clone()
                } else {
                    heartbeat_peer.clone()
                };
                ha.heartbeat_peer = if primary {
                    heartbeat_peer.clone()
                } else {
                    heartbeat_listen.clone()
                };
            }
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
        let mut adjusted = materialize_peer(local.clone())?;
        adjusted.fleet = secondary.fleet.clone();
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
    // The peer answers only after its live apply, which restarts its data
    // plane: its zoned links, the one carrying this request included, are
    // held down until the new agent has hooked them again. The budget covers
    // that restart, not just a round trip.
    system::curl_request(
        &format!("https://{peer}/api/v1/ha/pair"),
        Some(secret),
        "POST",
        Some(&staged.path),
        PAIR_ACK_SECS,
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
    match plan.appliance.system.ha.as_ref().expect("paired HA").mode {
        HaMode::Witness => println!(
            "HA pair configured: node 1 + node 2 at {peer}; authority is granted by the independent witness."
        ),
        HaMode::TwoNode => println!(
            "HA pair configured: node 1 + node 2 at {peer}; authenticated two-node heartbeats grant authority. WARNING: a total peer partition can promote both nodes; there is no external arbiter."
        ),
    }
    Ok(())
}

fn wireguard_policy(a: &Appliance) -> String {
    let control = control_interfaces(a).unwrap_or_default();
    let tunnels: Vec<_> = a
        .vpn
        .wireguard
        .iter()
        .filter(|w| !control.contains(&w.name))
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
    if ha.mode == HaMode::TwoNode {
        for endpoint in &ha.heartbeat_listen {
            control.insert(heartbeat_interface(a, heartbeat_endpoint(endpoint)?.ip())?.into());
        }
    }
    for tunnel in a
        .vpn
        .wireguard
        .iter()
        .filter(|w| control.contains(&w.name))
        .collect::<Vec<_>>()
    {
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

/// `show ha`: the agent's own view of forwarding authority, with the reason a
/// standby could not take over. "Backup" alone reads as "covered"; a standby
/// whose policy or state does not match the owner's is not.
pub fn render_status(status: &serde_json::Value) -> String {
    let role = status["role"].as_str().unwrap_or("unknown");
    if role == "standalone" {
        return "HA standalone (leased HA is not configured)\n".into();
    }
    let mut out = match status["not_ready"].as_str() {
        Some(reason) if role != "Master" => format!("HA {role} (not ready: {reason})\n"),
        _ => format!("HA {role}\n"),
    };
    if let Some(mode) = status["configured_mode"].as_str() {
        out.push_str(&format!("  configured mode {mode}\n"));
        if mode == "two-node" {
            out.push_str("  warning: total heartbeat partition can promote both members (no external arbiter)\n");
        }
    }
    let number = |key: &str| status[key].as_u64().map_or("-".into(), |v| v.to_string());
    out.push_str(&format!(
        "  node {}  cluster {}  term {}  owner {}\n",
        number("node"),
        status["cluster"].as_str().unwrap_or("-"),
        number("term"),
        number("owner"),
    ));
    if role == "Master" {
        out.push_str(&format!(
            "  lease remaining {} ms\n",
            number("lease_remaining_ms")
        ));
    } else {
        out.push_str(&format!(
            "  last complete state update {} ms ago\n",
            number("sync_age_ms")
        ));
    }
    out
}

/// How long a standby may be unable to take over before somebody is told.
/// Long enough to cover an ordinary configuration-sync delivery after a
/// commit, short enough that the gap is not discovered by the next outage.
pub const STANDBY_ALERT_AFTER: Duration = Duration::from_secs(30);
const WATCH_INTERVAL: Duration = Duration::from_secs(2);

/// Turns a stream of agent HA status reports into at most one alert per
/// episode of standby unreadiness, and one when it ends.
#[derive(Default)]
pub struct ReadinessWatch {
    since: Option<Instant>,
    alerted: bool,
}
impl ReadinessWatch {
    pub fn observe(
        &mut self,
        status: &serde_json::Value,
        now: Instant,
    ) -> Option<crate::alert::Alert> {
        let reason = matches!(status["role"].as_str(), Some("Backup" | "Fenced"))
            .then(|| status["not_ready"].as_str())
            .flatten();
        let Some(reason) = reason else {
            self.since = None;
            return std::mem::take(&mut self.alerted).then(|| crate::alert::Alert {
                subject: "HA standby ready again".into(),
                detail: "the standby can take over from the active member again".into(),
            });
        };
        let since = *self.since.get_or_insert(now);
        let waited = now.saturating_duration_since(since);
        if self.alerted || waited < STANDBY_ALERT_AFTER {
            return None;
        }
        self.alerted = true;
        Some(crate::alert::Alert {
            subject: "HA standby not ready".into(),
            detail: format!(
                "{reason} (for {} s): a failure of the active member now would not fail over",
                waited.as_secs()
            ),
        })
    }
}

/// `sentinel ha watch`, run by systemd: the alert path for a standby that
/// cannot take over. Unit failures already alert through `OnFailure=`; this is
/// the case where every unit is healthy and the pair is still not redundant.
pub fn watch(config: &Path) -> Result<()> {
    let mut readiness = ReadinessWatch::default();
    loop {
        let status = crate::velstra::query("ha-status")
            .ok()
            .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok());
        if let Some(alert) = status.and_then(|s| readiness.observe(&s, Instant::now())) {
            eprintln!("{}: {}", alert.subject, alert.detail);
            match Appliance::load(config) {
                Ok(a) => {
                    crate::alert::deliver(&a.services.alerts, &alert);
                }
                Err(error) => eprintln!("HA watch: cannot read alert targets: {error:#}"),
            }
        }
        std::thread::sleep(WATCH_INTERVAL);
    }
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
    for link in &mut facts.control.as_mut().unwrap().interfaces {
        if link.configuration.name == "sync0" {
            link.configuration.address = Some("10.20.0.2/24".into());
        }
    }
    primary.system.ha.as_mut().unwrap().peer_identity = Some(facts);
    primary.validate().unwrap();
    primary
}
#[cfg(test)]
mod tests {
    use super::*;

    fn two_node_members() -> Appliance {
        let mut primary = distinct_control_members();
        let ha = primary.system.ha.as_mut().unwrap();
        ha.mode = HaMode::TwoNode;
        ha.witness.clear();
        ha.heartbeat_listen = vec!["10.20.0.1:5441".into()];
        ha.heartbeat_peer = vec!["10.20.0.2:5441".into()];
        let identity = ha.peer_identity.as_mut().unwrap();
        identity.heartbeat_listen = ha.heartbeat_peer.clone();
        identity.heartbeat_peer = ha.heartbeat_listen.clone();
        primary.validate().unwrap();
        primary
    }

    #[test]
    fn compiler_declares_only_resolved_control_bindings_and_none_when_disabled() {
        let mut a = two_node_members();
        a.interfaces
            .iter_mut()
            .find(|i| i.name == "enp0s20f0u3")
            .unwrap()
            .zone = Some("control".into());
        let control = a
            .interfaces
            .iter()
            .find(|i| i.name == "enp0s20f0u3")
            .unwrap()
            .clone();
        let mut parent = control.clone();
        parent.name = "unbound-parent".into();
        parent.address = None;
        parent.zone = None;
        let logical = a
            .interfaces
            .iter_mut()
            .find(|i| i.name == control.name)
            .unwrap();
        logical.parent = Some(parent.name.clone());
        logical.vlan = Some(43);
        logical.hw_id = None;
        a.interfaces.push(parent);
        a.system.ha.as_mut().unwrap().peer_identity = None;
        a.validate().unwrap();
        assert_eq!(
            control_interfaces(&a).unwrap(),
            BTreeSet::from(["enp0s20f0u3".into(), "unbound-parent".into()])
        );
        let compiled: serde_json::Value = serde_json::to_value(dataplane(&a).unwrap()).unwrap();
        assert_eq!(
            compiled["control_interfaces"],
            serde_json::json!(["enp0s20f0u3"])
        );
        assert_eq!(compiled["interfaces"], serde_json::json!(["wan0"]));
        a.system.ha.as_mut().unwrap().enabled = false;
        let disabled = serde_json::to_value(dataplane(&a).unwrap()).unwrap();
        assert_eq!(disabled["enabled"], false);
        assert!(disabled.get("control_interfaces").is_none());
    }

    #[test]
    fn compiler_keeps_control_hardware_and_own_ip_out_of_tenant_port_security() {
        let mut primary = two_node_members();
        primary
            .interfaces
            .iter_mut()
            .find(|i| i.name == "enp0s20f0u3")
            .unwrap()
            .zone = Some("control".into());
        for link in &mut primary
            .system
            .ha
            .as_mut()
            .unwrap()
            .peer_identity
            .as_mut()
            .unwrap()
            .control
            .as_mut()
            .unwrap()
            .interfaces
        {
            link.configuration.zone = Some("control".into());
        }
        let secondary = materialize_peer(primary.clone()).unwrap();
        let compile = |a: &Appliance| {
            toml::from_str::<toml::Value>(&crate::compile::compile(a).to_toml().unwrap()).unwrap()
        };
        let first = compile(&primary);
        let second = compile(&secondary);
        for (document, name) in [(&first, "enp0s20f0u3"), (&second, "enp0s20f0u1")] {
            let binding = document["interface"]
                .as_array()
                .unwrap()
                .iter()
                .find(|i| i["name"].as_str() == Some(name))
                .unwrap();
            assert!(binding.get("bind_mac").is_none() && binding.get("bind_addresses").is_none());
            assert_eq!(
                document["ha"]["control_interfaces"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap())
                    .collect::<Vec<_>>(),
                vec![name]
            );
        }
        assert_ne!(
            primary
                .interfaces
                .iter()
                .find(|i| i.name == "enp0s20f0u3")
                .unwrap()
                .hw_id,
            secondary
                .interfaces
                .iter()
                .find(|i| i.name == "enp0s20f0u1")
                .unwrap()
                .hw_id
        );
    }

    #[test]
    fn witness_is_compatible_default_and_two_node_runtime_is_explicit() {
        let legacy = paired_fixture();
        assert_eq!(legacy.system.ha.as_ref().unwrap().mode, HaMode::Witness);
        let witness = serde_json::to_value(routing(&legacy).unwrap()).unwrap();
        assert_eq!(witness["mode"], "witness");
        assert_eq!(witness["witness"], "10.20.0.3:5440");
        assert!(witness.get("two_node").is_none());
        let a = two_node_members();
        let runtime = serde_json::to_value(routing(&a).unwrap()).unwrap();
        assert_eq!(runtime["mode"], "two-node");
        assert!(runtime.get("witness").is_none());
        assert_eq!(
            runtime["two_node"]["listen"],
            serde_json::json!(["10.20.0.1:5441"])
        );
        assert_eq!(
            runtime["two_node"]["peers"],
            serde_json::json!(["10.20.0.2:5441"])
        );
        assert_eq!(runtime["two_node"]["peer_timeout_ms"], 1000);
        assert_eq!(runtime["two_node"]["startup_delay_ms"], 3000);
        assert!(
            a.warnings()
                .iter()
                .any(|s| s.contains("total heartbeat partition"))
        );
        Appliance::from_toml(&a.to_toml().unwrap()).unwrap();
    }

    #[test]
    fn two_node_peer_endpoints_and_policy_survive_reverse_sync() {
        let mut primary = two_node_members();
        primary.services.ntp.serve_on = vec!["enp0s20f0u3".into()];
        let mut secondary = materialize_peer(primary.clone()).unwrap();
        secondary.validate().unwrap();
        assert_eq!(
            secondary.system.ha.as_ref().unwrap().heartbeat_listen,
            ["10.20.0.2:5441"]
        );
        assert_eq!(
            secondary.system.ha.as_ref().unwrap().heartbeat_peer,
            ["10.20.0.1:5441"]
        );
        assert_eq!(secondary.services.ntp.serve_on, ["enp0s20f0u1"]);
        assert_eq!(
            crate::configsync::shared_revision(&primary).unwrap(),
            crate::configsync::shared_revision(&secondary).unwrap()
        );
        secondary.firewall.block_icmp = !secondary.firewall.block_icmp;
        secondary.system.ha.as_mut().unwrap().peer_timeout_ms = Some(1100);
        primary = materialize_peer(secondary.clone()).unwrap();
        primary.validate().unwrap();
        assert_eq!(
            primary.system.ha.as_ref().unwrap().peer_timeout_ms,
            Some(1100)
        );
        assert_eq!(
            primary.system.ha.as_ref().unwrap().heartbeat_listen,
            ["10.20.0.1:5441"]
        );
        assert_eq!(primary.firewall.block_icmp, secondary.firewall.block_icmp);
        assert_eq!(
            guarded_interfaces(&primary),
            BTreeSet::from(["wan0".into()])
        );
        assert_eq!(
            crate::configsync::shared_revision(&primary).unwrap(),
            crate::configsync::shared_revision(&secondary).unwrap()
        );
    }

    #[test]
    fn two_node_invalid_paths_modes_and_timing_fail_closed() {
        let original = two_node_members();
        for (listen, peer) in [
            ("0.0.0.0:5441", "10.20.0.2:5441"),
            ("127.0.0.1:5441", "10.20.0.2:5441"),
            ("224.0.0.1:5441", "10.20.0.2:5441"),
            ("10.20.0.1:0", "10.20.0.2:5441"),
            ("10.20.0.99:5441", "10.20.0.2:5441"),
            ("10.20.0.1:5441", "10.20.0.1:5441"),
            ("10.20.0.1:5441", "[2001:db8::2]:5441"),
            ("10.20.0.1:5441", "peer.example.test:5441"),
            ("10.20.0.1:5441", "255.255.255.255:5441"),
        ] {
            let mut a = original.clone();
            let h = a.system.ha.as_mut().unwrap();
            h.heartbeat_listen = vec![listen.into()];
            h.heartbeat_peer = vec![peer.into()];
            assert!(a.validate().is_err(), "accepted {listen} -> {peer}");
        }
        for timeout in [0, 749, 999, 1201, 1500, u64::MAX] {
            let mut a = original.clone();
            a.system.ha.as_mut().unwrap().peer_timeout_ms = Some(timeout);
            assert!(a.validate().is_err(), "accepted timeout {timeout}");
        }
        for delay in [0, 1999, 120001, u64::MAX] {
            let mut a = original.clone();
            a.system.ha.as_mut().unwrap().startup_delay_ms = Some(delay);
            assert!(a.validate().is_err(), "accepted delay {delay}");
        }
        let mut a = original.clone();
        a.system.ha.as_mut().unwrap().heartbeat_listen.clear();
        assert!(a.validate().is_err());
        let mut a = original.clone();
        a.system
            .ha
            .as_mut()
            .unwrap()
            .heartbeat_peer
            .push("10.20.0.2:5441".into());
        assert!(a.validate().is_err());
        let mut a = original.clone();
        a.system.ha.as_mut().unwrap().witness = "10.20.0.3:5440".into();
        assert!(a.validate().is_err());
        let mut a = original;
        a.system.ha.as_mut().unwrap().mode = HaMode::Witness;
        assert!(a.validate().is_err());
    }

    #[test]
    fn two_node_all_control_paths_and_ancestors_are_local_not_fenced() {
        let mut primary = two_node_members();
        let mut secondary = materialize_peer(primary.clone()).unwrap();
        for (a, number, name, parent) in [
            (&mut primary, 1, "hb-primary", "enp0s20f0u3"),
            (&mut secondary, 2, "hb-secondary", "enp0s20f0u1"),
        ] {
            let mut link = a
                .interfaces
                .iter()
                .find(|i| i.name == parent)
                .unwrap()
                .clone();
            link.name = name.into();
            link.parent = Some(parent.into());
            link.vlan = Some(44);
            link.hw_id = None;
            link.address = Some(format!("10.30.0.{number}/24"));
            a.interfaces.push(link);
            let h = a.system.ha.as_mut().unwrap();
            h.heartbeat_listen.push(format!("10.30.0.{number}:5441"));
            h.heartbeat_peer
                .push(format!("10.30.0.{}:5441", 3 - number));
        }
        primary.system.ha.as_mut().unwrap().peer_identity = Some(capture(&secondary).unwrap());
        primary.validate().unwrap();
        secondary = materialize_peer(primary.clone()).unwrap();
        secondary.validate().unwrap();
        assert_eq!(
            control_interfaces(&secondary).unwrap(),
            BTreeSet::from(["enp0s20f0u1".into(), "hb-secondary".into()])
        );
        assert_eq!(
            guarded_interfaces(&secondary),
            BTreeSet::from(["wan0".into()])
        );
        assert_eq!(
            revision(&materialize_peer(secondary.clone()).unwrap()).unwrap(),
            revision(&primary).unwrap()
        );
        assert_eq!(
            crate::configsync::shared_revision(&primary).unwrap(),
            crate::configsync::shared_revision(&secondary).unwrap()
        );
        // A VIP on any heartbeat ancestry is not exempted by declaring a path.
        primary.protocols.vrrp[0].address_interface = Some("hb-primary".into());
        assert!(primary.validate().is_err());
    }

    fn distinct_control_members() -> Appliance {
        let mut primary = paired_fixture();
        let mut secondary = materialize_peer(primary.clone()).unwrap();
        for (member, name, mac) in [
            (&mut primary, "enp0s20f0u3", "00:e0:4c:36:00:90"),
            (&mut secondary, "enp0s20f0u1", "00:e0:4c:69:01:5f"),
        ] {
            let control = member
                .interfaces
                .iter_mut()
                .find(|i| i.name == "sync0")
                .unwrap();
            control.name = name.into();
            control.hw_id = Some(mac.into());
            member.system.ha.as_mut().unwrap().sync_interface = name.into();
            member.system.ha.as_mut().unwrap().peer_identity = None;
            // Heartbeats follow the local dedicated control link, while the
            // virtual address stays on the canonical fenced data interface.
            member.protocols.vrrp[0].interface = name.into();
            member.protocols.vrrp[0].address_interface = Some("wan0".into());
        }
        secondary.interfaces.swap(0, 1);
        primary.system.ha.as_mut().unwrap().peer_identity = Some(capture(&secondary).unwrap());
        primary.validate().unwrap();
        primary
    }

    #[test]
    fn different_physical_control_names_are_local_and_never_guarded() {
        let primary = distinct_control_members();
        let secondary = materialize_peer(primary.clone()).unwrap();
        secondary.validate().unwrap();
        assert_eq!(
            primary.system.ha.as_ref().unwrap().sync_interface,
            "enp0s20f0u3"
        );
        assert_eq!(
            secondary.system.ha.as_ref().unwrap().sync_interface,
            "enp0s20f0u1"
        );
        assert!(!secondary.interfaces.iter().any(|i| i.name == "enp0s20f0u3"));
        let nic = secondary
            .interfaces
            .iter()
            .find(|i| i.name == "enp0s20f0u1")
            .unwrap();
        assert_eq!(nic.hw_id.as_deref(), Some("00:e0:4c:69:01:5f"));
        assert_eq!(nic.address.as_deref(), Some("10.20.0.2/24"));
        assert_eq!(secondary.protocols.vrrp[0].interface, "enp0s20f0u1");
        assert_eq!(
            secondary.protocols.vrrp[0].address_interface.as_deref(),
            Some("wan0")
        );
        assert_eq!(
            guarded_interfaces(&primary),
            BTreeSet::from(["wan0".into()])
        );
        assert_eq!(guarded_interfaces(&primary), guarded_interfaces(&secondary));
        // Different control positions are not a shared-policy change.
        assert_eq!(secondary.interfaces[0].name, "enp0s20f0u1");
        assert_eq!(
            revision(&materialize_peer(secondary).unwrap()).unwrap(),
            revision(&primary).unwrap()
        );
    }

    #[test]
    fn asymmetric_control_profiles_share_revisions_and_preserve_policy_changes() {
        let mut primary = distinct_control_members();
        let mut secondary = materialize_peer(primary.clone()).unwrap();
        let shared = crate::configsync::shared_revision;
        assert_eq!(shared(&primary).unwrap(), shared(&secondary).unwrap());
        let original = shared(&primary).unwrap();
        primary.firewall.block_icmp = !primary.firewall.block_icmp;
        secondary = materialize_peer(primary.clone()).unwrap();
        assert_ne!(original, shared(&primary).unwrap());
        assert_eq!(shared(&primary).unwrap(), shared(&secondary).unwrap());
        secondary.interfaces[0].mtu = Some(1400); // control is member-local
        primary = materialize_peer(secondary.clone()).unwrap();
        assert_eq!(shared(&primary).unwrap(), shared(&secondary).unwrap());
        assert_eq!(
            materialize_peer(primary).unwrap().interfaces[0].mtu,
            Some(1400)
        );
    }

    #[test]
    fn control_bound_ntp_and_dns_preserve_shared_policy_in_both_directions() {
        let mut primary = distinct_control_members();
        primary.services.ntp.upstream = vec!["time.example.test".into()];
        primary.services.ntp.allow_from = vec!["0.0.0.0/0".into()];
        primary.services.ntp.serve_on = vec!["enp0s20f0u3".into(), "wan0".into()];
        primary.services.dns.upstream = vec!["192.0.2.53".into()];
        primary.services.dns.serve_on = primary.services.ntp.serve_on.clone();
        primary
            .services
            .dns
            .host_override
            .insert("pair.test".into(), "192.0.2.7".into());
        primary.validate().unwrap();
        let mut secondary = materialize_peer(primary.clone()).unwrap();
        secondary.validate().unwrap();
        assert_eq!(secondary.services.ntp.serve_on, ["enp0s20f0u1", "wan0"]);
        assert_eq!(secondary.services.dns.serve_on, ["enp0s20f0u1", "wan0"]);
        assert_eq!(
            secondary.services.ntp.upstream,
            primary.services.ntp.upstream
        );
        assert_eq!(
            secondary.services.ntp.allow_from,
            primary.services.ntp.allow_from
        );
        assert_eq!(
            secondary.services.dns.upstream,
            primary.services.dns.upstream
        );
        assert_eq!(
            secondary.services.dns.host_override,
            primary.services.dns.host_override
        );
        assert_eq!(
            crate::configsync::shared_revision(&primary).unwrap(),
            crate::configsync::shared_revision(&secondary).unwrap()
        );
        assert_eq!(
            revision(&materialize_peer(secondary.clone()).unwrap()).unwrap(),
            revision(&primary).unwrap()
        );
        // A standby policy edit still propagates. Only the local name changes,
        // not which services are enabled or which clients/upstreams are used.
        secondary.services.ntp.allow_from = vec!["198.51.100.0/24".into()];
        secondary.services.dns.blocklist = vec!["blocked.example.test".into()];
        primary = materialize_peer(secondary.clone()).unwrap();
        primary.validate().unwrap();
        assert_eq!(primary.services.ntp.serve_on, ["enp0s20f0u3", "wan0"]);
        assert_eq!(primary.services.dns.serve_on, ["enp0s20f0u3", "wan0"]);
        assert_eq!(
            primary.services.ntp.allow_from,
            secondary.services.ntp.allow_from
        );
        assert_eq!(
            primary.services.dns.blocklist,
            secondary.services.dns.blocklist
        );
        assert_eq!(
            crate::configsync::shared_revision(&primary).unwrap(),
            crate::configsync::shared_revision(&secondary).unwrap()
        );
    }

    #[test]
    fn same_name_control_service_bindings_remain_compatible() {
        let mut primary = paired_fixture();
        primary.services.ntp.serve_on = vec!["sync0".into(), "wan0".into()];
        primary.services.dns.serve_on = primary.services.ntp.serve_on.clone();
        let secondary = materialize_peer(primary.clone()).unwrap();
        secondary.validate().unwrap();
        assert_eq!(
            secondary.services.ntp.serve_on,
            primary.services.ntp.serve_on
        );
        assert_eq!(
            secondary.services.dns.serve_on,
            primary.services.dns.serve_on
        );
        assert_eq!(
            revision(&materialize_peer(secondary).unwrap()).unwrap(),
            revision(&primary).unwrap()
        );
    }

    #[test]
    fn service_bindings_do_not_guess_peer_control_ancestors() {
        let mut primary = distinct_control_members();
        let mut secondary = materialize_peer(primary.clone()).unwrap();
        for member in [&mut primary, &mut secondary] {
            let physical = member.system.ha.as_ref().unwrap().sync_interface.clone();
            let mut logical = member
                .interfaces
                .iter()
                .find(|i| i.name == physical)
                .unwrap()
                .clone();
            logical.name = "sync-vlan".into();
            logical.hw_id = None;
            logical.parent = Some(physical);
            logical.vlan = Some(901);
            logical.address = Some(format!(
                "10.21.0.{}/24",
                member.system.ha.as_ref().unwrap().node()
            ));
            member.interfaces.push(logical);
            member.system.ha.as_mut().unwrap().sync_interface = "sync-vlan".into();
            member.protocols.vrrp[0].interface = "sync-vlan".into();
            let node = member.system.ha.as_ref().unwrap().node();
            member.system.conntrack_sync.listen = Some(format!("10.21.0.{node}:5429"));
            member.system.conntrack_sync.peers = vec![format!("10.21.0.{}:5429", 3 - node)];
            member.system.config_sync.peers = vec![format!("10.21.0.{}:8080", 3 - node)];
        }
        primary.system.ha.as_mut().unwrap().peer_identity = Some(capture(&secondary).unwrap());
        // The selected logical link is shared by name. Its differently named
        // ancestors are not implicitly interchangeable service bindings.
        for ntp in [true, false] {
            let mut bound = primary.clone();
            if ntp {
                bound.services.ntp.serve_on = vec!["enp0s20f0u3".into()];
            } else {
                bound.services.dns.serve_on = vec!["enp0s20f0u3".into()];
            }
            let peer = materialize_peer(bound.clone()).unwrap();
            assert!(
                peer.validate()
                    .unwrap_err()
                    .to_string()
                    .contains("not a declared interface")
            );
            assert!(bound.validate().is_err());
        }
    }

    #[test]
    fn legacy_member_profiles_remain_accepted_without_new_fields() {
        let mut primary = paired_fixture();
        let identity = primary
            .system
            .ha
            .as_mut()
            .unwrap()
            .peer_identity
            .as_mut()
            .unwrap();
        identity.control = None;
        for link in identity.interfaces.values_mut() {
            link.link = None;
        }
        primary.validate().unwrap();
        let peer = materialize_peer(primary).unwrap();
        peer.validate().unwrap();
        assert_eq!(peer.system.ha.as_ref().unwrap().sync_interface, "sync0");
        assert_eq!(peer.interfaces[1].address.as_deref(), Some("10.20.0.2/24"));
    }

    #[test]
    fn data_hardware_binding_and_tunnel_endpoints_remain_member_local() {
        let mut primary = distinct_control_members();
        let mut secondary = materialize_peer(primary.clone()).unwrap();
        for (member, source, target, mac) in [
            (&mut primary, "10.20.0.1", "10.20.0.2", "02:00:00:00:00:01"),
            (
                &mut secondary,
                "10.20.0.2",
                "10.20.0.1",
                "02:00:00:00:00:02",
            ),
        ] {
            let data = member
                .interfaces
                .iter_mut()
                .find(|i| i.name == "wan0")
                .unwrap();
            data.if_type = Some(crate::config::IfaceType::Gretap);
            data.local = Some(source.into());
            data.remote = Some(target.into());
            data.tunnel_key = Some(44);
            data.hw_id = Some(mac.into());
        }
        primary.system.ha.as_mut().unwrap().peer_identity = Some(capture(&secondary).unwrap());
        primary.validate().unwrap();
        let peer = materialize_peer(primary.clone()).unwrap();
        peer.validate().unwrap();
        let data = peer.interfaces.iter().find(|i| i.name == "wan0").unwrap();
        assert_eq!(data.local.as_deref(), Some("10.20.0.2"));
        assert_eq!(data.remote.as_deref(), Some("10.20.0.1"));
        assert_eq!(data.hw_id.as_deref(), Some("02:00:00:00:00:02"));
        assert_eq!(
            crate::configsync::shared_revision(&primary).unwrap(),
            crate::configsync::shared_revision(&peer).unwrap()
        );
        assert_eq!(
            revision(&materialize_peer(peer).unwrap()).unwrap(),
            revision(&primary).unwrap()
        );
    }

    #[test]
    fn control_profile_cannot_claim_data_collisions_or_extra_exemptions() {
        let primary = distinct_control_members();
        let mut collision = primary.clone();
        collision
            .system
            .ha
            .as_mut()
            .unwrap()
            .peer_identity
            .as_mut()
            .unwrap()
            .control
            .as_mut()
            .unwrap()
            .interfaces[0]
            .configuration
            .name = "wan0".into();
        assert!(
            materialize_peer(collision)
                .unwrap_err()
                .to_string()
                .contains("lacks its sync interface")
        );

        let mut collision = primary.clone();
        let profile = collision
            .system
            .ha
            .as_mut()
            .unwrap()
            .peer_identity
            .as_mut()
            .unwrap()
            .control
            .as_mut()
            .unwrap();
        profile.sync_interface = "wan0".into();
        profile.interfaces[0].configuration.name = "wan0".into();
        assert!(
            materialize_peer(collision)
                .unwrap_err()
                .to_string()
                .contains("collides")
        );

        let mut duplicate = primary.clone();
        let profile = duplicate
            .system
            .ha
            .as_mut()
            .unwrap()
            .peer_identity
            .as_mut()
            .unwrap()
            .control
            .as_mut()
            .unwrap();
        profile.interfaces.push(profile.interfaces[0].clone());
        assert!(
            materialize_peer(duplicate)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );

        let mut extra = primary;
        let profile = extra
            .system
            .ha
            .as_mut()
            .unwrap()
            .peer_identity
            .as_mut()
            .unwrap()
            .control
            .as_mut()
            .unwrap();
        let mut unrelated = profile.interfaces[0].clone();
        unrelated.configuration.name = "extra-exempt".into();
        unrelated.position = 2;
        profile.interfaces.push(unrelated);
        assert!(
            materialize_peer(extra)
                .unwrap_err()
                .to_string()
                .contains("peer addressing")
        );
    }

    #[test]
    fn vlan_and_bridge_control_profiles_preserve_local_parent_members_and_mac() {
        for bridge in [false, true] {
            let mut primary = distinct_control_members();
            let mut secondary = materialize_peer(primary.clone()).unwrap();
            for member in [&mut primary, &mut secondary] {
                let physical_name = member.system.ha.as_ref().unwrap().sync_interface.clone();
                let physical = member
                    .interfaces
                    .iter_mut()
                    .find(|i| i.name == physical_name)
                    .unwrap();
                let mut control = physical.clone();
                control.name = "ctl-logical".into();
                control.hw_id = None;
                physical.address = None;
                if bridge {
                    control.if_type = Some(crate::config::IfaceType::Bridge);
                    control.members = vec![physical_name];
                } else {
                    control.parent = Some(physical_name);
                    control.vlan = Some(901);
                }
                member.interfaces.push(control);
                member.system.ha.as_mut().unwrap().sync_interface = "ctl-logical".into();
                member.protocols.vrrp[0].interface = "ctl-logical".into();
            }
            primary.system.ha.as_mut().unwrap().peer_identity = Some(capture(&secondary).unwrap());
            primary.validate().unwrap();
            let peer = materialize_peer(primary.clone()).unwrap();
            peer.validate().unwrap();
            let logical = peer
                .interfaces
                .iter()
                .find(|i| i.name == "ctl-logical")
                .unwrap();
            if bridge {
                assert_eq!(logical.members, vec!["enp0s20f0u1"]);
            } else {
                assert_eq!(logical.parent.as_deref(), Some("enp0s20f0u1"));
            }
            assert_eq!(
                control_interfaces(&peer).unwrap(),
                BTreeSet::from(["enp0s20f0u1".into(), "ctl-logical".into()])
            );
            assert_eq!(guarded_interfaces(&peer), BTreeSet::from(["wan0".into()]));
            assert_eq!(
                revision(&materialize_peer(peer).unwrap()).unwrap(),
                revision(&primary).unwrap()
            );
        }
    }

    #[test]
    fn control_profile_cannot_hide_a_data_ancestor_or_invent_an_unbound_link() {
        let mut primary = distinct_control_members();
        primary.interfaces[0].parent = Some("enp0s20f0u3".into());
        assert!(
            materialize_peer(primary)
                .unwrap_err()
                .to_string()
                .contains("fenced data/VIPs")
        );

        let mut primary = distinct_control_members();
        let target = primary
            .system
            .ha
            .as_mut()
            .unwrap()
            .peer_identity
            .as_mut()
            .unwrap();
        let mut unrelated = target.control.as_ref().unwrap().interfaces[0].clone();
        unrelated.configuration.name = "unbound0".into();
        unrelated.configuration.address = None;
        unrelated.configuration.hw_id = None;
        unrelated.position = 2;
        target.control.as_mut().unwrap().interfaces.push(unrelated);
        assert!(
            materialize_peer(primary)
                .unwrap_err()
                .to_string()
                .contains("exactly its dedicated control ancestry")
        );
    }

    #[test]
    fn control_profiles_and_local_bindings_round_trip_through_json_and_toml() {
        let primary = distinct_control_members();
        let text = primary.to_toml().unwrap();
        let parsed = Appliance::from_toml(&text).unwrap();
        assert_eq!(revision(&parsed).unwrap(), revision(&primary).unwrap());
        let json = serde_json::to_string(&primary).unwrap();
        let parsed = Appliance::from_json(&json).unwrap();
        assert_eq!(revision(&parsed).unwrap(), revision(&primary).unwrap());
        let mut invalid: serde_json::Value = serde_json::from_str(&json).unwrap();
        invalid["system"]["ha"]["peer-identity"]["control"]["not-a-field"] = true.into();
        assert!(Appliance::from_json(&invalid.to_string()).is_err());
    }

    #[test]
    fn shared_data_bridge_membership_still_converges_with_local_control_profiles() {
        let mut primary = distinct_control_members();
        let mut secondary = materialize_peer(primary.clone()).unwrap();
        for member in [&mut primary, &mut secondary] {
            let data = member
                .interfaces
                .iter_mut()
                .find(|i| i.name == "wan0")
                .unwrap();
            let mut bridge = data.clone();
            bridge.name = "br-data".into();
            bridge.if_type = Some(crate::config::IfaceType::Bridge);
            bridge.members = vec!["wan0".into()];
            data.address = None;
            member.interfaces.push(bridge);
            member.protocols.vrrp[0].address_interface = Some("br-data".into());
        }
        primary.system.ha.as_mut().unwrap().peer_identity = Some(capture(&secondary).unwrap());
        primary.validate().unwrap();
        let mut extra = primary
            .interfaces
            .iter()
            .find(|i| i.name == "wan0")
            .unwrap()
            .clone();
        extra.name = "extra-data".into();
        primary.interfaces.push(extra);
        primary
            .interfaces
            .iter_mut()
            .find(|i| i.name == "br-data")
            .unwrap()
            .members
            .push("extra-data".into());
        primary.validate().unwrap();
        let peer = materialize_peer(primary.clone()).unwrap();
        peer.validate().unwrap();
        assert_eq!(
            peer.interfaces
                .iter()
                .find(|i| i.name == "br-data")
                .unwrap()
                .members,
            vec!["wan0", "extra-data"]
        );
        assert_eq!(
            crate::configsync::shared_revision(&peer).unwrap(),
            crate::configsync::shared_revision(&primary).unwrap()
        );
    }

    #[test]
    fn control_wireguard_keys_and_distinct_underlays_stay_member_local() {
        use base64::Engine;
        let keys = [
            base64::engine::general_purpose::STANDARD.encode([1; 32]),
            base64::engine::general_purpose::STANDARD.encode([2; 32]),
        ];
        let mut primary = distinct_control_members();
        let mut secondary = materialize_peer(primary.clone()).unwrap();
        for (index, member) in [
            primary.system.ha.as_ref().unwrap().node(),
            secondary.system.ha.as_ref().unwrap().node(),
        ]
        .into_iter()
        .zip([&mut primary, &mut secondary])
        {
            let mut control = member
                .interfaces
                .iter()
                .find(|i| i.name == member.system.ha.as_ref().unwrap().sync_interface)
                .unwrap()
                .clone();
            control.name = "ctl-wg".into();
            control.if_type = Some(crate::config::IfaceType::Wireguard);
            control.hw_id = None;
            control.address = Some(format!("172.16.0.{index}/24"));
            member.interfaces.push(control);
            member.system.ha.as_mut().unwrap().sync_interface = "ctl-wg".into();
            member.system.conntrack_sync.listen = Some(format!("172.16.0.{index}:5429"));
            member.system.conntrack_sync.peers = vec![format!("172.16.0.{}:5429", 3 - index)];
            member.system.config_sync.peers = vec![format!("172.16.0.{}:8080", 3 - index)];
            member.protocols.vrrp[0].interface = "ctl-wg".into();
            member.vpn.wireguard = vec![serde_json::from_value(serde_json::json!({
                "name":"ctl-wg", "private-key":keys[usize::from(index - 1)], "listen-port":51820,
                "peer":[{"public-key":crate::wgkey::public_from_private(&keys[usize::from(2 - index)]).unwrap(),
                    "allowed-ips":[format!("172.16.0.{}/32", 3 - index)],
                    "endpoint":format!("10.20.0.{}:51820", 3 - index)}]
            })).unwrap()];
        }
        primary.system.ha.as_mut().unwrap().peer_identity = Some(capture(&secondary).unwrap());
        primary.validate().unwrap();
        let peer = materialize_peer(primary.clone()).unwrap();
        peer.validate().unwrap();
        assert_eq!(peer.vpn.wireguard.len(), 1);
        assert_eq!(peer.vpn.wireguard[0].private_key, keys[1]);
        assert_eq!(
            peer.vpn.wireguard[0].peers[0].endpoint.as_deref(),
            Some("10.20.0.1:51820")
        );
        assert_eq!(
            control_interfaces(&peer).unwrap(),
            BTreeSet::from(["ctl-wg".into(), "enp0s20f0u1".into()])
        );
        assert_eq!(guarded_interfaces(&peer), BTreeSet::from(["wan0".into()]));
        assert_eq!(
            revision(&materialize_peer(peer).unwrap()).unwrap(),
            revision(&primary).unwrap()
        );
    }
    fn witness_appliance(extra: &str) -> Result<Appliance> {
        let a = Appliance::from_toml(&format!(
            "[system]\nhostname=\"witness\"\n[system.ha-witness]\nlisten=\"10.20.0.3:5440\"\n{extra}"
        ))?;
        a.validate()?;
        Ok(a)
    }
    #[test]
    fn a_key_only_witness_holds_no_member_credential_and_keys_the_same_handshake() {
        let member = paired_fixture();
        let token = member.system.config_sync.secret.clone().unwrap();
        let key = witness_key(&token, "test-cluster-0123456789");
        let witness = witness_appliance(&format!(
            "key=\"{key}\"\ncluster=\"test-cluster-0123456789\"\nmember=[\"10.20.0.1\",\"10.20.0.2\"]\n"
        ))
        .unwrap();
        let runtime = witness_runtime(witness.system.ha_witness.as_ref().unwrap()).unwrap();
        // The members derive the handshake key from their credential; the
        // witness is handed the result and nothing it could sign in with.
        let routed = serde_json::to_value(routing(&member).unwrap()).unwrap();
        assert_eq!(routed["secret"], runtime.secret.as_str());
        assert_ne!(runtime.secret, token);
        assert!(!witness.to_toml().unwrap().contains(&token));
        let written = serde_json::to_string(&runtime).unwrap();
        assert!(!written.contains(&token));
        assert_eq!(
            runtime.members,
            vec![
                "10.20.0.1".parse::<IpAddr>().unwrap(),
                "10.20.0.2".parse().unwrap()
            ]
        );
        assert!(witness_warnings(&witness).is_empty());
    }
    #[test]
    fn a_legacy_credential_witness_keeps_its_pair_but_is_told_to_migrate() {
        let witness = witness_appliance(
            "secret=\"abcdefghijklmnopqrstuvwxyz0123456789\"\ncluster=\"test-cluster-0123456789\"\n",
        )
        .unwrap();
        let runtime = witness_runtime(witness.system.ha_witness.as_ref().unwrap()).unwrap();
        let routed = serde_json::to_value(routing(&paired_fixture()).unwrap()).unwrap();
        assert_eq!(
            routed["secret"],
            runtime.secret.as_str(),
            "upgrade keeps the handshake"
        );
        let warnings = witness_warnings(&witness);
        assert!(
            warnings.iter().any(|w| w.contains("witness-key")),
            "{warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("no member addresses")),
            "{warnings:?}"
        );
        assert!(witness.warnings().iter().any(|w| w.contains("witness-key")));
    }
    #[test]
    fn witness_configuration_is_refused_when_it_cannot_identify_or_restrict() {
        let key = "a".repeat(64);
        for bad in [
            format!("key=\"{key}\"\n"),
            format!(
                "key=\"{key}\"\nsecret=\"abcdefghijklmnopqrstuvwxyz0123456789\"\ncluster=\"test-cluster-0123456789\"\n"
            ),
            "key=\"short\"\ncluster=\"test-cluster-0123456789\"\n".into(),
            format!("key=\"{key}\"\ncluster=\"test-cluster-0123456789\"\nmember=[\"10.20.0.1\"]\n"),
            format!(
                "key=\"{key}\"\ncluster=\"test-cluster-0123456789\"\nmember=[\"10.20.0.1\",\"10.20.0.1\"]\n"
            ),
            format!(
                "key=\"{key}\"\ncluster=\"test-cluster-0123456789\"\nmember=[\"witness.example\",\"10.20.0.1\"]\n"
            ),
            format!(
                "key=\"{key}\"\ncluster=\"test-cluster-0123456789\"\nlease-ms=1000\npeer-silence-ms=2000\n"
            ),
        ] {
            assert!(witness_appliance(&bad).is_err(), "accepted {bad}");
        }
    }
    #[test]
    fn a_v4_mapped_witness_member_is_the_same_member_as_its_ipv4_form() {
        // The witness compares members after mapping `::ffff:a.b.c.d` to
        // `a.b.c.d` (an IPv4 member reaching a dual-stack listener arrives
        // mapped), so these two spellings are one member: a commit that
        // accepted them would leave a witness that refuses to start.
        let key = "a".repeat(64);
        let duplicate = format!(
            "key=\"{key}\"\ncluster=\"test-cluster-0123456789\"\nmember=[\"10.20.0.1\",\"::ffff:10.20.0.1\"]\n"
        );
        let error = witness_appliance(&duplicate).unwrap_err();
        assert!(
            format!("{error:#}").contains("two distinct member addresses"),
            "{error:#}"
        );

        // A mapped spelling of a distinct member is accepted, and handed to
        // the witness in the form the witness itself compares in.
        let mapped = witness_appliance(&format!(
            "key=\"{key}\"\ncluster=\"test-cluster-0123456789\"\nmember=[\"::ffff:10.20.0.1\",\"10.20.0.2\"]\n"
        ))
        .unwrap();
        let runtime = witness_runtime(mapped.system.ha_witness.as_ref().unwrap()).unwrap();
        assert_eq!(
            runtime.members,
            vec![
                "10.20.0.1".parse::<IpAddr>().unwrap(),
                "10.20.0.2".parse().unwrap()
            ]
        );
    }
    #[test]
    fn the_witness_timing_budget_is_validated_and_reaches_every_consumer() {
        check_budget(LEASE_MS, IO_MS).unwrap();
        let error = check_budget(250, 150).unwrap_err().to_string();
        assert!(error.contains("at least 345"), "{error}");
        check_witness_rtt(Duration::from_millis(20), IO_MS).unwrap();
        let error = check_witness_rtt(Duration::from_millis(50), IO_MS)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("io-timeout-ms to at least 200") && error.contains("at least 445"),
            "{error}"
        );
        let mut a = paired_fixture();
        let guard = serde_json::to_value(dataplane(&a).unwrap()).unwrap();
        assert_eq!(guard["role_fresh_ms"], 130);
        let ha = a.system.ha.as_mut().unwrap();
        ha.lease_ms = Some(250);
        ha.io_timeout_ms = Some(150);
        assert!(a.validate().is_err(), "a budget wren would refuse");
        a.system.ha.as_mut().unwrap().lease_ms = Some(400);
        a.validate().unwrap();
        let routed = serde_json::to_value(routing(&a).unwrap()).unwrap();
        assert_eq!(
            (routed["lease_ms"].as_u64(), routed["io_ms"].as_u64()),
            (Some(400), Some(150))
        );
        let guard = serde_json::to_value(dataplane(&a).unwrap()).unwrap();
        assert_eq!(guard["role_fresh_ms"], 200);
        let peer = materialize_peer(a).unwrap();
        assert_eq!(peer.system.ha.as_ref().unwrap().io_timeout_ms, Some(150));
    }
    #[test]
    fn show_ha_names_why_a_standby_cannot_take_over() {
        let backup = serde_json::json!({"role":"Backup","node":2,"cluster":"c","term":5,"owner":1,
            "ready":false,"not_ready":"policy differs from the owner's; awaiting configuration sync",
            "sync_age_ms":40});
        let text = render_status(&backup);
        assert!(
            text.starts_with("HA Backup (not ready: policy differs from the owner's; awaiting configuration sync)\n"),
            "{text}"
        );
        assert!(
            text.contains("node 2") && text.contains("40 ms ago"),
            "{text}"
        );
        let master = serde_json::json!({"role":"Master","node":1,"term":5,"owner":1,"lease_remaining_ms":180,"not_ready":null});
        assert!(render_status(&master).starts_with("HA Master\n"));
        assert!(render_status(&serde_json::json!({"role":"standalone"})).contains("standalone"));
    }
    #[test]
    fn an_unready_standby_alerts_once_after_the_threshold_and_once_on_recovery() {
        let mut watch = ReadinessWatch::default();
        let start = Instant::now();
        let unready = serde_json::json!({"role":"Backup","not_ready":"state snapshot is stale"});
        let ready = serde_json::json!({"role":"Backup","not_ready":null});
        assert!(watch.observe(&unready, start).is_none());
        assert!(
            watch
                .observe(
                    &unready,
                    start + STANDBY_ALERT_AFTER - Duration::from_millis(1)
                )
                .is_none()
        );
        let alert = watch
            .observe(&unready, start + STANDBY_ALERT_AFTER)
            .unwrap();
        assert_eq!(alert.subject, "HA standby not ready");
        assert!(alert.detail.contains("state snapshot is stale"));
        assert!(
            watch
                .observe(&unready, start + 10 * STANDBY_ALERT_AFTER)
                .is_none(),
            "one alert per episode"
        );
        assert_eq!(
            watch
                .observe(&ready, start + 11 * STANDBY_ALERT_AFTER)
                .unwrap()
                .subject,
            "HA standby ready again"
        );
        assert!(
            watch
                .observe(&ready, start + 12 * STANDBY_ALERT_AFTER)
                .is_none()
        );
        // A brief gap (a commit awaiting configuration sync) stays quiet.
        assert!(
            watch
                .observe(&unready, start + 13 * STANDBY_ALERT_AFTER)
                .is_none()
        );
        assert!(
            watch
                .observe(
                    &ready,
                    start + 13 * STANDBY_ALERT_AFTER + Duration::from_secs(3)
                )
                .is_none()
        );
        // The active member is not a standby, and neither is a standalone box.
        let master = serde_json::json!({"role":"Master","not_ready":null});
        assert!(
            watch
                .observe(&master, start + 20 * STANDBY_ALERT_AFTER)
                .is_none()
        );
        assert!(
            watch
                .observe(&master, start + 30 * STANDBY_ALERT_AFTER)
                .is_none()
        );
    }
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
