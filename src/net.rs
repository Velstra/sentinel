//! Live L3 addressing + VLAN subinterfaces via systemd-networkd.
//!
//! Each interface that carries an `address` is rendered to a `.network` unit in
//! networkd's **runtime** dir (`/run/systemd/network`, tmpfs) and networkd is
//! told to re-apply it — so `set interface eth0 address 10.0.0.1/24` configures
//! the NIC immediately, with no rebuild. A VLAN subinterface (`parent` + `vlan`)
//! additionally gets a `.netdev` that creates the 802.1Q link, and its parent's
//! `.network` gains a `VLAN=` reference so networkd attaches it. The units are
//! named so they take precedence over the image defaults, and the boot service
//! re-renders them from the saved config each boot (the same runtime-apply model
//! the hostname uses). Removing config removes the units, so changes reconcile
//! both ways.

use std::collections::{BTreeMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use anyhow::Result;

use crate::config::{
    Appliance, DhcpRelay, DhcpServer, Dns, Dyndns, IfaceType, Interface, Lldp, Mdns, MultiWan,
    Nat64, Ntp, Qos, QosDiscipline, RouterAdvert, Snmp, WAN_CHECK_FAIL, WAN_CHECK_INTERVAL,
    WAN_CHECK_RISE, WAN_CHECK_TIMEOUT, WanMode, WireguardTunnel,
};
use crate::system::{self, NETWORKD_RUNTIME_DIR};

/// Filename prefix for the units we own. The low number sorts ahead of the
/// image/test defaults so our config wins; the marker lets us reconcile
/// (remove ours without touching anyone else's).
const PREFIX: &str = "10-sentinel-";

fn network_name(iface: &str) -> String {
    format!("{PREFIX}{iface}.network")
}

fn netdev_name(iface: &str) -> String {
    format!("{PREFIX}{iface}.netdev")
}

/// The `.netdev` that creates a VLAN link `iface` with the given id. `protocol`
/// selects the tag TPID: `802.1q` (or `None` — the default C-VLAN) renders no
/// `Protocol=` line, while `802.1ad` emits `Protocol=802.1ad` for an S-VLAN
/// (service tag). Stacking an `802.1q` VLAN on an `802.1ad` VLAN gives 802.1ad
/// QinQ (roadmap C14).
fn netdev_body(iface: &str, vlan: u16, protocol: Option<&str>) -> String {
    let mut body = format!("[NetDev]\nName={iface}\nKind=vlan\n\n[VLAN]\nId={vlan}\n");
    if protocol == Some("802.1ad") {
        body.push_str("Protocol=802.1ad\n");
    }
    body
}

/// The `.netdev` for a MACVLAN pseudo-interface (roadmap C14): `Kind=macvlan`
/// plus a `[MACVLAN] Mode=` (default `bridge`). The device attaches to its
/// `parent` NIC through the parent's `.network` (`MACVLAN=<name>`), not here —
/// mirroring how a VLAN child attaches via the parent's `VLAN=`.
fn macvlan_netdev_body(iface: &Interface) -> String {
    let mode = iface.macvlan_mode.as_deref().unwrap_or("bridge");
    format!(
        "[NetDev]\nName={}\nKind=macvlan\n\n[MACVLAN]\nMode={mode}\n",
        iface.name
    )
}

/// The `[BridgeVLAN]` port section for a member of a VLAN-aware bridge: a `VLAN=`
/// per tagged id, plus `PVID=`/`EgressUntagged=` for the single untagged VLAN.
/// networkd merges the keys, so one section suffices. Empty when the port has no
/// VLAN membership (so it appends nothing).
fn bridge_vlan_body(tagged: &[u16], untagged: Option<u16>) -> String {
    if tagged.is_empty() && untagged.is_none() {
        return String::new();
    }
    let mut body = String::from("\n[BridgeVLAN]\n");
    for id in tagged {
        body.push_str(&format!("VLAN={id}\n"));
    }
    if let Some(pvid) = untagged {
        body.push_str(&format!("PVID={pvid}\nEgressUntagged={pvid}\n"));
    }
    body
}

/// The `.netdev` for a virtual L2 device: a bridge (`Kind=bridge`) or a bond
/// (`Kind=bond` + `[Bond] Mode=`, default `active-backup`). Members attach via
/// their own `.network` (`Bridge=`/`Bond=`), not here.
fn virtual_l2_netdev_body(iface: &Interface) -> String {
    match iface.if_type {
        Some(IfaceType::Bridge) => {
            let mut body = format!("[NetDev]\nName={}\nKind=bridge\n", iface.name);
            // A VLAN-aware bridge does 802.1Q filtering in the switch; the member
            // ports carry their tagged/untagged VLANs in `[BridgeVLAN]` sections.
            if iface.vlan_aware == Some(true) {
                body.push_str("\n[Bridge]\nVLANFiltering=yes\n");
            }
            body
        }
        Some(IfaceType::Bond) => {
            let mode = iface.bond_mode.as_deref().unwrap_or("active-backup");
            format!(
                "[NetDev]\nName={}\nKind=bond\n\n[Bond]\nMode={mode}\n",
                iface.name
            )
        }
        // A PPPoE client is brought up by `pppd` over its parent NIC, not by a
        // networkd netdev — `apply_pppoe` owns it, so there is nothing to render
        // here (same as an interface with no type). Kernel tunnels are handled by
        // `tunnel_netdev_body`, not this virtual-L2 renderer.
        None
        | Some(
            IfaceType::Pppoe
            | IfaceType::Wireguard
            | IfaceType::Gre
            | IfaceType::Ipip
            | IfaceType::Gretap
            // MACVLAN gets its own netdev renderer (macvlan_netdev_body), not
            // this virtual-L2 one.
            | IfaceType::Macvlan,
        ) => String::new(),
    }
}

/// The `.netdev` for a kernel point-to-point tunnel (roadmap C3): `Kind=gre`,
/// `ipip` or `gretap`, plus a `[Tunnel]` section carrying the `Local`/`Remote`
/// endpoint addresses and the optional `Key`/`TTL`. `Independent=yes` makes the
/// tunnel a standalone device (created from its endpoint addresses, not stacked
/// on a named base `.network`). The GRE `Key` is only emitted for gre/gretap —
/// validation rejects a key on ipip, so this never drops a meaningful value.
fn tunnel_netdev_body(iface: &Interface) -> String {
    let kind = match iface.if_type {
        Some(IfaceType::Gre) => "gre",
        Some(IfaceType::Ipip) => "ipip",
        Some(IfaceType::Gretap) => "gretap",
        // Non-tunnel types never reach here (apply only calls this for tunnels).
        _ => return String::new(),
    };
    let mut body = format!("[NetDev]\nName={}\nKind={kind}\n\n[Tunnel]\n", iface.name);
    if let Some(local) = &iface.local {
        body.push_str(&format!("Local={local}\n"));
    }
    if let Some(remote) = &iface.remote {
        body.push_str(&format!("Remote={remote}\n"));
    }
    if iface.tunnel_supports_key() {
        if let Some(key) = iface.tunnel_key {
            body.push_str(&format!("Key={key}\n"));
        }
    }
    if let Some(ttl) = iface.ttl {
        body.push_str(&format!("TTL={ttl}\n"));
    }
    body.push_str("Independent=yes\n");
    body
}

/// The `.netdev` that creates a WireGuard link: the `[WireGuard]` section
/// carries the private key (and optional listen port), and one
/// `[WireGuardPeer]` block per peer. The crypto is sourced from the interface's
/// matching `[[vpn.wireguard]]` tunnel. The file is a secret (private key) and is
/// installed 0640 root:systemd-network by [`apply`].
fn wireguard_netdev_body(name: &str, tunnel: &WireguardTunnel) -> String {
    let mut body = format!("[NetDev]\nName={name}\nKind=wireguard\n\n[WireGuard]\n");
    body.push_str(&format!("PrivateKey={}\n", tunnel.private_key));
    if let Some(port) = tunnel.listen_port {
        body.push_str(&format!("ListenPort={port}\n"));
    }
    for peer in &tunnel.peers {
        body.push_str("\n[WireGuardPeer]\n");
        body.push_str(&format!("PublicKey={}\n", peer.public_key));
        if !peer.allowed_ips.is_empty() {
            body.push_str(&format!("AllowedIPs={}\n", peer.allowed_ips.join(",")));
        }
        if let Some(ep) = &peer.endpoint {
            body.push_str(&format!("Endpoint={ep}\n"));
        }
        if let Some(psk) = &peer.preshared_key {
            body.push_str(&format!("PresharedKey={psk}\n"));
        }
        if let Some(k) = peer.persistent_keepalive {
            body.push_str(&format!("PersistentKeepalive={k}\n"));
        }
    }
    body
}

/// Render a `.network` unit for `iface`: bind its `address` (if any) and declare
/// any child VLAN links so networkd attaches them to this (parent) interface.
/// `"dhcp"` asks networkd to run a DHCP client; anything else is a static CIDR.
// A `.network` unit has many independent, orthogonal inputs (both address
// families, VLAN children, DHCP-server, RA, bridge/bond master, prefix
// delegation); passing them as discrete `Option`s keeps each render path
// explicit and each caller's intent readable.
#[allow(clippy::too_many_arguments)]
fn network_body(
    iface: &str,
    address: Option<&str>,
    address6: Option<&str>,
    vlan_children: &[String],
    macvlan_children: &[String],
    dhcp: Option<&DhcpServer>,
    ra: Option<&RouterAdvert>,
    master: Option<&str>,
    pd: Option<(&str, u8)>,
    mtu: Option<u16>,
    mac: Option<&str>,
    description: Option<&str>,
    disabled: bool,
) -> String {
    let v4dhcp = address == Some("dhcp");
    let v6dhcp = address6 == Some("dhcp");
    // An operator description becomes a comment header on the unit — documentary
    // only, but it makes a generated `/run` unit self-explaining.
    let mut body = String::new();
    if let Some(desc) = description {
        body.push_str(&format!("# {desc}\n"));
    }
    body.push_str(&format!("[Match]\nName={iface}\n\n[Network]\n"));
    // Static addresses (v4 then v6). "dhcp" is handled by the combined DHCP=
    // directive below; "auto" (v6) accepts RAs (SLAAC).
    if let Some(addr) = address {
        if addr != "dhcp" {
            body.push_str(&format!("Address={addr}\n"));
        }
    }
    match address6 {
        Some("auto") => body.push_str("IPv6AcceptRA=yes\n"),
        Some("dhcp") => {}
        Some(addr) => body.push_str(&format!("Address={addr}\n")),
        None => {}
    }
    // One combined DHCP= directive covers both families (v4 `address = "dhcp"`
    // keeps the historical `yes`; a v6-only DHCPv6 client is `ipv6`).
    match (v4dhcp, v6dhcp) {
        (true, _) => body.push_str("DHCP=yes\n"),
        (false, true) => body.push_str("DHCP=ipv6\n"),
        (false, false) => {}
    }
    // Enslavement to a bridge/bond master (`Bridge=br0` / `Bond=bond0`) — a
    // [Network] directive, so it goes here before any sub-section opens.
    if let Some(m) = master {
        body.push_str(&format!("{m}\n"));
    }
    for child in vlan_children {
        body.push_str(&format!("VLAN={child}\n"));
    }
    // MACVLAN children attach to this (parent) interface the same way VLAN
    // children do — a `[Network]` directive naming each pseudo-NIC riding on it.
    for child in macvlan_children {
        body.push_str(&format!("MACVLAN={child}\n"));
    }
    // Both the DHCP server and the RA sender are switched on by a directive in
    // [Network]; their detailed [DHCPServer] / [IPv6SendRA] / [IPv6Prefix]
    // sections follow. The enabling directives must be emitted here, before we
    // open any sub-section, or they would land in the wrong section.
    if dhcp.is_some() {
        body.push_str("DHCPServer=yes\n");
    }
    if ra.is_some() {
        body.push_str("IPv6SendRA=yes\n");
    }
    // A DHCPv6-PD downstream requests a slice of the uplink's delegated prefix
    // (the enabling directive stays in [Network]).
    if pd.is_some() {
        body.push_str("DHCPPrefixDelegation=yes\n");
    }

    // A DHCPv6 client (WAN uplink): solicit immediately rather than waiting for
    // a Router Advertisement, so a prefix delegation is requested up front.
    if v6dhcp {
        body.push_str("\n[DHCPv6]\nWithoutRA=solicit\n");
    }
    // The prefix-delegation downstream: take subnet `id` out of the uplink's
    // delegated prefix and advertise the resulting /64 to this interface's LAN.
    if let Some((uplink, subnet)) = pd {
        body.push_str("\n[DHCPPrefixDelegation]\n");
        body.push_str(&format!("UplinkInterface={uplink}\n"));
        body.push_str(&format!("SubnetId={subnet}\n"));
        body.push_str("Announce=yes\n");
    }

    // A built-in DHCP server serving this interface's static subnet. `EmitDNS`
    // and `DNS=` are only written when DNS servers were configured.
    if let Some(d) = dhcp {
        body.push_str("\n[DHCPServer]\n");
        if let Some(off) = d.pool_offset {
            body.push_str(&format!("PoolOffset={off}\n"));
        }
        if let Some(size) = d.pool_size {
            body.push_str(&format!("PoolSize={size}\n"));
        }
        if let Some(lease) = d.lease_time {
            body.push_str(&format!("DefaultLeaseTimeSec={lease}\n"));
        }
        if !d.dns.is_empty() {
            body.push_str("EmitDNS=yes\n");
            body.push_str(&format!("DNS={}\n", d.dns.join(" ")));
        }
        // An override default-router (option 3). Unset ⇒ networkd advertises the
        // server's own address, so we emit nothing.
        if let Some(gw) = &d.default_router {
            body.push_str(&format!("EmitRouter=yes\nRouter={gw}\n"));
        }
        // A domain name (option 15) — networkd has no dedicated key, so use the
        // generic SendOption escape hatch (`option:type:value`).
        if let Some(domain) = &d.domain {
            body.push_str(&format!("SendOption=15:string:{domain}\n"));
        }
        // Static reservations become one [DHCPServerStaticLease] section each
        // (networkd keys on MAC + address; the CLI `name` is not emitted).
        for lease in &d.static_mappings {
            body.push_str("\n[DHCPServerStaticLease]\n");
            body.push_str(&format!("MACAddress={}\n", lease.mac));
            body.push_str(&format!("Address={}\n", lease.ip));
        }
    }

    // IPv6 Router Advertisements: the [IPv6SendRA] flags/DNS, then one
    // [IPv6Prefix] per advertised prefix (`Assign=yes` so the router also binds
    // an address from each prefix to this interface — no separate v6 address).
    if let Some(r) = ra {
        body.push_str("\n[IPv6SendRA]\n");
        if r.managed {
            body.push_str("Managed=yes\n");
        }
        if r.other_config {
            body.push_str("OtherInformation=yes\n");
        }
        if let Some(life) = r.router_lifetime {
            body.push_str(&format!("RouterLifetimeSec={life}\n"));
        }
        if !r.dns.is_empty() {
            body.push_str("EmitDNS=yes\n");
            body.push_str(&format!("DNS={}\n", r.dns.join(" ")));
        }
        for prefix in &r.prefixes {
            body.push_str("\n[IPv6Prefix]\n");
            body.push_str(&format!("Prefix={prefix}\n"));
            body.push_str("Assign=yes\n");
        }
    }

    // Link tunables (MTU / MAC cloning) plus an admin-down policy — a `[Link]`
    // section networkd applies to the interface. Emitted only when something is
    // set. `ActivationPolicy=down` keeps an administratively disabled interface
    // down (networkd 257 also accepts `always-down`; `down` still allows a manual
    // `ip link set up` for diagnostics, which is the friendlier default).
    if mtu.is_some() || mac.is_some() || disabled {
        body.push_str("\n[Link]\n");
        if let Some(m) = mtu {
            body.push_str(&format!("MTUBytes={m}\n"));
        }
        if let Some(mac) = mac {
            body.push_str(&format!("MACAddress={mac}\n"));
        }
        if disabled {
            body.push_str("ActivationPolicy=down\n");
        }
    }
    body
}

/// systemd-resolved's runtime drop-in dir. A `.conf` here overrides the image
/// `resolved.conf`, and (like the networkd units) it lives on tmpfs so it is
/// re-asserted from the saved config each boot.
const RESOLVED_DROPIN_DIR: &str = "/run/systemd/resolved.conf.d";
const RESOLVED_DROPIN: &str = "10-sentinel-dns.conf";

/// Render the systemd-resolved drop-in — the **box's own** resolver, which
/// forwards the appliance's queries to the configured upstreams. `None` when no
/// upstream is set. LAN serving, host-overrides and blocklists are dnsmasq's job
/// ([`dnsmasq_conf_body`]), so this no longer binds LAN stub listeners.
fn resolved_dropin_body(dns: &Dns) -> Option<String> {
    if dns.upstream.is_empty() {
        return None;
    }
    let mut body = String::from("[Resolve]\n");
    body.push_str(&format!("DNS={}\n", dns.upstream.join(" ")));
    // A forwarder trusts its upstream; default DNSSEC off so an unsigned or
    // validation-breaking upstream still resolves. An explicit value overrides.
    body.push_str(&format!(
        "DNSSEC={}\n",
        dns.dnssec.as_deref().unwrap_or("no")
    ));
    Some(body)
}

/// dnsmasq's runtime confdir (the image enables `services.dnsmasq` with a
/// `conf-dir` pointing here). A `.conf` here turns the box into a LAN resolver:
/// forwarding, host-overrides and DNS blocklists, bound to the serving links.
const DNSMASQ_CONFDIR: &str = "/run/sentinel/dnsmasq.d";
const DNSMASQ_CONF: &str = "sentinel.conf";

/// Reject a value that would break the line-oriented daemon config it is
/// interpolated into. Control characters (newline/CR/NUL/tab) can splice an extra
/// directive; `extra` names any config-specific delimiter that would also corrupt
/// syntax (e.g. `'` inside a single-quoted field, `/` inside a `/domain/` pattern).
///
/// This is render-time defense in depth: config-side validation should already
/// reject these, but a hostile value must never reach a generated config intact —
/// and we prefer erroring loudly over silently mangling it. `field` names the
/// offending input so the error is actionable.
fn reject_unsafe(field: &str, value: &str, extra: &[char]) -> Result<()> {
    if let Some(c) = value.chars().find(|c| c.is_control() || extra.contains(c)) {
        anyhow::bail!(
            "{field} contains an unsafe character {c:?} that could corrupt the generated \
             daemon config; remove it"
        );
    }
    Ok(())
}

/// Render the dnsmasq drop-in for the LAN resolver, or `None` when no interface
/// serves DNS. `interface=`/`bind-interfaces` (base config) restrict dnsmasq to
/// exactly the serving links (so it never fights resolved for 127.0.0.53);
/// `server=` sets the upstreams, `address=/name/ip` is a host-override, and
/// `address=/domain/0.0.0.0` (+`::`) sinkholes a blocked domain.
fn dnsmasq_conf_body(dns: &Dns) -> Result<Option<String>> {
    if dns.serve_on.is_empty() {
        return Ok(None);
    }
    let mut body = String::from("# rendered by sentinel — LAN DNS (dnsmasq)\nno-resolv\n");
    for up in &dns.upstream {
        body.push_str(&format!("server={up}\n"));
    }
    for name in &dns.serve_on {
        body.push_str(&format!("interface={name}\n"));
    }
    // Cache sizing (dnsmasq default is 150) and the site's local domain: `local=`
    // answers the domain authoritatively (never forwarded) and `domain=` hands it
    // to clients as the DHCP/search suffix.
    if let Some(n) = dns.cache_size {
        body.push_str(&format!("cache-size={n}\n"));
    }
    if let Some(dom) = &dns.local_domain {
        // The domain is delimited by `/` in `local=/dom/`; a `/` (or control char)
        // would break the pattern and could splice a directive.
        reject_unsafe("dns local-domain", dom, &['/'])?;
        body.push_str(&format!("local=/{dom}/\n"));
        body.push_str(&format!("domain={dom}\n"));
    }
    for (host, ip) in &dns.host_override {
        reject_unsafe("dns host-override name", host, &['/'])?;
        body.push_str(&format!("address=/{host}/{ip}\n"));
    }
    for domain in &dns.blocklist {
        reject_unsafe("dns blocklist entry", domain, &['/'])?;
        // Sinkhole to a dead address (v4 and v6), the pfBlocker/pi-hole convention.
        body.push_str(&format!("address=/{domain}/0.0.0.0\n"));
        body.push_str(&format!("address=/{domain}/::\n"));
    }
    if dns.dnssec.as_deref() == Some("yes") {
        body.push_str("dnssec\n");
    }
    Ok(Some(body))
}

/// chrony's runtime confdir (the image enables `services.chrony` and includes
/// this dir). A `.conf` here layers the LAN NTP-server config onto the base
/// chrony config, re-asserted from the saved config each boot like the rest.
const CHRONY_CONFDIR: &str = "/run/sentinel/chrony.d";
const CHRONY_CONF: &str = "sentinel.conf";

/// The IPv4 network of a static CIDR (`"10.0.0.1/24"` → `"10.0.0.0/24"`) — the
/// subnet chrony `allow`s for a serving interface. `None` for a non-IPv4/`dhcp`
/// address (validation forbids serving NTP on such an interface).
fn ipv4_network(cidr: &str) -> Option<String> {
    let (ip, prefix) = cidr.split_once('/')?;
    let ip: Ipv4Addr = ip.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let net = u32::from(ip) & mask;
    Some(format!("{}/{prefix}", Ipv4Addr::from(net)))
}

/// Render chrony's confdir drop-in for the NTP server, or `None` when none is
/// configured. `server <up> iburst` syncs the box to each upstream; `allow
/// <subnet>` lets each serving interface's subnet query the box for time.
fn chrony_conf_body(ntp: &Ntp, ifaces: &[Interface]) -> Option<String> {
    if ntp.is_empty() {
        return None;
    }
    let mut body = String::new();
    for up in &ntp.upstream {
        body.push_str(&format!("server {up} iburst\n"));
    }
    for name in &ntp.serve_on {
        if let Some(net) = ifaces
            .iter()
            .find(|i| &i.name == name)
            .and_then(|i| i.address.as_deref())
            .and_then(ipv4_network)
        {
            body.push_str(&format!("allow {net}\n"));
        }
    }
    Some(body)
}

/// Which stage of the system's life a `net::apply` runs in — the difference is
/// whether it may touch running services. `Live` (a `commit`) reloads/restarts
/// units so a change lands immediately. `Boot` is the early `sentinel-boot`
/// service, which is ordered **Before** systemd-networkd: it may ONLY render
/// files (networkd units + resolved/dnsmasq/chrony drop-ins + pppoe peers) and
/// must perform ZERO unit operations — no `networkctl`, no `systemctl restart`,
/// no sudo — because every service it would poke is ordered after the network,
/// so any such call would deadlock networkd's own start against this unit. The
/// services read the freshly written files on their own (later) start; that is
/// exactly why sentinel-boot runs before them. Runtime-only state (tc qdiscs,
/// policy routes) that a file can't express is (re)applied by the post-networkd
/// `sentinel-boot-late` stage instead — see [`apply_link_runtime`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ApplyMode {
    /// `commit` on the running system — reload/restart units to apply live.
    Live,
    /// Early boot (before networkd) — render files only, never touch a unit.
    Boot,
}

/// Reconcile the chrony confdir drop-in to `appliance.services.ntp`: write it
/// when an NTP server is configured, remove it otherwise, and (only in `Live`
/// mode, and only when it changed) restart chrony — so a non-NTP commit never
/// disturbs the box's timekeeping, and boot never restarts a service out of
/// order (chronyd reads the drop-in on its own start).
fn apply_chrony(appliance: &Appliance, mode: ApplyMode) -> Result<()> {
    let path = Path::new(CHRONY_CONFDIR).join(CHRONY_CONF);
    match chrony_conf_body(&appliance.services.ntp, &appliance.interfaces) {
        Some(body) => {
            let changed = std::fs::read_to_string(&path)
                .map(|c| c != body)
                .unwrap_or(true);
            system::ensure_dir(Path::new(CHRONY_CONFDIR))?;
            system::install_file(&path, &body)?;
            if changed && mode == ApplyMode::Live {
                restart_chrony();
            }
        }
        None => {
            if path.exists() {
                system::remove_file(&path)?;
                if mode == ApplyMode::Live {
                    restart_chrony();
                }
            }
        }
    }
    Ok(())
}

/// Restart chrony best-effort (mirrors the resolved reconcile): the confdir file
/// is written regardless, so a boot-time chrony start still picks it up.
fn restart_chrony() {
    if let Err(e) = system::reload_chrony() {
        eprintln!("warning: restarting chrony failed (applies on next start): {e}");
    }
}

/// Reconcile the systemd-resolved drop-in to `appliance.dns`: write it when a
/// forwarder is configured, remove it otherwise, then restart resolved so the
/// stub listener (re)binds. Best-effort restart (mirrors networkd): the drop-in
/// is written regardless, so a boot-time resolved start still picks it up.
fn apply_resolved(appliance: &Appliance, mode: ApplyMode) -> Result<()> {
    let path = Path::new(RESOLVED_DROPIN_DIR).join(RESOLVED_DROPIN);
    let changed = match resolved_dropin_body(&appliance.services.dns) {
        Some(body) => {
            let changed = std::fs::read_to_string(&path)
                .map(|c| c != body)
                .unwrap_or(true);
            system::ensure_dir(Path::new(RESOLVED_DROPIN_DIR))?;
            system::install_file(&path, &body)?;
            changed
        }
        None => {
            let existed = path.exists();
            if existed {
                system::remove_file(&path)?;
            }
            existed
        }
    };
    // Boot never restarts (resolved reads the drop-in on its own start, and a
    // restart from the pre-networkd sentinel-boot would deadlock).
    if changed && mode == ApplyMode::Live {
        if let Err(e) = system::reload_resolved() {
            eprintln!("warning: restarting systemd-resolved failed (applies on next start): {e}");
        }
    }
    Ok(())
}

/// Reconcile the dnsmasq drop-in to the LAN DNS config: write it when an
/// interface serves DNS, remove it otherwise, and restart dnsmasq — but only
/// when the desired config changed, so a non-DNS commit never disturbs the LAN
/// resolver. Best-effort restart (the drop-in is written regardless, so a
/// boot-time dnsmasq start still picks it up).
fn apply_dnsmasq(appliance: &Appliance, mode: ApplyMode) -> Result<()> {
    let path = Path::new(DNSMASQ_CONFDIR).join(DNSMASQ_CONF);
    let changed = match dnsmasq_conf_body(&appliance.services.dns)? {
        Some(body) => {
            let changed = std::fs::read_to_string(&path)
                .map(|c| c != body)
                .unwrap_or(true);
            system::ensure_dir(Path::new(DNSMASQ_CONFDIR))?;
            system::install_file(&path, &body)?;
            changed
        }
        None => {
            let existed = path.exists();
            if existed {
                system::remove_file(&path)?;
            }
            existed
        }
    };
    // Boot never restarts (dnsmasq reads its conf-dir on its own start, and a
    // restart from the pre-networkd sentinel-boot would deadlock).
    if changed && mode == ApplyMode::Live {
        if let Err(e) = system::reload_dnsmasq() {
            eprintln!("warning: restarting dnsmasq failed (applies on next start): {e}");
        }
    }
    Ok(())
}

// --- Box services (roadmap C18) --------------------------------------------
//
// LLDP / SNMP / mDNS-reflector / dynamic-DNS / DHCP-relay are box-wide services
// the appliance *offers* (like DNS/NTP), each built on a standard NixOS-packaged
// daemon Sentinel owns the lifecycle of. Unlike the always-on resolved/dnsmasq/
// chrony co-services (whose drop-ins render in `apply_persistent`), these are
// off by default: Sentinel renders each one's config to a `/run/sentinel` file
// and starts/stops its unit from `apply_link_runtime` — the post-networkd stage,
// since a link-scoped service (LLDP/mDNS/relay) needs its interfaces up. All
// follow the change-detect-then-restart model the co-service drop-ins use.

/// lldpd's confdir (symlinked from `/etc/lldpd.d` by the appliance module, which
/// lldpd reads at start): a `.conf` here is an lldpcli command script scoping the
/// advertised interfaces.
const LLDPD_CONFDIR: &str = "/run/sentinel/lldpd.d";
const LLDPD_CONF: &str = "sentinel.conf";
const LLDPD_UNIT: &str = "lldpd.service";

/// The net-snmp agent config (rendered 0640 — it carries the community string)
/// and the Sentinel-owned unit that runs `snmpd` against it.
const SNMPD_CONF: &str = "/run/sentinel/snmpd.conf";
const SNMPD_UNIT: &str = "sentinel-snmpd.service";

/// The avahi reflector config + its Sentinel-owned unit.
const MDNS_CONF: &str = "/run/sentinel/avahi/avahi-daemon.conf";
const MDNS_UNIT: &str = "sentinel-mdns.service";

/// The ddclient config (rendered 0640 — it carries the provider password) + its
/// Sentinel-owned unit.
const DDCLIENT_CONF: &str = "/run/sentinel/ddclient/ddclient.conf";
const DDCLIENT_UNIT: &str = "sentinel-ddclient.service";

/// The DHCP-relay config (a dnsmasq relay-only instance) + its Sentinel-owned
/// unit. isc-dhcp's `dhcrelay` is gone from nixpkgs, so the relay rides on
/// dnsmasq's `--dhcp-relay` mode (the daemon is already in the image); this is a
/// SECOND, DNS-disabled dnsmasq instance distinct from the LAN resolver.
const DHCP_RELAY_CONF: &str = "/run/sentinel/dhcp-relay/relay.conf";
const DHCP_RELAY_UNIT: &str = "sentinel-dhcp-relay.service";

/// NAT64 (roadmap C10). tayga's daemon config + a datapath setup script (the
/// `nat64` tun device + pool/prefix routes tayga can't add itself), driven by the
/// Sentinel-owned `sentinel-nat64` unit. DNS64 rides a second `sentinel-dns64`
/// unit running unbound against a rendered config.
const NAT64_DIR: &str = "/run/sentinel/nat64";
const TAYGA_CONF: &str = "/run/sentinel/nat64/tayga.conf";
const TAYGA_SETUP: &str = "/run/sentinel/nat64/setup.sh";
const NAT64_UNIT: &str = "sentinel-nat64.service";
const DNS64_CONF: &str = "/run/sentinel/nat64/unbound.conf";
const DNS64_UNIT: &str = "sentinel-dns64.service";
/// The tun device tayga translates on (matches the `tun-device` in tayga.conf and
/// the routes in the setup script).
const NAT64_DEV: &str = "nat64";

/// Render lldpd's confdir drop-in, or `None` when LLDP is off. When an interface
/// whitelist is given it becomes an lldpcli `configure system interface pattern`
/// (a comma-separated glob list); an empty list ⇒ every interface (lldpd's own
/// default), so we emit just the header.
fn lldpd_conf_body(lldp: &Lldp) -> Option<String> {
    if !lldp.enable {
        return None;
    }
    let mut body = String::from("# rendered by sentinel — LLDP (lldpd)\n");
    if !lldp.interface.is_empty() {
        body.push_str(&format!(
            "configure system interface pattern {}\n",
            lldp.interface.join(",")
        ));
    }
    Some(body)
}

/// Render the net-snmp `snmpd.conf`, or `None` when no agent is configured. The
/// agent is read-only by construction — only `rocommunity`/`rocommunity6` lines
/// are ever emitted, never `rwcommunity`. Each source subnet scopes one
/// community clause; an empty `allow` list ⇒ `default` (any source).
fn snmpd_conf_body(snmp: &Snmp) -> Result<Option<String>> {
    let Some(community) = snmp.community.as_ref() else {
        return Ok(None);
    };
    let mut body = String::from("# rendered by sentinel — SNMP (read-only)\n");
    body.push_str(&format!(
        "agentaddress {}\n",
        snmp.listen.as_deref().unwrap_or("udp:161")
    ));
    if snmp.allow.is_empty() {
        body.push_str(&format!("rocommunity {community} default\n"));
    } else {
        for src in &snmp.allow {
            // net-snmp splits the read-only community by address family:
            // `rocommunity` for IPv4 sources, `rocommunity6` for IPv6.
            let directive = if src.contains(':') {
                "rocommunity6"
            } else {
                "rocommunity"
            };
            body.push_str(&format!("{directive} {community} {src}\n"));
        }
    }
    if let Some(loc) = &snmp.location {
        // syslocation/syscontact take the rest of the line as free text; a newline
        // would inject a fresh directive (e.g. `rwcommunity`), so reject controls.
        reject_unsafe("snmp location", loc, &[])?;
        body.push_str(&format!("syslocation {loc}\n"));
    }
    if let Some(contact) = &snmp.contact {
        reject_unsafe("snmp contact", contact, &[])?;
        body.push_str(&format!("syscontact {contact}\n"));
    }
    Ok(Some(body))
}

/// Render the avahi reflector config, or `None` when no reflector is configured.
/// `enable-reflector` bridges mDNS between the `allow-interfaces`; publishing is
/// disabled so the box only relays neighbours' announcements, never its own.
fn avahi_conf_body(mdns: &Mdns) -> Option<String> {
    if mdns.interface.is_empty() {
        return None;
    }
    let mut body = String::from("# rendered by sentinel — mDNS reflector (avahi)\n[server]\n");
    body.push_str(&format!("allow-interfaces={}\n", mdns.interface.join(",")));
    body.push_str("use-ipv4=yes\nuse-ipv6=yes\n");
    // No system bus on the appliance — avahi runs standalone as a pure reflector.
    body.push_str("enable-dbus=no\n");
    body.push_str("[publish]\ndisable-publishing=yes\n");
    body.push_str("[reflector]\nenable-reflector=yes\n");
    Some(body)
}

/// Render the ddclient config, or `None` when no client is configured. `use=if`
/// publishes a named interface's address; with no interface we fall back to
/// `use=web` (discover the WAN IP via the provider's checkip — correct behind
/// CGNAT). The password is single-quoted so an odd character can't break the
/// line; the whole file is installed 0640 (it carries the secret).
fn ddclient_conf_body(dd: &Dyndns) -> Result<Option<String>> {
    let Some(hostname) = dd.hostname.as_ref() else {
        return Ok(None);
    };
    // Every interpolated field lands on its own `key=value` (or bare) line, so a
    // newline in any of them would inject a directive; the password is additionally
    // single-quoted, so a literal `'` would break out of the quoting.
    reject_unsafe("dyndns hostname", hostname, &[])?;
    let mut body = String::from("# rendered by sentinel — dynamic DNS (ddclient)\n");
    body.push_str("daemon=300\nsyslog=yes\nssl=yes\n");
    body.push_str(&format!(
        "protocol={}\n",
        dd.provider.as_deref().unwrap_or("dyndns2")
    ));
    match &dd.interface {
        Some(iface) => body.push_str(&format!("use=if, if={iface}\n")),
        None => body.push_str("use=web\n"),
    }
    if let Some(server) = &dd.server {
        reject_unsafe("dyndns server", server, &[])?;
        body.push_str(&format!("server={server}\n"));
    }
    if let Some(login) = &dd.login {
        reject_unsafe("dyndns login", login, &[])?;
        body.push_str(&format!("login={login}\n"));
    }
    if let Some(password) = &dd.password {
        reject_unsafe("dyndns password", password, &['\''])?;
        body.push_str(&format!("password='{password}'\n"));
    }
    body.push_str(&format!("{hostname}\n"));
    Ok(Some(body))
}

/// The bare IPv4 of a static CIDR (`"10.0.7.1/24"` → `"10.0.7.1"`), or `None` for
/// a non-IPv4/`dhcp` address. The relay stamps this as the DHCP giaddr.
fn ipv4_of(addr: &str) -> Option<String> {
    let ip = addr.split('/').next()?;
    ip.parse::<Ipv4Addr>().ok().map(|_| ip.to_string())
}

/// Render the dnsmasq relay-only config, or `None` when no relay is configured.
/// `port=0` disables the DNS half (this instance ONLY relays DHCP), then one
/// `dhcp-relay=<local-addr>,<server>` line per (client-facing interface, upstream
/// server): dnsmasq listens for DHCP on the interface owning `<local-addr>` and
/// forwards to `<server>`. Interfaces without a resolvable static IPv4 are
/// skipped (validation already forbids them).
fn dhcp_relay_conf_body(relay: &DhcpRelay, ifaces: &[Interface]) -> Option<String> {
    if relay.server.is_empty() || relay.interface.is_empty() {
        return None;
    }
    let mut body = String::from("# rendered by sentinel — DHCP relay (dnsmasq)\nport=0\n");
    let mut any = false;
    for name in &relay.interface {
        let Some(local) = ifaces
            .iter()
            .find(|i| &i.name == name)
            .and_then(|i| i.address.as_deref())
            .and_then(ipv4_of)
        else {
            continue;
        };
        for server in &relay.server {
            body.push_str(&format!("dhcp-relay={local},{server}\n"));
            any = true;
        }
    }
    any.then_some(body)
}

/// Reconcile one Sentinel-owned box service to its rendered config: write the
/// file (0640 when it carries a secret) and (re)start the unit when the config
/// changed, or stop the unit and drop the file when the service is unconfigured.
/// The generic core behind [`apply_lldp`]/[`apply_snmp`]/… — mirrors
/// [`apply_multiwan`]'s model, parameterised over unit + path + body.
fn apply_box_service(unit: &str, path: &Path, body: Option<String>, secret: bool) -> Result<()> {
    match body {
        Some(body) => {
            let changed = file_changed(path, &body);
            if secret {
                system::install_service_secret(path, &body)?;
            } else {
                system::install_file(path, &body)?;
            }
            if changed {
                if let Err(e) = system::service_restart(unit) {
                    eprintln!("warning: (re)starting {unit} failed (applies on next start): {e}");
                }
            }
        }
        None => {
            if path.exists() {
                if let Err(e) = system::service_stop(unit) {
                    eprintln!("warning: stopping {unit}: {e}");
                }
                system::remove_file(path)?;
            }
        }
    }
    Ok(())
}

/// Reconcile all box services (LLDP/SNMP/mDNS/dyndns/DHCP-relay) to the config.
fn apply_box_services(appliance: &Appliance) -> Result<()> {
    let s = &appliance.services;
    apply_box_service(
        LLDPD_UNIT,
        &Path::new(LLDPD_CONFDIR).join(LLDPD_CONF),
        lldpd_conf_body(&s.lldp),
        false,
    )?;
    apply_box_service(
        SNMPD_UNIT,
        Path::new(SNMPD_CONF),
        snmpd_conf_body(&s.snmp)?,
        true,
    )?;
    apply_box_service(
        MDNS_UNIT,
        Path::new(MDNS_CONF),
        avahi_conf_body(&s.mdns),
        false,
    )?;
    apply_box_service(
        DDCLIENT_UNIT,
        Path::new(DDCLIENT_CONF),
        ddclient_conf_body(&s.dyndns)?,
        true,
    )?;
    apply_box_service(
        DHCP_RELAY_UNIT,
        Path::new(DHCP_RELAY_CONF),
        dhcp_relay_conf_body(&s.dhcp_relay, &appliance.interfaces),
        false,
    )?;
    Ok(())
}

// --- NAT64 + DNS64 (roadmap C10) -------------------------------------------
//
// tayga translates an IPv6-only segment's traffic to `64:ff9b::<v4>` into real
// IPv4 sourced from `pool`; unbound (DNS64) synthesises AAAA in the prefix for
// v4-only names so unmodified clients resolve+reach v4 hosts. Both are Sentinel-
// owned units started/stopped from apply_link_runtime (after networkd, so tayga's
// routes land on up links and unbound can bind the serving interface's address).

/// The bare IPv6 host of a static CIDR (`"2001:db8::1/64"` → `"2001:db8::1"`), or
/// `None` for a non-IPv6/`auto`/`dhcp` address. DNS64's unbound binds this.
fn ipv6_of(addr: &str) -> Option<String> {
    let ip = addr.split('/').next()?;
    ip.parse::<Ipv6Addr>().ok().map(|_| ip.to_string())
}

/// tayga's own IPv4 address — the first host of the pool (`"192.0.2.0/24"` →
/// `"192.0.2.1"`). tayga reserves this from the dynamic pool for its self / ICMP.
fn nat64_router_ipv4(pool: &str) -> Option<String> {
    let (net, prefix) = pool.split_once('/')?;
    let net: Ipv4Addr = net.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    // Mask to the network address, then +1 for the first host (a /0 masks nothing;
    // shifting a u32 by 32 is UB, so special-case it).
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let network = u32::from(net) & mask;
    Some(Ipv4Addr::from(network + 1).to_string())
}

/// Render tayga's daemon config, or `None` when NAT64 is off. The tun device +
/// prefix/pool routes are set up out-of-band by [`tayga_setup_body`]; this file is
/// only the translator's own knobs (its self-addresses, the prefix, the pool).
/// `ipv6-addr` is tayga's own node address (the source of its ICMPv6 errors),
/// taken from the serving interface's static v6 address — mandatory with the
/// well-known prefix and a non-global (e.g. behind-NAT) IPv4 pool.
fn tayga_conf_body(n64: &Nat64, ifaces: &[Interface]) -> Option<String> {
    if !n64.enabled {
        return None;
    }
    let pool = n64.pool.as_deref()?;
    let router = nat64_router_ipv4(pool)?;
    let iface = n64.interface.as_deref()?;
    let node6 = ifaces
        .iter()
        .find(|i| i.name == iface)
        .and_then(|i| i.address6.as_deref())
        .and_then(ipv6_of)?;
    let mut body = String::from("# rendered by sentinel — NAT64 (tayga)\n");
    body.push_str(&format!("tun-device {NAT64_DEV}\n"));
    body.push_str(&format!("ipv4-addr {router}\n"));
    body.push_str(&format!("ipv6-addr {node6}\n"));
    body.push_str(&format!("prefix {}\n", n64.effective_prefix()));
    body.push_str(&format!("dynamic-pool {pool}\n"));
    body.push_str(&format!("data-dir {NAT64_DIR}\n"));
    Some(body)
}

/// Render the datapath setup script tayga's unit runs before the daemon: create
/// the `nat64` tun, bring it up, add tayga's self-address and the pool/prefix
/// routes (so the kernel forwards `64:ff9b::/96` and pool traffic to the tun), and
/// enable forwarding. Idempotent (`replace`/existence-guarded) so a re-apply or a
/// restart is safe. `None` when NAT64 is off.
fn tayga_setup_body(n64: &Nat64) -> Option<String> {
    if !n64.enabled {
        return None;
    }
    let pool = n64.pool.as_deref()?;
    let router = nat64_router_ipv4(pool)?;
    let prefix = n64.effective_prefix();
    let mut body = String::from(
        "#!/bin/sh\n# rendered by sentinel — NAT64 datapath (tayga tun + routes)\nset -e\n",
    );
    body.push_str(&format!(
        "ip link show {NAT64_DEV} >/dev/null 2>&1 || tayga --mktun --config {TAYGA_CONF}\n"
    ));
    body.push_str(&format!("ip link set {NAT64_DEV} up\n"));
    body.push_str(&format!("ip addr replace {router}/32 dev {NAT64_DEV}\n"));
    body.push_str(&format!("ip route replace {pool} dev {NAT64_DEV}\n"));
    body.push_str(&format!("ip -6 route replace {prefix} dev {NAT64_DEV}\n"));
    body.push_str("sysctl -qw net.ipv6.conf.all.forwarding=1\n");
    body.push_str("sysctl -qw net.ipv4.ip_forward=1\n");
    Some(body)
}

/// Render the DNS64 unbound config, or `None` when DNS64 is off. unbound binds the
/// serving interface's IPv6 address on :53, forwards every query to the box's
/// configured upstream(s), and synthesises `AAAA` inside the NAT64 prefix for
/// v4-only names (`module-config: "dns64 iterator"`). Privilege-drop/chroot are
/// disabled — the unit already sandboxes it and /run is the only writable path.
fn unbound_dns64_body(n64: &Nat64, dns: &Dns, ifaces: &[Interface]) -> Option<String> {
    if !n64.enabled || !n64.dns64 {
        return None;
    }
    // Bind the serving interface's static IPv6 address (validation guarantees it).
    let iface = n64.interface.as_deref()?;
    let listen = ifaces
        .iter()
        .find(|i| i.name == iface)
        .and_then(|i| i.address6.as_deref())
        .and_then(ipv6_of)?;
    if dns.upstream.is_empty() {
        return None;
    }
    let mut body = String::from("# rendered by sentinel — DNS64 (unbound)\nserver:\n");
    body.push_str("    verbosity: 1\n");
    body.push_str(&format!("    interface: {listen}\n"));
    body.push_str("    port: 53\n");
    // Bind the serving v6 address even if networkd has not brought it up yet, so
    // a fresh commit/boot doesn't fail the first start (it would restart, but
    // freebind avoids the window entirely).
    body.push_str("    ip-freebind: yes\n");
    body.push_str("    do-ip4: yes\n    do-ip6: yes\n    do-udp: yes\n    do-tcp: yes\n");
    body.push_str("    access-control: 0.0.0.0/0 allow\n    access-control: ::/0 allow\n");
    body.push_str("    module-config: \"dns64 iterator\"\n");
    body.push_str(&format!("    dns64-prefix: {}\n", n64.effective_prefix()));
    body.push_str(&format!("    directory: \"{NAT64_DIR}\"\n"));
    body.push_str("    chroot: \"\"\n    username: \"\"\n    pidfile: \"\"\n    use-syslog: yes\n");
    body.push_str("forward-zone:\n    name: \".\"\n");
    for up in &dns.upstream {
        body.push_str(&format!("    forward-addr: {up}\n"));
    }
    Some(body)
}

/// Reconcile NAT64 (tayga) + DNS64 (unbound) to the config. tayga owns two
/// artifacts (its conf + the datapath setup script) behind one unit, so it can't
/// use the single-file [`apply_box_service`]; DNS64 (one config, one unit) does.
fn apply_nat64(appliance: &Appliance) -> Result<()> {
    let n64 = &appliance.nat.nat64;
    let conf_path = Path::new(TAYGA_CONF);
    let setup_path = Path::new(TAYGA_SETUP);
    match (
        tayga_conf_body(n64, &appliance.interfaces),
        tayga_setup_body(n64),
    ) {
        (Some(conf), Some(setup)) => {
            let changed = file_changed(conf_path, &conf) || file_changed(setup_path, &setup);
            system::ensure_dir(Path::new(NAT64_DIR))?;
            system::install_file(conf_path, &conf)?;
            system::install_file(setup_path, &setup)?;
            if changed {
                if let Err(e) = system::service_restart(NAT64_UNIT) {
                    eprintln!(
                        "warning: (re)starting {NAT64_UNIT} failed (applies on next start): {e}"
                    );
                }
            }
        }
        _ => {
            if conf_path.exists() || setup_path.exists() {
                if let Err(e) = system::service_stop(NAT64_UNIT) {
                    eprintln!("warning: stopping {NAT64_UNIT}: {e}");
                }
                if conf_path.exists() {
                    system::remove_file(conf_path)?;
                }
                if setup_path.exists() {
                    system::remove_file(setup_path)?;
                }
            }
        }
    }
    // DNS64 (unbound) — a single config behind a single unit.
    apply_box_service(
        DNS64_UNIT,
        Path::new(DNS64_CONF),
        unbound_dns64_body(n64, &appliance.services.dns, &appliance.interfaces),
        false,
    )?;
    Ok(())
}

// --- PPPoE client (roadmap C5) ---------------------------------------------
//
// A `type = "pppoe"` interface is brought up by `pppd` (not networkd) over the
// raw uplink NIC in `parent`, using the `rp-pppoe` plugin. Sentinel renders the
// pppd peer options to `/run/sentinel/ppp/peers/<name>` and the ISP credentials
// to a 0600 `chap-secrets`/`pap-secrets` (symlinked from pppd's `/etc/ppp`
// lookup paths by the appliance module), then (re)starts one `sentinel-pppoe@`
// systemd instance per session. On a PPPoE (and generally tunnel) egress the
// TCP MSS must be clamped to the path MTU, or large-segment TCP wedges behind
// the smaller PPPoE MTU; we render an nftables ruleset that clamps MSS to PMTU
// on each ppp interface (the VyOS/`--clamp-mss-to-pmtu` equivalent) and load it
// with `nft`. All render+reload paths follow the same change-detect model the
// DNS/NTP drop-ins use.

/// The runtime dir for all PPPoE render artifacts (peer options, secrets, the
/// MSS ruleset). tmpfs; re-seeded from the saved config each boot.
const PPPOE_RUNTIME_DIR: &str = "/run/sentinel/ppp";
/// pppd peer-option files, one per session — `pppd file <this>` reads them.
const PPPOE_PEERS_DIR: &str = "/run/sentinel/ppp/peers";
/// The credential files (both CHAP and PAP forms — pppd picks whichever the ISP
/// negotiates). 0600 root:root; the appliance module symlinks pppd's standard
/// `/etc/ppp/{chap,pap}-secrets` lookup paths here.
const PPP_CHAP_SECRETS: &str = "/run/sentinel/ppp/chap-secrets";
const PPP_PAP_SECRETS: &str = "/run/sentinel/ppp/pap-secrets";
/// The rendered TCP-MSS-clamp nftables ruleset (loaded with `nft -f`).
const PPPOE_MSS_NFT: &str = "/run/sentinel/ppp/mss.nft";

/// Render a pppd peer-options file for a PPPoE client interface. pppd's bundled
/// `pppoe.so` plugin rides on `parent` (the raw uplink NIC, given as `nic-<if>`);
/// `ifname` pins the resulting link name; `defaultroute`/`usepeerdns` take the
/// WAN default route + DNS from the ISP; `persist` re-dials on drop. The password
/// is NOT here — it lives in the 0600 secrets file, matched by `user`.
///
/// The plugin is `pppoe.so` (ppp ≥ 2.5), and the uplink is selected with the
/// `nic-<iface>` option rather than the legacy `plugin rp-pppoe.so <iface>`
/// positional form (removed in ppp 2.5). The `rp_pppoe_service`/`rp_pppoe_ac`
/// options are still accepted as legacy aliases by that plugin.
/// A PPPoE client that should be dialing: a `type = "pppoe"` interface that is
/// not administratively disabled. A disabled one renders no pppd peer/secret and
/// no MSS clamp, and — being absent from the desired set — is torn down by
/// [`apply_pppoe`] exactly like a removed interface.
fn is_active_pppoe(iface: &Interface) -> bool {
    iface.is_pppoe() && !iface.disabled
}

fn pppoe_peer_body(iface: &Interface) -> String {
    let p = iface
        .pppoe
        .as_ref()
        .expect("pppoe_peer_body on a non-pppoe interface");
    let parent = iface.parent.as_deref().unwrap_or_default();
    // PPPoE over 1500-byte Ethernet leaves 1492 after the 8-byte PPPoE header —
    // the classic default. An explicit `mtu` overrides; `mru` defaults to it.
    let mtu = iface.mtu.unwrap_or(1492);
    let mru = p.mru.unwrap_or(mtu);
    let mut body = format!("# rendered by sentinel — PPPoE client {}\n", iface.name);
    body.push_str(&format!("plugin pppoe.so\nnic-{parent}\n"));
    body.push_str(&format!("ifname {}\n", iface.name));
    body.push_str(&format!("user \"{}\"\n", p.username));
    body.push_str(&format!("mtu {mtu}\nmru {mru}\n"));
    if let Some(sn) = &p.service_name {
        body.push_str(&format!("rp_pppoe_service {sn}\n"));
    }
    if let Some(ac) = &p.ac_name {
        body.push_str(&format!("rp_pppoe_ac {ac}\n"));
    }
    // noipdefault: take our address from the peer (IPCP). noauth: don't require
    // the ISP to authenticate to us (we authenticate to it). LCP echoes detect a
    // dead session so `persist` re-dials.
    body.push_str(
        "noipdefault\ndefaultroute\npersist\nusepeerdns\nnoauth\nlcp-echo-interval 20\nlcp-echo-failure 3\n",
    );
    body
}

/// Render the shared PPPoE secrets file (`<user> * <password> *`, one line per
/// PPPoE interface). The same body is written to both the CHAP and PAP paths, so
/// whichever auth the ISP negotiates finds the credential. `None` when no PPPoE
/// interface is configured.
fn ppp_secrets_body(ifaces: &[Interface]) -> Option<String> {
    let ppp: Vec<&Interface> = ifaces.iter().filter(|i| is_active_pppoe(i)).collect();
    if ppp.is_empty() {
        return None;
    }
    let mut body =
        String::from("# rendered by sentinel — PPPoE credentials\n# client\tserver\tsecret\tIP\n");
    for i in ppp {
        if let Some(p) = &i.pppoe {
            body.push_str(&format!("\"{}\"\t*\t\"{}\"\t*\n", p.username, p.password));
        }
    }
    Some(body)
}

/// Render the nftables ruleset that clamps TCP MSS to the path MTU on every
/// PPPoE interface's egress — the `--clamp-mss-to-pmtu` equivalent, in the
/// `inet sentinel-mss` table so it never collides with any other firewall. The
/// leading `table`/`delete table` is the standard idempotent flush: re-loading
/// this file replaces our table wholesale, and with no PPPoE interface it just
/// removes it.
fn pppoe_mss_body(ifaces: &[Interface]) -> String {
    let ppp: Vec<&Interface> = ifaces.iter().filter(|i| is_active_pppoe(i)).collect();
    let mut body =
        String::from("# rendered by sentinel — PPPoE TCP MSS clamp (clamp-mss-to-pmtu)\n");
    body.push_str("table inet sentinel-mss\ndelete table inet sentinel-mss\n");
    if ppp.is_empty() {
        return body;
    }
    body.push_str("table inet sentinel-mss {\n\tchain clamp {\n");
    body.push_str("\t\ttype filter hook forward priority mangle; policy accept;\n");
    for i in &ppp {
        body.push_str(&format!(
            "\t\toifname \"{}\" tcp flags syn tcp option maxseg size set rt mtu\n",
            i.name
        ));
    }
    body.push_str("\t}\n}\n");
    body
}

/// Whether writing `body` to `path` would change what is already there (or the
/// file is absent) — the same change-detect the DNS/NTP drop-ins use.
fn file_changed(path: &Path, body: &str) -> bool {
    std::fs::read_to_string(path)
        .map(|c| c != body)
        .unwrap_or(true)
}

/// Reconcile the PPPoE clients to `appliance`: render each session's pppd peer
/// options + the shared secrets, load the MSS-clamp ruleset, and (re)start /
/// stop the `sentinel-pppoe@` instances — restarting only sessions whose
/// rendered config changed, so an unrelated commit never drops a live WAN link.
fn apply_pppoe(appliance: &Appliance) -> Result<()> {
    let ifaces = &appliance.interfaces;
    // Only *active* (enabled) PPPoE clients dial. A disabled interface is left out
    // of `desired` below, so the teardown loop stops+removes its session exactly
    // as it would for an interface deleted from the config.
    let ppp: Vec<&Interface> = ifaces.iter().filter(|i| is_active_pppoe(i)).collect();

    system::ensure_dir(Path::new(PPPOE_PEERS_DIR))?;

    // Peer-option files: write each wanted one, note which changed (→ restart).
    let mut desired: HashSet<String> = HashSet::new();
    let mut restart: HashSet<String> = HashSet::new();
    for i in &ppp {
        let path = Path::new(PPPOE_PEERS_DIR).join(&i.name);
        let body = pppoe_peer_body(i);
        if file_changed(&path, &body) {
            restart.insert(i.name.clone());
        }
        system::install_file(&path, &body)?;
        desired.insert(i.name.clone());
    }
    // Stop + remove sessions no longer configured.
    if let Ok(entries) = std::fs::read_dir(PPPOE_PEERS_DIR) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !desired.contains(&name) {
                if let Err(err) = system::pppoe_stop(&name) {
                    eprintln!("warning: stopping pppoe session {name}: {err}");
                }
                system::remove_file(&e.path())?;
            }
        }
    }

    // Credentials (CHAP + PAP). A change re-dials every session (any could use
    // the changed line). Removed when no PPPoE interface remains.
    match ppp_secrets_body(ifaces) {
        Some(body) => {
            let changed = file_changed(Path::new(PPP_CHAP_SECRETS), &body);
            system::install_ppp_secret(Path::new(PPP_CHAP_SECRETS), &body)?;
            system::install_ppp_secret(Path::new(PPP_PAP_SECRETS), &body)?;
            if changed {
                restart.extend(ppp.iter().map(|i| i.name.clone()));
            }
        }
        None => {
            system::remove_file(Path::new(PPP_CHAP_SECRETS))?;
            system::remove_file(Path::new(PPP_PAP_SECRETS))?;
        }
    }

    // MSS clamp: render + load. Load when the ruleset changed, or whenever any
    // PPPoE interface exists (so a fresh boot re-asserts the kernel table even
    // if the file on tmpfs happens to match).
    let mss_body = pppoe_mss_body(ifaces);
    let mss_changed = file_changed(Path::new(PPPOE_MSS_NFT), &mss_body);
    system::ensure_dir(Path::new(PPPOE_RUNTIME_DIR))?;
    system::install_file(Path::new(PPPOE_MSS_NFT), &mss_body)?;
    if mss_changed || !ppp.is_empty() {
        if let Err(e) = system::nft_load(Path::new(PPPOE_MSS_NFT)) {
            eprintln!("warning: loading PPPoE MSS-clamp nftables ruleset failed: {e}");
        }
    }

    // (Re)start the changed/new sessions.
    for name in &restart {
        if let Err(e) = system::pppoe_restart(name) {
            eprintln!(
                "warning: (re)starting pppoe session {name} failed (applies on next start): {e}"
            );
        }
    }
    Ok(())
}

// --- QoS / traffic shaping (roadmap C8) ------------------------------------
//
// A `[interface.qos]` block attaches a root egress qdisc — `cake` (a combined
// shaper + AQM that kills bufferbloat on a WAN uplink with one `bandwidth` knob)
// or `fq_codel` (a pure flow-queuing AQM). Unlike addressing (networkd) this is
// applied directly with `tc`, so it takes effect the instant a commit lands and
// is re-asserted each boot. Each shaped interface's rendered qdisc spec is
// stamped under `/run/sentinel/qos/<name>`; we only (re)run `tc` when that spec
// changed, so an unrelated commit never disturbs a live queue.

/// Runtime dir of per-interface qdisc-spec stamps (tmpfs; re-seeded each boot).
const QOS_RUNTIME_DIR: &str = "/run/sentinel/qos";

/// Build the `tc qdisc` argument vector for a QoS block — everything AFTER
/// `tc qdisc replace dev <name> root`. The field order is fixed so the joined
/// spec is a canonical change-detect stamp.
fn qos_qdisc_args(qos: &Qos) -> Vec<String> {
    let mut a: Vec<String> = Vec::new();
    match qos.discipline {
        QosDiscipline::Cake => {
            a.push("cake".into());
            // CAKE always takes a shaping rate; absent ⇒ `unlimited` (AQM only).
            match &qos.bandwidth {
                Some(bw) => {
                    a.push("bandwidth".into());
                    a.push(bw.clone());
                }
                None => a.push("unlimited".into()),
            }
            // A CAKE RTT preset (`internet`, `lan`, …) is a bare keyword; an
            // explicit time is given as `rtt <time>`.
            if let Some(rtt) = &qos.rtt {
                if crate::config::CAKE_RTT_KEYWORDS.contains(&rtt.as_str()) {
                    a.push(rtt.clone());
                } else {
                    a.push("rtt".into());
                    a.push(rtt.clone());
                }
            }
            // diffserv mode is a standalone keyword (`diffserv4`, `besteffort`, …).
            if let Some(ds) = &qos.diffserv {
                a.push(ds.clone());
            }
            if qos.nat {
                a.push("nat".into());
            }
            if qos.ack_filter {
                a.push("ack-filter".into());
            }
        }
        QosDiscipline::FqCodel => {
            a.push("fq_codel".into());
            if let Some(t) = &qos.target {
                a.push("target".into());
                a.push(t.clone());
            }
            if let Some(i) = &qos.interval {
                a.push("interval".into());
                a.push(i.clone());
            }
            if let Some(l) = qos.limit {
                a.push("limit".into());
                a.push(l.to_string());
            }
        }
    }
    a
}

/// Reconcile per-interface QoS to `appliance`: attach/refresh a root qdisc on
/// each shaped interface (only when its spec changed) and strip shaping from any
/// interface that no longer declares it. All `tc` calls are best-effort — a
/// device that isn't up yet (a PPPoE `ppp0`, a late VLAN) re-applies on the next
/// commit/boot rather than failing the whole reconcile.
fn apply_qos(appliance: &Appliance) -> Result<()> {
    let shaped: Vec<&Interface> = appliance
        .interfaces
        .iter()
        .filter(|i| i.qos.is_some())
        .collect();
    system::ensure_dir(Path::new(QOS_RUNTIME_DIR))?;

    let mut desired: HashSet<String> = HashSet::new();
    for i in &shaped {
        let qos = i.qos.as_ref().expect("filtered to qos-carrying interfaces");
        let args = qos_qdisc_args(qos);
        let spec = args.join(" ");
        let path = Path::new(QOS_RUNTIME_DIR).join(&i.name);
        if file_changed(&path, &spec) {
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            if let Err(e) = system::tc_qdisc_replace(&i.name, &refs) {
                eprintln!(
                    "warning: applying qos on {} failed (applies on next commit/boot): {e}",
                    i.name
                );
            }
        }
        system::install_file(&path, &spec)?;
        desired.insert(i.name.clone());
    }
    // Strip shaping from interfaces that no longer declare qos.
    if let Ok(entries) = std::fs::read_dir(QOS_RUNTIME_DIR) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !desired.contains(&name) {
                if let Err(err) = system::tc_qdisc_del(&name) {
                    eprintln!("warning: clearing qos on {name}: {err}");
                }
                system::remove_file(&e.path())?;
            }
        }
    }
    Ok(())
}

// --- Multi-WAN (roadmap C6) ------------------------------------------------
//
// Several WAN uplinks reconciled into failover or load-balancing with per-uplink
// health checks and policy-based routing — the VyOS `wan-load-balance` model.
// Each uplink owns a routing table (a default route via its gateway); a small
// rendered daemon pings every uplink's targets and programs the `main`-table
// default from the healthy uplinks (the lowest-`priority` one in failover, a
// weighted multipath across all of them in load-balance). Sentinel renders the
// daemon shell script + a change-detect stamp and (re)starts the
// `sentinel-multiwan` unit only when the rendered config changed; when no uplink
// is configured it stops the daemon and flushes the tables it owned. The tables
// managed on the last apply are recorded so a later teardown can flush them.

/// Runtime dir for the Multi-WAN daemon script + state (tmpfs; re-seeded each
/// boot from the saved config, like the other render artifacts).
const MULTIWAN_RUNTIME_DIR: &str = "/run/sentinel/multiwan";
/// The rendered health-check + failover daemon (run by `sentinel-multiwan`).
const MULTIWAN_SCRIPT: &str = "/run/sentinel/multiwan/health.sh";
/// The routing-table ids the daemon owns on the current apply — read on the next
/// reconcile so a removed uplink's table can be flushed.
const MULTIWAN_TABLES: &str = "/run/sentinel/multiwan/tables";

/// A shell-quoted single-token value: only the charset our validators already
/// allow (IPv4 / interface names) reaches here, so plain double-quotes suffice
/// and there is nothing to escape — but quote anyway so an empty gateway can't
/// splice the array.
fn shq(s: &str) -> String {
    format!("\"{s}\"")
}

/// Render the Multi-WAN health-check + failover daemon for `mw`. The script sets
/// up each uplink's routing table + a source-based `ip rule`, then loops probing
/// the uplinks and reprogramming the `main` default route on any up/down change.
/// The per-uplink parameters are unrolled into parallel bash arrays; the control
/// logic below them is fixed. `None` when no uplink is configured.
fn multiwan_script_body(mw: &MultiWan) -> Option<String> {
    if mw.uplinks.is_empty() {
        return None;
    }
    // Per-uplink parallel arrays, in configuration order.
    let mut ifs = Vec::new();
    let mut gws = Vec::new();
    let mut tbs = Vec::new();
    let mut wts = Vec::new();
    let mut prs = Vec::new();
    let mut tgts = Vec::new();
    let mut tmos = Vec::new();
    let mut failn = Vec::new();
    let mut risen = Vec::new();
    let mut ivs = Vec::new();
    for (idx, u) in mw.uplinks.iter().enumerate() {
        ifs.push(shq(&u.interface));
        // A `dhcp` (or unset) gateway is resolved at runtime from the link's
        // learned default route; an empty token signals that to the daemon.
        let gw = match u.gateway.as_deref() {
            Some("dhcp") | None => "",
            Some(g) => g,
        };
        gws.push(shq(gw));
        tbs.push(mw.table_for(idx, u).to_string());
        wts.push(u.weight.unwrap_or(1).to_string());
        // Default priority follows configuration order (10, 20, …) so uplinks
        // fail over in the order declared unless overridden.
        prs.push(u.priority.unwrap_or((idx as u32 + 1) * 10).to_string());
        tgts.push(shq(&u.check.targets.join(" ")));
        tmos.push(u.check.timeout.unwrap_or(WAN_CHECK_TIMEOUT).to_string());
        failn.push(u.check.fail.unwrap_or(WAN_CHECK_FAIL).to_string());
        risen.push(u.check.rise.unwrap_or(WAN_CHECK_RISE).to_string());
        // Each uplink keeps its OWN probe interval — the daemon schedules each on
        // its own cadence (see MULTIWAN_LOGIC), so a slow uplink is not dragged to
        // a fast neighbour's rate (nor the reverse).
        ivs.push(u.check.interval.unwrap_or(WAN_CHECK_INTERVAL).to_string());
    }
    let mode = match mw.mode {
        WanMode::Failover => "failover",
        WanMode::LoadBalance => "load-balance",
    };

    let mut s = String::new();
    s.push_str("#!/usr/bin/env bash\n");
    s.push_str("# rendered by sentinel — Multi-WAN health check + failover (roadmap C6)\n");
    s.push_str("set -u\n");
    s.push_str(&format!("MODE={}\n", shq(mode)));
    s.push_str(&format!("IF=({})\n", ifs.join(" ")));
    s.push_str(&format!("GW=({})\n", gws.join(" ")));
    s.push_str(&format!("TB=({})\n", tbs.join(" ")));
    s.push_str(&format!("WT=({})\n", wts.join(" ")));
    s.push_str(&format!("PR=({})\n", prs.join(" ")));
    s.push_str(&format!("TGT=({})\n", tgts.join(" ")));
    s.push_str(&format!("TMO=({})\n", tmos.join(" ")));
    s.push_str(&format!("FAILN=({})\n", failn.join(" ")));
    s.push_str(&format!("RISEN=({})\n", risen.join(" ")));
    s.push_str(&format!("IV=({})\n", ivs.join(" ")));
    // The fixed control logic. Kept as a raw block so the daemon reads clearly;
    // every dynamic value is already baked into the arrays above.
    s.push_str(MULTIWAN_LOGIC);
    Some(s)
}

/// The Multi-WAN daemon's fixed logic, appended after the per-uplink arrays.
/// `gw_of` resolves a runtime (DHCP) gateway from the link's learned default
/// route; `setup` programs each uplink's table + a source `ip rule`; `apply`
/// rebuilds the `main` default from the healthy uplinks; the loop probes and
/// reprograms on any state change.
const MULTIWAN_LOGIC: &str = r#"
N=${#IF[@]}
declare -a UP FAILC RISEC NEXT
now=$(date +%s)
# NEXT[i] is the epoch second uplink i is next due to be probed; seeding it to
# `now` makes every uplink due on the first pass, then each reschedules itself
# IV[i] seconds ahead — so each uplink is probed strictly on its own interval.
for ((i=0;i<N;i++)); do UP[i]=1; FAILC[i]=0; RISEC[i]=0; NEXT[i]=$now; done

gw_of() { # echo the gateway for uplink $1 (static, or learned from the link)
  local i=$1
  if [ -n "${GW[i]}" ]; then echo "${GW[i]}"; return; fi
  ip -4 route show default dev "${IF[i]}" 2>/dev/null | awk '/via/{print $3; exit}'
}

setup() {
  for ((i=0;i<N;i++)); do
    local gw src
    gw=$(gw_of "$i")
    if [ -n "$gw" ]; then
      ip route replace default via "$gw" dev "${IF[i]}" table "${TB[i]}" 2>/dev/null || true
    fi
    # Source-based PBR: traffic from this uplink's own address egresses via its
    # table, so a reply to an inbound connection returns out the same uplink.
    src=$(ip -4 -o addr show dev "${IF[i]}" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)
    if [ -n "$src" ]; then
      ip rule del from "$src" lookup "${TB[i]}" 2>/dev/null || true
      ip rule add from "$src" lookup "${TB[i]}" priority $((1000 + i)) 2>/dev/null || true
    fi
  done
}

check() { # $1 = uplink index; 0 = healthy
  local i=$1 t
  [ -z "${TGT[i]}" ] && return 0   # no targets ⇒ link-state only, assume up
  for t in ${TGT[i]}; do
    ping -I "${IF[i]}" -c1 -W "${TMO[i]}" "$t" >/dev/null 2>&1 && return 0
  done
  return 1
}

apply() {
  if [ "$MODE" = "load-balance" ]; then
    local args=() gw
    for ((i=0;i<N;i++)); do
      [ "${UP[i]}" = 1 ] || continue
      gw=$(gw_of "$i"); [ -n "$gw" ] || continue
      args+=(nexthop via "$gw" dev "${IF[i]}" weight "${WT[i]}")
    done
    if [ ${#args[@]} -gt 0 ]; then ip route replace default "${args[@]}" 2>/dev/null || true; fi
  else
    local best=-1 bestpr=2147483647 gw
    for ((i=0;i<N;i++)); do
      [ "${UP[i]}" = 1 ] || continue
      if [ "${PR[i]}" -lt "$bestpr" ]; then best=$i; bestpr=${PR[i]}; fi
    done
    if [ "$best" -ge 0 ]; then
      gw=$(gw_of "$best")
      if [ -n "$gw" ]; then
        ip route replace default via "$gw" dev "${IF[best]}" 2>/dev/null || true
      fi
      echo "$best" > /run/sentinel/multiwan/active 2>/dev/null || true
    fi
  fi
}

setup
apply
while true; do
  # Re-assert each uplink's table + source rule every tick: idempotent (`route
  # replace` / `rule del`+`add`), so this self-heals an uplink whose address
  # appears after the daemon starts, without ever blipping a live table.
  setup
  now=$(date +%s)
  changed=0
  for ((i=0;i<N;i++)); do
    # Skip uplinks not yet due; each one probes only every IV[i] seconds, so its
    # fail/rise counters advance at its own cadence.
    [ "$now" -lt "${NEXT[i]}" ] && continue
    NEXT[i]=$(( now + IV[i] ))
    if check "$i"; then
      RISEC[i]=$(( RISEC[i] + 1 )); FAILC[i]=0
      if [ "${UP[i]}" = 0 ] && [ "${RISEC[i]}" -ge "${RISEN[i]}" ]; then UP[i]=1; changed=1; fi
    else
      FAILC[i]=$(( FAILC[i] + 1 )); RISEC[i]=0
      if [ "${UP[i]}" = 1 ] && [ "${FAILC[i]}" -ge "${FAILN[i]}" ]; then UP[i]=0; changed=1; fi
    fi
  done
  [ "$changed" = 1 ] && apply
  # Sleep only until the soonest uplink is next due — no fixed tick, so distinct
  # per-uplink intervals are each honoured without busy-looping.
  nxt=${NEXT[0]}
  for ((i=1;i<N;i++)); do [ "${NEXT[i]}" -lt "$nxt" ] && nxt=${NEXT[i]}; done
  s=$(( nxt - $(date +%s) ))
  [ "$s" -lt 1 ] && s=1
  sleep "$s"
done
"#;

/// Reconcile the Multi-WAN daemon to `appliance.multiwan`: render the health
/// script + record the tables it owns, then (re)start `sentinel-multiwan` when
/// the script changed. When no uplink is configured, stop the daemon and flush
/// any routing tables a previous apply owned (so a removed uplink leaves no stale
/// policy route). Restarts are gated on a real change, so an unrelated commit
/// never disturbs a live failover daemon.
fn apply_multiwan(appliance: &Appliance) -> Result<()> {
    let mw = &appliance.multiwan;
    system::ensure_dir(Path::new(MULTIWAN_RUNTIME_DIR))?;
    let tables_path = Path::new(MULTIWAN_TABLES);
    let script_path = Path::new(MULTIWAN_SCRIPT);

    match multiwan_script_body(mw) {
        Some(body) => {
            let changed = file_changed(script_path, &body);
            system::install_file(script_path, &body)?;
            // Record the tables we own (newline-separated) for a future teardown.
            let tables: Vec<String> = mw
                .uplinks
                .iter()
                .enumerate()
                .map(|(idx, u)| mw.table_for(idx, u).to_string())
                .collect();
            system::install_file(tables_path, &format!("{}\n", tables.join("\n")))?;
            if changed {
                if let Err(e) = system::multiwan_restart() {
                    eprintln!(
                        "warning: (re)starting the multiwan daemon failed (applies on next start): {e}"
                    );
                }
            }
        }
        None => {
            // No uplink configured: stop the daemon and flush the tables it owned
            // (recorded on the last apply), then drop the runtime artifacts.
            if script_path.exists() {
                if let Err(e) = system::multiwan_stop() {
                    eprintln!("warning: stopping the multiwan daemon: {e}");
                }
            }
            if let Ok(list) = std::fs::read_to_string(tables_path) {
                for t in list.split_whitespace() {
                    if let Ok(table) = t.parse::<u32>() {
                        if let Err(e) = system::ip_route_flush_table(table) {
                            eprintln!("warning: flushing multiwan table {table}: {e}");
                        }
                    }
                }
            }
            system::remove_file(script_path)?;
            system::remove_file(tables_path)?;
            system::remove_file(&Path::new(MULTIWAN_RUNTIME_DIR).join("active"))?;
        }
    }
    Ok(())
}

/// Render the persistent network config: write a `.netdev` for every VLAN
/// subinterface and a `.network` for every interface that needs one (it has an
/// address, is a VLAN, or is a parent carrying VLANs), remove any stale sentinel
/// units, then reconcile the always-on co-services (resolved / dnsmasq / chrony)
/// by writing their drop-ins. In `ApplyMode::Boot` this is ALL it does — pure
/// file rendering, zero unit operations — so it is safe for the early
/// `sentinel-boot` unit ordered Before networkd (every service it would poke is
/// ordered after the network, so poking one deadlocks the boot; the services read
/// the freshly written files on their own start). In `ApplyMode::Live` (`commit`,
/// networkd already up) it additionally reloads networkd and restarts the changed
/// co-services so the change lands immediately. The link-dependent runtime state
/// (incl. PPPoE) is deferred to [`apply_link_runtime`].
pub fn apply_persistent(appliance: &Appliance, mode: ApplyMode) -> Result<()> {
    let ifaces = &appliance.interfaces;

    // A PPPoE client's raw uplink NIC (`parent`) must be link-up for pppd's
    // discovery to run, but carries no address itself — so it still needs a bare
    // networkd `.network` to be managed/brought up.
    let pppoe_parents: HashSet<&str> = ifaces
        .iter()
        .filter(|i| i.is_pppoe())
        .filter_map(|i| i.parent.as_deref())
        .collect();

    // Map each parent interface to the VLAN child links riding on it.
    let mut children: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for i in ifaces {
        if let (Some(parent), Some(_)) = (&i.parent, i.vlan) {
            children
                .entry(parent.as_str())
                .or_default()
                .push(i.name.clone());
        }
    }

    // Map each parent NIC to the MACVLAN pseudo-interfaces riding on it — the
    // MACVLAN counterpart of the VLAN `children` map (roadmap C14). A macvlan's
    // `parent` names its host NIC, whose `.network` gains a `MACVLAN=` per child.
    let mut macvlan_children: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for i in ifaces {
        if i.is_macvlan() {
            if let Some(parent) = &i.parent {
                macvlan_children
                    .entry(parent.as_str())
                    .or_default()
                    .push(i.name.clone());
            }
        }
    }

    // Map each member NIC to its owning bridge/bond device (name + whether it is a
    // bond), derived from every device's `member` list — the inverse of the old
    // per-member `master`. A member's `.network` gets `Bridge=`/`Bond=` from this.
    let mut master_of: BTreeMap<&str, (&str, bool)> = BTreeMap::new();
    for dev in ifaces {
        if dev.is_virtual_l2() {
            for m in &dev.members {
                master_of.insert(m.as_str(), (dev.name.as_str(), dev.is_bond()));
            }
        }
    }

    // Index the WireGuard tunnels by interface name so a `type = "wireguard"`
    // interface's `.netdev` can pull its keys + peers from `[[vpn.wireguard]]`.
    let wg_by_name: BTreeMap<&str, &WireguardTunnel> = appliance
        .vpn
        .wireguard
        .iter()
        .map(|t| (t.name.as_str(), t))
        .collect();

    system::ensure_dir(Path::new(NETWORKD_RUNTIME_DIR))?;

    let mut keep: HashSet<String> = HashSet::new();
    let mut writes: Vec<(String, String)> = Vec::new();
    // Files that carry a secret (a WireGuard private key): 0640 root:systemd-network.
    let mut secrets: HashSet<String> = HashSet::new();

    // VLAN .netdev units. `vlan_protocol` selects the tag TPID (802.1q default /
    // 802.1ad S-VLAN); a VLAN whose parent is itself a VLAN stacks (QinQ).
    for i in ifaces {
        if let (Some(_), Some(vlan)) = (&i.parent, i.vlan) {
            let name = netdev_name(&i.name);
            let body = netdev_body(&i.name, vlan, i.vlan_protocol.as_deref());
            writes.push((name.clone(), body));
            keep.insert(name);
        }
    }

    // MACVLAN .netdev units (roadmap C14): a pseudo-NIC with its own MAC on a
    // parent link. The parent's `.network` references it via `MACVLAN=` below.
    for i in ifaces {
        if i.is_macvlan() {
            let name = netdev_name(&i.name);
            writes.push((name.clone(), macvlan_netdev_body(i)));
            keep.insert(name);
        }
    }

    // WireGuard .netdev units (secret — the private key lives here → 0640). The
    // crypto comes from the matching `[[vpn.wireguard]]` tunnel; validation
    // guarantees one exists for every `type = "wireguard"` interface.
    for i in ifaces {
        if i.is_wireguard() {
            let Some(tunnel) = wg_by_name.get(i.name.as_str()) else {
                continue;
            };
            let name = netdev_name(&i.name);
            writes.push((name.clone(), wireguard_netdev_body(&i.name, tunnel)));
            secrets.insert(name.clone());
            keep.insert(name);
        }
    }

    // Bridge / bond .netdev units (virtual L2 devices this box synthesises).
    for i in ifaces {
        if i.is_virtual_l2() {
            let name = netdev_name(&i.name);
            writes.push((name.clone(), virtual_l2_netdev_body(i)));
            keep.insert(name);
        }
    }

    // Kernel tunnel .netdev units (GRE / IPIP / GRETAP point-to-point, roadmap C3).
    for i in ifaces {
        if i.is_tunnel() {
            let name = netdev_name(&i.name);
            writes.push((name.clone(), tunnel_netdev_body(i)));
            keep.insert(name);
        }
    }

    // .network units: anything with an address, a VLAN of its own, child VLANs,
    // a WireGuard link (which needs a `.network` to be brought up even when it
    // carries only AllowedIPs routes and no local address), a bridge/bond device,
    // or a member enslaved to one.
    let reloaded: Vec<String> = ifaces
        .iter()
        .filter(|i| {
            // A PPPoE client (ppp0) is owned by pppd, not networkd — never render
            // a unit for it (even if it carries an `mtu`).
            !i.is_pppoe()
                && (i.address.is_some()
                    || i.address6.is_some()
                    || (i.parent.is_some() && i.vlan.is_some())
                    || i.is_wireguard()
                    || i.router_advert.is_some()
                    || i.is_virtual_l2()
                    || i.is_tunnel()
                    || i.is_macvlan()
                    || macvlan_children.contains_key(i.name.as_str())
                    || master_of.contains_key(i.name.as_str())
                    || !i.vlan_tagged.is_empty()
                    || i.vlan_untagged.is_some()
                    || i.pd_from.is_some()
                    || i.mtu.is_some()
                    || i.mac.is_some()
                    || i.qos.is_some()
                    || i.disabled
                    || children.contains_key(i.name.as_str())
                    || pppoe_parents.contains(i.name.as_str()))
        })
        .map(|i| {
            let kids = children
                .get(i.name.as_str())
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let mv_kids = macvlan_children
                .get(i.name.as_str())
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            // Resolve this interface's bridge/bond membership (derived from the
            // owning device's `member` list) to the networkd directive.
            let master = master_of.get(i.name.as_str()).map(|(dev, is_bond)| {
                if *is_bond {
                    format!("Bond={dev}")
                } else {
                    format!("Bridge={dev}")
                }
            });
            let pd = i
                .pd_from
                .as_deref()
                .map(|up| (up, i.pd_subnet.unwrap_or(0)));
            let name = network_name(&i.name);
            let mut body = network_body(
                &i.name,
                i.address.as_deref(),
                i.address6.as_deref(),
                kids,
                mv_kids,
                i.dhcp_server.as_ref(),
                i.router_advert.as_ref(),
                master.as_deref(),
                pd,
                i.mtu,
                i.mac.as_deref(),
                i.description.as_deref(),
                i.disabled,
            );
            // 802.1Q port membership on a VLAN-aware bridge (appended as its own
            // [BridgeVLAN] section; empty for a non-filtering port).
            body.push_str(&bridge_vlan_body(&i.vlan_tagged, i.vlan_untagged));
            writes.push((name.clone(), body));
            keep.insert(name);
            i.name.clone()
        })
        .collect();

    // Remove sentinel units (either kind) no longer wanted.
    if let Ok(entries) = std::fs::read_dir(NETWORKD_RUNTIME_DIR) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let ours = name.starts_with(PREFIX)
                && (name.ends_with(".network") || name.ends_with(".netdev"));
            if ours && !keep.contains(&name) {
                system::remove_file(&entry.path())?;
            }
        }
    }

    // Write the wanted units. A WireGuard `.netdev` embeds the private key, so
    // it is installed 0640 root:systemd-network (readable by networkd, not by
    // ordinary users); everything else stays the default 0644.
    for (name, body) in &writes {
        let path = Path::new(NETWORKD_RUNTIME_DIR).join(name);
        if secrets.contains(name) {
            system::install_secret_file(&path, body)?;
        } else {
            system::install_file(&path, body)?;
        }
    }

    // Live only: ask networkd to re-read the units. At boot we DON'T — networkd
    // reads them on its own start, and a `networkctl reload` here would D-Bus-
    // activate networkd out of order (sentinel-boot is Before networkd) and
    // deadlock the boot.
    if mode == ApplyMode::Live {
        if let Err(e) = system::networkctl_reload(&reloaded) {
            eprintln!("warning: networkctl reload failed (networkd applies units on start): {e}");
        }
    }

    // DNS: resolved is the box's own forwarder (`[services.dns] upstream`),
    // dnsmasq is the LAN resolver (`serve-on` + host-overrides + blocklists).
    // Both track `[services.dns]` and (in Live mode) restart only when changed.
    apply_resolved(appliance, mode)?;
    apply_dnsmasq(appliance, mode)?;
    // The NTP server (chrony) likewise — its confdir drop-in tracks
    // `[services.ntp]`, and chrony is restarted only when that changed.
    apply_chrony(appliance, mode)?;
    // PKI (roadmap C19): the ACME descriptor renders in both modes; CA/leaf key
    // material is minted on a live commit only (idempotent, link-independent).
    crate::pki::apply(appliance, mode)?;
    Ok(())
}

/// Live runtime state that only exists once networkd has brought the links up:
/// the PPPoE sessions (pppd needs the parent NIC up), the tc egress qdiscs (QoS),
/// the Multi-WAN policy routes/tables, and the IPsec SAs loaded into charon. None
/// of it survives a reboot — the kernel comes up with a bare qdisc, no policy
/// routes and an empty charon — and none of it can be applied before its target
/// links exist (and starting a session/daemon from the early, Before-networkd
/// `sentinel-boot` would deadlock the boot). So `commit` runs it inline (the links
/// are already up), while at boot the dedicated `sentinel-boot-late` unit (ordered
/// after systemd-networkd) re-applies it.
pub fn apply_link_runtime(appliance: &Appliance) -> Result<()> {
    // PPPoE clients (pppd peer options + secrets + the MSS-clamp ruleset). This
    // *starts* the `sentinel-pppoe@` sessions, so it belongs after networkd (the
    // pppd discovery needs the parent NIC up) and out of the early sentinel-boot:
    // that unit is ordered Before networkd, and starting a session there — the
    // pppoe unit is After sentinel-boot — would deadlock the boot. The parent
    // NIC's own `.network` unit is still written by apply_persistent above.
    apply_pppoe(appliance)?;
    // Egress traffic shaping (tc qdiscs) — applied directly, after the links are
    // (re)configured so the target devices exist.
    apply_qos(appliance)?;
    // Multi-WAN failover daemon (roadmap C6) — rendered + (re)started last, after
    // the uplinks it steers are addressed/up.
    apply_multiwan(appliance)?;
    // IPsec tunnels (roadmap C2) — rendered swanctl config loaded into charon,
    // after the underlay uplinks the tunnels ride on are up.
    crate::ipsec::apply(appliance)?;
    // OpenConnect road-warrior VPN (roadmap C17) — rendered ocserv.conf + 0600
    // ocpasswd, then the ocserv unit (re)started, after the WAN the server binds
    // is up and after the PKI leaf it serves was minted by apply_persistent.
    crate::openconnect::apply(appliance)?;
    // L7 reverse proxy / load balancer (roadmap C22) — rendered haproxy.cfg +
    // per-frontend TLS bundles, then the haproxy unit (re)started, after the WAN
    // it binds is up and after the PKI leaf it terminates with was minted by
    // apply_persistent.
    crate::proxy::apply(appliance)?;
    // Box services (roadmap C18) — LLDP/SNMP/mDNS/dyndns/DHCP-relay, each a
    // Sentinel-owned daemon (re)started after networkd so the link-scoped ones
    // (LLDP/mDNS/relay) see their interfaces up.
    apply_box_services(appliance)?;
    // NAT64 + DNS64 (roadmap C10) — tayga's tun/routes need the up links, and the
    // DNS64 unbound binds the serving interface's address, so reconcile them here
    // (after networkd) too.
    apply_nat64(appliance)?;
    Ok(())
}

/// Apply the full network config to the running system: the persistent render
/// (networkd units + co-services) followed by the link-dependent runtime state.
/// Used by `commit`, where the links are already up so both phases run back to
/// back. The boot path splits them across two units (see [`apply_persistent`]
/// and [`apply_link_runtime`]) so the runtime state lands after networkd.
pub fn apply(appliance: &Appliance) -> Result<()> {
    apply_persistent(appliance, ApplyMode::Live)?;
    apply_link_runtime(appliance)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DhcpStaticLease, Pppoe, Qos, QosDiscipline};

    #[test]
    fn qos_qdisc_args_renders_cake_and_fq_codel() {
        // CAKE with the full knob set — order is fixed (canonical stamp).
        let cake = Qos {
            discipline: QosDiscipline::Cake,
            bandwidth: Some("100mbit".into()),
            rtt: Some("internet".into()),
            nat: true,
            ack_filter: true,
            diffserv: Some("diffserv4".into()),
            target: None,
            interval: None,
            limit: None,
        };
        assert_eq!(
            qos_qdisc_args(&cake).join(" "),
            "cake bandwidth 100mbit internet diffserv4 nat ack-filter"
        );

        // An explicit RTT time is prefixed with `rtt` (vs a bare preset keyword).
        let explicit = Qos {
            rtt: Some("50ms".into()),
            ..cake.clone()
        };
        assert_eq!(
            qos_qdisc_args(&explicit).join(" "),
            "cake bandwidth 100mbit rtt 50ms diffserv4 nat ack-filter"
        );

        // CAKE with no bandwidth ⇒ `unlimited` (AQM only, no shaper).
        let bare = Qos {
            discipline: QosDiscipline::Cake,
            bandwidth: None,
            rtt: None,
            nat: false,
            ack_filter: false,
            diffserv: None,
            target: None,
            interval: None,
            limit: None,
        };
        assert_eq!(qos_qdisc_args(&bare).join(" "), "cake unlimited");

        // fq_codel with its own knobs.
        let fq = Qos {
            discipline: QosDiscipline::FqCodel,
            bandwidth: None,
            rtt: None,
            nat: false,
            ack_filter: false,
            diffserv: None,
            target: Some("5ms".into()),
            interval: Some("100ms".into()),
            limit: Some(1200),
        };
        assert_eq!(
            qos_qdisc_args(&fq).join(" "),
            "fq_codel target 5ms interval 100ms limit 1200"
        );
    }

    #[test]
    fn static_address_renders_address_directive() {
        let u = network_body(
            "eth0",
            Some("10.0.0.1/24"),
            None,
            &[],
            &[],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(u.contains("Name=eth0"));
        assert!(u.contains("Address=10.0.0.1/24"));
    }

    #[test]
    fn dhcp_address_renders_dhcp_directive() {
        let u = network_body(
            "eth0",
            Some("dhcp"),
            None,
            &[],
            &[],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(u.contains("DHCP=yes"));
        assert!(!u.contains("Address="));
    }

    #[test]
    fn vlan_netdev_declares_kind_and_id() {
        let d = netdev_body("eth1.20", 20, None);
        assert!(d.contains("Name=eth1.20"));
        assert!(d.contains("Kind=vlan"));
        assert!(d.contains("Id=20"));
        // A plain (802.1q) VLAN renders no Protocol= line.
        assert!(!d.contains("Protocol="));
        assert_eq!(netdev_name("eth1.20"), "10-sentinel-eth1.20.netdev");

        // An 802.1ad S-VLAN adds Protocol=802.1ad; explicit 802.1q stays bare.
        let sv = netdev_body("eth1.100", 100, Some("802.1ad"));
        assert!(sv.contains("Protocol=802.1ad"), "{sv}");
        let cv = netdev_body("eth1.30", 30, Some("802.1q"));
        assert!(!cv.contains("Protocol="), "{cv}");
    }

    #[test]
    fn macvlan_netdev_declares_kind_and_mode() {
        // A macvlan renders Kind=macvlan + [MACVLAN] Mode=; the mode defaults to
        // bridge when unset (roadmap C14).
        let mv = Interface {
            name: "mv0".into(),
            zone: Some("lan".into()),
            address: Some("10.9.0.2/24".into()),
            address6: None,
            parent: Some("eth1".into()),
            vlan: None,
            vlan_protocol: None,
            macvlan_mode: Some("bridge".into()),
            dhcp_server: None,
            router_advert: None,
            if_type: Some(IfaceType::Macvlan),
            members: vec![],
            vlan_aware: None,
            vlan_tagged: vec![],
            vlan_untagged: None,
            bond_mode: None,
            pd_from: None,
            pd_subnet: None,
            mtu: None,
            mac: None,
            local: None,
            remote: None,
            tunnel_key: None,
            ttl: None,
            qos: None,
            pppoe: None,
            description: None,
            disabled: false,
        };
        let d = macvlan_netdev_body(&mv);
        assert!(d.contains("Name=mv0"), "{d}");
        assert!(d.contains("Kind=macvlan"), "{d}");
        assert!(d.contains("Mode=bridge"), "{d}");

        // An unset mode still defaults to bridge.
        let mv2 = Interface {
            macvlan_mode: None,
            ..mv.clone()
        };
        assert!(macvlan_netdev_body(&mv2).contains("Mode=bridge"));

        // A vepa mode is rendered verbatim.
        let mv3 = Interface {
            macvlan_mode: Some("vepa".into()),
            ..mv.clone()
        };
        assert!(macvlan_netdev_body(&mv3).contains("Mode=vepa"));
    }

    #[test]
    fn parent_network_references_macvlan_children() {
        // The parent NIC's .network lists each macvlan riding on it via MACVLAN=,
        // mirroring how VLAN children get VLAN= (roadmap C14).
        let u = network_body(
            "eth1",
            Some("10.0.0.1/24"),
            None,
            &[],
            &["mv0".into(), "mv1".into()],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(u.contains("MACVLAN=mv0"), "{u}");
        assert!(u.contains("MACVLAN=mv1"), "{u}");
    }

    #[test]
    fn tunnel_netdev_renders_kind_endpoints_key_and_ttl() {
        // A keyed GRE tunnel emits Kind=gre + a [Tunnel] with Local/Remote/Key/TTL
        // and Independent=yes (a standalone device from its endpoint addresses).
        let gre = Interface {
            name: "gre0".into(),
            zone: Some("vpn".into()),
            address: Some("172.16.0.1/30".into()),
            address6: None,
            parent: None,
            vlan: None,
            vlan_protocol: None,
            macvlan_mode: None,
            dhcp_server: None,
            router_advert: None,
            if_type: Some(IfaceType::Gre),
            members: vec![],
            vlan_aware: None,
            vlan_tagged: vec![],
            vlan_untagged: None,
            bond_mode: None,
            pd_from: None,
            pd_subnet: None,
            mtu: None,
            mac: None,
            local: Some("10.0.0.1".into()),
            remote: Some("10.0.0.2".into()),
            tunnel_key: Some(42),
            ttl: Some(64),
            qos: None,
            pppoe: None,
            description: None,
            disabled: false,
        };
        let d = tunnel_netdev_body(&gre);
        assert!(d.contains("Name=gre0"), "{d}");
        assert!(d.contains("Kind=gre"), "{d}");
        assert!(d.contains("Local=10.0.0.1"), "{d}");
        assert!(d.contains("Remote=10.0.0.2"), "{d}");
        assert!(d.contains("Key=42"), "{d}");
        assert!(d.contains("TTL=64"), "{d}");
        assert!(d.contains("Independent=yes"), "{d}");

        // IPIP carries no key: the same struct rendered as ipip drops Key= even if
        // one is set (validation forbids it upstream; the renderer is defensive).
        let ipip = Interface {
            if_type: Some(IfaceType::Ipip),
            ..gre.clone()
        };
        let d = tunnel_netdev_body(&ipip);
        assert!(d.contains("Kind=ipip"), "{d}");
        assert!(!d.contains("Key="), "{d}");
    }

    #[test]
    fn parent_network_references_child_vlans() {
        let u = network_body(
            "eth1",
            Some("10.0.0.1/24"),
            None,
            &["eth1.20".into(), "eth1.30".into()],
            &[],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(u.contains("VLAN=eth1.20"));
        assert!(u.contains("VLAN=eth1.30"));
    }

    #[test]
    fn unit_name_is_prefixed_and_scoped() {
        assert_eq!(network_name("eth0"), "10-sentinel-eth0.network");
    }

    #[test]
    fn dhcp_server_renders_pool_and_dns() {
        let dhcp = DhcpServer {
            pool_offset: Some(100),
            pool_size: Some(50),
            dns: vec!["10.0.0.1".into()],
            lease_time: Some(3600),
            default_router: None,
            domain: None,
            static_mappings: vec![],
        };
        let u = network_body(
            "eth1",
            Some("10.0.0.1/24"),
            None,
            &[],
            &[],
            Some(&dhcp),
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        // The static subnet is still bound, and the server is switched on.
        assert!(u.contains("Address=10.0.0.1/24"));
        assert!(u.contains("DHCPServer=yes"));
        // The [DHCPServer] section carries the pool + lease + DNS refinements.
        assert!(u.contains("[DHCPServer]"));
        assert!(u.contains("PoolOffset=100"));
        assert!(u.contains("PoolSize=50"));
        assert!(u.contains("DefaultLeaseTimeSec=3600"));
        assert!(u.contains("EmitDNS=yes"));
        assert!(u.contains("DNS=10.0.0.1"));
    }

    #[test]
    fn dhcp_server_without_dns_omits_emit_dns() {
        let dhcp = DhcpServer {
            pool_offset: None,
            pool_size: None,
            dns: vec![],
            lease_time: None,
            default_router: None,
            domain: None,
            static_mappings: vec![],
        };
        let u = network_body(
            "eth1",
            Some("10.0.0.1/24"),
            None,
            &[],
            &[],
            Some(&dhcp),
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(u.contains("DHCPServer=yes"));
        assert!(u.contains("[DHCPServer]"));
        assert!(!u.contains("EmitDNS"));
        assert!(!u.contains("DNS="));
    }

    #[test]
    fn dhcp_server_renders_router_domain_and_static_leases() {
        let dhcp = DhcpServer {
            pool_offset: Some(100),
            pool_size: Some(50),
            dns: vec!["10.0.0.1".into()],
            lease_time: Some(43_200),
            default_router: Some("10.0.0.254".into()),
            domain: Some("lan.example".into()),
            static_mappings: vec![DhcpStaticLease {
                name: "printer".into(),
                mac: "52:54:00:12:34:56".into(),
                ip: "10.0.0.20".into(),
            }],
        };
        let u = network_body(
            "eth1",
            Some("10.0.0.1/24"),
            None,
            &[],
            &[],
            Some(&dhcp),
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        // The override gateway (option 3) and domain (option 15).
        assert!(u.contains("EmitRouter=yes"), "got:\n{u}");
        assert!(u.contains("Router=10.0.0.254"), "got:\n{u}");
        assert!(u.contains("SendOption=15:string:lan.example"), "got:\n{u}");
        // The default lease time round-trips as networkd's key.
        assert!(u.contains("DefaultLeaseTimeSec=43200"), "got:\n{u}");
        // The static reservation becomes its own section keyed on MAC + address.
        assert!(u.contains("[DHCPServerStaticLease]"), "got:\n{u}");
        assert!(u.contains("MACAddress=52:54:00:12:34:56"), "got:\n{u}");
        assert!(u.contains("Address=10.0.0.20"), "got:\n{u}");
    }

    #[test]
    fn interface_description_and_disabled_render() {
        // A description becomes a leading comment; `disabled` adds a [Link] with
        // ActivationPolicy=down even when no MTU/MAC is set.
        let u = network_body(
            "eth7",
            Some("10.0.0.1/24"),
            None,
            &[],
            &[],
            None,
            None,
            None,
            None,
            None,
            None,
            Some("office LAN"),
            true,
        );
        assert!(u.starts_with("# office LAN\n"), "got:\n{u}");
        assert!(u.contains("[Link]"), "got:\n{u}");
        assert!(u.contains("ActivationPolicy=down"), "got:\n{u}");
    }

    #[test]
    fn dnsmasq_renders_cache_size_and_local_domain() {
        let dns = Dns {
            upstream: vec!["9.9.9.9".into()],
            serve_on: vec!["lan0".into()],
            host_override: std::collections::BTreeMap::new(),
            blocklist: vec![],
            dnssec: None,
            cache_size: Some(1000),
            local_domain: Some("lan.example".into()),
        };
        let d = dnsmasq_conf_body(&dns)
            .unwrap()
            .expect("LAN resolver configured");
        assert!(d.contains("cache-size=1000"), "got:\n{d}");
        assert!(d.contains("local=/lan.example/"), "got:\n{d}");
        assert!(d.contains("domain=lan.example"), "got:\n{d}");
    }

    #[test]
    fn dnsmasq_rejects_injection_in_local_domain() {
        // A `/` closes the `local=/dom/` pattern early; a newline splices a line.
        let slash = Dns {
            serve_on: vec!["lan0".into()],
            local_domain: Some("lan/address=/evil.com/1.2.3.4".into()),
            ..Dns::default()
        };
        assert!(dnsmasq_conf_body(&slash).is_err());
        let nl = Dns {
            serve_on: vec!["lan0".into()],
            local_domain: Some("lan\nserver=6.6.6.6".into()),
            ..Dns::default()
        };
        assert!(dnsmasq_conf_body(&nl).is_err());
    }

    #[test]
    fn ntp_server_renders_chrony_confdir() {
        let ntp = Ntp {
            upstream: vec!["pool.ntp.org".into(), "10.0.0.99".into()],
            serve_on: vec!["lan0".into()],
        };
        let ifaces = vec![Interface {
            name: "lan0".into(),
            zone: Some("lan".into()),
            address: Some("10.0.0.1/24".into()),
            address6: None,
            parent: None,
            vlan: None,
            vlan_protocol: None,
            macvlan_mode: None,
            dhcp_server: None,
            router_advert: None,
            if_type: None,
            members: vec![],
            vlan_aware: None,
            vlan_tagged: vec![],
            vlan_untagged: None,
            bond_mode: None,
            pd_from: None,
            pd_subnet: None,
            mtu: None,
            mac: None,
            local: None,
            remote: None,
            tunnel_key: None,
            ttl: None,
            qos: None,
            pppoe: None,
            description: None,
            disabled: false,
        }];
        let body = chrony_conf_body(&ntp, &ifaces).expect("ntp configured");
        assert!(body.contains("server pool.ntp.org iburst"));
        assert!(body.contains("server 10.0.0.99 iburst"));
        // The serving interface's *subnet* is allowed, not its host address.
        assert!(body.contains("allow 10.0.0.0/24"), "got:\n{body}");
        assert!(chrony_conf_body(&Ntp::default(), &ifaces).is_none());
    }

    #[test]
    fn ipv4_network_masks_host_bits() {
        assert_eq!(ipv4_network("10.0.0.1/24").as_deref(), Some("10.0.0.0/24"));
        assert_eq!(
            ipv4_network("192.168.5.130/26").as_deref(),
            Some("192.168.5.128/26")
        );
        assert_eq!(ipv4_network("10.9.9.9/8").as_deref(), Some("10.0.0.0/8"));
        assert_eq!(ipv4_network("dhcp"), None);
    }

    #[test]
    fn dns_renders_box_resolver_and_lan_dnsmasq() {
        let mut host_override = std::collections::BTreeMap::new();
        host_override.insert("nas.lan".to_string(), "10.0.0.5".to_string());
        let dns = Dns {
            upstream: vec!["9.9.9.9".into(), "2620:fe::fe".into()],
            serve_on: vec!["lan0".into()],
            host_override,
            blocklist: vec!["ads.example".into()],
            dnssec: None,
            cache_size: None,
            local_domain: None,
        };
        // resolved is the box's own forwarder: upstreams + DNSSEC, NO LAN stub.
        let r = resolved_dropin_body(&dns).expect("box forwarder configured");
        assert!(r.contains("[Resolve]"));
        assert!(r.contains("DNS=9.9.9.9 2620:fe::fe"));
        assert!(
            !r.contains("DNSStubListenerExtra"),
            "LAN serving is dnsmasq's job"
        );
        assert!(r.contains("DNSSEC=no"));
        // dnsmasq is the LAN resolver: forward, serve on the link, override + block.
        let d = dnsmasq_conf_body(&dns)
            .unwrap()
            .expect("LAN resolver configured");
        assert!(d.contains("server=9.9.9.9"), "got:\n{d}");
        assert!(d.contains("interface=lan0"), "got:\n{d}");
        assert!(
            d.contains("address=/nas.lan/10.0.0.5"),
            "host override:\n{d}"
        );
        assert!(
            d.contains("address=/ads.example/0.0.0.0"),
            "blocklist v4:\n{d}"
        );
        assert!(d.contains("address=/ads.example/::"), "blocklist v6:\n{d}");
        // No upstream ⇒ no box forwarder; no serve-on ⇒ no LAN resolver.
        assert!(resolved_dropin_body(&Dns::default()).is_none());
        assert!(dnsmasq_conf_body(&Dns::default()).unwrap().is_none());
    }

    #[test]
    fn dhcpv6_pd_renders_client_and_delegation() {
        // WAN uplink: DHCPv6 client soliciting up front (no RA needed).
        let wan = network_body(
            "wan0",
            Some("dhcp"),
            Some("dhcp"),
            &[],
            &[],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(wan.contains("DHCP=yes")); // v4 dhcp + v6 dhcp
        assert!(wan.contains("[DHCPv6]"));
        assert!(wan.contains("WithoutRA=solicit"));
        // A v6-only DHCPv6 client renders DHCP=ipv6, not yes.
        let wan6 = network_body(
            "wan0",
            None,
            Some("dhcp"),
            &[],
            &[],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(wan6.contains("DHCP=ipv6"));
        // LAN downstream: request subnet 2 of the uplink's delegated prefix and
        // advertise it.
        let lan = network_body(
            "lan0",
            Some("10.0.0.1/24"),
            None,
            &[],
            &[],
            None,
            None,
            None,
            Some(("wan0", 2)),
            None,
            None,
            None,
            false,
        );
        assert!(lan.contains("DHCPPrefixDelegation=yes"));
        assert!(lan.contains("[DHCPPrefixDelegation]"));
        assert!(lan.contains("UplinkInterface=wan0"));
        assert!(lan.contains("SubnetId=2"));
        assert!(lan.contains("Announce=yes"));
    }

    #[test]
    fn mtu_and_mac_render_link_section() {
        let u = network_body(
            "wan0",
            Some("dhcp"),
            None,
            &[],
            &[],
            None,
            None,
            None,
            None,
            Some(1492),
            Some("52:54:00:12:34:56"),
            None,
            false,
        );
        assert!(u.contains("[Link]"));
        assert!(u.contains("MTUBytes=1492"));
        assert!(u.contains("MACAddress=52:54:00:12:34:56"));
        let plain = network_body(
            "lan0",
            Some("10.0.0.1/24"),
            None,
            &[],
            &[],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(!plain.contains("[Link]"));
    }

    #[test]
    fn dual_stack_and_slaac_address6_render() {
        // A static dual-stack interface emits both an IPv4 and an IPv6 Address=.
        let u = network_body(
            "lan0",
            Some("10.0.0.1/24"),
            Some("2001:db8:1::1/64"),
            &[],
            &[],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(u.contains("Address=10.0.0.1/24"));
        assert!(u.contains("Address=2001:db8:1::1/64"));
        // `auto` accepts RAs (SLAAC) instead of binding a static v6 address.
        let a = network_body(
            "wan0",
            Some("dhcp"),
            Some("auto"),
            &[],
            &[],
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(a.contains("DHCP=yes"));
        assert!(a.contains("IPv6AcceptRA=yes"));
        assert!(!a.contains("Address=auto"));
    }

    #[test]
    fn bridge_netdev_and_member_enslavement_render() {
        let br = Interface {
            name: "br0".into(),
            zone: Some("lan".into()),
            address: Some("10.0.0.1/24".into()),
            address6: None,
            parent: None,
            vlan: None,
            vlan_protocol: None,
            macvlan_mode: None,
            dhcp_server: None,
            router_advert: None,
            if_type: Some(IfaceType::Bridge),
            members: vec![],
            vlan_aware: None,
            vlan_tagged: vec![],
            vlan_untagged: None,
            bond_mode: None,
            pd_from: None,
            pd_subnet: None,
            mtu: None,
            mac: None,
            local: None,
            remote: None,
            tunnel_key: None,
            ttl: None,
            qos: None,
            pppoe: None,
            description: None,
            disabled: false,
        };
        let d = virtual_l2_netdev_body(&br);
        assert!(d.contains("Name=br0"));
        assert!(d.contains("Kind=bridge"));
        assert!(!d.contains("[Bond]"));
        // A member's .network carries the Bridge= enslavement in [Network].
        let member = network_body(
            "lan1",
            None,
            None,
            &[],
            &[],
            None,
            None,
            Some("Bridge=br0"),
            None,
            None,
            None,
            None,
            false,
        );
        assert!(member.contains("[Network]"));
        assert!(member.contains("Bridge=br0"));
    }

    #[test]
    fn bond_netdev_renders_kind_and_mode() {
        let bond = Interface {
            name: "bond0".into(),
            zone: None,
            address: None,
            address6: None,
            parent: None,
            vlan: None,
            vlan_protocol: None,
            macvlan_mode: None,
            dhcp_server: None,
            router_advert: None,
            if_type: Some(IfaceType::Bond),
            members: vec![],
            vlan_aware: None,
            vlan_tagged: vec![],
            vlan_untagged: None,
            bond_mode: Some("802.3ad".into()),
            pd_from: None,
            pd_subnet: None,
            mtu: None,
            mac: None,
            local: None,
            remote: None,
            tunnel_key: None,
            ttl: None,
            qos: None,
            pppoe: None,
            description: None,
            disabled: false,
        };
        let d = virtual_l2_netdev_body(&bond);
        assert!(d.contains("Kind=bond"));
        assert!(d.contains("[Bond]"));
        assert!(d.contains("Mode=802.3ad"));
        let mut b2 = bond.clone();
        b2.bond_mode = None;
        assert!(virtual_l2_netdev_body(&b2).contains("Mode=active-backup"));
        let member = network_body(
            "lan2",
            None,
            None,
            &[],
            &[],
            None,
            None,
            Some("Bond=bond0"),
            None,
            None,
            None,
            None,
            false,
        );
        assert!(member.contains("Bond=bond0"));
    }

    #[test]
    fn router_advert_renders_send_ra_prefix_and_dns() {
        let ra = RouterAdvert {
            prefixes: vec!["2001:db8:1::/64".into()],
            dns: vec!["2001:db8:1::1".into()],
            managed: false,
            other_config: true,
            router_lifetime: Some(1800),
        };
        let u = network_body(
            "lan0",
            Some("10.0.0.1/24"),
            None,
            &[],
            &[],
            None,
            Some(&ra),
            None,
            None,
            None,
            None,
            None,
            false,
        );
        // The enabling directive stays in [Network]; the detail sections follow.
        assert!(u.contains("IPv6SendRA=yes"));
        assert!(u.contains("[IPv6SendRA]"));
        assert!(u.contains("OtherInformation=yes"));
        assert!(u.contains("RouterLifetimeSec=1800"));
        assert!(u.contains("EmitDNS=yes"));
        assert!(u.contains("DNS=2001:db8:1::1"));
        assert!(u.contains("[IPv6Prefix]"));
        assert!(u.contains("Prefix=2001:db8:1::/64"));
        assert!(u.contains("Assign=yes"));
        assert!(!u.contains("Managed=yes"));
    }

    #[test]
    fn dhcp_and_ra_enabling_directives_both_land_in_network_section() {
        // When an interface runs both a DHCP server and RA, both `DHCPServer=yes`
        // and `IPv6SendRA=yes` must appear before any sub-section opens, else one
        // would be swallowed into the other's section.
        let dhcp = DhcpServer {
            pool_offset: Some(100),
            pool_size: Some(10),
            dns: vec![],
            lease_time: None,
            default_router: None,
            domain: None,
            static_mappings: vec![],
        };
        let ra = RouterAdvert {
            prefixes: vec!["2001:db8:9::/64".into()],
            dns: vec![],
            managed: false,
            other_config: false,
            router_lifetime: None,
        };
        let u = network_body(
            "lan0",
            Some("10.0.0.1/24"),
            None,
            &[],
            &[],
            Some(&dhcp),
            Some(&ra),
            None,
            None,
            None,
            None,
            None,
            false,
        );
        let network_hdr = u.find("[Network]").unwrap();
        let first_subsection = u.find("[DHCPServer]").unwrap();
        let dhcp_on = u.find("DHCPServer=yes").unwrap();
        let ra_on = u.find("IPv6SendRA=yes").unwrap();
        // Both enabling directives sit inside [Network], above the first section.
        assert!(network_hdr < dhcp_on && dhcp_on < first_subsection);
        assert!(network_hdr < ra_on && ra_on < first_subsection);
    }

    #[test]
    fn wireguard_netdev_renders_kind_key_and_peer() {
        use crate::config::{WgPeer, WireguardTunnel};
        // The crypto now lives in a [[vpn.wireguard]] tunnel keyed by interface name.
        let tunnel = WireguardTunnel {
            name: "wg0".into(),
            private_key: "ICOioMTTlfQE/2NndOoEntortz+0tZ5Hll0AEM7tdmE=".into(),
            listen_port: Some(51820),
            peers: vec![WgPeer {
                public_key: "ukF+iwo+aai/wm9k1nIlxCBFRnZ+bLPb2xIu4+4PvmQ=".into(),
                allowed_ips: vec!["10.9.0.2/32".into()],
                endpoint: Some("192.0.2.7:51820".into()),
                persistent_keepalive: Some(25),
                preshared_key: None,
            }],
        };
        let d = wireguard_netdev_body("wg0", &tunnel);
        assert!(d.contains("Kind=wireguard"));
        assert!(d.contains("PrivateKey=ICOioMTTlfQE/2NndOoEntortz+0tZ5Hll0AEM7tdmE="));
        assert!(d.contains("ListenPort=51820"));
        assert!(d.contains("[WireGuardPeer]"));
        assert!(d.contains("PublicKey=ukF+iwo+aai/wm9k1nIlxCBFRnZ+bLPb2xIu4+4PvmQ="));
        assert!(d.contains("AllowedIPs=10.9.0.2/32"));
        assert!(d.contains("Endpoint=192.0.2.7:51820"));
        assert!(d.contains("PersistentKeepalive=25"));
    }

    #[test]
    fn vlan_aware_bridge_renders_filtering_and_port_vlans() {
        // A vlan-aware bridge netdev carries VLANFiltering=yes.
        let br = Interface {
            name: "br0".into(),
            zone: Some("lan".into()),
            address: Some("10.0.0.1/24".into()),
            address6: None,
            parent: None,
            vlan: None,
            vlan_protocol: None,
            macvlan_mode: None,
            dhcp_server: None,
            router_advert: None,
            if_type: Some(IfaceType::Bridge),
            members: vec!["lan1".into()],
            vlan_aware: Some(true),
            vlan_tagged: vec![],
            vlan_untagged: None,
            bond_mode: None,
            pd_from: None,
            pd_subnet: None,
            mtu: None,
            mac: None,
            local: None,
            remote: None,
            tunnel_key: None,
            ttl: None,
            qos: None,
            pppoe: None,
            description: None,
            disabled: false,
        };
        let d = virtual_l2_netdev_body(&br);
        assert!(d.contains("VLANFiltering=yes"), "{d}");
        // A port's [BridgeVLAN] section: one VLAN= per tagged id + PVID/EgressUntagged.
        let port = bridge_vlan_body(&[10, 20], Some(1));
        assert!(port.contains("[BridgeVLAN]"), "{port}");
        assert!(port.contains("VLAN=10"), "{port}");
        assert!(port.contains("VLAN=20"), "{port}");
        assert!(port.contains("PVID=1"), "{port}");
        assert!(port.contains("EgressUntagged=1"), "{port}");
        // A non-filtering port renders nothing.
        assert!(bridge_vlan_body(&[], None).is_empty());
    }

    /// A PPPoE client interface `ppp0` over uplink `parent`, with the given
    /// credentials — for the render tests below.
    fn pppoe_iface(parent: &str, username: &str, password: &str) -> Interface {
        Interface {
            name: "ppp0".into(),
            zone: Some("wan".into()),
            address: None,
            address6: None,
            pd_from: None,
            pd_subnet: None,
            parent: Some(parent.into()),
            vlan: None,
            vlan_protocol: None,
            macvlan_mode: None,
            dhcp_server: None,
            router_advert: None,
            if_type: Some(IfaceType::Pppoe),
            members: vec![],
            vlan_aware: None,
            vlan_tagged: vec![],
            vlan_untagged: None,
            bond_mode: None,
            mtu: Some(1492),
            mac: None,
            local: None,
            remote: None,
            tunnel_key: None,
            ttl: None,
            qos: None,
            pppoe: Some(Pppoe {
                username: username.into(),
                password: password.into(),
                service_name: Some("internet".into()),
                ac_name: None,
                mru: None,
            }),
            description: None,
            disabled: false,
        }
    }

    #[test]
    fn pppoe_peer_body_has_plugin_user_and_mtu() {
        let iface = pppoe_iface("eth0", "user@isp.de", "s3cret");
        let body = pppoe_peer_body(&iface);
        assert!(body.contains("plugin pppoe.so"), "got:\n{body}");
        assert!(body.contains("nic-eth0"), "got:\n{body}");
        assert!(body.contains("ifname ppp0"), "got:\n{body}");
        assert!(body.contains("user \"user@isp.de\""), "got:\n{body}");
        assert!(body.contains("mtu 1492"), "got:\n{body}");
        assert!(body.contains("mru 1492"), "got:\n{body}");
        assert!(body.contains("rp_pppoe_service internet"), "got:\n{body}");
        assert!(body.contains("defaultroute"), "got:\n{body}");
        assert!(body.contains("usepeerdns"), "got:\n{body}");
        assert!(body.contains("persist"), "got:\n{body}");
        // The password NEVER appears in the world-readable peer options.
        assert!(
            !body.contains("s3cret"),
            "peer options must not carry the password:\n{body}"
        );
    }

    #[test]
    fn ppp_secrets_body_lists_credentials_only_for_pppoe() {
        let ifaces = vec![pppoe_iface("eth0", "user@isp.de", "s3cret")];
        let body = ppp_secrets_body(&ifaces).expect("a pppoe interface yields secrets");
        assert!(
            body.contains("\"user@isp.de\"\t*\t\"s3cret\"\t*"),
            "got:\n{body}"
        );
        // No PPPoE interface → no secrets file at all.
        assert!(ppp_secrets_body(&[]).is_none());
    }

    #[test]
    fn pppoe_mss_body_clamps_to_pmtu_on_the_ppp_link() {
        let ifaces = vec![pppoe_iface("eth0", "u", "p")];
        let body = pppoe_mss_body(&ifaces);
        assert!(body.contains("table inet sentinel-mss {"), "got:\n{body}");
        assert!(
            body.contains("oifname \"ppp0\" tcp flags syn tcp option maxseg size set rt mtu"),
            "got:\n{body}"
        );
        // With no PPPoE interface the ruleset only flushes/removes the table.
        let empty = pppoe_mss_body(&[]);
        assert!(
            empty.contains("delete table inet sentinel-mss"),
            "got:\n{empty}"
        );
        assert!(!empty.contains("maxseg"), "got:\n{empty}");
    }

    #[test]
    fn disabled_pppoe_renders_nothing_and_is_torn_down_like_a_removed_one() {
        let mut iface = pppoe_iface("eth0", "user@isp.de", "s3cret");
        iface.disabled = true;
        // A disabled PPPoE client is not "active": no pppd session should dial.
        assert!(!is_active_pppoe(&iface));
        // No credentials and no MSS clamp are rendered for it.
        assert!(
            ppp_secrets_body(std::slice::from_ref(&iface)).is_none(),
            "disabled pppoe must not emit credentials"
        );
        let mss = pppoe_mss_body(std::slice::from_ref(&iface));
        assert!(
            !mss.contains("maxseg"),
            "disabled pppoe must not get an MSS clamp:\n{mss}"
        );
        // It is absent from the desired set that `apply_pppoe` builds, so the
        // teardown loop stops+removes its session exactly as for a removed one —
        // the same mechanism the enabled case leaves untouched.
        let mut enabled = pppoe_iface("eth0", "user@isp.de", "s3cret");
        enabled.disabled = false;
        assert!(is_active_pppoe(&enabled));
        assert!(ppp_secrets_body(std::slice::from_ref(&enabled)).is_some());
    }

    #[test]
    fn multiwan_script_renders_arrays_tables_and_failover() {
        use crate::config::{HealthCheck, MultiWan, WanMode, WanUplink};
        let mw = MultiWan {
            mode: WanMode::Failover,
            uplinks: vec![
                WanUplink {
                    interface: "wan0".into(),
                    priority: Some(10),
                    weight: None,
                    table: None,
                    gateway: Some("10.1.0.254".into()),
                    check: HealthCheck {
                        targets: vec!["1.1.1.1".into()],
                        interval: Some(2),
                        timeout: Some(1),
                        fail: Some(2),
                        rise: Some(2),
                    },
                },
                WanUplink {
                    interface: "wan1".into(),
                    priority: Some(20),
                    weight: None,
                    table: None,
                    gateway: Some("10.2.0.254".into()),
                    check: HealthCheck::default(),
                },
            ],
        };
        let s = multiwan_script_body(&mw).expect("uplinks configured");
        // Per-uplink arrays are unrolled with the config values.
        assert!(s.contains("MODE=\"failover\""), "got:\n{s}");
        assert!(s.contains("IF=(\"wan0\" \"wan1\")"), "got:\n{s}");
        assert!(
            s.contains("GW=(\"10.1.0.254\" \"10.2.0.254\")"),
            "got:\n{s}"
        );
        // Derived table ids (WAN_TABLE_BASE + idx).
        assert!(s.contains("TB=(200 201)"), "got:\n{s}");
        assert!(s.contains("PR=(10 20)"), "got:\n{s}");
        // Each uplink keeps its own probe interval (uplink 1 falls back to the
        // WAN_CHECK_INTERVAL default of 5) — no collapse to a single global tick.
        assert!(s.contains("IV=(2 5)"), "got:\n{s}");
        assert!(!s.contains("INTERVAL="), "no single global tick:\n{s}");
        // The scheduler probes each uplink only when its own NEXT[i] falls due.
        assert!(s.contains("NEXT[i]=$(( now + IV[i] ))"), "got:\n{s}");
        // The fixed logic sets up per-uplink tables + programs the main default.
        assert!(
            s.contains("ip route replace default via \"$gw\" dev \"${IF[i]}\" table \"${TB[i]}\""),
            "got:\n{s}"
        );
        assert!(
            s.contains("ip rule add from \"$src\" lookup \"${TB[i]}\""),
            "got:\n{s}"
        );
        // No uplink ⇒ no script.
        assert!(multiwan_script_body(&MultiWan::default()).is_none());
    }

    #[test]
    fn multiwan_load_balance_mode_renders() {
        use crate::config::{HealthCheck, MultiWan, WanMode, WanUplink};
        let mw = MultiWan {
            mode: WanMode::LoadBalance,
            uplinks: vec![
                WanUplink {
                    interface: "wan0".into(),
                    priority: None,
                    weight: Some(3),
                    table: Some(210),
                    gateway: None, // dhcp ⇒ resolved at runtime (empty token)
                    check: HealthCheck::default(),
                },
                WanUplink {
                    interface: "wan1".into(),
                    priority: None,
                    weight: Some(1),
                    table: Some(211),
                    gateway: Some("10.2.0.254".into()),
                    check: HealthCheck::default(),
                },
            ],
        };
        let s = multiwan_script_body(&mw).expect("uplinks configured");
        assert!(s.contains("MODE=\"load-balance\""), "got:\n{s}");
        // A dhcp/unset gateway renders an empty token (resolved at runtime).
        assert!(s.contains("GW=(\"\" \"10.2.0.254\")"), "got:\n{s}");
        assert!(s.contains("WT=(3 1)"), "got:\n{s}");
        assert!(s.contains("TB=(210 211)"), "got:\n{s}");
        // The multipath default is built from healthy uplinks by weight.
        assert!(
            s.contains("nexthop via \"$gw\" dev \"${IF[i]}\" weight \"${WT[i]}\""),
            "got:\n{s}"
        );
    }

    #[test]
    fn multiwan_uplinks_keep_distinct_check_intervals() {
        use crate::config::{HealthCheck, MultiWan, WanMode, WanUplink};
        let mk = |iface: &str, interval: u32| WanUplink {
            interface: iface.into(),
            priority: None,
            weight: None,
            table: None,
            gateway: Some("10.0.0.254".into()),
            check: HealthCheck {
                targets: vec!["1.1.1.1".into()],
                interval: Some(interval),
                ..HealthCheck::default()
            },
        };
        let mw = MultiWan {
            mode: WanMode::Failover,
            uplinks: vec![mk("wan0", 5), mk("wan1", 30)],
        };
        let s = multiwan_script_body(&mw).expect("uplinks configured");
        // Both cadences survive verbatim — the fast uplink does not force the slow
        // one to 5s, nor does the slow one relax the fast one to 30s.
        assert!(s.contains("IV=(5 30)"), "got:\n{s}");
        // A per-uplink next-due gate drives the scheduling.
        assert!(
            s.contains("[ \"$now\" -lt \"${NEXT[i]}\" ] && continue"),
            "got:\n{s}"
        );
        // The daemon sleeps only until the soonest uplink is due, never a fixed tick.
        assert!(s.contains("s=$(( nxt - $(date +%s) ))"), "got:\n{s}");
        assert!(!s.contains("sleep \"$INTERVAL\""), "no global tick:\n{s}");
    }

    // --- Box services (roadmap C18) ---------------------------------------

    #[test]
    fn lldp_conf_renders_pattern_or_nothing() {
        // Disabled ⇒ no file at all (the daemon stays stopped).
        assert!(lldpd_conf_body(&Lldp::default()).is_none());
        // Enabled with a whitelist ⇒ an interface pattern.
        let l = Lldp {
            enable: true,
            interface: vec!["lan0".into(), "wan0".into()],
        };
        let body = lldpd_conf_body(&l).expect("enabled");
        assert!(
            body.contains("configure system interface pattern lan0,wan0"),
            "got:\n{body}"
        );
        // Enabled with no whitelist ⇒ header only (lldpd's default = all links).
        let all = Lldp {
            enable: true,
            interface: vec![],
        };
        let body = lldpd_conf_body(&all).expect("enabled");
        assert!(!body.contains("interface pattern"), "got:\n{body}");
    }

    #[test]
    fn snmp_conf_is_read_only_and_scopes_by_family() {
        assert!(snmpd_conf_body(&Snmp::default()).unwrap().is_none());
        let s = Snmp {
            community: Some("public".into()),
            listen: Some("udp:10.0.0.1:161".into()),
            location: Some("rack 4".into()),
            contact: Some("noc@example".into()),
            allow: vec!["10.0.0.0/24".into(), "fd00::/64".into()],
        };
        let body = snmpd_conf_body(&s).unwrap().expect("configured");
        assert!(
            body.contains("agentaddress udp:10.0.0.1:161"),
            "got:\n{body}"
        );
        // IPv4 source ⇒ rocommunity; IPv6 source ⇒ rocommunity6. Read-only only.
        assert!(
            body.contains("rocommunity public 10.0.0.0/24"),
            "got:\n{body}"
        );
        assert!(
            body.contains("rocommunity6 public fd00::/64"),
            "got:\n{body}"
        );
        assert!(
            !body.contains("rwcommunity"),
            "must never render write access"
        );
        assert!(body.contains("syslocation rack 4"), "got:\n{body}");
        // No allow list ⇒ `default` (any source).
        let any = Snmp {
            community: Some("public".into()),
            ..Snmp::default()
        };
        assert!(
            snmpd_conf_body(&any)
                .unwrap()
                .expect("configured")
                .contains("rocommunity public default")
        );
    }

    #[test]
    fn snmp_rejects_injection_in_location_and_contact() {
        // A newline in location/contact would splice a fresh snmpd directive.
        let loc = Snmp {
            community: Some("public".into()),
            location: Some("rack\nrwcommunity evil".into()),
            ..Snmp::default()
        };
        assert!(snmpd_conf_body(&loc).is_err());
        let contact = Snmp {
            community: Some("public".into()),
            contact: Some("noc\nrwcommunity evil".into()),
            ..Snmp::default()
        };
        assert!(snmpd_conf_body(&contact).is_err());
    }

    #[test]
    fn avahi_reflector_conf_renders() {
        assert!(avahi_conf_body(&Mdns::default()).is_none());
        let m = Mdns {
            interface: vec!["lan0".into(), "iot0".into()],
        };
        let body = avahi_conf_body(&m).expect("configured");
        assert!(body.contains("enable-reflector=yes"), "got:\n{body}");
        assert!(body.contains("allow-interfaces=lan0,iot0"), "got:\n{body}");
    }

    #[test]
    fn ddclient_conf_renders_secret_and_use_modes() {
        assert!(ddclient_conf_body(&Dyndns::default()).unwrap().is_none());
        // An interface ⇒ use=if; a password is single-quoted.
        let d = Dyndns {
            provider: Some("cloudflare".into()),
            server: None,
            hostname: Some("fw.example.com".into()),
            login: Some("user@example".into()),
            password: Some("secret-token".into()),
            interface: Some("wan0".into()),
        };
        let body = ddclient_conf_body(&d).unwrap().expect("configured");
        assert!(body.contains("protocol=cloudflare"), "got:\n{body}");
        assert!(body.contains("use=if, if=wan0"), "got:\n{body}");
        assert!(body.contains("password='secret-token'"), "got:\n{body}");
        assert!(body.trim_end().ends_with("fw.example.com"), "got:\n{body}");
        // No interface ⇒ use=web (discover the WAN IP).
        let web = Dyndns {
            interface: None,
            ..d
        };
        assert!(
            ddclient_conf_body(&web)
                .unwrap()
                .expect("configured")
                .contains("use=web")
        );
    }

    #[test]
    fn ddclient_rejects_injection_in_fields() {
        // A `'` in the single-quoted password breaks out of the quoting.
        let pw = Dyndns {
            hostname: Some("fw.example.com".into()),
            password: Some("a'; evil".into()),
            ..Dyndns::default()
        };
        assert!(ddclient_conf_body(&pw).is_err());
        // A newline in a bare/`key=value` field would inject a directive.
        let host = Dyndns {
            hostname: Some("fw.example.com\nlogin=evil".into()),
            ..Dyndns::default()
        };
        assert!(ddclient_conf_body(&host).is_err());
        let login = Dyndns {
            hostname: Some("fw.example.com".into()),
            login: Some("u\nserver=evil".into()),
            ..Dyndns::default()
        };
        assert!(ddclient_conf_body(&login).is_err());
    }

    /// A bare interface carrying just a name + address (Interface has no Default).
    fn iface_addr(name: &str, address: &str) -> Interface {
        Interface {
            name: name.into(),
            zone: None,
            address: Some(address.into()),
            address6: None,
            parent: None,
            vlan: None,
            vlan_protocol: None,
            macvlan_mode: None,
            dhcp_server: None,
            router_advert: None,
            if_type: None,
            members: vec![],
            vlan_aware: None,
            vlan_tagged: vec![],
            vlan_untagged: None,
            bond_mode: None,
            pd_from: None,
            pd_subnet: None,
            mtu: None,
            mac: None,
            local: None,
            remote: None,
            tunnel_key: None,
            ttl: None,
            qos: None,
            pppoe: None,
            description: None,
            disabled: false,
        }
    }

    #[test]
    fn dhcp_relay_conf_renders_dnsmasq_relay_or_nothing() {
        let ifaces = vec![
            iface_addr("lan0", "10.0.7.1/24"),
            iface_addr("wan0", "dhcp"),
        ];
        assert!(dhcp_relay_conf_body(&DhcpRelay::default(), &ifaces).is_none());
        // No server ⇒ nothing (a relay needs an upstream).
        let no_srv = DhcpRelay {
            interface: vec!["lan0".into()],
            server: vec![],
        };
        assert!(dhcp_relay_conf_body(&no_srv, &ifaces).is_none());
        // A static-addressed relay interface ⇒ a `dhcp-relay=<local>,<server>`
        // line per server; `port=0` disables this instance's DNS half.
        let r = DhcpRelay {
            interface: vec!["lan0".into()],
            server: vec!["10.0.99.1".into(), "10.0.99.2".into()],
        };
        let body = dhcp_relay_conf_body(&r, &ifaces).expect("configured");
        assert!(body.contains("port=0"), "got:\n{body}");
        assert!(
            body.contains("dhcp-relay=10.0.7.1,10.0.99.1"),
            "got:\n{body}"
        );
        assert!(
            body.contains("dhcp-relay=10.0.7.1,10.0.99.2"),
            "got:\n{body}"
        );
    }

    #[test]
    fn nat64_router_ipv4_is_pool_first_host() {
        assert_eq!(
            nat64_router_ipv4("192.0.2.0/24").as_deref(),
            Some("192.0.2.1")
        );
        assert_eq!(
            nat64_router_ipv4("10.64.0.0/10").as_deref(),
            Some("10.64.0.1")
        );
        assert!(nat64_router_ipv4("192.0.2.1").is_none()); // no prefix
    }

    #[test]
    fn tayga_renders_conf_and_setup_or_nothing() {
        let mut lan6 = iface_addr("lan6", "dhcp");
        lan6.address = None;
        lan6.address6 = Some("2001:db8:64::1/64".into());
        let ifaces = vec![lan6];
        // Off ⇒ nothing.
        assert!(tayga_conf_body(&Nat64::default(), &ifaces).is_none());
        assert!(tayga_setup_body(&Nat64::default()).is_none());
        // Enabled with the well-known prefix + a pool ⇒ tayga.conf + setup script.
        let n64 = Nat64 {
            enabled: true,
            prefix: None,
            pool: Some("192.0.2.0/24".into()),
            interface: Some("lan6".into()),
            dns64: true,
        };
        let conf = tayga_conf_body(&n64, &ifaces).expect("configured");
        assert!(conf.contains("tun-device nat64"), "got:\n{conf}");
        assert!(conf.contains("ipv4-addr 192.0.2.1"), "got:\n{conf}");
        assert!(conf.contains("ipv6-addr 2001:db8:64::1"), "got:\n{conf}");
        assert!(conf.contains("prefix 64:ff9b::/96"), "got:\n{conf}");
        assert!(conf.contains("dynamic-pool 192.0.2.0/24"), "got:\n{conf}");
        let setup = tayga_setup_body(&n64).expect("configured");
        assert!(setup.contains("tayga --mktun"), "got:\n{setup}");
        assert!(
            setup.contains("ip route replace 192.0.2.0/24 dev nat64"),
            "got:\n{setup}"
        );
        assert!(
            setup.contains("ip -6 route replace 64:ff9b::/96 dev nat64"),
            "got:\n{setup}"
        );
        assert!(
            setup.contains("net.ipv6.conf.all.forwarding=1"),
            "got:\n{setup}"
        );
    }

    #[test]
    fn unbound_dns64_renders_synth_or_nothing() {
        let mut lan6 = iface_addr("lan6", "dhcp");
        lan6.address = None;
        lan6.address6 = Some("2001:db8:64::1/64".into());
        let ifaces = vec![lan6];
        let dns = Dns {
            upstream: vec!["10.64.2.2".into()],
            ..Dns::default()
        };
        // dns64 off ⇒ nothing.
        let off = Nat64 {
            enabled: true,
            pool: Some("192.0.2.0/24".into()),
            interface: Some("lan6".into()),
            dns64: false,
            ..Nat64::default()
        };
        assert!(unbound_dns64_body(&off, &dns, &ifaces).is_none());
        // dns64 on ⇒ unbound binds the serving interface's v6 addr, DNS64 synthesis
        // in the prefix, forwarding to the upstream.
        let on = Nat64 { dns64: true, ..off };
        let body = unbound_dns64_body(&on, &dns, &ifaces).expect("configured");
        assert!(body.contains("interface: 2001:db8:64::1"), "got:\n{body}");
        assert!(
            body.contains("module-config: \"dns64 iterator\""),
            "got:\n{body}"
        );
        assert!(body.contains("dns64-prefix: 64:ff9b::/96"), "got:\n{body}");
        assert!(body.contains("forward-addr: 10.64.2.2"), "got:\n{body}");
    }
}
