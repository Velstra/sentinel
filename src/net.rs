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
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::Result;

use crate::config::{Appliance, DhcpServer, Dns, IfaceType, Interface, Ntp, RouterAdvert};
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

/// The `.netdev` that creates an 802.1Q VLAN link `iface` with the given id.
fn netdev_body(iface: &str, vlan: u16) -> String {
    format!("[NetDev]\nName={iface}\nKind=vlan\n\n[VLAN]\nId={vlan}\n")
}

/// The `.netdev` for a virtual L2 device: a bridge (`Kind=bridge`) or a bond
/// (`Kind=bond` + `[Bond] Mode=`, default `active-backup`). Members attach via
/// their own `.network` (`Bridge=`/`Bond=`), not here.
fn virtual_l2_netdev_body(iface: &Interface) -> String {
    match iface.if_type {
        Some(IfaceType::Bridge) => format!("[NetDev]\nName={}\nKind=bridge\n", iface.name),
        Some(IfaceType::Bond) => {
            let mode = iface.bond_mode.as_deref().unwrap_or("active-backup");
            format!("[NetDev]\nName={}\nKind=bond\n\n[Bond]\nMode={mode}\n", iface.name)
        }
        None => String::new(),
    }
}

/// The `.netdev` that creates a WireGuard link: the `[WireGuard]` section
/// carries the private key (and optional listen port), and one
/// `[WireGuardPeer]` block per peer. The file is a secret (private key) and is
/// installed 0640 root:systemd-network by [`apply`].
fn wireguard_netdev_body(iface: &Interface) -> String {
    let name = &iface.name;
    let mut body = format!("[NetDev]\nName={name}\nKind=wireguard\n\n[WireGuard]\n");
    if let Some(pk) = &iface.private_key {
        body.push_str(&format!("PrivateKey={pk}\n"));
    }
    if let Some(port) = iface.listen_port {
        body.push_str(&format!("ListenPort={port}\n"));
    }
    for peer in &iface.peers {
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
    dhcp: Option<&DhcpServer>,
    ra: Option<&RouterAdvert>,
    master: Option<&str>,
    pd: Option<(&str, u8)>,
    mtu: Option<u16>,
    mac: Option<&str>,
) -> String {
    let v4dhcp = address == Some("dhcp");
    let v6dhcp = address6 == Some("dhcp");
    let mut body = format!("[Match]\nName={iface}\n\n[Network]\n");
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

    // Link tunables (MTU / MAC cloning) — a `[Link]` section networkd applies to
    // the interface. Emitted only when either is set.
    if mtu.is_some() || mac.is_some() {
        body.push_str("\n[Link]\n");
        if let Some(m) = mtu {
            body.push_str(&format!("MTUBytes={m}\n"));
        }
        if let Some(mac) = mac {
            body.push_str(&format!("MACAddress={mac}\n"));
        }
    }
    body
}

/// systemd-resolved's runtime drop-in dir. A `.conf` here overrides the image
/// `resolved.conf`, and (like the networkd units) it lives on tmpfs so it is
/// re-asserted from the saved config each boot.
const RESOLVED_DROPIN_DIR: &str = "/run/systemd/resolved.conf.d";
const RESOLVED_DROPIN: &str = "10-sentinel-dns.conf";

/// The IPv4 address of a static `address` CIDR (`"10.0.0.1/24"` → `"10.0.0.1"`).
/// `None` for `dhcp`/unset — validation already forbids serving DNS on such an
/// interface, so this only ever returns `None` defensively.
fn iface_ipv4(iface: &Interface) -> Option<&str> {
    match iface.address.as_deref() {
        Some(addr) if addr != "dhcp" => addr.split('/').next(),
        _ => None,
    }
}

/// Render the systemd-resolved drop-in for the DNS forwarder, or `None` when no
/// forwarder is configured. `DNS=` sets the upstreams the box forwards to and
/// `DNSStubListenerExtra=` binds an extra stub listener on each serving
/// interface's IP so LAN clients can use the box as their resolver.
fn resolved_dropin_body(dns: &Dns, ifaces: &[Interface]) -> Option<String> {
    if dns.is_empty() {
        return None;
    }
    let mut body = String::from("[Resolve]\n");
    if !dns.upstream.is_empty() {
        body.push_str(&format!("DNS={}\n", dns.upstream.join(" ")));
    }
    for name in &dns.serve_on {
        if let Some(ip) = ifaces.iter().find(|i| &i.name == name).and_then(iface_ipv4) {
            body.push_str(&format!("DNSStubListenerExtra={ip}\n"));
        }
    }
    // A forwarder trusts its upstream; default DNSSEC off so an unsigned or
    // validation-breaking upstream still resolves. An explicit value overrides.
    body.push_str(&format!("DNSSEC={}\n", dns.dnssec.as_deref().unwrap_or("no")));
    Some(body)
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
    let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
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

/// Reconcile the chrony confdir drop-in to `appliance.services.ntp`: write it
/// when an NTP server is configured, remove it otherwise, and restart chrony —
/// but only when the desired config actually changed, so a non-NTP commit never
/// disturbs the box's timekeeping.
fn apply_chrony(appliance: &Appliance) -> Result<()> {
    let path = Path::new(CHRONY_CONFDIR).join(CHRONY_CONF);
    match chrony_conf_body(&appliance.services.ntp, &appliance.interfaces) {
        Some(body) => {
            let changed = std::fs::read_to_string(&path).map(|c| c != body).unwrap_or(true);
            system::ensure_dir(Path::new(CHRONY_CONFDIR))?;
            system::install_file(&path, &body)?;
            if changed {
                restart_chrony();
            }
        }
        None => {
            if path.exists() {
                system::remove_file(&path)?;
                restart_chrony();
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
fn apply_resolved(appliance: &Appliance) -> Result<()> {
    let path = Path::new(RESOLVED_DROPIN_DIR).join(RESOLVED_DROPIN);
    match resolved_dropin_body(&appliance.services.dns, &appliance.interfaces) {
        Some(body) => {
            system::ensure_dir(Path::new(RESOLVED_DROPIN_DIR))?;
            system::install_file(&path, &body)?;
        }
        None => system::remove_file(&path)?,
    }
    if let Err(e) = system::reload_resolved() {
        eprintln!("warning: restarting systemd-resolved failed (applies on next start): {e}");
    }
    Ok(())
}

/// Reconcile networkd units to match `appliance`: write a `.netdev` for every
/// VLAN subinterface and a `.network` for every interface that needs one (it has
/// an address, is a VLAN, or is a parent carrying VLANs), remove any stale
/// sentinel units, then ask networkd to re-apply. Writing the units is required;
/// the reload is best-effort (at early boot networkd reads the files on start).
pub fn apply(appliance: &Appliance) -> Result<()> {
    let ifaces = &appliance.interfaces;

    // Map each parent interface to the VLAN child links riding on it.
    let mut children: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for i in ifaces {
        if let (Some(parent), Some(_)) = (&i.parent, i.vlan) {
            children.entry(parent.as_str()).or_default().push(i.name.clone());
        }
    }

    system::ensure_dir(Path::new(NETWORKD_RUNTIME_DIR))?;

    let mut keep: HashSet<String> = HashSet::new();
    let mut writes: Vec<(String, String)> = Vec::new();
    // Files that carry a secret (a WireGuard private key): 0640 root:systemd-network.
    let mut secrets: HashSet<String> = HashSet::new();

    // VLAN .netdev units.
    for i in ifaces {
        if let (Some(_), Some(vlan)) = (&i.parent, i.vlan) {
            let name = netdev_name(&i.name);
            writes.push((name.clone(), netdev_body(&i.name, vlan)));
            keep.insert(name);
        }
    }

    // WireGuard .netdev units (secret — the private key lives here → 0640).
    for i in ifaces {
        if i.is_wireguard() {
            let name = netdev_name(&i.name);
            writes.push((name.clone(), wireguard_netdev_body(i)));
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

    // .network units: anything with an address, a VLAN of its own, child VLANs,
    // a WireGuard link (which needs a `.network` to be brought up even when it
    // carries only AllowedIPs routes and no local address), a bridge/bond device,
    // or a member enslaved to one.
    let reloaded: Vec<String> = ifaces
        .iter()
        .filter(|i| {
            i.address.is_some()
                || i.address6.is_some()
                || (i.parent.is_some() && i.vlan.is_some())
                || i.is_wireguard()
                || i.router_advert.is_some()
                || i.is_virtual_l2()
                || i.master.is_some()
                || i.pd_from.is_some()
                || i.mtu.is_some()
                || i.mac.is_some()
                || children.contains_key(i.name.as_str())
        })
        .map(|i| {
            let kids = children.get(i.name.as_str()).map(Vec::as_slice).unwrap_or(&[]);
            // Resolve a member's `master` to the right networkd directive
            // (`Bridge=`/`Bond=`) by looking up the master's device type.
            let master = i.master.as_deref().and_then(|m| {
                ifaces.iter().find(|d| d.name == m).map(|d| {
                    if d.is_bond() {
                        format!("Bond={m}")
                    } else {
                        format!("Bridge={m}")
                    }
                })
            });
            let pd = i.pd_from.as_deref().map(|up| (up, i.pd_subnet.unwrap_or(0)));
            let name = network_name(&i.name);
            writes.push((
                name.clone(),
                network_body(
                    &i.name,
                    i.address.as_deref(),
                    i.address6.as_deref(),
                    kids,
                    i.dhcp_server.as_ref(),
                    i.router_advert.as_ref(),
                    master.as_deref(),
                    pd,
                    i.mtu,
                    i.mac.as_deref(),
                ),
            ));
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

    // Re-apply live. Non-fatal: networkd may not be up yet at boot, in which
    // case it picks up the files when it starts.
    if let Err(e) = system::networkctl_reload(&reloaded) {
        eprintln!("warning: networkctl reload failed (networkd applies units on start): {e}");
    }

    // The DNS forwarder (systemd-resolved) is reconciled the same way — its
    // runtime drop-in tracks `[services.dns]`, and resolved is restarted to
    // (re)bind the LAN stub listener.
    apply_resolved(appliance)?;
    // The NTP server (chrony) likewise — its confdir drop-in tracks
    // `[services.ntp]`, and chrony is restarted only when that changed.
    apply_chrony(appliance)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_address_renders_address_directive() {
        let u = network_body("eth0", Some("10.0.0.1/24"), None, &[], None, None, None, None, None, None);
        assert!(u.contains("Name=eth0"));
        assert!(u.contains("Address=10.0.0.1/24"));
    }

    #[test]
    fn dhcp_address_renders_dhcp_directive() {
        let u = network_body("eth0", Some("dhcp"), None, &[], None, None, None, None, None, None);
        assert!(u.contains("DHCP=yes"));
        assert!(!u.contains("Address="));
    }

    #[test]
    fn vlan_netdev_declares_kind_and_id() {
        let d = netdev_body("eth1.20", 20);
        assert!(d.contains("Name=eth1.20"));
        assert!(d.contains("Kind=vlan"));
        assert!(d.contains("Id=20"));
        assert_eq!(netdev_name("eth1.20"), "10-sentinel-eth1.20.netdev");
    }

    #[test]
    fn parent_network_references_child_vlans() {
        let u = network_body(
            "eth1",
            Some("10.0.0.1/24"),
            None,
            &["eth1.20".into(), "eth1.30".into()],
            None,
            None,
            None,
            None,
            None,
            None,
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
        };
        let u = network_body("eth1", Some("10.0.0.1/24"), None, &[], Some(&dhcp), None, None, None, None, None);
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
        };
        let u = network_body("eth1", Some("10.0.0.1/24"), None, &[], Some(&dhcp), None, None, None, None, None);
        assert!(u.contains("DHCPServer=yes"));
        assert!(u.contains("[DHCPServer]"));
        assert!(!u.contains("EmitDNS"));
        assert!(!u.contains("DNS="));
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
            private_key: None,
            listen_port: None,
            peers: vec![],
            dhcp_server: None,
            router_advert: None,
            if_type: None,
            master: None,
            bond_mode: None,
            pd_from: None,
            pd_subnet: None,
            mtu: None,
            mac: None,
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
        assert_eq!(ipv4_network("192.168.5.130/26").as_deref(), Some("192.168.5.128/26"));
        assert_eq!(ipv4_network("10.9.9.9/8").as_deref(), Some("10.0.0.0/8"));
        assert_eq!(ipv4_network("dhcp"), None);
    }

    #[test]
    fn dns_forwarder_renders_resolved_dropin() {
        let dns = Dns {
            upstream: vec!["9.9.9.9".into(), "2620:fe::fe".into()],
            serve_on: vec!["lan0".into()],
            dnssec: None,
        };
        let ifaces = vec![Interface {
            name: "lan0".into(),
            zone: Some("lan".into()),
            address: Some("10.0.0.1/24".into()),
            address6: None,
            parent: None,
            vlan: None,
            private_key: None,
            listen_port: None,
            peers: vec![],
            dhcp_server: None,
            router_advert: None,
            if_type: None,
            master: None,
            bond_mode: None,
            pd_from: None,
            pd_subnet: None,
            mtu: None,
            mac: None,
        }];
        let body = resolved_dropin_body(&dns, &ifaces).expect("forwarder configured");
        assert!(body.contains("[Resolve]"));
        assert!(body.contains("DNS=9.9.9.9 2620:fe::fe"));
        // The stub listener binds the serving interface's bare IP, not its CIDR.
        assert!(body.contains("DNSStubListenerExtra=10.0.0.1"));
        assert!(!body.contains("/24"));
        // No explicit DNSSEC ⇒ the appliance default (off).
        assert!(body.contains("DNSSEC=no"));
        // An unconfigured forwarder renders nothing.
        assert!(resolved_dropin_body(&Dns::default(), &ifaces).is_none());
    }

    #[test]
    fn dhcpv6_pd_renders_client_and_delegation() {
        // WAN uplink: DHCPv6 client soliciting up front (no RA needed).
        let wan = network_body("wan0", Some("dhcp"), Some("dhcp"), &[], None, None, None, None, None, None);
        assert!(wan.contains("DHCP=yes")); // v4 dhcp + v6 dhcp
        assert!(wan.contains("[DHCPv6]"));
        assert!(wan.contains("WithoutRA=solicit"));
        // A v6-only DHCPv6 client renders DHCP=ipv6, not yes.
        let wan6 = network_body("wan0", None, Some("dhcp"), &[], None, None, None, None, None, None);
        assert!(wan6.contains("DHCP=ipv6"));
        // LAN downstream: request subnet 2 of the uplink's delegated prefix and
        // advertise it.
        let lan = network_body(
            "lan0",
            Some("10.0.0.1/24"),
            None,
            &[],
            None,
            None,
            None,
            Some(("wan0", 2)),
            None,
            None,
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
            None,
            None,
            None,
            None,
            Some(1492),
            Some("52:54:00:12:34:56"),
        );
        assert!(u.contains("[Link]"));
        assert!(u.contains("MTUBytes=1492"));
        assert!(u.contains("MACAddress=52:54:00:12:34:56"));
        let plain =
            network_body("lan0", Some("10.0.0.1/24"), None, &[], None, None, None, None, None, None);
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
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(u.contains("Address=10.0.0.1/24"));
        assert!(u.contains("Address=2001:db8:1::1/64"));
        // `auto` accepts RAs (SLAAC) instead of binding a static v6 address.
        let a = network_body("wan0", Some("dhcp"), Some("auto"), &[], None, None, None, None, None, None);
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
            private_key: None,
            listen_port: None,
            peers: vec![],
            dhcp_server: None,
            router_advert: None,
            if_type: Some(IfaceType::Bridge),
            master: None,
            bond_mode: None,
            pd_from: None,
            pd_subnet: None,
            mtu: None,
            mac: None,
        };
        let d = virtual_l2_netdev_body(&br);
        assert!(d.contains("Name=br0"));
        assert!(d.contains("Kind=bridge"));
        assert!(!d.contains("[Bond]"));
        // A member's .network carries the Bridge= enslavement in [Network].
        let member = network_body("lan1", None, None, &[], None, None, Some("Bridge=br0"), None, None, None);
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
            private_key: None,
            listen_port: None,
            peers: vec![],
            dhcp_server: None,
            router_advert: None,
            if_type: Some(IfaceType::Bond),
            master: None,
            bond_mode: Some("802.3ad".into()),
            pd_from: None,
            pd_subnet: None,
            mtu: None,
            mac: None,
        };
        let d = virtual_l2_netdev_body(&bond);
        assert!(d.contains("Kind=bond"));
        assert!(d.contains("[Bond]"));
        assert!(d.contains("Mode=802.3ad"));
        let mut b2 = bond.clone();
        b2.bond_mode = None;
        assert!(virtual_l2_netdev_body(&b2).contains("Mode=active-backup"));
        let member = network_body("lan2", None, None, &[], None, None, Some("Bond=bond0"), None, None, None);
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
        let u = network_body("lan0", Some("10.0.0.1/24"), None, &[], None, Some(&ra), None, None, None, None);
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
        };
        let ra = RouterAdvert {
            prefixes: vec!["2001:db8:9::/64".into()],
            dns: vec![],
            managed: false,
            other_config: false,
            router_lifetime: None,
        };
        let u = network_body("lan0", Some("10.0.0.1/24"), None, &[], Some(&dhcp), Some(&ra), None, None, None, None);
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
        use crate::config::WgPeer;
        let iface = Interface {
            name: "wg0".into(),
            zone: Some("lan".into()),
            address: Some("10.9.0.1/24".into()),
            address6: None,
            parent: None,
            vlan: None,
            private_key: Some("ICOioMTTlfQE/2NndOoEntortz+0tZ5Hll0AEM7tdmE=".into()),
            listen_port: Some(51820),
            peers: vec![WgPeer {
                public_key: "ukF+iwo+aai/wm9k1nIlxCBFRnZ+bLPb2xIu4+4PvmQ=".into(),
                allowed_ips: vec!["10.9.0.2/32".into()],
                endpoint: Some("192.0.2.7:51820".into()),
                persistent_keepalive: Some(25),
                preshared_key: None,
            }],
            dhcp_server: None,
            router_advert: None,
            if_type: None,
            master: None,
            bond_mode: None,
            pd_from: None,
            pd_subnet: None,
            mtu: None,
            mac: None,
        };
        let d = wireguard_netdev_body(&iface);
        assert!(d.contains("Kind=wireguard"));
        assert!(d.contains("PrivateKey=ICOioMTTlfQE/2NndOoEntortz+0tZ5Hll0AEM7tdmE="));
        assert!(d.contains("ListenPort=51820"));
        assert!(d.contains("[WireGuardPeer]"));
        assert!(d.contains("PublicKey=ukF+iwo+aai/wm9k1nIlxCBFRnZ+bLPb2xIu4+4PvmQ="));
        assert!(d.contains("AllowedIPs=10.9.0.2/32"));
        assert!(d.contains("Endpoint=192.0.2.7:51820"));
        assert!(d.contains("PersistentKeepalive=25"));
    }
}
