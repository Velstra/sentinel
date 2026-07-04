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
use std::path::Path;

use anyhow::Result;

use crate::config::{Appliance, DhcpServer, Dns, Interface, RouterAdvert};
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
fn network_body(
    iface: &str,
    address: Option<&str>,
    vlan_children: &[String],
    dhcp: Option<&DhcpServer>,
    ra: Option<&RouterAdvert>,
) -> String {
    let mut body = format!("[Match]\nName={iface}\n\n[Network]\n");
    match address {
        Some("dhcp") => body.push_str("DHCP=yes\n"),
        Some(addr) => body.push_str(&format!("Address={addr}\n")),
        None => {}
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

    // .network units: anything with an address, a VLAN of its own, child VLANs,
    // or a WireGuard link (which needs a `.network` to be brought up even when it
    // carries only AllowedIPs routes and no local address).
    let reloaded: Vec<String> = ifaces
        .iter()
        .filter(|i| {
            i.address.is_some()
                || (i.parent.is_some() && i.vlan.is_some())
                || i.is_wireguard()
                || i.router_advert.is_some()
                || children.contains_key(i.name.as_str())
        })
        .map(|i| {
            let kids = children.get(i.name.as_str()).map(Vec::as_slice).unwrap_or(&[]);
            let name = network_name(&i.name);
            writes.push((
                name.clone(),
                network_body(
                    &i.name,
                    i.address.as_deref(),
                    kids,
                    i.dhcp_server.as_ref(),
                    i.router_advert.as_ref(),
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
    // runtime drop-in tracks `[dns]`, and resolved is restarted to (re)bind the
    // LAN stub listener.
    apply_resolved(appliance)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_address_renders_address_directive() {
        let u = network_body("eth0", Some("10.0.0.1/24"), &[], None, None);
        assert!(u.contains("Name=eth0"));
        assert!(u.contains("Address=10.0.0.1/24"));
    }

    #[test]
    fn dhcp_address_renders_dhcp_directive() {
        let u = network_body("eth0", Some("dhcp"), &[], None, None);
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
            &["eth1.20".into(), "eth1.30".into()],
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
        let u = network_body("eth1", Some("10.0.0.1/24"), &[], Some(&dhcp), None);
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
        let u = network_body("eth1", Some("10.0.0.1/24"), &[], Some(&dhcp), None);
        assert!(u.contains("DHCPServer=yes"));
        assert!(u.contains("[DHCPServer]"));
        assert!(!u.contains("EmitDNS"));
        assert!(!u.contains("DNS="));
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
            parent: None,
            vlan: None,
            private_key: None,
            listen_port: None,
            peers: vec![],
            dhcp_server: None,
            router_advert: None,
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
    fn router_advert_renders_send_ra_prefix_and_dns() {
        let ra = RouterAdvert {
            prefixes: vec!["2001:db8:1::/64".into()],
            dns: vec!["2001:db8:1::1".into()],
            managed: false,
            other_config: true,
            router_lifetime: Some(1800),
        };
        let u = network_body("lan0", Some("10.0.0.1/24"), &[], None, Some(&ra));
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
        let u = network_body("lan0", Some("10.0.0.1/24"), &[], Some(&dhcp), Some(&ra));
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
