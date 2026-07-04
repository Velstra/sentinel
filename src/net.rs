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

use crate::config::{Appliance, Interface};
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
/// installed mode 0600 by [`apply`].
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
fn network_body(iface: &str, address: Option<&str>, vlan_children: &[String]) -> String {
    let mut body = format!("[Match]\nName={iface}\n\n[Network]\n");
    match address {
        Some("dhcp") => body.push_str("DHCP=yes\n"),
        Some(addr) => body.push_str(&format!("Address={addr}\n")),
        None => {}
    }
    for child in vlan_children {
        body.push_str(&format!("VLAN={child}\n"));
    }
    body
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
    // Files that carry a secret (a WireGuard private key) and must be 0600.
    let mut secrets: HashSet<String> = HashSet::new();

    // VLAN .netdev units.
    for i in ifaces {
        if let (Some(_), Some(vlan)) = (&i.parent, i.vlan) {
            let name = netdev_name(&i.name);
            writes.push((name.clone(), netdev_body(&i.name, vlan)));
            keep.insert(name);
        }
    }

    // WireGuard .netdev units (secret — the private key lives here → 0600).
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
                || children.contains_key(i.name.as_str())
        })
        .map(|i| {
            let kids = children.get(i.name.as_str()).map(Vec::as_slice).unwrap_or(&[]);
            let name = network_name(&i.name);
            writes.push((name.clone(), network_body(&i.name, i.address.as_deref(), kids)));
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_address_renders_address_directive() {
        let u = network_body("eth0", Some("10.0.0.1/24"), &[]);
        assert!(u.contains("Name=eth0"));
        assert!(u.contains("Address=10.0.0.1/24"));
    }

    #[test]
    fn dhcp_address_renders_dhcp_directive() {
        let u = network_body("eth0", Some("dhcp"), &[]);
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
        let u = network_body("eth1", Some("10.0.0.1/24"), &["eth1.20".into(), "eth1.30".into()]);
        assert!(u.contains("VLAN=eth1.20"));
        assert!(u.contains("VLAN=eth1.30"));
    }

    #[test]
    fn unit_name_is_prefixed_and_scoped() {
        assert_eq!(network_name("eth0"), "10-sentinel-eth0.network");
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
