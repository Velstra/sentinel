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

use crate::config::Appliance;
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

    // VLAN .netdev units.
    for i in ifaces {
        if let (Some(_), Some(vlan)) = (&i.parent, i.vlan) {
            let name = netdev_name(&i.name);
            writes.push((name.clone(), netdev_body(&i.name, vlan)));
            keep.insert(name);
        }
    }

    // .network units: anything with an address, a VLAN of its own, or child VLANs.
    let reloaded: Vec<String> = ifaces
        .iter()
        .filter(|i| {
            i.address.is_some()
                || (i.parent.is_some() && i.vlan.is_some())
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

    // Write the wanted units.
    for (name, body) in &writes {
        system::install_file(&Path::new(NETWORKD_RUNTIME_DIR).join(name), body)?;
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
}
