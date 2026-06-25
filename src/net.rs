//! Live L3 addressing via systemd-networkd.
//!
//! Each interface that carries an `address` is rendered to a `.network` unit in
//! networkd's **runtime** dir (`/run/systemd/network`, tmpfs) and networkd is
//! told to re-apply it — so `set interface eth0 address 10.0.0.1/24` configures
//! the NIC immediately, with no rebuild. The units are named so they take
//! precedence over the image defaults, and the boot service re-renders them
//! from the saved config each boot (the same runtime-apply model the hostname
//! uses). Removing an address removes its unit, so the change reconciles both
//! ways.

use std::collections::HashSet;
use std::path::Path;

use anyhow::Result;

use crate::config::Appliance;
use crate::system::{self, NETWORKD_RUNTIME_DIR};

/// Filename prefix for the units we own. The low number sorts ahead of the
/// image/test defaults so our address wins; the marker lets us reconcile
/// (remove ours without touching anyone else's).
const PREFIX: &str = "10-sentinel-";

/// The unit filename for an interface.
fn unit_name(iface: &str) -> String {
    format!("{PREFIX}{iface}.network")
}

/// Render the `.network` unit body binding `address` to `iface`. `"dhcp"` asks
/// networkd to run a DHCP client; anything else is a static CIDR.
fn unit_body(iface: &str, address: &str) -> String {
    let network = if address == "dhcp" {
        "DHCP=yes".to_string()
    } else {
        format!("Address={address}")
    };
    format!("[Match]\nName={iface}\n\n[Network]\n{network}\n")
}

/// Reconcile networkd units to match `appliance`: write a unit for every
/// interface with an address, remove any stale sentinel units, then ask
/// networkd to re-apply. Writing the units is required; the reload is
/// best-effort (at early boot networkd reads the files itself on start).
pub fn apply(appliance: &Appliance) -> Result<()> {
    let desired: Vec<(&str, &str)> = appliance
        .interfaces
        .iter()
        .filter_map(|i| i.address.as_deref().map(|a| (i.name.as_str(), a)))
        .collect();

    system::ensure_dir(Path::new(NETWORKD_RUNTIME_DIR))?;

    // Remove sentinel units no longer wanted (an address was cleared/deleted).
    let keep: HashSet<String> = desired.iter().map(|(n, _)| unit_name(n)).collect();
    if let Ok(entries) = std::fs::read_dir(NETWORKD_RUNTIME_DIR) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(PREFIX) && name.ends_with(".network") && !keep.contains(&name) {
                system::remove_file(&entry.path())?;
            }
        }
    }

    // Write the wanted units.
    for (iface, address) in &desired {
        let path = Path::new(NETWORKD_RUNTIME_DIR).join(unit_name(iface));
        system::install_file(&path, &unit_body(iface, address))?;
    }

    // Re-apply live. Non-fatal: networkd may not be up yet at boot, in which
    // case it picks up the files when it starts.
    let ifaces: Vec<String> = desired.iter().map(|(n, _)| (*n).to_string()).collect();
    if let Err(e) = system::networkctl_reload(&ifaces) {
        eprintln!("warning: networkctl reload failed (networkd applies units on start): {e}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_address_renders_address_directive() {
        let u = unit_body("eth0", "10.0.0.1/24");
        assert!(u.contains("Name=eth0"));
        assert!(u.contains("Address=10.0.0.1/24"));
    }

    #[test]
    fn dhcp_address_renders_dhcp_directive() {
        let u = unit_body("eth0", "dhcp");
        assert!(u.contains("DHCP=yes"));
        assert!(!u.contains("Address="));
    }

    #[test]
    fn unit_name_is_prefixed_and_scoped() {
        assert_eq!(unit_name("eth0"), "10-sentinel-eth0.network");
    }
}
