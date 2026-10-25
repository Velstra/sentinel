//! Plan removal/recreation of networkd-owned links. networkd does not remove a
//! kernel device when its .netdev disappears, nor change immutable VLAN/type
//! settings on an existing device. Never infer ownership from a device name
//! alone: only our previously rendered .netdev files authorize retirement.

use std::collections::{BTreeMap, BTreeSet};

/// An omitted MTU is a desired default, not "keep the last configured value".
/// Ethernet defaults to 1500, VLANs inherit their parent and bridges use the
/// smallest member MTU. Do not consult current runtime MTUs: doing so would
/// preserve a previously configured value after deleting it from the config.
pub(crate) fn effective_mtu(
    iface: &crate::config::Interface,
    all: &[crate::config::Interface],
) -> Option<u16> {
    fn resolve(
        iface: &crate::config::Interface,
        all: &[crate::config::Interface],
        depth: usize,
    ) -> Option<u16> {
        if let Some(mtu) = iface.mtu {
            return Some(mtu);
        }
        if depth > all.len() {
            return None;
        }
        if iface.is_wireguard() {
            return Some(1420);
        }
        if iface.vlan.is_some() {
            return iface
                .parent
                .as_ref()
                .and_then(|name| all.iter().find(|i| &i.name == name))
                .and_then(|parent| resolve(parent, all, depth + 1));
        }
        if iface.is_virtual_l2() && !iface.members.is_empty() {
            return iface
                .members
                .iter()
                .filter_map(|name| all.iter().find(|i| &i.name == name))
                .filter_map(|member| resolve(member, all, depth + 1))
                .min();
        }
        if iface.is_tunnel() || iface.is_pppoe() || iface.is_macsec() {
            None
        } else {
            Some(1500)
        }
    }
    resolve(iface, all, 0)
}

/// A firewall-only commit must not discard an unchanged DHCP lease.
pub(crate) fn network_changed(
    name: &str,
    previous: &BTreeMap<String, String>,
    desired: &BTreeMap<String, String>,
) -> bool {
    ["network", "netdev", "link"].iter().any(|kind| {
        let file = format!("10-sentinel-{name}.{kind}");
        previous.get(&file) != desired.get(&file)
    })
}

fn device_name(file: &str) -> Option<&str> {
    let name = file.strip_prefix("10-sentinel-")?.strip_suffix(".netdev")?;
    (!name.is_empty()
        && name.len() <= 15
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c)))
    .then_some(name)
}

fn attachments(files: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (file, body) in files {
        let Some(parent) = file
            .strip_prefix("10-sentinel-")
            .and_then(|s| s.strip_suffix(".network"))
        else {
            continue;
        };
        for line in body.lines() {
            if let Some((key, child)) = line.split_once('=') {
                if matches!(key, "VLAN" | "MACVLAN" | "MACsec" | "Tunnel") {
                    out.insert(child.to_string(), parent.to_string());
                }
            }
        }
    }
    out
}

pub(crate) fn retire(
    previous: &BTreeMap<String, String>,
    desired: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    let old_parents = attachments(previous);
    let new_parents = attachments(desired);
    let mut retired = BTreeSet::new();
    for (file, body) in previous {
        let Some(name) = device_name(file) else {
            continue;
        };
        if desired.get(file) != Some(body) || old_parents.get(name) != new_parents.get(name) {
            retired.insert(name.to_string());
        }
    }
    // Deleting a parent deletes its VLAN/macvlan children in the kernel too.
    // Include those descendants even if their own netdev file is unchanged.
    loop {
        let before = retired.len();
        for (child, parent) in &old_parents {
            if retired.contains(parent)
                && previous.contains_key(&format!("10-sentinel-{child}.netdev"))
            {
                retired.insert(child.clone());
            }
        }
        if before == retired.len() {
            break;
        }
    }
    retired
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mtu_does_not_retain_removed_overrides() {
        let appliance: crate::config::Appliance = toml::from_str(
            r#"
            [system]
            hostname = "test"
            [[interface]]
            name = "eth0"
            mtu = 1400
            [[interface]]
            name = "vlan10"
            parent = "eth0"
            vlan = 10
        "#,
        )
        .unwrap();
        let mut ifaces = appliance.interfaces;
        assert_eq!(effective_mtu(&ifaces[1], &ifaces), Some(1400));
        ifaces[0].mtu = None;
        assert_eq!(effective_mtu(&ifaces[0], &ifaces), Some(1500));
        assert_eq!(effective_mtu(&ifaces[1], &ifaces), Some(1500));
    }

    #[test]
    fn retire_changes_and_deletions_but_never_physical_links() {
        let old = BTreeMap::from([
            (
                "10-sentinel-eth0.network".into(),
                "Address=192.0.2.1/24\nVLAN=vlan10\n".into(),
            ),
            (
                "10-sentinel-vlan10.netdev".into(),
                "Kind=vlan\nId=10\n".into(),
            ),
            ("10-sentinel-br0.netdev".into(), "Kind=bridge\n".into()),
        ]);
        assert!(retire(&old, &old).is_empty());
        let mut desired = old.clone();
        desired.remove("10-sentinel-br0.netdev");
        desired.insert(
            "10-sentinel-vlan10.netdev".into(),
            "Kind=vlan\nId=20\n".into(),
        );
        assert_eq!(
            retire(&old, &desired),
            BTreeSet::from(["br0".into(), "vlan10".into()])
        );
        assert_eq!(
            retire(&old, &BTreeMap::new()),
            BTreeSet::from(["br0".into(), "vlan10".into()])
        );
    }

    #[test]
    fn moving_a_vlan_to_another_parent_recreates_it_even_with_the_same_tag() {
        let old = BTreeMap::from([
            ("10-sentinel-eth0.network".into(), "VLAN=vlan10\n".into()),
            (
                "10-sentinel-vlan10.netdev".into(),
                "Kind=vlan\nId=10\n".into(),
            ),
        ]);
        let mut desired = old.clone();
        desired.remove("10-sentinel-eth0.network");
        desired.insert("10-sentinel-eth1.network".into(), "VLAN=vlan10\n".into());
        assert_eq!(retire(&old, &desired), BTreeSet::from(["vlan10".into()]));
    }

    #[test]
    fn recreating_a_parent_includes_its_unchanged_descendants() {
        let old = BTreeMap::from([
            ("10-sentinel-svlan.netdev".into(), "Id=100\n".into()),
            ("10-sentinel-svlan.network".into(), "VLAN=cvlan\n".into()),
            ("10-sentinel-cvlan.netdev".into(), "Id=200\n".into()),
        ]);
        let mut desired = old.clone();
        desired.insert("10-sentinel-svlan.netdev".into(), "Id=101\n".into());
        assert_eq!(
            retire(&old, &desired),
            BTreeSet::from(["svlan".into(), "cvlan".into()])
        );
    }
}

#[cfg(test)]
mod lease_tests {
    use super::*;
    #[test]
    fn only_changed_link_units_require_reconfiguration() {
        let previous = BTreeMap::from([
            (
                "10-sentinel-wan0.network".into(),
                "[Network]\nDHCP=ipv4\n".into(),
            ),
            (
                "10-sentinel-lan0.network".into(),
                "[Network]\nAddress=192.0.2.1/24\n".into(),
            ),
        ]);
        assert!(!network_changed("wan0", &previous, &previous));
        let mut desired = previous.clone();
        desired.insert(
            "10-sentinel-lan0.network".into(),
            "[Network]\nAddress=192.0.2.2/24\n".into(),
        );
        assert!(!network_changed("wan0", &previous, &desired));
        assert!(network_changed("lan0", &previous, &desired));
        desired.insert(
            "10-sentinel-wan0.link".into(),
            "[Link]\nMTUBytes=1400\n".into(),
        );
        assert!(network_changed("wan0", &previous, &desired));
    }
}
