//! Plan removal/recreation of networkd-owned links. networkd does not remove a
//! kernel device when its .netdev disappears, nor change immutable VLAN/type
//! settings on an existing device. Never infer ownership from a device name
//! alone: only our previously rendered .netdev files authorize retirement.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use anyhow::{Context, Result};
use serde::Deserialize;

/// A single Netlink snapshot, obtained through the appliance's pinned iproute2.
/// Required fields deliberately have no defaults: an unreadable inventory must
/// fail the apply rather than report that the desired state has converged.
#[derive(Debug, Deserialize)]
pub(crate) struct KernelLink {
    ifname: String,
    ifindex: u32,
    mtu: u32,
    flags: Vec<String>,
    master: Option<String>,
    address: Option<String>,
    link: Option<String>,
    link_index: Option<u32>,
    linkinfo: Option<LinkInfo>,
    addr_info: Vec<KernelAddress>,
}

#[derive(Debug, Deserialize)]
struct LinkInfo {
    info_kind: String,
    info_data: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct KernelAddress {
    local: IpAddr,
    prefixlen: u8,
    #[serde(default)]
    dadfailed: bool,
}

pub(crate) fn inventory() -> Result<BTreeMap<String, KernelLink>> {
    let out = crate::system::escalated_output("ip", &["-details", "-json", "address", "show"])?;
    anyhow::ensure!(
        out.status.success(),
        "reading kernel network inventory failed"
    );
    parse_inventory(&out.stdout)
}

fn parse_inventory(bytes: &[u8]) -> Result<BTreeMap<String, KernelLink>> {
    let links: Vec<KernelLink> =
        serde_json::from_slice(bytes).context("parsing kernel network inventory")?;
    let mut inventory = BTreeMap::new();
    for link in links {
        anyhow::ensure!(
            !inventory.contains_key(&link.ifname),
            "duplicate interface {} in kernel inventory",
            link.ifname
        );
        inventory.insert(link.ifname.clone(), link);
    }
    Ok(inventory)
}

/// Inspect mutable state as well as rendered files. Only a drifting link is
/// reconfigured, so a firewall-only commit leaves healthy DHCP leases intact.
pub(crate) fn drifted(
    iface: &crate::config::Interface,
    all: &[crate::config::Interface],
    master: Option<&str>,
    observed: &BTreeMap<String, KernelLink>,
) -> bool {
    let Some(link) = observed.get(&iface.name) else {
        return true;
    };
    if effective_mtu(iface, all).is_some_and(|mtu| u32::from(mtu) != link.mtu)
        || link.master.as_deref() != master
        || link.flags.iter().any(|flag| flag == "UP") == iface.disabled
        || iface.mac.as_ref().is_some_and(|mac| {
            !link
                .address
                .as_ref()
                .is_some_and(|actual| actual.eq_ignore_ascii_case(mac))
        })
    {
        return true;
    }
    if iface.disabled {
        return false;
    }
    [iface.address.as_deref(), iface.address6.as_deref()]
        .into_iter()
        .flatten()
        .filter_map(|cidr| cidr.split_once('/'))
        .any(|(address, prefix)| {
            let desired = address
                .parse::<IpAddr>()
                .ok()
                .zip(prefix.parse::<u8>().ok());
            !link.addr_info.iter().any(|actual| {
                desired == Some((actual.local, actual.prefixlen)) && !actual.dadfailed
            })
        })
}

/// Recover vanished or replaced owned netdevs, including their dependencies.
/// Existing VLAN identifiers, protocols and parents are immutable in networkd;
/// retire them when the actual link no longer matches the unchanged config.
pub(crate) fn retire_drifted(
    previous: &BTreeMap<String, String>,
    ifaces: &[crate::config::Interface],
    observed: &BTreeMap<String, KernelLink>,
    retired: &mut BTreeSet<String>,
) {
    for iface in ifaces {
        let Some(body) = previous.get(&format!("10-sentinel-{}.netdev", iface.name)) else {
            continue;
        };
        let Some(link) = observed.get(&iface.name) else {
            retired.insert(iface.name.clone());
            continue;
        };
        if body
            .lines()
            .find_map(|line| line.strip_prefix("Kind="))
            .is_some_and(|kind| {
                !link
                    .linkinfo
                    .as_ref()
                    .is_some_and(|info| info.info_kind == kind)
            })
        {
            retired.insert(iface.name.clone());
            continue;
        }
        if let Some(id) = iface.vlan {
            let expected_parent = iface.parent.as_ref().and_then(|p| observed.get(p));
            let vlan_matches = link.linkinfo.as_ref().is_some_and(|info| {
                info.info_kind == "vlan"
                    && info.info_data.as_ref().is_some_and(|data| {
                        data["id"].as_u64() == Some(u64::from(id))
                            && data["protocol"].as_str().is_some_and(|protocol| {
                                protocol.eq_ignore_ascii_case(
                                    iface.vlan_protocol.as_deref().unwrap_or("802.1q"),
                                )
                            })
                    })
            });
            let parent_matches = link.link.as_deref() == iface.parent.as_deref()
                || expected_parent.is_some_and(|p| Some(p.ifindex) == link.link_index);
            if !vlan_matches || !parent_matches {
                retired.insert(iface.name.clone());
            }
        }
    }
    include_descendants(previous, retired);
}

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

/// Recreating a VLAN/macvlan/tunnel also requires its unchanged parent to
/// create the replacement link. An unrelated DHCP link is still left alone.
pub(crate) fn recreates_child(
    name: &str,
    desired: &BTreeMap<String, String>,
    retired: &BTreeSet<String>,
) -> bool {
    attachments(desired)
        .iter()
        .any(|(child, parent)| parent == name && retired.contains(child))
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
    include_descendants(previous, &mut retired);
    retired
}

fn include_descendants(previous: &BTreeMap<String, String>, retired: &mut BTreeSet<String>) {
    let old_parents = attachments(previous);
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed_link() -> serde_json::Value {
        serde_json::json!({
            "ifname": "tenant0", "ifindex": 4, "mtu": 1400,
            "flags": ["BROADCAST", "UP"], "link": "eth1",
            "address": "02:00:00:00:00:01",
            "linkinfo": {"info_kind": "vlan", "info_data": {"id": 10, "protocol": "802.1Q"}},
            "addr_info": [
                {"local": "192.0.2.1", "prefixlen": 24},
                {"local": "2001:db8:10::1", "prefixlen": 64, "tentative": true}
            ]
        })
    }

    fn declared_links() -> Vec<crate::config::Interface> {
        toml::from_str::<crate::config::Appliance>(
            r#"
            [system]
            hostname = "test"
            [[interface]]
            name = "eth1"
            mtu = 1400
            [[interface]]
            name = "tenant0"
            parent = "eth1"
            vlan = 10
            address = "192.0.2.1/24"
            address6 = "2001:db8:10::1/64"
        "#,
        )
        .unwrap()
        .interfaces
    }

    fn inventory_from(value: serde_json::Value) -> BTreeMap<String, KernelLink> {
        parse_inventory(&serde_json::to_vec(&vec![value]).unwrap()).unwrap()
    }

    #[test]
    fn observes_mutable_kernel_drift_without_reconfiguring_healthy_links() {
        let ifaces = declared_links();
        let good = observed_link();
        assert!(!drifted(
            &ifaces[1],
            &ifaces,
            None,
            &inventory_from(good.clone())
        ));
        for (field, value) in [
            ("mtu", serde_json::json!(1300)),
            ("master", serde_json::json!("foreign0")),
            ("flags", serde_json::json!(["BROADCAST"])),
            (
                "addr_info",
                serde_json::json!([{ "local": "192.0.2.1", "prefixlen": 24 }]),
            ),
            (
                "addr_info",
                serde_json::json!([{ "local": "2001:db8:10::1", "prefixlen": 64 }]),
            ),
        ] {
            let mut changed = good.clone();
            changed[field] = value;
            assert!(
                drifted(&ifaces[1], &ifaces, None, &inventory_from(changed)),
                "{field}"
            );
        }
        let mut member = good.clone();
        member["master"] = serde_json::json!("br0");
        assert!(!drifted(
            &ifaces[1],
            &ifaces,
            Some("br0"),
            &inventory_from(member)
        ));
        assert!(drifted(
            &ifaces[1],
            &ifaces,
            Some("br0"),
            &inventory_from(good)
        ));
    }

    #[test]
    fn dynamic_addresses_do_not_need_a_static_lease_to_converge() {
        let mut ifaces = declared_links();
        ifaces[1].address = Some("dhcp".into());
        ifaces[1].address6 = Some("auto".into());
        let mut link = observed_link();
        link["addr_info"] = serde_json::json!([]);
        assert!(!drifted(&ifaces[1], &ifaces, None, &inventory_from(link)));
    }

    #[test]
    fn missing_and_replaced_owned_vlans_require_parent_reconfiguration() {
        let ifaces = declared_links();
        let previous = BTreeMap::from([
            (
                "10-sentinel-tenant0.netdev".into(),
                "Kind=vlan\nId=10\n".into(),
            ),
            ("10-sentinel-eth1.network".into(), "VLAN=tenant0\n".into()),
            (
                "10-sentinel-inner.netdev".into(),
                "Kind=vlan\nId=20\n".into(),
            ),
            ("10-sentinel-tenant0.network".into(), "VLAN=inner\n".into()),
        ]);
        let mut retired = BTreeSet::new();
        retire_drifted(
            &previous,
            &ifaces,
            &inventory_from(observed_link()),
            &mut retired,
        );
        assert!(retired.is_empty());
        for field in ["missing", "id", "parent", "protocol", "kind"] {
            let mut wrong = observed_link();
            match field {
                "id" => wrong["linkinfo"]["info_data"]["id"] = serde_json::json!(99),
                "parent" => wrong["link"] = serde_json::json!("eth2"),
                "protocol" => {
                    wrong["linkinfo"]["info_data"]["protocol"] = serde_json::json!("802.1ad")
                }
                "kind" => wrong["linkinfo"]["info_kind"] = serde_json::json!("dummy"),
                _ => {}
            }
            let observed = if field == "missing" {
                BTreeMap::new()
            } else {
                inventory_from(wrong)
            };
            retired.clear();
            retire_drifted(&previous, &ifaces, &observed, &mut retired);
            assert_eq!(retired, BTreeSet::from(["tenant0".into(), "inner".into()]));
            assert!(recreates_child("eth1", &previous, &retired));
            retired.clear();
            retire_drifted(&BTreeMap::new(), &ifaces, &observed, &mut retired);
            assert!(retired.is_empty(), "unowned devices cannot be retired");
        }
    }

    #[test]
    fn malformed_or_ambiguous_kernel_inventory_is_an_error() {
        assert!(parse_inventory(b"not-json").is_err());
        assert!(parse_inventory(br#"[{"ifname":"eth1"}]"#).is_err());
        assert!(
            parse_inventory(&serde_json::to_vec(&vec![observed_link(), observed_link()]).unwrap())
                .is_err()
        );
    }

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

#[cfg(test)]
mod recreation_tests {
    use super::*;
    #[test]
    fn recreating_a_vlan_reconfigures_its_unchanged_parent_only() {
        let desired = BTreeMap::from([
            (
                "10-sentinel-eth1.network".into(),
                "[Network]\nVLAN=tenant0\n".into(),
            ),
            (
                "10-sentinel-tenant0.network".into(),
                "[Network]\nAddress=192.0.2.2/24\n".into(),
            ),
            (
                "10-sentinel-tenant0.netdev".into(),
                "[NetDev]\nName=tenant0\nKind=vlan\n[VLAN]\nId=20\n".into(),
            ),
            (
                "10-sentinel-wan0.network".into(),
                "[Network]\nDHCP=ipv4\n".into(),
            ),
        ]);
        let mut previous = desired.clone();
        previous.insert(
            "10-sentinel-tenant0.netdev".into(),
            "[NetDev]\nName=tenant0\nKind=vlan\n[VLAN]\nId=10\n".into(),
        );
        let retired = retire(&previous, &desired);
        assert!(retired.contains("tenant0"));
        assert!(!network_changed("eth1", &previous, &desired));
        assert!(recreates_child("eth1", &desired, &retired));
        assert!(!recreates_child("wan0", &desired, &retired));
        assert!(!network_changed("wan0", &previous, &desired));
        assert!(!recreates_child("eth1", &desired, &BTreeSet::new()));
    }
}
