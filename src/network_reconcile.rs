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
    /// A finite lifetime: a DHCP lease, SLAAC, a delegated prefix. Somebody
    /// is managing it, so it is never treated as an out-of-band address.
    #[serde(default)]
    dynamic: bool,
    /// `global`, `link`, `host`. Absent is read as global, the strict side.
    #[serde(default)]
    scope: Option<String>,
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

/// Static, global addresses on a declared link that the configuration does not
/// put there: added by hand, or left behind by an earlier configuration with a
/// different prefix length.
///
/// Drift used to be one-sided — a *missing* address was repaired, an *extra* one
/// survived every commit, and with it whatever it made the box reachable as.
/// Excluded: addresses with a finite lifetime (leases, SLAAC, delegated
/// prefixes — each has its own manager), link-local scope, `tolerated` (the
/// virtual addresses the routing daemon adds and removes as mastership moves),
/// and every address of a family whose addresses something else assigns: a
/// DHCP/SLAAC family, a prefix-delegation downstream, and the router's own
/// address out of each prefix it advertises (networkd's `Assign=yes`, which
/// carries no lifetime). A disabled link is down and left alone, as is one the
/// kernel does not have.
pub(crate) fn foreign_addresses(
    iface: &crate::config::Interface,
    observed: &BTreeMap<String, KernelLink>,
    tolerated: &[IpAddr],
) -> Vec<(IpAddr, u8)> {
    if iface.disabled || iface.is_pppoe() {
        return Vec::new();
    }
    let Some(link) = observed.get(&iface.name) else {
        return Vec::new();
    };
    let desired: Vec<(IpAddr, u8)> = [iface.address.as_deref(), iface.address6.as_deref()]
        .into_iter()
        .flatten()
        .filter_map(|cidr| cidr.split_once('/'))
        .filter_map(|(address, prefix)| Some((address.parse().ok()?, prefix.parse().ok()?)))
        .collect();
    let leased_v4 = iface.address.as_deref() == Some("dhcp");
    let leased_v6 =
        matches!(iface.address6.as_deref(), Some("auto" | "dhcp")) || iface.pd_from.is_some();
    let advertised: Vec<&str> = iface
        .router_advert
        .iter()
        .flat_map(|ra| ra.prefixes.iter().map(String::as_str))
        .collect();
    link.addr_info
        .iter()
        .filter(|a| !a.dynamic && a.scope.as_deref().is_none_or(|s| s == "global"))
        .filter(|a| match a.local {
            IpAddr::V4(_) => !leased_v4,
            IpAddr::V6(_) => {
                !leased_v6 && !advertised.iter().any(|prefix| in_prefix(a.local, prefix))
            }
        })
        .map(|a| (a.local, a.prefixlen))
        .filter(|found| !desired.contains(found) && !tolerated.contains(&found.0))
        .collect()
}

/// Whether `address` lies inside `cidr`. A malformed prefix contains nothing.
fn in_prefix(address: IpAddr, cidr: &str) -> bool {
    let Some((network, len)) = cidr.split_once('/') else {
        return false;
    };
    let (Ok(network), Ok(len)) = (network.parse::<IpAddr>(), len.parse::<u32>()) else {
        return false;
    };
    match (address, network) {
        (IpAddr::V4(a), IpAddr::V4(n)) if len <= 32 => {
            let mask = u32::MAX.checked_shl(32 - len).unwrap_or(0);
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) if len <= 128 => {
            let mask = u128::MAX.checked_shl(128 - len).unwrap_or(0);
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

/// Physical links whose unit this configuration no longer renders.
///
/// networkd stops managing a link when its `.network` goes away, and stopping
/// is all it does: the addresses stay, the link stays up, and the data plane —
/// which only attaches to declared interfaces — no longer filters it. A device
/// of our own (a `.netdev`) is deleted by retirement instead; this is for the
/// hardware, which can only be emptied and taken down.
pub(crate) fn released_links(
    previous: &BTreeMap<String, String>,
    desired: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    previous
        .keys()
        .filter(|file| !desired.contains_key(*file))
        .filter_map(|file| file.strip_prefix("10-sentinel-")?.strip_suffix(".network"))
        .filter(|name| device_name(&format!("10-sentinel-{name}.netdev")).is_some())
        .filter(|name| !previous.contains_key(&format!("10-sentinel-{name}.netdev")))
        .map(str::to_string)
        .collect()
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
            && !(*kind == "netdev" && wireguard_in_place(previous.get(&file), desired.get(&file)))
    })
}

/// The `[NetDev]` section of a rendered `.netdev`: what makes the device the
/// device (its name and kind). Everything after it configures the device.
fn netdev_identity(body: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for line in body.lines() {
        if line.starts_with('[') {
            inside = line.trim() == "[NetDev]";
        }
        if inside {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Whether a changed WireGuard `.netdev` can be applied to the live device.
///
/// A WireGuard link's key, listen port and peers are all settable on an
/// existing device (`wg syncconf`), and recreating it for them drops the
/// tunnel's addresses, routes and data-plane hooks along with the link — so a
/// peer edit used to cut the whole VPN. (Peer sessions are reset either way:
/// networkd re-applies a changed `.netdev` replacing every peer, and the peers
/// handshake again.) Only a change to the device's identity, its `[NetDev]`
/// section, still needs a new device.
fn wireguard_in_place(previous: Option<&String>, desired: Option<&String>) -> bool {
    let (Some(previous), Some(desired)) = (previous, desired) else {
        return false;
    };
    let identity = netdev_identity(previous);
    identity == netdev_identity(desired)
        && identity.lines().any(|line| line.trim() == "Kind=wireguard")
}

/// WireGuard devices whose configuration changed in a way the live device can
/// take: they are kept, and their new key/port/peer set is synced onto them.
pub(crate) fn wireguard_updates(
    previous: &BTreeMap<String, String>,
    desired: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    previous
        .iter()
        .filter_map(|(file, body)| {
            let name = device_name(file)?;
            let wanted = desired.get(file)?;
            (wanted != body && wireguard_in_place(Some(body), Some(wanted)))
                .then(|| name.to_string())
        })
        .collect()
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
        let replaced =
            desired.get(file) != Some(body) && !wireguard_in_place(Some(body), desired.get(file));
        if replaced || old_parents.get(name) != new_parents.get(name) {
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

#[cfg(test)]
mod wireguard_tests {
    use super::*;

    fn wg(peers: &str, port: u16) -> String {
        format!(
            "[NetDev]\nName=wg0\nKind=wireguard\n\n[WireGuard]\nPrivateKey=priv\n\
             ListenPort={port}\n{peers}"
        )
    }

    const PEER_A: &str = "\n[WireGuardPeer]\nPublicKey=a\nAllowedIPs=10.8.0.2/32\n";
    const PEER_B: &str = "\n[WireGuardPeer]\nPublicKey=b\nAllowedIPs=10.8.0.3/32\n";

    fn files(netdev: String) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("10-sentinel-wg0.netdev".into(), netdev),
            (
                "10-sentinel-wg0.network".into(),
                "[Network]\nAddress=10.8.0.1/24\n".into(),
            ),
        ])
    }

    /// Deleting wg0 to add, change or remove a peer drops every other peer's
    /// session and takes the tunnel's routes down with the link — for an edit
    /// the kernel can apply in place.
    #[test]
    fn a_peer_edit_updates_wireguard_in_place_instead_of_recreating_it() {
        let previous = files(wg(PEER_A, 51820));
        for desired in [
            files(wg(&format!("{PEER_A}{PEER_B}"), 51820)),
            files(wg("", 51820)),
            files(wg(&PEER_A.replace("10.8.0.2/32", "10.8.0.0/24"), 51820)),
            files(wg(PEER_A, 51821)),
            files(wg(PEER_A, 51820).replace("PrivateKey=priv", "PrivateKey=other")),
        ] {
            assert!(retire(&previous, &desired).is_empty(), "{desired:?}");
            assert!(!network_changed("wg0", &previous, &desired), "{desired:?}");
            assert_eq!(
                wireguard_updates(&previous, &desired),
                BTreeSet::from(["wg0".to_string()])
            );
        }
        assert!(wireguard_updates(&previous, &previous).is_empty());
    }

    #[test]
    fn a_new_device_identity_still_recreates_it() {
        let previous = files(wg(PEER_A, 51820));
        for desired in [
            files(wg(PEER_A, 51820).replace("Kind=wireguard", "Kind=dummy")),
            files(wg(PEER_A, 51820).replace("[NetDev]\n", "[NetDev]\nMTUBytes=1300\n")),
        ] {
            assert_eq!(
                retire(&previous, &desired),
                BTreeSet::from(["wg0".to_string()]),
                "{desired:?}"
            );
            assert!(wireguard_updates(&previous, &desired).is_empty());
        }
        // Removed altogether: retired, and nothing left to update.
        let mut gone = previous.clone();
        gone.remove("10-sentinel-wg0.netdev");
        assert_eq!(
            retire(&previous, &gone),
            BTreeSet::from(["wg0".to_string()])
        );
        assert!(wireguard_updates(&previous, &gone).is_empty());
    }
}

#[cfg(test)]
mod foreign_address_tests {
    use super::*;

    fn lan() -> Vec<crate::config::Interface> {
        toml::from_str::<crate::config::Appliance>(
            r#"
            [system]
            hostname = "test"
            [[interface]]
            name = "lan0"
            address = "192.0.2.1/24"
            address6 = "2001:db8:10::1/64"
            [[interface]]
            name = "wan0"
            address = "dhcp"
        "#,
        )
        .unwrap()
        .interfaces
    }

    fn link(name: &str, addresses: serde_json::Value) -> BTreeMap<String, KernelLink> {
        let value = serde_json::json!({
            "ifname": name, "ifindex": 4, "mtu": 1500, "flags": ["UP"],
            "addr_info": addresses,
        });
        parse_inventory(&serde_json::to_vec(&vec![value]).unwrap()).unwrap()
    }

    /// An address somebody added by hand is not configuration. Convergence used
    /// to look only for missing addresses, so an out-of-band one survived every
    /// commit — and with it whatever it made the box reachable as.
    #[test]
    fn an_out_of_band_static_address_is_found() {
        let ifaces = lan();
        let observed = link(
            "lan0",
            serde_json::json!([
                {"local": "192.0.2.1", "prefixlen": 24, "scope": "global"},
                {"local": "2001:db8:10::1", "prefixlen": 64, "scope": "global"},
                {"local": "198.51.100.7", "prefixlen": 32, "scope": "global"},
                {"local": "2001:db8:99::7", "prefixlen": 64, "scope": "global"},
                // Not foreign: link-local, a lease/SLAAC (finite lifetime),
                // the group's virtual address, and the same address with a
                // different prefix length (that is a changed one, so it goes).
                {"local": "fe80::1", "prefixlen": 64, "scope": "link"},
                {"local": "2001:db8:10::abcd", "prefixlen": 64, "scope": "global", "dynamic": true},
                {"local": "192.0.2.254", "prefixlen": 24, "scope": "global"},
                {"local": "192.0.2.1", "prefixlen": 16, "scope": "global"}
            ]),
        );
        let vip: IpAddr = "192.0.2.254".parse().unwrap();
        let mut found = foreign_addresses(&ifaces[0], &observed, &[vip]);
        found.sort();
        let mut want: Vec<(IpAddr, u8)> = vec![
            ("198.51.100.7".parse().unwrap(), 32),
            ("2001:db8:99::7".parse().unwrap(), 64),
            ("192.0.2.1".parse().unwrap(), 16),
        ];
        want.sort();
        assert_eq!(found, want);
    }

    /// networkd's `Assign=yes` gives the router an address out of each prefix
    /// it advertises, with no lifetime — permanent, global, and not in the
    /// configuration. Removing it every commit would be a flap, not a repair.
    #[test]
    fn addresses_another_manager_assigns_are_not_foreign() {
        let mut ifaces = lan();
        ifaces[0].router_advert = Some(crate::config::RouterAdvert {
            prefixes: vec!["2001:db8:9::/64".into()],
            dns: vec![],
            managed: false,
            other_config: false,
            router_lifetime: None,
            dhcp6_pool: None,
        });
        let observed = link(
            "lan0",
            serde_json::json!([
                {"local": "2001:db8:9::5054:ff:fe12:3456", "prefixlen": 64, "scope": "global"},
                {"local": "2001:db8:99::7", "prefixlen": 64, "scope": "global"}
            ]),
        );
        assert_eq!(
            foreign_addresses(&ifaces[0], &observed, &[]),
            vec![("2001:db8:99::7".parse().unwrap(), 64)]
        );
        ifaces[0].address6 = Some("auto".into());
        assert!(foreign_addresses(&ifaces[0], &observed, &[]).is_empty());
        // A permanent lease (infinite lifetime) on a DHCP link is still a lease.
        let lease = link(
            "wan0",
            serde_json::json!([{"local": "203.0.113.9", "prefixlen": 24, "scope": "global"}]),
        );
        assert!(foreign_addresses(&ifaces[1], &lease, &[]).is_empty());
    }

    #[test]
    fn a_dhcp_link_keeps_its_lease_and_a_disabled_or_absent_one_is_left_alone() {
        let mut ifaces = lan();
        let lease = link(
            "wan0",
            serde_json::json!([{"local": "203.0.113.9", "prefixlen": 24, "scope": "global", "dynamic": true}]),
        );
        assert!(foreign_addresses(&ifaces[1], &lease, &[]).is_empty());
        let static_extra = link(
            "lan0",
            serde_json::json!([{"local": "198.51.100.7", "prefixlen": 32, "scope": "global"}]),
        );
        assert_eq!(foreign_addresses(&ifaces[0], &static_extra, &[]).len(), 1);
        ifaces[0].disabled = true;
        assert!(foreign_addresses(&ifaces[0], &static_extra, &[]).is_empty());
        assert!(foreign_addresses(&ifaces[1], &static_extra, &[]).is_empty());
    }

    /// A NIC taken out of the configuration loses its unit, and networkd then
    /// leaves the link exactly as it was — addressed, up, and with no firewall
    /// hook, because the data plane only attaches to declared interfaces.
    #[test]
    fn a_physical_link_removed_from_the_config_is_released() {
        let previous = BTreeMap::from([
            ("10-sentinel-eth0.network".into(), "[Network]\n".into()),
            ("10-sentinel-eth1.network".into(), "[Network]\n".into()),
            ("10-sentinel-vlan10.network".into(), "[Network]\n".into()),
            ("10-sentinel-vlan10.netdev".into(), "[NetDev]\n".into()),
        ]);
        let mut desired = previous.clone();
        desired.remove("10-sentinel-eth1.network");
        desired.remove("10-sentinel-vlan10.network");
        desired.remove("10-sentinel-vlan10.netdev");
        // vlan10 is a device of ours: retirement deletes it. eth1 is hardware.
        assert_eq!(
            released_links(&previous, &desired),
            BTreeSet::from(["eth1".to_string()])
        );
        assert!(released_links(&previous, &previous).is_empty());
    }
}
