//! VLAN device ownership and immutable-link reconciliation.
//!
//! networkd owns addressing, DHCP, bridge membership and link tunables. Sentinel
//! owns VLAN creation/removal because a networkd reload cannot replace an ID,
//! parent or TPID. New links are DOWN until their current ifindex has policy.
//! The caller holds the appliance apply lock, including boot and rollback.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::config::{Appliance, validate_iface_name};
use crate::system;

const JOURNAL: &str = "/var/lib/sentinel/managed-vlans.json";
const WAIT: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    parent: String,
    id: u16,
    protocol: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    // IFLA_GROUP is installed by RTM_NEWLINK before registration, unlike an
    // alias. It identifies even a link left by a crash before the alias write.
    group: u32,
    alias: String,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    owners: BTreeMap<String, Owner>,
}

#[derive(Clone, Debug, Deserialize)]
struct Link {
    ifname: String,
    ifindex: u32,
    #[serde(default)]
    link: Option<String>,
    #[serde(default)]
    group: serde_json::Value,
    #[serde(default)]
    ifalias: String,
    #[serde(default)]
    flags: Vec<String>,
    #[serde(default)]
    linkinfo: serde_json::Value,
    #[serde(default)]
    link_netnsid: Option<i32>,
}

fn protocol(value: &str) -> Option<&'static str> {
    match value.to_ascii_lowercase().as_str() {
        "802.1q" | "[33024]" => Some("802.1q"),
        "802.1ad" | "[34984]" => Some("802.1ad"),
        _ => None,
    }
}

fn number(value: &serde_json::Value) -> Option<u32> {
    value
        .as_u64()
        .and_then(|n| n.try_into().ok())
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
}

impl Link {
    fn spec(&self) -> Option<Spec> {
        if self.linkinfo["info_kind"] != "vlan" || self.link_netnsid.is_some() {
            return None;
        }
        let data = &self.linkinfo["info_data"];
        Some(Spec {
            parent: self.link.clone()?,
            id: data["id"].as_u64()?.try_into().ok()?,
            protocol: protocol(data["protocol"].as_str()?)?.to_owned(),
        })
    }

    fn owned_by(&self, owner: &Owner) -> bool {
        self.spec().is_some()
            && number(&self.group) == Some(owner.group)
            && (self.ifalias.is_empty() || self.ifalias == owner.alias)
    }

    fn up(&self) -> bool {
        self.flags.iter().any(|flag| flag == "UP")
    }
}

fn links() -> Result<BTreeMap<String, Link>> {
    let output = system::ip_link_list()?;
    let links: Vec<Link> =
        serde_json::from_str(&output).context("decoding actual network links")?;
    Ok(links
        .into_iter()
        .map(|link| (link.ifname.clone(), link))
        .collect())
}

fn desired(appliance: &Appliance) -> BTreeMap<String, Spec> {
    appliance
        .interfaces
        .iter()
        .filter_map(|iface| {
            Some((
                iface.name.clone(),
                Spec {
                    parent: iface.parent.clone()?,
                    id: iface.vlan?,
                    protocol: iface
                        .vlan_protocol
                        .as_deref()
                        .unwrap_or("802.1q")
                        .to_owned(),
                },
            ))
        })
        .collect()
}

fn decode_journal(bytes: &str) -> Result<Journal> {
    let journal: Journal = serde_json::from_str(bytes).context("decoding VLAN ownership")?;
    let mut groups = BTreeSet::new();
    for (name, owner) in &journal.owners {
        validate_iface_name(name)?;
        ensure!(
            owner.group >= 0x1000_0000 && owner.group <= 0x7fff_ffff && groups.insert(owner.group),
            "invalid or duplicate VLAN ownership group"
        );
        ensure!(
            owner.alias.starts_with("sentinel-vlan:")
                && owner.alias.len() == 46
                && owner.alias[14..].bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid VLAN ownership alias"
        );
    }
    Ok(journal)
}

fn load() -> Result<Journal> {
    match system::read_private_file(Path::new(JOURNAL)) {
        Ok(bytes) => decode_journal(&bytes),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|cause| cause.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(Journal::default())
        }
        Err(error) => Err(error).context("reading VLAN ownership"),
    }
}

fn save(journal: &Journal) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(journal)?;
    if system::private_file_changed(Path::new(JOURNAL), &bytes)? {
        system::install_config_file(Path::new(JOURNAL), bytes)
            .context("persisting VLAN ownership before link changes")?;
    }
    Ok(())
}

fn new_owner(used: &mut BTreeSet<u32>) -> Result<Owner> {
    loop {
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes)
            .map_err(|e| anyhow::anyhow!("VLAN ownership entropy: {e}"))?;
        let group = (u32::from_ne_bytes(bytes[..4].try_into()?) & 0x6fff_ffff) | 0x1000_0000;
        if used.insert(group) {
            return Ok(Owner {
                group,
                alias: format!(
                    "sentinel-vlan:{}",
                    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
                ),
            });
        }
    }
}

/// Names in dependency order; removal reverses this order. Reject corrupted
/// runtime graphs instead of recursing without a bound.
fn ordered(parents: &BTreeMap<String, String>) -> Result<Vec<String>> {
    let mut remaining: BTreeSet<_> = parents.keys().cloned().collect();
    let mut result = Vec::new();
    while !remaining.is_empty() {
        let ready: Vec<_> = remaining
            .iter()
            .filter(|name| !remaining.contains(&parents[*name]))
            .cloned()
            .collect();
        ensure!(!ready.is_empty(), "cycle in VLAN link dependencies");
        for name in ready {
            remaining.remove(&name);
            result.push(name);
        }
    }
    Ok(result)
}

fn removal_plan(
    journal: &Journal,
    desired: &BTreeMap<String, Spec>,
    actual: &BTreeMap<String, Link>,
) -> Result<BTreeSet<String>> {
    let mut remove = BTreeSet::new();
    for (name, owner) in &journal.owners {
        if let Some(link) = actual.get(name) {
            ensure!(
                link.owned_by(owner),
                "refusing to modify foreign interface {name:?}: VLAN ownership does not match"
            );
            if desired.get(name) != link.spec().as_ref() {
                remove.insert(name.clone());
            }
        }
    }
    loop {
        let mut added = false;
        for (name, link) in actual {
            if link.link_netnsid.is_none()
                && link
                    .link
                    .as_ref()
                    .is_some_and(|parent| remove.contains(parent))
            {
                ensure!(
                    journal
                        .owners
                        .get(name)
                        .is_some_and(|owner| link.owned_by(owner)),
                    "refusing to remove VLAN parent of foreign dependent interface {name:?}"
                );
                added |= remove.insert(name.clone());
            }
        }
        if !added {
            return Ok(remove);
        }
    }
}

/// Legacy ownership requires the last committed appliance, its exact generated
/// root-owned netdev file, and the matching kernel kind/parent/ID/TPID. A name
/// or a newly staged candidate alone is never evidence of prior management.
fn legacy_managed(name: &str, link: &Link) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    if number(&link.group).is_some_and(|group| group != 0) || !link.ifalias.is_empty() {
        return Ok(false);
    }
    let path = Path::new(system::NETWORKD_RUNTIME_DIR).join(format!("10-sentinel-{name}.netdev"));
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("reading legacy VLAN unit metadata"),
    };
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Ok(false);
    }
    let running = match Appliance::load(Path::new(crate::session::Session::RUNNING)) {
        Ok(running) => running,
        Err(_) => return Ok(false),
    };
    let previous = desired(&running);
    let Some(spec) = previous.get(name) else {
        return Ok(false);
    };
    if link.spec().as_ref() != Some(spec) {
        return Ok(false);
    }
    let protocol = (spec.protocol == "802.1ad").then_some("802.1ad");
    let expected = crate::net::netdev_body(name, spec.id, protocol);
    Ok(system::read_private_file(&path)? == expected)
}

/// Reserve the union durably before changing units or links. The group is
/// atomic at creation, so an interruption before the cosmetic alias write is
/// recoverable without adopting an unrelated device. Legacy migration is
/// separately proven against the last committed state and its generated unit.
pub fn prepare(appliance: &Appliance) -> Result<()> {
    let wanted = desired(appliance);
    let mut journal = load()?;
    let previous = Appliance::load(Path::new(crate::session::Session::RUNNING))
        .map(|appliance| desired(&appliance))
        .unwrap_or_default();
    if wanted.is_empty() && journal.owners.is_empty() && previous.is_empty() {
        return Ok(());
    }
    let mut actual = links()?;
    let mut used: BTreeSet<_> = actual
        .values()
        .filter_map(|link| number(&link.group))
        .chain(journal.owners.values().map(|owner| owner.group))
        .collect();
    let mut migrate = Vec::new();
    let names: BTreeSet<_> = wanted
        .keys()
        .chain(journal.owners.keys())
        .chain(previous.keys().filter(|name| actual.contains_key(*name)))
        .cloned()
        .collect();
    for name in names {
        if let Some(link) = actual.get(&name) {
            if !journal
                .owners
                .get(&name)
                .is_some_and(|owner| link.owned_by(owner))
            {
                ensure!(
                    legacy_managed(&name, link)?,
                    "refusing to adopt foreign interface {name:?}: VLAN ownership does not match"
                );
                migrate.push((name.clone(), link.ifindex));
            }
        }
        if let std::collections::btree_map::Entry::Vacant(entry) = journal.owners.entry(name) {
            entry.insert(new_owner(&mut used)?);
        }
    }
    // Preflight the migration and every destructive dependency without changing
    // the actual links. A foreign child must refuse before any owner is stamped.
    for (name, _) in &migrate {
        let link = actual.get_mut(name).context("legacy VLAN disappeared")?;
        link.group = serde_json::json!(journal.owners[name].group);
        link.ifalias = journal.owners[name].alias.clone();
    }
    removal_plan(&journal, &wanted, &actual)?;
    save(&journal)?;
    for (name, index) in migrate {
        let current = links()?;
        let link = current
            .get(&name)
            .context("legacy VLAN disappeared before migration")?;
        ensure!(
            link.ifindex == index && legacy_managed(&name, link)?,
            "legacy VLAN changed before ownership migration: {name}"
        );
        let owner = &journal.owners[&name];
        system::ip_link(&["set", "dev", &name, "group", &owner.group.to_string()])?;
        system::ip_link(&["set", "dev", &name, "alias", &owner.alias])?;
    }
    Ok(())
}

/// Close links whose old hooks will disappear with the candidate policy. This
/// runs before the firewall reload, not after it: even a short interval with an
/// old VLAN UP and no old policy would admit packets outside either config.
pub fn stage(appliance: &Appliance) -> Result<bool> {
    prepare(appliance)?;
    let journal = load()?;
    if journal.owners.is_empty() {
        return Ok(false);
    }
    let actual = links()?;
    let remove = removal_plan(&journal, &desired(appliance), &actual)?;
    let mut changed = false;
    for name in remove {
        let current = links()?;
        if let Some(link) = current.get(&name) {
            ensure!(
                link.owned_by(&journal.owners[&name]),
                "VLAN ownership changed before staging: {name}"
            );
            if link.up() {
                system::ip_link(&["set", "dev", &name, "down"]).with_context(|| {
                    format!("staging owned VLAN {name} DOWN before firewall update")
                })?;
                changed = true;
            }
        }
    }
    Ok(changed)
}

/// Reconcile kernel devices after networkd has forgotten old VLAN netdev units.
/// Addressing remains networkd's responsibility; every new device starts DOWN.
fn reconcile_links(appliance: &Appliance, journal: &Journal) -> Result<()> {
    let wanted = desired(appliance);
    let actual = links()?;
    let remove = removal_plan(journal, &wanted, &actual)?;
    let parents: BTreeMap<_, _> = remove
        .iter()
        .map(|name| (name.clone(), actual[name].link.clone().unwrap_or_default()))
        .collect();
    for name in ordered(&parents)?.into_iter().rev() {
        // Recheck the actual object and all its dependents immediately before
        // removal, rather than trusting a snapshot from before unit reload.
        let now = links()?;
        removal_plan(journal, &wanted, &now)?;
        if let Some(link) = now.get(&name) {
            ensure!(
                link.owned_by(&journal.owners[&name]),
                "VLAN ownership changed for {name:?}"
            );
            system::ip_link(&["delete", "dev", &name])
                .with_context(|| format!("removing owned VLAN {name}"))?;
        }
    }
    let parents = wanted
        .iter()
        .map(|(name, spec)| (name.clone(), spec.parent.clone()))
        .collect();
    for name in ordered(&parents)? {
        let spec = &wanted[&name];
        let owner = &journal.owners[&name];
        let deadline = Instant::now() + WAIT;
        while !links()?.contains_key(&spec.parent) {
            ensure!(
                Instant::now() < deadline,
                "VLAN {name}: parent {:?} is not present",
                spec.parent
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        if let Some(link) = links()?.get(&name) {
            ensure!(
                link.owned_by(owner) && link.spec().as_ref() == Some(spec),
                "VLAN {name} changed during reconciliation"
            );
        } else {
            system::ip_link(&[
                "add",
                "link",
                &spec.parent,
                "name",
                &name,
                "group",
                &owner.group.to_string(),
                "type",
                "vlan",
                "protocol",
                &spec.protocol,
                "id",
                &spec.id.to_string(),
            ])
            .with_context(|| format!("creating owned VLAN {name} DOWN"))?;
        }
        let now = links()?;
        let link = now.get(&name).context("new VLAN is absent")?;
        ensure!(
            link.owned_by(owner) && link.spec().as_ref() == Some(spec),
            "new VLAN ownership or attributes do not match for {name}"
        );
        if link.ifalias != owner.alias {
            system::ip_link(&["set", "dev", &name, "alias", &owner.alias])?;
        }
    }
    Ok(())
}

fn acknowledged(reply: &str, name: &str, index: u32, policy: u32) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(reply) else {
        return false;
    };
    value["ready"] == true
        && value["interface"] == name
        && value["ifindex"] == index
        && value["policy"] == policy
        && value["egress"].is_boolean()
}

/// Activate only after the agent proves the exact current ifindex and zone
/// policy, including its required TCX hooks. Missing/old agents never authorize
/// activation. Disabled VLANs are explicitly DOWN; unchanged healthy VLANs keep
/// their ifindex, leases and live connections.
pub fn apply(appliance: &Appliance) -> Result<()> {
    prepare(appliance)?;
    let mut journal = load()?;
    if journal.owners.is_empty() {
        return Ok(());
    }
    reconcile_links(appliance, &journal)?;
    let ids = crate::compile::zone_policy_ids(appliance);
    for iface in &appliance.interfaces {
        if iface.vlan.is_none() {
            continue;
        }
        let name = &iface.name;
        let owner = &journal.owners[name];
        if iface.disabled {
            system::ip_link(&["set", "dev", name, "down"])?;
            continue;
        }
        if let Some(zone) = &iface.zone {
            let deadline = Instant::now() + WAIT;
            loop {
                let actual = links()?;
                let link = actual
                    .get(name)
                    .context("VLAN disappeared before activation")?;
                ensure!(
                    link.owned_by(owner),
                    "VLAN ownership changed before activation: {name}"
                );
                let reply = crate::velstra::query(&format!("interface {name}"));
                if reply
                    .as_ref()
                    .is_ok_and(|reply| acknowledged(reply, name, link.ifindex, ids[zone.as_str()]))
                {
                    let index = std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))?
                        .trim()
                        .parse::<u32>()?;
                    if index == link.ifindex {
                        break;
                    }
                }
                if Instant::now() >= deadline {
                    system::ip_link(&["set", "dev", name, "down"])?;
                    bail!(
                        "VLAN {name} remains DOWN: firewall has not acknowledged its current interface and policy: {}",
                        reply.unwrap_or_else(|error| error.to_string()).trim()
                    );
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        let actual = links()?;
        let link = actual
            .get(name)
            .context("VLAN disappeared during activation")?;
        ensure!(
            link.owned_by(owner),
            "VLAN ownership changed during activation: {name}"
        );
        if !link.up() {
            system::ip_link(&["set", "dev", name, "up"])?;
        }
    }
    let wanted = desired(appliance);
    journal.owners.retain(|name, _| wanted.contains_key(name));
    save(&journal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn owner() -> Owner {
        Owner {
            group: 1073770533,
            alias: "sentinel-vlan:0123456789abcdef0123456789abcdef".into(),
        }
    }
    fn link(name: &str, parent: &str, id: u16) -> Link {
        serde_json::from_value(json!({"ifname":name,"ifindex":42,"link":parent,"group":"1073770533", "flags":["BROADCAST"],"linkinfo":{"info_kind":"vlan","info_data":{"id":id,"protocol":"802.1Q"}}})).unwrap()
    }

    #[test]
    fn ownership_survives_interruption_before_alias_write_but_not_foreign_links() {
        let mut link = link("iot", "eth0", 42);
        assert!(link.owned_by(&owner()));
        link.ifalias = "somebody-else".into();
        assert!(!link.owned_by(&owner()));
        link.ifalias.clear();
        link.group = json!(0);
        assert!(!link.owned_by(&owner()));
        link.group = json!(1073770533);
        link.linkinfo["info_kind"] = json!("dummy");
        assert!(!link.owned_by(&owner()));
    }

    #[test]
    fn actual_protocol_and_numeric_group_representations_normalize() {
        let mut link = link("iot", "eth0", 42);
        assert_eq!(link.spec().unwrap().protocol, "802.1q");
        link.linkinfo["info_data"]["protocol"] = json!("[34984]");
        assert_eq!(link.spec().unwrap().protocol, "802.1ad");
        link.link_netnsid = Some(0);
        assert!(link.spec().is_none());
        assert_eq!(number(&json!("1073770533")), Some(1073770533));
        assert!(number(&json!("default")).is_none());
    }

    #[test]
    fn removing_a_parent_also_replaces_owned_qinq_children_but_preserves_foreign_children() {
        let mut journal = Journal::default();
        journal.owners.insert("outer".into(), owner());
        journal.owners.insert("inner".into(), owner());
        let actual = BTreeMap::from([
            ("outer".into(), link("outer", "eth0", 42)),
            ("inner".into(), link("inner", "outer", 20)),
        ]);
        let wanted = BTreeMap::from([
            (
                "outer".into(),
                Spec {
                    parent: "eth0".into(),
                    id: 43,
                    protocol: "802.1q".into(),
                },
            ),
            ("inner".into(), actual["inner"].spec().unwrap()),
        ]);
        assert_eq!(
            removal_plan(&journal, &wanted, &actual).unwrap(),
            BTreeSet::from(["inner".into(), "outer".into()])
        );
        journal.owners.remove("inner");
        assert!(
            removal_plan(&journal, &wanted, &actual)
                .unwrap_err()
                .to_string()
                .contains("foreign dependent")
        );
        assert_eq!(
            ordered(&BTreeMap::from([
                ("outer".into(), "eth0".into()),
                ("inner".into(), "outer".into())
            ]))
            .unwrap(),
            ["outer", "inner"]
        );
        assert!(
            ordered(&BTreeMap::from([
                ("outer".into(), "inner".into()),
                ("inner".into(), "outer".into())
            ]))
            .is_err()
        );
    }

    #[test]
    fn corrupt_journal_is_an_error_not_permission_to_adopt_or_forget() {
        for value in [
            "",
            "null",
            "{}?",
            r#"{"owners":{"../x":{"group":1073770533,"alias":"x"}}}"#,
            r#"{"owners":{"iot":{"group":0,"alias":"sentinel-vlan:0123456789abcdef0123456789abcdef"}}}"#,
        ] {
            assert!(decode_journal(value).is_err(), "{value}");
        }
        let good = serde_json::to_string(&Journal {
            owners: BTreeMap::from([("iot".into(), owner())]),
        })
        .unwrap();
        assert!(decode_journal(&good).is_ok());
    }

    #[test]
    fn activation_requires_exact_interface_index_policy_and_complete_ack() {
        let good = json!({"ready":true,"interface":"iot","ifindex":42,"policy":7,"egress":false});
        assert!(acknowledged(&good.to_string(), "iot", 42, 7));
        for (field, value) in [
            ("ready", json!(false)),
            ("interface", json!("eth0")),
            ("ifindex", json!(41)),
            ("policy", json!(8)),
            ("egress", json!(null)),
        ] {
            let mut bad = good.clone();
            bad[field] = value;
            assert!(!acknowledged(&bad.to_string(), "iot", 42, 7), "{bad}");
        }
        assert!(!acknowledged("Ready\n", "iot", 42, 7));
    }
}
