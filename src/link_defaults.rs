//! Defaults for physical Ethernet link properties which networkd does not undo on reload.
//!
//! The journal is ownership/recovery metadata, not a second desired config. It
//! records the actual pre-override values and physical identity before any unit
//! can change them. An omitted, previously owned property restores that value.
//! Virtual devices have their own creation/inheritance semantics and are not
//! enrolled here. Callers hold the appliance apply lock, including rollback.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::config::{Appliance, Interface, validate_iface_name, validate_mac};
use crate::{net::ApplyMode, system};

const JOURNAL: &str = "/var/lib/sentinel/link-defaults.json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    device: String,
    permanent_mac: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Properties {
    mtu: Option<u32>,
    mac: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    identity: Identity,
    defaults: Properties,
    own_mtu: bool,
    own_mac: bool,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    links: BTreeMap<String, Entry>,
}

#[derive(Debug, Deserialize)]
struct Link {
    ifname: String,
    mtu: u32,
    #[serde(default)]
    address: String,
    #[serde(default)]
    permaddr: Option<String>,
}

impl Properties {
    fn differs(&self, link: &Link) -> bool {
        self.mtu.is_some_and(|mtu| mtu != link.mtu)
            || self
                .mac
                .as_ref()
                .is_some_and(|mac| !mac.eq_ignore_ascii_case(&link.address))
    }
}

fn links() -> Result<BTreeMap<String, Link>> {
    let links: Vec<Link> = serde_json::from_str(&system::ip_link_list()?)
        .context("reading physical link properties")?;
    Ok(links.into_iter().map(|l| (l.ifname.clone(), l)).collect())
}

fn identity(link: &Link) -> Result<Option<Identity>> {
    let base = Path::new("/sys/class/net").join(&link.ifname);
    let device = match base.join("device").canonicalize() {
        Ok(device) => device,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("reading physical NIC identity"),
    };
    // Use the kernel ARPHRD value rather than iproute2's rendered link_type:
    // `ip -N` renders Ethernet as "[1]", not "ether". Raw-IP modems are not
    // Ethernet and must keep their existing link lifecycle.
    if std::fs::read_to_string(base.join("type"))?.trim() != "1" {
        return Ok(None);
    }
    // IFLA_PERM_ADDRESS is emitted when the current address differs. Otherwise
    // accept the current address ONLY when the kernel marks it permanent.
    // Never use a cloned/random address as hardware identity.
    let permanent_mac = if let Some(mac) = &link.permaddr {
        mac.clone()
    } else {
        let kind = std::fs::read_to_string(base.join("addr_assign_type"))?;
        if kind.trim() == "0" {
            link.address.clone()
        } else {
            system::permanent_mac(&link.ifname)?
        }
    };
    validate_mac(&permanent_mac)?;
    Ok(Some(Identity {
        device: device.to_string_lossy().into_owned(),
        permanent_mac: permanent_mac.to_ascii_lowercase(),
    }))
}

fn decode(bytes: &str) -> Result<Journal> {
    let journal: Journal = serde_json::from_str(bytes).context("decoding link defaults")?;
    for (name, entry) in &journal.links {
        validate_iface_name(name)?;
        validate_mac(&entry.identity.permanent_mac)?;
        ensure!(
            entry.identity.device.starts_with("/sys/devices/"),
            "invalid physical device identity"
        );
        if let Some(mtu) = entry.defaults.mtu {
            ensure!(mtu > 0, "invalid MTU baseline");
        }
        if let Some(mac) = &entry.defaults.mac {
            validate_mac(mac)?;
        }
        ensure!(
            !entry.own_mtu || entry.defaults.mtu.is_some(),
            "owned MTU has no baseline"
        );
        ensure!(
            !entry.own_mac || entry.defaults.mac.is_some(),
            "owned MAC has no baseline"
        );
    }
    Ok(journal)
}

fn load() -> Result<Journal> {
    match system::read_private_file(Path::new(JOURNAL)) {
        Ok(bytes) => decode(&bytes),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(Journal::default())
        }
        Err(error) => Err(error).context("reading link defaults"),
    }
}

fn enroll(
    entry: Option<&Entry>,
    identity: Identity,
    actual: &Link,
    desired: &Interface,
    previous: Option<&Interface>,
    boot: bool,
) -> Result<Entry> {
    // A replacement card at the same name/PCI slot must never inherit another
    // card's MAC or MTU. Live legacy configurations may already have applied an
    // override: no reliable default can be inferred from that overridden value.
    let mut entry = entry
        .filter(|e| e.identity == identity)
        .cloned()
        .unwrap_or(Entry {
            identity,
            defaults: Properties::default(),
            own_mtu: false,
            own_mac: false,
        });
    if !entry.own_mtu && (boot || previous.is_none_or(|i| i.mtu.is_none())) {
        entry.defaults.mtu = Some(actual.mtu);
    }
    if !entry.own_mac && (boot || previous.is_none_or(|i| i.mac.is_none())) {
        entry.defaults.mac = Some(actual.address.clone());
    }
    if desired.mtu.is_some() || previous.is_some_and(|i| i.mtu.is_some()) {
        ensure!(
            entry.defaults.mtu.is_some(),
            "{}: pre-override MTU is unknown; capture the physical default during early boot before changing it",
            desired.name
        );
        entry.own_mtu = true;
    }
    if desired.mac.is_some() || previous.is_some_and(|i| i.mac.is_some()) {
        ensure!(
            entry.defaults.mac.is_some(),
            "{}: pre-override MAC is unknown; capture the physical default during early boot before changing it",
            desired.name
        );
        entry.own_mac = true;
    }
    Ok(entry)
}

pub struct Resolved {
    values: BTreeMap<String, Properties>,
    identities: BTreeMap<String, Identity>,
}

impl Resolved {
    pub fn mtu(&self, name: &str) -> Option<u32> {
        self.values.get(name).and_then(|p| p.mtu)
    }

    pub fn mac(&self, name: &str) -> Option<&str> {
        self.values.get(name).and_then(|p| p.mac.as_deref())
    }

    /// Constrain networkd too: a name-only unit could otherwise restore an old
    /// card's defaults onto a foreign device which appears between commits.
    pub fn permanent_mac(&self, name: &str) -> Option<&str> {
        self.identities
            .get(name)
            .map(|identity| identity.permanent_mac.as_str())
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.values.keys().map(String::as_str)
    }

    /// A reload only reconfigures changed unit files. Repair owned properties
    /// on unchanged units explicitly, after checking the physical identity.
    pub fn reconcile_unchanged(&self, changed: &BTreeSet<String>) -> Result<()> {
        let actual = links()?;
        for (name, wanted) in &self.values {
            if changed.contains(name) {
                continue;
            }
            let link = actual
                .get(name)
                .with_context(|| format!("{name}: physical link disappeared"))?;
            ensure!(
                identity(link)?.as_ref() == self.identities.get(name),
                "{name}: physical identity changed during apply"
            );
            if wanted.differs(link) {
                system::networkctl_reconfigure(name)
                    .with_context(|| format!("repairing physical properties on {name}"))?;
            }
        }
        Ok(())
    }

    /// networkctl reload accepts unit jobs; a successful reload does not prove
    /// the driver accepted a property. A commit must observe the actual values.
    pub fn verify(&self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let actual = links()?;
            let mut pending = Vec::new();
            for (name, wanted) in &self.values {
                let Some(link) = actual.get(name) else {
                    pending.push(format!("{name}: physical link disappeared"));
                    continue;
                };
                ensure!(
                    identity(link)?.as_ref() == self.identities.get(name),
                    "{name}: physical identity changed during apply"
                );
                if wanted.differs(link) {
                    pending.push(format!(
                        "{name}: expected MTU {:?}/MAC {:?}, observed {}/{}",
                        wanted.mtu, wanted.mac, link.mtu, link.address
                    ));
                }
            }
            if pending.is_empty() {
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                "physical link properties were not applied: {}",
                pending.join("; ")
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

pub fn prepare(appliance: &Appliance, mode: ApplyMode) -> Result<Resolved> {
    let mut journal = load()?;
    let actual = links()?;
    let previous = if mode == ApplyMode::Boot {
        None
    } else {
        match Appliance::load(Path::new(crate::session::Session::RUNNING)) {
            Ok(previous) => Some(previous),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                None
            }
            Err(error) => {
                return Err(error).context("reading previous physical link configuration");
            }
        }
    };
    for iface in &appliance.interfaces {
        if iface.if_type.is_none()
            && iface.parent.is_none()
            && iface.vlan.is_none()
            && iface.wwan.is_none()
            && iface.wireless.is_none()
            && (iface.mtu.is_some() || iface.mac.is_some())
        {
            ensure!(
                actual.contains_key(&iface.name),
                "{}: physical link must be present before recording MTU/MAC defaults",
                iface.name
            );
        }
    }
    let mut resolved = Resolved {
        values: BTreeMap::new(),
        identities: BTreeMap::new(),
    };
    for (name, link) in &actual {
        let desired = appliance.interfaces.iter().find(|i| i.name == *name);
        let retained = journal
            .links
            .get(name)
            .is_some_and(|e| e.own_mtu || e.own_mac);
        if desired.is_none() && !retained {
            continue;
        }
        let requested = desired.is_some_and(|i| i.mtu.is_some() || i.mac.is_some());
        let identity = match identity(link) {
            Ok(Some(identity)) => identity,
            Ok(None) => continue, // virtual link: a different lifecycle owns it
            Err(_) if !retained && !requested => continue,
            Err(error) => return Err(error),
        };
        let empty = Interface {
            name: name.clone(),
            ..Interface::default()
        };
        // Do not restore a previously managed property onto a replacement NIC
        // which is no longer declared by the appliance.
        if desired.is_none() && journal.links[name].identity != identity {
            continue;
        }
        let entry = enroll(
            journal.links.get(name),
            identity.clone(),
            link,
            desired.unwrap_or(&empty),
            previous
                .as_ref()
                .and_then(|a| a.interfaces.iter().find(|i| i.name == *name)),
            mode == ApplyMode::Boot,
        )?;
        let wanted = desired.unwrap_or(&empty);
        let values = Properties {
            mtu: wanted
                .mtu
                .map(u32::from)
                .or_else(|| entry.own_mtu.then_some(entry.defaults.mtu).flatten()),
            mac: wanted
                .mac
                .clone()
                .or_else(|| entry.own_mac.then(|| entry.defaults.mac.clone()).flatten()),
        };
        if values.mtu.is_some() || values.mac.is_some() {
            resolved.values.insert(name.clone(), values);
            resolved.identities.insert(name.clone(), identity);
        }
        journal.links.insert(name.clone(), entry);
    }
    let bytes = serde_json::to_vec_pretty(&journal)?;
    if system::private_file_changed(Path::new(JOURNAL), &bytes)? {
        system::install_config_file(Path::new(JOURNAL), bytes)
            .context("persisting pre-override link defaults")?;
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(mtu: u32, mac: &str) -> Link {
        Link {
            ifname: "eth0".into(),
            mtu,
            address: mac.into(),
            permaddr: None,
        }
    }
    fn id(mac: &str) -> Identity {
        Identity {
            device: "/sys/devices/pci0000:00/0000:00:01.0/virtio0".into(),
            permanent_mac: mac.into(),
        }
    }
    #[test]
    fn unowned_defaults_follow_the_device_until_the_first_override() {
        let blank = Interface {
            name: "eth0".into(),
            ..Interface::default()
        };
        let before = link(8950, "02:11:22:33:44:55");
        let initial = enroll(None, id(&before.address), &before, &blank, None, true).unwrap();
        let actual = link(1492, &before.address);
        let wanted = Interface {
            name: "eth0".into(),
            mtu: Some(9000),
            ..Interface::default()
        };
        let owned = enroll(
            Some(&initial),
            id(&before.address),
            &actual,
            &wanted,
            Some(&blank),
            false,
        )
        .unwrap();
        assert_eq!(owned.defaults.mtu, Some(1492));
    }

    #[test]
    fn baseline_is_actual_not_a_guessed_ethernet_mtu() {
        let actual = link(8950, "02:11:22:33:44:55");
        let desired = Interface {
            name: "eth0".into(),
            mtu: Some(9000),
            mac: Some("02:66:77:88:99:aa".into()),
            ..Interface::default()
        };
        let original = enroll(None, id(&actual.address), &actual, &desired, None, false).unwrap();
        assert_eq!(original.defaults.mtu, Some(8950));
        let changed = link(9000, "02:66:77:88:99:aa");
        let retry = enroll(
            Some(&original),
            id(&actual.address),
            &changed,
            &desired,
            Some(&desired),
            false,
        )
        .unwrap();
        assert_eq!(retry, original);
        let empty = Interface {
            name: "eth0".into(),
            ..Interface::default()
        };
        let removed = enroll(
            Some(&retry),
            id(&actual.address),
            &changed,
            &empty,
            Some(&desired),
            false,
        )
        .unwrap();
        assert_eq!(removed, original); // retains restore intent across crash/reboot
    }
    #[test]
    fn legacy_override_is_never_enrolled_as_a_default() {
        let desired = Interface {
            name: "eth0".into(),
            mtu: Some(9000),
            ..Interface::default()
        };
        let actual = link(9000, "02:11:22:33:44:55");
        assert!(
            enroll(
                None,
                id(&actual.address),
                &actual,
                &desired,
                Some(&desired),
                false
            )
            .is_err()
        );
        let cleared = Interface {
            name: "eth0".into(),
            ..Interface::default()
        };
        assert!(
            enroll(
                None,
                id(&actual.address),
                &actual,
                &cleared,
                Some(&desired),
                false
            )
            .is_err()
        );
        let raw_boot = link(8950, &actual.address);
        assert_eq!(
            enroll(
                None,
                id(&actual.address),
                &raw_boot,
                &desired,
                Some(&desired),
                true
            )
            .unwrap()
            .defaults
            .mtu,
            Some(8950)
        );
    }
    #[test]
    fn replaced_hardware_never_inherits_old_defaults() {
        let desired = Interface {
            name: "eth0".into(),
            mtu: Some(9000),
            ..Interface::default()
        };
        let old = link(8950, "02:11:22:33:44:55");
        let old = enroll(None, id(&old.address), &old, &desired, None, false).unwrap();
        let new = link(1500, "02:aa:bb:cc:dd:ee");
        let entry = enroll(Some(&old), id(&new.address), &new, &desired, None, true).unwrap();
        assert_eq!(entry.defaults.mtu, Some(1500));
        assert_eq!(entry.defaults.mac.as_deref(), Some(new.address.as_str()));
    }
    #[test]
    fn property_comparison_does_not_require_an_ethernet_address() {
        let raw = link(1500, "");
        assert!(!Properties::default().differs(&raw));
        assert!(
            Properties {
                mtu: Some(1492),
                mac: None
            }
            .differs(&raw)
        );
    }

    #[test]
    fn journal_rejects_missing_owned_baselines_and_invalid_identity() {
        let desired = Interface {
            name: "eth0".into(),
            mtu: Some(9000),
            ..Interface::default()
        };
        let actual = link(8950, "02:11:22:33:44:55");
        let entry = enroll(None, id(&actual.address), &actual, &desired, None, false).unwrap();
        let mut j = Journal {
            links: BTreeMap::from([("eth0".into(), entry)]),
        };
        assert!(decode(&serde_json::to_string(&j).unwrap()).is_ok());
        j.links.get_mut("eth0").unwrap().defaults.mtu = None;
        assert!(decode(&serde_json::to_string(&j).unwrap()).is_err());
        j.links.get_mut("eth0").unwrap().own_mtu = false;
        j.links.get_mut("eth0").unwrap().identity.device = "/tmp/foreign".into();
        assert!(decode(&serde_json::to_string(&j).unwrap()).is_err());
    }
}
