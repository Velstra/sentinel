//! The declarative appliance configuration — the single source of truth for an
//! **immutable** Sentinel box.
//!
//! Sentinel is not a mutable system you log into and tweak (VyOS-style). The
//! whole appliance state is one declarative document: you *declare* interfaces,
//! zones, and firewall rules, and the box reconciles to it atomically. This
//! module is the model + parser + validator the CLI is built on; compiling it
//! down to the Velstra data-plane config is the next slice.

use std::{collections::HashSet, net::Ipv4Addr, path::Path};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// A commented starting config, emitted by `sentinel config init`.
pub const EXAMPLE: &str = r#"# Velstra Sentinel — declarative appliance config.
# Declare the whole box here; `sentinel config apply` reconciles to it.

[system]
hostname = "sentinel-fw"

# Interfaces carry a zone role (wan | lan | dmz). Address is "dhcp" or a CIDR.
[[interface]]
name = "wan0"
role = "wan"
address = "dhcp"

[[interface]]
name = "lan0"
role = "lan"
address = "10.0.0.1/24"

# Zone-to-zone firewall rules (action: accept | drop | reject).
[[rule]]
name = "lan-to-wan"
from = "lan"
to = "wan"
action = "accept"

[[rule]]
name = "wan-to-lan"
from = "wan"
to = "lan"
action = "drop"
"#;

/// The whole declarative appliance config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Appliance {
    pub system: System,
    #[serde(default, rename = "interface")]
    pub interfaces: Vec<Interface>,
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct System {
    pub hostname: String,
}

/// A network zone — the trust boundary a firewall reasons about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Zone {
    Wan,
    Lan,
    Dmz,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    pub role: Zone,
    /// `"dhcp"` or a CIDR like `"10.0.0.1/24"`.
    pub address: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Accept,
    Drop,
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub from: Zone,
    pub to: Zone,
    pub action: Action,
}

impl Appliance {
    /// Parse and validate a config from TOML text.
    pub fn from_toml(toml_text: &str) -> Result<Self> {
        let appliance: Appliance = toml::from_str(toml_text).context("parsing TOML config")?;
        appliance.validate()?;
        Ok(appliance)
    }

    /// Parse and validate a config from JSON text.
    pub fn from_json(json_text: &str) -> Result<Self> {
        let appliance: Appliance =
            serde_json::from_str(json_text).context("parsing JSON config")?;
        appliance.validate()?;
        Ok(appliance)
    }

    /// Load and validate a config file, picking the format by extension
    /// (`.json` → JSON, anything else → TOML).
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            Self::from_json(&text)
        } else {
            Self::from_toml(&text)
        }
    }

    /// Serialize to canonical TOML.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).context("serializing to TOML")
    }

    /// Serialize to pretty JSON (for editors / a future web UI).
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("serializing to JSON")
    }

    /// Reject configs that parse but are not coherent.
    pub fn validate(&self) -> Result<()> {
        if self.system.hostname.trim().is_empty() {
            bail!("system.hostname must not be empty");
        }

        let mut seen = HashSet::new();
        for iface in &self.interfaces {
            if !seen.insert(&iface.name) {
                bail!("duplicate interface {:?}", iface.name);
            }
            validate_address(&iface.address)
                .with_context(|| format!("interface {:?}", iface.name))?;
        }

        // Every rule's zones must be backed by at least one interface, else the
        // rule can never match — a common, silent misconfiguration.
        let zones: HashSet<Zone> = self.interfaces.iter().map(|i| i.role).collect();
        for rule in &self.rules {
            for (which, zone) in [("from", rule.from), ("to", rule.to)] {
                if !zones.contains(&zone) {
                    bail!(
                        "rule {:?}: {which} zone {zone:?} has no interface",
                        rule.name
                    );
                }
            }
        }
        Ok(())
    }

    /// A human-readable summary for `config show`.
    pub fn summary(&self) -> String {
        let mut out = format!("hostname: {}\n", self.system.hostname);
        out.push_str(&format!("interfaces ({}):\n", self.interfaces.len()));
        for i in &self.interfaces {
            out.push_str(&format!(
                "  {:<8} {:<4} {}\n",
                i.name,
                zone_str(i.role),
                i.address
            ));
        }
        out.push_str(&format!("rules ({}):\n", self.rules.len()));
        for r in &self.rules {
            out.push_str(&format!(
                "  {:<14} {} -> {}  {}\n",
                r.name,
                zone_str(r.from),
                zone_str(r.to),
                action_str(r.action),
            ));
        }
        out
    }
}

/// Validate an interface address: `"dhcp"` or an IPv4 CIDR.
fn validate_address(addr: &str) -> Result<()> {
    if addr == "dhcp" {
        return Ok(());
    }
    let (ip, prefix) = addr
        .split_once('/')
        .with_context(|| format!("address {addr:?} must be \"dhcp\" or an IPv4 CIDR"))?;
    ip.parse::<Ipv4Addr>()
        .with_context(|| format!("invalid IPv4 in {addr:?}"))?;
    let prefix: u8 = prefix
        .parse()
        .with_context(|| format!("invalid prefix in {addr:?}"))?;
    if prefix > 32 {
        bail!("prefix /{prefix} in {addr:?} exceeds /32");
    }
    Ok(())
}

fn zone_str(z: Zone) -> &'static str {
    match z {
        Zone::Wan => "wan",
        Zone::Lan => "lan",
        Zone::Dmz => "dmz",
    }
}

fn action_str(a: Action) -> &'static str {
    match a {
        Action::Accept => "accept",
        Action::Drop => "drop",
        Action::Reject => "reject",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_example_config_is_valid() {
        let a = Appliance::from_toml(EXAMPLE).expect("example must parse + validate");
        assert_eq!(a.system.hostname, "sentinel-fw");
        assert_eq!(a.interfaces.len(), 2);
        assert_eq!(a.rules.len(), 2);
    }

    #[test]
    fn rejects_duplicate_interfaces() {
        let toml = r#"
            [system]
            hostname = "x"
            [[interface]]
            name = "eth0"
            role = "wan"
            address = "dhcp"
            [[interface]]
            name = "eth0"
            role = "lan"
            address = "10.0.0.1/24"
        "#;
        assert!(Appliance::from_toml(toml).is_err());
    }

    #[test]
    fn rejects_rule_zone_without_interface() {
        let toml = r#"
            [system]
            hostname = "x"
            [[interface]]
            name = "eth0"
            role = "lan"
            address = "10.0.0.1/24"
            [[rule]]
            name = "r"
            from = "lan"
            to = "dmz"
            action = "accept"
        "#;
        // `dmz` has no interface → invalid.
        assert!(Appliance::from_toml(toml).is_err());
    }

    #[test]
    fn rejects_bad_address_and_empty_hostname() {
        assert!(validate_address("10.0.0.1/33").is_err());
        assert!(validate_address("not-an-ip").is_err());
        assert!(validate_address("dhcp").is_ok());
        assert!(validate_address("192.168.1.1/24").is_ok());
    }

    #[test]
    fn toml_json_roundtrip_is_lossless() {
        let a = Appliance::from_toml(EXAMPLE).unwrap();
        // TOML -> JSON -> TOML preserves the config.
        let via_json = Appliance::from_json(&a.to_json().unwrap()).unwrap();
        let via_toml = Appliance::from_toml(&a.to_toml().unwrap()).unwrap();
        assert_eq!(a.summary(), via_json.summary());
        assert_eq!(a.summary(), via_toml.summary());
    }
}
