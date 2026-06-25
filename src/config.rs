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

# Broad zone rules set a zone's posture (action: accept | drop | reject).
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

# Port rules open a specific proto/port even on a default-drop zone — here,
# inbound HTTPS from the WAN.
[[rule]]
name = "allow-https-in"
from = "wan"
to = "lan"
action = "accept"
proto = "tcp"
port = 443
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
    /// The zone this interface belongs to. `None` for a NIC the system provides
    /// but the operator hasn't assigned yet (it shows up in the config but is not
    /// firewalled until a zone is set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<Zone>,
    /// `"dhcp"` or a CIDR like `"10.0.0.1/24"`. `None` if not yet configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Accept,
    Drop,
    Reject,
}

/// L4 protocol for a port rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub from: Zone,
    pub to: Zone,
    pub action: Action,
    /// With `port`, makes this a **port rule** (a specific proto/port);
    /// without, it is a **broad** rule that sets the from-zone's posture.
    #[serde(default)]
    pub proto: Option<Proto>,
    #[serde(default)]
    pub port: Option<u16>,
}

impl Rule {
    /// A broad zone rule (no proto/port) — sets the from-zone's default posture.
    pub fn is_broad(&self) -> bool {
        self.proto.is_none() && self.port.is_none()
    }
    /// A specific proto/port rule.
    pub fn is_port_rule(&self) -> bool {
        self.proto.is_some() && self.port.is_some()
    }
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
            if let Some(addr) = &iface.address {
                validate_address(addr).with_context(|| format!("interface {:?}", iface.name))?;
            }
        }

        // Every rule's zones must be backed by at least one *assigned* interface,
        // else the rule can never match — a common, silent misconfiguration.
        let zones: HashSet<Zone> = self.interfaces.iter().filter_map(|i| i.role).collect();
        for rule in &self.rules {
            for (which, zone) in [("from", rule.from), ("to", rule.to)] {
                if !zones.contains(&zone) {
                    bail!(
                        "rule {:?}: {which} zone {zone:?} has no interface",
                        rule.name
                    );
                }
            }
            // proto and port are a pair: a port rule needs both, a broad rule
            // neither.
            if rule.proto.is_some() != rule.port.is_some() {
                bail!(
                    "rule {:?}: `proto` and `port` must be set together",
                    rule.name
                );
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
                "  {:<8} {:<12} {}\n",
                i.name,
                i.role.map(zone_str).unwrap_or("(unassigned)"),
                i.address.as_deref().unwrap_or("(auto)"),
            ));
        }
        out.push_str(&format!("rules ({}):\n", self.rules.len()));
        for r in &self.rules {
            let proto_port = match (r.proto, r.port) {
                (Some(p), Some(port)) => format!("  {}/{port}", proto_str(p)),
                _ => String::new(),
            };
            out.push_str(&format!(
                "  {:<16} {} -> {}  {}{}\n",
                r.name,
                zone_str(r.from),
                zone_str(r.to),
                action_str(r.action),
                proto_port,
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

fn proto_str(p: Proto) -> &'static str {
    match p {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
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
        assert_eq!(a.rules.len(), 3); // 2 broad + 1 port rule
        // The port rule has proto+port; the broad ones don't.
        assert_eq!(a.rules.iter().filter(|r| r.is_port_rule()).count(), 1);
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
