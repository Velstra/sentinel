//! The declarative appliance configuration — the single source of truth for an
//! **immutable** Sentinel box.
//!
//! Sentinel is not a mutable system you log into and tweak (VyOS-style). The
//! whole appliance state is one declarative document: you *declare* interfaces,
//! zones, and firewall rules, and the box reconciles to it atomically. This
//! module is the model + parser + validator the CLI is built on; compiling it
//! down to the Velstra data-plane config is the next slice.

use std::{
    collections::{BTreeMap, HashSet},
    net::Ipv4Addr,
    path::Path,
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// A commented starting config, emitted by `sentinel config init`.
pub const EXAMPLE: &str = r#"# Velstra Sentinel — declarative appliance config.
# Declare the whole box here; `sentinel config apply` reconciles to it.

[system]
hostname = "sentinel-fw"

# Global firewall defaults — every zone inherits these unless it overrides them.
# stateful: allow return traffic for established flows (default true).
# block_icmp: drop inbound ICMP (default false).  blocklist: global source drops.
[firewall]
stateful = true
block_icmp = false
blocklist = []

# Per-zone posture overrides. Zones are arbitrary names; each becomes one
# data-plane policy. Here ICMP is blocked on the WAN but allowed elsewhere.
[zone.wan]
block_icmp = true

[zone.lan]
block_icmp = false

# Interfaces are assigned to a zone. Address is "dhcp" or a CIDR. A VLAN
# subinterface adds `parent` + `vlan`.
[[interface]]
name = "wan0"
zone = "wan"
address = "dhcp"

[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"

# A VLAN subinterface on lan0, in its own zone:
# [[interface]]
# name = "lan0.20"
# parent = "lan0"
# vlan = 20
# zone = "iot"
# address = "10.0.20.1/24"

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

# NAT is its own thing (address translation, not filtering). Source NAT
# masquerades a zone's outbound traffic to its egress IP; destination NAT is an
# inbound port-forward.
# [[nat.source]]
# name = "wan-masq"
# zone = "wan"
#
# [[nat.destination]]
# name = "web"
# zone = "wan"
# proto = "tcp"
# port = 443
# to = "10.0.0.10:8443"
"#;

/// The whole declarative appliance config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Appliance {
    pub system: System,
    /// Global firewall posture (stateful inspection, ICMP, source blocklist).
    /// Omitted in older configs ⇒ defaults (stateful on, ICMP allowed, no
    /// blocklist); skipped on output when it is exactly the default so saved
    /// files stay clean.
    #[serde(default, skip_serializing_if = "Firewall::is_default")]
    pub firewall: Firewall,
    /// Per-zone posture overrides, keyed by zone name (`[zone.wan]` …). A zone
    /// need not appear here — referencing it from an interface is enough; this
    /// table only carries non-default posture.
    #[serde(default, rename = "zone", skip_serializing_if = "BTreeMap::is_empty")]
    pub zones: BTreeMap<String, ZoneCfg>,
    #[serde(default, rename = "interface")]
    pub interfaces: Vec<Interface>,
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
    /// NAT — address translation, a top-level category distinct from the
    /// firewall (which only *filters*). `[[nat.source]]` masquerades a zone's
    /// outbound traffic; `[[nat.destination]]` is an inbound DNAT port-forward.
    /// Omitted from saved configs when empty.
    #[serde(default, skip_serializing_if = "Nat::is_empty")]
    pub nat: Nat,
}

/// NAT — Network Address Translation. Kept separate from [`Firewall`] because it
/// *rewrites* addresses rather than *filtering* packets — a different thing that
/// happens at a different stage. Split into source NAT (`[[nat.source]]`,
/// masquerade) and destination NAT (`[[nat.destination]]`, port-forward),
/// mirroring the VyOS `nat source` / `nat destination` model.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nat {
    /// Source NAT: masquerade traffic egressing a zone to that zone's egress IP
    /// (the classic WAN uplink). Enforced in the data plane (Phase 4b).
    #[serde(default, rename = "source", skip_serializing_if = "Vec::is_empty")]
    pub source: Vec<NatSource>,
    /// Destination NAT: inbound port-forwards.
    #[serde(default, rename = "destination", skip_serializing_if = "Vec::is_empty")]
    pub destination: Vec<NatDestination>,
}

impl Nat {
    /// True when no NAT is configured — lets `[nat]` be omitted from a saved
    /// config that never set any.
    pub fn is_empty(&self) -> bool {
        self.source.is_empty() && self.destination.is_empty()
    }
}

/// A source-NAT (masquerade) rule: SNAT all traffic egressing `zone` to that
/// zone's egress address. The classic WAN masquerade.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NatSource {
    pub name: String,
    /// The egress (WAN) zone whose outbound traffic is masqueraded — must be
    /// backed by an interface.
    pub zone: String,
}

/// A destination-NAT (port-forward) rule: traffic hitting `zone`'s public
/// address on `proto`/`port` is rewritten to the internal host `to` (`"ip"` or
/// `"ip:port"`). The reply is SNAT'd back automatically and the firewall is
/// opened for it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NatDestination {
    pub name: String,
    /// The ingress zone (the public side) — must be backed by an interface.
    pub zone: String,
    pub proto: Proto,
    /// Public destination port matched inbound.
    pub port: u16,
    /// Internal target, `"10.0.0.10"` or `"10.0.0.10:8443"`.
    pub to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct System {
    pub hostname: String,
}

/// Global firewall settings, applied to every firewalled (zoned) interface.
/// These map onto Velstra's per-policy `stateful` / `drop_icmp` / `blocklist`
/// — capabilities the data plane already enforces.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Firewall {
    /// Stateful inspection: track allowed flows so return traffic comes back
    /// without an explicit rule. On by default (a real firewall default).
    #[serde(default = "default_true")]
    pub stateful: bool,
    /// Drop inbound ICMP at firewalled interfaces (echo, etc.). Off by default
    /// — ICMP is useful (PMTU, ping); turn on to go quiet.
    #[serde(default)]
    pub block_icmp: bool,
    /// Source IPs/CIDRs dropped outright on every firewalled interface — a
    /// global denylist evaluated before any zone posture.
    #[serde(default)]
    pub blocklist: Vec<String>,
    /// The default ingress action a zone inherits when it neither sets its own
    /// `default_action` nor is opened by a broad accept rule. `drop` by default.
    #[serde(default = "default_drop")]
    pub default_action: Action,
    /// Log matched traffic by default (zones inherit this). Off by default.
    #[serde(default)]
    pub log: bool,
}

fn default_true() -> bool {
    true
}

fn default_drop() -> Action {
    Action::Drop
}

impl Default for Firewall {
    fn default() -> Self {
        Firewall {
            stateful: true,
            block_icmp: false,
            blocklist: Vec::new(),
            default_action: Action::Drop,
            log: false,
        }
    }
}

impl Firewall {
    /// True when this is exactly the default posture — used to omit `[firewall]`
    /// from saved configs that never touched it.
    pub fn is_default(&self) -> bool {
        self.stateful
            && !self.block_icmp
            && self.blocklist.is_empty()
            && self.default_action == Action::Drop
            && !self.log
    }
}

/// A named network zone — the trust boundary a firewall reasons about. Zones are
/// arbitrary (`wan`, `lan`, `dmz`, `guest`, `iot`, …); each becomes one Velstra
/// policy. Per-zone posture fields are optional and inherit the global
/// [`Firewall`] defaults when unset, so you can (for example) block ICMP on
/// `wan` but allow it on `lan`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneCfg {
    /// Stateful inspection for this zone (inherits `[firewall] stateful`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stateful: Option<bool>,
    /// Drop inbound ICMP on this zone (inherits `[firewall] block_icmp`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_icmp: Option<bool>,
    /// Source IPs/CIDRs dropped on this zone's interfaces (added to the global
    /// blocklist).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocklist: Vec<String>,
    /// Ingress default action for this zone (inherits `[firewall]
    /// default_action`, else `drop`). An explicit value overrides the
    /// rule-derived posture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_action: Option<Action>,
    /// Log matched traffic for this zone (inherits `[firewall] log`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<bool>,
}

/// A zone's posture after inheriting the global `[firewall]` defaults — the
/// concrete values the compiler emits onto the zone's Velstra policy.
#[derive(Debug, Clone)]
pub struct ResolvedZone {
    pub stateful: bool,
    pub block_icmp: bool,
    pub blocklist: Vec<String>,
    /// An explicit per-zone default-action override; `None` ⇒ the compiler uses
    /// the rule-derived posture (broad accept ⇒ pass) or the firewall default.
    pub default_action: Option<Action>,
    pub log: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    /// The zone this interface belongs to (a key in `[zone.*]` / referenced by
    /// rules). `None` for a NIC the system provides but the operator hasn't
    /// assigned yet (it shows up in the config but is not firewalled until a zone
    /// is set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// `"dhcp"` or a CIDR like `"10.0.0.1/24"`. `None` if not yet configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// For an 802.1Q VLAN subinterface: the parent interface it rides on. Set
    /// together with `vlan`. `None` for a physical NIC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// VLAN id (1–4094) for a subinterface. Set together with `parent`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u16>,
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
    /// Source zone name (must be a zone backed by at least one interface).
    pub from: String,
    /// Destination zone name.
    pub to: String,
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

        // Every blocklist entry must be a valid IPv4 address or CIDR.
        for entry in &self.firewall.blocklist {
            validate_cidr_or_ip(entry).context("firewall.blocklist")?;
        }

        // Per-zone blocklists must also be valid.
        for (name, z) in &self.zones {
            for entry in &z.blocklist {
                validate_cidr_or_ip(entry).with_context(|| format!("zone {name:?} blocklist"))?;
            }
        }

        let names: HashSet<&str> = self.interfaces.iter().map(|i| i.name.as_str()).collect();
        let mut seen = HashSet::new();
        for iface in &self.interfaces {
            if !seen.insert(&iface.name) {
                bail!("duplicate interface {:?}", iface.name);
            }
            if let Some(addr) = &iface.address {
                validate_address(addr).with_context(|| format!("interface {:?}", iface.name))?;
            }
            // VLAN subinterface: parent + vlan come as a pair; vlan in range; the
            // parent must be a declared interface.
            match (&iface.parent, iface.vlan) {
                (Some(parent), Some(vlan)) => {
                    if !(1..=4094).contains(&vlan) {
                        bail!("interface {:?}: vlan {vlan} out of range (1–4094)", iface.name);
                    }
                    if !names.contains(parent.as_str()) {
                        bail!(
                            "interface {:?}: parent {parent:?} is not a declared interface",
                            iface.name
                        );
                    }
                }
                (None, None) => {}
                _ => bail!(
                    "interface {:?}: `parent` and `vlan` must be set together",
                    iface.name
                ),
            }
        }

        // Every rule's zones must be backed by at least one *assigned* interface,
        // else the rule can never match — a common, silent misconfiguration.
        let zones_in_use: HashSet<&str> =
            self.interfaces.iter().filter_map(|i| i.zone.as_deref()).collect();
        for rule in &self.rules {
            for (which, zone) in [("from", &rule.from), ("to", &rule.to)] {
                if !zones_in_use.contains(zone.as_str()) {
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

        // Source NAT (masquerade) targets a zone that must have an interface.
        for src in &self.nat.source {
            if !zones_in_use.contains(src.zone.as_str()) {
                bail!(
                    "nat source {:?}: zone {:?} has no interface",
                    src.name,
                    src.zone
                );
            }
        }

        // Destination NAT (port-forward) targets a zone (must have an interface)
        // and a valid internal host.
        for dst in &self.nat.destination {
            if !zones_in_use.contains(dst.zone.as_str()) {
                bail!(
                    "nat destination {:?}: zone {:?} has no interface",
                    dst.name,
                    dst.zone
                );
            }
            parse_host_port(&dst.to)
                .with_context(|| format!("nat destination {:?}", dst.name))?;
        }
        Ok(())
    }

    /// The resolved posture for a zone: the zone's own override (`[zone.<name>]`)
    /// falling back to the global `[firewall]` defaults. Used by the compiler.
    pub fn zone_posture(&self, zone: &str) -> ResolvedZone {
        let z = self.zones.get(zone);
        let fw = &self.firewall;
        let mut blocklist = fw.blocklist.clone();
        if let Some(z) = z {
            blocklist.extend(z.blocklist.iter().cloned());
        }
        ResolvedZone {
            stateful: z.and_then(|z| z.stateful).unwrap_or(fw.stateful),
            block_icmp: z.and_then(|z| z.block_icmp).unwrap_or(fw.block_icmp),
            blocklist,
            default_action: z.and_then(|z| z.default_action),
            log: z.and_then(|z| z.log).unwrap_or(fw.log),
        }
    }

    /// A human-readable summary for `config show`.
    pub fn summary(&self) -> String {
        let mut out = format!("hostname: {}\n", self.system.hostname);
        out.push_str(&format!("interfaces ({}):\n", self.interfaces.len()));
        for i in &self.interfaces {
            out.push_str(&format!(
                "  {:<8} {:<12} {}\n",
                i.name,
                i.zone.as_deref().unwrap_or("(unassigned)"),
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
                r.from,
                r.to,
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

/// Parse a port-forward target `"ip"` or `"ip:port"` into an IPv4 + a port
/// (`0` when omitted, meaning "keep the public port").
pub(crate) fn parse_host_port(s: &str) -> Result<(Ipv4Addr, u16)> {
    let (ip, port) = match s.rsplit_once(':') {
        Some((ip, port)) => (
            ip,
            port.parse::<u16>()
                .with_context(|| format!("invalid port in {s:?}"))?,
        ),
        None => (s, 0),
    };
    let ip = ip
        .parse::<Ipv4Addr>()
        .with_context(|| format!("invalid IPv4 in {s:?}"))?;
    Ok((ip, port))
}

/// Validate a firewall blocklist entry: a bare IPv4 (`192.0.2.5`) or an IPv4
/// CIDR (`10.6.6.0/24`).
pub(crate) fn validate_cidr_or_ip(s: &str) -> Result<()> {
    if let Some((ip, prefix)) = s.split_once('/') {
        ip.parse::<Ipv4Addr>()
            .with_context(|| format!("invalid IPv4 in {s:?}"))?;
        let prefix: u8 = prefix
            .parse()
            .with_context(|| format!("invalid prefix in {s:?}"))?;
        if prefix > 32 {
            bail!("prefix /{prefix} in {s:?} exceeds /32");
        }
    } else {
        s.parse::<Ipv4Addr>()
            .with_context(|| format!("invalid IP/CIDR {s:?}"))?;
    }
    Ok(())
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
            zone = "wan"
            address = "dhcp"
            [[interface]]
            name = "eth0"
            zone = "lan"
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
            zone = "lan"
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
    fn nat_tables_round_trip_through_toml() {
        let toml = r#"
[system]
hostname = "fw"
[[interface]]
name = "wan0"
zone = "wan"
[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"

[[nat.source]]
name = "wan-masq"
zone = "wan"

[[nat.destination]]
name = "web"
zone = "wan"
proto = "tcp"
port = 443
to = "10.0.0.10:8443"
"#;
        let a = Appliance::from_toml(toml).expect("nat config parses + validates");
        assert_eq!(a.nat.source.len(), 1);
        assert_eq!(a.nat.destination.len(), 1);
        // Serialize back out and reparse — the `[[nat.source]]`/`[[nat.destination]]`
        // tables must survive a save→load cycle unchanged.
        let out = a.to_toml().unwrap();
        assert!(out.contains("[[nat.source]]"), "got:\n{out}");
        assert!(out.contains("[[nat.destination]]"), "got:\n{out}");
        let b = Appliance::from_toml(&out).expect("re-parses");
        assert_eq!(b.nat.source[0].zone, "wan");
        assert_eq!(b.nat.destination[0].to, "10.0.0.10:8443");
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
