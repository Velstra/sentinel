//! Where would this packet go, and which rule decides it — answered from the
//! configuration alone, before a single packet is sent.
//!
//! An operator with a rule set of any size eventually asks "why can host A not
//! reach host B", and the honest answers are scattered: which zone the arriving
//! link is in, whether a port-forward rewrites the destination first, where the
//! routing table sends it, which rule of the dozens naming that zone wins, and
//! whether the leaving link masquerades. This walks those steps in the order the
//! data plane takes them and says what it found at each — the same job a
//! `test security-policy-match` does on a Palo Alto or `fw monitor` on a Check
//! Point, for a box that has no such command yet.
//!
//! It is a **simulation against the compiled config**, not a capture. Matching
//! runs over [`crate::compile::compile`]'s output rather than the operator's
//! rules, so the ranking is the one the data plane loads (interface-scoped
//! first, then a typed ICMP rule, then longest prefix, and on an equal prefix
//! the stricter action) and cannot drift from it. What it cannot see is state
//! the box only has at runtime: an established connection, a route learned from
//! a routing protocol, which uplink multi-WAN currently prefers. Each of those is
//! named in the answer where it would matter, so the reader knows what was
//! assumed.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::compile::{Policy, PortRule, VelstraConfig, compile};
use crate::config::Appliance;

/// The packet being asked about, as it arrives on the box.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Query {
    /// The link the packet arrives on.
    #[serde(rename = "in")]
    pub in_interface: String,
    /// `tcp`, `udp`, `icmp`, `icmpv6`, or another name the rule grammar knows.
    pub proto: String,
    pub src: IpAddr,
    pub dst: IpAddr,
    /// Zero for a protocol without ports.
    #[serde(default)]
    pub port: u16,
    /// The sender's hardware address, when a MAC-group rule should be consulted.
    #[serde(default, rename = "src-mac", skip_serializing_if = "Option::is_none")]
    pub src_mac: Option<String>,
    /// The ICMP/ICMPv6 type, when the protocol has one and a typed rule should
    /// be consulted.
    #[serde(default, rename = "icmp-type", skip_serializing_if = "Option::is_none")]
    pub icmp_type: Option<u8>,
}

/// One thing the walk established, in the order the data plane would.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Step {
    pub stage: &'static str,
    pub text: String,
}

/// A rule that was looked at and did not decide, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Considered {
    pub rule: String,
    pub outcome: String,
}

/// The whole answer.
#[derive(Debug, Clone, Serialize)]
pub struct Trace {
    /// `pass`, `drop`, `reject` — or `unfiltered` on a link the data plane is
    /// not attached to.
    pub verdict: &'static str,
    /// What decided it: a rule name, `blocklist`, `default`, `port-forward`, …
    pub decided_by: String,
    pub ingress_zone: Option<String>,
    pub egress_interface: Option<String>,
    pub egress_zone: Option<String>,
    /// The destination after any DNAT, so a reader sees what the rules matched.
    pub destination: String,
    pub steps: Vec<Step>,
    pub considered: Vec<Considered>,
}

impl Trace {
    /// The answer as a person reads it on a terminal.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for s in &self.steps {
            out.push_str(&format!("{:<10} {}\n", format!("{}:", s.stage), s.text));
        }
        if !self.considered.is_empty() {
            out.push_str("\nrules looked at and passed over:\n");
            for c in &self.considered {
                out.push_str(&format!("  {:<24} {}\n", c.rule, c.outcome));
            }
        }
        out.push_str(&format!(
            "\nverdict:   {} ({})\n",
            self.verdict, self.decided_by
        ));
        out
    }
}

/// Walk the packet through the configuration.
///
/// Fails only when the question itself is malformed — a link that does not
/// exist, a protocol the grammar has no word for. A packet that would be dropped
/// is an answer, not an error.
pub fn trace(appliance: &Appliance, q: &Query) -> anyhow::Result<Trace> {
    let cfg = compile(appliance);
    Walk::new(appliance, &cfg, q)?.run()
}

/// The state of one walk. A struct rather than a long function so each stage
/// reads on its own and the order they run in is one list at the bottom.
struct Walk<'a> {
    appliance: &'a Appliance,
    cfg: &'a VelstraConfig,
    q: &'a Query,
    dst: IpAddr,
    dst_port: u16,
    steps: Vec<Step>,
    considered: Vec<Considered>,
    ingress_zone: Option<String>,
    egress_interface: Option<String>,
    egress_zone: Option<String>,
}

/// What a stage decided, when it decided anything.
enum Outcome {
    /// Keep walking.
    Continue,
    /// The walk is over: this verdict, decided by that.
    Final(&'static str, String),
}

impl<'a> Walk<'a> {
    fn new(appliance: &'a Appliance, cfg: &'a VelstraConfig, q: &'a Query) -> anyhow::Result<Self> {
        let known = [
            "tcp", "udp", "icmp", "icmpv6", "vrrp", "esp", "ah", "gre", "ospf", "pim",
        ];
        if !known.contains(&q.proto.as_str()) {
            anyhow::bail!(
                "unknown protocol {:?} (one of {})",
                q.proto,
                known.join(", ")
            );
        }
        if q.src.is_ipv4() != q.dst.is_ipv4() {
            anyhow::bail!("source and destination are in different address families");
        }
        if !appliance
            .interfaces
            .iter()
            .any(|i| i.name == q.in_interface)
        {
            anyhow::bail!("no interface named {:?}", q.in_interface);
        }
        Ok(Self {
            appliance,
            cfg,
            q,
            dst: q.dst,
            dst_port: q.port,
            steps: Vec::new(),
            considered: Vec::new(),
            ingress_zone: None,
            egress_interface: None,
            egress_zone: None,
        })
    }

    fn step(&mut self, stage: &'static str, text: impl Into<String>) {
        self.steps.push(Step {
            stage,
            text: text.into(),
        });
    }

    fn finish(self, verdict: &'static str, decided_by: String) -> Trace {
        Trace {
            verdict,
            decided_by,
            ingress_zone: self.ingress_zone,
            egress_interface: self.egress_interface,
            egress_zone: self.egress_zone,
            destination: endpoint(self.dst, self.dst_port),
            steps: self.steps,
            considered: self.considered,
        }
    }

    fn run(mut self) -> anyhow::Result<Trace> {
        // The order is the data plane's: what the link is, who is refused
        // outright, what the destination becomes, where it goes, which rule
        // speaks, and what the leaving link does to the source.
        let stages: [fn(&mut Self) -> Outcome; 7] = [
            Self::ingress,
            Self::blocklist,
            Self::source_validation,
            Self::dnat,
            Self::route,
            Self::rules,
            Self::snat,
        ];
        for stage in stages {
            if let Outcome::Final(verdict, by) = stage(&mut self) {
                return Ok(self.finish(verdict, by));
            }
        }
        Ok(self.finish("pass", "walk completed".into()))
    }

    fn policy(&self) -> Option<&'a Policy> {
        let zone = self.ingress_zone.as_deref()?;
        self.cfg.policies.iter().find(|p| p.name == zone)
    }

    // ---- the stages ---------------------------------------------------------

    fn ingress(&mut self) -> Outcome {
        let iface = self
            .appliance
            .interfaces
            .iter()
            .find(|i| i.name == self.q.in_interface)
            .expect("checked in new()");
        if iface.disabled {
            self.step(
                "ingress",
                format!("{} is disabled; nothing arrives on it", iface.name),
            );
            return Outcome::Final("drop", "interface disabled".into());
        }
        let Some(zone) = iface.zone.clone() else {
            self.step(
                "ingress",
                format!(
                    "{} is in no zone, so the data plane is not attached to it and \
                     filters nothing arriving there",
                    iface.name
                ),
            );
            return Outcome::Final("unfiltered", "interface has no zone".into());
        };
        let policy = self.cfg.policies.iter().find(|p| p.name == zone);
        let default = policy
            .map(|p| p.default_action)
            .unwrap_or(self.cfg.default_action);
        self.step(
            "ingress",
            format!(
                "{} is in zone {zone} (policy {}, default {default}, {})",
                iface.name,
                policy.map(|p| p.id).unwrap_or(0),
                if policy.is_some_and(|p| p.stateful) {
                    "stateful: replies to admitted flows pass by conntrack"
                } else {
                    "stateless"
                }
            ),
        );
        self.ingress_zone = Some(zone);
        Outcome::Continue
    }

    fn blocklist(&mut self) -> Outcome {
        let mut lists: Vec<(&str, &Vec<String>)> = vec![("firewall", &self.cfg.blocklist)];
        if let Some(p) = self.policy() {
            lists.push(("zone", &p.blocklist));
        }
        for (owner, list) in lists {
            if let Some(entry) = list.iter().find(|e| contains(e, self.q.src).is_some()) {
                self.step(
                    "blocklist",
                    format!(
                        "{} is on the {owner} blocklist ({entry}); dropped before any rule",
                        self.q.src
                    ),
                );
                return Outcome::Final("drop", "blocklist".into());
            }
        }
        Outcome::Continue
    }

    /// uRPF: is the source reachable back through the link it arrived on?
    fn source_validation(&mut self) -> Outcome {
        let Some(policy) = self.policy() else {
            return Outcome::Continue;
        };
        let mode = policy.source_validation;
        if mode == "disable" || mode.is_empty() {
            return Outcome::Continue;
        }
        let back = self.lookup(self.q.src);
        match back {
            Route::Via { interface, .. } if interface == self.q.in_interface => {
                self.step(
                    "urpf",
                    format!(
                        "{mode}: the way back to {} is {interface}, the arriving link",
                        self.q.src
                    ),
                );
                Outcome::Continue
            }
            Route::Via { interface, .. } if mode == "loose" => {
                self.step(
                    "urpf",
                    format!(
                        "loose: {} is routable (via {interface}), which is all loose asks",
                        self.q.src
                    ),
                );
                Outcome::Continue
            }
            Route::Via { interface, .. } => {
                self.step(
                    "urpf",
                    format!(
                        "strict: the way back to {} is {interface}, not {}; dropped as spoofed",
                        self.q.src, self.q.in_interface
                    ),
                );
                Outcome::Final("drop", "source validation".into())
            }
            Route::Blackhole(_) | Route::None => {
                self.step(
                    "urpf",
                    format!(
                        "{mode}: no route back to {}; dropped as unroutable",
                        self.q.src
                    ),
                );
                Outcome::Final("drop", "source validation".into())
            }
        }
    }

    fn dnat(&mut self) -> Outcome {
        let Some(policy) = self.policy() else {
            return Outcome::Continue;
        };
        let hit = self.cfg.port_forwards.iter().find(|f| {
            f.policy == policy.id
                && f.proto == self.q.proto
                && f.port == self.q.port
                && f.match_dst
                    .as_deref()
                    .is_none_or(|m| m.parse::<IpAddr>().ok() == Some(self.q.dst))
        });
        let Some(fwd) = hit else {
            return Outcome::Continue;
        };
        let name = self
            .appliance
            .nat
            .destination
            .iter()
            .find(|d| {
                !d.disabled
                    && d.proto
                        .concrete()
                        .iter()
                        .any(|p| proto_name(*p) == fwd.proto)
                    && d.port == fwd.port
            })
            .map(|d| d.name.clone())
            .unwrap_or_else(|| "?".into());
        let Ok(to) = fwd.dst_ip.parse::<IpAddr>() else {
            return Outcome::Continue;
        };
        self.dst = to;
        self.dst_port = fwd.dst_port;
        let hairpin = match &fwd.snat_ip {
            Some(s) => format!("; hairpin, source rewritten to {s}"),
            None => String::new(),
        };
        self.step(
            "dnat",
            format!(
                "port-forward {name} rewrites the destination to {}{hairpin}",
                endpoint(to, fwd.dst_port)
            ),
        );
        Outcome::Continue
    }

    fn route(&mut self) -> Outcome {
        if let Some(iface) = self.own_address(self.dst) {
            self.step(
                "route",
                format!(
                    "{} is this box's own address on {iface}; delivered locally",
                    self.dst
                ),
            );
            return Outcome::Continue;
        }
        if let Some(pbr) = self.policy_route() {
            self.step(
                "route",
                format!("policy route {} matches and sends it to table {}; that table's routes are not in the configuration", pbr.0, pbr.1),
            );
            return Outcome::Continue;
        }
        match self.lookup(self.dst) {
            Route::Via { interface, how } => {
                let zone = self
                    .appliance
                    .interfaces
                    .iter()
                    .find(|i| i.name == interface)
                    .and_then(|i| i.zone.clone());
                self.step(
                    "route",
                    format!(
                        "{} leaves on {interface} ({how}){}",
                        self.dst,
                        match &zone {
                            Some(z) => format!(", zone {z}"),
                            None => ", no zone".into(),
                        }
                    ),
                );
                if self.has_dynamic_routing() {
                    self.step(
                        "route",
                        "a routing protocol is configured; a route it learns is not in the \
                         configuration and a more specific one would win over this",
                    );
                }
                self.egress_interface = Some(interface);
                self.egress_zone = zone;
                Outcome::Continue
            }
            Route::Blackhole(prefix) => {
                self.step(
                    "route",
                    format!("{} falls in the blackhole route {prefix}", self.dst),
                );
                Outcome::Final("drop", "blackhole route".into())
            }
            Route::None => {
                self.step(
                    "route",
                    format!(
                        "no route to {}: no connected link, static route or uplink covers it{}",
                        self.dst,
                        if self.has_dynamic_routing() {
                            "; a routing protocol may still learn one at runtime"
                        } else {
                            ""
                        }
                    ),
                );
                Outcome::Final("drop", "no route".into())
            }
        }
    }

    fn rules(&mut self) -> Outcome {
        let Some(policy) = self.policy() else {
            return Outcome::Continue;
        };
        let is_icmp = self.q.proto == "icmp" || self.q.proto == "icmpv6";
        let forwarded = self.steps.iter().any(|s| s.stage == "dnat");
        if forwarded {
            self.step(
                "rules",
                "a matching port-forward admits the flow on its own; the zone's rules and \
                 default are not consulted for it",
            );
            return Outcome::Final("pass", "port-forward".into());
        }
        if is_icmp && policy.drop_icmp {
            self.step(
                "rules",
                format!(
                    "zone {} has block-icmp; every ICMP packet is dropped",
                    policy.name
                ),
            );
            return Outcome::Final("drop", "block-icmp".into());
        }
        let (winner, considered) = self.pick(policy);
        self.considered = considered;
        let Some(r) = winner else {
            self.step(
                "rules",
                format!(
                    "no rule in zone {} matches; the zone's default applies{}",
                    policy.name,
                    if policy.log {
                        " (logged: the zone logs)"
                    } else {
                        ""
                    }
                ),
            );
            if policy.default_action != "pass" {
                return Outcome::Final(policy.default_action, "default".into());
            }
            return Outcome::Continue;
        };
        let mut why = Vec::new();
        if let Some(i) = &r.in_interface {
            why.push(format!("scoped to {i}"));
        }
        if let Some(s) = &r.src {
            why.push(format!("source {s}"));
        }
        if let Some(d) = &r.dst {
            why.push(format!("destination {d}"));
        }
        if let Some(m) = &r.src_mac {
            why.push(format!("sender {m}"));
        }
        if r.port != 0 {
            why.push(format!("{}/{}", r.proto, r.port));
        } else {
            why.push(r.proto.to_string());
        }
        if let Some(t) = r.icmp_type {
            why.push(format!("type {t}"));
        }
        let mut notes = Vec::new();
        if r.log {
            notes.push("logged".to_string());
        }
        if let Some(l) = r.limit {
            notes.push(format!(
                "new flows limited to {l}/s; over that they are dropped"
            ));
        }
        self.step(
            "rules",
            format!(
                "rule {} matches ({}) → {}{}",
                r.name,
                why.join(", "),
                r.action,
                if notes.is_empty() {
                    String::new()
                } else {
                    format!("; {}", notes.join("; "))
                }
            ),
        );
        if r.action != "pass" {
            return Outcome::Final(r.action, r.name.clone());
        }
        let gated_elsewhere = policy.portal.as_ref().is_some_and(|portal| {
            ![portal.address.as_deref(), portal.address6.as_deref()]
                .into_iter()
                .flatten()
                .any(|a| a.parse::<IpAddr>().ok() == Some(self.dst))
        });
        if gated_elsewhere {
            self.step(
                "portal",
                "the zone is behind the captive portal: a device not yet admitted is \
                 redirected to it instead",
            );
        }
        Outcome::Continue
    }

    fn snat(&mut self) -> Outcome {
        let Some(egress) = self.egress_interface.clone() else {
            return Outcome::Final("pass", self.decider());
        };
        let Some(out) = self.cfg.interfaces.iter().find(|i| i.name == egress) else {
            return Outcome::Final("pass", self.decider());
        };
        if out.masquerade {
            let address = self
                .appliance
                .interfaces
                .iter()
                .find(|i| i.name == egress)
                .and_then(|i| {
                    if self.dst.is_ipv4() {
                        i.address.clone()
                    } else {
                        i.address6.clone()
                    }
                })
                .map(|a| a.split('/').next().unwrap_or(&a).to_string())
                .unwrap_or_else(|| "its address".into());
            let layout = if out.cgnat_block_size > 0 {
                format!(
                    " from a fixed block of {} ports per internal address (CGNAT)",
                    out.cgnat_block_size
                )
            } else {
                String::new()
            };
            self.step(
                "snat",
                format!("{egress} masquerades: the source becomes {address}{layout}"),
            );
        }
        Outcome::Final("pass", self.decider())
    }

    /// What passed it — the rule that matched, or the default.
    fn decider(&self) -> String {
        self.steps
            .iter()
            .find(|s| s.stage == "rules")
            .and_then(|s| s.text.strip_prefix("rule "))
            .and_then(|t| t.split(' ').next())
            .map(str::to_string)
            .unwrap_or_else(|| "default".into())
    }

    // ---- rule matching ------------------------------------------------------

    /// The rule the data plane would take, and the ones it would not.
    ///
    /// Mirrors `rule_winner_v4` in the fabric: a MAC verdict names the device
    /// and beats everything; a rule scoped to the arriving link beats one for
    /// the zone; a typed ICMP rule beats an untyped one; then the longest prefix
    /// on whichever end the rule binds, and on an equal prefix the stricter
    /// action.
    fn pick(&self, policy: &'a Policy) -> (Option<&'a PortRule>, Vec<Considered>) {
        let mut considered = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        let mut best: Option<(&PortRule, Rank)> = None;
        for r in &policy.port_rules {
            match self.mismatch(r) {
                Some(why) => {
                    if seen.insert(r.name.clone()) {
                        considered.push(Considered {
                            rule: r.name.clone(),
                            outcome: why,
                        });
                    }
                }
                None => {
                    let bits = match (&r.src, &r.dst) {
                        (Some(c), _) => contains(c, self.q.src).unwrap_or(0),
                        (_, Some(c)) => contains(c, self.dst).unwrap_or(0),
                        _ => 0,
                    };
                    let key = (
                        u8::from(r.src_mac.is_some()),
                        u8::from(r.in_interface.is_some()),
                        u8::from(r.icmp_type.is_some()),
                        bits,
                        strictness(r.action),
                    );
                    if best.is_none_or(|(_, k)| key > k) {
                        best = Some((r, key));
                    }
                }
            }
        }
        // A rule that matched but lost is worth naming too: "why did my rule
        // not fire" is usually "because that one is more specific".
        if let Some((winner, _)) = best {
            for r in &policy.port_rules {
                if r.name != winner.name
                    && self.mismatch(r).is_none()
                    && seen.insert(r.name.clone())
                {
                    considered.push(Considered {
                        rule: r.name.clone(),
                        outcome: format!("matches too, but {} is more specific", winner.name),
                    });
                }
            }
        }
        // Expanded rules share a name; the considered list should not repeat one
        // that also matched under another expansion.
        if let Some((winner, _)) = best {
            considered.retain(|c| c.rule != winner.name);
        }
        (best.map(|(r, _)| r), considered)
    }

    /// Why this compiled rule does not match, or `None` when it does.
    fn mismatch(&self, r: &PortRule) -> Option<String> {
        if let Some(mac) = &r.src_mac {
            return match &self.q.src_mac {
                Some(m) if m.eq_ignore_ascii_case(mac) => None,
                Some(_) => Some(format!("names sender {mac}")),
                None => Some("names a sender; no source MAC was given".into()),
            };
        }
        if r.direction.as_deref() == Some("out") {
            return Some("applies to traffic this box sends, not to arriving traffic".into());
        }
        if let Some(f) = &r.family {
            let v4 = f == "ipv4";
            if v4 != self.q.src.is_ipv4() {
                return Some(format!("is for {f} only"));
            }
        }
        if r.proto != self.q.proto {
            return Some(format!("is for {}", r.proto));
        }
        if let Some(t) = r.icmp_type {
            if self.q.icmp_type != Some(t) {
                return Some(format!("is for ICMP type {t}"));
            }
        }
        if r.port != 0 && r.port != self.dst_port {
            return Some(format!("is for port {}", r.port));
        }
        if let Some(i) = &r.in_interface {
            if *i != self.q.in_interface {
                return Some(format!("applies on {i} only"));
            }
        }
        if let Some(c) = &r.src {
            if contains(c, self.q.src).is_none() {
                return Some(format!("source {} is not in {c}", self.q.src));
            }
        }
        if let Some(c) = &r.dst {
            if contains(c, self.dst).is_none() {
                return Some(format!("destination {} is not in {c}", self.dst));
            }
        }
        None
    }

    // ---- routing ------------------------------------------------------------

    fn own_address(&self, addr: IpAddr) -> Option<String> {
        self.appliance
            .interfaces
            .iter()
            .filter(|i| !i.disabled)
            .find(|i| {
                [i.address.as_deref(), i.address6.as_deref()]
                    .into_iter()
                    .flatten()
                    .filter_map(|a| a.split('/').next()?.parse::<IpAddr>().ok())
                    .any(|a| a == addr)
            })
            .map(|i| i.name.clone())
    }

    fn policy_route(&self) -> Option<(String, u32)> {
        self.appliance
            .policy
            .routes
            .iter()
            .filter(|r| !r.disabled)
            .find(|r| {
                r.source
                    .as_deref()
                    .is_none_or(|c| contains(c, self.q.src).is_some())
                    && r.destination
                        .as_deref()
                        .is_none_or(|c| contains(c, self.dst).is_some())
                    && r.interface
                        .as_deref()
                        .is_none_or(|i| i == self.q.in_interface)
                    && r.proto.as_deref().is_none_or(|p| p == self.q.proto)
                    && r.destination_port
                        .as_deref()
                        .is_none_or(|p| port_matches(p, self.dst_port))
            })
            .map(|r| (r.name.clone(), r.table))
    }

    /// The plain routing decision: connected, then static, then a default the
    /// configuration implies.
    fn lookup(&self, addr: IpAddr) -> Route {
        let mut best: Option<(u8, Route)> = None;
        let mut offer = |bits: u8, route: Route| {
            if best.as_ref().is_none_or(|(b, _)| bits > *b) {
                best = Some((bits, route));
            }
        };
        for i in self.appliance.interfaces.iter().filter(|i| !i.disabled) {
            for a in [i.address.as_deref(), i.address6.as_deref()]
                .into_iter()
                .flatten()
            {
                if let Some(bits) = contains(a, addr) {
                    offer(
                        bits.saturating_add(1), // connected beats a static of equal length
                        Route::Via {
                            interface: i.name.clone(),
                            how: format!("connected, {a}"),
                        },
                    );
                }
            }
        }
        for s in &self.appliance.protocols.statics {
            let Some(bits) = contains(&s.prefix, addr) else {
                continue;
            };
            if s.blackhole {
                offer(bits, Route::Blackhole(s.prefix.clone()));
                continue;
            }
            let via_iface = s.dev.clone().or_else(|| {
                let via: IpAddr = s.via.as_deref()?.parse().ok()?;
                self.appliance
                    .interfaces
                    .iter()
                    .filter(|i| !i.disabled)
                    .find(|i| {
                        [i.address.as_deref(), i.address6.as_deref()]
                            .into_iter()
                            .flatten()
                            .any(|a| contains(a, via).is_some())
                    })
                    .map(|i| i.name.clone())
            });
            match via_iface {
                Some(interface) => offer(
                    bits,
                    Route::Via {
                        interface,
                        how: format!(
                            "static {}{}",
                            s.prefix,
                            s.via
                                .as_deref()
                                .map(|v| format!(" via {v}"))
                                .unwrap_or_default()
                        ),
                    },
                ),
                None => offer(bits, Route::None),
            }
        }
        if let Some((_, r)) = best {
            return r;
        }
        // Nothing covers it: the default the configuration implies — the first
        // multi-WAN uplink by priority, else the link that gets its address
        // from the provider.
        let uplinks = &self.appliance.multiwan.uplinks;
        if let Some(u) = uplinks
            .iter()
            .min_by_key(|u| u.priority.unwrap_or(u32::MAX))
        {
            return Route::Via {
                interface: u.interface.clone(),
                how: if uplinks.len() > 1 {
                    "multi-WAN: the uplink of highest priority, assumed healthy".into()
                } else {
                    "the multi-WAN uplink".into()
                },
            };
        }
        let provider = self
            .appliance
            .interfaces
            .iter()
            .filter(|i| !i.disabled)
            .find(|i| {
                if addr.is_ipv4() {
                    i.address.as_deref() == Some("dhcp") || i.pppoe.is_some()
                } else {
                    matches!(i.address6.as_deref(), Some("dhcp" | "auto")) || i.pppoe.is_some()
                }
            });
        match provider {
            Some(i) => Route::Via {
                interface: i.name.clone(),
                how: "default learned from the provider".into(),
            },
            None => Route::None,
        }
    }

    fn has_dynamic_routing(&self) -> bool {
        let p = &self.appliance.protocols;
        p.bgp.is_some()
            || p.ospf.is_some()
            || p.ospf3.is_some()
            || p.isis.is_some()
            || p.rip.is_some()
            || p.ripng.is_some()
            || p.babel.is_some()
    }
}

/// Where a lookup sends a packet.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Route {
    Via { interface: String, how: String },
    Blackhole(String),
    None,
}

/// How a matching rule ranks against another: a MAC verdict, then a rule scoped
/// to the link, then a typed ICMP rule, then the longer prefix, then the
/// stricter action — the data plane's own order.
type Rank = (u8, u8, u8, u8, u8);

/// pass < drop < reject, as the data plane ranks equal prefixes.
fn strictness(action: &str) -> u8 {
    match action {
        "reject" => 2,
        "drop" => 1,
        _ => 0,
    }
}

fn endpoint(addr: IpAddr, port: u16) -> String {
    match (addr, port) {
        (_, 0) => addr.to_string(),
        (IpAddr::V6(_), p) => format!("[{addr}]:{p}"),
        (_, p) => format!("{addr}:{p}"),
    }
}

fn proto_name(p: crate::config::Proto) -> &'static str {
    use crate::config::Proto::*;
    match p {
        Tcp => "tcp",
        Udp => "udp",
        Icmp => "icmp",
        Icmpv6 => "icmpv6",
        Vrrp => "vrrp",
        Esp => "esp",
        Ah => "ah",
        Gre => "gre",
        Ospf => "ospf",
        Pim => "pim",
        TcpUdp => "tcp_udp",
    }
}

/// `"80"`, `"8000-8100"` or `"80,443"` against a port.
fn port_matches(spec: &str, port: u16) -> bool {
    spec.split(',').any(|one| {
        let one = one.trim();
        match one.split_once('-') {
            Some((lo, hi)) => matches!(
                (lo.trim().parse::<u16>(), hi.trim().parse::<u16>()),
                (Ok(lo), Ok(hi)) if (lo..=hi).contains(&port)
            ),
            None => one.parse::<u16>().ok() == Some(port),
        }
    })
}

/// Whether `addr` is inside `entry` — a CIDR or a bare host — and how specific
/// that was. `None` when it is not, or when the families differ.
fn contains(entry: &str, addr: IpAddr) -> Option<u8> {
    let (net, len) = match entry.split_once('/') {
        Some((n, l)) => (n, l.parse::<u8>().ok()?),
        None => (entry, if entry.contains(':') { 128 } else { 32 }),
    };
    match (net.parse::<IpAddr>().ok()?, addr) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            if len > 32 {
                return None;
            }
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            (u32::from(n) & mask == u32::from(a) & mask).then_some(len)
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            if len > 128 {
                return None;
            }
            let mask = if len == 0 {
                0
            } else {
                u128::MAX << (128 - len)
            };
            (u128::from(n) & mask == u128::from(a) & mask).then_some(len)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOX: &str = r#"
[system]
hostname = "fw"

[firewall]
default_action = "drop"
blocklist = ["203.0.113.7"]

[zone.lan]
[zone.wan]
[zone.dmz]

[[interface]]
name = "wan0"
zone = "wan"
address = "198.51.100.2/24"

[[interface]]
name = "lan0"
zone = "lan"
address = "10.0.0.1/24"

[[interface]]
name = "dmz0"
zone = "dmz"
address = "10.9.0.1/24"

[[interface]]
name = "mgmt0"

[[protocols.static]]
prefix = "0.0.0.0/0"
via = "198.51.100.1"

[[protocols.static]]
prefix = "10.200.0.0/16"
blackhole = true

[[rule]]
name = "lan-out"
from = "lan"
action = "accept"

[[rule]]
name = "web-in"
from = "wan"
proto = "tcp"
port = 443
action = "accept"

[[rule]]
name = "no-ssh-from-guests"
from = "lan"
proto = "tcp"
port = 22
source = "10.0.0.128/25"
action = "drop"

[[rule]]
name = "ssh-to-dmz"
from = "lan"
proto = "tcp"
port = 22
action = "accept"

[[nat.source]]
name = "masq"
zone = "wan"

[[nat.destination]]
name = "web"
zone = "wan"
proto = "tcp"
port = 8080
to = "10.9.0.10:80"
"#;

    fn ask(iface: &str, proto: &str, src: &str, dst: &str, port: u16) -> Trace {
        let appliance = Appliance::from_toml(BOX).unwrap();
        trace(
            &appliance,
            &Query {
                in_interface: iface.into(),
                proto: proto.into(),
                src: src.parse().unwrap(),
                dst: dst.parse().unwrap(),
                port,
                src_mac: None,
                icmp_type: None,
            },
        )
        .unwrap()
    }

    fn stage<'a>(t: &'a Trace, s: &str) -> &'a str {
        &t.steps
            .iter()
            .find(|x| x.stage == s)
            .unwrap_or_else(|| panic!("no {s} step in {t:?}"))
            .text
    }

    #[test]
    fn a_lan_host_reaching_the_internet_passes_by_the_zone_default_and_masquerades() {
        let t = ask("lan0", "tcp", "10.0.0.5", "93.184.216.34", 443);
        assert_eq!(t.verdict, "pass");
        assert_eq!(t.decided_by, "default");
        assert_eq!(t.egress_interface.as_deref(), Some("wan0"));
        assert_eq!(t.egress_zone.as_deref(), Some("wan"));
        assert!(stage(&t, "route").contains("static 0.0.0.0/0 via 198.51.100.1"));
        assert!(stage(&t, "snat").contains("198.51.100.2"));
    }

    #[test]
    fn the_more_specific_rule_wins_and_the_other_is_named() {
        let t = ask("lan0", "tcp", "10.0.0.200", "10.9.0.10", 22);
        assert_eq!(t.verdict, "drop");
        assert_eq!(t.decided_by, "no-ssh-from-guests");
        assert!(
            t.considered
                .iter()
                .any(|c| c.rule == "ssh-to-dmz" && c.outcome.contains("more specific"))
        );
        // …and from the other half of the subnet the broad rule carries it.
        let t = ask("lan0", "tcp", "10.0.0.20", "10.9.0.10", 22);
        assert_eq!(t.verdict, "pass");
        assert_eq!(t.decided_by, "ssh-to-dmz");
        assert!(
            t.considered
                .iter()
                .any(|c| c.rule == "no-ssh-from-guests"
                    && c.outcome.contains("not in 10.0.0.128/25"))
        );
        assert_eq!(t.egress_interface.as_deref(), Some("dmz0"));
        assert!(stage(&t, "route").contains("connected"));
    }

    #[test]
    fn an_unmatched_inbound_packet_falls_to_the_wan_default() {
        let t = ask("wan0", "tcp", "8.8.8.8", "198.51.100.2", 22);
        assert_eq!(t.verdict, "drop");
        assert_eq!(t.decided_by, "default");
        assert!(stage(&t, "route").contains("own address"));
        assert!(
            t.considered
                .iter()
                .any(|c| c.rule == "web-in" && c.outcome == "is for port 443")
        );
    }

    #[test]
    fn a_port_forward_rewrites_the_destination_and_admits_on_its_own() {
        let t = ask("wan0", "tcp", "8.8.8.8", "198.51.100.2", 8080);
        assert_eq!(t.verdict, "pass");
        assert_eq!(t.decided_by, "port-forward");
        assert_eq!(t.destination, "10.9.0.10:80");
        assert!(stage(&t, "dnat").contains("port-forward web"));
        assert_eq!(t.egress_interface.as_deref(), Some("dmz0"));
    }

    #[test]
    fn a_blocklisted_source_is_dropped_before_any_rule() {
        let t = ask("wan0", "tcp", "203.0.113.7", "198.51.100.2", 443);
        assert_eq!(t.verdict, "drop");
        assert_eq!(t.decided_by, "blocklist");
        assert!(t.steps.iter().all(|s| s.stage != "rules"));
    }

    #[test]
    fn a_blackhole_route_drops_and_a_zoneless_link_is_unfiltered() {
        let t = ask("lan0", "udp", "10.0.0.5", "10.200.1.1", 53);
        assert_eq!(t.verdict, "drop");
        assert_eq!(t.decided_by, "blackhole route");
        let t = ask("mgmt0", "tcp", "10.0.0.5", "10.9.0.10", 22);
        assert_eq!(t.verdict, "unfiltered");
    }

    #[test]
    fn a_bad_question_is_refused_rather_than_answered() {
        let appliance = Appliance::from_toml(BOX).unwrap();
        let q = |iface: &str, proto: &str| Query {
            in_interface: iface.into(),
            proto: proto.into(),
            src: "10.0.0.5".parse().unwrap(),
            dst: "10.9.0.10".parse().unwrap(),
            port: 22,
            src_mac: None,
            icmp_type: None,
        };
        assert!(
            trace(&appliance, &q("eth9", "tcp"))
                .unwrap_err()
                .to_string()
                .contains("eth9")
        );
        assert!(
            trace(&appliance, &q("lan0", "sctp"))
                .unwrap_err()
                .to_string()
                .contains("sctp")
        );
    }

    #[test]
    fn the_rendering_reads_top_to_bottom() {
        let t = ask("lan0", "tcp", "10.0.0.5", "93.184.216.34", 443);
        let text = t.render();
        let first = text.lines().next().unwrap();
        assert!(first.starts_with("ingress:"), "{first}");
        assert!(
            text.trim_end().ends_with("verdict:   pass (default)"),
            "{text}"
        );
    }

    #[test]
    fn a_host_entry_on_a_blocklist_counts_as_a_full_prefix() {
        assert_eq!(
            contains("203.0.113.7", "203.0.113.7".parse().unwrap()),
            Some(32)
        );
        assert_eq!(
            contains("203.0.113.7", "203.0.113.8".parse().unwrap()),
            None
        );
        assert_eq!(
            contains("2001:db8::/32", "2001:db8::1".parse().unwrap()),
            Some(32)
        );
        assert!(port_matches("8000-8100", 8080));
        assert!(port_matches("80,443", 443));
        assert!(!port_matches("80,443", 8080));
    }
}
