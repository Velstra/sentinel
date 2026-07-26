//! Intrusion detection (roadmap C11): Suricata watching the wire.
//!
//! ## Why AF_PACKET works here at all
//!
//! Velstra's data plane runs the firewall in XDP, and an XDP program that
//! forwarded packets itself would make them invisible to everything above it. It
//! does not: an allowed packet ends on `XDP_PASS` and the kernel routes it
//! normally, so it still traverses the stack where AF_PACKET taps it. The
//! detector therefore sees exactly the traffic the firewall admitted — which is
//! the interesting set, since what the firewall dropped needs no second opinion.
//!
//! ## Detection, not prevention — deliberately
//!
//! Suricata can drop, but only in an IPS mode that needs either NFQUEUE or an
//! inline AF_PACKET pair. Both would put a second verdict stage behind the eBPF
//! firewall, and then a packet could disappear for a reason `show firewall`
//! cannot explain. Two places to look for "why did this not arrive" is the sort
//! of thing that costs an hour at 3am. Blocking stays with the data plane that
//! owns the policy; a rule's `drop` action is refused at commit rather than
//! accepted and quietly ignored.
//!
//! ## Alerts go to the journal
//!
//! EVE JSON is emitted through syslog, which journald receives and attributes to
//! the unit. That gets rotation for free, makes `show ids alerts` a journal
//! query, and means alerts reach a SIEM through the remote-syslog forwarding
//! that is already configured — instead of a second log file with its own
//! rotation policy and its own way of filling a disk. The unit disables
//! journald's rate limit for exactly this reason: an alert storm is when the
//! records matter most, and it is precisely what the default limit would
//! discard.
//!
//! (Not stdout, which would be the obvious way to reach the journal: systemd
//! hands a unit a socket there, and Suricata opens its output by path — so
//! `/dev/stdout` fails with ENXIO and the whole eve-log output silently does not
//! start.)

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

use crate::{
    config::{Appliance, Ids},
    system,
};

/// The rendered detector config. Under `/run` because it is derived from the
/// appliance config on every commit and has no reason to survive a boot.
pub const SURICATA_CONF: &str = "/run/sentinel/suricata.yaml";
/// The rendered rule file holding the rules written in the configuration.
pub const SURICATA_RULES: &str = "/run/sentinel/suricata.rules";
/// The unit the image defines; Sentinel starts and stops it with the config.
pub const SURICATA_UNIT: &str = "sentinel-ids.service";
/// Suricata insists on a writable log directory even when every output it is
/// given goes elsewhere. systemd creates and owns this one (`LogsDirectory=` on
/// the unit), so nothing here has to mkdir as root. EVE output does not land
/// here — see the module note.
const SURICATA_LOG_DIR: &str = "/var/log/suricata";

/// Where the classification and reference files ship. Suricata refuses to load a
/// rule whose `classtype:` it cannot resolve, and every published ruleset uses
/// them, so these are not optional. The image pins the path.
fn suricata_share() -> String {
    std::env::var("SENTINEL_SURICATA_SHARE")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "/etc/suricata".to_string())
}

/// The rule file Sentinel renders, or `None` when detection is off.
///
/// Only the rules written in the configuration land here; an operator's own
/// ruleset files are referenced by path instead, because a ruleset is megabytes
/// and copying it would make the config file the second copy that goes stale.
pub fn rules_body(ids: &Ids) -> Option<String> {
    if ids.is_empty() {
        return None;
    }
    let mut body = String::from("# rendered by sentinel — rules from the configuration\n");
    for rule in &ids.rules {
        body.push_str(rule.trim());
        body.push('\n');
    }
    Some(body)
}

/// The Suricata config, or `None` when no interface is watched.
///
/// Hand-rolled rather than derived from the packaged `suricata.yaml`: that file
/// is two thousand lines of defaults, and an appliance should ship the settings
/// it actually means. Everything interpolated here is validated — interface
/// names, CIDRs and ruleset paths — so nothing can break out into YAML.
pub fn suricata_yaml_body(ids: &Ids) -> Option<String> {
    if ids.is_empty() {
        return None;
    }
    let share = suricata_share();
    let home_net = ids.home_net().join(",");
    let mut body = String::from("%YAML 1.1\n---\n# rendered by sentinel — do not edit\n");

    body.push_str("vars:\n  address-groups:\n");
    body.push_str(&format!("    HOME_NET: \"[{home_net}]\"\n"));
    body.push_str("    EXTERNAL_NET: \"!$HOME_NET\"\n");
    // Published rules reference these by name. Pointing them all at $HOME_NET is
    // what the upstream default does; a rule that names a server group the
    // operator never declared then still matches the inside of the network
    // rather than nothing at all.
    for group in [
        "HTTP_SERVERS",
        "SMTP_SERVERS",
        "SQL_SERVERS",
        "DNS_SERVERS",
        "TELNET_SERVERS",
        "AIM_SERVERS",
        "DNP3_SERVER",
        "DNP3_CLIENT",
        "MODBUS_CLIENT",
        "MODBUS_SERVER",
        "ENIP_CLIENT",
        "ENIP_SERVER",
    ] {
        body.push_str(&format!("    {group}: \"$HOME_NET\"\n"));
    }
    body.push_str("  port-groups:\n");
    for (name, ports) in [
        ("HTTP_PORTS", "80"),
        ("SHELLCODE_PORTS", "!80"),
        ("ORACLE_PORTS", "1521"),
        ("SSH_PORTS", "22"),
        ("DNP3_PORTS", "20000"),
        ("MODBUS_PORTS", "502"),
        ("FILE_DATA_PORTS", "[$HTTP_PORTS,110,143]"),
        ("FTP_PORTS", "21"),
        ("GENEVE_PORTS", "6081"),
        ("VXLAN_PORTS", "4789"),
        ("TEREDO_PORTS", "3544"),
    ] {
        body.push_str(&format!("    {name}: \"{ports}\"\n"));
    }

    body.push_str(&format!("\ndefault-log-dir: {SURICATA_LOG_DIR}\n"));

    // EVE through syslog: journald receives it and attributes it to the unit.
    // See the module note on why this beats both a log file and stdout.
    body.push_str("\noutputs:\n");
    body.push_str("  - eve-log:\n");
    body.push_str("      enabled: yes\n");
    body.push_str("      filetype: syslog\n");
    body.push_str("      types:\n");
    body.push_str("        - alert:\n");
    body.push_str("            payload: no\n");
    body.push_str("            metadata: yes\n");
    body.push_str("        - stats:\n");
    body.push_str("            totals: yes\n");
    body.push_str("            threads: no\n");
    // Flow/HTTP/DNS records would multiply the volume by orders of magnitude and
    // are a flow-export job, not a detection one. Alerts and totals only.

    body.push_str("\nlogging:\n");
    body.push_str("  default-log-level: notice\n");
    body.push_str("  outputs:\n");
    body.push_str("    - console:\n        enabled: yes\n");

    body.push_str("\naf-packet:\n");
    for (i, iface) in ids.interfaces.iter().enumerate() {
        body.push_str(&format!("  - interface: {iface}\n"));
        // A distinct cluster id per interface: sharing one would make the kernel
        // load-balance packets from different links into the same fanout group,
        // and Suricata would reassemble flows that never belonged together.
        body.push_str(&format!("    cluster-id: {}\n", 99 - i));
        body.push_str("    cluster-type: cluster_flow\n");
        body.push_str("    defrag: yes\n");
        // The detector must never influence forwarding, and `copy-mode` is what
        // would make it do so. Left unset on purpose.
        body.push_str("    use-mmap: yes\n");
        body.push_str("    tpacket-v3: yes\n");
    }

    body.push_str("\ndefault-rule-path: /run/sentinel\n");
    body.push_str("rule-files:\n");
    if !ids.rules.is_empty() {
        body.push_str("  - suricata.rules\n");
    }
    for path in &ids.rulesets {
        // A named-but-absent ruleset is skipped with a warning rather than left
        // in to abort the load: partial coverage from the rules that do exist
        // beats a detector that will not start at all. `show ids` reports the
        // gap so it is loud rather than silent.
        if Path::new(path).exists() {
            body.push_str(&format!("  - {path}\n"));
        } else {
            eprintln!(
                "warning: services ids ruleset {path}: no such file — skipping it; \
                 the detector will run without those rules"
            );
        }
    }

    body.push_str(&format!(
        "\nclassification-file: {share}/classification.config\n"
    ));
    body.push_str(&format!(
        "reference-config-file: {share}/reference.config\n"
    ));
    // Named explicitly: left out, Suricata looks for a compiled-in /etc path that
    // does not exist in a Nix image, and says so on every start.
    body.push_str(&format!("threshold-file: {share}/threshold.config\n"));

    // Bounded, appliance-sized engine settings. The upstream defaults assume a
    // dedicated sensor; a firewall shares its box with the data plane and the
    // routing daemon, and a detector that starves them is a worse outage than
    // the one it was watching for.
    body.push_str("\napp-layer:\n  protocols:\n    tls:\n      enabled: yes\n");
    body.push_str("    http:\n      enabled: yes\n");
    body.push_str("    dns:\n      enabled: yes\n");
    body.push_str("\nstream:\n  memcap: 64mb\n  reassembly:\n    memcap: 128mb\n");
    body.push_str("\nflow:\n  memcap: 64mb\n");
    body.push_str("\nhost-mode: router\n");
    Some(body)
}

/// Reconcile the detector to the configuration: render both files and start or
/// stop the unit.
pub fn apply(appliance: &Appliance) -> Result<()> {
    let ids = &appliance.services.ids;
    let conf = Path::new(SURICATA_CONF);
    let rules = Path::new(SURICATA_RULES);
    match suricata_yaml_body(ids) {
        Some(yaml) => {
            let rules_body = rules_body(ids).unwrap_or_default();
            let changed = crate::net::file_changed(conf, &yaml)
                || crate::net::file_changed(rules, &rules_body);
            // Rules first: the config names the rule file, so writing them the
            // other way round leaves a window where a restart reads the new
            // config against the old rules.
            system::install_file(rules, &rules_body)?;
            system::install_file(conf, &yaml)?;
            if changed {
                if let Err(e) = system::service_restart(SURICATA_UNIT) {
                    eprintln!(
                        "warning: (re)starting {SURICATA_UNIT} failed \
                         (applies on next start): {e}"
                    );
                }
            }
        }
        None => {
            if conf.exists() {
                if let Err(e) = system::service_stop(SURICATA_UNIT) {
                    eprintln!("warning: stopping {SURICATA_UNIT}: {e}");
                }
                system::remove_file(conf)?;
                system::remove_file(rules)?;
            }
        }
    }
    Ok(())
}

/// One decoded EVE alert, reduced to what an operator reads in a list.
pub struct IdsAlert {
    pub timestamp: String,
    pub signature: String,
    pub severity: u64,
    pub src: String,
    pub dst: String,
    pub proto: String,
}

/// The most recent alerts, newest last, read back out of the journal.
///
/// Suricata's own status lines share the stream, so only well-formed EVE alert
/// objects are kept — a line that does not parse is skipped rather than shown as
/// a broken alert.
pub fn recent_alerts(limit: usize) -> Result<Vec<IdsAlert>> {
    // Ask for more lines than alerts wanted: the stream carries stats records and
    // Suricata's startup chatter too, so a 1:1 request would return almost none.
    let lines = (limit * 20).clamp(200, 20_000);
    let out = Command::new(system::bin("journalctl"))
        .args([
            "-u",
            SURICATA_UNIT,
            "-n",
            &lines.to_string(),
            "--no-pager",
            "-o",
            "cat",
        ])
        .output()
        .context("running journalctl")?;
    if !out.status.success() {
        anyhow::bail!(
            "journalctl exited {}: {}",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut alerts: Vec<IdsAlert> = text.lines().filter_map(parse_alert).collect();
    if alerts.len() > limit {
        alerts.drain(..alerts.len() - limit);
    }
    Ok(alerts)
}

/// Decode one EVE line into an alert, or `None` when it is not one.
fn parse_alert(line: &str) -> Option<IdsAlert> {
    let line = line.trim();
    if !line.starts_with('{') {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    if v.get("event_type")?.as_str()? != "alert" {
        return None;
    }
    let alert = v.get("alert")?;
    Some(IdsAlert {
        timestamp: v
            .get("timestamp")
            .and_then(|t| t.as_str())
            .unwrap_or("-")
            .to_string(),
        signature: alert
            .get("signature")
            .and_then(|s| s.as_str())
            .unwrap_or("(unnamed)")
            .to_string(),
        severity: alert.get("severity").and_then(|s| s.as_u64()).unwrap_or(0),
        src: endpoint(&v, "src_ip", "src_port"),
        dst: endpoint(&v, "dest_ip", "dest_port"),
        proto: v
            .get("proto")
            .and_then(|p| p.as_str())
            .unwrap_or("-")
            .to_string(),
    })
}

/// `addr:port`, or the bare address for a protocol that has no ports.
fn endpoint(v: &serde_json::Value, addr_key: &str, port_key: &str) -> String {
    let addr = v.get(addr_key).and_then(|a| a.as_str()).unwrap_or("-");
    match v.get(port_key).and_then(|p| p.as_u64()) {
        Some(port) => format!("{addr}:{port}"),
        None => addr.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(rules: &[&str]) -> Ids {
        Ids {
            interfaces: vec!["eth1".into()],
            home_net: Vec::new(),
            rules: rules.iter().map(|r| r.to_string()).collect(),
            rulesets: Vec::new(),
        }
    }

    const RULE: &str =
        r#"alert icmp any any -> any any (msg:"test ping"; itype:8; sid:1000001; rev:1;)"#;

    /// Nothing is rendered until an interface is watched: a config file for a
    /// detector with nothing to look at would start a unit that reads no packets.
    #[test]
    fn nothing_renders_until_an_interface_is_watched() {
        assert!(suricata_yaml_body(&Ids::default()).is_none());
        assert!(rules_body(&Ids::default()).is_none());
    }

    /// The default HOME_NET must reach the rendered config. Almost every rule is
    /// written as external → home, so an empty HOME_NET silently matches nothing
    /// and the whole ruleset goes quiet.
    #[test]
    fn home_net_defaults_to_the_private_ranges() {
        let body = suricata_yaml_body(&ids(&[RULE])).expect("configured");
        assert!(body.contains("10.0.0.0/8"), "got:\n{body}");
        assert!(body.contains("192.168.0.0/16"), "got:\n{body}");
        assert!(body.contains("100.64.0.0/10"), "got:\n{body}");
        assert!(
            body.contains(r#"EXTERNAL_NET: "!$HOME_NET""#),
            "got:\n{body}"
        );

        let mut custom = ids(&[RULE]);
        custom.home_net = vec!["203.0.113.0/24".into()];
        let body = suricata_yaml_body(&custom).expect("configured");
        assert!(
            body.contains(r#"HOME_NET: "[203.0.113.0/24]""#),
            "got:\n{body}"
        );
        // The default must not be merged in alongside an explicit one.
        assert!(!body.contains("10.0.0.0/8"), "got:\n{body}");
    }

    /// Alerts must land in the journal rather than a private log file — that is
    /// what gets them rotation and remote forwarding for free.
    #[test]
    fn eve_output_goes_to_syslog() {
        let body = suricata_yaml_body(&ids(&[RULE])).expect("configured");
        assert!(body.contains("filetype: syslog"), "got:\n{body}");
        assert!(body.contains("- alert:"), "got:\n{body}");
        // Not stdout: systemd gives a unit a socket there and Suricata opens its
        // output by path, so the whole eve-log output would fail to start.
        assert!(!body.contains("/dev/stdout"), "got:\n{body}");
    }

    /// Each watched interface needs its own fanout cluster: one shared id makes
    /// the kernel mix packets from different links into the same group, and the
    /// detector then reassembles flows that never belonged together.
    #[test]
    fn each_interface_gets_its_own_cluster() {
        let mut two = ids(&[RULE]);
        two.interfaces = vec!["eth1".into(), "eth2".into()];
        let body = suricata_yaml_body(&two).expect("configured");
        assert!(body.contains("- interface: eth1"), "got:\n{body}");
        assert!(body.contains("- interface: eth2"), "got:\n{body}");
        assert!(body.contains("cluster-id: 99"), "got:\n{body}");
        assert!(body.contains("cluster-id: 98"), "got:\n{body}");
        // No copy-mode anywhere: that is what would put the detector in the
        // forwarding path.
        assert!(!body.contains("copy-mode"), "got:\n{body}");
    }

    /// The rule file is referenced only when there is one, and the classification
    /// file always — a rule with a `classtype:` fails to load without it, which
    /// takes down the entire ruleset.
    #[test]
    fn rule_files_and_classification_are_wired() {
        let body = suricata_yaml_body(&ids(&[RULE])).expect("configured");
        assert!(body.contains("- suricata.rules"), "got:\n{body}");
        assert!(body.contains("classification-file:"), "got:\n{body}");
        assert!(body.contains("reference-config-file:"), "got:\n{body}");

        let mut only_sets = ids(&[]);
        only_sets.rulesets = vec!["/does/not/exist.rules".into()];
        let body = suricata_yaml_body(&only_sets).expect("configured");
        // No inline rules ⇒ the rendered file is not listed, and the missing
        // ruleset is skipped rather than left in to abort the load.
        assert!(!body.contains("- suricata.rules"), "got:\n{body}");
        assert!(!body.contains("/does/not/exist.rules"), "got:\n{body}");

        let rules = rules_body(&ids(&[RULE])).expect("configured");
        assert!(rules.contains("sid:1000001"), "got:\n{rules}");
    }

    /// An EVE alert is decoded; Suricata's own status lines and its stats records
    /// share the stream and must not appear as alerts.
    #[test]
    fn only_eve_alert_records_are_decoded() {
        let alert = r#"{"timestamp":"2026-07-26T10:00:00.000000+0000","event_type":"alert","src_ip":"198.51.100.7","src_port":1234,"dest_ip":"10.0.0.5","dest_port":80,"proto":"TCP","alert":{"signature":"test ping","severity":2}}"#;
        let decoded = parse_alert(alert).expect("an alert");
        assert_eq!(decoded.signature, "test ping");
        assert_eq!(decoded.severity, 2);
        assert_eq!(decoded.src, "198.51.100.7:1234");
        assert_eq!(decoded.dst, "10.0.0.5:80");

        assert!(parse_alert(r#"{"event_type":"stats","stats":{}}"#).is_none());
        assert!(parse_alert("26/7/2026 -- 10:00:00 - <Notice> - Suricata 8.0.3").is_none());
        assert!(parse_alert("{not json").is_none());

        // ICMP has no ports; the endpoint must degrade to the bare address rather
        // than printing a port that was never there.
        let icmp = r#"{"timestamp":"t","event_type":"alert","src_ip":"10.0.0.1","dest_ip":"10.0.0.2","proto":"ICMP","alert":{"signature":"ping","severity":3}}"#;
        let decoded = parse_alert(icmp).expect("an alert");
        assert_eq!(decoded.src, "10.0.0.1");
        assert_eq!(decoded.dst, "10.0.0.2");
    }
}
