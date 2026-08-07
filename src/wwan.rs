//! Cellular uplinks: a modem, its bearer, and ModemManager.
//!
//! A `type = "wwan"` interface is a net device the kernel already provides once
//! ModemManager has probed the modem. What Sentinel adds is the *bearer* — the
//! APN and credentials the modem dials — and the address comes from
//! `address = "dhcp"` the way it does on any other uplink. A modem is a WAN link
//! that happens to dial; giving it its own kind of addressing would be a second
//! path to the same answer.
//!
//! ModemManager has no configuration file for a bearer: connecting is an
//! imperative act (`mmcli --simple-connect`). So this renders a dial script per
//! interface and runs it from a templated unit, the way MACsec and L2TPv3 are
//! built by `ip` commands and PPPoE by `pppd` — the pattern this appliance uses
//! whenever the thing being configured has no config file.
//!
//! The script is 0600 root:root. It holds the APN password and the SIM PIN.
//!
//! **What is verified, and what is not.** A virtual machine has no modem, so
//! `checks.wwan` runs the rendered script through its unit against a stand-in
//! for `mmcli` that answers the way the real one does — and the stand-in reports
//! *two* modems, so "found by its interface" is an assertion rather than a
//! coincidence of both being zero. That exercises which modem is picked, whether
//! the SIM is unlocked and through which path, what is dialled, and whether a
//! dropped bearer is re-dialled. What it cannot show is that real ModemManager
//! output matches the stand-in's; that is the one thing left for hardware.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::config::{Appliance, Interface, Wwan};
use crate::system;

/// Runtime dir for the rendered dial scripts (tmpfs; re-seeded each boot).
///
/// 0755 with each script 0600 root:root, for the reason the radio directory
/// records: the reconcile has to list this directory to retire an uplink, and
/// `commit` does not run as root. The secrets are in the files.
const WWAN_RUNTIME_DIR: &str = "/run/sentinel/wwan";

/// The rendered dial script for one modem.
fn script_path(iface: &str) -> PathBuf {
    Path::new(WWAN_RUNTIME_DIR).join(format!("{iface}.sh"))
}

/// The templated unit that runs it.
fn unit(iface: &str) -> String {
    format!("sentinel-wwan@{iface}.service")
}

/// A single-quoted shell word. Every value here has passed validation, so the
/// charset is already narrow — quote anyway, so an empty APN cannot splice the
/// `--simple-connect` argument into something else.
fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The dial script for one modem.
///
/// A loop rather than a one-shot: a cellular bearer drops — a tunnel, a cell
/// change, an operator-side timeout — and an uplink that dials once is an uplink
/// that is down until somebody notices. The loop re-dials, and the unit's own
/// `Restart=` covers the case where the script itself dies.
pub(crate) fn dial_script(iface: &str, w: &Wwan) -> String {
    let mut s = String::from("#!/bin/sh\n# rendered by sentinel — cellular bearer\nset -u\n");
    // The modem is found by the net device it provides, not by an index: indices
    // are assigned in probe order and change when a modem is re-plugged or a
    // second one appears, and dialling the wrong modem is worse than not
    // dialling.
    s.push_str(&format!("IFACE={}\n", shq(iface)));
    s.push_str(
        r#"find_modem() {
  for m in $(mmcli -L --output-keys 2>/dev/null | sed -n 's#.*/Modem/\([0-9]\+\).*#\1#p'); do
    if mmcli -m "$m" --output-keys 2>/dev/null | grep -q "modem.generic.ports.*$IFACE"; then
      echo "$m"; return 0
    fi
  done
  return 1
}
"#,
    );
    let mut connect = format!("apn={}", w.apn);
    if let Some(u) = &w.username {
        connect.push_str(&format!(",user={u}"));
    }
    if let Some(p) = &w.password {
        connect.push_str(&format!(",password={p}"));
    }
    connect.push_str(&format!(
        ",ip-type={}",
        w.ip_type.as_deref().unwrap_or("ipv4v6")
    ));
    s.push_str(&format!("CONNECT={}\n", shq(&connect)));
    if let Some(pin) = &w.pin {
        s.push_str(&format!("PIN={}\n", shq(pin)));
    }
    s.push_str(
        r#"
while :; do
  M=$(find_modem) || { sleep 10; continue; }
"#,
    );
    // Only when a PIN is configured, and only when the SIM is actually asking
    // for one. A card that is not locked does not want a PIN, and sending one
    // anyway spends an attempt off a counter of three.
    if w.pin.is_some() {
        s.push_str(
            r#"  if mmcli -m "$M" --output-keys | grep -q 'modem.generic.state.*locked'; then
    # The SIM's own path, not the modem index. `-i` takes a SIM, and the two
    # coincide only when there is exactly one modem with one SIM — so using the
    # modem index works on most hardware and unlocks the wrong card on the
    # hardware where it matters.
    SIM=$(mmcli -m "$M" --output-keys | sed -n 's/^modem\.generic\.sim *: *//p')
    [ -n "$SIM" ] || { sleep 30; continue; }
    mmcli -i "$SIM" --pin="$PIN" || { sleep 30; continue; }
  fi
"#,
        );
    }
    s.push_str(
        r#"  if mmcli -m "$M" --simple-connect="$CONNECT"; then
    # Connected. Watch the bearer and re-dial when it goes away.
    while mmcli -m "$M" --output-keys 2>/dev/null | grep -q 'modem.generic.state.*connected'; do
      sleep 10
    done
  fi
  sleep 10
done
"#,
    );
    s
}

/// The modems this box dials.
fn modems(appliance: &Appliance) -> Vec<(&Interface, &Wwan)> {
    appliance
        .interfaces
        .iter()
        .filter_map(|i| i.wwan.as_ref().map(|w| (i, w)))
        .collect()
}

/// Reconcile the cellular uplinks to `appliance`.
pub fn apply(appliance: &Appliance) -> Result<()> {
    let modems = modems(appliance);
    if modems.is_empty() && !Path::new(WWAN_RUNTIME_DIR).exists() {
        return Ok(());
    }
    system::ensure_dir_mode(Path::new(WWAN_RUNTIME_DIR), "0755")?;

    let mut desired: HashSet<String> = HashSet::new();
    for (i, w) in &modems {
        let body = dial_script(&i.name, w);
        let path = script_path(&i.name);
        let changed = crate::net::file_changed(&path, &body);
        system::install_private_file(&path, &body)?;
        desired.insert(i.name.clone());
        // Only when the dial itself changed. A restart re-dials, and re-dialling
        // a working uplink because an unrelated setting moved is a WAN outage
        // nobody asked for.
        if changed {
            if let Err(e) = system::radio_restart(&unit(&i.name)) {
                eprintln!(
                    "warning: (re)dialling {} failed (applies on next commit/boot): {e}",
                    i.name
                );
            }
        }
    }

    let entries = std::fs::read_dir(WWAN_RUNTIME_DIR)
        .with_context(|| format!("listing {WWAN_RUNTIME_DIR}"))?;
    for e in entries.flatten() {
        let file = e.file_name().to_string_lossy().into_owned();
        let Some(name) = file.strip_suffix(".sh") else {
            continue;
        };
        if desired.contains(name) {
            continue;
        }
        let _ = system::radio_stop(&unit(name));
        system::remove_file(&e.path())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bearer() -> Wwan {
        Wwan {
            apn: "internet".into(),
            username: None,
            password: None,
            pin: None,
            ip_type: None,
        }
    }

    #[test]
    fn the_bearer_carries_the_apn_and_defaults_to_dual_stack() {
        let s = dial_script("wwan0", &bearer());
        assert!(s.contains("apn=internet"), "{s}");
        assert!(s.contains("ip-type=ipv4v6"), "{s}");
        assert!(s.contains("--simple-connect"), "{s}");
    }

    #[test]
    fn credentials_are_only_sent_when_configured() {
        let mut w = bearer();
        assert!(!dial_script("wwan0", &w).contains("user="));
        w.username = Some("alice".into());
        w.password = Some("s3cret".into());
        let s = dial_script("wwan0", &w);
        assert!(s.contains("user=alice"), "{s}");
        assert!(s.contains("password=s3cret"), "{s}");
    }

    /// A SIM PIN is spent off a counter of three, so the script asks the modem
    /// whether it is locked before sending one — and sends nothing at all when
    /// none is configured.
    #[test]
    fn a_pin_is_sent_only_when_set_and_only_to_a_locked_sim() {
        let s = dial_script("wwan0", &bearer());
        assert!(!s.contains("--pin"), "{s}");

        let mut w = bearer();
        w.pin = Some("1234".into());
        let s = dial_script("wwan0", &w);
        assert!(s.contains("--pin="), "{s}");
        // The guard, not just the command.
        assert!(s.contains("state.*locked"), "{s}");
        // And the SIM's own path rather than the modem index: `-i` takes a SIM,
        // and the two coincide only when there is one modem with one SIM.
        assert!(s.contains("modem\\.generic\\.sim"), "{s}");
        assert!(s.contains("--pin=\"$PIN\""), "{s}");
        assert!(!s.contains("mmcli -i \"$M\""), "{s}");
    }

    /// The modem is located by the net device it provides. An index changes when
    /// a modem is re-plugged or a second one appears, and dialling the wrong
    /// modem is worse than not dialling.
    #[test]
    fn the_modem_is_found_by_its_interface_not_by_an_index() {
        let s = dial_script("wwan0", &bearer());
        assert!(s.contains("IFACE='wwan0'"), "{s}");
        assert!(s.contains("find_modem"), "{s}");
        assert!(!s.contains("-m 0"), "{s}");
    }

    /// A bearer that drops has to be re-dialled: an uplink that dials once is an
    /// uplink that is down until somebody notices.
    #[test]
    fn a_dropped_bearer_is_redialled() {
        let s = dial_script("wwan0", &bearer());
        assert!(s.contains("while :; do"), "{s}");
        assert!(s.contains("state.*connected"), "{s}");
    }
}
