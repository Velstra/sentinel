//! Wireless radios: `hostapd` for an access point, `wpa_supplicant` for a
//! station.
//!
//! A `type = "wireless"` interface is a NIC the kernel already provides, so
//! unlike a bridge or a tunnel there is nothing to create. What is rendered is
//! the daemon that makes the radio do something: `hostapd` builds a network,
//! `wpa_supplicant` joins one. Both configs are written to
//! `/run/sentinel/wireless/` and the matching templated unit is (re)started —
//! the same render + change-detect + restart model the PPPoE, IPsec and
//! OpenConnect appliers use, so an unrelated commit never drops a live radio.
//!
//! **Both files are 0600.** They contain the pre-shared key, and unlike IPsec
//! there is no separate secrets file to split it into: hostapd and
//! wpa_supplicant each want the passphrase inside their one config.
//!
//! What is *not* here is the HT/VHT/HE capability surface — roughly 130 of the
//! ~150 nodes VyOS exposes for a radio. Those are a passthrough of hostapd's own
//! flags, each meaningful only with a particular chipset and each able to make a
//! working radio refuse to come up. This renders what decides whether the
//! network exists, who may join it and on which channel.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::config::{Appliance, Interface, Wireless};
use crate::system;

/// Runtime dir for the rendered radio configs (tmpfs; re-seeded each boot).
///
/// 0755, with each file inside it 0600 root:root. The key is what is secret, and
/// the file mode is what protects it; the *names* are just the interfaces that
/// have a radio, which `show configuration` prints anyway.
///
/// It was 0700 first, and that made the reconcile unable to retire anything. The
/// cleanup pass lists this directory to find configs no interface claims any
/// more, `commit` runs as the operator rather than as root, and a 0700 root-owned
/// directory cannot be listed. A deleted radio kept its config and its daemon.
const WIRELESS_RUNTIME_DIR: &str = "/run/sentinel/wireless";

/// The rendered config for one radio.
fn conf_path(iface: &str) -> PathBuf {
    Path::new(WIRELESS_RUNTIME_DIR).join(format!("{iface}.conf"))
}

/// The templated unit that runs the daemon for one radio.
fn unit(iface: &str, ap: bool) -> String {
    let kind = if ap { "hostapd" } else { "supplicant" };
    format!("sentinel-{kind}@{iface}.service")
}

/// `hw_mode` and the generation switch for a band.
///
/// The band decides the frequency as well as the generation — `b`/`g`/`n` are
/// 2.4 GHz and `a`/`ac`/`ax` are 5 GHz — which is why a channel that disagrees
/// with it is refused at commit rather than left for the driver to reject at
/// three in the morning.
fn hw_mode(band: &str) -> (&'static str, Option<&'static str>) {
    match band {
        "b" => ("b", None),
        "g" => ("g", None),
        "a" => ("a", None),
        "n" => ("g", Some("ieee80211n=1")),
        "ac" => ("a", Some("ieee80211ac=1")),
        "ax" => ("a", Some("ieee80211ax=1")),
        // Validation has already refused anything else.
        _ => ("g", None),
    }
}

/// The hostapd config for an access point.
pub(crate) fn hostapd_conf(iface: &str, w: &Wireless) -> String {
    let mut s = String::from("# rendered by sentinel — access point (hostapd)\n");
    s.push_str(&format!("interface={iface}\n"));
    s.push_str("driver=nl80211\n");
    s.push_str(&format!("ssid={}\n", w.ssid));
    if let Some(c) = &w.country {
        s.push_str(&format!("country_code={c}\n"));
        // Without this hostapd knows the country and does not act on it.
        s.push_str("ieee80211d=1\n");
    }
    let (mode, generation) = hw_mode(w.band.as_deref().unwrap_or("g"));
    s.push_str(&format!("hw_mode={mode}\n"));
    if let Some(g) = generation {
        s.push_str(&format!("{g}\n"));
    }
    // Channel 0 is hostapd's "pick one"; leaving it out entirely is not the
    // same thing, and on some drivers means refusing to start.
    s.push_str(&format!("channel={}\n", w.channel.unwrap_or(0)));
    if w.hide_ssid {
        s.push_str("ignore_broadcast_ssid=1\n");
    }
    if w.isolate_stations {
        s.push_str("ap_isolate=1\n");
    }
    if let Some(n) = w.max_stations {
        s.push_str(&format!("max_num_sta={n}\n"));
    }
    if let Some(wpa) = &w.wpa {
        // WPA2 is `wpa=2` with PSK; WPA3 is SAE, which rides the same `wpa=2`
        // with a different key management and mandatory management-frame
        // protection. A transition network offers both key managements at once,
        // and then MFP has to be optional or the WPA2 clients cannot associate.
        let mode = wpa.mode.as_deref().unwrap_or("wpa2");
        s.push_str("wpa=2\n");
        s.push_str("rsn_pairwise=CCMP\n");
        match mode {
            "wpa3" => {
                s.push_str("wpa_key_mgmt=SAE\n");
                s.push_str("ieee80211w=2\n");
                s.push_str(&format!("sae_password={}\n", wpa.passphrase));
            }
            "wpa2+wpa3" => {
                s.push_str("wpa_key_mgmt=WPA-PSK SAE\n");
                s.push_str("ieee80211w=1\n");
                s.push_str(&format!("wpa_passphrase={}\n", wpa.passphrase));
                s.push_str(&format!("sae_password={}\n", wpa.passphrase));
            }
            _ => {
                s.push_str("wpa_key_mgmt=WPA-PSK\n");
                s.push_str(&format!("wpa_passphrase={}\n", wpa.passphrase));
            }
        }
    }
    s
}

/// The wpa_supplicant config for a station.
pub(crate) fn supplicant_conf(w: &Wireless) -> String {
    let mut s = String::from("# rendered by sentinel — station (wpa_supplicant)\n");
    s.push_str("ctrl_interface=/run/wpa_supplicant\n");
    if let Some(c) = &w.country {
        s.push_str(&format!("country={c}\n"));
    }
    s.push_str("network={\n");
    s.push_str(&format!("    ssid=\"{}\"\n", w.ssid));
    // A hidden network does not answer a broadcast probe, so a station has to
    // be told to ask for it by name.
    if w.hide_ssid {
        s.push_str("    scan_ssid=1\n");
    }
    match &w.wpa {
        Some(wpa) => {
            let mode = wpa.mode.as_deref().unwrap_or("wpa2");
            if mode == "wpa3" {
                s.push_str("    key_mgmt=SAE\n");
                s.push_str("    ieee80211w=2\n");
            } else if mode == "wpa2+wpa3" {
                s.push_str("    key_mgmt=WPA-PSK SAE\n");
                s.push_str("    ieee80211w=1\n");
            } else {
                s.push_str("    key_mgmt=WPA-PSK\n");
            }
            s.push_str(&format!("    psk=\"{}\"\n", wpa.passphrase));
        }
        // A station may legitimately join an open network — it is somebody
        // else's network, and refusing to join it protects nobody.
        None => s.push_str("    key_mgmt=NONE\n"),
    }
    s.push_str("}\n");
    s
}

/// The radios this box configures.
fn radios(appliance: &Appliance) -> Vec<(&Interface, &Wireless)> {
    appliance
        .interfaces
        .iter()
        .filter_map(|i| i.wireless.as_ref().map(|w| (i, w)))
        .collect()
}

/// Reconcile the wireless radios to `appliance`: render each one's daemon config
/// and (re)start its unit when the rendered config changed; stop and forget a
/// radio that is no longer configured.
///
/// Best-effort on the unit operations, like the other appliers: a radio whose
/// hardware is not present yet must not fail the whole commit.
pub fn apply(appliance: &Appliance) -> Result<()> {
    let radios = radios(appliance);
    if radios.is_empty() && !Path::new(WIRELESS_RUNTIME_DIR).exists() {
        return Ok(());
    }
    system::ensure_dir_mode(Path::new(WIRELESS_RUNTIME_DIR), "0755")?;

    let mut desired: HashSet<String> = HashSet::new();
    for (i, w) in &radios {
        let ap = w.is_access_point();
        let body = if ap {
            hostapd_conf(&i.name, w)
        } else {
            supplicant_conf(w)
        };
        let path = conf_path(&i.name);
        let changed = crate::net::file_changed(&path, &body);
        // 0600 root:root, not the 0640 root:systemd-network the networkd secrets
        // use: nothing but the daemon reads a radio's key, and the daemon is
        // root.
        system::install_private_file(&path, &body)?;
        desired.insert(i.name.clone());
        if changed {
            if let Err(e) = system::radio_restart(&unit(&i.name, ap)) {
                eprintln!(
                    "warning: (re)starting the radio on {} failed (applies on next commit/boot): {e}",
                    i.name
                );
            }
        }
    }

    // A radio that is no longer configured: stop both possible daemons, because
    // the mode may have changed on the way out, and drop its config.
    // Not `if let Ok(..)`: a listing this pass cannot do is a radio it cannot
    // retire, and skipping it silently is how the 0700 directory above hid
    // itself — the commit reported success and the daemon kept running.
    let entries = std::fs::read_dir(WIRELESS_RUNTIME_DIR)
        .with_context(|| format!("listing {WIRELESS_RUNTIME_DIR}"))?;
    {
        for e in entries.flatten() {
            let file = e.file_name().to_string_lossy().into_owned();
            let Some(name) = file.strip_suffix(".conf") else {
                continue;
            };
            if desired.contains(name) {
                continue;
            }
            for ap in [true, false] {
                let _ = system::radio_stop(&unit(name, ap));
            }
            system::remove_file(&e.path())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WirelessWpa;

    fn ap() -> Wireless {
        Wireless {
            mode: "access-point".into(),
            ssid: "velstra".into(),
            country: Some("DE".into()),
            channel: Some(6),
            band: Some("n".into()),
            hide_ssid: false,
            isolate_stations: false,
            max_stations: None,
            wpa: Some(WirelessWpa {
                mode: None,
                passphrase: "correcthorsebattery".into(),
            }),
        }
    }

    #[test]
    fn an_access_point_renders_hostapd() {
        let s = hostapd_conf("wlan0", &ap());
        for want in [
            "interface=wlan0",
            "driver=nl80211",
            "ssid=velstra",
            "country_code=DE",
            // A country hostapd knows and does not act on is no country.
            "ieee80211d=1",
            "hw_mode=g",
            "ieee80211n=1",
            "channel=6",
            "wpa=2",
            "wpa_key_mgmt=WPA-PSK",
            "wpa_passphrase=correcthorsebattery",
        ] {
            assert!(s.contains(want), "{want:?} missing from:\n{s}");
        }
    }

    /// WPA3 is SAE with mandatory management-frame protection; a transition
    /// network offers both key managements and has to make the protection
    /// optional, or the WPA2 clients it exists for cannot associate.
    #[test]
    fn wpa3_is_sae_and_the_transition_mode_keeps_wpa2_able_to_join() {
        let mut w = ap();
        w.wpa.as_mut().unwrap().mode = Some("wpa3".into());
        let s = hostapd_conf("wlan0", &w);
        assert!(s.contains("wpa_key_mgmt=SAE"), "{s}");
        assert!(s.contains("ieee80211w=2"), "{s}");
        assert!(s.contains("sae_password="), "{s}");
        assert!(!s.contains("wpa_passphrase="), "{s}");

        w.wpa.as_mut().unwrap().mode = Some("wpa2+wpa3".into());
        let s = hostapd_conf("wlan0", &w);
        assert!(s.contains("wpa_key_mgmt=WPA-PSK SAE"), "{s}");
        assert!(s.contains("ieee80211w=1"), "{s}");
        assert!(s.contains("wpa_passphrase="), "{s}");
        assert!(s.contains("sae_password="), "{s}");
    }

    /// The 5 GHz generations select `hw_mode=a`, the 2.4 GHz ones `g` — the band
    /// carries the frequency, not just the generation.
    #[test]
    fn the_band_decides_the_frequency_as_well_as_the_generation() {
        for (band, mode) in [
            ("b", "b"),
            ("g", "g"),
            ("n", "g"),
            ("a", "a"),
            ("ac", "a"),
            ("ax", "a"),
        ] {
            let mut w = ap();
            w.band = Some(band.into());
            let s = hostapd_conf("wlan0", &w);
            assert!(s.contains(&format!("hw_mode={mode}\n")), "{band}: {s}");
        }
    }

    #[test]
    fn a_station_renders_a_supplicant_network_block() {
        let mut w = ap();
        w.mode = "station".into();
        w.hide_ssid = true;
        let s = supplicant_conf(&w);
        assert!(s.contains("ssid=\"velstra\""), "{s}");
        // A hidden network answers no broadcast probe, so a station must ask by
        // name.
        assert!(s.contains("scan_ssid=1"), "{s}");
        assert!(s.contains("key_mgmt=WPA-PSK"), "{s}");
        assert!(s.contains("psk=\"correcthorsebattery\""), "{s}");
    }

    /// A station may join an open network: it is somebody else's, and refusing
    /// protects nobody. An access point with no WPA is refused at commit.
    #[test]
    fn a_station_may_join_an_open_network() {
        let mut w = ap();
        w.mode = "station".into();
        w.wpa = None;
        assert!(supplicant_conf(&w).contains("key_mgmt=NONE"));
    }
}
