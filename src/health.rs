//! Read-only, bounded system diagnostics for authenticated management clients.
//!
//! Never read journal messages, private TPM blobs or credentials, and never
//! change the clock, reset failed units or clear/enroll a TPM while observing it.

use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{Value, json};

const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_OUTPUT: usize = 65_536;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct Unit {
    unit: String,
    load_state: Option<String>,
    active_state: Option<String>,
    sub_state: Option<String>,
    result: Option<String>,
    exit_status: Option<i32>,
    condition_result: Option<bool>,
}

/// A probe can fail without making its stderr (or a path/credential included in
/// it) part of an API response. The diagnostics distinguish failure from healthy.
fn command(program: &str, args: &[&str], timeout: Duration) -> Result<String, &'static str> {
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env("SYSTEMD_PAGER", "")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "probe unavailable")?;
    let mut stdout = child.stdout.take().expect("piped stdout");
    let fd = stdout.as_raw_fd();
    // Poll the pipe without a reader thread that a stalled child could retain.
    // SAFETY: fd belongs to the live stdout handle; these calls change only its
    // nonblocking flag and do not access memory through a raw pointer.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        let _ = child.kill();
        let _ = child.wait();
        return Err("probe unavailable");
    }
    let start = Instant::now();
    let mut bytes = Vec::new();
    let mut exited: Option<bool> = None;
    loop {
        let mut chunk = [0u8; 4096];
        loop {
            match stdout.read(&mut chunk) {
                Ok(0) => break,
                Ok(size) if bytes.len() + size <= MAX_OUTPUT => {
                    bytes.extend_from_slice(&chunk[..size]);
                }
                Ok(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("probe output limit exceeded");
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("probe unavailable");
                }
            }
            // A constantly writing child must not evade the deadline.
            if start.elapsed() >= timeout {
                let _ = child.kill();
                let _ = child.wait();
                return Err("probe timed out");
            }
        }
        // Drain once more after observing exit: a child can write its final
        // bytes between the preceding nonblocking read and try_wait().
        if let Some(status) = exited {
            if !status {
                return Err("probe unavailable");
            }
            return String::from_utf8(bytes).map_err(|_| "invalid probe response");
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                exited = Some(status.success());
            }
            Ok(None) if start.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("probe timed out");
            }
        }
    }
}

fn safe_word(word: &str) -> bool {
    !word.is_empty()
        && word.len() <= 256
        && word
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.@:\\".contains(&byte))
}

fn failed_units(text: &str) -> Result<Vec<Unit>, &'static str> {
    let mut units = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_whitespace();
        let words: Vec<_> = fields.by_ref().take(4).collect();
        if words.len() != 4 || words.iter().any(|word| !safe_word(word)) {
            return Err("invalid failed-unit response");
        }
        units.push(Unit {
            unit: words[0].into(),
            load_state: Some(words[1].into()),
            active_state: Some(words[2].into()),
            sub_state: Some(words[3].into()),
            result: None,
            exit_status: None,
            condition_result: None,
        });
    }
    Ok(units)
}

fn properties(text: &str) -> Result<Vec<Unit>, &'static str> {
    text.split("\n\n")
        .filter(|block| !block.trim().is_empty())
        .map(|block| {
            let fields: std::collections::HashMap<_, _> = block
                .lines()
                .filter_map(|line| line.split_once('='))
                .collect();
            let word = |name| {
                fields
                    .get(name)
                    .filter(|value| safe_word(value))
                    .map(|value| (*value).to_string())
            };
            Ok(Unit {
                unit: word("Id").ok_or("invalid unit response")?,
                load_state: word("LoadState"),
                active_state: word("ActiveState"),
                sub_state: word("SubState"),
                result: word("Result"),
                exit_status: fields
                    .get("ExecMainStatus")
                    .and_then(|value| value.parse().ok()),
                condition_result: fields
                    .get("ConditionResult")
                    .and_then(|value| match *value {
                        "yes" => Some(true),
                        "no" => Some(false),
                        _ => None,
                    }),
            })
        })
        .collect()
}

fn issue(code: &str, severity: &str, message: &str, action: &str) -> Value {
    json!({"code": code, "severity": severity, "message": message, "action": action})
}

fn route_present(text: &str) -> Result<bool, &'static str> {
    let parsed: Value = serde_json::from_str(text).map_err(|_| "invalid route response")?;
    let rows = parsed.as_array().ok_or("invalid route response")?;
    if rows.iter().any(|row| !row.is_object()) {
        return Err("invalid route response");
    }
    Ok(rows
        .iter()
        .any(|row| matches!(row["dst"].as_str(), Some("default" | "0.0.0.0/0" | "::/0"))))
}

fn either_default(
    ipv4: Result<bool, &'static str>,
    ipv6: Result<bool, &'static str>,
) -> Option<bool> {
    match (ipv4, ipv6) {
        (Ok(true), _) | (_, Ok(true)) => Some(true),
        (Ok(false), Ok(false)) => Some(false),
        _ => None,
    }
}

fn snapshot(
    appliance: Option<&crate::config::Appliance>,
    clock: crate::clock::Clock,
    failures: Result<Vec<Unit>, &'static str>,
    services: Result<Vec<Unit>, &'static str>,
    devices: Vec<String>,
    default_route: Option<bool>,
) -> Value {
    let service = |name: &str| {
        services
            .as_ref()
            .ok()
            .and_then(|units| units.iter().find(|unit| unit.unit == name))
    };
    let chrony = service("chronyd.service");
    let setup = service("systemd-tpm2-setup.service");
    let mut issues = Vec::new();
    match clock.synchronised {
        Some(true) => {}
        Some(false) => issues.push(issue(
            "clock-unsynchronised", "warning",
            "The system clock is not synchronised. Certificate checks, logs and HA lease timing may be unreliable.",
            "Configure reachable NTP upstreams under Services / NTP, then check chronyd.service and UDP port 123 connectivity.",
        )),
        None => issues.push(issue("clock-unavailable", "unknown", "Clock synchronisation could not be determined.", "Inspect the kernel clock discipline and time service status.")),
    }
    if appliance.is_none() {
        issues.push(issue(
            "configuration-unavailable",
            "unknown",
            "NTP configuration could not be read or validated.",
            "Validate the appliance configuration using sentinel config check.",
        ));
    }
    if default_route == Some(false) {
        issues.push(issue(
            "network.no_default_route", "warning",
            "No IPv4/IPv6 default route; external time servers may be unreachable.",
            "Configure a suitable default gateway or reachable local NTP upstreams. An isolated network may intentionally have no default route.",
        ));
    } else if default_route.is_none() {
        issues.push(issue(
            "network.route_status_unknown",
            "unknown",
            "Default route status could not be determined.",
            "Inspect IPv4 and IPv6 default routes with ip route and verify the configured gateway.",
        ));
    }
    match &failures {
        Ok(units) if !units.is_empty() => issues.push(issue("systemd-failed-units", "warning", "One or more system services have failed.", "Inspect the listed units with systemctl status and journalctl. Resolve the cause before clearing their failure state.")),
        Err(_) => issues.push(issue("systemd-unavailable", "unknown", "Failed system services could not be enumerated.", "Check that systemd and its system bus are available.")),
        _ => {}
    }
    if services.is_err() {
        issues.push(issue(
            "service-status-unavailable",
            "unknown",
            "Time and TPM service status could not be read.",
            "Check that systemd and its system bus are available.",
        ));
    }
    if chrony.is_some_and(|unit| {
        unit.load_state.as_deref() == Some("loaded")
            && unit.active_state.as_deref() != Some("active")
    }) {
        issues.push(issue("ntp-service-inactive", "warning", "The NTP service is not active.", "Check chronyd.service and the configured NTP upstreams; applying the NTP configuration must start the time service."));
    }
    let tpm_failed = setup.is_some_and(|unit| {
        unit.active_state.as_deref() == Some("failed")
            // Upstream permits exit 76 (authorization failure) as a graceful
            // boot outcome. It is not proof that TPM setup actually succeeded.
            || unit.exit_status.is_some_and(|status| status != 0)
            || unit
                .result
                .as_deref()
                .is_some_and(|result| result != "success")
    }) || failures.as_ref().is_ok_and(|units| {
        units.iter().any(|unit| {
            matches!(
                unit.unit.as_str(),
                "systemd-tpm2-setup.service" | "systemd-tpm2-setup-early.service"
            )
        })
    });
    let advice = "Inspect systemd-tpm2-setup.service and its journal for firmware, session or NvPCR anchor errors. Check firmware/TPM compatibility and the signed image version. Do not clear or reset the TPM: this can invalidate sealed keys and other operating systems' recovery material.";
    if tpm_failed {
        issues.push(issue(
            "tpm-setup-failed",
            "warning",
            "TPM initialisation failed; hardware-backed key setup is not healthy.",
            advice,
        ));
    }
    let present = !devices.is_empty();
    let tpm_status = if tpm_failed {
        "warning"
    } else if !present {
        "not-present"
    } else if setup.is_some_and(|unit| {
        unit.load_state.as_deref() == Some("loaded")
            && unit.active_state.as_deref() == Some("active")
            && unit.result.as_deref() == Some("success")
            && unit.exit_status == Some(0)
            && unit.condition_result == Some(true)
    }) {
        "ok"
    } else {
        "unknown"
    };
    if tpm_status == "unknown" {
        issues.push(issue(
            "tpm-setup-unverified",
            "unknown",
            "A TPM is present, but successful setup could not be confirmed.",
            advice,
        ));
    }
    let status = if issues.iter().any(|entry| entry["severity"] == "warning") {
        "warning"
    } else if !issues.is_empty() || tpm_status == "unknown" {
        "unknown"
    } else {
        "ok"
    };
    json!({
        "status": status,
        "clock": {
            "unix_seconds": clock.now,
            "utc": crate::archive::fmt_utc(clock.now),
            "synchronised": clock.synchronised,
            "ntp_configured": appliance.map(|config| !config.services.ntp.is_empty()),
            "ntp_servers": appliance.map(|config| &config.services.ntp.upstream),
            "service": chrony,
        },
        "systemd": {"available": failures.is_ok(), "failed_units": failures.as_ref().ok(), "error": failures.as_ref().err()},
        "network": {"default_route": default_route},
        "tpm": {"present": present, "devices": devices, "setup": setup, "status": tpm_status, "advice": advice},
        "issues": issues,
    })
}

/// A fresh observation. Four child processes, each killed/reaped after two
/// seconds; bounded output and an allow-list of properties prevent log leaks.
pub fn collect(config_path: &Path) -> Value {
    let appliance = crate::config::Appliance::load(config_path).ok();
    let systemctl = crate::system::bin("systemctl");
    let failures = command(
        &systemctl,
        &[
            "--no-pager",
            "--plain",
            "--no-legend",
            "--all",
            "--failed",
            "list-units",
        ],
        PROBE_TIMEOUT,
    )
    .and_then(|text| failed_units(&text));
    let services = command(
        &systemctl,
        &[
            "--no-pager",
            "show",
            "chronyd.service",
            "systemd-tpm2-setup.service",
            "--property=Id,LoadState,ActiveState,SubState,Result,ExecMainStatus,ConditionResult",
        ],
        PROBE_TIMEOUT,
    )
    .and_then(|text| properties(&text))
    .and_then(|units| {
        if ["chronyd.service", "systemd-tpm2-setup.service"]
            .iter()
            .all(|name| units.iter().any(|unit| unit.unit == *name))
        {
            Ok(units)
        } else {
            Err("incomplete unit response")
        }
    });
    let devices = ["/dev/tpm0", "/dev/tpmrm0", "/sys/class/tpm/tpm0"]
        .into_iter()
        .filter(|path| Path::new(path).exists())
        .map(String::from)
        .collect();
    let ip = crate::system::bin("ip");
    let default_route = std::thread::scope(|scope| {
        let ipv4 = scope.spawn(|| {
            command(
                &ip,
                &["-j", "-4", "route", "show", "default"],
                PROBE_TIMEOUT,
            )
            .and_then(|text| route_present(&text))
        });
        let ipv6 = command(
            &ip,
            &["-j", "-6", "route", "show", "default"],
            PROBE_TIMEOUT,
        )
        .and_then(|text| route_present(&text));
        either_default(ipv4.join().unwrap_or(Err("probe unavailable")), ipv6)
    });
    snapshot(
        appliance.as_ref(),
        crate::clock::current(),
        failures,
        services,
        devices,
        default_route,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn appliance() -> crate::config::Appliance {
        crate::config::Appliance::from_toml(
            "[system]\nhostname=\"health-test\"\n[services.ntp]\nupstream=[\"time.example.org\"]\n",
        )
        .unwrap()
    }

    fn clock(sync: Option<bool>) -> crate::clock::Clock {
        crate::clock::Clock {
            synchronised: sync,
            now: 1_793_554_000,
            newer_state: None,
        }
    }

    #[test]
    fn synchronised_clock_and_no_tpm_is_healthy_not_an_error() {
        let result = snapshot(
            Some(&appliance()),
            clock(Some(true)),
            Ok(vec![]),
            Ok(vec![]),
            vec![],
            Some(true),
        );
        assert_eq!(result["status"], "ok");
        assert_eq!(result["tpm"]["status"], "not-present");
        assert_eq!(result["clock"]["ntp_servers"][0], "time.example.org");
    }

    #[test]
    fn failed_tpm_and_unsynchronised_clock_are_visible_without_raw_logs() {
        let units = failed_units(
            "systemd-tpm2-setup.service loaded failed failed sensitive description ignored\n",
        )
        .unwrap();
        let result = snapshot(
            Some(&appliance()),
            clock(Some(false)),
            Ok(units),
            Ok(vec![]),
            vec!["/dev/tpm0".into()],
            Some(true),
        );
        assert_eq!(result["status"], "warning");
        assert_eq!(result["tpm"]["status"], "warning");
        assert_eq!(
            result["systemd"]["failed_units"][0]["unit"],
            "systemd-tpm2-setup.service"
        );
        assert!(
            result["tpm"]["advice"]
                .as_str()
                .unwrap()
                .contains("Do not clear or reset")
        );
        assert!(!result.to_string().contains("sensitive description"));
        assert!(
            result["issues"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["code"] == "clock-unsynchronised")
        );
    }

    #[test]
    fn probe_failure_and_unknown_clock_never_report_healthy() {
        let result = snapshot(
            None,
            clock(None),
            Err("probe timed out"),
            Err("probe unavailable"),
            vec![],
            None,
        );
        assert_eq!(result["status"], "unknown");
        assert_eq!(result["clock"]["synchronised"], Value::Null);
        assert_eq!(result["clock"]["ntp_configured"], Value::Null);
        assert_eq!(result["systemd"]["available"], false);
    }

    #[test]
    fn allowed_unit_properties_include_failure_exit_status_only() {
        let result = properties("Id=chronyd.service\nLoadState=loaded\nActiveState=active\nSubState=running\nResult=success\nExecMainStatus=0\nSecret=never-return-this\n\nId=systemd-tpm2-setup.service\nLoadState=loaded\nActiveState=failed\nResult=exit-code\nExecMainStatus=1\n").unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[1].exit_status, Some(1));
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("never-return-this")
        );
        assert!(properties("Secret=not-a-status\n").is_err());
        assert!(failed_units("unparseable\n").is_err());
    }

    #[test]
    fn default_route_detection_is_dual_stack_and_fail_closed() {
        assert_eq!(route_present("[]"), Ok(false));
        assert_eq!(
            route_present(r#"[{"dst":"default","gateway":"192.0.2.1","dev":"wan0"}]"#),
            Ok(true)
        );
        assert_eq!(route_present(r#"[{"dst":"::/0","dev":"wan0"}]"#), Ok(true));
        assert!(route_present("{}").is_err());
        assert_eq!(either_default(Ok(false), Ok(false)), Some(false));
        assert_eq!(either_default(Ok(false), Err("probe unavailable")), None);
        assert_eq!(
            either_default(Err("probe unavailable"), Ok(true)),
            Some(true)
        );
        let result = snapshot(
            Some(&appliance()),
            clock(Some(false)),
            Ok(vec![]),
            Ok(vec![]),
            vec![],
            Some(false),
        );
        assert!(
            result["issues"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["code"] == "network.no_default_route")
        );
        assert_eq!(result["network"]["default_route"], false);
    }

    #[test]
    fn skipped_or_authorisation_failed_tpm_setup_is_not_healthy() {
        for (status, active, condition, expected) in [
            (0, "inactive", "no", "unknown"),
            (76, "active", "yes", "warning"),
            (0, "active", "yes", "ok"),
        ] {
            let units = properties(&format!("Id=systemd-tpm2-setup.service\nLoadState=loaded\nActiveState={active}\nResult=success\nExecMainStatus={status}\nConditionResult={condition}\n")).unwrap();
            let result = snapshot(
                Some(&appliance()),
                clock(Some(true)),
                Ok(vec![]),
                Ok(units),
                vec!["/dev/tpm0".into()],
                Some(true),
            );
            assert_eq!(result["tpm"]["status"], expected);
        }
    }

    #[test]
    fn command_deadline_and_output_limit_are_enforced() {
        let start = Instant::now();
        assert_eq!(
            command("sh", &["-c", "exec sleep 5"], Duration::from_millis(30)),
            Err("probe timed out")
        );
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(
            command("sh", &["-c", "exec yes"], Duration::from_secs(1)),
            Err("probe output limit exceeded")
        );
        assert_eq!(
            command("sh", &["-c", "echo secret >&2; exit 1"], PROBE_TIMEOUT),
            Err("probe unavailable")
        );
        assert_eq!(
            command("sh", &["-c", "printf 'safe-output'"], PROBE_TIMEOUT).unwrap(),
            "safe-output"
        );
    }
}
