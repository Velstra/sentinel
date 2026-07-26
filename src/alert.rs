//! Alert notifications (roadmap C23): tell a human, now, that the appliance is
//! not doing its job.
//!
//! This is the opposite of remote syslog. Syslog ships *everything* somewhere for
//! later; an alert is for the few events where waiting until someone reads a log
//! is already too late. The one that matters most is a **failed unit**: an
//! appliance whose data plane died still answers ping and still answers SSH, so
//! nothing reveals it until traffic is already broken.
//!
//! ## The event source is systemd, not the journal
//!
//! Sentinel writes an `OnFailure=sentinel-alert@<unit>.service` drop-in on each
//! unit it owns. systemd already knows, exactly and only, when a unit failed —
//! whereas grepping the journal for something that looks like a failure fires on
//! a message that merely *mentions* one and misses a unit that died without
//! logging. `sentinel alert <unit>` is then a plain one-shot: gather context,
//! deliver, exit.
//!
//! ## Delivery is best-effort, and says so
//!
//! Every configured target is tried, one failing target never stops the others,
//! and the command still exits 0: a `Restart=`/`OnFailure=` loop that fails
//! because the *notification* failed would turn a single broken service into a
//! restart storm. Failures are logged (to the journal, which syslog forwarding
//! then ships) rather than propagated.

use std::{path::Path, process::Command};

use anyhow::{Context, Result};

use crate::{
    config::{Alerts, DEFAULT_ALERT_MAIL_PORT},
    system,
};

/// Where the rendered msmtp config lives. Under `/run` because it holds the relay
/// password and has no reason to outlive a boot — it is re-rendered on every
/// commit and by `sentinel-boot`.
pub const MSMTP_CONF: &str = "/run/sentinel/msmtp.conf";

/// How long to give a webhook. Short on purpose: this runs from an `OnFailure=`
/// handler, and an unreachable endpoint must not keep a systemd job alive for
/// minutes.
const WEBHOOK_TIMEOUT_SECS: u32 = 10;

/// How many journal lines of the failed unit to include. Enough to see the error,
/// not so many that a webhook body becomes a log dump.
const CONTEXT_LINES: usize = 20;

/// One alert: what happened, on which box, with the evidence.
pub struct Alert {
    /// The systemd unit that failed, or another short event name.
    pub subject: String,
    /// Human-readable detail — for a unit failure, its last journal lines.
    pub detail: String,
}

impl Alert {
    /// The alert for a failed unit, with the unit's own last journal lines as the
    /// evidence: an alert that only says "something failed" sends the operator
    /// looking, which is most of the delay it was supposed to remove.
    pub fn unit_failure(unit: &str) -> Self {
        Alert {
            subject: format!("unit failed: {unit}"),
            detail: journal_tail(unit),
        }
    }

    /// A JSON body a webhook receiver can act on. Hand-rolled rather than derived
    /// so the wire shape is visible here and cannot drift with a struct change.
    fn json(&self, host: &str) -> String {
        format!(
            "{{\"source\":\"sentinel\",\"host\":{},\"subject\":{},\"detail\":{}}}",
            json_string(host),
            json_string(&self.subject),
            json_string(&self.detail)
        )
    }
}

/// Minimal JSON string escaping (RFC 8259 §7). serde_json is already a dependency
/// but building a `Value` for three fields is more machinery than the escape.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Everything below 0x20 must be escaped; \u is the general form.
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The last [`CONTEXT_LINES`] journal lines for `unit`, or a note saying why not.
/// Never fails: the alert must go out even when the context could not be read.
fn journal_tail(unit: &str) -> String {
    let out = Command::new(system::bin("journalctl"))
        .args([
            "-u",
            unit,
            "-n",
            &CONTEXT_LINES.to_string(),
            "--no-pager",
            "-o",
            "short-iso",
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        Ok(o) => format!(
            "(could not read the journal for {unit}: {})",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => format!("(could not run journalctl: {e})"),
    }
}

/// Deliver `alert` to every configured target.
///
/// Returns the number of targets that accepted it. Delivery errors are logged and
/// counted, never returned: see the module note on why an alert failure must not
/// become the caller's failure.
pub fn deliver(alerts: &Alerts, alert: &Alert) -> usize {
    if alerts.is_empty() {
        return 0;
    }
    let host = system::current_hostname();
    let mut delivered = 0;
    let body = alert.json(&host);
    for url in &alerts.webhook {
        match post_webhook(url, &body) {
            Ok(()) => delivered += 1,
            Err(e) => eprintln!("alert: webhook {url} failed: {e:#}"),
        }
    }
    if alerts.mail.is_deliverable() {
        match send_mail(alerts, alert, &host) {
            Ok(()) => delivered += 1,
            Err(e) => eprintln!("alert: mail failed: {e:#}"),
        }
    }
    delivered
}

/// POST the JSON body to `url` with curl (already pinned in the image for the
/// update channel — no TLS stack is added to the appliance for this).
fn post_webhook(url: &str, body: &str) -> Result<()> {
    let out = Command::new(curl_bin())
        .args([
            "-fsS",
            "--max-time",
            &WEBHOOK_TIMEOUT_SECS.to_string(),
            "-H",
            "Content-Type: application/json",
            // The body goes in on stdin, so a long detail never hits ARG_MAX and
            // never appears in the process list of a shared box.
            "--data-binary",
            "@-",
            url,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(stdin) = child.stdin.as_mut() {
                stdin.write_all(body.as_bytes())?;
            }
            // Dropping stdin closes it, which curl needs to finish reading `@-`.
            drop(child.stdin.take());
            child.wait_with_output()
        })
        .context("running curl")?;
    if !out.status.success() {
        anyhow::bail!(
            "curl exited {}: {}",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Render the msmtp config for the configured relay, or `None` when mail is not
/// deliverable.
///
/// `tls_starttls` is only meaningful with `tls on`, and msmtp needs the CA bundle
/// pointed at explicitly in a Nix image (there is no distro-standard path).
pub fn msmtp_conf_body(alerts: &Alerts) -> Option<String> {
    let mail = &alerts.mail;
    if !mail.is_deliverable() {
        return None;
    }
    let relay = mail.relay.as_ref()?;
    let port = mail.port.unwrap_or(DEFAULT_ALERT_MAIL_PORT);
    let starttls = mail.starttls.unwrap_or(true);
    let mut body = String::from("# rendered by sentinel — alert mail (msmtp)\n");
    body.push_str("defaults\n");
    body.push_str("account sentinel\n");
    body.push_str(&format!("host {relay}\n"));
    body.push_str(&format!("port {port}\n"));
    if starttls {
        body.push_str("tls on\ntls_starttls on\n");
        // System CA bundle. Without this msmtp fails certificate verification in
        // the image, which would look like "the relay rejected us".
        body.push_str("tls_trust_file /etc/ssl/certs/ca-certificates.crt\n");
    } else {
        body.push_str("tls off\n");
    }
    if let Some(user) = &mail.user {
        body.push_str("auth on\n");
        body.push_str(&format!("user {user}\n"));
        if let Some(pw) = &mail.password {
            body.push_str(&format!("password {pw}\n"));
        }
    } else {
        body.push_str("auth off\n");
    }
    body.push_str("account default : sentinel\n");
    Some(body)
}

/// Send the alert as mail through msmtp against the rendered config.
fn send_mail(alerts: &Alerts, alert: &Alert, host: &str) -> Result<()> {
    let mail = &alerts.mail;
    let to = mail.to.as_deref().context("no recipient")?;
    let from = mail
        .from
        .clone()
        .unwrap_or_else(|| format!("sentinel@{host}"));
    if !Path::new(MSMTP_CONF).exists() {
        anyhow::bail!("{MSMTP_CONF} is missing — commit the config first");
    }
    // A minimal RFC 5322 message. msmtp reads the recipient from the command line
    // (`--`-terminated), so the headers are for the reader, not for routing.
    let message = format!(
        "From: {from}\nTo: {to}\nSubject: [sentinel/{host}] {}\n\n{}\n",
        alert.subject, alert.detail
    );
    let out = Command::new(msmtp_bin())
        .args(["-C", MSMTP_CONF, "-f", &from, "--", to])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(stdin) = child.stdin.as_mut() {
                stdin.write_all(message.as_bytes())?;
            }
            drop(child.stdin.take());
            child.wait_with_output()
        })
        .context("running msmtp")?;
    if !out.status.success() {
        anyhow::bail!(
            "msmtp exited {}: {}",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// The pinned `curl` (same resolution as the update channel's).
fn curl_bin() -> String {
    std::env::var("SENTINEL_CURL_BIN")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "curl".to_string())
}

/// The pinned `msmtp`.
fn msmtp_bin() -> String {
    std::env::var("SENTINEL_MSMTP_BIN")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "msmtp".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AlertMail;

    fn mail(user: Option<&str>, starttls: Option<bool>) -> Alerts {
        Alerts {
            webhook: Vec::new(),
            mail: AlertMail {
                to: Some("noc@example.com".into()),
                from: None,
                relay: Some("smtp.example.com".into()),
                port: None,
                user: user.map(str::to_string),
                password: user.map(|_| "s3cret".to_string()),
                starttls,
            },
        }
    }

    /// Nothing is rendered until mail can actually be delivered — a config with a
    /// recipient but no relay must not produce an msmtp account that fails at
    /// send time.
    #[test]
    fn msmtp_is_rendered_only_when_mail_can_be_sent() {
        assert!(msmtp_conf_body(&Alerts::default()).is_none());
        let mut half = mail(None, None);
        half.mail.relay = None;
        assert!(msmtp_conf_body(&half).is_none());
    }

    /// TLS on by default, with the CA bundle named: without `tls_trust_file` msmtp
    /// fails verification in the image, which reads as a rejecting relay.
    #[test]
    fn msmtp_defaults_to_starttls_with_a_trust_file() {
        let body = msmtp_conf_body(&mail(None, None)).expect("deliverable");
        assert!(body.contains("host smtp.example.com"), "got:\n{body}");
        assert!(body.contains("port 587"), "got:\n{body}");
        assert!(body.contains("tls on"), "got:\n{body}");
        assert!(body.contains("tls_starttls on"), "got:\n{body}");
        assert!(body.contains("tls_trust_file"), "got:\n{body}");
        // No credentials ⇒ auth is explicitly off, not left to msmtp's default.
        assert!(body.contains("auth off"), "got:\n{body}");
        assert!(!body.contains("password"), "got:\n{body}");

        let authed = msmtp_conf_body(&mail(Some("fw@example.com"), None)).expect("deliverable");
        assert!(authed.contains("auth on"), "got:\n{authed}");
        assert!(authed.contains("user fw@example.com"), "got:\n{authed}");
        assert!(authed.contains("password s3cret"), "got:\n{authed}");

        let plain = msmtp_conf_body(&mail(None, Some(false))).expect("deliverable");
        assert!(plain.contains("tls off"), "got:\n{plain}");
    }

    /// A detail is a journal excerpt: newlines, quotes and control characters all
    /// occur, and an unescaped one produces a body the receiver cannot parse.
    #[test]
    fn the_webhook_body_escapes_what_a_journal_line_contains() {
        let a = Alert {
            subject: "unit failed: velstra.service".into(),
            detail: "line one\nsaid \"no\"\ttab\u{1}ctrl".into(),
        };
        let body = a.json("fw1");
        assert!(body.contains(r#""host":"fw1""#), "got: {body}");
        assert!(body.contains(r#""subject":"unit failed: velstra.service""#));
        // The control character becomes \u0001 rather than vanishing: a receiver
        // that stores the detail should get what was actually logged.
        assert!(
            body.contains(r#"line one\nsaid \"no\"\ttab\u0001ctrl"#),
            "got: {body}"
        );
        // Exactly one JSON object, and the detail did not break out of its string.
        assert_eq!(body.matches('{').count(), 1);
        assert!(
            serde_json::from_str::<serde_json::Value>(&body).is_ok(),
            "{body}"
        );
    }

    /// With nothing configured there is no work to do — and importantly no error:
    /// alerting off is the default state, not a misconfiguration.
    #[test]
    fn delivering_with_no_targets_is_a_no_op() {
        assert_eq!(deliver(&Alerts::default(), &Alert::unit_failure("x")), 0);
    }
}
