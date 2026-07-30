//! C12 — **packet capture**: seeing what is actually on the wire.
//!
//! Every other diagnostic on this appliance reports what the box *decided* — a
//! counter, a flow, a log line. Sooner or later none of them answer the
//! question, because the packet never arrived, or arrived looking nothing like
//! the rule was written for. This is the one tool that shows the wire itself.
//!
//! ## Bounded on purpose
//!
//! A capture is the first diagnostic an operator reaches for and the easiest one
//! to leave running. Here it cannot be: every capture stops at a packet count
//! *and* a deadline, both capped, and there is no way to ask for more. That is
//! not timidity — an unbounded capture on a busy firewall competes with
//! forwarding for the CPU it is meant to be diagnosing, and one started from a
//! browser tab that was then closed would have nobody left to stop it.
//!
//! Nothing is written to disk. The output is the summary lines, returned to
//! whoever asked; a capture file would be a copy of production traffic sitting
//! on the appliance, and deciding when to delete it is a problem worth not
//! having.
//!
//! ## The filter
//!
//! The filter is a pcap expression and is passed to `tcpdump` as a **single
//! argument**, never through a shell, so an expression cannot become a command.
//! What it *could* still do is start with a dash and be read as an option —
//! `-w` would write a file, `-z` would run a program — so an expression that
//! begins with one is refused rather than quoted and hoped for.

use anyhow::{Result, bail};

use crate::system;

/// The most packets one capture may return.
///
/// Enough to see a handshake fail or a rule bite, and few enough that the reply
/// stays something a human reads rather than scrolls.
pub const MAX_PACKETS: u32 = 500;

/// The longest one capture may wait, in seconds.
///
/// A capture that finds nothing is an answer too — "that traffic is not
/// arriving" — and it should arrive promptly rather than hold the connection
/// open while an operator wonders whether the page has hung.
pub const MAX_SECONDS: u32 = 60;

/// A capture request, already checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capture {
    /// Interface to listen on.
    pub interface: String,
    /// pcap filter expression, empty for everything.
    pub filter: String,
    /// Stop after this many packets.
    pub packets: u32,
    /// Stop after this long.
    pub seconds: u32,
}

impl Capture {
    /// Check a request and clamp it into what this appliance will run.
    ///
    /// Counts and deadlines are **clamped**, because asking for more than the
    /// cap is a reasonable thing to want and refusing it teaches nothing. The
    /// interface and the filter are **refused**, because a wrong one there is a
    /// mistake whose result would otherwise look like "no traffic".
    pub fn new(interface: &str, filter: &str, packets: u32, seconds: u32) -> Result<Self> {
        let interface = interface.trim();
        if interface.is_empty() {
            bail!("a capture needs an interface");
        }
        // An interface name is a kernel identifier, not free text; anything else
        // is either a typo or an attempt to smuggle an argument.
        if !interface
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@'))
        {
            bail!("{interface:?} is not an interface name");
        }

        let filter = filter.trim();
        // See the module header: a leading dash would be read as an option, and
        // tcpdump has options that write files and run programs.
        if filter.starts_with('-') {
            bail!("a filter may not begin with '-'");
        }
        if filter.len() > 512 {
            bail!("that filter is too long to be one");
        }

        Ok(Self {
            interface: interface.to_string(),
            filter: filter.to_string(),
            packets: packets.clamp(1, MAX_PACKETS),
            seconds: seconds.clamp(1, MAX_SECONDS),
        })
    }

    /// The `tcpdump` arguments this capture runs as.
    ///
    /// Pure, so the flags are checked without a NIC. `-n` and `-nn` keep DNS and
    /// service lookups out of a diagnostic — a capture that stalls on a resolver
    /// is a capture that is now also testing the resolver. `-l` and
    /// `--immediate-mode` make the output appear as it happens rather than in
    /// block-buffered chunks, which matters when the deadline is what ends it.
    pub fn args(&self) -> Vec<String> {
        let mut args = vec![
            "-i".to_string(),
            self.interface.clone(),
            "-c".to_string(),
            self.packets.to_string(),
            "-nn".to_string(),
            "-l".to_string(),
            "--immediate-mode".to_string(),
            // Enough of each packet to see the headers that decide a verdict,
            // and not enough to carry away a payload.
            "-s".to_string(),
            "256".to_string(),
        ];
        if !self.filter.is_empty() {
            args.push(self.filter.clone());
        }
        args
    }
}

/// Run a capture and return what it saw.
///
/// The deadline is enforced by `timeout` around `tcpdump` rather than by
/// `tcpdump` itself: its own `-G` rotates files, which is the thing this
/// deliberately never does. A capture that hits the deadline exits non-zero and
/// that is a normal outcome, not a failure — the packets it did see are the
/// answer.
pub fn run(capture: &Capture) -> Result<String> {
    let mut cmd = std::process::Command::new(system::bin("timeout"));
    cmd.arg(capture.seconds.to_string())
        .arg(system::bin("tcpdump"))
        .args(capture.args());
    let out = cmd.output()?;

    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    // tcpdump reports its own progress ("N packets captured") on stderr, and
    // that line is often the whole answer when the body is empty.
    let err = String::from_utf8_lossy(&out.stderr);
    for line in err.lines() {
        if line.contains("packets captured")
            || line.contains("packets received")
            || line.contains("packets dropped")
        {
            text.push_str(line);
            text.push('\n');
        }
    }
    if text.trim().is_empty() {
        // Distinguish "nothing matched" from "that did not run", because they
        // send an operator in opposite directions.
        if out.status.success() || out.status.code() == Some(124) {
            text = format!(
                "no packets matched on {} within {}s\n",
                capture.interface, capture.seconds
            );
        } else {
            let why = err.trim();
            bail!(if why.is_empty() {
                "the capture did not run".to_string()
            } else {
                why.to_string()
            });
        }
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one input that could turn an expression into a command. `tcpdump -z`
    /// runs a program and `-w` writes a file; a filter beginning with a dash is
    /// refused rather than quoted and hoped for.
    #[test]
    fn a_filter_cannot_become_an_option() {
        assert!(Capture::new("eth0", "-z /bin/sh", 10, 5).is_err());
        assert!(Capture::new("eth0", "-w /tmp/x", 10, 5).is_err());
        // …while an ordinary expression, dashes and all, is fine.
        let c = Capture::new("eth0", "tcp port 443 and not host 10.0.0.1", 10, 5).unwrap();
        assert_eq!(
            c.args().last().unwrap(),
            "tcp port 443 and not host 10.0.0.1"
        );
    }

    /// The filter is one argument. If it were ever split, a filter with spaces
    /// would become several arguments and the ones after the first would be
    /// read as tcpdump's own.
    #[test]
    fn the_filter_is_a_single_argument() {
        let args = Capture::new("eth0", "icmp or arp", 10, 5).unwrap().args();
        let spaced: Vec<&String> = args.iter().filter(|a| a.contains(' ')).collect();
        assert_eq!(spaced.len(), 1, "the filter was split: {args:?}");
    }

    /// An interface name is a kernel identifier. Anything else is a typo or an
    /// attempt to smuggle an argument, and both are better refused.
    #[test]
    fn an_interface_is_a_name_not_free_text() {
        assert!(Capture::new("eth0", "", 10, 5).is_ok());
        assert!(Capture::new("vlan100@eth0", "", 10, 5).is_ok());
        assert!(Capture::new("", "", 10, 5).is_err());
        assert!(Capture::new("eth0 -w /tmp/x", "", 10, 5).is_err());
        assert!(Capture::new("../../etc/passwd", "", 10, 5).is_err());
    }

    /// Asking for more than the cap is a reasonable thing to want, so it is
    /// clamped rather than refused — but it is not granted.
    #[test]
    fn a_capture_is_always_bounded() {
        let c = Capture::new("eth0", "", 100_000, 3600).unwrap();
        assert_eq!(c.packets, MAX_PACKETS);
        assert_eq!(c.seconds, MAX_SECONDS);
        assert!(c.args().contains(&MAX_PACKETS.to_string()));

        // And zero is not a way to ask for "no limit".
        let z = Capture::new("eth0", "", 0, 0).unwrap();
        assert_eq!((z.packets, z.seconds), (1, 1));
    }

    /// A diagnostic must not become a test of the resolver, and must not carry
    /// payloads away.
    #[test]
    fn a_capture_resolves_nothing_and_truncates() {
        let args = Capture::new("eth0", "", 10, 5).unwrap().args();
        assert!(args.contains(&"-nn".to_string()), "{args:?}");
        let snap = args.iter().position(|a| a == "-s").expect("no snap length");
        assert_eq!(args[snap + 1], "256");
    }
}
