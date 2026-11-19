//! A best-effort line in the system journal for events an operator must be able
//! to find afterwards.
//!
//! A refused commit used to exist only on the terminal that ran it (PERF-06):
//! `journalctl -b` held no line for a configuration the data plane refused,
//! so the next person to look at the box could not tell it had happened.
//! Processes started by systemd already reach the journal through stderr; an
//! interactive `configure` does not, so this writes to the syslog socket that
//! journald owns. Failure to log never fails the operation being logged.

use std::os::unix::net::UnixDatagram;

/// The socket journald listens on for syslog-format datagrams.
const SYSLOG_SOCKET: &str = "/dev/log";
/// RFC 3164 facility `user` (1), shifted.
const FACILITY_USER: u8 = 1 << 3;
/// The longest message sent; journald accepts more, but a diagnostic that long
/// has stopped being one.
const MAX_MESSAGE: usize = 4096;

/// How loud the line is. Only errors are logged today.
#[derive(Clone, Copy)]
pub(crate) enum Severity {
    Error = 3,
}

/// One syslog datagram: `<PRI>TAG[PID]: MESSAGE`, with control characters
/// escaped so a hostile name inside a diagnostic cannot forge a second line.
fn datagram(severity: Severity, tag: &str, message: &str) -> Vec<u8> {
    let mut text = String::new();
    for character in message.chars() {
        if character.is_control() {
            text.extend(character.escape_debug());
        } else {
            text.push(character);
        }
        if text.len() >= MAX_MESSAGE {
            break;
        }
    }
    format!(
        "<{}>{tag}[{}]: {text}",
        FACILITY_USER | severity as u8,
        std::process::id()
    )
    .into_bytes()
}

/// Record `message` in the journal under `tag`. Silent when there is no journal
/// (off-box, a container without `/dev/log`).
pub(crate) fn note(severity: Severity, tag: &str, message: &str) {
    if let Ok(socket) = UnixDatagram::unbound() {
        let _ = socket.send_to(&datagram(severity, tag, message), SYSLOG_SOCKET);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_journal_line_is_one_line_with_the_syslog_priority() {
        let line = String::from_utf8(datagram(
            Severity::Error,
            "sentinel-commit",
            "refused\nforged: line",
        ))
        .unwrap();
        assert!(line.starts_with("<11>sentinel-commit["), "{line}");
        assert!(line.ends_with("]: refused\\nforged: line"), "{line}");
        assert!(!line.contains('\n'));
    }
}
