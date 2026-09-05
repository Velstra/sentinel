//! Client for the data plane agent's read-only query socket (roadmap C23).
//!
//! The agent owns the eBPF maps, so it is the only process that can say what the
//! firewall is doing right now. It answers a one-line request on a Unix socket
//! (`stats`, `flows [limit]`, `top [limit]`).
//!
//! Sentinel shells out to `wren` for routing views because wren ships its own
//! client; the agent has none, so this speaks the socket directly. That is a
//! handful of lines of blocking I/O — cheaper than adding a subcommand to the
//! agent purely so we could exec it.

use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, bail};

/// Where the appliance's agent serves its query socket (see
/// `nix/velstra-service.nix`).
pub const SOCKET: &str = "/run/velstra/query.sock";

/// How long to wait for the agent to answer. Short on purpose: this backs an
/// interactive `show`, and an agent that is wedged should produce a fallback
/// quickly rather than hanging the operator's terminal.
const TIMEOUT: Duration = Duration::from_secs(3);

/// Send one query and return the agent's whole reply.
///
/// Fails when the socket is absent (an older agent, or one started without
/// `--query-socket`) — callers are expected to fall back rather than surface the
/// error, since a missing diagnostics channel is not a broken firewall.
pub fn query(command: &str) -> Result<String> {
    query_at(Path::new(SOCKET), command)
}

/// [`query`] against an explicit path, escalating once if the socket is shut.
///
/// The agent's sockets are root-only on purpose, and every caller of this — the
/// flow table, rule attribution, port mappings, portal sessions — was therefore
/// closed to the operator account, each reporting it as the agent being absent.
/// Escalate here rather than at each call site, and rather than widening a
/// socket that can change what the data plane does.
pub fn query_at(path: &Path, command: &str) -> Result<String> {
    match query_direct(path, command) {
        Ok(reply) => Ok(reply),
        // As root there is nobody left to ask, so the error is the answer.
        Err(e) if crate::system::is_root() => Err(e),
        Err(e) => {
            let Some(sock) = path.to_str() else {
                return Err(e);
            };
            let out = crate::system::escalated_output(
                "sentinel-self",
                &["agent-query", "--socket", sock, command],
            );
            match out {
                Ok(o) if o.status.success() => Ok(String::from_utf8_lossy(&o.stdout).into_owned()),
                _ => Err(e),
            }
        }
    }
}

/// The socket conversation itself, without escalation.
fn query_direct(path: &Path, command: &str) -> Result<String> {
    if !path.exists() {
        bail!("{} does not exist", path.display());
    }
    let mut stream = UnixStream::connect(path)
        .with_context(|| format!("connecting to the agent at {}", path.display()))?;
    stream.set_read_timeout(Some(TIMEOUT)).ok();
    stream.set_write_timeout(Some(TIMEOUT)).ok();
    stream
        .write_all(format!("{command}\n").as_bytes())
        .context("sending the query")?;
    // The agent answers and closes, so read to EOF; no length framing needed.
    let mut reply = String::new();
    stream
        .read_to_string(&mut reply)
        .context("reading the agent's reply")?;
    if reply.is_empty() {
        bail!("the agent returned nothing");
    }
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A missing socket must be a plain error the caller can fall back on, not a
    /// panic and not a hang: an agent without `--query-socket` is a normal state.
    #[test]
    fn a_missing_socket_is_an_ordinary_error() {
        let missing = std::env::temp_dir().join("sentinel-no-such-agent.sock");
        let _ = std::fs::remove_file(&missing);
        let err = query_at(&missing, "stats").unwrap_err().to_string();
        assert!(err.contains("does not exist"), "{err}");
    }

    /// The round trip: the command reaches the agent with a trailing newline (its
    /// reader is line-based) and the whole reply comes back.
    #[test]
    fn a_query_round_trips_over_a_real_socket() {
        use std::io::{BufRead, BufReader};

        let path = std::env::temp_dir().join(format!("sentinel-agent-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).expect("read the command");
            let mut out = reader.into_inner();
            out.write_all(format!("got {line}").as_bytes())
                .expect("reply");
        });

        let reply = query_at(&path, "flows 5").expect("query");
        server.join().expect("server thread");
        assert_eq!(reply, "got flows 5\n");
        let _ = std::fs::remove_file(&path);
    }
}

// ---- reporting up ----------------------------------------------------------

/// The counters this box would tell a Velstra controller about.
///
/// One flat `(name, value)` list, because that is what `StatsReport` carries and
/// what a controller can aggregate without knowing anything about appliances.
/// Three sources, named so a reader of the controller's side can tell them
/// apart: the links (`iface.<name>.rx|tx`), the firewall's own totals
/// (`fw.<counter>`), and the rules that are carrying traffic
/// (`rule.<name>.flows|packets`).
///
/// Pure over what it is handed, so the shape can be tested without a data plane
/// or a controller — the gathering is [`report_counters`] below.
pub fn counters_from(
    interfaces: &[(String, u64, u64)],
    firewall: &[(String, u64)],
    rules: &[(String, u64, u64)],
    sessions: Option<u64>,
) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    for (name, rx, tx) in interfaces {
        out.push((format!("iface.{name}.rx"), *rx));
        out.push((format!("iface.{name}.tx"), *tx));
    }
    for (name, value) in firewall {
        out.push((format!("fw.{name}"), *value));
    }
    for (name, flows, packets) in rules {
        // A rule the operator did not name is one the compiler opened itself
        // (a load-balanced service); it has no name a controller could match
        // against a configuration, so it is left out rather than sent as noise.
        if name.starts_with('(') {
            continue;
        }
        out.push((format!("rule.{name}.flows"), *flows));
        out.push((format!("rule.{name}.packets"), *packets));
    }
    if let Some(n) = sessions {
        out.push(("sessions".to_string(), n));
    }
    out
}

/// Parse the agent's `stats` table into `(counter, value)`.
///
/// The agent prints a fixed-width table rather than JSON, so this reads it back
/// and skips anything that does not parse — a report that vanishes because one
/// row was odd is worse than one that is short by it.
pub fn parse_stats(text: &str) -> Vec<(String, u64)> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() != 2 {
                return None;
            }
            let value: u64 = f[1].parse().ok()?;
            let name = f[0];
            if !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
            {
                return None;
            }
            Some((name.to_string(), value))
        })
        .collect()
}

#[cfg(test)]
mod report_tests {
    use super::*;

    #[test]
    fn the_three_sources_are_named_apart_and_a_compiler_rule_is_left_out() {
        let counters = counters_from(
            &[("eth0".into(), 10, 20)],
            &[("passed_rule".into(), 7)],
            &[
                ("web-in".into(), 3, 400),
                ("(load-balancer vip)".into(), 9, 900),
            ],
            Some(42),
        );
        assert_eq!(
            counters,
            vec![
                ("iface.eth0.rx".into(), 10),
                ("iface.eth0.tx".into(), 20),
                ("fw.passed_rule".into(), 7),
                ("rule.web-in.flows".into(), 3),
                ("rule.web-in.packets".into(), 400),
                ("sessions".into(), 42),
            ]
        );
    }

    #[test]
    fn nothing_to_report_is_an_empty_list_rather_than_a_row_of_zeroes() {
        assert!(counters_from(&[], &[], &[], None).is_empty());
    }

    #[test]
    fn the_agents_table_is_read_back_and_odd_rows_are_skipped() {
        let text = "  counter                       value\n\
                    \x20 -------------------- --------------\n\
                    \x20 rx_packets                        4\n\
                    \x20 dropped_rule                     11\n\
                    \x20 not a number                      x\n";
        assert_eq!(
            parse_stats(text),
            vec![("rx_packets".into(), 4), ("dropped_rule".into(), 11)]
        );
    }
}
