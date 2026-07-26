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

/// [`query`] against an explicit path, so a test can point at its own socket.
pub fn query_at(path: &Path, command: &str) -> Result<String> {
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
            out.write_all(format!("got {line}").as_bytes()).expect("reply");
        });

        let reply = query_at(&path, "flows 5").expect("query");
        server.join().expect("server thread");
        assert_eq!(reply, "got flows 5\n");
        let _ = std::fs::remove_file(&path);
    }
}
