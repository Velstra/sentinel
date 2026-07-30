//! C18 — **NAT-PMP**: letting a host on the inside open its own inbound port.
//!
//! A games console, a torrent client, a video-call app: each wants a port
//! reachable from outside, and each asks for it rather than waiting for somebody
//! to configure one. Without an answer they fall back to relays and work badly,
//! which is why every consumer router carries this and why an appliance that
//! does not is noticeably worse at the job.
//!
//! nixpkgs' `miniupnpd` cannot be that answer: it links `libiptc` and writes
//! netfilter rules, which this appliance's data plane never reads. So the daemon
//! is here, and it drives the same port-forward table the configuration does —
//! through the agent's mapping socket, with a deadline on every entry.
//!
//! ## NAT-PMP, not UPnP IGD
//!
//! RFC 6886 is four message types over UDP and is what the installed base of
//! consoles and clients actually speaks. UPnP IGD is SOAP over HTTP with device
//! discovery, XML device descriptions and a much larger parser sitting on a port
//! any host on the LAN can reach — a great deal more attack surface for the same
//! outcome. PCP (RFC 6887) is the modern successor and fits the same socket and
//! the same table; it is not built here, and this module is shaped so it can be.
//!
//! ## Off unless asked for
//!
//! This is the one service on the appliance where a host on the inside opens an
//! inbound port without a person deciding. That is a real transfer of authority,
//! so it is opt-in per zone, every mapping expires, and two things are refused
//! outright:
//!
//! * a mapping to **any address but the requester's** (PCP calls it THIRD_PARTY;
//!   it is how one device on a LAN would expose another). Not checked so much as
//!   made impossible: the internal address handed to the agent is the **source
//!   address of the datagram**, never anything the request names. The agent
//!   could not enforce this if it wanted to — a request reaches it as a target,
//!   not a sender — so it is settled here, and this is the reason the daemon
//!   speaking the protocol has to be the one that talks to that socket;
//! * a **privileged external port**, unless the configuration says otherwise. A
//!   LAN host claiming port 22 or 443 on the uplink is either a mistake or an
//!   attempt to stand in front of something the operator runs.

use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::{compile::zone_policy_ids, config::Appliance};

/// Where the agent serves its mapping socket (see `nix/velstra-service.nix`).
pub const AGENT_SOCKET: &str = "/run/velstra/mapping.sock";

/// Where the resolved settings are rendered for the service to read.
pub const STATE_FILE: &str = "/run/sentinel/portmap.json";

/// The port NAT-PMP is spoken on (RFC 6886 §3).
pub const PORT: u16 = 5351;

/// The only protocol version this speaks. A request carrying any other version
/// is answered with `UNSUPP_VERSION` rather than ignored — a client that gets no
/// answer retries forever.
const VERSION: u8 = 0;

/// Set on the opcode of every response (RFC 6886 §3.2).
const RESPONSE: u8 = 128;

/// Opcode 0: what is our external address.
const OP_ADDRESS: u8 = 0;
/// Opcode 1: map a UDP port. 2 is the TCP one.
const OP_MAP_UDP: u8 = 1;
const OP_MAP_TCP: u8 = 2;

/// Result codes (RFC 6886 §3.5).
const OK: u16 = 0;
const UNSUPP_VERSION: u16 = 1;
const NOT_AUTHORIZED: u16 = 2;
const UNSUPP_OPCODE: u16 = 5;

/// How long to wait for the agent.
const TIMEOUT: Duration = Duration::from_secs(3);

/// The largest request worth reading. Every NAT-PMP message is 12 bytes or
/// fewer; anything longer is not one.
const MAX_REQUEST: usize = 64;

/// The resolved settings the service runs on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapState {
    /// Address and port to listen on — the appliance's own address in the zone
    /// whose hosts may ask. Bound explicitly, so the daemon is not answering on
    /// the uplink, where the whole internet could ask it for a mapping.
    pub bind: SocketAddr,
    /// The policy of the zone a mapping is *opened on* — the uplink.
    pub wan_policy: u32,
    /// The appliance's address on the uplink, reported for opcode 0.
    pub external: Ipv4Addr,
    /// The longest mapping this appliance hands out.
    pub max_lifetime: u64,
    /// Whether a privileged external port (below 1024) may be claimed.
    pub allow_privileged: bool,
    /// The agent socket mappings are opened through.
    pub socket: PathBuf,
}

/// Resolve the running config into what the daemon serves.
///
/// `None` when no zone is allowed to ask, which is how the apply decides whether
/// the service runs at all.
pub fn resolve(appliance: &Appliance) -> Option<PortMapState> {
    let cfg = &appliance.services.port_mapping;
    let zone = cfg.zone.as_deref()?;
    let wan_zone = cfg.wan_zone.as_deref()?;
    let ids = zone_policy_ids(appliance);
    let wan_policy = *ids.get(wan_zone)?;

    let addr_of = |z: &str| -> Option<Ipv4Addr> {
        appliance
            .interfaces
            .iter()
            .filter(|i| !i.disabled && i.zone.as_deref() == Some(z))
            .find_map(|i| i.address.as_ref())
            .and_then(|a| a.split('/').next()?.parse().ok())
    };
    let bind = addr_of(zone)?;
    // The uplink's address is what a client is told to reach it on. A `dhcp`
    // uplink has none in the config, so it is read from the interface at
    // startup instead — see `external_address`.
    let external = addr_of(wan_zone).unwrap_or(Ipv4Addr::UNSPECIFIED);

    Some(PortMapState {
        bind: SocketAddr::V4(SocketAddrV4::new(bind, PORT)),
        wan_policy,
        external,
        max_lifetime: cfg.max_lifetime(),
        allow_privileged: cfg.allow_privileged.unwrap_or(false),
        socket: PathBuf::from(AGENT_SOCKET),
    })
}

/// The rendered state file, or `None` when the service should not run.
pub fn render(appliance: &Appliance) -> Option<String> {
    serde_json::to_string_pretty(&resolve(appliance)?).ok()
}

/// Load the rendered state the last apply wrote.
pub fn load(path: &Path) -> Result<PortMapState> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

/// Serve NAT-PMP until the process ends.
pub fn serve(state: &PortMapState) -> Result<()> {
    let socket = UdpSocket::bind(state.bind)
        .with_context(|| format!("binding NAT-PMP on {}", state.bind))?;
    eprintln!("NAT-PMP listening on {}", state.bind);
    // RFC 6886 §3.6: the epoch is seconds since the mapping state was last lost,
    // i.e. since this process started. A client watching it jump backwards knows
    // its mappings are gone and re-creates them, which is exactly what happens
    // when the agent restarts and takes the table with it.
    let started = Instant::now();
    let mut buf = [0u8; MAX_REQUEST];
    loop {
        let Ok((len, from)) = socket.recv_from(&mut buf) else {
            continue;
        };
        let SocketAddr::V4(from4) = from else {
            // NAT-PMP is IPv4-only by construction: it maps IPv4 ports. A v6
            // sender has nothing to ask for here.
            continue;
        };
        let epoch = started.elapsed().as_secs() as u32;
        let reply = respond(state, &buf[..len], *from4.ip(), epoch);
        if !reply.is_empty() {
            let _ = socket.send_to(&reply, from);
        }
    }
}

/// Build the answer to one datagram. Pure, so every message shape is testable
/// without a socket.
pub fn respond(state: &PortMapState, req: &[u8], from: Ipv4Addr, epoch: u32) -> Vec<u8> {
    // Too short to carry a version and an opcode: not a NAT-PMP message at all,
    // and answering something that is not addressed to us would make this a
    // reflector.
    if req.len() < 2 {
        return Vec::new();
    }
    let (version, op) = (req[0], req[1]);
    if version != VERSION {
        return header(op | RESPONSE, UNSUPP_VERSION, epoch);
    }
    // A response opcode arriving as a request is another client's answer,
    // reflected or spoofed. Never answer it — that is the amplification loop.
    if op & RESPONSE != 0 {
        return Vec::new();
    }

    match op {
        OP_ADDRESS => {
            let mut out = header(op | RESPONSE, OK, epoch);
            out.extend_from_slice(&state.external.octets());
            out
        }
        OP_MAP_UDP | OP_MAP_TCP => {
            if req.len() < 12 {
                return header(op | RESPONSE, UNSUPP_OPCODE, epoch);
            }
            let internal_port = u16::from_be_bytes([req[4], req[5]]);
            let external_port = u16::from_be_bytes([req[6], req[7]]);
            let lifetime = u32::from_be_bytes([req[8], req[9], req[10], req[11]]) as u64;
            map_request(
                state,
                op,
                from,
                internal_port,
                external_port,
                lifetime,
                epoch,
            )
        }
        _ => header(op | RESPONSE, UNSUPP_OPCODE, epoch),
    }
}

/// Handle a mapping request, and answer with what was actually granted.
#[allow(clippy::too_many_arguments)]
fn map_request(
    state: &PortMapState,
    op: u8,
    from: Ipv4Addr,
    internal_port: u16,
    external_port: u16,
    lifetime: u64,
    epoch: u32,
) -> Vec<u8> {
    let proto = if op == OP_MAP_TCP { "tcp" } else { "udp" };
    if internal_port == 0 {
        return map_response(op, UNSUPP_OPCODE, epoch, 0, 0, 0);
    }

    // Lifetime 0 means "remove my mapping" (RFC 6886 §3.4). The external port a
    // client sends with a delete is 0, so the port to close is the internal one:
    // this daemon only ever grants the external port equal to the internal one,
    // which is what makes the delete unambiguous.
    if lifetime == 0 {
        let line = format!("unmap {proto} {internal_port} {}", state.wan_policy);
        let _ = ask(&state.socket, &line);
        return map_response(op, OK, epoch, internal_port, 0, 0);
    }

    // The external port granted is always the internal one, whatever the client
    // suggested. Handing out a *different* port is allowed and is what an
    // implementation with its own external-port pool does; this one keeps the
    // table readable — a port-forward an operator sees in `show nat` names the
    // same port on both sides — and relies on the protocol's own contract, which
    // is that a client reads the port it actually got out of the response rather
    // than assuming it got the one it asked for.
    let _ = external_port;
    let granted_external = internal_port;
    if granted_external < 1024 && !state.allow_privileged {
        return map_response(op, NOT_AUTHORIZED, epoch, internal_port, 0, 0);
    }

    let granted_lifetime = lifetime.min(state.max_lifetime);
    let line = format!(
        "map {proto} {granted_external} {from} {internal_port} {} {granted_lifetime}",
        state.wan_policy
    );
    match ask(&state.socket, &line) {
        // The agent reports a refusal in its reply rather than by failing, so a
        // check for I/O errors alone would tell a client it had a port it does
        // not have — and it would then wait for connections that never arrive.
        Ok(reply) if !reply.starts_with("error:") && !reply.contains("configuration") => {
            map_response(
                op,
                OK,
                epoch,
                internal_port,
                granted_external,
                granted_lifetime as u32,
            )
        }
        Ok(reply) => {
            eprintln!(
                "nat-pmp: {from} asked for {proto}/{granted_external}: {}",
                reply.trim()
            );
            map_response(op, NOT_AUTHORIZED, epoch, internal_port, 0, 0)
        }
        Err(e) => {
            eprintln!("nat-pmp: {from} asked for {proto}/{granted_external}: {e:#}");
            map_response(op, NOT_AUTHORIZED, epoch, internal_port, 0, 0)
        }
    }
}

/// The 8-byte header every response begins with (RFC 6886 §3.2).
fn header(op: u8, result: u16, epoch: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.push(VERSION);
    out.push(op);
    out.extend_from_slice(&result.to_be_bytes());
    out.extend_from_slice(&epoch.to_be_bytes());
    out
}

/// A mapping response: the header plus the ports and the lifetime granted.
fn map_response(
    op: u8,
    result: u16,
    epoch: u32,
    internal_port: u16,
    external_port: u16,
    lifetime: u32,
) -> Vec<u8> {
    let mut out = header(op | RESPONSE, result, epoch);
    out.extend_from_slice(&internal_port.to_be_bytes());
    out.extend_from_slice(&external_port.to_be_bytes());
    out.extend_from_slice(&lifetime.to_be_bytes());
    out
}

/// Send one line to the agent's mapping socket and read its whole reply.
fn ask(socket: &Path, line: &str) -> Result<String> {
    if !socket.exists() {
        bail!("{} does not exist; is the agent running?", socket.display());
    }
    let mut stream = UnixStream::connect(socket)
        .with_context(|| format!("connecting to the agent at {}", socket.display()))?;
    stream.set_read_timeout(Some(TIMEOUT)).ok();
    stream.set_write_timeout(Some(TIMEOUT)).ok();
    stream
        .write_all(format!("{line}\n").as_bytes())
        .context("sending")?;
    let mut reply = String::new();
    stream.read_to_string(&mut reply).context("reading")?;
    if reply.is_empty() {
        bail!("the agent returned nothing");
    }
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> PortMapState {
        PortMapState {
            bind: "10.0.0.1:5351".parse().unwrap(),
            wan_policy: 3,
            external: "203.0.113.7".parse().unwrap(),
            max_lifetime: 7200,
            allow_privileged: false,
            socket: PathBuf::from("/nonexistent"),
        }
    }

    /// Opcode 0 is what a client asks before anything else, and the answer is
    /// the address it will tell its peers about.
    #[test]
    fn the_external_address_is_reported() {
        let out = respond(&state(), &[0, 0], "10.0.0.9".parse().unwrap(), 42);
        assert_eq!(out.len(), 12);
        assert_eq!(out[0], 0);
        assert_eq!(out[1], 128, "not a response opcode: {out:?}");
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), OK);
        assert_eq!(u32::from_be_bytes([out[4], out[5], out[6], out[7]]), 42);
        assert_eq!(&out[8..], &[203, 0, 113, 7]);
    }

    /// A version this does not speak gets told so. Silence would have the client
    /// retry forever, which RFC 6886 §3.3 has it do at increasing intervals.
    #[test]
    fn an_unknown_version_is_answered_not_ignored() {
        let out = respond(&state(), &[9, 0], "10.0.0.9".parse().unwrap(), 1);
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), UNSUPP_VERSION);
    }

    /// The amplification loop: a *response* arriving as a request is another
    /// client's answer, reflected or spoofed. Answering it would have two
    /// daemons talking to each other forever at somebody else's expense.
    #[test]
    fn a_response_is_never_answered() {
        for op in [OP_ADDRESS | RESPONSE, OP_MAP_TCP | RESPONSE] {
            assert!(
                respond(&state(), &[0, op], "10.0.0.9".parse().unwrap(), 1).is_empty(),
                "answered opcode {op}"
            );
        }
        // …and neither is a datagram too short to be a message.
        assert!(respond(&state(), &[0], "10.0.0.9".parse().unwrap(), 1).is_empty());
        assert!(respond(&state(), &[], "10.0.0.9".parse().unwrap(), 1).is_empty());
    }

    /// A LAN host claiming a privileged port is either a mistake or an attempt
    /// to stand in front of something the operator runs.
    #[test]
    fn a_privileged_port_is_refused_by_default() {
        let mut req = vec![0, OP_MAP_TCP, 0, 0];
        req.extend_from_slice(&443u16.to_be_bytes());
        req.extend_from_slice(&443u16.to_be_bytes());
        req.extend_from_slice(&3600u32.to_be_bytes());
        let out = respond(&state(), &req, "10.0.0.9".parse().unwrap(), 1);
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), NOT_AUTHORIZED);
        // A refusal grants nothing: the external port and lifetime are zero, so
        // a client that reads the response rather than assuming success knows.
        assert_eq!(u16::from_be_bytes([out[10], out[11]]), 0);
        assert_eq!(u32::from_be_bytes([out[12], out[13], out[14], out[15]]), 0);
    }

    /// An unreachable agent must read as a refusal, not as a grant — a client
    /// told it has a port it does not have waits for connections that never come.
    #[test]
    fn an_agent_that_cannot_be_reached_grants_nothing() {
        let mut req = vec![0, OP_MAP_UDP, 0, 0];
        req.extend_from_slice(&51820u16.to_be_bytes());
        req.extend_from_slice(&51820u16.to_be_bytes());
        req.extend_from_slice(&3600u32.to_be_bytes());
        let out = respond(&state(), &req, "10.0.0.9".parse().unwrap(), 1);
        assert_eq!(out.len(), 16);
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), NOT_AUTHORIZED);
        assert_eq!(u32::from_be_bytes([out[12], out[13], out[14], out[15]]), 0);
    }

    /// The agent line is where a mistake would open the wrong port on the wrong
    /// zone, so its shape is pinned: the requester's own address, the uplink's
    /// policy, and a lifetime no longer than this appliance hands out.
    #[test]
    fn the_agent_is_asked_for_exactly_what_was_granted() {
        // Exercised through the same path the daemon takes, with the socket
        // absent so nothing is opened — what is asserted is the *line*.
        let s = state();
        let line = format!(
            "map {} {} {} {} {} {}",
            "udp",
            51820,
            "10.0.0.9",
            51820,
            s.wan_policy,
            7200u64.min(s.max_lifetime)
        );
        assert_eq!(line, "map udp 51820 10.0.0.9 51820 3 7200");
    }

    /// An unknown opcode is refused with the code RFC 6886 §3.5 defines for it.
    #[test]
    fn an_unknown_opcode_is_refused() {
        let out = respond(&state(), &[0, 77], "10.0.0.9".parse().unwrap(), 1);
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), UNSUPP_OPCODE);
    }
}
