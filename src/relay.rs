//! C18 — **UDP broadcast relay**.
//!
//! A broadcast stops at the router. That is correct, and it is also why a printer
//! on one VLAN is invisible from another, why Wake-on-LAN only works from the
//! same segment, and why a game-server browser finds nothing. The relay carries a
//! named UDP port's broadcasts from each of its interfaces onto the others, so
//! discovery that assumes one flat LAN keeps working across a segmented one.
//!
//! There is no package for this — nixpkgs ships neither `udp-broadcast-relay` nor
//! its `-redux` successor — so it is a small daemon here rather than a rendered
//! config, which is why this module is longer than its neighbours.
//!
//! ## Preserving the sender
//!
//! A relayed packet is emitted with the **original source address**, not the
//! router's. That is the difference between a relay that works and one that
//! appears to: SSDP, mDNS-style discovery and most device protocols answer a
//! broadcast query with a *unicast* reply addressed to whatever source they saw.
//! Rewrite the source and every answer comes back to the router and dies there —
//! the query crosses the segment, the answer never does, and the symptom is
//! "discovery is flaky" rather than "the relay is broken".
//!
//! Preserving it needs a raw socket and a hand-built IPv4 header (`CAP_NET_RAW`),
//! which is the price of the feature working at all.
//!
//! ## Breaking the loop
//!
//! Every relayed packet is emitted with a fixed, deliberately unusual **TTL**, and
//! any packet received carrying that TTL is not relayed again. Without a marker
//! the relay feeds itself: a packet re-emitted onto B is received on B and
//! re-emitted onto A, forever.
//!
//! The marker is the TTL rather than something with no collisions at all because
//! a UDP socket can be told to report the TTL (`IP_RECVTTL`) and cannot be told to
//! report the IP id. The cost is exact and small: a genuine broadcast that happens
//! to arrive with [`RELAY_TTL_MARK`] is not relayed. Real link-local broadcasts
//! carry 1, 2, 4, 32, 64, 128 or 255 — never this — and the same reasoning is what
//! the reference implementation runs on.
//!
//! ## What the firewall has to allow
//!
//! The relay reads from an ordinary socket, so a broadcast has already passed the
//! XDP firewall by the time it gets here. Under a deny-by-default zone the packets
//! never arrive and the relay looks broken while being blameless — so
//! [`crate::config`] warns at commit when a relay's interfaces sit in a zone that
//! has no rule admitting its port.

use std::{
    io,
    net::Ipv4Addr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::mpsc,
    thread,
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::config::BroadcastRelay;

/// The rendered relay set the daemon reads.
///
/// Rendered at apply time rather than read from the saved appliance config,
/// because `commit` applies *before* `save` writes and a `commit` without a
/// `save` never writes at all — the daemon would enforce the previous config.
pub const RELAY_CONF: &str = "/run/sentinel/broadcast-relay.toml";

/// The systemd unit that runs [`run`].
pub const RELAY_UNIT: &str = "sentinel-broadcast-relay.service";

/// The TTL every relayed packet carries, and the one value that marks a packet as
/// already-relayed. See the module header for why this is the marker.
pub const RELAY_TTL_MARK: u8 = 57;

/// The largest datagram we will carry. A UDP payload cannot exceed this, so
/// nothing is ever truncated — a truncated relay would corrupt silently.
const MAX_DGRAM: usize = 65_535;

/// One relay as the daemon sees it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayEntry {
    pub name: String,
    pub port: u16,
    pub interface: Vec<String>,
}

/// The daemon's whole configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayConfig {
    #[serde(default, rename = "relay")]
    pub relays: Vec<RelayEntry>,
}

/// Render the daemon's config from the appliance's relays, or `None` when none is
/// enabled (the unit is then stopped rather than run with nothing to do).
pub fn conf_body(relays: &[BroadcastRelay]) -> Option<String> {
    let enabled: Vec<RelayEntry> = relays
        .iter()
        .filter(|r| !r.disabled)
        .map(|r| RelayEntry {
            name: r.name.clone(),
            port: r.port,
            interface: r.interface.clone(),
        })
        .collect();
    if enabled.is_empty() {
        return None;
    }
    let cfg = RelayConfig { relays: enabled };
    let mut body = String::from("# rendered by sentinel — UDP broadcast relay (do not edit)\n");
    body.push_str(&toml::to_string_pretty(&cfg).ok()?);
    Some(body)
}

/// Validate one relay at commit time.
///
/// Both rules refuse a relay that would look configured and do nothing, which on a
/// discovery feature is indistinguishable from "the devices are broken".
pub fn validate(relay: &BroadcastRelay) -> Result<()> {
    if relay.port == 0 {
        bail!("broadcast-relay {:?}: port 0 is not a UDP port", relay.name);
    }
    if relay.interface.len() < 2 {
        bail!(
            "broadcast-relay {:?}: needs at least two interfaces — a relay only ever \
             emits onto the interfaces a packet did NOT arrive on, so with one it \
             would carry nothing",
            relay.name
        );
    }
    Ok(())
}

/// Render the relay config and bring the daemon into line with it.
///
/// The unit is restarted on every apply that leaves a config behind, not only
/// when the file changed: the relay holds its sockets open for the lifetime of
/// the process, so a changed interface set does not take effect any other way.
pub fn apply(appliance: &crate::config::Appliance) -> Result<()> {
    let path = std::path::Path::new(RELAY_CONF);
    match conf_body(&appliance.services.broadcast_relay) {
        Some(body) => {
            crate::system::install_file(path, &body)?;
            if let Err(e) = crate::system::service_restart(RELAY_UNIT) {
                eprintln!("warning: (re)starting {RELAY_UNIT} failed: {e}");
            }
        }
        None => {
            if crate::system::unit_active(RELAY_UNIT) {
                if let Err(e) = crate::system::service_stop(RELAY_UNIT) {
                    eprintln!("warning: stopping {RELAY_UNIT}: {e}");
                }
            }
            if path.exists() {
                crate::system::remove_file(path)?;
            }
        }
    }
    Ok(())
}

/// Read the rendered config and relay until something fails.
pub fn run() -> Result<()> {
    let text =
        std::fs::read_to_string(RELAY_CONF).with_context(|| format!("reading {RELAY_CONF}"))?;
    let cfg: RelayConfig =
        toml::from_str(&text).with_context(|| format!("parsing {RELAY_CONF}"))?;
    if cfg.relays.is_empty() {
        bail!("no relays configured");
    }

    // A dead relay thread must take the process down so systemd restarts every
    // relay: a process that keeps running with one leg missing is exactly the
    // silent half-failure this feature cannot afford.
    let (tx, rx) = mpsc::channel::<anyhow::Error>();
    for relay in cfg.relays {
        for iface in &relay.interface {
            let others: Vec<String> = relay
                .interface
                .iter()
                .filter(|o| *o != iface)
                .cloned()
                .collect();
            let (name, port, iface) = (relay.name.clone(), relay.port, iface.clone());
            let tx = tx.clone();
            thread::Builder::new()
                .name(format!("relay-{name}-{iface}"))
                .spawn(move || {
                    if let Err(e) = relay_loop(&name, port, &iface, &others) {
                        let _ = tx.send(e);
                    }
                })
                .context("spawning a relay thread")?;
        }
    }
    drop(tx);

    match rx.recv() {
        Ok(e) => Err(e),
        // Every thread ended without reporting a failure, which a relay loop
        // never does on its own.
        Err(_) => bail!("every relay thread exited"),
    }
}

/// Receive on `iface` and re-emit onto `others` forever.
fn relay_loop(name: &str, port: u16, iface: &str, others: &[String]) -> Result<()> {
    let listener = listen_on(iface, port)
        .with_context(|| format!("relay {name}: listening on {iface}:{port}"))?;
    let mut senders = Vec::with_capacity(others.len());
    for out in others {
        let (fd, ifindex) =
            packet_sender(out).with_context(|| format!("relay {name}: packet socket for {out}"))?;
        senders.push((out.clone(), fd, ifindex));
    }
    eprintln!(
        "relay {name}: {iface} -> {} on udp/{port}",
        others.join(",")
    );

    let mut buf = vec![0u8; MAX_DGRAM];
    loop {
        let (len, src_addr, src_port, ttl) = recv_with_ttl(&listener, &mut buf)
            .with_context(|| format!("relay {name}: receiving on {iface}"))?;
        if ttl == RELAY_TTL_MARK {
            continue; // our own echo — see the module header
        }
        let packet = build_datagram(src_addr, src_port, port, &buf[..len]);
        for (out, fd, ifindex) in &senders {
            if let Err(e) = send_broadcast(fd, *ifindex, &packet) {
                // One interface refusing a packet is not a reason to stop
                // relaying on the others, but it must not be silent either.
                eprintln!("relay {name}: sending on {out}: {e}");
            }
        }
    }
}

// --- sockets ---------------------------------------------------------------

/// A UDP socket that receives `port`'s broadcasts arriving on `iface`, and
/// reports each packet's TTL.
fn listen_on(iface: &str, port: u16) -> Result<OwnedFd> {
    // SAFETY: every call below is a plain libc socket call on a fd we own; the
    // option values are `c_int`/byte-slice locals whose addresses and lengths are
    // passed together, and the fd is wrapped in `OwnedFd` so it is closed once.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error()).context("socket(AF_INET, SOCK_DGRAM)");
        }
        let fd = OwnedFd::from_raw_fd(fd);
        // Several sockets — this relay's other interfaces, and any other relay on
        // the same port — bind the same address. For UDP that is what
        // `SO_REUSEADDR` permits, and a broadcast is then delivered to every
        // socket that matches.
        //
        // `SO_REUSEPORT` must NOT be set here, however tempting it looks: it puts
        // the sockets in one load-balancing group, and for a broadcast the kernel
        // picks exactly ONE member of that group to deliver to — chosen by a hash,
        // *before* the bound-device check. A packet that arrived on eth1 then gets
        // handed to the socket listening on eth2, which drops it. The relay
        // silently carries a fraction of the traffic, and which fraction depends
        // on a hash of the flow.
        setsockopt_int(&fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
        setsockopt_int(&fd, libc::SOL_SOCKET, libc::SO_BROADCAST, 1)?;
        // Without this the packet's TTL is not delivered and the loop marker
        // cannot be read.
        setsockopt_int(&fd, libc::IPPROTO_IP, libc::IP_RECVTTL, 1)?;
        bind_to_device(&fd, iface)?;

        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        };
        if libc::bind(
            fd.as_raw_fd(),
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) < 0
        {
            return Err(io::Error::last_os_error()).context("bind");
        }
        Ok(fd)
    }
}

/// A socket that puts a frame directly onto `iface`, returned with the interface
/// index the send needs.
///
/// `AF_PACKET`/`SOCK_DGRAM` rather than a raw IP socket, because a relay works at
/// the segment level and an IP socket makes the kernel *route* the packet: the
/// destination is `255.255.255.255`, every interface has a broadcast route to it,
/// and which one wins is not something the relay gets to say. The packet then
/// leaves by whichever interface the routing table preferred — commonly the one it
/// arrived on — and the segment that was supposed to receive it never does, while
/// the local loopback copy makes everything look like it worked.
///
/// `SOCK_DGRAM` (not `SOCK_RAW`) leaves the Ethernet header to the kernel, built
/// from the address passed to `sendto`, so [`build_datagram`] still only has to
/// produce IP and UDP.
fn packet_sender(iface: &str) -> Result<(OwnedFd, i32)> {
    let name = std::ffi::CString::new(iface).context("interface name")?;
    // SAFETY: `name` is a NUL-terminated string that outlives the call.
    let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if ifindex == 0 {
        return Err(io::Error::last_os_error()).with_context(|| format!("no interface {iface:?}"));
    }
    // SAFETY: as in `listen_on` — a libc socket call on a fd wrapped in `OwnedFd`.
    // The protocol is a 16-bit EtherType in network order widened to an int —
    // NOT `i32::to_be`, which would shift it into the high half of the word.
    let proto = (ETH_P_IP as u16).to_be() as i32;
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM, proto) };
    if fd < 0 {
        return Err(io::Error::last_os_error())
            .context("socket(AF_PACKET, SOCK_DGRAM) — needs CAP_NET_RAW");
    }
    // SAFETY: `fd` was just returned by `socket` and is not owned elsewhere.
    Ok((unsafe { OwnedFd::from_raw_fd(fd) }, ifindex as i32))
}

/// `ETH_P_IP` — the EtherType the frames we emit carry.
const ETH_P_IP: i32 = 0x0800;

/// SAFETY: `fd` must be a valid socket; `value` is a local whose address and size
/// are passed together.
unsafe fn setsockopt_int(fd: &OwnedFd, level: i32, name: i32, value: i32) -> Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            &value as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error()).context("setsockopt");
    }
    Ok(())
}

/// Pin a socket to one interface, so "which segment did this arrive on" is a
/// property of the socket rather than something to work out per packet.
///
/// SAFETY: `fd` must be a valid socket; the name buffer outlives the call.
unsafe fn bind_to_device(fd: &OwnedFd, iface: &str) -> Result<()> {
    let name = iface.as_bytes();
    if name.len() >= libc::IFNAMSIZ {
        bail!("interface name {iface:?} is too long");
    }
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr() as *const libc::c_void,
            name.len() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error()).with_context(|| format!("SO_BINDTODEVICE {iface}"));
    }
    Ok(())
}

/// Receive one datagram, returning its length, source address, source port and
/// TTL. `recvmsg` rather than `recv_from` because the TTL arrives as a control
/// message and nothing else can deliver it.
fn recv_with_ttl(fd: &OwnedFd, buf: &mut [u8]) -> Result<(usize, Ipv4Addr, u16, u8)> {
    let mut from: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // Room for one `IP_TTL` control message.
    let mut control = [0u8; 64];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut from as *mut libc::sockaddr_in as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control.len();

    // SAFETY: `msg` points at locals that outlive the call, with matching lengths.
    let len = unsafe { libc::recvmsg(fd.as_raw_fd(), &mut msg, 0) };
    if len < 0 {
        return Err(io::Error::last_os_error()).context("recvmsg");
    }

    // Walk the control messages for the TTL. A packet whose TTL we cannot read
    // is reported as 0, which is not the marker, so it is relayed — failing
    // toward carrying traffic rather than dropping it.
    let mut ttl = 0u8;
    // SAFETY: the control buffer was filled by the kernel and is walked with the
    // CMSG macros, which is the only defined way to traverse it.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::IPPROTO_IP && (*cmsg).cmsg_type == libc::IP_TTL {
                ttl = *(libc::CMSG_DATA(cmsg) as *const libc::c_int) as u8;
                break;
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    let src = Ipv4Addr::from(u32::from_be(from.sin_addr.s_addr));
    Ok((len as usize, src, u16::from_be(from.sin_port), ttl))
}

/// Put one IPv4 datagram onto `ifindex` as an Ethernet broadcast.
fn send_broadcast(fd: &OwnedFd, ifindex: i32, packet: &[u8]) -> Result<()> {
    // SAFETY: `sockaddr_ll` is plain data; zeroing it is the documented way to
    // start one, and every field set below is a scalar.
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = (ETH_P_IP as u16).to_be();
    addr.sll_ifindex = ifindex;
    addr.sll_halen = 6;
    addr.sll_addr[..6].copy_from_slice(&[0xff; 6]);

    // SAFETY: `packet` and `addr` are locals passed with their own lengths.
    let rc = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error()).context("sendto");
    }
    Ok(())
}

// --- packet construction ---------------------------------------------------

/// Build the IPv4 + UDP datagram for a relayed packet: the sender's address kept,
/// the destination rewritten to the local broadcast, and the TTL set to the loop
/// marker.
///
/// The UDP checksum is left at 0, which IPv4 defines as "not computed" — the IPv4
/// header checksum below still covers the addressing, and a wrong checksum would
/// be worse than an absent one.
pub fn build_datagram(src: Ipv4Addr, src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let total = 20 + 8 + payload.len();
    let mut p = Vec::with_capacity(total);

    p.push(0x45); // IPv4, 5 × 32-bit words of header
    p.push(0); // DSCP/ECN
    p.extend_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes()); // id
    p.extend_from_slice(&0u16.to_be_bytes()); // flags + fragment offset
    p.push(RELAY_TTL_MARK);
    p.push(17); // UDP
    p.extend_from_slice(&0u16.to_be_bytes()); // checksum, filled in below
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&Ipv4Addr::BROADCAST.octets());

    let sum = ipv4_checksum(&p[..20]);
    p[10..12].copy_from_slice(&sum.to_be_bytes());

    p.extend_from_slice(&src_port.to_be_bytes());
    p.extend_from_slice(&dst_port.to_be_bytes());
    p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes()); // checksum: not computed
    p.extend_from_slice(payload);
    p
}

/// The one's-complement sum of a header, as RFC 791 defines it.
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in header.chunks(2) {
        let word = match pair {
            [hi, lo] => u16::from_be_bytes([*hi, *lo]),
            [hi] => u16::from_be_bytes([*hi, 0]),
            _ => unreachable!(),
        };
        sum += word as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(name: &str, port: u16, ifaces: &[&str]) -> BroadcastRelay {
        BroadcastRelay {
            name: name.into(),
            description: None,
            disabled: false,
            port,
            interface: ifaces.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn a_relay_with_one_interface_is_refused() {
        // It would carry nothing at all, and look configured while doing so.
        let err = validate(&relay("wol", 9, &["eth1"])).unwrap_err();
        assert!(err.to_string().contains("at least two"), "{err}");
        validate(&relay("wol", 9, &["eth1", "eth2"])).unwrap();
    }

    #[test]
    fn port_zero_is_refused() {
        assert!(validate(&relay("wol", 0, &["eth1", "eth2"])).is_err());
    }

    #[test]
    fn nothing_is_rendered_until_a_relay_is_enabled() {
        assert!(conf_body(&[]).is_none());
        let mut off = relay("wol", 9, &["eth1", "eth2"]);
        off.disabled = true;
        assert!(
            conf_body(&[off]).is_none(),
            "a disabled relay must not keep the daemon running"
        );
    }

    #[test]
    fn the_rendered_config_round_trips() {
        let body = conf_body(&[relay("wol", 9, &["eth1", "eth2"])]).unwrap();
        let cfg: RelayConfig = toml::from_str(&body).unwrap();
        assert_eq!(cfg.relays.len(), 1);
        assert_eq!(cfg.relays[0].port, 9);
        assert_eq!(cfg.relays[0].interface, ["eth1", "eth2"]);
    }

    #[test]
    fn a_relayed_packet_keeps_its_sender_and_carries_the_loop_marker() {
        let payload = b"magic";
        let p = build_datagram(Ipv4Addr::new(10, 0, 0, 7), 4321, 9, payload);

        assert_eq!(p.len(), 20 + 8 + payload.len());
        assert_eq!(p[0], 0x45);
        assert_eq!(u16::from_be_bytes([p[2], p[3]]), p.len() as u16);
        // The marker is what stops the relay feeding itself.
        assert_eq!(p[8], RELAY_TTL_MARK);
        assert_eq!(p[9], 17, "UDP");
        // The sender survives; only the destination is rewritten.
        assert_eq!(&p[12..16], &[10, 0, 0, 7], "the original source is kept");
        assert_eq!(&p[16..20], &[255, 255, 255, 255]);

        assert_eq!(u16::from_be_bytes([p[20], p[21]]), 4321, "source port kept");
        assert_eq!(u16::from_be_bytes([p[22], p[23]]), 9);
        assert_eq!(u16::from_be_bytes([p[24], p[25]]), 8 + payload.len() as u16);
        assert_eq!(&p[28..], payload);
    }

    #[test]
    fn the_header_checksum_is_the_one_a_receiver_will_verify() {
        let p = build_datagram(Ipv4Addr::new(192, 168, 1, 50), 68, 67, &[0u8; 300]);
        // A receiver sums the header including the checksum field; a correct one
        // makes the total zero. That is the only property that matters, and it
        // catches a byte-order slip that a hand-computed expected value would not.
        assert_eq!(ipv4_checksum(&p[..20]), 0);
    }
}
