# One bound for "the owner fails and its standby takes over", shared by every
# HA VM check (loaded as a module by the test driver; call ha_use_tcpdump first).
#
# What a client sees, measured from a capture on the client with the fault
# anchored in the client's own clock: 12 runs on 2026-11-22 measured under
# concurrent VM load on the builders (load only lengthens these, so the budgets
# below are conservative), then 15 runs on an idle builder, where the takeover
# P was 0.25-0.44 s (witness, witness+SYN proxy, VRRP, VRRP+SYN proxy) and
# fault -> resume was 0.84-0.88 s (wren SIGKILL), 1.18-1.27 s (velstra
# SIGKILL), 0.57-1.18 s (owner VM paused):
#
#   s   outage start: the client's first segment that is never answered.
#       VRRP crash: 0.02-0.05 s after the fault. Witness lease: the owner keeps
#       forwarding until its 250 ms lease lapses and it fences itself, so
#       0.30-0.40 s after the fault. The lease delays the outage; it is not
#       part of it.
#   P   takeover: s to the new owner's first ARP for the VIP (witness grant,
#       promotion, VIP, GARP). 0.19-0.38 s in every variant.
#   R   the client's retransmission timeout, max(200 ms, srtt + 4 rttvar):
#       0.21-0.22 s. Its retries of the lost segment come at s+R, s+2R (with
#       SACK, a tail-loss probe first) or s+R, s+3R (without SACK: a SYN-proxied
#       connection loses SACK and timestamps), then doubling.
#   The first answered packet was, in every run, the first retry sent after
#   the new owner's ARP: state continuity (conntrack sync, the SYN-proxy
#   splice) added nothing measurable.
#
# The gap a TCP stream sees is P rounded up to the next retry. Upper-bounding
# the retry schedule by the no-SACK one, R(2^k - 1) for k = 1, 2, 3, the first
# retry at or after P is T(P) <= 3 R_max whenever P <= 3 R_min. So:
#
#   HA_TAKEOVER_MAX       P  <= 0.6 s                  (measured <= 0.38)
#   HA_RTO_MAX            R  <= 0.30 s                 (measured <= 0.22)
#   HA_GAP_MAX            gap <= 3 R_max + RTT + margin = 0.9 + 0.05 + 0.25 = 1.2 s
#   HA_LEASE_RUNOUT_MAX   fault -> s <= 0.4 s          (measured <= 0.40)
#   HA_FAULT_TO_RESUME_MAX fault -> resume <= 0.4 + 1.2 = 1.6 s
#   HA_WIREGUARD_EXTRA    a WireGuard peer may have to wait for a handshake
#                         retry: REKEY_TIMEOUT 5 s + REKEY_TIMEOUT_JITTER_MAX 1/3 s
#                         (so a WireGuard fault -> resume is 1.6 + 5.33 = 6.93 s)
#   HA_DRIVER_LATENCY_MAX a test-driver observation trails the capture by up to 0.3 s
#
# A takeover slower than HA_TAKEOVER_MAX fails (a) by name, a lost state
# handoff fails (b), and HA_GAP_MAX stays as the backstop for what the
# capture cannot see.
import re as _ha_re

HA_TAKEOVER_MAX = 0.6
HA_RTO_MAX = 0.30
HA_RTT_MAX = 0.05
HA_MARGIN = 0.25
HA_GAP_MAX = 3 * HA_RTO_MAX + HA_RTT_MAX + HA_MARGIN
HA_LEASE_RUNOUT_MAX = 0.4
HA_FAULT_TO_RESUME_MAX = HA_LEASE_RUNOUT_MAX + HA_GAP_MAX
HA_WIREGUARD_EXTRA = 5.0 + 1.0 / 3.0
# A driver-side observation (polling a VM over the test driver's channel)
# trails the client capture by 0.15-0.25 s (measured).
HA_DRIVER_LATENCY_MAX = 0.3
# A stalled data-plane agent on the owner (SIGSTOP, a wedged process). Wren's
# request carries the agent's report only while it is fresh, so it stops
# renewing once the last report is FRESH old; the VIPs go when the lease it
# last renewed ends, at the decision after the exchange in flight, on its next
# poll. Measured inside the owner from the stop to both VIPs gone; the watch
# itself polls every 5 ms and runs `ip`.
HA_AGENT_FRESH = 0.1      # Wren FRESH_NS
HA_LEASE = 0.25           # Wren TTL_MS, the default lease
HA_WITNESS_IO = 0.08      # Wren IO_MS, one exchange
HA_COORDINATOR_POLL = 0.025  # Wren POLL_MS
HA_WATCH_MARGIN = 0.05
HA_STALLED_AGENT_RELEASE_MAX = (
    HA_AGENT_FRESH + HA_LEASE + HA_WITNESS_IO + HA_COORDINATOR_POLL + HA_WATCH_MARGIN
)
# A two-node pair has no witness: the standby takes over only once it has
# not heard its peer for the configured peer timeout (1000 ms in the checks).
HA_TWO_NODE_PEER_TIMEOUT = 1.0
HA_CAPTURE = "/tmp/ha-bound.pcap"
HA_TCPDUMP = "tcpdump"


def ha_use_tcpdump(path):
    """The tcpdump binary the client runs (a store path in the test)."""
    global HA_TCPDUMP
    HA_TCPDUMP = path


def ha_capture_start(client, interface, port):
    """Capture the stream and every ARP on the client's link to the VIP."""
    client.succeed(
        "systemd-run --unit=ha-bound-capture " + HA_TCPDUMP
        + " -p -U -w " + HA_CAPTURE + " -i " + interface
        + " 'tcp port " + str(port) + " or arp'"
    )
    client.wait_until_succeeds(
        "journalctl -u ha-bound-capture --no-pager | grep -q 'listening on'", timeout=5
    )


def ha_fault_anchor(client):
    """The client's wall clock just before the fault: the capture's time base."""
    return float(client.succeed("date +%s.%N"))


def _ha_packets(client, anchor):
    text = client.succeed(HA_TCPDUMP + " -tt -n -e -S -r " + HA_CAPTURE + " 2>/dev/null")
    packets = []
    for line in text.splitlines():
        head = _ha_re.match(r"(\d+\.\d+) (\S+) > (\S+),", line)
        if head:
            packets.append((float(head.group(1)) - anchor, head.group(2), line))
    return packets


def ha_takeover(client, anchor, new_mac, vip, server_ip, port, takeover_max=HA_TAKEOVER_MAX):
    """Assert (a) the takeover time P and (b) that the first client retry after
    the new owner's ARP is answered. Returns the measured timeline."""
    packets = _ha_packets(client, anchor)
    sent = {}  # first byte of a client data segment -> its send times
    replies = []  # (time, ack) of server data segments
    to_server = "> " + server_ip + "." + str(port) + ":"
    from_server = server_ip + "." + str(port) + " >"
    for when, _mac, line in packets:
        if when < -0.5:
            continue
        data = _ha_re.search(r"seq (\d+):(\d+)", line)
        if to_server in line and data:
            sent.setdefault(int(data.group(1)), []).append((when, int(data.group(2))))
        elif from_server in line and data:
            ack = _ha_re.search(r"ack (\d+)", line)
            replies.append((when, int(ack.group(1)) if ack else 0))
    timeline = {"anchor": anchor}
    # Only the new owner's announcement of the VIP, not its other ARP traffic.
    arps = [when for when, mac, line in packets
            if mac == new_mac and "ARP" in line and (" " + vip + " ") in line and when > 0]
    assert arps, ("no ARP for " + vip + " from the new owner " + new_mac + " after the fault", timeline,
                  client.succeed(HA_TCPDUMP + " -tt -n -e -r " + HA_CAPTURE + " 2>/dev/null | tail -n 60"))
    arp = arps[0]
    # The outage segment: the earliest one first sent before the new owner's
    # ARP and retried after it. A retry that a lossy test link caused before
    # or after the takeover does not span it.
    spanning = sorted((times[0][0], times) for times in sent.values()
                      if len(times) > 1 and times[0][0] < arp < times[-1][0])
    if not spanning:
        # No segment was lost across the takeover: it beat the first retry.
        timeline.update({"first_arp_s": round(arp, 3), "outage": None})
        print("HA takeover:", timeline)
        return timeline
    start, times = spanning[0]
    end = times[0][1]
    timeline.update({"outage_start_s": round(start, 3),
                     "sends_s": [round(when, 3) for when, _ in times]})
    timeline.update({"first_arp_s": round(arp, 3), "takeover_s": round(arp - start, 3)})
    after = [when for when, _ in times if when > arp]
    answered = None
    if after:
        retry = after[0]
        answered = next((when for when, ack in replies if retry < when <= retry + HA_RTO_MAX and ack >= end), None)
        timeline.update({"retry_after_arp_s": round(retry, 3),
                         "answered_s": round(answered, 3) if answered is not None else None})
    print("HA takeover:", timeline)
    capture_tail = client.succeed(HA_TCPDUMP + " -tt -n -e -S -r " + HA_CAPTURE + " 2>/dev/null | tail -n 80")
    assert arp - start <= takeover_max, ("(a) takeover exceeded " + str(takeover_max) + " s", timeline, capture_tail)
    assert answered is not None, ("(b) the first retry after the new owner's ARP was not answered", timeline, capture_tail)
    return timeline
