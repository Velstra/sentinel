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
#
# Per fault class (HA_TAKEOVER_DESIGN below) the witness-mode fault stages are
# judged in two parts, from the client's own capture and reply times, never
# from when the test driver happened to look:
#   (1) the takeover P, s to the new owner's first frame, within its design,
#       which is built from Wren's and the agent's named terms: this judges
#       the product;
#   (2) the resume at the first retransmission at or after s + P_max on the
#       client's measured schedule (plus HA_RETRY_ANSWER_MAX): TCP's share. A
#       takeover inside its design that ends just after the 3R retry passes at
#       7R; one beyond its design fails on (1) whatever TCP does.
# Measured 2026-11-23 (idle builders, witness + SYN proxy, early announcement):
# agent crash P 0.42-0.48 s, wren crash 0.22-0.25 s, VM pause 0.34-0.42 s.
# HA_TAKEOVER_MAX and HA_FAULT_TO_RESUME_MAX above stay for the first stage
# and the handovers (preemption, the witness's return), which have no class.
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
# The takeover P of each fault class, by design, from the client's first
# unanswered segment s to the new owner's first frame (its gratuitous ARP).
# Wren and agent terms (wren-ha, velstra-app ha.rs):
HA_AGENT_TICK = 0.02           # the agent's HA monitor tick
HA_AGENT_ACK = 2 * HA_AGENT_TICK  # it reports the grant, then opens forwarding on the next tick
HA_WITNESS_MARGIN = 0.02       # Wren MARGIN_MS: a member's own deadline ends this much early
HA_TAKEOVER_MARGIN = 0.05      # stated margin on every class
# Common tail: the standby's next request (one poll), the grant exchange (the
# witness writes the new authority durably first, 48-74 ms measured), the
# agent's acknowledgement, and the announcement on the coordinator's next tick.
_HA_GRANT_AND_ANNOUNCE = HA_COORDINATOR_POLL + HA_WITNESS_IO + HA_AGENT_ACK + HA_COORDINATOR_POLL
HA_TAKEOVER_DESIGN = {
    # The owner stops at once (paused VM): the witness lease it last renewed
    # before the fault runs out.
    "vm pause": HA_LEASE + _HA_GRANT_AND_ANNOUNCE + HA_TAKEOVER_MARGIN,
    # The agent's exit fences the owner at once, but its Wren keeps renewing on
    # the dead agent's last report until that report is FRESH old (one more
    # renewal may start within a poll and take an exchange); then the lease.
    "agent crash": HA_AGENT_FRESH + HA_COORDINATOR_POLL + HA_WITNESS_IO + HA_LEASE
    + _HA_GRANT_AND_ANNOUNCE + HA_TAKEOVER_MARGIN,
    # The owner forwards until its own deadline, which ends at most one
    # exchange plus the margin before the witness's lease.
    "wren crash": HA_WITNESS_IO + HA_WITNESS_MARGIN + _HA_GRANT_AND_ANNOUNCE + HA_TAKEOVER_MARGIN,
    # Unhealthy links stop the owner's renewals at its next poll and fence it;
    # then the lease. Derived only: no check exercises this class yet.
    "link loss": HA_COORDINATOR_POLL + HA_LEASE + _HA_GRANT_AND_ANNOUNCE + HA_TAKEOVER_MARGIN,
}
# The client's retransmission timeout R, Linux TCP_RTO_MIN up to the HA_RTO_MAX
# above; a lost segment is retried at s+R, s+3R, s+7R without SACK.
HA_RTO_MIN = 0.2
# From the fault anchor (taken just before the fault command) to the fault
# taking effect on the stream: measured 0.10-0.32 s.
HA_FAULT_COMMAND_MAX = 0.35


def ha_retry_at_or_after(sends, point):
    """The lost segment's first retransmission at or after `point`: measured
    sends first, then the doubling schedule from the last measured interval."""
    for when in sends:
        if when >= point:
            return when
    when = sends[-1]
    interval = sends[-1] - sends[-2] if len(sends) > 1 else HA_RTO_MIN
    while when < point:
        interval *= 2
        when += interval
    return when


# The server's answer to a retransmission trails it by one round trip and
# whatever the server's own TCP holds it for: 4-82 ms measured (idle
# builders, witness+SYN proxy). Only the secondary assertion uses it.
HA_RETRY_ANSWER_MAX = 0.1


def ha_judge_takeover(s, sends, owner_frame, resumed, p_max, rtt=HA_RETRY_ANSWER_MAX):
    """(1) the takeover P against its design P_max: this judges the product;
    (2) the resume against the first retransmission at or after s + P_max on
    the client's measured schedule, plus one round trip: what TCP then allows."""
    limit = ha_retry_at_or_after(sends, s + p_max) + rtt
    return {"P": round(owner_frame - s, 3), "P_max": round(p_max, 3),
            "resumed_s": round(resumed - s, 3), "resume_limit_s": round(limit - s, 3),
            "primary": owner_frame - s <= p_max, "secondary": resumed <= limit}


def ha_fault_to_resume_max(fault):
    """Backstop from the fault anchor on the client's reply times, for checks
    without a capture: the worst R decides at which retransmission a takeover
    of design length is answered (3R if it fits below 3 R_min, else 7R)."""
    design = HA_TAKEOVER_DESIGN[fault]
    retries = 3 if design <= 3 * HA_RTO_MIN else 7
    onset = HA_FAULT_COMMAND_MAX + (HA_LEASE if fault == "wren crash" else 0.0)
    return onset + retries * HA_RTO_MAX + HA_RTT_MAX


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
        + " -p -U --immediate-mode -w " + HA_CAPTURE + " -i " + interface
        + " 'tcp port " + str(port) + " or arp'"
    )
    client.wait_until_succeeds(
        "journalctl -u ha-bound-capture --no-pager | grep -q 'listening on'", timeout=5
    )


# The client stream sends one message every 20 ms and waits for its echo, so
# a healthy stream replies every 20 ms plus one round trip. A longer silence
# is an outage.
HA_STREAM_GAP = 0.1
# Replies that must follow the end of an outage before it counts as resumed:
# one answered retransmission alone is not a working stream.
HA_STREAM_PROGRESS = 3
# Steady replies after the last silence before the outage is judged over: a
# fault takes up to HA_FAULT_COMMAND_MAX plus one lease to bite.
HA_STREAM_SETTLE = 1.0


def ha_resume(times, anchor, outage=True, gap=HA_STREAM_GAP, progress=HA_STREAM_PROGRESS,
              settle=HA_STREAM_SETTLE):
    """The instant forwarding resumed, on the client's own clock: the end of the
    longest silence longer than `gap` after `anchor`, once the stream has run
    steadily for `settle` since its last silence (so a short stall before the
    fault bites is not taken for its end) and `progress` replies follow it.
    `times` are the client stream's reply times (client wall clock). None
    while it has not resumed.

    With `outage` false (a handover already under way when the check starts),
    the first reply after the anchor that `progress` replies follow is the
    resume: a silence spanning the anchor ends there."""
    previous = None
    silences = []  # (length, end index)
    for index, when in enumerate(times):
        if when <= anchor:
            previous = when
            continue
        if not outage and previous is not None:
            return when if len(times) - index - 1 >= progress else None
        if previous is not None and when - previous > gap:
            silences.append((when - previous, index))
        previous = when
    if not silences:
        return None
    if times[-1] - times[silences[-1][1]] < settle:
        return None
    length, index = max(silences, key=lambda silence: (silence[0], -silence[1]))
    return times[index] if len(times) - index - 1 >= progress else None


def ha_resumed_within(resumed, anchor, bound):
    """Judge the resume instant itself, never the moment a poll saw it."""
    return resumed is not None and resumed - anchor <= bound


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


def _ha_lost_segment(packets, new_mac, vip, server_ip, port):
    """The first client segment after the anchor that was sent more than once,
    its sends, the server's first answer covering it, and the new owner's
    first ARP for the VIP after it (None where not captured yet)."""
    to_server = "> " + server_ip + "." + str(port) + ":"
    from_server = server_ip + "." + str(port) + " >"
    sent, replies = {}, []
    for when, _mac, line in packets:
        if when < -0.05:
            continue
        data = _ha_re.search(r"seq (\d+):(\d+)", line)
        if to_server in line and data:
            sent.setdefault(int(data.group(1)), []).append((when, int(data.group(2))))
        elif from_server in line and data:
            ack = _ha_re.search(r"ack (\d+)", line)
            replies.append((when, int(ack.group(1)) if ack else 0))
    lost = sorted((times[0][0], times) for times in sent.values() if len(times) > 1)
    if not lost:
        return None
    s, times = lost[0]
    end = times[0][1]
    answer = next((when for when, ack in replies if when > s and ack >= end), None)
    arps = [when for when, mac, line in packets
            if mac == new_mac and "ARP" in line and (" " + vip + " ") in line and when > s]
    return s, [when for when, _ in times], answer, (arps[0] if arps else None)


def ha_takeover_split(client, anchor, new_mac, vip, server_ip, port, fault, extra=0.0, settle=5.0):
    """The split check of one takeover from the client capture: (1) P within
    the design of its fault class, (2) the resume at the retransmission that
    design allows. Returns the verdict; asserts both. The capture reaches the
    file a little after the stream resumed: read it until the answer is in."""
    import time as _ha_time
    until = _ha_time.monotonic() + settle
    while True:
        found = _ha_lost_segment(_ha_packets(client, anchor), new_mac, vip, server_ip, port)
        if (found and found[2] is not None) or _ha_time.monotonic() > until:
            break
        _ha_time.sleep(0.5)
    if not found:
        verdict = {"fault": fault, "outage": None}
        print("HA takeover split:", verdict)
        return verdict
    s, sends, answer, arp = found
    owner_frame = arp if arp is not None else answer
    capture_tail = client.succeed(HA_TCPDUMP + " -tt -n -e -S -r " + HA_CAPTURE + " 2>/dev/null | tail -n 60")
    assert answer is not None and owner_frame is not None, (fault, "no answer after the lost segment", sends, capture_tail)
    verdict = ha_judge_takeover(s, sends, owner_frame, answer, HA_TAKEOVER_DESIGN[fault] + extra)
    verdict.update({"fault": fault, "s": round(s, 3), "sends_s": [round(w, 3) for w in sends],
                    "owner_frame": "ARP" if arp is not None else "first answer"})
    print("HA takeover split:", verdict)
    assert verdict["primary"], ("(1) the takeover exceeded its design", verdict, capture_tail)
    assert verdict["secondary"], ("(2) the client resumed after the retransmission its design allows", verdict, capture_tail)
    return verdict
