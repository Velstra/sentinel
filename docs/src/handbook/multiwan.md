# Multi-WAN & updates

## Multi-WAN

`multiwan` binds two or more WAN uplinks into a failover or load-balancing
group, each with its own policy-routing table and health checks. A small daemon
pings each uplink's targets and swings the default route to (or shares it
across) the healthy uplink(s).

```text
set multiwan mode failover                  # or load-balance
```

Per-uplink (`set multiwan uplink <if> …`):

| Field | Meaning |
|---|---|
| `priority` | Failover order (lower = preferred; default by config order). |
| `weight` | Load-balance share (default 1). |
| `table` | Policy-routing table id (default 200 + index). |
| `gateway` | Next-hop IPv4, or `dhcp` (resolve from the lease). |

Health check (`set multiwan uplink <if> check …`):

| Field | Meaning |
|---|---|
| `target` | An IPv4 to ping out this uplink (repeatable). |
| `interval` | Seconds between probe rounds (default 5). |
| `timeout` | Per-ping timeout seconds (default 2). |
| `fail` | Consecutive losses to mark down (default 3). |
| `rise` | Consecutive successes to mark up (default 3). |

```text
set multiwan mode failover
set multiwan uplink eth0 priority 10
set multiwan uplink eth0 gateway dhcp
set multiwan uplink eth0 check target 1.1.1.1
set multiwan uplink eth1 priority 20
set multiwan uplink eth1 gateway 192.0.2.1
set multiwan uplink eth1 check target 9.9.9.9
```

Both uplinks are firewalled `wan`-zone interfaces with source NAT
(`set nat source wan-masq zone wan`). On failure of `eth0`, the default route
moves to `eth1`; it moves back on recovery.

## Software updates

Sentinel is an A/B image OS: an update writes the new image to the inactive
slot and you reboot into it (rolling back is booting the previous slot). The
`update` node pins where images come from and the key that signs them.

| Field | Meaning |
|---|---|
| `url` | Channel base URL (holds `manifest.json` + images). |
| `public-key` | Pinned Ed25519 signing key (PEM, or `file:<path>`). |

```text
set update url https://updates.example.com/sentinel/stable
set update public-key file:/var/lib/sentinel/update.pub
```

Then, operationally: `sentinel update` (fetch + verify + write the inactive
slot) and reboot. See [Updating (A/B + rollback)](../operations/update.md).


## SD-WAN: steering, not just failover

Failover answers "the uplink died, now what". Steering answers the question
before it: *this* traffic belongs on *that* uplink, and moves only when the
uplink stops being good enough for it. A video call and a nightly backup want
opposite things from the same two links, and a priority number cannot say so.

### Out of SLA is not the same as down

A link that answers every probe in 400 ms is up by any reachability test and
useless for a call. So a health check can carry thresholds:

| Field | Meaning |
|---|---|
| `latency` | Round-trip above which the uplink is out of SLA (ms). |
| `jitter` | Variation in round-trip above which it is out of SLA (ms). |
| `loss` | Packet loss above which it is out of SLA (%). |
| `probes` | Pings per round. A threshold needs a sample; default 5. |

```text
set multiwan uplink eth1 check target 9.9.9.9
set multiwan uplink eth1 check latency 80
set multiwan uplink eth1 check loss 2
```

The daemon now **measures** rather than only asking: one round yields average
round-trip, deviation and loss, and the same sample answers both questions. A
check with no threshold stays a single ping, as before — one probe cannot measure
loss or jitter at all, which is why setting a threshold silently raises the
sample.

### Steering policies

```text
set multiwan policy voip proto udp
set multiwan policy voip destination-port 5060
set multiwan policy voip uplink eth1,eth2
set multiwan policy voip strict true
```

The match is the same vocabulary a policy route uses, because it is the same
question. What differs is the answer: a policy route names one table; this names
an **ordered preference** and lets the daemon pick.

The daemon sends the traffic out the first uplink that is up **and** within its
SLA. If none qualifies it falls back to the first that is merely up — a degraded
path beats no path — **unless** the policy is `strict`, which holds the traffic
instead. That is for the traffic where a bad answer is worse than no answer.

Steering rules sit at priority 20000+, **below** the explicit policy routes at
10000+: what an operator pinned by hand wins, and steering moves the rest.

Refused at commit: a policy naming an uplink that does not exist, a port with no
protocol, and `strict` on a set of uplinks where none has a threshold to be
strict about — being strict about nothing is a rule that can never act.

### Seeing it

```text
show multiwan
```

What each uplink measured on its last round, and where each policy is currently
sending traffic. This is the state as of the last probe rather than a fresh
measurement, which is the honest thing to show: a fresh one would say nothing
about the trend that moved the traffic.
