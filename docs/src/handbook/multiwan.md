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
