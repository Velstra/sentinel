# Configuring the appliance

`sentinel configure` is the VyOS/vtysh-style candidate session. You edit a
candidate, `compare` it, then `commit` (apply live) and/or `save` (persist).

## A session

```text
$ sentinel configure
sentinel# set system hostname fw-a
sentinel# set interface eth0 role wan
sentinel# set interface eth0 address dhcp
sentinel# compare
     system {
-        hostname sentinel
+        hostname fw-a
     }
sentinel# commit save
sentinel# exit
```

- **`commit`** applies the candidate to the running system (live).
- **`save`** persists it to `/var/lib/sentinel/appliance.toml`.
- **`commit save`** does both. See [the commit model](../architecture/commit-model.md).

## Zones, interfaces & VLANs

Sentinel is **zone-based**: a *zone* is a named trust domain (`wan`, `lan`,
`dmz`, `guest`, `iot`, … — arbitrary names), and every interface is assigned to
one. Rules and posture are expressed per zone; each zone becomes one policy in
the data plane.

```text
sentinel# set interface eth0 zone wan
sentinel# set interface eth0 address dhcp
sentinel# set interface eth1 zone lan
sentinel# set interface eth1 address 10.0.0.1/24
```

A **VLAN** is just a subinterface with a `parent` and a `vlan` id — it gets its
own zone like any other interface:

```text
sentinel# set interface eth1.20 parent eth1
sentinel# set interface eth1.20 vlan 20
sentinel# set interface eth1.20 zone iot
sentinel# set interface eth1.20 address 10.0.20.1/24
```

## Firewall posture — global defaults + per-zone overrides

Posture is layered: the global `[firewall]` section sets **defaults**, and each
`[zone.<name>]` **overrides** them for that zone. This is what lets you (for
example) block ICMP on the WAN but allow it on the LAN. These map straight onto
capabilities the Velstra data plane already enforces per policy (stateful flows,
ICMP filtering, an LPM blocklist).

```text
sentinel# set firewall stateful true          # global defaults …
sentinel# set firewall block-icmp false
sentinel# set firewall default-action drop
sentinel# set firewall block 203.0.113.0/24    # global source denylist (repeatable)

sentinel# set zone wan block-icmp true          # … overridden per zone
sentinel# set zone wan masquerade true          # SNAT outbound (NAT — Phase 4)
sentinel# set zone iot block-icmp true
sentinel# set zone iot block 198.51.100.0/24    # per-zone source drop
sentinel# commit save
```

Per-zone fields (each inherits the `[firewall]` default when unset):

- **`stateful`** — track allowed flows so replies come back without a rule.
- **`block-icmp`** — drop inbound ICMP (ping/PMTU) on this zone.
- **`default-action`** — `accept` / `drop` / `reject` ingress posture.
- **`log`** — log this zone's matched traffic.
- **`masquerade`** — SNAT outbound to the zone's egress IP (a WAN uplink).
- **`block <IP|CIDR>`** — source denylist for this zone (`delete zone <name>
  block <IP|CIDR>` to remove).

`[firewall]` and any `[zone.*]` block are omitted from a saved config while they
are exactly the default, so saved files stay clean.

## NAT — port-forwards

Expose an internal service to a public (e.g. WAN) zone with an inbound DNAT
port-forward. The data plane rewrites the destination to the internal host and
SNATs the reply back automatically (connection-tracked), and the rule implicitly
opens the firewall for that port:

```text
sentinel# set port-forward web zone wan        # the public/ingress zone
sentinel# set port-forward web proto tcp
sentinel# set port-forward web port 8080        # public port hit from outside
sentinel# set port-forward web to 10.0.0.10:8443   # internal host[:port]
sentinel# commit save
```

- **`zone`** — the ingress (public) zone; must be backed by an interface.
- **`to`** — `"ip"` (keep the public port) or `"ip:port"` (remap).
- Remove one with `delete port-forward <name>`.

This enforcement lives in the eBPF datapath (reusing the load-balancer's NAT +
connection-tracking machinery), so it works on real forwarded traffic with no
`iptables`.

## Completion (the vtysh feel)

- **`?`** or **Tab** shows suggestions **with descriptions**, one per line.
- At a value position that names an interface, completion offers the **real
  NICs** discovered from `/sys/class/net` (e.g. `set interface <Tab>` →
  `eth0`, `lo`, …) — so you complete against what the box actually has.
- Completion is context-aware: `show interfaces <Tab>` suggests interface names,
  not the same keywords as the level above.

## Operational `show` (outside configure)

From a plain shell, `sentinel show <what> [target]` reflects live system state:

```shell
sentinel show status
sentinel show interfaces [<iface>]   # scope to one NIC, vtysh-style
sentinel show routes
sentinel show neighbors
sentinel show config
sentinel show log
sentinel show version
```

## Off-box editing

`sentinel configure --no-apply` edits the candidate without touching the running
system — useful for preparing a config off the box or in CI. `compare` still
shows the diff against the saved config; `commit` in this mode is session-only.

## Discovered interfaces

Even before you assign anything, the real NICs show up in the config (VyOS-like),
so they're ready to reference. The minimal factory config has no interfaces of
its own; `show` in a fresh session lists what the hardware provides.
