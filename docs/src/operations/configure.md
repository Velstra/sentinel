# Configuring the appliance

`sentinel configure` is the VyOS/vtysh-style candidate session. You edit a
candidate, `compare` it, then `commit` (apply live) and/or `save` (persist).

## A session

```text
$ sentinel configure
sentinel# set system hostname fw-a
sentinel# set interface eth0 zone wan
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

## The config tree

There are **four** top-level nodes, each a clear domain, so it's always obvious
where a setting lives. Press **Tab** or **`?`** at any level to see what's
available next (with a description for each), VyOS-style:

```text
system     hostname <name>
interface  <name>   zone | address | parent | vlan
firewall   global        stateful | block-icmp | default-action | log | block
           zone <z>      stateful | block-icmp | default-action | log | block
           rule <r>      from | to | action | proto | port
nat        source <s>      zone
           destination <d> zone | proto | port | to
```

The split is deliberate: **`firewall`** *filters* packets (zones, posture,
zone-to-zone rules), while **`nat`** *translates* addresses — a different thing
that happens at a different stage, so it's its own top-level node (as in VyOS),
not buried under the firewall. `nat source` is masquerade (SNAT); `nat
destination` is a port-forward (DNAT). `show` prints the candidate as this same
nested tree.

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
sentinel# set firewall global stateful true          # global defaults …
sentinel# set firewall global block-icmp false
sentinel# set firewall global default-action drop
sentinel# set firewall global block 203.0.113.0/24    # global source denylist (repeatable)

sentinel# set firewall zone wan block-icmp true          # … overridden per zone
sentinel# set firewall zone iot block-icmp true
sentinel# set firewall zone iot block 198.51.100.0/24    # per-zone source drop
sentinel# commit save
```

Per-zone fields (each inherits the `[firewall]` default when unset):

- **`stateful`** — track allowed flows so replies come back without a rule.
- **`block-icmp`** — drop inbound ICMP (ping/PMTU) on this zone.
- **`default-action`** — `accept` / `drop` / `reject` ingress posture.
- **`log`** — log this zone's matched traffic.
- **`block <IP|CIDR>`** — source denylist for this zone (`delete firewall zone
  <name> block <IP|CIDR>` to remove).

(NAT — masquerading a zone's outbound traffic — is **not** a firewall-zone
field; it lives under `nat source`, below.)

`[firewall]` and any `[zone.*]` block are omitted from a saved config while they
are exactly the default, so saved files stay clean.

## Firewall rules — zone-to-zone & ports

A **broad** rule (no `proto`/`port`) sets a from-zone's ingress posture: a
`from = <zone>, action = accept` lets that zone initiate, so its policy passes by
default. A **port** rule (`proto` + `port`) opens or blocks a specific service —
e.g. inbound HTTPS even on a default-drop WAN:

```text
sentinel# set firewall rule lan-out from lan to wan action accept   # lan may initiate
sentinel# set firewall rule https from wan to lan action accept
sentinel# set firewall rule https proto tcp
sentinel# set firewall rule https port 443
sentinel# commit save
```

- **`from` / `to`** — source and destination zone (each must be backed by an
  interface).
- **`action`** — `accept` / `drop` / `reject` (a `reject` sends a TCP RST rather
  than dropping silently).
- **`proto` / `port`** — set together to make a port rule; omit both for a broad
  rule.
- **`port`** — a single port (`443`) **or an inclusive range** written as
  `lo-hi`. A range opens a contiguous block of ports (e.g. passive-FTP data):

  ```text
  sentinel# set firewall rule ftp-data from wan to lan action accept
  sentinel# set firewall rule ftp-data proto tcp
  sentinel# set firewall rule ftp-data port 49152-50175
  ```

  A range expands to one data-plane rule per port, so it is capped at 1024 ports
  — a wider span is rejected at commit time (split it, or open the zone).
- Remove a rule with `delete firewall rule <name>`.

## NAT — its own top-level node

NAT *translates* addresses; the firewall *filters* packets. They're separate
concerns at separate stages, so NAT is its own `nat` node (VyOS-style), split
into `source` (SNAT/masquerade) and `destination` (DNAT/port-forward).

### `nat source` — masquerade

SNAT a zone's outbound traffic to that zone's egress IP — the classic WAN
uplink, so a private LAN can reach the internet behind one public address:

```text
sentinel# set nat source wan-masq zone wan      # masquerade everything leaving wan
sentinel# commit save
```

- **`zone`** — the egress (WAN) zone whose outbound traffic is masqueraded; must
  be backed by an interface.
- Remove one with `delete nat source <name>`.

### `nat destination` — port-forward

Expose an internal service to a public (e.g. WAN) zone with an inbound DNAT. The
data plane rewrites the destination to the internal host and SNATs the reply
back automatically (connection-tracked), and the rule implicitly opens the
firewall for that port:

```text
sentinel# set nat destination web zone wan          # the public/ingress zone
sentinel# set nat destination web proto tcp
sentinel# set nat destination web port 8080          # public port hit from outside
sentinel# set nat destination web to 10.0.0.10:8443  # internal host[:port]
sentinel# commit save
```

- **`zone`** — the ingress (public) zone; must be backed by an interface.
- **`to`** — `"ip"` (keep the public port) or `"ip:port"` (remap).
- Remove one with `delete nat destination <name>`.

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
