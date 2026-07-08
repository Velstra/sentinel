# Configuring the appliance

`sentinel configure` is the VyOS/vtysh-style candidate session. You edit a
candidate, `compare` it, then `commit` (apply live) and/or `save` (persist).

## A session

```text
$ sentinel configure
admin@sentinel# set system hostname fw-a
admin@sentinel*# set interface eth0 zone wan
admin@sentinel*# set interface eth0 address dhcp
admin@sentinel*# compare
     system {
-        hostname sentinel
+        hostname fw-a
     }
admin@sentinel*# commit
✔ commit ok: applied live (not persisted — `save` to keep across reboot)
admin@fw-a# save
✔ saved /var/lib/sentinel/appliance.toml (persists across reboot)
admin@fw-a# exit
```

- **`commit`** applies the candidate to the running system (live).
- **`save`** persists it to `/var/lib/sentinel/appliance.toml`.
- A **`*`** in the prompt marks uncommitted edits.
- See [the commit model](../architecture/commit-model.md).

## One grammar, no modes

The shell has exactly one rule: **every command names a path in the config
tree**. There is no implicit `set`, no bare-path context shorthand, and no
mode switching — a line always means exactly one thing. `help` shows a grouped
command overview, `help <command>` details and examples, and a mistyped line
answers with the correct spelling (`did you mean …`, or the explicit
`set`/`edit` form when you typed a config path without a command).

## Contexts (`edit`)

`edit <path>` descends into any subtree; `set`, `delete`, and `show` are then
relative to it. The position shows as an `[edit …]` banner line above the
prompt:

```text
admin@fw-a# edit firewall rule web
[edit firewall rule web]
admin@fw-a# set from wan
[edit firewall rule web]
admin@fw-a*# set action accept
```

- **`up`** goes one level up (a keyword+instance pair like `interface eth0`
  counts as one level).
- **`top`** returns to the top of the tree.
- **`exit`** returns to the top; at the top it leaves the session.

## The config tree

There are **four** top-level nodes, each a clear domain, so it's always obvious
where a setting lives. Press **Tab** or **`?`** at any level to see what's
available next (with a description for each), VyOS-style:

```text
system     hostname <name>
interface  <name>   zone | address | type | parent | vlan | member | vlan-aware | …
firewall   global        stateful | block-icmp | default-action | log | block
           zone <z>      stateful | block-icmp | default-action | log | block
           rule <r>      from | to | action | proto | port
nat        source <s>      zone
           destination <d> zone | proto | port | to
vpn        ipsec <name>      local | remote | local-subnet | remote-subnet | psk | …
           wireguard <if>    private-key | listen-port | peer <pubkey> …
           openconnect       certificate | port | pool | dns | routes | default-route | zone | user <name> …
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

A **VLAN** is just an 802.1Q subinterface with a `parent` and a `vlan` id — it
gets its own zone like any other interface. Naming it `<parent>.<id>` lets
Sentinel infer both, so the `parent`/`vlan` lines are optional (set them
explicitly only to override; a name/value mismatch is an error):

```text
sentinel# set interface eth1.20 zone iot
sentinel# set interface eth1.20 address 10.0.20.1/24
```

## Bridges, bonds & VLAN-aware switching

A **bridge** (software switch) or a **bond** (link aggregation) is a
`type = "bridge"`/`"bond"` device. The member NICs are listed on the device
itself with `member` (repeat it to add more; `delete … member <nic>` removes
one). Set the bond's aggregation mode with `bond-mode`:

```text
sentinel# set interface br0 type bridge
sentinel# set interface br0 zone lan
sentinel# set interface br0 address 10.0.0.1/24
sentinel# set interface br0 member eth1
sentinel# set interface br0 member eth2
sentinel# set interface bond0 type bond
sentinel# set interface bond0 bond-mode active-backup
sentinel# set interface bond0 member eth3
```

Mark a bridge `vlan-aware` to do 802.1Q filtering in the switch, then give each
member port its tagged VLAN ids and/or a single untagged (PVID) VLAN:

```text
sentinel# set interface br0 vlan-aware true
sentinel# set interface eth1 vlan-tagged 10,20
sentinel# set interface eth1 vlan-untagged 1
```

## WireGuard

A **WireGuard** tunnel is a `type = "wireguard"` interface (address/zone like any
interface) whose keys and peers live under `vpn`, keyed by the interface name.
`private-key` accepts a literal key or `generate`:

```text
sentinel# set interface wg0 type wireguard
sentinel# set interface wg0 zone vpn
sentinel# set interface wg0 address 10.9.0.1/24
sentinel# set vpn wireguard wg0 private-key generate
sentinel# set vpn wireguard wg0 listen-port 51820
sentinel# set vpn wireguard wg0 peer <pubkey> allowed-ips 10.9.0.2/32
sentinel# set vpn wireguard wg0 peer <pubkey> endpoint 203.0.113.9:51820
```

## OpenConnect (road-warrior VPN)

**OpenConnect** is a TLS client VPN (AnyConnect-compatible, served by `ocserv`)
for roaming devices — the client-VPN modality alongside site-to-site
[IPsec](#) and peer-to-peer [WireGuard](#wireguard). Because it rides over
TLS on port 443 by default, it traverses restrictive networks that only allow
HTTPS. There is at most **one** server per box, so it lives under `vpn
openconnect` as a singleton (no name key).

The server needs a TLS identity: name a `pki certificate` (roadmap C19) — a leaf
issued by the on-box PKI (or `acme`) — as its `certificate`. Clients authenticate
with a **password**; each `user <name> password <secret>` is rendered into a
`0600` password file (never into `ocserv.conf`).

```text
sentinel# set pki ca corp common-name corp.example.com
sentinel# set pki certificate vpn-server ca corp
sentinel# set pki certificate vpn-server common-name vpn.example.com
sentinel# set vpn openconnect certificate vpn-server
sentinel# set vpn openconnect pool 10.99.0.0/24        # client address pool (required)
sentinel# set vpn openconnect port 443                 # optional; 443 by default
sentinel# set vpn openconnect dns 10.99.0.1            # pushed resolver(s), repeatable
sentinel# set vpn openconnect routes 10.0.0.0/8        # split-tunnel route(s), repeatable
sentinel# set vpn openconnect zone vpn                 # firewall zone for the tun device
sentinel# set vpn openconnect user alice password s3cret
sentinel# commit save
```

Notes:

- **`pool`** and **`certificate`** are required, and at least one **`user`** —
  a server with no users can accept no one.
- **`routes`** pushes split-tunnel routes; **`default-route true`** makes it a
  full tunnel instead (all client traffic over the VPN). The two are mutually
  exclusive.
- **`dns`** / **`routes`** append and de-duplicate (`delete vpn openconnect dns
  <ip>` / `routes <cidr>` removes one entry); `delete vpn openconnect user
  <name>` removes one credential; `delete vpn openconnect` removes the whole
  server.
- **`disabled true`** parks the server without deleting its config.

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
sentinel# set firewall rule lan-out from lan
sentinel# set firewall rule lan-out action accept       # lan may initiate
sentinel# set firewall rule https from wan
sentinel# set firewall rule https action accept
sentinel# set firewall rule https proto tcp
sentinel# set firewall rule https port 443
sentinel# commit
sentinel# save
```

- **`from`** — source zone (must be backed by an interface).
- **`to`** — *optional* destination zone. The datapath does not enforce the
  destination zone yet: a rule applies from its `from` zone toward **all**
  zones, and setting `to` declares intent but draws a commit warning until
  egress-zone matching lands in the eBPF datapath. Omit it unless you want to
  document the intent in the config.
- **`action`** — `accept` / `drop` / `reject` (a `reject` sends a TCP RST rather
  than dropping silently).
- **`proto` / `port`** — set together to make a port rule; omit both for a broad
  rule.
- **`port`** — a single port (`443`) **or an inclusive range** written as
  `lo-hi`. A range opens a contiguous block of ports (e.g. passive-FTP data):

  ```text
  sentinel# set firewall rule ftp-data from wan
  sentinel# set firewall rule ftp-data action accept
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

## Reverse proxy / load balancer (`services reverse-proxy`)

A `services reverse-proxy <name>` frontend is the **L7 tier**: it listens on a
port, optionally **terminates TLS** with an on-box PKI certificate, and forwards
requests to one or more **backends** round-robin (host:port). This is
HTTP-aware routing + TLS termination that sits *on top of* the datapath — the
XDP L4 load-balancer (fabric) is the separate high-throughput path; use this
when you want TLS termination or per-host HTTP routing rather than raw L4
forwarding.

Each frontend is a keyed section (keyed by name, like firewall rules or `nat`
entries), so you can define as many as you like on distinct ports:

```text
sentinel# set pki ca corp common-name corp.example.com
sentinel# set pki certificate web-cert ca corp
sentinel# set pki certificate web-cert common-name web.example.com
sentinel# set services reverse-proxy web port 443            # listen port (default 443)
sentinel# set services reverse-proxy web certificate web-cert # TLS via the PKI cert
sentinel# set services reverse-proxy web backends 10.0.0.10:8080,10.0.0.11:8080
sentinel# commit save
```

- **`port`** — the listen port. Defaults to `443`; every frontend must use a
  distinct port.
- **`certificate`** — a `pki certificate` name (or `acme`) used to terminate
  TLS on the listen port. **Omit it for plain HTTP** (no termination).
- **`backends`** — one or more upstreams as `host:port`, load-balanced
  round-robin. At least one is required. The list appends+dedups, so you can add
  more in a later `set …` and drop one with
  `delete services reverse-proxy web backends 10.0.0.11:8080`.
- **`disabled true`** — administratively park a frontend without deleting it.
- Remove a whole frontend with `delete services reverse-proxy <name>`.

The frontends are rendered into an HAProxy `frontend`/`backend` pair by the
appliance.

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
