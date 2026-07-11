# The configuration CLI

Everything on a Sentinel appliance is driven from one place: `sentinel
configure`, a VyOS/vtysh-style candidate session. You edit a **candidate**
config, `compare` it against what's running, then `commit` it (apply live)
and/or `save` it (persist across reboot).

```text
$ sentinel configure
admin@sentinel# set system hostname fw-a
admin@sentinel*# set interface eth0 zone wan
admin@sentinel*# set interface eth0 address dhcp
admin@sentinel*# commit
✔ commit ok: applied live (not persisted — `save` to keep across reboot)
admin@fw-a# save
✔ saved /var/lib/sentinel/appliance.toml (persists across reboot)
admin@fw-a# exit
```

A `*` in the prompt marks uncommitted edits. On the appliance you can also type
`configure` and `show` directly (shell aliases), and the interactive shell
offers Tab-completion and `?` at every level.

## One grammar

The shell has exactly one rule: **every command names a path in the config
tree**. There is no implicit `set` and no mode switching — a line always means
one thing. Press `<Tab>` (or type `?`) after any word to see the valid
continuations, each with a one-line description.

```text
admin@fw-a# set services ssh ?
  enable                    run the SSH daemon (true|false; default true)
  port                      TCP port sshd listens on (default 22)
  listen-address            restrict sshd to one local address (default: all)
  password-authentication   allow password logins over SSH (default false)
```

## Editing the candidate

| Command | What it does |
|---|---|
| `set <path> <value>` | Set a configuration value. |
| `delete <path>` | Remove a node, or clear a field. |
| `show [section]` | Show the candidate config (optionally one section). |
| `edit <path>` | Descend into a subtree (VyOS-style context); `up` / `top` to leave. |
| `compare` | Diff the candidate vs the saved config (or vs/between archived revisions). |
| `discard` | Drop all uncommitted edits. |

Values that are lists (a rule's `source`, a service's `serve-on`, …) accept a
comma-separated set and are additive; `delete` clears them. Repeatable keyed
nodes (a login, a BGP neighbor, a firewall rule) are addressed by their name or
key.

## Applying & persisting

| Command | What it does |
|---|---|
| `commit` | Apply the candidate to the **running** system (live). Not persisted. |
| `save` | Persist the running config to `/var/lib/sentinel/appliance.toml` (survives reboot). |
| `commit-confirm [mins]` | Apply live **and** arm an auto-rollback timer (default 10 min). If you don't `confirm`, the box reverts to the saved config — your safety net for a remote change that might cut your own access. |
| `confirm` | Keep a `commit-confirm` change (cancel the pending rollback). |
| `rollback <N>` | Revert the running system to archived revision `N` (`0` = newest) and persist it. |

Every `save` archives a timestamped revision under
`/var/lib/sentinel/archive/` (the newest 50 are kept). `show system commit`
lists them; `compare <N>` diffs the candidate against a revision, and
`compare <N> <M>` diffs two revisions.

> **Immutable OS.** The commit applies the config to the *running* system
> (networkd units, the eBPF data plane, the routing daemon, service configs)
> without rebuilding the OS image. The image itself is A/B-updated separately —
> see [the commit model](../architecture/commit-model.md) and
> [A/B updates](../architecture/ab-updates.md).

## Operational commands (`run show` / `show`)

Outside of edits, `sentinel show …` (or `run show …` inside a session, or just
`show …` at the appliance shell) reports live state:

| Command | Shows |
|---|---|
| `show interfaces` | Live interfaces and addresses. |
| `show ip route` / `show ipv6 route` | The routing table (via the wren RIB). |
| `show ip bgp [neighbors\|summary]` | BGP routes / sessions. |
| `show ip ospf [neighbors\|database]`, `show ipv6 ospf3 …` | OSPF / OSPFv3 state. |
| `show isis …`, `show babel …`, `show ip rip`, `show ipv6 ripng` | Other IGPs. |
| `show vrrp`, `show bfd` | First-hop redundancy / liveness sessions. |
| `show firewall [statistics\|log]` | Firewall summary, per-rule counters, the eBPF log. |
| `show nat` | NAT configuration summary. |
| `show vpn ipsec [sas\|connections]` | IPsec security associations / loaded connections. |
| `show pki` | Local CAs + issued certificates (with expiry). |
| `show arp` | The ARP / neighbour table. |
| `show configuration` | The saved configuration, in config syntax. |
| `show log [velstra\|wren]` | Recent service log. |
| `show version` | Software versions. |

The rest of this handbook is a tour of the config tree, section by section,
each with the commands it exposes and a worked example. The final chapter,
[Example configurations](examples.md), ties them together into complete boxes.
