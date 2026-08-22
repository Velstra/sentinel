# The commit model (runtime apply)

`sentinel configure` is a VyOS-style candidate session (`set` / `show` /
`delete` / `compare` / `commit` / `save`). On this immutable appliance,
**`commit` applies the edited config to the running system at runtime** — no
rebuild, no reboot, fully airgapped.

> This supersedes the earlier *rebuild-on-commit* design (kept as a
> [historical note](../appendix/design-notes-commit.md)). The implemented model
> does **not** build a new NixOS generation on commit.

## `commit` vs `save`

| Command | Effect | Survives reboot? |
|---|---|---|
| `commit` | apply the candidate to the **running** system, live | no, on its own |
| `save` | persist the candidate to `/var/lib/sentinel/appliance.toml` | yes |
| `commit save` | both — apply live **and** persist | yes |

This mirrors VyOS in spirit: `commit` makes it live, `save` makes it durable.

## What a `commit` reconciles

A `commit` is not three actions — it reconciles the **whole** appliance to the
edited config in one apply. Representative mechanisms:

| Area | Mechanism on `commit` |
|---|---|
| Firewall rules / zones / NAT | `sentinel compile` → `/run/sentinel/velstra.toml` → reload `velstra.service` |
| Dynamic routing (BGP, static) | `wren` compile → `/run/sentinel/wren.toml` → reload `wren.service` |
| Hostname | `hostname <name>` (plain `sethostname(2)`) — **not** `hostnamectl` (NixOS blocks it) |
| Interface addressing | write `/run/systemd/network/10-sentinel-<iface>.network` → `networkctl reload`/`reconfigure` |
| VPN | WireGuard `.netdev`/`.network`, IPsec (swanctl/charon), OpenConnect (ocserv) |
| Services | DNS, NTP (chrony), SNMP, LLDP, dyndns, DHCP relay, captive portal |
| Security | on-box PKI + ACME certs, IDS (Suricata), AAA (RADIUS/LDAP/TOTP), login passwords, sshd |
| Links | sysctl, offload (ethtool), multi-WAN failover, wireless (hostapd), WWAN (ModemManager) |

In all it drives roughly thirty co-services plus the data plane. Every one
touches only **running services** and the single persistent config partition —
the OS image is fixed.

The **same apply path** backs three entry points: the interactive `commit`, the
REST `PUT /api/v1/config`, and the two-stage boot reconcile below. They share one
compiler and one apply function, so there is no CLI-vs-API drift.

## Atomicity and rollback

`commit` compiles **everything** before it changes anything, so a bad config is
rejected before a single live edit. The first three stages — firewall, routing,
hostname — each record how to undo themselves, and a failure in one rolls the
completed ones back and reports a clean rollback.

The broad final stage (the ~30 co-services above) has **no automatic undo**: if
it fails partway, the three covered stages are rolled back but the co-services
may be partly applied. The tool says so honestly — it reports a **mixed state**
and points at recovery (reboot to the saved config, or `rollback <N>`), rather
than claiming a rollback that did not cover that stage.

Concurrent applies are serialised by a cross-process advisory lock
(`/run/sentinel/apply.lock`), so an interactive `commit`, an API `PUT`, and the
boot reconcile cannot corrupt each other's staged files.

## Undo and safety nets

| Command | Effect |
|---|---|
| `commit-confirm [min]` | apply live **and** arm an auto-revert timer; `confirm` keeps the change, otherwise it reverts to the saved config after the window |
| `rollback <N>` | re-apply an archived revision (`0` = newest) live + save |
| `compare [running \| <rev>]` | diff the candidate against the running config or an archived revision |
| `discard` | drop the candidate's uncommitted edits |

Every `save` archives a config revision (kept per `system commit-revisions`), so
`rollback` and `compare` have history to work from.

> **Why `hostname`, not `hostnamectl`.** NixOS rejects `hostnamectl set-hostname`
> ("Changing system settings via systemd is not supported on NixOS"). The plain
> `hostname` command sets the live kernel hostname; `sentinel-boot.service`
> re-applies it from the saved config each boot, so it persists.

## How it persists across reboot

Boot re-applies the saved config in **two stages**, because some state can only
be set once the links networkd brought up actually exist:

1. `sentinel-boot.service` (oneshot, before `velstra.service`) seeds
   `/var/lib/sentinel/appliance.toml` from the factory default on first boot,
   then runs `sentinel apply-boot`: set the hostname, compile the firewall +
   routing configs, and render the networkd units and co-service drop-ins
   (render only — it must not poke networkd before networkd has started).
2. `sentinel-boot-late.service` (after networkd) runs `sentinel apply-boot-late`:
   the runtime-only state a file cannot express — tc qdiscs, multi-WAN policy
   routes, IPsec SAs — once the interfaces are up.

Both stages load the saved config **leniently** (an unknown key from a newer
build must not keep the box from coming up) and take the same apply lock as an
interactive commit. So a `commit save` writes the durable file, and the boot
services re-assert it every boot — no generation, no rebuild.

## Privilege path

Edits are written by the admin (wheel-group, so no root needed for the file);
`sentinel` escalates the live actions (`hostname`, `networkctl`, `systemctl`)
through **passwordless sudo**, with every tool resolved to an absolute store path
(`SENTINEL_*_BIN`) so neither `$PATH` nor sudo's `secure_path` can miss it.

## Verifying it

The `commit` test boots the appliance with **no network**, edits the hostname +
a firewall rule + a live interface address as the admin user, and asserts the
changes apply live and (with `save`) persist:

```shell
nix build .#checks.x86_64-linux.commit -L
```

See [Configuring the appliance](../operations/configure.md) for the operator
walkthrough.
