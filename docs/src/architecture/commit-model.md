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

## What each change actually does

| Setting | Mechanism on `commit` |
|---|---|
| Firewall rules / zones | `sentinel compile` → `/run/sentinel/velstra.toml` → `systemctl reload-or-restart velstra.service` |
| Hostname | `hostname <name>` (plain `sethostname(2)`) — **not** `hostnamectl` (NixOS blocks it) |
| Interface address | write `/run/systemd/network/10-sentinel-<iface>.network` → `networkctl reload`/`reconfigure` |

All of these touch only **running services** and the one persistent config
partition. The OS image is fixed.

> **Why `hostname`, not `hostnamectl`.** NixOS rejects `hostnamectl set-hostname`
> ("Changing system settings via systemd is not supported on NixOS"). The plain
> `hostname` command sets the live kernel hostname; `sentinel-boot.service`
> re-applies it from the saved config each boot, so it persists.

## How it persists across reboot

`sentinel-boot.service` (oneshot, ordered before `velstra.service`) runs on every
boot:

1. seed `/var/lib/sentinel/appliance.toml` from the factory default on first boot;
2. run `sentinel apply-boot` — set the hostname and compile the active config
   (the runtime file if present, else the factory default) into
   `/run/sentinel/velstra.toml`.

So a `commit save` writes the durable file, and the boot service re-asserts it
every boot — no generation, no rebuild.

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
