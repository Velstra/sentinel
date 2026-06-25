# The commit model — how `commit` activates config on an immutable appliance

This is the design for making `sentinel configure` → `commit` actually change
the running box, on a NixOS-based **immutable** appliance.

## The problem

On VyOS (mutable), `commit` mutates live system state in place. Sentinel is
immutable: the running OS is a NixOS **generation** built from the flake. The
hostname, interface addresses, SSH, and the firewall all come from that
generation. So writing `appliance.toml` and reloading a file does **not** change
the system — that is exactly why a `commit`+`save` left the old hostname in
place.

Two kinds of settings, two natural activation paths:

| Setting | Owned by | Can change at runtime? |
|---|---|---|
| Firewall rules / zones | the velstra agent (eBPF maps) | **yes** — the agent live-reloads maps |
| Hostname, interface IPs, SSH, packages | NixOS (the generation) | **no** — needs a new generation |

## Decision: rebuild-on-commit (one model for everything)

`commit` builds a **new NixOS generation** from the edited config and switches to
it atomically. This is the "better than VyOS" property: an atomic switch with
**rollback** — a bad config is one reboot (or one `nixos-rebuild switch
--rollback`) away from the previous working generation. The firewall comes along
for free because the velstra service in the new generation loads the recompiled
config.

We do **not** split runtime-vs-rebuild (the rejected "firewall live, OS via
rebuild" option): one mechanism is simpler to reason about, and the atomicity +
rollback guarantee is the whole point. (A future optimization may *additionally*
hot-reload just the firewall for speed, but the source of truth stays the
generation.)

## How it works

### 1. The flake + config live on the box

The appliance image includes:
- the Sentinel **flake source** (pinned, read-only) at a known path, e.g.
  `/etc/sentinel/flake` (a copy of this repo's flake + its `flake.lock`), and
- the **active appliance config** at a writable, persistent path, e.g.
  `/var/lib/sentinel/appliance.toml`.

The flake's `appliance` nixosConfiguration reads the appliance config from that
writable path (not a baked-in file), so a rebuild picks up edits. The config
path is on persistent storage (survives reboots); everything else stays
read-only.

### 2. `commit` = validate → write → rebuild → switch

```
sentinel commit
  1. materialize + validate the candidate           (already implemented)
  2. write it atomically to /var/lib/sentinel/appliance.toml
  3. nixos-rebuild switch --flake /etc/sentinel/flake#appliance
     (or `nixos-rebuild build` then `switch-to-configuration switch`)
  4. on success: the new generation is active (hostname, IPs, firewall)
     on failure: nothing switched; the candidate is rejected with the build error
```

Because nixos-rebuild is itself atomic (it builds fully, then switches), a failed
build never half-applies. The previous generation remains the boot default until
the switch succeeds.

### 3. `save` vs `commit`

- `commit` — validate + activate (build + switch a new generation).
- `save` — just persist the appliance config file without rebuilding (the
  "write it down but don't apply yet" escape hatch; the next `commit`/reboot
  picks it up).

This matches the VyOS `commit`/`save` split in spirit: `commit` makes it live,
`save` makes it durable. On an immutable box "live" means "a new generation".

### 4. Rollback UX

- `sentinel rollback` → `nixos-rebuild switch --rollback` (previous generation).
- `sentinel generations` → list generations (wraps `nix-env --list-generations`
  / the bootloader entries) so an operator can see and pick one.
- The bootloader also lists generations, so even a box that won't boot the new
  config recovers by selecting the previous entry — no reflash.

## Speed — a commit does **not** reboot the box

A rebuild-on-commit sounds heavy, but on NixOS it isn't a reboot and it isn't a
full rebuild:

- **No reboot.** `nixos-rebuild switch` runs `switch-to-configuration switch`,
  which activates the new generation **live**: it sets the hostname, re-applies
  network/etc, and restarts **only the systemd units that actually changed**.
  Your SSH session survives. The *only* thing that needs a reboot is a new
  **kernel/initrd** — and even then everything else is applied immediately; you
  reboot later, at your convenience, just to pick up the kernel.

- **Only what changed restarts.** Change a firewall rule → only the `velstra`
  service restarts (~1s). Change the hostname → hostname is set + a couple of
  units refresh. Nothing else is touched.

- **Incremental, cached build.** Nix only rebuilds the derivations that changed.
  The expensive part — the **eBPF object** — is a hash-pinned fixed-output
  derivation, so it is **cached and never rebuilt** for a config change. A commit
  rebuilds only the tiny compiled `velstra.toml` (a `sentinel compile`, ms) and
  the system closure (mostly symlinks, seconds). Typical commit: **~5–15 s**, not
  a reboot.

### Optional firewall fast-path (sub-second)

For *firewall-only* changes we can go faster still, because the velstra agent
already live-reloads its eBPF maps without dropping the data plane. A commit can:

1. Always build + record the new generation (so rollback still works), **and**
2. If only the firewall changed (zones/rules, no OS-level diff), additionally do
   an immediate `sentinel apply`-style reload of the agent — sub-second — instead
   of waiting on the unit restart.

The generation stays the source of truth (rollback intact); the fast-path is a
latency optimization layered on top. OS-level changes (hostname, IPs, SSH) always
go through the normal `switch`, which is still no-reboot.

### Summary

| Change | What happens | Reboot? | Rough time |
|---|---|---|---|
| Firewall rule | velstra reload (fast-path) or unit restart | no | <1 s – few s |
| Hostname / IP / SSH | `switch` re-applies + restarts changed units | no | ~5–15 s |
| New kernel | applied on next reboot (rest applies live) | yes (deferred) | reboot |

## Security

- `commit`/`rollback` need root (they switch the system). The CLI runs them via
  the appliance's privilege model (sudo/polkit for the admin user, or a small
  setuid helper / a privileged `sentineld` the CLI talks to).
- The flake source is **read-only** and pinned (`flake.lock`), so a rebuild is
  reproducible and can't pull arbitrary upstream changes at commit time.
- Only `/var/lib/sentinel/appliance.toml` is writable input; its schema is
  validated before any rebuild, so a malformed config fails fast, before nix runs.

## Implementation steps (later)

1. **Image plumbing**: ship the flake source to `/etc/sentinel/flake`; make the
   `appliance` config read `/var/lib/sentinel/appliance.toml`; mark that path
   persistent.
2. **`commit`**: after validate, write the config and shell out to
   `nixos-rebuild switch --flake /etc/sentinel/flake#appliance`; surface build
   output; non-zero exit ⇒ commit fails, candidate kept.
3. **`rollback` / `generations`** subcommands wrapping nixos-rebuild / the
   bootloader.
4. **Privilege path** for the rebuild (sudo rule or `sentineld`).
5. **Dev/test**: a `--dry-run` that runs `nixos-rebuild build` (no switch) so
   commit can be validated off-box / in CI.

Until this lands, `commit` validates + activates **in-session only** and `save`
writes the file; nothing touches the running generation. The CLI says so, to set
expectations.
