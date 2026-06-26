> **⚠️ Historical design note — superseded.**
> This describes an earlier design that mixed NixOS *generations/rollback* into
> the commit path. The implemented appliance uses a **fixed verified-boot image +
> runtime config apply** (no self-rebuild). For the current architecture see
> [The appliance model](../architecture/overview.md). Kept for context only.

# Sentinel OS — architecture

How Velstra Sentinel is built as an **immutable firewall/router appliance OS**.

## Decision: NixOS foundation

Sentinel is built on **NixOS**. The requirements were: SSH access + an admin API
(for a web UI), the ability to install packages, and "if something breaks, reload
and it just works" — i.e. atomic upgrades with **rollback**. That is precisely
the NixOS model:

| Requirement | NixOS |
|---|---|
| SSH (like VyOS) | native |
| install packages | declarative, in config |
| "reload → it works again" | **generations + rollback** (boot a previous generation) |
| immutable feel | read-only `/nix/store`, reproducible |
| admin API for a web UI | Sentinel API daemon on top |
| atomic upgrades | each generation is a complete, bootable closure |

It is "VyOS, but better": declarative, reproducible, rollback-safe — without the
mutable-Debian underbelly. (Talos was considered but rejected: it has *no* SSH
and *no* packages, the opposite of what we want.)

Trade-offs accepted: NixOS images are larger than a Buildroot/mkosi-minimal
image, and *we* (the builders) need some Nix knowledge — but the **end user only
ever sees Sentinel's simple config**, never Nix. Tighter lockdown (Secure Boot
via lanzaboote, dm-verity, impermanence) is available and can be layered in later.

## Layers

```
  Sentinel config  (one simple, declarative TOML/JSON document — the user writes this)
        │
        │  sentinel compiler
        ├─────────────► NixOS configuration  ── nixos-rebuild ──►  generation N  (rollback-able)
        │               (hostname, SSH, packages, services, users)
        │
        └─────────────► velstra-config  ── velstra agent (systemd) ──►  eBPF/XDP data plane
                        (firewall, routing, NAT, overlay)
```

The user authors **one** declarative document. The compiler fans it out into (a)
the NixOS system config and (b) the Velstra data-plane config. Apply = rebuild a
new generation; the data plane reloads its maps without dropping the box.

## Boot & lifecycle

- **Generations + rollback.** Every apply builds a new NixOS generation. The
  bootloader lists them; a bad config is undone by booting the previous one — the
  "reload and it works again" guarantee.
- **Atomic.** A generation is switched in whole or not at all; there is no
  half-applied state.
- **Read-only by construction.** The system closure lives in the read-only
  `/nix/store`; the box is reproduced from config, not mutated in place.

## Access & management

- **SSH** is on (like VyOS) for hands-on administration.
- **Sentinel API** (a daemon, gRPC/REST) is the programmatic surface a future web
  UI drives — and how `sentinel` talks to the box remotely. It speaks the Velstra
  control protocol ([`velstra-proto`](https://crates.io/crates/velstra-proto)) to
  the data plane.
- **The CLI is the same tool** locally and remotely; the box is always driven by
  the declarative config, never by editing live state.

## Security

- Read-only `/nix/store`; nothing mutable on the system path.
- Minimal surface: only our daemons listen; no package manager exposed at runtime.
- seccomp/landlock on the daemons; `eBPF` data plane runs with the narrow caps it
  needs.
- *Roadmap:* Secure Boot (signed UKI via lanzaboote), `dm-verity`, measured boot
  (TPM), and `impermanence` (wipe-on-boot `/`) for a Talos-grade lockdown when
  wanted — without giving up SSH.

## Build & distribution

- A **Nix flake** packages `sentinel` and defines the appliance
  `nixosConfiguration`(s).
- Images via `nixos-rebuild build-vm` (a throwaway QEMU box to try it) or
  `nixos-generators` (ISO / qcow2 / raw for bare metal & cloud).
- Updates: ship a new generation (pull the flake, rebuild) — rollback is always
  one boot away.

## Config ergonomics (roadmap)

Easy to write **and** easy to understand at scale:

- **TOML** primary, with **JSON ⇄ TOML** convert (done: `sentinel config
  convert`) for editors / the web UI.
- **Modules/includes** so a large config splits into readable files.
- **`config show` as a tree** (zones → interfaces → rules) + **queries** (e.g.
  "all rules touching WAN") so a big config is comprehensible, not a flat dump.
- **`config fmt`** canonical formatter and **`config explain <field>`** in-CLI
  docs.
- A **JSON Schema** export for editor autocomplete/validation.
- Strong, line-accurate validation errors (started).

## Next slices

1. **The compiler** — Sentinel config → `velstra-config` (firewall/routing) — via
   a git dependency on the Velstra Fabric crates (they are not on crates.io yet,
   blocked on a git-`aya` release; Sentinel is `publish = false`, so a git dep is
   fine).
2. **The NixOS flake** — package `sentinel`, an appliance `nixosConfiguration`
   with SSH + the velstra agent as a systemd service, buildable to a VM.
3. **The Sentinel API daemon** — the surface for the web UI.
