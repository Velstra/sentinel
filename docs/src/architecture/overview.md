# The appliance model

Sentinel uses **NixOS as a reproducible image builder**, in immutable-image mode
with verified boot — and applies configuration to the **running** system at
runtime, not by rebuilding the OS.

## Why image + runtime-apply (and not self-rebuild)

eBPF/XDP is a Linux-kernel technology, so "custom OS" can only mean "custom
minimal Linux". The hard question was *what happens on `commit`*. A full
airgapped **self-rebuild-from-source** of a NixOS system turned out to be
impractical: nixpkgs packages come pre-built from the binary cache, so their
source FODs are never in the local store, and `system.includeBuildDependencies`
over-reaches trying to fetch them offline.

Every real appliance OS (VyOS, OPNsense, Talos) does the same thing instead:
**fixed image + runtime config apply**. Sentinel follows that. The Velstra eBPF
engine is OS-agnostic, so nothing is locked in.

> The earlier *rebuild-on-commit* design (and its trade-off table) is preserved
> in the [historical design notes](../appendix/design-notes-commit.md) — it was
> investigated and rejected.

## The pieces

```
        ┌────────────────────────────────────────────────┐
        │  ESP (signed systemd-boot + signed UKIs)        │  ← Secure Boot
        ├────────────────────────────────────────────────┤
        │  store-A (erofs) + verity-A   │  store-B + ...  │  ← A/B slots
        │  /nix/store, root hash sealed │  (update target)│  ← dm-verity
        │  into the UKI                 │                 │
        ├────────────────────────────────────────────────┤
        │  data (ext4, label=data) → /var/lib/sentinel    │  ← the only writable
        └────────────────────────────────────────────────┘     persistent state

   root = tmpfs (volatile)        config lives on `data`, applied live by `commit`
```

- **Boot** is systemd-boot, baked offline into the ESP, selecting a slot's UKI.
- **The store** is read-only erofs, integrity-checked by dm-verity against a root
  hash sealed in the UKI.
- **The config** (`/var/lib/sentinel/appliance.toml`) is the one writable input;
  `sentinel-boot.service` seeds it from the factory default on first boot and a
  `commit` applies edits to the running system.

## Lifecycle at a glance

| Action | Mechanism | Reboot? |
|---|---|---|
| Change firewall / hostname / IP | `sentinel commit` → live apply | no |
| Persist config across reboot | `sentinel save` → write `appliance.toml` | no |
| Update the OS image | `sentinel update` → write inactive A/B slot | yes (into new slot) |
| New slot fails to boot | systemd-boot auto-rollback after 3 tries | automatic |

Read on:

- [Verified boot (dm-verity)](verified-boot.md)
- [A/B update slots](ab-updates.md)
- [Secure Boot](secure-boot.md)
- [The commit model (runtime apply)](commit-model.md)
