# Building images

This is the short version: **one command builds the flashable, Secure-Boot-signed
appliance disk image.**

```shell
nix build .#sentinel-image
```

The result symlink points at a store directory containing the raw image:

```shell
ls -lh result/
# the raw disk image — its exact filename is config.image.filePath:
nix eval --raw .#nixosConfigurations.sentinel-image.config.image.filePath
# -> velstra-sentinel.raw  (a GPT raw image you can dd/flash)
```

> **`fabric` must be present and committed first.** The image embeds the
> `velstra` agent built from the Fabric checkout — see
> [Prerequisites](prerequisites.md). Building the image with no `fabric` at the
> pinned path will fail at evaluation.

## What you get

`.#sentinel-image` is the `system.build.finalImageSigned` derivation: the
dm-verity verified-boot image **with its UKI signed for Secure Boot in place**.
It is a GPT raw image with six partitions:

| # | Partition | Purpose |
|---|---|---|
| 1 | `esp` (vfat) | signed systemd-boot + the slot-A UKI + PK/KEK/db enrollment payloads |
| 2 | `store-verity-a` | dm-verity hash tree for slot A |
| 3 | `store-a` (erofs) | the Nix store for slot A (read-only, integrity-checked) |
| 4 | `store-verity-b` | reserved for [A/B updates](../architecture/ab-updates.md) |
| 5 | `store-b` | reserved for A/B updates |
| 6 | `data` (ext4, label `data`) | the one persistent, writable partition (`/var/lib/sentinel`) |

Root is a volatile `tmpfs`; only partition 6 survives a reboot. The store's
verity root hash is sealed into the UKI, so the kernel mounts `/nix/store` only
if it matches. See [Verified boot](../architecture/verified-boot.md) and
[Secure Boot](../architecture/secure-boot.md) for the why and how.

## Writing the image to disk

Two ways, depending on whether you want a clean factory layout or to drive the
guided installer:

### Direct flash (single disk, simplest)

```shell
# DESTROYS the target disk. Pick the right device!
sudo dd if=result/velstra-sentinel.raw of=/dev/sdX bs=4M conv=fsync status=progress
```

The image's `data` partition is small as built; it is grown / re-created on first
boot or by the installer. For RAID, multi-disk, or interactive device selection,
use the installer instead.

### Guided installer (single / RAID, interactive)

Boot the [installer ISO](iso.md) (or run `sentinel install` from a booted
appliance) and pick disks + RAID level interactively. See
[Installing to disk](../operations/install.md) for the full flow. The installer
clones the sealed ESP + verity + store partitions block-for-block and lays down
the `data` partition (or an `mdadm` array) for you.

## Trying it in a VM first

You don't need to flash anything to see it boot. The fastest throwaway VM is the
appliance config (no verity, boots straight to a shell). The easiest way — works
on **any** host, no `result` symlink to juggle:

```shell
nix run .#vm
```

> **On a non-NixOS host** (Arch/CachyOS/Debian/macOS, …) there is **no
> `nixos-rebuild` command** — it only exists on NixOS. `nix run .#vm` is the
> portable replacement for `nixos-rebuild build-vm`. If you'd rather have the
> runner script on disk:
>
> ```shell
> nix build .#nixosConfigurations.appliance.config.system.build.vm
> ./result/bin/run-sentinel-fw-vm
> ```
>
> The runner is `run-<hostname>-vm`, where the hostname comes from
> `[system] hostname` in `example-appliance.toml` (default `sentinel-fw`). Pass
> `-m 2048` etc. via `QEMU_OPTS` if you need more RAM.

> **`.#sentinel-image` is *not* a VM runner.** It builds a raw **disk image**
> (the flashable artifact) — its `result/` has the `.raw` file, **no**
> `bin/run-*-vm`. To boot *that* exact verity/Secure-Boot image in QEMU/OVMF the
> way hardware does, run the `verified-boot` check below; it spins up QEMU for
> you.

To boot the **real verified-boot image** in QEMU/OVMF exactly as the hardware
would, the `verified-boot` test does precisely that — see
[Test suite](../reference/tests.md). It is the highest-fidelity "did the image
actually boot?" check:

```shell
nix build .#checks.x86_64-linux.verified-boot -L
```

## Build cost & caching

The expensive part — the **eBPF object** (`velstra-ebpf`) — is a hash-pinned
fixed-output derivation, so it is **cached and never rebuilt** unless the Fabric
source changes. A repeat image build after a CLI-only change re-runs only the
small derivations (the `sentinel` wrapper, the repart assembly, the post-build
signing). The first ever build compiles the nightly toolchain + eBPF and takes a
while; budget accordingly.

## Where to next

- [Building the installer ISO](iso.md) — wrap this image in a live USB installer.
- [A/B update slots](../architecture/ab-updates.md) — how slot B and
  `sentinel update` work.
- [Flake outputs](../reference/flake-outputs.md) — every buildable attribute.
