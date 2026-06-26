# Verified boot (dm-verity)

The Nix store ships on a **dm-verity-protected** partition whose root hash is
baked into the Unified Kernel Image (UKI). The kernel mounts `/nix/store` only if
the partition's contents hash to that exact root hash — any tampering with the
store is detected at block level and refuses to mount.

## How it's assembled

`nix/image.nix` imports NixOS' `image/repart.nix` and enables the
`verityStore` module. The build is two-stage:

1. build the erofs store + its dm-verity hash tree, compute the **root hash**;
2. bake that root hash into the UKI, and inject the UKI into the ESP.

The shipped artifact is `system.build.finalImage` (the two-stage verity build) —
**not** `system.build.image`, which is the unsealed single-pass variant with no
bootloader. (Newer nixpkgs renames `finalImage` → `image`; on the pinned 25.05 it
is `finalImage`.) The Secure-Boot wrapper `finalImageSigned` is built on top of
it — see [Secure Boot](secure-boot.md).

## The filesystem layout at runtime

- **`/`** is a volatile `tmpfs` (`mode=0755`) — nothing on the root path
  survives a reboot.
- **`/nix/store`** is a bind from `/usr/nix/store` (the verity-protected `/usr`).
  The pinned verityStore module does **not** set this bind itself, so the image
  config does — without it the initrd's `find-nixos-closure` can't see the store
  and drops to emergency mode.
- **`/var/lib/sentinel`** is the ext4 `data` partition (addressed by
  `LABEL=data`), the one writable, persistent partition.

## Gotchas that cost real debugging

These are pinned-nixpkgs-25.05 specifics worth keeping in mind if you touch
`nix/image.nix`:

- **Minimize'd partitions collapse to 4K.** The verity store + hash partitions
  are `Minimize`-marked; with auto image-sizing they shrink to 4K. Set explicit
  `repartConfig.SizeMinBytes` floors (store ≈ 1300M, store-verity ≈ 96M).
- **`image.repart.imageSize` doesn't exist** in 25.05 (added later) — size via
  `SizeMinBytes` on partitions instead.
- **Sector size 512.** OVMF/UEFI needs 512-byte sectors, not repart's default
  4096 — set `image.repart.sectorSize = 512`.
- **`/usr/bin/env` activation step** is skipped (`system.activationScripts
  .usrbinenv = ""`) because `/usr` is read-only — the nixpkgs verity-appliance
  pattern.

## Verifying it boots

The `verified-boot` test boots the **real** image in QEMU/OVMF and asserts it
reaches multi-user with the verity store mounted (and that a clean boot is
"blessed" — see [A/B updates](ab-updates.md)):

```shell
nix build .#checks.x86_64-linux.verified-boot -L
```
