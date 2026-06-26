# Building the installer ISO

A live-boot USB/ISO that carries the appliance image and runs the installer.

```shell
nix build .#sentinel-iso
ls -lh result/iso/velstra-sentinel-installer.iso
```

Write it to a USB stick and boot it:

```shell
# DESTROYS the target stick. Pick the right device!
sudo dd if=result/iso/velstra-sentinel-installer.iso of=/dev/sdX bs=4M conv=fsync status=progress
```

## What it does

The ISO is a hybrid EFI/USB live image (~900 MB). On boot it:

1. comes up as a minimal live NixOS,
2. **bundles the signed appliance image** (`.#sentinel-image`) inside it, exposed
   to the installer via `$SENTINEL_INSTALL_SOURCE`, and
3. **autostarts `sentinel install` on tty1** — the interactive wizard where you
   pick single-disk vs RAID (0/1/10) and choose the target disks by number.

So the operator boots the stick, answers a couple of prompts, confirms, and the
appliance is laid down on the chosen disks. See
[Installing to disk](../operations/install.md) for the wizard walkthrough.

## How it's wired (flake)

`nix/iso.nix` is a NixOS module fed two things via `specialArgs` from the flake:

- `sentinelPkg` — the `sentinel` CLI, and
- `sentinelImageRaw` — the raw path of the **signed** image
  (`finalImageSigned/${config.image.filePath}`), bundled into the live system.

Because `sentinelImageRaw` points at the signed image, the ISO always installs a
Secure-Boot-ready appliance — the same artifact `.#sentinel-image` produces.

## Verifying the ISO actually installs

The `install-iso` test boots the ISO, runs a non-interactive install from the
bundled image onto a blank disk, and asserts the result is a bootable ESP:

```shell
nix build .#checks.x86_64-linux.install-iso -L
```

(The test passes targets explicitly and reads from `$SENTINEL_INSTALL_SOURCE`
rather than driving the tty wizard, which would block on stdin.)
