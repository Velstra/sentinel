# Installing to disk

`sentinel install` lays the appliance down on real disks — single disk or a RAID
array — either interactively or flag-driven.

## Interactive (the ISO default)

Boot the [installer ISO](../building/iso.md). It autostarts the wizard on tty1:

1. **Pick a layout** — single disk, RAID0 (stripe), RAID1 (mirror), or RAID10.
2. **Pick the disks** by number from the discovered list.
3. **Confirm** — the wizard prints the plan and waits for a yes before touching
   anything.

Disk discovery reads `lsblk -dnb -o NAME,SIZE,TYPE,RM,MODEL` and skips
`zram`/`md`/`dm` devices, so only real target disks are offered.

## Flag-driven (scripted / non-interactive)

```shell
# single disk
sentinel install /dev/sda --commit

# RAID1 mirror across two disks
sentinel install /dev/sda /dev/sdb --raid mirror --commit

# install from a specific image instead of the booted/bundled source
sentinel install /dev/sda --source /path/to/velstra-sentinel.raw --commit
```

- `--raid <none|stripe|mirror|mirror10>` chooses the layout.
- `--commit` is required to actually write; without it the plan is printed only.
- `--source <file|device>` installs from a given raw image (a file via a loop
  device, or a block device); on the ISO this defaults to
  `$SENTINEL_INSTALL_SOURCE` (the bundled image).

## What it writes

For each target the installer:

1. `sgdisk --replicate=<dest> <src>` clones the GPT from the source image;
2. `dd` clones the **sealed** ESP + UKI, dm-verity hash, and store partitions
   block-for-block (partitions 1–3);
3. recreates the `data` partition (#6), as plain ext4 (`LABEL=data`) for a single
   disk or as an `mdadm` array for RAID.

Because `/var/lib/sentinel` is mounted by `LABEL=data`, the same image boots
correctly whether `data` is a partition or a RAID array.

## Verifying it

Two tests cover this:

```shell
nix build .#checks.x86_64-linux.install -L       # single + RAID1 on blank disks
nix build .#checks.x86_64-linux.install-iso -L   # live-boot install from the ISO's bundled image
```

## Gotchas (for hacking on `src/install.rs`)

- `lsblk -s` draws tree characters (`└─`); the installer uses `-r` (raw) and
  filters `TYPE=disk`.
- `sgdisk --replicate=<DEST> <SOURCE>` — the **dest** is the option value;
  getting it backwards corrupts the source.
- The appliance `$PATH` has no `sgdisk`/`mdadm` (only sentinel's wrapper does);
  tests assert via `lsblk`/`blkid`, not those tools directly.
