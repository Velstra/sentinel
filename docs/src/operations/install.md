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

## Disk encryption (LUKS2)

The A/B root is dm-verity and read-only — it has integrity, and nothing on it is
secret. Every secret the box holds lives on the ONE writable partition: the TLS
key and certificate, config-sync pins and tokens, per-account password hashes,
WireGuard/IPsec keys. `--encrypt` protects that partition at rest with LUKS2:

```shell
# passphrase prompted (twice, to confirm)
sentinel install /dev/sda --encrypt --commit

# or supply it non-interactively (scripted installs)
SENTINEL_LUKS_PASSPHRASE='…' sentinel install /dev/sda --encrypt --commit
```

The `data` partition becomes a LUKS2 container; the ext4 (`LABEL=data`) is created
**inside** it. RAID composes as expected — the array is assembled first, then
encrypted. The passphrase is resolved and checked **before** any disk is erased,
so a mistyped or missing one fails while the target is still intact.

### Unlocking at boot

An encrypted box asks for its passphrase at each boot, before mounting
`/var/lib/sentinel`. `sentinel-unlock.service` runs `sentinel unlock`, which
prompts via `systemd-ask-password` (answerable at the console or by a remote
`systemd-tty-ask-password-agent`) and opens the volume as `/dev/mapper/data`.

The service is **conditional and shipped in every image**: on a plaintext box it
finds no LUKS volume and does nothing, so the ordinary `LABEL=data` mount takes
over. The `/var/lib/sentinel` mount takes an
`x-systemd.requires=sentinel-unlock.service` dependency, so on an encrypted box it
waits for the unlock and on a plaintext box the no-op just succeeds.

> **TPM2 unattended unlock is a documented follow-up, not yet wired.** The on-disk
> format is standard LUKS2, so a TPM2 token (`systemd-cryptenroll`) can be enrolled
> onto the same volume later without reformatting — an unattended box would then
> reboot without a console passphrase. Today, encrypted means a passphrase at boot.

## Verifying it

Three tests cover this:

```shell
nix build .#checks.x86_64-linux.install -L       # single + RAID1 on blank disks
nix build .#checks.x86_64-linux.install-iso -L   # live-boot install from the ISO's bundled image
nix build .#checks.x86_64-linux.luks -L          # encrypted install: LUKS2 container, passphrase unlock, secrets inside
```

## Gotchas (for hacking on `src/install.rs`)

- `lsblk -s` draws tree characters (`└─`); the installer uses `-r` (raw) and
  filters `TYPE=disk`.
- `sgdisk --replicate=<DEST> <SOURCE>` — the **dest** is the option value;
  getting it backwards corrupts the source.
- The appliance `$PATH` has no `sgdisk`/`mdadm` (only sentinel's wrapper does);
  tests assert via `lsblk`/`blkid`, not those tools directly.
