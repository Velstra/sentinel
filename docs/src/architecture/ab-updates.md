# A/B update slots

The image carries **two store slots** so an OS update is written to the inactive
one and activated by switching the bootloader — with automatic rollback if the
new slot won't boot cleanly.

## Partition layout

Six partitions, with `data` last so it can grow to fill the disk:

```
1 = ESP                 (signed systemd-boot + UKIs + key payloads)
2 = store-verity-A      ┐ slot A: built + verity-typed at image time
3 = store-A             ┘
4 = store-verity-B      ┐ slot B: reserved space, generic type
5 = store-B             ┘ (sentinel update fills + re-types it)
6 = data                (persistent /var/lib/sentinel)
```

At build time only slot A is populated and typed with the verity GPT GUIDs; slot
B is reserved `linux-generic` so the build's root-hash extraction matches **only**
slot A. `sentinel update` fills slot B and re-types it to the verity GUIDs (which
the running system exposes in `/etc/sentinel/slot-types.env`).

## Boot counting (automatic boot assessment)

Boot is **systemd-boot**, baked offline into the ESP (it can't be
`bootctl install`ed inside a repart build):

- `${pkgs.systemd}/lib/.../systemd-boot.efi` → `/EFI/BOOT/BOOTX64.EFI`
- `/loader/loader.conf` with `default sentinel-a*`
- the slot UKI at `/EFI/Linux/sentinel-a+3.efi`

The `+3` is the **try counter**: `boot.uki.tries = 3` names the UKI with three
remaining tries. Three upstream systemd units make a clean boot get **blessed**
(the counter stripped, so it becomes permanent):

```nix
systemd.additionalUpstreamSystemUnits = [
  "boot-complete.target"
  "systemd-bless-boot.service"
  "systemd-boot-check-no-failures.service"
];
```

`check-no-failures` gates the bless on there being no failed units. If a freshly
updated slot fails to come up cleanly three times, systemd-boot counts it down to
`+0`, marks it bad, and **falls back to the other slot** — automatic rollback.
This bless mechanism is verified live (`Marked boot as 'good'`) in the
`verified-boot` test.

## What `sentinel update` does

`sentinel update <image|device> --commit` (in `src/install.rs::update`):

1. detect the **active** slot via `/dev/mapper/usr`;
2. `dd` the new image's store + verity into the **inactive** slot;
3. `sgdisk --typecode` re-type that slot to the usr / usr-verity GUIDs;
4. copy the new UKI to `/EFI/Linux/sentinel-<inactive>+3.efi`;
5. rewrite `loader.conf` `default` to the slot it just wrote.

The running ESP is auto-mounted at `/boot` (systemd-gpt-auto, read-only); the
updater remounts it read-write in place rather than re-mounting the device.

## Verifying it

The `update` test verifies this **structurally** (slot B written + re-typed,
bootloader switched). The actual cross-reboot slot switch is *not* auto-tested —
`machine.reboot()` of an OVMF image hangs in the nixosTest harness — but the
bless/rollback mechanism is proven separately in `verified-boot`.

```shell
nix build .#checks.x86_64-linux.update -L
```

Operator-facing walkthrough: [Updating (A/B + rollback)](../operations/update.md).
