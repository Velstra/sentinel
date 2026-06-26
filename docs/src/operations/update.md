# Updating (A/B + rollback)

OS updates are **A/B**: a new image is written to the inactive store slot and the
bootloader is switched to it. If the new slot fails to boot cleanly, systemd-boot
rolls back automatically. The architecture is in
[A/B update slots](../architecture/ab-updates.md); this is the operator view.

## Applying an update

```shell
# from a new raw image (built with `nix build .#sentinel-image`)
sentinel update /path/to/velstra-sentinel.raw --commit

# or from a block device / mounted source
sentinel update /dev/sdX --commit
```

What happens:

1. the **active** slot is detected (via `/dev/mapper/usr`);
2. the new image's store + verity are written to the **inactive** slot;
3. that slot is re-typed to the verity GPT GUIDs;
4. the new UKI is installed as `sentinel-<inactive>+3.efi` with **3 boot tries**;
5. `loader.conf` `default` is pointed at the new slot.

Without `--commit`, the plan is printed but nothing is written.

## The rollback guarantee

The new slot boots with `+3` tries. A clean boot (no failed units) is **blessed**
permanent. If it fails three times, systemd-boot marks it bad and boots the
**previous** slot — which is untouched, because the update only ever wrote the
inactive one. So a bad update self-heals without intervention.

To roll back deliberately, point `default` back at the other slot from the
systemd-boot menu (or re-run an update with the known-good image).

## Reboot to activate

Unlike `commit` (which is live and never reboots), an OS image update takes effect
on the **next reboot** into the new slot. Schedule the reboot when convenient; the
running slot keeps serving until then.

## Verifying

```shell
nix build .#checks.x86_64-linux.update -L
```

The test verifies the slot is written, re-typed, and the bootloader switched. The
cross-reboot switch itself isn't auto-tested (OVMF `machine.reboot()` hangs in the
harness); the bless/rollback mechanism is proven in the `verified-boot` test.
