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
- `/loader/loader.conf` with `preferred sentinel-a*` and `default sentinel-*`
- the slot UKI at `/EFI/Linux/sentinel-a+3.efi`

The `+3` is the **try counter**: `boot.uki.tries = 3` names the UKI with three
remaining tries. `systemd-bless-boot.service` waits for `boot-complete.target`;
successful assessment strips the counter so the entry becomes permanent.
An assessment service must actually be required by that target: merely installing
`systemd-boot-check-no-failures.service` does not enable its generic failed-unit
check. Release images must wire their product-health gate explicitly and report
its scope accurately; blessing is not proof of every hardware or HA property.

On systemd-boot 260 and newer, **`preferred` honors exhausted boot counters but a
hard per-slot `default` does not**; see the upstream
[systemd v260 selection implementation](https://github.com/systemd/systemd/blob/v260/src/boot/boot.c#L1687-L1723).
The broad `default sentinel-*` lets the retained
healthy slot sort ahead of an exhausted candidate. A hard `default sentinel-a*`
can repeatedly select `sentinel-a+0-N.efi`, defeating fallback even though the
counter works. Both factory configuration and every staged update must retain
the preferred-plus-broad-default policy. Fallback also requires a retained,
bootable other slot and a failed-boot reboot/watchdog path.

## What `sentinel update` does

`sentinel update <image|device> --commit` (in `src/install.rs::update_verified`):

1. detect the **active** slot via `/dev/mapper/usr`;
2. open the image once and hash all of it against the signed digest, reading
   its GPT (partition offsets and GUIDs) from the same bytes; nothing is written
   unless it matches;
3. verify the running UEFI bootloader is systemd-boot 260 or newer and that no
   nonempty firmware default/preferred/one-shot override supersedes appliance
   selection, then copy the new image's store + verity into the **inactive** slot from that
   same open file, re-hashing each partition — a source that changed since step
   2 is refused before anything below happens;
4. `sgdisk --typecode` re-type that slot to the usr / usr-verity GUIDs, stamping
   the GUIDs read in step 2;
5. copy the new UKI to `/EFI/Linux/sentinel-<inactive>+3.efi`, from a private
   copy of the image's ESP;
6. migrate all old `default`/`preferred` directives to `preferred
   sentinel-<inactive>*` plus the broad `default sentinel-*` fallback.

Firmware overrides are never silently cleared. An unsupported loader, malformed
EFI value or nonempty override refuses the update before inactive writes. The
error names the relevant `bootctl set-default ''`, `set-preferred ''` or
`set-oneshot ''` operation for explicit operator review. Both signed and
`--allow-unsigned` paths enforce this boot-selection preflight.

`--allow-unsigned` (`src/install.rs::update`) skips signature/digest verification
and `dd`s from the device as given — the trusted re-seal path. It does **not**
skip boot-selection preflight or the active-device refusal checks.

The running ESP is auto-mounted at `/boot` (systemd-gpt-auto, read-only); the
updater remounts it read-write in place rather than re-mounting the device.

## Which image am I running?

`show version` answers it, and it answers with the image's own identity rather
than with a number somebody typed:

```text
image:      3f8a1c92e7b4 (dm-verity /usr, slot sentinel-b)
binaries:   sentinel 1qxk9v2m  wren r7d0k3ap  velstra p2v7yr4c
```

The first field is the **dm-verity root hash** of the running `/usr`, which the
UKI puts on the kernel command line as `usrhash=`. The kernel refuses to mount
the store unless every block under it hashes back to that value, so it changes if
and only if the image changes — two builds can never print the same, and one
build can never print two things. Twelve hex characters is enough to compare over
the phone; `cat /proc/cmdline` has the whole hash.

The second line is the Nix store path hash of each running binary, which is a
hash of that binary's build inputs. It is what identifies a build on a boot with
no verity at all (a VM test, the installer medium), and there `show version` says
plainly that the image itself is unidentified rather than printing something that
looks like an answer.

Version *numbers* are still printed above both, because people read them — they
just cannot tell two builds apart on their own.

## Verifying it

The `update` test verifies slot-writing structure; `verified-boot` verifies
blessing. Neither alone proves automatic fallback of the exact release. A
candidate-bound UEFI/QEMU gate must install a healthy B update, stage a signed
deliberately failing A image, observe three failed assessments and the exhausted
counter, then boot and bless retained B without changing loader settings from
the test controller. Retain image hashes and boot evidence; unit tests of the
selection renderer do not replace this cross-reboot proof.

```shell
nix build .#checks.x86_64-linux.update -L
```

Operator-facing walkthrough: [Updating (A/B + rollback)](../operations/update.md).
