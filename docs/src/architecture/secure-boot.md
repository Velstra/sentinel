# Secure Boot

The whole boot chain is signed at **image-build time**, and the image ships the
PK/KEK/db enrollment payloads so a firmware in setup mode can be locked down to
trust only Sentinel's keys.

## Why build-time `sbsign`, not lanzaboote

[lanzaboote](https://github.com/nix-community/lanzaboote) is a
`nixos-rebuild`/activation-time tool — it signs during system activation on a
running machine. That is the wrong fit for an **offline repart image** that is
never "activated" on a builder. So Sentinel signs the finished artifacts directly
with `sbsign`. All tooling (`sbsigntool`, `efitools`, `virt-firmware`, `openssl`)
is already in nixpkgs — no extra flake input.

## What gets signed, and how

`nix/image.nix`:

1. **Generates self-signed PK/KEK/db** (`sbKeys`, openssl, build-time cached).
   These are a **demo default** — a real deployment overrides them with the
   operator's own keys so future updates stay signed by a key the firmware trusts.
2. **Signs systemd-boot** (`signedSdBoot`) with the db key and bakes it into the
   ESP at `/EFI/BOOT/BOOTX64.EFI` and `/EFI/systemd/`.
3. **Bakes the enrollment payloads** — PK/KEK/db `.auth` (efitools) — under
   `/loader/keys/sentinel/` so an operator can enroll them from the firmware
   setup screen.
4. **Signs the UKI post-build** via `system.build.finalImageSigned`: a derivation
   that `mtools`-edits the ESP at its byte offset (`sfdisk` finds the ESP start)
   to `sbsign` `sentinel-a+3.efi` **in place**.

### Why the UKI is signed *after* the build

The verityStore rebuilds the UKI with an internal `ukify` call we can't hand a
signing tool to, and `ukify` + `systemd-sbsign` refuse to sign it
(`cannot verify existing PE binaries`). So `finalImageSigned` opens the finished
image and signs the UKI directly with `sbsign`. This is safe because:

- signing **doesn't touch** the embedded verity root hash or kernel cmdline, and
- [boot counting](ab-updates.md) only **renames** the UKI file (`+3` → `+2` …),

so the signature stays valid across both verity checks and boot-count
decrements. `finalImageSigned` is what `.#sentinel-image` and the ISO ship.

## The keys are demo keys — override them for production

`system.build.sentinelSbKeys` exposes the generated keys. They exist so the build
and the test are self-contained; **do not** ship the demo keys to real hardware
as your root of trust. A production build replaces `sbKeys` with the operator's
PK/KEK/db (kept out of the repo — `.gitignore` blocks `*.key`/`*.crt`).

## Verifying enforcement

The `secureboot` test builds an OVMF VARS file with our PK/KEK/db **enrolled**
(`virt-fw-vars`) and boots the **signed** image under enforcing Secure Boot,
asserting it reaches multi-user in a single boot:

```shell
nix build .#checks.x86_64-linux.secureboot -L
# kernel log shows: "EFI stub: UEFI Secure Boot is enabled"
# bootctl status:   "Secure Boot: enabled"
```

It uses pre-enrolled vars and a single boot (no in-test reboot), which sidesteps
the OVMF `machine.reboot()` hang in the harness.
