# Secure Boot

Sentinel's development image signs systemd-boot and its Unified Kernel Image
(UKI) and carries PK/KEK/db enrollment payloads. Firmware must actually enroll
and enforce the intended trust before those signatures protect boot.

**The public build's default keys are demonstration keys generated in a Nix
derivation. Their private halves are readable in the Nix store. They are not a
production root of trust, and the image must not be advertised as one.**

## Development build

The shared image builder in `nix/appliance-image.nix`, selected by
`nix/image.nix`, generates demo PK/KEK/db material, signs systemd-boot and places
enrollment payloads under `/loader/keys/sentinel/`. The final signing derivation
signs the roothash-bearing UKI in the completed ESP. `sentinel-image` and the
installer ISO consume that signed artifact.

UKI signing preserves its embedded dm-verity root hash and kernel command line.
Boot counting renames the UKI entry; it does not replace the signed bytes. See
[verified boot](verified-boot.md) and [A/B slots](ab-updates.md).

## Production boundary

`system.build.sentinelSbKeys` exposes the demonstration material; it is not a
safe external-key provisioning API. The public module does not yet provide a
complete supported production-key input/custody/rotation workflow. Do not fix
that by copying a real PK, KEK or db private key into the repository, a Nix
source path, a derivation or the resulting image.

A production workflow must sign outside the world-readable store, protect the
private keys, ship only public enrollment material and signed artifacts, and
test key rotation, revocation and recovery. Secure Boot identities and OTA
manifest-signing identities have different purposes; one does not substitute
for the other. The exact trust configuration and signed image need their own
acceptance evidence before release.

Do not enroll development keys on a production appliance or replace existing
firmware trust without a recovery plan.

## Verify test enforcement

```sh
nix build .#checks.x86_64-linux.secureboot -L
```

This check uses OVMF with the **test** PK/KEK/db enrolled and checks that the
signed image boots under enforcement. It proves that test chain, not production
key custody or every firmware implementation. Inspect the guest's
`bootctl status` and kernel log for enforcement; a signed file alone does not
prove Secure Boot is enabled.

For counted failures, actual reboot and rollback behavior, run the separate
[boot/fallback checks](../reference/tests.md#run-a-real-vm-check).
