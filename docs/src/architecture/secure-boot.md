# Verify the UEFI boot chain

<a id="secure-boot"></a>

Sentinel signs systemd-boot and the unified kernel image at image-build time. Firmware enrollment determines which signer the machine trusts.

<a id="verifying-enforcement"></a>

## Inspect firmware enforcement

```sh
bootctl status
```

Look for the Secure Boot state. Use a signed appliance image and firmware with the intended keys enrolled. A signed file alone cannot prove the firmware enforced a signature.

<a id="why-build-time-sbsign-not-lanzaboote"></a><a id="what-gets-signed-and-how"></a><a id="why-the-uki-is-signed-after-the-build"></a><a id="the-keys-are-demo-keys--override-them-for-production"></a>

## Choose the signing identity

Public source builds generate development PK, KEK and db material for reproducible test procedures. For a production trust chain, supply your own signing material and an enrollment and recovery plan. The ESP carries enrollment payloads under `/loader/keys/sentinel/`. Preserve firmware recovery access before changing enrolled keys.

## Exercise the signed image

```sh
nix build .#checks.x86_64-linux.secureboot -L
```

This fixture enrolls the test keys in OVMF and boots the signed image with enforcement. [Verify the store](verified-boot.md).
