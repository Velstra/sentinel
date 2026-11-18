# Flake outputs

The flake targets `x86_64-linux`. Query the checked-out source rather than
relying on a frozen output or test count:

```sh
nix flake show
nix eval --json .#packages.x86_64-linux --apply builtins.attrNames
nix eval --json .#checks.x86_64-linux --apply builtins.attrNames
```

## Packages

Build with `nix build .#<name>`:

| Name | Output |
| --- | --- |
| `sentinel` / `default` | Management CLI with wrapped tool paths. |
| `sentinel-ui` | Locally bundled console assets; no runtime CDN. |
| `velstra` | Fabric data-plane agent. |
| `velstra-ebpf` | Fixed-output eBPF object. Keep its hash and Fabric source coherent. |
| `wren` | Routing daemon. |
| `sentinel-image` | Signed development raw GPT image with dm-verity and A/B slots. Included Secure Boot keys are not production trust. |
| `sentinel-iso` | Installer ISO containing that raw image. |
| `qemu-firmware` | OVMF firmware for the [VM quickstart](../operations/quickstart.md). |

`sentinel-image` is a disk artifact, **not** a VM runner. This public package
set does not expose an Enterprise certificate, a prebuilt QCOW2 or a production
sysupdate bundle merely because related machinery exists elsewhere.

## VM app and NixOS configurations

```sh
nix run .#vm
```

The `vm` app starts a disposable appliance configuration. It does not boot the
exact verified-boot disk image. To test that image use the relevant
[image checks](tests.md#run-a-real-vm-check).

| Configuration | Purpose |
| --- | --- |
| `nixosConfigurations.appliance` | Base appliance and VM runner. |
| `nixosConfigurations.sentinel-image` | Immutable disk-image configuration. |
| `nixosConfigurations.sentinel-iso` | Installer ISO configuration. |

Useful queries:

```sh
nix eval --raw .#nixosConfigurations.sentinel-image.config.image.filePath
nix path-info .#sentinel-image
```

## Modules

| Attribute | Purpose |
| --- | --- |
| `nixosModules.sentinel` | Sentinel CLI, appliance services and factory configuration. |
| `nixosModules.applianceImage` | Shared immutable image builder. |
| `nixosModules.applianceIso` | Shared installer ISO builder. |

Module availability is not qualification of every downstream combination.
Review [signing limitations](../architecture/secure-boot.md) before distributing
an image and [test evidence](tests.md) before interpreting a green evaluation.
