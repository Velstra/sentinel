# Flake outputs

Everything buildable in `flake.nix` (`system = x86_64-linux`).

## Packages — `nix build .#<name>`

| Attribute | What it is |
|---|---|
| `sentinel` (also `default`) | the `sentinel` CLI (stable rustc, wrapped tool paths) |
| `velstra` | the eBPF/XDP data-plane agent (nightly toolchain + Fabric) |
| `velstra-ebpf` | just the compiled eBPF object (fixed-output derivation) |
| `sentinel-image` | the flashable, Secure-Boot-signed verity disk image (`finalImageSigned`) |
| `sentinel-iso` | the live-boot installer ISO bundling the image |

## NixOS configurations — `nixosConfigurations.<name>`

| Attribute | What it is |
|---|---|
| `appliance` | the base appliance (CLI + velstra service). Boot it in a throwaway QEMU VM with **`nix run .#vm`** (portable, no NixOS needed) |

## Apps — `nix run .#<name>`

| App | What it does |
|---|---|
| `vm` | boot the `appliance` config in a throwaway QEMU VM (the easy local-test path; no `result` symlink, no `nixos-rebuild`) |
| `sentinel-image` | `appliance` + `nix/image.nix` → the verity/A-B/Secure-Boot image |
| `sentinel-iso` | `nix/iso.nix` → the installer ISO (gets `sentinelPkg` + `sentinelImageRaw` via `specialArgs`) |

## Modules

| Attribute | What it is |
|---|---|
| `nixosModules.sentinel` | the appliance module: imports `nix/appliance.nix` + `nix/velstra-service.nix`, installs the CLI, wires `services.velstra` and `networking.hostName` from the factory config |

## Checks — `nix build .#checks.x86_64-linux.<name> -L`

| Check | Asserts |
|---|---|
| `commit` | live runtime apply of hostname + firewall + interface address, persistence, airgapped |
| `verified-boot` | the real verity image boots in QEMU/OVMF to multi-user; clean boot blessed |
| `install` | `sentinel install` on blank disks — single + RAID1 |
| `install-iso` | live-boot install from the ISO's bundled image → bootable ESP |
| `update` | A/B: inactive slot written + re-typed, bootloader switched |
| `secureboot` | the signed image boots under **enforcing** Secure Boot (enrolled keys) |

Run them all:

```shell
for c in commit verified-boot install install-iso update secureboot; do
  nix build ".#checks.x86_64-linux.$c" -L || break
done
```

## Useful eval queries

```shell
# exact raw image filename inside result/
nix eval --raw .#nixosConfigurations.sentinel-image.config.image.filePath

# the signed image's full store path
nix eval --raw .#sentinel-image
```
