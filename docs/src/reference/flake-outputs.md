# Choose a flake output

<a id="flake-outputs"></a>

Build from an x86-64 Linux checkout. The command determines whether you get an executable, boot media or a VM test.

<a id="packages--nix-build-name"></a>

## Packages

| Goal | Output |
|---|---|
| Run the CLI | `nix build .#sentinel` |
| Build the immutable disk image | `nix build .#sentinel-image` |
| Build installation media | `nix build .#sentinel-iso` |
| Obtain OVMF for a UEFI VM | `nix build .#qemu-firmware` |
| Build the web frontend | `nix build .#sentinel-ui` |
| Build Fabric, the eBPF object or Wren | `.#velstra`, `.#velstra-ebpf`, `.#wren` |

<a id="nixos-configurations--nixosconfigurationsname"></a><a id="apps--nix-run-name"></a><a id="modules"></a><a id="useful-eval-queries"></a>

## Run a VM or inspect outputs

```sh
nix run .#vm
# From the build host, list the outputs of your checkout:
nix flake show --no-write-lock-file
```

The VM app boots a development appliance. A disk image is a package and does not contain a VM launcher. The NixOS configurations and modules are listed separately by the flake.

<a id="checks--nix-build-checksx86_64-linuxname--l"></a>

## Select a check

```sh
nix build .#checks.x86_64-linux.quickstart -L
```

Use the [test catalog](tests.md) to select an image, protocol, management or recovery test. VM checks require KVM.

## Evidence boundaries

Query the current attributes instead of relying on a frozen package or test count:

```sh
nix eval --json .#packages.x86_64-linux --apply builtins.attrNames
nix eval --json .#checks.x86_64-linux --apply builtins.attrNames
```

Public image builds use development signing identities. A public package or module is not an Enterprise QCOW2/sysupdate certification. The `vm` application is a development VM, not necessarily a boot of the exact release disk. Evaluate, build and boot-test the intended artifact and dependency cohort separately.
