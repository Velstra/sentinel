# Build an appliance image

<a id="building-images"></a>

Use the raw image for a UEFI virtual disk or as input to the installer. Use the ISO when you want disk selection and first-boot setup.

<a id="what-you-get"></a><a id="build-cost--caching"></a>

## Build and locate the image

```sh
nix build .#sentinel-image --out-link result-image
find -L result-image -name '*.raw' -type f
```

The output includes the ESP, a signed kernel image, the verified store, space for the alternate slot, and a writable data partition. Source builds sign with per-build development keys that are not a trust identity: their private keys sit in the builder's world-readable Nix store, so do not enroll them in firmware. The image ships no enrollment payloads for them (`/loader/keys/sentinel/` holds only a README); release images are re-signed outside the store with the release identity. `nix build .#sentinel-image-unsigned` builds the same image before any signature. See [compare the unsigned image](reproducibility.md#compare-the-unsigned-image-not-the-signed-one).

<a id="trying-it-in-a-vm-first"></a>

## Try it in a VM first

For a disposable configuration session use `nix run .#vm`. That target (`nixosConfigurations.appliance`) is a development VM, not an appliance image: it alone logs `admin` in on the console automatically and has the KNOWN password `sentinel`, so never reuse it for a real box. The exported modules (`nixosModules.sentinel`, `nixosModules.applianceImage`) set no password and no autologin, and the flashable image asserts at build time that it has neither. To validate the real image and boot chain, run `nix build .#checks.x86_64-linux.verified-boot -L`. To install a persistent evaluation appliance, follow the [VM quickstart](../operations/quickstart.md).

<a id="seeding-a-cloud-import"></a>

## Seed a raw image for a cloud import

A raw or QCOW2 import has no administrator, no address and no cloud-init: the first boot reads `appliance.toml` and the SSH host key from the data partition (GPT name and ext4 label `data`). Write them into a copy of the image with the pinned seeding tool:

```sh
nix run .#seed-image -- --image result-image/velstra-sentinel_1.0.0.raw \
  --config my-appliance.toml --output seeded.raw --qcow2 seeded.qcow2
```

The tool runs this build's own `sentinel config check`, refuses a configuration with no way in (no read-write login with an SSH key or password hash, SSH disabled, or no interface) unless `--allow-unreachable` is given, and adds the files to the image's factory filesystem as root-owned files (the configuration and private host key mode 0600). It never modifies the input image. It prints the generated host key and its fingerprint (pin it in `known_hosts`); `--host-key` reuses an existing ed25519 key. The data partition grows to fill the disk on first boot.

Name only interfaces the machine has: a configured interface that is missing fails boot health. Interface names follow PCI slot order, so a removed or re-ordered NIC moves every later name. Bind each zoned interface with `hw-id = "<mac>"`; the tool and `sentinel config check` warn about zoned interfaces bound by name only.

<a id="writing-the-image-to-disk"></a><a id="direct-flash-single-disk-simplest"></a><a id="guided-installer-single--raid-interactive"></a><a id="where-to-next"></a>

## Install to disk

Choose the [installer ISO](iso.md) for interactive disk and RAID selection. Installation erases the selected disks. Review the plan before committing. [Install to disk](../operations/install.md).
