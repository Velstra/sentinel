# Build an appliance image

<a id="building-images"></a>

Use the raw image for a UEFI virtual disk or as input to the installer. Use the ISO when you want disk selection and first-boot setup.

<a id="what-you-get"></a><a id="build-cost--caching"></a>

## Build and locate the image

```sh
nix build .#sentinel-image --out-link result-image
find -L result-image -name '*.raw' -type f
```

The output includes the ESP, a signed kernel image, the verified store, space for the alternate slot, and a writable data partition. Source builds use development signing keys.

<a id="trying-it-in-a-vm-first"></a>

## Try it in a VM first

For a disposable configuration session use `nix run .#vm`. To validate the real image and boot chain, run `nix build .#checks.x86_64-linux.verified-boot -L`. To install a persistent evaluation appliance, follow the [VM quickstart](../operations/quickstart.md).

<a id="writing-the-image-to-disk"></a><a id="direct-flash-single-disk-simplest"></a><a id="guided-installer-single--raid-interactive"></a><a id="where-to-next"></a>

## Install to disk

Choose the [installer ISO](iso.md) for interactive disk and RAID selection. Installation erases the selected disks. Review the plan before committing. [Install to disk](../operations/install.md).
