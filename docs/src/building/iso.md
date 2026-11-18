# Build the installation ISO

<a id="building-the-installer-iso"></a>

The ISO is bootable media with the appliance image and installer on board.

<a id="what-it-does"></a><a id="how-its-wired-flake"></a>

## Create the ISO

```sh
nix build .#sentinel-iso --out-link result-iso
ls -lh result-iso/iso/velstra-sentinel-installer.iso
```

Attach the ISO to a UEFI VM or prepare installer media. Check disk identities before using a physical target.

<a id="verifying-the-iso-actually-installs"></a>

## Test the installer

```sh
nix build .#checks.x86_64-linux.install-iso -L
```

The fixture boots the ISO and exercises installation. To try a fresh installation interactively, use the [VM quickstart](../operations/quickstart.md).
