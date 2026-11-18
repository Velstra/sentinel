# Prepare a build host

<a id="prerequisites"></a>

Use an x86-64 Linux workstation with Nix and flakes. The installed appliance runs without a developer toolchain.

<a id="what-you-need"></a><a id="the-fabric-source-dependency"></a><a id="a-note-on-network-access-during-the-build"></a>

## Check the workstation

```sh
nix --version
nix flake show --no-write-lock-file
```

Run the second command from the checked-out Sentinel repository. If flakes are disabled, enable `experimental-features = nix-command flakes` in the Nix configuration. Initial builds need their pinned sources or a populated cache.

## Check VM support

```sh
test -w /dev/kvm && echo "KVM available"
```

KVM is needed for the VM-based checks; image builds alone do not require it. Continue with the [VM quickstart](../operations/quickstart.md) or [build the installer](iso.md).
