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

## Allow unprivileged user namespaces

The image build runs `systemd-repart` inside an unprivileged user namespace to assemble the partitions. A host that forbids those namespaces stops the build in the repart step with:

```text
unshare: write failed /proc/self/uid_map: Operation not permitted
```

Ubuntu 24.04 and later forbid them by default through AppArmor (`kernel.apparmor_restrict_unprivileged_userns = 1`). Check the host first:

```sh
unshare -Ur true && echo "user namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
```

If `unshare` fails, either allow unprivileged user namespaces on the build host:

```sh
echo 'kernel.apparmor_restrict_unprivileged_userns = 0' | sudo tee /etc/sysctl.d/90-nix-userns.conf
sudo sysctl --system
```

or keep the restriction and give the Nix daemon and its build users an AppArmor profile that permits `userns`. The sysctl is host-wide, so prefer the profile on a shared machine. Re-run `unshare -Ur true` to confirm.

## Size the build host

Measured on a 16 vCPU / 32 GB builder:

| Item | Size or time |
|---|---|
| Cold `nix build .#sentinel-image` | about 10 minutes |
| Rebuild with cached dependencies | about 8 minutes (the Rust unit tests run inside the build) |
| Appliance closure | about 1.5 GiB; must fit the 2.5 GiB store slot |
| Raw image | about 5.6 GiB apparent (1.7 GiB allocated) |
| Free disk | tens of GiB for the Nix store, and more for the VM checks |

## Check VM support

```sh
test -w /dev/kvm && echo "KVM available"
```

KVM is needed for the VM-based checks; image builds alone do not require it. Continue with the [VM quickstart](../operations/quickstart.md) or [build the installer](iso.md).
