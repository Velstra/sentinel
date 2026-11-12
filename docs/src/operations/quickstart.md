# VM quickstart

Run the build commands on an x86_64 Linux workstation with Nix flakes. For this
QEMU recipe, also install QEMU and enable writable `/dev/kvm`. The installed
appliance does not need Nix, Node.js or a Rust toolchain.

## Build and boot

From the Sentinel repository root:

```sh
nix build .#sentinel-iso --out-link result-iso
firmware=$(nix build .#qemu-firmware --no-link --print-out-paths)
qemu-img create -f qcow2 sentinel.qcow2 32G
cp "$firmware/FV/OVMF_VARS.fd" sentinel-vars.fd
chmod u+w sentinel-vars.fd
qemu-system-x86_64 -enable-kvm -machine q35 -cpu host -smp 2 -m 4096 \
  -drive if=pflash,format=raw,readonly=on,file="$firmware/FV/OVMF_CODE.fd" \
  -drive if=pflash,format=raw,file=sentinel-vars.fd \
  -drive file=sentinel.qcow2,if=virtio,format=qcow2 \
  -cdrom result-iso/iso/velstra-sentinel-installer.iso -boot order=d \
  -netdev user,id=wan -device virtio-net-pci,netdev=wan,mac=52:54:00:10:00:01 \
  -netdev user,id=lan,net=192.168.50.0/24,host=192.168.50.2,hostfwd=tcp:127.0.0.1:8443-192.168.50.1:8443 \
  -device virtio-net-pci,netdev=lan,mac=52:54:00:10:00:02
```

Use a new working directory for a new VM; do not overwrite an existing disk or
firmware state. The first NIC is WAN, the second LAN. In the installer select
the empty virtual disk, create an administrator, set WAN to DHCP and LAN to
`192.168.50.1/24`, and confirm the disk erase. Eject the ISO, then boot the same
VM command with `-boot order=c` and without `-cdrom`.

For Proxmox, use q35/OVMF, a 32 GiB disk, 4 GiB RAM and two VirtIO NICs on the
intended WAN/LAN bridges. Install from the ISO, eject it and boot from disk.
Development signing keys are not production Secure Boot trust; see
[Secure Boot](../architecture/secure-boot.md).

## Configure WAN, LAN and management

On the installed appliance, use `sentinel show interfaces` to match names to
the MACs above. Copy [quickstart.cli](https://github.com/Velstra/sentinel/blob/main/examples/quickstart.cli) to the
appliance and replace `eth0`/`eth1` with the actual names before applying:

```sh
sentinel configure < quickstart.cli
sentinel config check /var/lib/sentinel/appliance.toml
sentinel show interfaces
sentinel show nat
```

The batch retains installer accounts and configures DHCP WAN, LAN DHCP/DNS,
outbound masquerading and a LAN-only HTTPS console on port 8443. The complete
TOML sample is [quickstart.toml](https://github.com/Velstra/sentinel/blob/main/examples/quickstart.toml); do not
replace the saved configuration with it without retaining your accounts.

Open `https://localhost:8443/` for QEMU forwarding, or
`https://192.168.50.1:8443/` on a directly attached LAN/Proxmox bridge.
Compare the management certificate with the identity in
`journalctl -u sentinel-api.service` before trusting it. Log in with the account
created during installation; there is no factory password.

Web/API changes are provisional. Verify access and choose **Keep change**
before the confirmation deadline, otherwise the working configuration returns.
See [management recovery](configure.md).

Zoned interfaces stay down until the dataplane attaches. For recovery, retain
serial/local console access or an unzoned management interface; see
[interface recovery](../handbook/interfaces.md#zoned-links-stay-down-until-the-firewall-has-them).
HA and fleet setup are separate procedures in the
[HA guide](https://github.com/Velstra/sentinel/blob/main/docs/ha-phase3.md) and
[fleet guide](https://github.com/Velstra/sentinel/blob/main/docs/fleet-phase5.md).
