# Velstra Sentinel

Velstra Sentinel is a declarative, immutable Rust + eBPF/XDP firewall and routing
appliance. `appliance.toml` is its desired state; CLI, embedded web console and
optional fleet management reconcile the same document without a reboot.

The v1.0 feature set includes stateful filtering/NAT, VLANs/bridges, WireGuard,
DHCPv4/v6 and DNS, Wren BGP/OSPF routing, witness-authorized active/passive HA,
connection-state/config replication, commit-confirm recovery and authenticated
live telemetry. Local operation requires no cloud service.

## 5-minute quickstart

Start with an available x86_64 installer ISO, a 32 GiB virtual disk, 4 GiB RAM,
two VirtIO NICs and hardware virtualization. The five minutes cover initial
setup after the image is available; building/downloading the Nix closure and
provisioning an independent HA witness take additional time.

### 1. Build and boot the installer

On a Linux build host with Nix flakes enabled:

```sh
nix build .#sentinel-iso --out-link result-iso
nix build .#qemu-firmware --out-link result-firmware
qemu-img create -f qcow2 sentinel.qcow2 32G
cp result-firmware-fd/FV/OVMF_VARS.fd sentinel-vars.fd
chmod u+w sentinel-vars.fd
qemu-system-x86_64 -enable-kvm -machine q35 -cpu host -smp 2 -m 4096 \
  -drive if=pflash,format=raw,readonly=on,file=result-firmware-fd/FV/OVMF_CODE.fd \
  -drive if=pflash,format=raw,file=sentinel-vars.fd \
  -drive file=sentinel.qcow2,if=virtio,format=qcow2 \
  -cdrom result-iso/iso/velstra-sentinel-installer.iso -boot order=d \
  -netdev user,id=wan -device virtio-net-pci,netdev=wan,mac=52:54:00:10:00:01 \
  -netdev user,id=lan,net=192.168.50.0/24,host=192.168.50.2,hostfwd=tcp:127.0.0.1:8443-192.168.50.1:8443 \
  -device virtio-net-pci,netdev=lan,mac=52:54:00:10:00:02
```

The first NIC is WAN; the second is LAN. In the installer choose the empty
virtual disk, create your administrator/password, set the first NIC to WAN/DHCP
and the second to LAN/192.168.50.1/24, then confirm installation. Eject the ISO and
boot from disk (`-boot order=c`, without `-cdrom`). The installed image has no
factory password or console autologin; use the administrator you just created.

For **Proxmox**, upload the same ISO and create a q35/OVMF VM with a 32 GiB disk,
4 GiB RAM and two VirtIO NICs. Attach WAN/LAN to the intended bridges. Install,
then eject the ISO and put the disk first in the boot order. Use the LAN address
directly instead of QEMU's localhost forwarding. Firmware setup for your own
Secure Boot trust is separate; the default source build uses development
firmware-signing keys. See the [Proxmox VM reference](https://github.com/proxmox/pve-docs/blob/master/qm.adoc)
and [verified-boot handbook](docs/src/architecture/secure-boot.md).

### 2. Apply the sample desired state

From the appliance console, run `sentinel show interfaces` and identify the WAN
and LAN NIC names by the MACs above. The samples use `eth0`/`eth1`; substitute
your actual names before applying. The complete network sample is
[examples/quickstart.toml](examples/quickstart.toml). Its matching
[CLI batch](examples/quickstart.cli) preserves the installer-created administrator
and permission groups while writing the same network settings to canonical
`/var/lib/sentinel/appliance.toml`:

```sh
sentinel configure < quickstart.cli
sentinel config check /var/lib/sentinel/appliance.toml
sentinel show interfaces
sentinel show nat
```

Copy `examples/quickstart.cli` to the appliance as `quickstart.cli`, or paste its
commands into `sentinel configure`. The batch configures DHCP on WAN, LAN
`192.168.50.1/24`, LAN DHCP/DNS, outbound masquerading and a LAN-only HTTPS console
on port 8443. WAN input defaults to drop with an explicit DHCP-client reply rule. Keep the installer accounts when
authoring a complete replacement TOML document.

Zoned interfaces (WAN and LAN here) stay down until the firewall data plane
has hooked them, so a data plane that cannot start leaves the LAN — and the
console on it — dark. The quickstart uses two NICs for brevity; on a real
deployment add an **unzoned management port** and/or the serial console as a
way in that does not depend on the data plane. `sentinel show interfaces` marks
such a link `held: waiting for datapath`; recovery is covered in the
[interfaces handbook](docs/src/handbook/interfaces.md#zoned-links-stay-down-until-the-firewall-has-them).

### 3. Open the console and confirm changes

Open **https://localhost:8443/** for the QEMU command above, or
**https://192.168.50.1:8443/** from the LAN/Proxmox bridge. Compare the self-signed
management certificate with the identity printed in
`journalctl -u sentinel-api.service` before trusting it, then log in with the
installer account. **Dashboard** shows live health; **Policy → Firewall rules**
includes the live flow/rule inspector; **System → Configuration** offers the
validated side-by-side TOML editor.

UI/API changes are provisional. Verify connectivity and choose **Keep change**
within the default 60-second window. Otherwise the saved document and working
network return automatically—even after API restart or a reboot. Details:
[management and recovery](docs/management-phase4.md).

### 4. Pair two appliances

Use distinct member addresses and a dedicated control network reachable by an
independent Sentinel witness. The witness is required for partition-safe leased
HA; two members alone do not provide that authority. The fully exercised lab
uses primary `10.3.0.1`, secondary `10.3.0.2`, witness `10.3.0.3` and HTTPS
management port 8080. Generate one private enrollment credential of at least
32 bytes and configure it as `system.config-sync.secret` on the secondary. The
witness never receives it: `sentinel ha witness-key` (token on stdin) prints the
derived `key` and `cluster` for `[system.ha-witness]`, which also lists the two
member addresses (`member = ["10.3.0.1", "10.3.0.2"]`) and listens on
`10.3.0.3:5440`.

On the primary, prepare `system.ha.enabled = false` and
`system.ha.witness = "10.3.0.3:5440"`, then run (the token is prompted for
without echo; it never appears on a command line):

```sh
sentinel ha pair 10.3.0.2:8080 --witness 10.3.0.3:5440
sentinel show ha
```

Pairing binds member identities and management TLS pins, reconciles both nodes
and persists a recoverable plan. The automated pairing check asserts this
command completes in under 30 seconds once the network/witness are ready.
For the complete shared VIP/interface preparation and failover guarantees, use
[the HA guide](docs/ha-phase3.md) and [the executable lab](nix/ha-pair-test.nix).

## Optional fleet management

Provision a node-specific mTLS identity and the controller's command-signing
public key, then configure `[fleet]` or **System → Fleet enrollment**. The
controller can request telemetry and deliver signed desired-state revisions;
changes retain local validation, CAS and explicit commit-confirm recovery.
Without this section the agent stays stopped. [Configuration and controller
protocol](docs/fleet-phase5.md).

## Build and verify

```sh
cargo fmt --all -- --check
cargo check --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --workspace --locked
bash tests/console/run.sh
nix build .#checks.x86_64-linux.api .#checks.x86_64-linux.quickstart -L
nix build .#checks.x86_64-linux.ha-pair .#checks.x86_64-linux.install-iso -L
nix build .#sentinel-image .#sentinel-iso -L
```

The web assets are compiled into the Rust binary and Nix appliance; there is no
runtime asset server. The React/TypeScript management views are built and tested
with npm, then embedded in the Rust binary (see below). The test suite boots Linux VMs for
real packet forwarding/NAT, kernel verifier loading, service reconciliation,
HA/replication, management rollback and mTLS fleet commands. Hardware-specific
TPM/Secure Boot provisioning and physical NIC compatibility still require
validation on the deployment hardware. Encrypted installations use LUKS2 and a
boot-time passphrase; no unattended TPM enrollment is claimed here.

The [mdBook handbook](docs/) covers installation, verified A/B boot, routing,
services and signed image updates. Build it with `nix run nixpkgs#mdbook -- build
docs`. The image and ISO are source-build outputs; this README does not imply a
published vendor update channel or signing authority.

## License

**AGPL-3.0-or-later**. A commercial license is available; contributions are under
the project CLA.

### React management UI

The live dashboard, flow/rule inspector, TOML editor and global Commit-Confirm
banner are React/TypeScript components in `ui/`. They use the same authenticated
API, telemetry collector and durable safe-apply worker as the CLI-backed console.
The navigation, login and remaining configuration forms retain their existing
implementation during this incremental migration. The shared shell uses the same
light/dark tokens as the React views. On narrow screens, open **Menu** to find
a destination; Escape closes it. Dashboard cards and quick access buttons open
the corresponding management page. **Policy → Firewall rules** opens the rule
editor, while **Policy → Live packets** opens the live inspector. Its **Blocked**
preset includes both dropped and rejected packets. Technical source errors and
additional dashboard diagnostics can be expanded when needed.

```sh
cd ui
npm ci
npm test
npm run build
npm run check:assets
cd ..
cargo build --locked
CONSOLE_TEST_FILE=react.test.mjs bash tests/console/run.sh target/debug/sentinel
nix build .#sentinel-ui .#sentinel
```

Commit `ui/dist/management.js` and `ui/dist/management.css` with source changes so
plain Cargo builds work without Node. CI rejects stale bundles. Nix rebuilds and
tests the assets from the pinned npm lockfile in its sandbox, compares them with
the committed output, and embeds that result into Sentinel and its appliance
images. There are no runtime package downloads or CDN requests.

The dashboard displays measured interface throughput/PPS, HA authority and replica
age, BGP/OSPF neighbors and WireGuard handshake age. Source failures remain unknown.
The flow inspector filters the bounded live event window by action, rule, endpoint
or interface and supports pagination and a paused display. The configuration editor
reveals secrets only on request, retains rejected drafts, provides a side-by-side
visual diff, and validates through the same parser/schema as `sentinel validate`.
Applying starts the server's confirmation window (60 seconds by default). Only
**Keep change** confirms it; polling and navigation never extend the deadline.
