# Test suite (nixosTests)

Sentinel is verified by **six nixosTests** plus the Rust unit tests. The
nixosTests boot real QEMU/OVMF VMs, so they need `/dev/kvm`.

## The six checks

```shell
nix build .#checks.x86_64-linux.commit        -L
nix build .#checks.x86_64-linux.verified-boot -L
nix build .#checks.x86_64-linux.install       -L
nix build .#checks.x86_64-linux.install-iso   -L
nix build .#checks.x86_64-linux.update        -L
nix build .#checks.x86_64-linux.secureboot    -L
```

| Check | Boots | Proves |
|---|---|---|
| `commit` | appliance, **no network** | `commit` applies hostname/firewall/address live; `save` persists |
| `verified-boot` | the **real** signed image (OVMF) | verity store mounts; reaches multi-user; clean boot **blessed** |
| `install` | a live env with blank disks | single + RAID1 install lay down a bootable layout |
| `install-iso` | the **ISO** | live-boot install from the bundled image → bootable ESP |
| `update` | the image | A/B slot B written + re-typed; bootloader switched |
| `secureboot` | the signed image, **keys enrolled** | boots under **enforcing** Secure Boot |

## Rust unit tests

```shell
cargo test                       # 27 unit tests
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

CI (`.github/workflows/ci.yml`) runs fmt + clippy + test + release build on every
push/PR. The heavier nixosTests are run locally / on a KVM-capable runner.

## Why some things are verified structurally

`machine.reboot()` of an OVMF image **hangs** in the nixosTest harness (a
firmware-vars / `-no-reboot` quirk). So tests that would otherwise reboot
(A/B slot switch, persistence-across-reboot) verify the **structure** instead —
the slot is written and re-typed, the bootloader default is switched, the data
partition is separate and writable — and the boot-counting/bless mechanism is
proven on its own in `verified-boot` (`Marked boot as 'good'`). The `secureboot`
test uses pre-enrolled vars and a single boot for the same reason.

## Loading & verifying eBPF

The eBPF data plane can only be **loaded/verified by a privileged host** (it needs
root to attach XDP). The nixosTests run that inside their sandboxed VMs. On a dev
box, loading the agent against a live kernel is a manual, root-only step — it is
not part of `cargo test`.
