# Prerequisites

Everything is built through the **Nix flake** at the repo root. You do not need a
Rust toolchain, `protoc`, or `bpf-linker` on your machine — the flake pins all of
them.

## What you need

| Requirement | Why | Notes |
|---|---|---|
| **Nix with flakes** | the whole build is flake-driven | enable `experimental-features = nix-command flakes` |
| **x86_64-linux** | the only target system the flake defines | images are UEFI/x86-64 |
| **KVM** (for the `checks.*` tests) | the nixosTests boot real QEMU/OVMF VMs | `/dev/kvm` present; not needed for plain `nix build .#sentinel-image` |

Enable flakes once, system-wide:

```ini
# /etc/nix/nix.conf  (or ~/.config/nix/nix.conf)
experimental-features = nix-command flakes
```

## The `fabric` source dependency

The flake fetches public Fabric and Wren revisions from `flake.lock`; no sibling
checkout or developer-specific filesystem path is required. Keep the reviewed
input revisions and fixed-output BPF hash coherent when changing dependencies.
The separate legacy Fabric input is only for mixed-version tests, not the
production dataplane. See [reproducibility](reproducibility.md).

## A note on network access during the build

Two derivations are **fixed-output derivations (FODs)** and are allowed network
access during the build (their results are pinned by output hash, so they stay
reproducible):

- `velstra-ebpf` — the compiled eBPF object. `-Z build-std` needs std's own
  build-deps, which a sealed sandbox can't fetch.
- the fenix **rust nightly manifest** — fetched at evaluation time (IFD).

Everything else builds offline. If you are fully airgapped, see
[Reproducibility & pinned hashes](reproducibility.md) for how the nightly
manifest is re-fetched into the store so even *evaluation* works offline.
