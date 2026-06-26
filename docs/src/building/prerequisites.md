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
| **A checkout of `fabric`** | the eBPF data-plane agent source | see below |

Enable flakes once, system-wide:

```ini
# /etc/nix/nix.conf  (or ~/.config/nix/nix.conf)
experimental-features = nix-command flakes
```

## The `fabric` source dependency

The Velstra eBPF agent (`velstra`) is compiled from the **Fabric** repository.
While Fabric is private, the flake references a **local checkout** by absolute
path:

```nix
# flake.nix
fabric = {
  url = "git+file:///home/mbrandt/01_repositories/velstra/fabric";
  flake = false;
};
```

So before building anything that pulls in the agent (`velstra`, `velstra-ebpf`,
`sentinel-image`, `sentinel-iso`, or any `checks.*`), make sure Fabric is checked
out at that path **and your changes there are committed** — the flake builds
Fabric's committed `HEAD`, not your working tree.

> Once Fabric is public, switch the `url` to `github:Velstra/fabric` so the build
> works for CI and other contributors. Building only `.#sentinel` (the CLI) does
> **not** need Fabric.

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
