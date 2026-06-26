# Reproducibility & pinned hashes

The build is reproducible because the moving parts are pinned by hash. When you
bump a dependency you update the corresponding hash. This page is the map of
which hash is which.

## The pins, and where they live (all in `flake.nix`)

| Pin | Variable | What it covers |
|---|---|---|
| nixpkgs | `inputs.nixpkgs` | `nixos-25.05` — ships `rustc ≥ 1.85` and an LLVM-20 `bpf-linker` |
| nightly toolchain | `nightlyDate` + `nightlySha` | the fenix nightly used to compile the eBPF |
| nightly manifest | `rustNightlyManifest` (fetchurl, same `nightlySha`) | re-fetched so **offline eval** works |
| aya crates | `ayaHash` / `ayaOutputHashes` | all `aya-*` git crates share one checkout hash |
| eBPF object | `ebpfHash` | the `velstra-ebpf` fixed-output derivation |
| Fabric source | `inputs.fabric` (`flake.lock`) | the data-plane agent source commit |

## Why nightly must match LLVM 20

`bpf-linker` in nixpkgs 25.05 is **LLVM 20**. A newer nightly emits LLVM 22
bitcode, which that linker can't read (`Unknown attribute kind`). So the pinned
nightly (`2025-06-15`) is deliberately from the LLVM-20 era. If you bump nixpkgs
to a release with a newer LLVM, bump the nightly to match — not independently.

## Updating a hash (the fakeHash dance)

For the FOD-style pins (`ebpfHash`, `ayaHash`, `nightlySha`): set it to
`lib.fakeHash`, build, and Nix prints the real hash in the mismatch error. Paste
that back in. For example, after changing the Fabric source:

```shell
# 1. temporarily set ebpfHash = lib.fakeHash; in flake.nix
nix build .#velstra-ebpf 2>&1 | grep -A2 'specified:'
# 2. copy the 'got:' hash into ebpfHash, rebuild — now it's pinned
```

## Airgapped builds

Two FODs need network (`velstra-ebpf` and IFD of the nightly manifest). The flake
already **re-fetches the nightly manifest into the store** with the same hash
(`rustNightlyManifest`), so a content-addressed copy exists locally and even
*evaluation* succeeds offline. For a fully sealed build, pre-populate the store
with:

- the `velstra-ebpf` output (build it once online, it's then cached by hash), and
- the nightly toolchain + manifest.

After that, `nix build .#sentinel-image` runs with no network.

## What is *not* committed

Secret material is never in the tree (enforced by `.gitignore`):

- `*.pem`, `*.key`, `*.crt`, `*.qcow2` are ignored.
- The Secure Boot **demo** PK/KEK/db keys are **generated at build time** in a Nix
  derivation (`sbKeys` in `nix/image.nix`), not committed. A real deployment
  overrides them with the operator's own keys — see
  [Secure Boot](../architecture/secure-boot.md).
