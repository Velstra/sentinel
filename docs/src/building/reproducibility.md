# Reproducibility & pinned hashes

The build is reproducible because the moving parts are pinned by hash. When you
bump a dependency you update the corresponding hash. This page is the map of
which hash is which.

## The pins, and where they live (all in `flake.nix`)

| Pin | Variable | What it covers |
|---|---|---|
| nixpkgs | `inputs.nixpkgs` (`flake.lock`) | appliance packages and stable Rust |
| nightly toolchain | `nightlyDate` + `nightlySha` | the fenix nightly used to compile the eBPF |
| BPF linker | `bpfLinker` | hash-verified upstream `bpf-linker` 0.10.3, built with LLVM 22 |
| nightly manifest | `rustNightlyManifest` (fetchurl, same `nightlySha`) | re-fetched so **offline eval** works |
| aya crates | `ayaHash` / `ayaOutputHashes` | all `aya-*` git crates share one checkout hash |
| eBPF object | `ebpfHash` | the `velstra-ebpf` fixed-output derivation, named with its Fabric/compiler/linker identity |
| Fabric source | `inputs.fabric` (`flake.lock`) | the data-plane agent source commit |
| Wren source | `inputs.wren` (`flake.lock`) | routing daemon source commit |

## Why the compiler and linker must agree

The appliance pins nightly **2026-08-01** and the LLVM-22 build of
[`bpf-linker` 0.10.3](https://github.com/aya-rs/bpf-linker/releases/tag/v0.10.3).
The older LLVM-20 pipeline cannot compile the current datapath. A newer nightly
must also be verified against its linker and the appliance kernel; changing the
date alone is insufficient.

The fixed-output object's name includes the Fabric source revision, compiler
date and linker version. This prevents a source update from silently reusing an
older object with the same recorded output hash. `checks.ebpf-maps` checks the
agent's map lookups against the actual object; packet VM tests verify loading
and forwarding. Preserve BTF and avoid host ELF stripping on the BPF object.

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

The eBPF fixed-output build fetches its pinned source and dependencies. The
nightly manifest is also needed during evaluation. The flake
**re-fetches the nightly manifest into the store** with the same hash
(`rustNightlyManifest`), so a content-addressed copy exists locally and even
evaluation can run offline once its inputs are available. For a sealed rebuild,
pre-populate the complete build-input closure, including:

- the `velstra-ebpf` output (build it once online, it's then cached by hash);
- the nightly toolchain and manifest;
- the pinned linker archive and tool outputs;
- flake sources, vendored Rust dependencies and the other appliance build inputs.

Caching only the eBPF object and compiler does not supply missing appliance
dependencies. Verify the offline rebuild before moving a cache into an isolated
environment.

## What is *not* committed

Secret material is never in the tree (enforced by `.gitignore`):

- `*.pem`, `*.key`, `*.crt`, `*.qcow2` are ignored.
- The Secure Boot **demo** PK/KEK/db keys are **generated at build time** in a Nix
  derivation (`sbKeys` in `nix/image.nix`), not committed. A real deployment
  overrides them with the operator's own keys — see
  [Secure Boot](../architecture/secure-boot.md).
