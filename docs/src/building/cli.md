# Building the CLI & agent

The image bundles these, but you can build each on its own.

## The `sentinel` CLI

```shell
nix build .#sentinel
./result/bin/sentinel --help
```

Stable `rustc` is fine for the CLI (it does **not** need Fabric or the nightly
toolchain). It is the `configure`/`commit`/`show`/`install`/`update` tool.

> **Why it's wrapped.** The build wraps the binary so every external tool it
> shells out to (`hostname`, `ip`, `networkctl`, `sgdisk`, `dd`, `mdadm`, …) is
> pinned to an absolute store path via `SENTINEL_*_BIN` env vars. Without this, a
> `commit` on a NixOS box could fail with
> `Failed to execute /run/current-system/sw/...` when a tool isn't on the admin's
> `$PATH` or in sudo's `secure_path`. See `src/system.rs::bin`.

### Dev loop (without Nix)

For fast iteration you can use Cargo directly — CI does exactly this:

```shell
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

`velstra-proto` vendors its own `protoc`, so no system `protoc` is needed for the
CLI.

## The `velstra` eBPF agent

```shell
nix build .#velstra        # the agent binary
nix build .#velstra-ebpf   # just the compiled eBPF object
```

This is the part that needs the pinned **nightly** toolchain (with `rust-src` +
`bpf-linker`) and the `fabric` source. Two things worth knowing:

- **`velstra-ebpf` is a fixed-output derivation** (network-allowed, hash-pinned)
  because `-Z build-std` can't fetch std's build-deps in a sealed sandbox.
- The agent binary uses `remove-references-to` to remove a retained toolchain
  path. That is one closure-reduction step, not a measurement of the complete
  image. Inspect the actual built image's closure before making size claims.

Both details are pinned-hash territory — if you bump the toolchain or Fabric, see
[Reproducibility & pinned hashes](reproducibility.md).
