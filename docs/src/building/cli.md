# Build the CLI and dataplane agent

<a id="building-the-cli--agent"></a>

Use the CLI on a workstation to inspect commands and validate configurations. Runtime operations require the appliance services and appropriate privileges.

<a id="the-sentinel-cli"></a>

## Build the packaged CLI

```sh
nix build .#sentinel --out-link result-cli
./result-cli/bin/sentinel --help
```

The Nix package wraps external commands with their store paths.

<a id="dev-loop-without-nix"></a>

## Run the Rust checks

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Run from the repository root on a development host.

<a id="the-velstra-ebpf-agent"></a>

## Build individual dataplane outputs

```sh
nix build .#velstra --out-link result-agent
nix build .#velstra-ebpf --out-link result-ebpf
```

Fabric and the eBPF compiler inputs are pinned. See [Reproduce a build](reproducibility.md).

## Build boundary

The eBPF Rust nightly and LLVM tooling must remain compatible. Review the pinned inputs when changing either. Removing build-time references from a binary is only one closure-reduction step, not proof of a small or toolchain-free appliance: inspect the final runtime closure and image. See [reproducibility](reproducibility.md).
