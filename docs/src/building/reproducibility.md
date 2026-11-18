# Reproduce a build

<a id="reproducibility--pinned-hashes"></a>

Use the same repository revision, lock file and pinned build inputs when comparing appliance artifacts.

<a id="the-pins-and-where-they-live-all-in-flakenix"></a>

## Record your inputs

```sh
git rev-parse HEAD
nix flake metadata --json --no-write-lock-file > sentinel-flake-metadata.json
```

The Git revision identifies local build definitions; the lock file identifies external inputs. Keep both with your build record.

<a id="why-nightly-must-match-llvm-20"></a><a id="updating-a-hash-the-fakehash-dance"></a><a id="what-is-not-committed"></a>

## Build the pinned image

```sh
nix build .#sentinel-image --no-write-lock-file --print-out-paths
```

Record the resulting store path. The eBPF object also depends on the pinned Rust nightly, build tools and fixed-output hashes. If a dependency changes, review the expected sources before updating hashes.

<a id="airgapped-builds"></a>

## Build offline

Populate or copy the required store paths and fixed-output sources first. A source checkout alone cannot satisfy network fetches on an air-gapped builder. See the [flake outputs](../reference/flake-outputs.md).
