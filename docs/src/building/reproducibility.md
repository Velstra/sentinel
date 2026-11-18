# Pinned inputs and reproducibility

Pins identify the inputs of a build; they do **not** prove that two independent
builds produce identical images. Bit-for-bit reproducibility remains a release
test, including signing, timestamps and filesystem construction.

## Inspect the actual pins

From the repository root:

```sh
nix flake metadata --no-write-lock-file
git diff -- flake.nix flake.lock
```

`flake.lock` records the exact nixpkgs, Fenix, Fabric and Wren revisions.
`flake.nix` selects the nixpkgs branch and contains the eBPF nightly date,
manifest hash, Aya source hashes and fixed-output `ebpfHash`. Read those current
values rather than copying release names or hash values from this page. The
legacy Fabric input is test-only and must remain independent of the production
pin.

## Changing Fabric or its toolchain

Update reviewed source pins and the lockfile together. Rebuild the eBPF object
from that source, record the measured output hash, and run the kernel verifier
and packet regression gates. The object embeds its source identity; the agent
build refuses an object from a different Fabric source instead of silently
combining new userspace with cached old eBPF. This guard is development work;
the Sentinel dependency-pin and packaging migration still needs integration
qualification. Do not assume a previously published package contains it.

A fixed-output derivation can reuse cached bytes by output hash. Merely changing
the input revision is not proof that a new object was produced. To measure a
changed output during development, temporarily use `lib.fakeHash` for
`ebpfHash`, build `velstra-ebpf`, inspect the mismatch, and record the real hash.
Do not leave a fake hash, dirty worktree override or unreviewed source URL in a
release cohort.

The Rust nightly and `bpf-linker` must use compatible LLVM bitcode versions.
Verify that compatibility from the pinned toolchain; do not advance a nightly
independently and assume a successful host Rust build covers eBPF.

## Offline builds

An offline build needs **all** required sources, toolchains, fixed-output
artifacts and substitutes already in the store. The flake's cached nightly
manifest helps offline evaluation; it does not populate the rest of the closure.
Prove an airgapped build using an isolated builder with network access disabled,
not by observing that one warm local build made no request.

## Release comparison

Build the same reviewed source/lockfile on two independent builders, retain the
unsigned and signed artifact hashes, and explain every difference. Preserve the
commands, builder/tool versions and signing inputs in provenance. A self-issued
attestation or a matching version string is not an independent comparison.

## Secret handling

An ignore rule prevents accidental additions only when it matches; it is not a
secret scanner, credential revocation or Git-history cleanup. Never place keys,
passwords, credentials, images or unredacted appliance archives in the source
tree or upload private QA work directories.

The default public Secure Boot keys are generated in a Nix derivation and are
readable in the store. They are for development only. A production key must not
be passed through a Nix derivation; the external-key signing interface and
custody requirements remain separate work. See [Secure Boot](../architecture/secure-boot.md).
