# Historical source patches

Production Fabric and Wren pins already contain these fixes; the production
packages no longer apply this backport chain. Do not apply it to appliances.

[Historical patch notes](../../docs/qa-historical-backports-2026-11-12.md)
retain the original observations, hashes and verification boundaries.

From the repository root:

```sh
python3 -B -m unittest nix.test_source_patches tests.test_source_pins -v
nix build .#checks.x86_64-linux.source-patches-unit .#checks.x86_64-linux.source-cohort -L
```

The source-patch helper rejects partial/incompatible application.
The legacy allocator input exists only for mixed-version tests.
