# Rustix extended-attribute dependency correction

[RUSTSEC-2026-0486](https://rustsec.org/advisories/RUSTSEC-2026-0486.html),
issued November 11, 2026, covers the locked `rustix 1.1.4`. The release source
now selects patched `1.1.6` with registry checksum
`e5e76742e5294153d4dde1207dbec5bdd81eef6fabdc0d2118babadabfd858aa`.
The unaffected `0.38.44` and unrelated package versions are retained.

Sentinel resolves the affected entry through crossterm/fd-lock as well as the
temporary-file/protobuf build chain. No exploitability of the affected xattr
functions in Sentinel is inferred merely from this dependency graph. The
dependency is fixed rather than suppressed in the scanner or waived by tests.

Formatting, strict all-target Clippy and all 1,038 host tests pass. An independent
real user-xattr probe checks nonempty roundtrips and initialized zero-length
slices against all six affected functions. Original 1.1.4 returns unwritten byte
counts and fails the same empty-buffer assertion that patched 1.1.6 passes.
Unsupported filesystems are failures, not silent skips; the unsafe Vec variant
is deliberately not executed. The bounded local proof's SHA-256 is
`a2ef44bbda199d8bb6a5bacf6663213117dd2c2eef4efecfc17ba4c776c5462c`.

The same dependency correction is required in the production Fabric input.
The old allocator remains an explicit historical test-only input, never the
production dataplane. A fresh source/object comparison and actual kernel/HA/OTA
cohort are required after changing the production pin. Earlier VM receipts stay
bound to their original source; a green host suite or this dependency fix does
not certify the final production-signed image. The full-OS SBOM/CVE and native
Enterprise provider/distribution gates remain mandatory.
