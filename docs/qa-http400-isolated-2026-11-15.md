# Atomic configuration refusals

This is an independently tested extraction from the larger audit worktree,
based on `f15fa0e8b0784c28ebc356b0dd3b1540f80246a4`. It is not an appliance
image or release certification.

## Changes

Invalid configuration batches now return HTTP 400 and the existing error
diagnostic, rather than HTTP 200 with `ok: false`. Both numbered command errors
and complete-candidate validation fail before admission or persistence.
OpenAPI describes the new contract.

The console maps numbered refusals to the immutable submitted batch. It retains
all staged edits, renders labels as text, and does not replay configuration
requests on this path. Unnumbered, out-of-range, permission and transport
failures receive no guessed attribution. Legacy HTTP-200 refusal handling
remains unchanged and can still use its historical diagnostic replay.

Browser tests require the specific HTTP 400 diagnostic and unchanged saved
bytes; unrelated exceptions do not count as successful input validation.
Creation/posture fixtures now supply complete valid objects and check both
API and installed CLI validation. A private synthetic GeoIP fixture makes
these checks independent of host files or downloads.

## Verification

- `cargo check --workspace --locked --offline`: passed.
- `cargo fmt --all -- --check`: passed.
- `cargo clippy --all-targets --locked --offline -- -D warnings`: passed.
- `cargo test --workspace --locked --offline`: 1,085 passed, none ignored.
- Standalone real-browser refusal regression: 4/4 passed.
- Complete Console: 139/139 passed.
- Complete UX: 170/170 passed, including the update-URL negative cases.
- Bash/JavaScript syntax and `git diff --check`: passed.
- Nix console derivation evaluation: passed
  (`3j6wng5jwwld1s82p5vzx245vffci80i-sentinel-console.drv`); not executed.

Final host binary SHA-256:
`466ca713f5a22eb3c7f2760221cf536654ed817828e3852bf96c8822e7864e00`.
All nine changed source/test inputs and this binary were hash-checked unchanged
after the final browser runs. The Rust suite includes complete-candidate
refusals with and without `commit`/`save`, unchanged bytes and no pending
transaction. Browsers use disposable loopback `--no-apply` instances.

The first complete Console run was 137/139: the old creation/posture fixtures
omitted required fields and supplied an invalid country code. These fixtures
previously tolerated non-parser refusals. They were corrected, not skipped;
all 34 creation panels and eight posture controls now require actual validation.
The initial failure log is retained alongside the passing rerun.

Private receipts: `commit-checkpoint-20261115.RwqTpv/http400-*` in the Enterprise
work directory. The larger audit worktree's 1,220 Rust and 199 UX counts belong
to a different source cohort and are not attributed to this extraction.
No Cargo, embedded assets, dataplane, production pins or release artifacts
changed. Nix VM/image qualification and GitHub CI are separate gates.
