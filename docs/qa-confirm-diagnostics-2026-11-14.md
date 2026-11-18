# Commit-confirm diagnostics: 2026-11-14

Status: host checks and the actual packaged VM regression passed. Final signed
image certification remains separate.

The independent retest reported three missing-unit errors around an otherwise
successful commit-confirm. That retest used an older image. Current timer arming
already avoids obsolete stop/reset-failed cleanup; the remaining fix captures
timer-stop output and treats absence as benign only after both exit status 5 and
an exact, successful `LoadState=not-found` response. Permission, bus, malformed
response and execution errors remain visible. Confirmation still verifies real
PID-1 state before reporting success; an error message alone cannot disarm it.

The systemd property-query behavior is documented in its
[systemctl implementation](https://github.com/systemd/systemd/blob/main/src/systemctl/systemctl-show.c).
This is not a text-message/localization-based classifier.

## Evidence

- Host Rust workspace: 1,158 passed, none failed or ignored.
- Host Clippy, all targets with warnings denied: passed.
- Rust formatting and patch whitespace checks: passed.
- `nix/confirm-diagnostics-test.nix`: actual VM PASS in 23.06s on Linux
  6.12.113, registered output
  `/nix/store/32fkvyg6l8jflyh4x58vffvjgakrz3g2-vm-test-run-sentinel-confirm-diagnostics`.
  `confirm-diagnostics-v1.log` records actual missing-unit stop status 5,
  successful cancellation status 0 and an injected refusal status 4 with
  CLI status 1 and the real timer still active. All protected intent and
  timer/deadline/bound-restore comparisons pass; no reset-failed call occurs.
- The frozen packaged core also passes all 1,171 tests under Nix, with no
  failures or ignored cases. Core executable SHA-256:
  `ad68f4957df72faa3509120f147157966e23f6b95ecc78ffc01a464ff0498fc7`.

Host logs are retained in the private audit work directory as
`confirm-timer-noise-host-tests-v1.log` and
`confirm-timer-noise-host-clippy-v1.log`. These are host-source checks, not an
image boot or release certification.

## Executed runtime acceptance

The fixture uses the installed Sentinel core and actual systemd transient units.
Only the pinned systemctl wrapper is instrumented: state queries and ordinary
commands still reach real PID 1; a disposable marker can refuse one timer stop.

1. Restore an already saved baseline with no timer present. Require one actual
   stop status 5, absent-unit verification, unchanged intent and no obsolete
   missing-unit diagnostics.
2. Apply a real hostname change with commit-confirm, then confirm it. Require an
   armed real timer, one successful stop, unchanged saved/active/snapshot hashes
   during confirmation, and no reset-failed calls.
3. Refuse cancellation while another real trial is armed. Require a failing CLI
   result, the genuine diagnostic, no success message, unchanged intent hashes,
   and the real timer still active with the same deadline and bound restore.
   Remove the fault and confirm normally.

The fixture does not assert an unchanged mutation generation on a failed
confirmation: the existing protocol advances that generation before attempting
cancellation. It does require that saved configuration, RUNNING, the rollback
snapshot and actual hostname remain unchanged.

Still outside this check: reboot-durable/unified transaction journaling,
privilege-escalation integration for non-root operators, immutable OTA admission,
hardware behavior and final signed-image/SBOM/CVE qualification. Earlier accepted
confirmation fixtures and their receipts remain separate evidence.
