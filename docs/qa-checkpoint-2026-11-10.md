# QA checkpoint and outstanding qualification

This checkpoint preserves the development workspace. It is **not a production
release approval**, and closing an unqualified pull request does not resolve its
underlying findings. Retained branches and follow-up issues own that work.

## Preserved work

- Management/API, configuration validation, archive privacy, public update-key
  validation, IPsec reconciliation, interface handling and console regressions.
- Immutable boot assessment/fallback, persistent identity, first-boot state
  growth, installer and signing/update regression fixtures.
- Explicit pinned Fabric/Wren source backports with matching package hooks,
  host tests and real VM traffic regressions. Removing a backport requires
  updating its input pin and build hook together, not silently dropping it.
- UI design/interaction contracts and scoped evidence notes in this directory.

Source changes are preserved separately from private QA captures, machine
credentials, signing material, runtime lock files and generated audit reports.
None of those private/generated files belongs in the source checkpoint.

## Evidence boundaries

The public-main atomic permission correction was merged in #45. Its companion
privileged-result correction is independently reviewed in #44; the combined
exact head passed 798 host tests, formatting, check and strict Clippy under a
restrictive umask. This evidence does not certify the larger workspace below.

The separately frozen OpenStack candidate passed 940 host tests and 193 browser
cases. Its selected sequential VM cohort passed 24 of 25 checks; the installer
check failed. A subsequent isolated installer correction passed its strict VM
regression, but is not retroactively part of that earlier candidate. The local
workspace, frozen candidates and later isolated corrections are distinct source
revisions and must not borrow each other's passing counts.

The older diagnostic cohort passed 89 of 94 VM checks. Failures in IPsec,
installer, legacy-update and wireless fixtures remain in their original logs;
separate narrower corrections do not erase those outcomes. Full final-candidate
qualification must be rerun after integration.

## Open qualification gates

1. Integrate individually reviewed source/fixture corrections and bind fresh
   host, browser, image and VM evidence to one exact resulting commit.
2. Finish capacity cancellation, owner-death, tamper and full-stage/B-boot tests.
   The real low-space refusal passed; a fixture executable lookup failed before
   the owner-death product process started. Offline fixture tests are not a VM
   pass.
3. Finish the signed native rolling-upgrade/original-TCP-flow and hard-failure
   proof. The current attempt stopped before opening its socket because stale
   exact reverse-NAT tuples were present. Diagnose their lifecycle; do not flush
   maps, forge role state or reboot merely to manufacture a passing preflight.
4. Finish native DHCP delivery/policy evidence and the remaining CLI/UI feature
   inventory. Missing pre-XDP delivery evidence is blocked, not a pass.
5. Resolve the held asynchronous update-job concurrency/CAS design before
   integrating that separate backend or exposing its UI as production-ready.
6. Complete final-image security, signing identity, hardware and gated-channel
   release criteria. No production release is authorized by this checkpoint.

Closed PRs must retain their remote branches and link an open follow-up issue.
No merge-check bypass, automatic release or deletion of preserved work is part
of this housekeeping operation.
