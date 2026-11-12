# Peer write context and configuration-sync boundaries

Scope: source corrections for OSQA-009/012/171, not a production certificate.
QA6 installs the first corrections; the coherent-refresh follow-up below is
newer than QA6 and requires a new immutable build. Native failed receipts,
cleanup and protected configuration backups remain retained separately.

## Selected member is an observation context

The account permission stays separate from the selected member. Legacy forms
now share `writeBlockReason` between staging and the late-render write gate.
Peer views disable Stage/New/Edit/Delete/Apply and local operational mutations,
with a persistent accessible explanation. Existing local drafts survive member
switches. Returning local restores only context-gated controls, not buttons
already disabled by a prerequisite. Readable navigation remains available.

The backend authorization and the existing local-only Apply guard are unchanged.
The React document editor retains its existing remote/member boundary. No new
remote configuration endpoint or expanded permission is introduced.

## Delivery is not reachability

Stack and the member rail share `configSyncState`/`configSyncBadge`. Delivered
means this appliance's outbox has no pending local changes for that peer, not
that both complete model documents are identical. Pending delivery, Conflict
and Unknown remain distinct from authenticated reachability. Persistent conflict
and recovery guidance remains visible, including outside the narrow table's
intentional horizontal scroller. Unknown values never default to a green state.

The browser presentation matrix uses explicitly synthetic GET response fixtures;
it is not evidence of real outbox convergence or conflict recovery. Real pinned
TLS member reads and wrong-pin/session isolation are tested separately in the
same browser suite. Native cloud policy/conflict tests are still required.

Actual QA6 native1198 passes7/7 for CLI A->B GUI and confirmed GUI B->A policy
with real independent packets, unrelated complete models and prepared peer
facts retained. Actual native1199 independently verifies durable pending,
concurrent conflict refusal and explicit common-base resolution. Both originals
and owned filter/timer cleanup are verified. It also retains TWO real GUI
failures: ordinary Refresh updates the table but leaves the rail Delivered.

The follow-up gives both surfaces one coalesced, bounded, session-owned read.
Page navigation/Refresh updates both; a failed read clears stale green delivery
and exposes unavailable notices. Revision reads are separately token/member/
epoch guarded so a slow revision cannot block delivery. Sign-out aborts and
invalidates member reads and clears their DOM. No new network permission,
configuration write, force resolution or status-semantic change is introduced.

The real-browser regressions fail8/10 against the immutable QA6 binary, then
pass10/10 against corrected source. Tests use the actual Refresh and Sign out
controls with explicitly synthetic presentation/delay fixtures; they do not
replace the native1199 reproduction or a future installed-image recheck.

## Preserve prepared future peer interface facts

An actual QA5 reverse sync exposed a separate loss: a prepared nonempty peer
address disappeared from the receiver's identity profile when the sender had
not yet declared that interface. `capture` can observe only declared source
interfaces, so replacing the reverse profile with that capture loses intent.

The merge retains missing entries from the receiver's existing trusted peer
profile. Captured facts always win for declared sender links; explicit local
profile removals remain removed. It does not retain old hostnames, node IDs,
management endpoints or current addresses over fresh source facts. Cluster,
member, full schema and revision-conflict checks remain authoritative.

The new Rust regression proves prepared IPv4/IPv6/MAC facts survive an unrelated
reverse policy push, fresh declared addressing wins, shared revisions agree,
the prepared link can later materialize correctly, and explicit removal stays
removed. It fails at the lost entry against the pre-fix merge. Actual cloud
retesting must use a newly built immutable candidate, never a runtime binary
replacement or forced model repair.

## Checks

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
CONSOLE_TEST_FILE=peer.test.mjs tests/console/run.sh
CONSOLE_TEST_FILE=ux.test.mjs tests/console/run.sh
tests/console/run.sh
nix build .#checks.x86_64-linux.console .#checks.x86_64-linux.console-ux
```

Loopback browser APIs use throwaway documents and `--no-apply`. Native reference
traffic and exact candidate deployment provide separate evidence. Passing field
reachability, a presentation fixture or a focused derivation never establishes
complete feature, hardware, whole-flake or production-release certification.
