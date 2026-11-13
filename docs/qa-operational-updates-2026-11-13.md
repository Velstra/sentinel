# Operational OTA CLI and console

Both interfaces use update_jobs; neither owns the image writer. The new CLI is
`system status` and `system update check|stage|job`. Stage requires an exact
reviewed offer ID. The native legacy install command is refused rather than
dispatching an unreviewed private helper. Community local-image behavior remains
unchanged. No automatic reboot, downgrade override or remote member write exists.

System updates reuses the existing Panel/buttons/description lists and shows
boot identity, exact signed review, worker history, refusals and uncertainty.
The worker survives browser/CLI disconnects. A lost POST can only be reconciled
through retained request IDs; it is never automatically retried. Reads are
bounded, stale/member/session replies cannot authorize a write, and pending
configuration or local drafts withhold update actions.

Evidence layers are deliberately separate:

- Rust request/grammar tests and existing durable-worker/protocol regressions.
- React unit tests including cancellation, uncertainty and exact review binding.
- Chromium console tests against the real off-box API refusal and explicitly
  simulated operational responses. These prove UI behavior, not slot writes.
- The native VM probe uses actual CLI Check/Stage/Job, refuses an incorrect offer
  before writing, observes the same jobs through the API, retains all previous
  native fault cases and requires cold boot into the new assessed slot.

Component qualification, private source pin migration, final signed-image
certification and publication are separate gates. Source tests alone are not a
production release certificate. The owner's VM-only qualification policy remains.
