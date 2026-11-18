> **Development record — not current operator guidance or release approval.**
> Results apply only to the source/image and scope recorded below. Original
> findings are retained; use the [documentation map](https://github.com/Velstra/sentinel/blob/main/docs/README.md) for current guides.

# Safe management and live inspection

Web/API edits are provisional. A worker applies the candidate while an independent recovery timer preserves the previous working configuration.

## Confirm a management change

1. Keep a local console and an authenticated session on the working address. Review the diff before applying the candidate.
2. Reconnect on the intended address and select **Keep change** before the displayed deadline. Polling the status does not extend it.
3. If the change fails, restore access on the previous path. The transaction reports whether it was confirmed, reverted, or failed during apply. An expired or stale confirmation returns HTTP 409.

The CLI session uses a separate workflow. After a CLI `commit-confirm`, `confirm` cancels its timer; use `save` to persist.

## Inspect the API

| Request | Purpose |
|---|---|
| `GET /api/v1/config/transaction` | Read the pending transaction and latest result. |
| `POST /api/v1/config/confirm` | Confirm the exact pending transaction after testing the new path. |
| `POST /api/v1/config/revert` | Request recovery of the preceding working configuration. |
| `GET /api/v1/telemetry` | Receive authenticated server-sent telemetry events. |

Send credentials in an authorization header over HTTPS. A HTTP 409 response means the supplied identity or baseline is no longer current. Fetch the latest state before deciding whether to submit another edit. If the recovery worker reports repeated failure, inspect the appliance locally before accepting its current state.

## Read telemetry

Inspect error fields alongside counters and rates. A failed probe is unavailable; it does not mean zero traffic. Slow consumers keep the latest snapshot and can detect gaps via event IDs. Use a separate log destination when a complete audit trail is required.

## Verify

```sh
nix build .#checks.x86_64-linux.management -L
nix build .#checks.x86_64-linux.console -L
```

Use a KVM-enabled build host for the VM checks. For app-level UI tests, see the console test reference.
