# Safe management and live inspection

`appliance.toml` remains the desired-state document for the CLI, API and embedded
console. No external UI or cloud service is required. The console's HTML,
styles and JavaScript are compiled into Sentinel and included in the Nix CLI,
VM and appliance packages.

## Confirmed management changes

Live `PUT /api/v1/config`, committed `POST /api/v1/configure` batches and
`POST /api/v1/config/document` use the same durable transaction engine.
Malformed batches are rejected in full before mutation. Configure accepts
`set`, `delete`, `rollback <revision>`, `commit` and `save`; it does not execute
operational commands or write arbitrary export paths.

Before changing the network, Sentinel privately journals the exact saved and
running baselines. An independent systemd unit applies the proposed document,
so changing the API's own address, port or TLS settings does not interrupt the
operation. An accepted response includes `pending.id`, `pending.ready` and
`pending.remaining_seconds`. `ready = false` means the independent worker is
still applying. Poll `GET /api/v1/config/transaction` until ready, then test
management access and forwarding before sending:

```text
POST /api/v1/config/confirm
Content-Type: application/json
Authorization: Bearer <management-token>

{"id":"<pending.id>"}
```

The default window is 60 seconds after reconciliation. Set
`[services.web] confirm-timeout = 90` (or the CLI equivalent
`set services web confirm-timeout 90`) to choose 1–3600 seconds. An edit uses
the previous working document's timeout. Status polling never renews it.
Expired identities and stale confirmations return HTTP 409.

`POST /api/v1/config/revert` with the same identity requests immediate rollback.
For a live appliance its response reports `reverting: true`: the independent
recovery service completes the reverse network change even if that terminates
the API connection. Reconnect at the previous endpoint and poll transaction
status. `last_result` identifies the completed transaction as `confirmed`,
`reverted` or `apply-failed`; this non-secret receipt lets a reconnecting client
distinguish confirmation from recovery. Repeated confirmation of the same
current revision is idempotent. The console retains reverted drafts and staged
form changes for review.

The independent recovery timer retries failures every second and retains its
private journal until saved bytes and the working network have been restored.
An unconfirmed journal is recovered before boot rendering, even if its deadline
had not elapsed when power was lost. Apply workers have a bounded 180-second
runtime; an interrupted application also retains recovery protection. Other
CLI/API commits and saves cannot overwrite a pending transaction. Confirmed
revisions enter the normal revision archive and durable HA outbox; provisional
configurations are not sent to the peer. SSH administrators can use `confirm`
in configuration mode, or `sentinel confirm-rollback` to recover immediately.

## Document editor and API

`GET /api/v1/config/document` returns `toml` and `revision` with `Cache-Control:
no-store`. It contains secrets and requires write access. The ordinary
`GET /api/v1/config` remains redacted for read-only operators.

Submit `{toml, expected_revision, validate_only: true}` to
`POST /api/v1/config/document` for the same parsing and schema validation as
`sentinel validate`, plus a real configuration diff without mutation. Omit
`validate_only` to begin a provisional application. A changed baseline returns
409 instead of silently overwriting another administrator's work. The console's
Reload current baseline action preserves the draft for an explicit new review.

The console reveals the document only after an explicit action, displays the
current and proposed TOML side by side, retains rejected drafts, and offers the
same Keep change / Revert now banner on every page. Reopen the console at the
new endpoint after changing its management address, port or TLS mode. Drafts
and secrets are not persisted in browser storage.

## Streaming telemetry

`GET /api/v1/telemetry` is a bearer-authenticated SSE stream; each `telemetry`
event contains one JSON snapshot. Use a fetch streaming client that sends the
Authorization header. Credentials must never be placed in a query string.
Credential revocation closes an existing stream on its next snapshot.

A single collector drains the agent's ring and fans out to every subscriber.
Slow consumers keep only the latest snapshot. A 512-event window includes
monotonic event IDs, `oldest_event_id` and `next_event_id`, making history gaps
visible. This bounded diagnostic stream is not a lossless audit log.

Snapshots include matched rule name/ID, action, source/destination addresses
and ports, protocol, interface index/name, up to 512 exact per-rule counters
with a total-rule count and kernel ring-overflow count, bounded
firewall-state samples with a total count, the NAT table and top NAT talkers,
interface byte/packet rates, Wren BGP/OSPF neighbors and routes, HA authority,
and WireGuard latest handshakes. Individual unavailable sources appear in
`errors`; they are not reported as zero traffic or healthy sessions. Interface
rates use actual sample intervals and become unknown on counter resets.
Standby `sync_age_ms` measures the age of its latest authenticated replica
update. The active node does not receive remote apply acknowledgements in
VCS2 and therefore reports remote apply latency as unmeasured.

## Verification

```sh
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
bash tests/console/run.sh
# Fast management regression subset, using the same real API/browser harness:
CONSOLE_TEST_FILE=management-only.test.mjs bash tests/console/run.sh
nix build .#checks.x86_64-linux.management -L
nix build .#checks.x86_64-linux.console -L
```

The management VM exercises a real lost management address, worker/API process
separation during port/TLS changes, API death, explicit confirmation, reboot
recovery, CLI write exclusion and two concurrent consumers of actual eBPF
accept/drop events. Existing API, commit, reconciliation, config-sync and HA
checks remain regression gates. The existing per-PR API check depends on the
management safety VM, so these new regressions run automatically on pull
requests as well as in the complete nightly matrix.
