# SSH service health — 2026-11-15

Status: source, host and packaged API/boot acceptance pass. These results are
not final-image certification.

## Contract

SSH is enabled by default. An empty failed-unit list does not prove it is
running: systemd reports an automatic restart as `activating/auto-restart`.
The authenticated health response now includes `ssh.enabled`, `ssh.service`
and `ssh.status`:

| Configured intent and observed unit | Status | Issue |
| --- | --- | --- |
| Enabled; loaded, active/running, successful exit metadata and condition | `ok` | None |
| Enabled; starting, retrying, inactive, failed or otherwise not running | `warning` | `ssh-service-inactive` |
| Enabled; missing, incomplete or unavailable unit observation | `unknown` | `ssh-service-unavailable` |
| Configuration unavailable | `unknown` | `configuration-unavailable`, `ssh-service-unavailable` |
| Explicitly disabled | `disabled` | No SSH issue |

The existing two-second, 65,536-byte service probe now requests `sshd.service`
alongside the time and TPM units; no additional child process is needed.
Duplicate properties, duplicate unit IDs, malformed records and an incomplete
set of requested units are rejected. Unknown fields and probe stderr do not
become API diagnostics. Observation never restarts services, clears failures,
reads journals or exposes configuration credentials.

`ok` describes the observed daemon, not successful SSH authentication or ingress
isolation. `disabled` describes configured intent, not an independent packet
scan. Listener and boot-assessment acceptance need the real VM below.

## Host evidence

Logs are retained in the private pipeline's ignored
`work/audit-fixes-20261113.O9Vnp70C/`:

| Check | Result | Log |
| --- | --- | --- |
| Focused health tests | 12 passed, 0 failed | `ssh-health-scoped-v1.log` |
| Focused formatting | Passed | `ssh-health-fmt-v1.log` |
| Complete Rust workspace | 1,209 passed, 0 failed, 0 ignored | `ssh-endpoint-combined-full-host-v1.log` |
| All-target Clippy, warnings denied | Passed | `ssh-endpoint-combined-clippy-v1.log` |
| Workspace formatting | Passed | `ssh-endpoint-combined-fmt-v1.log` |

The focused cases include default-enabled healthy SSH, eight non-running/error
states with an empty failed-unit list, explicit disablement, missing/error and
partial observations, unknown configuration, strict service parsing and secret
marker exclusion. Existing command deadline and output-limit checks also pass.
The complete run includes the separately owned web endpoint failure-atomicity
changes; it ran against stable source before later API advisory work.

`src/health.rs` SHA-256:
`6a0e89e6ecd23eb494265cd8cc54f9a78025bf97d350ef4a5fa2d28c33dc84b1`.
The simultaneously tested `src/session.rs` SHA-256 is
`793053b831f2fa0f4b253c871e358adc8cfffbdb1b8683032a5d1193b0d9993e`.

The full host command used two Cargo build jobs and the existing independently
qualified password helper and libcrypt pins. No production secret or runtime
configuration was changed.

## Packaged acceptance

The separate frozen `ssh-listen-boot` cohort passed actual delayed address
assignment and reboot recovery, wrong-address health warnings despite an empty
failed-unit list, boot-complete refusal, recovery and explicit disabled-SSH
exemption. It exercised the authenticated health API, remote listener and host
key continuity, not only pure host tests. Exact hashes, timings and remaining
adjacent checks are in [the integration receipt](qa-ssh-delayed-address-2026-11-15.md).
