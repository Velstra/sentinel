# Console test reference

These suites launch real Chromium against a real Sentinel API. The API uses a
throwaway TOML document, a loopback listener and `--no-apply`: no workstation
networking, physical firewall or production configuration is changed. Node and
Chromium are build/test dependencies, never appliance runtime dependencies.

From the repository root, run the complete frontend gate:

```sh
cargo build
(
  for suite in ux layout console react health ha-mode peer archive; do
    CONSOLE_TEST_FILE="$suite.test.mjs" tests/console/run.sh target/debug/sentinel || exit 1
  done
)
```

For a single suite, omit the loop. Set `CONSOLE_PORT` if the default loopback
port 18099 is already occupied. Never run two suites against the same listener
or mutable configuration. The runner copies the binary for each API process so
a concurrent rebuild cannot change the executable underneath a running test.

| Suite | Scope |
| --- | --- |
| `ux` | Switch cancellation/keyboard activation; suggestion disclosure; invalid/valid numbers and URLs; rule port ranges; retryable diagnostics; identifier labels; shared alignment and HA mobile copy |
| `layout` | Every palette destination at 1440, 390 and 320 px; associated input labels; overlapping grid fields; clipped controls outside intentional scroll regions; no document overflow |
| `console` | Navigation/tabs, create panels, staged changes, persistence/defaults, authentication/permissions, dialog flows, secrets; includes the strict Stage contract below and a separate grammar-field exposure inventory |
| `stage-contract` | Explicit form/value cases: actual controls and physical Stage clicks, strict real API and installed CLI validation, unchanged-value feedback and invalid inputs. Runs inside `console`; standalone execution is available for focused diagnosis |
| `update-url` | Shared default/Add/Edit channel URL policy: invalid schemes, HTTPS/offline mirrors, keyboard Stage, associated error and focus recovery at 1440/390/320 px. Runs inside `ux`; standalone execution is available for diagnosis |
| `react` | Dashboard/flows/editor, safe apply/confirm/expiry, drafts, mobile navigation, both themes and sensitive-state cleanup |
| `health` | Real health API; explicitly synthetic clock/TPM/failure cases; retry and NTP navigation |
| `ha-mode` | Election controls, risk guidance, canonical staging, invalid timing and narrow themes; does not enroll a cluster |
| `peer` | Two disposable APIs with real pinned HTTPS, member observations, read-only peer write gates/local draft preservation, late renders, pin mismatch and session isolation; actual Refresh/sign-out lifecycle with explicitly synthetic delivery-state/delay fixtures, not native config-sync certification |
| `archive` | Actual CLI/UI saves and revision rollbacks, invalid Validate without a write, on-disk private modes and preserved credentials; the separate `archive-privacy` VM gate proves UID isolation and live OS behavior |

Optional evidence output:

```sh
CONSOLE_TEST_FILE=layout.test.mjs \
  CONSOLE_SCREENSHOTS=/absolute/path/to/owned-evidence \
  tests/console/run.sh
```

The layout JSON includes network responses and browser logs as well as JS
exceptions. Failed operational probes are not healthy measurements. A development
machine without the appliance's Wren/systemd/dataplane services may legitimately
return HTTP errors for those reads; the console must show unavailable status and
retain diagnostic details. Negative authentication/validation tests deliberately
produce refusal responses. Do not label those runs "zero HTTP errors", suppress
the evidence, or infer hardware/HA/data-plane certification from frontend tests.

Also run the production asset and code checks:

```sh
npm run format:check --prefix ui
npm run typecheck --prefix ui
npm test --prefix ui
npm run build --prefix ui
npm run check:assets --prefix ui
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```
