# Console verification

These suites launch real Chromium against a real Sentinel API. The API uses a
throwaway TOML document, a loopback listener and `--no-apply`: no workstation
networking, physical firewall or production configuration is changed. Node and
Chromium are build/test dependencies, never appliance runtime dependencies.

From the repository root, run the complete frontend gate:

```sh
cargo build
(
  for suite in ux layout console react health ha-mode peer; do
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
| `console` | Navigation/tabs, all create panels, staged changes, real persistence/defaults, authentication/permissions, dialog flows, secrets and CLI-field inventory |
| `react` | Dashboard/flows/editor, safe apply/confirm/expiry, drafts, mobile navigation, both themes and sensitive-state cleanup |
| `health` | Real health API; explicitly synthetic clock/TPM/failure cases; retry and NTP navigation |
| `ha-mode` | Election controls, risk guidance, canonical staging, invalid timing and narrow themes; does not enroll a cluster |
| `peer` | Two disposable APIs with real pinned HTTPS, member observations, pin mismatch and session isolation |

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
