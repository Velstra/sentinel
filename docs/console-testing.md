# Console test reference

Run the web console against the real API with a disposable configuration and the no-apply backend. Node.js and Chromium are workstation test dependencies.

## Run a focused suite

From the repository root:

```sh
cargo build --locked
CONSOLE_TEST_FILE=layout.test.mjs tests/console/run.sh target/debug/sentinel
```

Use another `CONSOLE_PORT` if the loopback port is occupied. Give each concurrent suite a separate configuration and listener. The layout suite checks desktop and narrow-screen controls.

| Suite | Choose it for |
|---|---|
| `ux`, `layout` | Keyboard controls, form validation, mobile and desktop layout. |
| `console`, `stage-contract` | Stage a configuration and exercise the real CLI/API validation path. |
| `react`, `health` | Drafts, confirmation and expiry, health status and unavailable probes. |
| `ha-mode`, `peer` | Election controls, peer observations and per-member session behavior. |
| `archive` | Save, inspect and restore configuration revisions. |

## Run the full frontend gate

```sh
cargo build
(
  for suite in ux layout console react health ha-mode peer archive; do
    CONSOLE_TEST_FILE="$suite.test.mjs" tests/console/run.sh target/debug/sentinel || exit 1
  done
)
```

Collect screenshots for a focused layout run with `CONSOLE_SCREENSHOTS=/absolute/path/to/owned-evidence`. A no-apply API can report missing OS services; use appliance VM checks when evaluating real dataplane, failover or boot behavior.
