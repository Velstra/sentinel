# Console tests

Runs Chromium against disposable Sentinel APIs with `--no-apply`.
It does not change host networking or production configuration.

Requires Rust, Node.js and Chromium/Chrome. From the repository root:

```sh
npm ci --prefix ui
npm run format:check --prefix ui
npm run build --prefix ui
npm test --prefix ui
npm run check:assets --prefix ui
cargo build --locked
```

Run one browser suite:

```sh
CONSOLE_TEST_FILE=react.test.mjs bash tests/console/run.sh target/debug/sentinel
```

Run the complete browser set, sequentially:

```sh
(
for suite in ux layout console react health ha-mode peer archive; do
  CONSOLE_TEST_FILE="$suite.test.mjs" bash tests/console/run.sh target/debug/sentinel || exit 1
done
)
```

Set `CHROMIUM` for a nonstandard browser path, or `CONSOLE_PORT` for a free
loopback port. Do not run suites against the same port concurrently.

[Suite coverage, screenshots and evidence limits](../../docs/console-testing.md).
Browser passes do not certify native HA, packet forwarding or a release image.
