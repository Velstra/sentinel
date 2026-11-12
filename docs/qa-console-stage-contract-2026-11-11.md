# Console behavioral validation and field exposure

The former generic control walk emitted 217 commands but only four distinct
commands in the release candidate. It repeatedly queried hidden controls,
changed form inputs without pressing their Stage buttons, swallowed browser
evaluation failures and exempted broad classes of backend error messages.
A green result did not prove that the corresponding forms could be staged.

The replacement is an explicit behavioral contract shared by the main console
gate and a standalone Chromium suite. It exercises 76 planned form/value cases
across ten settings panels: system identity, firewall posture and timeouts,
BGP, OSPFv2/v3, DNS, NTP, SSH and the web service. Requested changes must be
emitted by the real form and a physical Stage click, accepted by the real API
with an exact validation-only reply, and accepted separately by the installed
CLI's actual `configure --no-apply`/`commit` validation path. No commands are
synthesized in place of staging, no API calls are stubbed and no prerequisite
error is waived. Known-value Stage feedback is measured separately; it does
not count as a changed-command API/CLI proof.

Invalid SSH ports and update URLs must be rejected independently by inline
form validation, the real API and the installed CLI. Synthetic malformed
reply checks separately prove that the test verifier cannot accept `ok:false`,
incomplete evidence or an unexpected applied/pending state. All saved-document
bytes must remain unchanged throughout this validation-only test.

The separate 537-field grammar inventory still requires every field to be
exposed. Its count is not relabeled as behavioral coverage. Neither inventory
nor this finite contract proves every option/value combination, persistence,
native routing, packet filtering or physical HA. Those require their own
explicit scenarios and image-bound VM/hardware evidence.

Run the focused suite with a freshly built binary:

```sh
CONSOLE_TEST_FILE=stage-contract.test.mjs \
  tests/console/run.sh target/debug/sentinel
```

`CONSOLE_SCREENSHOTS` optionally retains the exact planned cases, actual staged
commands, dual-validator results, no-op observations and negative cases in
`stage-contract.json`. A missing case or collapsed distinct-command inventory
fails the gate; evidence is not inferred from the rendered field count.

## Update URL finding and shared fix

The strict browser contract reproduced an actual discrepancy: the default
channel form staged `javascript:alert(1)`, although configuration validation
permits only `https://` or `file://`. Native URL syntax validation alone accepts
other schemes. The shared `bindField` now captures update-field ownership when
the form is built and applies that existing backend policy to default, named
Add and named Edit forms. Generic URL syntax and authoritative API/CLI checks
remain unchanged; file mirrors are still supported.

`update-url.mjs`, included in the normal `ux` gate, explicitly rejects
JavaScript, HTTP and FTP through all three interfaces. It also stages and
validates HTTPS and offline mirrors through all three forms at 1440, 390 and
320 CSS pixels. Correction, native Enter activation, value retention,
associated inline errors, first-error focus and geometry are checked in real
Chromium. Only a private `--no-apply` fixture is seeded/restored with the actual
CLI; no host network, appliance or update channel is modified.

Focused local results on the newly built source: 81/81 Stage assertions
(76 form/value cases, 70 distinct changed commands) and 48/48 URL assertions.
Those are finite validation proofs, not OTA download/reboot or exhaustive
537-option behavioral certification. Source/binary receipts and broader gate
results are recorded separately with the qualification evidence.

The first combined Nix console attempt passed its 132 preceding assertions but
timed out at navigation: the negative URL test had correctly left an unstaged
invalid draft, activating the existing `beforeunload` protection. The contract
now exercises the real Refresh control and verifies a replacement form, empty
draft/staging state and unchanged saved bytes before handing the page to the
next test. It does not disable the product guard or auto-accept a leave dialog.
This additional cleanup assertion is included in the 81-case focused result;
the failed 132/133 combined attempt remains retained, not relabeled green.
