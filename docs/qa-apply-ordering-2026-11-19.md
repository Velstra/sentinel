# First provisioning and protected CLI reads

This follow-up is not 1.0.0 release approval. The outstanding dataplane and
exact-image gates in [the release findings](qa-release-findings-2026-11-18.md)
still apply.

## Changes

- Dataplane launch settings are installed before activation. Launch-only
  changes force restart; rollback restores the old environment before recovery.
  Failed first activation also removes the candidate launch settings.
- Firewall protection still precedes link activation. Network addresses now
  precede synchronous routing convergence. A routing failure reconciles the
  last-good network and restores the old firewall hooks before restoring Wren
  again. The old uplink can be held down until those hooks are restored. HA
  guard recovery remains last; fencing is not weakened to make rollback pass.
- Live CLI sessions read protected saved/running intent through the existing
  bounded, no-symlink privileged reader. File permissions and viewer sudo rules
  are not broadened. JSON loading and offline non-escalation remain covered.
- Viewer `show version` reads udev filesystem metadata without sudo; boot unlock
  still reads block signatures as root. Missing metadata is unknown, never an
  assertion that the data is plaintext. This informational view does not certify
  Secure Boot or the installed image.

## Checks

- Local: 1,279 Rust unit tests, four offline CLI tests, formatting and
  warning-denying all-target Clippy passed.
- Browser: 31 workflow assertions passed at desktop/mobile widths against the
  local API in no-apply mode, including no JavaScript errors. This is not live
  routing/UI parity certification.
- Release tooling: 20 community-release contract tests passed. All 176 exported
  checks passed flake evaluation (`nix flake check --no-build`). Evaluation is
  not a VM execution result.
- `apply-ordering` is a mandatory release check. It provisions a previously
  unzoned NIC with no `eth0`, installs its address and dependent route in one
  admin commit, then checks real traffic and failed-route rollback.
- `data-status-readonly` uses a disposable real disk with ext4 and LUKS headers
  to compare root/viewer diagnostics and prove viewers still cannot read the
  block device or run sudo. Its linear mapper supplies test topology only;
  installer checks separately cover real image boots and encrypted/mirrored data.

## Runtime qualification

The first `data-status-readonly` run passed in 57.62 seconds, exercising real
ext4/LUKS signatures and missing metadata as root and an unprivileged viewer.
Its log SHA-256 is
`e62654203800e4217ac8b338bd83d4ae83b93920dea49bc6a65688a5a264fbf5`.

The first provisioning fixture failed during setup: it omitted the image's
boot-health module, so its supposedly unprovisioned appliance had started the
dataplane. That is not a product pass. The failed log is preserved with SHA-256
`bc656d2e3010c0ddd2e9e3b348a451de248b48a9c6891d794863afc8946f9a8d`.
The corrected fixture imports the same boot-health module as the image.

The source cohort `/nix/store/vvf10sybdz8x4ccsz7sjd939mlk0210x-source` passed
`apply-ordering` (164.75s), `data-status-readonly` (56.64s),
`wren-static-reload` (208.48s), `boothealth` (171.79s) and `commit` (218.92s).

An additional uplink-migration rollback case exposed a real gap despite those
passes: recovery tried Wren before the old firewall hooks brought the original
NIC back up. The CLI correctly reported incomplete recovery. That failed log
has SHA-256 `36dd29476acbf5d12f14ca683d75d217bb9e20ec05fa65604f6afcd290cb61fd`.
The expanded test is retained, not weakened.

The corrected recovery ordering is frozen in
`/nix/store/c0ncyq0wih9z76w9h2cshdwxh6r8vlnl-source`. The final rerun passed:

| Check | VM script duration |
| --- | ---: |
| `apply-ordering`, including failed uplink migration | 232.32s |
| `data-status-readonly` | 56.09s |
| `wren-static-reload` (CLI/API and actual FIB/packets) | 227.42s |
| `boothealth` | 177.38s |
| `commit` | 225.87s |
| `ipsec` | 134.23s |
| `vti` | 212.58s |

The same source passed 1,279 release-profile Rust unit tests and four offline
CLI tests, the 31 browser workflow assertions, and all 176 flake evaluations.
[Derivation identities and full log digests](qa-apply-ordering-2026-11-19.json)
record the targeted VM receipts. The extended installer assertions were not
rerun in this batch; direct block-device diagnostics do not certify installer
or mirrored-image behavior.

No full-catalog runtime, final signed-image, hardware or production deployment
claim is made here.
