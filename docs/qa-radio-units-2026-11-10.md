# Radio unit and reference-client regression

The access-point, station and cellular templates placed
`StartLimitIntervalSec=0` inside `[Service]`. systemd ignores that placement;
the declared unlimited retry policy was therefore not effective. The option
now belongs to `unitConfig`, producing `[Unit]`, without changing daemon
commands, restart delays, activation conditions or privilege policy.

The wireless VM fixture independently used bare `wpa_cli` against a manually
created reference station. The pinned Nixpkgs package changes both its default
remote control and local client-socket directories. The reference now creates
separate private control/client paths, explicitly configures the remote path
and supplies both `-p` and `-s`. The command must succeed before its exact
completed-state assertion is evaluated. Production station configuration and
package defaults are not changed to accommodate this reference client.

The existing wireless check retains normal-admin CLI configuration, private
key-file permissions, AP kernel mode, a namespace-isolated station, actual
association, IP traffic over the simulated radios and normal-admin removal.
It additionally checks systemd's effective start-limit interval for all three
templates. The pure five-case regression checks scope and embedded-driver
syntax; it does not establish live radio or cellular behavior.

The VM uses mac80211_hwsim, not a physical chipset or cellular modem. Its AP
case does not certify Sentinel's station role, AP/station role transitions,
WPA3 hardware interoperability or modem behavior. Those remain separate
qualification requirements. Prepared checks are not reported as executed.

## Executed verification

On 2026-11-10 both actual Nix VM checks passed against frozen source
`l8kwblyvcyribja162xnx3d61ay7f0pn-source` (NAR
`sha256-CSqkqVaEhEwYsO+rnfckrnlE1P288kHiQhJj1zp/xQg=`):

- Wireless: 45.06 seconds; effective systemd start-limit properties, normal
  admin configuration, key permissions, association, namespace-isolated IP
  traffic and admin removal/daemon shutdown all passed. Output:
  `qrigigbara35mp74cs62spzg9sgh6d5h-vm-test-run-sentinel-wireless`.
- WWAN: 49.22 seconds; correct modem selection, SIM-path PIN unlock, dropped
  bearer redial, removal of PIN and bearer deletion passed against the command
  double. Output: `8j7ahljqbrrp3jg9dmkpisa6kvr709y0-vm-test-run-sentinel-wwan`.
- The same build ran 906 Rust tests: all passed, none ignored. Five dedicated
  source regressions also passed independently.

These results establish the stated VM behaviors, not physical chipset/modem
certification, station-role transitions or the entire release gate.

Primary references: [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
and the pinned [Nixpkgs supplicant patch](https://github.com/NixOS/nixpkgs/blob/1f607aa79b6356ed45d3cd3c8079c196e79efa2c/pkgs/os-specific/linux/wpa_supplicant/unprivileged-daemon.patch).
