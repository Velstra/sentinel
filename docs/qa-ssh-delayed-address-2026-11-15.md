# SSH readiness with delayed DHCP

Status: source, host, all six public acceptance targets and the private
Enterprise product-health VM pass. Not final-image certification.
Not release-image certification.

## Change

An explicit SSH listen address can be assigned after sshd starts. Previously,
the rapid restart loop exhausted systemd's start limit before the DHCP lease
arrived. SSH stayed unavailable until an operator intervened.

The appliance retries every five seconds without a start-rate lockout. It never
changes or widens the configured listen address. A failed bind can therefore
stay `activating/auto-restart`, absent from `systemctl --failed`. Both the health
API and the boot verifier must independently require enabled SSH to be ready.
Explicitly disabled SSH is not a failure; omitted SSH settings mean enabled.

The systemd settings were checked against its upstream unit/service
documentation through Context7. The external audit agent supplied the initial
DHCP reproduction and restart patch; this integration adds the health and boot
assessment safeguards and reruns the fixture against the integrated sources.

## Checks

- Python boot-health regression: six failing subcases before the readiness
  check; all 13 tests pass after it. Covers omitted/empty/enabled/disabled SSH
  settings and inactive services independent of the failed-unit list.
- `ssh-listen-boot`: real two-VM delayed DHCP, runtime CLI save, cold reboot,
  exact listener, persistent host key, authenticated health API, permanent bad
  address, recovery, and deliberate disable. The bad-address case must block
  the real boot-complete dependency graph without starting the blessing unit.
- Adjacent regression targets: `ssh-policy`, `ssh-persistence`,
  `management-ingress`, `boothealth` and `boothealth-unit`.

The combined source passes 1,209 workspace tests, Clippy with warnings denied,
and format checks. The 13 boot-health tests also pass as a Nix derivation. The
Enterprise adapter's ten Python tests pass; it delegates readiness to the same
immutable public checker. Its VM service-failure loop now includes sshd.

The frozen Sentinel seed is `hdvsx6mb693if5d1218hd2xw4bbh1kmg-source`, with
Fabric `dy543yln5gmyv57m1zgaf67w922kqhyd-source` (v5 diagnostic ELF SHA-256
`a3dce51a50b111772c5a8f15baed51463843f22ca7360cfe68f5bd6f77465b40`) and Wren
`k4wbkqh8qb5j42anh6s6wwzvr1zzvvr3-source`. Production pins are unchanged.
Logs use the `ssh-readiness-v1-` prefix in the private audit work directory.
The external agent's prior VM runs are not certificates for this integration.

## Packaged result

The real delayed-DHCP test passed in 192.44 seconds. The first explicit-address
bind failed at 10.462 seconds, DHCP supplied the address at 26.098 seconds, and
sshd was running at 26.223 seconds after three retries. Only `10.78.0.11:22`
listened; the host key matched the pre-reboot key. Authenticated health reported
`ok` and the actual boot-complete dependency graph succeeded.

With the address deliberately absent, retries continued with no listeners and
an empty failed-unit list. Health correctly reported `ssh-service-inactive`;
boot-complete failed without starting the blessing unit. Restoring the address
recovered readiness. Explicit disablement stopped retries, reported `disabled`
and passed boot assessment.

Receipt: `/nix/store/5f2m3dp2f6fr2ppabpndjrfz9a905mdr-vm-test-run-sentinel-ssh-listen-address-before-dhcp-lease/ssh-listen-boot.json`.
SHA-256: `d5f52234b676f5654890714cf457d1477698d6a44c8b5dc7aa5ea43151bd73f5`.
Packaged Sentinel ELF SHA-256:
`ba1f8bfcb652f8d9123d20f2846f1a1712f002c6fd2dfc16e7f471ed493f7ec4`.
Its packaged test phase also passed all 1,209 Rust tests. Later API advisory
and React changes are not part of this frozen package.

All six public targets passed against the same cohort:

| Target | Evidence |
| --- | --- |
| `ssh-listen-boot` | Delayed DHCP, exact listener, key continuity, bad-address refusal, recovery, disablement |
| `boothealth` | Real public health/boot dependency checks |
| `ssh-policy` | Declarative boot and live SSH policy |
| `ssh-persistence` | Host keys and offered identity survive cold boots |
| `management-ingress` | Explicit IPv4/IPv6 ingress ACLs with allowed management/forwarding controls and reboot |
| `boothealth-unit` | All 13 Python tests in the Nix derivation |

Batch `run-ssh-readiness-v1.sh` exited zero. The ingress test proves explicit
ACL behavior, not automatic isolation merely from setting a listen address.

The private Enterprise adapter VM also passed in 119.48 seconds against this
same public cohort. It tests factory readiness, saved hostname across a real
60-second rollback and reboot, live activation, detached XDP refusal without
rebooting a permanent boot, malformed desired-state refusal, and each stopped
configured service including SSH. The adapter uses the immutable public checker.
Output: `/nix/store/s13vl0p6yc7x7y4a9g9g658h3cqpqcgr-vm-test-run-enterprise-product-health`.
Retained log `ssh-readiness-v1-enterprise-product-health.log` SHA-256:
`93441f0a7b1c8b0a46600d9ad00b6b01cc4c970e5a0de7e99286e15619f2cf9c`.

## Boundaries

The normal boot-readiness deadline remains 60 seconds. An enabled SSH daemon
whose required address does not arrive within that interval withholds boot
assessment, even if DHCP would eventually recover. This is not a proof of EFI
boot counting, all address families, the signed image, or hardware behavior.
Binding to an address does not replace ingress firewall policy.
