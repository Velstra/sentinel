# Read-only local observations

The November 14 retest found a real CLI/API mismatch: a read-only account could
read the API but could not read protected configuration, routing or flow state
over SSH. Restoring wheel or granting a generic privileged socket client would
also grant mutation capabilities. Neither is used here.

## Boundary

The installed CLI requests one of six literal capabilities:

| User command | Capability |
| --- | --- |
| `show configuration` | `configuration` |
| `show configuration commands` | `configuration-commands` |
| `show ip bgp summary` | `bgp-summary` |
| `show flows` | `flows` |
| `show firewall statistics` | `firewall-statistics` |
| `show firewall capacity` | `firewall-capacity` |

Sudoers names the exact unwrapped store executable and each complete argument
vector, with `NOPASSWD` and `NOSETENV`. It does not authorize general `show`,
Wren, a shell, file reads, arbitrary socket paths or agent control operations.
The capability requires sudo's numeric origin UID, the matching current local
account, active durable managed-account ownership and the current API account
grant. It checks that grant again before releasing output. Retired accounts,
UID reuse, missing ownership or corrupt protected state fail closed.

Read-only output uses the existing `NoSecrets` renderer and secret scrubber;
account-administrator capability output never becomes the machine credential.
Protected parse errors and failed collector output are not disclosed. Existing
wheel accounts retain their previous ordinary CLI privileges, including the
factory recovery administrator. Checking their actual kernel groups only
chooses that existing path; it does not grant privileges to another account.

Collectors have fixed inputs, cleared environments, bounded output and an
eight-second collection deadline. BGP uses the pinned Wren read client directly;
the other collectors render configuration or query a fixed agent socket. They
are leaf processes with a Linux parent-death signal and a race-closing parent
PID check. A nonblocking root-owned permit prevents concurrent collectors.

## Evidence and limits

The observation cohort's host suite passed 1,171 tests. It includes literal-argument refusal,
current grant/managed-UID revocation, opaque parse errors, fixed child inputs,
unsafe/concurrent permit refusal, output/deadline limits and real collector
termination when its helper parent is killed.

The separate `nix/observe-readonly-test.nix` two-VM fixture passed in 42.80 seconds
on kernel 6.12.113. It verified installed sudoers and real SSH, established eBGP,
32 echoed DNAT datagrams (9,216 bytes), live map/counter reads, API parity,
forged environment and generic privilege refusals, grant/UID revocation,
opaque protected parse errors and missing-daemon recovery. Its management link
is separate from the dataplane, so stopping the agent does not prevent the
test from reaching the helper. The receipt is
`/nix/store/87z634r23yaqvf8phbsxpcm6ljvmw9qz-vm-test-run-sentinel-six-local-readonly-capabilities/observe-readonly.json`.

The first run correctly denied a revoked grant but captured stdout only,
missing the stderr diagnostic. V2 captures both streams, retaining all denial
and nondisclosure assertions. No product change or assertion waiver was needed.
Fixture SHA-256:
`dfe5f6e73775488fb7137f70c0a2ab8b8b0f5558017108ce48b8339c3aa1de13`.
The frozen core also passes 1,171 Nix-packaged tests; executable SHA-256:
`ad68f4957df72faa3509120f147157966e23f6b95ecc78ffc01a464ff0498fc7`.

This is a six-command repair, not authorization for every operational CLI view
or final signed-image/release certification. This cohort predates the separate
API failed-show disclosure fix; it does not certify that later source change.
