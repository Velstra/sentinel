# Explicit expiry maintenance: bounded verification

**The standalone maintenance path passed its targeted tests. The release gate
remains failed.** This change does not repair LRU eviction or 20,000-flow
admission/retention. See the [pressure retest](qa-nat-pressure-retest-2026-11-18.md).

## What changed

The privileged agent query socket implements `expire-state <nat|firewall>
<scan-limit>`. It refuses HA/replication, stale applied intent, non-ready gates,
incomplete generations and generation overflow. The firewall writer lock and
NAT handle exclusion protect one continuously closed admission interval. A
kernel reader drain precedes the monotonic expiry sample. Candidates are read
again before individual deletion; reverse keys are not implicitly removed.

Failures after attempted closure leave an explicit failure diagnostic. Failure
to write the failed-state fence is reported as uncertain forwarding, not a
healthy result. Only successful configuration reconciliation clears the fault.

## Executed checks

All compilation and functional tests ran on the remote builder/its KVM guests.
The production packet object remained byte-identical; only userspace changed.

- Agent binary compiled; scoped Clippy passed with `-D warnings`.
- 220 agent tests passed in a real VM; eight pre-existing privileged tests
  remained ignored. The separate test executable passed seven non-privileged
  tests, including the same maintenance protocol tests and BTF helpers; these
  are not seven additional unique product capabilities.
- A separate instrumented four-entry HASH map passed 16 cycles: full live state
  is retained, expired state alone is reclaimed, a fresh reverse survives, the
  freed slot accepts a new owner, and a limited scan reports incompleteness.
  This uses real kernel map operations and the reader barrier, not packet load.
- Two VMs ran the real query handler and attached normal XDP/TC programs.
  Invalid command forms were rejected without losing readiness. Firewall
  maintenance examined four entries and removed only the expired one; NAT
  maintenance examined two and removed only the expired one. Fresh comparison
  records remained byte-identical, with unchanged map IDs.
- One original TCP socket exchanged nonce-bearing messages before and after
  both operations. It was deliberately idle during maintenance. This proves
  preservation across the operation, not lossless continuous traffic or HA.

Observed closed-transaction times in that two-VM case were 7.139176 ms for
firewall state and 24.341083 ms for NAT. These are individual observations,
not a latency guarantee. The tiny-map fixture is not a pressure benchmark.

## Evidence identity

Agent executable SHA-256:
`cf1c5596377e60ca50d5d64c12e8400b193ae9c161d12e61cef474c26e18bdf9`.

Maintenance implementation SHA-256:
`16a128441c096203791a6bfbf447c72c5bdb41deae76534225f4c0298af0b579`.

Normal packet object SHA-256:
`6bab5656e2419e6d54d5a02b8b406851ebe52852d0c9dbb741e744b55236fd6e`.

Instrumented HASH4 object SHA-256:
`aa7d8348940a3e9ea749c2a3e4d89ff6291fd23e9def1525933334c8ea8b926d`.

Kernel-test log SHA-256:
`bda251ed2bd47fb3d2a300ce0e440a22b4f0320d9ceafb337be85c2cd9dcdcf8`.

Live-test log SHA-256:
`f1f27d426edd4ef0b7ba246331d6a70693f8bc231dff3db383b92f49a5a01a34`.

Both use guest kernel 6.12.113. Fresh nonces force actual VM execution; completed
logs and raw JSON were archived with every transferred file hash verified.
Earlier packaging, type-inference, sandbox-environment and test-argument failures
were retained. Environment-dependent unit tests were moved into the VM, not
skipped; the live fixture's invalid `--mode` was corrected to `--xdp-mode`.

## Limits and next tests

The scan is a bounded prefix without a persistent cursor; repeated small scans
do not guarantee whole-map coverage. There is no background sweep or SYN-proxy
collector. The work budget is not a hard bound on kernel calls or reader drain.
Failure injection covers the transaction protocol, not every kernel syscall
failure while packets race a refresh. Deterministic refresh/fence races,
kernel read/delete/reopen failures, large-map interruption budgets and HA
compatibility still need dedicated execution before broader qualification.
No production pins, signed images or release approval changed.
