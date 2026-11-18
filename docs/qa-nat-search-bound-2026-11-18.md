# NAT pressure: discovery cost and retained state

**Release gate: still failed.** The bounded-discovery candidate admits every
requested connection within the unchanged opening budget. It does not fix
firewall-state eviction.

## Measured candidate

Normal object SHA-256:
`8b0d3f1b27ffd49c5d506b76376f818ff7a1d55076aaec4bf87e2ee1322d371b`.
Immutable source-manifest SHA-256:
`d30f013c6011a919364183e2940e516600131bd8d94331323104896c8426d953`.

All compilation and functional checks ran on the remote test builder. Three
live KVM guests supplied client, stateful router and backend. Workload counts,
45-second budgets, both stateful policies and 65,536-entry map capacities were
unchanged from the [failed baseline](qa-nat-pressure-retest-2026-11-18.md).
Complete logs and raw outputs were archived with every file hash verified.

| Requested | Initial echoes | Held echoes | Firewall records |
| ---: | ---: | ---: | ---: |
| 1 | 1 | 1 | 4 |
| 64 | 64 | 64 | 256 |
| 12,000 | 12,000 | 12,000 | 48,000 |
| 15,000 | 15,000 | 15,000 | 60,000 |
| 16,000 | 16,000 | 16,000 | 64,000 |
| 17,000 | 17,000 | 16,320 | 65,280 |
| 20,000 | 20,000 | 16,324 | 65,306 |

There are no opening failures, skipped opening attempts or observed external
tuple aliases. Map IDs remain unchanged throughout. At 20,000, 3,679 owned NAT
entries lack expected firewall roles; 3,676 streams time out and three still
echo. Snapshots are not atomic: these
findings are not an exact eviction count. Four firewall roles per connection
still exceed the fixed table's capacity above 16,384 complete connections.

Pressure log SHA-256:
`95e1c89b1ad967f73114394ad13990c7600c46120f5cb28ed053436467fb4d72`.
The final 158-file evidence archive, including host-load samples, has SHA-256
`bd4281d4f6a0e1f1e02d7a933bb4b883f8d293b3e88a370c0aba20beb462ea9a`.

## Completed prerequisite checks

- All 21 programs load on each of kernels 6.6.159, 6.12.113 and 6.18.57.
- 252 common unit tests, 14 documentation tests and three writer-inventory
  guards pass. The guards are not concurrent packet-race proofs.
- The nine-collider assertions pass all initial and held echoes. The additional
  live test observes summary 15 (16 candidates), then a real
  ICMP NAT writer invalidates it to 65,535. The same nine original TCP sockets
  still echo after full-domain discovery is restored.
- The compiler-signature probes pass with the release nightly and Rust 1.95
  (bootstrap only for metadata probing), including host-target bypass and an
  expected compiler rejection. Workflow `actionlint` passes. This is not a
  claim that all CI jobs or the whole workspace Clippy gate passed.

## Earlier candidate and scope

Before the compiler-compatibility adjustment, object
`c1ec3269f9592401c6dffb7bb4d05ef82cf8d9bdaa15a4daf7e3fe51b7af4a6e`
also admitted 20,000 and retained 16,321. Its unchanged nine-collider test and
these additional regressions passed:

- 128 simultaneous native TCP sockets; removing an earlier unrelated
  reservation preserves the original ninth socket; a 65-port CGNAT block
  retains all 65 admitted sockets while rejecting the 66th without replacement.

Initial compiler-interface errors, test-script indentation and a missing test
linker are preserved as failures, not counted as packet tests. After the
compatibility adjustment, the three-kernel loads, common/guard tests, live
nine-collider/invalidation test and complete pressure workload were repeated
against the current object identified above.

The speedup is scoped to the standalone default port domain. Other NAT writers
can permanently force full discovery until service restart. The fallback is
tested for correctness, not for 20,000-flow opening performance. This is not a
general guarantee against opening-budget exhaustion in every mixed workload.

## Remaining work

Retain complete firewall flows without live-state eviction; establish bounded
admission/reclamation and HA compatibility. A more compact representation is
needed to hold 20,000 stateful NAT connections at the existing entry limit.
Neither a larger table nor disabled stateful policy was used to pass a test.
Production pins, combined candidate, final signed image and release are not
qualified by this report.
