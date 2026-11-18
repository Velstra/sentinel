# Firewall state publication — 18 November 2026

Preparatory fail-closed repair, **not a capacity fix or release qualification**.
The preceding [20,000-flow stateful pressure gate](qa-nat-pressure-reference-2026-11-17.md)
remains red. No map type, size, timeout or HA state format changes here.

## Change

Firewall state writers previously ignored directional map insertion failures.
They now return an explicit outcome: no publication attempted, both helper
calls succeeded, or failure. All 17 current packet-path call sites inspect
failure and drop instead of forwarding. Missing per-CPU scratch also fails
closed. Existing non-opener, unsupported-protocol and pre-existing seed no-ops
remain no-ops; they do not prove that both directions exist.

The second insert is not attempted if the first fails. If only the second
fails, the first is deliberately retained: deleting by key is not safe rollback
when another CPU may have advanced or replaced it. A post-SNAT failure drops the
modified skb before transmission, but does not undo NAT or partial firewall
state. Successful LRU inserts can still evict live entries; this repair cannot
prevent that.

The append-only counter `firewall_state_write_failed` identifies the reason.
Aggregate drops remain counted once by the existing egress/ingress/SYN-proxy
counter. Direct policy events now include publication failure before reporting
their verdict. Earlier accepted policy events can still precede a failure in a
later NAT or cookie tail: they are not final-wire-success evidence. ICMP's
successful masquerade counter is emitted only after publication succeeds.

SYN-proxy admission may leave its previously inserted pending splice after a
firewall write failure. It remains fail-closed and can prevent immediate retry;
transactional recovery is not implemented here. Existing reset deletion races,
paired publication races, expiry collection and HA writer coordination remain
separate work.

## Verification

- 249 common Rust tests and 14 doctests pass, including five ordered-write
  fault/no-rollback tests. These inject helper results, not kernel packet faults.
- 214 agent tests pass; eight privileged tests remain ignored locally.
- Five source-wiring guards cover every writer call, the shared fallible helper,
  explicit no-op/failure separation and ICMP counter ordering.
- Host eBPF compilation, scoped Clippy, rustfmt and workflow lint pass.
  A separate host `cargo clippy -p velstra-ebpf -- -D warnings` attempt failed
  with 233 lints, including generic-map borrow and same-type-cast warnings.
  No whole-workspace Clippy pass is claimed; blindly replacing eBPF references
  with by-value copies is unsafe for the verifier's stack constraints.
- The first object (`8509360f780f1876de3fac2d1592c5c8378de067cef2e316a9450d8a5885a488`)
  failed all three verifiers: the SRv6 bridge branch spilled an uninitialized
  optional rewrite payload. Explicitly initialized rewrite fields removed that
  error. That intermediate object passed 6.12/6.18 but failed 6.6 at 544 bytes
  of cumulative BPF stack (512-byte limit).
- ELF review identified nested compiler-generated `memset` calls while creating
  IPv4 keys. Direct, aligned scalar initialization in the existing per-CPU slot
  removes those extra frames without changing key layout or bytes.
- Current frozen candidate: `gxylrax3l93l6cl8azv7k4airql673r9-manifest.json`.
  Object SHA-256: `6bab5656e2419e6d54d5a02b8b406851ebe52852d0c9dbb741e744b55236fd6e`.
  All 21 programs pass on 6.6.159, 6.12.113 and 6.18.57 in remotely hosted
  KVM guests (completed 10:57 UTC). All three raw receipts were copied and
  transport hashes verified. Normal-object firewall expiry, all 11 NAT lifecycle
  cases, strict nine-collider admission/retention and the 128-flow concurrency
  regression also pass; their raw outputs were copied and hashes verified.
  SYN proxy, egress and IPv6-rule tests also pass. These legacy tests emit no
  raw output files; their full logs and derivations, not packet JSON receipts,
  are the retained evidence. Hairpin, RELATED ICMP and the broad NAT/CLI suite
  also pass (11:45 UTC). RELATED covers 19 reports and 145 observations with
  no reported failures. RELATED and NAT raw files and all three full logs were
  copied and SHA-256 verified; hairpin emits no raw files. The same-candidate
  mixed-source and same-source causal HA checks also pass. Thus all twelve
  selected normal-object packet suites and both causal HA variants have a
  passing run; the two original fixture failures remain preserved below.
- The new privileged harness has 18 cases across IPv4 ingress, egress, TCP NAT
  and ICMP NAT. Its four host tests and all 18 kernel cases pass on 6.12.113
  (11:01 UTC, source-bound instrumented object
  `aa7d8348940a3e9ea749c2a3e4d89ff6291fd23e9def1525933334c8ea8b926d`).
  It deliberately replaces only `FW_FLOWS` with an ordinary four-entry HASH
  to force first/second insertion failures. This is **instrumented-object**
  evidence, not production LRU retention or exact-release-object qualification.
  The VM verifies both source stamps and requires the exact case matrix.
  Every packet starts with checked `0xa5` scratch contents on all possible CPUs;
  exact directional keys verify that IPv4 initialization clears old tails.
  Packet bytes, counters, preserved/partial states and source identities are
  retained in the raw receipt, copied and transport-hash verified.

The shared outcome contract follows Aya's fallible map insertion API:
[Aya eBPF API](https://github.com/aya-rs/aya/blob/main/xtask/public-api/aya-ebpf.txt).
Helper success does not imply atomic publication or retained ownership.

## Rejected capture run

The first normal-object ICMP ownership run selected an older frozen fixture.
Its ingress listener ended before the driver invoked the client. The preserved
receipt reports `delivery=true`, `translated=true`, `arrived=false`: the client
received the correct checksum-valid reply and the backend observed the correct
translated request, but the ingress witness was empty. This run remains failed;
it cannot qualify the ownership matrix.

The private wrapper now selects the already-reviewed synchronized capture
fixture. It requires both listeners to stay alive until the client finishes,
then stops them explicitly and rejects premature expiry. The one-second client
deadline and all delivery/ownership assertions are unchanged; counter checks
add requirements. A local selection guard prevents accidental reuse of the
old wrapper. The same-candidate rerun passes all six ownership cases and their
positive controls (11:26 UTC), including the extra reason-counter checks.

## SRv6 startup race

The first SRv6 run fails its unchanged unicast counter oracle. Its three pings
were sent before the agent finished attaching interfaces: the fixture only
waited for systemd's active state, while the agent was still loading BPF.
The public test now also requires the fresh agent unit's live message, emitted
after successful attachment and configuration-gate reopening. The later
untrusted-peer restart receives the same readiness check. No packet count,
counter threshold or stimulus retry changed. The barrier-only rerun passes
(11:28 UTC): unicast, broadcast replication, routed traffic, non-gateway bridging
and untrusted-source rejection all satisfy the existing counter oracles. This
legacy fixture emits no packet receipts; the complete log is copied and its
hash verified. Both failed original runs remain retained, not relabelled green.

## Causal HA regression

Both private causal two-node variants pass on the same candidate (completed
11:51 UTC). The original TCP socket and translated tuple survive the forced
active-node failure. All raw files and complete logs were copied and SHA-256
verified.

| Variant | Promotion | Exchanges | Maximum echo gap | Preserved public tuple |
| --- | ---: | ---: | ---: | --- |
| Historical-source peer + candidate | 1.218 s | 375 | 1.773 s | `10.1.0.100:47009` |
| Candidate on both peers | 1.336 s | 376 | 1.781 s | `10.1.0.100:59268` |

Both meet the unchanged 1.5-second causal promotion bound. Promotion time and
maximum echo gap are different measurements, not interchangeable latency claims.
The historical peer is independently rebuilt from the specified historical
source; it is not asserted to be the byte-identical old QA7 binary. These results
do not waive earlier host-poll timing failures, qualify new HA allocator modes,
prove config-sync coverage, or resolve the intermittent witness root cause.

## Remaining gate

This tranche is complete, not the release audit. The previously failed full
20,000-flow stateful test was not rerun: fallible insertion does not stop
successful LRU eviction, and four firewall keys per flow exceed the unchanged
65,536-entry table at that workload. Safe complete-flow admission, retention,
reclamation and HA compatibility still need implementation and qualification.
Earlier unexplained below-capacity echo failures also remain open. No production
pin, deployed appliance or signed release image was changed or certified here.
