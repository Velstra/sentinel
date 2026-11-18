# NAT refusal diagnostics — 17 November 2026

Status: counter implementation locally and packet/verifier checked; allocator and
pressure gates still red. Pressure cause investigation continues.
This is not an allocator, state-retention or release-readiness repair.

## Changes

- Append two counter IDs without renumbering existing counters: bounded candidate
  exhaustion (46) and non-competing-insertion reservation error (47).
- Count refused ICMP NAT requests in aggregate egress drops, matching TCP/UDP.
- Keep reason counters out of the aggregate drop-rate sum. They count packet
  attempts, including retransmissions, not connections or map-full incidents.
- Add a strict live-statistics parser to the collision and ICMP packet tests.
  Missing, malformed, duplicate, overflowing or reset counters fail observation.
  Reads are not atomic across indexes/CPUs.
- Keep all original packet/ownership assertions. In particular, the ninth-flow
  collision is still required to work; its known failure is not an expected pass.
- Extend the pressure fixture with client/backend/firewall runtime observations
  around opening and probing, preserving kernel TCP counters, backend metrics,
  scheduler observations and live firewall statistics. No workload limits or
  pass criteria are relaxed.

Local checks: 212 Fabric agent tests passed (8 privileged tests ignored), 240
common tests and 14 doc tests passed; targeted clippy and Rust formatting passed.
The collision/counter, ICMP ownership and pressure-probe Python suites pass
33 tests, including explicit errors for missing/malformed runtime measurements.
Targeted Ruff passes. These are not substitutes for real packet tests.

## Full pressure rerun, before these counter changes

The seven phases all executed against the frozen `jsln3y...` source manifest;
the full gate failed. Both endpoint VMs still reported 12,000 established
sockets at the 12,000-flow phase. All 7,074 failed echoes in that phase were
timeouts with owned NAT and firewall keys in the earlier snapshot; all 48,000
firewall entries were established and unexpired under the documented defaults.
The 45-second probe budget was not exhausted (probe duration 24.56 seconds).
This does **not** prove where the packets were lost or exclude a testbench
resource issue. Later snapshots and probes are not an atomic observation.

| Requested | Initial echoes | Held echoes | NAT entries | Firewall entries |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 1 | 1 | 1 | 4 |
| 64 | 64 | 64 | 64 | 256 |
| 12,000 | 12,000 | 4,926 | 12,000 | 48,000 |
| 15,000 | 14,999 | 4,784 | 14,999 | 59,998 |
| 16,000 | 15,999 | 4,784 | 15,999 | 63,998 |
| 17,000 | 16,999 | 5,139 | 16,999 | 65,408 |
| 20,000 | 19,999 | 1,138 | 19,999 | 65,408 |

Exact evidence (private receipts, not a final signed image):

- Run `cloud-retry-jnmo9thn`, completed 08:50:30 UTC in 422.04 seconds.
- Derivation `w1nv0dfjhxy16cjc6wjq9pgibxsnr4gb-vm-test-run-sentinel-nat-capacity-stateful-20000.drv`.
- Log SHA-256 `0be13e5c9ee25c01443d083336770cb5cb1db16e97d783e37a634cb7e41c5940`.
- Output `3gx97lrm8viq3w47y85mfmzmvb5d50gj-vm-test-run-sentinel-nat-capacity-stateful-20000`;
  all 68 raw output files copied locally and SHA-256 checked against cloud bytes.
- Local archive `receipts-_lk6pcm2/cloud-retry-jnmo9thn/raw-output` under the
  private `cloud-admission-20261115.W8W3cg` work directory.
- Nested KVM on the owned remote builder, not a native cloud-network datapath or hardware
  performance qualification.

The old pressure findings remain historical evidence; this rerun must not be
described as reproducing their exact loss mechanism. Diagnosis must account for
the earlier onset and the owned-state timeouts before changing product code.
Later rounds also report nonce/flow/round mismatches after earlier timeouts;
those are not independently proved new connection losses. At 17,000 and 20,000,
649 and 3,648 flows respectively lack at least one firewall ownership key in
the before snapshot. This is additional pressure evidence, not a unique cause
for every failed echo.

## New source identity

The diagnostic candidate is frozen by
`/nix/store/lz5rlsn345irylz2i3q7207nbdffs2v4-manifest.json`.
Its measured eBPF fixed-output hash is
`sha256-PoiIdqFeys846nvZ/sRx5Xs0WoIAt8OO2/p9Vj6DTKY=`.
Measurement run `cloud-retry-wodkyhwg` deliberately supplied a zero hash to
obtain this value; its hash-mismatch exit is **not** a passing test.
Verifier and real packet outcomes are separate from that measurement.

## Exact-object verifier results

`cloud-retry-ltpn78_l` passes all 21 BPF program loads on each of kernel
6.6.159, 6.12.113 and 6.18.57. The ELF SHA-256 in each guest is
`3e888876a15ecacf38ea7bd9fec471e57b345a8200b7c38edbfa7d563e834ca6`.

| Kernel series | Log SHA-256 |
| --- | --- |
| 6.6 | `32b21542027343415081df9b3d84f2cbbf7a0a00894007e51ac433debe0a2fe2` |
| 6.12 | `a99818ed5e569dfd07b9bbe0a165acf712ba3f048cc5aede158a89fa10443641` |
| 6.18 | `fc341c4a4288ad8347f6e4a220372a8b62227ad567fda7d4abfb1579f1766916` |

These are loader/verifier results, not packet or final-image qualification.

## Real packet counter checks

`cloud-retry-agfgubca` passes all six ICMP ownership cases and their separate
positive controls. Clean and own-later translations each produce one masquerade
event, zero drops and zero refusal reasons. Each foreign-live, foreign-expired,
wrong-flags and secondary-translation case preserves foreign state, delivers no
translated echo and increments both `egress_nat_no_candidate` and aggregate
`egress_dropped` by one. The claim-error counter stays zero; no map-helper error
was injected in this packet run.

- ICMP derivation `bkmf5qpxsfc0msi7hbr1941kysg1z8rf-vm-test-run-sentinel-icmp-nat-ownership.drv`;
  235.60 seconds including build, completed 15:27:17 UTC.
- Log SHA-256 `ac54bfbbce772697e67662664b539f77cfdb660a4a145e7247388966bae82806`.

The strict collision gate is **still red**: phases 1 and 8 pass, while nine
requested connections yield eight initial/held echoes and eight NAT entries
out of 65,536. In that final phase, two packet attempts increment both the
no-candidate and aggregate drop counters, with zero claim-helper errors.
This verifies reason attribution, not successful ninth-flow admission.

- Collision derivation `kin7w7wq7wh87nbklg88xpzdj33z3d2p-vm-test-run-sentinel-nat-admission-nine-colliding-flows.drv`;
  153.36 seconds including build, completed 15:29:50 UTC.
- Log SHA-256 `0badac398a01f23856a05ece7b7d6eed6c49bf76acf9e73990633bf0cefea279`.

No counter or gate is promoted to a final signed-image certificate. Production
dependency pins, map capacities, allocation windows, NAT/HA wire layouts and
the stateful dataplane architecture remain unchanged by this diagnostic tranche.

## Instrumented 12,000-flow follow-up

`cloud-retry-1cg308wt` passes phases 1, 64 and 12,000 on the new diagnostic
candidate. All 12,000 initial and held nonce echoes pass; both endpoints retain
12,000 established sockets. Backend metrics report 12,000 active connections
and 24,065 echo frames. Both NAT refusal counters remain zero.

This does not resolve the earlier timeout failure: both the object identity and
the observation timing differ. Added runtime reads introduce pauses; this is
not a controlled proof that the source change repaired packet delivery. It is
also **not** the complete 20,000-flow gate (`pressure_complete` is false).

- Derivation `9la73y930hi6p0r5s59v810qw7fhiw7a-vm-test-run-sentinel-nat-capacity-stateful-12000.drv`.
- Completed 15:35:06 UTC in 219.74 seconds including build.
- Log SHA-256 `dff75db3ea4cf1ade233974176baf3bfa7736ad5ef65826818a5341ec3688dfb`.
- Runtime observations contain actual per-host kernel counters and backend
  event-loop metrics. Missing measurements remain errors, not fabricated zeros.

The same object also passes the separate 128-flow NAPT concurrency regression:
`cloud-retry-_yexwsso`, derivation
`kzlkqm8ba850c6a561cp8l19xsy2r8dd-vm-test-run-sentinel-napt-concurrency.drv`,
completed 15:37:50 UTC in 75.91 seconds including build. Log SHA-256:
`b37edcfa043f571821ed2ef9f566fb98f2721d7562a4b1352c7ed3e400e13807`.

## Complete instrumented pressure gate — still red

`cloud-retry-3eb5g2iv` completes every requested phase, within the unchanged
600-second test limit. The per-operation timeout and nonce/ownership verdicts
are unchanged. This run passes through 16,000, but loses established flows
above that level:

| Requested | Initial echoes | Held echoes | NAT entries | Firewall entries | Flows missing firewall ownership keys |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 1 | 1 | 1 | 4 | 0 |
| 64 | 64 | 64 | 64 | 256 | 0 |
| 12,000 | 12,000 | 12,000 | 12,000 | 48,000 | 0 |
| 15,000 | 15,000 | 15,000 | 15,000 | 60,000 | 0 |
| 16,000 | 16,000 | 16,000 | 16,000 | 64,000 | 0 |
| 17,000 | 16,997 | 16,319 | 16,997 | 65,284 | 678 |
| 20,000 | 19,992 | 16,320 | 19,992 | 65,280 | 3,675 |

All initially verified flows retain owned NAT bindings in the before snapshots.
At 20,000, every failed held echo correlates with missing firewall keys; three
additional flows have missing keys yet still echo. At 17,000, one failed echo
has all keys in the before snapshot. These are non-atomic correlations, not
per-packet eviction traces. Endpoints still report 19,992 established sockets.

Eight initial connections time out. At the final phase's before-open sample,
`egress_nat_no_candidate` is 6; before held probes it is 16, and after probes it
remains 16. `egress_nat_claim_failed` stays zero. Aggregate egress drops follow
the same 6/16/16 values. During held probes, `dropped_default` increases from
13,162 to 58,565. Thus the admission refusal events and established-state loss
must not be conflated into a single "NAT map full" diagnosis.
Independent analysis of the recorded source endpoints finds all eight current
allocator candidates occupied by foreign owners for each of the eight failed
connections in the final before-probe snapshot. This supports candidate-window
exhaustion, but the snapshot is not an atomic admission-time trace.

Client/backend TCP memory-pressure, abort-on-memory, receive-queue-drop and
backlog-drop counters remain zero in those final-phase samples. Their TCP
checksum-error counters are also zero. The backend still reports 19,992 active
connections; its maximum observed event-loop lag is about 602 ms. These
measurements narrow confounders but do not prove absence of all scheduling or
network loss. The earlier owned-state timeouts at 12,000 remain unexplained.

- Derivation `iyrnjf78bag5xym5i7943i3hw4pakbib-vm-test-run-sentinel-nat-capacity-stateful-20000.drv`.
- Completed 15:48:19 UTC in 505.22 seconds including build, exit 1.
- Log SHA-256 `2f44e628c45ae23f9ecb2f3cb4b6ad4541ab35a1e11d80c25988ffa74ca75b4c`;
  verified locally in private `receipts-p470w_cn/cloud-retry-3eb5g2iv`.
- Output `4h6g3in0nkh59484dnpbr7yiqhif0mcd-vm-test-run-sentinel-nat-capacity-stateful-20000`.
- All 152 raw files (255 MB) are copied into the private run directory's
  `cloud-retry-3eb5g2iv/raw-output` and SHA-256 verified against cloud bytes.
  The final receipt records complete pressure execution and unchanged
  configuration, but a failed gate. No cloud jobs remain running from this tranche.

Next implementation must address admission and retention separately, while
preserving stateful eBPF and HA compatibility. Raising a candidate-window or
map-size constant alone does not establish safe ownership or retention. The
[ownership implementation plan](napt-ownership-next-steps.md) remains applicable.
