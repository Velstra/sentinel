# Standalone NAT admission — 17 November 2026

Working-source qualification, not a production release. The prior candidate's
strict nine-flow failure is preserved in [the reference comparison](qa-nat-admission-reference-2026-11-17.md).

**Outcome:** standalone9/9 admission, CGNAT exhaustion and the earlier-vacancy
regression pass. The full pressure gate still fails: opening-budget exhaustion
and established firewall-state loss remain release blockers.

The follow-up [pressure controls](qa-nat-pressure-reference-2026-11-17.md)
separate nftables endpoint behavior, round-aware failures and the observed
four-role state pressure; they do not waive this gate.

## Change

The TCP/UDP allocator now searches the complete allowed port domain when neither
HA nor conntrack synchronization is configured. It first discovers existing
owned state, then reserves a vacancy with `BPF_NOEXIST`. Ordinary NAT covers
32768–65535; CGNAT covers exactly the subscriber's configured block. Cyclic
enumeration also handles non-power-of-two blocks and seeds near `u32::MAX`.
Current and historical eight-candidate discovery remains ahead of this fallback.
The reverse NAT map remains authoritative; there is no new forward cache or
replication record format. RELATED ICMP lookup can recover expanded TCP/UDP
bindings too. ICMP echo identifier allocation is unchanged.

HA and synchronized configurations deliberately retain the previous allocator.
Their ninth-flow admission defect is **not** fixed by this tranche. Changing
HA/sync settings requires the existing service-restart path, which recreates the
unpinned connection-state maps. The central reconfigure entry now rejects those
changes before replacing its base configuration, including controller callers
that previously bypassed the query-layer guard. Allocator mode is programmed
only behind the existing quiesced configuration gate.

## Candidate history

- Manifest: `/nix/store/l5d8qmqny1mgilck49f6db2y9apy8lgs-manifest.json`.
- Measured object: `sha256-g+RTXVt2+okYFEaRRjA6Jvd+oASTyF/pEtL0tiBs1rg=`.
- Measurement `usip_39o` completed at20:07:14UTC. Its deliberately incorrect
  zero hash produced the expected fixed-output mismatch; this is a measurement,
  not a passed runtime test. The log SHA is
  `f93f6d5357632513869b7c939e7a769abd8c24f6dbd1959bf97d8a73bef96bdc`.
- Three-kernel verifier batch: `obaqk7nl` failed on all three kernels, completed
  at20:15:11UTC. Three programs were rejected before instruction analysis:
  `last insn is not an exit or jmp`. Disassembly contains a remainder-by-zero
  panic helper ending in a call rather than a valid BPF exit/jump.
- `xw5kwq36` and `qq6ecyv3` were prepared against this rejected object and
  **must not be launched**. They are not runtime evidence.
- Correction: explicit empty-domain/out-of-range guards eliminate the panic
  path in the local object. Manifest
  `/nix/store/y0mlfv3g6jpj2v28b4diw7xszzx790bs-manifest.json`;
  measurement `8ybrf45a` completed at20:17:14UTC with object SHA-256
  `b17b36a922748896ea798cb9985928e78be9553282f33b8774950a1226032bf8`.
  Verifier batch `s54i3_j5` failed on all three kernels, completed20:23:21UTC:
  only `velstra_masquerade` remained rejected, with combined stack544bytes
  exceeding512. The other20programs, including both RELATED egress programs,
  loaded. Plans `qgi7863l`, `ophqpkty`, `jcbfh5rw` are superseded/unlaunched.
- Stack correction: the unchanged legacy eight-candidate claim loop is now
  outlined, reducing the parent frame shared with complete-domain callbacks.
  Read-only review against the previous frozen file found no ownership,
  candidate-order, HA-WireGuard, counter or cleanup semantic change.
  Manifest `/nix/store/9f1x09gjjmh6w1sfc12hi3w5irn2rz5k-manifest.json`;
  measurement `eia_3ekp` completed20:25:31UTC, object SHA-256
  `5ceeb0fc58368b5399fe693a843f6d7e11e78c3545b6f418326125a98ce4aae8`.
  Verifier batch `x926qr9c` completed20:31:46UTC: all21 programs loaded on
  kernels6.6.159,6.12.113 and6.18.57 with the identical object hash.
  Packet batch `pl29ua4f` started20:32:19UTC. Fresh reference `crirwyfl` and
  HA/RELATED/full-pressure `poc4of0c` were queued next; their completed results
  are recorded below.

## Packet results

The unchanged strict nine-collider gate passed at20:34:57UTC (157.74s):
all nine connections delivered their initial and held nonce-bearing echoes on
the original sockets. Public ports were38184–38192, with nine NAT entries,
36 firewall entries and no SYN entries. NAT no-candidate, claim-failure and
drop counter deltas were all zero. Log SHA-256:
`87889ad0c1e548ef0c51288d7af03528bbf1948e4971892733587fee2b0bab6d`.
No source-port premise, timeout or assertion was relaxed.

CGNAT passed at20:36:56UTC (119.06s). All65 held connections occupied exactly
ports43770–43834. Connection66 timed out at connect, incrementing no-candidate
and drop by2, with zero claim failures; all65 original sockets still passed
the next nonce/round echo and kept their tuples. Log SHA-256:
`523ed0fbe2b74738270ce38316145eeb765b8350f340cf6d7b6d4d038de08eaf`.
The same packet batch completed at20:45:16UTC with all five checks passing:

| Additional regression | Result | Completed UTC |
| --- | --- | --- |
| 128 concurrent connections | PASS | 20:38:11 |
| Eleven NAT expiry/lifecycle packet cases | PASS | 20:41:32 |
| Six ICMP NAT ownership cases | PASS | 20:45:16 |

Completed logs are copied and hash-verified in `receipts-l1j9v27o`. Subject,
CGNAT, concurrency and lifecycle raw guest files are also transport-hash
verified. The fresh nftables reference `crirwyfl` passed at20:47:13UTC.
The unchanged comparator returns0 for this exact candidate/kernel and all
three phases: both Sentinel and nftables admit and retain1/1,8/8 and9/9.
Reference log SHA-256:
`408e1b163158ce1d1b54f41af5a950c309c8d217f60366057ef61505c7314bb6`.
The original8/9 failure and its reference receipts remain preserved.
The earlier-vacancy regression passed
at20:49:36UTC (105.58s), log SHA-256
`9c0ab993596394abf9d62d9b0cbbc64937fd8e2da99c247664d048686dd214d9`.
This is not release qualification.

Local validation:244 common unit tests,214 agent tests and14 doc tests passed;
eight privileged agent tests are ignored locally. Warning-denying targeted
Clippy, formatting,54 NAT Python contracts and33 source-freeze
contracts passed. The central-transition ordering test is a source contract,
**not** a live controller-transition test.

The new `nat-domain-cgnat` VM gate uses the existing endpoint probe unchanged
and requires65 real held TCP flows in exactly one65-port block. The66th must
time out during connect while every original socket still echoes its exact
nonce/round. Six oracle contracts reject incomplete, misattributed, out-of-block
or stolen-flow receipts. This fixture is wired into the flake and public VM CI;
the live test passed as recorded above. A separate `nat-domain-hole` gate now
tests an earlier vacancy preceding a later held allocation. It deletes only a
precisely checked unrelated reverse key in a marked disposable VM, then requires
the ninth original TCP socket to retain its public tuple and nonce/round echo.
Seven contracts cover malformed receipts, wrong owners and refused mutation.
This is deliberate test injection, not a concurrent compare-and-delete or
production garbage-collection claim. The live test passed on the same product
object: the ninth original socket survives with its unchanged public tuple,
and the earlier candidate remains vacant.

The new probe scripts received lint-only import/literal normalization after the
first CGNAT pass. `8v3mkk_y` qualifies the exact final scripts: earlier-vacancy
and CGNAT both pass. CGNAT completed at20:51:07UTC (90.57s), log SHA-256
`8ef02d45944ce7f1122f679dd6ae0b2caaad1cb52ece1269fc55fd7708e4ab47`.
Prior evidence is retained unchanged. The HA/RELATED/full-pressure batch also
finished against the same product object, with the results below.

Mixed-source causal HA passed at20:54:02UTC: promotion1.366s,410 verified
exchanges on one TCP socket, maximum reply gap1.719s and unchanged SNAT tuple
`10.1.0.100:47009`. Log SHA-256:
`ac977d527f8117c9026b5282605fbe3d0a1cd84195bbe5e9318c4e11afec92f7`.
This private causal diagnostic does not clear the earlier host-poll timing
failures, all HA scenarios, or complete-domain admission under replication.

Same-source causal HA passed at20:56:05UTC: promotion1.332s,366 exchanges on
the same socket, maximum gap1.754s and unchanged tuple `10.1.0.100:59268`.
Log SHA-256:
`faead5cc839f11745e32e04ab06843f659d1025e326ec2d58cc771c882f12c26`.
The same diagnostic scope limits apply. RELATED passed at21:01:29UTC;
log SHA-256 `6ba6294091d4c7ae8165b72b830578f5e1fcda6f4856164a0c7856be20ec1d51`.
This ordinary RELATED regression does not by itself prove quoted-packet lookup
for an allocation beyond the original candidate window.

## Full pressure gate: still failed

`poc4of0c` completed at21:10:17UTC. The unchanged full pressure check failed
after528.28s; log SHA-256:
`f017886bbeeadf48d2b47b432d19458d2d979ee6214bde427e883bbda2dbef68`.

| Requested | Initial verified connections | Later verified echoes |
| --- | --- | --- |
| 1 | 1 | 1 |
| 64 | 64 | 64 |
| 12,000 | 11,072 | 11,072 |
| 15,000 | 14,072 | 14,072 |
| 16,000 | 15,072 | 15,072 |
| 17,000 | 16,072 | 16,072 |
| 20,000 | 19,072 | 16,321 |

At the12k phase, the unchanged45-second opening budget expired after45.10s.
The remaining928 connections were **not attempted**, not refused by NAT and
not counted as successful. Those same unattempted records carry through the
later cumulative phases. The earlier candidate opened12,000 in28.72s in its
recorded run; this new budget miss is a performance regression signal, not
yet a controlled CPU-cost attribution. Do not raise the budget to hide it.

At20k,2,751 original sockets timed out. All2,753 ownership failures had missing
firewall roles while their NAT reverse bindings remained owned (two still
echoed). The firewall map held65,280 entries. There were no external tuple
aliases and no NAT no-candidate/claim-failure drops. This remains an established
state-retention problem, not the repaired sparse nine-collider refusal.
The previously observed lower-load delayed/incorrect-round loss is not thereby
explained or closed; these runs do not have equal actual admitted cohorts.

All completed logs are verified in `receipts-wxrwq4c_`. All raw outputs from
the final packet, reference, earlier-vacancy, CGNAT, HA, RELATED and pressure
runs have been copied and transport-hash checked. All cloud jobs are finished.

## Still required

Complete-domain lookup performs up to32768 ordinary or65535 CGNAT lookups per
new-flow miss. It touches foreign LRU entries and can increase CPU cost,
including RELATED-ICMP misses. Do not call this a fast-path/performance fix.
Kernel verifier loading, real nine-flow and CGNAT traffic, stable held tuples
and targeted same/mixed-source causal HA now pass. Worst-case CPU, complete-domain
UDP/expanded RELATED coverage, live controller-mode transitions, replicated
admission and full pressure qualification are still required.
Existing generic publication races, LRU state loss, physical expiry collection,
fragment NAT/PMTU and signed-image/SBOM/CVE release gates remain open.

No production pin, update channel, appliance deployment or release was changed.
