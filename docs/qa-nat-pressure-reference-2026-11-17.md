# NAT pressure controls — 17 November 2026

Not release qualification. The standalone nine-flow repair remains verified;
the 20,000-flow stateful gate remains blocked.

## What is being isolated

The previous complete run admitted 19,072 connections and retained 16,321
verified echoes. Its first 2,753 flow identities had missing firewall roles,
although their NAT bindings remained owned. The first 2,751 timed out; two
still echoed despite missing roles. The one-flow sample established four
firewall entries per connection. `FW_FLOWS` is a 65,536-entry LRU map, and
publication currently ignores insertion results. An ordinary hash-map swap
alone would therefore introduce unchecked partial admission, not a safe fix.

Separately, 928 connections were **not attempted** after the 45-second opening
budget expired. Those records are not NAT refusals. Full-domain discovery cost
is a candidate cause, not yet an isolated CPU measurement.

## New controls

- `nat-pressure-reference`: independent nftables routing/NAT, using the same
  endpoint probe, addresses, node resources, kernel selection, seven increasing
  counts through 20,000, and 45-second opening/probe budgets.
- Stateful Sentinel rerun: unchanged candidate, same workload and strict map
  ownership/held-echo verdict; only additive echo-failure evidence is new.
- Separate LAN-stateless diagnostic: same candidate and workload, but only the
  WAN policy is stateful. The expected template has two public firewall roles.
  This removes security checks as well as state pressure; it is **not a product
  fix, recommended configuration, or substitute for the stateful gate**.

The shared probe now preserves expected/received nonce, flow and round identity
when parsing is valid, plus frame length and SHA-256. It still rejects anything
other than the exact expected bytes. It does not drain delayed frames, retry,
reconnect, extend timeouts or turn an expected failure into success.

Reference success cannot qualify Sentinel. Host scheduling, state collection
pauses and ephemeral source-port choices differ between runs; these are
functional controls, not a controlled throughput/CPU benchmark.

## Frozen inputs and execution

- Product manifest: `9f1x09gjjmh6w1sfc12hi3w5irn2rz5k-manifest.json`.
- eBPF SHA-256: `5ceeb0fc58368b5399fe693a843f6d7e11e78c3545b6f418326125a98ce4aae8`.
- Shared probe SHA-256: `d89d6cada4344ecdc3fb931d9ec5ac566f1013ea10b3af0ac19e901a0aa833df`.
- Frozen fixture directory: `fjsvfps3ng8zv45zhxx9h318livkxncr-velstra-pressure-paired.k435LULw`.
- Reference `9y5kb3fv`: **PASS**, finished 22:27:27 UTC, 393.57 seconds.
  All seven phases, including 20,000 initial and held echoes, pass.
  Log SHA-256: `10e3ace934d48ee49d1452b72ce8c0d56b95819ddd3c265292102e0dff7d652b`.
- Stateful subject `kugn3cd1`: **FAIL**, finished 22:36:39 UTC, 520.98 seconds.
  Log SHA-256: `3636c8b094d159934f2ef0cbd7ea3efc5d885d14fd90c7a4ca36fcc3955ebbaf`.
  At 12,000, 672 were not attempted after 45.6477 seconds of opening; all 11,328
  admitted flows echoed. At 20,000, 19,328 initial echoes became 16,319 held echoes.
  All 3,010 ownership failures retained NAT bindings but missed firewall roles;
  3,009 timed out and one still echoed. This run produced no late-round mismatch
  and does not explain the older below-capacity delayed-echo finding.
- LAN-stateless diagnostic `uh496vv8`: **FAIL**, finished 22:45:11 UTC,
  496.56 seconds. All 18,554 admitted connections retained their original
  nonce-verified streams, with no ownership failures or external tuple aliases.
  Its template contains only the two public firewall roles (37,108 entries at
  20,000 requested). However, 1,440 connections were not attempted after the
  12,000 phase exhausted its opening budget (45.3144 seconds), and six more
  completed TCP connect but timed out waiting for the backend greeting during
  the 15,000 phase. Those six failures remain unexplained; both NAT no-candidate
  and claim-failed counters stayed zero across that opening phase. Retention
  above the stateful plateau supports a firewall-state capacity contribution,
  but changing policy also changes processing work and is not an isolated
  causal proof or a repair.
  Log SHA-256: `7b32a3767f28c637e824d1c8d1c99b3f579028b314277b473bb7f64c027287a8`.

The hash/cohort-bound comparator exits **1** (complete evidence of a Sentinel
failure, not missing evidence). It rejects a stateless subject, a failed
reference, mismatched probe/kernel/candidate identities and contradictory counts.

| Requested | nftables initial / held | Stateful Sentinel initial / held | Two-role diagnostic initial / held |
| --- | --- | --- | --- |
| 1 | 1 / 1 | 1 / 1 | 1 / 1 |
| 64 | 64 / 64 | 64 / 64 | 64 / 64 |
| 12,000 | 12,000 / 12,000 | 11,328 / 11,328 | 10,560 / 10,560 |
| 15,000 | 15,000 / 15,000 | 14,328 / 14,328 | 13,554 / 13,554 |
| 16,000 | 16,000 / 16,000 | 15,328 / 15,328 | 14,554 / 14,554 |
| 17,000 | 17,000 / 17,000 | 16,328 / 16,321 | 15,554 / 15,554 |
| 20,000 | 20,000 / 20,000 | 19,328 / 16,319 | 18,554 / 18,554 |

At 12,000 the observed opening durations were 23.95s for the reference and 45.65s
for Sentinel; the latter exhausted its 45s between-batch budget. These isolated
observations do not establish a throughput ratio or exclusive CPU cause.

All three completed raw-output trees were copied and every file hash checked against
the builder. The reference/subject report SHA-256 values are respectively
`e1f1ac9fb567465bf7f66954ac1c5788cd872fc2a189d82398f02c3614c90740`
and `785deba81ab5be864d8bdfe5c8db1678be69ef4781770f99cc162e5fe9f7d6d7`.
The diagnostic report SHA-256 is
`a8501803f0beccaeb2711c11a5a209325e21fdb2d12235a538bb784c9f1a2d89`.
All three serial cloud jobs are complete; no product change was made for these controls.

Local validation: 73 NAT/echo/reference/comparison contracts pass, Nix syntax and workflow
actionlint pass. This is not a full workspace or final signed-image check.

## Repair boundary

Retention needs fallible complete-flow admission, non-evicting authoritative
ownership and synchronized reclamation, including HA writers. A larger LRU map
only moves the threshold. An append-only negative-membership accelerator was
reviewed but not implemented: publication ordering and concurrent lookup safety
need proof before it may skip authoritative discovery. Existing publication,
expiry-collection and replicated allocator limitations remain open.
