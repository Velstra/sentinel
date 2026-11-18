# NAT expiry must not delete by key during lookup

Status: this qualification batch is complete. The outlined correction passes
kernel, lifecycle, NAT, RELATED and targeted HA regressions. Collision admission
and full pressure remain red; no release clearance. Every result below is tied
to its source manifest, not a final signed image.

Previously, `fabric/velstra-ebpf/src/main.rs::account_flow` observed expiry
through a map value pointer and then deleted by key. The observation does not own that later
deletion: another packet or replication writer may refresh/replace the value
between the operations. The lookup repair removes this deletion. An
expired observation still returns no usable translation and does not account
the packet or refresh activity. Existing live accounting remains best-effort,
not atomic ownership. Lookup can still influence LRU recency.

## Regression scope

`nix/nat-expiry-test.nix` runs the actual agent in three disposable VMs on the
owned remote nested-KVM builder. TCP, UDP and ICMP each get live, expired and
absent-map cases. Only absent, case-specific NAT keys are seeded (`NOEXIST`).

- Live: the exact nonce packet reaches the internal receiver with translated
  IP/port or echo identifier and valid IP/transport checksums. Translation
  metadata is unchanged; counters advance by exactly one packet and its frame
  length; activity is refreshed.
- Expired: the seeded value must remain byte-identical, without accounting or
  refreshing. No translation reaches the internal receiver.
- Absent: no binding is created and no translation reaches the internal receiver.
- In both negative cases the original packet must reach the local WAN raw
  socket unmodified. Explicit probe permits isolate lookup behavior; a timeout
  or unrelated firewall drop cannot pass as NAT refusal. The initial nine-case
  fixture used a stateless allow policy. The expanded fixture uses stateful
  default-drop plus those explicit permits to test canonical-state fallback.
- Every case preserves a separately seeded neighbouring key, the map identity
  and the appliance configuration. Both capture windows must finish normally.

These are deterministic seeded-age packet tests, **not** a reproduction of a
concurrent refresh race or a full stateful-policy/NAT lifecycle qualification.
The fixture uses explicit raw-packet socket operations checked against Python's
socket API documentation via Context7; it does not mock Sentinel's dataplane.

## Boundaries

Removing this delete does not reclaim expired entries. Foreign expired NAPT
slots remain unavailable until another existing writer/reset/eviction reclaims
them. A fenced collector is still required; an unfenced sweep is not safe.
Generic NAT publication can still overwrite state, failed-rewrite cleanup can
still delete by key, and live accounting is not synchronized with every writer.
The candidate windows, map sizes/layouts, timeouts and HA wire ABI must remain
unchanged in this tranche.

The nine-collider admission failure and 20k pressure failure are separate open
release gates. A passing expiry regression cannot close either, nor establish
physical NIC or native cloud-network forwarding certification.

## Before-fix evidence

Run `v8_mobwd`, unchanged manifest
`/nix/store/1iidwn17mn2n27kd38k6r8cjwmiw9fhl-manifest.json`, finished at
17:51:28 UTC (195.08 seconds including build). All nine cases executed:
the six live/absent controls pass; all three expired cases fail specifically
because the NAT key is removed. All nine neighbours and the configuration are
unchanged. Translation/no-translation and checksum observations are correct in
all cases, so this is not an unreachable receiver or a malformed packet.

- Derivation `2q4gi48pcvjgr4wnr6gvg93k7xb9cvc7-vm-test-run-sentinel-nat-expiry-read-only.drv`.
- Log SHA-256 `df8421235f722df8d7ec9488f7248c257a756276e6ec907fac5aa5dccb4eed1a`.
- Fixture store `l5z3mb22071hn17vsgp7f45mps3zx7ns-velstra-nat-expiry.D3GDy8Oo`.
- All raw files copied to private `cloud-retry-v8_mobwd/raw-output` and checked
  against the cloud SHA-256 values with pipeline failure propagation enabled.

## Intermediate fix identity (not the final candidate)

New manifest `/nix/store/qw23ackry4sdwkh2wz503bkhcnamycsv-manifest.json`
extends the baseline with only `fabric/velstra-ebpf/src/main.rs`:
SHA-256 `fede891329385e71051cc3ca6b2a7e4c064c89ee593125109bf6d64cbbdf0e92`.
Its only executable change is removal of the expired-observation deletion;
comments also stop implying exclusive per-CPU ownership of the shared map.
No other dirty-worktree edits were newly included in this candidate.

Local checks pass: 212 agent tests (8 privileged ignored), 240 common tests,
14 doctests, targeted warning-denying Clippy/rustfmt, 41 Python probe contracts,
33 private source-freeze contracts, targeted Ruff and actionlint. These do not
replace exact-object kernel/packet tests or full workspace/image qualification.

## Exact-object kernel checks

Measurement `l35crsyy` ended with the deliberately mismatching zero hash;
that build is **not** counted as a passing test. Measured object SRI:
`sha256-4LZBLllk/7H8d6PLHvVaCs7sJNnDU6lG8nfsC2sYEh8=`.
Measurement log SHA-256:
`a41f1656c888d1d191bf2293ee4c06965e23406af755939e12c57bab705b3391`.

All 21 programs load on all three kernels in `kce4y48u`. Guest receipts
identify the same ELF SHA-256
`e0b6412e5964ffb1fc77a3cb1ef55a0aceec24d9c353a946f277ec0b6b18121f`.

| Kernel | Derivation prefix | Completed UTC | Log SHA-256 |
| --- | --- | --- | --- |
| 6.6.159 | `h87prc35kb935h6w0a4gqyv7f136r6k5` | 17:57:36 | `7a5eb51a4e3f7e87a9812bdb097d3e431e4ddaf6f20ad5ef66578cbfdefdd16c` |
| 6.12.113 | `6qabyjzb7v96gccjdss1siq5m5c8g6sf` | 17:58:38 | `ecb7f9bcb379405f53a33824e4f139e134214cbbcd1e6329560c122b0fda934b` |
| 6.18.57 | `l212ib7wdn3aadwjzwdb7kvllgjcvpzg` | 17:59:39 | `b25a3eea9b9862775bd61a7ca18bfdff76d57d6aba78a5ff1c62ec65e1d359b2` |

## Lifecycle review and expanded regression

The intermediate `qw23…` candidate passes the original nine cases in
`kwf70oln` (18:03:59 UTC, 179.41 seconds). It also passes the prior firewall
expiry, six ICMP ownership cases and 128-flow NAPT. Those passes are insufficient:

- `try_port_forward` previously skipped publication for **any physically
  present** forward entry. Retaining an expired one would therefore strand
  that configured tuple. Only a live binding should defer to existing-NAT
  translation; normal policy-authorized new-flow publication must remain
  reachable after logical expiry.
- `ct_router_normalize` also let an expired tenant entry shadow the live
  router-NAT namespace. It must ignore the expired local entry when resolving
  the canonical firewall identity.

The expanded eleven-case fixture adds actual UDP translation after expired
DNAT state and stateful default-drop admission through a live canonical
binding despite an expired tenant shadow. The reuse guard permits the old
path's single retransmission but requires real translated delivery; immediate
delivery of both probes also passes. The shadow case has no explicit allow
rule: only the seeded live canonical firewall permission can admit its packet.

Expanded fixture store:
`fyxlyp2pvinhdmh408a8rqbakpz8w3n8-velstra-nat-expiry-lifecycle.aS7Jr0it`.
Candidate manifest:
`/nix/store/5vwy8zxkknps7vw4zvh7fgdw98wxbjxs-manifest.json`.
Both expiry-aware lookup checks are added to the intermediate deletion removal.
This does **not** make existing generic `ANY` paired publication atomic or prove
exclusion of concurrent writers. It preserves the authorized lifecycle while
removing expiry deletion from the lookup itself; the separate publication and
GC work remains necessary.

Prepared intermediate-source batches `iio1stop` / `x88j8nm9` were not launched
and must not be mistaken for qualification of the expanded candidate. The
ten-case-only preparation `d47i29si` is also superseded and unlaunched. Every
new source version requires its own object measurement and verifier/runtime
checks; the earlier object hashes above cannot qualify it.

The intermediate candidate fails the expanded fixture in `oyvgl1ob`, completed
18:16:53 UTC (192.09 seconds): the original nine cases pass; DNAT reuse delivers
zero translated packets and two unmodified local packets; tenant-shadow
admission delivers no packet at either receiver. This confirms both dependency
failures in the real dataplane rather than only inferring them from source.
Derivation `fyrdi4f00c77dyrxz0ammlwaksa284gr-vm-test-run-sentinel-nat-expiry-read-only.drv`;
log SHA-256 `01bc1b6cf3675616c6f46788a82c28b118c13ea6291d6f0e84af8dcd845430a4`.
Completed intermediate reports/logs are verified in private
`receipts-da9pf6w_`. The later measurement may still be running in that snapshot.

The original `1iid…` source also ran the identical expanded fixture in
`v0b5ebi5` (18:23:30 UTC, 193.57 seconds). Its three expiry-retention cases fail,
and the tenant shadow already fails there. **DNAT reuse passes with one of two
packets translated**: the intermediate delete-only removal would regress this
behavior, so that intermediate source is not suitable for promotion.
Derivation `70yg2v68zi8h5m1a63656insipzc5z3i-vm-test-run-sentinel-nat-expiry-read-only.drv`;
log SHA-256 `d0579a7378e565c4556f5468f2166318f12f874ac0fa87ea5db2af04fc589510`.

Rejected inline candidate source file hashes in `5vwy…`:

- `main.rs`: `75d42a670c7b1b354661c8ca5cf672986305a82d0c28dce98270a79ab523a54d`.
- `conntrack.rs`: `f80f5da06f80a0b3dcbefa85d1a23c1d1f7d6dd30cff57bbe5a851ccd5a21fe1`.

Measurement `ot53zfox`, completed 18:18:22 UTC, yields
`sha256-9wpNVp3cb7pJAb+702wkj/8kScBVsyEowbNRqm1buVQ=`. Its expected
zero-hash mismatch is not a passing verification. Measurement log SHA-256:
`f3e854ea2e10ae9f3d00276f8c2ada37cc24aed8115ac852c15e5801ea343d2e`.
The latest local check now includes 43 Python probe contracts; Rust/lint results
remain passing. No production pin or image has changed.

## Verifier rejection and revised candidate

The inline candidate failed all three kernel checks in `6m5vjdw0` (finished
18:28:46 UTC). On 6.6, `velstra_forward` is rejected at a generated register
spill with `R5 !read_ok`; the other 20 programs load. This is not an instruction
limit waiver, and userspace tests cannot override the failure. Completed logs
are hash-verified in private `receipts-jyypix3j`.

Prepared packet batches `kri7kes3` and `b0daqn6m` were never launched and are
superseded. The next candidate outlines the expiry lookup into a small,
scalar-returning `nat_binding_live` subprogram, keeping the same logical
behavior without inlining its timeout branches into the forwarding tail.
Manifest: `/nix/store/a68klqlrfy6fvy5k8zvafxlz2k000c5r-manifest.json`.
Fresh object measurement and all kernel/packet checks are required before this
candidate can be considered qualified. No acceptance threshold was changed.

The outlined candidate now passes all 21 loads on 6.6.159, 6.12.113 and
6.18.57 (`ofxwsnfm`, finished 18:39:14 UTC). All three guest receipts identify
ELF SHA-256 `26734a927f037bb04e12e8cbb671539cf9196990415e6d9c7eb1cf508b772c63`.
The measured SRI is `sha256-JnNKkn8De7BOEujLtnFTnPkZaZBBXm2cfrHPUIt3LGM=`;
measurement `jrfuyonh` is the expected zero-hash mismatch, not a passing test.
Completed logs are hash-verified in private `receipts-ekudzxni`.

| Kernel | Derivation prefix | Log SHA-256 |
| --- | --- | --- |
| 6.6.159 | `zm9py5c25amca2rd0vkhh6l8lqh6nvl5` | `bb7fdb41a5c8e7390942098c21d3273dd58e0bb1d1d5149291f61888fb4f751b` |
| 6.12.113 | `w6jf8k8v03qg21dypb1rljxc36w73j0d` | `dfd8997d84e490c60c15f979ca3510b0b94c78d45d6e26047d822f7bdc27c18a` |
| 6.18.57 | `2nd3yg0xl04j9s69zs4whf00h5l150bc` | `5a1bafb050c8161f9ee8c9c064af45ac34eea7821c95239c1d8d11778e01c947` |

Source hashes: `main.rs` is
`ee195acc593a6077f5488e11d5da430c5ca2951ccda6a12ea39b9e92368ab98f`;
`conntrack.rs` is
`658fc1c3aa15412a8c7e0879e57f96466311fc4b5cf29149750c0cc7f34fd575`.
Verifier success alone does not establish packet behavior or close the
independent capacity/ownership gates; runtime results follow separately below.

The identical eleven-case fixture now passes against `a68kl…` in `lbv45p18`
(18:43:29 UTC, 206.97 seconds including build). All live/expired/absent controls,
DNAT reuse and canonical-state fallback pass; the appliance configuration is
unchanged. Derivation:
`d84qaywfjk9y2lyipqsz2h63rdnwqv60-vm-test-run-sentinel-nat-expiry-read-only.drv`.
Log SHA-256: `79008e6f69d51ad0285c77c29d82039f9c1c42f88d6d0a7ccf41d64fb67005cc`.
Broader NAT/hairpin/RELATED and HA/pressure checks still require their own
results for this candidate. No generic concurrent-publication or GC fix is
claimed by these deterministic tests.

The same batch also passes the full native NAT/CLI regression at 18:53:30 UTC
(600.64 seconds), including UDP/bulk TCP, load-balancer creation and collision
rejection, default-drop return paths, destination rules, rate limits and live
flow statistics. Hairpin NAT passes at 18:55:26 UTC (116.44 seconds).

| Check | Derivation prefix | Log SHA-256 |
| --- | --- | --- |
| Native NAT/CLI | `pfiywzb5ar3jm5rynpl4cxkzcslr1msv` | `dd57788d79632151a169e10bcaf130a5fcd98fe715c5d43f71747798a82aade4` |
| Hairpin NAT | `qbmki19a38bjflypzn9p6vbnr0hg93h9` | `e81c8afd0fee9b4718d73a41f7cda65eb01888f44e6bef4010857a9cab1a7722` |

The eleven-case fixture's complete raw files and the native NAT fixture's two
iperf/bulk JSON artifacts were copied and individually hash-checked against the
builder. The existing hairpin fixture emits no files in its output directory;
its evidence is the successful derivation and complete hashed test log, not an
invented packet-capture artifact.

## RELATED comparison: retain and correct the stale stimulus run

The original RELATED entry point finishes red at 19:01:27 UTC with one exact
comparison mismatch: DNAT `bad-quote-checksum` has residual `0xfeff` in the
reference and `0x0100` in Sentinel. All individual delivery, checksum-envelope
and endpoint-error assertions pass. Inspection confirms this entry point used
the old probe SHA `ff176a8524d0b4205ccc03baaca221d1fb7a9aa70675e6ceb056d863783f5b4a`,
whose `quote[10] ^= 1` introduces either +256 or -256 depending on the original
checksum bit. It therefore does not inject an equivalent malformed checksum
into both lanes. The failed report is retained, not relabelled as passed.

The already-reviewed working probe SHA
`085daa2c2493b7174db9f3fa969b07472a62dce5ee1ec29738104d36e4c4c68c`
uses one's-complement addition to introduce the same residual. Its 16 self-tests
pass, including an independent arithmetic check over all 65,536 checksum words.
The new private entry point explicitly selects this immutable probe and asserts
the unchanged fixture hash
`0ae0731f456826cbc17604ac4a3c07d98c7b4d42737172c37e509985a9c6edd5`.
It does not remove residual comparison or change delivery expectations, timeouts
or product source. The repeat run is pending. Original complete logs are
hash-verified in `receipts-2h5n7cbz`; its raw RELATED report is also copied and
hash-checked against the builder.

The corrected-stimulus repeat `tnphzo4n` passes at 19:11:45 UTC (322.94 seconds):
19 reports, 145 observations, zero failures. Its receipt identifies the same
product ELF `26734a92…`, unchanged fixture `0ae0731f…` and probe `085daa2c…`.
Derivation `vi0lrdgci3zdcpgi587w47bwl8vk7cp6-vm-test-run-sentinel-related-icmp-netfilter.drv`;
log SHA-256 `8201b13eff6410a846356e6c8b46f063f1be5c4a0667236c798ab46f47725396`.
Complete logs are verified in `receipts-wtcbovw0`. The default private RELATED
wrapper now selects the corrected probe explicitly to prevent another stale
stimulus run. This closes this targeted UDP-quote comparison on the current
candidate, not fragmented NAT, general PMTU or TCP-error-quote qualification.

## Independent admission and capacity gates

On the same product, `6niss56n` passes the 128-flow concurrency regression at
19:13:45 UTC (78.68 seconds), log SHA-256
`0c72c340c082f3bb9838f722f923cf737b4dc512c2e1279bb1a5dd2401fd16cc`.
The strict collision fixture remains red at 19:16:21 UTC (155.86 seconds):
1/1 and 8/8 controls pass, but nine colliders produce only eight initial and
eight held echoes. No-candidate and aggregate-drop counters both increase by
two; claim-helper errors remain zero. Configuration is unchanged.
Log SHA-256 `e942e7488a4ca2253d8ffe8d7b973fef8f2ae65ba1cbca7e2786015958a9f09e`.
This is an unchanged open allocator limitation, not fixed by logical expiry.
The full-pressure run completed all seven phases at 19:25:51 UTC (569.94
seconds), with unchanged configuration and `pressure_complete=true` but
`passed=false`. Its log SHA-256 is
`d627adb102b21b70e3a49716397db9f7cfaa11c017614ebd687a7c170ecf876e`.

| Requested | Initial nonce echoes | Correct held-round echoes |
| ---: | ---: | ---: |
| 1 | 1 | 1 |
| 64 | 64 | 64 |
| 12,000 | 12,000 | 3,253 |
| 15,000 | 14,998 | 3,253 |
| 16,000 | 15,997 | 3,253 |
| 17,000 | 16,997 | 2,611 |
| 20,000 | 19,992 | 0 |

At 12k, all 8,747 failed held probes time out despite owned NAT and all expected
firewall keys in the recorded snapshot. All 48,000 firewall entries are marked
established and unexpired under the configured defaults. This repeats the
earlier unexplained below-capacity symptom, not a proven LRU-only failure.
The backend emits 11,876 additional echo frames between the surrounding runtime
samples; client/backend TCP retransmissions increase by 50,428/49,749. Recorded
TCP checksum errors, backlog drops and memory-pressure counters are zero on
both endpoints. These observations do not locate the loss, prove state at each
packet instant, or distinguish product behavior from the virtual transport.

At 20k, 3,643 flows lack firewall roles but retain NAT ownership. **Zero correct
echoes does not mean zero received packets:** 13,744 failures are exact
nonce/flow/round mismatches and 6,248 are timeouts. Prior delayed rounds can
affect later checks; the first 12k timeout cohort must be investigated separately.
Next diagnosis needs synchronized wire captures and identical endpoint/load
controls through a reference dataplane, without increasing the acceptance
timeouts or interpreting larger maps as a fix.

## HA and evidence completion

Both strict causal HA tests pass with one existing TCP connection, unchanged
public tuple and the original 1.5-second promotion bound:

| Pair | Promotion | Exchanges | Maximum echo gap | Completed UTC |
| --- | ---: | ---: | ---: | --- |
| Historical-source/current | 1.363 s | 362 | 1.780 s | 19:28:09 |
| Current/current | 1.317 s | 376 | 1.758 s | 19:30:16 |

Mixed log SHA-256:
`17e918cc82c8b798b3f320f0ed273191e49924223849d26ca0e69a3c440196ec`.
Same-source log SHA-256:
`b1dbea7764a6a9bbb3b76a89c849fc3304e9a6ab3ae2aeb968c5efe4852102af`.
The historical build uses its independently qualified rebuilt hash; this is
not a byte-identical old-release or complete rolling-upgrade certificate.

All completed logs, including rejected candidates and stale-stimulus runs, are
verified in private `receipts-snqafqu5`. Complete raw collision, pressure and
both HA outputs were copied and each file checked against its cloud SHA-256.
No staged index, production pin, deployed appliance, release or update channel
was changed. Fragment NAT/PMTU, reset validation, ownership reclamation and
final signed-image/SBOM/CVE qualification remain separate open work.
