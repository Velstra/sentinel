# Dataplane support and conformance

Sentinel retains Fabric's stateful eBPF firewall. This is a development candidate,
not a production support promise. A passing parser, host unit test or verifier
load is not a passing packet test.

## Latest source checkpoint — 18–19 November 2026

- **Not release-ready:** the full pressure gate opens all 20,000 connections,
  but only 16,322 pass the held-connection probe. NAT bindings remain present
  while firewall state is missing. A safe supported connection limit has not
  been established.
- **Still failing:** wrong-sequence, nonexact in-window and checksum-corrupt
  TCP resets destroy live state; fragmented IPv4 UDP/ICMP SNAT fails against
  the independent netfilter reference.
- **Passing within scope:** plain NAT, hairpin, generated reject packets,
  pairing/config-sync with and without a witness, and same-source/historical
  mixed-source single-flow failover. These do not qualify a complete rolling
  upgrade, loaded failover or signed image.
- **Verifier:** all 22 shipped programs load on 6.6.159, 6.12.113 and 6.18.57
  from the same object, SHA-256
  `a2d2ef90c895df56bb6a049535222f0186bedaa0fbd56ae919991189aaf53c47`.

The [remediation record](https://github.com/Velstra/sentinel/blob/main/docs/qa-release-findings-2026-11-18.md)
separates source cohorts, fixed test fixtures, actual runtime fixes and failures.
Earlier measurements below remain historical evidence, not extra guarantees.

## Current boundaries

| Path | Current status / limitation |
| --- | --- |
| Routed IPv4/IPv6 filtering | XDP ingress plus kernel routing and TC egress. Allowed traffic is **not** generally kernel-bypassed. |
| Stateful TCP/UDP | Ordinary-flow and bulk-TCP regressions pass. Known release blocker: out-of-window, in-window nonexact and checksum-corrupt TCP resets delete live firewall state even when the endpoint rejects them, interrupting the existing connection. Sequence/window/checksum validation remains incomplete. |
| IPv4 source NAT and destination NAT | Targeted plain DNAT, hairpin, concurrent TCP/UDP and established-flow HA tests pass on reviewed working sources. The latest standalone allocator passes nine deliberately colliding held connections; HA/synchronized configurations still use the restricted eight-candidate allocator. Capacity, broader regression and final committed-image qualification remain pending. |
| Live IPv4 inventory changes | Working-branch tests cover added, labelled and removed addresses, DNAT/LB discovery and one surviving SNAT TCP flow. Observer errors and stale rollback snapshots hold the dataplane closed until reconciliation. This does not qualify every DHCP or link-replacement scenario. |
| Fragmented IPv4 through NAT | Known release blocker. Large UDP datagrams and fragmented echo can be lost. Do not rely on this for production DNS, IKE or other large datagrams. |
| ICMP errors related to NAT flows | Targeted IPv4 UDP-quote differential passes SNAT/DNAT/hairpin, including malformed quotes and error-queue checks. General PMTU, TCP quotes, fragmented NAT and final-image qualification remain open. Echo support alone does not establish RELATED ICMP support. |
| IPv6 | Filtering / routed forwarding is distinct from NAT64, NPTv6 and overlay support. No IPv6 stateful redirect fast path is claimed. Each requires its own packet gate. |
| Conntrack capacity | Separate fixed 65,536-entry NAT and firewall-state maps. Entries per connection depend on the NAT path and policy; there is no universally qualified connection limit. A 128-connection pass does not clear sparse-map allocation failure, live-entry eviction or the 20,000-flow pressure gate. Occupancy warnings do not prevent these failures. |
| XDP redirects | Fabric has explicit IPv4 FIB, load-balancer and overlay redirect paths. Those do **not** establish an established-flow fast path for the Sentinel router/NAT configuration. |
| SYN proxy | IPv4 only; IPv6 SYNs to a protected port are not proxied. Scoped to the zones that admit the port (see the firewall handbook). Proxied connections lose window scaling, SACK and timestamps. |
| Generic/SKB XDP | Driver fallback, not native-XDP performance. Native mode and each NIC driver require separate qualification. |
| HA | Experimental. Targeted flow/fencing tests are not clearance for all witness-loss, partition and rolling-upgrade scenarios. Keep independent management and recovery access. |
| Kernel compatibility | 6.12 is the current appliance selection. 6.6 / 6.12 / 6.18 checks load the same object on real guest kernels. A configured CI lane is not a compatibility claim: require its passing receipt for the exact object hash. |

An unsupported case is an open bug, not a silent success. There is no `xfail`
list in the differential gate. No Mpps-per-core figures have been established
for a Sentinel established-flow redirect path.

A separate working-source fragment containment regression
now proves that unsupported nonlocal fragments on the Sentinel TC masquerade
path are refused rather than leaking an untranslated source. This is not
fragmented NAT support: fragmented routed replies on that masquerade uplink are
also conservatively refused. Non-masquerade links are outside this guard.
The full differential gate remains mandatory and red for fragmented NAT.

The independent baseline concurrency run retained 16,261 working connections
from 20,000 attempts. That remains an unresolved capacity finding, not a
universal NAT-map limit: ordinary masquerade uses one NAT entry, DNAT uses two,
and firewall tracking consumes additional entries in its separate map. The
active-state count excludes expired records and is not a map-occupancy or
eviction-pressure metric.

The [17 November instrumented rerun](https://github.com/Velstra/sentinel/blob/main/docs/qa-nat-failure-diagnostics-2026-11-17.md)
passes through 16,000 and fails at 17,000/20,000. At 20,000 attempts, 19,992
connections initially echo but only 16,320 pass the later probe; missing
firewall state correlates with loss while their NAT bindings remain owned.
This is not a supported connection-limit claim or final-image qualification.

A later [same-day candidate rerun](https://github.com/Velstra/sentinel/blob/main/docs/qa-nat-expiry-2026-11-17.md) also
reproduces loss below that pressure boundary: 12,000 initial connections pass,
but only 3,253 later echoes are verified despite recorded established state.
At 20k, none matches the required probe round; this includes delayed/wrong-round
responses as well as timeouts and must not be described as zero packet delivery.
The root cause of the early loss is unresolved; a 16k connection limit is not
qualified by the earlier run.

The [17 November standalone allocator](https://github.com/Velstra/sentinel/blob/main/docs/qa-nat-domain-2026-11-17.md) now
passes that unchanged nine-flow workload with nine initial and held echoes,
nine unique public ports and zero NAT failure counters. All 21 programs load
on all three verifier kernels. This complete-domain search is not enabled
with HA or conntrack synchronization, and its extra lookup cost is not yet
performance-qualified. It does not fix publication, collection or LRU loss.

Its full pressure rerun remains red:928 of the first12,000 requests were not
attempted before the unchanged45-second opening deadline. At20,000 requested,
19,072 connections initially worked but only16,321 later echoes passed;
missing firewall state accompanied2,753 ownership failures while NAT bindings
remained owned. Do not advertise a supported connection limit or relax the
deadline based on the sparse-collision fix.

The 16 November candidate reproduced the nine-flow admission failure with only
8 of 65,536 reverse-map entries occupied. Atomic reservation prevents that claim
path from replacing a foreign owner; it does not make the allocator complete or
remove expiry, cleanup and LRU races. ICMP echo ownership passes six targeted
packet cases on the same candidate, not a full concurrent allocation-race gate.

The [17 November expiry correction](https://github.com/Velstra/sentinel/blob/main/docs/qa-nat-expiry-2026-11-17.md) passes
eleven targeted packet cases, including reuse of an expired DNAT tuple and
canonical router-state lookup despite an expired tenant entry. Expired lookup
no longer deletes NAT state. This is **not** garbage collection: retained
expired reservations, generic paired publication and LRU loss remain separate
ownership/admission problems. The exact outlined object passes all three
kernel verifiers; this does not certify a final release image.

`nat-capacity-pressure` tests the held-connection requirement separately from
occupancy telemetry. It runs real client/masquerade/backend traffic with unique
echo payloads and retains raw maps and per-flow failures before rejecting a
run. A 64-flow smoke pass is not 20,000-flow qualification. The test does not
alter capacity, insert synthetic state or waive known connection loss.

## Run the oracle comparison

Build workstation: Linux, Nix with flakes, writable `/dev/kvm`. Never run these
on an installed appliance or production interfaces.

```sh
python3 -B -m unittest discover -s nix/conformance -v
nix build .#checks.x86_64-linux.dataplane-conformance -L --out-link result-conformance
cat result-conformance/conformance.json
```

The six-VM topology uses separate LAN/WAN segments for nftables and Sentinel.
Both have identical addresses, policies, payloads, MTUs and kernel versions.
The endpoints use native sockets, not Fabric's parser. A peer reports the actual
source address and payload digest; TCP also verifies the returned payload.
The test independently validates the oracle's expected result before comparing
Sentinel. A failure on both sides is a setup/oracle error, **not** a pass.

The initial inventory contains 17 cases: IPv4 TCP/UDP masquerade, four-MiB
bidirectional TCP, fragmented UDP, echo and fragmented echo, RELATED ICMP
port-unreachable, IPv6 TCP/UDP forwarding, TCP/UDP DNAT, unsolicited IPv4/IPv6
drop, IPv4/IPv6 TCP reset, and a 1280-byte egress-MTU fault. This inventory is
finite: it does not yet cover overlapping/out-of-order fragments, every TCP
state, NAT exhaustion, malformed packets or full IPv6 extension-header cases.

Receipts include kernel versions, object/config hashes, nftables rules and
counters, observed payloads and the complete comparison. Packet captures remain
in the VM test driver's output. On a rejected Nix build, inspect `nix log` for
`CONFORMANCE_RECEIPT`; a failed derivation is not a registered release artifact.

The 14 November targeted checkpoint passes 15 of these 17 cases, with the
netfilter reference independently meeting all 17 expectations. Fragmented UDP
SNAT and fragmented echo SNAT still fail, so the whole gate remains red. The
comparator validates both probes' expectations against its own case inventory;
matching packet loss or matching rewritten expectations cannot count as success.

## Run the kernel matrix

```sh
nix build --keep-going -L \
  .#checks.x86_64-linux.ebpf-verifier-6-6 \
  .#checks.x86_64-linux.ebpf-verifier-6-12 \
  .#checks.x86_64-linux.ebpf-verifier-6-18
```

Every lane loads all shipped entry points into the guest's kernel verifier;
receipts record the actual `uname -r`, object SHA-256 and individual programs.
CI runs each lane independently on PRs and nightly and retains failed-load logs.
No rejected kernel is silently replaced with 6.12 or marked as an expected pass.

The 14 November working-source checkpoint loads all 21 entry points on
6.6.159, 6.12.113 and 6.18.57 with the same ELF SHA-256:

```text
2af0a7e7c0d7fe66a3be34fb705147aa19c4aa3df3a62adb726b2aba64e1d411
```

That receipt qualifies only this object on those guest kernels. It does not
qualify a different locked Fabric revision, a final image, NIC drivers or
packet behavior. A subsequent hairpin repair, ELF SHA-256
`18e8bfe667fb117d7684143d478440f184e04b01f97a302e671b06868582a860`, also passes
all three kernel checks. It passes 18 targeted ICMP cases on each of ordinary
SNAT, DNAT and hairpin, plus five policy controls. The full differential gate
still fails: the reference forwards two malformed error variants that Sentinel
rejects on all three paths. A subsequent test-only extension also proves
rejection after deleting the exact physical flow state, on the wrong ingress
interface with reverse-path filtering disabled, and after idle expiry: 62/62
Sentinel cases pass. Those checks prove actual injection and no state refresh;
they do not turn the six reference discrepancies into passes. General RELATED
qualification remains open.
Fragment NAT and redirect performance remain open as well.

The endpoint follow-up also reads the real UDP error queue (`IP_RECVERR`), not
only packet captures. Linux delivers the bad quoted IPv4 checksum and unassigned
Time Exceeded code 2 to the application on all three NAT paths; Sentinel drops
both. These six differences remain failures. Keeping the stricter checksum
check versus matching Linux requires an explicit compatibility decision:
[RFC 5508 section 4.1](https://www.rfc-editor.org/rfc/rfc5508#section-4.1)
recommends dropping an invalid embedded IPv4 checksum. That recommendation does
not settle unknown ICMP-code handling. No exception has been approved.

Those 14 November RELATED discrepancies are historical. The
[17 November candidate](https://github.com/Velstra/sentinel/blob/main/docs/qa-nat-expiry-2026-11-17.md) passes the expanded
strict UDP-quote comparison: 145 observations across 19 reports, including
opaque error codes, deliberately invalid quoted checksums, wrong ingress,
missing physical state and idle expiry. A stale XOR stimulus was first rejected
because it injected different checksum errors into the two lanes; the reviewed
constant-error stimulus then passes without relaxing the comparator. This
supersedes the targeted UDP-quote discrepancy, not general PMTU, TCP quotes or
fragmented NAT. No exception or final-image qualification is implied.

A later loader-only rollback repair is separately qualified with object SHA-256
`af9bc39c35f0d231621402efb3869f63c4e0904909b0c6fb7d5730428680d736` on the same
three kernels. Its live address-change test proves that a failed configuration
apply cannot reopen stale maps after an intervening address change. The same
race test fails against the previous loader. This source-stamped object has its
own verifier receipts; older packet results are not a final-image certificate.

## NAT failure diagnostics

On builds containing the NAT diagnostics change, `sentinel show firewall statistics`
reports two additional packet-attempt counters:

| Counter | Meaning |
| --- | --- |
| `egress_nat_no_candidate` | The bounded NAT candidate search found no claimable/reusable binding. This can happen with an almost empty map; it does **not** mean the map is full. |
| `egress_nat_claim_failed` | A new binding could not be reserved because the map helper returned an error other than a competing insertion. This alone does not identify a capacity failure. |

These are reasons within `egress_dropped`, not additional drops to sum into it.
Retransmissions count again; the values are not counts of failed connections.
Reads across counters/CPUs are not atomic, and counters restart with the agent.
Missing counters on an older image must not be interpreted as zero failures.
They do not repair the collision/admission, ownership-reclamation or established
state-retention limitations above, and are not evidence of final-image qualification.

## Established-flow redirect acceptance

A router fast path must not be implemented by simply enabling Fabric's existing
FIB redirect: that bypasses TC egress, including egress policy and source NAT.
Before enabling one, require all of the following:

- Only fully admitted established flows; policy-generation and HA lease checks
  on **both** ingress and selected egress, with immediate revocation on changes.
- Correct SNAT/DNAT in both directions, neighbour/FIB refresh, TTL/checksum,
  MTU/ICMP handling and a safe kernel fallback for unsupported packets.
- No bypass of shaping, PBR/VRF, IPsec, raw-IP tunnels or other egress services.
  Ineligible flows stay on the classified kernel/TC path, not an unchecked path.
- Differential traffic tests run with fast path both on and off, including
  policy replacement, route withdrawal and an established-flow HA failover.
- Packet counters prove redirect, not `XDP_PASS`; an independent receiver
  verifies payload, loss and bidirectional state.

Performance publication then needs dedicated, disclosed hardware, native-XDP
driver, exact source/object/kernel hashes, packet sizes, pinned cores/queues,
warmup and repeated measurements. Compare identical policies against nftables
both without and with flowtables; report loss, latency and the sustained packet
rate per actual dataplane core. Shared QEMU timings are regression evidence,
not hardware Mpps benchmarks.
