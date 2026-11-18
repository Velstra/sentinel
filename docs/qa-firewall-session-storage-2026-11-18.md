# Compact firewall storage contract

**Partial implementation, not a fixed traffic gate.** The new common types
pack both directional firewall states under one canonical key. The production
`FW_FLOWS` map, packet programs and HA protocol have not switched formats.
The previous traffic result remains 20,000 opened / 16,324 retained.

## Candidate

- Common storage model SHA-256:
  `b968e65fc71278a7a404367092dd4fe1a09a4fec0f75f092d5e8ffe9b6d7aca0`.
- Kernel probe SHA-256 (source):
  `2265ba8b27fb603150313952dabbf5712e3c53b3f8a77506a32458388d994b02`.
- Common exports SHA-256:
  `d67afac6af21594eac714587e02d798859a3199d9e37a33ed19012c3ce77f5d1`.

All compilation and execution are on the remote test builder. The isolated
probe never attaches a packet program or opens an appliance's live maps.
Normal unprivileged Cargo runs do not execute the ignored root-only probe;
the dedicated VM fixture explicitly runs it and requires its receipt.

## Verification status

The final frozen candidate passes 263 common tests (including 11 new storage
tests), 14 documentation tests and scoped warning-denying Clippy. The explicit
root-only storage test passes on all three kernels; the final run completed
at 14:41:08 UTC on 18 November. Actual KVM descriptors were observed on the
remote builder. No guest remained at the final 14:42 check.

| Kernel | Storage/capacity | Synchronized claim rounds | Whole-value reads | Mixed values |
| --- | --- | ---: | ---: | ---: |
| 6.6.159 | PASS | 2,048 | 32,289 | 0 |
| 6.12.113 | PASS | 2,048 | 32,623 | 0 |
| 6.18.57 | PASS | 2,048 | 28,441 | 0 |

Every kernel retains all synthetic directional values at 20,000 modeled flows
(40,000 physical entries), then at 32,768 modeled flows (65,536 entries).
Overflow refuses the new key without changing existing values. Four workers
produce exactly one winner per key, with both stored versions observed in the
separate concurrent read/write check. These are observed syscall-map results,
not a proof about packet-program in-place updates or read/modify/write races.

All three guests execute the same probe binary, SHA-256:
`b0a9f998e767e8fae01212ec2892946bf91ee8a5a118ea4282654cb191c50f9c`.
All 15 evidence files (including logs, raw receipts and the test binary) were
individually checked. Evidence archive SHA-256:
`5106b9e54f90789834ec44ab94f07ba67d46e965351ac9703668c4f346e9c946`.

Log SHA-256 values:

- Build/contracts: `c61192bc03658863c7e139c2f60cd5ceb259f18a3cc7bd28bcd8f7faa6a8ccab`.
- 6.6: `cfe5fa17c24799644566f35445ec9e54264efb55343461d1fd5ca6f9aa4da86a`.
- 6.12: `39b335a4a32fc8664a4fade968bd7aece3b4a1d34f5af0bc16d3882937375dc0`.
- 6.18: `2c73a6bd32f2dbaaba7fef477d89934499504a576b6c0da57bcd2b27d2012ba8`.

The initial harness build failed on a missing Aya trait import, before any VM
test ran; its failed logs are retained. An intermediate kernel suite passed
but synchronized workers only once. Raw evidence showed one worker could get
ahead, so the final suite requires two rendezvous per key and reruns all kernels.
No failed build or weaker intermediate run is counted as final qualification.

## Required runtime observations

The kernel test creates synthetic records representing two policies and both
directions of each connection. **It creates no TCP sockets.** It must verify:

- All directional values retained through 20,000 modeled flows, then through
  the full 65,536-entry table (32,768 modeled two-policy flows).
- New-key exhaustion and duplicate `NOEXIST` claims do not evict or replace
  retained owners. `EXIST` can update an owner at capacity, not create a new one.
- Four workers rendezvous before and after each of 2,048 claims, producing
  exactly one complete winner per key.
- Whole-value syscall updates expose neither mixed directional values nor
  absent state; both versions and an active writer must actually be observed.

## Scope and next gate

Distinct policies and independent directional ages/phases are preserved.
Packing rejects incomplete/conflicting pairs instead of synthesizing permissions.
This does not serialize packet read/modify/write, atomically admit a flow across
multiple policies and NAT, implement reclamation, or migrate HA state.

The 48-byte value replaces two 24-byte directional values and removes one
44-byte duplicate key per policy. Per complete pair, payload falls from 136 to
92 bytes. At a fixed 65,536-entry limit, preallocated key/value payload rises
from 4.25 to 5.75 MiB before kernel overhead. These are layout calculations,
not measured kernel memory consumption.

Next: integrate a safe writer/admission protocol and all map consumers, qualify
the actual packet object and HA migration, then rerun the unchanged stateful
20,000-connection traffic test. No production pin, image or release is qualified
by this storage contract.
