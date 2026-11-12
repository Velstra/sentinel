# Routing and dataplane safety backports

## Fabric synthesized-reply TOS (OSQA-169)

`fabric-reply-tos.patch` clears DSCP/ECN in synthesized TCP reject and SYN-proxy
headers, matching the TOS-zero headers used by their checksum planners. On the
installed QA2 image, an independent native client gets immediate refusal for
TOS0 but times out for TOS184/40/252. Wire capture confirms that TOS184 RSTs
arrive with valid TCP checksums but invalid IPv4 checksums. NIC offloads are not
disabled. Ordinary routed TOS0 reject is independently working on QA2; this is
not a claimed explanation or closure of OSQA-001 on the older HA image.

The shared `apply-source-patches.sh` accepts a complete forward patch or a
complete already-applied reverse patch, and otherwise fails closed. It forces
the requested direction: GNU `patch --batch --reverse` alone can silently ignore
`-R` on individual files and falsely accept partial application (OSQA-180).
`checks.source-patches-unit` reproduces that old negative control and verifies
forward, repeated, either partial direction, incompatible, missing and empty inputs.
The fixed-output eBPF hash must be
regenerated for this code, not retained from the old object. The expanded
`checks.x86_64-linux.reject` exercises every DSCP class with native TCP sockets
and checks that the receiving kernel has no new IPv4 header errors. SYN-proxy
uses the same correction but still requires its separate live behavior gate.

## Fabric NAPT tuple mixing (OSQA-010)

`fabric-napt.patch` is applied after the reply-TOS backport to both the BPF
object and agent source trees. It shares the exact candidate computation with
the no_std host tests, mixes all tuple bits before reducing to the ephemeral
range, and uses explicit network byte order. Previously the high source-port
bits disappeared modulo32768, forcing ten real connections into one eight-port
window. Probe count, map ABI, reservation rules and failure behavior are unchanged.
This distribution function is not a cryptographic secret or a SYN-cookie hash.

The reviewed signed public basis is
`f72cf32c001293ee1a1d9873f4e145cdc1a7287d`. The backports reproduce all 79 runtime
Rust/Cargo files of the separately tested corrected source byte-for-byte.
Before the later conntrack/reply backport, the NAPT-only object was pinned to
`sha256-1H8zDeaIp0A5YBHKXg8e0ycrM5AL8RgXkVi6jOMIvdY=`; retaining a stale FOD
would silently reuse the broken allocation code. The corrected object passed
the actual appliance-kernel verifier. `checks.fabric-napt-unit` runs the shared
host regressions against the pinned, patched source. `checks.napt-concurrency` boots three
real VMs and holds 128 TCP sessions from two IPs through two backend ports,
verifying WAN source translation, unique translated ports and byte-exact replies.
It inspects the real TCX egress link/program and actual agent command, not a
classic-TC listing that cannot see modern Aya attachments.

These are scoped component regressions. New immutable-image, native OpenStack,
GUI and HA evidence must still be bound to the final candidate. Source backports
do not waive signed commits or production release criteria.

## Fabric routed TCP/UDP replies and closing-tuple reuse (OSQA-013/181)

`fabric-conntrack-reply.patch` follows both earlier Fabric patches. A live,
protocol-valid responder direction keeps its original routed TCP/UDP tuple
instead of acquiring a new masquerade mapping. The existing firewall-state
reply bit, phase, age and policy key are authoritative; untracked, expired or
invalid packets do not get an exemption. Intentional HA WireGuard VIP source
translation stays on its existing path. No map ABI or timeout changes.

A fresh TCP SYN reusing CLOSING/RESET state is classified as a NEW policy
decision, not established traffic. Denied openers do not delete/refresh old
state; the existing recorder replaces both directions only after admission.
Active connections and malformed SYN combinations remain invalid.

Seven new pure state tests bring the shared suite to165. Independent no-VPN
three-VM `checks.routed-reply` captures the external NIC: the old object sends
SYN/ACK from the WAN IP and a new port, causing RST, while ordinary outbound
SNAT still works. `checks.ipsec-provenance` independently exercises the same
reverse health path alongside the confidentiality guards. New object hash
`sha256-DAILkYqvprXveJofEhxWBtu5ojLQFTcRi1PG4cmZtyk=` was measured by explicit
isolated discovery, not copied from the old object. Kernel verifier, traffic,
HA, native and release evidence must still pass on this new object; source
and host-unit success alone are NOT a closure. Ordinary routed ICMP replies
are a separate path and are not certified by these TCP/UDP assertions.

## Fabric established NAPT ports across rolling upgrades (OSQA-190)

`fabric-ha-napt-port.patch` follows all three earlier Fabric patches. The real
mixed-version OpenStack trace replicated the existing reverse NAT entry, yet
the upgraded owner changed WAN source port39759 to57646 for the same TCP
sequence; the independent server reset the changed tuple. A new allocator must
not replace a live binding with its preferred candidate.

The bounded egress search now prefers valid owned existing bindings across the
whole current window and the deployed pre-avalanche allocator's window before
allocating a free port. A free earlier collision slot cannot renumber an active
flow. Only new flows use the corrected avalanche distribution. DNAT, hairpin,
foreign origin and expired entries do not qualify as owned live mappings. Map
and replication ABIs remain unchanged; legacy candidates are searched only for
existing state, never used to reintroduce the old new-flow allocation defect.
Keep this compatibility search while rolling upgrades from that allocator are
supported; this does not certify an arbitrary future allocation algorithm.

The shared tests include the exact captured tuple and hole-before-owned-slot
cases for ordinary NAPT and CGNAT. The actual newly compiled object hash is
`sha256-qMdamgqUkrqNvtdYmxfZRA3zP/gcUDKZFhVb2qQ7w+I=` (isolated discovery1538;
patch SHA256f7c4e325e730624534c91d81568eb9eb003be3db56d4d1cc5f7eebc94383f26d).
The regular `ha-napt-mixed-version` check runs the pinned public old agent/BPF
on the primary and the current agent/BPF on the secondary, requires the old
allocated WAN port, real replicated state, a single TCP socket, unchanged WAN
tuple and no RST through warm takeover and power loss. No test-written NAT or
role state and no runtime binary replacement. Compilation/host tests alone do
not close the finding: kernel verifier, real VM and new signed native evidence
are required; the original failed native trace must remain visible.

## Fabric fail-closed publication and DHCP FIB classification

`fabric-failclosed.patch` follows the DHCP-client backport and incorporates the
separate working-tree audit without changing the reviewed public input pin.
The default agent and BPF build use the same patch chain. Its source must match
the independently host-tested Fabric runtime/protocol files byte-for-byte.

- A unicast DHCP exception requires `NOT_FWDED`, not `FWD_DISABLED`. Linux
  6.12.113 returns the latter before looking up the route, so it cannot prove
  that an owned-address entry is still local. Broadcast discovery is unchanged.
- Masquerade must successfully publish reverse state and rewrite the packet;
  either failure drops rather than emitting a private or unreturnable tuple.
  Failed rewriting of a newly created binding attempts to remove that binding.
- A failed HA deadline publication attempts a zero deadline and publishes zero
  forwarding readiness instead of retaining the old userspace forwarding term.
  If both map writes fail, the old bounded kernel lease must expire; the log
  must not falsely claim the fence was cleared.
- CNI controller deletion retains its recorded port identifier on failure so
  a normal retry still knows what to delete. CNI is not a Sentinel appliance
  functionality certificate.

Isolated actual FOD compilation1655 measured
`sha256-ZaTzCatwITEGJNS4INPaXyogZSVFNk/dBzHruAHtFgg=`. Host gates1654 pass,
including the added shared/HA/CNI regressions; seven CAP_BPF tests are ignored
on this workstation and are NOT counted as passes. Real candidate kernel,
DHCP/NAT/HA traffic and signed native-image evidence remain required.

## Wren routing safety

`wren-routing-safety.patch` carries the same changes implemented in the sibling
Wren working tree, based on `547bd1b43d32dbdd9b4078ba35a4d99615eb7e85`:

- Apply VRF and global static-import policy before startup and reload admission;
  reconcile only admitted static prefixes (OSQA-167).
- Support less-specific prefix patterns and reject malformed Unicode raw extended
  communities without panicking (OSQA-166 and parser hardening).
- Use owned protocol/table/type/next-hop/metric selectors instead of deleting
  by prefix alone; preserve connected routes and retain failed withdrawals for retry
  (OSQA-026 and related reconciliation hardening).
- Recheck existence before every IPv4 metric-zero removal attempt, including
  transient retries. Linux treats priority zero as a wildcard even if its
  attribute is present, so a repeat after the original route disappeared could
  otherwise remove a different metric. The real namespace regression retains
  that other route. This does not provide atomic exclusion against simultaneous
  foreign FIB writers; Linux has no compare-and-delete operation for metric zero.
- Retain blackhole routes when reading back the owned kernel FIB.

The patch applies without fuzz to the reviewed signed upstream revision
`547bd1b43d32dbdd9b4078ba35a4d99615eb7e85`. The package hook first checks and
applies the complete patch. An overridden source that already contains the
complete patch is accepted after a reverse dry-run. Partial/incompatible source
trees fail the build; there is no best-effort or ignored patch failure.

This avoids shipping an unchanged routing engine while tests use a corrected
local override. Once the Wren changes are published, update the input pin and
remove the backport and its hook together. No HA code is removed from a newer
source override.

Verification includes Wren workspace tests, the real daemon startup/SIGHUP
integration test, `scripts/netlink-kernel-smoke.sh` in disposable namespaces,
and Sentinel's `checks.x86_64-linux.staticimport` three-VM TCP/UDP gate.
These are regression checks, not complete appliance or production certification.

The zero-priority behavior is explicit in Linux 6.12.113
[`fib_nh_match`](https://github.com/gregkh/linux/blob/v6.12.113/net/ipv4/fib_semantics.c#L855):
the priority comparison is conditional on a nonzero requested priority. The
namespace proof also runs against the workstation kernel, not just a mock FIB;
it is not itself a test of the frozen cloud candidate's kernel or HA behavior.
