# High availability and config sync

**Experimental.** Use a dedicated lab and retain console access to both members.
Selected pairing, state-sync and flow-failover tests exist; that is not complete
HA qualification or a rolling-upgrade guarantee.

## Choose the failure model

| Mode | Authority | Important limitation |
| --- | --- | --- |
| `witness` | An independent witness grants short forwarding leases to one member. | The witness is a single point of failure for forwarding: losing it stops forwarding on both members within one lease, even when both appliances are healthy (see [Witness loss](#witness-loss-is-a-single-point-of-failure)). |
| `two-node` | Two appliances exchange authenticated heartbeats without a witness. | A total partition can promote both members. Independent heartbeat paths reduce, but do not remove, that risk. |
| Legacy VRRP and sync | VRRP election and separately configured synchronization. | Not equivalent to fenced pairing; do not infer split-brain protection from a shared VIP. |

Do not mix these models or assume that two-node mode has witness-mode fencing
guarantees. No mode should be described as production-certified while the
release acceptance and open HA failure cases remain unresolved.

## Prepare two members

1. Install the same reviewed image on both. Save each node's configuration and
   verify console recovery before changing HA.
2. Prepare distinct, static control addresses, for example `10.3.0.1/24` and
   `10.3.0.2/24`. The route to the peer endpoint must use an explicitly declared
   control interface, not a shared/fenced data link. Prepare matching logical
   data-interface names and member-specific hardware bindings.
3. Keep a separate unzoned management NIC on an isolated management network.
   Give each node its own management IP and SSH bind address. Address binding
   alone is **not** cross-interface access isolation.
4. Configure the intended firewall, NAT, routing and VRRP VIP policy on the
   primary. The peer must have its own local addresses already declared. A
   newly introduced static link needs explicit peer identity facts, not an
   address copied from the primary.
5. On **each member**, explicitly bind `services web listen-address` to that
   member's static control address (`10.3.0.1` / `10.3.0.2` here), and keep TLS
   enabled. Set the secondary's `system config-sync secret` to a private, random
   enrollment credential: generate one with `sentinel ha secret generate` (32
   random bytes as 64 hex digits). A short or patterned secret is refused at
   commit, because the enrollment proof lets anybody who can reach the
   management port test guesses against it offline. The credential starts its
   HTTPS machine API even with the web console disabled, but never widens its
   listener: an unset address remains `127.0.0.1`, including when web and sync
   are both enabled. Save both configurations and verify the actual endpoints
   before pairing. A custom `services web port` must appear in the peer endpoint.
   Keep the credential out of shell arguments, public logs and screenshots.

6. **Run NTP on both members** (`services ntp upstream`). Certificate checks,
   one-time passwords, log timestamps and update freshness all read the wall
   clock. With HA WireGuard a member also aligns its clock with its
   predecessor's when it takes over (see Failure behaviour), but only within
   bounds; NTP is what keeps it right. The appliance's chrony steps any offset
   over one second as soon as it measures it (`makestep 1.0 -1`), so a member
   resumed from a VM pause is corrected at its next poll.

Do not activate an incomplete election by setting `system.ha.enabled = true`
manually. Pairing validates and records the member profiles.

## Pair without a witness

On the primary, after preparing the secondary as above:

```sh
sentinel ha pair 10.3.0.2:8080 --mode two-node
```

Enter the secondary's enrollment credential at the hidden prompt. For automation
use `--secret-stdin` with a protected secret source, never `--secret` or a token
in argv. An explicit cluster identifier must agree between prepared members.

Pairing authenticates the peer using a fresh TLS-bound challenge, captures local
identities and applies both documents. A partial attempt retains
`/var/lib/sentinel/ha-pair.json`; retry the same endpoint, mode and credential to
resume. Do not delete a pending plan to bypass a reported conflict.

Pairing refuses a default or explicit loopback listener before writing a local
plan or enrolling a peer. An explicitly configured wildcard is permitted but is
not required; prefer the intended control address and an explicit ingress ACL.

## Pair with a witness

Derive the witness-only credential on a member:

```sh
sentinel ha witness-key
```

Enter the same enrollment credential at the hidden prompt. If using an explicit
cluster, pass `--cluster` with that identifier. Provision the printed `cluster`
and `key` in the independent witness's `system.ha-witness` configuration; set
its listen endpoint and restrict `member` to the two control IPs. The witness
does not need the machine enrollment token itself.

Then pair on the primary:

```sh
sentinel ha pair 10.3.0.2:8080 --witness 10.3.0.3:5440
```

Members that compute the shared policy differently — an image whose compiler
numbers zones or encodes rules differently — never agree on the readiness
digest. During a rolling upgrade across such a change the standby stays not
ready and no state crosses; the switch-over to the upgraded member is an outage
with connection loss, not a warm failover.

A reachable TCP port does not prove that the witness will authorize the correct
cluster/key/member pair. Verify authority, standby readiness and actual traffic
before considering the lab operational. Do not deploy witness or member upgrades
independently unless that exact mixed-version combination has a passing test.

## Verify policy, identity and traffic

On **each** member:

```sh
sentinel show ha
sentinel show vrrp
sentinel show interfaces
sentinel show ip route
systemctl --failed --no-pager
journalctl -u sentinel-configsync.service -u wren.service -u velstra.service
```

Check one owner, a ready standby, the expected VIP, local addresses and SSH access
on both management NICs. Test a real client connection through the VIP; preserve
the same TCP socket during a controlled lab failover. A role label or matching
saved files alone does not prove forwarding or established-flow continuity.

Shared configuration changes use a durable sync outbox. Member identity includes
local interfaces, management/control endpoints and local SSH settings; do not
replace the secondary's complete configuration with the primary's file. A new
static link can require `--peer-identity` during initial pairing. Concurrent edits
can be refused as conflicts rather than silently overwriting one side: inspect
`sentinel-configsync.service` and the stack's sync state, decide which change to
retain, and resolve the competing revision deliberately.

Timing is a safety parameter, not a latency claim. Witness defaults use a 250 ms
lease and an 80 ms exchange budget; the lease must cover
`2 × io-timeout-ms + 45 ms`. Measure under load and test loss/recovery before
changing them. A larger lease also lengthens the time an old owner can retain
authority. Do not tune away a failure by making the guard less conservative.

## What a member trusts its peer with

The shared secret is the **peer credential**, not an administrator login and
not the member's machine token. A peer holding it can:

- read what a read-only account reads (the stack view, enrollment);
- push the shared configuration (`PUT /api/v1/config-sync`) and complete a
  pairing (`POST /api/v1/ha/pair`).

It cannot replace a member's whole configuration through the ordinary API,
post `configure` lines, stage updates or confirm or revert a commit-confirm
window, and it cannot post a different pairing to a member that is already
paired (re-pairing a paired member needs that member's machine token, or
unpairing it first; repeating the applied pairing works). Neither a push nor a
pairing changes who manages the receiver: its
accounts (with their SSH keys, password hashes and TOTP secrets), groups, AAA
servers, update channels and keys, SSH server and serial console stay its own,
so configure them on **each** member.

What the peer *can* change is the shared policy — firewall, NAT, routing, VPN,
services — and, through pairing, the HA identity. That is the point of
synchronization, and it means the secret is the authority to change the
traffic policy of both members: anybody who obtains it, or controls a member,
controls what both members forward. Keep the secret to the two members,
rotate it if either is suspect (set a new generated value on both; the outbox
delivers the rotation with the old credential), and treat a compromised
member as a compromised pair. Enrollment hands the peer the receiver's
configuration without its accounts, AAA servers and update channels; the
shared policy secrets in it (VPN keys, PSKs) are the pair's anyway.

Each source address may request ten enrollment proofs per ten minutes (a
flood of fresh addresses can delay a pairing; retry), thirty invalid bearers
make a source's further invalid ones `429` for five minutes, and every
non-read use of the peer credential or the machine token is logged with its
source address (`journalctl -u sentinel-api`).

### Upgrading a pair with a weak secret

An appliance upgraded with a secret that is now considered weak still boots,
keeps its pairing and serves its API, prints a warning at every apply, hands
out no enrollment proof, and refuses every configuration change until the
secret is rotated. Descriptive strings such as `ha-test-credential-…` count
as weak; use `sentinel ha secret generate`. Rotate it on
both members, one commit each. The first boot of the new image also replaces
`/var/lib/sentinel/api-token` when an earlier release had written the secret
(current or since removed) into it; read the new machine token from that
file. A token you placed there yourself is kept.

### Mixed versions during an upgrade

Pairing and config-sync keep working between a member that has been updated
and one that has not: the proof, the bearer and the base revisions a push
names are understood by both. While the members run different versions, do
not change accounts, AAA, update, SSH, console, BGP update-source or PPPoE
local-address settings on either member: the updated member keeps its own, the
older one still sends and adopts them, and the two then disagree on their
shared revision, so the next push is held as a conflict (resolve it as any
conflict). Pushes from the updated member still replace these settings on
the older one, as before the upgrade. Finish the upgrade promptly.

Upgrade in this order: the standby first, then fail over to it, then the old
primary. **Never fail back onto a member that is not yet upgraded.** A
masqueraded connection that an upgraded (1.0) member owns does not survive a
takeover by a pre-1.0 peer. The older allocator looks for the connection's
public port in a different place, so it does not find it and assigns a new
one, and the connection breaks. The other direction is covered: connections
the older member owns survive the switch-over to the upgraded one
(`checks.ha-napt-mixed-version`). An upgrade from 0.4 is not hitless anyway,
because 1.0's members compute a different readiness digest (see above).
## Standby readiness

`sentinel show ha` on the standby must read plain `HA Backup`. A reason in
parentheses means the witness would refuse it authority right now, and a
failure of the active member would not fail over. The readiness digest covers
the shared policy only: a rule `to firewall` is written symbolically (each
member's agent expands it to that member's own addresses, DHCP leases and the
VRRP addresses it holds) and a captive-portal gate names each member's own
address, and those addresses are deliberately left out of it, so two members
with the same shared configuration agree. A standby that stays
"policy differs from the owner's" after configuration sync has delivered means
the shared policy really differs; inspect both members' configurations. A
state-sync refusal for that reason is logged as a warning (once a minute).

| Reason | Meaning |
| --- | --- |
| `policy differs from the owner's; awaiting configuration sync` | A commit has not reached this member, or the shared policy differs. |
| `fresh agent has no state snapshot yet` | The agent just started. It imports the owner's state within a second. |
| `no complete state snapshot from the owner` / `state snapshot is stale` | State sync from the owner is not arriving. |
| `stale state discarded; awaiting a state snapshot` | State stayed unusable for 5 s and was dropped, see below. |

A standby whose replicated state stays unusable for 5 s (stale, or imported
under a policy it no longer holds) discards it and votes as an empty member.
This removes a deadlock: if the active member's agent crashed meanwhile, it
restarts empty too, and two empty members let the witness open a new epoch.
Established connections do not survive that path; new ones do.

## Failure behaviour (witness mode)

These cases are exercised by `checks.ha-witness-failover`:

- **Data-plane agent crash on the active member** (`velstra` killed, OOM): the
  kernel fence closes the old member at once; the ready standby takes over and
  established flows continue (the check bounds the gap at 3 s; about 1 s was
  measured in the VM check). The crashed
  member restarts empty, imports the new owner's state and rejoins.
- **Routing daemon crash** (`wren` killed): the lease lapses and the standby
  takes over the same way.
- **VM pause, suspend or live migration**: a resumed member catches up from the
  current owner by itself and is eligible again; the next failure still fails
  over. A paused VM's clock stops with it, so for up to one lease (250 ms by
  default) after it resumes, its data plane can still consider its old lease
  valid while the witness has already granted the peer. Drain or demote an
  active member before migrating or suspending it.
  Its wall clock also falls behind by the pause until NTP corrects it. Both
  members answer WireGuard peers with one shared identity, and a peer accepts
  a handshake from that identity only with a newer timestamp than the last
  one. So a member that takes over with HA WireGuard interfaces first steps
  its wall clock forward to its predecessor's, which the owner replicates
  over the authenticated state stream. Tunnels then follow the takeover in
  about a second (`checks.ha-wireguard-failover`, including preemption by a
  member that was paused). The step is logged with the old and new time and
  is never taken backward. It is refused when the lag exceeds 10 minutes, and
  when this member's clock is NTP-synchronised and its predecessor's is not.
  A refused step still takes over, and `sentinel show health` reports
  `ha-clock-behind-peer`; tunnels may then stall for up to the clock offset
  until NTP corrects it.
- **Agent crash while the witness is away**: both members end up unable to use
  their state; once the witness returns, the pair opens a new epoch on its own
  (see Standby readiness). Expect a short outage and new connections.

### Witness loss is a single point of failure

Losing the witness stops forwarding on both members within one lease. This is
the price of split-brain protection, not a defect that a setting can tune away:
the active member cannot tell "the witness is down" from "I am cut off from the
witness and the peer is not". In the second case the witness grants the peer
when the lease runs out, so a member that kept forwarding on its own would
forward alongside its successor. When the witness returns, the previous owner
is granted again from its retained state and forwarding resumes.

Continuing through a witness outage would be safe only with the peer as a
second vote: the active member keeps forwarding only on the peer's fresh,
authenticated promise not to seek authority itself, and a returning witness
waits out every such promise. Sentinel does not implement that protocol. Until
it does, run the witness on independent power and network, monitor it, and
prefer `two-node` mode only if availability through a witness outage matters
more than exclusive ownership through a partition.

## Configuration writes on either member

Master/Backup describes forwarding ownership, not configuration permissions.
An authorized commit on either member can replicate to its peer, including a
commit made on Backup. Use one management session at a time for shared policy;
do not treat the standby as a private configuration sandbox. Conflicting
concurrent revisions are rejected and remain pending for operator resolution.

A CLI `commit` on a member that is not the forwarding owner (HA Backup or
Fenced) ends with a warning that names this member, the current owner and the
term; the commit still applies here and replicates. If the role cannot be read
before the commit, the warning says so instead. Check the member role and
pending synchronization state before changing policy.

## Regression entry points

```sh
nix build .#checks.x86_64-linux.ha-pair -L
nix build .#checks.x86_64-linux.ha-two-node -L
nix build .#checks.x86_64-linux.ha-two-node-flow -L
nix build .#checks.x86_64-linux.ha-witness-failover -L
nix build .#checks.x86_64-linux.ha-napt-mixed-version -L
nix build .#checks.x86_64-linux.configsync -L
```

Use the [test inventory](../reference/tests.md) for scope and evidence rules.
Legacy configuration vocabulary is listed under
[system synchronization](system.md#ha-config-sync); it is not the recommended
way to assemble a new fenced pair.

## Migrate legacy state sync

Unauthenticated UDP state replication is no longer supported. An enabled
`system.conntrack-sync` block needs explicit state peers and a shared, random
32–1024-byte `system.config-sync.secret` on both members. Listen-only replication
is rejected. No credential or management listener is configured automatically.

Before an image upgrade, save both configurations and review the intended
pairing mode. Use the authenticated pairing procedure above for a new fenced
pair; do not silently turn a legacy VRRP deployment into a different failure
model. Provision the shared credential through a protected configuration or
hidden prompt, not command-line arguments or public logs. Configuration sync
delivers policy over HTTPS; the separate VCS2 TCP state transport authenticates
flow updates but does not encrypt them.

If retiring legacy state replication, remove the block on **both** members
before upgrading:

```text
sentinel configure
delete system conntrack-sync
commit
save
```

This disables state transfer; it is not an HA migration or a guarantee that
existing connections survive failover. Re-test actual traffic and established
flows against the same upgraded image. Rejection of an unsigned legacy
configuration proves only the negative safety check, not positive HA acceptance.
