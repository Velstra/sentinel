# High availability and config sync

**Experimental.** Use a dedicated lab and retain console access to both members.
Selected pairing, state-sync and flow-failover tests exist; that is not complete
HA qualification or a rolling-upgrade guarantee.

## Choose the failure model

| Mode | Authority | Important limitation |
| --- | --- | --- |
| `witness` | An independent witness grants short forwarding leases to one member. | Loss of witness authority can stop forwarding even when both appliances are healthy. An authenticated witness preflight and outage-continuity qualification remain open. |
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
   enrollment credential of 32–1024 non-control bytes. The credential starts its
   HTTPS machine API even with the web console disabled, but never widens its
   listener: an unset address remains `127.0.0.1`, including when web and sync
   are both enabled. Save both configurations and verify the actual endpoints
   before pairing. A custom `services web port` must appear in the peer endpoint.
   Keep the credential out of shell arguments, public logs and screenshots.

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
