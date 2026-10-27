# Witness-authorized high availability

Sentinel's leased HA mode uses two appliances and an independent witness. The
witness serializes forwarding authority; a pinned eBPF deadline closes the data
interfaces when that authority expires. A two-node heartbeat cannot safely
identify a failed peer during a partition and is not used as the authority for
this mode.

## Prepare and pair

Use matching Sentinel versions and logical interface names on both appliances.
Declare their real, distinct physical/control addresses first. Put the intended
shared firewall, NAT, service, routing and virtual-address policy on the primary.
The control interface must remain outside every fenced data interface and its
bridge/VLAN ancestry. Enable a reachable HTTPS management API on the secondary.
Use its machine enrollment credential, not an account token.

Put the enrollment credential on the secondary:

```toml
[system.config-sync]
secret = "a-strong-random-enrollment-credential-of-at-least-32-bytes"
```

The witness never holds that credential: it is also both members' API machine
token. Derive the witness's own key from it on either member (the token is read
from stdin, or prompted for without echo; add `--cluster` if the pair uses an
explicit one):

```sh
sentinel ha witness-key
```

and provision the independent witness through its own `appliance.toml` with the
printed `cluster` and `key`, plus the two members' control addresses:

```toml
[system.ha-witness]
listen = "10.3.0.3:5440"
cluster = "printed-cluster-identifier"
key = "64-hex-digit-derived-witness-key"
member = ["10.3.0.1", "10.3.0.2"]
```

The key authenticates lease sessions and nothing else; it cannot sign in to
either member. The handshake is keyed by exactly the bytes the members derive,
so a witness moved from `secret` to `key` keeps serving the same pair.

**Upgrading a witness** that still has `secret`: it keeps working (a refused
document at boot would take the pair's authority down with it), but every
commit warns until `secret` is replaced by `key` and `cluster`. A witness
without `member` likewise warns: any host that reaches the port can then hold
the sessions both members need. With `member` set, every other source is
closed before it can occupy a session, and each member has its own small
session pool, so neither a third party nor one member's abandoned exchanges
can starve the other's renewals. A witness on a Sentinel box should also only
admit TCP to its port from the two members in its input policy, for example
in a default-drop control zone, one rule per member:

```toml
[[rule]]
name = "witness-member-1"
from = "control"
source = "10.3.0.1"
proto = "tcp"
port = 5440
action = "accept"
```

A witness on another host needs the equivalent host-firewall allow-list. Upgrade both members and the witness together: the members' and
witness's runtime files carry the new timing fields.

The secondary's API starts over HTTPS on port 8080 when configuration sync alone
is enabled. Its self-signed management identity persists in
`/var/lib/sentinel/web-tls`. An explicitly configured web service retains its
own bind address, port and certificate paths.

Prepare the primary without activating an unpaired election:

```toml
[system.ha]
enabled = false
witness = "10.3.0.3:5440"
```

Then run on the primary:

```sh
sentinel ha pair 10.3.0.2:8080
```

The token is prompted for without echo, or read from standard input with
`--secret-stdin` (`printf %s "$TOKEN" | sentinel ha pair … --secret-stdin`). A
`--secret` argument is refused: a token on a command line is visible in the
process list to every local user and stays in shell history.

The command authenticates possession of the credential using a fresh challenge
bound to the peer's actual TLS public key **before** sending any bearer or
configuration secret. It records both management pins, captures explicit member
identities, validates both complete documents, and applies the secondary and
primary using the ordinary reconcile/persist path. The cluster identifier and
separate witness/state protocol keys are derived with distinct domains from the
enrollment credential. Alternatively, configure an explicit identical `cluster`
on the witness and prepared primary.

A private durable plan at `/var/lib/sentinel/ha-pair.json` survives an interrupted
or ambiguously acknowledged operation. Repeat the same command to finish it.
Enrollment compares canonical revisions under the common apply lock; a
concurrent configuration edit causes a conflict instead of being overwritten.
A partially completed operation reports that its plan remains pending. An
administrator must review a conflicting edit before discarding that plan.

The normal privileged re-execution passes the credential through stdin, rather
than adding it to sudo's command line. Authenticated HTTP helpers likewise pass
bearer headers through a private pipe to curl.

## Desired state and member identity

The resulting `system.ha.peer-identity` is part of canonical `appliance.toml`.
It records the peer's hostname, router ID, interface addresses and tunnel-local
addresses, state-sync endpoint, election preference, management endpoint/TLS
identity and dedicated control-WireGuard configuration. All declared data links, including links without VIPs, are fenced; the dedicated
control link and its declared connected WireGuard underlay are excluded. A control
VPN needs numeric static peer endpoints on an independent declared underlay; it
cannot depend on a fenced data/WAN link. Shared data VPNs retain
the same long-term identity. A received revision materializes the explicit peer
profile, validates it, applies it and saves it atomically; it does not enqueue a
reverse push.

A new static interface must include its peer-specific facts in this profile.
The receiver never guesses an address or copies a primary's member address.
For initial pairing, `--peer-identity path.json` supplies facts for new links
that are not already present on the secondary. Existing shared MTU, VLAN,
bridge, firewall, NAT, routing and service changes converge through the durable
configuration outbox. Failed deliveries remain pending, including credentials
needed to deliver a rotation after an outage or ambiguous acknowledgement.
Each push names the shared revisions it was built on, and a member applies it
only while it still holds one of them. When both members commit before either
push lands, both pushes are refused as a conflict instead of each member
silently taking the other's change: the outbox keeps them, the journal of
`sentinel-configsync.service` says `CONFLICT`, and `GET /api/v1/stack` reports
the member's `sync` as `conflict`. Roll back the member whose change should be
discarded; the other member's held push then applies there. Only the machine
credential may push (`PUT /api/v1/config-sync`); an account token is refused.
Both members must run the same Sentinel version: a push from a version that
does not name its base is refused as a conflict once the receiver has been
synchronized.
In leased mode, masquerade uses the egress link's single shared IPv4 VIP. Multiple
VIPs require an explicit `nat.source.to` so the source identity is unambiguous;
a member's private WAN address is never selected as the shared masquerade identity.
Changing the witness credential also requires updating the independent
witness; the pair fails closed while its authority cannot be authenticated.

`system.ha.enabled = false` fences a prepared/disabled pair and suppresses the
legacy VRRP election. Removing the HA configuration explicitly disables the
retained guard. An ordinary standalone diagnostic object cannot un-fence an
existing appliance.

## Witness timing budget

A lease is valid locally from the instant its member *started* connecting,
minus a 20ms margin, so every round trip to the witness is spent out of the
lease. One exchange is about three round trips (TCP connect, nonce and tag,
request and reply) and is abandoned after `io-timeout-ms`. The lease must
survive one abandoned exchange plus the coordinator's 25ms poll:

    2 x io-timeout-ms + 25 + 20 <= lease-ms

The defaults, `lease-ms = 250` and `io-timeout-ms = 80`, need a witness round
trip of at most 20ms (three round trips in three quarters of the I/O budget).
A distant witness needs both raised, for example a 50ms round trip needs
`io-timeout-ms = 200` and `lease-ms = 445` or more:

```toml
[system.ha]
lease-ms = 500
io-timeout-ms = 200

[system.ha-witness]   # on the witness
lease-ms = 500
```

Set the same lease on the witness and both members; a member honours the
shorter of its own lease and the witness's grant, which is always safe but
makes a too-short member lease flap. A longer lease lengthens the time a
failed owner keeps authority, so failover takes correspondingly longer.
Commit refuses a budget that does not fit; `sentinel ha pair` measures the
witness round trip first and refuses to pair across a link that cannot fit
the configured budget. Wren logs a warning whenever an exchange uses more
than three quarters of its budget. The coordinator's role file is accepted
by the data plane while it is at most `io-timeout-ms + 50ms` old (at least
100ms); the lease deadline inside it, enforced by the kernel, is what fences
forwarding.

## Authority, readiness and recovery

The witness durably records monotonically increasing authority terms before
acknowledging a new grant. It quarantines after restart for longer than a full
old lease. Renewals and claims require authenticated fresh sessions; a lease is
bound to the member, coordinator incarnation and common policy fingerprint.
The durable record also binds the exact complete baseline and agent incarnation.
Authenticated replies repeat that claim, allowing an unacknowledged warm or cold
grant to recover without treating stale or partial tables as empty.
Leases last 250ms, with a conservative local margin. Both kernel and userspace
use `CLOCK_BOOTTIME`, including system suspend. The persistent TC guard survives
ordinary hook teardown and agent exit; attached XDP and TC entry points enforce
the same deadline. A separately pinned `sched_process_exit` program revokes the
agent's liveness before its file table can detach NAT hooks; a graceful-exit
guard revokes it before userspace teardown. This prevents untranslated packets
and TCP resets during the remaining lease interval after an agent crash. The
appliance service runs in the host PID namespace used by this kernel fence.
Recreated data links receive the guard before being brought up. When a link leaves the guarded scope, reconciliation removes only the
Sentinel guard at reserved TC priority 1 / handle 1, after verifying the kernel
program identity; other filters remain intact. This assumes a trusted kernel and
monotonic clock; restoring a VM snapshot with old memory/clock state is not an HA
recovery procedure.

All VIPs are one transaction. The agent opens forwarding only after the
coordinator has installed every VIP and matched the exact agent incarnation and
complete state generation. GARP/unsolicited NA bursts follow the forwarding
acknowledgement immediately, at 100ms and 200ms, and periodically thereafter.
Preemption requires a complete current-generation replica. A restarted former
master accepts authoritative successor state, including deletions of its old
locally owned entries, while retaining local accounting counters. A partial
multi-map installation invalidates readiness until a complete snapshot succeeds.
Expired or partially installed tables never vote as empty state. A retained last
owner may accept a later witness epoch only when the grant names its exact
complete baseline and current agent incarnation, including after a long witness
outage. A single empty agent cannot displace a warm owner. If both agents lose their
state, fresh cold votes from both members allow node 1 to establish a new empty
epoch; flows lost from both machines cannot be recovered.

A **lone survivor** recovers on its own. When one member is gone for good and
the other restarts its agent (or reboots), the survivor is cold: it has no
claim to retry and no second cold vote. Once the witness has heard nothing
authenticated from the other member for `peer-silence-ms` (default 10000, set
on the witness; at least four leases), it grants the cold survivor a new empty
epoch under the survivor's own policy fingerprint. The silence is counted from
the witness's own start, never presumed across a witness restart. It decides
only that the other member's state is lost; whether authority may move at all
is still the witness's lease expiry, which the silent member's kernel deadline
precedes, so this never creates a second forwarding owner. A member that is
merely slow keeps talking to the witness and is never silent. One that returns
after such a grant holds a superseded generation and imports the survivor's
snapshot before it is eligible again. A member partitioned from the witness
for longer than the silence loses its flows to the survivor's new epoch.

**Readiness after a commit.** A commit changes the owner's policy fingerprint
at once, and the witness binds authority to it. Until configuration sync
delivers the same policy to the standby, the standby refuses the owner's state
and cannot take over. It is not made eligible under the old fingerprint: it
would then enforce the policy the commit just replaced and import entries
created under the new one. Instead the gap is reported: `show ha`, `show vrrp`,
the agent's `ha-status`, telemetry and the console HA card say
`Backup (not ready: <reason>)`, and the `sentinel-ha-watch` worker sends an
alert to the configured targets when a standby stays unable to take over for
more than 30 seconds, and again when it recovers.

State sync uses authenticated framed TCP at a default 50ms polling interval,
batched kernel map reads, ordered updates/deletions and policy/authority fencing.
It replicates NAT, IPv4/IPv6 firewall and SYN-proxy splice entries. An active
owner exports its complete baseline, including unchanged imported splices.
Activity time is sampled after each map dump, so concurrent kernel updates cannot
be mistaken for expired entries and turned into deletion records. Node-local
control connections retain their own firewall state, so a complete data snapshot
cannot overwrite or delete witness, state-sync, routing or management sessions.
Handshake
cookies not yet turned into a splice remain node-local and can require a fresh
handshake. A private HA link or a dedicated WireGuard control tunnel is required
when flow metadata must be confidential: authentication alone does not encrypt
it. Each member's Wren instance reconciles its own Linux FIB; use the unfenced
control network for BGP/OSPF sessions needed before takeover. Explicit legacy
second-based polling intervals are refused in leased mode.

WireGuard's ephemeral kernel sessions are not copied. Public learned roaming
endpoints travel in the authenticated state stream and are bound to the shared
VPN policy. Promotion reconstructs configured peers with their shared long-term
keys and initiates new handshakes. A root-only recovery file protects an
interrupted reconstruction. Unconfigured public keys cannot create peers; the
original persistent-keepalive policy is restored after initiation. Host UDP NAT
returns the encrypted traffic to the shared WAN VIP after takeover.

## Acceptance checks

```sh
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
nix build .#checks.x86_64-linux.ebpf-maps
nix build .#checks.x86_64-linux.ebpf-verifier
nix build .#checks.x86_64-linux.ha-kernel
nix build .#checks.x86_64-linux.ha-witness-failover
nix build .#checks.x86_64-linux.ha-witness-synproxy-failover
nix build .#checks.x86_64-linux.ha-masquerade-failover
nix build .#checks.x86_64-linux.ha-wireguard-failover
nix build .#checks.x86_64-linux.ha-pair
```

Run the Rust gates in Sentinel, Fabric and Wren. `ha-kernel` exercises actual
LRU maps, authenticated transport, successor ownership, deletions, accounting and
concurrent activity updates during batched dumps.
The five-node witness fixture tests a persistent NAT TCP socket, sub-second
promotion, paused coordinator/agent processes, control partitions, witness
outage/restart, synchronized failback, a non-member witness connection and a
lone survivor that restarts cold after its peer is lost for good. The WireGuard variant sends that socket
through an encrypted tunnel with a learned endpoint. The pairing fixture checks
credential rejection, enrollment in under 30 seconds, repeat enrollment,
member-specific addresses, both members' cold boots, persisted credentials and
automatic shared-policy delivery after those boots.

Retain `ha-failover`, `ha-synproxy-failover`, `conntracksync`, `configsync`, API,
commit, reconciliation and Wren namespace smoke checks as regression coverage.
The legacy VRRP and unauthenticated trusted-link UDP modes remain available
outside leased HA; they do not provide its witness fencing guarantees.
