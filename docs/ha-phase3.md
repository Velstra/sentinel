# Phase 3 HA implementation and qualification

Phase 3 is in progress. The authenticated state transport and config outbox do
not by themselves provide a release-ready HA pair.

## Implemented

* Wren keeps VIPs on their declared operational interfaces, repairs address
  removal, and recovers after link recreation. IPv6 elected addresses bypass
  DAD. GARP/unsolicited NA announcements repeat at 100ms and 200ms and then every
  30s. Both families reject VRRP packets whose TTL/hop-limit is not 255; peers
  must advertise the same VIP set.
* With a configured `system.config-sync.secret`, conntrack sync uses mutually
  authenticated TCP with a separately derived protocol key. Initial snapshots,
  updates and deletions synchronize NAT and IPv4/IPv6 firewall LRU state.
  Batched kernel reads avoid per-entry lookup syscalls. Local packet updates
  take precedence; imported entries are not echoed. Policy fingerprints and
  the live-reconcile lock reject obsolete state.
* Local CLI commits and API configuration updates queue a durable configuration
  revision. A systemd worker retries failed peers. Received revisions do not
  queue another push, and an old acknowledgement cannot erase a newer commit.
  An unsaved CLI revision left over from a prior boot is discarded when it no
  longer matches the saved or currently running configuration.
* Apply and persist share a reentrant cross-process lock. Saved configurations
  use exclusively created private staging files, flush, and atomic rename,
  including when an operator must escalate privileges. A received revision is
  revalidated after merging member identity. Shared MTU/VLAN/bridge/service
  intent converges while existing member addresses remain local.

## Configuration

On each member, keep its own addresses and reverse the peer endpoints:

```toml
[system.config-sync]
peer = ["10.3.0.2:8080"]
secret = "replace-with-a-strong-random-pair-credential"
# Explicit TLS certificate public-key pin; standard base64 SHA-256.
# peer-fingerprint = "..."

[system.conntrack-sync]
listen = "10.3.0.1:5429"
peer = ["10.3.0.2:5429"]
```

An omitted conntrack `interval` uses 50ms with a pair credential. An explicitly
configured interval remains in seconds and increases the potential state-loss
window. Configurations without a pair credential retain the legacy trusted-link
UDP transport. TCP authentication does not encrypt flow metadata: use a private
HA network or WireGuard for confidentiality. Both peers must explicitly name
their state-sync peers and run matching policy generations.

Existing receiver-specific addresses are preserved by interface name. A new
interface with a node-specific static address must first have its receiver
identity declared on that member; synchronization rejects ambiguous addressing
instead of copying the primary's address. This restriction still needs to be
integrated with the pairing/member-profile workflow.

## Automated acceptance checks

```sh
nix build .#checks.x86_64-linux.ha-kernel -L
nix build .#checks.x86_64-linux.ha-failover -L
nix build .#checks.x86_64-linux.configsync -L
```

`ha-kernel` exercises real LRU map batch reads, authenticated TCP delivery,
updates/deletions, local ownership and policy-generation rejection. The
four-node `ha-failover` test streams through a stateful default-deny firewall
using a shared WAN SNAT VIP, terminates the master VM without shutdown, and
requires sub-second promotion and continuity of the same TCP socket. The
config-sync VM test covers both CLI and API changes, a stopped peer, retries,
shared MTU convergence, and preservation of the receiver's IP address.

The Wren `scripts/vrrp-ha-smoke.sh` test uses isolated user/network namespaces
to verify IPv4/IPv6 VIP ownership, link recreation, address drift, shutdown and
rejection of routed VRRP packets. Existing nightly runners discover the new
smoke script and Nix checks automatically.

## Remaining release gates

* Select and implement split-brain fencing. A two-node heartbeat alone cannot
  distinguish a dead master from a network partition. A witness must be paired
  with an enforceable lease/fencing mechanism, including when userspace pauses
  while the kernel continues forwarding. Hardware/hypervisor fencing is an
  alternative. Fail-closed behavior without an independent decision sacrifices
  availability and needs an explicit operating policy.
* Gate cold-start promotion/preemption on synchronized state and implement
  authority handover for entries owned locally by a previous master. Test
  recovery, link partitions, process pauses and failback. The current crash
  test qualifies a warm, already synchronized standby.
* Implement `sentinel ha pair <peer-endpoint> --secret <token>` with authenticated
  TLS bootstrap, member identity profiles, idempotent recovery and the selected
  fencing policy; verify pairing in under 30 seconds.
* Qualify additional flow-bearing subsystems. This transport replicates
  `CONNTRACK` and `FW_FLOWS`; SYN-proxy sequence-adjustment state and WireGuard
  session state are not replicated by it.

These gates must pass before Phase 3 is declared complete or Phase 4 begins.
