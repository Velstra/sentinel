# Witness-backed HA configuration

Use this reference with two matching appliances and one independent witness. Keep console access and verify management on both members before enrollment. The operator runbook is published at [Verify witness-backed HA](https://velstra.github.io/sentinel/operations/high-availability.html).

## Prepare and pair

1. Set distinct member control addresses and configure the secondary’s HTTPS management endpoint. Give the two members their site-issued enrollment secret of at least 32 bytes. Keep the control path independent of fenced data interfaces, including bridge and VLAN dependencies.
2. On a member, run `sentinel ha witness-key`. Supply the enrollment credential at the prompt. On the witness, configure only the derived key and cluster identifier. Allow both members’ control addresses and restrict the witness port at the host firewall.
3. On the primary, prepare the witness address with HA disabled. Run `sentinel ha pair <secondary-control-address>:<https-port>` and enter the credential at the prompt. Use the actual endpoint for that secondary.

Example witness configuration. Replace the example addresses and both placeholder strings before applying:

```toml
[system.ha-witness]
listen = "192.0.2.13:5440"
cluster = "<derived-cluster-id>"
key = "<derived-64-hex-character-key>"
member = ["192.0.2.11", "192.0.2.12"]
```

Example prepared primary:

```toml
[system.ha]
enabled = false
witness = "192.0.2.13:5440"
```

Pairing validates both complete documents and records a durable enrollment plan. If a connection fails mid-enrollment, retry the same intended pairing; review conflicting configuration edits before discarding a plan.

## Desired state and member identity

Replicate shared policy while retaining the distinct hostnames, control addresses, router IDs, interfaces and peer management identities. Include peer-specific facts when adding a static interface. Keep the membership and witness configuration consistent across the pair.

## Witness timing budget

The members and witness must agree on a usable lease. Use measured control-plane RTT; latency and liveness affect renewal. The configuration requires:

```text
2 × io-timeout-ms + 25 + 20 ≤ lease-ms
```

For example, a 200 ms I/O timeout needs a lease of at least 445 ms. A 500 ms lease meets that bound. Increasing the lease also increases the time authority can survive a lost renewal.

## Authority, readiness and recovery

```sh
sentinel show ha
sentinel show vrrp
```

Inspect the authority owner and the backup’s replication readiness. If the backup reports that it is not ready, review the reason before maintenance. The former owner’s kernel fences data traffic when its lease expires. A valid lease cannot make an incomplete replica ready. Flow state replicates asynchronously; protect the replication path if it carries sensitive metadata. WireGuard reestablishes peer handshakes during takeover.

## Acceptance checks

On a KVM-enabled x86-64 build host:

```sh
nix build .#checks.x86_64-linux.ha-pair -L
nix build .#checks.x86_64-linux.ha-witness-failover -L
```

The pair fixture exercises enrollment. The failover fixture observes traffic while the old active loses authority. Repeat the appropriate workload and failure cases in a staging environment with your link delays and topology.

## Qualification limits

HA remains experimental. This runbook describes witness-backed configuration, not proof that a particular image passed failover or partition testing. For mode selection, migration and known failure modes, also read the [current HA guide](https://github.com/Velstra/sentinel/blob/main/docs/src/handbook/ha.md). Retain an independent recovery path and qualify the exact image and dependency cohort.
