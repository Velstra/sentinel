# Verify witness-backed HA

Use two matching Sentinel appliances and a reachable, independent witness when a partition must leave at most one node authorized to forward. The witness grants a timed lease; a kernel guard enforces its expiration on data interfaces.

## Prepare the control path

Use distinct member control addresses and matching logical data-interface names. The control link and its underlying links must stay outside the fenced data interfaces. Allow each member to reach the witness and the secondary management API. Set a strong enrollment secret on the secondary, using the site’s credential-handling procedure.

## Enroll the witness and pair the members

On a member, derive the witness key from the pair enrollment credential. Enter the credential at the prompt:

```sh
sentinel ha witness-key
```

Configure the witness with the returned cluster ID and derived key; restrict it to the two member control addresses. Configure the primary with its intended witness while HA is disabled. Then pair from the primary, using the secondary’s actual HTTPS management endpoint:

```sh
sentinel ha pair 192.0.2.12:8080
```

The address is illustrative; use your dedicated control network. The command prompts for the enrollment credential. The witness receives its derived key only. For enrollment, topology, timing and recovery settings, see the [HA configuration reference](ha-reference.md).

## Observe the owner, then verify a failover

```sh
sentinel show ha
sentinel show vrrp
```

Check each member’s role, authority and replica readiness. Run failover acceptance on an isolated evaluation network with a continuous test flow and console access to both members. If the active member loses its lease, the old member must stop forwarding. The standby needs valid authority and sufficient replica state to take over; state continuity depends on the workload and replication status.

## Run the multi-VM acceptance test

```sh
nix build .#checks.x86_64-linux.ha-witness-failover -L
```

The fixture pauses the former active process while its kernel remains alive, monitors a client connection, and checks that the old path does not continue forwarding after expiry. Do not extrapolate lab timings into a deployment SLA.
