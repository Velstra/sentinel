# Design note: a per-endpoint overflow window for masquerade ports

Status: proposed for after 1.0. Not implemented.

## Where 1.0 stands

The standalone masquerade allocator (fabric `velstra-ebpf/src/napt_domain.rs`)
gives each flow a fixed window of 128 candidate ports, scattered over its
source's port domain. It claims the first free one, and it finds an existing
binding by scanning the same window. Cost per new flow is bounded, and the
result depends only on the flow tuple (PERF-02).

The price is paid only when one remote endpoint is nearly saturated.
Contention exists only between flows to the same (remote ip, remote port,
protocol) from one public address. Refusal per new flow is about
`fill^128`, measured by fabric's `refusal_rate_by_domain_fill`:

| Fill of the endpoint's 32768 ports | Refused |
| ---: | ---: |
| 90 % | 0 |
| 95 % | 0.145 % |
| 99 % | 27.3 % |

## Proposal

Add a second window, for example 1024 further probes of the same per-flow
sequence. Scan it only for endpoints that are marked as overflowing.

- **Marker.** One entry per overflowing endpoint, keyed by
  (policy, remote ip, public ip, remote port, protocol). The allocator writes
  it before it claims any second-window port, and the claim refuses if the
  write fails. Discovery scans the second window only when the marker exists,
  so every other endpoint keeps the 1.0 cost.
- **Lifetime.** The marker must outlive every second-window binding of its
  endpoint. Refresh it from each such binding's packets and give it the
  binding timeouts. The userspace reclaimer may delete a marker only when a
  complete walk saw no second-window binding for the endpoint and the
  marker was not refreshed during that walk. The reclaimer can recompute
  window membership with velstra-common's `NaptDomain`.
- **Eviction.** A marker that is lost while second-window bindings exist
  makes those bindings undiscoverable. So it must not live in an LRU map,
  or it must be refreshed often enough to survive one, and a full marker
  map must refuse the claim rather than drop a marker.
- **Restart.** With `[state] persist` the marker must be adopted together
  with CONNTRACK. Pin it alongside the state maps (layout tag change), or
  rebuild the markers from CONNTRACK before the new programs attach. The
  removed 1.0 search bound failed exactly this way: it was not persisted.
- **HA.** Replicated configurations keep their own allocator; this does not
  apply to them.

## Why not in 1.0

The two simpler options both fall short. A larger flat window (256 or 512)
puts its cost on every new connection everywhere, only to help an endpoint
at more than 95 % fill. And 99 % fill of one remote ip:port is about 32,400
concurrent connections from one address, close to the hard 32,768 ceiling
that any NAT has. The real remedy there is more public addresses.

The marker is new datapath state with persistence and reclaim obligations.
Its failure mode (an undiscoverable binding) breaks established
connections, which is worse than the refusal it removes.
