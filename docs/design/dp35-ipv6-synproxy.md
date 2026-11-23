# Design: IPv6 SYN proxy (audit DP-35) — planned for 1.1

Status: not implemented. In 1.0 the SYN proxy protects IPv4 only. `config check`
names every zone where a protected port is reachable over IPv6 and says that IPv6
SYNs there are not proxied. This note is the starting point for the 1.1 work. It
covers fabric (data plane, agent, HA sync) and Sentinel (tests only).

## Why it is not in 1.0

The verifier instruction budget is not the obstacle; a new tail-call program gets
its own budget. The risk is in two format changes that need care across upgrades
and HA pairs:

- a new pinned state map, which needs a state-layout version bump;
- a new conntrack-sync record, which needs a wire-version bump.

## Data plane (fabric `velstra-ebpf`)

1. **Placement.** A new tail-call program `velstra_synproxy_v6` in
   `VELSTRA_PROGS` (next free slot). `velstra_v6_state` enters it after a Pass
   verdict and before `npt66_ingress_v6`, for TCP whose header directly follows
   the fixed IPv6 header (`off == 54`). This is the IPv6 twin of the IPv4 rule
   that only 20-byte headers are proxied. It is entered when either
   `SYNPROXY[(policy, dport)]` (client half) or
   `SYNPROXY[SynProxyKey::server_side(sport)]` (server half) matches.
   - A program of its own gets a fresh 512-byte stack, the reason the IPv4 proxy
     runs in `velstra_forward`. It also keeps its paths out of `velstra_v6_state`.
   - The handoff is a per-CPU, single-use slot, with `ready` written last and
     consumed first, as `V4Verdict` does. A missing program or a stale handoff
     drops the packet.
2. **Scope.** The DP-31 key `SynProxyKey { policy, port, proto }` says nothing
   about the address family. Sentinel's per-zone entries therefore apply to both
   families unchanged, and no new configuration is needed.
3. **Cookie.** The IPv4 layout `epoch(5) | mss_index(3) | mac(24)`. The MAC is
   SipHash-2-4 over four words instead of two: client address high, client
   address low, ports with epoch and MSS index, and a family tag. It is unrolled
   with no loops, and `#[inline(always)]` because of the argument count.
4. **MSS.** The advertised IPv6 MSS is the configured MSS less 20 bytes, the same
   convention as the IPv6 MSS clamp (`ipv6_mss_ceiling`). The 3-bit MSS index
   points into an IPv6 table (1220…1440).
5. **Synthesised packets.** `plan_syn_ack6`, `plan_server_syn6` and
   `plan_server_ack6` in `velstra-common/src/synproxy.rs`, host-tested like the
   IPv4 planners.
   - Swap the MAC addresses and the 32 address bytes; hop limit 64.
   - Payload length 24 for a SYN-ACK carrying the MSS option.
   - TCP checksum over the IPv6 pseudo-header; IPv6 has no header checksum.
   - Call `bpf_xdp_adjust_tail` first (it invalidates packet pointers), then do
     one constant-offset write, as `write_synth` does.
6. **Sequence translation.** Both directions, with `csum_replace_u32`. The
   pseudo-header does not change, so the IPv4 helper applies as it is.
7. **NPTv6.** The proxy runs before the ingress translation. The state key holds
   the client address as it arrived and zeroes the server address, as on IPv4,
   so destination translation behind the proxy is transparent.

## State and persistence (agent)

- `SYN_FLOWS6: LruHashMap<SynFlowKey6, SynFlow>`, where `SynFlowKey6` is
  `{ client: [u8; 16], client_port, service_port, _pad }`. It is sized like
  `SYN_FLOWS`.
- It must join the pinned state maps of `[state] persist` (bump the agent's
  `STATE_LAYOUT_VERSION`), and the program arrays must stay pinned. Otherwise an
  agent restart drops every spliced IPv6 connection.
- The SYN-cookie secret (`SYN_SECRET`) is shared with IPv4.

## HA (conntrack-sync)

- A `Record::SynProxy6` record, with a wire-version bump and the existing
  refusal of mismatched peers. Without it every proxied IPv6 connection breaks on
  failover, because its sequence delta is lost.
- The HA policy digest is unchanged: it already records the `[[synproxy]]`
  entries.

## Sentinel

- Remove the IPv6 note from `synproxy_out` (`src/compile.rs`), or keep it only
  for zones the data plane still cannot proxy, such as SYNs behind extension
  headers.
- Update the handbook (firewall, SYN-flood protection) and the limitation row in
  the data plane support page.

## Tests

- **Host:** cookie (an IPv4 and an IPv6 cookie of the same ports differ;
  changing the epoch or MSS index invalidates the MAC), the three planners,
  checksums against a reference implementation.
- **`checks.synproxy`**, extended with an IPv6 client:
  - a page and 256 KiB through the splice;
  - 200 spoofed IPv6 SYNs raise `synproxy_challenged` without moving
    `synproxy_admitted`;
  - the DP-31 negative over IPv6: an outbound LAN SYN to the protected port is
    not proxied.
- **`checks.ha-synproxy-failover`**: an IPv6 flow survives failover.
- **`checks.agent-restart-persist`**: a spliced IPv6 connection survives an agent
  restart.
- **Verifier:** `velstra_synproxy_v6` on 6.6, 6.12, 6.18 and the CI runner kernel,
  under the 700,000-instruction budget `velstra verify-ebpf` enforces.
