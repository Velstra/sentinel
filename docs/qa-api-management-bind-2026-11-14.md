# Management listener and telemetry contract — 2026-11-14

Status: source, host checks, isolated package tests, real listener VM and migrated
config-sync gate pass. Full HA qualification is pending.
This is not final-image or browser certification.

## Changes

- `net::apply_api` uses the one configured `services.web` address and port when
  either web or config-sync enables the API. A credential never implicitly
  changes loopback to `0.0.0.0`. Explicit wildcards remain an operator choice.
- HA pairing rejects default/configured loopback and non-TLS listeners before
  local plan writes or peer enrollment, and repeats local validation under the
  apply lock. Config-sync-only member identity now honors a custom web port.
- Legacy config-sync keeps the receiver's web listen address and port. Other
  web settings remain shared policy. Shared revisions normalize only those two
  endpoint fields to fixed explicit values, keeping the web table serialized so
  a TLS change cannot disappear from its hash.
- The config-sync and HA fixtures now declare their intended control addresses.
  The receive-fault probe takes an explicit fixture host; its disposable ENOSPC
  server remains isolated on loopback port 18080.
- OpenAPI describes the optional additive `TelemetryFrame.system`, its nullable
  observations, units and filesystem rows for both local and peer snapshots.
  SSE is still a string stream, with a documented JSON event-data schema and
  the real initial `collecting` event. No dashboard behavior changed here.

## Host evidence

Logs are retained in the private pipeline's
`work/audit-fixes-20261113.O9Vnp70C/`:

| Check | Result | Log |
| --- | --- | --- |
| OpenAPI contract | 5 passed | `telemetry-openapi-host-v1.log` |
| Management-focused tests | 14 passed | `api-management-targeted-v2.log` |
| Complete Rust workspace | 1,190 passed, 0 failed | `api-management-full-host-v1.log` |
| Clippy, all targets, warnings denied | Passed | `api-management-clippy-v1.log` |
| Rust formatting | Passed | `api-management-fmt-v1.log` |
| Isolated packaged Rust tests | 1,190 passed, 0 failed | `api-management-bind-vm-v1.log` |
| Packaged destination-zone CLI warning | 14 passed | `api-management-zone-warning-v1.log` |
| Two-VM listener, TLS and reboot | Passed, 49.70 seconds | `api-management-bind-vm-v3.log` |
| Two-VM config-sync, receive faults and local endpoints | Passed, 73.02 seconds | `api-management-configsync-vm-v2.log` |

The host tests execute bidirectional authenticated legacy API pushes with
different local addresses and ports, verify equal shared revisions after policy
convergence, and verify that enable/TLS/confirmation policy is not normalized.
Pairing's loopback rejection uses a real unused local listener and verifies no
connection or configuration/plan side effect. The initial focused v1 failure is
retained: it exposed the empty-web-table hash omission; it was not waived.

## Actual listener acceptance

`nix/api-management-bind-test.nix` covers default secret-only IPv4 loopback,
secret-only explicit management address and custom port, pinned TLS and wrong-pin
refusal, web plus sync on IPv4/IPv6 loopback, saved bind persistence across reboot,
and no failed units. Exact socket addresses and positive link probes distinguish
binding refusal from a firewall/network outage. These cases passed on kernel
6.12.113 (firewall) with a separate 6.18.57 client VM, including an actual reboot.

The immutable cohort is Sentinel seed
`/nix/store/vblmfpxc903x7a3cjzw8affg8jb0dzbd-source`, diagnostic overlay
`/nix/store/klapscmjzpxdg7wir1fgl7yhixg9vfd0-source`, old stable Fabric
`pnjdy74gxfm32bdxcnpvx2q3iwi0i210` and Wren `k4wbkqh8qb5j42anh6s6wwzvr1zzvvr3`.
The packaged raw Sentinel ELF is
`/nix/store/xq5zjnyzhqjf1iliw5578bdy4id4gaga-sentinel-1.0.0/bin/sentinel`, SHA-256
`e87310a3ce114af65c1d4e47aaaa27b1e56cea3146522216d4b859c94cc03810`.
The final fixture is frozen at
`/nix/store/076hc6nc5zivhi2b0jhwrji8cdbpvm5p-api-management-bind-test.nix`.
Its structured receipt is
`/nix/store/ka4rj8zfjwmxxmj1nk3brzr4qjmq7cp5-vm-test-run-sentinel-api-explicit-management-bind/api-management-bind.json`
(SHA-256 `4646900a20831d5d9f088b9e8ab1211a4bd525e94d8b22a190b06dc1fbd3baf8`).

Earlier failed VM receipts remain intact. V1 incorrectly demanded identical
certificate bytes across a bind-IP/SAN change; the product correctly renews its
certificate while retaining its pinned key. V2 correctly caught a fixture that
set address/port without explicitly disabling their implicit web-enable effect.
V3 requires `enable false` last, asserts it persisted, and uses the public key
sampled **before** any rebind to pin actual TLS requests after every IPv4/IPv6
change and reboot. Certificate bytes must remain identical across the final
unchanged-binding reboot; key continuity is never relaxed.

## Remaining qualification

The strengthened config-sync gate passed all four real receive-fault/restart/
CLI-rollback cases, deferred worker delivery after downtime, TLS pinning and
receiver-local address preservation. Both saved web flags remained false and
exact listeners stayed `10.9.0.1:8080` / `10.9.0.2:8080`, with HTTPS health 200.
Its fixture-only source overlay is
`/nix/store/pacnpf14jps9jx622hd309magb2yyv88-source`, derived from the
same frozen Rust seed with an updated Nix fixture; evaluation explicitly required
the identical packaged raw Sentinel path `xq5zjnyzhqjf1iliw5578bdy4id4gaga`.
No newer working-tree CPU/TLS-renderer follow-ups entered this cohort.
Structured receipts are under
`/nix/store/xlhhdwi43vdfrg6c43bq5hynbfri90gx-vm-test-run-sentinel-configsync/`:

- `management-endpoints.json`: SHA-256
  `66261c7de247e9104eee74720e1773e31891cfac6ae9924d5f38e32fb1116560`.
- `receive-faults.json`: SHA-256
  `f9ea9b958d16da12b1554d95f0e3e81182061b3d106723b0cb4b585e9e71a52f`.

Both pairing modes and HA failover/existing-flow gates still need to run against
the assembled final source cohort. Earlier VM passes qualify
their earlier cohorts only. Explicit destination binding is not ingress-interface
isolation under Linux's weak-host behavior; the separate opt-in management ACL
test and handbook recipe remain applicable.

Before upgrading legacy peers, finish/reconcile outstanding delivery and upgrade
both peers together. The canonical shared-revision change can leave an old queued
base in conflict. Preserve outboxes and receive journals; do not erase admission
fences or silently reinterpret an ambiguous pre-upgrade transaction.

Private hardware fixture migration is also pending: the `ha_pair_seed` document
in `tests/hil-two-node/hil_node_agent.py` still needs a deliberately selected
local control listener before its next pairing run. Its independent legacy-sync
receiver already launches explicitly on port 18443. Review whether
`enterprise-tests/five-node.nix` needs remote management; a state-only topology
may intentionally keep its secret-activated API on loopback. Neither fixture
was edited or executed on physical hardware or cloud resources in this tranche.
