# Tests and evidence

Run these commands from the repository root. Test counts change with the source;
the commands below, not a number copied into this handbook, define the suite.
A configured check is not a passing test or a release certificate.

This inventory includes development fixtures whose flake wiring and dependency
pins are still being integrated. Query the checked-out flake before selecting a
name; a fixture file or a standalone receipt does not mean that the published
package exposes it or uses the same tested dependency cohort.

## Source checks

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

For the React console:

```sh
npm --prefix ui ci
npm --prefix ui test
npm --prefix ui run build
tests/console/run.sh
```

The browser runner needs Node.js and Chromium. It starts a temporary loopback
API with `--no-apply`: it tests browser interactions and configuration writes,
not the workstation's network or a deployed firewall. See
[the browser test instructions](https://github.com/Velstra/sentinel/blob/main/tests/console/README.md)
for prerequisites and targeted suites. Live packet and HA tests are separate.

## List and evaluate the current Nix checks

```sh
nix eval --json .#checks.x86_64-linux --apply builtins.attrNames
nix flake check --no-build --no-write-lock-file
```

The first command gets names directly from the current flake. The second only
evaluates them: it does **not** execute the VM tests or prove that images boot.

## Run a real VM check

Use an x86_64 Linux host with usable `/dev/kvm` and enough RAM for the selected
topology. Each command below builds its dependencies and executes that check:

```sh
nix build .#checks.x86_64-linux.quickstart -L
nix build .#checks.x86_64-linux.nat -L
nix build .#checks.x86_64-linux.bootfallback -L
```

Useful starting points; query the flake for the complete inventory:

| Area | Check names | Scope |
| --- | --- | --- |
| Image and installation | `verified-boot`, `secureboot`, `install`, `install-iso`, `install-boot`, `install-boot-luks`, `install-boot-raid1` | Boot integrity, installer and installed-image regressions; Secure Boot uses test keys. |
| Update and recovery | `update`, `updatechannel`, `update-release`, `bootfallback`, `boothealth`, `missing-nic-boot`, `reboot` | Slot staging, signed release handling, boot assessment, missing-NIC factory exhaustion and console recovery. Read each fixture's scope before interpreting its result. |
| Active configuration | `commit`, `commitconfirm`, `confirm-crash`, `confirm-failed-recovery`, `cli-edge`, `confighistory`, `refresh-running`, `api` | Apply/save, actual CLI termination, failed recovery admission and explicit retry, offline editing, invalid batches/addresses/durations, stale-session admission and management reads. |
| Authentication lifecycle | `loginlifecycle`, `radius-interop`, `auth-bounds` | SSH/PAM account removal, stable identities, persistent TOTP replay, real FreeRADIUS PAP, source-bound HTTPS login limits and actual viewer/admin write authorization. |
| Management ingress | `management-ingress` | Real IPv4/IPv6 SSH and HTTPS across interfaces; explicit destination ACLs block LAN access while management and same-port forwarded traffic remain available, including after reboot. Binding an address alone is not ingress isolation. |
| Signed metadata | `update-release` | Actual packaged CLI and disposable Ed25519 proofs: image-version floor, signed scope/expiry, replay and sequence substitution, cold-boot persistence, clock rollback and corrupt/missing trust-state refusal. The crypto fixture is deliberately not bootable and proves no slot write. |
| Packet handling | `nat`, `hairpin`, `masq`, `reject`, `rejectudp`, `egress`, `rulescope`, `v6exthdr` | Real traffic through the data plane. A NAT pass does not establish fragment or RELATED-ICMP support. |
| Netfilter comparison | `dataplane-conformance`, `icmp-related`, `tcp-reset-validation` | Matched traffic and policies against an independent nftables reference. The reset check compares socket continuity and firewall state after foreign-tuple, out-of-window, in-window nonexact, checksum-corrupt and valid resets; includes pre-guest wire captures and native challenge-ACK counters. Known differences fail CI; see [conformance scope](dataplane-support.md). |
| Firewall map occupancy | `firewall-capacity` | Real kernel occupancy versus independent `bpftool` counts, expired-slot warnings, authenticated HTTP/CLI parity and missing-agent/restart handling. This is not a connection-limit or eviction-pressure benchmark. |
| Held NAT connection pressure | `nat-capacity-pressure`, `nat-capacity-contract` | Three disposable VMs hold nonce-verified TCP flows up to 20,000; fresh map identities and hash-checked raw snapshots correlate each flow with its NAT/firewall ownership. Lost flows or missing state fail, not an expected-bug pass. Pure probe contracts are separate from the live gate. |
| Kernel fragment mechanics | `kernel-fragment-egress-{6-6,6-12,6-18}`, `kernel-fragment-combined-{6-6,6-12,6-18}` | Isolated reassembly/refragmentation and ingress-domain isolation on three real kernels. These do not execute Sentinel NAT, policy or HA and cannot clear a failing product differential. |
| TCX fragment dispatch | `kernel-fragment-tcx-{6-6,6-12,6-18}` | Actual pinned-Aya attachment and legacy-chain dispatch; deliberately reproduces bypass from PASS and stale readiness after chain loss. Passing hazard controls are not production loader safety or NAT qualification. |
| Guarded ingress handoff | `kernel-fragment-handoff-{6-6,6-12,6-18}` | Reserved-flow reassembly, one-use bounded tickets and original ingress routing context; chain deletion and ticket exhaustion must drop. Does not execute Sentinel NAT/policy or solve ordinary unfragmented admission. |
| Immutable update admission during recovery | `ota-confirmation` | Real EFI/verity boot and transient confirmation/recovery units, including actual partial restore failure. CLI/API Check must be refused before jobs/network traffic; exact retry restores availability. Uses disposable test identities, not production keys; does not certify Stage/CAS. |
| Boot and console write admission | `confirm-special-entrypoints`, `confirm-boot-journal`, `confirm-boot-late` | Failed recovery and live HTTPS transactions block replay; automatic console/network refresh preserves active intent. Includes actual CAKE bandwidth and reboot recovery, not every subsystem or a shared CLI/API journal. |
| Periodic firewall recovery admission | `confirm-refresh` | Real failed rollback and queued recovery cannot replay trial policy over a restored firewall. Fresh TCP traffic and compiled/intent state are checked; normal, armed CLI and ready HTTPS trials retain legitimate refresh. |
| Confirmation diagnostics | `confirm-diagnostics` | Missing timers are silent, genuine stop failures remain visible, and a refused cancellation cannot confirm a live trial. Checks actual PID-1 protection and unchanged intent. |
| Local read-only observation | `observe-readonly` | Six exact SSH/sudo capabilities, protected data redaction, live BGP/NAT and API parity, privilege denials, account revocation and honest daemon failure. Not unrestricted CLI access. |
| API observation error privacy | `api-show-disclosure` | Actual packaged binary and loopback HTTP: malformed private history cannot leak unknown historical secrets to account users or narrowed machine requests. Retains HTTP errors and valid-read redaction. |
| Routing | `bgp`, `bgp-static-reload`, `ospf`, `ospfinterop`, `bfd`, `vrrp`, `staticimport` | Adjacencies, preserved BGP sockets during static-route edits, a third-party OSPFv2 peer and route recovery; not comprehensive protocol certification. |
| HA and synchronization | `ha-pair`, `ha-two-node`, `ha-failover`, `ha-two-node-flow`, `configsync` | Pairing, policy/state synchronization and selected failure cases. HA remains experimental. |
| Nonpreempting HA rejoin | `ha-rejoin`, `ha-rejoin-contract` | Five disposable VMs with a continuously healthy witness and clean config-sync outboxes. Continuous existing/fresh TCP traffic, real VIP SNAT and incumbent role/deadline/NAT observations span the returning member's entire boot. Hard-failover losses are recorded separately; this is not witness-loss, queued-policy replay or final-image certification. |
| Browser | `console`, `console-ux` | Browser interactions against a test API; complements the live packet checks. |
| Compiler/agent boundary | `contract` | Compiled configuration is accepted by the pinned Fabric loader. |

Checks for additional protocols and services are development coverage, not a
claim that every option, peer implementation or failure mode is supported. See
[routing status](../handbook/routing.md#qualification-status) and
[dataplane support](dataplane-support.md).

Run the complete current check set with:

```sh
nix flake check -L
```

This can build images and run many multi-VM topologies. Allow substantial disk,
memory and time. A failure, timeout, interrupted check or unexecuted check is not
a pass. Save logs and output paths before removing build artifacts.

## Release evidence

Record the exact Git revisions, input lockfile, eBPF object hash, image SHA-256,
command, result and retained output for each release check. Source unit tests,
evaluation and a development-image VM are different evidence classes. None can
replace a complete acceptance run and SBOM/CVE assessment of the final signed
image. Do not reuse a result from another source cohort.

The public workflow is
[.github/workflows/ci-public.yml](https://github.com/Velstra/sentinel/blob/main/.github/workflows/ci-public.yml).
Inspect its current matrix to see which checks actually run on a PR. The
scheduled dependency audit is not a scheduled execution of the entire VM suite.

## Kernel verifier compatibility

Host Rust tests cannot verify an eBPF program. Compatibility requires loading
the exact object into each target kernel in a privileged test VM. The
[dataplane matrix](dataplane-support.md) distinguishes configured kernel lanes
from passing receipts; an unexecuted lane is not support for that kernel.
