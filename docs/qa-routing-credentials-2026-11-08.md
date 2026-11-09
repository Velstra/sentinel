# Routing and credential regression fixes

This change set addresses the observed failures OSQA-017/157, 026, 164, 165,
166 and 167, plus boot ordering/assessment findings 016 and 019. It is not a complete resolution of the OpenStack QA backlog or a
production release certificate. Existing failed execution records are retained.

## Product changes

- One shared credential classification now controls masked editors, deliberate
  Show/Hide, summary redaction and JSON-token encoding. Credential whitespace is
  preserved instead of silently trimmed.
- An unset reverse-proxy protocol correctly says HTTP, independently of the
  multi-WAN failover default; its existing port default remains 443.
- DDNS protocol names cannot inject line breaks or configuration delimiters.
  Both model validation and the renderer enforce the boundary.
- Route maps validate the complete prefix pattern, protocol, next-hop address
  and each community type against the routing engine's grammar. Originated BGP
  standard/large/extended communities retain their distinct wire encodings.
- Wren supports less-specific (`prefix-`) matches and rejects malformed Unicode
  raw extended communities without a parser panic.
- Configured statics pass VRF and global import policy before entering the RIB
  at startup and SIGHUP. A policy-only change can withdraw a configured static;
  repeated reloads do not accumulate metric transformations.
- Startup cleanup and ordinary withdrawals remove an exact owned route rather
  than wildcarding another route at its prefix. Failed withdrawals retain the
  exact identity for retry and do not falsely publish successful removal.
  Blackhole routes are included in owned-route readback.
- Both the actual SSH key generator and SSH daemon require the persistent data
  mount. A delayed `nofail` mount can no longer race key generation.
- The public image now requires product readiness and the generic failed-unit
  check before `boot-complete.target`. The checker validates the saved model,
  compares its actual compilation with runtime state, checks selected services,
  the real dataplane `Ready` response, reconciled links/static addresses and
  kernel XDP program identities. It never applies or repairs configuration.
  Automatic retry is restricted to a counted EFI trial, not permanent installs.
  Unprovisioned images skip the unrequested dataplane; malformed bindings fail.

The private enterprise adapter can override the public check with its existing
product-specific checker; that adapter's additional readiness coverage must be
assessed independently. Neither a unit-graph check nor a direct health probe is
the final immutable-image three-boot fallback certificate.

The locked Wren build receives the same backport from
`nix/patches/wren-routing-safety.patch`. A fully patched local/HA input is accepted
after an exact reverse dry-run; partial/incompatible input fails the build.
See the patch directory's README for removal after the upstream pin is updated.

## Reproduce the checks

In Sentinel:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
npm run format:check --prefix ui
npm run typecheck --prefix ui
npm test --prefix ui
npm run build --prefix ui
npm run check:assets --prefix ui
cargo build
for suite in ux layout console react health ha-mode peer; do
  CONSOLE_TEST_FILE="$suite.test.mjs" tests/console/run.sh target/debug/sentinel || exit 1
done
nix build .#checks.x86_64-linux.staticimport -L
nix build .#checks.x86_64-linux.ssh-persistence -L
nix build .#checks.x86_64-linux.boothealth-unit .#checks.x86_64-linux.boothealth -L
nix build .#checks.x86_64-linux.bootfallback --max-jobs 1 --cores 4 -L
```

In Wren, an isolated target directory avoids reusing an unrelated old checkout's
build artifacts:

```sh
export CARGO_TARGET_DIR=target/qa-routing-safety
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
bash scripts/netlink-kernel-smoke.sh
```

The kernel smoke test creates disposable user/network namespaces; it does not
change workstation routes. It explicitly verifies that removing the owned OSPF
route preserves the same-prefix connected route and a different-metric owned
route, for both IPv4 and IPv6.

The three-VM `staticimport` gate uses a real Sentinel firewall, an independent
LAN client and a native echo server. Both TCP and UDP must reach only the
admitted target. It exercises prefix-window changes, protocol mismatch,
first-match sequence order, idempotency and normal deletion. Return routes force
both directions through Sentinel; negative verdicts include independent endpoint
health controls.

The focused SSH VM uses the real shipped NixOS keygen and sshd units. It delays
the persistent mount after sysinit, then verifies both key fingerprints and the
key actually offered over SSH across two cold boots. The boot-health VM checks
real XDP detachment, invalid input, runtime drift and a stopped dataplane; it
must refuse `boot-complete.target` without fabricating a successful bless.
The separate `bootfallback` gate builds real immutable good/broken images,
stages the candidate with a disposable QA signature through the actual updater,
counts distinct failed-boot UUIDs and checks exhausted B plus restored healthy A,
configuration and SSH identities. It contains no rescue boot-target timer.

Local browser/API tests and KVM gates do not prove that the old cloud image has
been upgraded. Installed-candidate verification, the remaining findings, real
provider DNS publication and missing WLAN/WWAN hardware evidence remain separate
release requirements.
