# Changelog

## [Unreleased]

## [1.0.0]

The first release with a stable configuration language. The release date is
the date of the signed `v1.0.0` tag. It follows 0.4.2 and supersedes the 1.0.0
candidate of 2026-10-26, which was never released. The independent release
audit of 2026-11-18/19 (run 8b6181) found blocking issues in both editions;
every finding cited below was fixed, or is listed as a known limitation in the
[release notes](docs/src/release-notes-1.0.0.md).

### Upgrade warnings

Read the [release notes](docs/src/release-notes-1.0.0.md) before upgrading.

- **HA pairs are not upgraded hitlessly.** Stable zone identifiers (DP-13) and
  ingress-only direction-less rules (DP-15) change the shared-policy digest:
  while the members run different versions the standby is not ready and
  conntrack sync refuses its sessions, so the switch-over is one outage with
  connection loss per upgrade, and the first commit afterwards reloads the
  data plane once with fresh state. Upgrade the standby, fail over to it, then
  upgrade the old primary; never fail back onto a member that is not yet
  upgraded, because masqueraded connections a 1.0 member owns do not survive
  a takeover by a pre-1.0 peer.
- **IPv4 options:** TCP and UDP whose IPv4 header carries options are dropped
  on stateful zones (DP-34).
- **New refusals:** port forwards and load balancers other than
  `tcp`/`udp`/`tcp_udp` (DP-18), data-plane capacity (DP-17, DP-29, PERF-03),
  inert or over-qualified proto-less accepts (DP-14), control characters and
  malformed daemon-bound fields (CTRL-08 and others), weak config-sync secrets
  (CTRL-01). A saved file that fails validation at the first boot of 1.0.0
  fails that trial boot, and the update falls back to the previous image.
- **Changed matching:** a rule without `direction` is ingress-only, and
  blocklists and GeoIP name sources only, so they no longer stop the inside
  reaching a listed address (DP-15); `syn-protect` proxies a port only on the
  zones that admit it (DP-31); IPv4 rules no longer match IPv6 (DP-11);
  `block-icmp` refuses new inbound ICMP only and never neighbour discovery
  (DP-10).
- **Update channels:** signed channel metadata must carry a freshness policy
  (sequence, at most 14 days of validity); local proofs without a release
  version need `--allow-downgrade` (CTRL-26). `save` never confirms a pending
  `commit-confirm`.
- **Credentials:** the config-sync secret is no longer an API bearer, and the
  API token file is re-minted if it held the secret (CTRL-01, CTRL-07); config
  sync no longer carries accounts, AAA, update, SSH or console settings
  (CTRL-09, CTRL-10); `save` refuses uncommitted edits (CTRL-14).

### Data plane (Fabric)

- Masqueraded TCP no longer freezes about a second into a transfer (DP-02,
  PERF-01).
- RSTs are validated against the tracked sequence window; XMAS, NULL, FIN-only
  and out-of-state packets are dropped on stateful zones; retransmitted
  SYN-ACKs, tuple reuse and half-closed connections are tolerated (DP-03,
  DP-25, DP-37). Non-SYN TCP no longer creates NAT state (DP-08).
- Masquerade no longer leaks private sources: GRE, ESP, SCTP and 6in4 are
  translated, AH, ICMP timestamp and ICMP with options are dropped at WAN
  egress (DP-04). IPv4 fragments are translated through NAT (DP-05).
- Connection tables are sized from memory with a floor of 16,384 and a
  reclaimer frees expired state, removing the ~16,250-connection ceiling and
  the eviction of live flows (DP-06, DP-07). The agent returns freed
  memory after a reconfigure (PERF-04).
- ICMPv6 neighbour discovery and MLD always pass; `block-icmp` refuses new
  inbound ICMP only; RELATED ICMP errors, including IPv6 packet-too-big, are
  delivered (DP-10, DP-21).
- An IPv4 rule on `0.0.0.0/…` no longer applies to IPv6 (DP-11). MAC-group
  rules and per-rule rate limits enforce on IPv6 too (DP-19, DP-20).
- Under fail-closed, non-IP EtherTypes outside an allow-list are dropped
  (DP-22).
- Hairpin NAT rewrites the client port (DP-23); concurrent NAT claims no longer
  overwrite each other (DP-24). Each new masqueraded connection examines a
  fixed window of 128 ports, so masquerade no longer collapses to a few
  hundred new connections per second after one ICMP echo or port-forward
  (DP-26, PERF-02; `checks.nat-cps`, 2 x 20,000 opens at 2,000/s). The
  remaining ceiling is about 31,000 concurrent connections to one remote
  ip:port per public address, counted in `egress_nat_no_candidate`.
- Zone and global blocklists and GeoIP countries name sources only: the inside
  can reach a listed address and receive its answers, and whatever a listed
  address starts is refused (DP-15; `checks.blocklist-direction`).
- `syn-protect` proxies a port only on the zones that admit it (an accept
  rule, a port-forward or a load balancer); outbound connections from other
  zones to that port are no longer proxied (DP-31). IPv6 SYNs are MSS-clamped
  like IPv4, and ICMPv6 errors about connections behind NPTv6 or quoting
  extension headers reach the host (`checks.v6-mss-npt-related`).
- `velstra verify-ebpf`, and so the `ebpf-verifier` checks, refuse a program
  that needs more than 700,000 verifier instructions.
- An agent restart keeps hooks, tail-call tables and state pinned, so it
  neither fails open nor drops NAT sessions (DP-12, DP-27). A reconfigure
  rewrites only the entries that changed, so a commit no longer stalls traffic
  in proportion to the configuration size (DP-28).
- A torn netlink dump no longer blocks the data plane (DP-32); a truncated TCP
  header at a reject rule is dropped (DP-33); TCP and UDP with IPv4 options
  are refused on stateful zones (DP-34); IPv6 UDP reject sends ICMPv6
  port-unreachable (DP-35); raw-IP links are no longer parsed as Ethernet
  (DP-36); `expire-state` no longer gates the data plane (DP-41); a zero UDP
  checksum is written as 0xFFFF after NAT (DP-42); the MSS clamp writes a
  correct TCP checksum (DP-09); reject sends a valid TCP RST (EDGE-02).
- The pinned agent carries no known Rust advisories (STATIC-02); Fabric gained
  a supply-chain policy and pins its aya revision (STATIC-05).

### Firewall compilation and validation

- `to firewall` is compiled symbolically, so the agent matches the box's live
  addresses, DHCP and SLAAC leases and held VRRP addresses: DHCP management no
  longer locks itself out (DP-16, HA-01, PROV-03). `sentinel trace` on the box
  judges `to firewall` against the same live addresses.
- Zone policy identifiers are stable hashes, not alphabetical ranks (DP-13).
  Rules without `direction` compile as ingress rules (DP-15).
- `config check`, `commit`, `save`, the boot apply and the periodic refresh
  check every data-plane capacity the agent enforces — rule tries, MAC rules,
  rate-limited rules, the per-zone copies of the global blocklist, forwards,
  services, backends, SYN proxy entries (DP-17, DP-29, PERF-03) — and run the
  image's own agent validator on the compiled configuration before anything
  live changes (DP-01 class).
- Port forwards and load balancers accept only `tcp`, `udp` and `tcp_udp`
  (DP-18). A proto-less accept that cannot be enforced as written is refused
  (DP-14). Two rules on one key hold the stricter verdict, as `trace` reports
  (DP-30).
- `config check` names the zones a SYN-protected port is proxied on, says when
  no zone admits it (then it is proxied everywhere), and names the zones where
  it is reachable over IPv6 without the proxy (DP-31, DP-35); `commit` warns
  about hairpin on a DHCP or PPPoE WAN (DP-39); time-based rules are re-evaluated after a clock or
  time-zone change (DP-40); handbook examples and the GeoIP budget match the
  code (DP-43, IMG-10).

### Configuration, commit and boot

- A saved configuration the data plane refuses no longer boots the box dark:
  boot falls back to the last-known-good configuration or a management-only
  reduction, and says so in the journal, the console, `show system` and the
  configure banner (DP-01, PERF-06).
- `rollback N` becomes the running configuration (CTRL-04); `save` writes the
  committed running configuration and refuses uncommitted edits (CTRL-14); a
  commit interrupted by a signal, I/O error or panic finishes or rolls back
  (CTRL-15); runtime files are replaced atomically (CTRL-20); routing reloads
  after addresses are set at boot (CTRL-19).
- One validator for the CLI, the API document path and config sync, with
  control characters refused everywhere (CTRL-08); daemon-bound fields are
  shape-checked, closing command and directive injection through dynamic DNS,
  the SSH log level, Wi-Fi, DHCP options, chrony, bonding and PPPoE
  (CTRL-02, CTRL-03, CTRL-12, CTRL-13, CTRL-16, CTRL-17, CTRL-18, CTRL-29). A
  saved file with such a value still boots, with that setting switched off.
- An operator's on-box `configure` session escalates once instead of once per
  privileged step: an unchanged commit as `admin` took 21-31 s with 76 sudo
  round trips; it now takes 4.6 s against 4.0 s as root
  (`checks.commit-latency`).
- The read-write admin reads the protected saved configuration without sudo
  (PROV-05).
- Found in qualification: an escalated `configure` session judged "the account
  running this commit" by its effective uid (root), so an operator could
  delete and retire their own account; it now uses the sudo-authenticated
  operator. A commit that creates the agent's uplink (a new VLAN, for example)
  keeps the old uplink until the link exists. Runtime directories are
  traversable whatever the umask, so PPPoE and BNG start under umask 077.

### Management plane and API

- The config-sync secret is a scoped peer credential, not a full-access token;
  weak secrets are refused, `sentinel ha secret generate` makes one, and HA
  proofs, sign-in and bearer failures are rate-limited per source (CTRL-01,
  CTRL-07, CTRL-27).
- Per-source, per-network and total connection caps with header and body
  deadlines stop a slowloris from taking down the API, console and sync
  (CTRL-05); HA pairing no longer blocks the API runtime (CTRL-06).
- The commit-confirm timer forwards only an environment allow-list (CTRL-21);
  `show`/`clear` words are validated and `lookup` is bounded (CTRL-28);
  sessions are bounded under clock jumps and HSTS is sent (CTRL-29).

### HA and config sync

- The standby becomes ready: the readiness digest no longer contains
  member-local addresses (HA-02, HA-03); a stale standby goes cold after 5 s,
  so killing the active member's agent fails over instead of leaving both
  members backup (HA-04); conntrack sync replicates sessions again.
- A config-sync peer can no longer manage the receiving member: accounts,
  groups, AAA, update, SSH and console stay local, and sender-local addresses
  are not copied (CTRL-09, CTRL-10). A commit on the backup member warns.
- Wren no longer withdraws a healthy owner's addresses after a slow witness
  exchange (pinned Wren ba95bca).
- WireGuard through an HA pair follows a takeover in about a second, also when
  the new owner was VM-paused: its wall clock lagged, and the remote peers
  dropped its handshakes as replays until the lag had passed (6 s to beyond
  15 s measured). The owner now replicates its clock to standbys that
  announce support, and a member that takes over steps its clock forward to
  its predecessor's after taking the VIPs and before reconfiguring WireGuard.
  The socket-activated `wren-ha-clock-step` helper takes the step; it holds
  only `CAP_SYS_TIME`, and Wren keeps `ProtectClock` and no clock capability.
  The step is forward-only and logged: at most 10 minutes, at most 60 seconds
  between two NTP-synchronised clocks, and never by an NTP-synchronised member
  from an unsynchronised peer. A refused step is reported by
  `sentinel show health` (`ha-clock-behind-peer`) until NTP resolves it.
  Checked by `checks.ha-wireguard-failover`.

### Updates and boot trust

- No slot can be written during an unblessed trial boot (CTRL-11); an
  interrupted first freshness check no longer refuses updates forever
  (CTRL-23); a new channel label inherits the key pin and sequence floor
  (CTRL-24); `sha256:` digests are accepted consistently (CTRL-25); an
  unversioned local proof needs `--allow-downgrade` and raw-signature copies are
  bounded (CTRL-26); a prior boot's retry time no longer defers recovery
  (CTRL-22).

### Image and supply chain

- DP-34: IPv4 packets with options are refused on stateful zones (TCP and
  UDP whose IPv4 header carries options cannot be tracked or translated).
- IMG-02: imported `$1$`/`$5$`/`$6$` hashes now work over SSH as well as the
  API; the shipped libcrypt also verifies md5crypt and sha256crypt (new
  passwords stay yescrypt). Checked by `checks.legacy-hash-login`.
- IMG-03: no enrollment payloads ship for the per-build development keys;
  systemd-boot and the UKI are signed after the image is assembled, so
  `.#sentinel-image-unsigned` and its usrhash are the attestation target;
  signatures use a fixed signing time.
- IMG-04: nixpkgs advanced to nixos-26.05 2026-11-16 (curl 8.23.0, OpenSSH
  10.6p2, zlib CVE-2026-85091, Linux 6.12.117, ...); libcap 2.78, the
  Net-SNMP SMUX fix, Suricata 8.0.7, SQLite 3.54.1, lego/dnsproxy with current
  golang.org/x and gRPC modules and a Linux-PAM without Berkeley DB are
  backported into the shipped closure without rebuilding nixpkgs; HAProxy is
  3.4.1. The eBPF object keeps its own pinned
  toolchain (`nixpkgs-ebpf`), so a userspace bump no longer moves `ebpfHash`.
  The gate's remaining 21 findings and 171 kernel matches have PROPOSED,
  unreviewed waivers in `scripts/cve-waivers.json`; the gate fails until a
  person reviews them.
- Release CVE review: the image ships Linux 6.12.118 (the pin's recipe at the
  newer 6.12.y source, `nix/kernel.nix`), HAProxy 3.4.8, glibc 2.42-113 (the
  release/2.42 branch head), gzip 1.15, krb5 1.22.3 and hostapd 2.12, and
  patched GLib (CVE-2026-58016) and sudo (CVE-2026-35535); cyrus-sasl is
  built without SRP; lego, dnsproxy and libcap's captree are built with Go
  1.26.11. Backports also rewrite bare store hashes after whole base names,
  which GLib's own binaries require. `checks.image-security-floor`
  fails the build when the image closure falls below a recorded version
  floor, when a backport did not replace the package it backports, or when
  the `sqlite3` shell or `ocspcheck` ships.
- IMG-05: an image-level CVE gate with a maintained Nix-to-NVD CPE table
  (`scripts/nix_cpe_map.json`), the kernel cataloger and vulnix as a second
  source; it fails when a critical package cannot be matched.
- IMG-06: rsyslog is built with only the modules Sentinel renders; no
  compiler, binutils or -dev output ships (`checks.image-closure`).
- IMG-07: `sentinel-boot-late` waits only for the links Sentinel configured.
- IMG-08 / EDGE-03: charon stays off without an IPsec configuration
  (already on the candidate, now asserted at boot); pkexec is no longer setuid.
- IMG-11 / STATIC-04: the image names its release (`IMAGE_VERSION`, raw file
  name), the agent's store name carries its crate version, ESP files no longer
  date from 2098, and `sentinel --version`, `show version` and the OpenAPI
  info report the source revision.
- IMG-12: the unprivileged-user-namespace builder prerequisite is documented.
- STATIC-03: the changelog, README, SECURITY.md and operator guide describe
  the release as it is.
- STATIC-07 / STATIC-08: the console browser suite resolves the pinned password
  helper (or stops with a clear message) and removes its Chromium profiles on
  every exit path.
- STATIC-09: a licensing and corresponding-source note for distributors.
- STATIC-10: CI fails when nixpkgs is older than 21 days or an input floats.
- STATIC-11: the exported modules set no password and no autologin; only the
  development VM (`nix run .#vm`) has its known console login.
- PROV-01: `nix run .#seed-image` seeds a raw image's data partition for a
  cloud import, refusing configurations with no way in.
- PROV-02 / HA-00: the data filesystem is checked and grown offline before its
  check and mount, and a failed grow no longer fails the boot.
- PROV-04: `sentinel config check` warns for zoned NICs without `hw-id`.
- Found in qualification: the ESP is mounted `noatime`, so read-only update
  checks no longer write the boot partition; an encrypted install opens the
  target's volume under its own mapper name, so installing onto a second disk
  no longer unmounts the running box's own state; the full-screen installer
  no longer exits on a serial console that does not answer cursor queries.

### Release 1.0.0 datapath

- DP-15: zone and global blocklists and GeoIP countries name sources only.
  The LAN can reach a listed address and receive its answers; whatever a
  listed address starts is still refused. There is no outbound blocklist.
  Checked by `checks.blocklist-direction`.
- DP-31: `syn-protect` proxies a port only on the zones that admit it (an
  accept rule, a port-forward or a load balancer). Outbound connections from
  other zones to that port are no longer proxied. A port no zone admits that
  way stays proxied everywhere, and `config check` says so.
- Known limitation: IPv6 is not SYN-proxied in 1.0; the SYN proxy protects
  IPv4 only. `config check` names every zone where a protected port is
  reachable over IPv6. The IPv6 proxy is planned for 1.1
  (`docs/design/dp35-ipv6-synproxy.md`).
- IPv6 SYNs are MSS-clamped like IPv4 (PPPoE included). ICMPv6 errors about
  connections behind NPTv6, or quoting extension headers, now reach the host.
  Checked by `checks.v6-mss-npt-related`.
- `velstra verify-ebpf` (and so the `ebpf-verifier` checks) refuses a program
  that uses more than 700,000 verifier instructions.
- PERF-02: masquerade no longer collapses to a few hundred new connections per
  second after one ICMP echo or port-forward. Each new connection examines a
  fixed window of 128 ports, whatever the box has seen before. The handbook
  states the remaining ceiling: about 31,000 concurrent connections to one
  remote ip:port per public address, with refusals counted in
  `egress_nat_no_candidate`. Checked by `checks.nat-cps` (2 x 20,000 opens at
  2000/s) and `checks.nat-domain-cgnat`.
- Known limitation, documented (HA rolling upgrade): masqueraded connections
  that a 1.0 member owns do not survive a takeover by a pre-1.0 peer. The
  older allocator cannot find their ports. This is unchanged by PERF-02.
  Upgrade the standby, fail over to it, then upgrade the old primary, and
  never fail back onto a peer that is not yet upgraded. The 1.0 readiness
  digest change (DP-13/DP-15) already makes the 0.4 to 1.0 upgrade
  non-hitless.
- Known limitation, documented: a NIC that strips VLAN tags in hardware makes
  the parent's zone judge VLAN traffic under native XDP (DP-22); turn
  `offload rxvlan` off on such a parent.

### Release verification

Every `checks.x86_64-linux.*` check (194) is run under KVM on the release
commit, and the release is not tagged unless each one passes or is listed
here with its reason. Result on the release commit: PLACEHOLDER (filled in
from the integrated qualification run).

Defects found by qualification and fixed before release, beyond the audit
findings above:

- An update fence missed a same-size rewrite of a protected file within one
  kernel timestamp tick (pre-6.13 kernels stamp writes from the coarse
  clock); a fence now records a file's stamp only once that tick has passed.
- The once-a-second recovery timer held the configuration locks even with
  nothing to recover, so an update check or the API's update admission could
  be refused as busy at random; an idle tick no longer locks.
- An escalated `configure` session let an operator retire their own account;
  installing onto a second disk could unmount the running box's state; the
  full-screen installer exited on a serial console; read-only update checks
  wrote the boot partition (see the sections above).

### Earlier work in this release

#### From the 2026-10-26 candidate to the audit

Summarised from the commit history between the 1.0.0 candidate date and the
start of the remediation (102 commits); see `git log` for detail.

- **Platform:** the appliance base moved to NixOS 26.05 with the Linux 6.12 LTS
  kernel, verified against the 6.6, 6.12 and 6.18 eBPF verifiers. Fabric and
  Wren are pinned to a single reviewed source cohort, with a legacy HA
  allocator retained only as a test fixture.
- **Updates:** durable, guarded OTA image-update jobs, the native update
  provider, boot-identity validation of counted UKI names, bounded signed
  downloads, validated update URLs, and an operational update console.
- **Configuration and apply:** atomic configuration permissions under a
  restrictive umask, concurrency-safe locks and group lookups, live firewall
  intent preserved across periodic refresh, commit-confirm and rollback
  publishing the running intent, transactional provisioning and uplink
  rollback, and CLI failures propagated as exit status.
- **HA and config sync:** config sync fenced durably before policy application
  and authorized before acknowledgement; optional witness grants and two-node
  pairing documented; HA continuity checks kept in the mandatory release floor.
- **Management plane:** hardened admission authentication, authoritative
  privileged command results, clustered management and system health, and
  atomic HTTP 400 refusals attributed in the console without replay.
- **Release engineering:** a Community release workflow that qualifies and
  signs image bundles, a source SBOM with coverage checks, source and runtime
  artifact policies, rejection of bootable artifacts anywhere in history, and
  the real yescrypt helper in CI.
- **Security fixes:** the findings of the 2026-10-26 security audit, the
  Fabric XDP control-plane and malformed-packet fix, and the Rustix xattr
  advisory in Sentinel and the pinned Fabric build.
- **Documentation:** the operator manual rewritten around tested deployment
  tasks, focused setup guides, branding, contribution templates and private
  security reporting.

#### The 2026-10-26 candidate

This was written for a 1.0.0 release on 2026-10-26. That release was not
tagged or published; it is kept as the record of what the candidate
contained at that date.

#### Added

- Optional declarative fleet management with provisioned mTLS identity,
  independent Ed25519 command signatures, challenge/target binding and durable
  replay protection. Signed revisions use the existing validation, CAS,
  independent apply worker and explicit commit-confirm recovery engine.
- Fleet telemetry requests, member-local enrollment across HA synchronization,
  and a shared-form enrollment/disconnect workflow in the embedded console.
- Verified network samples and an account-preserving CLI batch, a QEMU/Proxmox
  quickstart, and pinned QEMU firmware for the installer workflow.

#### Fixed

- DHCP WAN acquisition and address replacement refresh Fabric's live SNAT
  targets without restarting the agent or clearing established connection state.
- Enrollment rotation rejects late telemetry acknowledgements as well as late
  signed commands, preserving the new identity's replay-protection state.

#### Release verification

- Rust formatting, check, warning-free clippy and workspace tests; full browser
  console/field coverage; real mTLS, network, HA and recovery VM regressions.
- Appliance disk image and installer ISO builds and installer/verified-boot
  checks. Deployment-specific hardware and firmware trust remain operator-owned.


#### Added

- **The firewall log is searchable, and reaches back further than fifty lines.**
  `show firewall log` took no arguments and printed the last fifty lines, which
  is not enough to answer "what happened at nine this morning". It now takes a
  depth (up to 5000 lines) or a period — `since 15m|1h|6h|24h|7d` — both bounded
  here rather than passed through, because those words reach `journalctl`. The
  console gets the same under **Policy → Firewall log**: one row per refusal,
  marked by verdict, with the time, the source and what it was carrying, and the
  reason; a search box that narrows what is already on screen; and **Every line**
  for the journal unparsed. A row's **Explain** opens the packet trace with that line's numbers
  filled in — the log records the counter that was bumped, not the rule that
  decided, so the tracer is the honest way from a line to a rule. The old
  read-only *Firewall → Recent log* panel is gone; this replaces it.

#### Fixed

- **The packet trace and the packet capture no longer cover their own answer.**
  Both put their query form in a `.card.addpanel`, which the console styles as a
  drawer fixed to the right edge — the right 44rem of the page, on top of
  whatever is under it. For an add-form that is opened and closed again that is
  the point; for a form that is always open it meant the trace walk and the
  capture output were read through a panel sitting on them. Both are now cards
  in the page, with their fields on the same mask grid every other form uses.
- **`checks.update` updates from a different image, as a real update does.**
  It re-sealed the booted medium into the other slot, which `sentinel update`
  has refused since the identical-image guard (two partitions with one
  PARTUUID, an initrd that hangs instead of rolling back) — so the check had
  been red since then. It now builds a donor image (the same appliance plus one
  marker file, hence a different root hash and different GUIDs), attaches it as
  a second disk, asserts the refusal of the identical image, updates from the
  donor, and after the reboot proves by the marker that slot B is what booted.
- **The medium an update was read from must be unplugged before the reboot.**
  The check above found it: slot B is given the source's partition GUIDs (that
  is how the initrd finds it), and a medium still attached at boot answers to
  the same GUIDs — systemd took the *donor's* store partition for `/usr`.
  `sentinel update` from a block device now says so when it finishes, and the
  check blanks the donor before rebooting.
- **`checks.ospfinterop` explains a missed route.** On a timeout it now prints
  both link-state databases, Wren's neighbours and routes and FRR's routing
  table, so a route that never crossed is told apart from an LSA that never
  arrived.
- **Apply says that it is applying.** The button and the pending-changes
  badge show the work while the batch runs — the verb in the present tense, a
  spinner, a pulsing badge — and go back to themselves when the appliance has
  answered. A button that went quiet for the second an apply takes read as a
  button that did nothing, which is when somebody presses it again.
- **A read-only account can no longer stage a change it could never apply.**
  New/Edit/Delete were gated once per view, but every list redraws itself
  after each fetch, and a row's Edit and Delete drawn after the gate ran were
  live — so a read-only operator could stage "delete firewall rule web-in" and
  then sit with a pending change whose Apply *and* Discard were disabled. The
  gate now re-runs whenever the page redraws, and `stage()` itself refuses a
  read-only account with the sentence the buttons carry. Covered by the
  console suite's read-only test.
- **The console has a tab icon.** Browsers ask for `/favicon.ico` on every
  load whether the page names one or not, and every load answered 404 into
  the API log and the browser console. Served as a 96-byte PNG from the API;
  the page itself stays self-contained.
- **`ebgp-require-policy = false` reaches Wren.** The compiled `wren.toml` only
  carried the key when it was `true`. Wren now defaults a missing key to `true`
  (RFC 8212 default-deny), so an appliance that never touched the setting — the
  documented permit-all default — handed the decision to Wren and exchanged no
  eBGP routes at all. The key is written both ways now; `checks.bgp` is the
  proof, run against the current Wren.

#### Added

- **The appliance reports up.** `sentinel report --controller <url>` hands a
  Velstra controller what this box is carrying — per-link rx/tx, the data
  plane's own counters, the rules that are carrying traffic, and the session
  count — as one `ReportStats` call over the wire types the `ports` query
  already used. `--dry-run` prints the list instead of sending it, and
  `--node` names the box to the controller (its hostname otherwise).

  Only observations go: what the links carried, what the firewall did. Nothing
  about the configuration, and nothing comes back — an appliance that took
  configuration from a controller would have two writers for the one document
  it reconciles to. A box whose configuration cannot be read still reports its
  links and its data plane, which is when a controller most wants them.
- **The API describes itself.** `GET /api/v1/openapi.json` (and `sentinel api
  --openapi`) is the management API as OpenAPI 3.1 — every route, its
  parameters, bodies and answers — for a client generator, a Terraform
  provider or an IDE. Open like `health`, because a client has to read it
  before it can know how to sign in. A unit test reads the routes out of the
  router and fails when one is served and not documented, or documented and
  not served. Velstra Cloud serves the same document at the same path.
- **A packet trace: ask before you send.** `sentinel trace --in lan0 tcp
  10.0.0.200 10.9.0.10 22` walks a packet through the configuration in the
  order the data plane takes it — the arriving link's zone, the blocklist,
  source validation, a port-forward's rewrite, the routing decision, the rule
  that wins and the ones that were looked at and passed over (with the
  reason), and the masquerade on the way out — and says what decided the
  verdict. Matching runs over the *compiled* rules, so the ranking is the one
  the eBPF program applies (a MAC verdict, then a link-scoped rule, then a
  typed ICMP rule, then the longest prefix, then the stricter action) and
  cannot drift from it. What the box only knows at runtime — an established
  flow, a learned route, which uplink is up — is named in the answer rather
  than guessed. The console has it under Policy → Packet trace, the API as
  `GET /api/v1/trace`, and `--json` prints the same walk as data.
- **Named update channels + subscriptions — the enterprise update channel.**
  The single `[update] url` grows into named channels
  (`set update channel <name> url|public-key|subscription-key …`, with the
  bare `set update channel <name>` selecting the active one), each signed by
  its **own** pinned Ed25519 key — the community/subscription split from
  LICENSING.md is a trust split, and trusting one channel must never mean
  trusting another. The old bare `url`/`public-key` pair keeps working
  unchanged as the unnamed default channel, so a fielded box loses nothing on
  upgrade. A channel's `subscription-key` is the entitlement, sent to the
  channel server as a bearer token; it is a secret — redacted by the read API,
  masked to its last four characters in `show subscription`, carried to curl
  via a 0600 header file rather than argv, and never logged. **An expired or
  rejected subscription never disables the appliance**: an HTTP 401/403 from
  the channel is answered with a refusal that names the channel and the fix,
  and the one and only consequence is that new images from that channel are
  unavailable — no nag, no phone-home, no degraded data plane; the promise is
  written where the refusal is built (`update::fetch`) and proven by the new
  `checks.updatesub` VM test, which drives a bearer-gated HTTPS channel server
  through the wrong-key refusal (configuration untouched) and the right-key
  install. `show subscription` (CLI and console) reports the channels, the
  active one, whether a key is set (masked), and the last check's outcome as
  recorded — expiry is reported as "not reported by the channel server",
  because no server contract for expiry exists yet and this box does not
  guess. The console's System page gains the channel list with an add panel
  beside the existing update mask.

- **TACACS+ authentication (RFC 8907), completing the admin-AAA trio.**
  `set system aaa tacacs <host> secret <s>` points the login path at a TACACS+
  server the way `radius` and `ldap` already could; the appliance speaks the
  ASCII authentication flow (START, GETPASS, CONTINUE, PASS/FAIL) over TCP 49
  with its own small codec, wire-pinned in tests the way the RADIUS one is.
  The rules that hold for the other two hold here: local accounts are tried
  first, so a box whose directory is unreachable stays enterable; a server
  that rejects has answered and a server that cannot be reached has not; the
  shared secret is redacted from the read API like every other secret; and the
  body obfuscation is called what the RFC calls it — obfuscation, not
  encryption — so the server belongs on a trusted segment. A refusal from a
  directory now names the protocol that refused (RADIUS, LDAP or TACACS+),
  because with three kinds of server configurable, "not accepted" alone sends
  an operator diffing three configs. Authorization and accounting are
  deliberately not implemented: an appliance login needs a yes or a no, and
  what an account may do is decided by its group. The web console gains a
  TACACS+ server list beside the RADIUS and LDAP ones, and a new
  `checks.aaa` VM test drives the flow against a real tac_plus server —
  including the wrong-password 401 and the directory-outage 503 staying
  distinct, and the local account still entering while the directory is down.

- **`delete system aaa …` now works.** The completion tables offered `delete`
  for the RADIUS and LDAP entries, but the delete grammar had no arms for
  them: every attempt ended in "unknown delete path". A server can now be
  removed by host, an optional field cleared, and a required field (a shared
  secret, an LDAP base-dn) answers with the delete that works instead —
  a server without its secret is not a server.

- **`show version` says which image is running, not just which version number
  somebody typed.** An A/B update that demonstrably replaced the running system
  — new slot, new dm-verity root hash, new store path for every binary —
  printed the identical two lines before and after, which on a box that updates
  A/B leaves its one identifying command unable to answer. It now prints the
  dm-verity root hash of the running `/usr` (the value the kernel is actually
  enforcing, so it changes if and only if the image does) with the slot backing
  it, and the Nix store path hash of each running binary underneath. Twelve hex
  characters is short enough to read over the phone. A boot with no verity —
  a VM, the installer medium, a dev build — says so plainly instead of printing
  a number that looks like an answer.

- **The appliance says when its clock cannot be trusted.** A box that boots
  years slow routes and filters exactly as usual while every log timestamp is
  wrong, every certificate expiry is judged against a date that has not
  happened, and every scheduled firewall rule opens its window on the wrong
  day. `show version` now carries a `clock:` line and `show status` repeats it
  while it is bad; the judgement is the kernel's own clock-discipline flag —
  the same signal `timedatectl` reports — and a reading that also looks
  implausible is quoted as corroboration, never as the reason. A commit
  carrying a time-based rule warns on the spot, and the timer that re-applies
  at each window boundary writes the same warning to the journal. Nothing is
  corrected automatically.

- **`commit` warns when it has just changed the way you reach the box and
  nothing has been saved.** A commit applies to the running system and a `save`
  writes the boot config, so a changed SSH key, login password, SSH daemon, web
  console or firewall decision on the management path is undone by the next
  reboot — and by the next commit, which reloads from the saved file. The
  warning names the paths that changed, says the next boot loads the saved
  configuration instead, and says `save` is what makes it stick. It is a
  warning, never a refusal. Which paths count is derived from the configuration
  model rather than listed, so a setting added under an account, an
  administration service or a management-port rule is covered the day it is
  added.

## [0.4.2] — 2026-08-02

A test fix; the appliance is unchanged.

### Fixed

- **`checks.api` asserted a section the console no longer has.** Its list of
  "every management section is reachable from the browser" still named
  `view-routes`, which stopped existing when routing became one section with a
  pane per protocol. The check was describing an older console and failed on a
  correct page. The panes are now asserted alongside the view, because a
  routing section can be present while every protocol inside it has gone —
  and a green check that guarantees less than it claims is worse than a red one.


## [0.4.1] — 2026-08-02

A build fix: 0.4.0 shipped with an `ebpfHash` that no longer described the data
plane it pins, so every `nixosTest` refused to build.

### Fixed

- **`ebpfHash` matches the pinned data plane again.** Repinning fabric to 0.4.0
  brought in the port-mapping commit, which changes `velstra-ebpf` — so the
  object's hash changed with it and the pin was left naming the old one. Every
  check that boots a VM failed with `hash mismatch in fixed-output derivation`;
  the appliance itself was never affected, because a build that cannot produce
  the object cannot produce a wrong one either.

  Worth writing down, because it will happen again: a **local** check does not
  catch this. Nix finds the old object already in the store under the old hash
  and never rebuilds, so the mismatch only appears on a cold store — which is
  what CI has and a workstation does not. Verify a repin by forcing the rebuild
  (put a deliberately wrong hash in and read the real one out of the error),
  not by watching a check go green.

## [0.4.0] — 2026-08-01

The release the appliance becomes usable without a terminal: a web console that
can drive every section the CLI has, accounts to drive it as, and a large part
of the remaining parity list — intrusion detection, a captive portal, GeoIP,
CGNAT, SYN protection, ACME, flow export and remote logging.

### Added

- **A web console.** Every section the CLI has is drivable from the page, and
  the page writes **CLI commands** rather than a configuration document — so
  there is one grammar, one validator and one audit trail, and a setting the
  console can reach is by construction a setting the appliance understands.
  Edits stage locally and are applied on a word from the operator; Validate
  checks the batch without committing it. The page fetches **nothing** from
  outside itself — no webfont, no CDN, no analytics — because an appliance is
  expected to work on an isolated network, and a console that renders as
  unstyled text during an incident is not a console. It is served from the
  appliance's own API and needs no build step.
- **Accounts and permission groups.** `[[system.group]]` writes a permission
  down once and accounts point at it, so nobody has to remember what a
  particular account may do. Two levels only, deliberately. A password is hashed
  by the appliance and only the hash is stored; `POST /api/v1/login` answers with
  that account's own token. Shell access and management access stay separate
  grants — an account with no group can log in to the box and reach nothing
  through the API. `show users` reports them from the saved configuration, which
  is the authority, rather than from the token directory, which is only secrets.
- **Intrusion detection and blocking (C11).** Suricata watches the wire; an
  alert can block its source through the eBPF blocklist — never through
  Suricata, so a detection engine failure cannot become a forwarding failure. A
  block has a deadline, an operator can lift one or all of them from the CLI,
  and `sni-block` refuses a server by the name it announces in TLS, blocking it
  as a *source* so its answers never return.
- **A captive portal (C20).** A guest zone holds every device until it logs in.
  Admission is keyed by MAC, so one decision covers both address families, and
  the appliance answers RFC 8910/8908 rather than intercepting traffic to
  announce itself — interception is what makes portals fight with HSTS.
- **NAT-PMP port mapping (C18).** A host on the inside can open an inbound port
  for a while. Third-party mapping is impossible rather than merely refused, and
  UPnP is declined on purpose.
- **Blocking by country (C15).** `dbip-country-lite` is extracted at build time
  and countries expand to ordinary CIDRs, so the datapath does not grow a GeoIP
  engine — only a larger blocklist.
- **Domain groups and rate limits (C15).** A firewall rule can match DNS names,
  with an on-disk cache so a failed lookup does not silently empty a blocking
  group; and a rule can carry a `limit`/`burst` token bucket.
- **SYN protection (C15).** `syn-protect` on a port completes the handshake with
  a cookie before the real connection is opened.
- **Deterministic CGNAT (C16).** A fixed block of WAN ports per internal address
  gives attribution without a translation log. `show nat cgnat` asks the agent,
  so there is one implementation of the answer rather than two.
- **Source validation (uRPF/BCP 38)** per zone, with the DHCP and link-local
  exemptions a real link needs.
- **Destination-end rules.** A rule may constrain its destination address as
  well as its source, and a rule's destination *zone* is now enforced.
- **ACME certificates (C19).** `ca = "acme"` really obtains certificates, in a
  timer rather than in the commit, verified against a real ACME server.
- **Load-balanced services (C22)**, configured from the CLI and reported by
  `show`.
- **Remote syslog (C12)** — the journal shipped to collectors as RFC 5424 — and
  **IPFIX flow export**, which sends **deltas** because a collector sums what it
  receives.
- **Alerts (C23).** A failed unit reaches a webhook or a mailbox. The event
  source is systemd itself rather than a grep over the journal, and the watched
  list is deliberately narrow.
- **A UDP broadcast relay (C18)** between segments, and **packet capture from
  the console**, within limits.
- **The data plane's fail-closed switch**, exposed in the CLI.
- **IS-IS authentication** in the CLI (cleartext, HMAC-MD5, HMAC-SHA-256).
- **The appliance answers what a value means.** `GET /api/v1/lookup/{kind}/…`
  resolves an AS number over RDAP and a name through the resolver the box
  already uses, cached, with reserved ranges answered without a request. It
  belongs on the appliance rather than in the browser: a console that asks a
  whois service directly hands the operator's network to a third party, and on
  an isolated box it would show nothing at all.
- **A warning for an addressed interface left without a zone** — the commonest
  way traffic ends up governed by nothing in particular.
- **HA conntrack sync (C9)** — `set system conntrack-sync`: mirror the eBPF
  conntrack table to peer firewalls (`listen` / `peer` / `interval`) so established
  NAT'd connections survive a VRRP failover instead of being dropped. `peer` is
  repeatable, so it scales past a pair to an **N-node full mesh** (matching VRRP's
  and config-sync's own N-node support). Completes the HA triad: VRRP (virtual IP)
  + config-sync (running config) + conntrack-sync (connection state). The
  `checks.conntracksync` nixosTest proves a masquerading master pushing its flow
  table to **two** backups, both applying it into their own conntrack map, end to
  end in the eBPF datapath. Docs: a new HA-conntrack-sync handbook section and a
  three-node HA-cluster example.
- **DHCPv6 relay (C18)** — `set services dhcp-relay server6 <ip|ff05::1:3>`: the
  IPv6 sibling of the DHCP relay, on the same in-image dnsmasq `--dhcp-relay`
  engine. A link can relay IPv4, IPv6 or both (each family needs a static address
  of its own — the v6 relay stamps the interface's `address6`). `checks.dhcprelay6`
  nixosTest proves a client on a server-less segment obtaining a lease from a
  far-segment DHCPv6 pool through the relay.

### Fixed

- **PPPoE and SNMP configuration injection is rejected**, and staged secrets are
  written `0600` — config-sync's secret included. An IPv6 peer is bracketed, and
  a protocol unwrap is guarded.
- **A service claims the router-NAT namespace**, so a port forward's reply is
  not lost to a policy-scoped conntrack miss.
- **`show configuration` was dropping settings it owns** — permission grants, the
  captive portal, port mapping, IS-IS authentication and the CGNAT leaves were
  all settable and none of them came back out, so a saved configuration quietly
  lost them. A certificate subject may now contain a space.
- **Every `show` reads the configuration the API was pointed at**, so a console
  serving one file while a `show` beside it reads another is no longer possible.
- **`syn-protect` is offered where it is looked for** in the CLI.
- **Three console defects that each looked like the console working:** Validate
  cleared what it had just validated so the change could no longer be applied; a
  batch whose first command would be refused applied the rest anyway; and a
  failed read left an empty page indistinguishable from an empty configuration.

### Changed
- **Repin fabric for the SRv6 L2 data plane (B9).** The appliance's eBPF object
  now carries the full SRv6 `End.DT2U` L2 path — headend encap (`SRV6_CONFIG` +
  `SRV6_FDB`, `srv6_encap`) *and* endpoint decap (`SRV6_LOCAL_SIDS`, `srv6_decap`)
  — alongside the existing VXLAN/Geneve overlay, so two fabric hosts bridge an L2
  tenant over SRv6 end to end. `ebpfHash` bumped to match the rebuilt object;
  verifier acceptance is confirmed by the nixosTest suite loading it (`checks.nat`
  boots and NATs green with the SRv6-enabled object). SRv6 is a fabric-level
  primitive with no Sentinel CLI surface yet.

### Tested

- **The console is driven in a real browser.** `tests/console/` clicks its way
  through every rail entry, every create panel and every mask, and `checks.console`
  runs it in the build sandbox — no VM, because loopback and `--no-apply` are
  enough. Three failure modes that pass every static check and every unit test
  live here: a function that was never written, an element a redesign removed,
  and a command the appliance answers with "unknown set path". It found that 19
  of 22 create panels staged a path the CLI refuses.
- **Per-protocol routing VM checks for RIPng, Babel and IS-IS** — two-appliance
  `nixosTest`s (`checks.ripng` / `checks.babel` / `checks.isis`) that form an
  adjacency over the real Velstra datapath and verify each node learns and installs
  the other's redistributed prefix, closing the standing per-protocol coverage gap
  (RIP/OSPFv2/OSPFv3/BGP/BFD/VRRP already had one). IS-IS also confirms Velstra's
  XDP passes its L2 (non-IP) frames. The Babel check surfaced a real requirement —
  Babel needs a unique per-node `router-id` (it keys route origins on it, RFC 8966
  §3.5); the docs/examples set one.

## [0.3.2] — 2026-07-12

## [0.3.1] — 2026-07-12

## [0.3.0] — 2026-07-11

Completes NAT and the interface-type matrix, adds time-based firewall rules and a
stateful DHCPv6 server, and brings high availability to the appliance: CLI-
configurable SSH with per-user logins, and config sync across an HA pair. Ships
with a complete CLI handbook. Each slice ships with a `nixosTest` that loads the
real config (and, where it touches the datapath, the real eBPF) in a sandboxed VM.

### Firewall & NAT

- **Hairpin NAT (NAT reflection)** — the eBPF-datapath piece deferred in 0.2.0:
  reach a port-forwarded service via its public IP from inside
  (`nat destination … hairpin`).
- **NPTv6 / NAT66** (RFC 6296) — stateless, checksum-neutral IPv6 prefix
  translation (`nat npt66`).
- **Time-based firewall rules** — a rule may carry a weekly local-time schedule
  (`rule … schedule days/start/end`) and is only in force while its window is
  open; a systemd timer re-applies at the boundaries.

### Interfaces

- **MACsec (802.1AE)** encrypted point-to-point links and **L2TPv3** Ethernet
  pseudowires, completing the VyOS interface-type parity list.

### Services

- **Stateful DHCPv6 server** (`interface … router-advert dhcp6-pool`).
- Dynamic-DNS PATH fix (`ddclient` gets iproute2 + util-linux); end-to-end mDNS
  reflector and DHCP-relay VM tests.

### High availability & management

- **SSH management, CLI-configurable** — `services ssh` (daemon port / listen /
  password-auth, key-only by default) and `system login <user>` (per-user SSH
  keys + crypt(3) hashed passwords, VyOS-style; accounts created at commit via
  `mutableUsers`).
- **HA config sync** — `system config-sync` pushes the running config to peer
  firewalls on every commit, over the existing REST API (shared bearer secret,
  loop-safe).
- **VRRP, BFD and OSPFv3** are now covered by end-to-end 2-node `nixosTest`s
  (VRRP virtual-IP failover, BFD sub-second fast-detection, OSPFv3 IPv6 adjacency)
  — including a fix to the wren daemon so graceful shutdown (and thus a clean VRRP
  hand-off) runs under `systemctl stop`, not just Ctrl-C.

### Documentation

- A complete **CLI handbook** in the mdBook — every command by section, with
  worked examples and four full example configurations, auto-published to GitHub
  Pages.

## [0.2.0] — 2026-07-07

A large release. Sentinel gains a coherent VyOS/JunOS-style configuration
shell, the full per-object routing surface, an on-box PKI, a REST management
API, NAT64/DNS64, and a reboot-persistence fix — all still driving the one
declarative config model.

### Added

- **A single-paradigm configuration shell (pure VyOS/JunOS).** The config is a
  tree and every command names a path in it: `set` / `delete` / `show` /
  `edit` (+ `up` / `top` / `exit`), with the transactional `commit` /
  `commit-confirm` / `save` / `rollback` / `compare` lifecycle. Every line
  means exactly one thing — there is no implicit `set`, no bare-path context
  shorthand, and no absolute-path mode switching. The edit context renders as
  its own `[edit …]` banner line above a short prompt, and a `*` in the prompt
  marks uncommitted edits. Per-object configuration throughout (interfaces,
  rules, NAT, zones, neighbors, areas).
- **A readable CLI presentation layer.** Grouped, aligned, coloured `help`
  (with `help <command>` details and examples), contextual Tab/`?` completion
  with per-keyword descriptions, colour-coded errors/warnings/success (TTY
  only, `NO_COLOR` respected), and did-you-mean guidance — mistyped commands,
  retired spellings (`no`/`do`/`end`), and bare config paths all point at the
  correct VyOS spelling.
- **Value hints everywhere (vtysh style).** Every value position shows what to
  type: `<A.B.C.D>`, `<X:X::X:X>`, `<A.B.C.D/M>`, `<1-65535>`, `<1-4094>`,
  `<xx:xx:xx:xx:xx:xx>`, `<host:port>`, … as display-only completion entries
  (Tab never inserts them) plus a dimmed inline ghost hint at single-value
  positions. Live names are offered wherever a value references something that
  exists: interfaces, zones, rules, NAT rules, groups, route filters, VRFs,
  IPsec connections, PKI CAs/certificates, WireGuard tunnels. The completion
  list is typographically layered (bold keywords, italic hints, dim
  descriptions) and the command word highlights green/red as you type.
- **C14 — MACVLAN + QinQ.** `type = macvlan` (a pseudo-NIC with its own MAC on
  a parent, `macvlan-mode`), and `vlan-protocol 802.1ad` on a VLAN subinterface
  for 802.1ad QinQ (stack a C-tag VLAN on an S-tag VLAN) — rendered as networkd
  netdevs.
- **L2 done right: bridge/bond members and 802.1Q on the device.** Membership
  now lives on the bridge/bond itself — `set interface br0 member eth1`
  (repeatable, per-member delete); the old per-NIC `master` field is gone. A
  bridge can be `vlan-aware` with per-port `vlan-tagged <ids>` and
  `vlan-untagged <pvid>` (rendered as networkd `VLANFiltering=` +
  `[BridgeVLAN]`). A VLAN subinterface named `<parent>.<id>` infers `parent`
  and `vlan` from its name at commit.
- **WireGuard moved under `vpn`.** `set interface wg0 type wireguard` creates
  the interface (address/zone as usual); keys and peers live at
  `set vpn wireguard wg0 private-key|listen-port|peer <pubkey> …` next to
  IPsec — cross-checked both ways at commit.
- **Config-model audit fixes.** `firewall rule … to <zone>` is now optional
  and draws an explicit commit warning (the datapath does not enforce the
  destination zone yet — rules apply from their source zone); broad
  drop/reject rules are rejected with the working alternative named. List
  fields (BGP communities/networks, IGP interface/redistribute lists, group
  members, service upstreams, VRRP addresses, …) gained per-item add/remove
  instead of replace-on-set. Dozens of new validations: injection-shaped
  characters in SNMP/dyndns/DNS free-text (also rejected again at render
  time), VRF table ranges + collision with multi-WAN policy tables,
  OSPF/IS-IS `dead > hello`, BFD/VRRP/ROA ranges, DHCP pools inside the
  interface subnet, IPsec PSK length, NAT port 0, `protocols import` keyed to
  the routing daemon's actual protocol set. Multi-WAN health checks honour
  per-uplink intervals; a disabled PPPoE interface tears its session down;
  OSPFv3 `redistribute` values the daemon can't express error instead of
  silently vanishing.
- **Full per-neighbour BGP.** Every wren neighbor field is now reachable:
  `local-as`, `update-source`, `ebgp-multihop`, `description`, `shutdown`,
  `hold-time`, and more; route-maps, communities,
  RPKI, confederation, and aggregate-address.
- **Routing policy (`policy`).** VyOS-style `set policy prefix-list` +
  `set policy route-map` with explicit `match` / `set` clauses and
  `match prefix-list`, replacing `[[protocols.filter]]`; route-maps are
  referenced by BGP neighbours, VRFs and redistribution.
- **Per-object IGP + routing surface.** OSPFv2 / OSPFv3 (areas, auth, timers,
  stub/NSSA), IS-IS, RIP / RIPng, Babel, VRRP with interface/route tracking,
  global BFD, multicast (IGMP/MLD), VRFs, and per-protocol redistribution
  filters.
- **C18 — services parity.** LLDP, read-only SNMP, Wake-on-LAN, mDNS repeater,
  dynamic DNS, and DHCP relay.
- **C17 — OpenConnect VPN server.** An AnyConnect-compatible TLS road-warrior
  VPN (`set vpn openconnect …`, served by ocserv): client address pool, pushed
  DNS/routes or full-tunnel, password auth, TLS identity from the on-box PKI —
  the client-VPN modality alongside site-to-site IPsec and peer WireGuard.
- **C19 — PKI + ACME.** An on-box certificate authority with leaf issuance
  (runtime, idempotent, private keys mode `0600`) plus ACME / Let's Encrypt
  account configuration.
- **C12 — REST management API.** `sentinel api`: a bearer-token REST server
  over the *same* config model the CLI edits. `GET`/`PUT /api/v1/config` run the
  exact parse → live-apply → persist path a CLI `commit` takes; `GET
  /api/v1/status` and `/api/v1/show/*` proxy the operational `show` data. No
  UI-vs-CLI config drift.
- **C10 — NAT64 / DNS64.** tayga (NAT64) + unbound (DNS64) for IPv6-only
  networks reaching IPv4 destinations, with a documented no-ALG stance.
  (Hairpin NAT is deferred — it needs the eBPF datapath.)
- **C13 — signed update channel.** `[update]` pins a channel URL + an Ed25519
  release-signing key; `sentinel update check`/`install` fetch a signed
  manifest, verify its detached signature against the pinned key and the image's
  SHA-256 before ever writing an A/B slot — the authenticity gate in front of
  the existing verified-boot slot switch.
- **Per-object polish.** Description and `disabled` on interfaces, firewall
  rules, NAT rules, and zones; DHCP static mappings plus lease / domain /
  router / DNS options; DNS cache-size and local-domain tunables.
- **Integration tests.** Per-protocol routing nixosTests (OSPFv3, IS-IS,
  RIPng, Babel, VRRP, BFD) alongside the existing BGP/OSPF/RIP checks, plus
  new `api`, `pki`, `nat64`, `lldp`, `snmp`, and `dhcp-relay` VM tests and
  interface/service tunable coverage.

### Changed

- **Explicit `ApplyMode { Live, Boot }`** through the config-apply pipeline, so
  boot-time reconciliation and live `commit` share one code path with distinct,
  intentional behaviour.

### Fixed

- **Reboot persistence.** Saved config now fully survives a reboot: fixed a
  boot-time deadlock and the missing runtime re-apply that could leave a
  rebooted appliance short of its saved state.

## [0.1.0] — 2026-07-05

First tagged release of the Sentinel immutable firewall/router appliance.

### Included
- Named zones + per-zone posture, VLANs, firewall (address/port groups,
  port ranges, per-rule log, source-CIDR, reject), NAT (masquerade + DNAT
  port-forwards).
- WireGuard (C1); DHCPv4 + RA/SLAAC + DNS (dnsmasq: forwarding, host-
  overrides, blocklists) + NTP (C7); dual-stack IPv6 + DHCPv6-PD.
- Bridges + bonding, per-interface MTU/MAC (C14 part); full routing CLI
  (BGP/OSPF/OSPFv3/IS-IS/RIP/RIPng/Babel/VRRP/static).
- **PPPoE client + TCP-MSS clamping (C5)** — real WAN uplinks.
- **QoS / traffic shaping (C8)** — per-interface CAKE / fq_codel.
- **C22 — L7 reverse proxy / load balancer.** `services reverse-proxy <name>`
  terminates TLS on a listen port using an on-box PKI certificate and forwards
  to one or more backends round-robin (HAProxy) — HTTP-aware routing + TLS
  termination on top of the datapath's L4 path.
- Verified boot / A-B / secure boot / atomic commit with commit-confirm,
  config archive, rollback-N, diff (C21).

### Not yet included (roadmap)
- IPsec (C2), multi-WAN (C6), stateful HA (C9), IDS/IPS (C11), REST/Web UI
  + AAA (C12), signed update channel (C13), PKI/ACME (C19), and the rest of
  the C-track parity list.

[0.2.0]: https://github.com/Velstra/sentinel/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Velstra/sentinel/releases/tag/v0.1.0
