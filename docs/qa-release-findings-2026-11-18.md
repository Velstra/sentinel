# Release-readiness remediation — 18 November 2026

**Not a release approval.** These are source/component regressions, not a
certificate for a signed appliance disk. No production key or update channel
was used.

## Corrections

- Invalid candidate `show` sections and failed in-session `run` commands now
  fail a piped configuration session before later commands can save changes.
- Offline saves use a private, atomic sibling file. They work in writable
  shared directories such as `/tmp`, never invoke sudo, and refuse symlinks or
  files owned by another account. Failure messages identify the destination.
- The CLI no longer says that the live console reads only the saved file.
  `commit` still applies live; `save` is required for reboot persistence.
- Both quickstart examples remove a redundant broad `to wan` rule. Their
  existing LAN-accept policy is now explicitly described as all-destination
  access, not WAN-only protection. A real CLI test checks both sample forms.
- Fabric is pinned to `9168f8512f1e72bbef84de56683025c3076ccd0f`, which accepts
  the compiler's `local_destination` field. The measured BPF object hash is
  `sha256-otLvkMiV31a7agSVNSIvAYa+2qD71WrpGZkRiar1PEc=`. The object embeds a
  source identity checked before userspace compilation, preventing silent
  reuse of an old fixed-output object with new source.
- The reject fixture targets `local`, because its packets target the firewall
  itself. The commit fixture checks both live NIC discovery and the absence of
  host NIC discovery in offline mode. Neither packet expectation was relaxed.
- Password helpers and read-only observer capabilities are wired into the
  appliance. Wren's static reload adapter waits for its acknowledged routing
  generation instead of treating signal delivery as successful convergence.
- NTP's existing late-source/dead-RTC test now also requires the CLI and systemd
  to agree after synchronization.
- The IKE service is available on demand, not a factory boot listener. Its
  runtime configuration must exist before it can start. Policy-based and VTI
  tests now require the service to be absent before the first IPsec commit;
  the policy-based test also requires its sockets to close after tunnel removal.
  Its separate policy-based and VTI runtime regressions pass (see cohorts below).
- A subsequent factory test exposed readiness rejecting an account-only commit
  when no NIC is configured. Zero compiled bindings now request a stopped
  dataplane and require an actually inactive service. Nonempty, missing or
  malformed bindings never waive the normal active/socket readiness checks.
  The real first-binding/last-binding transition and negative boot-readiness
  cases pass in the follow-up VM cohort.

## Mandatory gates restored

The public catalog now exports **174 checks**. It includes the complete
20,000-connection pressure workload, native TCP-reset differential, 17-case
netfilter differential, and verifier guests for Linux 6.6, 6.12 and 6.18.
Preserved differential/pressure oracle tests were restored rather than replacing
failed expectations with smaller smoke tests. All 22 shipped entry points are
required by each verifier lane. PR/nightly CI runs the kernel matrix.

The Community release planner, aggregator and pre-sign/publish validation reject
a catalog missing the mandatory safety checks, even if the remaining receipts
are green. The floor also retains witness/two-node pairing, same-source retained
flows and mixed-version HA; a passing pairing test cannot replace the latter.
Every other exported check remains mandatory too. The Enterprise
catalog/source pin must be migrated together after this source revision is
qualified; its older 164-check catalog must not be called equivalent.

## Verification record

- Final local Rust recheck: 1,275 unit tests and four real CLI
  subprocess/filesystem tests pass; warning-denying Clippy and formatting pass.
  Earlier frozen cohorts below predate the additional factory-readiness tests.
- All nine loopback browser suites pass. These exercise the actual API and CLI
  with offline application disabled, not live packet forwarding.
- Python: 74 release/source tests, 141 appliance helper tests, eight differential
  oracle contracts and 19 pressure-observation contracts pass. Synthetic signing
  tests use newly generated test-only keys, never production identities.
- Workflow syntax passes Actionlint. Full `nix flake check --no-build` passes
  for the expanded 174-check catalog, including the corrected NTP/pairing
  fixtures. The later HA observer change separately passes the real NixOS
  driver typecheck/lint and its VM check; evaluation is not runtime proof.
- The handbook builds successfully; its link checker passes 661 local links
  across 43 generated pages. The support matrix highlights the current failed
  gates rather than presenting older successful smoke tests as release proof.
- Initial runtime cohort:
  `/nix/store/ajbw02vy5fqz3c4nmkwzdmq9fqp8i5r5-source`.
  Commit (175 seconds), hairpin (68 seconds) and NAT (221 seconds) pass. Review
  found the NAT fixture's last step omitted rather than deleted an active rate
  limit; the corrected fixture must prove removal in its compiled configuration.
  Reject failed because the newly named local zone lacked its explicit `local`
  flag. The corrected fixture declares that flag and its interface address.
- Follow-up cohort with the corrected tests, new gates and helper/NTP tests:
  `/nix/store/svkr54r5ska2d6rb3zj1i8svr2dp6gvx-source`.
  The 15-check batch completed with 11 passes and four failures: NTP,
  full-load retention, TCP-reset validation and fragment conformance. The
  earlier prepared `sr9ifjrx` cohort was not executed.
  Commit (205 seconds), corrected NAT (217 seconds), hairpin and corrected reject (69 seconds) pass on
  this cohort too. This reject test checks generated rejection packets, not the
  separate still-open validation of incoming forged TCP resets.
  The real HTTPS authentication-boundary/rate-limit/authority check passes
  in 154 seconds.
  Login lifecycle, SSH/PAM revocation and TOTP replay across reboots pass
  (271 seconds), as do all six restricted read-only capabilities (209 seconds).
  Wren's acknowledged static reload passes for root, admin and API callers,
  including actual off-link FIB failure and rollback (194 seconds).
- All three verifier checks pass: Linux 6.6.159, 6.12.113 and 6.18.57 each load
  all 22 expected programs from object SHA-256
  `a2d2ef90c895df56bb6a049535222f0186bedaa0fbd56ae919991189aaf53c47`.
  The copied receipts match their builder-side SHA-256 hashes.
- The same cohort's additional factory boot-health test reproduces the
  unconfigured IKE listener: `strongswan-swanctl.service` is unexpectedly active.
  The corrected service wiring and IPsec/VTI regressions ran from
  `/nix/store/bar9s1rjx1ajm3hdzwzivkx4ypm7mm27-source`.
  Policy-based IPsec passes (140 seconds), including socket closure after the
  last tunnel is removed. The VTI test passes (227 seconds). The corrected
  factory boot-health test passed the IKE/listener checks, then exposed the
  separate factory commit-readiness defect described above.
- Follow-up `/nix/store/b5clwl5vyb89ckwd3m5145fpcg89c1hw-source` tested factory
  readiness, first/last binding transitions, commit and NTP. Local 1,275 unit
  tests, four CLI process tests, Clippy and formatting pass. The builder also
  passes those 1,279 Rust tests. Boot health passes in 178 seconds, including
  the factory account change, first/last NIC transitions and refusal to bless
  missing interfaces or a stopped configured dataplane. Commit passes again
  (219 seconds). The earlier NTP
  run failed its first upstream synchronization before the added CLI/systemd
  agreement assertion. The follow-up retains the timeout and adds packet,
  chrony and journal diagnostics; that diagnostic-only attempt did not fix
  the acquisition timeout (see the completed NTP follow-up below).
- The `b5clwl5v` HA pairing fixture refuses enrollment because it relied on
  silently widening the default loopback API listener. The corrected fixture
  explicitly binds each member's control address and checks that synchronization
  preserves both addresses. Cohort
  `/nix/store/nd5f5p22if8rxcbja39mi1wrvajmbhz6-source` passes the complete
  two-node pairing, bidirectional synchronization, reboot, partition and
  recovery test (398 seconds); its witness variant also passes (387 seconds). The
  retained-flow failover check fails its 1.5-second promotion budget
  (2.003 seconds observed). A repeat without other test guests also fails
  (2.137 seconds). Guest logs report forwarding earlier than the driver's
  observation. Cohort `/nix/store/bimdaz2w483gbpfbg0y0c0fi4n8dkg9h-source`
  observes from one guest process while retaining the same host-side 1.5-second
  deadline (including SIGSTOP command and observation return costs). The whole
  check passes in 105 seconds: promotion 1.338 seconds, 211 exchanges through
  one unchanged TCP socket/SNAT tuple, maximum traffic gap 1.743 seconds below
  the unchanged 3-second bound, no resets, old-MAC fencing and continued
  traffic after powering off the primary. Both original failed logs remain
  retained. The same cohort also passes the historical-source mixed-version
  check in 108 seconds: promotion 1.486 seconds, 232 exchanges, unchanged public
  port 47009 and maximum traffic gap 1.811 seconds. Its independently pinned
  legacy object rebuilt with the expected hash. The 14-ms promotion margin is
  narrow; neither this single-flow pass nor the same-source pass qualifies
  loaded failover, every rolling-upgrade scenario or a final signed-image update.
- NTP diagnostics show the initial eight requests received no replies during
  the deliberate outage. The source's next poll interval was 128 seconds,
  longer than the old 120-second test deadline. An additional bidirectional
  ping control verifies restored reachability. The follow-up observes normal
  retry for up to 300 seconds without restarting chrony, forcing a burst or
  changing the shipped clock configuration. Cohort
  `/nix/store/zpw3fgx1llldlczhbnlbpz573b61wy5b-source` passes the complete test
  in 384 seconds: late-source recovery with the same chrony PID, correction of
  the dead RTC, CLI/systemd agreement, LAN-client synchronization, and reboot
  after restoring the default client-only configuration. The initial
  packet collector also needed a startup barrier and `any` interface capture
  to survive the deliberately downed link; failed runs remain recorded.
- The complete `svkr54r5` pressure run remains red. All 20,000 initial echoes
  succeed, but only 16,322 held echoes pass (17,000: 16,321; through 16,000:
  all pass). All 20,000 NAT bindings remain present. Non-atomic map snapshots
  identify missing firewall roles for 3,682 flows; this count is not identical
  to socket failures measured at a different time. The summary's copied SHA-256
  is `9eda36bd59f7ecae809f078000ca4a6c0eb5321478efa7491a622325b8baec88`.
  The complete raw-output tree was copied and its sorted SHA-256 manifest
  matches the builder: `807ed639c2af2b99903b342f0508c40893ce8ab0f2df132c065b05e446def3e1`.
- The same cohort's netfilter differential completes all 17 cases: 15 pass,
  fragmented IPv4 UDP SNAT and fragmented IPv4 ICMP SNAT fail. Both reference
  controls deliver successfully; Sentinel times out or loses the echo. This
  is fresh reproduction, not a fix or a waived expectation.
- TCP reset validation reproduces three distinct state-destruction failures:
  a wrong sequence, an in-window nonexact reset and an invalid TCP checksum.
  The subsequent same-socket echo fails in each Sentinel case. Foreign-tuple
  and genuine-reset controls pass. The final run's five nftables reference
  cases all pass. An earlier attempt also failed the in-window reference
  control; that observation is not treated as a product failure or erased by
  the subsequent pass. The final copied receipt SHA-256 is
  `2e7e50e36d476649db230869f880e856cdf96fcff9086c522613b0c6c0424bc6`.

## Still blocking 1.0.0

The last complete pressure run loses established flows above the tested lower
cohorts. Invalid TCP resets can still destroy live state, and fragmented IPv4
NAT still fails its differential gate. Restoring these gates does not fix those
dataplane defects. Full HA/rolling-upgrade qualification, a supportable base
maintenance plan, exact signed-image tests and fresh image SBOM/CVE assessment
remain required. Hardware performance/certification is not claimed.
