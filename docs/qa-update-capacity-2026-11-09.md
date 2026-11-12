# Default-capacity signed OTA gate: implemented, execution pending

Run in release CI/build infrastructure, never on a customer appliance:

    nix build .#checks.x86_64-linux.update-capacity -L

The gate uses the same immutable image factory and product boot assessment as
the existing installer/boot-fallback checks. It deliberately does NOT emulate
the updater, replace crypto, mount a host store, add an update storage disk,
increase RAM, override TMPDIR, or manually bless/select a boot target.

## Exact intended execution

- One started UEFI appliance,4 GiB RAM and10 GiB backing disk, real six-entry
  GPT, EROFS/dm-verity and ordinarily grown ext4 data on vda6.
- An unstarted donor image from the same exact source, different OS release
  and marker, full6,040,866,816-byte signed RAW. Host computes its complete
  signed SHA256 and the source-A partition hashes used to assess target B.
- A bounded loopback TLS reference in the test driver, reached through the
  normal QEMU user-network host address10.0.2.2. The donor image never enters
  the DUT's store closure. Only disposable PUBLIC CA/release-key material is
  included in the guest; fixture private keys remain a separate derivation
  output used by the host reference/publisher.
- Real system-CA HTTPS and Ed25519 atomic-envelope metadata, not an HTTP
  shortcut, TLS exception, unsigned manifest, or local-image substitution.
- Bad signed metadata refuses before an image GET. A complete full-size RAW
  with one flipped byte refuses at the signed whole-image digest.
- SIGKILL targets only the recorded update child with matching PID start time,
  command and actual anonymous stage. The real curl owner-death behavior and
  shared update lock are observed, not injected into product code.
- A genuinely insufficient128 MiB ext4 fixture is created ONLY in a private
  mount namespace for that negative updater process. It holds an exact copy
  of the saved channel config, is mounted over the namespace's state path and
  triggers the real reserve refusal before image GET. It is NOT a global
  state replacement, auxiliary update disk, host/native disk-fill experiment,
  or positive-case staging workaround. Cleanup never recursively deletes a
  mounted directory or force-unmounts an unknown filesystem.
- Every refusal/cancellation rechecks the active/inactive partition bytes,
  whole ESP, both GPT headers/entries, saved config, SSH/TLS keys, archives,
  boot ID and machine ID. Only legitimate update-status records may change.
- Before the baseline, the real Web console is enabled on loopback with its
  ordinary persistent TLS identity, and the ordinary CLI save path creates an
  actual archive revision. Config, both SSH key pairs, TLS files and a revision
  must exist; preservation assertions cannot pass on empty sets.
- The positive path runs the packaged normal channel CLI with TMPDIR/TMP/TEMP
  unset on the original vda6 filesystem. It samples the actual anonymous0600
  stage through /proc, exact logical length, sparse physical allocation, updater
  PID RSS (not a sum of all descendants),
  shmem, free-state reserve and OOM counters.
- Success must match donor verity/store exactly in B, leave A/config/keys and
  protected GPT geometry intact, and stage B+3 while retaining permanent A.
  A real shutdown/start must then boot donor B and become permanent through
  the unchanged product health/bless ordering, with no manual boot repair.
  The same VM's raw machine-ID hash must stay unchanged, as must both staged
  GPT header/entry regions after automatic boot assessment.

The single started VM explicitly has a stable QEMU firmware UUID, checked
before and after boot. Raw machine-ID equality is scoped to that unchanged
virtual hardware, not a new promise that tmpfs `/etc/machine-id` survives
hardware replacement. No machine-ID file or kernel override is injected. The
separate persistent commercial `update-machine-id` enrollment is not tested by
this plaintext-capacity gate.

A permanent factory boot must have its four core services ready and pass the
actual installed read-only product checker. Trial-only boot-complete/bless
units need not run on that boot and are never started manually. The counted
updated B boot still must activate both automatic assessment units, pass the
same checker and become permanent. No trial-success requirement is waived.

On success the derivation writes default-capacity-update.json with artifact
SHA256, TLS transfer receipts, real child/file/memory observations and boot
assessment witnesses. Failure must fail the derivation; no green report is
created from configuration acceptance alone.

## Evidence boundaries

This source adds a complete VM test, but no Nix build/evaluation or VM was
launched during its preparation. Syntax parsing, embedded-Python compilation
and small actual-loopback TLS/fixture unit tests are separate HOST evidence.
They do not close OSQA015 or certify the future combined source/image.

The intended VM scope is plaintext ext4 only. LUKS-backed ext4, mdraid ext4,
an independent default-path OpenStack boot, native hardware and a deliberately
bad-image fallback remain separately required scopes; the existing bootfallback
gate still provides that distinct regression. Do not label this gate as all
installer options, all release checks, native HA, or production certification.
