# Update trust and recovery reference

For the short operating procedure, start with [review and stage an update](../operations/update.md). This reference retains the trust, boot-selection and recovery constraints behind that procedure.

OS updates are **A/B**: a new image is written to the inactive store slot and the
bootloader is switched to it. Automatic fallback requires an intact, previously
blessed slot; an unprovisioned or broken first installation has no such guarantee.
The architecture is in
[A/B update slots](../architecture/ab-updates.md); this is the operator view.

## Signed channel: local CLI or Web UI

On the live A/B appliance, as an administrator:

```shell
sudo sentinel system status
sudo sentinel system update check --wait
sudo sentinel system status
# Review the offered version, image digest and signing identity first.
sudo sentinel system update stage --offer <exact-offer-id>
sudo sentinel system update job <job-id> --wait
```

Output is JSON. Submissions return a durable job; `--wait` observes it for at
most five minutes without owning or cancelling it. Disconnects and API restarts
do not stop the independent worker. If a submission's outcome is unknown, inspect
`system status` using its request correlation; do not resubmit it blindly.

In **System → System updates**, refresh, **Check signed channel**, review the
exact verified offer, then **Download & stage update**. CLI jobs appear in the
same retained history. Changes to configuration, trust or boot identity require
a fresh check/review. Pending config changes, remote member selection, read-only
accounts and stale observations cannot authorize Stage.

Staging replaces the inactive slot and selects a counted next boot. It does not
reboot or claim a successful boot. Inspect boot selection and cluster readiness
before rebooting one member at a time. There is no trust/downgrade override.
Native Enterprise `update check` uses this worker too; the former unreviewed
`update install` path is refused. Off-box/no-apply consoles cannot run OTA jobs.

### Expiry and replay protection

Online offers must carry signed channel, architecture, sequence and validity
timestamps. Metadata expires within 14 days; expired or incorrectly scoped offers
and issue times beyond the five-minute clock-skew allowance are refused.
Synchronize the appliance clock before checking for
updates. A check persists its highest accepted sequence and clock observation in
`/var/lib/sentinel/update-trust`; lower sequences, changed bytes at the same
sequence, unauthorized signing-key changes and substantial clock rollback fail
closed. Stage rechecks the exact offer before writing the inactive slot.

Do not delete this directory to clear an error: that would discard rollback
protection. Repair the clock or obtain fresh, correctly signed metadata instead.
A missing or corrupt ledger that was once published requires investigated
recovery, not an automatic reset. A first check interrupted before its ledger
was published (only the lock and staged files exist) is completed by the next
check. Signing-key rotation is not yet implemented by this ledger.

The key pin and the sequence floor are not per channel name. A channel label
the appliance has not used before must be signed by a key already pinned for
another label, and its sequence must not be lower than the highest sequence
that key reached under any label: one signing key has one sequence space.
Selecting a channel signed by a different key therefore needs the same
investigated recovery as a key rotation.

A slot write (CLI or UI, signed or `--allow-unsigned`) is refused while the
running image is an unblessed counted trial or is not the next default:
overwriting the other slot then would remove the only known-good fallback.
Older appliance versions without this validation must first be upgraded; new
metadata alone cannot protect an old reader. Offline media and automatic boot
fallback use their separate policies below.

## Community offline/local-image updates

This section applies only to the Community RAW-image writer. Native Enterprise
images refuse this writer, including `--allow-unsigned`; use the reviewed
channel workflow above. An offline proof authenticates operator-selected bytes,
not their online freshness or subscription entitlement.

```shell
# from a new raw image (built with `nix build .#sentinel-image`) plus its
# signed digest velstra-sentinel.raw.sha256(.sig) beside it
sudo sentinel update /path/to/velstra-sentinel.raw --commit

# from a USB stick the image was dd'd onto, with the release's proof from
# another medium (a signed manifest, or the signed digest)
sudo sentinel update /dev/sdX --commit --signature /mnt/release/manifest.json.sig
```

For a signed Community local update:

1. the image's signature is **verified** (see below);
2. a release older than the running one is **refused** unless
   `--allow-downgrade` (when the proof states a version);
3. the **active** slot is detected (via `/dev/mapper/usr`);
4. the image is read once and hashed in full against the signed digest —
   nothing is written unless it matches;
5. the new image's store + verity are written to the **inactive** slot from that
   same open file, re-hashed on the way, so an image that changes underneath
   (a rewritten file, a swapped stick) is refused before the slot is activated;
6. that slot receives the source image's verity partition types and GUIDs;
7. the new UKI is installed as `sentinel-<inactive>+3.efi` with **3 boot tries**;
8. `loader.conf` prefers the new slot with `preferred sentinel-<inactive>*`,
   retaining `default sentinel-*` so an exhausted candidate can fall back.

Before any inactive-slot write, both signed and unsigned commits require the
**running UEFI systemd-boot version 260 or newer** and no nonempty firmware
default, preferred or one-shot entry override. Older/non-systemd loaders and
malformed or unreadable EFI state are refused. Sentinel does not silently clear
firmware variables: inspect the override named in the error and explicitly
review the suggested `bootctl` clearing command before retrying. Bootloader
maintenance is a separate operation, not a package-manager update on the node.
A hard per-slot `default` is unsafe here: systemd-boot 260 honors that selection
even when its boot counter reaches zero.

Without `--commit`, the plan is printed but nothing is written.
An image carrying the active slot's verity/store GUIDs is refused before any
write, including an unsigned source. Do not re-seal the booted medium. Unplug a
USB donor before reboot: it now shares the candidate's GUIDs and could otherwise
be mistaken for the installed slot.

### Local images are signature-checked by default

A local `sentinel update <image>` verifies an Ed25519 proof before writing. It
uses `<image>.sha256` and its detached signature when the digest file exists;
otherwise it uses `<image>.sig`. An explicit proof can be named by
`--signature <file>`. The updater tries pinned release keys in this order:

1. `--pubkey <pem|file:path>` on the command line;
2. the saved `[update]` channel's `public-key`;
3. a release key baked into the image at `/etc/sentinel/release.pem`.

Missing keys, missing signatures and invalid proofs fail closed. Publishers
should sign a small digest for multi-GiB images: direct Ed25519 signing buffers
the entire input. The digest file contains only 64 hex digits and an optional
newline, not a filename.

```shell
sha256sum velstra-sentinel.raw | cut -d ' ' -f 1 > velstra-sentinel.raw.sha256
openssl pkeyutl -sign -inkey release-priv.pem -rawin \
  -in velstra-sentinel.raw.sha256 -out velstra-sentinel.raw.sha256.sig
```

The updater verifies the signed digest, then hashes the entire image. A bad
digest proof never falls back to a raw signature. Legacy direct image signatures
are supported for regular files up to 64 MiB: a private copy is verified and
installed. Larger images need the signed digest.
Signing belongs on the publisher's protected machine, not on customer nodes.

### USB sticks and other block devices

Nothing can sit "beside" `/dev/sdX`, and a stick is larger than the image on it,
so a raw signature cannot say where the image ends. A block device is proven by
`--signature` naming one of:

- `…/manifest.json.sig` — the channel's signed release manifest (copy the
  channel directory to a second medium). It names the image's SHA-256 and the
  release version, so the downgrade check below applies.
- `…/velstra-sentinel.raw.sha256.sig` — the signed digest (above).

The device is read up to the end of the image its own partition table describes
(the backup GPT header), and those bytes must hash to the signed value.

### Downgrades

An online offer and an offline signed manifest are checked against the running
**OS image release**, not just the Sentinel package version. Older releases and
unusable image version identities are refused. Equal versions may pass the
version check, but identical active partition GUIDs still cannot be staged.

The reviewed CLI/UI workflow has no downgrade override. Only the legacy
Community writer accepts `--allow-downgrade` as an explicit operator exception.
A signed digest or raw signature contains no release version and therefore
cannot rule out a downgrade: such a proof is refused unless `--allow-downgrade`
accepts it explicitly. Use a signed manifest for a normal offline update.
Offline proofs do not consult the online expiry/sequence ledger. Online offers,
including `file://` channel directories, must satisfy
[expiry and replay protection](#expiry-and-replay-protection).

An optional manifest `product` must equal `velstra-sentinel` when present.
Legacy offline manifests may omit it; do not treat that compatibility as proof
of a current online offer.

`--allow-unsigned` deliberately skips local signature verification on Community
only. It does **not** bypass bootloader, identity or identical-image safeguards,
does not permit re-sealing the active image, and is not an OTA trust override.

## Configure a signed channel

Pin a channel URL and its Ed25519 signing key in the saved local configuration:

```shell
configure
set update url https://updates.velstra.example/sentinel
set update public-key file:/etc/sentinel/release.pem
commit
save
```

- `url` is the channel base: an `https://` or local `file://` directory holding
  `release.json` (or the compatibility manifest/signature pair) and its images.
  Local channel directories still require signed online freshness.
- `public-key` is the pinned Ed25519 release-signing key, PEM. `file:<path>`
  reads it from disk (so the key can live in the immutable image rather than the
  config); an inline PEM also works.
- The fetch is the pinned curl with `--disable` and an **empty environment**:
  `HTTPS_PROXY`/`ALL_PROXY`, `SSLKEYLOGFILE`, `CURL_CA_BUNDLE`/`SSL_CERT_FILE`
  and `~/.curlrc` are ignored. An `https://` channel is checked against the
  system trust store; proxies are not supported.
- The whole `[update]` section is local-only: a fleet controller cannot change
  it (see the fleet documentation).

Both fields are required. Use `sudo sentinel system update check --wait`, review
the exact offer, then Stage as above. Native Enterprise `sentinel update check`
is an alias for that worker; `sentinel update install` is refused. Community
retains a legacy `update check`/`install` adapter, but that is not the reviewed
offer/job workflow and should not be used as an unattended replacement for it.
No channel path accepts an unsigned release or bypasses online freshness.

## Named channels and subscriptions

A box can hold several named channels, each with its own URL, signing key and
optional subscription credential. A channel name is not proof of certification;
review the release's verification evidence.

```shell
configure
set update channel community url https://updates.velstra.example/community
set update channel community public-key file:/etc/sentinel/community.pem
set update channel enterprise url https://updates.velstra.example/enterprise
set update channel enterprise public-key file:/etc/sentinel/enterprise.pem
set update channel enterprise subscription-key <key>
set update channel enterprise        # ← selects the active channel
commit
save
```

- Pin `url` and `public-key` independently for each channel. Reusing a signing
  key shares that trust; the channel name does not create a separate identity.
- `set update channel <name>` selects an existing channel. The single-channel
  configuration above remains the unnamed `default` channel.
- `subscription-key` is a bearer secret. The read API redacts it and
  `show subscription` masks all but its last four characters. Saved configuration
  and local `show configuration` contain the full credential: protect them.

### What an expired subscription does — and does not — do

An expired or rejected subscription prevents fetching new images from that
channel; it does not disable routing, filtering, saved configuration or the
console. Authentication failures are reported, not treated as unsigned offers.

Subscription expiry is not signed **metadata expiry**. An entitled customer
still needs a fresh, scoped offer; a metadata refusal never disables the
running data plane either.

### `show subscription`

This legacy view reads saved configuration and the legacy adapter's last-check
record; it performs no fresh network request. Use `sentinel system status` for
the durable worker's offers and jobs. The displayed `expiry: not reported`
means **subscription entitlement expiry is not provided by this view**. It says
nothing about the mandatory expiry timestamp in signed online metadata; do not
infer a license expiry date from a release's validity window.

## The rollback guarantee

The candidate starts with `+3` tries. The product health gate verifies saved
configuration against live hardware, reconciled addresses, configured services,
dataplane readiness and XDP attachment. Only a successful assessment plus the
no-failed-units gate allows blessing; service activation alone is not success.

When a candidate fails assessment and an intact, blessed previous slot exists,
bounded retries let systemd-boot exhaust it and select the good slot. This is
not a guarantee against every firmware, storage or kernel hang. A persisted
configuration is shared by both slots: falling back does not automatically
repair a bad configuration or remove an unavailable NIC.

On a Community factory installation with no good alternative, a configured **missing
NIC** consumes the counted trials, remains unblessed, and stops automatic
reboots for console recovery. It is not treated as ordinary carrier loss or a
temporarily absent DHCP server. Inspect with:

```shell
sudo sentinel config check --live /var/lib/sentinel/appliance.toml
```

Repair the saved interface configuration from the recovery console, then
explicitly reboot and verify normal health/blessing.

For a deliberate recovery boot, select the verified good entry once in the
boot menu. Do not write a hard per-slot `default`: it can override exhausted
counters. Follow the updater's `preferred`/wildcard policy and review any
firmware override before staging again.

## Reboot to activate

Unlike `commit` (which is live and never reboots), an OS image update takes effect
on the **next reboot** into the new slot. Schedule the reboot when convenient; the
running slot keeps serving until then.

## Verifying

```shell
nix build .#checks.x86_64-linux.update -L
```

That test drives a real donor-image A→B boot and normal product blessing; it
does not replace the negative/fallback checks:

```shell
nix build .#checks.x86_64-linux.bootfallback -L
nix build .#checks.x86_64-linux.missing-nic-boot -L
```

The [broken-candidate fixture](https://github.com/Velstra/sentinel/blob/main/nix/boot-fallback-test.nix)
exercises three failed dataplane boots and fallback to a previously blessed
image. The [missing-NIC fixture](https://github.com/Velstra/sentinel/blob/main/nix/missing-nic-boot-test.nix)
exercises exhausted factory trials and product CLI repair. Driver backdoor
commands are not proof of an authenticated physical console login. These are
source-level VM gates: their existence, or a pass on another candidate, is not
certification of the final signed release and its exact hashes.

## Bounded metadata and atomic channel promotion

The channel reader prefers `release.json`: one JSON object with `schema = 1`,
`manifest` (base64 of the exact signed bytes) and `signature` (base64 of the
64-byte Ed25519 signature). The envelope is at most 128 KiB and its decoded
manifest at most 64 KiB. The pinned key authenticates the exact manifest bytes
before any release fields are trusted; the envelope is not a new trust root.

Only an absent endpoint (HTTP 404, or a missing local file for a file channel)
allows compatibility fallback to `manifest.json` and `manifest.json.sig`.
Malformed, oversized, unauthorized, timed-out or incorrectly signed envelopes
never fall back. Publishers must keep the old root manifest/signature pair
frozen while upgrading legacy readers, upload immutable versioned resources
first, and promote only the single envelope object last. Both public and native
Enterprise readers must be upgraded before production channel migration.

Connections are limited to ten seconds. Metadata has a 60-second overall and
15-second no-progress budget. Image downloads have a separate six-hour overall,
60-second no-progress and 64-GiB transfer ceiling (native Enterprise resources
retain their stricter individual limits). Limits are enforced during transfer,
including chunked responses, with appliance-pinned curl 8.4 or newer. Incomplete
downloads are removed and failures leave the active slot unchanged. On Linux,
the curl child is killed automatically if its update owner exits.

Channel RAW images are staged sparsely in an anonymous 0600 file on the mounted
ext4 state filesystem (`/var/lib/sentinel`), not in RAM-backed `/tmp` and not
in an operator-selected `TMPDIR`. Every zero byte still contributes to the
signed image digest and exact logical length; only nonzero blocks allocate
payload space. The open descriptor survives through whole-image verification
and partition copying, and is automatically reclaimed when the updater exits.
There is no persistent image cache to clear after a crash.

The updater checks a reserve of the greater of 512 MiB or 5% of the state filesystem,
with additional metadata headroom, and refuses an extent that exceeds its
staging budget. Concurrent unrelated filesystem writers can still consume
space; such allocation or sync failures safely refuse the update. A genuine
signed dense image can require more staging space than a sparse release.
Missing/unmounted/volatile/read-only state and insufficient capacity are
explicit errors; the updater never deletes configuration, archives, logs or a
fallback slot to make room. The recommended 32 GiB appliance disk provides room
for state and releases; a smaller disk that can boot is not a guarantee that
every future release will fit. The bounded ESP copy is verified before any
inactive-slot payload is overwritten.

Only one image update can run at a time, including signed local and deliberately
unsigned local writes. A second writer receives `another update is in progress`.
This update lock does not block ordinary configuration commits or metadata
checks while a download is in progress.

The persistent subscription identity is published only after its private contents
are complete and synced. Concurrent first use converges on one identity;
corrupt or insecure existing files are refused rather than silently replaced
with a new subscription seat. No deployed node is changed by a source update:
fresh image and OTA/rollback qualification are required before rollout.
