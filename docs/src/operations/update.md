# Updating (A/B + rollback)

OS updates are **A/B**: a new image is written to the inactive store slot and the
bootloader is switched to it. If the new slot fails to boot cleanly, systemd-boot
rolls back automatically. The architecture is in
[A/B update slots](../architecture/ab-updates.md); this is the operator view.

## Applying an update

```shell
# from a new raw image (built with `nix build .#sentinel-image`) plus its
# detached signature velstra-sentinel.raw.sig
sentinel update /path/to/velstra-sentinel.raw --commit

# or from a block device / mounted source (no signature — see --allow-unsigned)
sentinel update /dev/sdX --commit --allow-unsigned
```

What happens:

1. the image's signature is **verified** (see below) unless `--allow-unsigned`;
2. the **active** slot is detected (via `/dev/mapper/usr`);
3. the new image's store + verity are written to the **inactive** slot;
4. that slot is re-typed to the verity GPT GUIDs;
5. the new UKI is installed as `sentinel-<inactive>+3.efi` with **3 boot tries**;
6. `loader.conf` `default` is pointed at the new slot.

Without `--commit`, the plan is printed but nothing is written.

### Local images are signature-checked by default

A local `sentinel update <image>` now **verifies the image before writing it** —
the same authenticity gate the channel path applies, so a local install is no
longer a way around it. It looks for a detached Ed25519 signature `<image>.sig`
beside the image and verifies it against a pinned release key, tried in order:

1. `--pubkey <pem|file:path>` on the command line;
2. the saved `[update]` channel's `public-key`;
3. a release key baked into the image at `/etc/sentinel/release.pem`.

If no key is available, or the signature is missing or does not verify, the write
is **refused** and nothing is touched. Sign an image with the release key:

```shell
openssl pkeyutl -sign -inkey release-priv.pem -rawin \
  -in velstra-sentinel.raw -out velstra-sentinel.raw.sig
```

> **`--allow-unsigned` is the trusted-operator escape hatch.** A re-seal from the
> booted medium or an air-gapped block device has no `.sig` to check; pass
> `--allow-unsigned` to write it exactly as given. It is loud and logged — never
> silent — so it can't be mistaken for a verified update.

## Signed updates (`update check` / `update install`)

The **channel** updater refuses any image whose release manifest isn't signed by
a key you have pinned. (The local `sentinel update <path>|<device>` form above is
the trusted-operator path and does no such check.) Pin the channel in config
(roadmap C13):

```shell
configure
set update url https://updates.velstra.example/sentinel
set update public-key file:/etc/sentinel/release.pem
commit
save
```

- `url` is the channel base — an `https://` (or `file://` for an offline
  mirror) directory holding the signed `manifest.json` and the images it names.
- `public-key` is the pinned Ed25519 release-signing key, PEM. `file:<path>`
  reads it from disk (so the key can live in the immutable image rather than the
  config); an inline PEM also works.

Both fields are required — `commit` rejects a half-specified channel. With a
channel pinned:

```shell
sentinel update check            # fetch + verify the manifest, report the version
sentinel update install --commit # re-verify, then write the inactive A/B slot
```

`check` fetches the manifest, verifies its detached signature against the pinned
`public-key`, and only then trusts the version + image digest it names.
`install` re-verifies the signature **and** the image's SHA-256 before writing
anything — the authenticity gate in front of the verified-boot slot switch
below. An unsigned or wrong-key manifest is refused; no slot is touched.

## Named channels and subscriptions

A box can know several channels at once — a community channel anyone can use,
and a subscription channel carrying **tested, delayed-stability images**. That
is the whole commercial model: the code is the same and open, what a
subscription buys is verification work, never withheld features.

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

- **Each channel has its own `public-key`, on purpose.** A channel is only as
  trustworthy as the key that vouches for it: the enterprise channel's releases
  are signed by a different key than the community channel's, so trusting one
  never means trusting the other. `url` and `public-key` are required per
  channel; `https://` only (or `file://` for an air-gapped mirror).
- **`set update channel <name>`** with nothing after the name selects which
  channel `update check`/`install` use. A selection that names no defined
  channel is refused at `commit`, not discovered during an incident.
- The single-channel form above (`set update url …`) keeps working unchanged —
  it is the unnamed *default* channel, and a box configured before named
  channels existed loses nothing on upgrade.
- **`subscription-key` is a secret.** It is sent to the channel server as a
  bearer token, redacted by the read API, and masked everywhere it is shown —
  `show subscription` prints only its last four characters. (One deliberate
  exception: `show configuration` prints it in full, like every other secret in
  the config document, because that document is what gets replayed onto a
  second appliance and a masked value replayed is a corrupted config.)

### What an expired subscription does — and does not — do

**An expired or rejected subscription never disables the appliance.** The box
keeps routing, keeps filtering, keeps its configuration, and keeps serving its
console. The one and only consequence is that *new images from that channel*
are unavailable: the channel server answers 401/403, and `update check` reports
it plainly —

```
channel "enterprise": this subscription is not valid for this channel (HTTP 401).
The appliance keeps running unchanged — only new images from this channel are
unavailable. Renew the subscription with your vendor, or correct the key …
```

There is no phone-home timer, no nag screen, no degraded data plane. A firewall
whose vendor relationship lapses is still a firewall.

### `show subscription`

The state, as facts this box holds:

```
channels:
  community
  enterprise (active)
active channel: enterprise
url:            https://updates.velstra.example/enterprise
subscription:   key configured (ends …a1b2)
last check:     2026-08-24 10:12:03 UTC — release 0.4.0 available
expiry:         not reported by the channel server — nothing is assumed
```

`last check` is whatever the most recent `update check`/`install` actually
said — never a fresh fetch (a `show` must not be the thing that talks to the
internet). Expiry is shown **only if the server reports one**; today the
channel protocol carries no expiry, so the honest answer is "not reported",
not a locally computed countdown.

## The rollback guarantee

The new slot boots with `+3` tries. A clean boot (no failed units) is **blessed**
permanent. If it fails three times, systemd-boot marks it bad and boots the
**previous** slot — which is untouched, because the update only ever wrote the
inactive one. So a bad update self-heals without intervention.

To roll back deliberately, point `default` back at the other slot from the
systemd-boot menu (or re-run an update with the known-good image).

## Reboot to activate

Unlike `commit` (which is live and never reboots), an OS image update takes effect
on the **next reboot** into the new slot. Schedule the reboot when convenient; the
running slot keeps serving until then.

## Verifying

```shell
nix build .#checks.x86_64-linux.update -L
```

The test verifies the slot is written, re-typed, and the bootloader switched. The
cross-reboot switch itself isn't auto-tested (OVMF `machine.reboot()` hangs in the
harness); the bless/rollback mechanism is proven in the `verified-boot` test.
