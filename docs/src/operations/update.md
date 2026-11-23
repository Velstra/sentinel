# Review and stage an appliance update

<a id="updating-ab--rollback"></a>

```sh
sudo sentinel system status
sudo sentinel system update check --wait
sudo sentinel system status
```

Use an installed A/B appliance. Record the current slot and keep console access. Then follow the route for your update source: a signed channel offer or a locally obtained image.

```mermaid
flowchart LR
  check[Check signed channel] --> review[Review offer] --> stage[Stage inactive slot]
  local[Local image + signed proof] --> stage
  stage --> reboot[Reboot] --> gate{Boot healthy?}
  gate -->|yes| blessed[Slot blessed]
  gate -->|no, tries used up| prev[Previous blessed slot]
```

<a id="signed-updates-update-check--update-install"></a><a id="bounded-metadata-and-atomic-channel-promotion"></a>

Read the [trust and recovery reference](../reference/update-trust.md) before first use or migration. It documents signed metadata expiry, scope and sequence checks, bootloader requirements, offline proof formats and bounded downloads.

Online checks persist rollback protection in `/var/lib/sentinel/update-trust`. Missing/corrupt state, clock rollback or unauthorized key changes require investigated recovery; do not delete the ledger. Signing-key rotation is not implemented by that ledger. A signed offline image is not proof of online freshness.

## Signed channel: local CLI or Web UI

Run the three commands above, then review the offered version, image digest and signing identity. To stage the offer you reviewed, substitute its actual ID, then the job ID that `stage` returns:

```sh
sudo sentinel system update stage --offer <exact-offer-id>
sudo sentinel system update job <job-id> --wait
```

In **System → System updates**, run **Check signed channel**, inspect the offer, then choose **Download & stage update**. A reconnect or expired wait does not cancel a submitted job; inspect `system status` before retrying. A change to trust, configuration or boot identity requires a fresh offer.

<a id="local-images-are-signature-checked-by-default"></a><a id="usb-sticks-and-other-block-devices"></a><a id="downgrades"></a>

Stage writes only the inactive slot and does not certify a successful boot. Native Enterprise's unreviewed `update install` path is refused; use the exact reviewed offer. Off-box/no-apply consoles cannot authorize OTA jobs.

## Community local-image updates

```sh
sentinel show version
sudo sentinel update /path/to/velstra-sentinel.raw --commit
```

Obtain the raw image and its matching signed proof, validate the expected release identity, and configure the trusted public key before staging. Preserve the other bootable slot. The example expects a matching `.sha256` and `.sig` beside the image as documented by the release. A disk or USB source requires a separately supplied release proof. Review the identified target and version before authorizing a write.

<a id="what-an-expired-subscription-does--and-does-not--do"></a><a id="show-subscription"></a>

The Community writer is refused on native Enterprise images, including with `--allow-unsigned`. Signed and unsigned local writes keep bootloader and active-GUID safeguards. A digest proof signs a small file containing the image's 64 hex digest, not a filename; an invalid selected proof never falls back to another format. Unplug a USB donor before reboot because it shares the staged slot's GUIDs.

## Named channels and subscriptions

A configured channel specifies a base URL and trusted public key; licensed channels may also require a subscription credential. Inspect the selected channel with `sentinel show subscription`. Do not share a full configuration dump, which can include secrets. An expired entitlement prevents new downloads from the licensed channel; the installed appliance keeps forwarding.

## Reboot to activate

```sh
sentinel show version
bootctl status
```

Staging prepares the inactive slot and its next boot entry; it does not reboot. Check boot selection, management reachability and peer readiness first, and update one HA member at a time. After the reboot, run the commands above and test traffic on your normal management and data paths.

<a id="the-rollback-guarantee"></a><a id="verifying"></a>

Fallback needs an intact, previously blessed slot. It cannot repair a bad persisted configuration shared by both slots. A factory installation with a configured missing NIC exhausts its counted trials and remains unblessed for console recovery; it is not a normal carrier or DHCP delay. Inspect `sudo sentinel config check --live /var/lib/sentinel/appliance.toml` and follow the [recovery constraints](../reference/update-trust.md#the-rollback-guarantee).

## Verify fallback separately

```sh
nix build .#checks.x86_64-linux.bootfallback -L
```

On a KVM build host, this runs the failed-boot fixture. [Boot slots and fallback](../architecture/ab-updates.md) explains the difference between a boot failure and an application regression.
