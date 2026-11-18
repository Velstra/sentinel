# Review and stage an appliance update

<a id="updating-ab--rollback"></a>

Use an installed A/B appliance. Record the current slot and keep console access. Follow the route for your update source: a signed channel offer or a locally obtained image.

<a id="signed-updates-update-check--update-install"></a><a id="bounded-metadata-and-atomic-channel-promotion"></a>

## Signed channel: local CLI or Web UI

```sh
sudo sentinel system status
sudo sentinel system update check --wait
sudo sentinel system status
```

Review the offered version, image digest and signing identity. To stage the offer you reviewed, substitute its actual ID and the job ID returned by the first command:

```sh
sudo sentinel system update stage --offer <exact-offer-id>
sudo sentinel system update job <job-id> --wait
```

In **System → System updates**, run **Check signed channel**, inspect the offer, then choose **Download & stage update**. A reconnect or expired wait does not cancel a submitted job. Inspect `system status` before retrying. A change to trust, configuration or boot identity requires a fresh offer.

<a id="local-images-are-signature-checked-by-default"></a><a id="usb-sticks-and-other-block-devices"></a><a id="downgrades"></a>

## Community local-image updates

Obtain the raw image and its matching signed proof. Validate the expected release identity and configure the trusted public key before staging. Preserve the other bootable slot.

```sh
sentinel show version
sentinel update /path/to/velstra-sentinel.raw --commit
```

The example expects a matching `.sha256` and `.sig` beside the image as documented by the release. A disk or USB source requires a separately supplied release proof. Review the identified target and version before authorizing a write.

<a id="what-an-expired-subscription-does--and-does-not--do"></a><a id="show-subscription"></a>

## Named channels and subscriptions

A configured channel specifies a base URL and trusted public key. Licensed channels may additionally require a subscription credential. Use `sentinel show subscription` to inspect the selected channel. Do not share a full configuration dump, which can include secrets. An expired entitlement prevents new downloads from the licensed channel; the installed appliance continues forwarding.

## Reboot to activate

Staging prepares the inactive slot and its next boot entry. It does not reboot the appliance. Check boot selection, management reachability and peer readiness first; update one HA member at a time. After reboot, run `sentinel show version` and `bootctl status` and test traffic on your normal management and data paths.

<a id="the-rollback-guarantee"></a><a id="verifying"></a>

## Verify fallback separately

```sh
nix build .#checks.x86_64-linux.bootfallback -L
```

On a KVM build host, this runs the failed-boot fixture. [Boot slots and fallback](../architecture/ab-updates.md) explains the difference between a boot failure and an application regression.
