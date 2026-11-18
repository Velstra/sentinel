# Install Sentinel to disk

<a id="installing-to-disk"></a>

Boot the installer ISO in UEFI mode. Installation replaces the selected disks. Use the local console to inspect device names, capacity and model before confirming.

## Interactive (the ISO default)

Select the intended disks, choose the single-disk or RAID layout, review the on-screen plan and confirm. Create a local administrator and configure the WAN and LAN as prompted. Detach the ISO before rebooting. For a repeatable evaluation, use the [VM quickstart](quickstart.md).

<a id="flag-driven-scripted--non-interactive"></a><a id="what-it-writes"></a>

## Preview a scripted install

```sh
lsblk -d -o NAME,SIZE,MODEL
sentinel install /dev/vdb
```

This example previews a single disk. Replace `/dev/vdb` with the disk you have identified. Only add `--commit` after reviewing the plan. For a mirror, select two independent disks and use `--raid mirror`.

<a id="unlocking-at-boot"></a>

## Disk encryption (LUKS2)

Add `--encrypt` when installing to encrypt the writable data filesystem. A passphrase is required on subsequent boots; plan how you will unlock the appliance after an unattended restart. On a RAID layout the encrypted filesystem sits above the data array. Encryption and system-store integrity serve different purposes.

<a id="verifying-it"></a><a id="gotchas-for-hacking-on-srcinstallrs"></a>

## Verify the installed image

```sh
sentinel show version
lsblk -f
findmnt /var/lib/sentinel
```

Check that the disk booted with its intended slot and that the writable data filesystem is mounted. Retain an independent console while establishing first management access.
