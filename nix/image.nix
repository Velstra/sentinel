# Verified-boot appliance image with A/B update slots.
#
# The Nix store ships on a **dm-verity-protected** partition whose roothash is
# baked into a Unified Kernel Image (UKI) — the kernel mounts `/nix/store` only
# if it matches. Root is a volatile tmpfs; the one writable partition holds the
# editable config.
#
# **A/B:** there are TWO store-slot partition pairs. The image is built into
# slot A (populated, typed verity); slot B is reserved space (generic type)
# that `sentinel update` fills with a new image and re-types to verity. systemd-
# boot manages the two slots' UKIs in /EFI/Linux with automatic boot assessment
# (boot counting): a freshly-updated slot boots with `+3` tries; a clean boot is
# blessed permanent; if it fails 3×, systemd-boot rolls back to the other slot.
{
  config,
  lib,
  pkgs,
  modulesPath,
  ...
}:
let
  inherit (config.image.repart.verityStore) partitionIds;
  efiArch = config.nixpkgs.hostPlatform.efiArch;
  sdBoot = "${pkgs.systemd}/lib/systemd/boot/efi/systemd-boot${efiArch}.efi";
  # systemd-boot config: short timeout, default to slot A's entry (a glob so it
  # keeps matching after bless strips the `+N` counter). `sentinel update`
  # rewrites `default` to the slot it just wrote.
  loaderConf = pkgs.writeText "loader.conf" ''
    timeout 3
    default sentinel-a*
    editor no
    auto-entries no
    auto-firmware no
  '';
  # GPT type GUIDs for the verity store pair (x86-64), used to re-type slot B.
  usrType = "8484680c-9521-48c6-9c11-b0720656f69e";
  usrVerityType = "77ff5f63-e7b6-4633-acf4-1565b864c0e6";
in
{
  imports = [ "${modulesPath}/image/repart.nix" ];

  # systemd-boot is baked into the ESP offline (it can't be `bootctl install`ed
  # in a repart build), so keep the imperative NixOS installers off. Don't touch
  # EFI NVRAM — the appliance is immutable.
  boot.loader.grub.enable = lib.mkForce false;
  boot.loader.systemd-boot.enable = lib.mkForce false;
  boot.loader.efi.canTouchEfiVariables = lib.mkForce false;
  boot.initrd.systemd.enable = true;

  # The slot-A UKI is `sentinel-a+3.efi` (3 boot tries before it's deemed bad).
  boot.uki.name = "sentinel-a";
  boot.uki.version = lib.mkForce null; # no `_<version>` infix; keep the name clean
  boot.uki.tries = 3;

  # Automatic boot assessment: these upstream systemd units aren't NixOS
  # defaults. With them present, the bless generator marks a clean boot good
  # (counter stripped); `check-no-failures` gates that on no failed units.
  systemd.additionalUpstreamSystemUnits = [
    "boot-complete.target"
    "systemd-bless-boot.service"
    "systemd-boot-check-no-failures.service"
  ];

  system.image.id = "velstra-sentinel";
  system.image.version = "1";

  fileSystems = {
    # Volatile root.
    "/" = lib.mkForce {
      fsType = "tmpfs";
      options = [ "mode=0755" ];
    };
    # The real /nix/store lives on the dm-verity-protected /usr partition;
    # bind it into place. (The pinned verityStore module leaves this to the
    # consumer — without it the initrd's find-nixos-closure can't see the store
    # on the tmpfs root and drops to emergency mode.)
    "/nix/store" = {
      device = "/usr/nix/store";
      fsType = "none";
      options = [ "bind" ];
    };
    # The one writable, persistent partition: the editable appliance config.
    # Addressed by ext4 LABEL=data so the same mount works for the image, a
    # single-disk install, and a `sentinel install` mdadm RAID array.
    "/var/lib/sentinel" = {
      device = "/dev/disk/by-label/data";
      fsType = "ext4";
      options = [
        "rw"
        "nofail"
      ];
    };
  };

  # mdadm RAID support, so a RAID install assembles its data array at boot.
  boot.swraid.enable = true;

  # `sentinel update` mounts the ESP (vfat) to install the new slot's UKI.
  boot.supportedFilesystems.vfat = true;

  # sentinel-boot seeds + reads the editable config — order it after the data
  # partition is mounted so the seed lands on persistent storage, not tmpfs.
  systemd.services.sentinel-boot.unitConfig.RequiresMountsFor = [ "/var/lib/sentinel" ];

  # Read-only /usr: skip the /usr/bin/env activation step (nixpkgs' verity
  # appliance pattern).
  system.activationScripts.usrbinenv = lib.mkForce "";

  image.repart = {
    name = "velstra-sentinel";
    # OVMF/UEFI needs a 512-byte sector size, not systemd-repart's default 4096.
    sectorSize = 512;
    # Label the ext4 data partition `data` (mounted by fs-label everywhere).
    mkfsOptions.ext4 = [
      "-L"
      "data"
    ];
    verityStore.enable = true;
    # ukiPath defaults to /EFI/Linux/${ukiFile} = /EFI/Linux/sentinel-a+3.efi —
    # the BLS Type 2 location systemd-boot auto-discovers.
    partitions = {
      ${partitionIds.esp} = {
        repartConfig = {
          Type = "esp";
          Format = "vfat";
          SizeMinBytes = "128M";
        };
        # Bake systemd-boot + its config into the ESP (the verityStore module
        # injects the slot-A UKI on top of this via finalPartitions).
        contents = {
          "/EFI/BOOT/BOOT${lib.toUpper efiArch}.EFI".source = sdBoot;
          "/EFI/systemd/systemd-boot${efiArch}.efi".source = sdBoot;
          "/loader/loader.conf".source = loaderConf;
        };
      };
      # Slot A (verity), sized to fit the closure + its hash tree. The module
      # marks these `Minimize`; auto image-sizing then leaves them at 4K, so set
      # explicit floors.
      ${partitionIds.store}.repartConfig.SizeMinBytes = "1300M";
      ${partitionIds.store-verity}.repartConfig.SizeMinBytes = "96M";
      # Slot B: reserved space, typed generic so the build's roothash extraction
      # only matches slot A. `sentinel update` fills these and re-types them to
      # the verity GUIDs above.
      "30-store-verity-b".repartConfig = {
        Type = "linux-generic";
        Label = "store-verity-b";
        SizeMinBytes = "96M";
        SizeMaxBytes = "96M";
      };
      "40-store-b".repartConfig = {
        Type = "linux-generic";
        Label = "store-b";
        SizeMinBytes = "1300M";
        SizeMaxBytes = "1300M";
      };
      # Persistent state partition (after both slots).
      "50-data".repartConfig = {
        Type = "linux-generic";
        Format = "ext4";
        Label = "data";
        SizeMinBytes = "128M";
      };
    };
  };

  # Expose the verity GPT type GUIDs to the running system (the updater re-types
  # slot B to these when it fills it).
  environment.etc."sentinel/slot-types.env".text = ''
    SENTINEL_USR_TYPE=${usrType}
    SENTINEL_USR_VERITY_TYPE=${usrVerityType}
  '';
}
