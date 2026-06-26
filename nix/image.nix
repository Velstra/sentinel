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

  # --- Secure Boot ---------------------------------------------------------
  # Self-signed PK/KEK/db keys. NOTE: generated at build time (cached, so stable
  # across rebuilds) — a DEMO/default. A real deployment overrides these with the
  # operator's own keys so updates stay signed by a key the firmware trusts.
  sbKeys = pkgs.runCommand "sentinel-sb-keys" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir -p $out
    for k in PK KEK db; do
      openssl req -new -x509 -newkey rsa:2048 -nodes -days 7300 -sha256 \
        -subj "/CN=Velstra Sentinel Secure Boot $k/" \
        -keyout $out/$k.key -out $out/$k.crt
    done
  '';
  # systemd-boot, signed with the db key (the firmware verifies it).
  signedSdBoot =
    pkgs.runCommand "sentinel-systemd-boot-signed.efi" { nativeBuildInputs = [ pkgs.sbsigntool ]; }
      ''sbsign --key ${sbKeys}/db.key --cert ${sbKeys}/db.crt --output $out ${sdBoot}'';
  # PK/KEK/db enrollment payloads for the operator (baked under /loader/keys).
  sbGuid = "a5a5a5a5-1234-5678-9abc-def012345678";
  sbAuth = pkgs.runCommand "sentinel-sb-auth" { nativeBuildInputs = [ pkgs.efitools ]; } ''
    mkdir -p $out
    cert-to-efi-sig-list -g ${sbGuid} ${sbKeys}/PK.crt  PK.esl
    cert-to-efi-sig-list -g ${sbGuid} ${sbKeys}/KEK.crt KEK.esl
    cert-to-efi-sig-list -g ${sbGuid} ${sbKeys}/db.crt  db.esl
    sign-efi-sig-list -g ${sbGuid} -k ${sbKeys}/PK.key  -c ${sbKeys}/PK.crt  PK  PK.esl  $out/PK.auth
    sign-efi-sig-list -g ${sbGuid} -k ${sbKeys}/PK.key  -c ${sbKeys}/PK.crt  KEK KEK.esl $out/KEK.auth
    sign-efi-sig-list -g ${sbGuid} -k ${sbKeys}/KEK.key -c ${sbKeys}/KEK.crt db  db.esl  $out/db.auth
  '';
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
  # Secure Boot: the systemd-boot binary is signed in the ESP `contents` below;
  # the roothash UKI is signed post-build (the verityStore rebuilds the UKI with
  # an internal ukify call we can't hand a signtool to, and ukify+systemd-sbsign
  # can't verify the inner kernel — so we sbsign the finished UKI in the ESP via
  # mtools in `system.build.finalImageSigned`).

  # Expose the Secure Boot keys so the test can build a firmware vars file with
  # them enrolled (and an operator can find them).
  system.build.sentinelSbKeys = sbKeys;

  # The shipped, Secure-Boot-ready image: the verity image with its UKI signed
  # by the db key in place. Signing doesn't touch the embedded roothash/cmdline,
  # and boot-counting only renames the file, so the signature stays valid.
  system.build.finalImageSigned =
    pkgs.runCommand "velstra-sentinel-signed"
      {
        nativeBuildInputs = [
          pkgs.mtools
          pkgs.sbsigntool
          pkgs.util-linux
        ];
      }
      ''
        mkdir -p "$(dirname "$out/${config.image.filePath}")"
        img="$out/${config.image.filePath}"
        cp ${config.system.build.finalImage}/${config.image.filePath} "$img"
        chmod +w "$img"
        # ESP is the first partition; mtools addresses it at its byte offset.
        start=$(sfdisk -d "$img" | grep 'name="esp"' | grep -oE 'start=[[:space:]]*[0-9]+' | grep -oE '[0-9]+')
        off=$(( start * 512 ))
        mcopy -i "$img@@$off" "::/EFI/Linux/sentinel-a+3.efi" uki.efi
        sbsign --key ${sbKeys}/db.key --cert ${sbKeys}/db.crt --output uki.signed.efi uki.efi
        sbverify --cert ${sbKeys}/db.crt uki.signed.efi
        mcopy -o -i "$img@@$off" uki.signed.efi "::/EFI/Linux/sentinel-a+3.efi"
      '';

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
        # Bake the **signed** systemd-boot + its config into the ESP (the
        # verityStore module injects the signed slot-A UKI on top via
        # finalPartitions). The PK/KEK/db enrollment payloads go under
        # /loader/keys/sentinel so an operator can enroll them from the firmware.
        contents = {
          "/EFI/BOOT/BOOT${lib.toUpper efiArch}.EFI".source = signedSdBoot;
          "/EFI/systemd/systemd-boot${efiArch}.efi".source = signedSdBoot;
          "/loader/loader.conf".source = loaderConf;
          "/loader/keys/sentinel/PK.auth".source = "${sbAuth}/PK.auth";
          "/loader/keys/sentinel/KEK.auth".source = "${sbAuth}/KEK.auth";
          "/loader/keys/sentinel/db.auth".source = "${sbAuth}/db.auth";
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
