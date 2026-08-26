# Verified-boot appliance image with A/B update slots — the shared factory.
#
# The Nix store ships on a **dm-verity-protected** partition whose roothash is
# baked into a Unified Kernel Image (UKI) — the kernel mounts `/nix/store` only
# if it matches. Root is a volatile tmpfs; the one writable partition holds the
# editable state.
#
# **A/B:** there are TWO store-slot partition pairs. The image is built into
# slot A (populated, typed verity); slot B is reserved space (generic type)
# that the product's updater fills with a new image and re-types to verity.
# systemd-boot manages the two slots' UKIs in /EFI/Linux with automatic boot
# assessment (boot counting): a freshly-updated slot boots with `+3` tries; a
# clean boot is blessed permanent; if it fails 3×, systemd-boot rolls back to
# the other slot.
#
# This module is the PRODUCT-NEUTRAL machinery, exposed by the Sentinel flake
# as `nixosModules.applianceImage` so sibling appliances (the Velstra Cloud
# compute node) build with the same factory. Everything Sentinel-specific is an
# option under `velstra.appliance.*` whose DEFAULT is Sentinel's historical
# value — Sentinel imports this via nix/image.nix untouched and builds the same
# image it always did, while another product overrides the identity options.
#
# What is NOT parametrised, on purpose (the honest boundary):
#   - the partition ORDER and numbers (ESP=1, verity-A=2, store-A=3,
#     verity-B=4, store-B=5, data=6) and the labels `store-verity-b`,
#     `store-b`, `data` — every installer/updater built against this factory
#     hardcodes those, and two products whose disks disagree about partition 6
#     would need two installers anyway;
#   - the boot-counting policy (3 tries) and the systemd-boot loader flow;
#   - the demo Secure Boot key material shape (self-signed PK/KEK/db —
#     a real deployment overrides the keys, not the shape).
{
  config,
  lib,
  pkgs,
  modulesPath,
  ...
}:
let
  cfg = config.velstra.appliance;
  inherit (config.image.repart.verityStore) partitionIds;
  efiArch = config.nixpkgs.hostPlatform.efiArch;
  sdBoot = "${pkgs.systemd}/lib/systemd/boot/efi/systemd-boot${efiArch}.efi";
  # systemd-boot config: short timeout, default to slot A's entry (a glob so it
  # keeps matching after bless strips the `+N` counter). The updater rewrites
  # `default` to the slot it just wrote.
  loaderConf = pkgs.writeText "loader.conf" ''
    timeout 3
    default ${cfg.slotPrefix}-a*
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
  sbKeys = pkgs.runCommand "${cfg.slotPrefix}-sb-keys" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir -p $out
    for k in PK KEK db; do
      openssl req -new -x509 -newkey rsa:2048 -nodes -days 7300 -sha256 \
        -subj "/CN=${cfg.secureBootCommonName} $k/" \
        -keyout $out/$k.key -out $out/$k.crt
    done
  '';
  # systemd-boot, signed with the db key (the firmware verifies it).
  signedSdBoot =
    pkgs.runCommand "${cfg.slotPrefix}-systemd-boot-signed.efi"
      { nativeBuildInputs = [ pkgs.sbsigntool ]; }
      ''sbsign --key ${sbKeys}/db.key --cert ${sbKeys}/db.crt --output $out ${sdBoot}'';
  # PK/KEK/db enrollment payloads for the operator (baked under /loader/keys).
  sbGuid = "a5a5a5a5-1234-5678-9abc-def012345678";
  sbAuth = pkgs.runCommand "${cfg.slotPrefix}-sb-auth" { nativeBuildInputs = [ pkgs.efitools ]; } ''
    mkdir -p $out
    cert-to-efi-sig-list -g ${sbGuid} ${sbKeys}/PK.crt  PK.esl
    cert-to-efi-sig-list -g ${sbGuid} ${sbKeys}/KEK.crt KEK.esl
    cert-to-efi-sig-list -g ${sbGuid} ${sbKeys}/db.crt  db.esl
    sign-efi-sig-list -g ${sbGuid} -k ${sbKeys}/PK.key  -c ${sbKeys}/PK.crt  PK  PK.esl  $out/PK.auth
    sign-efi-sig-list -g ${sbGuid} -k ${sbKeys}/PK.key  -c ${sbKeys}/PK.crt  KEK KEK.esl $out/KEK.auth
    sign-efi-sig-list -g ${sbGuid} -k ${sbKeys}/KEK.key -c ${sbKeys}/KEK.crt db  db.esl  $out/db.auth
  '';
  # The slot-A UKI's filename in the ESP, e.g. `sentinel-a+3.efi`.
  ukiFile = "${config.boot.uki.name}+${toString config.boot.uki.tries}.efi";
in
{
  imports = [ "${modulesPath}/image/repart.nix" ];

  options.velstra.appliance = {
    productName = lib.mkOption {
      type = lib.types.str;
      default = "Velstra Sentinel";
      description = "Human name shown in the boot menu and os-release PRETTY_NAME/NAME.";
    };
    osId = lib.mkOption {
      type = lib.types.str;
      default = "velstra-sentinel";
      description = "Machine identity: os-release ID, system.image.id and the repart image name.";
    };
    slotPrefix = lib.mkOption {
      type = lib.types.str;
      default = "sentinel";
      description = ''
        Prefix for the A/B boot slot names: the UKIs are <prefix>-a / <prefix>-b
        and the loader defaults to <prefix>-a*. The product's installer and
        updater must agree on this string.
      '';
    };
    defaultHostname = lib.mkOption {
      type = lib.types.str;
      default = "sentinel";
      description = "os-release DEFAULT_HOSTNAME (what a box is called before it is configured).";
    };
    ansiColor = lib.mkOption {
      type = lib.types.str;
      default = "0;36";
      description = "os-release ANSI_COLOR.";
    };
    imageVersion = lib.mkOption {
      type = lib.types.str;
      default = "1";
      description = "system.image.version / os-release IMAGE_VERSION.";
    };
    stateDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/sentinel";
      description = "Mount point of the one writable, persistent partition (LABEL=data).";
    };
    unlockUnit = lib.mkOption {
      type = lib.types.str;
      default = "sentinel-unlock.service";
      description = ''
        The unit that opens the LUKS volume on an encrypted install (a no-op on
        a plaintext one). The stateDir mount Requires + is ordered After it.
        The consuming product must define this service.
      '';
    };
    stateDirServices = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "sentinel-boot" ];
      description = ''
        Services (unit names without .service) that seed or read the editable
        state — ordered after the stateDir mount so their writes land on
        persistent storage, not the tmpfs root.
      '';
    };
    slotTypesEnvFile = lib.mkOption {
      type = lib.types.str;
      default = "sentinel/slot-types.env";
      description = "Path under /etc for the slot GPT-type reference file.";
    };
    espSize = lib.mkOption {
      type = lib.types.str;
      default = "128M";
      description = "ESP SizeMinBytes.";
    };
    storeSize = lib.mkOption {
      type = lib.types.str;
      default = "2560M";
      description = ''
        Store slot size (both slots — slot B is reserved at exactly this size).
        Must fit the product's closure; on overflow `systemd-repart` names the
        partition and the shortfall (`nix log` on the failing derivation — the
        build's own tail truncates the line away).
      '';
    };
    veritySize = lib.mkOption {
      type = lib.types.str;
      default = "192M";
      description = ''
        Verity hash-tree slot size (both slots). A fixed fraction of the store
        it covers — raise it together with storeSize, or the "doesn't fit"
        merely moves one partition along.
      '';
    };
    dataSize = lib.mkOption {
      type = lib.types.str;
      default = "128M";
      description = "Data partition floor in the built image (the installer grows it to the disk).";
    };
    secureBootCommonName = lib.mkOption {
      type = lib.types.str;
      default = "Velstra Sentinel Secure Boot";
      description = "CN prefix of the generated demo Secure Boot keys.";
    };
  };

  config = {
    # systemd-boot is baked into the ESP offline (it can't be `bootctl install`ed
    # in a repart build), so keep the imperative NixOS installers off. Don't touch
    # EFI NVRAM — the appliance is immutable.
    boot.loader.grub.enable = lib.mkForce false;
    boot.loader.systemd-boot.enable = lib.mkForce false;
    boot.loader.efi.canTouchEfiVariables = lib.mkForce false;
    boot.initrd.systemd.enable = true;

    # The slot-A UKI is `<prefix>-a+3.efi` (3 boot tries before it's deemed bad).
    # The name in the installed system's boot menu. systemd-boot shows a UKI's
    # PRETTY_NAME, which NixOS builds from these — left alone it reads "NixOS
    # 25.05", which says nothing about the appliance that was installed.
    #
    # A notch weaker than mkForce: the VM test framework pins some of these with
    # mkForce, and two definitions of equal strength are a conflict rather than an
    # override.
    system.nixos.distroName = lib.mkOverride 60 cfg.productName;
    system.nixos.distroId = lib.mkOverride 60 cfg.osId;

    # NixOS composes PRETTY_NAME as "<name> <release> (<codeName>)" and both of
    # the latter are read-only, so setting the name alone still leaves the boot
    # menu reading "<name> 25.05 (Warbler)". This is the appliance's own
    # identity file; IMAGE_ID and IMAGE_VERSION are kept because the A/B update
    # machinery reads them.
    environment.etc."os-release".text = lib.mkForce ''
      NAME="${cfg.productName}"
      ID=${cfg.osId}
      ID_LIKE=nixos
      PRETTY_NAME="${cfg.productName}"
      ANSI_COLOR="${cfg.ansiColor}"
      IMAGE_ID=${config.system.image.id}
      IMAGE_VERSION=${toString config.system.image.version}
      VERSION_ID=${toString config.system.image.version}
      DEFAULT_HOSTNAME=${cfg.defaultHostname}
    '';

    boot.uki.name = "${cfg.slotPrefix}-a";
    boot.uki.version = lib.mkForce null; # no `_<version>` infix; keep the name clean
    boot.uki.tries = 3;
    # Secure Boot: the systemd-boot binary is signed in the ESP `contents` below;
    # the roothash UKI is signed post-build (the verityStore rebuilds the UKI with
    # an internal ukify call we can't hand a signtool to, and ukify+systemd-sbsign
    # can't verify the inner kernel — so we sbsign the finished UKI in the ESP via
    # mtools in `system.build.finalImageSigned`).

    # Expose the Secure Boot keys so a test can build a firmware vars file with
    # them enrolled (and an operator can find them).
    system.build.applianceSbKeys = sbKeys;

    # The shipped, Secure-Boot-ready image: the verity image with its UKI signed
    # by the db key in place. Signing doesn't touch the embedded roothash/cmdline,
    # and boot-counting only renames the file, so the signature stays valid.
    system.build.finalImageSigned =
      pkgs.runCommand "${cfg.osId}-signed"
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
          mcopy -i "$img@@$off" "::/EFI/Linux/${ukiFile}" uki.efi
          sbsign --key ${sbKeys}/db.key --cert ${sbKeys}/db.crt --output uki.signed.efi uki.efi
          sbverify --cert ${sbKeys}/db.crt uki.signed.efi
          mcopy -o -i "$img@@$off" uki.signed.efi "::/EFI/Linux/${ukiFile}"
        '';

    # Automatic boot assessment: these upstream systemd units aren't NixOS
    # defaults. With them present, the bless generator marks a clean boot good
    # (counter stripped); `check-no-failures` gates that on no failed units.
    systemd.additionalUpstreamSystemUnits = [
      "boot-complete.target"
      "systemd-bless-boot.service"
      "systemd-boot-check-no-failures.service"
    ];

    system.image.id = cfg.osId;
    system.image.version = cfg.imageVersion;

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
      # The one writable, persistent partition: the editable appliance state.
      # Addressed by ext4 LABEL=data so the same mount works for the image, a
      # single-disk install, and an installer-built mdadm RAID array.
      ${cfg.stateDir} = {
        device = "/dev/disk/by-label/data";
        fsType = "ext4";
        options = [
          "rw"
          "nofail"
          # On an ENCRYPTED install the LABEL=data ext4 lives inside a LUKS volume,
          # so it does not exist until the unlock unit has opened it.
          # `x-systemd.requires=` makes this mount Require + After that service. On a
          # plaintext install the service is a harmless no-op (exit 0) and the mount
          # proceeds as before, so the same option is correct for both.
          "x-systemd.requires=${cfg.unlockUnit}"
        ];
      };
    };

    # mdadm RAID support, so a RAID install assembles its data array at boot.
    boot.swraid.enable = true;

    # The updater mounts the ESP (vfat) to install the new slot's UKI.
    boot.supportedFilesystems.vfat = true;

    # The product's state-seeding services read + write the editable state —
    # order them after the data partition is mounted so the seed lands on
    # persistent storage, not tmpfs.
    systemd.services = lib.genAttrs cfg.stateDirServices (_: {
      unitConfig.RequiresMountsFor = [ cfg.stateDir ];
    });

    # Read-only /usr: skip the /usr/bin/env activation step (nixpkgs' verity
    # appliance pattern).
    system.activationScripts.usrbinenv = lib.mkForce "";

    image.repart = {
      name = cfg.osId;
      # OVMF/UEFI needs a 512-byte sector size, not systemd-repart's default 4096.
      sectorSize = 512;
      # Label the ext4 data partition `data` (mounted by fs-label everywhere).
      mkfsOptions.ext4 = [
        "-L"
        "data"
      ];
      verityStore.enable = true;
      # ukiPath defaults to /EFI/Linux/${ukiFile} — the BLS Type 2 location
      # systemd-boot auto-discovers.
      partitions = {
        ${partitionIds.esp} = {
          repartConfig = {
            Type = "esp";
            Format = "vfat";
            SizeMinBytes = cfg.espSize;
          };
          # Bake the **signed** systemd-boot + its config into the ESP (the
          # verityStore module injects the signed slot-A UKI on top via
          # finalPartitions). The PK/KEK/db enrollment payloads go under
          # /loader/keys/<prefix> so an operator can enroll them from the firmware.
          contents = {
            "/EFI/BOOT/BOOT${lib.toUpper efiArch}.EFI".source = signedSdBoot;
            "/EFI/systemd/systemd-boot${efiArch}.efi".source = signedSdBoot;
            "/loader/loader.conf".source = loaderConf;
            "/loader/keys/${cfg.slotPrefix}/PK.auth".source = "${sbAuth}/PK.auth";
            "/loader/keys/${cfg.slotPrefix}/KEK.auth".source = "${sbAuth}/KEK.auth";
            "/loader/keys/${cfg.slotPrefix}/db.auth".source = "${sbAuth}/db.auth";
          };
        };
        # Slot A (verity), sized to fit the closure + its hash tree. The module
        # marks these `Minimize`; auto image-sizing then leaves them at 4K, so set
        # explicit floors (see the storeSize/veritySize option descriptions for
        # what happens when the closure outgrows them).
        ${partitionIds.store}.repartConfig.SizeMinBytes = cfg.storeSize;
        ${partitionIds.store-verity}.repartConfig.SizeMinBytes = cfg.veritySize;
        # Slot B: reserved space, typed generic so the build's roothash extraction
        # only matches slot A. The updater fills these and re-types them to
        # the verity GUIDs above.
        "30-store-verity-b".repartConfig = {
          Type = "linux-generic";
          Label = "store-verity-b";
          SizeMinBytes = cfg.veritySize;
          SizeMaxBytes = cfg.veritySize;
        };
        "40-store-b".repartConfig = {
          Type = "linux-generic";
          Label = "store-b";
          SizeMinBytes = cfg.storeSize;
          SizeMaxBytes = cfg.storeSize;
        };
        # Persistent state partition (after both slots).
        "50-data".repartConfig = {
          Type = "linux-generic";
          Format = "ext4";
          Label = "data";
          SizeMinBytes = cfg.dataSize;
        };
      };
    };

    # Expose the verity GPT type GUIDs to the running system (a reference for
    # the updater that re-types slot B — the Sentinel updater carries them as
    # consts and does not read this file, but an operator debugging a half-
    # written slot B will want them on the box).
    environment.etc.${cfg.slotTypesEnvFile}.text = ''
      SENTINEL_USR_TYPE=${usrType}
      SENTINEL_USR_VERITY_TYPE=${usrVerityType}
    '';
  };
}
