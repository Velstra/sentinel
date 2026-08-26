# Live-boot installer ISO — the shared factory.
#
# A small, hybrid USB/CD-bootable NixOS live system that carries a sealed
# verified-boot appliance image (in the closure) and drops straight into the
# product's installer. The installer clones the bundled image onto the chosen
# target disk(s) — single disk or a RAID array — via its `--source` mode
# (there's no booted verity store to clone from in the live environment).
#
# This module is the PRODUCT-NEUTRAL half, exposed by the Sentinel flake as
# `nixosModules.applianceIso`. The product supplies its installer package, the
# raw image to bundle, and its branding via `velstra.iso.*`; every default is
# Sentinel's historical value, so Sentinel's nix/iso.nix wrapper only has to
# name its two artefacts.
{
  config,
  lib,
  pkgs,
  modulesPath,
  ...
}:
let
  cfg = config.velstra.iso;

  # `#22d3ee` → `#FF22D3EE`: the AARRGGBB form syslinux wants, fully opaque.
  argb = c: "#FF${lib.toUpper (lib.removePrefix "#" c)}";

  # The UEFI boot menu. GRUB reads a theme directory, so this is the smallest
  # one that works: a font it can load and a theme.txt. No pixmaps — the
  # selection is shown by colour, which needs no image assets and cannot break
  # on a console that has no graphics mode.
  grubTheme = pkgs.runCommand "${cfg.brandId}-grub-theme" { } ''
    mkdir -p $out
    cp ${pkgs.grub2}/share/grub/unicode.pf2 $out/
    cat > $out/theme.txt <<'THEME'
    title-text: "${cfg.productName}"
    title-color: "${cfg.accent}"
    desktop-color: "${cfg.ink}"
    terminal-left: "5%"
    terminal-top: "5%"
    terminal-width: "90%"
    terminal-height: "90%"

    + boot_menu {
      left = 15%
      top = 30%
      width = 70%
      height = 40%
      item_color = "${cfg.paper}"
      selected_item_color = "${cfg.accent}"
      item_height = 24
      item_spacing = 8
    }

    + label {
      top = 100%-40
      left = 0
      width = 100%
      align = "center"
      color = "${cfg.paper}"
      text = "${cfg.tagline}"
    }
    THEME
  '';
in
{
  imports = [ "${modulesPath}/installer/cd-dvd/iso-image.nix" ];

  options.velstra.iso = {
    productName = lib.mkOption {
      type = lib.types.str;
      default = "Velstra Sentinel";
      description = "Human name shown in both boot menus and the console banner.";
    };
    brandId = lib.mkOption {
      type = lib.types.str;
      default = "sentinel";
      description = "Short machine identity used in derivation names.";
    };
    installerPackage = lib.mkOption {
      type = lib.types.package;
      description = "The package whose installer CLI the live system drops into.";
    };
    installCommand = lib.mkOption {
      type = lib.types.str;
      default = "sentinel install";
      description = "The command the auto-logged-in console runs (the first-boot wizard).";
    };
    imageSource = lib.mkOption {
      type = lib.types.str;
      description = "Store path of the sealed raw appliance image to bundle and clone from.";
    };
    sourceEnvVar = lib.mkOption {
      type = lib.types.str;
      default = "SENTINEL_INSTALL_SOURCE";
      description = ''
        Environment variable the installer reads the bundled image's path from.
        Referencing the image here pulls it into the system closure (and so
        onto the ISO).
      '';
    };
    label = lib.mkOption {
      type = lib.types.str;
      default = cfg.installerPackage.version;
      defaultText = "the installer package's version";
      description = ''
        The medium's version label. Defaults to the installer package's version
        so the boot menu and the CLI on the medium cannot disagree.
      '';
    };
    tagline = lib.mkOption {
      type = lib.types.str;
      default = "Installs the verified-boot appliance onto internal storage";
      description = "One line under the boot menu and in the console banner.";
    };
    isoBaseName = lib.mkOption {
      type = lib.types.str;
      default = "velstra-sentinel-installer";
      description = "Basename of the produced .iso file.";
    };
    volumeId = lib.mkOption {
      type = lib.types.str;
      default = "VELSTRA_SENTINEL";
      description = "ISO9660 volume ID.";
    };
    hostname = lib.mkOption {
      type = lib.types.str;
      default = "sentinel-installer";
      description = "Hostname of the live system.";
    };
    # The product accent + supporting colours, drawn by both boot menus.
    accent = lib.mkOption {
      type = lib.types.str;
      default = "#22d3ee";
      description = "Accent colour (selection, title).";
    };
    paper = lib.mkOption {
      type = lib.types.str;
      default = "#c9d4e4";
      description = "Foreground text colour.";
    };
    ink = lib.mkOption {
      type = lib.types.str;
      default = "#0b1220";
      description = "Background colour.";
    };
    muted = lib.mkOption {
      type = lib.types.str;
      default = "#7b8da6";
      description = "De-emphasised text colour (help line, timeout).";
    };
  };

  config = {
    # The ISO is an appliance installer, not a NixOS install disc, and the boot
    # menu is the first thing anyone sees of it. This is what puts the product's
    # name in the entry, the volume label and the two boot menus.
    system.nixos.distroName = lib.mkForce cfg.productName;
    # Otherwise the entry carries the NixOS channel string, which says nothing
    # about the appliance being installed. The medium's version is the
    # appliance's.
    #
    # A notch weaker than mkForce on purpose: the VM test framework pins the
    # label to "test" with mkForce, and two definitions of equal strength are a
    # conflict, not an override — every check that boots this module would fail
    # to evaluate. This still beats the stock default, which is all it has to do.
    system.nixos.label = lib.mkOverride 60 cfg.label;
    system.nixos.tags = lib.mkOverride 60 [ ];

    isoImage = {
      isoBaseName = lib.mkForce cfg.isoBaseName;
      volumeID = lib.mkForce cfg.volumeId;
      makeEfiBootable = true;
      makeUsbBootable = true;
      # The image is large; squashfs-compress it rather than storing it raw.
      squashfsCompression = "zstd -Xcompression-level 6";

      # Reads "Install <product> <version>". The default suffix is
      # " Installer", which on a medium that only installs is a word for nothing.
      prependToMenuLabel = "Install ";
      appendToMenuLabel = lib.mkForce "";
      inherit grubTheme;

      # The BIOS/isolinux menu, in the same colours.
      syslinuxTheme = ''
        MENU TITLE ${cfg.productName}
        MENU RESOLUTION 800 600
        MENU CLEAR
        MENU ROWS 6
        MENU CMDLINEROW -4
        MENU TIMEOUTROW -3
        MENU TABMSGROW  -2
        MENU HELPMSGROW -1
        MENU HELPMSGENDROW -1
        MENU MARGIN 0

        #                                FG:AARRGGBB  BG:AARRGGBB   shadow
        MENU COLOR BORDER       30;44      #00000000    #00000000   none
        MENU COLOR SCREEN       37;40      #FF000000    #00000000   none
        MENU COLOR TITLE        37;40      ${argb cfg.accent}    #00000000   none
        MENU COLOR UNSEL        37;40      ${argb cfg.paper}    #00000000   none
        MENU COLOR SEL          30;47      ${argb cfg.ink}    ${argb cfg.accent}   none
        MENU COLOR HELP         37;40      ${argb cfg.muted}    #00000000   none
        MENU COLOR TIMEOUT      37;40      ${argb cfg.muted}    #00000000   none
        MENU COLOR TIMEOUT_MSG  37;40      ${argb cfg.muted}    #00000000   none
        MENU COLOR TABMSG       37;40      ${argb cfg.muted}    #00000000   none
        MENU COLOR CMDMARK      37;40      ${argb cfg.accent}    #00000000   none
        MENU COLOR CMDLINE      37;40      ${argb cfg.paper}    #00000000   none
      '';
    };

    # The installer CLI (wrapped: it resolves its disk tools by absolute path).
    # The bundled sealed image is referenced via the env var below, which pulls
    # it into the system closure (and so onto the ISO).
    environment.systemPackages = [ cfg.installerPackage ];
    environment.variables.${cfg.sourceEnvVar} = cfg.imageSource;

    # Auto-login as root on the console and launch the installer. Ctrl-C drops to a
    # shell (the wizard cancels a line; exiting the wizard leaves a root prompt).
    services.getty.autologinUser = lib.mkForce "root";
    programs.bash.loginShellInit = ''
      if [ "$(tty)" = /dev/tty1 ]; then
        cat <<'BANNER'

        ${cfg.productName} — live installer
        ${cfg.tagline}.
        (Exit the wizard for a root shell.)

      BANNER
        ${cfg.installCommand} || true
      fi
    '';

    networking.hostName = cfg.hostname;
    # The live ISO doesn't persist; silence the stateVersion prompt.
    system.stateVersion = "25.05";
  };
}
