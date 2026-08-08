# Live-boot installer ISO.
#
# A small, hybrid USB/CD-bootable NixOS live system that carries the sealed
# verified-boot appliance image (`sentinelImageRaw`, in the closure) and drops
# straight into `sentinel install`. The installer clones the bundled image onto
# the chosen target disk(s) — single disk or a RAID array — via its `--source`
# mode (there's no booted verity store to clone from in the live environment).
#
# Build:  nix build .#sentinel-iso     →  result/iso/velstra-sentinel-installer.iso
{
  config,
  lib,
  pkgs,
  modulesPath,
  sentinelPkg,
  sentinelImageRaw,
  ...
}:
let
  # The product's accent, the same cyan the installer draws its frames in.
  accent = "#22d3ee";
  paper = "#c9d4e4";
  ink = "#0b1220";

  # The UEFI boot menu. GRUB reads a theme directory, so this is the smallest
  # one that works: a font it can load and a theme.txt. No pixmaps — the
  # selection is shown by colour, which needs no image assets and cannot break
  # on a console that has no graphics mode.
  grubTheme = pkgs.runCommand "sentinel-grub-theme" { } ''
    mkdir -p $out
    cp ${pkgs.grub2}/share/grub/unicode.pf2 $out/
    cat > $out/theme.txt <<'THEME'
    title-text: "Velstra Sentinel"
    title-color: "${accent}"
    desktop-color: "${ink}"
    terminal-left: "5%"
    terminal-top: "5%"
    terminal-width: "90%"
    terminal-height: "90%"

    + boot_menu {
      left = 15%
      top = 30%
      width = 70%
      height = 40%
      item_color = "${paper}"
      selected_item_color = "${accent}"
      item_height = 24
      item_spacing = 8
    }

    + label {
      top = 100%-40
      left = 0
      width = 100%
      align = "center"
      color = "${paper}"
      text = "Installs the verified-boot appliance onto internal storage"
    }
    THEME
  '';
in
{
  imports = [ "${modulesPath}/installer/cd-dvd/iso-image.nix" ];

  # The ISO is an appliance installer, not a NixOS install disc, and the boot
  # menu is the first thing anyone sees of it. This is what puts the product's
  # name in the entry, the volume label and the two boot menus.
  system.nixos.distroName = lib.mkForce "Velstra Sentinel";
  # Otherwise the entry carries the NixOS channel string, which says nothing
  # about the appliance being installed. The medium's version is the
  # appliance's.
  #
  # A notch weaker than mkForce on purpose: the VM test framework pins the
  # label to "test" with mkForce, and two definitions of equal strength are a
  # conflict, not an override — every check that boots this module would fail
  # to evaluate. This still beats the stock default, which is all it has to do.
  system.nixos.label = lib.mkOverride 60 sentinelPkg.version;
  system.nixos.tags = lib.mkOverride 60 [ ];

  isoImage = {
    isoBaseName = lib.mkForce "velstra-sentinel-installer";
    volumeID = lib.mkForce "VELSTRA_SENTINEL";
    makeEfiBootable = true;
    makeUsbBootable = true;
    # The image is large; squashfs-compress it rather than storing it raw.
    squashfsCompression = "zstd -Xcompression-level 6";

    # Reads "Install Velstra Sentinel <version>". The default suffix is
    # " Installer", which on a medium that only installs is a word for nothing.
    prependToMenuLabel = "Install ";
    appendToMenuLabel = lib.mkForce "";
    inherit grubTheme;

    # The BIOS/isolinux menu, in the same colours.
    syslinuxTheme = ''
      MENU TITLE Velstra Sentinel
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
      MENU COLOR TITLE        37;40      #FF22D3EE    #00000000   none
      MENU COLOR UNSEL        37;40      #FFC9D4E4    #00000000   none
      MENU COLOR SEL          30;47      #FF0B1220    #FF22D3EE   none
      MENU COLOR HELP         37;40      #FF7B8DA6    #00000000   none
      MENU COLOR TIMEOUT      37;40      #FF7B8DA6    #00000000   none
      MENU COLOR TIMEOUT_MSG  37;40      #FF7B8DA6    #00000000   none
      MENU COLOR TABMSG       37;40      #FF7B8DA6    #00000000   none
      MENU COLOR CMDMARK      37;40      #FF22D3EE    #00000000   none
      MENU COLOR CMDLINE      37;40      #FFC9D4E4    #00000000   none
    '';
  };

  # The installer CLI (wrapped: it resolves sgdisk/dd/mdadm/losetup/… by absolute
  # path). The bundled sealed image is referenced via the env var below, which
  # pulls it into the system closure (and so onto the ISO).
  environment.systemPackages = [ sentinelPkg ];
  environment.variables.SENTINEL_INSTALL_SOURCE = sentinelImageRaw;

  # Auto-login as root on the console and launch the installer. Ctrl-C drops to a
  # shell (the wizard cancels a line; exiting the wizard leaves a root prompt).
  services.getty.autologinUser = lib.mkForce "root";
  programs.bash.loginShellInit = ''
    if [ "$(tty)" = /dev/tty1 ]; then
      cat <<'BANNER'

      Velstra Sentinel — live installer
      Installs the verified-boot appliance onto internal storage.
      (Exit the wizard for a root shell.)

    BANNER
      sentinel install || true
    fi
  '';

  networking.hostName = "sentinel-installer";
  # The live ISO doesn't persist; silence the stateVersion prompt.
  system.stateVersion = "25.05";
}
