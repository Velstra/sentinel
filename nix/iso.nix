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
{
  imports = [ "${modulesPath}/installer/cd-dvd/iso-image.nix" ];

  isoImage = {
    isoBaseName = lib.mkForce "velstra-sentinel-installer";
    makeEfiBootable = true;
    makeUsbBootable = true;
    # The image is large; squashfs-compress it rather than storing it raw.
    squashfsCompression = "zstd -Xcompression-level 6";
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
