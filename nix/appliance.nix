# The Sentinel appliance NixOS configuration.
#
# Minimal and immutable-leaning: SSH on (key-only), a firewall, and the
# `sentinel` CLI available. Each `nixos-rebuild` is a new generation in the boot
# menu, so a bad change is undone by booting the previous one — the "reload and
# it works again" guarantee.
#
# Wiring the Velstra agent (the eBPF data plane) as a systemd service that loads
# `sentinel compile`'s output is the next slice.
{
  config,
  pkgs,
  lib,
  ...
}:
{
  networking.hostName = lib.mkDefault "sentinel-fw";

  # SSH like VyOS — but declarative and key-only.
  services.openssh = {
    enable = true;
    settings = {
      PasswordAuthentication = false;
      PermitRootLogin = "no";
    };
  };

  users.users.admin = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];
    # Put your public key here (or override this in your own config).
    openssh.authorizedKeys.keys = [
      # "ssh-ed25519 AAAA... you@host"
    ];
  };
  security.sudo.wheelNeedsPassword = lib.mkDefault false;

  # EFI + systemd-boot so generations are listed at boot (the rollback path).
  # `nixos-rebuild build-vm` overrides this for the throwaway VM.
  boot.loader.systemd-boot.enable = lib.mkDefault true;
  boot.loader.efi.canTouchEfiVariables = lib.mkDefault true;

  # A root filesystem so the config evaluates for image/VM builds. Adjust the
  # device for real hardware; `build-vm` supplies its own.
  fileSystems."/" = lib.mkDefault {
    device = "/dev/disk/by-label/nixos";
    fsType = "ext4";
  };

  system.stateVersion = "24.11";
}
