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
  # networking.hostName is set from the appliance config in flake.nix (so a
  # `commit` that changes the hostname changes the system), not here.

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

  # `sentinel commit` shells out to nixos-rebuild (and rollback). The admin is in
  # `wheel`, which is passwordless above — so commit/rollback work without a
  # prompt. (Tighten to a specific command rule for production.)

  # Test-VM convenience: a console login (SSH is key-only, so the QEMU console
  # would otherwise be a dead end). INSECURE — for `build-vm` only; a real
  # appliance image should drop these.
  users.users.admin.initialPassword = lib.mkDefault "sentinel";
  services.getty.autologinUser = lib.mkDefault "admin";

  # VyOS-like operational shell: after login you type `configure` directly —
  # no `sentinel` prefix needed.
  environment.shellAliases = {
    configure = "sentinel configure";
    show = "sentinel show";
  };

  # Dynamic prompt: `$(hostname)` is re-evaluated each render (bash promptvars),
  # so a committed hostname change shows up live in the running shell instead of
  # only after a reboot/relogin (plain `\h` is cached at shell start).
  programs.bash.promptInit = ''
    PS1='\[\e[1;32m\]\u@$(hostname)\[\e[0m\]:\w\$ '
  '';

  # A short greeting so it's clear how to start.
  users.motd = ''
    Velstra Sentinel appliance.
      show <Tab>    live status / interfaces / routes / neighbors / log / version / config
      configure     edit the config (Tab or `?` lists options); `commit` applies live, `save` persists
  '';

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

  # The active appliance config lives here (writable, persistent). `sentinel
  # commit` writes it and applies it live; `sentinel-boot` seeds + re-applies it
  # at boot. Group-writable by `wheel` so the admin (who runs `configure`, not as
  # root) can write it; the live apply escalates via sudo.
  systemd.tmpfiles.rules = [
    "d /var/lib/sentinel 0775 root wheel -"
    # The compiled agent config the admin's `commit` writes + the agent reads.
    # /run is tmpfs (recreated each boot); wheel-writable so `configure` (run as
    # admin, not root) can install it.
    "d /run/sentinel 0775 root wheel -"
  ];

  system.stateVersion = "25.05";
}
