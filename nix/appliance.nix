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

  # systemd-networkd is the L3 backend: `sentinel commit` drops per-interface
  # `.network` units into /run/systemd/network and reloads networkd, so
  # `set interface eth0 address …` is applied live. The boot service re-renders
  # them from the saved config each boot.
  networking.useNetworkd = true;
  networking.useDHCP = false;
  # Don't block boot waiting for a routable link — an appliance may come up with
  # all NICs down until the operator assigns addresses.
  systemd.network.wait-online.enable = false;

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

  # Prompt uses bash's `\h` hostname escape rather than a `$(hostname)` command
  # substitution: embedding a live command substitution in PS1 (with promptvars
  # on) is an unnecessary prompt-injection footgun for zero real benefit. The
  # hostname is charset-validated at config time (see config::validate_hostname),
  # and a committed change is picked up by the next login shell.
  programs.bash.promptInit = ''
    PS1='\[\e[1;32m\]\u@\h\[\e[0m\]:\w\$ '
  '';

  # Operational-mode tab completion (vtysh-like): `show <Tab>` and
  # `sentinel show <Tab>` offer the real subcommands instead of bash's default
  # filename completion. Registered against the `show` alias name too.
  programs.bash.interactiveShellInit = ''
    _sentinel_show_kinds="status interfaces routes neighbors config log version"
    # vtysh-style context: the `show` kind, then (for net views) the live NICs.
    _sentinel_show_at() {
      # $1 = index of the show KIND word; complete relative to it. (Separate
      # `local` lines: a var isn't visible to a later RHS on the same `local`.)
      local kind_i=$1
      local cur="''${COMP_WORDS[COMP_CWORD]}"
      local rel=$((COMP_CWORD - kind_i))
      if [ "$rel" -eq 0 ]; then
        COMPREPLY=( $(compgen -W "$_sentinel_show_kinds" -- "$cur") )
      elif [ "$rel" -eq 1 ]; then
        case "''${COMP_WORDS[kind_i]}" in
          interfaces|routes|neighbors)
            COMPREPLY=( $(compgen -W "$(ls /sys/class/net 2>/dev/null)" -- "$cur") ) ;;
          *) COMPREPLY=() ;;
        esac
      else
        COMPREPLY=()
      fi
    }
    # `show <kind> [nic]` (the alias) — KIND is at word index 1.
    _sentinel_show() { _sentinel_show_at 1; }
    complete -F _sentinel_show show

    # Block devices the installer/updater target (real disks, /dev-prefixed).
    _sentinel_disks() { lsblk -dnro NAME 2>/dev/null | sed 's,^,/dev/,'; }
    _sentinel() {
      local cur="''${COMP_WORDS[COMP_CWORD]}"
      if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "configure show config compile apply apply-boot install update ports" -- "$cur") )
      elif [ "''${COMP_WORDS[1]}" = "show" ]; then
        # `sentinel show <kind> [nic]` — KIND is at word index 2.
        _sentinel_show_at 2
      elif [ "''${COMP_WORDS[1]}" = "install" ]; then
        # target disk(s) + flags; --source/image also takes a file path.
        COMPREPLY=( $(compgen -W "$(_sentinel_disks) --raid --source --commit" -- "$cur") $(compgen -f -- "$cur") )
      elif [ "''${COMP_WORDS[1]}" = "update" ]; then
        # a new image (file) or the inactive-slot device, + --commit.
        COMPREPLY=( $(compgen -W "$(_sentinel_disks) --commit" -- "$cur") $(compgen -f -- "$cur") )
      else
        COMPREPLY=()
      fi
    }
    complete -F _sentinel sentinel
  '';

  # Handy for the operator at the plain shell; sentinel itself calls these by
  # absolute path (wrapped), so it doesn't depend on this.
  environment.systemPackages = with pkgs; [
    iproute2
    nettools
  ];

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
