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
  # PAM must be *able* to check a password, even though sshd will not offer
  # password authentication until the running config says so.
  #
  # NixOS derives sshd's PAM stack from the build-time setting:
  #   unixAuth = if settings.PasswordAuthentication == true then true else false
  # and this image sets that to false (key-only is the right default). The
  # result was a runtime switch that could not work: `set services ssh
  # password-authentication true` flips sshd's own setting through a drop-in,
  # sshd then asks PAM, and PAM has no unix module left to ask. Every password
  # was refused with a correct hash in the shadow file and `sshd -T` reporting
  # `passwordauthentication yes`.
  #
  # This does not weaken the default: sshd still refuses password auth until
  # the appliance config enables it. It only stops the image from deciding, at
  # build time, something the operator is supposed to decide at runtime.
  security.pam.services.sshd.unixAuth = lib.mkForce true;

  # There is exactly one firewall on this box, and it is the one the operator
  # configures. NixOS ships its own nftables firewall enabled by default, and on
  # an appliance that is a second, invisible filter underneath the real one:
  # `allowPing` defaults to true, so ICMP passed a zone with `block-icmp true`,
  # and `allowedTCPPorts` is empty, so an SSH port and a web console that were
  # both listening were dropped before they were ever consulted. None of it is
  # expressible in the appliance's own config, and none of it appears in `show`.
  #
  # Every VM check already disables it — which is why the checks never saw any
  # of that: they ran a configuration the shipped image does not have.
  networking.firewall.enable = lib.mkForce false;

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

  # SSH like VyOS — but declarative and key-only, and runtime-configurable via
  # `set services ssh …` (roadmap C21). Sentinel renders two files under
  # /run/sentinel-ssh that sshd reads on its start:
  #   /run/sentinel-ssh/authorized_keys  — the admin's allowed keys
  #   /run/sentinel-ssh/*.conf           — a Port/ListenAddress drop-in
  # They live in a root:root 0755 dir (NOT the wheel-writable /var/lib/sentinel):
  # sshd's StrictModes refuses an AuthorizedKeysFile with a group-writable ancestor.
  # /run is a tmpfs, so sentinel-boot re-renders both from the saved config at boot
  # (and sshd is ordered after it, below). `ports = []` emits no `Port` line, so the
  # drop-in fully owns the listen port (sshd's built-in default 22 when absent) — a
  # true port change, not an added listener.
  services.openssh = {
    enable = true;
    ports = lib.mkForce [ ];
    # Host keys have to outlive a reboot, and on the shipped image `/` is a
    # tmpfs — so the default /etc/ssh location quietly regenerates them at every
    # boot. A live box confirmed it: booted 15:57, host key created 15:57:36.
    #
    # That is worse than an inconvenience. Every reboot greets every operator
    # with REMOTE HOST IDENTIFICATION HAS CHANGED, and an operator who has been
    # taught to clear the warning and carry on will clear it for a real
    # impersonation too. The one persistent partition is /var/lib/sentinel, so
    # the keys are generated into it once and reused from then on.
    hostKeys = [
      {
        path = "/var/lib/sentinel/ssh/ssh_host_ed25519_key";
        type = "ed25519";
      }
      {
        path = "/var/lib/sentinel/ssh/ssh_host_rsa_key";
        type = "rsa";
        bits = 4096;
      }
    ];
    # Per-user keys: sshd substitutes %u with the login name, so Sentinel renders
    # /run/sentinel-ssh/authorized_keys.<user> from each [[system.login]].
    authorizedKeysFiles = [ "/run/sentinel-ssh/authorized_keys.%u" ];
    extraConfig = "Include /run/sentinel-ssh/*.conf";
    settings = {
      # Key-only by default; a [services.ssh] password-authentication=true renders a
      # `Match all` drop-in that overrides this to `yes`.
      PasswordAuthentication = false;
      PermitRootLogin = "no";
    };
  };

  # Local login accounts ([[system.login]], roadmap C21) are created at commit time
  # via useradd/usermod, so the user database must be mutable (the declarative
  # `admin` below is still created; runtime accounts are added alongside it).
  users.mutableUsers = true;
  # sshd must see the rendered keys + Port drop-in on its first start at boot, so
  # order it after the boot service that renders them (sentinel-boot runs early,
  # Before networkd, so this does not delay a routable network).
  systemd.services.sshd.after = [ "sentinel-boot.service" ];
  systemd.services.sshd.wants = [ "sentinel-boot.service" ];
  # The host keys now live on the persistent partition, and sshd generates any
  # that are missing on its first start. If it ran before that partition were
  # mounted it would generate a fresh pair onto the tmpfs underneath the
  # mountpoint — reintroducing the churn this is meant to end, and hiding it
  # behind a directory that looks right afterwards.
  systemd.services.sshd.unitConfig.RequiresMountsFor = "/var/lib/sentinel";

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
    # `wg show` — the only way to see a tunnel's handshakes, endpoints and
    # transfer counters. The appliance configures WireGuard through networkd and
    # never shells out to this, but an operator diagnosing a tunnel that will not
    # come up has nothing else to look at.
    wireguard-tools
    # The same openssl the PKI already issues with (the `sentinel` wrapper points
    # at it through SENTINEL_OPENSSL_BIN) — put on PATH so an operator can read
    # back what the box handed out. An appliance that issues certificates and
    # cannot show you the expiry, the SANs or whether a leaf chains to its CA
    # asks you to trust it on the strength of a summary line.
    openssl
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
    # SSH runtime config (roadmap C21): the authorized_keys + Port/ListenAddress
    # drop-in Sentinel renders here must be root-owned with NO group-writable
    # ancestor, or sshd's StrictModes refuses the AuthorizedKeysFile. So it is a
    # dedicated root:root 0755 dir on the tmpfs (NOT under the wheel-writable
    # /var/lib/sentinel) — Sentinel writes the files via sudo; sentinel-boot
    # re-renders them from the saved config each boot.
    "d /run/sentinel-ssh 0755 root root -"
    # The sshd host keys (see services.openssh.hostKeys below). Its own dir,
    # root:root 0700, rather than /var/lib/sentinel itself: that one is
    # group-writable by wheel so `configure` can save, and an operator who can
    # replace the host key can impersonate the appliance to every other operator.
    "d /var/lib/sentinel/ssh 0700 root root -"
    # The compiled agent config the admin's `commit` writes + the agent reads.
    # /run is tmpfs (recreated each boot); wheel-writable so `configure` (run as
    # admin, not root) can install it.
    "d /run/sentinel 0775 root wheel -"
  ];

  system.stateVersion = "25.05";
}
