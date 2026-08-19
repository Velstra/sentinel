# NixOS module: run the Velstra eBPF/XDP data plane as a service.
#
# The agent config is **rendered at apply time** into /run/sentinel/velstra.toml
# by `sentinel apply-boot` and by every `commit`, not baked into the generation.
# That is the appliance's model: the image is immutable and rollback-able, while
# the configuration is a document the running system reconciles to — so a firewall
# change takes effect without a rebuild, and `commit-confirm` can undo it on a
# timer. (An earlier version of this file described a build-time /etc config; the
# appliance never worked that way.)
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.velstra;
in
{
  options.services.velstra = {
    enable = lib.mkEnableOption "the Velstra eBPF/XDP data plane";

    package = lib.mkOption {
      type = lib.types.package;
      description = "The velstra agent package (the eBPF data plane).";
    };

    sentinel = lib.mkOption {
      type = lib.types.package;
      description = "The sentinel package, used to compile the appliance config.";
    };

    appliance = lib.mkOption {
      type = lib.types.path;
      description = "The declarative Sentinel appliance config (TOML or JSON).";
    };

    interface = lib.mkOption {
      type = lib.types.str;
      example = "eth0";
      description = "Underlay/uplink interface the agent attaches the XDP hook to.";
    };
  };

  config = lib.mkIf cfg.enable {
    # Seed the runtime firewall config at boot: compile the **active** appliance
    # config (operator-edited /var/lib if present, else the factory default
    # baked into the image) into the writable /run path the agent reads. This is
    # the immutable-appliance model: the image is fixed; config is applied to the
    # running system. `sentinel commit` rewrites /run/sentinel/velstra.toml live
    # and reloads the agent — no rebuild.
    systemd.services.sentinel-boot = {
      description = "Seed Velstra config + hostname from the active appliance config";
      wantedBy = [ "multi-user.target" ];
      # Before networkd so the `.network` units are in place when it starts
      # (it reads /run/systemd/network on startup); before velstra so the agent
      # sees the compiled firewall config.
      before = [
        "velstra.service"
        "systemd-networkd.service"
      ];
      # `hostname` (nettools) on PATH for the live hostname apply.
      path = [ pkgs.nettools ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        mkdir -p /run/sentinel /var/lib/sentinel
        # Seed the editable config from the factory default on first boot, so
        # `configure` edits the real config (not an empty draft).
        if [ ! -f /var/lib/sentinel/appliance.toml ]; then
          cp ${cfg.appliance} /var/lib/sentinel/appliance.toml
        fi
        # Set the hostname + write the agent config from the active config.
        ${cfg.sentinel}/bin/sentinel apply-boot \
          --config /var/lib/sentinel/appliance.toml \
          --out /run/sentinel/velstra.toml
      '';
    };

    # The console keymap, put back after systemd has had its say.
    #
    # systemd owns the virtual console: it runs systemd-vconsole-setup at boot
    # and again from a udev rule whenever a console appears, each time writing
    # the image's keymap. A layout chosen in the installer was therefore loaded
    # and then reset, every time. Disabling NixOS's console module removed the
    # reset — and the login prompt with it, because getty never came up. So
    # order after it and follow it instead: PartOf means this runs again each
    # time vconsole-setup does, and the operator's choice has the last word.
    systemd.services.sentinel-console = {
      description = "Apply the appliance's console keyboard, locale and timezone";
      wantedBy = [ "multi-user.target" ];
      after = [
        "systemd-vconsole-setup.service"
        "sentinel-boot.service"
      ];
      partOf = [ "systemd-vconsole-setup.service" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${cfg.sentinel}/bin/sentinel apply-console --config /var/lib/sentinel/appliance.toml";
      };
    };

    systemd.services.velstra = {
      description = "Velstra eBPF/XDP data plane";
      wantedBy = [ "multi-user.target" ];
      after = [
        "network-pre.target"
        "sentinel-boot.service"
      ];
      requires = [ "sentinel-boot.service" ];
      before = [ "network.target" ];
      # Every `sentinel commit` reload-or-restarts the agent to pick up the new
      # config. Those are INTENTIONAL restarts, so don't let a burst of commits
      # trip systemd's start rate limiter and lock the data plane out
      # (start-limit-hit). Restart=on-failure below still self-heals real crashes.
      startLimitIntervalSec = 0;
      # The fallback when no zoned interface has been configured yet.
      environment.VELSTRA_IFACE = cfg.interface;
      serviceConfig = {
        # The query socket (C23) is what `show flows` / `show firewall statistics`
        # read: the agent owns the eBPF maps, so it is the only process that can
        # answer what the data plane is doing. RuntimeDirectory creates (and
        # cleans up) /run/velstra for it.
        #
        # The portal socket (C20) and the mapping socket (C18) are separate from
        # it and from each other, and deliberately: the query socket can only add
        # a drop, the portal one admits a device to a zone's ordinary rules, and
        # the mapping one opens an inbound port. Three different amounts of
        # trust, so three files — a service that needs one is not handed the
        # others. All live in the same root-owned 0700 directory, which is what
        # governs who may ask.
        # The uplink comes from the appliance config at runtime (sentinel writes
        # it here on every apply), not from a build-time constant: an image
        # baked with `eth0` never attached on a box whose NIC is called
        # anything else, and the firewall then simply did not run. The option
        # below stays as the fallback for a box with no zoned interface yet.
        EnvironmentFile = "-/run/sentinel/velstra.env";
        # `$VELSTRA_FLOWSPEC_ARGS` unbraced on purpose: systemd splits that
        # form into words and drops it entirely when empty, which is how A3
        # enforcement goes on and off without rebuilding the unit. The braced
        # form would pass one argument containing spaces.
        ExecStart = "${cfg.package}/bin/velstra run --iface \${VELSTRA_IFACE} --config /run/sentinel/velstra.toml --query-socket /run/velstra/query.sock --portal-socket /run/velstra/portal.sock --mapping-socket /run/velstra/mapping.sock $VELSTRA_FLOWSPEC_ARGS";
        RuntimeDirectory = "velstra";
        RuntimeDirectoryMode = "0700";
        Restart = "on-failure";
        RestartSec = 2;
        # Loading + attaching XDP/eBPF needs these capabilities. CAP_SYS_ADMIN is
        # broad; on kernels that accept CAP_BPF+CAP_PERFMON for XDP load it can be
        # narrowed — verify against the target kernel via the nixosTest before
        # dropping it.
        AmbientCapabilities = [
          "CAP_BPF"
          "CAP_NET_ADMIN"
          "CAP_SYS_ADMIN"
        ];
        CapabilityBoundingSet = [
          "CAP_BPF"
          "CAP_NET_ADMIN"
          "CAP_SYS_ADMIN"
        ];
        # Sandboxing. Only directives that cannot interfere with eBPF/XDP load,
        # netlink or raw packet I/O are enabled here; stronger confinement
        # (ProtectSystem=strict, RestrictAddressFamilies, SystemCallFilter) should
        # be added once validated against the datapath nixosTests, since a wrong
        # restriction silently breaks the firewall.
        NoNewPrivileges = true;
        ProtectHome = true;
        ProtectClock = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
      };
    };
  };
}
