# NixOS module: run the Velstra eBPF/XDP data plane as a service.
#
# The agent config is compiled from the declarative Sentinel appliance config at
# **build time** and placed in this generation's read-only /etc — so the whole
# firewall is part of the immutable, rollback-able system closure. Change the
# appliance config, rebuild, and a bad change is undone by booting the previous
# generation.
#
# Not yet wired into flake.nix: it needs `services.velstra.package` — the velstra
# agent built as a Nix package (the eBPF data plane). That packaging (nightly
# rust + rust-src + bpf-linker in the sandbox) is the next milestone.
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
      before = [ "velstra.service" ];
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

    systemd.services.velstra = {
      description = "Velstra eBPF/XDP data plane";
      wantedBy = [ "multi-user.target" ];
      after = [
        "network-pre.target"
        "sentinel-boot.service"
      ];
      requires = [ "sentinel-boot.service" ];
      before = [ "network.target" ];
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/velstra run --iface ${cfg.interface} --config /run/sentinel/velstra.toml";
        Restart = "on-failure";
        RestartSec = 2;
        # Loading + attaching XDP/eBPF needs these capabilities.
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
      };
    };
  };
}
