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
    # Compile appliance config -> agent config at build time (declarative,
    # immutable). It lives in the read-only /etc of this generation.
    environment.etc."sentinel/velstra.toml".source =
      pkgs.runCommand "velstra.toml" { } ''
        ${cfg.sentinel}/bin/sentinel compile ${cfg.appliance} > "$out"
      '';

    systemd.services.velstra = {
      description = "Velstra eBPF/XDP data plane";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-pre.target" ];
      before = [ "network.target" ];
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/velstra run --iface ${cfg.interface} --config /etc/sentinel/velstra.toml";
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
