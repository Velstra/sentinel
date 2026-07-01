# NixOS module: run the Wren routing daemon (BGP/OSPF/IS-IS/RIP/Babel/VRRP) as a
# service alongside the Velstra data plane.
#
# Wren is the control plane: it computes routes (dynamic protocols + static) and
# programs the kernel FIB via netlink. Velstra (the data plane) filters/​forwards
# packets; Wren decides where they go. Its config is compiled from the same
# declarative appliance config as Velstra's — the `sentinel-boot` service (in
# velstra-service.nix) writes /run/sentinel/wren.toml at boot via `apply-boot`,
# and `sentinel commit` rewrites it live and reloads this unit.
#
# Operational state is inspected with `wren show …` (routes, bgp neighbors, …)
# against the daemon's control socket at /run/wren/wren.sock.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.wren;
in
{
  options.services.wren = {
    enable = lib.mkEnableOption "the Wren routing daemon";

    package = lib.mkOption {
      type = lib.types.package;
      description = "The wren daemon package (the routing control plane).";
    };
  };

  config = lib.mkIf cfg.enable {
    # Put the `wren` binary on the operator's PATH so `wren show bgp neighbors`,
    # `wren show routes`, etc. work on the box (it doubles as the control client).
    environment.systemPackages = [ cfg.package ];

    systemd.services.wren = {
      description = "Wren routing daemon (control plane)";
      wantedBy = [ "multi-user.target" ];
      # After the boot service (which compiles /run/sentinel/wren.toml) and after
      # the network is being set up (BGP/OSPF need the interface addresses).
      after = [
        "network-pre.target"
        "sentinel-boot.service"
        "systemd-networkd.service"
      ];
      requires = [ "sentinel-boot.service" ];
      wants = [ "network.target" ];
      # `sentinel commit` reload-or-restarts this to pick up the new routing
      # config; those are intentional restarts, so don't let a burst of commits
      # trip systemd's start rate limiter and lock the router out.
      startLimitIntervalSec = 0;
      # The daemon serves (and the `show` client connects to) this socket.
      serviceConfig = {
        RuntimeDirectory = "wren";
        ExecStart = "${cfg.package}/bin/wren --config /run/sentinel/wren.toml --backend kernel --socket /run/wren/wren.sock";
        Restart = "on-failure";
        RestartSec = 2;
        # Programming the kernel FIB (netlink) needs CAP_NET_ADMIN; the raw
        # sockets the IGPs open (OSPF/IS-IS/RIP/Babel/VRRP) need CAP_NET_RAW; and
        # binding BGP's privileged TCP port 179 needs CAP_NET_BIND_SERVICE.
        AmbientCapabilities = [
          "CAP_NET_ADMIN"
          "CAP_NET_RAW"
          "CAP_NET_BIND_SERVICE"
        ];
        CapabilityBoundingSet = [
          "CAP_NET_ADMIN"
          "CAP_NET_RAW"
          "CAP_NET_BIND_SERVICE"
        ];
      };
    };
  };
}
