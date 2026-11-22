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

    systemd.services.sentinel-witness = {
      description = "Independent durable Sentinel HA lease witness";
      wantedBy = [ "multi-user.target" ];
      after = [ "sentinel-boot.service" "network.target" ];
      requires = [ "sentinel-boot.service" ];
      unitConfig.ConditionPathExists = "/run/sentinel/witness.json";
      # Both members fence within one lease of the witness going away, so a
      # crash loop must never trip the default start limit and leave it down.
      startLimitIntervalSec = 0;
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/wren-witness --config /run/sentinel/witness.json";
        StateDirectory = "sentinel/witness";
        StateDirectoryMode = "0700";
        Restart = "on-failure";
        RestartSec = "100ms";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        RestrictSUIDSGID = true;
      };
    };
    # The HA WireGuard clock step (wren-ha clock.rs). A member that takes over
    # brings its wall clock up to its predecessor's before WireGuard initiates,
    # or the remote peers drop its handshakes as replays. Wren parses untrusted
    # routing protocols, so it does not hold CAP_SYS_TIME: it connects here and
    # sends nothing. One sandboxed helper instance per connection reads the
    # agent's replicated clock itself, applies the rules (forward only; at most
    # 10 min, or 60 s when both clocks are NTP-synchronised; never by a
    # synchronised member onto an unsynchronised peer), steps, records
    # /run/velstra/ha/clock.json and answers with its decision.
    systemd.sockets.wren-ha-clock-step = {
      description = "HA WireGuard clock-step requests from Wren";
      wantedBy = [ "sockets.target" ];
      socketConfig = {
        ListenStream = "/run/velstra-ha-clock.sock";
        Accept = true;
        SocketUser = "root";
        SocketGroup = "root";
        SocketMode = "0600";
        MaxConnections = 4;
      };
    };
    systemd.services."wren-ha-clock-step@" = {
      description = "Step the wall clock for an HA WireGuard takeover";
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/wren-ha-clock-step";
        StandardInput = "socket";
        StandardOutput = "socket";
        StandardError = "journal";
        RuntimeMaxSec = 10;
        # CAP_SYS_TIME and nothing else; clock_settime must stay unfiltered.
        CapabilityBoundingSet = [ "CAP_SYS_TIME" ];
        AmbientCapabilities = [ "CAP_SYS_TIME" ];
        ProtectClock = false;
        SystemCallFilter = [ "@system-service" "@clock" ];
        SystemCallArchitectures = "native";
        # It reads wireguard.json and writes clock.json there, nothing else.
        ProtectSystem = "strict";
        ReadWritePaths = [ "/run/velstra/ha" ];
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        PrivateNetwork = true;
        RestrictAddressFamilies = [ "AF_UNIX" ];
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectHostname = true;
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        NoNewPrivileges = true;
        UMask = "0077";
      };
    };
    systemd.services.wren = {
      environment.WREN_WG_BIN = "${pkgs.wireguard-tools}/bin/wg";
      description = "Wren routing daemon (control plane)";
      wantedBy = [ "multi-user.target" ];
      # After the boot service (which compiles /run/sentinel/wren.toml) and after
      # the network is being set up (BGP/OSPF need the interface addresses).
      # networkd merely being started is not enough (CTRL-19): wren reads the
      # connected networks when its protocols start, so it waits for
      # sentinel-boot-late, which itself waits (bounded, 30s) for links to come
      # online and installs the link-runtime state. Only ordering: a failed
      # boot-late never keeps routing down.
      after = [
        "network-pre.target"
        "sentinel-boot.service"
        "systemd-networkd.service"
        "sentinel-boot-late.service"
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
        ReadWritePaths = [ "/run/velstra/ha" ];
        ExecStart = "${cfg.package}/bin/wren --config /run/sentinel/wren.toml --backend kernel --socket /run/wren/wren.sock";
        # A successful reload means kernel reconciliation completed, not merely
        # that a signal was delivered. Keep validation and execution on one pin.
        ExecReload = [
          "${cfg.package}/bin/wren --config /run/sentinel/wren.toml check"
          "${cfg.package}/bin/wren --socket /run/wren/wren.sock reload"
        ];
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
        # Sandboxing. wren writes only its control socket under /run/wren
        # (RuntimeDirectory, which stays writable under ProtectSystem=strict) and
        # reads /run/sentinel/wren.toml; nothing under /usr, /etc, /home or /boot,
        # so these confinements are safe. Stronger ones (RestrictAddressFamilies,
        # SystemCallFilter) should be added once validated against the routing
        # nixosTests.
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectClock = true;
        ProtectKernelModules = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
      };
    };
  };
}
