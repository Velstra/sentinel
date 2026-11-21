{ pkgs, self }:
# A masquerade binding must hold its public port for as long as the remote end
# may keep the 4-tuple in TIME_WAIT, even when the client reused its source
# port and an EARLIER connection on that tuple ended in a reset.
#
# Found by checks.nat-cps (after-expiry phase, 1-2 of 20000 connections hung,
# each with five stateful-invalid drops): a client tuple's first connection
# was reset, its next one on the same binding closed cleanly, and the binding
# kept the RESET lifetime bit, so it expired after the 30 s closing timeout.
# The server still held that 4-tuple in TIME_WAIT (60 s) when another client
# was handed the same public port, answered its SYN with a TIME_WAIT ACK, and
# the firewall dropped that ACK as invalid until the client gave up.
#
# Made deterministic with a one-port CGNAT block: every connection from the
# client has the same public port, so after the reset-then-clean sequence a
# second client tuple can only be refused (port still held) or be given the
# port (the defect). The refusal counter tells the two apart; which way the
# server's TIME_WAIT then answers is random and is not what this asserts.
let
  lib = pkgs.lib;
  python = "${pkgs.python3}/bin/python3";
  probe = ./nat-port-reopen-probe.py;
  # Past the closing timeout (30 s) that the stale RESET bit selected, inside
  # the server's TIME_WAIT (60 s) and the clean close's hold (120 s).
  idle = 40;
in
pkgs.testers.runNixOSTest {
  name = "sentinel-nat-port-reopen";
  globalTimeout = 600;
  nodes = {
    client = {
      virtualisation.vlans = [ 2 ];
      networking = {
        useNetworkd = true;
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1.ipv4.addresses = [ { address = "198.18.20.50"; prefixLength = 24; } ];
        defaultGateway = { address = "198.18.20.1"; interface = "eth1"; };
      };
    };
    backend = {
      virtualisation.vlans = [ 1 ];
      networking = {
        useNetworkd = true;
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1.ipv4.addresses = [ { address = "198.18.10.254"; prefixLength = 24; } ];
      };
      systemd.services.reopen-peer = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig.ExecStart = "${python} -u ${probe} serve";
      };
    };
    fw = {
      imports = [ self.nixosModules.sentinel ];
      networking.hostName = lib.mkForce "fw";
      networking.firewall.enable = lib.mkForce false;
      boot.kernelPackages = self.nixosConfigurations.appliance.config.boot.kernelPackages;
      virtualisation = { vlans = [ 1 2 ]; memorySize = 1536; };
      services.velstra = {
        interface = lib.mkForce "eth1";
        appliance = lib.mkForce ((pkgs.formats.toml {}).generate "nat-port-reopen.toml" {
          system.hostname = "fw";
          zone.lan = { default_action = "accept"; stateful = true; };
          zone.wan = { default_action = "drop"; stateful = true; };
          interface = [
            { name = "eth0"; address = "dhcp"; }
            { name = "eth1"; address = "198.18.10.100/24"; zone = "wan"; }
            { name = "eth2"; address = "198.18.20.1/24"; zone = "lan"; }
          ];
          nat.source = [{ name = "wan-cgnat"; zone = "wan"; cgnat-block-size = 1; cgnat-base-port = 40000; }];
        });
      };
      environment.systemPackages = [ pkgs.bpftools ];
    };
  };
  testScript = ''
    import importlib.util
    import json
    import os
    from pathlib import Path
    from typing import Any

    spec = importlib.util.spec_from_file_location("nat_counters", "${./nat-failure-counters.py}")
    assert spec is not None and spec.loader is not None
    nat = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(nat)
    receipt: dict[str, Any] = {"idle_s": ${toString idle}, "steps": []}

    def preserve():
        Path(os.environ["out"], "nat-port-reopen.json").write_text(json.dumps(receipt, indent=2))

    def sample():
        return nat.snapshot(fw.succeed("sentinel show firewall statistics"))

    def connect(name, port, abort=False, timeout=5):
        before = sample()
        result = json.loads(client.succeed(
            "${python} ${probe} open --source 198.18.20.50 --port " + str(port)
            + (" --abort" if abort else "") + " --timeout " + str(timeout)))
        result["step"] = name
        result["counters"] = nat.delta(before, sample())
        receipt["steps"].append(result)
        preserve()
        return result

    start_all()
    fw.wait_for_unit("sentinel-boot.service")
    fw.wait_for_unit("velstra.service")
    backend.wait_for_unit("reopen-peer.service")
    backend.wait_until_succeeds("ss -Hltn sport = :9300 | grep -q 9300", timeout=60)
    for interface in ["eth1", "eth2"]:
        fw.wait_until_succeeds("ip -details link show " + interface + " | grep -q prog/xdp", timeout=60)
    fw.succeed("sentinel config check /var/lib/sentinel/appliance.toml")
    client.wait_until_succeeds("ping -c1 -W1 198.18.20.1", timeout=60)

    # One tuple, two connections: the first ends in a reset, the second
    # reuses the binding and closes cleanly (the server closes first and
    # keeps the 4-tuple in TIME_WAIT).
    first = connect("reset", 40001, abort=True)
    second = connect("clean", 40001)
    for step in (first, second):
        # A live, translating datapath: the server saw the public address.
        assert step["outcome"] == "ok", step
        assert step["public"][0] == "198.18.10.100", step
        assert step["counters"]["egress_masqueraded"] > 0, step
    public = second["public"][1]
    assert first["public"][1] == public, (first, second)
    receipt["public_port"] = public
    backend.succeed("ss -Htan state time-wait | grep -q ':" + str(public) + "'")

    fw.sleep(${toString idle})
    # The server still holds the 4-tuple in TIME_WAIT ...
    backend.succeed("ss -Htan state time-wait | grep -q ':" + str(public) + "'")
    # ... so the one public port must not go to another client tuple yet.
    third = connect("other-tuple-inside-time-wait", 40002, timeout=4)
    receipt["held"] = third["counters"]["egress_nat_no_candidate"] > 0
    preserve()
    print(json.dumps(receipt, indent=2))
    assert receipt["held"], (
        "public port " + str(public) + " was handed to another client " + str(${toString idle})
        + " s after a clean close, while the server held it in TIME_WAIT", third)
    assert third["outcome"] != "ok" and third["counters"]["egress_nat_claim_failed"] == 0, third
    fw.succeed("systemctl is-active sentinel-boot.service velstra.service")
  '';
}
