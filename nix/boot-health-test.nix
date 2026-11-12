# Product gate and real kernel hooks. This is not the separate immutable-image
# EFI boot-counter/fallback proof: no fake successful bless marker is used here.
{ pkgs, self }:
let
  checker = "${pkgs.python3}/bin/python3 -I ${./boot-health.py}";
  sentinel = self.packages.x86_64-linux.sentinel;
in pkgs.testers.runNixOSTest {
  name = "sentinel-boot-health";
  nodes.factory = { lib, ... }: {
    imports = [ self.nixosModules.sentinel ./boot-health.nix ];
    system.name = "factory";
    virtualisation.memorySize = 1024;
    services.velstra.appliance = lib.mkForce (pkgs.writeText "boot-health-factory.toml" ''
      [system]
      hostname = "unprovisioned-fw"
    '');
  };
  nodes.machine = { lib, ... }: {
    imports = [ self.nixosModules.sentinel ./boot-health.nix ];
    system.name = "machine";
    virtualisation.memorySize = 1536;
    virtualisation.vlans = [ 1 ];
    environment.systemPackages = [ pkgs.bpftools ];
    services.velstra.appliance = lib.mkForce (pkgs.writeText "boot-health-appliance.toml" ''
      [system]
      hostname = "boot-health-fw"
      [[interface]]
      name = "eth1"
      address = "192.0.2.1/24"
      zone = "lan"
    '');
    services.velstra.interface = lib.mkForce "eth1";
    # Bound negative unit-graph tests without replacing the product checker.
    systemd.services.velstra-boot-verify.serviceConfig.TimeoutStartSec = lib.mkForce "5s";
  };
  testScript = ''
    import json
    factory.wait_for_unit("multi-user.target")
    with subtest("unprovisioned factory does not start an invented dataplane or reboot"):
        factory.succeed("systemctl start boot-complete.target")
        factory.succeed("systemctl is-active velstra-boot-verify.service boot-complete.target")
        factory.fail("systemctl is-active --quiet velstra.service")
        factory.fail("systemctl is-failed --quiet velstra.service")
        factory.fail("${checker} dataplane-enabled")
        factory.succeed("test $(systemctl --failed --plain --no-legend | wc -l) -eq 0")
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("velstra.service")
    machine.wait_for_unit("wren.service")
    verify = "${checker} verify --sentinel ${sentinel}/bin/sentinel --systemctl ${pkgs.systemd}/bin/systemctl --ip ${pkgs.iproute2}/bin/ip --timeout 1"

    with subtest("real configured services, reconciled addresses and XDP allow assessment"):
        machine.wait_until_succeeds(verify, timeout=30)
        machine.succeed("systemctl start boot-complete.target")
        machine.succeed("systemctl is-active velstra-boot-verify.service boot-complete.target")
        required = machine.succeed("systemctl show boot-complete.target -p Requires --value").split()
        assert "velstra-boot-verify.service" in required, required
        assert "systemd-boot-check-no-failures.service" in required, required
        links = json.loads(machine.succeed("ip -j -d address show eth1"))
        assert links[0]["xdp"]["prog"]["id"] > 0, links

    with subtest("active agent without its real XDP hook cannot pass"):
        # Aya owns an XDP BPF_LINK; netlink's `ip ... xdp off` correctly refuses
        # to replace it. Detach the exact link as a real, disposable-VM fault.
        attachments = json.loads(machine.succeed("bpftool -j link show"))
        selected = [link for link in attachments if link.get("type") == "xdp"
                    and link.get("prog_id") == links[0]["xdp"]["prog"]["id"]]
        assert len(selected) == 1, attachments
        machine.succeed(f"bpftool link detach id {selected[0]['id']}")
        machine.succeed("systemctl is-active velstra.service")
        machine.fail(verify)
        machine.succeed("systemctl restart velstra.service")
        machine.wait_until_succeeds(verify, timeout=30)

    with subtest("malformed saved candidate and compiled-runtime drift are refused read-only"):
        machine.succeed("printf '[system\\n' > /tmp/invalid-boot.toml")
        machine.fail(verify + " --config /tmp/invalid-boot.toml")
        machine.succeed("printf 'different=true\\n' > /tmp/drifted-runtime.toml")
        machine.fail(verify + " --runtime /tmp/drifted-runtime.toml")

    with subtest("a stopped selected dataplane blocks boot-complete instead of blessing"):
        machine.succeed("systemctl stop boot-complete.target velstra-boot-verify.service systemd-boot-check-no-failures.service")
        machine.succeed("systemctl stop velstra.service")
        machine.fail(verify)
        machine.fail("systemctl start boot-complete.target")
        machine.fail("systemctl is-active --quiet boot-complete.target")
        # A normal test VM has no counted EFI UKI: never reboot it in a loop.
        machine.fail("${checker} trial")
        assert machine.succeed("systemctl show systemd-bless-boot.service -p ExecMainStartTimestampMonotonic --value").strip() in ("", "0")
        machine.succeed("systemctl start velstra.service")
        machine.wait_until_succeeds(verify, timeout=30)
  '';
}
