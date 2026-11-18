# Admission must refuse new unsafe policy without stranding owned recovery.
{ pkgs, self }:
pkgs.testers.runNixOSTest {
  name = "sentinel-destination-admission-timer";
  globalTimeout = 300;
  nodes.fw = { lib, ... }: {
    imports = [ self.nixosModules.sentinel ];
    virtualisation.memorySize = 1536;
    virtualisation.vlans = [ 1 ];
    networking.firewall.enable = lib.mkForce false;
    services.velstra.interface = lib.mkForce "eth1";
    services.velstra.appliance = lib.mkForce ((pkgs.formats.toml {}).generate "legacy-policy.toml" {
      system.hostname = "legacy-boot";
      interface = [
        { name = "eth0"; address = "dhcp"; zone = "wan"; }
        { name = "eth1"; address = "192.0.2.1/24"; zone = "lan"; }
      ];
      firewall.default_action = "accept";
      rule = [{ name = "deny-telnet"; from = "lan"; to = "wan";
                action = "reject"; proto = "tcp"; port = 23; }];
    });
  };
  testScript = ''
    import json, shlex
    fw.wait_for_unit("multi-user.target")
    fw.wait_for_unit("sentinel-boot.service")
    fw.wait_for_unit("velstra.service")
    saved = "/var/lib/sentinel/appliance.toml"
    running = "/run/sentinel/running.toml"
    def command(lines):
        return "printf %s " + shlex.quote("\n".join(lines + ["exit", ""])) + " | sentinel configure 2>&1"
    def config(path):
        return json.loads(fw.succeed("${pkgs.python3}/bin/python3 -c " + shlex.quote(
            "import json,tomllib; print(json.dumps(tomllib.load(open(" + repr(path) + ", 'rb'))))")))
    def digest(path):
        return fw.succeed("sha256sum " + path).split()[0]
    with subtest("legacy policy genuinely boots and unrelated identity remains editable"):
        assert config(saved)["rule"][0]["to"] == "wan"
        fw.succeed(command(["set system hostname legacy-owned", "commit", "save"]))
        assert fw.succeed("hostname").strip() == "legacy-owned"
    with subtest("new policy and caller-spoofed timer are refused before mutation"):
        before = [digest(saved), digest(running)]
        refused = fw.fail(command(["set firewall rule deny-telnet port 24", "commit-confirm 1"]))
        assert "destination-zone admission refused" in refused, refused
        assert [digest(saved), digest(running)] == before
        fw.fail("systemctl is-active --quiet sentinel-confirm.timer")
        spoofed = fw.fail("sentinel confirm-rollback --commit-confirm 2>&1")
        assert "reserved for the systemd-owned rollback worker" in spoofed, spoofed
        assert [digest(saved), digest(running)] == before
    with subtest("real PID1 timer restores grandfathered policy after explicit migration"):
        fw.succeed(command(["delete firewall rule deny-telnet to",
            "set firewall rule deny-telnet destination 203.0.113.0/24",
            "set system hostname migrated-trial", "commit-confirm 1"]))
        assert fw.succeed("hostname").strip() == "migrated-trial"
        assert "to" not in config(running)["rule"][0]
        assert config(saved)["rule"][0]["to"] == "wan"
        fw.succeed("systemctl is-active sentinel-confirm.timer")
        fw.wait_until_succeeds("test $(hostname) = legacy-owned", timeout=110)
        fw.wait_until_succeeds("grep -q legacy-owned " + running, timeout=20)
        assert config(running)["rule"][0]["to"] == "wan"
        assert [digest(saved), digest(running)] == before
        fw.succeed("systemctl is-active velstra.service")
    print("DESTINATION_ADMISSION_REAL_TIMER_PASS", flush=True)
  '';
}
