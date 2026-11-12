# Actual packets across a real live-only CLI commit and the periodic service.
{ pkgs, self }:
let
  lib = pkgs.lib;
in pkgs.testers.runNixOSTest {
  name = "sentinel-firewall-refresh-running-intent";
  globalTimeout = 600;
  nodes = {
    fw = {
      imports = [ self.nixosModules.sentinel ];
      virtualisation = { vlans = [ 1 ]; memorySize = 1536; };
      networking.firewall.enable = lib.mkForce false;
      networking.interfaces.eth1.ipv4.addresses = [{ address = "10.90.0.1"; prefixLength = 24; }];
      services.velstra.interface = lib.mkForce "eth1";
      services.velstra.appliance = lib.mkForce (pkgs.writeText "refresh-appliance.toml" ''
        [system]
        hostname = "refresh-fw"
        [[interface]]
        name = "eth0"
        address = "dhcp"
        zone = "wan"
        [[interface]]
        name = "eth1"
        address = "10.90.0.1/24"
        zone = "wan"
      '');
      environment.systemPackages = [ pkgs.python3 pkgs.curl ];
    };
    client = {
      virtualisation = { vlans = [ 1 ]; memorySize = 768; };
      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4.addresses = [{ address = "10.90.0.2"; prefixLength = 24; }];
      environment.systemPackages = [ pkgs.curl ];
    };
  };
  testScript = ''
    import shlex
    start_all()
    for node in (fw, client):
        node.wait_for_unit("multi-user.target")
    for unit in ("sentinel-boot.service", "velstra.service", "wren.service"):
        fw.wait_for_unit(unit)
    fw.wait_until_succeeds("ip -4 addr show eth1 | grep -q 10.90.0.1/24")
    client.wait_until_succeeds("ip -4 addr show eth1 | grep -q 10.90.0.2/24")
    fw.succeed("systemd-run --unit=qa-refresh-http ${pkgs.python3}/bin/python3 -m http.server 9999 --bind 0.0.0.0")
    fw.wait_for_unit("qa-refresh-http.service")
    probe = "curl -fsS --connect-timeout 1 --max-time 2 http://10.90.0.1:9999/"
    fw.wait_until_succeeds("curl -fsS --max-time 2 http://127.0.0.1:9999/")
    saved = fw.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0]
    client.fail(probe)
    # Legitimate initial boot: no live commit yet, so the timer uses saved intent.
    fw.succeed("systemctl start sentinel-fwsched.service")
    client.fail(probe)
    with subtest("live-only CLI policy remains active after the real periodic refresh"):
        commands = ["set firewall rule live-only from wan", "set firewall rule live-only action accept",
                    "set firewall rule live-only proto tcp", "set firewall rule live-only port 9999",
                    "commit", "exit"]
        script = "printf '%s\\n' " + " ".join(shlex.quote(c) for c in commands) + " | sentinel configure 2>&1"
        output = fw.succeed("su admin -c " + shlex.quote(script))
        assert "commit ok" in output and "error:" not in output.lower(), output
        assert fw.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0] == saved
        fw.succeed("grep -q '9999' /run/sentinel/running.toml")
        client.wait_until_succeeds(probe)
        fw.succeed("systemctl start sentinel-fwsched.service")
        fw.succeed("systemctl is-active velstra.service qa-refresh-http.service")
        # Require actual new connections, not only configuration acceptance.
        client.succeed(probe)
        fw.succeed("grep -q 'port = 9999' /run/sentinel/velstra.toml")
        assert fw.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0] == saved
    with subtest("invalid running intent never silently falls back to an older saved policy"):
        fw.succeed("cp -p /run/sentinel/running.toml /run/qa-refresh-running-backup")
        before = fw.succeed("sha256sum /run/sentinel/velstra.toml").split()[0]
        fw.succeed("printf 'invalid = [' > /run/sentinel/running.toml")
        fw.fail("systemctl start sentinel-fwsched.service")
        assert fw.succeed("sha256sum /run/sentinel/velstra.toml").split()[0] == before
        client.succeed(probe)
        fw.succeed("cp -p /run/qa-refresh-running-backup /run/sentinel/running.toml")
        # Normal successful service retry, never reset-failed to invent health.
        fw.succeed("systemctl start sentinel-fwsched.service")
        client.succeed(probe)
    with subtest("an explicitly named apply file keeps its original CLI meaning"):
        fw.succeed("sentinel apply /var/lib/sentinel/appliance.toml --out /run/sentinel/velstra.toml --reload velstra.service")
        client.fail(probe)
        fw.succeed("systemctl start sentinel-fwsched.service")
        client.succeed(probe)
    fw.succeed("test $(systemctl --failed --no-legend --plain | wc -l) -eq 0")
    print("FIREWALL_REFRESH_LIVE_INTENT_REAL_TRAFFIC_PASS", flush=True)
  '';
}
