# C15 SYN proxy on an edge box as it is really deployed (DP-31): the WAN zone
# drops by default and masquerades, a port-forward remaps its port to a LAN
# server (8080 -> 80), a second one fronts a server that speaks first
# (2525 -> 25), and a routed rule admits another server-first service (9443).
# `checks.synproxy` proves the splice on a routed, default-accept, NAT-free
# path; none of what this check covers ran there:
#
#  * the admitting ACK leaves the proxy as a SYN with a rewritten IP header,
#    and the port-forward's DNAT must patch THAT header, not the one the
#    packet arrived with (a stale base was dropped as a bad checksum);
#  * a remapped port means the server answers from 80 while the client
#    dialled 8080, and both halves of the proxy must find one connection;
#  * the ACK the proxy sends the server never crosses an egress hook, so the
#    firewall must learn of it, or a server's banner is refused as invalid
#    until the client happens to speak;
#  * `syn-protect` must survive commit, save, an unrelated commit and a
#    reboot (DP-31-persist).
#
# Every scenario runs and the failures are reported together, so one run
# shows every defect that is still present.
{ pkgs, self }:
let
  banner = ./synproxy-banner.py;
in
pkgs.testers.runNixOSTest {
  name = "sentinel-synproxy-edge";
  globalTimeout = 1800;
  nodes = {
    client =
      { pkgs, ... }:
      {
        virtualisation.vlans = [ 1 ];
        networking = {
          useNetworkd = true;
          useDHCP = false;
          firewall.enable = false;
          interfaces.eth1.ipv4.addresses = [
            {
              address = "10.1.0.9";
              prefixLength = 24;
            }
          ];
          interfaces.eth1.ipv4.routes = [
            {
              address = "10.2.0.0";
              prefixLength = 24;
              via = "10.1.0.1";
            }
          ];
        };
        environment.systemPackages = [ pkgs.curl pkgs.python3 ];
      };
    server =
      { pkgs, ... }:
      {
        virtualisation.vlans = [ 2 ];
        networking = {
          useNetworkd = true;
          useDHCP = false;
          firewall.enable = false;
          interfaces.eth1.ipv4.addresses = [
            {
              address = "10.2.0.2";
              prefixLength = 24;
            }
          ];
          defaultGateway = {
            address = "10.2.0.1";
            interface = "eth1";
          };
        };
        systemd.services.web = {
          wantedBy = [ "multi-user.target" ];
          after = [ "network-online.target" ];
          script = ''
            mkdir -p /srv/web && echo hello-from-edge > /srv/web/index.html
            exec ${pkgs.python3}/bin/python3 -m http.server 80 --directory /srv/web
          '';
        };
        systemd.services.banner = {
          wantedBy = [ "multi-user.target" ];
          after = [ "network-online.target" ];
          script = "exec ${pkgs.python3}/bin/python3 ${banner} serve 25 9443";
        };
      };
    fw =
      { lib, ... }:
      {
        imports = [ self.nixosModules.sentinel ./test-network-seed.nix ];
        networking.hostName = lib.mkForce "fw";
        networking.firewall.enable = lib.mkForce false;
        networking.interfaces.eth1.ipv4.addresses = [
          {
            address = "10.1.0.1";
            prefixLength = 24;
          }
        ];
        networking.interfaces.eth2.ipv4.addresses = [
          {
            address = "10.2.0.1";
            prefixLength = 24;
          }
        ];
        virtualisation.vlans = [
          1
          2
        ];
        virtualisation.memorySize = 2048;
        boot.kernel.sysctl = {
          "net.ipv4.ip_forward" = 1;
          "net.ipv4.conf.all.rp_filter" = 0;
          "net.ipv4.conf.default.rp_filter" = 0;
          "net.ipv4.conf.all.accept_local" = 1;
        };
        services.velstra.interface = lib.mkForce "eth1";
      };
  };
  testScript = ''
    import re

    failures = []

    def scenario(name, body):
        try:
            with subtest(name):
                body()
        except Exception as error:
            failures.append(f"{name}: {error}")
            print(f"SCENARIO FAILED: {name}: {error}")

    def configure(lines):
        quoted = " ".join("'" + line + "'" for line in lines)
        return fw.succeed(
            f"su admin -c \"printf '%s\\n' {quoted} exit | sentinel configure\" 2>&1"
        )

    def counter(name):
        text = fw.succeed("sentinel show firewall statistics")
        m = re.search(rf"^\s*{name}\s+(\d+)", text, re.M)
        return int(m.group(1)) if m else 0

    def proxied(what, command, attempts=30):
        """`command` succeeds on the client AND the proxy challenged it.

        Retried because a commit only writes the agent's file; a connection
        made before the agent re-reads it goes through unproxied and proves
        nothing, which is why success alone is never accepted."""
        last = ""
        for _ in range(attempts):
            base = counter("synproxy_challenged")
            status, output = client.execute(command)
            last = output.strip()[-300:]
            if status == 0 and counter("synproxy_challenged") > base:
                return
            fw.sleep(2)
        raise AssertionError(f"{what}: never both completed and was proxied; last: {last}")

    def agent_proxies(n):
        got = int(fw.succeed("grep -c '^\\[\\[synproxy\\]\\]' /run/sentinel/velstra.toml || true").strip() or 0)
        assert got == n, f"the agent runs {got} [[synproxy]] entries, expected {n}"

    def datapath_enforces():
        # The WAN zone drops by default, and nothing admits port 80 from it:
        # reaching the server directly would mean the datapath is not running
        # (a dead datapath under kernel forwarding passes every check above).
        client.fail("curl -s --max-time 4 http://10.2.0.2:80/")
        fw.fail("journalctl -u velstra.service | grep -q 'Error: loading'")

    def web_through_forward():
        proxied(
            "HTTP via the remapping port-forward 8080 -> 80",
            "curl -s --max-time 8 http://10.1.0.1:8080/ | grep -q hello-from-edge",
        )

    def banner_routed():
        proxied(
            "server-first service, routed (9443)",
            "python3 ${banner} probe 10.2.0.2 9443",
        )

    def banner_through_forward():
        proxied(
            "server-first service via the port-forward 2525 -> 25",
            "python3 ${banner} probe 10.1.0.1 2525",
        )

    def persisted(where, committed=True):
        shown = fw.succeed(
            "su admin -c \"printf '%s\\n' show exit | sentinel configure\" 2>&1"
        )
        for port in ("8080", "9443", "2525"):
            assert f"syn-protect {port}" in shown, f"{where}: show configuration lacks syn-protect {port}:\n{shown}"
        # running.toml lives on /run and is written by a commit, so a freshly
        # booted box has none until the first one; it runs the saved file.
        paths = ["/var/lib/sentinel/appliance.toml"]
        if committed:
            paths.append("/run/sentinel/running.toml")
        for path in paths:
            got = int(fw.succeed(f"grep -c '^\\[\\[firewall.syn-protect\\]\\]' {path} || true").strip() or 0)
            assert got == 3, f"{where}: {path} holds {got} syn-protect entries, expected 3"

    def boot():
        fw.wait_for_unit("multi-user.target")
        fw.wait_for_unit("velstra.service")
        fw.wait_until_succeeds("ip addr show eth2 | grep -q 10.2.0.1", timeout=30)

    start_all()
    boot()
    server.wait_for_unit("web.service")
    server.wait_for_unit("banner.service")
    server.wait_until_succeeds("ss -Hltn 'sport = :80' | grep -q .", timeout=60)
    server.wait_until_succeeds("ss -Hltn 'sport = :25' | grep -q .", timeout=60)
    server.wait_until_succeeds("ss -Hltn 'sport = :9443' | grep -q .", timeout=60)
    client.wait_for_unit("multi-user.target")

    configure([
        "set interface eth1 zone wan",
        "set interface eth2 zone lan",
        "set firewall zone wan default-action drop",
        "set firewall zone lan default-action accept",
        "set nat source wan-masq zone wan",
        "set nat destination web zone wan",
        "set nat destination web proto tcp",
        "set nat destination web port 8080",
        "set nat destination web to 10.2.0.2:80",
        "set nat destination smtp zone wan",
        "set nat destination smtp proto tcp",
        "set nat destination smtp port 2525",
        "set nat destination smtp to 10.2.0.2:25",
        "set firewall rule banner-in from wan",
        "set firewall rule banner-in to lan",
        "set firewall rule banner-in proto tcp",
        "set firewall rule banner-in port 9443",
        "set firewall rule banner-in action accept",
        "set firewall syn-protect 8080",
        "set firewall syn-protect 9443",
        "set firewall syn-protect 2525",
        "commit",
        "save",
    ])
    fw.wait_for_unit("velstra.service")
    fw.wait_until_succeeds("grep -q '^\\[\\[synproxy\\]\\]' /run/sentinel/velstra.toml", timeout=30)

    scenario("the datapath is loaded and enforcing", datapath_enforces)
    scenario("syn-protect is in show, running and saved config after commit + save",
             lambda: persisted("after save"))
    scenario("remapping port-forward 8080 -> 80 behind the proxy", web_through_forward)
    scenario("server speaks first, routed through a masquerading box", banner_routed)
    scenario("server speaks first, through a port-forward", banner_through_forward)

    def unrelated_commit():
        configure(["set firewall rule banner-in log true", "commit"])
        fw.sleep(3)
        agent_proxies(3)
        web_through_forward()
    scenario("an unrelated commit keeps the proxy", unrelated_commit)

    def after_reboot():
        configure(["save"])
        fw.shutdown()
        fw.start()
        boot()
        fw.wait_until_succeeds("grep -q '^\\[\\[synproxy\\]\\]' /run/sentinel/velstra.toml", timeout=60)
        agent_proxies(3)
        persisted("after reboot", committed=False)
        datapath_enforces()
        web_through_forward()
        banner_routed()
        banner_through_forward()
    scenario("the proxy survives a reboot", after_reboot)

    stats = fw.succeed("sentinel show firewall statistics")
    print(stats)
    assert not failures, "SYN-proxy edge scenarios failed:\n  " + "\n  ".join(failures)
  '';
}
