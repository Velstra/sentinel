# Native-to-generic replacement must never remove the last ingress protection.
{ pkgs, sentinelModule, sentinel, velstra }:
let
  policy = pkgs.writeText "mode-policy.toml" ''
    default_action = "pass"
    [[policy]]
    id = 7
    default_action = "pass"
    drop_icmp = true
    [[interface]]
    name = "eth1"
    policy = 7
    mss = 1400
  '';
in pkgs.testers.runNixOSTest {
  name = "sentinel-xdp-mode-transition";
  nodes = {
    fw = { lib, ... }: {
      imports = [ sentinelModule ];
      networking.hostName = lib.mkForce "fw";
      services.velstra.interface = lib.mkForce "eth0";
      virtualisation.vlans = [ 1 ];
      virtualisation.memorySize = 2048;
      systemd.network.networks."05-mode-test" = {
        matchConfig.Name = "eth1";
        networkConfig.Address = [ "198.18.90.1/24" ];
      };
      environment.systemPackages = [ pkgs.bpftools pkgs.curl ];
    };
    client = {
      virtualisation.vlans = [ 1 ];
      networking.useDHCP = false;
      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4.addresses = [ { address = "198.18.90.2"; prefixLength = 24; } ];
      environment.systemPackages = [ pkgs.curl ];
    };
  };
  testScript = ''
    import json
    import shlex

    start_all()
    fw.wait_for_unit("multi-user.target")
    client.wait_for_unit("multi-user.target")
    fw.wait_until_succeeds("ip addr show eth1 | grep 198.18.90.1")
    client.wait_until_succeeds("ip addr show eth1 | grep 198.18.90.2")
    state = "/sys/fs/bpf/mode-test"
    agent = "${velstra}/bin/velstra"
    query = "${sentinel}/bin/sentinel agent-query --socket /run/mode-test.sock "
    index = fw.succeed("cat /sys/class/net/eth1/ifindex").strip()
    native = state + "/xdp-" + index + "-driver"
    generic = state + "/xdp-" + index + "-skb"
    guard = state + "/handoff-" + index
    egress = state + "/egress-" + index
    ping = "ping -c 1 -W 1 198.18.90.1"
    web = "curl -fsS --noproxy '*' --max-time 3 http://198.18.90.1:18088/"

    def start(name, ready=True):
        fw.succeed("systemd-run --unit=" + name + " --property=Restart=no " + agent +
            " run --iface eth1 --xdp-mode auto --config ${policy} --datapath-state-dir " + state +
            " --query-socket /run/mode-test.sock")
        if ready:
            fw.wait_until_succeeds(query + "status | grep '^Ready$'", timeout=30)
            fw.succeed("systemctl is-active --quiet " + name)

    with subtest("the actual underlay and HTTP service work before filtering"):
        fw.succeed("mkdir -p /run/mode-web; printf mode-switch-ok > /run/mode-web/index.html")
        fw.succeed("systemd-run --unit=mode-web ${pkgs.python3}/bin/python3 -m http.server 18088 --directory /run/mode-web")
        fw.wait_for_open_port(18088)
        client.succeed(ping)
        assert "mode-switch-ok" in client.succeed(web)

    with subtest("auto starts with actual native enforcement at the normal MTU"):
        start("mode-first")
        fw.succeed("test -e " + native + "; test ! -e " + generic)
        client.fail(ping)
        assert "mode-switch-ok" in client.succeed(web)
        fw.succeed("systemctl stop mode-first.service")

    with subtest("a partial jumbo-MTU replacement retains a real ingress guard"):
        # Keep the original TC hook alive but place a real incompatible object
        # at its public pin. Startup will fail AFTER the XDP mode handoff.
        shadow = "/sys/fs/bpf/mode-egress-saved"
        fw.succeed("mv " + egress + " " + shadow)
        fw.succeed("bpftool map create " + egress + " type array key 4 value 4 entries 1 name bad_egress")
        fw.succeed("ip link set dev eth1 mtu 9000")
        start("mode-broken", ready=False)
        fw.wait_until_succeeds("systemctl is-failed --quiet mode-broken.service", timeout=30)
        fw.succeed("journalctl -u mode-broken --no-pager -o cat | grep 'persistent ingress guard'")
        fw.succeed("test -e " + guard + "; test -e " + generic + "; test ! -e " + native)
        client.fail(ping)
        client.fail(web)
        assert "mode-switch-ok" in fw.succeed(web)

    with subtest("the pinned guard alone blocks packets with no XDP hook or daemon"):
        # Recreate the kernel state of a crash between native unpin and SKB
        # attach: the failed process owns no descriptors, only the guard remains.
        fw.succeed("rm " + generic)
        # The saved egress link must not mask a missing ingress guard by
        # dropping every reply. Detach it too: only the ingress guard remains.
        fw.succeed("bpftool link detach pinned " + shadow)
        link = json.loads(fw.succeed("ip -j link show eth1"))[0]
        assert not link.get("xdp"), link
        fw.succeed("test -e " + guard)
        client.fail(ping)
        client.fail(web)
        assert "mode-switch-ok" in fw.succeed(web)

    with subtest("retry recovers at jumbo MTU and retires the guard after complete apply"):
        fw.succeed("rm " + egress + "; rm " + shadow)
        start("mode-recovered")
        fw.succeed("test -e " + generic + "; test ! -e " + native + "; test ! -e " + guard)
        fw.succeed("test \"$(cat /sys/class/net/eth1/mtu)\" = 9000")
        status = json.loads(fw.succeed(query + shlex.quote("interface eth1")))
        assert status["ready"] is True and status["policy"] == 7 and status["egress"] is True, status
        client.fail(ping)
        assert "mode-switch-ok" in client.succeed(web)
        fw.succeed("systemctl stop mode-recovered.service")
        client.fail(ping)
        assert "mode-switch-ok" in client.succeed(web)
        fw.succeed(agent + " detach --datapath-state-dir " + state)
        client.succeed(ping)
  '';
}
