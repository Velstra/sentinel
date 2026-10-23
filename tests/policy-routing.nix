{ pkgs, self, velstra }:
pkgs.testers.runNixOSTest {
  name = "sentinel-policy-routing-dual-stack-lifecycle";
  nodes.machine = {
    imports = [ self.nixosModules.sentinel ];
    virtualisation.memorySize = 2048;
    environment.systemPackages = [ pkgs.python3 pkgs.curl ];
  };
  testScript = ''
    import json
    import shlex
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("sentinel-boot-late.service")
    def apply(*commands):
        output = machine.succeed("printf '%s\\n' " + " ".join(shlex.quote(c) for c in [*commands, "commit", "save"]) + " | sentinel configure 2>&1", timeout=120)
        assert "commit ok: applied live" in output, output
        assert "installing policy route" not in output and "Command \\\"-" not in output, output
        machine.wait_until_succeeds("sentinel agent-query status | grep '^Ready$'", timeout=30)
    machine.succeed("ip netns add rp-client; ip netns add rp-server; ip link add rp-front type veth peer name client; ip link set client netns rp-client; ip link add rp-back type veth peer name server; ip link set server netns rp-server")
    machine.succeed("ip -n rp-client link set lo up; ip -n rp-client link set client up; ip -n rp-client addr add 192.0.2.2/24 dev client; ip -n rp-client route add default via 192.0.2.1; ip -n rp-server link set lo up; ip -n rp-server link set server up; ip -n rp-server addr add 198.51.100.2/24 dev server; ip -n rp-server route add default via 198.51.100.1")
    machine.succeed("ip -n rp-client -6 addr add 2001:db8:510::2/64 dev client nodad; ip -n rp-client -6 route add default via 2001:db8:510::1; ip -n rp-server -6 addr add 2001:db8:520::2/64 dev server nodad; ip -n rp-server -6 route add default via 2001:db8:520::1")
    apply("set interface rp-front zone lan", "set interface rp-front address 192.0.2.1/24", "set interface rp-front address6 2001:db8:510::1/64", "set interface rp-back zone lan", "set interface rp-back address 198.51.100.1/24", "set interface rp-back address6 2001:db8:520::1/64", "set firewall global default-action accept", "set firewall global stateful true", "set system sysctl net.ipv4.ip_forward value 1", "set system sysctl net.ipv6.conf.all.forwarding value 1")
    machine.succeed("mkdir /run/rp-web; echo route-data-plane > /run/rp-web/index.html")
    for label, address in [("v4", "198.51.100.2"), ("v6", "2001:db8:520::2")]:
        machine.succeed("systemd-run --unit=rp-web-" + label + " ip netns exec rp-server ${pkgs.python3}/bin/python3 -m http.server 8080 --bind " + address + " --directory /run/rp-web")
    web4 = "ip netns exec rp-client curl -4 -fsS --noproxy '*' --connect-timeout 1 --max-time 3 http://198.51.100.2:8080/ | grep route-data-plane"
    web6 = "ip netns exec rp-client curl -6 -g -fsS --noproxy '*' --connect-timeout 1 --max-time 3 http://[2001:db8:520::2]:8080/ | grep route-data-plane"
    def allowed(command):
        machine.wait_until_succeeds(command, timeout=20)
    def rules(family):
        return [r for r in json.loads(machine.succeed("ip " + family + " -j rule show")) if 10000 <= r.get("priority", 0) <= 19999]
    allowed(web4)
    allowed(web6)
    machine.succeed("ip -4 route add blackhole default table 201; ip -6 route add blackhole default table 201; ip -6 route add blackhole default table 202; ip -4 rule add priority 9000 from 203.0.113.0/24 table 203")
    with subtest("source and port selectors steer actual IPv4 traffic"):
        apply("set policy route only-v4 source 192.0.2.2/32", "set policy route only-v4 destination 198.51.100.2/32", "set policy route only-v4 proto tcp", "set policy route only-v4 destination-port 8080", "set policy route only-v4 table 201")
        assert len(rules("-4")) == 1 and not rules("-6")
        machine.fail(web4)
        allowed(web6)
    with subtest("IPv6 rules are observed, replaced and removed independently"):
        apply("set policy route only-v6 source 2001:db8:510::2/128", "set policy route only-v6 destination 2001:db8:520::2/128", "set policy route only-v6 proto tcp", "set policy route only-v6 destination-port 8080", "set policy route only-v6 table 202")
        machine.fail(web4)
        machine.fail(web6)
        apply("set firewall global log true")
        assert len(rules("-4")) == 1 and len(rules("-6")) == 1
        apply("delete policy route only-v4")
        assert not rules("-4") and len(rules("-6")) == 1
        allowed(web4)
        machine.fail(web6)
        apply("delete policy route only-v6")
        assert not rules("-4") and not rules("-6")
        allowed(web4)
        allowed(web6)
    with subtest("a port-only selector covers both families and can be disabled"):
        apply("set policy route both proto tcp", "set policy route both destination-port 8080", "set policy route both table 201")
        assert len(rules("-4")) == 1 and len(rules("-6")) == 1
        machine.fail(web4)
        machine.fail(web6)
        apply("set policy route both disabled true")
        assert not rules("-4") and not rules("-6")
        allowed(web4)
        allowed(web6)
        machine.succeed("ip -4 rule show | grep '^9000:.*203.0.113.0/24.*lookup 203'")
    print("ACTUAL_POLICY_ROUTING_DUAL_STACK_LIFECYCLE PASS", flush=True)
  '';
}
