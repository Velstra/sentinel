# Egress policy applies before source translation, including local WAN traffic.
{ pkgs, sentinelModule, sentinel }:
pkgs.testers.runNixOSTest {
  name = "sentinel-masquerade-policy";
  nodes.machine = {
    imports = [ sentinelModule ];
    networking.hostName = pkgs.lib.mkForce "machine";
    virtualisation.memorySize = 2048;
    virtualisation.vlans = [ 1 ];
    boot.kernel.sysctl."net.ipv4.ip_forward" = 1;
    environment.systemPackages = [ pkgs.curl pkgs.python3 ];
  };
  nodes.peer = {
    networking.hostName = "peer";
    networking.useDHCP = false;
    networking.firewall.enable = false;
    virtualisation.vlans = [ 1 ];
    networking.interfaces.eth1.ipv4.addresses = [ { address = "198.18.90.2"; prefixLength = 24; } ];
    environment.systemPackages = [ pkgs.python3 ];
  };
  testScript = ''
    import json
    import shlex

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("sentinel-boot-late.service")
    peer.wait_for_unit("multi-user.target")
    python = "${pkgs.python3}/bin/python3"
    port = 44300

    def apply(*lines):
        source = "\n".join([*lines, "commit", "save", "exit", ""])
        output = machine.succeed("su admin -c " + shlex.quote("printf %s " + shlex.quote(source) + " | ${sentinel}/bin/sentinel configure 2>&1"))
        assert "commit ok: applied live" in output and "saved /" in output, output
        ready = json.loads(machine.succeed("${sentinel}/bin/sentinel agent-query 'interface eth1'"))
        assert ready["ready"] and ready["egress"], ready

    def drops():
        stats = machine.succeed("${sentinel}/bin/sentinel agent-query stats")
        return int(next(line.split()[-1] for line in stats.splitlines() if line.strip().startswith("egress_dropped ")))

    def observe(forwarded, permitted):
        global port
        port += 1
        marker = "/run/nat-capture-" + str(port)
        capture = "import socket,time,pathlib,json; s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800)); s.bind(('eth1',0)); s.settimeout(0.1); count=0; pathlib.Path(" + repr(marker + "-ready") + ").touch(); end=time.monotonic()+2;\nwhile time.monotonic()<end:\n try: p=s.recv(65535)\n except TimeoutError: continue\n if len(p)<54 or p[23]!=6: continue\n off=14+(p[14]&15)*4\n if len(p)>off+13 and int.from_bytes(p[off+2:off+4],'big')==18092 and p[off+13]&0x12==2: count+=1\npathlib.Path(" + repr(marker + ".json") + ").write_text(json.dumps({'syns':count}))\n"
        peer.succeed("systemd-run --unit=nat-capture-" + str(port) + " " + python + " -u -c " + shlex.quote(capture))
        peer.wait_until_succeeds("test -e " + marker + "-ready", timeout=10)
        before = drops()
        prefix = "ip netns exec nat-policy-client " if forwarded else ""
        code, body = machine.execute(prefix + "curl -4 -fsS --noproxy '*' --local-port " + str(port) + " --connect-timeout 1 --max-time 2 http://198.18.90.2:18092/")
        peer.wait_until_succeeds("test -e " + marker + ".json", timeout=10)
        seen = json.loads(peer.succeed("cat " + marker + ".json"))["syns"]
        delta = drops() - before
        if permitted:
            assert code == 0 and "actual-nat-policy-ok" in body and seen > 0, (forwarded, code, body, seen)
        else:
            assert code == 28 and seen == 0 and delta > 0, (forwarded, code, body, seen, delta)

    machine.succeed("ip netns add nat-policy-client")
    machine.succeed("ip link add lan-policy type veth peer name client-policy")
    machine.succeed("ip link set client-policy netns nat-policy-client")
    for command in ["ip link set lo up", "ip link set client-policy up", "ip addr add 10.90.0.2/24 dev client-policy", "ip route add default via 10.90.0.1"]:
        machine.succeed("ip netns exec nat-policy-client " + command)
    peer.succeed("mkdir -p /run/nat-policy-web; printf actual-nat-policy-ok > /run/nat-policy-web/index.html")
    peer.succeed("systemd-run --unit=nat-policy-web " + python + " -m http.server 18092 --bind 198.18.90.2 --directory /run/nat-policy-web")
    peer.wait_for_open_port(18092, addr="198.18.90.2", timeout=15)

    with subtest("NAT and local connections retain stateful replies under WAN ingress default drop"):
        apply("set interface eth1 address 198.18.90.1/24", "set interface eth1 zone wan", "set interface lan-policy address 10.90.0.1/24", "set interface lan-policy zone lan", "set firewall global default-action accept", "set firewall global stateful true", "set firewall zone wan default-action drop", "set nat source internet zone wan")
        observe(True, True)
        assert "198.18.90.1 - -" in peer.succeed("journalctl -u nat-policy-web --no-pager")
        observe(False, True)

    with subtest("an outbound denial blocks translated and host-originated traffic at egress"):
        apply("set firewall rule outbound from wan", "set firewall rule outbound direction out", "set firewall rule outbound proto tcp", "set firewall rule outbound port 18092", "set firewall rule outbound action drop")
        observe(True, False)
        observe(False, False)
        apply("set firewall rule outbound action accept")
        observe(True, True)
        observe(False, True)

    with subtest("source CIDRs match the original source before NAT translation"):
        apply("set firewall rule outbound action drop", "set firewall rule outbound source 10.90.0.3/32")
        observe(True, True)
        apply("set firewall rule outbound source 10.90.0.2/32")
        observe(True, False)
        observe(False, True)
        apply("set firewall rule outbound source 198.18.90.1/32")
        observe(True, True)
        observe(False, False)
        apply("delete firewall rule outbound")

    with subtest("a destination blocklist stops packets before they reach the peer"):
        apply("set firewall zone wan block 198.18.90.2/32")
        observe(True, False)
        observe(False, False)
        apply("delete firewall zone wan", "set firewall zone wan default-action drop")
        observe(True, True)
        observe(False, True)

    with subtest("local ICMP uses state tracking and remains subject to explicit outbound policy"):
        machine.succeed("ping -4 -c 1 -W 1 198.18.90.2")
        apply("set firewall rule echo from wan", "set firewall rule echo direction out", "set firewall rule echo proto icmp", "set firewall rule echo action drop")
        before = drops()
        machine.fail("ping -4 -c 1 -W 1 198.18.90.2")
        assert drops() > before
        apply("delete firewall rule echo")
        machine.succeed("ping -4 -c 1 -W 1 198.18.90.2")
  '';
}
