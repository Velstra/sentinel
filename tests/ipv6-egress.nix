# Real dual-stack policy enforcement at TC egress, including header chains.
{ pkgs, sentinelModule, sentinel }:
pkgs.testers.runNixOSTest {
  name = "sentinel-ipv6-egress";
  nodes.machine = {
    imports = [ sentinelModule ];
    networking.hostName = pkgs.lib.mkForce "machine";
    virtualisation.memorySize = 2048;
    virtualisation.vlans = [ 1 ];
    environment.systemPackages = [ pkgs.python3 pkgs.curl ];
  };
  nodes.peer = {
    networking.hostName = "peer";
    networking.useDHCP = false;
    networking.firewall.enable = false;
    virtualisation.vlans = [ 1 ];
    networking.interfaces.eth1.ipv4.addresses = [ { address = "198.18.80.2"; prefixLength = 24; } ];
    networking.interfaces.eth1.ipv6.addresses = [ { address = "2001:db8:80::2"; prefixLength = 64; } ];
    environment.systemPackages = [ pkgs.python3 ];
  };
  testScript = ''
    import json
    import shlex

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("sentinel-boot-late.service")
    peer.wait_for_unit("multi-user.target")
    python = "${pkgs.python3}/bin/python3"

    def apply(*lines):
        source = "\n".join([*lines, "commit", "save", "exit", ""])
        output = machine.succeed("su admin -c " + shlex.quote("printf %s " + shlex.quote(source) + " | ${sentinel}/bin/sentinel configure 2>&1"))
        assert "commit ok: applied live" in output and "saved /" in output, output
        ready = json.loads(machine.succeed("${sentinel}/bin/sentinel agent-query 'interface eth1'"))
        assert ready["ready"] and ready["egress"], ready

    def tcp(family, allowed=True):
        address = "198.18.80.2" if family == 4 else "[2001:db8:80::2]"
        code, output = machine.execute("curl -g -" + str(family) + " -fsS --noproxy '*' --connect-timeout 1 --max-time 3 http://" + address + ":18090/")
        assert (code == 0) == allowed, (family, allowed, code, output)
        if allowed:
            assert "actual-egress-ok" in output, output

    def tcp_pair(v4=True, v6=True):
        tcp(4, v4)
        tcp(6, v6)

    def udp(family, allowed=True):
        address = "198.18.80.2" if family == 4 else "2001:db8:80::2"
        source = "import socket,sys; s=socket.socket(socket.AF_INET" + ("6" if family == 6 else "") + ",socket.SOCK_DGRAM); s.settimeout(1); s.connect((" + repr(address) + ",18091)); s.send(b'probe');\ntry: reply=s.recv(64)\nexcept TimeoutError: sys.exit(2)\nassert reply==b'echo:probe',reply\n"
        code, output = machine.execute(python + " -c " + shlex.quote(source))
        assert code == (0 if allowed else 2), (family, allowed, code, output)

    def dropped():
        stats = machine.succeed("${sentinel}/bin/sentinel agent-query stats")
        return int(next(line.split()[-1] for line in stats.splitlines() if line.strip().startswith("egress_dropped ")))

    def options_tcp(allowed=True):
        source = "import socket,sys; s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM); s.settimeout(1); s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_DSTOPTS,bytes([6,0,1,4,0,0,0,0]));\ntry:\n s.connect(('2001:db8:80::2',18090)); s.sendall(b'GET / HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n'); data=bytes()\n while True:\n  part=s.recv(4096)\n  if not part: break\n  data+=part\nexcept TimeoutError: sys.exit(2)\nassert b'actual-egress-ok' in data,data\n"
        code, output = machine.execute(python + " -c " + shlex.quote(source))
        assert code == (0 if allowed else 2), (allowed, code, output)

    peer.succeed("mkdir -p /run/egress-web; printf actual-egress-ok > /run/egress-web/index.html")
    peer.succeed("systemd-run --unit=egress-web " + python + " -m http.server 18090 --bind :: --directory /run/egress-web")
    peer.wait_for_open_port(18090)
    echo = "import socket; s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0); s.bind(('::',18091));\nwhile True:\n data,peer=s.recvfrom(2048); s.sendto(b'echo:'+data,peer)\n"
    peer.succeed("systemd-run --unit=egress-udp " + python + " -u -c " + shlex.quote(echo))
    peer.wait_until_succeeds("ss -H -lun 'sport = :18091' | grep -q .")

    with subtest("dual-stack TCP and UDP controls use an active egress hook"):
        apply("set interface eth1 address 198.18.80.1/24", "set interface eth1 address6 2001:db8:80::1/64", "set interface eth1 zone wan", "set firewall global default-action accept", "set firewall global stateful true", "set firewall rule neighbour-out from wan", "set firewall rule neighbour-out direction out", "set firewall rule neighbour-out proto icmpv6", "set firewall rule neighbour-out action accept")
        assert "actual-egress-ok" in machine.wait_until_succeeds("curl -g -6 -fsS --noproxy '*' --connect-timeout 1 --max-time 3 http://[2001:db8:80::2]:18090/", timeout=15)
        tcp_pair()
        udp(4)
        udp(6)

    with subtest("generic outbound TCP deny and live rule update cover both families"):
        before = dropped()
        apply("set firewall rule outbound from wan", "set firewall rule outbound direction out", "set firewall rule outbound proto tcp", "set firewall rule outbound port 18090", "set firewall rule outbound action drop")
        tcp_pair(False, False)
        assert dropped() > before
        udp(4)
        udp(6)
        apply("set firewall rule outbound action accept")
        tcp_pair()

    with subtest("family scope changes retire the old family verdict"):
        apply("set firewall rule outbound action drop", "set firewall rule outbound family ipv6")
        tcp_pair(True, False)
        apply("set firewall rule outbound family ipv4")
        tcp_pair(False, True)
        apply("delete firewall rule outbound")
        tcp_pair()

    with subtest("source and destination IPv6 CIDRs constrain egress matches"):
        for field, mismatch, match in [("source", "2001:db8:80::3/128", "2001:db8:80::1/128"), ("destination", "2001:db8:80::3/128", "2001:db8:80::2/128")]:
            apply("set firewall rule scoped from wan", "set firewall rule scoped direction out", "set firewall rule scoped proto tcp", "set firewall rule scoped port 18090", "set firewall rule scoped action drop", "set firewall rule scoped " + field + " " + mismatch)
            tcp_pair()
            apply("set firewall rule scoped " + field + " " + match)
            tcp_pair(True, False)
            apply("delete firewall rule scoped")
            tcp_pair()

    with subtest("an ingress-only rule does not prohibit outbound connections"):
        apply("set firewall rule incoming from wan", "set firewall rule incoming direction in", "set firewall rule incoming proto tcp", "set firewall rule incoming port 18090", "set firewall rule incoming action drop")
        tcp_pair()
        apply("delete firewall rule incoming")

    with subtest("UDP port denial is enforced independently of TCP"):
        apply("set firewall rule datagrams from wan", "set firewall rule datagrams direction out", "set firewall rule datagrams proto udp", "set firewall rule datagrams port 18091", "set firewall rule datagrams action drop")
        udp(4, False)
        udp(6, False)
        tcp_pair()
        apply("delete firewall rule datagrams")
        udp(4)
        udp(6)

    with subtest("IPv6 destination blocklist drops at egress rather than only on replies"):
        tcp(6)
        apply("set firewall zone wan block 2001:db8:80::2/128")
        before = dropped()
        tcp_pair(True, False)
        udp(6, False)
        assert dropped() > before
        apply("delete firewall zone wan")
        tcp_pair()
        udp(6)

    with subtest("ICMPv6 type filtering leaves ND and TCP usable"):
        machine.succeed("ping -6 -c 1 -W 1 2001:db8:80::2")
        apply("set firewall rule echoes from wan", "set firewall rule echoes direction out", "set firewall rule echoes proto icmpv6", "set firewall rule echoes icmp-type 128", "set firewall rule echoes action drop")
        machine.fail("ping -6 -c 1 -W 1 2001:db8:80::2")
        machine.succeed("ping -4 -c 1 -W 1 198.18.80.2")
        tcp(6)
        apply("delete firewall rule echoes")
        machine.succeed("ping -6 -c 1 -W 1 2001:db8:80::2")

    with subtest("actual Destination Options TCP packets face the same L4 policy"):
        capture = "import socket,pathlib,time; s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x86dd)); s.bind(('eth1',0)); s.settimeout(1); pathlib.Path('/run/options-capture-ready').touch(); end=time.monotonic()+10;\nwhile time.monotonic()<end:\n try: p=s.recv(65535)\n except TimeoutError: continue\n if len(p)>=62 and p[20]==60 and p[54]==6: pathlib.Path('/run/dstopts-seen').touch(); break\n"
        peer.succeed("systemd-run --unit=egress-options-capture " + python + " -u -c " + shlex.quote(capture))
        peer.wait_for_unit("egress-options-capture.service")
        peer.wait_until_succeeds("test -e /run/options-capture-ready", timeout=10)
        options_tcp()
        peer.wait_until_succeeds("test -e /run/dstopts-seen", timeout=10)
        apply("set firewall rule options from wan", "set firewall rule options direction out", "set firewall rule options proto tcp", "set firewall rule options port 18090", "set firewall rule options action drop")
        options_tcp(False)
        apply("delete firewall rule options")
        options_tcp()

    with subtest("truncated and overlong header chains cannot escape through default allow"):
        capture = "import socket,pathlib,json,time; s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x86dd)); s.bind(('eth1',0)); s.settimeout(0.2); counts={0x43121:0,0x43122:0,0x43123:0}; pathlib.Path('/run/raw-capture-ready').touch(); end=time.monotonic()+3;\nwhile time.monotonic()<end:\n try: p=s.recv(65535)\n except TimeoutError: continue\n if len(p)>=54:\n  label=int.from_bytes(p[14:18],'big')&0xfffff\n  if label in counts: counts[label]+=1\npathlib.Path('/run/raw-capture.json').write_text(json.dumps(counts))\n"
        peer.succeed("systemd-run --unit=egress-raw-capture " + python + " -u -c " + shlex.quote(capture))
        peer.wait_until_succeeds("test -e /run/raw-capture-ready", timeout=10)
        mac = peer.succeed("cat /sys/class/net/eth1/address").strip()
        # AF_PACKET reports TC_ACT_SHOT as ENOBUFS. Permit that only for
        # negative probes; peer capture and the kernel drop counter still prove
        # enforcement, and the valid marker must send and arrive successfully.
        sender = "import socket,struct,pathlib,errno; dst=bytes.fromhex(" + repr(mac.replace(":", "")) + "); src=bytes.fromhex(pathlib.Path('/sys/class/net/eth1/address').read_text().replace(':',str())); eth=dst+src+bytes.fromhex('86dd'); s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x86dd)); s.bind(('eth1',0));\ndef send(label,next,payload,blocked=False):\n h=struct.pack('!IHBB16s16s',0x60000000|label,len(payload),next,64,socket.inet_pton(socket.AF_INET6,'2001:db8:80::1'),socket.inet_pton(socket.AF_INET6,'2001:db8:80::2')); frame=eth+h+payload\n try: written=s.send(frame)\n except OSError as error:\n  if not blocked or error.errno!=errno.ENOBUFS: raise\n  print('EXPECTED_TC_DROP',label,flush=True)\n else: assert written==len(frame),written\nchain=bytes([60,0,1,4,0,0,0,0])*8+bytes([6,0,1,4,0,0,0,0])+bytes(20)\nfor _ in range(3):\n send(0x43122,60,bytes([6,255]),True); send(0x43123,60,chain,True); send(0x43121,59,bytes())\n"
        before = dropped()
        machine.succeed(python + " -c " + shlex.quote(sender))
        peer.wait_until_succeeds("test -e /run/raw-capture.json", timeout=10)
        counts = json.loads(peer.succeed("cat /run/raw-capture.json"))
        assert counts["274721"] > 0, counts
        assert counts["274722"] == 0 and counts["274723"] == 0, counts
        assert dropped() >= before + 6
  '';
}
