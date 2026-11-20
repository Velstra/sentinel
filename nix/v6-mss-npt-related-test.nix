# IPv6 parity on a live data plane: the MSS clamp, and ICMPv6 errors about
# connections behind NPTv6 or quoting extension headers.
#
# * A WAN interface with `mss 1400` clamped IPv4 SYNs only, so a PPPoE uplink
#   left every IPv6 connection to discover the smaller MTU by path-MTU discovery.
#   An IPv6 SYN now advertises the ceiling less the 20 extra header bytes.
# * An ICMPv6 error about a connection behind NPTv6 quotes the inside host by
#   its EXTERNAL address, while the firewall tracks the flow under the internal
#   one: the error was not recognised as RELATED, so a Packet Too Big was dropped
#   behind a deny-by-default WAN, and even where it got through, the quote named
#   an address the host does not hold and its stack ignored it. Now the lookup
#   and the quote are translated like the envelope (in and out).
# * A quote whose packet carried an extension header was refused outright; the
#   chain is now walked to the transport header.
#
# Every assertion is on the receiving host's own stack (the PMTU its socket
# learnt, the MSS on the wire, the error its socket got), never on firewall
# counters alone.
{ pkgs, self }:
let
  py = "${pkgs.python3}/bin/python3";
  # Upstream: a UDP service that answers each datagram with a Packet Too Big
  # (MTU 1280) quoting the datagram as it arrived. The first payload byte picks
  # the quote: `P` plain, `E` with a destination-options header in front of the
  # UDP header (as if the sender had added one).
  ptbServer = pkgs.writeText "qa-ptb-server.py" ''
    import socket, struct
    rx = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    rx.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
    rx.bind(("::", 9999))
    raw = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    while True:
        data, anc, _, peer = rx.recvmsg(65535, socket.CMSG_SPACE(20))
        local = next(d[:16] for level, kind, d in anc
                     if level == socket.IPPROTO_IPV6 and kind == socket.IPV6_PKTINFO)
        src = socket.inet_pton(socket.AF_INET6, peer[0])
        udp = struct.pack("!HHHH", peer[1], 9999, 8 + len(data), 0) + data
        if data[:1] == b"E":
            ext = bytes([17, 0, 1, 4, 0, 0, 0, 0])  # next UDP, 8 bytes, PadN
            inner = ext + udp
            next_header = 60
        else:
            inner = udp
            next_header = 17
        quote = struct.pack("!IHBB", 6 << 28, len(inner), next_header, 63) + src + local + inner
        ptb = struct.pack("!BBHI", 2, 0, 0, 1280) + quote[:1232]
        raw.sendto(ptb, (peer[0], 0, 0, 0))
  '';
  # LAN: send one 1400-byte datagram, then wait for the socket's path MTU.
  ptbClient = pkgs.writeText "qa-ptb-client.py" ''
    import socket, sys, time
    IPV6_MTU = 24
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.connect((sys.argv[1], 9999))
    s.send(sys.argv[2].encode() + b"x" * 1399)
    deadline = time.time() + 20
    while time.time() < deadline:
        mtu = s.getsockopt(socket.IPPROTO_IPV6, IPV6_MTU)
        if mtu == 1280:
            print("path MTU", mtu)
            sys.exit(0)
        time.sleep(0.5)
    sys.exit(f"path MTU still {mtu}: the Packet Too Big never reached this socket")
  '';
  # Upstream: a datagram to a closed LAN port must come back as an error this
  # socket recognises (ECONNREFUSED) — only if the quote names the address the
  # datagram was sent to.
  refusedProbe = pkgs.writeText "qa-refused.py" ''
    import socket, sys
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.bind((sys.argv[2], 0))
    s.connect((sys.argv[1], 9))
    for _ in range(3):
        s.send(b"probe")
        try:
            s.recv(16)
        except ConnectionRefusedError:
            print("refused, as the inside host said")
            sys.exit(0)
        except socket.timeout:
            continue
    sys.exit("no port-unreachable this socket recognised")
  '';
  # LAN: connect, read to EOF, print the byte count.
  fetch = pkgs.writeText "qa-fetch.py" ''
    import socket, sys
    s = socket.create_connection((sys.argv[1], 8080), timeout=10)
    total = 0
    while True:
        part = s.recv(65536)
        if not part:
            break
        total += len(part)
    print(total)
  '';
  listener = pkgs.writeText "qa-listen.py" ''
    import socket
    s = socket.socket(socket.AF_INET6)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.bind(("::", 8080))
    s.listen(16)
    while True:
        c, _ = s.accept()
        c.sendall(b"x" * 65536)
        c.close()
  '';
in
pkgs.testers.runNixOSTest {
  name = "sentinel-v6-mss-npt-related";
  globalTimeout = 900;
  nodes = {
    firewall = { lib, ... }: {
      imports = [ self.nixosModules.sentinel ];
      virtualisation.vlans = [ 1 2 ];
      virtualisation.memorySize = 2048;
      networking.firewall.enable = lib.mkForce false;
      networking.useDHCP = false;
      services.velstra.interface = lib.mkForce "eth1";
      services.velstra.appliance = lib.mkForce (pkgs.writeText "v6-mss-npt.toml" ''
        [system]
        hostname = "v6-parity-fw"
        [[interface]]
        name = "eth1"
        zone = "wan"
        address = "203.0.113.1/24"
        address6 = "2001:db8:1::1/64"
        mss = "1400"
        [[interface]]
        name = "eth2"
        zone = "lan"
        address = "10.84.1.254/24"
        address6 = "fd00:84:0:1::1/64"
        [firewall]
        default_action = "drop"
        stateful = true
        [zone.lan]
        default_action = "accept"
        [zone.wan]
        default_action = "drop"
        [[rule]]
        name = "discard-in"
        from = "wan"
        proto = "udp"
        port = 9
        action = "accept"
        [[nat.npt66]]
        name = "v6"
        interface = "eth1"
        internal = "fd00:84::/48"
        external = "2001:db8:84::/48"
      '');
      environment.systemPackages = [ pkgs.bpftools ];
    };
    upstream = { lib, ... }: {
      # Only the fixture's own addresses: the test framework's automatic
      # 2001:db8:<vlan>::/64 ones would win IPv6 source selection and leave
      # through the firewall from an address nothing routes back to.
      virtualisation.vlans = [ 1 ];
      virtualisation.memorySize = 768;
      networking.firewall.enable = false;
      networking.useDHCP = false;
      networking.interfaces.eth1.ipv4.addresses = lib.mkForce [ { address = "203.0.113.66"; prefixLength = 24; } ];
      networking.interfaces.eth1.ipv4.routes = [ { address = "10.84.1.0"; prefixLength = 24; via = "203.0.113.1"; } ];
      networking.interfaces.eth1.ipv6.addresses = lib.mkForce [
        { address = "2001:db8:1::66"; prefixLength = 64; }
        { address = "2001:db8:1::77"; prefixLength = 64; }
      ];
      networking.interfaces.eth1.ipv6.routes = [
        { address = "2001:db8:84::"; prefixLength = 48; via = "2001:db8:1::1"; }
      ];
      environment.systemPackages = [ pkgs.tcpdump ];
      systemd.services.qa-ptb = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${py} ${ptbServer}";
      };
      systemd.services.qa-web = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${py} ${listener}";
      };
    };
    lan = { lib, ... }: {
      # Only the fixture's own addresses: the test framework's automatic
      # 2001:db8:<vlan>::/64 ones would win IPv6 source selection and leave
      # through the firewall from an address nothing routes back to.
      virtualisation.vlans = [ 2 ];
      virtualisation.memorySize = 512;
      networking.firewall.enable = false;
      networking.useDHCP = false;
      networking.interfaces.eth1.ipv4.addresses = lib.mkForce [ { address = "10.84.1.10"; prefixLength = 24; } ];
      networking.interfaces.eth1.ipv6.addresses = lib.mkForce [ { address = "fd00:84:0:1::10"; prefixLength = 64; } ];
      networking.defaultGateway = { address = "10.84.1.254"; interface = "eth1"; };
      networking.defaultGateway6 = { address = "fd00:84:0:1::1"; interface = "eth1"; };
      environment.systemPackages = [ pkgs.ethtool ];
    };
  };
  testScript = ''
    import contextlib

    failures = []

    @contextlib.contextmanager
    def case(title):
        """A subtest whose failure is recorded, so one run shows every case."""
        with subtest(title):
            try:
                yield
            except Exception as error:
                failures.append(f"{title}: {error}")
                print(f"CASE FAILED: {title}: {error}")
    start_all()
    for node in (firewall, upstream, lan):
        node.wait_for_unit("multi-user.target")
    firewall.wait_for_unit("velstra.service")
    for link in ("eth1", "eth2"):
        firewall.wait_until_succeeds(f"ip -details link show {link} | grep -q xdp", timeout=60)
    for node in (upstream, lan):
        node.wait_until_succeeds("! ip -6 address show dev eth1 | grep -q tentative", timeout=30)
    upstream.wait_until_succeeds("ss -lun | grep -q ':9999 '", timeout=20)
    upstream.wait_until_succeeds("ss -ltn | grep -q ':8080 '", timeout=20)
    # Offload off: the clamped SYN's checksum is then the one on the wire,
    # so a wrong checksum adjustment fails the connection (DP-09's lesson).
    lan.succeed("ethtool -K eth1 tx off rx off")

    def why():
        return ("\ncompiled:\n" + firewall.execute("cat /run/sentinel/velstra.toml")[1]
                + "\nstatistics:\n" + firewall.execute("sentinel show firewall statistics")[1]
                + "\nagent:\n" + firewall.execute("journalctl -u velstra --no-pager -n 40")[1])

    def capture(node, name, flt, count=""):
        """Start a packet capture on `node`; returns a function that stops it
        and returns what it saw."""
        node.succeed(
            f"systemd-run --unit=qa-cap-{name} --property=Type=exec "
            f"${pkgs.bash}/bin/sh -c \"${pkgs.tcpdump}/bin/tcpdump --immediate-mode -nn -v {count} "
            f"-i eth1 '{flt}' > /tmp/{name}.txt 2>/tmp/{name}.err\"")
        node.wait_until_succeeds(f"grep -q listening /tmp/{name}.err", timeout=20)

        def stop():
            node.execute(f"systemctl stop qa-cap-{name}")
            return node.execute(f"cat /tmp/{name}.txt")[1]
        return stop

    def syn_mss(target, family_filter, name):
        stop = capture(upstream, name, f"{family_filter} and tcp dst port 8080", "-c 1")
        lan.succeed(f"${py} ${fetch} {target}")
        upstream.wait_until_succeeds(f"! systemctl is-active --quiet qa-cap-{name}", timeout=20)
        return stop()

    def v6_flows():
        return firewall.execute(
            "bpftool -j map dump name FW_FLOWS | ${py} -c "
            "'import json,sys; [print(e[\"key\"]) for e in json.load(sys.stdin)"
            " if e[\"key\"][-3] == \"0x06\"]' | head -40")[1]

    with case("the agent loaded the configuration"):
        status, agent_log = firewall.execute("journalctl -u velstra --no-pager | grep -E 'velstra\\[[0-9]+\\]: Error'")
        assert status != 0, "the agent reported an error:\n" + agent_log
        compiled = firewall.succeed("cat /run/sentinel/velstra.toml")
        assert "mss = 1400" in compiled and "[[npt66]]" in compiled, compiled

    with case("control: an IPv4 SYN leaving the WAN advertises the 1400 ceiling"):
        text = syn_mss("203.0.113.66", "ip", "syn4")
        assert "mss 1400" in text, text + why()

    with case("an IPv6 SYN leaving the WAN advertises the ceiling less 20 bytes"):
        text = syn_mss("2001:db8:1::66", "ip6", "syn6")
        assert "mss 1380" in text, text + why()
        # The transfer behind it completes: the adjusted checksum is right.
        got = lan.succeed("${py} ${fetch} 2001:db8:1::66").strip()
        assert got == "65536", got

    with case("NPTv6: a Packet Too Big reaches the inside host and its socket learns the MTU"):
        at_lan = capture(lan, "ptb-lan", "icmp6 or udp port 9999")
        at_up = capture(upstream, "ptb-up", "icmp6 or udp port 9999")
        status, out = lan.execute("${py} ${ptbClient} 2001:db8:1::66 P 2>&1")
        seen_lan, seen_up = at_lan(), at_up()
        assert status == 0, (out + "\nat lan:\n" + seen_lan + "\nat upstream:\n" + seen_up
                             + "\nv6 flows:\n" + v6_flows() + why())

    with case("a Packet Too Big quoting an extension header is RELATED too"):
        lan.succeed("${py} ${ptbClient} 2001:db8:1::77 E >&2")

    def npt_out(host_words):
        """RFC 6296 for this fixture's /48s: the LAN host's external address."""
        def oc(a, b):
            s = a + b
            return ((s & 0xffff) + (s >> 16)) & 0xffff
        def psum(words):
            total = 0
            for w in words:
                total = oc(total, w)
            return total
        delta = oc(psum([0xfd00, 0x0084, 0x0000]), ~psum([0x2001, 0x0db8, 0x0084]) & 0xffff)
        subnet = oc(host_words[0], delta) or 0xffff
        return "2001:db8:84:%x::%x" % (subnet, host_words[1])

    with case("NPTv6 outward: the inside host's port-unreachable names the external address"):
        external = npt_out([0x0001, 0x10])
        upstream.succeed(f"${py} ${refusedProbe} {external} 2001:db8:1::66 >&2")

    assert not failures, "\n".join(failures)
  '';
}
