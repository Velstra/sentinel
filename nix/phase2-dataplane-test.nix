{ pkgs, self }:
let
  echo = pkgs.writeText "phase2-echo.py" ''
    import socket, threading, time
    def tcp_client(conn, peer):
        with conn:
            while conn.recv(4096):
                conn.sendall((peer[0] + "\n").encode())
    def tcp():
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.bind(("::", 9090)); s.listen()
        while True:
            c, p = s.accept()
            threading.Thread(target=tcp_client, args=(c,p), daemon=True).start()
    threading.Thread(target=tcp, daemon=True).start()
    def icmp():
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        with open("/tmp/icmp-requests", "a", buffering=1) as log:
            while True:
                packet, peer = s.recvfrom(65535)
                off = (packet[0] & 15) * 4
                if len(packet) >= off + 8 and packet[off] == 8:
                    identifier = int.from_bytes(packet[off+4:off+6], "big")
                    log.write(f"{peer[0]} {identifier}\n")
    threading.Thread(target=icmp, daemon=True).start()
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.bind(("::", 9091))
    def late(peer):
        time.sleep(5)
        s.sendto(b"late", peer)
    while True:
        data, peer = s.recvfrom(4096)
        s.sendto((peer[0] + "\n").encode(), peer)
        if data == b"defer":
            threading.Thread(target=late, args=(peer,), daemon=True).start()
  '';
  host = ip4: ip6: vlan: gateway4: gateway6: { lib, ... }: {
    virtualisation.vlans = [ vlan ];
    networking.firewall.enable = false;
    networking.interfaces.eth1.ipv4.addresses = [{ address = ip4; prefixLength = 24; }];
    networking.interfaces.eth1.ipv6.addresses = [{ address = ip6; prefixLength = 64; }];
    networking.interfaces.eth1.ipv4.routes = [{ address = "0.0.0.0"; prefixLength = 0; via = gateway4; }];
    # Prefer the appliance over QEMU's management NIC router advertisement.
    networking.interfaces.eth1.ipv6.routes = [{ address = "::"; prefixLength = 0; via = gateway6; options.metric = "100"; }];
    environment.systemPackages = [ pkgs.python3 pkgs.netcat-openbsd pkgs.tcpdump ];
  };
in pkgs.testers.runNixOSTest {
  name = "sentinel-phase2-dataplane";
  nodes = {
    client = host "10.1.1.2" "2001:db8:101::2" 1 "10.1.1.1" "2001:db8:101::1";
    server = args: (host "10.2.2.2" "2001:db8:102::2" 2 "10.2.2.1" "2001:db8:102::1" args) // {
      systemd.services.phase2-echo = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${echo}";
      };
    };
    fw = { lib, ... }: {
      imports = [ self.nixosModules.sentinel ];
      networking.hostName = lib.mkForce "fw";
      virtualisation.vlans = [ 1 2 ];
      virtualisation.memorySize = 2048;
      virtualisation.cores = 2;
      networking.firewall.enable = lib.mkForce false;
      services.velstra.interface = lib.mkForce "eth1";
    };
  };
  testScript = ''
    import json, shlex, time
    start_all()
    for node in (client, server, fw):
        node.wait_for_unit("multi-user.target")
    fw.wait_for_unit("velstra.service")
    server.wait_for_unit("phase2-echo.service")
    server.wait_until_succeeds("ss -Hltn 'sport = :9090' | grep -q .", timeout=60)
    client.succeed("ip -6 route get 2001:db8:102::2 | grep -q 'dev eth1'")

    def python(node, code):
        return node.succeed("python3 -c " + shlex.quote(code))
    def show(what):
        return fw.succeed("sentinel show firewall " + what)
    def configure(*commands, persist=False):
        # A session edits the SAVED configuration: `commit` alone changes the
        # running box, and the next session starts again from what was saved.
        # `persist` saves too, for a change a later session has to see.
        tail = ["commit", "save", "exit"] if persist else ["commit", "exit"]
        script = "printf '%s\\n' " + " ".join(shlex.quote(c) for c in list(commands) + tail) + " | sentinel configure"
        output = fw.succeed("su admin -c " + shlex.quote(script))
        assert "error:" not in output.lower() and "commit failed" not in output.lower(), output
    inbound_seen = ""

    def unsolicited_from_wan():
        # Counted where it would land, on the LAN host's wire, so the answer
        # does not depend on whether anything there would have replied. Both
        # families, TCP and UDP, to ports no rule mentions.
        # The capture must be running before the first probe and must hand
        # over every packet before it stops. libpcap batches packets into
        # ring blocks it retires only on a timeout (1 s by default), and a
        # capture stopped sooner loses the unretired block: once the
        # firewall delivered RELATED ICMP errors (DP-10), the UDP probes got
        # their port-unreachable at once instead of waiting out `nc -w 1`,
        # the capture stopped within that second and the step read "0
        # admitted probes" although the client had answered every one.
        # Hence --immediate-mode, and a wait for 'listening' before probing.
        # Captured by port only and counted by source below, so a probe that
        # arrives with a rewritten source shows up in the failure message
        # instead of as an empty capture.
        client.succeed("rm -f /tmp/inbound.pcap /tmp/inbound.err; tcpdump --immediate-mode -n -U -i eth1 -w /tmp/inbound.pcap "
                       "'tcp dst port 9092 or udp dst port 9093' "
                       ">/dev/null 2>/tmp/inbound.err & echo $! >/tmp/inbound.pid")
        client.wait_until_succeeds("grep -q 'listening on eth1' /tmp/inbound.err", timeout=30)
        # The sender's view (not the firewall's: a capture there changed the
        # timing enough to hide the failure): who answers the probes, with
        # which TTL and MAC.
        server.succeed("rm -f /tmp/sent.pcap /tmp/sent.err; tcpdump --immediate-mode -n -U -i eth1 -w /tmp/sent.pcap "
                       "'port 9092 or port 9093 or icmp or icmp6' >/dev/null 2>/tmp/sent.err & echo $! >/tmp/sent.pid")
        server.wait_until_succeeds("grep -q 'listening on eth1' /tmp/sent.err", timeout=30)
        sent = []
        for address in ("10.1.1.2", "2001:db8:101::2"):
            sent.append(server.execute(f"nc -v -z -w 2 {address} 9092 2>&1"))
            sent.append(server.execute(f"echo probe | nc -v -u -w 1 {address} 9093 2>&1"))
        client.succeed("pid=$(cat /tmp/inbound.pid); kill -INT $pid; "
                       "for i in $(seq 100); do kill -0 $pid 2>/dev/null || exit 0; sleep 0.1; done; exit 1")
        server.succeed("pid=$(cat /tmp/sent.pid); kill -INT $pid; "
                       "for i in $(seq 100); do kill -0 $pid 2>/dev/null || exit 0; sleep 0.1; done; exit 1")
        arrived = client.succeed("tcpdump -n -r /tmp/inbound.pcap 2>/dev/null")
        global inbound_seen
        inbound_seen = (arrived + "probes: " + repr(sent) + "\nthe sender saw:\n"
                        + server.succeed("tcpdump -n -e -v -r /tmp/sent.pcap 2>/dev/null"))
        # Counted on the LAN host's capture only.
        return sum(1 for line in arrived.splitlines()
                   if " 10.2.2.2." in line or " 2001:db8:102::2." in line)
    lines = [
        "set interface eth1 zone lan", "set interface eth1 address 10.1.1.1/24",
        "set interface eth1 address6 2001:db8:101::1/64",
        "set interface eth2 zone wan", "set interface eth2 address 10.2.2.1/24",
        "set interface eth2 address6 2001:db8:102::1/64",
        "set firewall global stateful true", "set firewall global fail-closed true",
        "set firewall global conntrack udp 3", "set firewall global conntrack udp-stream 3",
        "set nat source static zone wan", "set nat source static to 203.0.113.10",
    ]
    for name, proto, port, action in [("allow-tcp", "tcp", 9090, "accept"), ("allow-udp", "udp", 9091, "accept"), ("deny-tcp", "tcp", 9099, "drop")]:
        lines += [f"set firewall rule {name} from lan", f"set firewall rule {name} proto {proto}",
                  f"set firewall rule {name} port {port}", f"set firewall rule {name} action {action}",
                  f"set firewall rule {name} log true"]
    for zone in ("lan", "wan"):
        for kind in (135, 136):
            name = f"nd-{zone}-{kind}"
            lines += [f"set firewall rule {name} from {zone}", f"set firewall rule {name} proto icmpv6",
                      f"set firewall rule {name} icmp-type {kind}", f"set firewall rule {name} action accept"]
    lines += ["set firewall rule allow-echo from lan", "set firewall rule allow-echo proto icmp",
              "set firewall rule allow-echo icmp-type echo-request", "set firewall rule allow-echo action accept",
              "set firewall rule allow-echo log true"]
    script = "printf '%s\\n' " + " ".join(shlex.quote(x) for x in lines + ["commit", "save", "exit"]) + " | sentinel configure"
    output = fw.succeed("su admin -c " + shlex.quote(script))
    assert "error:" not in output.lower() and "commit failed" not in output.lower(), output
    fw.wait_until_succeeds("ip -6 addr show eth2 | grep -q 2001:db8:102::1")
    fw.wait_until_succeeds("grep -q snat_address /run/sentinel/velstra.toml")

    with subtest("unsolicited WAN-to-LAN traffic is refused with no rule allowing it"):
        # The WAN zone states no default action, so the global default (drop)
        # decides. Nothing in the configuration permits WAN to LAN.
        crossed = unsolicited_from_wan()
        assert crossed == 0, f"{crossed} unsolicited WAN packets reached the LAN"
        # The control: the same probes, with a rule that admits them, do cross.
        # Without it a broken route would pass the check above for the wrong
        # reason.
        configure(
            "set firewall rule wan-probe-tcp from wan", "set firewall rule wan-probe-tcp proto tcp",
            "set firewall rule wan-probe-tcp port 9092", "set firewall rule wan-probe-tcp action accept",
            "set firewall rule wan-probe-udp from wan", "set firewall rule wan-probe-udp proto udp",
            "set firewall rule wan-probe-udp port 9093", "set firewall rule wan-probe-udp action accept",
            persist=True,
        )
        crossed = unsolicited_from_wan()
        assert crossed >= 4, f"only {crossed} admitted probes crossed: the path itself is broken; captured:\n{inbound_seen}"
        configure("delete firewall rule wan-probe-tcp", "delete firewall rule wan-probe-udp", persist=True)
        assert unsolicited_from_wan() == 0

    with subtest("TCP forwarding, checksums and static SNAT work across both families"):
        for address, result in [("10.2.2.2", "/tmp/tcp4"), ("2001:db8:102::2", "/tmp/tcp6")]:
            # Held across the later subtests, which take well over 90 s, and
            # patient enough to ride out the repair below: forwarding is off
            # from the sysctl until the unchanged commit restores it (~12 s
            # into a non-root commit), which TCP retransmission survives but a
            # 5 s receive timeout did not.
            code = ("import socket,time; s=socket.create_connection((" + repr(address) + ",9090),5); "
                    "s.settimeout(60); f=open(" + repr(result) + ",'ab',buffering=0); "
                    "exec(\"for i in range(300):\\n s.sendall(b'probe')\\n f.write(s.recv(200))\\n time.sleep(1)\")")
            client.succeed("python3 -c " + shlex.quote(code) + " >/tmp/tcp-probe.log 2>&1 &")
        client.wait_until_succeeds("grep -q 203.0.113.10 /tmp/tcp4", timeout=30)
        client.wait_until_succeeds("grep -q 2001:db8:101::2 /tmp/tcp6", timeout=30)
        states = json.loads(show("states"))
        assert any(s["phase"] == 3 and s["src"] == "10.1.1.2" for s in states), states
        assert any(s["phase"] == 3 and s["src"] == "2001:db8:101::2" for s in states), states

    with subtest("ICMP source NAT translates identifiers and repairs both checksums"):
        for identifier in (0, 65535):
            client.succeed(f"ping -n -e {identifier} -c 2 -W 2 10.2.2.2")
        server.wait_until_succeeds("test $(grep -c '^203.0.113.10 ' /tmp/icmp-requests) -ge 4")

    with subtest("live rules and unchanged commits preserve established flows"):
        fw.succeed("sysctl -qw net.ipv6.conf.all.forwarding=0")
        repaired = fw.succeed("su admin -c \"printf '%s\\n' commit exit | sentinel configure\"")
        assert "error:" not in repaired.lower(), repaired
        fw.succeed("test $(sysctl -n net.ipv6.conf.all.forwarding) = 1")
        before = fw.succeed("systemctl show -p InvocationID --value velstra.service").strip()
        update = "printf '%s\\n' 'set firewall zone lan default-action accept' 'set firewall rule deny-tcp log false' commit exit | sentinel configure"
        output = fw.succeed("su admin -c " + shlex.quote(update))
        assert "error:" not in output.lower() and "commit failed" not in output.lower(), output
        output = fw.succeed("su admin -c " + shlex.quote("printf 'commit\\nexit\\n' | sentinel configure"))
        assert "error:" not in output.lower() and "commit failed" not in output.lower(), output
        assert fw.succeed("systemctl show -p InvocationID --value velstra.service").strip() == before
        for address in ["10.2.2.2", "2001:db8:102::2"]:
            python(client, "import socket; s=socket.create_connection((" + repr(address) + ",9090),5); "
                   "s.settimeout(5); s.sendall(b'new-after-update'); assert s.recv(200)")
        sizes = [int(client.succeed("stat -c %s " + path)) for path in ("/tmp/tcp4", "/tmp/tcp6")]
        time.sleep(3)
        for path, size in zip(("/tmp/tcp4", "/tmp/tcp6"), sizes):
            grown = int(client.succeed("stat -c %s " + path))
            assert grown > size, f"{path} stopped at {grown} bytes: " + client.succeed("cat /tmp/tcp-probe.log; ss -tni")
        # Restore logging so the drop probe below must also produce an event,
        # and the LAN posture: every later check runs against the
        # configuration it was written for, not one this subtest left behind.
        # The session starts from the saved configuration, which never had the
        # LAN default-action (it was committed above, not saved), so committing
        # it puts the posture back; there is no zone entry left to delete.
        configure("set firewall rule deny-tcp log true")

    with subtest("UDP reply permission expires at the configured idle deadline"):
        python(client, "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(6); "
               "s.sendto(b'defer',('10.2.2.2',9091)); first=s.recv(200); assert b'203.0.113.10' in first; "
               "exec(\"try:\\n s.recv(200)\\n raise AssertionError('expired UDP reply was admitted')\\nexcept socket.timeout:\\n pass\")")
        states = json.loads(show("states"))
        assert not any(s["protocol"] == 17 and (s["src_port"] == 9091 or s["dst_port"] == 9091) for s in states), states

    with subtest("firewall reply state expires on its own, and for IPv6"):
        # The IPv4 check above cannot tell the two expiries apart: the late
        # reply is addressed to the SNAT address, so it dies when the NAT entry
        # does, whatever the firewall state says. IPv6 is not translated here,
        # so the only thing admitting a late reply through the WAN's drop
        # default is the stateful firewall entry — and it must have expired.
        python(client, "import socket; s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.settimeout(6); "
               "s.sendto(b'defer',('2001:db8:102::2',9091)); first=s.recv(200); assert b'2001:db8:101::2' in first, first; "
               "exec(\"try:\\n s.recv(200)\\n raise AssertionError('expired IPv6 UDP reply was admitted')\\nexcept socket.timeout:\\n pass\")")
        # The control: inside the deadline the same reply path is open.
        python(client, "import socket; s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.settimeout(3); "
               "s.sendto(b'echo',('2001:db8:102::2',9091)); assert b'2001:db8:101::2' in s.recv(200)")

    with subtest("drops and allows have exact named counters and ring events"):
        client.fail("nc -z -w 1 10.2.2.2 9099")
        counters = json.loads(show("counters"))
        rows = {r["rule"]: r for r in counters["rules"] if r["rule"]}
        assert rows["allow-tcp"]["accepted"] > 0 and rows["allow-tcp"]["bytes"] > 0, counters
        assert rows["deny-tcp"]["dropped"] > 0, counters
        events = []
        for _ in range(41):
            batch = [json.loads(line) for line in show("events").splitlines() if line.strip()]
            events.extend(batch)
            if len(batch) < 100:
                break
        assert any(e["rule"] == "deny-tcp" and e["action"] == "drop" for e in events), events
        assert any(e["rule"] == "allow-tcp" and e["action"] == "accept" and e["family"] == 6 for e in events), events
        assert counters["events_lost"] == 0, counters
        fw.fail("journalctl -b -u velstra --no-pager | grep -E 'Verifier error|BTF couldn.t be loaded'")

    with subtest("adding a zone keeps every other zone's policy ID and its connections"):
        # Release audit 8b6181 DP-13: ids were the rank of the zone name, so a
        # zone sorting first ("aaa") renumbered every other zone and the commit
        # reset all connection state on the box. Ids are now a hash of the
        # name; only a zone whose own id changed can lose state.
        import tomllib
        def ids():
            compiled = tomllib.loads(fw.succeed("cat /run/sentinel/velstra.toml"))
            return {p["name"]: p["id"] for p in compiled["policy"]}
        before_ids = ids()
        code = ("import socket,time; s=socket.create_connection(('10.2.2.2',9090),5); "
                "f=open('/tmp/held','ab',buffering=0); "
                "exec(\"for i in range(600):\\n s.sendall(b'held')\\n f.write(s.recv(200))\\n time.sleep(0.5)\")")
        client.succeed("python3 -c " + shlex.quote(code) + " >/tmp/held.log 2>&1 &")
        client.wait_until_succeeds("test -s /tmp/held", timeout=15)
        before = fw.succeed("systemctl show -p InvocationID --value velstra.service").strip()
        update = "printf '%s\\n' 'set interface guest0 type dummy' 'set interface guest0 zone aaa' commit save exit | sentinel configure"
        output = fw.succeed("su admin -c " + shlex.quote(update))
        assert "error:" not in output.lower() and "commit failed" not in output.lower(), output
        assert fw.succeed("systemctl show -p InvocationID --value velstra.service").strip() == before
        after_ids = ids()
        assert "aaa" in after_ids, after_ids
        for zone, policy in before_ids.items():
            assert after_ids[zone] == policy, (before_ids, after_ids)
        # The connection opened before the commit keeps being answered after it
        # (it runs for five minutes; a commit takes tens of seconds here).
        size = int(client.succeed("stat -c %s /tmp/held"))
        time.sleep(3)
        grown = int(client.succeed("stat -c %s /tmp/held"))
        assert grown > size, "the held connection stopped at the zone commit: " + client.succeed("cat /tmp/held.log")
        states = json.loads(show("states"))
        assert any(s["protocol"] == 6 and s["dst_port"] == 9090 for s in states), states
  '';
}
