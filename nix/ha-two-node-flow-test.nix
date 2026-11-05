{ pkgs, self }:
let
  secret = "two-node-flow-vm-only-credential-at-least-32-bytes";
  cluster = "two-node-flow-cluster-0123456789";
  appliance = node: (pkgs.formats.toml {}).generate "two-node-flow-member.toml" {
    system = {
      hostname = if node == 1 then "flow-primary" else "flow-secondary";
      config-sync = { inherit secret; peer = [ "10.3.0.${toString (3 - node)}:8080" ]; };
      conntrack-sync = {
        listen = "10.3.0.${toString node}:5429";
        peer = [ "10.3.0.${toString (3 - node)}:5429" ];
      };
      ha = {
        enabled = true;
        inherit cluster;
        inherit node;
        mode = "two-node";
        sync-interface = "eth3";
        heartbeat-listen = [ "10.3.0.${toString node}:5441" ];
        heartbeat-peer = [ "10.3.0.${toString (3 - node)}:5441" ];
        peer-timeout-ms = 1000;
        startup-delay-ms = 3000;
        priority = if node == 1 then 200 else 100;
        preempt = false;
      };
    };
    interface = [
      { name = "eth1"; zone = "wan"; address = "10.1.0.${toString node}/24"; }
      { name = "eth2"; zone = "lan"; address = "10.2.0.${toString node}/24"; }
      { name = "eth3"; zone = "control"; address = "10.3.0.${toString node}/24"; }
    ];
    firewall = { default_action = "drop"; stateful = true; fail_closed = true; };
    zone = {
      wan.default_action = "drop";
      lan.default_action = "drop";
      control.default_action = "accept";
    };
    rule = [ { name = "single-echo"; from = "lan"; proto = "tcp"; port = 8443; action = "accept"; } ];
    nat.source = [ { name = "shared-snat"; zone = "wan"; to = "10.1.0.100"; } ];
    protocols.vrrp = map (vip: {
      inherit (vip) name vrid;
      interface = "eth3";
      address-interface = vip.interface;
      virtual-address = [ vip.address ];
      prefix-length = 24;
      priority = if node == 1 then 200 else 100;
      preempt = false;
    }) [
      { name = "wan"; interface = "eth1"; vrid = 20; address = "10.1.0.100"; }
      { name = "lan"; interface = "eth2"; vrid = 21; address = "10.2.0.100"; }
    ];
  };
  member = node: { lib, ... }: {
    imports = [ self.nixosModules.sentinel ];
    virtualisation.vlans = [ 1 2 3 ];
    virtualisation.memorySize = 2048;
    virtualisation.cores = 2;
    networking.firewall.enable = lib.mkForce false;
    services.velstra.interface = lib.mkForce "eth1";
    services.velstra.appliance = lib.mkForce (appliance node);
    environment.systemPackages = [ pkgs.python3 pkgs.bpftools pkgs.tcpdump ];
    systemd.services.wren.environment.RUST_LOG = "wren::vrrp=debug";
    systemd.services.velstra.environment.RUST_LOG = "velstra::conntrack_sync=debug,velstra::ha=debug";
  };
  echo = pkgs.writeText "two-node-single-connection-echo.py" ''
    import json, socket, threading

    def serve(connection):
        with connection, connection.makefile("rb") as reader:
            for line in reader:
                connection.sendall(line)

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", 8443))
    listener.listen()
    with open("/tmp/accepted", "a", buffering=1) as accepted:
        while True:
            connection, peer = listener.accept()
            accepted.write(json.dumps({"host": peer[0], "port": peer[1]}) + "\n")
            threading.Thread(target=serve, args=(connection,), daemon=True).start()
  '';
  stream = pkgs.writeText "two-node-one-socket-stream.py" ''
    import json, os, socket, time

    def publish(status):
        with open("/tmp/stream-status.next", "w") as output:
            json.dump(status, output)
        os.replace("/tmp/stream-status.next", "/tmp/stream-status")

    # Exactly one connect call, fixed original tuple, no reconnect/retry path.
    connection = socket.socket()
    connection.settimeout(2.9)
    connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    connection.bind(("10.2.0.10", 41000))
    connection.connect(("10.1.0.10", 8443))
    status = {"count": 0, "maximum_gap": 0.0, "completed": False,
              "local": connection.getsockname(), "remote": connection.getpeername()}
    with connection, connection.makefile("rb") as reader:
        last = time.monotonic()
        while not os.path.exists("/tmp/stream-stop"):
            payload = (str(status["count"]) + "\n").encode()
            connection.sendall(payload)
            assert reader.readline() == payload, "single established TCP stream changed/reset"
            now = time.monotonic()
            status["maximum_gap"] = max(status["maximum_gap"], now - last)
            assert status["maximum_gap"] < 3.0, status
            last = now
            status["count"] += 1
            publish(status)
            time.sleep(0.02)
    assert status["count"] >= 100, status
    status["completed"] = True
    publish(status)
  '';
  oldMacProbe = pkgs.writeText "two-node-old-mac-syn.py" ''
    import socket, struct, sys, time

    def checksum(data):
        if len(data) % 2:
            data += b"\0"
        value = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
        while value >> 16:
            value = (value & 65535) + (value >> 16)
        return (~value) & 65535

    source = socket.inet_aton("10.2.0.10")
    destination = socket.inet_aton("10.1.0.10")
    tcp = struct.pack("!HHIIBBHHH", 41001, 8443, 424242, 0, 5 << 4, 2, 4096, 0, 0)
    pseudo = source + destination + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 777, 0, 64, 6, 0, source, destination)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    mac = lambda text: bytes.fromhex(text.replace(":", ""))
    local_mac = open("/sys/class/net/eth1/address").read().strip()
    frame = mac(sys.argv[1]) + mac(local_mac) + b"\x08\x00" + ip + tcp
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as packet:
        packet.bind(("eth1", 0))
        for _ in range(3):
            packet.send(frame)
            time.sleep(0.02)
  '';
in pkgs.testers.runNixOSTest {
  name = "sentinel-ha-two-node-established-snat-flow";
  nodes = {
    primary = member 1;
    secondary = member 2;
    client = {
      virtualisation.vlans = [ 2 ];
      virtualisation.memorySize = 512;
      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4.addresses = [ { address = "10.2.0.10"; prefixLength = 24; } ];
      networking.interfaces.eth1.ipv4.routes = [ { address = "10.1.0.0"; prefixLength = 24; via = "10.2.0.100"; } ];
      environment.systemPackages = [ pkgs.python3 pkgs.tcpdump ];
    };
    server = {
      virtualisation.vlans = [ 1 ];
      virtualisation.memorySize = 512;
      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4.addresses = [ { address = "10.1.0.10"; prefixLength = 24; } ];
      networking.interfaces.eth1.ipv4.routes = [ { address = "10.2.0.0"; prefixLength = 24; via = "10.1.0.100"; } ];
      environment.systemPackages = [ pkgs.python3 pkgs.tcpdump ];
      systemd.services.ha-flow-echo = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${echo}";
      };
    };
  };
  testScript = ''
    import json, re, shlex, time

    def py(source):
        return "${pkgs.python3}/bin/python3 -c " + shlex.quote(source)

    def status():
        return json.loads(client.succeed("cat /tmp/stream-status"))

    def progress(previous, amount, label):
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            client.succeed("systemctl is-active --quiet ha-flow-stream.service")
            current = status()
            assert current["maximum_gap"] < 3.0, (label, current)
            if current["count"] >= previous + amount:
                print(label, current)
                return current
            time.sleep(0.02)
        raise AssertionError("same established socket made no bounded progress: " + label)

    def diagnostic():
        for node in ((primary, secondary) if primary_alive else (secondary,)):
            print(node.name, node.execute("ip -br address; ip -s neigh; timeout 3 sentinel show ha; timeout 3 sentinel show vrrp; timeout 3 sentinel show firewall flows; timeout 3 sentinel show firewall statistics; cat /run/velstra/ha/role.json /run/velstra/ha/agent.json; bpftool -j map dump pinned /sys/fs/bpf/velstra-ha/deadline; ss -tnlp; journalctl -u wren -u velstra --no-pager -n 100")[1])
        for node in (client, server):
            print(node.name, node.execute("ip route; ip -s neigh; cat /tmp/stream-status /tmp/accepted 2>/dev/null; journalctl -u ha-flow-stream -u ha-flow-echo --no-pager -n 40")[1])
            print(node.execute("systemctl stop ha-flow-packets; ${pkgs.tcpdump}/bin/tcpdump -nn -tt -e -S -r /tmp/flow.pcap 2>/dev/null | tail -n 100")[1])

    start_all()
    primary_alive = True
    try:
        # Exactly two HA appliances and two traffic endpoints: no witness or
        # arbitration service, hidden controller vote, or synthetic role writer.
        assert {node.name for node in machines} == {"primary", "secondary", "client", "server"}
        for node in (primary, secondary, client, server):
            node.wait_for_unit("multi-user.target")
        for node in (primary, secondary):
            node.wait_for_unit("velstra.service")
            node.wait_for_unit("wren.service")
            node.succeed("! systemctl is-active --quiet sentinel-witness.service")
            node.succeed(py('import tomllib; c=tomllib.load(open("/var/lib/sentinel/appliance.toml","rb")); h=c["system"]["ha"]; assert h["mode"]=="two-node" and not h.get("witness") and not c["system"].get("ha-witness"); assert h["peer-timeout-ms"]==1000; assert c["firewall"]["stateful"] and c["firewall"]["default_action"]=="drop"'))
            node.wait_until_succeeds("journalctl -u velstra --no-pager | grep -q 'authenticated TCP listening'", timeout=60)
        primary.wait_until_succeeds("ip -o address show eth1 | grep -q 10.1.0.100 && ip -o address show eth2 | grep -q 10.2.0.100", timeout=30)
        secondary.succeed("! ip -o address show eth1 | grep -q 10.1.0.100 && ! ip -o address show eth2 | grep -q 10.2.0.100")
        primary.wait_until_succeeds(py('import json,time; r=json.load(open("/run/velstra/ha/role.json")); a=json.load(open("/run/velstra/ha/agent.json")); assert r["authority"]["owner"]==1 and r["deadline_ns"]>time.clock_gettime_ns(time.CLOCK_BOOTTIME) and a["forwarding_term"]==r["authority"]["term"]>0'), timeout=15)
        old_mac = primary.succeed("cat /sys/class/net/eth2/address").strip()
        server.wait_for_unit("ha-flow-echo.service")
        for node in (client, server):
            node.succeed("systemd-run --unit=ha-flow-packets ${pkgs.tcpdump}/bin/tcpdump -p -U -w /tmp/flow.pcap -i eth1 tcp port 8443")
            node.wait_until_succeeds("journalctl -u ha-flow-packets --no-pager | grep -q 'listening on eth1'", timeout=5)
        client.succeed("systemd-run --unit=ha-flow-stream ${pkgs.python3}/bin/python3 ${stream}")
        client.wait_until_succeeds("test -s /tmp/stream-status", timeout=8)
        baseline = progress(0, 50, "before fault")
        assert baseline["local"] == ["10.2.0.10", 41000] and baseline["remote"] == ["10.1.0.10", 8443], baseline
        accepted = [json.loads(line) for line in server.succeed("cat /tmp/accepted").splitlines()]
        assert len(accepted) == 1 and accepted[0]["host"] == "10.1.0.100", accepted
        translated = accepted[0]
        owner = json.loads(primary.succeed("cat /run/velstra/ha/role.json"))["authority"]
        # A flow entry AND a fresh complete matching-generation snapshot must
        # already exist on the real standby before disrupting its owner.
        secondary.wait_until_succeeds("sentinel show firewall flows | grep '10.2.0.10:41000' | grep '10.1.0.10:8443' | grep -q tcp", timeout=15)
        secondary.wait_until_succeeds(py('import json,time; r=json.load(open("/run/velstra/ha/role.json")); a=json.load(open("/run/velstra/ha/agent.json")); assert a["eligible"] and a["ready_term"]==r["authority"]["term"]>0 and a["policy"]==r["authority"]["policy"] and a["forwarding_term"]==0 and time.clock_gettime_ns(time.CLOCK_BOOTTIME)-a["updated_ns"]<100_000_000'), timeout=15)
        before = status()["count"]
        started = time.monotonic()
        primary.succeed("systemctl kill --kill-who=main --signal=SIGSTOP wren.service")
        # Both VIPs and actual data-plane acknowledgement, not desired election
        # state alone. The 1500ms ceiling follows the real replica freshness
        # budget; the 1000ms peer timeout cannot satisfy a 1-second assertion.
        while True:
            code, _ = secondary.execute(py('import json,time,subprocess; r=json.load(open("/run/velstra/ha/role.json")); a=json.load(open("/run/velstra/ha/agent.json")); assert r["authority"]["owner"]==2 and a["forwarding_term"]==r["authority"]["term"]>0 and r["vips_ready"] and r["deadline_ns"]>time.clock_gettime_ns(time.CLOCK_BOOTTIME); assert "10.1.0.100/24" in subprocess.check_output(["ip","-o","address","show","eth1"],text=True); assert "10.2.0.100/24" in subprocess.check_output(["ip","-o","address","show","eth2"],text=True)'))
            elapsed = time.monotonic() - started
            assert elapsed <= 1.5, f"warm two-node promotion exceeded replica budget: {elapsed:.3f}s"
            if code == 0:
                break
            time.sleep(0.005)
        successor = json.loads(secondary.succeed("cat /run/velstra/ha/role.json"))["authority"]
        assert successor["term"] > owner["term"] and successor["policy"] == owner["policy"], (owner, successor)
        primary.succeed(py('import json,time; r=json.load(open("/run/velstra/ha/role.json")); assert r["authority"]["owner"]==1 and r["deadline_ns"]<time.clock_gettime_ns(time.CLOCK_BOOTTIME)'))
        # The paused process leaves its old VIPs behind; packet fencing must
        # work independently of userspace removing those addresses.
        primary.succeed("ip -o address show eth2 | grep -q 10.2.0.100")
        after = progress(before, 15, "after SIGSTOP and expired old kernel lease")
        server.succeed("systemd-run --unit=old-mac-capture ${pkgs.tcpdump}/bin/tcpdump -p -U -w /tmp/old-mac.pcap -i eth1 'tcp src port 41001 and tcp dst port 8443'")
        server.wait_until_succeeds("journalctl -u old-mac-capture --no-pager | grep -q 'listening on eth1'", timeout=5)
        # Raw Ethernet targets the old MAC without changing the live stream's
        # neighbor table or creating a second accepted TCP connection.
        client.succeed("${pkgs.python3}/bin/python3 ${oldMacProbe} " + shlex.quote(old_mac))
        time.sleep(0.2)
        server.succeed("systemctl stop old-mac-capture")
        leaked = server.succeed("${pkgs.tcpdump}/bin/tcpdump -nn -r /tmp/old-mac.pcap 2>/dev/null")
        assert not leaked.strip(), "expired old-primary kernel guard leaked SYN: " + leaked
        before_crash = status()["count"]
        primary_alive = False
        primary.crash()
        after_crash = progress(before_crash, 50, "same socket after primary power loss")
        assert secondary.succeed("sentinel show ha").splitlines()[0] == "HA Master"
        client.succeed("touch /tmp/stream-stop")
        client.wait_until_succeeds(py('import json; assert json.load(open("/tmp/stream-status"))["completed"]'), timeout=5)
        final = status()
        assert final["count"] >= 100 and final["maximum_gap"] < 3.0, final
        client.succeed("test $(systemctl show ha-flow-stream.service -p ExecMainStatus --value) = 0")
        accepted_after = [json.loads(line) for line in server.succeed("cat /tmp/accepted").splitlines()]
        assert accepted_after == [translated], (translated, accepted_after)
        for node in (client, server):
            node.succeed("systemctl stop ha-flow-packets")
            resets = node.succeed("${pkgs.tcpdump}/bin/tcpdump -nn -r /tmp/flow.pcap 'tcp[13] & 4 != 0' 2>/dev/null")
            assert not resets.strip(), f"{node.name} observed TCP RST: {resets}"
        wire = server.succeed("${pkgs.tcpdump}/bin/tcpdump -nn -r /tmp/flow.pcap 'src host 10.1.0.100 and dst host 10.1.0.10 and tcp dst port 8443' 2>/dev/null")
        ports = {int(port) for port in re.findall(r"IP 10\.1\.0\.100\.(\d+) > 10\.1\.0\.10\.8443:", wire)}
        assert ports == {translated["port"]}, (ports, translated)
        print(f"two-node warm promotion {elapsed:.3f}s; unchanged SNAT tuple {translated}; one TCP socket; final {final}")
    except BaseException:
        # Do not let a stopped controller or a powered-off VM hide the original
        # assertion behind a diagnostic command that can no longer return.
        try:
            diagnostic()
        except Exception as error:
            print("diagnostic collection incomplete:", error)
        raise
  '';
}
