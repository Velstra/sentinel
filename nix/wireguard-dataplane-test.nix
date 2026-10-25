{ pkgs, self }:
let
  fwKey = "ICOioMTTlfQE/2NndOoEntortz+0tZ5Hll0AEM7tdmE=";
  fwPub = "6gUqcU72dUQr2VqzOWxiON1qzkzIOQD7SkZjPjPFWXs=";
  clientKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
  clientPub = "pOCSkrZRwni5dyxWn1+puxPZBrRqtoyd+dwrRAn4ogk=";
  echo = pkgs.writeText "wg-echo.py" ''
    import socket, threading
    def serve(port):
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.bind(("::", port)); s.listen()
        while True:
            conn, peer = s.accept()
            try:
                with conn:
                    conn.sendall(b"protected\n")
                    while data := conn.recv(65536):
                        conn.sendall(data)
            except (ConnectionResetError, BrokenPipeError):
                # Readiness probes and clients may close without draining the
                # greeting. They must not terminate the listening test server.
                continue
    threading.Thread(target=serve, args=(9090,), daemon=True).start()
    serve(9099)
  '';
in pkgs.testers.runNixOSTest {
  name = "sentinel-wireguard-dataplane";
  nodes = {
    fw = { lib, ... }: {
      imports = [ self.nixosModules.sentinel ];
      networking.hostName = lib.mkForce "fw";
      networking.firewall.enable = lib.mkForce false;
      virtualisation.vlans = [ 1 ];
      virtualisation.memorySize = 2048;
      environment.systemPackages = [ pkgs.bpftools ];
      services.velstra.interface = lib.mkForce "eth1";
      systemd.services.wg-echo = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${echo}";
      };
    };
    client = {
      virtualisation.vlans = [ 1 ];
      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4.addresses = [{ address = "10.66.0.2"; prefixLength = 24; }];
      networking.wireguard.interfaces.wg0 = {
        ips = [ "10.9.0.2/24" "fd00:9::2/64" ];
        privateKey = clientKey;
        listenPort = 51821;
        peers = [{ publicKey = fwPub; allowedIPs = [ "10.9.0.1/32" "fd00:9::1/128" ]; endpoint = "10.66.0.1:51820"; }];
      };
      environment.systemPackages = [ pkgs.python3 pkgs.wireguard-tools ];
    };
  };
  testScript = ''
    import json, shlex
    start_all()
    for node in (fw, client):
        node.wait_for_unit("multi-user.target")
    fw.wait_for_unit("velstra.service")
    fw.wait_for_open_port(9090)
    fw.wait_for_open_port(9099)

    def configure(lines):
        script = "printf '%s\\n' " + " ".join(shlex.quote(x) for x in lines + ["commit", "save", "exit"]) + " | sentinel configure"
        output = fw.succeed("su admin -c " + shlex.quote(script))
        assert "error:" not in output.lower(), output

    lines = ["set interface eth1 zone wan", "set interface eth1 address 10.66.0.1/24",
             "set interface wg0 type wireguard", "set interface wg0 zone vpn",
             "set interface wg0 address 10.9.0.1/24", "set interface wg0 address6 fd00:9::1/64",
             "set vpn wireguard wg0 private-key ${fwKey}", "set vpn wireguard wg0 listen-port 51820",
             "set vpn wireguard wg0 peer ${clientPub} allowed-ips 10.9.0.2/32",
             "set vpn wireguard wg0 peer ${clientPub} allowed-ips fd00:9::2/128",
             "set vpn wireguard wg0 peer ${clientPub} endpoint 10.66.0.2:51821"]
    for name, zone, proto, port, action in [("tunnel", "wan", "udp", 51820, "accept"), ("vpn-allow", "vpn", "tcp", 9090, "accept"), ("vpn-deny", "vpn", "tcp", 9099, "drop")]:
        lines += [f"set firewall rule {name} from {zone}", f"set firewall rule {name} proto {proto}",
                  f"set firewall rule {name} port {port}", f"set firewall rule {name} action {action}", f"set firewall rule {name} log true"]
    configure(lines)

    def connection(address, port):
        code = f"import socket; s=socket.create_connection(({address!r},{port}),2); assert s.recv(100)==b'protected\\n'"
        return "python3 -c " + shlex.quote(code)

    with subtest("encrypted IPv4 and IPv6 packets obey the VPN zone"):
        for address in ("10.9.0.1", "fd00:9::1"):
            client.wait_until_succeeds(connection(address, 9090), timeout=30)
            client.fail(connection(address, 9099))
            # Large transfers exercise segmentation, MTU and checksum offloads,
            # including removal of the classifier's temporary Ethernet header.
            code = (f"import socket; s=socket.create_connection(({address!r},9090),5); "
                    "assert s.recv(100)==b'protected\\n'; payload=bytes(range(256))*1024; s.sendall(payload); "
                    "out=bytearray(); exec('while len(out)<len(payload):\\n part=s.recv(65536)\\n assert part\\n out.extend(part)'); assert out==payload")
            client.succeed("python3 -c " + shlex.quote(code))
        client.succeed("wg show wg0 latest-handshakes | grep -Eq '[1-9][0-9]*$'")
        counters = json.loads(fw.succeed("sentinel show firewall counters"))
        rows = {r["rule"]: r for r in counters["rules"] if r["rule"]}
        assert rows["vpn-allow"]["accepted"] > 0, counters
        assert rows["vpn-deny"]["dropped"] > 0, counters
        assert counters["events_lost"] == 0, counters
        events = []
        for _ in range(41):
            batch = [json.loads(line) for line in fw.succeed("sentinel show firewall events").splitlines()]
            events.extend(batch)
            if len(batch) < 100:
                break
        else:
            raise AssertionError("packet event stream did not drain")
        for family in (4, 6):
            assert any(e["family"] == family and e["rule"] == "vpn-deny" and e["action"] == "drop" for e in events), events
        links = json.loads(fw.succeed("bpftool -j link show"))
        assert any(l.get("devname") == "wg0" and l.get("attach_type") == "tcx_egress" for l in links), links

    with subtest("no-op commit preserves the tunnel and removing a peer revokes it live"):
        index = fw.succeed("cat /sys/class/net/wg0/ifindex")
        configure([])
        assert fw.succeed("cat /sys/class/net/wg0/ifindex") == index
        client.succeed(connection("10.9.0.1", 9090))
        configure(["delete vpn wireguard wg0 peer ${clientPub}"])
        fw.wait_until_succeeds("test -z \"$(wg show wg0 peers)\"")
        client.fail(connection("10.9.0.1", 9090))
  '';
}
