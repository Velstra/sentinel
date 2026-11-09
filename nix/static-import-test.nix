# Route-policy regression: real Sentinel CLI -> Wren -> kernel FIB -> independent
# TCP/UDP endpoints, with replies forced back through the firewall. No mock FIB.
{ pkgs, self }:
let
  reference = pkgs.writeText "static-import-reference.py" ''
    import socketserver, threading
    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            while True:
                data = self.request.recv(4096)
                if not data: break
                self.request.sendall(data)
    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            sock.sendto(data, self.client_address)
    tcp = socketserver.ThreadingTCPServer(("0.0.0.0", 18590), TCP)
    # A wildcard UDP socket may answer from the primary WAN address rather
    # than the queried /32. Connected clients correctly reject that reply.
    # Bind each independent endpoint so its response has the tested identity.
    for address in ("198.19.244.1", "198.19.244.129"):
        udp = socketserver.ThreadingUDPServer((address, 18591), UDP)
        threading.Thread(target=udp.serve_forever, daemon=True).start()
    tcp.serve_forever()
  '';
  probe = pkgs.writeText "static-import-probe.py" ''
    import json, secrets, socket, sys
    result = []
    for target in ("198.19.244.1", "198.19.244.129"):
        for proto, port in (("tcp", 18590), ("udp", 18591)):
            payload = secrets.token_bytes(128)
            source, delivered = None, False
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM) as sock:
                sock.settimeout(1)
                try:
                    sock.connect((target, port))
                    source = sock.getsockname()[0]
                    sock.sendall(payload)
                    data = b""
                    while len(data) < len(payload):
                        chunk = sock.recv(4096)
                        if not chunk: break
                        data += chunk
                    delivered = data == payload
                except OSError:
                    pass
            result.append({"target": target, "protocol": proto, "source": source, "delivered": delivered})
    print(json.dumps(result))
  '';
in
pkgs.testers.runNixOSTest {
  name = "sentinel-static-import";
  nodes = {
    fw = { lib, ... }: {
      imports = [ self.nixosModules.sentinel ./test-network-seed.nix ];
      networking.hostName = lib.mkForce "static-import-fw";
      networking.firewall.enable = lib.mkForce false;
      virtualisation.vlans = [ 1 2 ];
      virtualisation.memorySize = 1536;
      services.velstra.interface = lib.mkForce "eth1";
      networking.interfaces = {
        eth1.ipv4.addresses = [ { address = "10.10.0.1"; prefixLength = 24; } ];
        eth2.ipv4.addresses = [ { address = "10.11.0.1"; prefixLength = 24; } ];
      };
    };
    reference = { ... }: {
      virtualisation.vlans = [ 1 ];
      virtualisation.memorySize = 512;
      networking.firewall.enable = false;
      networking.interfaces = {
        eth1.ipv4 = {
          addresses = [
            { address = "10.10.0.2"; prefixLength = 24; }
            { address = "198.19.244.1"; prefixLength = 32; }
            { address = "198.19.244.129"; prefixLength = 32; }
          ];
          routes = [ { address = "10.11.0.0"; prefixLength = 24; via = "10.10.0.1"; } ];
        };
      };
      systemd.services.echo-reference = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" "network-addresses-eth1.service" ];
        requires = [ "network-addresses-eth1.service" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${reference}";
      };
    };
    client = { ... }: {
      virtualisation.vlans = [ 2 ];
      virtualisation.memorySize = 512;
      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4 = {
        addresses = [ { address = "10.11.0.2"; prefixLength = 24; } ];
        routes = [ { address = "198.19.244.0"; prefixLength = 24; via = "10.11.0.1"; } ];
      };
    };
  };
  testScript = ''
    import json, shlex
    start_all()
    for machine in (fw, reference, client):
        machine.wait_for_unit("multi-user.target")
    fw.wait_for_unit("sentinel-boot.service")
    reference.wait_for_unit("echo-reference.service")
    reference.wait_until_succeeds("ss -lnt | grep -q :18590", timeout=20)
    reference.wait_until_succeeds("ss -lnu | grep -q :18591", timeout=20)
    for target in ("198.19.244.1", "198.19.244.129"):
        reference.succeed("ip -4 route get " + target + " | grep -q '^local '")

    def configure(commands):
        payload = "\n".join(commands + ["commit", "save", "exit"]) + "\n"
        command = "printf %s " + shlex.quote(payload) + " | sentinel configure"
        # The REPL writes confirmations/errors to stderr, not stdout.
        output = fw.succeed("su admin -c " + shlex.quote(command) + " 2>&1")
        assert "commit ok" in output and "error:" not in output.lower(), output
        fw.wait_for_unit("wren.service")

    def verify(allowed):
        for target in ("198.19.244.1", "198.19.244.129"):
            command = "ip -j -4 route show exact " + target + "/32"
            fw.wait_until_succeeds(command + " | ${pkgs.python3}/bin/python3 -c " + shlex.quote(
                "import json,sys; assert bool(json.load(sys.stdin)) == " + repr(target in allowed)), timeout=20)
        rib = fw.succeed("wren show routes static")
        for target in ("198.19.244.1", "198.19.244.129"):
            assert (target + "/32" in rib) == (target in allowed), rib
        # Independent endpoint health controls run even for negative policy cases.
        healthy = json.loads(reference.succeed("${pkgs.python3}/bin/python3 ${probe}"))
        assert all(row["delivered"] for row in healthy), healthy
        actual = json.loads(client.succeed("${pkgs.python3}/bin/python3 ${probe}"))
        assert all(row["delivered"] == (row["target"] in allowed) for row in actual), actual
        assert all(row["source"] == "10.11.0.2" for row in actual if row["delivered"]), actual

    with subtest("global static import is enforced before RIB/FIB admission and routed TCP/UDP delivery"):
        configure([
            "set firewall global default-action accept",
            "set interface eth1 zone wan", "set interface eth2 zone lan",
            "set protocols static 198.19.244.1/32 via 10.10.0.2",
            "set protocols static 198.19.244.129/32 via 10.10.0.2",
            "set policy prefix-list ADMIT rule 10 prefix 198.19.244.0/25",
            "set policy prefix-list ADMIT rule 10 ge 32", "set policy prefix-list ADMIT rule 10 le 32",
            "set policy route-map IMPORT default deny",
            "set policy route-map IMPORT rule 10 action permit",
            "set policy route-map IMPORT rule 10 match prefix-list ADMIT",
            "set policy route-map IMPORT rule 10 match protocol static",
            "set protocols import static IMPORT",
        ])
        verify({"198.19.244.1"})
    with subtest("prefix-window change withdraws the previously admitted static"):
        configure(["set policy prefix-list ADMIT rule 10 prefix 198.19.244.128/25"])
        verify({"198.19.244.129"})
    with subtest("protocol condition cannot admit a static as BGP"):
        configure(["set policy route-map IMPORT rule 10 match protocol bgp"])
        verify(set())
    with subtest("earlier sequence wins and repeated configuration is idempotent"):
        configure(["set policy route-map IMPORT rule 10 match protocol static",
            "set policy route-map IMPORT rule 5 action deny"])
        verify(set())
        configure(["delete policy route-map IMPORT rule 5"])
        verify({"198.19.244.129"})
        configure(["set policy prefix-list ADMIT rule 10 prefix 198.19.244.128/25"])
        verify({"198.19.244.129"})
    with subtest("normal deletion leaves no policy or route behind"):
        configure(["delete protocols import static", "delete protocols static 198.19.244.1/32",
            "delete protocols static 198.19.244.129/32", "delete policy route-map IMPORT",
            "delete policy prefix-list ADMIT"])
        verify(set())
  '';
}
