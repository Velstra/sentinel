# Real query handler, attached production datapath and one original TCP socket.
{ pkgs, probe }:
let
  config = pkgs.writeText "expiry-live.toml" ''
    default_action = "pass"
    [[policy]]
    id = 2
    name = "test"
    default_action = "drop"
    stateful = true
    [[policy.port_rule]]
    proto = "tcp"
    port = 9000
    action = "pass"
    [[interface]]
    name = "eth1"
    policy = 2
  '';
  traffic = pkgs.writeText "expiry-held-tcp.py" ''
    import json, socket, sys, time
    from pathlib import Path
    if sys.argv[1] == "server":
        with socket.socket() as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("198.18.10.100", 9000))
            server.listen(1)
            Path("/run/echo-ready").touch()
            connection, _ = server.accept()
            with connection, connection.makefile("rb") as stream:
                while data := stream.readline():
                    connection.sendall(data)
    else:
        with socket.create_connection(("198.18.10.100", 9000), 5) as connection:
            initial_tuple = connection.getsockname()
            with connection.makefile("rb") as stream:
                connection.sendall(b"before-maintenance-unique-01\n")
                assert stream.readline() == b"before-maintenance-unique-01\n"
                Path("/run/client-ready").touch()
                end = time.monotonic() + 90
                while not Path("/run/continue").exists():
                    assert time.monotonic() < end, "driver did not resume held stream"
                    time.sleep(.05)
                connection.sendall(b"after-maintenance-unique-02\n")
                assert stream.readline() == b"after-maintenance-unique-02\n"
                assert connection.getsockname() == initial_tuple
                Path("/run/held-tcp.json").write_text(json.dumps({"same_socket": True, "tuple": initial_tuple, "echoes": 2}))
  '';
  query = pkgs.writeText "expiry-query.py" ''
    import socket, sys
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(10)
        connection.connect("/run/velstra/query.sock")
        connection.sendall((" ".join(sys.argv[1:]) + "\n").encode())
        connection.shutdown(socket.SHUT_WR)
        chunks = []
        while chunk := connection.recv(65536):
            chunks.append(chunk)
        print(b"".join(chunks).decode(), end="")
  '';
  python = "${pkgs.python3}/bin/python3";
  fwProbe = "${python} ${./firewall-expiry-probe.py} --support ${./icmp-nat-ownership-probe.py} --case expired";
  natProbe = "${python} ${./nat-expiry-probe.py} --support ${./icmp-nat-ownership-probe.py} --case expired --protocol udp";
  node = address: {
    boot.kernelPackages = pkgs.linuxPackages_6_12;
    virtualisation = { vlans = [ 1 ]; memorySize = 1536; cores = 2; };
    networking = {
      useDHCP = false;
      useNetworkd = true;
      firewall.enable = false;
      interfaces.eth1.ipv4.addresses = [{ inherit address; prefixLength = 24; }];
    };
    environment.systemPackages = [ pkgs.python3 pkgs.bpftools ];
  };
in pkgs.testers.runNixOSTest {
  name = "sentinel-expiry-maintenance-live";
  globalTimeout = 240;
  nodes = {
    client = node "198.18.10.254";
    fw = pkgs.lib.recursiveUpdate (node "198.18.10.100") {
      systemd.tmpfiles.rules = [
        "d /run/velstra 0700 root root -"
        "f /run/qa-firewall-expiry-disposable 0600 root root - disposable-test-only"
        "f /run/qa-nat-expiry-disposable 0600 root root - disposable-test-only"
      ];
      systemd.services.agent = {
        wantedBy = [ "multi-user.target" ];
        after = [ "systemd-networkd.service" ];
        environment.RUST_LOG = "info";
        serviceConfig.ExecStart = "${probe}/bin/velstra run --iface eth1 --xdp-mode skb --egress --config ${config} --query-socket /run/velstra/query.sock";
      };
    };
  };
  testScript = ''
    import json, os
    from pathlib import Path
    evidence = Path(os.environ["out"], "expiry-live.json")
    receipt = {"passed": False, "rows": []}
    evidence.write_text(json.dumps(receipt))
    start_all()
    fw.wait_for_unit("agent.service")
    fw.wait_until_succeeds("journalctl -u agent --no-pager | grep -F 'Velstra is live. Press Ctrl-C to detach.'")
    client.wait_until_succeeds("ip -4 address show dev eth1 | grep -F 198.18.10.254/24")
    q = "${python} ${query} "
    assert fw.succeed(q + "status").strip() == "Ready"
    for invalid in ("expire-state", "expire-state all 1", "expire-state nat 0", "expire-state nat 65537", "expire-state firewall 1 extra"):
        assert fw.succeed(q + invalid).startswith("usage:"), invalid
    assert fw.succeed(q + "status").strip() == "Ready"
    fw.succeed("systemd-run --unit echo ${python} ${traffic} server")
    fw.wait_until_succeeds("test -e /run/echo-ready")
    client.succeed("systemd-run --unit held ${python} ${traffic} client")
    client.wait_until_succeeds("test -e /run/client-ready")
    rows = receipt["rows"]
    for table, command in (("firewall", "${fwProbe}"), ("nat", "${natProbe}")):
        fw.succeed(command + " seed --output /run/before.json")
        before = json.loads(fw.succeed("cat /run/before.json"))
        result = json.loads(fw.succeed(q + "expire-state " + table + " 65536"))
        row = dict(table=table, result=result, before=before)
        rows.append(row)
        evidence.write_text(json.dumps(receipt, indent=2))
        assert result["removed"] == 1 and result["scan_complete"], result
        assert not result["budget_exhausted"], result
        if table == "firewall":
            assert result["examined"] >= 4, "held TCP state must exist alongside the two seeded directions"
        assert fw.succeed(q + "status").strip() == "Ready"
        fw.succeed(command + " inspect --output /run/after.json")
        after = json.loads(fw.succeed("cat /run/after.json"))
        row["after"] = after
        evidence.write_text(json.dumps(receipt, indent=2))
        assert before["map_id"] == after["map_id"] and before["keys"] == after["keys"]
        assert before["values"][0] is not None and after["values"][0] is None
        assert before["values"][1] is not None and before["values"][1] == after["values"][1]
    client.succeed("touch /run/continue")
    client.wait_until_succeeds("test -e /run/held-tcp.json")
    held = json.loads(client.succeed("cat /run/held-tcp.json"))
    assert held["same_socket"] and held["echoes"] == 2
    receipt.update(passed=True, held_tcp=held)
    evidence.write_text(json.dumps(receipt, indent=2))
  '';
}
