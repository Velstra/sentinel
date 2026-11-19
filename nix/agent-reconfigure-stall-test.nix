# DP-28 / PERF-04: a live reconfigure on top of a large blocklist must not stall
# traffic. A TCP stream through the attached datapath runs while the agent
# reloads (a) the identical configuration and (b) the same configuration plus
# one blocklist entry. The longest gap between delivered messages is measured
# on the receiver. Before the differential writer, every reload deleted and
# rewrote all 120,000 entries with the gate closed (seconds of stall).
{ pkgs, self }:
let
  agent = self.packages.x86_64-linux.velstra;
  python = "${pkgs.python3}/bin/python3";
  blocks = 120000;
  configs = pkgs.runCommand "stall-configs" { } ''
    mkdir -p $out
    ${python} - <<'EOF'
    import os
    out = os.environ["out"]
    def write(name, extra):
        cidrs = [f"100.{64 + i // 65536}.{(i // 256) % 256}.{i % 256}/32" for i in range(${toString blocks})]
        cidrs += extra
        with open(f"{out}/{name}.toml", "w") as f:
            f.write('default_action = "pass"\n')
            f.write("[[policy]]\nid = 2\nname = \"test\"\ndefault_action = \"drop\"\nstateful = true\n")
            f.write("blocklist = [" + ",".join(f'"{c}"' for c in cidrs) + "]\n")
            f.write('[[policy.port_rule]]\nproto = "tcp"\nport = 9000\naction = "pass"\n')
            f.write('[[interface]]\nname = "eth1"\npolicy = 2\n')
    write("base", [])
    write("plus-one", ["203.0.113.77/32"])
    EOF
  '';
  stream = pkgs.writeText "stall-stream.py" ''
    import json, socket, sys, time
    from pathlib import Path
    if sys.argv[1] == "server":
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("198.18.10.100", 9000))
        server.listen(1)
        Path("/run/stream-ready").touch()
        conn, _ = server.accept()
        last = time.monotonic()
        gaps = []
        buf = b""
        while True:
            data = conn.recv(65536)
            if not data:
                break
            now = time.monotonic()
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                gaps.append((now - last, line.decode()))
                last = now
            mark = Path("/run/stream-mark")
            if mark.exists():
                phase = mark.read_text().strip()
                Path(f"/run/gaps-{phase}.json").write_text(json.dumps(sorted(gaps)[-5:]))
                mark.unlink()
                gaps = []
    else:
        conn = socket.create_connection(("198.18.10.100", 9000), 10)
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        end = time.monotonic() + float(sys.argv[2])
        n = 0
        while time.monotonic() < end:
            conn.sendall(f"{n}\n".encode())
            n += 1
            time.sleep(0.002)
        conn.close()
  '';
  query = pkgs.writeText "stall-query.py" ''
    import socket, sys
    with socket.socket(socket.AF_UNIX) as c:
        c.settimeout(120)
        c.connect("/run/velstra/query.sock")
        c.sendall((" ".join(sys.argv[1:]) + "\n").encode())
        c.shutdown(socket.SHUT_WR)
        out = b""
        while chunk := c.recv(65536):
            out += chunk
        print(out.decode(), end="")
  '';
  node = address: {
    boot.kernelPackages = pkgs.linuxPackages_6_12;
    virtualisation = { vlans = [ 1 ]; memorySize = 2048; cores = 2; };
    networking = {
      useDHCP = false;
      useNetworkd = true;
      firewall.enable = false;
      interfaces.eth1.ipv4.addresses = [{ inherit address; prefixLength = 24; }];
    };
    environment.systemPackages = [ pkgs.python3 ];
  };
in pkgs.testers.runNixOSTest {
  name = "sentinel-agent-reconfigure-stall";
  globalTimeout = 900;
  nodes = {
    client = node "198.18.10.254";
    fw = pkgs.lib.recursiveUpdate (node "198.18.10.100") {
      systemd.tmpfiles.rules = [ "d /run/velstra 0700 root root -" "d /etc/velstra 0700 root root -" ];
      systemd.services.agent = {
        wantedBy = [ "multi-user.target" ];
        after = [ "systemd-networkd.service" ];
        environment.RUST_LOG = "info";
        preStart = "cp ${configs}/base.toml /etc/velstra/active.toml";
        serviceConfig.ExecStart = "${agent}/bin/velstra run --iface eth1 --xdp-mode skb --egress --config /etc/velstra/active.toml --query-socket /run/velstra/query.sock";
      };
    };
  };
  testScript = ''
    import json, os
    from pathlib import Path
    q = "${python} ${query} "
    from typing import Any
    receipt: dict[str, Any] = {"passed": False, "blocklist_entries": ${toString blocks}}
    evidence = Path(os.environ["out"], "reconfigure-stall.json")
    def rss():
        pid = fw.succeed("systemctl show -p MainPID --value agent").strip()
        return int(fw.succeed(f"awk '/VmRSS/ {{print $2}}' /proc/{pid}/status").strip())
    start_all()
    fw.wait_until_succeeds("journalctl -u agent --no-pager | grep -F 'Velstra is live.'", timeout=300)
    assert fw.succeed(q + "status").strip() == "Ready"
    receipt["rss_kib_loaded"] = rss()
    fw.succeed("systemd-run --unit stream-server ${python} ${stream} server")
    fw.wait_until_succeeds("test -e /run/stream-ready")
    client.succeed("systemd-run --unit stream-client ${python} ${stream} client 120")
    fw.succeed("sleep 3; echo warmup > /run/stream-mark")
    fw.wait_until_succeeds("test -e /run/gaps-warmup.json")
    for phase, config in (("noop", "base"), ("one-entry", "plus-one"), ("back", "base"), ("noop2", "base")):
        fw.succeed(f"cp ${configs}/{config}.toml /etc/velstra/active.toml")
        answer = fw.succeed(q + "reload").strip()
        assert answer == "ok", (phase, answer)
        fw.succeed(f"sleep 3; echo {phase} > /run/stream-mark")
        fw.wait_until_succeeds(f"test -e /run/gaps-{phase}.json")
        gaps = json.loads(fw.succeed(f"cat /run/gaps-{phase}.json"))
        receipt[phase] = {"largest_gaps_s": gaps, "rss_kib": rss()}
        evidence.write_text(json.dumps(receipt, indent=2))
    journal = fw.succeed("journalctl -u agent --no-pager")
    receipt["unchanged_logged"] = journal.count("configuration unchanged")
    receipt["diff_lines"] = [l for l in journal.splitlines() if "policy tries:" in l]
    evidence.write_text(json.dumps(receipt, indent=2))
    print(json.dumps(receipt, indent=2))
    worst = lambda phase: max(g for g, _ in receipt[phase]["largest_gaps_s"])
    # The bound: a reload that changes nothing stalls nothing beyond scheduling
    # noise; a one-entry change closes the gate only for the difference.
    assert worst("noop") < 0.3 and worst("noop2") < 0.3, receipt
    assert worst("one-entry") < 0.5 and worst("back") < 0.5, receipt
    assert receipt["unchanged_logged"] >= 2, receipt
    assert fw.succeed(q + "status").strip() == "Ready"
    receipt["passed"] = True
    evidence.write_text(json.dumps(receipt, indent=2))
  '';
}
