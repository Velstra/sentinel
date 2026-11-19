# DP-12 / DP-27: an agent that dies must leave its links filtered, and the one
# that replaces it must adopt the connections in flight.
#
# The firewall node runs the agent directly (no restart policy, so the test
# decides when it comes back) with a deny-by-default stateful zone on eth1:
#   * tcp/9000 inbound is admitted by rule (the control: always reachable);
#   * tcp/8080 inbound has a listener on the box but no rule (must stay shut);
#   * the box holds an OUTBOUND connection to the client's tcp/7000, whose
#     replies are admitted only by connection state.
# The agent is SIGKILLed. While it is dead, 8080 must stay unreachable and the
# outbound connection must keep working (the pinned programs and maps). After a
# restart the new agent must adopt the pinned hooks and the state, and the same
# outbound connection must still work. Finally `velstra release-datapath` with
# the agent stopped detaches everything: then 8080 is reachable, which proves the
# pins, not something else, kept it shut.
{ pkgs, self, persist ? true }:
let
  agent = self.packages.x86_64-linux.velstra;
  python = "${pkgs.python3}/bin/python3";
  config = pkgs.writeText "persist.toml" (''
    default_action = "pass"
  '' + pkgs.lib.optionalString persist ''
    [state]
    persist = true
  '' + ''
    [[policy]]
    id = 2
    name = "test"
    default_action = "drop"
    stateful = true
    [[policy.port_rule]]
    proto = "tcp"
    port = 9000
    action = "pass"
    direction = "in"
    [[interface]]
    name = "eth1"
    policy = 2
  '');
  echo = pkgs.writeText "persist-echo.py" ''
    import socket, sys, threading
    def serve(port):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen(16)
        while True:
            c, _ = s.accept()
            def run(c=c):
                with c:
                    while d := c.recv(4096):
                        c.sendall(d)
            threading.Thread(target=run, daemon=True).start()
    ts = [threading.Thread(target=serve, args=(int(p),), daemon=True) for p in sys.argv[1:]]
    [t.start() for t in ts]
    [t.join() for t in ts]
  '';
  # Holds one outbound connection and answers "ok"/"fail" per line on a FIFO.
  holder = pkgs.writeText "persist-holder.py" ''
    import os, socket, time
    from pathlib import Path
    c = socket.create_connection(("198.18.10.254", 7000), 10)
    c.settimeout(8)
    Path("/run/holder-ready").touch()
    n = 0
    while True:
        req = Path("/run/holder-ask")
        if req.exists():
            tag = req.read_text().strip()
            req.unlink()
            msg = f"probe-{n}\n".encode()
            n += 1
            try:
                c.sendall(msg)
                got = b""
                while len(got) < len(msg):
                    got += c.recv(4096)
                result = "ok" if got == msg else "mismatch"
            except Exception as e:
                result = f"fail {e}"
            Path(f"/run/holder-{tag}").write_text(result)
        time.sleep(0.05)
  '';
  query = pkgs.writeText "persist-query.py" ''
    import socket, sys
    with socket.socket(socket.AF_UNIX) as c:
        c.settimeout(30)
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
    virtualisation = { vlans = [ 1 ]; memorySize = 1536; cores = 2; };
    networking = {
      useDHCP = false;
      useNetworkd = true;
      firewall.enable = false;
      interfaces.eth1.ipv4.addresses = [{ inherit address; prefixLength = 24; }];
    };
    environment.systemPackages = [ pkgs.python3 pkgs.netcat-openbsd pkgs.bpftools ];
  };
in pkgs.testers.runNixOSTest {
  name = "sentinel-agent-restart-persist${pkgs.lib.optionalString (!persist) "-off"}";
  globalTimeout = 600;
  nodes = {
    client = node "198.18.10.254";
    fw = pkgs.lib.recursiveUpdate (node "198.18.10.100") {
      systemd.tmpfiles.rules = [ "d /run/velstra 0700 root root -" ];
      systemd.services.agent = {
        after = [ "systemd-networkd.service" ];
        environment.RUST_LOG = "info";
        serviceConfig = {
          ExecStart = "${agent}/bin/velstra run --iface eth1 --xdp-mode skb --config ${config} --query-socket /run/velstra/query.sock";
          Restart = "no";
        };
      };
    };
  };
  testScript = ''
    import json, os
    from pathlib import Path
    from typing import Any
    receipt: dict[str, Any] = {"persist": ${if persist then "True" else "False"}, "passed": False}
    evidence = Path(os.environ["out"], "restart-persist.json")
    def save():
        evidence.write_text(json.dumps(receipt, indent=2))
    def reachable(port):
        return client.execute(f"echo hi | timeout 4 nc -w 3 198.18.10.100 {port}")[0] == 0
    def held(tag):
        fw.succeed(f"echo {tag} > /run/holder-ask")
        fw.wait_until_succeeds(f"test -e /run/holder-{tag}", timeout=20)
        return fw.succeed(f"cat /run/holder-{tag}").strip()
    start_all()
    client.succeed("systemd-run --unit echo ${python} ${echo} 7000")
    fw.succeed("systemd-run --unit echo ${python} ${echo} 8080 9000")
    fw.succeed("systemctl start agent")
    fw.wait_until_succeeds("journalctl -u agent --no-pager | grep -F 'Velstra is live.'")
    client.wait_until_succeeds("echo hi | timeout 4 nc -w 3 198.18.10.100 9000")
    receipt["before"] = {"rule_port": reachable(9000), "closed_port": reachable(8080)}
    fw.succeed("systemd-run --unit holder ${python} ${holder}")
    fw.wait_until_succeeds("test -e /run/holder-ready")
    receipt["before"]["held"] = held("before")
    save()
    assert receipt["before"] == {"rule_port": True, "closed_port": False, "held": "ok"}, receipt

    fw.succeed("systemctl kill -s KILL --kill-whom=all agent")
    fw.wait_until_succeeds("! systemctl is-active agent")
    receipt["dead"] = {
        "closed_port": reachable(8080),
        "held": held("dead"),
        "xdp": fw.succeed("ip -d link show eth1 | grep -c 'prog/xdp' || true").strip(),
        "pins": fw.succeed("ls -R /sys/fs/bpf/velstra 2>/dev/null || true"),
    }
    save()
    assert not receipt["dead"]["closed_port"], f"agent death left the link unfiltered: {receipt}"
    assert receipt["dead"]["held"] == "ok", f"agent death dropped connection state: {receipt}"

    fw.succeed("systemctl start agent")
    fw.wait_until_succeeds("journalctl -u agent --no-pager | grep -c 'Velstra is live.' | grep -qx 2")
    journal = fw.succeed("journalctl -u agent --no-pager")
    restarted: dict[str, Any] = {
        "closed_port": reachable(8080),
        "held": held("restarted"),
        "adopted_state": "adopting the connection state of the previous agent" in journal,
        "adopted_xdp": "adopted the pinned XDP attachment on eth1" in journal,
        "adopted_egress": "adopted the pinned egress firewall on eth1" in journal,
        "capacity": json.loads(fw.succeed("${python} ${query} capacity")),
    }
    receipt["restarted"] = restarted
    save()
    r = restarted
    assert not r["closed_port"] and r["held"] == "ok", receipt
    assert r["adopted_state"] and r["adopted_xdp"] and r["adopted_egress"], receipt
    assert r["capacity"]["state_adopted_from_previous_agent"] is True, receipt

    fw.succeed("systemctl stop agent")
    receipt["stopped"] = {"closed_port": reachable(8080), "held": held("stopped")}
    fw.succeed("${agent}/bin/velstra release-datapath")
    receipt["released"] = {"closed_port": reachable(8080)}
    save()
    assert not receipt["stopped"]["closed_port"] and receipt["stopped"]["held"] == "ok", receipt
    assert receipt["released"]["closed_port"], "release-datapath must detach the pinned hooks"
    receipt["passed"] = True
    save()
  '';
}
