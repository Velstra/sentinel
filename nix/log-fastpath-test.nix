# checks.log-fastpath: `log` on a policy or zone logs decisions (drops and
# rejects), never the packets of flows it already admitted.
#
# With `log = true` on a busy WAN zone the data plane used to write a line for
# every reverse-NAT packet (`NAT(ct)`), every forwarded one (`FWD`) and every
# encapsulated one (`ENCAP`). That flooded the journal and stalled the agent
# and the box (checks.nat-cps: 844 drops, held connections timed out). A
# firewall must never take itself down by logging.
#
# The check masquerades a LAN client to a WAN server with logging on
# everywhere, moves megabytes through the reverse-NAT path and asserts that no
# fast-path line was logged — and that a deliberately dropped packet IS
# logged, so it cannot pass on a dead logger. Then it floods the WAN with
# packets the policy drops (every one a log candidate) while 32 masqueraded
# connections are held open and new ones keep being made, and requires that
# the held connections survive, transfers keep working, the agent keeps
# answering, and the drop lines stay inside the agent's log budget (a burst
# of 100, then 10 a second) with a "suppressed" summary for the rest.
# The serial console only gets warnings here, as in the HA checks: the test
# driver forwards journal lines to it synchronously, which would measure the
# emulated UART rather than the appliance; the bound that matters on a box
# is the journal's.
{ pkgs, self }:
let
  # Sends `rate` UDP datagrams a second to ports 9-1008 of `target` for
  # `seconds`: every one dropped by the WAN zone and offered to the log. The
  # rate is what a NAT stress run offered the log (about 5000 a second), far
  # above the log budget, and below what saturates a test VM's CPU (a flood
  # that does measures the emulator, not the logging).
  flood = pkgs.writeText "log-flood.py" ''
    import socket, sys, time
    target, seconds, rate = sys.argv[1], float(sys.argv[2]), int(sys.argv[3])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"x" * 64
    start = time.monotonic()
    sent = 0
    while (now := time.monotonic()) < start + seconds:
        due = int((now - start) * rate)
        while sent < due:
            try:
                s.sendto(payload, (target, 9 + sent % 1000))
            except OSError:
                pass
            sent += 1
        time.sleep(0.005)
    print(f"sent {sent} datagrams", flush=True)
  '';
  echo = pkgs.writeText "log-echo.py" ''
    import socket, threading
    def serve(conn):
        with conn:
            while data := conn.recv(4096):
                conn.sendall(data)
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 7000)); s.listen(128)
    while True:
        threading.Thread(target=serve, args=(s.accept()[0],), daemon=True).start()
  '';
  # Holds `count` connections through the masquerade for `seconds`, echoing a
  # line on each every second; exits non-zero if any of them breaks.
  hold = pkgs.writeText "log-hold.py" ''
    import socket, sys, time
    count, seconds = int(sys.argv[1]), float(sys.argv[2])
    conns = [socket.create_connection(("10.1.0.2", 7000), 5) for _ in range(count)]
    for c in conns:
        c.settimeout(5)
    end = time.monotonic() + seconds
    rounds = 0
    while time.monotonic() < end:
        for i, c in enumerate(conns):
            msg = f"{i}:{rounds}\n".encode()
            c.sendall(msg)
            got = b""
            while len(got) < len(msg):
                got += c.recv(len(msg) - len(got))
            assert got == msg, (i, got, msg)
        rounds += 1
        time.sleep(1)
    print(f"held {count} connections for {rounds} rounds", flush=True)
  '';
in
pkgs.testers.runNixOSTest {
  name = "sentinel-log-fastpath";
  nodes = {
    client =
      { pkgs, ... }:
      {
        virtualisation.vlans = [ 2 ];
        networking = {
          useNetworkd = true;
          useDHCP = false;
          firewall.enable = false;
          interfaces.eth1.ipv4.addresses = [
            {
              address = "10.2.0.2";
              prefixLength = 24;
            }
          ];
          defaultGateway = {
            address = "10.2.0.1";
            interface = "eth1";
          };
        };
        environment.systemPackages = [ pkgs.curl pkgs.python3 ];
      };
    server =
      { pkgs, ... }:
      {
        virtualisation.vlans = [ 1 ];
        networking = {
          useNetworkd = true;
          useDHCP = false;
          firewall.enable = false;
          interfaces.eth1.ipv4.addresses = [
            {
              address = "10.1.0.2";
              prefixLength = 24;
            }
          ];
        };
        environment.systemPackages = [ pkgs.curl pkgs.python3 ];
        systemd.services.echo = {
          wantedBy = [ "multi-user.target" ];
          after = [ "network-online.target" ];
          serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${echo}";
        };
        systemd.services.web = {
          wantedBy = [ "multi-user.target" ];
          after = [ "network-online.target" ];
          script = ''
            mkdir -p /srv/web && head -c 4194304 /dev/zero > /srv/web/payload.bin
            exec ${pkgs.python3}/bin/python3 -m http.server 80 --directory /srv/web
          '';
        };
      };
    fw =
      { lib, ... }:
      {
        imports = [ self.nixosModules.sentinel ./test-network-seed.nix ];
        networking.hostName = lib.mkForce "fw";
        networking.firewall.enable = lib.mkForce false;
        networking.interfaces.eth1.ipv4.addresses = [
          {
            address = "10.1.0.1";
            prefixLength = 24;
          }
        ];
        networking.interfaces.eth2.ipv4.addresses = [
          {
            address = "10.2.0.1";
            prefixLength = 24;
          }
        ];
        virtualisation.vlans = [
          1
          2
        ];
        virtualisation.memorySize = 2048;
        boot.kernel.sysctl = {
          "net.ipv4.ip_forward" = 1;
          "net.ipv4.conf.all.rp_filter" = 0;
          "net.ipv4.conf.default.rp_filter" = 0;
        };
        services.velstra.interface = lib.mkForce "eth1";
        services.journald.extraConfig = lib.mkAfter "MaxLevelConsole=warning\n";
      };
  };
  testScript = ''
    import time
    FAST_PATH = "'NAT\\(ct\\)|FWD -> ifindex|ENCAP vni=|DNAT [0-9]'"

    def agent_lines(pattern):
        return int(fw.succeed(f"journalctl -u velstra --no-pager -o cat | grep -cE {pattern} || true").strip())

    start_all()
    fw.wait_for_unit("velstra.service")
    server.wait_for_unit("web.service")
    fw.wait_until_succeeds("ip addr show eth1 | grep -q 10.1.0.1", timeout=20)
    fw.wait_until_succeeds("ip addr show eth2 | grep -q 10.2.0.1", timeout=20)

    # Logging on at both levels: the policy-wide default and the WAN zone.
    fw.succeed(
        "su admin -c \"printf '%s\\n' "
        "'set interface eth1 zone wan' "
        "'set interface eth2 zone lan' "
        "'set firewall zone lan default-action accept' "
        "'set firewall global log true' "
        "'set firewall zone wan log true' "
        "'set nat source wan-masq zone wan' "
        "commit save exit "
        "| sentinel configure\""
    )
    fw.wait_for_unit("velstra.service")
    fw.succeed("grep -q 'masquerade = true' /run/sentinel/velstra.toml")
    fw.succeed("grep -q 'log = true' /run/sentinel/velstra.toml")

    # Established, reverse-NAT traffic: 3 x 4 MiB through the masquerade, about
    # 9000 reply packets un-NAT'd on the WAN ingress fast path.
    client.wait_until_succeeds("curl -s --max-time 5 -o /dev/null http://10.1.0.2:80/payload.bin", timeout=60)
    for _ in range(3):
        client.succeed("curl -s --max-time 20 -o /dev/null http://10.1.0.2:80/payload.bin")
    fw.succeed("sentinel show flows | grep -q 10.1.0.2")
    time.sleep(2)
    fast_path = agent_lines(FAST_PATH)
    print(f"fast-path log lines: {fast_path}")
    assert fast_path == 0, f"{fast_path} per-packet lines logged for already admitted traffic"

    # A deliberately dropped packet IS logged: the WAN zone drops unsolicited
    # traffic to the fw, and `log` records that decision.
    server.fail("curl -s --max-time 2 http://10.1.0.1:9/")
    fw.wait_until_succeeds("journalctl -u velstra --no-pager -o cat | grep -q 'DROP 10.1.0.2 '", timeout=20)

    # Flood the WAN with packets the policy drops, every one of them a log
    # candidate, while connections are held and new ones made. The log path
    # must shed load, not stall, and stay inside its budget.
    def counter(name):
        out = fw.succeed("timeout 5 sentinel show firewall statistics")
        for line in out.splitlines():
            f = line.split()
            if len(f) == 2 and f[0] == name:
                return int(f[1])
        raise AssertionError(f"no {name} in:\n{out}")
    server.wait_for_unit("echo.service")
    client.succeed("systemd-run --unit=log-hold ${pkgs.python3}/bin/python3 ${hold} 32 75")
    client.wait_until_succeeds("ss -tn state established '( dport = :7000 )' | grep -c 10.1.0.2 | grep -qx 32", timeout=20)
    client.succeed("systemd-run --unit=log-churn /run/current-system/sw/bin/sh -c 'for i in $(seq 600); do /run/current-system/sw/bin/curl -s --max-time 3 -o /dev/null http://10.1.0.2:80/ || echo miss; done'")
    drops_before = agent_lines("'DROP'")
    dropped_before = counter("dropped_default")
    server.succeed("systemd-run --unit=log-flood ${pkgs.python3}/bin/python3 ${flood} 10.1.0.1 40 5000")
    flood_started = time.monotonic()
    time.sleep(3)
    for round in range(4):
        started = time.monotonic()
        client.succeed("curl -s --max-time 30 -o /dev/null http://10.1.0.2:80/payload.bin")
        print(f"transfer {round} under flood: {time.monotonic() - started:.2f}s")
        fw.succeed("timeout 5 sentinel show firewall statistics >/dev/null")
    server.wait_until_succeeds("! systemctl is-active --quiet log-flood", timeout=60)
    print(server.succeed("journalctl -u log-flood --no-pager -o cat | tail -1"))
    # The last summary comes at most one interval after the flood.
    fw.wait_until_succeeds("journalctl -u velstra --no-pager -o cat | grep -qE 'suppressed [0-9]+ data-plane log record'", timeout=30)
    window = time.monotonic() - flood_started
    drop_lines = agent_lines("'DROP'") - drops_before
    dropped = counter("dropped_default") - dropped_before
    suppressed = counter("log_lines_suppressed")
    print(f"flood window {window:.0f}s: {dropped} drops counted, {drop_lines} logged, {suppressed} held back")
    assert 0 < drop_lines <= 100 + 10 * window + 20, f"{drop_lines} drop lines in {window:.0f}s"
    assert suppressed > 0 and dropped > drop_lines * 10, (dropped, drop_lines, suppressed)
    # The held connections survived all of it, and new ones kept being made.
    client.wait_until_succeeds("! systemctl is-active --quiet log-hold", timeout=90)
    assert client.succeed("systemctl show log-hold -p ExecMainStatus --value").strip() == "0", client.succeed("journalctl -u log-hold --no-pager -o cat")
    print(client.succeed("journalctl -u log-hold --no-pager -o cat | tail -1"))
    client.wait_until_succeeds("! systemctl is-active --quiet log-churn", timeout=120)
    misses = int(client.succeed("journalctl -u log-churn --no-pager -o cat | grep -c miss || true").strip())
    print(f"new connections missed during the flood: {misses} of 600")
    assert misses <= 6, f"{misses} of 600 new connections failed"
    # Still no fast-path line after all of it.
    assert agent_lines(FAST_PATH) == 0
  '';
}
