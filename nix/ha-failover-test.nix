{ pkgs, self, synproxy ? false }:
let
  name = if synproxy then "sentinel-ha-synproxy-failover" else "sentinel-ha-failover";
  secret = "ha-vm-test-credential-at-least-32-bytes";
  appliance = number: priority: (pkgs.formats.toml {}).generate "ha-appliance.toml" {
    system = {
      hostname = if number == "1" then "master" else "backup";
      config-sync.secret = secret;
      conntrack-sync = {
        listen = "10.3.0.${number}:5429";
        peer = [ "10.3.0.${if number == "1" then "2" else "1"}:5429" ];
      };
    };
    interface = [
      { name = "eth1"; zone = "wan"; address = "10.1.0.${number}/24"; }
      { name = "eth2"; zone = "lan"; address = "10.2.0.${number}/24"; }
      { name = "eth3"; zone = "sync"; address = "10.3.0.${number}/24"; }
    ];
    firewall = { default_action = "drop"; stateful = true; fail_closed = true; } //
      pkgs.lib.optionalAttrs synproxy { syn-protect = [{ port = 8443; }]; };
    zone = { wan.default_action = "drop"; lan.default_action = "drop"; sync.default_action = "accept"; };
    rule = [{ name = "echo"; from = "lan"; proto = "tcp"; port = 8443; action = "accept"; }];
    nat.source = pkgs.lib.optionals (!synproxy) [{ name = "shared-snat"; zone = "wan"; to = "10.1.0.100"; }];
    protocols.vrrp = map (link: {
      name = link.name; interface = "eth3"; address-interface = link.interface;
      vrid = link.vrid; inherit priority; advert-interval = 100; preempt = true;
      prefix-length = 24; virtual-address = [ link.address ];
    }) [
      { name = "wan"; interface = "eth1"; vrid = 20; address = "10.1.0.100"; }
      { name = "lan"; interface = "eth2"; vrid = 21; address = "10.2.0.100"; }
    ];
  };
  firewall = number: priority: { lib, ... }: {
    imports = [ self.nixosModules.sentinel ];
    virtualisation.vlans = [ 1 2 3 ];
    virtualisation.memorySize = 2048;
    virtualisation.cores = 2;
    networking.hostName = lib.mkForce (if number == "1" then "master" else "backup");
    networking.firewall.enable = lib.mkForce false;
    services.velstra.interface = lib.mkForce "eth1";
    services.velstra.appliance = lib.mkForce (appliance number priority);
  };
  echo = pkgs.writeText "ha-echo.py" ''
    import socket, threading
    def serve(connection, peer):
        with connection, connection.makefile("rb") as reader:
            for line in reader:
                connection.sendall(line)
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0",8443)); listener.listen()
    with open("/tmp/accepted", "a", buffering=1) as accepted:
        while True:
            connection, peer = listener.accept()
            accepted.write(f"{peer[0]}:{peer[1]}\n")
            threading.Thread(target=serve,args=(connection,peer),daemon=True).start()
  '';
  stream = pkgs.writeText "ha-stream.py" ''
    import socket, time, json
    connection = socket.create_connection(("10.1.0.10",8443),timeout=4)
    connection.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
    reader = connection.makefile("rb")
    count = 0; maximum_gap = 0; last = time.monotonic()
    with open("/tmp/stream-ready", "w") as ready: ready.write("connected")
    while not __import__("os").path.exists("/tmp/stream-stop"):
        message = f"{count}\n".encode()
        connection.sendall(message)
        assert reader.readline() == message, "TCP stream changed or reset"
        now = time.monotonic(); maximum_gap=max(maximum_gap,now-last);last=now
        count+=1
        with open("/tmp/stream-status","w") as status:
            json.dump({"count":count,"maximum_gap":maximum_gap},status)
        time.sleep(0.02)
    assert count>50
    connection.close()
  '';
in pkgs.testers.runNixOSTest {
  inherit name;
  nodes = {
    master = firewall "1" 200;
    backup = firewall "2" 100;
    client = {
      virtualisation.vlans = [ 2 ];
      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4.addresses = [{ address = "10.2.0.10"; prefixLength = 24; }];
      networking.interfaces.eth1.ipv4.routes = [{ address = "10.1.0.0"; prefixLength = 24; via = "10.2.0.100"; }];
      environment.systemPackages = [ pkgs.python3 ];
    };
    server = {
      virtualisation.vlans = [ 1 ];
      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4.addresses = [{ address = "10.1.0.10"; prefixLength = 24; }];
      networking.interfaces.eth1.ipv4.routes = [{ address = "10.2.0.0"; prefixLength = 24; via = "10.1.0.100"; }];
      systemd.services.ha-echo = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${echo}";
      };
    };
  };
  testScript = ''
    import time, json
    start_all()
    for node in (master,backup,client,server):
        node.wait_for_unit("multi-user.target")
    for node in (master,backup):
        node.wait_for_unit("velstra.service")
        node.wait_for_unit("wren.service")
        node.wait_until_succeeds("journalctl -u velstra --no-pager | grep -q 'authenticated TCP listening'",timeout=60)
    master.wait_until_succeeds("ip -o address show eth2 | grep -q 10.2.0.100",timeout=30)
    backup.succeed("! ip -o address show eth2 | grep -q 10.2.0.100")
    server.wait_for_unit("ha-echo.service")
    client.succeed("systemd-run --unit=ha-stream ${pkgs.python3}/bin/python3 ${stream}")
    client.wait_until_succeeds("test -f /tmp/stream-ready",timeout=20)
    # Prove the flow crossed the intended datapath before the crash. Splicing
    # on a real socket checks TCP sequence translation and checksum correction.
    ${if synproxy then ''
    master.wait_until_succeeds("sentinel show firewall statistics | awk 'BEGIN {ok=0} /^[[:space:]]*synproxy_spliced[[:space:]]/ {ok=($2 >= 1)} END {exit !ok}'",timeout=30)
    '' else ''
    backup.wait_until_succeeds("sentinel show firewall flows | grep -q 10.2.0.10",timeout=20)
    ''}
    time.sleep(2)
    before=json.loads(client.succeed("cat /tmp/stream-status"))["count"]
    # No priority-zero advert, service shutdown or graceful address removal.
    started=time.monotonic()
    master.crash()
    while True:
        code,_=backup.execute("ip -o address show eth2 | grep -q 10.2.0.100")
        if code == 0: break
        assert time.monotonic()-started < 1.0, "VIP promotion exceeded one second"
        time.sleep(0.01)
    elapsed=time.monotonic()-started
    backup.succeed("ip -o address show eth1 | grep -q 10.1.0.100")
    time.sleep(2)
    after=json.loads(client.succeed("cat /tmp/stream-status"))
    assert after["count"] > before+20, "established TCP connection did not continue"
    assert after["maximum_gap"] < 1.0, after
    client.succeed("touch /tmp/stream-stop")
    client.wait_until_succeeds("test $(systemctl show ha-stream -p ExecMainStatus --value) = 0 && ! systemctl is-active --quiet ha-stream",timeout=10)
    server.succeed("test $(wc -l </tmp/accepted) = 1; grep -q '^${if synproxy then "10.2.0.10" else "10.1.0.100"}:' /tmp/accepted")
    print(f"ungraceful failover {elapsed:.3f}s; one TCP socket, ${if synproxy then "preserved SYN-proxy splice" else "preserved SNAT"}, {after}")
  '';
}
