{ pkgs, self, synproxy ? false, leased ? false, wireguard ? false, masquerade ? false }:
let
  name = if masquerade then "sentinel-ha-masquerade-failover" else if wireguard then "sentinel-ha-wireguard-failover" else if leased && synproxy then "sentinel-ha-witness-synproxy-failover" else if leased then "sentinel-ha-witness-failover" else if synproxy then "sentinel-ha-synproxy-failover" else "sentinel-ha-failover";
  secret = "ha-vm-test-credential-at-least-32-bytes";
  appliance = number: priority: (pkgs.formats.toml {}).generate "ha-appliance.toml" {
    system = {
      hostname = if number == "1" then "master" else "backup";
      config-sync = { inherit secret; } // pkgs.lib.optionalAttrs leased {peer=["10.3.0.${if number == "1" then "2" else "1"}:8080"];};
      conntrack-sync = {
        listen = "10.3.0.${number}:5429";
        peer = [ "10.3.0.${if number == "1" then "2" else "1"}:5429" ];
      };
    } // pkgs.lib.optionalAttrs leased {ha={enabled=true;cluster="vm-cluster-0123456789";node=pkgs.lib.toInt number;witness="10.3.0.3:5440";sync-interface="eth3";inherit priority;preempt=true;};};
    interface = [
      ({ name = "eth1"; zone = "wan"; address = "10.1.0.${number}/24"; } // pkgs.lib.optionalAttrs leased {address6="fd42:1::${number}/64";})
      ({ name = "eth2"; zone = "lan"; address = "10.2.0.${number}/24"; } // pkgs.lib.optionalAttrs leased {address6="fd42:2::${number}/64";})
      { name = "eth3"; zone = "sync"; address = "10.3.0.${number}/24"; }
    ] ++ pkgs.lib.optionals leased [{name="dmz0";type="dummy";zone="dmz";address="192.0.2.${number}/24";}]
      ++ pkgs.lib.optionals wireguard [{name="wg0";type="wireguard";address="10.9.0.1/24";zone="vpn";}];
    vpn.wireguard=pkgs.lib.optionals wireguard [{name="wg0";private-key="ICOioMTTlfQE/2NndOoEntortz+0tZ5Hll0AEM7tdmE=";listen-port=51820;peer=[{public-key="pOCSkrZRwni5dyxWn1+puxPZBrRqtoyd+dwrRAn4ogk=";allowed-ips=["10.9.0.2/32"];}];}];
    firewall = { default_action = "drop"; stateful = true; fail_closed = true; } //
      pkgs.lib.optionalAttrs synproxy { syn-protect = [{ port = 8443; }]; };
    zone = { wan.default_action = "drop"; lan.default_action = "drop"; sync.default_action = "accept"; };
    rule = [{ name = "echo"; from = if wireguard then "vpn" else "lan"; proto = "tcp"; port = 8443; action = "accept"; }]
      ++ pkgs.lib.optionals leased [{name="v6-neighbors";from="lan";proto="icmpv6";action="accept";}]
      ++ pkgs.lib.optionals wireguard [{name="vpn-handshake";from="wan";proto="udp";port=51820;action="accept";}];
    nat.source = pkgs.lib.optionals (!synproxy) [({ name = "shared-snat"; zone = "wan"; } // pkgs.lib.optionalAttrs (!masquerade) {to="10.1.0.100";})];
    protocols.vrrp = map (link: {
      name = link.name; interface = "eth3"; address-interface = link.interface;
      vrid = link.vrid; inherit priority; advert-interval = 100; preempt = true;
      prefix-length = link.prefix; virtual-address = [ link.address ];
    }) ([
      { name = "wan"; interface = "eth1"; vrid = 20; address = "10.1.0.100"; prefix=24; }
      { name = "lan"; interface = "eth2"; vrid = 21; address = "10.2.0.100"; prefix=24; }
    ] ++ pkgs.lib.optionals leased [{name="lan6";interface="eth2";vrid=22;address="fd42:2::100";prefix=64;}]);
  };
  firewall = number: priority: { lib, ... }: {
    imports = [ self.nixosModules.sentinel ];
    environment.systemPackages=[pkgs.python3 pkgs.wireguard-tools pkgs.bpftools];
    virtualisation.vlans = [ 1 2 3 ];
    virtualisation.memorySize = 2048;
    virtualisation.cores = 2;
    networking.hostName = lib.mkForce (if number == "1" then "master" else "backup");
    networking.firewall.enable = lib.mkForce false;
    services.velstra.interface = lib.mkForce "eth1";
    services.velstra.appliance = lib.mkForce (appliance number priority);
    systemd.services.wren.environment.RUST_LOG = "wren::vrrp=debug";
    systemd.services.velstra.environment.RUST_LOG = "velstra::conntrack_sync=debug,velstra::ha=debug";
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
        with open("/tmp/stream-status.next","w") as status:
            json.dump({"count":count,"maximum_gap":maximum_gap},status)
        __import__("os").replace("/tmp/stream-status.next","/tmp/stream-status")
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
      virtualisation.vlans = if wireguard then [ 2 1 ] else [2];
      networking.interfaces.eth2=pkgs.lib.mkIf wireguard {ipv4.addresses=[{address="10.1.0.20";prefixLength=24;}];};
      networking.wireguard.interfaces=pkgs.lib.optionalAttrs wireguard {wg0={
        ips=["10.9.0.2/24"];listenPort=51821;privateKey="AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        peers=[{publicKey="6gUqcU72dUQr2VqzOWxiON1qzkzIOQD7SkZjPjPFWXs=";allowedIPs=["10.1.0.10/32"];endpoint="10.1.0.100:51820";}];
      };};
      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4.addresses = [{ address = "10.2.0.10"; prefixLength = 24; }];
      networking.interfaces.eth1.ipv6.addresses=pkgs.lib.optionals leased [{address="fd42:2::10";prefixLength=64;}];
      networking.interfaces.eth1.ipv4.routes = [{ address = "10.1.0.0"; prefixLength = 24; via = "10.2.0.100"; }];
      environment.systemPackages = [ pkgs.python3 pkgs.tcpdump pkgs.wireguard-tools ];
    };
    server = {
      environment.systemPackages = [ pkgs.tcpdump ];
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
  } // pkgs.lib.optionalAttrs leased {
    witness = {lib,...}: {
      networking.hostName=lib.mkForce "witness";
      imports=[self.nixosModules.sentinel];
      virtualisation.vlans=[3];virtualisation.memorySize=1536;
      environment.systemPackages=[pkgs.python3];
      networking.firewall.enable=lib.mkForce false;
      services.velstra.interface=lib.mkForce "eth1";
      services.velstra.appliance=lib.mkForce ((pkgs.formats.toml {}).generate "witness-appliance.toml" {
        system={hostname="witness";ha-witness={listen="10.3.0.3:5440";inherit secret;cluster="vm-cluster-0123456789";};};
        interface=[{name="eth1";address="10.3.0.3/24";zone="control";}];
        firewall.default_action="accept";
      });
    };

  };
  testScript = ''
    import time, json, shlex
    def python_command(script):
        return "${pkgs.python3}/bin/python3 -c " + shlex.quote(script)
    def check_stream(label):
        before=json.loads(client.succeed("cat /tmp/stream-status"))["count"]
        until=time.monotonic()+3
        while time.monotonic()<until:
            current=json.loads(client.succeed("cat /tmp/stream-status"))
            code,_=client.execute("systemctl is-active --quiet ha-stream")
            if code==0 and current["count"]>before+3:
                print(f"TCP checkpoint {label}: {current}")
                return
            if code!=0:break
            time.sleep(0.05)
        for node in (master,backup):
            print(node.execute("sentinel show firewall flows; sentinel show firewall statistics; bpftool -j map dump name SYN_FLOWS; ip -s neigh; cat /run/velstra/ha/role.json /run/velstra/ha/agent.json; journalctl -u velstra -u wren --no-pager -n 35")[1])
        print(client.execute("journalctl -u ha-stream --no-pager -n 25; ip -s neigh")[1])
        print(server.succeed("cat /tmp/accepted"))
        for node in (client,server):
            node.succeed("systemctl stop ha-packets")
            print(node.succeed("${pkgs.tcpdump}/bin/tcpdump -tt -n -e -S -r /tmp/ha-packets.pcap 2>/dev/null | tail -n 55"))
        raise AssertionError(f"established TCP stream stalled after {label}")
    start_all()
    ${pkgs.lib.optionalString leased ''
    witness.wait_for_unit("sentinel-witness.service")
    ''}
    for node in (master,backup,client,server):
        node.wait_for_unit("multi-user.target")
    for node in (master,backup):
        node.wait_for_unit("velstra.service")
        node.wait_for_unit("wren.service")
        node.wait_until_succeeds("journalctl -u velstra --no-pager | grep -q 'authenticated TCP listening'",timeout=60)
    master.wait_until_succeeds("ip -o address show eth2 | grep -q 10.2.0.100",timeout=30)
    backup.succeed("! ip -o address show eth2 | grep -q 10.2.0.100")
    ${pkgs.lib.optionalString leased ''
    for node in (master,backup):
        print(node.succeed(python_command('import json,time; r=json.load(open("/run/velstra/ha/role.json")); a=json.load(open("/run/velstra/ha/agent.json")); print(json.dumps({"role":r,"agent":a,"remaining_ms":(r["deadline_ns"]-time.clock_gettime_ns(time.CLOCK_BOOTTIME))/1000000,"policy_match":a["policy"]==r["authority"]["policy"],"agent_match":a["agent_boot"]==r["claimed_agent_boot"]}))')))
        print(node.execute("bpftool -j map dump pinned /sys/fs/bpf/velstra-ha/deadline")[1])
        print(node.execute("ip -o link; ip -6 -o addr")[1])
    client.succeed("ping -6 -c1 -W2 fd42:2::100")
    ''}
    ${pkgs.lib.optionalString wireguard ''
    # The cold owner's empty complete baseline must exist before VPN recovery,
    # even after its witness claim has already matured to the active term.
    master.wait_until_succeeds(python_command('import json; r=json.load(open("/run/velstra/ha/role.json")); c=json.load(open("/run/velstra/ha/wireguard.json")); assert r["vpn_ready"] and c["node"]==1 and c["endpoints"]==[]'),timeout=15)
    ''}
    server.wait_for_unit("ha-echo.service")
    for node in (client, server):
        node.succeed("systemd-run --unit=ha-packets ${pkgs.tcpdump}/bin/tcpdump -p -U -w /tmp/ha-packets.pcap -i eth1 tcp port 8443")
    client.succeed("systemd-run --unit=ha-stream ${pkgs.python3}/bin/python3 ${stream}")
    client.wait_until_succeeds("test -f /tmp/stream-ready",timeout=20)
    # Prove the flow crossed the intended datapath before the crash. Splicing
    # on a real socket checks TCP sequence translation and checksum correction.
    ${if synproxy then ''
    master.wait_until_succeeds("sentinel show firewall statistics | awk 'BEGIN {ok=0} /^[[:space:]]*synproxy_spliced[[:space:]]/ {ok=($2 >= 1)} END {exit !ok}'",timeout=30)
    '' else ''
    backup.wait_until_succeeds("sentinel show firewall flows | grep -q ${if wireguard then "10.9.0.2" else "10.2.0.10"}",timeout=20)
    ''}
    ${pkgs.lib.optionalString wireguard ''
    backup.wait_until_succeeds(python_command('import json; assert json.load(open("/run/velstra/ha/wireguard.json"))["endpoints"]'),timeout=20)
    client.succeed("wg show wg0 latest-handshakes | grep -v ' 0$'")
    ''}
    time.sleep(2)
    before=json.loads(client.succeed("cat /tmp/stream-status"))["count"]
    # No priority-zero advert, service shutdown or graceful address removal.
    started=time.monotonic()
    ${if leased then ''
    master.succeed("systemctl kill --kill-who=main --signal=SIGSTOP wren.service")
    '' else "master.crash()"}
    while True:
        # Legacy VRRP groups have independent timers. Promotion is complete
        # only when both WAN and LAN VIPs are present within the same deadline.
        code,_=backup.execute("ip -o address show eth2 | grep -q 10.2.0.100 && ip -o address show eth1 | grep -q 10.1.0.100")
        if code == 0: break
        assert time.monotonic()-started < 1.0, "VIP promotion exceeded one second"
        time.sleep(0.01)
    elapsed=time.monotonic()-started
    backup.succeed("ip -o address show eth1 | grep -q 10.1.0.100")
    ${pkgs.lib.optionalString leased ''
    backup.succeed("ip -6 -o address show eth2 | grep fd42:2::100 | grep -v tentative")
    client.succeed("ping -6 -c1 -W2 fd42:2::100")
    new_mac=backup.succeed("cat /sys/class/net/eth2/address").strip()
    client.wait_until_succeeds(f"ip -6 neigh show fd42:2::100 | grep -q {new_mac}",timeout=3)
    ''}
    time.sleep(2)
    after=json.loads(client.succeed("cat /tmp/stream-status"))
    if after["count"] <= before+20 or after["maximum_gap"] >= 1.0:
        print(f"TCP progress before crash={before}, after={after}")
        print(backup.succeed("sentinel show firewall flows; sentinel show firewall statistics; ip -s neighbour; journalctl -u velstra --no-pager -n 100"))
        for node in (client, server):
            node.succeed("systemctl stop ha-packets")
            print(node.succeed("ip route; ip -s neighbour; journalctl -u ha-stream --no-pager -n 30"))
            print(node.succeed("${pkgs.tcpdump}/bin/tcpdump -n -e -r /tmp/ha-packets.pcap 2>&1 | tail -n 80"))
        print(server.succeed("cat /tmp/accepted"))
    assert after["count"] > before+20, "established TCP connection did not continue"
    assert after["maximum_gap"] < 1.0, after
    ${pkgs.lib.optionalString leased ''
    # Old process is paused, yet its still-live kernel must enforce expiry.
    master.succeed(python_command('import json,time; r=json.load(open("/run/velstra/ha/role.json")); assert r["deadline_ns"] < time.clock_gettime_ns(time.CLOCK_BOOTTIME)'))
    master.succeed("tc filter show dev eth1 ingress | grep -q bpf; tc filter show dev eth1 egress | grep -q bpf")
    ${pkgs.lib.optionalString (!wireguard) ''
    # Address ownership alone is insufficient: direct the probe at the old MAC
    # while its old kernel remains alive. No SYN may leave the fenced appliance.
    old_mac=master.succeed("cat /sys/class/net/eth2/address").strip()
    server.succeed("systemd-run --unit=ha-guard-capture ${pkgs.tcpdump}/bin/tcpdump -p -U -w /tmp/ha-guard.pcap -i eth1 'tcp dst port 8443 and tcp[13] & 2 != 0'")
    time.sleep(0.1)
    # Control ingress must not bypass the data-egress fence via XDP redirect.
    # A SYN-proxy may answer the client handshake locally; payload delivery
    # and the backend SYN capture must still prove the old data path is closed.
    witness.succeed("ip route replace 10.1.0.0/24 via 10.3.0.1 dev eth1")
    witness.fail(python_command('import socket; s=socket.create_connection(("10.1.0.10",8443),0.3); s.sendall(b"guard-probe"+bytes([10])); assert s.recv(100)==b"guard-probe"+bytes([10])'))
    master.succeed("systemctl stop velstra.service")
    client.succeed(f"ip neigh replace 10.2.0.100 lladdr {old_mac} nud permanent dev eth1")
    client.fail(python_command('import socket; s=socket.create_connection(("10.1.0.10",8443),0.3); s.sendall(b"guard-probe"+bytes([10])); assert s.recv(100)==b"guard-probe"+bytes([10])'))
    client.succeed("ip neigh del 10.2.0.100 dev eth1")
    server.succeed("systemctl stop ha-guard-capture")
    leaked=server.succeed("${pkgs.tcpdump}/bin/tcpdump -n -r /tmp/ha-guard.pcap 2>/dev/null")
    assert not leaked.strip(),f"expired HA kernel fence leaked a SYN: {leaked}"
    master.succeed("systemctl start velstra.service")
    ''}
    master.succeed("systemctl kill --kill-who=main --signal=SIGCONT wren.service")
    master.wait_until_succeeds(python_command('import json; assert json.load(open("/run/velstra/ha/agent.json"))["ready_term"] > 1'),timeout=20)
    # Preemption is allowed only after the successor's complete snapshot.
    master.wait_until_succeeds("ip -o address show eth2 | grep -q 10.2.0.100",timeout=20)
    backup.wait_until_succeeds("! ip -o address show eth2 | grep -q 10.2.0.100",timeout=10)
    # Isolate the old owner's entire control egress while its data links remain
    # up. The independent witness must admit exactly one forwarding successor.
    check_stream("synchronized failback after old-kernel packet fencing")
    master.succeed("tc qdisc replace dev eth3 root netem loss 100%")
    backup.wait_until_succeeds("ip -o address show eth2 | grep -q 10.2.0.100",timeout=10)
    master.wait_until_succeeds("! ip -o address show eth2 | grep -q 10.2.0.100",timeout=10)
    time.sleep(0.5)
    assert json.loads(client.succeed("cat /tmp/stream-status"))["count"]>before+30
    check_stream("control partition")
    master.succeed("tc qdisc del dev eth3 root")
    master.wait_until_succeeds("ip -o address show eth2 | grep -q 10.2.0.100",timeout=20)
    check_stream("control partition healed and preempted")
    # Abrupt process exits retain the independent pinned guard. A fresh agent
    # must import complete successor state before its higher priority can win.
    for service in ("velstra.service","wren.service"):
        master.succeed(f"systemctl kill --kill-who=main --signal=SIGKILL {service}")
        backup.wait_until_succeeds("ip -o address show eth2 | grep -q 10.2.0.100",timeout=10)
        check_stream(service+" abrupt exit")
        master.wait_until_succeeds("ip -o address show eth2 | grep -q 10.2.0.100",timeout=25)
        check_stream(service+" recovered and preempted")
    # Recreated non-VIP data links must also be fenced before they go up.
    old_index=master.succeed("cat /sys/class/net/dmz0/ifindex").strip()
    master.succeed("ip link del dmz0; ip link add dmz0 type dummy")
    master.wait_until_succeeds("test -e /sys/class/net/dmz0/ifindex && tc filter show dev dmz0 ingress | grep -q bpf && tc filter show dev dmz0 egress | grep -q bpf",timeout=10)
    assert master.succeed("cat /sys/class/net/dmz0/ifindex").strip()!=old_index
    master.succeed(python_command('import json,subprocess; old='+old_index+'; new=int(open("/sys/class/net/dmz0/ifindex").read()); entries=json.loads(subprocess.check_output(["bpftool","-j","map","dump","name","HA_IFACES"])); indexes={int.from_bytes(bytes(int(x,16) for x in row["key"]),"little") for row in entries}; assert old not in indexes and new in indexes, indexes'))
    master.wait_until_succeeds("ip -o address show eth2 | grep -q 10.2.0.100",timeout=20)
    # The witness outage removes authority from both live dataplanes.
    witness.succeed("systemctl stop sentinel-witness")
    time.sleep(0.5)
    for node in (master,backup):
        node.wait_until_succeeds("! ip -o address show eth2 | grep -q 10.2.0.100",timeout=5)
    witness.succeed("systemctl start sentinel-witness")
    master.wait_until_succeeds("ip -o address show eth2 | grep -q 10.2.0.100",timeout=20)
    # SIGSTOP the data-plane userspace: the independent guard must still expire.
    master.succeed("systemctl kill --kill-who=main --signal=SIGSTOP velstra.service")
    backup.wait_until_succeeds("ip -o address show eth2 | grep -q 10.2.0.100",timeout=10)
    master.succeed("systemctl kill --kill-who=main --signal=SIGCONT velstra.service")
    master.wait_until_succeeds("ip -o address show eth2 | grep -q 10.2.0.100",timeout=20)
    ''}
    check_stream("all fault and recovery scenarios")
    client.succeed("touch /tmp/stream-stop")
    client.wait_until_succeeds("test $(systemctl show ha-stream -p ExecMainStatus --value) = 0 && ! systemctl is-active --quiet ha-stream",timeout=10)
    server.succeed("test $(wc -l </tmp/accepted) = 1; grep -q '^${if synproxy then "10.2.0.10" else "10.1.0.100"}:' /tmp/accepted")
    ${pkgs.lib.optionalString leased ''
    # Both agents cold: the old terms cannot authorize empty new map instances.
    # Fresh cold votes from both members permit a new node-1 bootstrap epoch.
    for node in (master,backup):node.succeed("systemctl stop wren velstra")
    for node in (master,backup):node.succeed("systemctl start velstra wren")
    master.wait_until_succeeds("ip -o address show eth2 | grep -q 10.2.0.100",timeout=25)
    backup.wait_until_succeeds(python_command('import json; assert json.load(open("/run/velstra/ha/agent.json"))["ready_term"] > 0'),timeout=20)
    client.succeed(python_command('import socket; s=socket.create_connection(("10.1.0.10",8443),4); data=b"recovered"+bytes([10]); s.sendall(data); assert s.recv(100)==data'))
    ''}
    ${pkgs.lib.optionalString leased ''
    # Persistent filters must also reconcile removals: a former data link can
    # become a control link without rebooting or deleting unrelated TC filters.
    master.succeed("systemctl stop wren velstra")
    master.succeed(python_command('import tomllib,json,re; from pathlib import Path; text=Path("/run/sentinel/velstra.toml").read_text(); names=tomllib.loads(text)["ha"]["interfaces"]; names.remove("dmz0"); section=re.search(r"(?ms)^\\[ha\\]\\n(.*?)(?=^\\[|\\Z)",text); assert section; block=re.sub(r"(?ms)^interfaces\\s*=\\s*\\[.*?\\]","interfaces = "+json.dumps(names),section.group()); assert tomllib.loads(block)["ha"]["interfaces"]==names; Path("/tmp/guard-scope.toml").write_text(text[:section.start()]+block+text[section.end():])'))
    master.succeed("${self.packages.x86_64-linux.velstra}/bin/velstra ha-guard /tmp/guard-scope.toml")
    master.succeed("! tc filter show dev dmz0 ingress | grep -q bpf; ! tc filter show dev dmz0 egress | grep -q bpf; tc filter show dev eth2 ingress | grep -q bpf")
    master.succeed("${self.packages.x86_64-linux.velstra}/bin/velstra ha-guard /run/sentinel/velstra.toml")
    master.succeed("tc filter show dev dmz0 ingress | grep -q bpf; tc filter show dev dmz0 egress | grep -q bpf")
    master.succeed("systemctl start velstra wren")
    ''}
    print(f"ungraceful failover {elapsed:.3f}s; one TCP socket, ${if synproxy then "preserved SYN-proxy splice" else "preserved SNAT"}, {after}")
  '';
}
