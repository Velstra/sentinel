{ pkgs, self, synproxy ? false, leased ? false, wireguard ? false, masquerade ? false, logStall ? false }:
let
  name = if logStall then "sentinel-ha-log-stall" else if masquerade then "sentinel-ha-masquerade-failover" else if wireguard then "sentinel-ha-wireguard-failover" else if leased && synproxy then "sentinel-ha-witness-synproxy-failover" else if leased then "sentinel-ha-witness-failover" else if synproxy then "sentinel-ha-synproxy-failover" else "sentinel-ha-failover";
  secret = "3495f763f76345f694398991ac86dc4f1b6c48ab2334e10f5b4a3ddd1fc4bd50";
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
    # A realistic pair: rules `to firewall` compile to each member's OWN
    # addresses (HA-02). A fixture without them hid a readiness digest that
    # differed between members on every real deployment.
    zone = { wan.default_action = "drop"; lan.default_action = "drop"; sync.default_action = "accept"; firewall.local = true; };
    rule = [{ name = "echo"; from = if wireguard then "vpn" else "lan"; proto = "tcp"; port = 8443; action = "accept"; }
      { name = "mgmt-ssh"; from = "lan"; to = "firewall"; proto = "tcp"; port = 22; action = "accept"; }
      { name = "mgmt-api"; from = "wan"; to = "firewall"; proto = "tcp"; port = 8443; action = "accept"; }]
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
  # The NixOS test driver forwards every journal line, debug included, to the
  # VM's emulated serial console, and journald writes it synchronously. The
  # members' debug logging and periodic statistics tables back that console
  # up; journald then stops reading, the agents' log writes block, wren's
  # 25 ms lease renewals stall past the 250 ms witness lease, and ownership
  # flaps in a quiet pair (measured: 2 of 3 runs reached term 3 before any
  # fault). An appliance does not forward its journal to a console. The full
  # journal stays available to the diagnostics through journalctl.
  quietConsole = { lib, ... }: {
    services.journald.extraConfig = lib.mkAfter "MaxLevelConsole=warning\n";
  };
  firewall = number: priority: { lib, ... }: {
    imports = [ self.nixosModules.sentinel quietConsole ]
      ++ lib.optional (logStall && number == "1") logStallOutputs;
    environment.systemPackages=[pkgs.python3 pkgs.wireguard-tools pkgs.bpftools pkgs.curl];
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
  # checks.ha-log-stall: on the master, wren's and the agent's stdout and
  # stderr go to FIFOs that a holder keeps open. Until /run/log-stall/stop
  # exists the holder copies them to its own journal; then it stops reading
  # but keeps them open, which is what a journal that stopped reading looks
  # like to a writer. 4 KiB pipes and a one-line log queue make a quiet daemon
  # reach the blocked (or, fixed, the dropping) path within seconds, without
  # loading the VM the way console forwarding does.
  logStallHolder = pkgs.writeText "log-stall-holder.py" ''
    import fcntl, os, select, subprocess, sys, time
    paths = ["/run/log-stall/wren.fifo", "/run/log-stall/velstra.fifo"]
    for path in paths:
        if not os.path.exists(path):
            os.mkfifo(path, 0o600)
    fds = {os.open(path, os.O_RDWR | os.O_NONBLOCK): path for path in paths}
    for fd in fds:
        fcntl.fcntl(fd, fcntl.F_SETPIPE_SZ, 4096)
    subprocess.run(["systemd-notify", "--ready"], check=True)
    stopped = False
    while True:
        if os.path.exists("/run/log-stall/stop"):
            if not stopped:
                print("log-stall holder: no longer reading", flush=True)
                stopped = True
            time.sleep(0.2)
            continue
        if stopped:
            print("log-stall holder: reading again", flush=True)
            stopped = False
        ready, _, _ = select.select(list(fds), [], [], 0.2)
        for fd in ready:
            try:
                data = os.read(fd, 65536)
            except BlockingIOError:
                continue
            sys.stdout.write(data.decode(errors="replace"))
        sys.stdout.flush()
  '';
  # The test driver forwards every journal line to each VM's emulated serial
  # console, synchronously, which starves a VM of CPU and moves ownership by
  # itself; an appliance does not do that. Keep it to warnings in this check
  # so what it measures is the daemons' own log writes.
  logStallOutputs = { lib, ... }: {
    systemd.services.log-stall-holder = {
      wantedBy = [ "multi-user.target" ];
      before = [ "wren.service" "velstra.service" ];
      serviceConfig = {
        Type = "notify";
        NotifyAccess = "all";
        RuntimeDirectory = "log-stall";
        RuntimeDirectoryPreserve = "yes";
        ExecStart = "${pkgs.python3}/bin/python3 ${logStallHolder}";
      };
    };
    systemd.services.wren = {
      requires = [ "log-stall-holder.service" ];
      after = [ "log-stall-holder.service" ];
      environment.WREN_LOG_QUEUE_LINES = "1";
      serviceConfig.StandardOutput = lib.mkForce "file:/run/log-stall/wren.fifo";
      serviceConfig.StandardError = lib.mkForce "file:/run/log-stall/wren.fifo";
    };
    systemd.services.velstra = {
      requires = [ "log-stall-holder.service" ];
      after = [ "log-stall-holder.service" ];
      environment.VELSTRA_LOG_QUEUE_LINES = "1";
      serviceConfig.StandardOutput = lib.mkForce "file:/run/log-stall/velstra.fifo";
      serviceConfig.StandardError = lib.mkForce "file:/run/log-stall/velstra.fifo";
    };
  };
  # checks.ha-log-stall: the master's log outputs stop being read (see
  # logStallOutputs) while both daemons keep logging. A daemon whose logging
  # blocks then stalls: wren's 25 ms lease renewals miss the 250 ms witness
  # lease, or the agent's HA heartbeat goes stale, and ownership moves with no
  # fault. Fixed, both drop and count log lines instead, and the term does not
  # move for 60 s. Only the quiet pair is needed, not the fault matrix.
  logStallScript = ''
    import time, shlex
    def python_command(script):
        return "${pkgs.python3}/bin/python3 -c " + shlex.quote(script)
    start_all()
    witness.wait_for_unit("sentinel-witness.service")
    for node in (master,backup):
        node.wait_for_unit("velstra.service")
        node.wait_for_unit("wren.service")
    master.wait_until_succeeds("journalctl -u log-stall-holder --no-pager | grep -q 'authenticated TCP listening'",timeout=90)
    master.wait_until_succeeds("ip -o address show eth2 | grep -q 10.2.0.100",timeout=60)
    master.wait_until_succeeds(python_command('import json,subprocess; state=json.loads(subprocess.check_output(["sentinel","agent-query","ha-status"])); assert state["role"]=="Master"'),timeout=30)
    backup.wait_until_succeeds("sentinel show ha | grep -qx 'HA Backup'",timeout=30)
    term_script='import json; print(json.load(open("/run/velstra/ha/role.json"))["authority"]["term"])'
    terms_before={n.name:int(n.succeed(python_command(term_script)).strip()) for n in (master,backup)}
    master.succeed("touch /run/log-stall/stop")
    master.wait_until_succeeds("journalctl -u log-stall-holder --no-pager | grep -q 'no longer reading'",timeout=10)
    # wren is quiet when nothing changes; each routing reload logs its
    # admission. The agent prints its statistics table every 5 s.
    master.succeed("systemd-run --unit=log-stall-load --setenv=PATH=/run/current-system/sw/bin /run/current-system/sw/bin/sh -c 'for i in $(seq 400); do timeout 2 wren --socket /run/wren/wren.sock reload >/dev/null 2>&1; done'")
    # Then make the lease task itself log: 10 s in, once the pipes are full,
    # delay the master's packets on its control link (eth3, to the witness)
    # by 21 ms for 3 s. A witness exchange waits on three of them (connect,
    # handshake, request), about 65 ms: inside the 80 ms I/O budget, so every
    # renewal still succeeds, but past the 60 ms threshold of the "close to
    # its I/O budget" warning, which the lease task writes. Blocking, that
    # write never returns and the lease lapses; lossy, the line is dropped.
    master.succeed("systemd-run --unit=log-stall-slow --setenv=PATH=/run/current-system/sw/bin /run/current-system/sw/bin/sh -c 'sleep 10; tc qdisc add dev eth3 root netem delay 21ms; sleep 3; tc qdisc del dev eth3 root'")
    seen=set()
    quiet_end=time.monotonic()+60
    while time.monotonic()<quiet_end:
        seen.add(tuple(int(n.succeed(python_command(term_script)).strip()) for n in (master,backup)))
        time.sleep(1)
    terms_after={n.name:int(n.succeed(python_command(term_script)).strip()) for n in (master,backup)}
    print("log-stall terms", terms_before, terms_after, sorted(seen))
    if not (terms_after==terms_before and seen=={(terms_before["master"],terms_before["backup"])}):
        master.succeed("rm -f /run/log-stall/stop")
        time.sleep(3)
        print(master.execute("journalctl -u log-stall-holder --no-pager -n 80 -o cat")[1])
        print(backup.execute("journalctl -u wren --no-pager -n 40 -o cat")[1])
        raise AssertionError(("HA ownership moved while the log output was blocked", terms_before, terms_after, sorted(seen)))
    master.succeed("sentinel show ha | grep -qx 'HA Master'")
    # Both daemons reached the drop path and count it.
    wren_dropped=int(master.succeed("timeout 5 wren --socket /run/wren/wren.sock show metrics | awk '/^wren_log_lines_dropped_total / {print $2}'").strip() or 0)
    agent_dropped=int(master.succeed("timeout 5 sentinel show firewall statistics | awk '/log_lines_dropped/ {print $2}'").strip() or 0)
    print("log-stall dropped", {"wren": wren_dropped, "agent": agent_dropped})
    assert wren_dropped>0 and agent_dropped>0, (wren_dropped, agent_dropped)
  '';
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
    # Through WireGuard the timeout must outlast one handshake retry (5 s).
    connection = socket.create_connection(("10.1.0.10",8443),timeout=${if wireguard then "8" else "4"})
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
      imports=[self.nixosModules.sentinel quietConsole];
      virtualisation.vlans=[3];virtualisation.memorySize=1536;
      environment.systemPackages=[pkgs.python3];
      networking.firewall.enable=lib.mkForce false;
      services.velstra.interface=lib.mkForce "eth1";
      services.velstra.appliance=lib.mkForce ((pkgs.formats.toml {}).generate "witness-appliance.toml" {
        # Only the derived witness key (`sentinel ha witness-key`), never the
        # members' credential; only the two members may open sessions. A long
        # peer silence gives the lone-survivor check room to observe the wait.
        system={hostname="witness";ha-witness={listen="10.3.0.3:5440";key="ede32ebbc01f514a3c8bde6847eea86ad380a43132139a495002b91c52d0ac1a";cluster="vm-cluster-0123456789";member=["10.3.0.1" "10.3.0.2"];peer-silence-ms=20000;};};
        interface=[{name="eth1";address="10.3.0.3/24";zone="control";}];
        firewall.default_action="accept";
      });
    };

  };
  testScript = if logStall then logStallScript else ''
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
    # A WireGuard handover also needs the client's tunnel to handshake with
    # the new owner. The new owner initiates at once, so it normally costs no
    # more than any handover (about 1 s). The bound allows one lost
    # initiation: WireGuard retries after REKEY_TIMEOUT (5 s) plus up to
    # REKEY_TIMEOUT_JITTER_MAX (1/3 s; WireGuard protocol, Linux
    # drivers/net/wireguard/messages.h), on top of the slowest measured
    # handover without WireGuard (1.28 s over 13 runs) and 0.5 s margin:
    # 7.2 s. A handshake that needs two retries (2 x REKEY_TIMEOUT) fails it.
    handover_bound=${if wireguard then "7.2" else "3.0"}
    def wait_forwarding(label, started, bound, paused=None):
        # Forwarding has resumed once the established stream advances again.
        before=json.loads(client.succeed("cat /tmp/stream-status"))["count"]
        while True:
            current=json.loads(client.succeed("cat /tmp/stream-status"))["count"]
            if current>before+3:
                elapsed=time.monotonic()-started
                print(f"{label}: forwarding resumed {elapsed:.2f}s after the fault")
                return elapsed
            if time.monotonic()-started>bound:
                # Diagnostics run commands on every member: a paused VM would
                # hang them, so resume it first.
                if paused is not None:
                    paused.send_monitor_command("cont")
                check_stream(label+f" (forwarding not resumed within {bound}s)")
                raise AssertionError(f"{label}: forwarding did not resume within {bound}s")
            time.sleep(0.05)
    def agent_caught_up(node):
        # Eligible again, holding the cluster's current generation: what the
        # witness needs to hand this member authority at the next failure.
        return python_command('import json; a=json.load(open("/run/velstra/ha/agent.json")); r=json.load(open("/run/velstra/ha/role.json")); assert a["eligible"] and a["ready_term"]==r["authority"]["term"]>0 and a["policy"]==r["authority"]["policy"], (a,r["authority"])')
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
    # The fixture must carry `to firewall` rules, or it proves nothing about
    # HA-02. They compile symbolically (`dst-local`, no address; each agent
    # expands them to its own member's addresses, DP-16), so both members
    # compile the same local rules.
    local_script='import tomllib,json; d=tomllib.load(open("/run/sentinel/velstra.toml","rb")); print(json.dumps(sorted([r.get("name",""),r.get("proto",""),r.get("port",0),"dst" in r or "src" in r] for p in d["policy"] for r in p.get("port_rule",[]) if r.get("dst-local"))))'
    local_rules={n.name:json.loads(n.succeed(python_command(local_script))) for n in (master,backup)}
    assert local_rules["master"] and local_rules["master"]==local_rules["backup"],local_rules
    assert not any(r[3] for r in local_rules["master"]),local_rules
    ${pkgs.lib.optionalString leased ''
    # Keep live management telemetry active throughout the HA fault matrix.
    # Querying state must not interfere with lease refresh or TCP continuity.
    for node in (master,backup):
        node.wait_for_unit("sentinel-api.service")
        node.succeed("curl -skN --max-time 180 -H 'Authorization: Bearer ${secret}' https://127.0.0.1:8080/api/v1/telemetry > /tmp/live-management 2>/tmp/live-management-errors &")
    witness.succeed("! grep -rq '${secret}' /var/lib/sentinel /run/sentinel")
    # A source that is not a member is closed before it can hold a session.
    witness.succeed(python_command('import socket; s=socket.create_connection(("10.3.0.3",5440),1); s.settimeout(1); assert s.recv(1)==b""'))
    master.wait_until_succeeds(python_command('import json,subprocess; state=json.loads(subprocess.check_output(["sentinel","agent-query","ha-status"])); assert state["role"]=="Master" and state["sync_age_ms"] is None'),timeout=20)
    backup.wait_until_succeeds(python_command('import json,subprocess; state=json.loads(subprocess.check_output(["sentinel","agent-query","ha-status"])); assert state["role"]=="Backup" and state["sync_age_ms"] is not None and state["sync_age_ms"]<1500'),timeout=20)
    backup.wait_until_succeeds("sentinel show ha | grep -qx 'HA Backup'",timeout=20)
    master.succeed("sentinel show ha | grep -qx 'HA Master'")
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
    backup.wait_until_succeeds(python_command('import json; frames=[json.loads(line[5:]) for line in open("/tmp/live-management") if line.startswith("data:")]; assert any(frame.get("ha",{}).get("role")=="Master" for frame in frames if frame.get("ha"))'),timeout=15)
    ''}
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
    # HA-04: SIGKILL every process of the owner's unit, as an OOM kill or a
    # crash does. The warm standby must be forwarding within a bound, and the
    # restarted member must rejoin by itself (no reboot, no manual restart).
    for service in ("velstra.service","wren.service"):
        started=time.monotonic()
        master.succeed(f"systemctl kill --kill-who=all --signal=SIGKILL {service}")
        wait_forwarding(service+" SIGKILL on the owner",started,handover_bound)
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
    check_stream("recreated data link")
    # The witness outage removes authority from both live dataplanes.
    witness_lost=time.monotonic()
    witness.succeed("systemctl stop sentinel-witness")
    time.sleep(0.5)
    for node in (master,backup):
        node.wait_until_succeeds("! ip -o address show eth2 | grep -q 10.2.0.100",timeout=5)
    witness.succeed("systemctl start sentinel-witness")
    master.wait_until_succeeds("ip -o address show eth2 | grep -q 10.2.0.100",timeout=20)
    # Witness loss stops forwarding by design. Wait for this outage to end
    # before the next fault: chaining two faults onto one stream measured
    # neither, and (with the WireGuard handover) overran the stream's timeout.
    wait_forwarding("witness outage (by design)",witness_lost,10.0)
    # SIGSTOP the data-plane userspace: the independent guard must still expire.
    master.succeed("systemctl kill --kill-who=main --signal=SIGSTOP velstra.service")
    backup.wait_until_succeeds("ip -o address show eth2 | grep -q 10.2.0.100",timeout=10)
    master.succeed("systemctl kill --kill-who=main --signal=SIGCONT velstra.service")
    master.wait_until_succeeds("ip -o address show eth2 | grep -q 10.2.0.100",timeout=20)
    # HA-03: pause a whole member VM (hypervisor stall, live migration, suspend).
    # Its clock stops with it. A resumed member must become an eligible, caught
    # up standby again by itself, and the pair must survive the NEXT failure
    # too, without restarting velstra anywhere.
    def resume(node):
        # A resumed VM's wall clock is behind by its pause, and these VMs run
        # no NTP. That is the case under test: the members share one
        # WireGuard identity, a remote peer accepts a handshake from it only
        # with a newer wall-clock timestamp than the last one, and the new
        # owner itself must bring its clock up to its predecessor's before it
        # initiates (wren-ha clock). The test must not resync it.
        node.send_monitor_command("cont")
    def clock_caught_up(label):
        # The returning owner stepped its wall clock to its predecessor's.
        status=json.loads(master.succeed("cat /run/velstra/ha/clock.json"))
        ours=float(master.succeed("date +%s.%N")); theirs=float(backup.succeed("date +%s.%N"))
        print(f"{label}: clock decision {status}, master-backup {ours-theirs:+.3f}s")
        assert status["action"]=="step" and "error" not in status, (label,status)
        assert abs(theirs-ours) < 1.0, (label,ours,theirs)
    def pause(node, seconds):
        node.send_monitor_command("stop")
        time.sleep(seconds)
        resume(node)
    # (1) The owner pauses: the standby takes over; the owner returns, catches
    # up from its successor and (preempt) takes ownership back.
    # The stream must be alive going in, or a pause could not be judged.
    check_stream("before the VM pause scenarios")
    started=time.monotonic()
    master.send_monitor_command("stop")
    wait_forwarding("owner VM paused",started,max(5.0,handover_bound),paused=master)
    backup.wait_until_succeeds("ip -o address show eth2 | grep -q 10.2.0.100",timeout=10)
    time.sleep(8)
    resume(master)
    master.wait_until_succeeds("ip -o address show eth2 | grep -q 10.2.0.100",timeout=30)
    master.wait_until_succeeds(agent_caught_up(master),timeout=20)
    ${pkgs.lib.optionalString wireguard ''
    clock_caught_up("paused owner resumed and preempted")
    ''}
    check_stream("paused owner resumed and preempted")
    # (2) The standby pauses and resumes: it must catch up again by itself.
    pause(backup,8)
    backup.wait_until_succeeds(agent_caught_up(backup),timeout=20)
    # (3) The next failure: the resumed standby takes over.
    started=time.monotonic()
    master.send_monitor_command("stop")
    wait_forwarding("second consecutive pause failover",started,max(5.0,handover_bound),paused=master)
    backup.wait_until_succeeds("ip -o address show eth2 | grep -q 10.2.0.100",timeout=10)
    time.sleep(3)
    resume(master)
    master.wait_until_succeeds("ip -o address show eth2 | grep -q 10.2.0.100",timeout=30)
    # Preemption is a handover like any other, with the same bound: a
    # WireGuard client must first handshake with the returning owner.
    wait_forwarding("resumed owner preempted after the second pause",time.monotonic(),handover_bound)
    ${pkgs.lib.optionalString wireguard ''
    clock_caught_up("resumed owner preempted after the second pause")
    ''}
    check_stream("both members recovered from VM pauses")
    ''}
    check_stream("all fault and recovery scenarios")
    client.succeed("touch /tmp/stream-stop")
    client.wait_until_succeeds("test $(systemctl show ha-stream -p ExecMainStatus --value) = 0 && ! systemctl is-active --quiet ha-stream",timeout=10)
    server.succeed("test $(wc -l </tmp/accepted) = 1; grep -q '^${if synproxy then "10.2.0.10" else "10.1.0.100"}:' /tmp/accepted")
    ${pkgs.lib.optionalString leased ''
    # HA-04, double fault: the owner's agent dies while the witness is away.
    # The restarted owner is cold and the standby's snapshot goes stale, so
    # neither can be granted on its own state. Once the witness is back, the
    # pair must open a new epoch by itself, with no agent restarted by hand.
    master.wait_until_succeeds("ip -o address show eth2 | grep -q 10.2.0.100",timeout=25)
    backup.wait_until_succeeds(python_command('import json; assert json.load(open("/run/velstra/ha/agent.json"))["ready_term"] > 0'),timeout=20)
    witness.succeed("systemctl stop sentinel-witness")
    master.succeed("systemctl kill --kill-who=all --signal=SIGKILL velstra.service")
    master.wait_until_succeeds("systemctl is-active velstra.service",timeout=20)
    time.sleep(3)
    started=time.monotonic()
    witness.succeed("systemctl start sentinel-witness")
    try:
        client.wait_until_succeeds(python_command('import socket; s=socket.create_connection(("10.1.0.10",8443),2); data=b"double-fault"+bytes([10]); s.sendall(data); assert s.recv(100)==data'),timeout=30)
    except Exception:
        for node in (master,backup):
            print(node.execute("sentinel show ha; cat /run/velstra/ha/role.json /run/velstra/ha/agent.json; journalctl -u velstra -u wren --no-pager -n 40")[1])
        raise
    print(f"double fault (owner agent crash during witness outage) recovered {time.monotonic()-started:.1f}s after the witness returned")
    print(backup.succeed("sentinel show ha; journalctl -u velstra --no-pager | grep -E 'discarded replicated state' || true"))
    ''}
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
    # Reclassifying a resolved binding requires an explicit exact partition.
    # The incomplete old fixture must be rejected without removing any guard.
    scope_script = "\n".join([
        "import tomllib,json,re; from pathlib import Path",
        'text=Path("/run/sentinel/velstra.toml").read_text(); cfg=tomllib.loads(text)',
        'names=cfg["ha"]["interfaces"]; names.remove("dmz0")',
        r'section=re.search(r"(?ms)^\[ha\]\n(.*?)(?=^\[|\Z)",text); assert section',
        r'block=re.sub(r"(?ms)^interfaces\s*=\s*\[.*?\]","interfaces = "+json.dumps(names),section.group())',
        'assert tomllib.loads(block)["ha"]["interfaces"]==names',
        'Path("/tmp/guard-scope-incomplete.toml").write_text(text[:section.start()]+block+text[section.end():])',
        'controls=cfg["ha"]["control_interfaces"]; assert "dmz0" not in controls; controls.append("dmz0")',
        r'block=re.sub(r"(?ms)^control_interfaces\s*=\s*\[.*?\]","control_interfaces = "+json.dumps(controls),block)',
        'moved=tomllib.loads(block)["ha"]; assert moved["interfaces"]==names and moved["control_interfaces"]==controls and set(names).isdisjoint(controls)',
        'Path("/tmp/guard-scope.toml").write_text(text[:section.start()]+block+text[section.end():])',
    ])
    master.succeed(python_command(scope_script))
    status, diagnostic = master.execute("${self.packages.x86_64-linux.velstra}/bin/velstra ha-guard /tmp/guard-scope-incomplete.toml 2>&1")
    assert status != 0 and "HA guard/control sets must cover every resolved binding" in diagnostic, diagnostic
    master.succeed("tc filter show dev dmz0 ingress | grep -q bpf; tc filter show dev dmz0 egress | grep -q bpf; tc filter show dev eth2 ingress | grep -q bpf")
    master.succeed("${self.packages.x86_64-linux.velstra}/bin/velstra ha-guard /tmp/guard-scope.toml")
    master.succeed("! tc filter show dev dmz0 ingress | grep -q bpf; ! tc filter show dev dmz0 egress | grep -q bpf; tc filter show dev eth2 ingress | grep -q bpf")
    master.succeed("${self.packages.x86_64-linux.velstra}/bin/velstra ha-guard /run/sentinel/velstra.toml")
    master.succeed("tc filter show dev dmz0 ingress | grep -q bpf; tc filter show dev dmz0 egress | grep -q bpf")
    master.succeed("systemctl start velstra wren")
    ''}
    ${pkgs.lib.optionalString leased ''
    # A lone survivor. Node 1 is lost for good and node 2 then restarts its
    # agent and coordinator, so it is cold and can neither retry a claim nor
    # win a two-member cold vote. Once the witness has heard nothing from node
    # 1 for the configured peer silence, node 2 alone opens a new empty epoch.
    master.wait_until_succeeds("ip -o address show eth2 | grep -q 10.2.0.100",timeout=25)
    backup.wait_until_succeeds(python_command('import json; assert json.load(open("/run/velstra/ha/agent.json"))["ready_term"] > 0'),timeout=20)
    lost=time.monotonic()
    # crash() waits for QEMU to exit. Start before cutting power, otherwise its
    # blocking wait is wrongly subtracted from the witness's peer-silence age.
    master.crash()
    backup.wait_until_succeeds("ip -o address show eth2 | grep -q 10.2.0.100",timeout=10)
    backup.succeed("systemctl stop wren velstra")
    backup.succeed("systemctl start velstra wren")
    backup.wait_until_succeeds("sentinel show ha | grep -q '^HA Backup (not ready: '",timeout=10)
    print(backup.succeed("sentinel show ha; sentinel show vrrp"))
    backup.wait_until_succeeds("ip -o address show eth2 | grep -q 10.2.0.100",timeout=40)
    waited=time.monotonic()-lost
    assert waited>=19.5,f"lone cold member took over {waited:.1f}s after its peer went silent"
    backup.wait_until_succeeds("sentinel show ha | grep -qx 'HA Master'",timeout=10)
    client.wait_until_succeeds(python_command('import socket; s=socket.create_connection(("10.1.0.10",8443),4); data=b"survivor"+bytes([10]); s.sendall(data); assert s.recv(100)==data'),timeout=15)
    ''}
    print(f"ungraceful failover {elapsed:.3f}s; one TCP socket, ${if synproxy then "preserved SYN-proxy splice" else "preserved SNAT"}, {after}")
  '';
}
