# Real kernel failures must preserve the active firewall or block traffic.
{ pkgs, sentinelModule, sentinel, velstra, controller }:
let
  working = pkgs.writeText "working-policy.toml" ''
    default_action = "pass"
    drop_icmp = true
  '';
  broken = pkgs.writeText "candidate-policy.toml" ''
    default_action = "pass"
    [[policy]]
    id = 1
    name = "additional"
    default_action = "drop"
  '';
  fillMap = pkgs.writeText "fill-policy-map.py" ''
    import json
    import subprocess
    import sys
    from pathlib import Path
    info = json.loads(subprocess.check_output(["bpftool", "-j", "map", "show", "name", "CONFIG"]))
    if isinstance(info, list):
        info = info[0]
    print(info, flush=True)
    commands = []
    for number in range(10000, 10000 + info["max_entries"] - 1):
        key = number.to_bytes(info["bytes_key"], "little").hex(" ")
        if sys.argv[1] == "fill":
            value = (1).to_bytes(info["bytes_value"], "little").hex(" ")
            commands.append(f"map update id {info['id']} key hex {key} value hex {value}")
        else:
            commands.append(f"map delete id {info['id']} key hex {key}")
    batch = Path("/run/verify-map.batch")
    batch.write_text("\n".join(commands) + "\n")
    subprocess.run(["bpftool", "batch", "file", str(batch)], check=True)
  '';
  backendA = pkgs.writeTextDir "index.html" "temporary-backend";
  backendB = pkgs.writeTextDir "index.html" "configured-backend";
  configured = pkgs.writeText "static-mapping.toml" (builtins.readFile broken + ''
    [[port_forward]]
    policy = 0
    proto = "tcp"
    port = 33001
    dst_ip = "198.51.100.2"
    dst_port = 8082
  '');
in pkgs.testers.runNixOSTest {
  name = "sentinel-configuration-transaction";
  nodes.machine = {
    imports = [ sentinelModule ];
    virtualisation.memorySize = 2048;
    virtualisation.cores = 2;
    boot.kernel.sysctl."net.ipv4.ip_forward" = 1;
    boot.kernel.sysctl."net.ipv4.conf.all.rp_filter" = 0;
    boot.kernel.sysctl."net.ipv4.conf.default.rp_filter" = 0;
    # Reverse DNAT presents the local frontend IP as the reply source at
    # XDP ingress. Match the isolated NAT test's kernel-forwarding prerequisites.
    boot.kernel.sysctl."net.ipv4.conf.all.accept_local" = 1;
    environment.systemPackages = [ pkgs.bpftools pkgs.python3 pkgs.curl pkgs.tcpdump ];
  };
  testScript = ''
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("sentinel-boot.service")
    machine.succeed("systemctl stop velstra.service")
    machine.succeed("systemctl mask --runtime velstra.service")
    machine.succeed("ip netns add verify-client")
    machine.succeed("ip link add verify-u type veth peer name verify-up")
    machine.succeed("ip link set verify-up netns verify-client")
    machine.succeed("ip link set verify-u up")
    machine.succeed("ip address add 192.0.2.1/24 dev verify-u")
    machine.succeed("ip netns exec verify-client ip link set lo up")
    machine.succeed("ip netns exec verify-client ip link set verify-up up")
    machine.succeed("ip netns exec verify-client ip address add 192.0.2.2/24 dev verify-up")
    traffic = "ip netns exec verify-client ping -c 1 -W 1 192.0.2.1"
    machine.succeed(traffic)
    machine.succeed("mkdir -p /run/verify-controller; cp ${working} /run/verify-controller/probe.toml")
    machine.succeed("systemd-run --unit=verify-controller ${controller}/bin/velstra-controller serve --listen 127.0.0.1:50051 --config-dir /run/verify-controller --poll-interval 1")
    machine.wait_for_open_port(50051)
    machine.succeed("systemd-run --unit=verify-agent ${velstra}/bin/velstra run --iface verify-u --auto-attach verify-b --xdp-mode skb --egress --mapping-socket /run/verify-mapping.sock --node-id probe --controller http://127.0.0.1:50051 --query-socket /run/verify-agent.sock")
    machine.wait_until_succeeds("test -S /run/verify-agent.sock", timeout=30)
    machine.fail(traffic)
    query = "${sentinel}/bin/sentinel agent-query --socket /run/verify-agent.sock "
    mapping = "${sentinel}/bin/sentinel agent-query --socket /run/verify-mapping.sock "
    publish = "cp {} /run/verify-controller/probe.next; mv /run/verify-controller/probe.next /run/verify-controller/probe.toml"
    pid = machine.succeed("systemctl show verify-agent -p MainPID --value").strip()
    machine.succeed("ip netns add verify-backend")
    machine.succeed("ip link add verify-b type veth peer name verify-bp")
    machine.succeed("ip link set verify-bp netns verify-backend")
    machine.succeed("ip link set verify-b up; ip address add 198.51.100.1/24 dev verify-b")
    machine.succeed("ip netns exec verify-backend ip link set lo up; ip netns exec verify-backend ip link set verify-bp up")
    machine.succeed("ip netns exec verify-backend ip address add 198.51.100.2/24 dev verify-bp")
    machine.succeed("ip netns exec verify-backend ip route add 192.0.2.0/24 via 198.51.100.1")
    machine.succeed("systemd-run --unit=verify-http-a ip netns exec verify-backend ${pkgs.python3}/bin/python3 -m http.server 8081 --directory ${backendA}")
    machine.succeed("systemd-run --unit=verify-http-b ip netns exec verify-backend ${pkgs.python3}/bin/python3 -m http.server 8082 --directory ${backendB}")
    machine.wait_until_succeeds("curl --fail --max-time 2 http://198.51.100.2:8081 | grep temporary-backend", timeout=20)
    machine.succeed(mapping + "'map tcp 33001 198.51.100.2 8081 0 300' | grep '33001 ->'")
    fetch = "ip netns exec verify-client curl --fail --max-time 3 http://192.0.2.1:33001"
    machine.succeed("systemd-run --unit=verify-nat-capture ${pkgs.tcpdump}/bin/tcpdump -U -n -i any -w /run/verify-nat.pcap tcp")
    machine.wait_until_succeeds("journalctl -u verify-nat-capture --no-pager | grep 'listening on'", timeout=10)
    try:
        machine.succeed(fetch + " | grep temporary-backend")
    except Exception:
        machine.succeed("systemctl kill --signal=SIGINT verify-nat-capture.service")
        machine.wait_until_succeeds("! systemctl is-active --quiet verify-nat-capture", timeout=10)
        print(machine.succeed("${pkgs.tcpdump}/bin/tcpdump -n -vv -r /run/verify-nat.pcap 2>&1"))
        print(machine.succeed(query + "'flows 0'"))
        print(machine.succeed("journalctl -u verify-agent -u verify-http-a --no-pager"))
        raise
    machine.succeed("python3 ${fillMap} fill")
    machine.succeed("systemd-run --unit=verify-denied-pings ip netns exec verify-client ${pkgs.iputils}/bin/ping -n -i 0.01 -w 7 192.0.2.1")
    machine.succeed(publish.format("${broken}"))
    machine.wait_until_succeeds("journalctl -u verify-agent --no-pager | grep 'previous configuration restored'", timeout=30)
    machine.wait_until_succeeds("! systemctl is-active --quiet verify-denied-pings", timeout=20)
    denied = machine.succeed("journalctl -u verify-denied-pings --no-pager")
    print(denied)
    assert "0 received" in denied, denied
    machine.fail(traffic)
    print(machine.succeed(query + "status | grep '^Ready'"))
    machine.succeed(query + "status | grep 'Last update:'")
    machine.succeed(fetch + " | grep temporary-backend", timeout=20)
    machine.succeed("python3 ${fillMap} clear")
    machine.wait_until_succeeds(traffic, timeout=30)
    machine.succeed(fetch + " | grep temporary-backend", timeout=20)
    machine.succeed("bpftool map update name APPLY_STATE key hex 00 00 00 00 value hex 02 00 00 00")
    machine.wait_until_succeeds("journalctl -u verify-agent --no-pager | grep 'retrying configuration recovery'", timeout=15)
    machine.wait_until_succeeds(query + "status | grep '^Ready'", timeout=15)
    machine.succeed(fetch + " | grep temporary-backend")
    assert machine.succeed("systemctl show verify-agent -p MainPID --value").strip() == pid
    machine.succeed("bpftool map freeze name CONFIG")
    machine.succeed(publish.format("${working}"))
    machine.wait_until_succeeds(query + "status | grep '^Failed (traffic blocked)'", timeout=30)
    machine.fail(fetch)
    machine.fail(traffic)
    print(machine.succeed(query + "status"))
    print(machine.succeed("journalctl -u verify-agent --no-pager"))
    machine.succeed("systemctl stop verify-agent.service verify-controller.service")

    # Static appliance forwards are file-config-only in the current protocol.
    # Exercise that real path separately rather than assuming gRPC carries them.
    machine.succeed("systemd-run --unit=verify-file-agent ${velstra}/bin/velstra run --iface verify-u verify-b --egress --xdp-mode skb --config ${configured} --query-socket /run/verify-agent.sock --mapping-socket /run/verify-mapping.sock")
    machine.wait_until_succeeds(query + "status | grep '^Ready'", timeout=30)
    machine.wait_until_succeeds(fetch + " | grep configured-backend", timeout=20)
    machine.succeed(mapping + "'map tcp 33001 198.51.100.2 8081 0 300' | grep 'forwarded by the configuration'")
    machine.succeed(mapping + "'unmap tcp 33001 0'")
    machine.succeed(fetch + " | grep configured-backend")
    machine.succeed("bpftool map update name APPLY_STATE key hex 00 00 00 00 value hex 02 00 00 00")
    machine.wait_until_succeeds("journalctl -u verify-file-agent --no-pager | grep 'retrying configuration recovery'", timeout=15)
    machine.wait_until_succeeds(query + "status | grep '^Ready'", timeout=15)
    machine.succeed(fetch + " | grep configured-backend")
    machine.succeed("systemctl stop verify-file-agent.service")
  '';
}
