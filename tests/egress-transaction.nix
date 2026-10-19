# Real kernel failures must preserve the active firewall or block traffic.
{ pkgs, sentinelModule, sentinel, velstra, controller }:
let
  working = pkgs.writeText "working-policy.toml" ''
    default_action = "pass"
    drop_icmp = true
    [[policy]]
    id = 7
    default_action = "pass"
    egress_default_drop = true
    [[interface]]
    name = "verify-e"
    policy = 7
  '';
  broken = pkgs.writeText "candidate-policy.toml" ''
    default_action = "pass"
    [[policy]]
    id = 1
    name = "additional"
    default_action = "drop"
  '';
in pkgs.testers.runNixOSTest {
  name = "sentinel-configuration-egress-rollback";
  nodes.machine = {
    imports = [ sentinelModule ];
    virtualisation.memorySize = 2048;
    virtualisation.cores = 2;
    boot.kernel.sysctl."net.ipv4.ip_forward" = 1;
    boot.kernel.sysctl."net.ipv4.conf.all.rp_filter" = 0;
    boot.kernel.sysctl."net.ipv4.conf.default.rp_filter" = 0;
    environment.systemPackages = [ pkgs.bpftools pkgs.tcpdump ];
  };
  testScript = ''
    import time
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("sentinel-boot.service")
    machine.succeed("systemctl stop velstra.service")
    machine.succeed("systemctl mask --runtime velstra.service")
    machine.succeed("ip netns add verify-output")
    machine.succeed("ip link add verify-e type veth peer name verify-ep")
    machine.succeed("ip link set verify-ep netns verify-output; ip link set verify-e up; ip address add 203.0.113.1/24 dev verify-e")
    machine.succeed("ip netns exec verify-output ip link set lo up; ip netns exec verify-output ip link set verify-ep up; ip netns exec verify-output ip address add 203.0.113.2/24 dev verify-ep")
    traffic = "ping -c 1 -W 1 203.0.113.2"
    machine.succeed(traffic)
    machine.succeed("mkdir -p /run/verify-controller; cp ${working} /run/verify-controller/probe.toml")
    machine.succeed("systemd-run --unit=verify-controller ${controller}/bin/velstra-controller serve --listen 127.0.0.1:50051 --config-dir /run/verify-controller --poll-interval 1")
    machine.wait_for_open_port(50051)
    machine.succeed("systemd-run --unit=verify-agent ${velstra}/bin/velstra run --iface lo --xdp-mode skb --node-id probe --controller http://127.0.0.1:50051 --query-socket /run/verify-agent.sock")
    machine.wait_until_succeeds("test -S /run/verify-agent.sock", timeout=30)
    machine.fail(traffic)
    machine.succeed("systemd-run --unit=verify-egress-capture ip netns exec verify-output ${pkgs.tcpdump}/bin/tcpdump -U -n -i verify-ep -w /run/verify-egress.pcap 'icmp and icmp[0] = 8'")
    machine.wait_until_succeeds("journalctl -u verify-egress-capture --no-pager | grep 'listening on'", timeout=10)
    machine.succeed("systemd-run --unit=verify-egress-pings ${pkgs.iputils}/bin/ping -n -i 0.001 -w 5 203.0.113.2")
    machine.succeed("bpftool map freeze name CONFIG")
    machine.succeed("cp ${broken} /run/verify-controller/probe.next; mv /run/verify-controller/probe.next /run/verify-controller/probe.toml")
    query = "${sentinel}/bin/sentinel agent-query --socket /run/verify-agent.sock "
    machine.wait_until_succeeds(query + "status | grep '^Failed (traffic blocked)'", timeout=30)
    print(machine.succeed(query + "status"))
    machine.wait_until_succeeds("! systemctl is-active --quiet verify-egress-pings", timeout=15)
    machine.succeed("systemctl kill --signal=SIGINT verify-egress-capture.service")
    machine.wait_until_succeeds("! systemctl is-active --quiet verify-egress-capture", timeout=10)
    captures = machine.succeed("${pkgs.tcpdump}/bin/tcpdump -n -r /run/verify-egress.pcap 2>/dev/null")
    print(captures)
    assert not captures.strip(), "blocked egress requests reached the backend during a failed update"
    machine.fail(traffic)
    started = time.monotonic()
    machine.succeed("systemctl stop verify-agent.service verify-controller.service")
    assert time.monotonic() - started < 15, "unresponsive controller delayed agent shutdown"
  '';
}
