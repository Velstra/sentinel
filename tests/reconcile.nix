# Failed controller updates retain policy and retry when dependencies recover.
{
  pkgs,
  sentinelModule,
  velstra,
  controller,
}:
let
  working = pkgs.writeText "reconcile-working.toml" ''
    default_action = "pass"
    drop_icmp = true
  '';
  vxlan = pkgs.writeText "reconcile-vxlan.toml" ''
    default_action = "pass"
    [overlay]
    local_vtep = "192.0.2.1"
    underlay_iface = "verify-vx"
    encap = "vxlan"
  '';
  srv6 = pkgs.writeText "reconcile-srv6.toml" ''
    default_action = "pass"
    [srv6]
    local_src = "2001:db8::1"
    underlay_iface = "verify-sr"
  '';
  route = pkgs.writeText "reconcile-route.toml" ''
    default_action = "pass"
    [[route]]
    dest = "198.51.100.0/24"
    out_iface = "verify-route"
    via_mac = "02:00:00:00:00:01"
  '';
in pkgs.testers.runNixOSTest {
  name = "sentinel-controller-reconciliation";
  nodes.machine = {
    imports = [ sentinelModule ];
    virtualisation.memorySize = 2048;
    environment.systemPackages = [ pkgs.bpftools ];
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
    machine.succeed("systemd-run --unit=verify-agent ${velstra}/bin/velstra run --iface verify-u --xdp-mode skb --node-id probe --controller http://127.0.0.1:50051 --query-socket /run/verify-agent.sock")
    machine.wait_until_succeeds("test -S /run/verify-agent.sock", timeout=30)
    agent_pid = machine.succeed("systemctl show -p MainPID --value verify-agent.service").strip()
    machine.fail(traffic)

    def messages_containing(text):
        return machine.succeed("journalctl -u verify-agent --no-pager").count(text)

    def replace_config(candidate):
        # Publish a complete revision; polling must never see a truncated file.
        machine.succeed(f"cp {candidate} /run/verify-controller/probe.next")
        machine.succeed("mv /run/verify-controller/probe.next /run/verify-controller/probe.toml")

    for name, candidate, interface in [("VXLAN", "${vxlan}", "verify-vx"), ("SRv6", "${srv6}", "verify-sr")]:
        with subtest(f"{name} failure preserves policy and recovers without a new revision"):
            failures = messages_containing("failed to apply controller update")
            applied = messages_containing("applied controller update")
            replace_config(candidate)
            machine.wait_until_succeeds(f"test $(journalctl -u verify-agent --no-pager | grep -c 'failed to apply controller update') -ge {failures + 2}", timeout=30)
            machine.fail(traffic)
            machine.succeed(f"ip link add {interface} type veth peer name {interface}p")
            machine.succeed(f"ip link set {interface} up")
            machine.succeed(f"ip link set {interface}p up")
            machine.wait_until_succeeds(f"test $(journalctl -u verify-agent --no-pager | grep -c 'applied controller update') -gt {applied}", timeout=30)
            machine.succeed(traffic)
            assert machine.succeed("systemctl show -p MainPID --value verify-agent.service").strip() == agent_pid
            replace_config("${working}")
            machine.wait_until_fails(traffic, timeout=30)

    with subtest("a deferred route is installed when its egress appears"):
        replace_config("${route}")
        machine.wait_until_succeeds(traffic, timeout=30)
        machine.fail("bpftool -j map dump name ROUTES | grep -q '\"key\"'")
        machine.succeed("ip netns add verify-backend")
        machine.succeed("ip link add verify-route type veth peer name verify-next")
        machine.succeed("ip link set verify-next netns verify-backend")
        machine.succeed("ip link set verify-route up")
        machine.succeed("ip address add 198.51.100.1/24 dev verify-route")
        machine.succeed("ip netns exec verify-backend ip link set lo up")
        machine.succeed("ip netns exec verify-backend ip link set verify-next address 02:00:00:00:00:01")
        machine.succeed("ip netns exec verify-backend ip link set verify-next up")
        machine.succeed("ip netns exec verify-backend ip address add 198.51.100.2/24 dev verify-next")
        machine.succeed("ip netns exec verify-backend ip route add 192.0.2.0/24 via 198.51.100.1")
        machine.succeed("ip netns exec verify-client ip route add 198.51.100.0/24 via 192.0.2.1")
        machine.succeed("sysctl -w net.ipv4.ip_forward=1")
        # Requests must use XDP, while replies may use Linux forwarding. The
        # deliberately prohibited reverse lookup must not discard those replies.
        machine.succeed("ip route add prohibit 198.51.100.2/32")
        machine.succeed("sysctl -w net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.verify-route.rp_filter=0 net.ipv4.conf.verify-u.rp_filter=0")
        machine.wait_until_succeeds("bpftool -j map dump name ROUTES | grep -q '\"key\"'", timeout=30)
        machine.succeed("ip netns exec verify-client ping -c 3 -W 2 198.51.100.2")
        assert machine.succeed("systemctl show -p MainPID --value verify-agent.service").strip() == agent_pid

    machine.succeed("systemctl stop verify-agent.service verify-controller.service")
  '';
}
