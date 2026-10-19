# Wren's live FIB stream must recover without duplicate route advertisements.
{ pkgs, sentinelModule, velstra }:
let
  overlay = pkgs.writeText "wren-overlay-policy.toml" ''
    default_action = "pass"
    [overlay]
    local_vtep = "192.0.2.1"
    underlay_iface = "verify-vx"
    encap = "vxlan"
  '';
  plain = pkgs.writeText "wren-plain-policy.toml" ''
    default_action = "pass"
  '';
  empty = pkgs.writeText "wren-empty.toml" ''
    router-id = "192.0.2.1"
  '';
  route = pkgs.writeText "wren-one-route.toml" ''
    router-id = "192.0.2.1"
    [[static]]
    prefix = "203.0.113.0/24"
    via = "198.51.100.2"
    dev = "verify-b"
  '';
  twoRoutes = pkgs.writeText "wren-two-routes.toml" (builtins.readFile route + ''
    [[static]]
    prefix = "203.0.114.0/24"
    via = "198.51.100.2"
    dev = "verify-b"
  '');
in pkgs.testers.runNixOSTest {
  name = "sentinel-wren-reconciliation";
  nodes.machine = {
    imports = [ sentinelModule ];
    virtualisation.memorySize = 2048;
    virtualisation.cores = 2;
    boot.kernel.sysctl."net.ipv4.ip_forward" = 1;
    environment.systemPackages = [ pkgs.bpftools pkgs.python3 ];
  };
  testScript = ''
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("sentinel-boot.service")
    machine.wait_for_unit("wren.service")
    machine.succeed("systemctl stop velstra.service; systemctl mask --runtime velstra.service")
    machine.succeed("ip netns add verify-client; ip netns add verify-backend")
    machine.succeed("ip link add verify-u type veth peer name verify-up; ip link set verify-up netns verify-client")
    machine.succeed("ip link set verify-u up; ip address add 192.0.2.1/24 dev verify-u")
    machine.succeed("ip netns exec verify-client ip link set lo up; ip netns exec verify-client ip link set verify-up up")
    machine.succeed("ip netns exec verify-client ip address add 192.0.2.2/24 dev verify-up")
    machine.succeed("ip netns exec verify-client ip route add 203.0.113.0/24 via 192.0.2.1")
    machine.succeed("ip link add verify-b type veth peer name verify-bp; ip link set verify-bp netns verify-backend")
    machine.succeed("ip link set verify-b up; ip address add 198.51.100.1/24 dev verify-b")
    machine.succeed("ip netns exec verify-backend ip link set lo up; ip netns exec verify-backend ip link set verify-bp address 02:00:00:00:00:22")
    machine.succeed("ip netns exec verify-backend ip link set verify-bp up; ip netns exec verify-backend ip address add 198.51.100.2/24 dev verify-bp")
    machine.succeed("ip netns exec verify-backend ip address add 203.0.113.1/32 dev lo; ip netns exec verify-backend ip route add 192.0.2.0/24 via 198.51.100.1")
    machine.succeed("ip neigh replace 198.51.100.2 lladdr 02:00:00:00:00:22 nud permanent dev verify-b")
    # The prohibited reverse lookup isolates XDP forwarding from Linux's FIB.
    machine.succeed("sysctl -w net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.verify-u.rp_filter=0 net.ipv4.conf.verify-b.rp_filter=0")
    machine.succeed("ip route add prohibit 203.0.113.1/32")
    traffic = "ip netns exec verify-client ping -c 3 -W 1 203.0.113.1"
    mapped = "bpftool -j map dump name ROUTES | grep -q '\"key\"'"
    wren_pid = machine.succeed("systemctl show wren -p MainPID --value").strip()

    def publish(candidate):
        machine.succeed(f"cp {candidate} /run/sentinel/wren.next")
        machine.succeed("mv /run/sentinel/wren.next /run/sentinel/wren.toml")
        machine.succeed("systemctl kill --signal=HUP wren.service")

    def failures():
        return machine.succeed("journalctl -u verify-route-agent --no-pager").count("wren routes could not be programmed")

    with subtest("failed route installs and withdrawals retry while Wren is quiescent"):
        machine.succeed("ip link add verify-vx type dummy; ip link set verify-vx up")
        publish("${empty}")
        machine.succeed("systemd-run --unit=verify-route-agent ${velstra}/bin/velstra run --iface verify-u --xdp-mode skb --config ${overlay} --query-socket /run/verify-route.sock --wren-routes --wren-socket /run/wren/wren.sock")
        machine.wait_until_succeeds("test -S /run/verify-route.sock", timeout=30)
        machine.wait_until_succeeds("journalctl -u verify-route-agent --no-pager | grep 'subscribed to wren'", timeout=30)
        agent_pid = machine.succeed("systemctl show verify-route-agent -p MainPID --value").strip()
        machine.fail(traffic)
        for candidate, installing in [("${route}", True), ("${empty}", False)]:
            before = failures()
            machine.succeed("ip link del verify-vx")
            publish(candidate)
            machine.wait_until_succeeds(f"test $(journalctl -u verify-route-agent --no-pager | grep -c 'wren routes could not be programmed') -gt {before}", timeout=20)
            # Keep the real stream open, with no further control-plane event.
            machine.succeed("systemctl kill --signal=STOP wren.service")
            try:
                machine.succeed("ip link add verify-vx type dummy; ip link set verify-vx up")
                if installing:
                    machine.wait_until_succeeds(mapped, timeout=20)
                    machine.succeed(traffic)
                else:
                    machine.wait_until_fails(mapped, timeout=20)
                    machine.fail(traffic)
            finally:
                machine.succeed("systemctl kill --signal=CONT wren.service")
            assert machine.succeed("systemctl show verify-route-agent -p MainPID --value").strip() == agent_pid
            assert machine.succeed("systemctl show wren -p MainPID --value").strip() == wren_pid
        machine.succeed("systemctl stop verify-route-agent.service")

    with subtest("an unavailable ARP observation preserves forwarding and retries"):
        publish("${route}")
        machine.succeed("systemd-run --unit=verify-observer-agent ${velstra}/bin/velstra run --iface verify-u --xdp-mode skb --config ${plain} --query-socket /run/verify-observer.sock --wren-routes --wren-socket /run/wren/wren.sock")
        machine.wait_until_succeeds("test -S /run/verify-observer.sock", timeout=30)
        machine.wait_until_succeeds(mapped, timeout=30)
        machine.succeed(traffic)
        observer_pid = machine.succeed("systemctl show verify-observer-agent -p MainPID --value").strip()
        machine.succeed("ip netns exec verify-client ip route add 203.0.114.0/24 via 192.0.2.1")
        machine.succeed("ip netns exec verify-backend ip address add 203.0.114.1/32 dev lo")
        machine.succeed("ip route add prohibit 203.0.114.1/32")
        limits = machine.succeed(f"cat /proc/{observer_pid}/limits")
        descriptors = next(line.split()[3:5] for line in limits.splitlines() if line.startswith("Max open files"))
        machine.succeed(f"prlimit --pid {observer_pid} --nofile=3:{descriptors[1]}")
        try:
            publish("${twoRoutes}")
            machine.wait_until_succeeds("wren show routes | grep 203.0.114.0/24", timeout=30)
            machine.wait_until_succeeds("journalctl -u verify-observer-agent --no-pager | grep 'reading kernel ARP table'", timeout=30)
            packets = machine.succeed(traffic)
            assert ", 0% packet loss" in packets, packets
        finally:
            machine.succeed(f"prlimit --pid {observer_pid} --nofile={descriptors[0]}:{descriptors[1]}")
        machine.wait_until_succeeds("bpftool -j map dump name ROUTES | python3 -c 'import json,sys; assert len(json.load(sys.stdin)) == 2'", timeout=20)
        machine.succeed("ip netns exec verify-client ping -c 3 -W 1 203.0.114.1")
        # Empty desired state is authoritative even when ARP cannot be read.
        machine.succeed(f"prlimit --pid {observer_pid} --nofile=3:{descriptors[1]}")
        try:
            publish("${empty}")
            machine.wait_until_fails(mapped, timeout=20)
            machine.fail(traffic)
        finally:
            machine.succeed(f"prlimit --pid {observer_pid} --nofile={descriptors[0]}:{descriptors[1]}")
        assert machine.succeed("systemctl show verify-observer-agent -p MainPID --value").strip() == observer_pid
        assert machine.succeed("systemctl show wren -p MainPID --value").strip() == wren_pid

    with subtest("resolved gateway MAC changes converge without a route event"):
        publish("${route}")
        machine.wait_until_succeeds(mapped, timeout=20)
        machine.succeed(traffic)
        machine.succeed("systemctl kill --signal=STOP wren.service")
        try:
            for mac in ["02:00:00:00:00:33", "02:00:00:00:00:22"]:
                machine.succeed(f"ip netns exec verify-backend ip link set verify-bp address {mac}")
                machine.succeed(f"ip neigh replace 198.51.100.2 lladdr {mac} nud permanent dev verify-b")
                machine.wait_until_succeeds("ip netns exec verify-client ping -c 1 -W 1 -w 2 203.0.113.1", timeout=12)
                packets = machine.succeed(traffic)
                assert ", 0% packet loss" in packets, packets
        finally:
            machine.succeed("systemctl kill --signal=CONT wren.service")
        assert machine.succeed("systemctl show verify-observer-agent -p MainPID --value").strip() == observer_pid
        assert machine.succeed("systemctl show wren -p MainPID --value").strip() == wren_pid
    print(machine.succeed("journalctl -u verify-route-agent -u verify-observer-agent -u wren --no-pager"))
    machine.succeed("systemctl stop verify-observer-agent.service")
  '';
}
