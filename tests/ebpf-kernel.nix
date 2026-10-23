# Real kernel acceptance, attachment lifetime and resource-failure recovery.
{
  pkgs,
  sentinelModule,
  sentinel,
  velstra,
  fabric,
}:
let
  limitConfig = count: pkgs.writeText "verifier-${toString count}-limits.toml" (
    ''default_action = "pass"
    '' + pkgs.lib.concatStrings (pkgs.lib.genList (index: ''
      [[port_rule]]
      proto = "tcp"
      port = ${toString (10000 + index)}
      action = "pass"
      limit = 100
    '') count)
  );
  config = pkgs.writeText "verifier-overlay.toml" ''
    default_action = "pass"
    [overlay]
    local_vtep = "192.0.2.1"
    underlay_iface = "verify-u"
    encap = "vxlan"
    [[policy]]
    id = 7
    name = "verification"
    default_action = "pass"
    [[interface]]
    name = "verify-t"
    policy = 7
    vni = 5000
  '';
in pkgs.testers.runNixOSTest {
  name = "sentinel-all-ebpf-programs";
  nodes.machine = {
    imports = [ sentinelModule ];
    virtualisation.memorySize = 2048;
    environment.systemPackages = [ pkgs.bpftools ];
  };
  testScript = ''
    import json
    import re
    import time
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("sentinel-boot.service")
    # Keep boot-late from starting a second agent during the isolated run.
    machine.succeed("systemctl stop velstra.service")
    machine.succeed("systemctl mask --runtime velstra.service")
    machine.succeed("ip link add verify-u type veth peer name verify-up")
    machine.succeed("ip link add verify-t type veth peer name verify-tp")
    for interface in ["verify-u", "verify-up", "verify-t", "verify-tp"]:
        machine.succeed(f"ip link set {interface} up")
    machine.succeed("ip address add 192.0.2.1/24 dev verify-u")
    machine.succeed("ip netns add verify-client")
    machine.succeed("ip link set verify-up netns verify-client")
    machine.succeed("ip netns exec verify-client ip link set lo up")
    machine.succeed("ip netns exec verify-client ip link set verify-up up")
    machine.succeed("ip netns exec verify-client ip address add 192.0.2.2/24 dev verify-up")
    machine.succeed("ip netns exec verify-client ping -c 1 -W 2 192.0.2.1")
    machine.succeed("${velstra}/bin/velstra validate ${config}")
    machine.succeed("${velstra}/bin/velstra validate ${limitConfig 127}")
    refused = machine.fail("${velstra}/bin/velstra validate ${limitConfig 128} 2>&1")
    assert "128 rate-limited rules" in refused, refused
    machine.succeed("mkfifo /run/verify-statistics.fifo")
    machine.succeed(
        "systemd-run --unit=verify-ebpf /bin/sh -c "
        "'head -n 1 < /run/verify-statistics.fifo > /dev/null & exec "
        "${velstra}/bin/velstra run "
        "--iface verify-t verify-u --egress --xdp-mode skb "
        "--query-socket /run/verify-ebpf.sock --portal-socket /run/verify-portal.sock "
        "--mapping-socket /run/verify-mapping.sock --config ${config} > /run/verify-statistics.fifo'"
    )
    machine.wait_for_unit("verify-ebpf.service")
    machine.wait_until_succeeds("test -S /run/verify-ebpf.sock", timeout=30)
    time.sleep(12)
    machine.succeed("systemctl is-active verify-ebpf.service")
    assert "could not write datapath statistics" in machine.succeed("journalctl -u verify-ebpf --no-pager")
    programs = json.loads(machine.succeed("bpftool -j prog show"))
    program_source = machine.succeed("cat ${fabric}/velstra-ebpf/src/main.rs")
    definitions = re.findall(r"#\[(xdp|classifier)\]\s*pub fn (\w+)", program_source)
    expected = {name: "xdp" if kind == "xdp" else "sched_cls" for kind, name in definitions}
    assert len(expected) >= 6, "the embedded program inventory is incomplete"
    loaded = {program.get("name"): program for program in programs}
    agent_log = machine.succeed("journalctl -u verify-ebpf --no-pager")
    assert set(expected).issubset(loaded), f"missing programs: {set(expected) - set(loaded)}; loaded: {set(loaded)}\n{agent_log}"
    for name, program_type in expected.items():
        program = loaded[name]
        assert program["type"] == program_type, program
        assert program["bytes_xlated"] > 0 and program["map_ids"], program
        assert program["jited"], f"program did not use the kernel JIT: {name}"
    assert "BUM replication attach failed" not in agent_log, agent_log
    def tenant_hooks_ready():
        attachment_states = json.loads(machine.succeed("bpftool -j net show dev verify-t"))
        classifiers = [item for state in attachment_states for item in state.get("tc", [])]
        return all(any(item.get("kind") == kind and item.get("prog_id") == loaded[name]["id"] for item in classifiers)
                   for kind, name in [("tcx/ingress", "velstra_bum"), ("tcx/egress", "velstra_egress")])

    assert tenant_hooks_ready(), "the verified programs did not attach to both tenant TCX hooks"
    agent_pid = machine.succeed("systemctl show -p MainPID --value verify-ebpf.service").strip()
    def kernel_link_fds():
        targets = machine.succeed(f"find /proc/{agent_pid}/fd -maxdepth 1 -type l -printf '%l\\n'").splitlines()
        return sum(target.startswith("anon_inode:") and "bpf" in target and "link" in target for target in targets)

    before_link_fds = kernel_link_fds()
    assert before_link_fds >= 3, "could not inventory the agent's active TCX descriptors"
    for _ in range(2):
        previous_ifindex = machine.succeed("cat /sys/class/net/verify-t/ifindex").strip()
        machine.succeed("ip link del verify-t")
        machine.succeed("ip link add verify-t type veth peer name verify-tp")
        machine.succeed("ip link set verify-t up; ip link set verify-tp up")
        assert machine.succeed("cat /sys/class/net/verify-t/ifindex").strip() != previous_ifindex
        for attempt in range(30):
            if tenant_hooks_ready():
                break
            time.sleep(1)
        assert tenant_hooks_ready(), "tenant hooks were not restored after interface recreation"
        assert machine.succeed("systemctl show -p MainPID --value verify-ebpf.service").strip() == agent_pid
    traffic = "ip netns exec verify-client ping -c 1 -W 1 192.0.2.1"
    machine.succeed(traffic)
    machine.succeed("${sentinel}/bin/sentinel agent-query 'block 192.0.2.2/32 300' --socket /run/verify-ebpf.sock")
    machine.fail(traffic)
    limits = machine.succeed(f"cat /proc/{agent_pid}/limits")
    descriptor_limits = next(line.split()[3:5] for line in limits.splitlines() if line.startswith("Max open files"))
    machine.succeed(f"prlimit --pid {agent_pid} --nofile=3:{descriptor_limits[1]}")
    try:
        for socket_name, command in [("verify-ebpf", "stats"), ("verify-portal", "sessions"), ("verify-mapping", "mappings")]:
            machine.execute(f"timeout 3 ${sentinel}/bin/sentinel agent-query {command} --socket /run/{socket_name}.sock")
        time.sleep(6)
        machine.fail(traffic)
        assert tenant_hooks_ready(), "resource pressure detached the active firewall hooks"
        pressure_log = machine.succeed("journalctl -u verify-ebpf --no-pager")
        for socket_type in ["query", "portal", "mapping"]:
            assert f"{socket_type} socket accept failed: Too many open files" in pressure_log, pressure_log
        assert "retaining link: opening interface lookup socket: Too many open files" in pressure_log, pressure_log
    finally:
        machine.succeed(f"prlimit --pid {agent_pid} --nofile={descriptor_limits[0]}:{descriptor_limits[1]}")
    for socket_name, command in [("verify-ebpf", "stats"), ("verify-portal", "sessions"), ("verify-mapping", "mappings")]:
        answer = machine.succeed(f"${sentinel}/bin/sentinel agent-query {command} --socket /run/{socket_name}.sock")
        assert answer.strip() and not answer.startswith("error:"), answer
    machine.fail(traffic)
    machine.succeed("${sentinel}/bin/sentinel agent-query 'unblock 192.0.2.2/32' --socket /run/verify-ebpf.sock")
    machine.succeed(traffic)
    machine.succeed("systemctl is-active verify-ebpf.service")
    assert machine.succeed("systemctl show -p MainPID --value verify-ebpf.service").strip() == agent_pid
    after_link_fds = kernel_link_fds()
    print(f"BPF link descriptors before/after two interface replacements: {before_link_fds}/{after_link_fds}")
    assert after_link_fds == before_link_fds, "recreated interfaces leaked kernel BPF link descriptors"
    print("All embedded programs accepted; hooks, filtering and management recover without restart or leaked links.")
    machine.succeed("systemctl stop verify-ebpf.service")
    machine.succeed(
        "systemd-run --unit=verify-limit-boundary ${velstra}/bin/velstra run "
        "--iface verify-u --xdp-mode skb --query-socket /run/verify-limit.sock "
        "--config ${limitConfig 127}"
    )
    machine.wait_until_succeeds("test -S /run/verify-limit.sock", timeout=30)
    entries = json.loads(machine.succeed("bpftool -j map dump name PORT_RULES"))
    slots = {(int.from_bytes(bytes(int(byte, 16) for byte in entry["value"]), "little") >> 24) & 0x7f
             for entry in entries}
    assert slots == set(range(1, 128)), f"not every configured limit reached its kernel bucket: {slots}"
    machine.succeed("systemctl stop verify-limit-boundary.service")
  '';
}
