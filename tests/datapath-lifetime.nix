# Actual kernel links, daemon crashes and replacement failures; no agent double.
{ pkgs, sentinelModule, sentinel, velstra }:
let
  policy = pkgs.writeText "persistent-policy.toml" ''
    default_action = "pass"
    drop_icmp = true
    [[policy]]
    id = 7
    default_action = "pass"
    egress_default_drop = true
    [[interface]]
    name = "guard-e"
    policy = 7
  '';
in pkgs.testers.runNixOSTest {
  name = "sentinel-datapath-lifetime";
  nodes.machine = {
    imports = [ sentinelModule ];
    virtualisation.memorySize = 2048;
    environment.systemPackages = [ pkgs.bpftools pkgs.curl ];
  };
  testScript = ''
    import json
    import shlex

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("velstra.service")
    state = "/sys/fs/bpf/guard-test"
    agent = "${velstra}/bin/velstra"
    query = "${sentinel}/bin/sentinel agent-query --socket /run/guard-agent.sock "
    ingress = "ip netns exec guard-client ping -c 1 -W 1 192.0.2.1"
    ingress6 = "ip netns exec guard-client ping -6 -c 1 -W 1 2001:db8:7401::1"
    web6 = "ip netns exec guard-client curl -g -fsS --noproxy '*' --max-time 3 http://[2001:db8:7401::1]:18081/"
    egress = "ping -c 1 -W 1 203.0.113.2"
    web = "ip netns exec guard-client curl -fsS --noproxy '*' --max-time 3 http://192.0.2.1:18080/"

    machine.succeed("ip netns add guard-client")
    machine.succeed("ip link add guard-u type veth peer name guard-up")
    machine.succeed("ip link set guard-up netns guard-client")
    machine.succeed("ip link set guard-u up; ip addr add 192.0.2.1/24 dev guard-u")
    machine.succeed("ip netns exec guard-client ip link set lo up")
    machine.succeed("ip netns exec guard-client ip link set guard-up up")
    machine.succeed("ip netns exec guard-client ip addr add 192.0.2.2/24 dev guard-up")
    machine.succeed("ip -6 addr add 2001:db8:7401::1/64 dev guard-u nodad")
    machine.succeed("ip netns exec guard-client ip -6 addr add 2001:db8:7401::2/64 dev guard-up nodad")
    local_mac = machine.succeed("cat /sys/class/net/guard-u/address").strip()
    peer_mac = json.loads(machine.succeed("ip netns exec guard-client ip -j link show dev guard-up"))[0]["address"]
    machine.succeed("ip -6 neigh replace 2001:db8:7401::2 lladdr " + peer_mac + " dev guard-u nud permanent")
    machine.succeed("ip netns exec guard-client ip -6 neigh replace 2001:db8:7401::1 lladdr " + local_mac + " dev guard-up nud permanent")
    machine.succeed("ip netns add guard-output")
    machine.succeed("ip link add guard-e type veth peer name guard-ep")
    machine.succeed("ip link set guard-ep netns guard-output")
    machine.succeed("ip link set guard-e up; ip addr add 203.0.113.1/24 dev guard-e")
    machine.succeed("ip netns exec guard-output ip link set lo up")
    machine.succeed("ip netns exec guard-output ip link set guard-ep up")
    machine.succeed("ip netns exec guard-output ip addr add 203.0.113.2/24 dev guard-ep")
    machine.succeed("mkdir -p /run/guard-web; printf kernel-datapath > /run/guard-web/index.html")
    machine.succeed("systemd-run --unit=guard-web ${pkgs.python3}/bin/python3 -m http.server 18080 --directory /run/guard-web")
    machine.wait_for_open_port(18080)
    machine.succeed("systemd-run --unit=guard-web6 ${pkgs.python3}/bin/python3 -m http.server 18081 --bind :: --directory /run/guard-web")
    machine.wait_for_open_port(18081)

    def invocation(config="${policy}"):
        return agent + " run --iface guard-u --xdp-mode skb --config " + config + " --datapath-state-dir " + state + " --query-socket /run/guard-agent.sock"

    def start(name, config="${policy}"):
        machine.succeed("systemd-run --unit=" + name + " --property=Restart=no " + invocation(config))
        machine.wait_until_succeeds(query + "status | grep '^Ready$'", timeout=30)
        machine.succeed("systemctl is-active --quiet " + name)

    def policy_works():
        machine.fail(ingress)
        machine.fail(ingress6)
        assert "kernel-datapath" in machine.succeed(web6)
        machine.fail(egress)
        assert "kernel-datapath" in machine.succeed(web)

    def pin_identity():
        return machine.succeed("stat -c '%n:%i' " + state + "/xdp-* " + state + "/egress-* " + state + "/programs " + state + "/ipv6-programs " + state + "/ipv6-tc-programs " + state + "/apply-state")

    def tail_calls():
        return json.loads(machine.succeed("bpftool -j map dump pinned " + state + "/programs"))

    def interface_status(name):
        return machine.succeed(query + shlex.quote("interface " + name))

    def protected(name):
        status = json.loads(interface_status(name))
        assert status["ready"] is True and status["interface"] == name, status
        assert status["ifindex"] == int(machine.succeed("cat /sys/class/net/" + name + "/ifindex")), status
        return status

    def integer(data):
        return int.from_bytes(bytes(int(part, 16) for part in data), "little")

    def policy_map():
        entries = tail_calls()
        main = [integer(entry["value"]) for entry in entries if integer(entry["key"]) == 1]
        assert len(main) == 1, entries
        info = json.loads(machine.succeed("bpftool -j prog show id " + str(main[0])))
        policies = []
        for index in info["map_ids"]:
            entry = json.loads(machine.succeed("bpftool -j map show id " + str(index)))
            if entry.get("name") == "IFACE_POLICY":
                policies.append(index)
        assert len(policies) == 1, policies
        return policies[0]

    # The VM's built-in VLAN uses 2001:db8:1::/64. Verify that the
    # namespace fixture's distinct prefix actually routes over its own veth.
    route6 = machine.succeed("ip -6 route get 2001:db8:7401::2 from 2001:db8:7401::1")
    assert "dev guard-u" in route6, route6
    with subtest("the actual unfiltered paths are reachable"):
        machine.succeed(ingress6)
        assert "kernel-datapath" in machine.succeed(web6)
        machine.succeed(ingress)
        machine.succeed(egress)
        assert "kernel-datapath" in machine.succeed(web)

    with subtest("stateful CLI interfaces observe both TCP directions without explicit egress"):
        config = 'default_action = "pass"\nstateful = true\n'
        machine.succeed("printf %s " + shlex.quote(config) + " > /run/guard-cli-stateful.toml")
        start("guard-cli-stateful", "/run/guard-cli-stateful.toml")
        assert "kernel-datapath" in machine.succeed(web6)
        assert "kernel-datapath" in machine.succeed(web)
        machine.succeed("systemctl stop guard-cli-stateful.service")
        machine.succeed(agent + " detach --datapath-state-dir " + state)
        machine.succeed("test -z \"$(ls -A " + state + ")\"")
        machine.succeed("rmdir " + state)

    with subtest("automatically discovered stateful ports observe the TCP reply path"):
        command = invocation("/run/guard-cli-stateful.toml").replace(
            "--iface guard-u", "--iface guard-e --auto-attach guard-u --auto-policy 0"
        )
        machine.succeed("systemd-run --unit=guard-auto-stateful --property=Restart=no " + command)
        machine.wait_until_succeeds(query + "status | grep '^Ready$'", timeout=30)
        # Wait for actual discovery/attachment before starting the flow; an
        # unfiltered connection before discovery would be a false success.
        machine.wait_until_succeeds("bpftool net show | grep -F 'guard-u('", timeout=20)
        assert "kernel-datapath" in machine.succeed(web6)
        assert "kernel-datapath" in machine.succeed(web)
        machine.succeed("systemctl stop guard-auto-stateful.service")
        machine.succeed(agent + " detach --datapath-state-dir " + state)
        machine.succeed("test -z \"$(ls -A " + state + ")\"")
        machine.succeed("rmdir " + state)

    with subtest("normal filesystems cannot silently disable persistent enforcement"):
        machine.succeed("mkdir -m 0700 /run/guard-not-bpf")
        output = machine.fail(invocation().replace(state, "/run/guard-not-bpf") + " 2>&1")
        assert "must be on bpffs" in output, output
        machine.succeed(ingress)

    with subtest("unsupported persistent hardware offload fails before attaching"):
        output = machine.fail(invocation().replace("--xdp-mode skb", "--xdp-mode hw") + " 2>&1")
        assert "hardware offload has no pinnable link" in output, output
        machine.succeed("test ! -e " + state)
        machine.succeed(ingress)

    with subtest("both XDP ingress and TC egress enforce actual packets"):
        start("guard-first")
        policy_works()
        identities = pin_identity()
        gate_id = json.loads(machine.succeed("bpftool -j map show pinned " + state + "/apply-state"))["id"]
        program_array_id = json.loads(machine.succeed("bpftool -j map show pinned " + state + "/programs"))["id"]
        ipv6_array_id = json.loads(machine.succeed("bpftool -j map show pinned " + state + "/ipv6-programs"))["id"]
        assert len(json.loads(machine.succeed("bpftool -j map dump pinned " + state + "/ipv6-programs"))) == 3
        tc6_array_id = json.loads(machine.succeed("bpftool -j map show pinned " + state + "/ipv6-tc-programs"))["id"]
        assert len(json.loads(machine.succeed("bpftool -j map dump pinned " + state + "/ipv6-tc-programs"))) == 1
        assert len(tail_calls()) == 3
        assert machine.succeed("stat -c '%U:%a' " + state).strip() == "root:700"
        machine.fail("su admin -c " + shlex.quote("ls " + state))

    with subtest("per-interface readiness requires the actual declared policy"):
        status = protected("guard-e")
        assert status["policy"] == 7 and status["egress"] is True, status
        assert interface_status("absent-guard").startswith("error:"), "unknown interfaces must not be acknowledged"
        assert interface_status("guard-u").startswith("error:"), "implicit uplinks are not declared policy assignments"
        index = status["ifindex"]
        key = " ".join(str(part) for part in index.to_bytes(4, "little"))
        policies = policy_map()
        pid = machine.succeed("systemctl show -p MainPID --value guard-first.service")
        try:
            machine.succeed("bpftool map update id " + str(policies) + " key " + key + " value 99 0 0 0")
            reply = interface_status("guard-e")
            if reply.startswith("error:"):
                assert "policy has not converged" in reply or "configuration is not Ready" in reply, reply
            else:
                assert json.loads(reply)["policy"] == 7, reply
            # The real background reconciler must repair the actual map; the
            # test does not restore it or restart the service to obtain success.
            machine.wait_until_succeeds(query + shlex.quote("interface guard-e") + " | grep -q '\"policy\":7'", timeout=10)
            assert machine.succeed("systemctl show -p MainPID --value guard-first.service") == pid
            protected("guard-e")
            policy_works()
        finally:
            machine.succeed("bpftool map update id " + str(policies) + " key " + key + " value 7 0 0 0")

    with subtest("a detached actual TC hook cannot acknowledge protected activation"):
        index = protected("guard-e")["ifindex"]
        pin = state + "/egress-" + str(index)
        machine.succeed("bpftool link detach pinned " + pin)
        machine.succeed(query + "status | grep '^Ready$'")
        assert "required egress enforcement is not attached" in interface_status("guard-e")
        # Removing the intentionally detached pin permits the real daemon to
        # create a new hook. Keep all other hooks and shared maps in place.
        machine.succeed("rm " + pin)
        machine.succeed("systemctl restart guard-first.service")
        machine.wait_until_succeeds(query + "status | grep '^Ready$'", timeout=30)
        protected("guard-e")
        policy_works()

    with subtest("a map sharing the numeric XDP type cannot impersonate a kernel link"):
        index = protected("guard-e")["ifindex"]
        pin = state + "/xdp-" + str(index) + "-skb"
        shadow = "/sys/fs/bpf/readiness-real-xdp"
        fw_command = "mv " + pin + " " + shadow
        machine.succeed(fw_command)
        try:
            machine.succeed("bpftool map create " + pin + " type percpu_array key 4 value 4 entries " + str(index) + " name wrong_class")
            assert "does not refer to a kernel BPF link" in interface_status("guard-e")
            policy_works()
        finally:
            machine.succeed("rm " + pin + "; mv " + shadow + " " + pin)
        protected("guard-e")

    with subtest("a detached pinned XDP link is not an active interface attachment"):
        index = protected("guard-e")["ifindex"]
        pin = state + "/xdp-" + str(index) + "-skb"
        machine.succeed("bpftool link detach pinned " + pin)
        machine.succeed(query + "status | grep '^Ready$'")
        assert "XDP link is detached" in interface_status("guard-e")
        machine.succeed("rm " + pin)
        machine.succeed("systemctl restart guard-first.service")
        machine.wait_until_succeeds(query + "status | grep '^Ready$'", timeout=30)
        protected("guard-e")
        policy_works()
        identities = pin_identity()

    with subtest("a concurrent writer and explicit detach cannot steal the live datapath"):
        output = machine.fail("timeout 10 " + invocation() + " 2>&1")
        assert "another agent owns" in output, output
        output = machine.fail(agent + " detach --datapath-state-dir " + state + " 2>&1")
        assert "another agent owns" in output, output
        policy_works()

    with subtest("an incompatible actual control map is rejected before modifying kernel state"):
        other = "/sys/fs/bpf/guard-wrong-map"
        machine.succeed("mkdir -m 0700 " + other)
        machine.succeed("bpftool map create " + other + "/apply-state type array key 4 value 8 entries 1 name wrong_gate")
        before = machine.succeed("bpftool -j map dump pinned " + other + "/apply-state")
        output = machine.fail(invocation().replace(state, other) + " 2>&1")
        assert "incompatible persistent control map" in output, output
        assert machine.succeed("bpftool -j map dump pinned " + other + "/apply-state") == before
        policy_works()
        machine.succeed("rm " + other + "/apply-state; rmdir " + other)

    with subtest("a real SIGKILL leaves both policies attached without a replacement daemon"):
        machine.succeed("systemctl kill --signal=KILL --kill-whom=main guard-first.service")
        machine.wait_until_fails("systemctl is-active --quiet guard-first.service", timeout=10)
        assert len(tail_calls()) == 3, "a pinned hook must retain its actual tail-call entries"
        for _ in range(3):
            policy_works()
        assert pin_identity() == identities

    with subtest("restart replaces existing links without recreating their pin identities"):
        start("guard-second")
        policy_works()
        assert pin_identity() == identities
        assert json.loads(machine.succeed("bpftool -j map show pinned " + state + "/apply-state"))["id"] == gate_id
        assert json.loads(machine.succeed("bpftool -j map show pinned " + state + "/programs"))["id"] == program_array_id
        assert json.loads(machine.succeed("bpftool -j map show pinned " + state + "/ipv6-programs"))["id"] == ipv6_array_id
        assert json.loads(machine.succeed("bpftool -j map show pinned " + state + "/ipv6-tc-programs"))["id"] == tc6_array_id
        assert len(tail_calls()) == 3

    with subtest("a normal service stop also retains the last working policy"):
        machine.succeed("systemctl stop guard-second.service")
        policy_works()

    with subtest("a partially failed replacement closes inherited and new datapaths"):
        machine.succeed("ip link add guard-f type veth peer name guard-fp")
        machine.succeed("ip link set guard-f up; ip link set guard-fp up")
        third_index = machine.succeed("cat /sys/class/net/guard-f/ifindex").strip()
        bad_pin = state + "/egress-" + third_index
        # A map at a link path is a real incompatible kernel object. Existing
        # protected links are untouched by the fault injection itself.
        machine.succeed("bpftool map create " + bad_pin + " type array key 4 value 4 entries 1 name wrong_hook")
        config = machine.succeed("cat ${policy}") + '\n[[interface]]\nname = "guard-f"\npolicy = 7\n'
        machine.succeed("printf %s " + shlex.quote(config) + " > /run/guard-extra.toml")
        machine.succeed("systemd-run --unit=guard-broken --property=Restart=no " + invocation("/run/guard-extra.toml"))
        machine.wait_until_succeeds("systemctl is-failed --quiet guard-broken.service", timeout=30)
        machine.fail(ingress)
        machine.fail(egress)
        machine.fail(web)
        # The server is still healthy. Only the protected ingress is closed.
        assert "kernel-datapath" in machine.succeed("curl -fsS --noproxy '*' --max-time 3 http://192.0.2.1:18080/")
        machine.succeed("rm " + bad_pin)

    with subtest("retry restores policy and removes only obsolete owned hooks"):
        start("guard-third")
        policy_works()
        machine.succeed("test ! -e " + state + "/xdp-" + third_index + "-skb")
        machine.succeed("ip link show guard-f")
        machine.succeed("systemctl stop guard-third.service")

    with subtest("explicit cleanup validates foreign objects before changing the gate"):
        machine.succeed("bpftool map create " + state + "/foreign-map type array key 4 value 4 entries 1 name foreign_map")
        output = machine.fail(agent + " detach --datapath-state-dir " + state + " 2>&1")
        assert "unexpected object" in output, output
        machine.succeed("test -e " + state + "/foreign-map")
        policy_works()
        machine.succeed("rm " + state + "/foreign-map")

    with subtest("only an explicit privileged detach permits unfiltered traffic"):
        output = machine.fail("su admin -c " + shlex.quote(agent + " detach --datapath-state-dir " + state + " 2>&1"))
        assert "requires root" in output, output
        machine.succeed(agent + " detach --datapath-state-dir " + state)
        machine.succeed("test -z \"$(ls -A " + state + ")\"")
        machine.succeed(ingress)
        machine.succeed(egress)
        machine.succeed("ip link show guard-f")

    with subtest("a late-interface reconciliation starts from working packet paths"):
        config = 'default_action = "pass"\n[[interface]]\nname = "guard-late"\npolicy = 0\n'
        machine.succeed("printf %s " + shlex.quote(config) + " > /run/guard-late.toml")
        start("guard-diagnostic", "/run/guard-late.toml")
        diagnostic_pid = machine.succeed("systemctl show -p MainPID --value guard-diagnostic.service").strip()
        machine.succeed(ingress)
        assert "kernel-datapath" in machine.succeed(web)

    with subtest("a real hook-retirement error reports Failed instead of Updating indefinitely"):
        machine.succeed("bpftool map create " + state + "/foreign-map type array key 4 value 4 entries 1 name foreign_map")
        machine.succeed("ip link add name guard-late type dummy; ip link set guard-late up")
        machine.wait_until_succeeds(query + "status | grep '^Failed'", timeout=20)
        status = machine.succeed(query + "status")
        assert "Last update:" in status and "unexpected object" in status and "foreign-map" in status, status
        machine.succeed("test -e " + state + "/foreign-map")
        machine.fail(ingress)
        machine.fail(web)
        assert "kernel-datapath" in machine.succeed("curl -fsS --noproxy '*' --max-time 3 http://192.0.2.1:18080/")

    with subtest("removing the fault recovers live without a manual service restart"):
        machine.succeed("rm " + state + "/foreign-map")
        machine.wait_until_succeeds(query + "status | grep '^Ready$'", timeout=20)
        assert machine.succeed("systemctl show -p MainPID --value guard-diagnostic.service").strip() == diagnostic_pid
        machine.succeed(ingress)
        assert "kernel-datapath" in machine.succeed(web)
        status = protected("guard-late")
        assert status["policy"] == 0, status
  '';
}
