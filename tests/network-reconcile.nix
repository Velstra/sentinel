# Networkd must acknowledge changes before a commit can be saved as successful.
{ pkgs, sentinelModule, sentinel }:
pkgs.testers.runNixOSTest {
  name = "sentinel-network-reconcile";
  nodes.machine = {
    imports = [ sentinelModule ];
    virtualisation.memorySize = 2048;
  };
  testScript = ''
    import shlex
    import json
    import tomllib

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("sentinel-boot.service")
    machine.wait_for_unit("systemd-networkd.service")
    pending = "/run/sentinel/networkd-reload.pending"
    network = "/run/systemd/network/10-sentinel-eth0.network"
    address = "192.0.2.55/24"

    def command(*lines):
        script = "\n".join([*lines, "commit", "save", "exit", ""])
        body = "printf %s " + shlex.quote(script) + " | ${sentinel}/bin/sentinel configure 2>&1"
        return "su admin -c " + shlex.quote(body)

    def saved():
        return tomllib.loads(machine.succeed("cat /var/lib/sentinel/appliance.toml"))

    def running():
        return tomllib.loads(machine.succeed("cat /run/sentinel/running.toml"))

    with subtest("VLAN uniqueness matches real kernel constraints including TPID"):
        machine.succeed("ip netns add vlan-validation")
        try:
            machine.succeed("ip -n vlan-validation link add name carrier type dummy")
            machine.succeed("ip -n vlan-validation link add link carrier name first type vlan id 42")
            output = machine.fail("ip -n vlan-validation link add link carrier name duplicate type vlan id 42 2>&1")
            assert "already exists" in output or "File exists" in output, output
            machine.succeed("ip -n vlan-validation link add link carrier name service type vlan protocol 802.1ad id 42")
            link = json.loads(machine.succeed("ip -j -d -n vlan-validation link show dev service"))[0]
            assert link["linkinfo"]["info_data"]["id"] == 42, link
            assert link["linkinfo"]["info_data"]["protocol"] == "802.1ad", link
        finally:
            machine.succeed("ip netns del vlan-validation")

    with subtest("impossible parent graphs fail before touching runtime state"):
        previous_saved, previous_running = saved(), running()
        output = machine.fail(command("set interface cyclea parent cyclea", "set interface cyclea vlan 42"))
        assert "interface parent cycle" in output, output
        assert "commit ok: applied live" not in output and "saved /" not in output, output
        assert saved() == previous_saved and running() == previous_running
        machine.succeed("test ! -e /run/systemd/network/10-sentinel-cyclea.netdev")

    with subtest("a real reload failure cannot be saved as success"):
        previous_saved, previous_running = saved(), running()
        machine.succeed("systemctl mask --runtime systemd-networkd.service")
        machine.succeed("systemctl stop systemd-networkd.service")
        try:
            output = machine.fail(command("set interface eth0 address " + address))
            assert "applying network configuration with networkd" in output, output
            assert "commit ok: applied live" not in output and "saved /" not in output, output
            assert saved() == previous_saved
            assert running() == previous_running
            machine.fail("ip addr show eth0 | grep -q 192.0.2.55")
            machine.succeed("test -s " + pending)
        finally:
            machine.succeed("systemctl unmask --runtime systemd-networkd.service")
            machine.succeed("systemctl start systemd-networkd.service")

    with subtest("retry after networkd recovery configures the actual address"):
        output = machine.succeed(command("set interface eth0 address " + address))
        assert "commit ok: applied live" in output and "saved /" in output, output
        machine.wait_until_succeeds("ip addr show eth0 | grep -q 192.0.2.55", timeout=20)
        machine.succeed("test ! -e " + pending)
        assert any(i.get("address") == address for i in saved()["interface"])

    with subtest("pending reload survives an interruption after files were written"):
        # Render the next unit without notifying networkd, as an interrupted
        # writer would do. The following commit finds already-equal file bytes.
        machine.succeed("sed -i s/192.0.2.55/192.0.2.56/g " + network)
        identity = machine.succeed("stat -c '%i:%y' " + network)
        machine.fail("ip addr show eth0 | grep -q 192.0.2.56")
        # This is exactly the state left by a process killed after writing the
        # units but before networkd acknowledges them: identical files + intent.
        machine.succeed("printf 'networkd reload required\n' > " + pending)
        output = machine.succeed(command("set interface eth0 address 192.0.2.56/24"))
        assert "commit ok: applied live" in output, output
        machine.wait_until_succeeds("ip addr show eth0 | grep -q 192.0.2.56", timeout=20)
        assert machine.succeed("stat -c '%i:%y' " + network) == identity
        machine.succeed("test ! -e " + pending)

    with subtest("an acknowledged unchanged network needs no further reload"):
        machine.succeed("systemctl mask --runtime systemd-networkd.service")
        machine.succeed("systemctl stop systemd-networkd.service")
        try:
            # A needless reload would fail against the unavailable service.
            output = machine.succeed(command())
            assert "commit ok: applied live" in output, output
            machine.succeed("test ! -e " + pending)
        finally:
            machine.succeed("systemctl unmask --runtime systemd-networkd.service")
            machine.succeed("systemctl start systemd-networkd.service")

    with subtest("the saved address still works after reboot"):
        machine.shutdown()
        machine.start()
        machine.wait_for_unit("sentinel-boot.service")
        machine.wait_for_unit("systemd-networkd.service")
        machine.wait_until_succeeds("ip addr show eth0 | grep -q 192.0.2.56", timeout=20)
        machine.succeed("test ! -e " + pending)
  '';
}
