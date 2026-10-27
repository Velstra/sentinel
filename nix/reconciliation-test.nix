{ pkgs, self }:
pkgs.testers.runNixOSTest {
  name = "sentinel-reconciliation";
  nodes.fw = { lib, ... }: {
    imports = [ self.nixosModules.sentinel ];
    networking.hostName = lib.mkForce "fw";
    networking.firewall.enable = lib.mkForce false;
    virtualisation.vlans = [ 1 2 ];
    virtualisation.memorySize = 2048;
    environment.systemPackages = [ pkgs.bpftools ];
    services.velstra.interface = lib.mkForce "eth2";
  };
  testScript = ''
    import json, shlex
    start_all()
    fw.wait_for_unit("multi-user.target")
    fw.wait_for_unit("velstra.service")

    def configure(lines):
        script = "printf '%s\\n' " + " ".join(shlex.quote(x) for x in lines + ["commit", "save", "exit"]) + " | sentinel configure"
        output = fw.succeed("su admin -c " + shlex.quote(script))
        assert "commit failed" not in output.lower(), output
        assert "error:" not in output.lower(), output
        return output

    with subtest("create physical, VLAN, bridge and dummy state without reboot"):
        configure([
            "set interface eth1 mtu 1400",
            "set interface tenant0 parent eth1", "set interface tenant0 vlan 10",
            "set interface tenant0 zone lan",
            "set interface tenant0 address 192.0.2.1/24",
            "set interface tenant0 address6 2001:db8:10::1/64",
            "set interface d0 type dummy", "set interface br0 type bridge",
            "set interface br0 member d0", "set interface br0 address 198.51.100.1/24",
        ])
        fw.wait_until_succeeds("ip -d link show tenant0 | grep -q 'id 10 '")
        fw.wait_until_succeeds("ip -6 addr show tenant0 | grep -q 2001:db8:10::1")
        fw.wait_until_succeeds("ip link show d0 | grep -q 'master br0'")
        fw.succeed("ip link show eth1 | grep -q 'mtu 1400'")
        fw.succeed("ip -d link show tenant0 | grep -q 'prog/xdp'")
        links = json.loads(fw.succeed("bpftool -j link show"))
        assert any(l.get("devname") == "tenant0" and l.get("attach_type") == "tcx_egress" for l in links), links
        first = fw.succeed("cat /sys/class/net/tenant0/ifindex").strip()

    with subtest("an unchanged commit preserves the existing device"):
        invocation = fw.succeed("systemctl show -p InvocationID --value systemd-networkd.service").strip()
        configure([])
        assert fw.succeed("cat /sys/class/net/tenant0/ifindex").strip() == first
        assert fw.succeed("systemctl show -p InvocationID --value systemd-networkd.service").strip() == invocation

    with subtest("an unchanged commit recovers the network supervisor"):
        fw.succeed("systemctl stop systemd-networkd.service")
        fw.fail("systemctl is-active systemd-networkd.service")
        configure([])
        fw.succeed("systemctl is-active systemd-networkd.service")
        fw.wait_until_succeeds("ip -4 addr show tenant0 | grep -q 192.0.2.1")

    with subtest("an unchanged commit repairs mutable kernel drift"):
        fw.succeed("ip link set eth1 mtu 1300")
        fw.succeed("ip addr del 192.0.2.1/24 dev tenant0")
        fw.succeed("ip -6 addr del 2001:db8:10::1/64 dev tenant0")
        fw.succeed("ip link set d0 nomaster")
        configure([])
        fw.wait_until_succeeds("ip link show eth1 | grep -q 'mtu 1400'")
        fw.wait_until_succeeds("ip -4 addr show tenant0 | grep -q 192.0.2.1")
        fw.wait_until_succeeds("ip -6 addr show tenant0 | grep -q 2001:db8:10::1")
        fw.wait_until_succeeds("ip link show d0 | grep -q 'master br0'")
        assert fw.succeed("cat /sys/class/net/tenant0/ifindex").strip() == first

    with subtest("an unchanged commit recreates a deleted owned VLAN"):
        fw.succeed("ip link delete tenant0")
        configure([])
        fw.wait_until_succeeds("ip -d link show tenant0 | grep -q 'id 10 '")
        fw.wait_until_succeeds("ip -4 addr show tenant0 | grep -q 192.0.2.1")
        fw.wait_until_succeeds("ip -6 addr show tenant0 | grep -q 2001:db8:10::1")
        first = fw.succeed("cat /sys/class/net/tenant0/ifindex").strip()
        fw.succeed("ip -d link show tenant0 | grep -q 'prog/xdp'")

    with subtest("an unchanged commit replaces an owned VLAN with the wrong tag"):
        fw.succeed("ip link delete tenant0")
        fw.succeed("ip link add link eth1 name tenant0 type vlan id 99")
        configure([])
        fw.wait_until_succeeds("ip -d link show tenant0 | grep -q 'id 10 '")
        fw.wait_until_succeeds("ip -4 addr show tenant0 | grep -q 192.0.2.1")
        fw.wait_until_succeeds("ip -6 addr show tenant0 | grep -q 2001:db8:10::1")
        first = fw.succeed("cat /sys/class/net/tenant0/ifindex").strip()
        configure([])
        assert fw.succeed("cat /sys/class/net/tenant0/ifindex").strip() == first

    with subtest("a recreated zoned link stays down until the data plane has hooked it"):
        # With the agent stopped nothing can hook the link, so a link that
        # comes up anyway forwards unfiltered: exactly the window between a
        # link appearing and the agent's next pass. networkd recreates the
        # deleted VLAN from its unit when it configures the parent (a reload
        # alone leaves an unchanged parent, and so the VLAN, alone); the hold
        # must keep it down.
        fw.succeed("systemctl stop velstra.service")
        fw.succeed("ip link delete tenant0")
        fw.succeed("networkctl reconfigure eth1")
        fw.wait_until_succeeds("test -e /sys/class/net/tenant0")
        for _ in range(5):
            flags = json.loads(fw.succeed("ip -j link show dev tenant0"))[0]["flags"]
            assert "UP" not in flags, f"tenant0 came up with no data plane: {flags}"
            fw.sleep(1)
        # Dark, and said so: `ip` alone shows it exactly like a link somebody
        # switched off.
        shown = fw.succeed("sentinel show interfaces")
        assert "tenant0: held: waiting for datapath" in shown, shown
        fw.succeed("systemctl start velstra.service")
        fw.wait_until_succeeds("ip -o link show dev tenant0 | grep -Eq '[<,]UP[,>]'", timeout=30)
        fw.succeed("ip -d link show tenant0 | grep -q 'prog/xdp'")
        fw.wait_until_succeeds("ip -4 addr show tenant0 | grep -q 192.0.2.1")
        assert "held:" not in fw.succeed("sentinel show interfaces")
        first = fw.succeed("cat /sys/class/net/tenant0/ifindex").strip()

    with subtest("a zoned link disabled and enabled again comes back up"):
        # The agent keeps its hook on a link while it is disabled, so enabling
        # it again attaches nothing new. It must still be raised — otherwise it
        # stays dark and every later commit fails on it.
        configure(["set interface tenant0 disabled true"])
        fw.wait_until_fails("ip -o link show dev tenant0 | grep -Eq '[<,]UP[,>]'")
        configure(["delete interface tenant0 disabled"])
        fw.wait_until_succeeds("ip -o link show dev tenant0 | grep -Eq '[<,]UP[,>]'", timeout=30)
        fw.succeed("ip -d link show tenant0 | grep -q 'prog/xdp'")
        fw.wait_until_succeeds("ip -4 addr show tenant0 | grep -q 192.0.2.1")
        configure([])
        first = fw.succeed("cat /sys/class/net/tenant0/ifindex").strip()

    with subtest("a crashed agent puts its raised zoned links back into the hold"):
        # The XDP program dies with the agent, so a zoned link left up would
        # forward with nothing on it until the restart hooks it again. The
        # unit's ExecStopPost takes it down; the restarted agent raises it.
        # The journal line is the proof: Restart=on-failure brings the agent
        # back within seconds, so sampling the link state alone could race.
        #
        # A crash kills the agent alone. Killing the whole unit kills the
        # ExecStopPost with it, so for that the next start's ExecStartPre
        # repeats the hold before the agent runs; either way the line appears.
        for whom in ("main", "all"):
            cursor = fw.succeed("journalctl -n 0 --show-cursor | sed -n 's/^-- cursor: //p'").strip()
            fw.wait_until_succeeds("ip -o link show dev tenant0 | grep -Eq '[<,]UP[,>]'", timeout=30)
            fw.succeed(f"systemctl kill --kill-whom={whom} -s KILL velstra.service")
            fw.wait_until_succeeds(
                f"journalctl --after-cursor='{cursor}' -u velstra.service "
                "| grep -q 'hold-links-down: tenant0 held until the data plane hooks it again'",
                timeout=30,
            )
            fw.wait_until_succeeds("systemctl is-active velstra.service", timeout=30)
            fw.wait_until_succeeds("ip -o link show dev tenant0 | grep -Eq '[<,]UP[,>]'", timeout=30)
            fw.succeed("ip -d link show tenant0 | grep -q 'prog/xdp'")
            assert "held:" not in fw.succeed("sentinel show interfaces")

    with subtest("an unchanged commit removes addresses the configuration does not set"):
        fw.succeed("ip addr add 203.0.113.77/32 dev tenant0")
        fw.succeed("ip -6 addr add 2001:db8:77::7/64 dev tenant0 nodad")
        configure([])
        fw.wait_until_fails("ip -4 addr show tenant0 | grep -q 203.0.113.77")
        fw.wait_until_fails("ip -6 addr show tenant0 | grep -q 2001:db8:77::7")
        fw.succeed("ip -4 addr show tenant0 | grep -q 192.0.2.1")
        assert fw.succeed("cat /sys/class/net/tenant0/ifindex").strip() == first

    with subtest("recreating a bridge reattaches its unchanged members"):
        before = fw.succeed("cat /sys/class/net/br0/ifindex").strip()
        configure(["set interface br0 bridge stp true"])
        fw.wait_until_succeeds("test $(cat /sys/class/net/br0/bridge/stp_state) = 1")
        fw.wait_until_succeeds("ip link show d0 | grep -q 'master br0'")
        assert fw.succeed("cat /sys/class/net/br0/ifindex").strip() != before

    with subtest("an unchanged commit replaces an owned bridge with the wrong device kind"):
        fw.succeed("ip link delete br0")
        fw.succeed("ip link add br0 type dummy")
        configure([])
        fw.wait_until_succeeds("test -d /sys/class/net/br0/bridge")
        fw.wait_until_succeeds("ip link show d0 | grep -q 'master br0'")
        fw.wait_until_succeeds("ip -4 addr show br0 | grep -q 198.51.100.1")

    with subtest("removing the MTU override restores the Ethernet and VLAN defaults"):
        configure(["delete interface eth1 mtu"])
        fw.wait_until_succeeds("ip link show eth1 | grep -q 'mtu 1500'")
        fw.wait_until_succeeds("ip link show tenant0 | grep -q 'mtu 1500'")

    with subtest("a changed VLAN ID is applied to the actual kernel link"):
        configure(["set interface tenant0 vlan 20", "set interface tenant0 address 192.0.2.2/24"])
        fw.wait_until_succeeds("ip -d link show tenant0 | grep -q 'id 20 '")
        fw.wait_until_succeeds("ip -4 addr show tenant0 | grep -q 192.0.2.2")
        fw.fail("ip -4 addr show tenant0 | grep -q 192.0.2.1/")
        assert fw.succeed("cat /sys/class/net/tenant0/ifindex").strip() != first
        fw.succeed("ip -d link show tenant0 | grep -q 'prog/xdp'")
        links = json.loads(fw.succeed("bpftool -j link show"))
        assert any(l.get("devname") == "tenant0" and l.get("attach_type") == "tcx_egress" for l in links), links

    with subtest("removing addressing retains an explicit empty network unit"):
        configure(["delete interface tenant0 address", "delete interface tenant0 address6"])
        fw.wait_until_fails("ip -4 addr show tenant0 | grep -q 'inet '")
        fw.wait_until_fails("ip -6 addr show tenant0 | grep -q 2001:db8:")

    with subtest("removing bridge membership releases the existing member"):
        configure(["delete interface br0 member d0"])
        fw.wait_until_fails("ip link show d0 | grep -q 'master br0'")
        fw.succeed("ip link show br0")

    with subtest("removing virtual interfaces removes kernel devices and files"):
        configure(["delete interface tenant0", "delete interface br0", "delete interface d0"])
        for name in ["tenant0", "br0", "d0"]:
            fw.fail("ip link show dev " + name)
            fw.fail("test -e /run/systemd/network/10-sentinel-" + name + ".netdev")
        fw.fail("test -e /run/sentinel/network-retire.json")
        configure([])

    with subtest("a physical interface removed from the configuration is released"):
        # networkd only forgets a link whose unit disappears; the address and
        # the up state would stay, on a link the data plane no longer hooks.
        configure(["set interface eth1 address 203.0.113.1/24"])
        fw.wait_until_succeeds("ip -4 addr show eth1 | grep -q 203.0.113.1")
        configure(["delete interface eth1"])
        fw.wait_until_fails("ip -4 addr show eth1 | grep -q 203.0.113.1")
        flags = json.loads(fw.succeed("ip -j link show dev eth1"))[0]["flags"]
        assert "UP" not in flags, flags

    with subtest("DNS changes settle without restarting on every commit"):
        configure(["set services dns upstream 192.0.2.53"])
        before = fw.succeed("systemctl show -p InvocationID --value systemd-resolved.service").strip()
        assert before
        configure([])
        assert fw.succeed("systemctl show -p InvocationID --value systemd-resolved.service").strip() == before
        fw.fail("test -e /run/systemd/resolved.conf.d/10-sentinel-dns.conf.sentinel-pending")
        fw.succeed("systemctl stop systemd-resolved.service")
        configure([])
        fw.succeed("systemctl is-active systemd-resolved.service")
  '';
}
