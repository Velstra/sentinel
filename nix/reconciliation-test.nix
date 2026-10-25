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
        configure([])
        assert fw.succeed("cat /sys/class/net/tenant0/ifindex").strip() == first

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
