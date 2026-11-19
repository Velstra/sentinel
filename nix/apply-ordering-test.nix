# First provisioning must not rely on an eth0 launch default or pre-existing
# addresses. Exercise the installed CLI and actual FIB, including full rollback.
{ pkgs, self }:
pkgs.testers.runNixOSTest {
  name = "sentinel-apply-ordering";
  globalTimeout = 480;
  nodes.machine = { lib, ... }: {
    imports = [ self.nixosModules.sentinel ./boot-health.nix ];
    virtualisation.memorySize = 2048;
    virtualisation.vlans = [ 1 ];
    services.velstra.appliance = lib.mkForce (pkgs.writeText "unprovisioned.toml" ''
      [system]
      hostname = "first-apply"
    '');
  };
  nodes.reference = { ... }: {
    virtualisation.vlans = [ 1 ];
    networking.firewall.enable = false;
    networking.interfaces.eth1.ipv4.addresses = [
      { address = "192.0.2.2"; prefixLength = 24; }
      { address = "198.51.100.10"; prefixLength = 32; }
    ];
  };
  testScript = ''
    import shlex
    start_all()
    for node in (machine, reference):
        node.wait_for_unit("multi-user.target")
    machine.wait_for_unit("sentinel-boot.service")
    machine.fail("systemctl is-active --quiet velstra.service")
    machine.succeed("ip link set eth1 down; ip link set eth1 name enp42s0")
    machine.succeed("ip link set eth0 down; ip link set eth0 name mgmt0")
    machine.fail("test -e /sys/class/net/eth0")
    machine.succeed("chown root:root /var/lib/sentinel/appliance.toml; chmod 0600 /var/lib/sentinel/appliance.toml")
    assert "first-apply" in machine.succeed("su admin -c 'sentinel show configuration'")
    machine.fail("su -s /bin/sh nobody -c 'sentinel configure </dev/null'")

    def configure(commands, success=True):
        payload = "\n".join(commands + ["commit", "exit"]) + "\n"
        command = "printf %s " + shlex.quote(payload) + " | sentinel configure"
        command = "su admin -c " + shlex.quote(command) + " 2>&1"
        output = machine.succeed(command) if success else machine.fail(command)
        assert ("commit ok" in output) == success, output
        return output

    with subtest("protected admin first commit installs launch settings, addresses and dependent route"):
        configure([
            "compare",
            "set firewall global default-action accept",
            "set interface enp42s0 zone wan",
            "set interface enp42s0 address 192.0.2.1/24",
            "set protocols static 198.51.100.10/32 via 192.0.2.2",
        ])
        machine.succeed("grep -Fx VELSTRA_IFACE=enp42s0 /run/sentinel/velstra.env")
        machine.succeed("ip -details link show enp42s0 | grep -q prog/xdp")
        machine.succeed("ip -4 route show exact 198.51.100.10/32 | grep -q 'via 192.0.2.2'")
        machine.succeed("ping -c 3 -W 2 198.51.100.10")
        # A later session must load the protected unsaved running revision, not
        # the empty saved file or an unprivileged fallback draft.
        machine.succeed("chown root:root /run/sentinel/running.toml; chmod 0600 /run/sentinel/running.toml")
        configure(["compare", "compare running", "show", "set interface enp42s0 description protected-live-session"])
        machine.succeed("ping -c 1 -W 2 198.51.100.10")

    with subtest("unreachable candidate gateway restores old address, launch settings and actual route"):
        previous = machine.succeed("sha256sum /run/sentinel/running.toml /var/lib/sentinel/appliance.toml /run/sentinel/velstra.env")
        output = configure([
            "set interface enp42s0 address 192.0.3.1/24",
            "set protocols static 198.51.100.10/32 via 203.0.113.9",
        ], success=False)
        assert "MIXED STATE" not in output, output
        assert "ROLLED BACK to the last-good running configuration" in output, output
        assert previous == machine.succeed("sha256sum /run/sentinel/running.toml /var/lib/sentinel/appliance.toml /run/sentinel/velstra.env")
        machine.succeed("ip -4 address show enp42s0 | grep -q '192.0.2.1/24'")
        machine.fail("ip -4 address show enp42s0 | grep -q '192.0.3.1/24'")
        machine.succeed("ip -4 route show exact 198.51.100.10/32 | grep -q 'via 192.0.2.2'")
        machine.succeed("ping -c 3 -W 2 198.51.100.10")
        machine.succeed("grep -Fx VELSTRA_IFACE=enp42s0 /run/sentinel/velstra.env")
        machine.succeed("systemctl is-active velstra.service wren.service")

    with subtest("failed uplink migration restores launch environment and original packet hooks"):
        previous = machine.succeed("sha256sum /run/sentinel/running.toml /var/lib/sentinel/appliance.toml /run/sentinel/velstra.env")
        output = configure([
            "delete interface enp42s0 zone",
            "set interface mgmt0 zone wan",
            "set interface mgmt0 address 192.0.3.1/24",
            "set protocols static 198.51.100.10/32 via 203.0.113.9",
        ], success=False)
        assert "ROLLED BACK to the last-good running configuration" in output, output
        assert "MIXED STATE" not in output, output
        assert previous == machine.succeed("sha256sum /run/sentinel/running.toml /var/lib/sentinel/appliance.toml /run/sentinel/velstra.env")
        machine.succeed("grep -Fx VELSTRA_IFACE=enp42s0 /run/sentinel/velstra.env")
        machine.succeed("ip -details link show enp42s0 | grep -q prog/xdp")
        machine.fail("ip -details link show mgmt0 | grep -q prog/xdp")
        machine.fail("ip -4 address show mgmt0 | grep -q '192.0.3.1/24'")
        machine.succeed("ip -4 route show exact 198.51.100.10/32 | grep -q 'via 192.0.2.2'")
        machine.succeed("ping -c 3 -W 2 198.51.100.10")
  '';
}
