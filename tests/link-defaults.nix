# Physical properties must converge on removal, failure, retry and reboot.
{ pkgs, sentinelModule, sentinel, limitedMtu ? false }:
pkgs.testers.runNixOSTest {
  name = "sentinel-link-defaults${pkgs.lib.optionalString limitedMtu "-driver-limit"}";
  nodes.machine = {
    imports = [ sentinelModule ];
    networking.hostName = pkgs.lib.mkForce "machine";
    virtualisation.memorySize = 2048;
    # Real virtio capability, not a mocked command: the kernel rejects >1500.
    virtualisation.qemu.options = pkgs.lib.optionals limitedMtu [
      "-global" "virtio-net-pci.host_mtu=1500"
    ];
    virtualisation.vlans = [ 1 ];
    virtualisation.emptyDiskImages = [ 512 ];
    virtualisation.fileSystems."/var/lib/sentinel" = {
      device = "/dev/vdb";
      fsType = "ext4";
      autoFormat = true;
    };
    # Deliberately not 1500: returning a guessed Ethernet default is a bug.
    systemd.services.sentinel-boot.preStart = "${pkgs.iproute2}/bin/ip link set dev eth1 mtu 1460";
    environment.systemPackages = [ pkgs.curl pkgs.python3 ];
  };
  nodes.client = { pkgs, ... }: {
    virtualisation.vlans = [ 1 ];
    networking.useDHCP = false;
    networking.interfaces.eth1.ipv4.addresses = [ { address = "198.18.60.2"; prefixLength = 24; } ];
    networking.interfaces.eth1.ipv6.addresses = [ { address = "2001:db8:60::2"; prefixLength = 64; } ];
    environment.systemPackages = [ pkgs.curl ];
  };
  testScript = ''
    import json
    import shlex
    import tomllib

    machine.start(allow_reboot=True)
    client.start()
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("sentinel-boot-late.service")
    client.wait_for_unit("multi-user.target")
    journal = "/var/lib/sentinel/link-defaults.json"
    clone = "02:66:77:88:99:aa"
    configured_mtu = ${toString (if limitedMtu then 1492 else 9000)}
    drift_mtu = ${toString (if limitedMtu then 1480 else 8800)}
    limited_mtu = ${if limitedMtu then "True" else "False"}

    def props():
        return json.loads(machine.succeed("ip -j -d link show dev eth1"))[0]

    def command(*lines):
        script = "\n".join([*lines, "commit", "save", "exit", ""])
        return "su admin -c " + shlex.quote("printf %s " + shlex.quote(script) + " | ${sentinel}/bin/sentinel configure 2>&1")

    def apply(*lines):
        output = machine.succeed(command(*lines))
        assert "commit ok: applied live" in output and "saved /" in output, output
        return output

    def saved():
        return tomllib.loads(machine.succeed("cat /var/lib/sentinel/appliance.toml"))

    def archive_state():
        source = "from pathlib import Path; import hashlib; p=Path('/var/lib/sentinel/archive'); assert p.is_dir(); print(sorted((f.name,f.stat().st_mtime_ns,hashlib.sha256(f.read_bytes()).hexdigest()) for f in p.iterdir() if f.is_file()))"
        return machine.succeed("${pkgs.python3}/bin/python3 -c " + shlex.quote(source))

    def web():
        client.succeed("ip neigh flush dev eth1")
        assert "link-defaults-ok" in client.wait_until_succeeds("curl -fsS --noproxy '*' --max-time 3 http://198.18.60.1:18088/", timeout=20)
        client.fail("ping -c 1 -W 1 198.18.60.1")
        assert "link-defaults-ok" in client.wait_until_succeeds("curl -g -6 -fsS --noproxy '*' --max-time 3 http://[2001:db8:60::1]:18089/", timeout=20)

    def start_web():
        machine.succeed("mkdir -p /run/link-web; printf link-defaults-ok > /run/link-web/index.html")
        machine.succeed("systemd-run --unit=link-web ${pkgs.python3}/bin/python3 -m http.server 18088 --directory /run/link-web")
        machine.wait_for_open_port(18088)
        machine.succeed("systemd-run --unit=link-web6 ${pkgs.python3}/bin/python3 -m http.server 18089 --bind :: --directory /run/link-web")
        machine.wait_for_open_port(18089)

    initial = props()
    assert initial["mtu"] == 1460, initial
    original_mac = initial["address"]
    start_web()
    with subtest("first override records actual pre-override physical defaults durably"):
        apply("set interface eth1 address 198.18.60.1/24", "set interface eth1 address6 2001:db8:60::1/64", "set interface eth1 zone physical-test", "set firewall global default-action accept", "set firewall global block-icmp false", "set firewall rule physical-no-ping from physical-test", "set firewall rule physical-no-ping action drop", "set firewall rule physical-no-ping proto icmp", "set interface eth1 mtu " + str(configured_mtu), "set interface eth1 mac " + clone)
        actual = props()
        assert actual["mtu"] == configured_mtu and actual["address"] == clone, actual
        entry = json.loads(machine.succeed("cat " + journal))["links"]["eth1"]
        assert entry["defaults"] == dict(mtu=1460, mac=original_mac), entry
        assert entry["own_mtu"] and entry["own_mac"], entry
        web()

    with subtest("an unchanged apply preserves daemon, link and durable baseline"):
        inode = machine.succeed("stat -c '%i:%y' " + journal)
        pid = machine.succeed("systemctl show -p MainPID --value velstra.service")
        index = props()["ifindex"]
        apply()
        assert props()["ifindex"] == index
        assert machine.succeed("stat -c '%i:%y' " + journal) == inode
        assert machine.succeed("systemctl show -p MainPID --value velstra.service") == pid
        web()

    with subtest("unchanged units repair actual MTU and MAC drift without restarting the agent"):
        inode = machine.succeed("stat -c '%i:%y' " + journal)
        pid = machine.succeed("systemctl show -p MainPID --value velstra.service")
        machine.succeed("ip link set dev eth1 mtu " + str(drift_mtu) + " address 02:66:77:88:99:bb")
        drifted = props()
        assert drifted["mtu"] == drift_mtu and drifted["address"] != clone, drifted
        apply()
        actual = props()
        assert actual["mtu"] == configured_mtu and actual["address"] == clone, actual
        assert machine.succeed("stat -c '%i:%y' " + journal) == inode
        assert machine.succeed("systemctl show -p MainPID --value velstra.service") == pid
        web()

    with subtest("removing fields restores measured defaults and actual traffic immediately"):
        apply("delete interface eth1 mtu", "delete interface eth1 mac")
        actual = props()
        assert actual["mtu"] == 1460 and actual["address"] == original_mac, actual
        desired = next(i for i in saved()["interface"] if i["name"] == "eth1")
        assert "mtu" not in desired and "mac" not in desired, desired
        web()

    with subtest("invalid source MACs fail validation before any runtime or archive writes"):
        before = saved()
        running = machine.succeed("cat /run/sentinel/running.toml")
        ownership = machine.succeed("stat -c '%i:%y' " + journal)
        network_unit = machine.succeed("stat -c '%i:%y' /run/systemd/network/10-sentinel-eth1.network")
        history = archive_state()
        pid = machine.succeed("systemctl show -p MainPID --value velstra.service")
        for invalid in ["00:00:00:00:00:00", "01:66:77:88:99:aa", "FF:FF:FF:FF:FF:FF"]:
            output = machine.fail(command("set interface eth1 mac " + invalid))
            assert "non-zero unicast" in output, output
            assert "commit ok" not in output and "saved /" not in output, output
            assert saved() == before
            assert machine.succeed("cat /run/sentinel/running.toml") == running
            assert machine.succeed("stat -c '%i:%y' " + journal) == ownership
            assert machine.succeed("stat -c '%i:%y' /run/systemd/network/10-sentinel-eth1.network") == network_unit
            assert archive_state() == history
            assert machine.succeed("systemctl show -p MainPID --value velstra.service") == pid
            actual = props()
            assert actual["mtu"] == 1460 and actual["address"] == original_mac, actual
        web()

    if limited_mtu:
        with subtest("real driver MTU limits and downstream clamping preserve the last good configuration"):
            assert props()["max_mtu"] == 1500, props()
            rejection = machine.fail("ip link set dev eth1 mtu 9000 2>&1")
            assert "mtu greater than device maximum" in rejection, rejection
            assert props()["mtu"] == 1460, props()

            before = saved()
            running = machine.succeed("cat /run/sentinel/running.toml")
            # The schema accepts9000, but this actual device cannot. networkd
            # clamps to the advertised maximum1500; an accepted job must not
            # report that different MTU as a successful application of9000.
            output = machine.fail(command("set interface eth1 mtu 9000", "set interface eth1 mac " + clone))
            assert "physical link properties were not applied" in output, output
            assert "expected MTU Some(9000)" in output and "observed 1500/" in output, output
            assert "ROLLED BACK" in output and "MIXED STATE" not in output, output
            assert "commit ok: applied live" not in output and "saved /" not in output, output
            assert saved() == before
            assert machine.succeed("cat /run/sentinel/running.toml") == running
            actual = props()
            assert actual["mtu"] == 1460 and actual["address"] == original_mac, actual
            web()

    with subtest("saved overrides and measured defaults survive actual warm reboot"):
        apply("set interface eth1 mtu " + str(configured_mtu), "set interface eth1 mac " + clone)
        baseline = machine.succeed("cat " + journal)
        machine.reboot()
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("sentinel-boot-late.service")
        assert machine.succeed("cat " + journal) == baseline
        actual = props()
        assert actual["mtu"] == configured_mtu and actual["address"] == clone, actual
        start_web()
        web()
        apply("delete interface eth1 mtu", "delete interface eth1 mac")
        actual = props()
        assert actual["mtu"] == 1460 and actual["address"] == original_mac, actual
        web()

    with subtest("removing the whole interface also clears previously owned physical properties"):
        apply("set interface eth1 mtu " + str(configured_mtu), "set interface eth1 mac " + clone)
        apply("delete firewall rule physical-no-ping", "delete interface eth1")
        actual = props()
        assert actual["mtu"] == 1460 and actual["address"] == original_mac, actual
        assert not any(i["name"] == "eth1" for i in saved()["interface"])

    with subtest("networkd cannot apply old defaults to a foreign same-name device"):
        body = machine.succeed("cat /run/systemd/network/10-sentinel-eth1.network")
        assert "PermanentMACAddress=" + original_mac in body, body
        # Keep the actual old physical device alive elsewhere, then create a
        # real unrelated same-name kernel device before any further commit.
        machine.succeed("ip netns add retired-physical; ip link set dev eth1 netns retired-physical")
        machine.succeed("ip link add name eth1 mtu 1780 address 02:aa:bb:cc:dd:ee type dummy")
        machine.sleep(3)
        foreign = props()
        assert foreign["linkinfo"]["info_kind"] == "dummy", foreign
        assert foreign["mtu"] == 1780 and foreign["address"] == "02:aa:bb:cc:dd:ee", foreign
        old = json.loads(machine.succeed("ip -n retired-physical -j link show dev eth1"))[0]
        assert old["mtu"] == 1460 and old["address"] == original_mac, old

  '';
}
