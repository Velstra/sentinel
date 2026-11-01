# Actual kernel ownership, tagged traffic, immutable replacement and recovery.
{ pkgs, sentinelModule, sentinel }:
pkgs.testers.runNixOSTest {
  name = "sentinel-vlan-lifecycle";
  nodes.machine = {
    imports = [ sentinelModule ];
    virtualisation.memorySize = 2048;
    virtualisation.vlans = [ 1 ];
    # Match the appliance's persistent state partition across the real reboot.
    virtualisation.emptyDiskImages = [ 512 ];
    virtualisation.fileSystems."/var/lib/sentinel" = {
      device = "/dev/vdb";
      fsType = "ext4";
      autoFormat = true;
    };
    environment.systemPackages = [ pkgs.bpftools pkgs.curl pkgs.dnsutils ];
  };
  testScript = ''
    import json
    import re
    import shlex
    import tomllib

    machine.start(allow_reboot=True)
    machine.wait_for_unit("multi-user.target")
    machine.succeed("findmnt -no SOURCE /var/lib/sentinel | grep -q /dev/")
    machine.wait_for_unit("velstra.service")
    query = "${sentinel}/bin/sentinel agent-query "
    machine.wait_until_succeeds(query + "status | grep '^Ready$'", timeout=20)
    journal = "/var/lib/sentinel/managed-vlans.json"
    programs = "/sys/fs/bpf/sentinel/programs"

    def command(*lines):
        script = "\n".join([*lines, "commit", "save", "exit", ""])
        return "su admin -c " + shlex.quote("printf %s " + shlex.quote(script) + " | ${sentinel}/bin/sentinel configure 2>&1")

    def apply(*lines):
        output = machine.succeed(command(*lines))
        assert "commit ok: applied live" in output and "saved /" in output, output
        return output

    def link(name):
        return json.loads(machine.succeed("ip -j -d link show dev " + name))[0]

    def owner(name):
        return json.loads(machine.succeed("cat " + journal))["owners"][name]

    def protected(name):
        state = json.loads(machine.succeed(query + shlex.quote("interface " + name)))
        assert state["ready"] is True and state["ifindex"] == link(name)["ifindex"], state
        return state

    def saved():
        return tomllib.loads(machine.succeed("cat /var/lib/sentinel/appliance.toml"))

    def web(address):
        return "ip netns exec vlan-client curl -fsS --noproxy '*' --max-time 3 http://" + address + ":18088/"

    machine.succeed("ip netns add vlan-client")
    machine.succeed("ip link add tenant-wire type veth peer name client-wire")
    machine.succeed("ip link set client-wire netns vlan-client; ip link set tenant-wire up")
    machine.succeed("ip netns exec vlan-client ip link set lo up; ip netns exec vlan-client ip link set client-wire up")
    for tag in [42, 43]:
        machine.succeed("ip netns exec vlan-client ip link add link client-wire name client" + str(tag) + " type vlan id " + str(tag))
        machine.succeed("ip netns exec vlan-client ip addr add 198.18." + str(tag) + ".2/24 dev client" + str(tag))
        machine.succeed("ip netns exec vlan-client ip link set client" + str(tag) + " up")
    machine.succeed("mkdir -p /run/vlan-web; printf guarded-vlan-ok > /run/vlan-web/index.html")
    machine.succeed("systemd-run --unit=vlan-web ${pkgs.python3}/bin/python3 -m http.server 18088 --directory /run/vlan-web")
    machine.wait_for_open_port(18088)

    with subtest("declared VLAN has actual ownership, address, XDP and tagged traffic"):
        apply("set interface tenant-wire description vlan-parent", "set interface iot-test parent tenant-wire", "set interface iot-test vlan 42", "set interface iot-test zone iot", "set interface iot-test address 198.18.42.1/24", "set firewall global default-action accept", "set firewall global block-icmp true", "set services dns serve-on iot-test", "set services dns host-override vlan.test 192.0.2.42")
        state = link("iot-test")
        assert state["linkinfo"]["info_data"]["id"] == 42 and "UP" in state["flags"], state
        assert int(state["group"]) == owner("iot-test")["group"], state
        assert state["ifalias"] == owner("iot-test")["alias"], state
        protected("iot-test")
        assert "guarded-vlan-ok" in machine.wait_until_succeeds(web("198.18.42.1"), timeout=20)
        machine.fail("ip netns exec vlan-client ping -c 1 -W 1 198.18.42.1")
        machine.wait_until_succeeds("ip netns exec vlan-client dig +short +time=2 +tries=1 @198.18.42.1 vlan.test A | grep -Fx 192.0.2.42", timeout=15)
        dns_pid = machine.succeed("systemctl show -p MainPID --value dnsmasq.service")
        network = machine.succeed("cat /run/systemd/network/10-sentinel-iot-test.network")
        assert "ActivationPolicy=manual" in network and "ConfigureWithoutCarrier=yes" in network, network
        machine.succeed("test ! -e /run/systemd/network/10-sentinel-iot-test.netdev")

    with subtest("unchanged apply preserves link, ownership file and daemon"):
        before = link("iot-test")["ifindex"]
        identity = machine.succeed("stat -c '%i:%y' " + journal)
        pid = machine.succeed("systemctl show -p MainPID --value velstra.service")
        output = apply()
        assert "is not present yet" not in output, output
        assert link("iot-test")["ifindex"] == before
        assert machine.succeed("stat -c '%i:%y' " + journal) == identity
        assert machine.succeed("systemctl show -p MainPID --value velstra.service") == pid
        assert "guarded-vlan-ok" in machine.succeed(web("198.18.42.1"))

    with subtest("an early service failure restores the staged link with previous policy"):
        before = saved()
        index = link("iot-test")["ifindex"]
        fault = "/run/systemd/system/wren.service.d/90-start-fault.conf"
        machine.succeed("mkdir -p /run/systemd/system/wren.service.d")
        machine.succeed("printf '[Unit]\nAssertPathExists=/run/vlan-routing-start-allowed\n' > " + fault)
        machine.succeed("systemctl daemon-reload")
        machine.succeed("systemctl cat wren.service | grep AssertPathExists=/run/vlan-routing-start-allowed")
        try:
            output = machine.fail(command("set interface iot-test vlan 43"))
            assert "commit ok: applied live" not in output and "saved /" not in output, output
            machine.fail("systemctl is-active --quiet wren.service")
            assert "ROLLBACK INCOMPLETE" in output, output
        finally:
            machine.succeed("rm " + fault)
            machine.succeed("systemctl daemon-reload")
        assert saved() == before
        assert link("iot-test")["ifindex"] == index and "UP" in link("iot-test")["flags"]
        assert link("iot-test")["linkinfo"]["info_data"]["id"] == 42
        apply()
        machine.wait_for_unit("wren.service")
        protected("iot-test")
        assert "guarded-vlan-ok" in machine.wait_until_succeeds(web("198.18.42.1"), timeout=20)

    with subtest("tag change replaces the actual interface and switches tagged traffic"):
        before, ownership = link("iot-test")["ifindex"], owner("iot-test")
        apply("set interface iot-test vlan 43", "set interface iot-test address 198.18.43.1/24")
        after = link("iot-test")
        assert after["ifindex"] != before and after["linkinfo"]["info_data"]["id"] == 43, after
        assert owner("iot-test") == ownership
        protected("iot-test")
        assert "guarded-vlan-ok" in machine.wait_until_succeeds(web("198.18.43.1"), timeout=20)
        machine.fail(web("198.18.42.1"))
        machine.wait_until_succeeds("ip netns exec vlan-client dig +short +time=2 +tries=1 @198.18.43.1 vlan.test A | grep -Fx 192.0.2.42", timeout=15)
        assert machine.succeed("systemctl show -p MainPID --value dnsmasq.service") == dns_pid
        machine.fail("ip netns exec vlan-client ping -c 1 -W 1 198.18.43.1")

    with subtest("parent change is real and returning to the old parent restores traffic"):
        machine.succeed("ip link add alternate type dummy; ip link set alternate up")
        before = link("iot-test")["ifindex"]
        apply("set interface alternate description alternative-parent", "set interface iot-test parent alternate")
        after = link("iot-test")
        assert after["link"] == "alternate" and after["ifindex"] != before, after
        protected("iot-test")
        apply("set interface iot-test parent tenant-wire")
        assert link("iot-test")["link"] == "tenant-wire"
        assert "guarded-vlan-ok" in machine.wait_until_succeeds(web("198.18.43.1"), timeout=20)

    with subtest("QinQ ancestor replacement recreates owned children in dependency order"):
        apply("set interface outer-test parent tenant-wire", "set interface outer-test vlan 100", "set interface outer-test vlan-protocol 802.1ad", "set interface inner-test parent outer-test", "set interface inner-test vlan 20", "set interface inner-test zone iot", "set interface inner-test address 198.18.120.1/24")
        machine.succeed("ip netns exec vlan-client ip link add link client-wire name outer type vlan protocol 802.1ad id 100")
        machine.succeed("ip netns exec vlan-client ip link set outer up; ip netns exec vlan-client ip link add link outer name inner type vlan id 20")
        machine.succeed("ip netns exec vlan-client ip addr add 198.18.120.2/24 dev inner; ip netns exec vlan-client ip link set inner up")
        assert "guarded-vlan-ok" in machine.wait_until_succeeds(web("198.18.120.1"), timeout=20)
        machine.fail("ip netns exec vlan-client dig +short +time=1 +tries=1 @198.18.120.1 vlan.test A")
        before = link("inner-test")["ifindex"]
        apply("set interface outer-test vlan 101")
        assert link("outer-test")["linkinfo"]["info_data"]["id"] == 101
        assert link("inner-test")["ifindex"] != before and link("inner-test")["link"] == "outer-test"
        protected("inner-test")
        machine.succeed("ip netns exec vlan-client ip link del outer")
        machine.succeed("ip netns exec vlan-client ip link add link client-wire name outer type vlan protocol 802.1ad id 101")
        machine.succeed("ip netns exec vlan-client ip link set outer up; ip netns exec vlan-client ip link add link outer name inner type vlan id 20")
        machine.succeed("ip netns exec vlan-client ip addr add 198.18.120.2/24 dev inner; ip netns exec vlan-client ip link set inner up")
        assert "guarded-vlan-ok" in machine.wait_until_succeeds(web("198.18.120.1"), timeout=20)

    with subtest("TPID changes replace the actual QinQ stack and keep tagged traffic working"):
        before = link("inner-test")["ifindex"]
        apply("set interface outer-test vlan-protocol 802.1q")
        assert link("outer-test")["linkinfo"]["info_data"]["protocol"] == "802.1Q"
        assert link("inner-test")["ifindex"] != before
        protected("inner-test")
        machine.succeed("ip netns exec vlan-client ip link del outer")
        machine.succeed("ip netns exec vlan-client ip link add link client-wire name outer type vlan protocol 802.1q id 101")
        machine.succeed("ip netns exec vlan-client ip link set outer up; ip netns exec vlan-client ip link add link outer name inner type vlan id 20")
        machine.succeed("ip netns exec vlan-client ip addr add 198.18.120.2/24 dev inner; ip netns exec vlan-client ip link set inner up")
        assert "guarded-vlan-ok" in machine.wait_until_succeeds(web("198.18.120.1"), timeout=20)

    with subtest("foreign collisions and dependent interfaces are preserved"):
        before = saved()
        pid = machine.succeed("systemctl show -p MainPID --value velstra.service")
        machine.succeed("ip link add blocked type dummy")
        foreign = link("blocked")["ifindex"]
        output = machine.fail(command("set interface blocked parent tenant-wire", "set interface blocked vlan 52"))
        assert "refusing to adopt foreign interface" in output, output
        assert link("blocked")["ifindex"] == foreign and link("blocked")["linkinfo"]["info_kind"] == "dummy"
        assert saved() == before
        assert machine.succeed("systemctl show -p MainPID --value velstra.service") == pid
        machine.succeed("ip link add link iot-test name outsider type vlan id 20")
        foreign = link("outsider")["ifindex"]
        original = link("iot-test")["ifindex"]
        output = machine.fail(command("delete services dns", "delete interface iot-test"))
        assert "foreign dependent interface" in output, output
        assert link("outsider")["ifindex"] == foreign and link("iot-test")["ifindex"] == original
        assert saved() == before
        assert machine.succeed("systemctl show -p MainPID --value velstra.service") == pid
        machine.succeed("ip link del outsider; ip link del blocked")

    with subtest("real daemon startup fault keeps a new zoned VLAN DOWN until recovery"):
        original = json.loads(machine.succeed("bpftool -j map show pinned " + programs))["id"]
        shadow = "/sys/fs/bpf/vlan-saved-programs"
        machine.succeed("bpftool map pin id " + str(original) + " " + shadow)
        machine.succeed("rm " + programs)
        machine.succeed("bpftool map create " + programs + " type array key 4 value 4 entries 3 name bad_programs")
        try:
            script = command("set interface delayed-test parent tenant-wire", "set interface delayed-test vlan 55", "set interface delayed-test zone iot")
            machine.succeed("(" + script + "; echo $? > /run/vlan-commit.exit) > /run/vlan-commit.log 2>&1 &")
            machine.wait_until_succeeds("test -e /sys/class/net/delayed-test", timeout=12)
            for _ in range(3):
                assert "UP" not in link("delayed-test")["flags"]
                machine.sleep(1)
            machine.succeed("test ! -e /run/vlan-commit.exit")
            machine.succeed("journalctl -u velstra --no-pager -o cat | grep 'incompatible persistent control map programs'")
        finally:
            # No test-triggered daemon restart: systemd's normal retry and the
            # in-flight config reconciliation must recover from the real fault.
            machine.succeed("mv -f " + shadow + " " + programs)
        machine.wait_until_succeeds("test -e /run/vlan-commit.exit", timeout=25)
        assert machine.succeed("cat /run/vlan-commit.exit").strip() == "0", machine.succeed("cat /run/vlan-commit.log")
        assert "UP" in link("delayed-test")["flags"]
        protected("delayed-test")

    with subtest("an interrupted alias write is recoverable through atomic group ownership"):
        before = link("iot-test")["ifindex"]
        machine.succeed("ip link set iot-test alias \"\"")
        apply()
        assert link("iot-test")["ifindex"] == before
        assert link("iot-test")["ifalias"] == owner("iot-test")["alias"]

    with subtest("legacy generated VLAN is adopted only with exact committed provenance"):
        # Reproduce the actual pre-ownership artifacts, leaving the same real
        # networkd-managed VLAN and last committed appliance in place.
        machine.succeed("ip link set iot-test group 0; ip link set iot-test alias \"\"")
        machine.succeed("printf '%s' '[NetDev]\nName=iot-test\nKind=vlan\n\n[VLAN]\nId=43\n' > /run/systemd/network/10-sentinel-iot-test.netdev")
        machine.succeed("${pkgs.python3}/bin/python3 - <<'PY'\nimport json\np='" + journal + "'\nd=json.load(open(p)); del d['owners']['iot-test']; open(p,'w').write(json.dumps(d))\nPY")
        before = link("iot-test")["ifindex"]
        apply("set interface iot-test vlan 42", "set interface iot-test address 198.18.42.1/24")
        assert link("iot-test")["ifindex"] != before and link("iot-test")["linkinfo"]["info_data"]["id"] == 42
        assert link("iot-test")["ifalias"] == owner("iot-test")["alias"]
        assert "guarded-vlan-ok" in machine.wait_until_succeeds(web("198.18.42.1"), timeout=20)

    with subtest("deleting declarations removes VLANs without an unfiltered interval"):
        recorder = "import pathlib,subprocess; log=open('/run/vlan-delete-packets.log','w'); result=subprocess.run(['${pkgs.iproute2}/bin/ip','netns','exec','vlan-client','${pkgs.iputils}/bin/ping','-i','0.01','-w','8','198.18.42.1'],stdout=log,stderr=subprocess.STDOUT); log.close(); pathlib.Path('/run/vlan-delete-packets.exit').write_text(str(result.returncode)); pathlib.Path('/run/vlan-delete-packets.done').touch()"
        machine.succeed("systemd-run --unit=vlan-delete-traffic --property=Restart=no ${pkgs.python3}/bin/python3 -c " + shlex.quote(recorder))
        machine.wait_for_unit("vlan-delete-traffic.service")
        machine.sleep(1)
        apply("delete services dns", "delete interface iot-test", "delete interface inner-test", "delete interface outer-test", "delete interface delayed-test")
        for name in ["iot-test", "inner-test", "outer-test", "delayed-test"]:
            machine.fail("ip link show dev " + name)
        assert json.loads(machine.succeed("cat " + journal))["owners"] == {}
        machine.succeed("ip link show tenant-wire; ip link show alternate")
        machine.wait_until_succeeds("test -e /run/vlan-delete-packets.done", timeout=10)
        packets = machine.succeed("cat /run/vlan-delete-packets.log")
        assert machine.succeed("cat /run/vlan-delete-packets.exit").strip() == "1", packets
        summary = re.search(r"(\d+) packets transmitted, (\d+) received", packets)
        assert summary and int(summary.group(1)) > 20 and int(summary.group(2)) == 0, packets

    with subtest("reboot recreates and protects the saved VLAN before activation"):
        apply("set interface boot-vlan parent eth1", "set interface boot-vlan vlan 60", "set interface boot-vlan zone iot", "set interface boot-vlan address 198.18.60.1/24")
        ownership = owner("boot-vlan")
        protected("boot-vlan")
        machine.reboot()
        machine.wait_for_unit("sentinel-boot-late.service")
        assert owner("boot-vlan") == ownership
        assert "UP" in link("boot-vlan")["flags"]
        protected("boot-vlan")
        machine.wait_until_succeeds("ip addr show boot-vlan | grep 198.18.60.1", timeout=20)
        apply("delete interface boot-vlan")
        machine.fail("ip link show boot-vlan")
  '';
}
