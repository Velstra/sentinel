# Release audit 8b6181, DP-15 (blocklist half), on a live data plane.
#
# A zone's blocklist and GeoIP countries name SOURCES: what may not reach in
# through the zone. The data plane also matched them against the DESTINATION
# of every packet leaving through the zone, so `zone wan blocklist X` (and
# `geoip-block XX`) cut the LAN off from X, and the blocklist outranked
# connection state, so X's answers to a connection the LAN opened were dropped
# as well. Now the compiler marks Sentinel's blocklists source-only
# (`blocklist_ingress_only`) and the data plane lets a listed address answer
# while still refusing everything it starts.
#
# Checked over IPv4 through masquerade (the home/SMB uplink) and over routed
# IPv6, with an unlisted second address on the same upstream host as the
# control that proves the refusal comes from the blocklist and that the data
# plane is loaded and enforcing.
{ pkgs, self }:
let
  # Accept-and-answer TCP listener, both families: a probe only asks whether
  # a connection completes and one byte comes back.
  listener = pkgs.writeText "qa-listen.py" ''
    import socket, sys
    s = socket.socket(socket.AF_INET6)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.bind(("::", int(sys.argv[1])))
    s.listen(64)
    while True:
        c, _ = s.accept()
        try:
            c.sendall(b"x")
        finally:
            c.close()
  '';
  listen = port: "${pkgs.python3}/bin/python3 ${listener} ${toString port}";
  # One byte back over a completed connection, from an explicit source.
  probe = pkgs.writeText "qa-probe.py" ''
    import socket, sys
    family = socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET
    s = socket.socket(family)
    s.settimeout(4)
    if len(sys.argv) > 3:
        s.bind((sys.argv[3], 0))
    s.connect((sys.argv[1], int(sys.argv[2])))
    assert s.recv(1) == b"x"
  '';
  listed4 = "203.0.113.66";
  clear4 = "203.0.113.20";
  listed6 = "2001:db8:1::66";
  clear6 = "2001:db8:1::20";
in
pkgs.testers.runNixOSTest {
  name = "sentinel-blocklist-direction";
  globalTimeout = 900;
  nodes = {
    firewall = { lib, ... }: {
      imports = [ self.nixosModules.sentinel ];
      virtualisation.vlans = [ 1 2 ];
      virtualisation.memorySize = 2048;
      networking.firewall.enable = lib.mkForce false;
      networking.useDHCP = false;
      services.velstra.interface = lib.mkForce "eth1";
      services.velstra.appliance = lib.mkForce (pkgs.writeText "blocklist-direction.toml" ''
        [system]
        hostname = "blocklist-fw"
        [[interface]]
        name = "eth1"
        zone = "wan"
        address = "203.0.113.1/24"
        address6 = "2001:db8:1::1/64"
        [[interface]]
        name = "eth2"
        zone = "lan"
        address = "10.84.1.254/24"
        address6 = "fd00:84::1/64"
        [firewall]
        default_action = "drop"
        stateful = true
        [zone.lan]
        default_action = "accept"
        [zone.wan]
        default_action = "drop"
        blocklist = ["${listed4}", "${listed6}"]
        [[rule]]
        name = "web-in"
        from = "wan"
        proto = "tcp"
        port = 8080
        action = "accept"
        [[nat.source]]
        name = "outbound"
        zone = "wan"
        [[nat.destination]]
        name = "web"
        zone = "wan"
        proto = "tcp"
        port = 8080
        to = "10.84.1.10:8080"
      '');
      environment.systemPackages = [ pkgs.bpftools ];
    };
    upstream = { lib, ... }: {
      # Only the fixture's own addresses: the test framework's automatic
      # 2001:db8:<vlan>::/64 ones would win IPv6 source selection and leave
      # through the firewall from an address nothing routes back to.
      virtualisation.vlans = [ 1 ];
      virtualisation.memorySize = 512;
      networking.firewall.enable = false;
      networking.useDHCP = false;
      networking.interfaces.eth1.ipv4.addresses = lib.mkForce [
        { address = listed4; prefixLength = 24; }
        { address = clear4; prefixLength = 24; }
      ];
      networking.interfaces.eth1.ipv6.addresses = lib.mkForce [
        { address = listed6; prefixLength = 64; }
        { address = clear6; prefixLength = 64; }
      ];
      networking.interfaces.eth1.ipv6.routes = [
        { address = "fd00:84::"; prefixLength = 64; via = "2001:db8:1::1"; }
      ];
      systemd.services.qa-web = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = listen 80;
      };
    };
    lan = { lib, ... }: {
      # Only the fixture's own addresses: the test framework's automatic
      # 2001:db8:<vlan>::/64 ones would win IPv6 source selection and leave
      # through the firewall from an address nothing routes back to.
      virtualisation.vlans = [ 2 ];
      virtualisation.memorySize = 512;
      networking.firewall.enable = false;
      networking.useDHCP = false;
      networking.interfaces.eth1.ipv4.addresses = lib.mkForce [ { address = "10.84.1.10"; prefixLength = 24; } ];
      networking.interfaces.eth1.ipv6.addresses = lib.mkForce [ { address = "fd00:84::10"; prefixLength = 64; } ];
      networking.defaultGateway = { address = "10.84.1.254"; interface = "eth1"; };
      networking.defaultGateway6 = { address = "fd00:84::1"; interface = "eth1"; };
      systemd.services.qa-web = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = listen 8080;
      };
    };
  };
  testScript = ''
    ${import ./uplink-ready.nix { inherit pkgs; }}
    import contextlib

    failures = []

    @contextlib.contextmanager
    def case(title):
        """A subtest whose failure is recorded, so one run shows every case."""
        with subtest(title):
            try:
                yield
            except Exception as error:
                failures.append(f"{title}: {error}")
                print(f"CASE FAILED: {title}: {error}")
    import re

    start_all()
    for node in (firewall, upstream, lan):
        node.wait_for_unit("multi-user.target")
    firewall.wait_for_unit("velstra.service")
    for link in ("eth1", "eth2"):
        firewall.wait_until_succeeds(f"ip -details link show {link} | grep -q xdp", timeout=60)
    upstream.wait_until_succeeds("ss -ltn | grep -q ':80 '", timeout=20)
    lan.wait_until_succeeds("ss -ltn | grep -q ':8080 '", timeout=20)
    for addr in ("${listed6}", "${clear6}"):
        upstream.wait_until_succeeds(f"ip -6 address show dev eth1 | grep -q '{addr}/64 scope global'"
                                     " && ! ip -6 address show dev eth1 | grep -q tentative", timeout=30)
    lan.wait_until_succeeds("! ip -6 address show dev eth1 | grep -q tentative", timeout=30)

    uplink_ready.wait_uplink_addressed(firewall, "eth1", "203.0.113.1")
    def why():
        return ("\ncompiled:\n" + firewall.execute("cat /run/sentinel/velstra.toml")[1]
                + "\nstatistics:\n" + firewall.execute("sentinel show firewall statistics")[1]
                + "\nv6 flows:\n" + firewall.execute(
                    "bpftool -j map dump name FW_FLOWS | ${pkgs.python3}/bin/python3 -c "
                    "'import json,sys; [print(e[\"key\"], e[\"value\"][:24]) for e in json.load(sys.stdin)"
                    " if e[\"key\"][-3] == \"0x06\"]' | head -40")[1]
                + "\nagent:\n" + firewall.execute("journalctl -u velstra --no-pager -n 40")[1])

    def reaches(node, host, port, source=None):
        cmd = f"${pkgs.python3}/bin/python3 ${probe} {host} {port}"
        if source:
            cmd += f" {source}"
        return node.execute(cmd)[0] == 0

    def blocklist_drops():
        text = firewall.succeed("sentinel show firewall statistics")
        m = re.search(r"^\s*dropped_blocklist\s+(\d+)", text, re.M)
        return int(m.group(1)) if m else 0

    with case("control: an unlisted upstream address reaches the forwarded port, both families"):
        upstream.wait_until_succeeds(
            "${pkgs.python3}/bin/python3 ${probe} 203.0.113.1 8080 ${clear4}", timeout=60)
        upstream.wait_until_succeeds(
            "${pkgs.python3}/bin/python3 ${probe} fd00:84::10 8080 ${clear6}", timeout=60)

    with case("a listed address cannot start a connection in, both families"):
        before = blocklist_drops()
        assert not reaches(upstream, "203.0.113.1", 8080, "${listed4}"), "listed v4 source got in" + why()
        assert not reaches(upstream, "fd00:84::10", 8080, "${listed6}"), "listed v6 source got in" + why()
        firewall.wait_until_succeeds(
            f"test $(sentinel show firewall statistics | sed -n 's/^ *dropped_blocklist *//p') -gt {before}",
            timeout=30)

    with case("control: the LAN reaches an unlisted upstream address over IPv6"):
        assert reaches(lan, "${clear6}", 80), "LAN could not reach an unlisted v6 address" + why()

    with case("DP-15: the LAN reaches a listed address and its answers come back"):
        assert reaches(lan, "${listed4}", 80), "LAN could not reach a listed v4 address (masquerade)" + why()
        assert reaches(lan, "${listed6}", 80), "LAN could not reach a listed v6 address (routed)" + why()
        lan.succeed("ping -c 2 -W 2 ${listed4}")
        lan.succeed("ping -6 -c 2 -W 2 ${listed6}")

    with case("answering does not open the door: a listed address still cannot start one"):
        assert not reaches(upstream, "203.0.113.1", 8080, "${listed4}"), "listed v4 source got in" + why()
        assert not reaches(upstream, "fd00:84::10", 8080, "${listed6}"), "listed v6 source got in" + why()

    with case("the compiled blocklist is source-only and the agent loaded it"):
        compiled = firewall.succeed("cat /run/sentinel/velstra.toml")
        assert "blocklist_ingress_only = true" in compiled, compiled
        status, agent_log = firewall.execute("journalctl -u velstra --no-pager | grep -E 'velstra\\[[0-9]+\\]: Error'")
        assert status != 0, "the agent reported an error:\n" + agent_log

    assert not failures, "\n".join(failures)
  '';
}
