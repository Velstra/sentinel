# Release audit 8b6181, DP-16 / HA-01 / PROV-03 and DP-15, on a live data plane.
#
# DP-16: `to firewall` was compiled from the configuration's STATIC addresses,
# so a DHCP management port was locked out by its own management rules (the
# static LAN address was the only "local" one), and an all-DHCP box widened
# the rule to every destination. Now the rule says `dst-local = true` and the
# agent resolves it from the addresses the box holds — checked here against a
# real DHCP lease, a secondary address added at run time (the VRRP case), and
# a routed host behind the box that must stay unreachable.
#
# DP-15: a direction-less `from mgmt proto tcp port 25 drop` was also applied
# at TC egress under the zone a packet LEAVES through, so it blocked LAN hosts
# sending SMTP out through mgmt. It must keep port 25 out and let it leave.
{ pkgs, self }:
let
  # Accept-and-close TCP listener: the probes only ask whether a SYN gets an
  # answer, so a connection is the whole protocol.
  listener = pkgs.writeText "qa-listen.py" ''
    import socket, sys
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", int(sys.argv[1])))
    s.listen(64)
    while True:
        c, _ = s.accept()
        c.close()
  '';
  listen = port: "${pkgs.python3}/bin/python3 ${listener} ${toString port}";
in
pkgs.testers.runNixOSTest {
  name = "sentinel-local-destination";
  globalTimeout = 900;
  nodes = {
    firewall = { lib, ... }: {
      imports = [ self.nixosModules.sentinel ];
      virtualisation.vlans = [ 1 2 ];
      virtualisation.memorySize = 2048;
      networking.firewall.enable = lib.mkForce false;
      networking.useDHCP = false;
      services.velstra.interface = lib.mkForce "eth1";
      services.velstra.appliance = lib.mkForce (pkgs.writeText "local-destination.toml" ''
        [system]
        hostname = "local-dst-fw"
        [[interface]]
        name = "eth1"
        zone = "mgmt"
        address = "dhcp"
        [[interface]]
        name = "eth2"
        zone = "lan"
        address = "10.84.1.254/24"
        [firewall]
        default_action = "drop"
        stateful = true
        [zone.firewall]
        local = true
        [zone.lan]
        default_action = "accept"
        [[rule]]
        name = "mgmt-ssh"
        from = "mgmt"
        to = "firewall"
        proto = "tcp"
        port = 2222
        action = "accept"
        [[rule]]
        name = "mgmt-ping"
        from = "mgmt"
        to = "firewall"
        proto = "icmp"
        icmp-type = "echo-request"
        action = "accept"
        [[rule]]
        name = "no-smtp-in"
        from = "mgmt"
        proto = "tcp"
        port = 25
        action = "drop"
      '');
      environment.systemPackages = [ pkgs.netcat-openbsd pkgs.bpftools ];
    };
    mgmt = {
      virtualisation.vlans = [ 1 ];
      virtualisation.memorySize = 512;
      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4.addresses = [ { address = "10.81.0.10"; prefixLength = 24; } ];
      environment.systemPackages = [ pkgs.netcat-openbsd ];
      systemd.services.qa-dhcp = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        serviceConfig.ExecStart = "${pkgs.dnsmasq}/bin/dnsmasq --no-daemon --user=root --port=0 --interface=eth1 --bind-dynamic --dhcp-range=10.81.0.100,10.81.0.100,255.255.255.0,600s --dhcp-authoritative --dhcp-leasefile=/run/qa-dhcp.leases --log-dhcp --log-facility=-";
      };
      systemd.services.qa-smtp = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = listen 25;
      };
    };
    lan = {
      virtualisation.vlans = [ 2 ];
      virtualisation.memorySize = 512;
      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4.addresses = [ { address = "10.84.1.10"; prefixLength = 24; } ];
      networking.defaultGateway = { address = "10.84.1.254"; interface = "eth1"; };
      environment.systemPackages = [ pkgs.netcat-openbsd ];
      systemd.services.qa-smtp = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = listen 25;
      };
      systemd.services.qa-admin = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = listen 2222;
      };
    };
  };
  testScript = ''
    start_all()
    for node in (firewall, mgmt, lan):
        node.wait_for_unit("multi-user.target")
    firewall.wait_for_unit("velstra.service")
    for link in ("eth1", "eth2"):
        firewall.wait_until_succeeds(f"ip -details link show {link} | grep -q xdp", timeout=60)
    firewall.wait_until_succeeds("ip -o -4 address show dev eth1 | grep -q '10.81.0.100/'", timeout=90)
    lease = "10.81.0.100"
    mgmt.succeed(f"ip route replace 10.84.1.0/24 via {lease}")
    for port in (2222, 2223):
        firewall.succeed(f"systemd-run --unit=qa-listen-{port} ${pkgs.python3}/bin/python3 ${listener} {port}")
        firewall.wait_until_succeeds(f"ss -ltn | grep -q ':{port} '", timeout=10)
    lan.wait_until_succeeds("ss -ltn | grep -q ':2222 '", timeout=10)

    compiled = firewall.succeed("cat /run/sentinel/velstra.toml")
    # The member-independent form: no address of this box is in the policy.
    assert "dst-local = true" in compiled, compiled
    assert lease not in compiled and "10.84.1.254/32" not in compiled, compiled

    def why():
        return ("\ncompiled:\n" + firewall.execute("cat /run/sentinel/velstra.toml")[1]
                + "\nstatistics:\n" + firewall.execute("sentinel show firewall statistics")[1]
                + "\nDST_RULES:\n" + firewall.execute("bpftool map dump name DST_RULES")[1]
                + "\naddresses:\n" + firewall.execute("ip -br address")[1]
                + "\nagent:\n" + firewall.execute("journalctl -u velstra --no-pager -n 40")[1])

    def reaches(node, host, port):
        return node.execute(f"nc -z -w 3 {host} {port}")[0] == 0

    with subtest("DP-16: the DHCP management address is local to `to firewall` rules"):
        mgmt.wait_until_succeeds(f"nc -z -w 3 {lease} 2222", timeout=30)
        mgmt.succeed(f"ping -c 2 -W 2 {lease}")
        # …the datapath is enforcing: a port no rule opens stays closed.
        assert not reaches(mgmt, lease, 2223), "default-drop mgmt admitted an unopened port" + why()

    with subtest("DP-16: a local rule never widens to a routed host behind the box"):
        lan.succeed("ping -c 1 -W 2 10.81.0.10")  # the route exists both ways
        assert not reaches(mgmt, "10.84.1.10", 2222), "`to firewall` admitted a LAN host" + why()

    with subtest("DP-16: an address added at run time becomes local (the VRRP case)"):
        assert not reaches(mgmt, "10.81.0.200", 2222)
        firewall.succeed("ip address add 10.81.0.200/24 dev eth1")
        mgmt.wait_until_succeeds("nc -z -w 2 10.81.0.200 2222", timeout=30)
        assert not reaches(mgmt, "10.81.0.200", 2223), why()

    with subtest("DP-15: a direction-less drop keeps SMTP out and lets it leave"):
        assert reaches(lan, "10.81.0.10", 25), "LAN SMTP leaving through mgmt was dropped" + why()
        assert not reaches(mgmt, "10.84.1.10", 25), "inbound SMTP from mgmt was admitted" + why()
  '';
}
