{ pkgs, self }:
pkgs.testers.runNixOSTest {
  name = "sentinel-quickstart";
  nodes = {
    fw = { lib, ... }: {
      imports = [ self.nixosModules.sentinel ];
      networking.hostName = lib.mkForce "fw";
      networking.firewall.enable = lib.mkForce false;
      virtualisation.vlans = [ 1 2 ];
      virtualisation.memorySize = 2048;
      services.velstra.interface = lib.mkForce "eth1";
      environment.systemPackages = [ pkgs.curl pkgs.python3 pkgs.bpftools pkgs.netcat-openbsd ];
    };
    wan = {
      virtualisation.vlans = [ 1 ];
      networking.firewall.enable = false;
      networking.useNetworkd = true;
      networking.useDHCP = false;
      systemd.network.networks."10-uplink" = {
        matchConfig.Name = "eth1";
        address = [ "10.60.0.1/24" ];
        networkConfig.DHCPServer = true;
        dhcpServerConfig = { PoolOffset = 10; PoolSize = 40; EmitDNS = false; };
      };
      systemd.services.quickstart-http = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -m http.server 8088 --bind 0.0.0.0";
      };
      environment.systemPackages = [ pkgs.curl pkgs.netcat-openbsd pkgs.tcpdump ];
    };
    lan = {
      virtualisation.vlans = [ 2 ];
      networking.firewall.enable = false;
      networking.useNetworkd = true;
      networking.useDHCP = false;
      systemd.network.networks."10-lan" = { matchConfig.Name = "eth1"; networkConfig.DHCP = "ipv4"; };
      environment.systemPackages = [ pkgs.curl ];
    };
  };
  testScript = ''
    import json, shlex
    start_all()
    for node in (fw, wan, lan):
        node.wait_for_unit("multi-user.target")
    fw.wait_for_unit("velstra.service")
    # The driver's eth0 is its private backdoor. Apply the identical documented
    # WAN/LAN batch with the two corresponding real data-link names.
    script = open("${../examples/quickstart.cli}").read()
    script = script.replace("eth1", "QUICKSTART_LAN").replace("eth0", "eth1").replace("QUICKSTART_LAN", "eth2")
    script = "set system group operators permission read-write\nset system login operator group operators\n" + script
    output = fw.succeed("printf %s " + shlex.quote(script) + " | sentinel configure 2>&1")
    assert "error:" not in output.lower(), output
    fw.succeed("sentinel config check /var/lib/sentinel/appliance.toml")
    fw.wait_until_succeeds("ip -4 addr show eth1 | grep -q '10.60.0.'", timeout=45)
    lan.wait_until_succeeds("ip -4 addr show eth1 | grep -q '192.168.50.'", timeout=45)
    fw.wait_for_unit("sentinel-api.service")
    with subtest("the shipped sample forwards and masquerades real packets"):
        wan.wait_for_open_port(8088)
        # DHCP and the two-second map watcher converge asynchronously.
        lan.wait_until_succeeds("curl -fsS --max-time 3 http://10.60.0.1:8088/ >/dev/null", timeout=15)
        wan.succeed("journalctl -u quickstart-http --no-pager | grep -E '10.60.0.[0-9]+ - -' | grep -q GET")
        # The default WAN zone rejects direct access to management. Probed on
        # SSH, which the sample leaves listening on every address: the console
        # binds the LAN address only, so a refused connection to it from the
        # WAN would prove nothing about the firewall. First prove the WAN
        # address really answers on 22 (a local connection never crosses the
        # data plane), so that the WAN side's failure can only be the drop.
        address = fw.succeed("ip -4 -o addr show eth1 | awk '{print $4}' | cut -d/ -f1").strip()
        fw.wait_until_succeeds("nc -z -w 2 " + address + " 22", timeout=30)
        wan.fail("nc -z -w 3 " + address + " 22")
        wan.fail("nc -z -w 2 " + address + " 8443")
    with subtest("a live WAN address change refreshes NAT without applying configuration"):
        pid = fw.succeed("systemctl show -p MainPID --value velstra.service").strip()
        revision = fw.succeed("sha256sum /var/lib/sentinel/appliance.toml").strip()
        # Withdraw the real DHCP lease, then let the upstream DHCP server
        # offer a different address. No Sentinel commit or agent restart occurs.
        fw.succeed("networkctl down eth1")
        # The uplink keeps its entry, unaddressed (0.0.0.0), rather than losing
        # it: without one, traffic leaving it would not be masqueraded at all.
        unaddressed = "bpftool -j map dump name MASQUERADE | python3 -c 'import json,sys; e=json.load(sys.stdin); assert len(e) == 1 and [int(b, 0) if isinstance(b, str) else b for b in e[0][\"value\"]] == [0, 0, 0, 0], e'"
        fw.wait_until_succeeds(unaddressed, timeout=10)
        wan.succeed("mkdir -p /run/systemd/network; cp /etc/systemd/network/10-uplink.network /run/systemd/network/05-uplink.network")
        wan.succeed("sed -i -e 's/PoolOffset=10/PoolOffset=60/' -e 's/PoolSize=40/PoolSize=1/' /run/systemd/network/05-uplink.network")
        wan.succeed("networkctl reload; networkctl reconfigure eth1")
        fw.succeed("networkctl up eth1")
        fw.wait_until_succeeds("ip -4 addr show eth1 | grep -q '10.60.0.60/'", timeout=45)
        lan.wait_until_succeeds("curl -fsS --max-time 3 http://10.60.0.1:8088/ >/dev/null", timeout=15)
        wan.succeed("journalctl -u quickstart-http --no-pager | grep '10.60.0.60 - -' | grep -q GET")
        assert fw.succeed("systemctl show -p MainPID --value velstra.service").strip() == pid
        assert fw.succeed("sha256sum /var/lib/sentinel/appliance.toml").strip() == revision
    with subtest("a WAN without an address carries no LAN source out"):
        # The lease is gone but the link is up and a route out of it survives:
        # exactly when traffic used to leave un-translated, from a private
        # source, because the masquerade entry had been deleted with the lease.
        wan.succeed("systemctl stop systemd-networkd.service systemd-networkd.socket")
        fw.succeed("networkctl down eth1")
        fw.wait_until_succeeds(unaddressed, timeout=10)
        fw.succeed("ip link set eth1 up")
        fw.succeed("ip -4 addr flush dev eth1 scope global")
        fw.succeed("ip route replace 10.60.0.0/24 dev eth1")
        fw.wait_until_succeeds(unaddressed, timeout=10)
        wan.succeed("tcpdump -n -i eth1 -w /tmp/leak.pcap 'ip src net 192.168.50.0/24' >/dev/null 2>&1 & echo $! > /tmp/leak.pid")
        wan.sleep(1)
        lan.fail("curl -fsS --max-time 3 http://10.60.0.1:8088/ >/dev/null")
        wan.succeed("kill -INT $(cat /tmp/leak.pid); sleep 1")
        leaked = wan.succeed("tcpdump -n -r /tmp/leak.pcap 2>/dev/null | wc -l").strip()
        assert leaked == "0", f"{leaked} LAN-sourced packets left an unaddressed WAN"
        # …while the box's own address request still leaves, from 0.0.0.0.
        wan.succeed("systemctl start systemd-networkd.service")
        fw.succeed("ip route del 10.60.0.0/24 dev eth1 || true")
        fw.succeed("networkctl reconfigure eth1")
        fw.wait_until_succeeds("ip -4 addr show eth1 | grep -q '10.60.0.'", timeout=45)
        lan.wait_until_succeeds("curl -fsS --max-time 3 http://10.60.0.1:8088/ >/dev/null", timeout=15)
    with subtest("the embedded HTTPS UI and generated desired document are ready"):
        lan.succeed("curl -kfsS --max-time 5 https://192.168.50.1:8443/ -o /tmp/quickstart-console.html")
        lan.succeed("grep -q 'Fleet enrollment' /tmp/quickstart-console.html")
        document = json.loads(fw.succeed("sentinel config convert /var/lib/sentinel/appliance.toml --to json"))
        assert any(login["username"] == "operator" for login in document["system"]["login"]), document["system"]
        assert document["services"]["web"]["tls"] is True
        assert document["nat"]["source"][0]["zone"] == "wan"
        fw.succeed("sentinel show nat")
    with subtest("saved sample state survives a reboot"):
        fw.shutdown()
        fw.start()
        fw.wait_for_unit("multi-user.target")
        fw.wait_for_unit("sentinel-api.service")
        lan.wait_until_succeeds("curl -kfsS --max-time 5 https://192.168.50.1:8443/api/v1/health")
        lan.wait_until_succeeds("curl -fsS --max-time 3 http://10.60.0.1:8088/ >/dev/null", timeout=15)
  '';
}
