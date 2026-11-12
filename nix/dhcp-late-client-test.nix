# Start the real DHCP authority only after the WAN XDP policy is attached.
# Fast pre-firewall leases must not hide a bootstrap/recovery lockout.
{ pkgs, self, stateful ? true }:
pkgs.testers.runNixOSTest {
  name = "sentinel-late-dhcp-client-default-drop-${if stateful then "stateful" else "stateless"}";
  globalTimeout = 600;
  nodes = {
    firewall = { lib, ... }: {
      imports = [ self.nixosModules.sentinel ];
      virtualisation.vlans = [ 1 ];
      virtualisation.memorySize = 2048;
      networking.firewall.enable = lib.mkForce false;
      networking.useDHCP = false;
      services.velstra.interface = lib.mkForce "eth1";
      services.velstra.appliance = lib.mkForce (pkgs.writeText "late-dhcp-client.toml" ''
        [system]
        hostname = "late-dhcp-fw"
        [[interface]]
        name = "eth1"
        zone = "wan"
        address = "dhcp"
        [firewall]
        stateful = ${if stateful then "true" else "false"}
        default_action = "drop"
        [[rule]]
        name = "installer-ssh"
        from = "wan"
        proto = "tcp"
        port = 22
        action = "accept"
      '');
      environment.systemPackages = [ pkgs.tcpdump pkgs.bpftools ];
    };
    authority = {
      virtualisation.vlans = [ 1 ];
      virtualisation.memorySize = 512;
      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4.addresses = [ { address = "198.18.88.1"; prefixLength = 24; } ];
      environment.systemPackages = [ pkgs.tcpdump ];
      # Test reference only, deliberately NOT started during normal boot.
      systemd.services.qa-late-dhcp = {
        serviceConfig = {
          Type = "simple";
          ExecStart = "${pkgs.dnsmasq}/bin/dnsmasq --no-daemon --user=root --port=0 --interface=eth1 --bind-dynamic --dhcp-range=198.18.88.100,198.18.88.100,255.255.255.0,120s --dhcp-authoritative --dhcp-leasefile=/run/qa-late-dhcp.leases --log-dhcp --log-facility=-";
        };
      };
    };
  };
  testScript = ''
    import json, os, shlex
    from pathlib import Path

    start_all()
    for node in (firewall, authority):
        node.wait_for_unit("multi-user.target")
    firewall.wait_for_unit("sentinel-boot.service")
    firewall.wait_for_unit("velstra.service")
    firewall.wait_until_succeeds("ip -details link show eth1 | grep -q xdp", timeout=30)
    firewall.succeed("test -z \"$(ip -o -4 address show dev eth1)\"")
    authority.fail("systemctl is-active --quiet qa-late-dhcp.service")
    authority.succeed("systemd-run --unit=qa-dhcp-packets ${pkgs.tcpdump}/bin/tcpdump -p -U -s 0 -w /tmp/dhcp.pcap -i eth1 'ip proto 17'")
    authority.wait_until_succeeds("journalctl -u qa-dhcp-packets --no-pager | grep -q 'listening on eth1'", timeout=5)
    before = firewall.succeed("sentinel show firewall statistics")
    authority.succeed("systemctl start qa-late-dhcp.service")
    try:
        firewall.wait_until_succeeds("ip -o -4 address show dev eth1 | grep -q '198.18.88.100/'", timeout=75)
        address = firewall.succeed("ip -o -4 address show dev eth1")
        lease = authority.succeed("cat /run/qa-late-dhcp.leases")
        assert "198.18.88.100" in lease, lease
        # Wait for normal address reconciliation, never insert a DUT map entry.
        firewall.sleep(3)
        mac = firewall.succeed("cat /sys/class/net/eth1/address").strip()
        index = int(firewall.succeed("cat /sys/class/net/eth1/ifindex").strip())
        client_lease = "/run/systemd/netif/leases/" + str(index)
        lease_written = int(firewall.succeed("stat -c %Y " + client_lease).strip())
        firewall.succeed("systemd-run --unit=qa-dhcp-local ${pkgs.tcpdump}/bin/tcpdump -p -U -s 0 -w /tmp/local-dhcp.pcap -i eth1 'ip proto 17'")
        firewall.wait_until_succeeds("journalctl -u qa-dhcp-local --no-pager | grep -q 'listening on eth1'", timeout=5)
        cases = ["broadcast", "unicast", "foreign-destination", "foreign-client", "wrong-cookie",
                 "request-not-reply", "wrong-hardware", "wrong-hardware-length", "wrong-source-port",
                 "wrong-destination-port", "fragment", "later-fragment", "invalid-source",
                 "short-bootp", "bad-udp-length", "short-ip-length", "truncated-ip",
                 "ipv4-options", "reserved-fragment-bit"]
        for index, case in enumerate(cases):
            authority.succeed("${pkgs.python3}/bin/python3 ${./dhcp-client-probe.py} eth1 " + mac + " " + case + " " + hex(0x51a00000 + index))
        firewall.sleep(1)
        firewall.succeed("systemctl stop qa-dhcp-local")
        authority.succeed("systemctl kill --signal=SIGUSR2 qa-dhcp-packets")
        observations = []
        for index, case in enumerate(cases):
            # Match the independent BOOTP transaction marker in the received
            # capture; rejected packets must never reach even AF_PACKET.
            xid = 0x51a00000 + index
            # Raw IP offsets deliberately avoid libpcap's implicit first-
            # fragment guard for `udp[...]`, which could hide a leaked later
            # fragment and falsely report an XDP rejection.
            offset = 36 if case == "ipv4-options" else 32
            marker = "ip[4:2] = " + hex(xid & 65535) + " and ip[" + str(offset) + ":4] = " + hex(xid)
            received = int(firewall.succeed("${pkgs.tcpdump}/bin/tcpdump -nn -r /tmp/local-dhcp.pcap '" + marker + "' 2>/dev/null | wc -l").strip())
            emitted = int(authority.succeed("${pkgs.tcpdump}/bin/tcpdump -nn -r /tmp/dhcp.pcap '" + marker + "' 2>/dev/null | wc -l").strip())
            assert emitted == 3, {"case": case, "independent_reference_wire_count": emitted}
            expected = case in ("broadcast", "unicast")
            observations.append({"case": case, "reference_wire": emitted, "received": received, "expected_local_admission": expected})
            assert (received == 3 if expected else received == 0), observations
        # Genuine renewal, not the synthetic unknown-xid probes: observe a
        # second real authority ACK and retention of the actual lease.
        authority.wait_until_succeeds("test $(journalctl -u qa-late-dhcp --no-pager | grep -c 'DHCPACK(eth1) 198.18.88.100') -ge 2", timeout=90)
        # networkd dirties/saves the accepted lease on renewal. A server ACK
        # alone, while the old lease is still valid, would not prove delivery.
        firewall.wait_until_succeeds("test $(stat -c %Y " + client_lease + ") -gt " + str(lease_written), timeout=10)
        firewall.succeed("ip -o -4 address show dev eth1 | grep -q '198.18.88.100/'")
        def configure(commands):
            # Exercise the installed CLI and normal live reconciliation, never
            # write runtime files/maps or restart networkd as a test repair.
            # Each invocation starts a fresh edit session from SAVED config.
            # A live-only commit intentionally does not persist across sessions.
            text = "\n".join(commands + ["commit", "save", "exit"]) + "\n"
            output = firewall.succeed("printf %s " + shlex.quote(text) + " | sentinel configure")
            assert "error:" not in output.lower() and "unknown" not in output.lower(), output

        policy_observations = []
        def local_probe(label, expected):
            unit = "qa-dhcp-policy-" + str(len(policy_observations))
            path = "/tmp/" + unit + ".pcap"
            xid = hex(0x51b00000 + len(policy_observations))
            firewall.succeed("systemd-run --unit=" + unit + " ${pkgs.tcpdump}/bin/tcpdump -p -U -s 0 -w " + path + " -i eth1 'ip proto 17'")
            firewall.wait_until_succeeds("journalctl -u " + unit + " --no-pager | grep -q 'listening on eth1'", timeout=5)
            authority.succeed("${pkgs.python3}/bin/python3 ${./dhcp-client-probe.py} eth1 " + mac + " broadcast " + xid)
            firewall.sleep(1)
            firewall.succeed("systemctl stop " + unit)
            received = int(firewall.succeed("${pkgs.tcpdump}/bin/tcpdump -nn -r " + path + " 'udp[12:4] = " + xid + "' 2>/dev/null | wc -l").strip())
            policy_observations.append({"case": label, "received": received, "expected_admission": expected})
            assert (received == 3 if expected else received == 0), policy_observations

        configure(["set firewall rule qa-no-dhcp from wan", "set firewall rule qa-no-dhcp proto udp",
                   "set firewall rule qa-no-dhcp port 68", "set firewall rule qa-no-dhcp action drop"])
        local_probe("explicit-drop-wins", False)
        configure(["delete firewall rule qa-no-dhcp", "set firewall global block 198.18.88.1/32"])
        local_probe("blocklist-wins", False)
        configure(["delete firewall global block 198.18.88.1/32"])
        local_probe("policy-removal-recovers", True)
        configure(["set interface eth1 address 198.18.88.100/24"])
        local_probe("static-interface-has-no-DHCP-exemption", False)
        configure(["set interface eth1 address dhcp"])
        firewall.wait_until_succeeds("ip -o -4 address show dev eth1 | grep -q '198.18.88.100/'", timeout=75)
        local_probe("declared-client-reenabled", True)
        Path(os.environ["out"], "late-dhcp-client.json").write_text(json.dumps({
            "server_started_after_real_XDP_attachment": True,
            "default_drop_and_only_SSH_rule": True,
            "actual_DHCP_address": address,
            "actual_authoritative_lease": lease,
            "stateful": ${if stateful then "True" else "False"},
            "adversarial_local_capture": observations,
            "genuine_renewal_ACK_observed": True,
            "client_lease_rewritten_after_genuine_renewal": True,
            "real_CLI_policy_priority_and_client_removal": policy_observations,
            "DUT_restart_manual_address_or_policy_repair": False
        }, indent=2))
    finally:
        authority.succeed("systemctl stop qa-dhcp-packets")
        print("Counters before DHCP server start:\n" + before)
        print(firewall.succeed("ip -br address; networkctl status eth1 --no-pager; sentinel show firewall statistics; journalctl -u systemd-networkd --no-pager -n 25"))
        print(authority.succeed("journalctl -u qa-late-dhcp --no-pager -n 30; ${pkgs.tcpdump}/bin/tcpdump -nn -vvv -r /tmp/dhcp.pcap 2>/dev/null"))
  '';
}
