{ pkgs, self }:
let
  inherit (pkgs) lib;
  probe = pkgs.writeShellScriptBin "conformance-probe" ''
    exec ${pkgs.python3}/bin/python3 ${./conformance/probe.py} "$@"
  '';
  kernelPackages = self.nixosConfigurations.appliance.config.boot.kernelPackages;
  endpoint = side: vlan: {
    boot = { inherit kernelPackages; };
    # No harness-generated secondary addresses: RFC 6724 source selection must
    # choose the identical test addresses on both otherwise-isolated paths.
    virtualisation = { interfaces.eth1 = { inherit vlan; }; memorySize = 512; };
    networking = {
      useNetworkd = true;
      useDHCP = false;
      firewall.enable = false;
      interfaces.eth1 = {
        ipv4.addresses = [{ address = if side == "lan" then "198.18.20.50" else "198.18.10.254"; prefixLength = 24; }];
        ipv6.addresses = [{ address = if side == "lan" then "2001:db8:20::50" else "2001:db8:10::fe"; prefixLength = 64; }];
      };
      defaultGateway = { interface = "eth1"; address = if side == "lan" then "198.18.20.1" else "198.18.10.100"; };
      defaultGateway6 = { interface = "eth1"; address = if side == "lan" then "2001:db8:20::1" else "2001:db8:10::100"; };
    };
    environment.systemPackages = [ probe pkgs.iputils pkgs.tcpdump ];
    systemd.services.conformance-peer = {
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      serviceConfig.ExecStart = "${probe}/bin/conformance-probe server " +
        (if side == "lan" then "198.18.20.50 2001:db8:20::50" else "198.18.10.254 2001:db8:10::fe");
    };
  };
  appliance = pkgs.writeText "conformance-appliance.toml" ''
    [system]
    hostname="dut"
    [zone.lan]
    default_action="accept"
    [zone.wan]
    default_action="drop"
    [[interface]]
    name="eth0"
    address="dhcp"
    [[interface]]
    name="eth1"
    address="198.18.10.100/24"
    address6="2001:db8:10::100/64"
    zone="wan"
    [[interface]]
    name="eth2"
    address="198.18.20.1/24"
    address6="2001:db8:20::1/64"
    zone="lan"
    [[rule]]
    name="reject-test"
    from="wan"
    proto="tcp"
    port="18082"
    action="reject"
    [[rule]]
    name="wan-neighbour-solicitation"
    from="wan"
    proto="icmpv6"
    icmp-type="135"
    action="accept"
    [[rule]]
    name="wan-neighbour-advertisement"
    from="wan"
    proto="icmpv6"
    icmp-type="136"
    action="accept"
    [[nat.source]]
    name="outbound"
    zone="wan"
    [[nat.destination]]
    name="tcp"
    zone="wan"
    proto="tcp"
    port=18080
    to="198.18.20.50:18080"
    [[nat.destination]]
    name="udp"
    zone="wan"
    proto="udp"
    port=18081
    to="198.18.20.50:18081"
  '';
in pkgs.testers.runNixOSTest {
  name = "sentinel-netfilter-differential";
  globalTimeout = 420;
  nodes = {
    lan_dut = endpoint "lan" 2;
    wan_dut = endpoint "wan" 1;
    lan_ref = endpoint "lan" 4;
    wan_ref = endpoint "wan" 3;
    dut = {
      imports = [ self.nixosModules.sentinel ];
      networking.hostName = lib.mkForce "dut";
      networking.firewall.enable = lib.mkForce false;
      boot = { inherit kernelPackages; };
      virtualisation = {
        interfaces = { eth1.vlan = 1; eth2.vlan = 2; };
        memorySize = 2048; cores = 4;
      };
      services.velstra = {
        interface = lib.mkForce "eth1";
        appliance = lib.mkForce appliance;
      };
      environment.systemPackages = [ pkgs.tcpdump pkgs.bpftools ];
    };
    reference = {
      boot = { inherit kernelPackages; };
      boot.kernel.sysctl = {
        "net.ipv4.ip_forward" = 1;
        "net.ipv6.conf.all.forwarding" = 1;
        "net.ipv4.conf.all.accept_local" = 0;
      };
      virtualisation = {
        interfaces = { eth1.vlan = 3; eth2.vlan = 4; };
        memorySize = 768; cores = 4;
      };
      networking = {
        useNetworkd = true;
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1 = {
          ipv4.addresses = [{ address = "198.18.10.100"; prefixLength = 24; }];
          ipv6.addresses = [{ address = "2001:db8:10::100"; prefixLength = 64; }];
        };
        interfaces.eth2 = {
          ipv4.addresses = [{ address = "198.18.20.1"; prefixLength = 24; }];
          ipv6.addresses = [{ address = "2001:db8:20::1"; prefixLength = 64; }];
        };
        nftables = {
          enable = true;
          ruleset = ''
            table inet conformance_filter {
              chain input {
                type filter hook input priority filter; policy drop;
                iifname "lo" accept
                iifname "eth0" accept
                icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept
                ct state established,related counter accept
                iifname "eth2" counter accept
                iifname "eth1" tcp dport 18082 counter reject with tcp reset
              }
              chain forward {
                type filter hook forward priority filter; policy drop;
                ct state established,related counter accept
                iifname "eth2" counter accept
                ct status dnat counter accept
                counter drop
              }
            }
            table ip conformance_nat {
              chain prerouting {
                type nat hook prerouting priority dstnat; policy accept;
                iifname "eth1" ip daddr 198.18.10.100 tcp dport 18080 counter dnat to 198.18.20.50:18080
                iifname "eth1" ip daddr 198.18.10.100 udp dport 18081 counter dnat to 198.18.20.50:18081
              }
              chain postrouting {
                type nat hook postrouting priority srcnat; policy accept;
                oifname "eth1" ip saddr 198.18.20.0/24 counter masquerade
              }
            }
          '';
        };
      };
      environment.systemPackages = [ pkgs.nftables pkgs.tcpdump ];
    };
  };
  testScript = ''
    import importlib.util, json, os
    from pathlib import Path
    spec = importlib.util.spec_from_file_location("probe", "${./conformance/probe.py}")
    assert spec is not None and spec.loader is not None
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    start_all()
    dut.wait_for_unit("sentinel-boot.service")
    dut.wait_for_unit("velstra.service")
    reference.wait_for_unit("nftables.service")
    peers = [lan_ref, wan_ref, lan_dut, wan_dut]
    for peer in peers:
        peer.wait_for_unit("conformance-peer.service")
        peer.wait_until_succeeds("ss -ltn | grep -q ':18080'", timeout=30)
        peer.succeed("systemd-run --unit=conformance-capture tcpdump -U -n -i eth1 -w /tmp/conformance.pcap")
    for router in [reference, dut]:
        router.wait_until_succeeds("ip -4 addr show eth1 | grep -q 198.18.10.100", timeout=30)
        assert router.succeed("cat /proc/sys/net/ipv4/conf/all/accept_local").strip() == "0"
    for interface in ["eth1", "eth2"]:
        dut.succeed("ip -details link show " + interface + " | grep -q prog/xdp")
    oracle, subject = [], []
    for destination, lan, wan in [(oracle, lan_ref, wan_ref), (subject, lan_dut, wan_dut)]:
        destination.extend(json.loads(lan.succeed("conformance-probe client lan")))
        destination.extend(json.loads(wan.succeed("conformance-probe client wan")))
    # Same MTU fault, after ordinary traffic, on both independently routed paths.
    for router in [reference, dut]:
        router.succeed("ip link set dev eth1 mtu 1280")
    oracle.extend(json.loads(lan_ref.succeed("conformance-probe client pmtu")))
    subject.extend(json.loads(lan_dut.succeed("conformance-probe client pmtu")))
    report = {
        "schema": 1, "cases": probe.compare(oracle, subject),
        "dut_kernel": dut.succeed("uname -r").strip(),
        "oracle_kernel": reference.succeed("uname -r").strip(),
        "object_sha256": dut.succeed("sha256sum ${self.packages.x86_64-linux.velstra-ebpf}").split()[0],
        "config_sha256": dut.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0],
        "nft_version": reference.succeed("nft --version").strip(),
        "oracle_ruleset": json.loads(reference.succeed("nft --json list ruleset")),
        "dut_programs": json.loads(dut.succeed("bpftool -j prog show")),
        "topology": {peer.name: {
            "addresses": json.loads(peer.succeed("ip -j address show")),
            "ipv4_routes": json.loads(peer.succeed("ip -j -4 route show table all")),
            "ipv6_routes": json.loads(peer.succeed("ip -j -6 route show table all")),
        } for peer in [reference, dut] + peers},
    }
    Path(os.environ["out"], "conformance.json").write_text(json.dumps(report, indent=2))
    for peer in peers:
        peer.succeed("systemctl stop conformance-capture.service")
        # Also retain on failure in the driver's VM output directory.
        peer.copy_from_machine("/tmp/conformance.pcap", "captures/" + peer.name)
    print("CONFORMANCE_RECEIPT=" + json.dumps(report))
    invalid = [r["case"] for r in report["cases"] if not r["oracle_valid"]]
    failed = [r["case"] for r in report["cases"] if not r["passed"]]
    assert not invalid, "Oracle/setup failure (not a Sentinel pass): " + repr(invalid)
    assert not failed, "Dataplane conformance bugs: " + repr(failed)
  '';
}
