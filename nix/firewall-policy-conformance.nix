{ pkgs, self }:
# Firewall-policy differential test (audit 8b6181: DP-09, DP-10, DP-11, DP-21,
# DP-C07, EDGE-02). Same harness and the same netfilter oracle as
# dataplane-conformance, but the DUT's WAN zone is the posture the handbook
# recommends and the audit found broken: deny by default AND block-icmp, with
# NO ICMPv6 rule of any kind (neighbour discovery has to work by itself), an
# IPv4 bogon rule and an IPv4 accept that contain 0.0.0.0, and an MSS clamp.
# The LAN peers send with checksum offload off, so a clamped SYN is not
# CHECKSUM_PARTIAL and a wrong checksum is not repaired behind the datapath's
# back.
let
  inherit (pkgs) lib;
  probe = pkgs.writeShellScriptBin "conformance-probe" ''
    exec ${pkgs.python3}/bin/python3 ${./conformance/probe.py} "$@"
  '';
  kernelPackages = self.nixosConfigurations.appliance.config.boot.kernelPackages;
  endpoint = side: vlan: {
    boot = { inherit kernelPackages; };
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
    environment.systemPackages = [ probe pkgs.iputils pkgs.tcpdump pkgs.ethtool ];
    systemd.services.conformance-peer = {
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      serviceConfig.ExecStart = "${probe}/bin/conformance-probe server " +
        (if side == "lan" then "198.18.20.50 2001:db8:20::50" else "198.18.10.254 2001:db8:10::fe");
    };
  };
  appliance = pkgs.writeText "firewall-policy-appliance.toml" ''
    [system]
    hostname="dut"
    [zone.lan]
    default_action="accept"
    [zone.wan]
    default_action="drop"
    block_icmp=true
    [[interface]]
    name="eth0"
    address="dhcp"
    [[interface]]
    name="eth1"
    address="198.18.10.100/24"
    address6="2001:db8:10::100/64"
    zone="wan"
    mss="1400"
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
    name="reject-udp-test"
    from="wan"
    proto="udp"
    port="18082"
    action="reject"
    [[rule]]
    name="v4-bogon-same-port"
    from="wan"
    source="0.0.0.0/8"
    proto="tcp"
    port="18082"
    action="drop"
    [[rule]]
    name="v4-lower-half"
    from="wan"
    source="0.0.0.0/1"
    proto="tcp"
    port="18083"
    action="accept"
    [[rule]]
    name="wan-icmp-accept-under-block-icmp"
    from="wan"
    proto="icmp"
    action="accept"
    [[rule]]
    name="wan-icmpv6-accept-under-block-icmp"
    from="wan"
    proto="icmpv6"
    action="accept"
    [[nat.source]]
    name="outbound"
    zone="wan"
  '';
in pkgs.testers.runNixOSTest {
  name = "sentinel-firewall-policy-differential";
  globalTimeout = 480;
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
        # The oracle states the intended semantics directly: ND is admitted,
        # RELATED and ESTABLISHED are admitted, a new ping from the WAN is not,
        # and an IPv4 rule says nothing about IPv6.
        nftables = {
          enable = true;
          ruleset = ''
            table inet conformance_filter {
              chain input {
                type filter hook input priority filter; policy drop;
                iifname "lo" accept
                iifname "eth0" accept
                icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, mld-listener-query } accept
                ct state established,related counter accept
                iifname "eth2" counter accept
                iifname "eth1" tcp dport 18082 counter reject with tcp reset
                iifname "eth1" udp dport 18082 counter reject
              }
              chain forward {
                type filter hook forward priority filter; policy drop;
                ct state established,related counter accept
                iifname "eth2" counter accept
                counter drop
              }
            }
            table ip conformance_nat {
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
    sides = ("policy-lan", "policy-wan", "pmtu6")
    start_all()
    dut.wait_for_unit("sentinel-boot.service")
    dut.wait_for_unit("velstra.service")
    reference.wait_for_unit("nftables.service")
    peers = [lan_ref, wan_ref, lan_dut, wan_dut]
    for peer in peers:
        peer.wait_for_unit("conformance-peer.service")
        peer.wait_until_succeeds("ss -ltn | grep -q ':18080'", timeout=30)
        peer.succeed("systemd-run --unit=conformance-capture tcpdump -U -n -i eth1 -w /tmp/conformance.pcap")
    for lan in [lan_ref, lan_dut]:
        # Full software checksums on the sender: nothing downstream may count on
        # CHECKSUM_PARTIAL to repair a checksum the datapath wrote wrong.
        lan.succeed("ethtool -K eth1 tx off")
    for router in [reference, dut]:
        router.wait_until_succeeds("ip -4 addr show eth1 | grep -q 198.18.10.100", timeout=30)
    # The datapath is loaded and this is the posture under test. A dead or
    # default-accept datapath passes most "this works" cases for the wrong
    # reason; the two blocked-ping cases below are the ones it cannot pass.
    for interface in ["eth1", "eth2"]:
        dut.succeed("ip -details link show " + interface + " | grep -q prog/xdp")
    oracle, subject = [], []
    for destination, lan, wan in [(oracle, lan_ref, wan_ref), (subject, lan_dut, wan_dut)]:
        destination.extend(json.loads(lan.succeed("conformance-probe client policy-lan")))
        destination.extend(json.loads(wan.succeed("conformance-probe client policy-wan")))
        # DP-21: hold a tracked UDP flow open on the LAN side, then have the WAN
        # host play the narrower router and answer it with Packet Too Big.
        lan.succeed("rm -f /tmp/pmtu6.json /tmp/pmtu6.ready")
        lan.succeed("systemd-run --unit=pmtu6-client conformance-probe pmtu6-client /tmp/pmtu6.json /tmp/pmtu6.ready")
        lan.wait_for_file("/tmp/pmtu6.ready", timeout=20)
        wan.succeed("conformance-probe ptb6 2001:db8:20::50 18300 2001:db8:10::fe 18081 1280")
        lan.wait_for_file("/tmp/pmtu6.json", timeout=20)
        destination.extend(json.loads(lan.succeed("conformance-probe client pmtu6")))
    for peer in peers:
        peer.succeed("systemctl stop conformance-capture.service")
        peer.copy_from_machine("/tmp/conformance.pcap", "captures/" + peer.name)
    # DP-09: the DUT really clamped the forwarded SYNs, and the far end saw a
    # valid checksum on every one. Asserting that the clamp ran is what keeps
    # the TCP case above from passing because nothing was rewritten.
    syns = wan_dut.succeed(
        "tcpdump -r /tmp/conformance.pcap -nn -vv "
        "'tcp dst port 18080 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'"
    )
    report = {
        "schema": 1, "cases": probe.compare(oracle, subject, sides),
        "dut_kernel": dut.succeed("uname -r").strip(),
        "object_sha256": dut.succeed("sha256sum ${self.packages.x86_64-linux.velstra-ebpf}").split()[0],
        "config_sha256": dut.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0],
        "dut_neighbours": dut.succeed("ip -6 neigh show dev eth1"),
        "dut_velstra_log": dut.succeed("journalctl -u velstra.service --no-pager | tail -n 40"),
        "clamped_syns_at_wan_peer": syns,
    }
    Path(os.environ["out"], "firewall-policy.json").write_text(json.dumps(report, indent=2))
    print("FIREWALL_POLICY_RECEIPT=" + json.dumps(report))
    invalid = [r["case"] for r in report["cases"] if not r["oracle_valid"]]
    failed = [r["case"] for r in report["cases"] if not r["passed"]]
    assert not invalid, "Oracle/setup failure (not a Sentinel pass): " + repr(invalid)
    assert "mss 1400" in syns, "the DUT did not clamp the forwarded SYN: " + syns
    assert "incorrect" not in syns, "a clamped SYN left with a bad TCP checksum: " + syns
    assert not failed, "Firewall policy bugs: " + repr(failed)
  '';
}
