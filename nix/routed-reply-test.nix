{
  pkgs,
  self,
  withTupleReuse ? false,
}:
pkgs.testers.runNixOSTest {
  name =
    if withTupleReuse then "sentinel-closing-tuple-reuse" else "sentinel-routed-reply-with-source-nat";
  globalTimeout = 180;
  nodes = {
    outside = {
      virtualisation.vlans = [ 1 ];
      networking = {
        useNetworkd = true;
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1.ipv4.addresses = [
          {
            address = "198.18.10.254";
            prefixLength = 24;
          }
        ];
        defaultGateway = {
          address = "198.18.10.100";
          interface = "eth1";
        };
      };
      environment.systemPackages = [
        pkgs.curl
        pkgs.tcpdump
      ];
      systemd.services.qa-target = {
        wantedBy = [ "multi-user.target" ];
        wants = [ "network-online.target" ];
        after = [ "network-online.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -u ${./ipsec-failclosed-target.py} 198.18.10.254 9102";
      };
      systemd.services.qa-udp-target = {
        wantedBy = [ "multi-user.target" ];
        wants = [ "network-online.target" ];
        after = [ "network-online.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -u ${./routed-reply-udp.py} server --address 198.18.10.254";
      };
    };
    inside = {
      virtualisation.vlans = [ 2 ];
      networking = {
        useNetworkd = true;
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1.ipv4.addresses = [
          {
            address = "198.18.20.50";
            prefixLength = 24;
          }
        ];
        defaultGateway = {
          address = "198.18.20.1";
          interface = "eth1";
        };
      };
      environment.systemPackages = [ pkgs.curl ];
      systemd.services.qa-target = {
        wantedBy = [ "multi-user.target" ];
        wants = [ "network-online.target" ];
        after = [ "network-online.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -u ${./ipsec-failclosed-target.py} 198.18.20.50 9103";
      };
      systemd.services.qa-udp-target = {
        wantedBy = [ "multi-user.target" ];
        wants = [ "network-online.target" ];
        after = [ "network-online.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -u ${./routed-reply-udp.py} server --address 198.18.20.50";
      };
    };
    fw = {
      imports = [ self.nixosModules.sentinel ];
      networking.hostName = pkgs.lib.mkForce "fw";
      networking.firewall.enable = pkgs.lib.mkForce false;
      virtualisation = {
        vlans = [
          1
          2
        ];
        memorySize = 2048;
      };
      boot.kernelPackages = self.nixosConfigurations.appliance.config.boot.kernelPackages;
      services.velstra = {
        interface = pkgs.lib.mkForce "eth1";
        appliance = pkgs.lib.mkForce (
          pkgs.writeText "routed-reply.toml" ''
            [system]
            hostname="fw"
            [zone.lan]
            default_action="accept"
            [zone.wan]
            default_action="accept"
            [[interface]]
            name="eth0"
            address="dhcp"
            [[interface]]
            name="eth1"
            address="198.18.10.100/24"
            zone="wan"
            [[interface]]
            name="eth2"
            address="198.18.20.1/24"
            zone="lan"
            ${pkgs.lib.optionalString (!withTupleReuse) ''
              [[nat.source]]
              name="wan-masq"
              zone="wan"
            ''}
          ''
        );
      };
    };
  };
  testScript =
    if withTupleReuse then
      ''
        import json
        import os
        from pathlib import Path
        start_all()
        fw.wait_for_unit("sentinel-boot-late.service")
        fw.wait_for_unit("velstra.service")
        assert fw.succeed("readlink -f /run/current-system/sw/bin/sentinel").strip()=="${self.packages.x86_64-linux.sentinel}/bin/sentinel"
        for node,address,port in ((outside,"198.18.10.254",9102),(inside,"198.18.20.50",9103)):
            node.wait_for_unit("qa-target.service")
            node.wait_until_succeeds("curl --fail --silent --max-time 2 http://"+address+":"+str(port)+"/",timeout=15)
        assert "no NAT configured" in fw.succeed("sentinel show nat")
        # Type=simple being active does not mean asynchronous hook attachment
        # and both links are ready. Prove real cross-firewall reachability on
        # a different tuple before the strict, non-retried reuse experiment.
        inside.wait_until_succeeds("curl --fail --silent --max-time 2 http://198.18.10.254:9102/ >/run/reuse-readiness.json",timeout=15)
        assert json.loads(inside.succeed("cat /run/reuse-readiness.json"))["peer"]=="198.18.20.50"
        code,output=inside.execute("${pkgs.python3}/bin/python3 ${./conntrack-reuse-probe.py}")
        print("CLOSING_TUPLE_REUSE_OBSERVATION "+json.dumps({"exit":code,"actual_probe":output}),flush=True)
        assert code==0,"valid same-tuple reconnect failed before the unchanged closing timeout"
        actual=json.loads(output)
        assert actual["same_tuple_connections"]==40 and actual["elapsed"]<20
        Path(os.environ["out"],"conntrack-reuse.json").write_text(json.dumps(actual,indent=2))
      ''
    else
      ''
        import json
        import os
        from pathlib import Path
        start_all()
        fw.wait_for_unit("sentinel-boot-late.service")
        fw.wait_for_unit("velstra.service")
        assert fw.succeed("readlink -f /run/current-system/sw/bin/sentinel").strip()=="${self.packages.x86_64-linux.sentinel}/bin/sentinel"
        for node,address,port in ((outside,"198.18.10.254",9102),(inside,"198.18.20.50",9103)):
            node.wait_for_unit("qa-target.service")
            node.wait_until_succeeds("curl --fail --silent --max-time 2 http://"+address+":"+str(port)+"/",timeout=15)
        # No VPN/shunt is configured. This isolates ordinary routed replies from
        # IPsec provenance rules, rather than blaming a confidentiality guard.
        fw.fail("test -e /run/sentinel/ipsec-guards.json")
        outbound=json.loads(inside.succeed("curl --fail --silent --show-error --max-time 5 http://198.18.10.254:9102/"))
        assert outbound["peer"]=="198.18.10.100",outbound
        outside.succeed("systemd-run --unit=qa-routed-reply-wire --property=RuntimeMaxSec=45 ${pkgs.tcpdump}/bin/tcpdump --immediate-mode -U -ni eth1 -w /run/routed-reply.pcap 'tcp or udp'")
        outside.wait_until_succeeds("journalctl -u qa-routed-reply-wire --no-pager | grep -q 'listening on eth1'",timeout=5)
        code,output=outside.execute("curl --fail --silent --show-error --max-time 3 http://198.18.20.50:9103/")
        # Independent real UDP servers and connected clients prove the reply
        # tuple too; TCP-only success must not certify the UDP code path.
        for node in (inside,outside):
            node.wait_for_unit("qa-udp-target.service")
            node.wait_until_succeeds("ss -lun | grep -q ':9105 '",timeout=10)
        udp_outbound=json.loads(inside.succeed("${pkgs.python3}/bin/python3 ${./routed-reply-udp.py} probe --address 198.18.10.254 --source 198.18.20.50 --expected-peer 198.18.10.100"))
        udp_inbound=json.loads(outside.succeed("${pkgs.python3}/bin/python3 ${./routed-reply-udp.py} probe --address 198.18.20.50 --source 198.18.10.254 --expected-peer 198.18.10.254"))
        outside.succeed("systemctl kill --signal=SIGUSR2 qa-routed-reply-wire.service")
        outside.succeed("systemctl stop qa-routed-reply-wire.service")
        wire=outside.succeed("${pkgs.tcpdump}/bin/tcpdump -nn -r /run/routed-reply.pcap 2>/dev/null")
        observation={"ordinary_outbound_SNAT":outbound,"routed_inbound_exit":code,"routed_inbound_response":output,
                     "independent_outside_NIC_wire":wire,"no_IPsec_or_guard_configured":True,
                     "ordinary_outbound_SNAT_UDP":udp_outbound,"routed_inbound_UDP":udp_inbound}
        print("ROUTED_REPLY_OBSERVATION "+json.dumps(observation),flush=True)
        assert code==0,"a source-NAT rule must not rewrite an ordinary routed responder's tuple"
        assert json.loads(output)["peer"]=="198.18.10.254",output
        Path(os.environ["out"],"routed-reply.json").write_text(json.dumps(observation,indent=2))
      '';
}
