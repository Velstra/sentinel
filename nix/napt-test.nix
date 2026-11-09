{ pkgs, self }:
let
  lib=pkgs.lib;
  sentinel=self;
  agent=self.packages.x86_64-linux.velstra;
  object=self.packages.x86_64-linux.velstra-ebpf;
  probe=pkgs.writeShellScriptBin "sentinel-napt-probe" ''
    exec ${pkgs.python3}/bin/python3 ${./napt-probe.py}
  '';
in pkgs.testers.runNixOSTest {
  name="sentinel-napt-concurrency";
  globalTimeout=420;
  nodes={
    client={
      virtualisation.vlans=[2];
      networking={
        useNetworkd=true;
        useDHCP=false;
        firewall.enable=false;
        interfaces.eth1.ipv4.addresses=[
          {address="198.18.20.50";prefixLength=24;}
          {address="198.18.20.51";prefixLength=24;}
        ];
        defaultGateway={address="198.18.20.1";interface="eth1";};
      };
      environment.systemPackages=[probe];
    };
    backend={
      virtualisation.vlans=[1];
      networking={
        useNetworkd=true;
        useDHCP=false;
        firewall.enable=false;
        interfaces.eth1.ipv4.addresses=[{address="198.18.10.254";prefixLength=24;}];
      };
      systemd.services.qa-peer={
        wantedBy=["multi-user.target"];
        after=["network-online.target"];
        wants=["network-online.target"];
        serviceConfig.ExecStart="${pkgs.python3}/bin/python3 -u ${./napt-backend.py}";
      };
    };
    fw={
      imports=[sentinel.nixosModules.sentinel];
      networking.hostName=lib.mkForce "fw";
      networking.firewall.enable=lib.mkForce false;
      boot.kernelPackages=sentinel.nixosConfigurations.appliance.config.boot.kernelPackages;
      virtualisation={vlans=[1 2];memorySize=2048;};
      services.velstra={
        interface=lib.mkForce "eth1";
        appliance=lib.mkForce (pkgs.writeText "napt-concurrency.toml" ''
          [system]
          hostname="fw"
          [zone.lan]
          default_action="accept"
          [[interface]]
          name="eth0"
          address="dhcp"
          zone="management"
          [[interface]]
          name="eth1"
          address="198.18.10.100/24"
          zone="wan"
          [[interface]]
          name="eth2"
          address="198.18.20.1/24"
          zone="lan"
          [[nat.source]]
          name="wan-masq"
          zone="wan"
        '');
      };
      environment.etc."qa-napt-object".source=object;
      environment.systemPackages=[agent pkgs.iproute2 pkgs.bpftools];
    };
  };
  testScript=''
    import json
    import os
    from pathlib import Path
    start_all()
    fw.wait_for_unit("sentinel-boot.service")
    fw.wait_for_unit("velstra.service")
    backend.wait_for_unit("qa-peer.service")
    fw.succeed("sentinel config check /var/lib/sentinel/appliance.toml")
    fw.wait_until_succeeds("ip -4 address show eth1 | grep -q 198.18.10.100/24",timeout=30)
    fw.wait_until_succeeds("ip -4 address show eth2 | grep -q 198.18.20.1/24",timeout=30)
    client.wait_until_succeeds("ip -4 address show eth1 | grep -q 198.18.20.51/24",timeout=30)
    fw.succeed("ip -details link show eth1 | grep -q prog/xdp")
    fw.succeed("ip -details link show eth2 | grep -q prog/xdp")
    # Aya6f6859f defaults to real TCX links on kernel>=6.6. A classic
    # tc-filter listing is empty even with correctly attached TCX programs.
    wan_index=int(fw.succeed("cat /sys/class/net/eth1/ifindex"))
    links=json.loads(fw.succeed("bpftool -j link show"))
    egress=[link for link in links if link.get("type")=="tcx"
            and link.get("ifindex")==wan_index and link.get("attach_type")=="tcx_egress"]
    assert egress,links
    loaded=[]
    for link in egress:
        program=json.loads(fw.succeed("bpftool -j prog show id "+str(link["prog_id"])))
        if isinstance(program,list):
            assert len(program)==1,program
            program=program[0]
        loaded.append({key:program[key] for key in ("id","type","name","tag")})
    assert any(program["name"]=="velstra_egress" for program in loaded),loaded
    service_command=fw.succeed("systemctl show velstra.service -p ExecStart --value")
    assert "${agent}/bin/velstra" in service_command,service_command
    before=fw.succeed("sha256sum /var/lib/sentinel/appliance.toml")
    result=json.loads(client.succeed("sentinel-napt-probe"))
    result["read_only_kernel_attachment"]={"WAN_ifindex":wan_index,"TCX_egress_links":egress,
                                           "programs":loaded,"actual_service_command":service_command}
    assert result["concurrent_connections"]==128 and result["verified_echo_bytes"]>2*1024**2
    assert fw.succeed("sha256sum /var/lib/sentinel/appliance.toml")==before
    fw.succeed("systemctl is-active sentinel-boot.service velstra.service wren.service")
    Path(os.environ["out"],"napt-traffic.json").write_text(json.dumps(result,indent=2))
  '';
}
