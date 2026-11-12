{
  pkgs,
  self,
  withAllDirections ? false,
  withAllSelectors ? false,
  withOwnership ? false,
  withRouteOwnership ? false,
  withLifecycle ? false,
}:
let
  lib = pkgs.lib;
  expectedSentinel = self.packages.x86_64-linux.sentinel;
  peerConfig = pkgs.writeText "sentinel-ipsec-failclosed-reference.conf" ''
    connections {
      reference-peer {
        version = 2
        local_addrs = 198.18.10.254
        remote_addrs = 198.18.10.100
        proposals = aes256-sha256-modp2048
        local {
          auth = psk
          id = 198.18.10.254
        }
        remote {
          auth = psk
          id = 198.18.10.100
        }
        children {
          qa-site {
            local_ts = ${if withAllSelectors then "0.0.0.0/0" else "198.19.210.0/24"}
            remote_ts = ${if withAllSelectors then "0.0.0.0/0" else "198.18.20.0/24"}
            esp_proposals = aes256-sha256
            start_action = none
          }
        }
      }
      ${lib.optionalString withLifecycle ''
        reference-keep {
          version = 2
          local_addrs = 198.18.10.254
          remote_addrs = 198.18.10.100
          proposals = aes256-sha256-modp2048
          local {
            auth = psk
            id = peer-keep.example
          }
          remote {
            auth = psk
            id = fw-keep.example
          }
          children {
            qa-keep {
              local_ts = 198.19.211.0/24
              remote_ts = 198.18.20.0/24
              esp_proposals = aes256-sha256
              start_action = none
            }
          }
        }
      ''}
    }
    secrets {
      ike-qa1294 {
        id-1 = 198.18.10.254
        id-2 = 198.18.10.100
        secret = "public-ephemeral-ipsec-failclosed-fixture"
      }
      ${lib.optionalString withLifecycle ''
        ike-keep {
          id-1 = peer-keep.example
          id-2 = fw-keep.example
          secret = "public-ephemeral-IPsec-keep-fixture"
        }
      ''}
    }
  '';
in
pkgs.testers.runNixOSTest {
  name =
    if withLifecycle then
      "sentinel-ipsec-SA-lifecycle"
    else if withRouteOwnership then
      "sentinel-ipsec-route-ownership"
    else if withOwnership then
      "sentinel-ipsec-shunt-ownership"
    else if withAllSelectors then
      "sentinel-ipsec-full-selectors"
    else if withAllDirections then
      "sentinel-ipsec-provenance"
    else
      "sentinel-ipsec-failclosed";
  globalTimeout = 480;
  nodes = {
    client = {
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
      systemd.services.qa-client-target = {
        wantedBy = [ "multi-user.target" ];
        wants = [ "network-online.target" ];
        after = [ "network-online.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -u ${./ipsec-failclosed-target.py} 198.18.20.50 9103";
      };
    };
    peer = {
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
      boot.kernelModules = [ "dummy" ];
      services.strongswan-swanctl = {
        enable = true;
        includes = [ peerConfig ];
        strongswan.extraConfig = ''
          charon {
            install_routes = no
          }
        '';
      };
      systemd.services.qa-protected-address = {
        wantedBy = [ "multi-user.target" ];
        before = [
          "strongswan-swanctl.service"
          "qa-target.service"
        ];
        after = [ "network-pre.target" ];
        path = [ pkgs.iproute2 ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''
          ip link add protected0 type dummy
          ip address add 198.19.210.9/24 dev protected0
          ip link set protected0 up
          ${lib.optionalString withLifecycle "ip address add 198.19.211.9/24 dev protected0"}
        '';
      };
      systemd.services.qa-target = {
        wantedBy = [ "multi-user.target" ];
        after = [ "qa-protected-address.service" ];
        requires = [ "qa-protected-address.service" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -u ${./ipsec-failclosed-target.py}";
      };
      systemd.services.qa-keep-target = lib.mkIf withLifecycle {
        wantedBy = [ "multi-user.target" ];
        after = [ "qa-protected-address.service" ];
        requires = [ "qa-protected-address.service" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -u ${./ipsec-failclosed-target.py} 198.19.211.9 9105";
      };
      environment.systemPackages = [
        pkgs.strongswan
        pkgs.curl
        pkgs.tcpdump
      ];
    };
    fw = {
      imports = [ self.nixosModules.sentinel ];
      networking.hostName = lib.mkForce "fw";
      networking.firewall.enable = lib.mkForce false;
      boot.kernelPackages = self.nixosConfigurations.appliance.config.boot.kernelPackages;
      virtualisation = {
        vlans = [
          1
          2
        ];
        memorySize = 2048;
      };
      services.velstra = {
        interface = lib.mkForce "eth1";
        appliance = lib.mkForce (
          pkgs.writeText "sentinel-ipsec-failclosed.toml" ''
            [system]
            hostname="fw"
            [zone.lan]
            default_action="accept"
            [zone.wan]
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
            [[vpn.ipsec]]
            name="qa-site"
            local="198.18.10.100"
            remote="198.18.10.254"
            local-subnet="198.18.20.0/24"
            remote-subnet="198.19.210.0/24"
            psk="public-ephemeral-ipsec-failclosed-fixture"
          ''
        );
      };
      environment.systemPackages = [
        pkgs.curl
        pkgs.strongswan
      ];
      systemd.services.qa-local-target = {
        wantedBy = [ "multi-user.target" ];
        after = [ "sentinel-boot-late.service" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 -u ${./ipsec-failclosed-target.py} 198.18.20.1 9104";
      };
    };
  };
  testScript =
    if withLifecycle then
      builtins.replaceStrings [ "__SENTINEL__" ] [ "${expectedSentinel}/bin/sentinel" ] (
        builtins.readFile ./ipsec-lifecycle-test.py
      )
    else if withRouteOwnership then
      builtins.replaceStrings [ "__SENTINEL__" ] [ "${expectedSentinel}/bin/sentinel" ] (
        builtins.readFile ./ipsec-routes-test.py
      )
    else if withOwnership then
      builtins.replaceStrings
        [ "__SENTINEL__" "__NFT__" ]
        [ "${expectedSentinel}/bin/sentinel" "${pkgs.nftables}/bin/nft" ]
        (builtins.readFile ./ipsec-ownership-test.py)
    else if withAllSelectors then
      builtins.replaceStrings
        [ "__SENTINEL__" "__NFT__" "__TCPDUMP__" "__PYTHON__" ]
        [
          "${expectedSentinel}/bin/sentinel"
          "${pkgs.nftables}/bin/nft"
          "${pkgs.tcpdump}/bin/tcpdump"
          "${pkgs.python3}/bin/python3"
        ]
        (builtins.readFile ./ipsec-fullselectors-test.py)
    else
      ''
        import json
        import os
        import time
        from pathlib import Path

        def capture(label, lifetime=90):
            unit="qa-ipsec-wire-"+label
            path="/run/qa-wire-"+label+".pcap"
            peer.succeed("systemd-run --unit="+unit+" --property=RuntimeMaxSec="+str(lifetime)+" ${pkgs.tcpdump}/bin/tcpdump --immediate-mode -U -ni eth1 -w "+path+" 'esp or (host 198.19.210.9 and tcp port 9102)'")
            peer.wait_until_succeeds("journalctl -u "+unit+" --no-pager | grep -q 'listening on eth1'",timeout=10)
            return unit,path

        def finish_capture(unit,path):
            peer.succeed("systemctl kill --signal=SIGUSR2 "+unit+".service")
            peer.succeed("systemctl stop "+unit+".service")
            return {
                "all_captured_packets":peer.succeed("${pkgs.tcpdump}/bin/tcpdump -nn -r "+path+" 2>/dev/null"),
                "esp":peer.succeed("${pkgs.tcpdump}/bin/tcpdump -nn -r "+path+" 'esp' 2>/dev/null"),
                "WAN_source_plaintext":peer.succeed("${pkgs.tcpdump}/bin/tcpdump -nn -r "+path+" 'src host 198.18.10.100 and dst host 198.19.210.9 and tcp dst port 9102' 2>/dev/null")
            }

        start_all()
        try:
            fw.wait_for_unit("sentinel-boot.service")
        except Exception:
            print("IPSEC_EARLY_GUARD_BOOT_FAILURE "+json.dumps({
                "kernel_policies_only":fw.execute("ip -s xfrm policy"),
                "owned_guard_journal":fw.execute("cat /run/sentinel/ipsec-guards.json"),
                "guard_boot_log":fw.execute("journalctl -u sentinel-boot.service --no-pager")}),flush=True)
            raise
        actual_sentinel=fw.succeed("readlink -f /run/current-system/sw/bin/sentinel").strip()
        assert actual_sentinel=="${expectedSentinel}/bin/sentinel",actual_sentinel
        guard_evidence=None
        guard_evidence={"journal":json.loads(fw.succeed("cat /run/sentinel/ipsec-guards.json")),
                        "actual_early_shunts":fw.succeed("${pkgs.nftables}/bin/nft -s -nn list table inet sentinel_ipsec_shunt")}
        assert len(guard_evidence["journal"]["guards"])==3,guard_evidence
        assert guard_evidence["actual_early_shunts"].count("counter drop")==4,guard_evidence
        fw.wait_for_unit("velstra.service")
        fw.wait_for_unit("sentinel-boot-late.service")
        fw.wait_for_unit("strongswan-swanctl.service")
        peer.wait_for_unit("strongswan-swanctl.service")
        peer.wait_for_unit("qa-target.service")
        peer.wait_until_succeeds("ss -lnt | grep -q '198.19.210.9:9102'",timeout=15)
        fw.wait_until_succeeds("ip -4 address show eth1 | grep -q 198.18.10.100/24",timeout=30)
        client.wait_until_succeeds("ip -4 address show eth1 | grep -q 198.18.20.50/24",timeout=30)
        client.wait_for_unit("qa-client-target.service")
        fw.wait_for_unit("qa-local-target.service")
        client.succeed("curl --fail --silent --max-time 3 http://198.18.20.50:9103/")
        fw.succeed("curl --fail --silent --max-time 3 http://198.18.20.1:9104/")
        fw.succeed("sentinel config check /var/lib/sentinel/appliance.toml")
        initially_loaded=fw.succeed("swanctl --list-conns")
        assert "conn-qa-site" in initially_loaded, "saved IPsec connection absent after the complete late boot stage"
        print("IPSEC_SHUNT_BEFORE_COMMIT "+json.dumps(guard_evidence),flush=True)
        # Boot-race evidence is separate from the no-SA packet-path assertion.
        # Reassert via the real product configuration transaction, never by loading
        # a test-generated config into the product daemon directly.
        fw.succeed("printf '%s\\n' 'set vpn ipsec qa-site psk public-ephemeral-ipsec-failclosed-fixture' commit save exit | sentinel configure")
        loaded_after_commit=fw.succeed("swanctl --list-conns")
        assert "conn-qa-site" in loaded_after_commit,loaded_after_commit
        fw.execute("swanctl --initiate --child qa-site --timeout 30")
        fw.wait_until_succeeds("swanctl --list-sas | grep -q ESTABLISHED",timeout=60)
        peer.wait_until_succeeds("swanctl --list-sas | grep -q ESTABLISHED",timeout=60)
        fw.wait_until_succeeds("swanctl --list-sas | grep -q INSTALLED",timeout=30)
        peer.wait_until_succeeds("swanctl --list-sas | grep -q INSTALLED",timeout=30)
        command="curl --fail --silent --show-error --max-time 8 http://198.19.210.9:9102/"
        assert json.loads(peer.succeed(command))["marker"]=="sentinel-ipsec-failclosed-target"
        good_unit,good_path=capture("authenticated")
        good_code,good_output=client.execute(command)
        good_wire=finish_capture(good_unit,good_path)
        if good_code:
            diagnostics={"exit":good_code,"output":good_output,"wire":good_wire,
                         "fw_routes":fw.succeed("ip -4 route show"),
                         "fw_policy":fw.succeed("ip xfrm policy"),
                         "fw_SA_counts":fw.succeed("ip xfrm state count"),
                         "peer_policy":peer.succeed("ip xfrm policy"),
                         "peer_listener":peer.succeed("ss -lntp"),
                         "peer_target_log":peer.succeed("journalctl -u qa-target.service --no-pager")}
            print("IPSEC_AUTHENTICATED_CONTROL_FAILURE "+json.dumps(diagnostics),flush=True)
        assert good_code==0,"authenticated control failed before the fail-closed assertion"
        good=json.loads(good_output)
        assert good=={"peer":"198.18.20.50","marker":"sentinel-ipsec-failclosed-target"},good
        assert good_wire["esp"] and not good_wire["WAN_source_plaintext"],good_wire
        # Remove only this owned IKE connection through the real daemon API, not
        # a global XFRM/map flush or a test replacement of the crypto engine.
        fw.execute("swanctl --terminate --ike conn-qa-site --timeout 15")
        peer.execute("swanctl --terminate --ike reference-peer --timeout 15")
        fw.succeed("printf '%s\\n' 'set vpn ipsec qa-site psk public-WRONG-ipsec-failclosed-fixture' commit save exit | sentinel configure")
        refusal_code,refusal=fw.execute("swanctl --initiate --child qa-site --timeout 30 2>&1")
        assert refusal_code!=0 and "AUTHENTICATION_FAILED" in refusal,refusal
        assert "ESTABLISHED" not in fw.succeed("swanctl --list-sas")
        assert "ESTABLISHED" not in peer.succeed("swanctl --list-sas")
        for node in (fw,peer):
            # Check only on the guest, emit no state/key material. An empty state
            # listing is empty stdout (not JSON [] with this pinned iproute2).
            node.wait_until_succeeds("${pkgs.python3}/bin/python3 -c 'import subprocess; assert not subprocess.check_output([\"ip\",\"xfrm\",\"state\"]).strip()'",timeout=15)
        # Observe the independent reference NIC. With no SA and a non-selector
        # WAN source, this cannot be a decrypted inner packet mistaken for wire data.
        bad_unit,bad_path=capture("refused")
        bad_code,bad_output=client.execute(command)
        bad_wire=finish_capture(bad_unit,bad_path)
        plaintext=bad_wire["WAN_source_plaintext"]
        # Independent application health control from outside the protected local
        # selector must remain reachable; do not confuse a dead server with shunting.
        health=json.loads(fw.succeed(command+" --interface 198.18.10.100"))
        assert health=={"peer":"198.18.10.100","marker":"sentinel-ipsec-failclosed-target"},health
        observation={"authenticated_control":good,"fresh_authentication_refused":True,
                     "actual_installed_sentinel":actual_sentinel,"early_kernel_guards":guard_evidence,
                     "boot_connection_present_before_commit":"conn-qa-site" in initially_loaded,
                     "connection_present_after_product_commit":True,
                     "no_established_SA":True,"protected_request_exit":bad_code,
                     "protected_response":bad_output,"wire_WAN_source_plaintext":plaintext,
                     "authenticated_wire":good_wire,"failed_authentication_wire":bad_wire,
                     "nonprotected_source_health_control":health,
                     "independent_target_healthy":True,"no_XFRM_key_dump":True}
        print("IPSEC_FAILCLOSED_OBSERVATION "+json.dumps(observation),flush=True)
        assert bad_code!=0 and not plaintext,"protected traffic leaked without a CHILD SA"

        with subtest("normal daemon restart restores the saved connection without another commit"):
            fw.succeed("systemctl restart strongswan-swanctl.service")
            loaded=fw.succeed("swanctl --list-conns")
            assert "conn-qa-site" in loaded,"normal daemon restart lost the saved IPsec connection"

        def configure(action, key):
            fw.succeed("printf '%s\\n' 'set vpn ipsec qa-site start-action "+action+"' 'set vpn ipsec qa-site psk "+key+"' commit save exit | sentinel configure")
            assert "conn-qa-site" in fw.succeed("swanctl --list-conns")

        def terminate():
            fw.execute("swanctl --terminate --ike conn-qa-site --timeout 15")
            peer.execute("swanctl --terminate --ike reference-peer --timeout 15")

        def no_states():
            for node in (fw, peer):
                node.wait_until_succeeds("${pkgs.python3}/bin/python3 -c 'import subprocess; assert not subprocess.check_output([\"ip\",\"xfrm\",\"state\"]).strip()'",timeout=15)

        def assert_blocked(label):
            assert len(json.loads(fw.succeed("cat /run/sentinel/ipsec-guards.json"))["guards"])==3
            assert fw.succeed("${pkgs.nftables}/bin/nft -s -nn list table inet sentinel_ipsec_shunt").count("counter drop")==4
            unit,path=capture(label)
            code,output=client.execute(command)
            wire=finish_capture(unit,path)
            health=json.loads(fw.succeed(command+" --interface 198.18.10.100"))
            assert health["peer"]=="198.18.10.100",health
            assert code!=0 and not wire["WAN_source_plaintext"],(label,code,output,wire)
            fw_code,_=fw.execute(command+" --interface 198.18.20.1")
            assert fw_code!=0,"locally generated protected traffic leaked without IPsec"
            reverse=[]
            if ${if withAllDirections then "True" else "False"}:
                for address,port in (("198.18.20.50",9103),("198.18.20.1",9104)):
                    url="curl --fail --silent --show-error --max-time 3 http://"+address+":"+str(port)+"/"
                    code,_=peer.execute(url+" --interface 198.19.210.9")
                    assert code!=0,"plaintext protected-source packet reached "+address
                    unit="qa-ipsec-control-"+label+"-"+str(port)
                    path="/run/"+unit+".pcap"
                    fw.succeed("systemd-run --unit="+unit+" --property=RuntimeMaxSec=15 ${pkgs.tcpdump}/bin/tcpdump --immediate-mode -U -ni any -w "+path+" 'tcp port "+str(port)+"'")
                    fw.wait_until_succeeds("journalctl -u "+unit+" --no-pager | grep -q 'listening on any'",timeout=5)
                    before=fw.succeed("${pkgs.nftables}/bin/nft -j list table inet sentinel_ipsec_shunt")
                    control_code,control_output=peer.execute(url+" --interface 198.18.10.254")
                    after=fw.succeed("${pkgs.nftables}/bin/nft -j list table inet sentinel_ipsec_shunt")
                    fw.succeed("systemctl kill --signal=SIGUSR2 "+unit+".service; systemctl stop "+unit+".service")
                    if control_code:
                        print("IPSEC_REVERSE_CONTROL_FAILURE "+json.dumps({"label":label,"target":address,"exit":control_code,
                              "wire_on_fw":fw.succeed("${pkgs.tcpdump}/bin/tcpdump -nn -r "+path+" 2>/dev/null"),
                              "shunts_before":json.loads(before),"shunts_after":json.loads(after),
                              "independent_listener":client.execute("curl --fail --silent --max-time 2 http://198.18.20.50:9103/"),
                              "fw_routes":fw.succeed("ip -4 route"),"peer_routes":peer.succeed("ip -4 route")}),flush=True)
                    assert control_code==0,"nonprotected reverse health control failed"
                    control=json.loads(control_output)
                    assert control["peer"]=="198.18.10.254",control
                    reverse.append({"target":address,"protected_request_exit":code,"independent_control":control})
            return {"label":label,"protected_request_exit":code,"wire":wire,"independent_health":health,
                    "local_outbound_refused":True,"inbound_and_forward_plaintext_refused":reverse}

        def assert_encrypted(label, responder=False, initiate=False, traffic_acquire=False):
            initiation={"requested":responder or initiate,"already_installed":False}
            if responder or initiate:
                # Credentials reload does not promise a new IKE initiation. The
                # source confidentiality gate explicitly exercises the normal
                # daemon API after correcting a previously refused key; it does
                # not certify automatic start-mode retry/recovery.
                # Conversely, start_action=start may already have installed this
                # exact child while a genuine commit/restart completed. A duplicate
                # initiation is not a product failure. Never accept an unrelated
                # API error or substitute this check for actual encrypted traffic.
                node=peer if responder else fw
                def installed():
                    return any(line.strip().startswith("qa-site:") and ", INSTALLED," in line
                               for line in node.succeed("swanctl --list-sas").splitlines())
                initiation["already_installed"]=installed()
                if not initiation["already_installed"]:
                    status,message=node.execute("swanctl --initiate --child qa-site --timeout 30 2>&1")
                    duplicate=status!=0 and "existing duplicate" in message and installed()
                    assert status==0 or duplicate,message
                    initiation.update({"exit":status,"verified_duplicate_race":duplicate})
            acquisition_expiry=int(fw.succeed("cat /proc/sys/net/core/xfrm_acq_expires").strip()) if traffic_acquire else 0
            assert 0<=acquisition_expiry<=300,"explicit bounded fixture budget; do not alter the kernel timeout"
            # strongSwan's documented default is165, not30. Correcting a PSK does
            # not flush an earlier failed kernel acquire. Wait for that REAL
            # configured interval with traffic; never shorten it or remove state.
            acquisition_budget=acquisition_expiry+15
            unit,path=capture(label,max(90,acquisition_budget+25))
            began=time.monotonic()
            policies_before=fw.succeed("ip -s xfrm policy") if traffic_acquire else "not a trap-acquisition case"
            traps_before=fw.succeed("swanctl --list-pols") if traffic_acquire else "not a trap-acquisition case"
            attempts=[]
            while True:
                code,output=client.execute(command)
                attempts.append({"exit":code,"elapsed":time.monotonic()-began})
                if code==0 or not traffic_acquire or time.monotonic()-began>=acquisition_budget:
                    break
                # Only genuine new client traffic retries acquisition. No policy,
                # SA, conntrack or acquisition timer reset is permitted.
            wire=finish_capture(unit,path)
            if code:
                print("IPSEC_RECOVERY_FAILURE "+json.dumps({"label":label,"attempts":attempts,
                      "policies_before":policies_before,"traps_before":traps_before,
                      "policies_after":fw.succeed("ip -s xfrm policy"),
                      "traps_after":fw.succeed("swanctl --list-pols"),
                      "connections":fw.succeed("swanctl --list-conns"),
                      "shunts":fw.succeed("${pkgs.nftables}/bin/nft -j list table inet sentinel_ipsec_shunt"),
                      "acquisition_expiry":fw.execute("cat /proc/sys/net/core/xfrm_acq_expires"),
                      "xfrm_counters":fw.execute("cat /proc/net/xfrm_stat"),
                      "charon_log":fw.succeed("journalctl -u strongswan-swanctl.service -n 90 --no-pager")}),flush=True)
            assert code==0,(label,code,output,wire)
            assert json.loads(output)["peer"]=="198.18.20.50",output
            assert wire["esp"] and not wire["WAN_source_plaintext"],wire
            local=json.loads(fw.succeed(command+" --interface 198.18.20.1"))
            assert local["peer"]=="198.18.20.1",local
            if ${if withAllDirections then "True" else "False"}:
                for address,port in (("198.18.20.50",9103),("198.18.20.1",9104)):
                    url="curl --fail --silent --show-error --max-time 5 http://"+address+":"+str(port)+"/ --interface 198.19.210.9"
                    assert json.loads(peer.succeed(url))["peer"]=="198.19.210.9"
            return {"label":label,"actual_response":json.loads(output),"wire":wire,"actual_attempts":attempts,
                    "actual_acquisition_expiry":acquisition_expiry,"traffic_acquisition_budget":acquisition_budget,
                    "initiation":initiation}

        modes=[]
        for action in ("start","trap","none"):
            with subtest("wrong PSK and authenticated recovery: "+action):
                terminate()
                configure(action,"public-WRONG-ipsec-failclosed-fixture")
                code,error=fw.execute("swanctl --initiate --child qa-site --timeout 30 2>&1")
                assert code!=0 and "AUTHENTICATION_FAILED" in error,error
                no_states()
                blocked=assert_blocked("wrong-"+action)
                configure(action,"public-ephemeral-ipsec-failclosed-fixture")
                encrypted=assert_encrypted("recovered-"+action,responder=action=="none",initiate=action=="start",traffic_acquire=action=="trap")
                modes.append({"action":action,"authentication_refusal":blocked,"recovery":encrypted})
        observation["start_mode_matrix"]=modes

        daemon=[]
        for action in ("start","trap","none"):
            with subtest("daemon stop and normal restart: "+action):
                terminate()
                configure(action,"public-ephemeral-ipsec-failclosed-fixture")
                assert_encrypted("before-stop-"+action,responder=action=="none",initiate=action=="start",traffic_acquire=action=="trap")
                fw.succeed("systemctl stop strongswan-swanctl.service")
                peer.execute("swanctl --terminate --ike reference-peer --timeout 15")
                no_states()
                blocked=assert_blocked("daemon-down-"+action)
                fw.succeed("systemctl start strongswan-swanctl.service")
                loaded=fw.succeed("swanctl --list-conns")
                assert "conn-qa-site" in loaded,"normal daemon restart lost the saved IPsec connection"
                encrypted=assert_encrypted("daemon-restarted-"+action,responder=action=="none",traffic_acquire=action=="trap")
                daemon.append({"action":action,"daemon_down":blocked,"normal_restart":encrypted})
        observation["daemon_lifecycle_matrix"]=daemon
        observation["reverse_provenance_checked"]=${if withAllDirections then "True" else "False"}
        Path(os.environ["out"],"ipsec-failclosed.json").write_text(json.dumps(observation,indent=2))
      '';
}
