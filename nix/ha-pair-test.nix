{ pkgs, self, twoNode ? false }:
let
  pairArguments = if twoNode then "--mode two-node" else "--witness 10.3.0.3:5440";
  secret = "pair-vm-credential-with-at-least-32-bytes";
  cluster = "f3b87b448394bd3e40442bcb14054727";
  physicalControl = node: if node == 1 then "ctrl-primary" else "ctrl-secondary";
  logicalControl = node: if node == 1 then "sync-primary" else "sync-secondary";
  qemuCommon = import "${pkgs.path}/nixos/lib/qemu-common.nix" {
    inherit (pkgs) lib stdenv;
  };
  seed = node: controlMac: (pkgs.formats.toml {}).generate "pair-member.toml" {
    system = {
      hostname = if node == 1 then "pair-primary" else "pair-secondary";
      config-sync.secret = secret;
    # Enrollment activates the peer first. Explicitly request preemption for
    # this two-node fixture's deterministic initial owner; the later cold-boot
    # case explicitly turns it off and proves incumbent ownership is retained.
    } // pkgs.lib.optionalAttrs (node==2 || twoNode) {ha={enabled=false;inherit cluster;mode=if twoNode then "two-node" else "witness";} // pkgs.lib.optionalAttrs (!twoNode) {witness="10.3.0.3:5440";} // pkgs.lib.optionalAttrs (twoNode && node==1) {preempt=true;};};
    interface = [
      {name="eth1";address="10.1.0.${toString node}/24";zone="wan";}
      {name=physicalControl node;hw-id=controlMac;zone="control";}
      {name=logicalControl node;parent=physicalControl node;vlan=43;address="10.3.0.${toString node}/24";zone="control";}
    ];
    firewall.default_action="accept";
    services = {
      ntp = {serve-on=[(logicalControl node)];allow-from=["10.3.0.0/24"];};
      dns = {serve-on=[(logicalControl node)];host-override."pair-control.test"="192.0.2.43";};
    };
    protocols.vrrp=[({name="wan";interface="eth1";vrid=42;virtual-address=["10.1.0.100"];priority=if node==1 then 200 else 100;} // pkgs.lib.optionalAttrs (twoNode && node==1) {preempt=true;})];
  };
  member = node: {config,lib,...}: {
    networking.hostName=lib.mkForce (if node==1 then "primary" else "secondary");
    imports=[self.nixosModules.sentinel];
    # Actual guest NICs have different names, not just mocked identities. Their
    # logical VLAN names differ too: pairing must preserve both local profiles.
    virtualisation.vlans=[];
    # Driver commands use the virtio serial backdoor, not a management NIC.
    # Omit the default SLiRP interface: otherwise CLI hardware discovery would
    # correctly persist a fourth, unmodelled physical NIC on the first commit.
    virtualisation.qemu.networkingOptions=lib.mkForce [];
    virtualisation.interfaces = {
      # Without SLiRP, the first NIC starts as eth0 and the second as eth1.
      # Rename control away from eth0; data already has its final eth1 name.
      "${physicalControl node}".vlan=3;
      z-data={name="eth1";vlan=1;};
    };
    virtualisation.memorySize=2048;
    networking.firewall.enable=lib.mkForce false;
    services.velstra.interface=lib.mkForce "eth1";
    services.velstra.appliance=lib.mkForce (seed node
      (pkgs.lib.toLower (qemuCommon.qemuNicMac 3 config.virtualisation.test.nodeNumber)));
    systemd.services.velstra.environment.RUST_LOG=lib.mkForce "velstra=info,velstra::conntrack_sync::secure=debug";
    environment.systemPackages=[pkgs.python3 pkgs.curl pkgs.bpftools pkgs.dig pkgs.iptables];
  };
in pkgs.testers.runNixOSTest {
  name=if twoNode then "sentinel-ha-pair-two-node" else "sentinel-ha-pair";
  nodes={
    primary=member 1;secondary=member 2;
  } // pkgs.lib.optionalAttrs (!twoNode) {
    witness={lib,...}: {
      networking.hostName=lib.mkForce "witness";
      imports=[self.nixosModules.sentinel];
      virtualisation.vlans=[3];virtualisation.memorySize=1536;
      networking.firewall.enable=lib.mkForce false;
      services.velstra.interface=lib.mkForce "eth1";
      services.velstra.appliance=lib.mkForce ((pkgs.formats.toml {}).generate "pair-witness-appliance.toml" {
        # The derived key `sentinel ha witness-key` prints for this token and
        # cluster; the witness never holds the members' machine token.
        system={hostname="witness";ha-witness={listen="10.3.0.3:5440";key="b080d20c3e5dfd7ba3cfc3f7a2713448f452ebd8b56a9ef6dac76ff570b69da8";inherit cluster;member=["10.3.0.1" "10.3.0.2"];};};
        interface=[
          {name="eth1";zone="control";}
          {name="witness-sync";parent="eth1";vlan=43;address="10.3.0.3/24";zone="control";}
        ];
        firewall.default_action="accept";
      });
    };

  };
  testScript=''
    import time,json,shlex
    two_node=${if twoNode then "True" else "False"}
    witness_node=globals().get("witness")
    assert (witness_node is None) == two_node,"wrong test topology: witness presence does not match selected HA mode"
    def python_command(script):
        return "${pkgs.python3}/bin/python3 -c " + shlex.quote(script)
    def read_config(node):
        return json.loads(node.succeed(python_command('import tomllib,json; print(json.dumps(tomllib.load(open("/var/lib/sentinel/appliance.toml","rb"))))')))
    def wait_outbox(node):
        node.wait_until_succeeds("test ! -e /var/lib/sentinel/configsync/pending.json",timeout=30)
    controls={
        1:{"physical":"ctrl-primary","logical":"sync-primary","other_physical":"ctrl-secondary","other_logical":"sync-secondary"},
        2:{"physical":"ctrl-secondary","logical":"sync-secondary","other_physical":"ctrl-primary","other_logical":"sync-primary"},
    }
    control_macs={}
    def assert_local_identity(node,number):
        expected=controls[number]
        config=read_config(node)
        links={i["name"]:i for i in config["interface"]}
        assert set(links)=={"eth1",expected["physical"],expected["logical"]},links
        assert links["eth1"]["address"]==f"10.1.0.{number}/24",links
        assert links[expected["physical"]]["hw-id"]==control_macs[number],links
        assert links[expected["logical"]]["parent"]==expected["physical"],links
        assert links[expected["logical"]]["vlan"]==43,links
        assert links[expected["logical"]]["address"]==f"10.3.0.{number}/24",links
        ha=config["system"]["ha"]
        assert ha["enabled"] and ha["node"]==number,ha
        assert ha["sync-interface"]==expected["logical"],ha
        assert ha["mode"]==("two-node" if two_node else "witness"),ha
        if two_node:
            assert not ha.get("witness"),ha
            assert ha["heartbeat-listen"]==[f"10.3.0.{number}:5441"],ha
            assert ha["heartbeat-peer"]==[f"10.3.0.{3-number}:5441"],ha
        assert config["services"]["ntp"]["serve-on"]==[expected["logical"]],config["services"]
        assert config["services"]["ntp"]["allow-from"]==["10.3.0.0/24"],config["services"]
        assert config["services"]["dns"]["serve-on"]==[expected["logical"]],config["services"]
        assert config["services"]["dns"]["host-override"]=={"pair-control.test":"192.0.2.43"},config["services"]
        profile=ha["peer-identity"]["control"]
        assert profile["sync-interface"]==expected["other_logical"],profile
        other_links={i["configuration"]["name"]:i["configuration"] for i in profile["interface"]}
        assert set(other_links)=={expected["other_physical"],expected["other_logical"]},profile
        assert other_links[expected["other_physical"]]["hw-id"]==control_macs[3-number],profile
        assert other_links[expected["other_logical"]]["parent"]==expected["other_physical"],profile
        assert other_links[expected["other_logical"]]["vlan"]==43,profile
        compiled=json.loads(node.succeed(python_command('import json,tomllib; print(json.dumps(tomllib.load(open("/run/sentinel/velstra.toml","rb"))))')))
        assert compiled["ha"]["enabled"] and compiled["ha"]["interfaces"]==["eth1"],compiled["ha"]
        assert set(compiled["ha"]["control_interfaces"])=={expected["physical"],expected["logical"]},compiled["ha"]
        node.succeed("ip link show " + expected["physical"] + "; ip -d link show " + expected["logical"] + " | grep -q 'vlan protocol 802.1Q id 43'")
        # Compiled intent alone is insufficient: control links must never have
        # the persistent TC fencing filter that belongs on the shared data NIC.
        programs=json.loads(node.succeed("bpftool -j prog show"))
        guards={p["id"] for p in programs if p.get("name","").startswith("velstra_ha_guar")}
        assert guards,"HA guard program was not loaded on the real dataplane"
        for link in (expected["physical"],expected["logical"]):
            for direction in ("ingress","egress"):
                result=node.succeed("tc -j filter show dev "+link+" "+direction)
                assert not any(f.get("options",{}).get("id") in guards for f in json.loads(result)),f"HA guard fenced control link {link}/{direction}: {result}"
        node.succeed("curl -ksf -H 'Authorization: Bearer ${secret}' https://10.3.0."+str(3-number)+":8080/api/v1/status >/dev/null")
        node.succeed("systemctl is-active chronyd dnsmasq")
        node.succeed("grep -qx 'allow 10.3.0.0/24' /run/sentinel/chrony.d/sentinel.conf")
        node.succeed("grep -qx 'interface="+expected["logical"]+"' /run/sentinel/dnsmasq.d/sentinel.conf")
        node.wait_until_succeeds("test \"$(dig +time=2 +tries=1 +short @10.3.0."+str(3-number)+" pair-control.test A)\" = 192.0.2.43",timeout=15)
        # A wire request proves the peer still serves NTP after materialization;
        # synchronization/stratum is deliberately not inferred from a reply.
        ntp_probe='import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3); s.sendto(bytes([35])+bytes(47),("10.3.0.'+str(3-number)+'",123)); data,peer=s.recvfrom(512); assert len(data)>=48 and data[0]&7==4,(data,peer)'
        node.wait_until_succeeds(python_command(ntp_probe),timeout=15)
    def dump_ha():
        diagnostic='import json,tomllib,hashlib; d=tomllib.load(open("/run/sentinel/velstra.toml","rb")); s=d.get("conntrack_sync",{}).copy(); secret=s.pop("secret",None); s["secret_sha256"]=hashlib.sha256(secret.encode()).hexdigest() if secret else None; print(json.dumps({"ha":d.get("ha"),"conntrack_sync":s,"interfaces":d.get("interface"),"policies":d.get("policy")},sort_keys=True))'
        for label,member in (("primary",primary),("secondary",secondary)):
            print(label+" HA failure: "+member.execute("sentinel show ha; sentinel show vrrp; ip -d -o addr; ip route; ss -tnlp; cat /run/velstra/ha/role.json /run/velstra/ha/agent.json; journalctl -u wren -u velstra --no-pager -n 120")[1])
            print(label+" compiled state-sync and guard intent: "+member.execute(python_command(diagnostic))[1])
        if witness_node is not None:print("witness durable state: "+witness_node.execute("cat /var/lib/sentinel/witness/state.json")[1])
    def wait_ready(node,timeout=20):
        try:
            node.wait_until_succeeds(python_command('import json; assert json.load(open("/run/velstra/ha/agent.json"))["ready_term"] > 0'),timeout=timeout)
        except Exception:
            dump_ha()
            raise
    def wait_role(node, role, timeout=25):
        try:
            node.wait_until_succeeds("sentinel show vrrp | grep -q 'HA "+role+"'",timeout=timeout)
        except Exception:
            dump_ha()
            raise
    start_all()
    members=[primary,secondary]
    if witness_node is not None:members.append(witness_node)
    for node in members:node.wait_for_unit("multi-user.target")
    for node in (primary,secondary):
        node.wait_for_unit("sentinel-api.service")
        node.wait_for_unit("velstra.service")
        node.wait_until_succeeds("curl -ksf https://127.0.0.1:8080/api/v1/health",timeout=30)
    for node,number in ((primary,1),(secondary,2)):
        physical=controls[number]["physical"]
        logical=controls[number]["logical"]
        node.wait_until_succeeds("ip -4 -o addr show "+logical+" | grep -q 10.3.0."+str(number),timeout=30)
        physical_nics=json.loads(node.succeed(python_command('import json,pathlib; print(json.dumps(sorted(p.name for p in pathlib.Path("/sys/class/net").iterdir() if (p/"device").exists())))')))
        assert set(physical_nics)=={"eth1",physical},physical_nics
        control_macs[number]=node.succeed("cat /sys/class/net/"+physical+"/address").strip()
        assert next(i for i in read_config(node)["interface"] if i["name"]==physical)["hw-id"]==control_macs[number]
    if not two_node:
        assert witness_node is not None,"witness VM is required for witness-mode verification"
        witness_node.wait_until_succeeds("ip -4 -o addr show witness-sync | grep -q 10.3.0.3",timeout=30)
        witness_node.wait_for_unit("sentinel-witness.service")
        witness_node.succeed("test $(stat -c %a /run/sentinel/witness.json) = 600")
        witness_node.succeed("! grep -rq '${secret}' /var/lib/sentinel /run/sentinel")
        # The printed key is what this witness was given.
        printed=primary.succeed("printf %s '${secret}' | sentinel ha witness-key --secret-stdin")
        assert 'key = "b080d20c3e5dfd7ba3cfc3f7a2713448f452ebd8b56a9ef6dac76ff570b69da8"' in printed and 'cluster = "${cluster}"' in printed, printed
    # A credential failure must happen before either document changes.
    before=primary.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0]
    secondary_before=secondary.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0]
    primary.fail("printf %s wrong-credential-with-at-least-32-bytes | sentinel ha pair 10.3.0.2:8080 ${pairArguments} --secret-stdin")
    # A token on the command line is refused outright, not merely discouraged.
    refused=primary.fail("sentinel ha pair 10.3.0.2:8080 ${pairArguments} --secret ${secret} 2>&1")
    assert "process list" in refused, refused
    assert primary.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0]==before
    assert secondary.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0]==secondary_before
    started=time.monotonic()
    primary.succeed("su admin -c " + shlex.quote("printf %s '${secret}' | sentinel ha pair 10.3.0.2:8080 ${pairArguments} --secret-stdin"))
    assert time.monotonic()-started<30,"one-command HA pairing exceeded 30 seconds"
    wait_role(primary,"Master")
    primary.wait_until_succeeds("ip -o addr show eth1 | grep -q 10.1.0.100",timeout=20)
    wait_ready(secondary)
    primary.succeed("test ! -e /var/lib/sentinel/ha-pair.json")
    # Repeating a completed enrollment must retain the same member identities.
    primary.succeed("echo '${secret}' | sentinel ha pair 10.3.0.2:8080 ${pairArguments} --secret-stdin")
    for node,number in ((primary,1),(secondary,2)):
        assert_local_identity(node,number)

    # A local change is automatically delivered with the secondary's facts.
    primary.succeed("printf '%s\\n' 'set interface eth1 mtu 1400' commit save exit | sentinel configure")
    secondary.wait_until_succeeds("ip -o link show eth1 | grep -q 'mtu 1400'",timeout=30)
    secondary.succeed("ip -o addr show eth1 | grep -q 10.1.0.2")
    wait_outbox(primary)
    # The standby is a real policy editor too, not a no-apply receiver. Wait
    # for the first delivery before reversing direction so CAS cannot race.
    secondary.succeed("printf '%s\\n' 'set interface eth1 mtu 1410' commit save exit | sentinel configure")
    primary.wait_until_succeeds("ip -o link show eth1 | grep -q 'mtu 1410'",timeout=30)
    wait_outbox(secondary)
    for node,number in ((primary,1),(secondary,2)):
        assert_local_identity(node,number)
    # HA actor replacement keeps the control query route and waits for the
    # previous coordinator's lock before binding the new generation.
    primary.succeed("printf '%s\\n' 'set system ha priority 210' 'set protocols vrrp wan priority 210' 'set system ha preempt true' 'set protocols vrrp wan preempt true' commit save exit | sentinel configure")
    wait_role(primary,"Master")
    wait_role(secondary,"Backup")
    wait_outbox(primary)
    # The receiving node's machine credential remains usable after live apply.
    secondary.succeed("curl -ksf -H 'Authorization: Bearer ${secret}' https://127.0.0.1:8080/api/v1/status >/dev/null")
    # Cold boots must load persisted paired intent instead of either factory
    # seed (primary standalone / secondary prepared), preserving identity/pins.
    for node in (secondary,primary):
        if node is primary:
            # Without preemption, a healthy incumbent must retain ownership
            # when the higher-priority member returns with a complete replica.
            primary.succeed("printf '%s\\n' 'set system ha preempt false' 'set protocols vrrp wan preempt false' commit save exit | sentinel configure")
            secondary.wait_until_succeeds(python_command('import tomllib; assert not tomllib.load(open("/var/lib/sentinel/appliance.toml","rb"))["system"]["ha"]["preempt"]'),timeout=30)
            wait_outbox(primary)
        node.shutdown()
        node.start()
        for unit in ("multi-user.target","sentinel-boot.service","velstra.service","wren.service","sentinel-api.service"):
            node.wait_for_unit(unit)
        wait_ready(node,timeout=30)
        if node is secondary:
            wait_role(primary,"Master")
            wait_role(secondary,"Backup")
        else:
            wait_role(secondary,"Master")
            wait_role(primary,"Backup")
        node.succeed("tc filter show dev eth1 ingress | grep -q bpf; tc filter show dev eth1 egress | grep -q bpf")
        node.succeed("curl -ksf -H 'Authorization: Bearer ${secret}' https://127.0.0.1:8080/api/v1/status >/dev/null")
        assert_local_identity(node,1 if node is primary else 2)
    # Enabling preemption live permits takeover only after full state import.
    primary.succeed("printf '%s\\n' 'set system ha preempt true' 'set protocols vrrp wan preempt true' commit save exit | sentinel configure")
    wait_role(primary,"Master")
    wait_role(secondary,"Backup")
    primary.succeed("printf '%s\\n' 'set interface eth1 mtu 1420' commit save exit | sentinel configure")
    secondary.wait_until_succeeds("ip -o link show eth1 | grep -q 'mtu 1420'",timeout=30)
    wait_outbox(primary)
    secondary.succeed("printf '%s\\n' 'set interface eth1 mtu 1430' commit save exit | sentinel configure")
    primary.wait_until_succeeds("ip -o link show eth1 | grep -q 'mtu 1430'",timeout=30)
    wait_outbox(secondary)
    for node,number in ((primary,1),(secondary,2)):
        assert_local_identity(node,number)

    if two_node:
        # No third VM, no witness process and no external arbiter. A complete
        # heartbeat cut cannot distinguish a dead peer from a partition: prove
        # the documented availability tradeoff and deterministic recovery.
        # Peer heartbeats use authenticated TCP. Cut both directions and all
        # peer control traffic; the VM driver's separate management NIC stays
        # reachable. A one-way UDP cut would not exercise loss of heartbeats.
        primary.succeed("iptables -I INPUT 1 -s 10.3.0.2 -j DROP")
        primary.succeed("iptables -I OUTPUT 1 -d 10.3.0.2 -j DROP")
        try:
            wait_role(secondary,"Master",timeout=15)
            secondary.succeed("ip -o addr show eth1 | grep -q 10.1.0.100")
            for chain in ("INPUT","OUTPUT"):
                counters=primary.succeed("iptables -nvx -L "+chain)
                assert any(row.split()[0].isdigit() and int(row.split()[0])>0 for row in counters.splitlines() if "DROP" in row and "10.3.0.2" in row),counters
        finally:
            primary.succeed("iptables -D INPUT -s 10.3.0.2 -j DROP")
            primary.succeed("iptables -D OUTPUT -d 10.3.0.2 -j DROP")
        wait_role(primary,"Master",timeout=30)
        wait_role(secondary,"Backup",timeout=30)
        for node,number in ((primary,1),(secondary,2)):
            assert_local_identity(node,number)

  '';
}
