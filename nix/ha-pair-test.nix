{ pkgs, self }:
let
  secret = "pair-vm-credential-with-at-least-32-bytes";
  cluster = "f3b87b448394bd3e40442bcb14054727";
  seed = node: (pkgs.formats.toml {}).generate "pair-member.toml" {
    system = {
      hostname = if node == 1 then "pair-primary" else "pair-secondary";
      config-sync.secret = secret;
    } // pkgs.lib.optionalAttrs (node==2) {ha={enabled=false;inherit cluster;witness="10.3.0.3:5440";};};
    interface = [
      {name="eth1";address="10.1.0.${toString node}/24";zone="wan";}
      {name="eth2";address="10.3.0.${toString node}/24";zone="control";}
    ];
    firewall.default_action="accept";
    protocols.vrrp=[{name="wan";interface="eth1";vrid=42;virtual-address=["10.1.0.100"];priority=if node==1 then 200 else 100;}];
  };
  member = node: {lib,...}: {
    networking.hostName=lib.mkForce (if node==1 then "primary" else "secondary");
    imports=[self.nixosModules.sentinel];
    virtualisation.vlans=[1 3];virtualisation.memorySize=2048;
    networking.firewall.enable=lib.mkForce false;
    services.velstra.interface=lib.mkForce "eth1";
    services.velstra.appliance=lib.mkForce (seed node);
    environment.systemPackages=[pkgs.python3 pkgs.curl];
  };
in pkgs.testers.runNixOSTest {
  name="sentinel-ha-pair";
  nodes={
    primary=member 1;secondary=member 2;
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
        interface=[{name="eth1";address="10.3.0.3/24";zone="control";}];
        firewall.default_action="accept";
      });
    };

  };
  testScript=''
    import time,json,shlex
    def python_command(script):
        return "${pkgs.python3}/bin/python3 -c " + shlex.quote(script)
    def wait_role(node, role, timeout=25):
        try:
            node.wait_until_succeeds("sentinel show vrrp | grep -q 'HA "+role+"'",timeout=timeout)
        except Exception:
            for label,member in (("primary",primary),("secondary",secondary)):
                print(label+" HA failure: "+member.execute("sentinel show vrrp; ip -o addr; cat /run/velstra/ha/role.json /run/velstra/ha/agent.json; journalctl -u wren -u velstra --no-pager -n 50")[1])
            print("witness durable state: "+witness.execute("cat /var/lib/sentinel/witness/state.json")[1])
            raise
    start_all()
    for node in (primary,secondary,witness):node.wait_for_unit("multi-user.target")
    for node in (primary,secondary):
        node.wait_for_unit("sentinel-api.service")
        node.wait_for_unit("velstra.service")
        node.wait_until_succeeds("curl -ksf https://127.0.0.1:8080/api/v1/health",timeout=30)
    witness.wait_for_unit("sentinel-witness.service")
    witness.succeed("test $(stat -c %a /run/sentinel/witness.json) = 600")
    witness.succeed("! grep -rq '${secret}' /var/lib/sentinel /run/sentinel")
    # The printed key is what this witness was given.
    printed=primary.succeed("printf %s '${secret}' | sentinel ha witness-key --secret-stdin")
    assert 'key = "b080d20c3e5dfd7ba3cfc3f7a2713448f452ebd8b56a9ef6dac76ff570b69da8"' in printed and 'cluster = "${cluster}"' in printed, printed
    # A credential failure must happen before either document changes.
    before=primary.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0]
    primary.fail("printf %s wrong-credential-with-at-least-32-bytes | sentinel ha pair 10.3.0.2:8080 --witness 10.3.0.3:5440 --secret-stdin")
    # A token on the command line is refused outright, not merely discouraged.
    refused=primary.fail("sentinel ha pair 10.3.0.2:8080 --witness 10.3.0.3:5440 --secret ${secret} 2>&1")
    assert "process list" in refused, refused
    assert primary.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0]==before
    started=time.monotonic()
    primary.succeed("su admin -c " + shlex.quote("printf %s '${secret}' | sentinel ha pair 10.3.0.2:8080 --witness 10.3.0.3:5440 --secret-stdin"))
    assert time.monotonic()-started<30,"one-command HA pairing exceeded 30 seconds"
    primary.wait_until_succeeds("ip -o addr show eth1 | grep -q 10.1.0.100",timeout=20)
    secondary.wait_until_succeeds(python_command('import json; assert json.load(open("/run/velstra/ha/agent.json"))["ready_term"] > 0'),timeout=20)
    primary.succeed("test ! -e /var/lib/sentinel/ha-pair.json")
    # Repeating a completed enrollment must retain the same member identities.
    primary.succeed("echo '${secret}' | sentinel ha pair 10.3.0.2:8080 --witness 10.3.0.3:5440 --secret-stdin")
    for node,number,address in [(primary,1,"10.1.0.1/24"),(secondary,2,"10.1.0.2/24")]:
        config=json.loads(node.succeed(python_command('import tomllib,json; print(json.dumps(tomllib.load(open("/var/lib/sentinel/appliance.toml","rb"))))')))
        assert config["system"]["ha"]["node"]==number
        assert next(i for i in config["interface"] if i["name"]=="eth1")["address"]==address
    # A local change is automatically delivered with the secondary's facts.
    primary.succeed("printf '%s\\n' 'set interface eth1 mtu 1400' commit save exit | sentinel configure")
    secondary.wait_until_succeeds("ip -o link show eth1 | grep -q 'mtu 1400'",timeout=30)
    secondary.succeed("ip -o addr show eth1 | grep -q 10.1.0.2")
    # HA actor replacement keeps the control query route and waits for the
    # previous coordinator's lock before binding the new generation.
    primary.succeed("printf '%s\\n' 'set system ha priority 210' 'set protocols vrrp wan priority 210' 'set system ha preempt true' 'set protocols vrrp wan preempt true' commit save exit | sentinel configure")
    wait_role(primary,"Master")
    wait_role(secondary,"Backup")
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
        node.shutdown()
        node.start()
        for unit in ("multi-user.target","sentinel-boot.service","velstra.service","wren.service","sentinel-api.service"):
            node.wait_for_unit(unit)
        node.wait_until_succeeds(python_command('import json; assert json.load(open("/run/velstra/ha/agent.json"))["ready_term"] > 0'),timeout=30)
        if node is secondary:
            wait_role(primary,"Master")
            wait_role(secondary,"Backup")
        else:
            wait_role(secondary,"Master")
            wait_role(primary,"Backup")
        node.succeed("tc filter show dev eth1 ingress | grep -q bpf; tc filter show dev eth1 egress | grep -q bpf")
        node.succeed("curl -ksf -H 'Authorization: Bearer ${secret}' https://127.0.0.1:8080/api/v1/status >/dev/null")
    # Enabling preemption live permits takeover only after full state import.
    primary.succeed("printf '%s\\n' 'set system ha preempt true' 'set protocols vrrp wan preempt true' commit save exit | sentinel configure")
    wait_role(primary,"Master")
    wait_role(secondary,"Backup")
    primary.succeed("printf '%s\\n' 'set interface eth1 mtu 1420' commit save exit | sentinel configure")
    secondary.wait_until_succeeds("ip -o link show eth1 | grep -q 'mtu 1420'",timeout=30)

  '';
}
