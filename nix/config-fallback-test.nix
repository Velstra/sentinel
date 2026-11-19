# Never boot dark (DP-01 class, DP-17) plus the save/rollback lifecycle that
# feeds the boot config (CTRL-14, CTRL-04). The management NIC is zoned, so a
# data plane that refuses the saved configuration holds it down: the only
# honest test is a reboot with such a configuration and a client that must
# still reach SSH afterwards.
{ pkgs, self }:
let
  good = pkgs.writeText "good-appliance.toml" ''
    [system]
    hostname = "good"
    [services.ssh]
    enable = true
    [zone.lan]
    default_action = "drop"
    [zone.firewall]
    local = true
    [[interface]]
    name = "eth1"
    zone = "lan"
    address = "192.0.2.1/24"
    [[rule]]
    name = "ssh-in"
    from = "lan"
    to = "firewall"
    proto = "tcp"
    port = 22
    action = "accept"
  '';
in
pkgs.testers.runNixOSTest {
  name = "sentinel-config-fallback";
  globalTimeout = 1500;
  nodes.fw = { lib, ... }: {
    imports = [ self.nixosModules.sentinel ];
    virtualisation.memorySize = 2048;
    virtualisation.vlans = [ 1 ];
    services.velstra.appliance = lib.mkForce good;
  };
  nodes.client = { ... }: {
    virtualisation.vlans = [ 1 ];
    networking.firewall.enable = false;
    networking.interfaces.eth1.ipv4.addresses = [ { address = "192.0.2.2"; prefixLength = 24; } ];
  };
  testScript = ''
    import json, shlex

    def ssh_banner():
        return client.succeed(
            "timeout 10 bash -c 'exec 3<>/dev/tcp/192.0.2.1/22; head -c 7 <&3'"
        )

    def configure(lines, success=True):
        payload = "\n".join(lines + ["exit"]) + "\n"
        command = "printf %s " + shlex.quote(payload) + " | sentinel configure 2>&1"
        return fw.succeed(command) if success else fw.fail(command)

    def boot():
        fw.wait_for_unit("multi-user.target")
        fw.wait_for_unit("sentinel-boot-verify.service")
        fw.wait_for_unit("velstra.service")

    start_all()
    client.wait_for_unit("multi-user.target")
    boot()

    with subtest("a healthy boot is remembered as the last-known-good"):
        assert ssh_banner() == "SSH-2.0", "management must work on the good config"
        fw.fail("test -e /run/sentinel/config-fallback.json")
        assert 'hostname = "good"' in fw.succeed("cat /var/lib/sentinel/last-good.toml")

    with subtest("CTRL-14: save writes the running configuration, never an uncommitted edit"):
        before = fw.succeed("sha256sum /var/lib/sentinel/appliance.toml")
        output = configure(["set system hostname never-committed", "save"], success=False)
        assert "uncommitted" in output, output
        assert before == fw.succeed("sha256sum /var/lib/sentinel/appliance.toml")

    with subtest("commit asks the data plane first, and a refusal is journaled"):
        output = configure([
            "set nat destination game zone lan proto tcp_udp port 27015 to 192.0.2.10:27015",
            "commit",
        ], success=False)
        assert "commit ok" not in output, output
        fw.fail("grep -q game /var/lib/sentinel/appliance.toml /run/sentinel/velstra.toml")
        if "data plane refuses" in output:
            fw.succeed("journalctl -b -t sentinel-commit | grep -q 'commit refused'")
        assert ssh_banner() == "SSH-2.0"

    with subtest("CTRL-04: a rollback is what the next session starts from"):
        configure(["set system hostname second", "commit", "save"])
        configure(["set system hostname third", "commit", "save"])
        configure(["rollback 1"])
        fw.succeed("grep -q 'hostname = \"second\"' /run/sentinel/running.toml")
        shown = fw.succeed("sentinel configure <<< 'show system' 2>&1")
        assert "hostname second" in shown and "hostname third" not in shown, shown
        configure(["set interface eth1 description after-rollback", "commit"])
        fw.succeed("grep -q 'hostname = \"second\"' /run/sentinel/running.toml")
        fw.succeed("hostname | grep -x second")

    with subtest("DP-01 class: a saved config the agent refuses boots the last-known-good"):
        # As a restored backup or an upgrade would deliver it: written directly,
        # since save itself now refuses such a configuration.
        fw.succeed(
            "cp ${good} /var/lib/sentinel/appliance.toml && "
            "printf '%s\\n' '[[nat.destination]]' 'name = \"game\"' 'zone = \"lan\"' "
            "'proto = \"tcp_udp\"' 'port = 27015' 'to = \"192.0.2.10:27015\"' "
            ">> /var/lib/sentinel/appliance.toml"
        )
        fw.shutdown()
        fw.start()
        boot()
        status = json.loads(fw.succeed("cat /run/sentinel/config-fallback.json"))
        assert status["applied"] == "last-known-good", status
        assert ssh_banner() == "SSH-2.0", "management must survive a refused saved config"
        fw.fail("grep -q game /run/sentinel/running.toml")
        assert "CONFIGURATION FALLBACK" in fw.succeed("sentinel show system")
        assert "CONFIGURATION FALLBACK" in fw.succeed("sentinel configure <<< 'exit' 2>&1")
        fw.succeed("journalctl -b | grep -q 'CONFIGURATION FALLBACK'")
        fw.succeed("systemctl is-active velstra.service")

    with subtest("saving the running configuration clears the fallback"):
        configure(["save"])
        fw.fail("test -e /run/sentinel/config-fallback.json")
        fw.fail("grep -q game /var/lib/sentinel/appliance.toml")

    with subtest("DP-17: a config only the kernel load refuses still boots reachable"):
        fw.succeed("cp ${good} /var/lib/sentinel/appliance.toml")
        fw.succeed(
            "for i in $(seq 0 8999); do printf '[[rule]]\\nname = \"bulk%d\"\\nfrom = \"lan\"\\n"
            "proto = \"tcp\"\\nport = %d\\naction = \"drop\"\\n' $i $((10000 + i)); done "
            ">> /var/lib/sentinel/appliance.toml"
        )
        assert fw.succeed("grep -c '^name = \"bulk' /var/lib/sentinel/appliance.toml").strip() == "9000"
        fw.shutdown()
        fw.start()
        boot()
        status = json.loads(fw.succeed("cat /run/sentinel/config-fallback.json"))
        assert status["applied"] in ("last-known-good", "management-only"), status
        assert ssh_banner() == "SSH-2.0", "management must survive a map that fills at load"
        fw.fail("grep -q bulk /run/sentinel/running.toml")
        print("DP-17 fallback stage: " + status["stage"])
  '';
}
