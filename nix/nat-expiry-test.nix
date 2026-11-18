{ pkgs, self }:
let
  inherit (pkgs) lib;
  command = "${pkgs.python3}/bin/python3 -B ${./nat-expiry-probe.py} --support ${./icmp-nat-ownership-probe.py}";
  endpoint = vlan: address: {
    virtualisation = { vlans = [ vlan ]; memorySize = 512; };
    services.timesyncd.enable = false;
    networking = {
      useNetworkd = true;
      useDHCP = false;
      firewall.enable = false;
      interfaces.eth1.ipv4.addresses = [{ inherit address; prefixLength = 24; }];
    };
  };
in pkgs.testers.runNixOSTest {
  name = "sentinel-nat-expiry-read-only";
  globalTimeout = 240;
  nodes = {
    client = lib.recursiveUpdate (endpoint 2 "198.18.20.50") {
      networking.defaultGateway = { address = "198.18.20.1"; interface = "eth1"; };
    };
    remote = endpoint 1 "198.18.10.254";
    fw = {
      imports = [ self.nixosModules.sentinel ];
      boot.kernelPackages = self.nixosConfigurations.appliance.config.boot.kernelPackages;
      virtualisation = { vlans = [ 1 2 ]; memorySize = 1536; cores = 2; };
      networking.firewall.enable = lib.mkForce false;
      services.timesyncd.enable = lib.mkForce false;
      systemd.tmpfiles.rules = [ "f /run/qa-nat-expiry-disposable 0600 root root - disposable-test-only" ];
      services.velstra = {
        interface = lib.mkForce "eth1";
        appliance = lib.mkForce ((pkgs.formats.toml {}).generate "nat-expiry.toml" {
          system.hostname = "nat-expiry-fixture";
          # Explicit permits isolate ordinary expiry probes. The shadow case
          # has NO matching permit: only its live canonical state can admit it.
          zone.lan = { default_action = "accept"; stateful = false; };
          zone.wan = { default_action = "drop"; stateful = true; };
          rule = [
            { name = "tcp-probes"; from = "wan"; proto = "tcp"; port = "45000-45002"; action = "accept"; }
            { name = "udp-probes"; from = "wan"; proto = "udp"; port = "45000-45002"; action = "accept"; }
            { name = "icmp-probes"; from = "wan"; proto = "icmp"; action = "accept"; }
          ];
          interface = [
            { name = "eth0"; address = "dhcp"; }
            { name = "eth1"; address = "198.18.10.100/24"; zone = "wan"; }
            { name = "eth2"; address = "198.18.20.1/24"; zone = "lan"; }
          ];
          nat.destination = [{
            name = "reuse-guard"; zone = "wan"; proto = "udp";
            port = 45003; to = "198.18.20.50:46003";
          }];
        });
      };
      environment.systemPackages = [ pkgs.python3 pkgs.bpftools ];
    };
  };
  testScript = ''
    import hashlib, importlib.util, json, os, shlex, time, uuid
    from pathlib import Path
    from typing import Any

    spec = importlib.util.spec_from_file_location("nat_expiry", "${./nat-expiry-probe.py}")
    assert spec is not None and spec.loader is not None
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    artifacts = Path(os.environ["out"])
    receipt: dict[str, Any] = {"passed": False, "cases": [], "scope": "seeded NAT age; not concurrent refresh, GC or pressure qualification"}

    def read(machine, path):
        expected = machine.succeed("sha256sum " + shlex.quote(path)).split()[0]
        directory = "guest-files/" + machine.name
        machine.copy_from_machine(path, directory)
        raw = (artifacts / directory / Path(path).name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected
        return json.loads(raw)

    def preserve():
        (artifacts / "nat-expiry.json").write_text(json.dumps(receipt, indent=2, sort_keys=True))

    try:
        start_all()
        fw.wait_for_unit("sentinel-boot.service")
        for machine, address in ((fw, "198.18.10.100"), (remote, "198.18.10.254"), (client, "198.18.20.50")):
            machine.wait_until_succeeds("ip -4 address show dev eth1 | grep -F " + address + "/24")
        fw.wait_until_succeeds("sentinel show firewall statistics >/dev/null")
        config = fw.succeed("sha256sum /var/lib/sentinel/appliance.toml")
        receipt["kernel"] = fw.succeed("uname -r").strip()
        receipt["service_exec"] = fw.succeed("systemctl show velstra.service --property ExecStart --value").strip()
        for protocol, proto in probe.PROTOCOLS.items():
            for case in (*probe.CASES, probe.REUSE, probe.SHADOW) if proto == 17 else probe.CASES:
                with subtest(protocol + "-" + case):
                    prefix = "/run/nat-expiry-" + protocol + "-" + case
                    nonce = "nat-expiry-" + uuid.uuid4().hex
                    command = "${command} --protocol " + protocol + " --case " + case
                    fw.succeed(command + " seed --output " + prefix + "-before.json")
                    before = read(fw, prefix + "-before.json")
                    for machine in (client, fw):
                        unit = "nat-expiry-" + protocol + "-" + case
                        machine.succeed("systemd-run --unit " + unit + " --service-type=exec " + command
                                        + " listen --role " + machine.name + " --nonce " + nonce
                                        + " --ready " + prefix + "-ready --stop " + prefix + "-stop"
                                        + " --output " + prefix + "-capture.json")
                        machine.wait_until_succeeds("test -f " + prefix + "-ready")
                    remote.succeed(command + " send --nonce " + nonce + " --output " + prefix + "-send.json")
                    sent = read(remote, prefix + "-send.json")
                    time.sleep(1)
                    captures = {}
                    for machine in (client, fw):
                        machine.fail("test -e " + prefix + "-capture.json")
                        machine.succeed("touch " + prefix + "-stop")
                        machine.wait_until_succeeds("test -f " + prefix + "-capture.json")
                        captures[machine.name] = read(machine, prefix + "-capture.json")
                    fw.succeed(command + " inspect --output " + prefix + "-after.json")
                    after = read(fw, prefix + "-after.json")
                    row = dict(protocol=protocol, case=case, before=before, after=after, captures=captures, sent=sent,
                               passed=probe.verdict(proto, case, before, after, captures, sent))
                    receipt["cases"].append(row)
                    preserve()
                    print("NAT-EXPIRY " + json.dumps(row, sort_keys=True))
        receipt["configuration_unchanged"] = config == fw.succeed("sha256sum /var/lib/sentinel/appliance.toml")
        receipt["passed"] = receipt["configuration_unchanged"] and len(receipt["cases"]) == 11 and all(row["passed"] for row in receipt["cases"])
        assert receipt["passed"], "NAT expiry modified state or violated packet translation; see receipt"
    except Exception as error:
        receipt["error"] = str(error)
        raise
    finally:
        preserve()
  '';
}
