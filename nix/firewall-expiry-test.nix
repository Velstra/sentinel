{ pkgs, self }:
let
  inherit (pkgs) lib;
  command = "${pkgs.python3}/bin/python3 -B ${./firewall-expiry-probe.py} --support ${./icmp-nat-ownership-probe.py}";
in pkgs.testers.runNixOSTest {
  name = "sentinel-firewall-expiry-read-only";
  globalTimeout = 180;
  nodes = {
    client = {
      virtualisation = { vlans = [ 1 ]; memorySize = 512; };
      services.timesyncd.enable = false;
      networking = {
        useNetworkd = true;
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1.ipv4.addresses = [{ address = "198.18.10.254"; prefixLength = 24; }];
      };
    };
    fw = {
      imports = [ self.nixosModules.sentinel ];
      boot.kernelPackages = self.nixosConfigurations.appliance.config.boot.kernelPackages;
      virtualisation = { vlans = [ 1 ]; memorySize = 1536; cores = 2; };
      networking.firewall.enable = lib.mkForce false;
      services.timesyncd.enable = lib.mkForce false;
      systemd.tmpfiles.rules = [ "f /run/qa-firewall-expiry-disposable 0600 root root - disposable-test-only" ];
      services.velstra = {
        interface = lib.mkForce "eth1";
        appliance = lib.mkForce ((pkgs.formats.toml {}).generate "firewall-expiry.toml" {
          system.hostname = "firewall-expiry-fixture";
          zone.wan = { default_action = "drop"; stateful = true; };
          interface = [
            { name = "eth0"; address = "dhcp"; }
            { name = "eth1"; address = "198.18.10.100/24"; zone = "wan"; }
          ];
        });
      };
      environment.systemPackages = [ pkgs.python3 pkgs.bpftools ];
    };
  };
  testScript = ''
    import hashlib, importlib.util, json, os, shlex, time, uuid
    from pathlib import Path
    from typing import Any

    spec = importlib.util.spec_from_file_location("expiry", "${./firewall-expiry-probe.py}")
    assert spec is not None and spec.loader is not None
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    artifacts = Path(os.environ["out"])
    receipt: dict[str, Any] = {"passed": False, "cases": [], "scope": "seeded directional ages, not a concurrent race"}

    def read(path):
        expected = fw.succeed("sha256sum " + shlex.quote(path)).split()[0]
        fw.copy_from_machine(path, "guest-files")
        raw = (artifacts / "guest-files" / Path(path).name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected
        return json.loads(raw)

    def preserve():
        (artifacts / "firewall-expiry.json").write_text(json.dumps(receipt, indent=2, sort_keys=True))

    try:
        start_all()
        fw.wait_for_unit("sentinel-boot.service")
        client.wait_for_unit("systemd-networkd.service")
        fw.wait_until_succeeds("sentinel show firewall statistics >/dev/null")
        for machine, address in ((fw, "198.18.10.100"), (client, "198.18.10.254")):
            machine.wait_until_succeeds("ip -4 address show dev eth1 | grep -F " + address + "/24")
        config = fw.succeed("sha256sum /var/lib/sentinel/appliance.toml")
        receipt["kernel"] = fw.succeed("uname -r").strip()
        receipt["service_exec"] = fw.succeed("systemctl show velstra.service --property ExecStart --value").strip()
        for case in probe.CASES:
            with subtest(case):
                prefix = "/run/expiry-" + case
                nonce = "expiry-" + uuid.uuid4().hex
                command = "${command} --case " + case
                fw.succeed(command + " seed --output " + prefix + "-before.json")
                before = read(prefix + "-before.json")
                fw.succeed("systemd-run --unit expiry-" + case + " --service-type=exec " + command
                           + " listen --nonce " + nonce + " --ready " + prefix + "-ready --stop " + prefix
                           + "-stop --output " + prefix + "-capture.json")
                fw.wait_until_succeeds("test -f " + prefix + "-ready")
                counters_before = fw.succeed("sentinel show firewall statistics")
                client.succeed(command + " send --nonce " + nonce + " --output /run/expiry-send-" + case + ".json")
                time.sleep(1)
                fw.fail("test -e " + prefix + "-capture.json")
                fw.succeed("touch " + prefix + "-stop")
                fw.wait_until_succeeds("test -f " + prefix + "-capture.json")
                capture = read(prefix + "-capture.json")
                fw.succeed(command + " inspect --output " + prefix + "-after.json")
                after = read(prefix + "-after.json")
                counters_after = fw.succeed("sentinel show firewall statistics")
                # Background IPv6 multicast may drop even during a valid IPv4
                # probe. Attribute the positive control to established passes;
                # its exact nonce/checksum receipt remains mandatory.
                name = "established_allowed" if case == "live" else "dropped_default"
                counter_delta = probe.counter(counters_after, name) - probe.counter(counters_before, name)
                row = dict(case=case, before=before, after=after, capture=capture,
                           counters_before=counters_before, counters_after=counters_after,
                           passed=probe.verdict(case, before, after, capture)
                                  and counter_delta > 0)
                receipt["cases"].append(row)
                preserve()
                print("FIREWALL-EXPIRY " + json.dumps(row, sort_keys=True))
        receipt["configuration_unchanged"] = config == fw.succeed("sha256sum /var/lib/sentinel/appliance.toml")
        receipt["passed"] = receipt["configuration_unchanged"] and all(row["passed"] for row in receipt["cases"])
        assert receipt["passed"], "expiry classification deleted state or violated packet verdict; see receipt"
    except Exception as error:
        receipt["error"] = str(error)
        raise
    finally:
        preserve()
  '';
}
