# Real simultaneous TCP sockets exhaust exactly one non-power-of-two CGNAT
# block. The 66th socket must fail without replacing any of the first 65.
{ pkgs, self }:
let
  lib = pkgs.lib;
  shared = ./nat-capacity-pressure-probe.py;
  oracle = ./nat-domain-probe.py;
  command = "${pkgs.python3}/bin/python3 -B ${shared}";
  sourcePorts = lib.concatMapStringsSep " " (port: "--source-port ${toString port}") (lib.range 20000 20065);
in pkgs.testers.runNixOSTest {
  name = "sentinel-nat-domain-cgnat-65-held-and-exhaustion";
  globalTimeout = 240;
  nodes = {
    client = {
      virtualisation = { vlans = [ 2 ]; memorySize = 512; };
      services.timesyncd.enable = false;
      networking = {
        useNetworkd = true;
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1.ipv4.addresses = [{ address = "198.18.20.50"; prefixLength = 24; }];
        defaultGateway = { address = "198.18.20.1"; interface = "eth1"; };
      };
      environment.systemPackages = [ pkgs.python3 pkgs.iproute2 ];
      systemd.services.qa-domain-client = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig = {
          ExecStart = "${command} client --source 198.18.20.50 --target 198.18.10.254 --public 198.18.10.100 ${sourcePorts}";
          LimitNOFILE = 65536;
        };
      };
    };
    backend = {
      virtualisation = { vlans = [ 1 ]; memorySize = 512; };
      services.timesyncd.enable = false;
      networking = {
        useNetworkd = true;
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1.ipv4.addresses = [{ address = "198.18.10.254"; prefixLength = 24; }];
      };
      environment.systemPackages = [ pkgs.python3 pkgs.iproute2 ];
      systemd.services.qa-domain-peer = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig = {
          ExecStart = "${command} serve --address 198.18.10.254";
          LimitNOFILE = 65536;
        };
      };
    };
    fw = {
      imports = [ self.nixosModules.sentinel ];
      boot.kernelPackages = self.nixosConfigurations.appliance.config.boot.kernelPackages;
      virtualisation = { vlans = [ 1 2 ]; memorySize = 1536; cores = 2; };
      networking.firewall.enable = lib.mkForce false;
      services.timesyncd.enable = lib.mkForce false;
      services.velstra = {
        interface = lib.mkForce "eth1";
        appliance = lib.mkForce ((pkgs.formats.toml {}).generate "nat-domain-cgnat.toml" {
          system.hostname = "nat-domain-fixture";
          zone.lan = { default_action = "accept"; stateful = true; };
          zone.wan = { default_action = "drop"; stateful = true; };
          interface = [
            { name = "eth0"; address = "dhcp"; }
            { name = "eth1"; address = "198.18.10.100/24"; zone = "wan"; }
            { name = "eth2"; address = "198.18.20.1/24"; zone = "lan"; }
          ];
          nat.source = [{ name = "wan-cgnat"; zone = "wan"; cgnat-block-size = 65; cgnat-base-port = 40000; }];
        });
      };
      environment.systemPackages = [ pkgs.python3 pkgs.bpftools pkgs.iproute2 ];
    };
  };
  testScript = ''
    import hashlib, importlib.util, json, os, shlex
    from pathlib import Path
    from typing import Any

    def load(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        value = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(value)
        return value

    diagnostic = load("nat_domain_shared", "${shared}")
    oracle = load("nat_domain_oracle", "${oracle}")
    counters = load("nat_domain_counters", "${./nat-failure-counters.py}")
    artifacts = Path(os.environ["out"])
    receipt: dict[str, Any] = dict(version=1, scope="real TCP CGNAT 65-port domain and refusal; not pressure or HA qualification",
                                 phases=[], passed=False)

    def preserve(name, value):
        (artifacts / name).write_text(json.dumps(value, separators=(",", ":")) + "\n")

    def read_json(machine, path):
        expected = machine.succeed("sha256sum " + shlex.quote(path)).split()[0]
        directory = "guest-files/" + machine.name
        machine.copy_from_machine(path, directory)
        raw = (artifacts / directory / Path(path).name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected, (path, "guest transport hash mismatch")
        return json.loads(raw)

    def collect(machine, verb, name, options=""):
        path = "/run/qa-domain-" + name + ".json"
        status, output = machine.execute("${command} " + verb + options + " --output " + shlex.quote(path))
        value = read_json(machine, path)
        preserve(name + ".json", value)
        assert status == 0, (name, output)
        return value

    def ids(sample):
        assert sample["complete"]
        return {name: row["metadata"]["id"] for name, row in sample["maps"].items()}

    try:
        start_all()
        for unit in ("sentinel-boot.service", "velstra.service", "wren.service"):
            fw.wait_for_unit(unit)
        client.wait_for_unit("qa-domain-client.service")
        backend.wait_for_unit("qa-domain-peer.service")
        client.wait_until_succeeds("test -S /run/qa-nat-capacity.sock", timeout=30)
        backend.wait_until_succeeds("ss -Hln sport = :9000 | grep -q 9000", timeout=30)
        fw.wait_until_succeeds("${command} snapshot --output /run/qa-domain-initial.json", timeout=30)
        initial = read_json(fw, "/run/qa-domain-initial.json")
        preserve("initial-raw-maps.json", initial)
        fw.succeed("systemctl restart velstra.service")
        fw.wait_until_succeeds("${command} snapshot --output /run/qa-domain-baseline.json", timeout=30)
        baseline = read_json(fw, "/run/qa-domain-baseline.json")
        preserve("baseline-raw-maps.json", baseline)
        assert all(ids(initial)[name] != ids(baseline)[name] for name in diagnostic.MAP_LAYOUTS)
        assert all(baseline["maps"][name]["raw_count"] == 0 for name in ("CONNTRACK", "FW_FLOWS", "SYN_FLOWS"))
        for name in ("eth1", "eth2"):
            fw.wait_until_succeeds("ip -details link show " + name + " | grep -q prog/xdp", timeout=30)
        fw.succeed("sentinel config check /var/lib/sentinel/appliance.toml")
        config_hash = fw.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0]
        receipt["cohort"] = dict(sentinel="${self.packages.x86_64-linux.sentinel}",
                                 agent="${self.packages.x86_64-linux.velstra}",
                                 object="${self.packages.x86_64-linux.velstra-ebpf}",
                                 kernel=fw.succeed("uname -r").strip(), config_hash=config_hash)
        lan_index = int(fw.succeed("cat /sys/class/net/eth2/ifindex"))
        wan_index = int(fw.succeed("cat /sys/class/net/eth1/ifindex"))
        template, previous = None, None
        for count in oracle.PHASES:
            with subtest("CGNAT exact domain real sockets " + str(count)):
                name = "count-" + str(count)
                counter_before = counters.snapshot(fw.succeed("sentinel show firewall statistics"))
                manifest = collect(client, "control", name + "-flows",
                                   " --action open --count " + str(count) + " --budget 30")
                before = collect(fw, "snapshot", name + "-before-maps")
                echoes = collect(client, "control", name + "-echoes", " --action probe --budget 30")
                after = collect(fw, "snapshot", name + "-after-maps")
                delta = counters.delta(counter_before, counters.snapshot(fw.succeed("sentinel show firewall statistics")))
                analysis = diagnostic.analyse(after, manifest, echoes, template,
                                              lan_index=lan_index, wan_index=wan_index)
                template = analysis["observed_ownership_template"]
                phase = dict(requested=count, analysis=analysis, counters=delta, passed=False)
                receipt["phases"].append(phase)
                preserve("nat-domain-cgnat.json", receipt)
                phase["transport"] = oracle.transport_result(manifest, echoes, count, previous)
                assert ids(before) == ids(after) == ids(baseline), "state-map identity changed"
                assert before["maps"]["CONNTRACK"]["raw_count"] == min(count, 65)
                assert after["maps"]["CONNTRACK"]["raw_count"] == min(count, 65)
                assert not analysis["owned_flow_failures"] and analysis["external_tuple_aliases"] == 0
                assert delta["egress_nat_claim_failed"] == 0
                if count == 66:
                    assert len(analysis["opening_failures"]) == 1 and analysis["opening_failures"][0]["id"] == 65
                    assert delta["egress_nat_no_candidate"] > 0 and delta["egress_dropped"] > 0
                else:
                    assert analysis["passed"] and delta["egress_nat_no_candidate"] == 0
                phase["passed"] = True
                previous = manifest
                preserve("nat-domain-cgnat.json", receipt)
                print("NAT-DOMAIN-CGNAT " + json.dumps(dict(requested=count, transport=phase["transport"], counters=delta)))
        receipt["configuration_unchanged"] = fw.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0] == config_hash
        receipt["passed"] = receipt["configuration_unchanged"] and len(receipt["phases"]) == 3 and all(p["passed"] for p in receipt["phases"])
        assert receipt["passed"], "CGNAT complete-domain/exhaustion regression"
    except Exception as error:
        receipt["error"] = str(error)
        raise
    finally:
        preserve("nat-domain-cgnat.json", receipt)
  '';
}
