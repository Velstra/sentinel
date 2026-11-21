# Low-occupancy regression: nine real sockets must coexist. The old allocator
# gives these distinct sources the same eight candidates; expected loss is RED.
{ pkgs, self }:
let
  lib = pkgs.lib;
  shared = ./nat-capacity-pressure-probe.py;
  collision = ./nat-admission-collision-probe.py;
  command = "${pkgs.python3}/bin/python3 -B ${shared}";
in pkgs.testers.runNixOSTest {
  name = "sentinel-nat-admission-nine-colliding-flows";
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
      systemd.services.qa-collision-client = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig = {
          ExecStart = "${pkgs.python3}/bin/python3 -B ${collision} --shared-probe ${shared}";
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
      systemd.services.qa-collision-peer = {
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
        appliance = lib.mkForce ((pkgs.formats.toml {}).generate "nat-admission-collision.toml" {
          system.hostname = "nat-admission-fixture";
          zone.lan = { default_action = "accept"; stateful = true; };
          zone.wan = { default_action = "drop"; stateful = true; };
          interface = [
            { name = "eth0"; address = "dhcp"; }
            { name = "eth1"; address = "198.18.10.100/24"; zone = "wan"; }
            { name = "eth2"; address = "198.18.20.1/24"; zone = "lan"; }
          ];
          nat.source = [{ name = "wan-masquerade"; zone = "wan"; }];
        });
      };
      environment.systemPackages = [ pkgs.python3 pkgs.bpftools pkgs.iproute2 ];
    };
  };
  testScript = ''
    import hashlib, importlib.util, json, os, shlex, time
    from pathlib import Path
    from typing import Any

    def load(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        value = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(value)
        return value

    diagnostic = load("nat_collision_shared", "${shared}")
    premise = load("nat_collision_premise", "${collision}").proof()
    counters = load("nat_failure_counters", "${./nat-failure-counters.py}")
    artifacts = Path(os.environ["out"])
    receipt: dict[str, Any] = dict(version=1, scope="nine real sequential NAT admissions, not pressure qualification",
                                 premise=premise, phases=[], passed=False)

    def preserve(name, value):
        (artifacts / name).write_text(json.dumps(value, separators=(",", ":")) + "\n")

    def read_json(machine, path):
        expected = machine.succeed("sha256sum " + shlex.quote(path)).split()[0]
        directory = "guest-files/" + machine.name
        machine.copy_from_machine(path, directory)
        raw = (artifacts / directory / Path(path).name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected, (path, "guest transport hash mismatch")
        return json.loads(raw)

    def collect(machine, role, verb, name, options=""):
        path = "/run/qa-collision-" + name + ".json"
        status, output = machine.execute("${command} " + verb + options + " --output " + shlex.quote(path))
        value = read_json(machine, path)
        preserve(role + "-" + name + ".json", value)
        assert status == 0, (role, name, output)
        return value

    def ids(sample):
        assert sample["complete"]
        return {name: row["metadata"]["id"] for name, row in sample["maps"].items()}

    def runtimes(name):
        return {role: collect(machine, role, "runtime", name + "-runtime")
                for role, machine in (("client", client), ("backend", backend), ("fw", fw))}

    try:
        start_all()
        for unit in ("sentinel-boot.service", "velstra.service", "wren.service"):
            fw.wait_for_unit(unit)
        client.wait_for_unit("qa-collision-client.service")
        backend.wait_for_unit("qa-collision-peer.service")
        client.wait_until_succeeds("test -S /run/qa-nat-capacity.sock", timeout=30)
        backend.wait_until_succeeds("ss -Hln sport = :9000 | grep -q 9000", timeout=30)
        fw.wait_until_succeeds("${command} snapshot --output /run/qa-collision-initial.json", timeout=30)
        initial = read_json(fw, "/run/qa-collision-initial.json")
        preserve("initial-raw-maps.json", initial)
        fw.succeed("systemctl restart velstra.service")
        fw.wait_until_succeeds("${command} snapshot --output /run/qa-collision-baseline.json", timeout=30)
        baseline = read_json(fw, "/run/qa-collision-baseline.json")
        preserve("baseline-raw-maps.json", baseline)
        receipt["initial_map_ids"], receipt["baseline_map_ids"] = ids(initial), ids(baseline)
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
        template = None
        for count in (1, 8, 9):
            with subtest("sequential real nonce echo admissions " + str(count)):
                prefix = "count-" + str(count)
                runtime_before = runtimes(prefix + "-before")
                counter_before = counters.snapshot(fw.succeed("sentinel show firewall statistics"))
                manifest = collect(client, "client", "control", prefix + "-flows",
                                   " --action open --count " + str(count) + " --budget 30")
                time.sleep(0.1)
                before = collect(fw, "fw", "snapshot", prefix + "-before-maps")
                echoes = collect(client, "client", "control", prefix + "-echoes", " --action probe --budget 30")
                after = collect(fw, "fw", "snapshot", prefix + "-after-maps")
                runtime_after = runtimes(prefix + "-after")
                analysis = diagnostic.analyse(before, manifest, echoes, template,
                                              lan_index=lan_index, wan_index=wan_index)
                counter_after = counters.snapshot(fw.succeed("sentinel show firewall statistics"))
                analysis["nat_failure_counter_before"] = counter_before
                analysis["nat_failure_counter_after"] = counter_after
                analysis["nat_failure_counter_delta"] = counters.delta(counter_before, counter_after)
                template = analysis["observed_ownership_template"]
                analysis["map_ids_unchanged"] = ids(before) == ids(after) == ids(baseline)
                analysis["runtime_before"], analysis["runtime_after"] = runtime_before, runtime_after
                analysis["source_endpoints_recorded_before_connect"] = all("source" in row for row in manifest["attempts"])
                analysis["wire_ports_observed"] = [row["wire_peer"][1] for row in manifest["attempts"] if row.get("initial_echo")]
                analysis["passed"] = analysis["passed"] and analysis["map_ids_unchanged"] and analysis["source_endpoints_recorded_before_connect"]
                receipt["phases"].append(analysis)
                preserve("nat-admission-collision.json", receipt)
                print("NAT-ADMISSION-COLLISION " + json.dumps({key: analysis[key] for key in (
                    "requested", "initial_nonce_echoes", "verified_held_echoes", "raw_maps", "wire_ports_observed", "nat_failure_counter_delta", "passed")}))
        receipt["configuration_unchanged"] = fw.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0] == config_hash
        receipt["passed"] = receipt["configuration_unchanged"] and all(phase["passed"] for phase in receipt["phases"])
        preserve("nat-admission-collision.json", receipt)
        assert receipt["passed"], "real NAT admission/held-state failure at negligible map occupancy; inspect preserved exact source/candidate/map evidence"
    except Exception as error:
        receipt["error"] = str(error)
        raise
    finally:
        preserve("nat-admission-collision.json", receipt)
  '';
}
