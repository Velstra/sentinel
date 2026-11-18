# Explicitly disposable injection: remove one precisely identified unrelated
# reservation, then send on the ninth ORIGINAL socket. Never a GC/race claim.
{ pkgs, self }:
let
  lib = pkgs.lib;
  shared = ./nat-capacity-pressure-probe.py;
  collision = ./nat-admission-collision-probe.py;
  probe = ./nat-domain-hole-probe.py;
  command = "${pkgs.python3}/bin/python3 -B ${shared}";
  hole = "${pkgs.python3}/bin/python3 -B ${probe} --shared-probe ${shared} --collision-probe ${collision}";
in pkgs.testers.runNixOSTest {
  name = "sentinel-nat-domain-earlier-hole-preserves-ninth-socket";
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
      systemd.services.qa-hole-client = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig = { ExecStart = "${hole} client"; LimitNOFILE = 65536; };
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
      systemd.services.qa-hole-peer = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig = { ExecStart = "${command} serve --address 198.18.10.254"; LimitNOFILE = 65536; };
      };
    };
    fw = {
      imports = [ self.nixosModules.sentinel ];
      boot.kernelPackages = self.nixosConfigurations.appliance.config.boot.kernelPackages;
      virtualisation = { vlans = [ 1 2 ]; memorySize = 1536; cores = 2; };
      networking.firewall.enable = lib.mkForce false;
      services.timesyncd.enable = lib.mkForce false;
      environment.etc."sentinel-qa-nat-domain-hole".text = "disposable-nat-domain-hole-fixture-v1\n";
      services.velstra = {
        interface = lib.mkForce "eth1";
        appliance = lib.mkForce ((pkgs.formats.toml {}).generate "nat-domain-hole.toml" {
          system.hostname = "nat-domain-hole-fixture";
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

    shared = load("hole_shared", "${shared}")
    oracle = load("hole_oracle", "${probe}")
    premise = load("hole_collision", "${collision}").proof()
    artifacts = Path(os.environ["out"])
    receipt: dict[str, Any] = dict(version=1, scope="disposable unrelated-key deletion and original ninth TCP socket; not concurrent GC or pressure qualification", passed=False)

    def preserve(name, value):
        (artifacts / name).write_text(json.dumps(value, separators=(",", ":")) + "\n")

    def read_json(machine, path):
        expected = machine.succeed("sha256sum " + shlex.quote(path)).split()[0]
        directory = "guest-files/" + machine.name
        machine.copy_from_machine(path, directory)
        raw = (artifacts / directory / Path(path).name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected, "guest artifact transport hash mismatch"
        return json.loads(raw)

    def collect(machine, verb, name, options=""):
        path = "/run/qa-hole-" + name + ".json"
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
        client.wait_for_unit("qa-hole-client.service")
        backend.wait_for_unit("qa-hole-peer.service")
        client.wait_until_succeeds("test -S /run/qa-nat-capacity.sock", timeout=30)
        backend.wait_until_succeeds("ss -Hln sport = :9000 | grep -q 9000", timeout=30)
        fw.wait_until_succeeds("${command} snapshot --output /run/qa-hole-initial.json", timeout=30)
        initial = read_json(fw, "/run/qa-hole-initial.json")
        fw.succeed("systemctl restart velstra.service")
        fw.wait_until_succeeds("${command} snapshot --output /run/qa-hole-baseline.json", timeout=30)
        baseline = read_json(fw, "/run/qa-hole-baseline.json")
        assert all(ids(initial)[name] != ids(baseline)[name] for name in shared.MAP_LAYOUTS)
        assert all(baseline["maps"][name]["raw_count"] == 0 for name in ("CONNTRACK", "FW_FLOWS", "SYN_FLOWS"))
        for name in ("eth1", "eth2"):
            fw.wait_until_succeeds("ip -details link show " + name + " | grep -q prog/xdp", timeout=30)
        fw.succeed("sentinel config check /var/lib/sentinel/appliance.toml")
        config_hash = fw.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0]
        receipt["cohort"] = dict(sentinel="${self.packages.x86_64-linux.sentinel}",
                                 agent="${self.packages.x86_64-linux.velstra}",
                                 object="${self.packages.x86_64-linux.velstra-ebpf}",
                                 kernel=fw.succeed("uname -r").strip(), config_hash=config_hash)
        manifest = collect(client, "control", "flows", " --action open --count 9 --budget 30")
        before_echo = collect(client, "control", "before-echo", " --action probe --budget 30")
        receipt["before_echo"] = oracle.transport(premise, manifest, before_echo, 1)
        # No application traffic on the unrelated victim socket after admission.
        # Let delayed ACKs settle; this pause is NOT a concurrent writer fence.
        time.sleep(0.2)
        before = collect(fw, "snapshot", "before-maps")
        before_bindings = oracle.bindings(shared, premise, manifest, before)
        fw.succeed("printf '%s\\n' " + shlex.quote(json.dumps(manifest)) + " > /run/qa-hole-client-manifest.json")
        fw.succeed("${hole} delete-earlier --manifest /run/qa-hole-client-manifest.json --snapshot /run/qa-hole-before-maps.json --output /run/qa-hole-deletion.json")
        deletion = read_json(fw, "/run/qa-hole-deletion.json")
        preserve("deletion.json", deletion)
        receipt["deletion"] = {key: deletion[key] for key in ("scope", "map_id", "removed", "selected_before")}
        after_echo = collect(client, "control", "after-echo", " --action probe --budget 30")
        after_manifest = collect(client, "control", "after-manifest", " --action manifest")
        receipt["after_echo"] = oracle.transport(premise, after_manifest, after_echo, 2, manifest)
        after = collect(fw, "snapshot", "after-maps")
        after_bindings = oracle.bindings(shared, premise, after_manifest, after, missing=(0,))
        assert ids(before) == ids(deletion["after"]) == ids(after) == ids(baseline)
        assert deletion["removed"] == before_bindings[0]
        assert deletion["selected_before"] == before_bindings[8]
        assert {row["key"] for row in after_bindings.values()} == {row["key"] for row in before_bindings.values()} - {before_bindings[0]["key"]}
        assert after_bindings[8]["key"] == before_bindings[8]["key"], "selected flow moved to earlier vacancy"
        receipt["configuration_unchanged"] = fw.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0] == config_hash
        receipt["passed"] = receipt["configuration_unchanged"]
        assert receipt["passed"]
    except Exception as error:
        receipt["error"] = str(error)
        raise
    finally:
        preserve("nat-domain-hole.json", receipt)
  '';
}
