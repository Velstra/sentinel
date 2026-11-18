# Same live endpoint workload and resource limits as nat-capacity-pressure-test.
# This isolates endpoint/probe pressure from Sentinel; green is not product green.
{ pkgs, self }:
let
  shared = ./nat-capacity-pressure-probe.py;
  oracle = ./nat-pressure-reference-oracle.py;
  command = "${pkgs.python3}/bin/python3 -B ${shared}";
in pkgs.testers.runNixOSTest {
  name = "sentinel-nat-pressure-netfilter-reference-20000";
  globalTimeout = 600;
  nodes = {
    client = {
      virtualisation = { vlans = [ 2 ]; memorySize = 768; };
      services.timesyncd.enable = false;
      networking = {
        useNetworkd = true;
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1.ipv4.addresses = [{ address = "198.18.20.50"; prefixLength = 24; }];
        defaultGateway = { address = "198.18.20.1"; interface = "eth1"; };
      };
      environment.systemPackages = [ pkgs.python3 pkgs.iproute2 ];
      systemd.services.qa-capacity-client = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig = {
          ExecStart = "${command} client --source 198.18.20.50 --public 198.18.10.100 --target 198.18.10.253 --target 198.18.10.254";
          LimitNOFILE = 65536;
        };
      };
    };
    backend = {
      virtualisation = { vlans = [ 1 ]; memorySize = 768; };
      services.timesyncd.enable = false;
      networking = {
        useNetworkd = true;
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1.ipv4.addresses = [
          { address = "198.18.10.253"; prefixLength = 24; }
          { address = "198.18.10.254"; prefixLength = 24; }
        ];
      };
      environment.systemPackages = [ pkgs.python3 pkgs.iproute2 ];
      systemd.services.qa-capacity-peer = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig = {
          ExecStart = "${command} serve --address 198.18.10.253 --address 198.18.10.254";
          LimitNOFILE = 65536;
        };
      };
    };
    fw = {
      boot.kernelPackages = self.nixosConfigurations.appliance.config.boot.kernelPackages;
      boot.kernel.sysctl."net.ipv4.ip_forward" = 1;
      virtualisation = { vlans = [ 1 2 ]; memorySize = 1536; cores = 2; };
      services.timesyncd.enable = false;
      networking = {
        useNetworkd = true;
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1.ipv4.addresses = [{ address = "198.18.10.100"; prefixLength = 24; }];
        interfaces.eth2.ipv4.addresses = [{ address = "198.18.20.1"; prefixLength = 24; }];
        nftables = {
          enable = true;
          ruleset = ''
            table ip qa_pressure {
              chain forward {
                type filter hook forward priority 0; policy drop;
                ct state invalid counter drop
                ct state established,related counter accept
                iifname "eth2" oifname "eth1" ip saddr 198.18.20.0/24 counter accept
              }
              chain postrouting {
                type nat hook postrouting priority 100; policy accept;
                oifname "eth1" ip saddr 198.18.20.0/24 meta l4proto tcp counter masquerade to :32768-65535
              }
            }
          '';
        };
      };
      environment.etc."qa-compared-agent".text = "${self.packages.x86_64-linux.velstra}";
      environment.systemPackages = [ pkgs.python3 pkgs.iproute2 pkgs.conntrack-tools ];
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

    shared = load("pressure", "${shared}")
    oracle = load("pressure_reference", "${oracle}")
    counts = shared.validate_counts(list(oracle.PHASES))
    artifacts = Path(os.environ["out"])
    receipt: dict[str, Any] = dict(version=1, implementation="nftables-reference-only",
        scope="endpoint/probe pressure control; no Sentinel map or release qualification",
        requested_counts=counts, pressure_requested=True, pressure_complete=False,
        pressure_complete_means="requested20000 phase executed, not necessarily passed",
        probe_sha256=hashlib.sha256(Path("${shared}").read_bytes()).hexdigest(),
        oracle_sha256=hashlib.sha256(Path("${oracle}").read_bytes()).hexdigest(),
        phases=[], passed=False)

    def preserve(name, value):
        (artifacts / name).write_text(json.dumps(value, separators=(",", ":")) + "\n")

    def read_json(machine, path):
        expected = machine.succeed("sha256sum " + shlex.quote(path)).split()[0]
        target = "guest-files/" + machine.name
        machine.copy_from_machine(path, target)
        raw = (artifacts / target / Path(path).name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected, "guest artifact transport hash mismatch"
        return json.loads(raw)

    def control(action, name, count=None):
        path = "/run/qa-capacity-" + name + ".json"
        option = " --count " + str(count) if count is not None else ""
        client.succeed("${command} control --action " + action + option + " --budget 45 --output " + shlex.quote(path))
        value = read_json(client, path)
        preserve(name + ".json", value)
        return value

    def runtime_sample(name):
        samples = {}
        for machine in (client, backend, fw):
            path = "/run/qa-capacity-runtime-" + name + ".json"
            machine.succeed("${command} runtime --output " + shlex.quote(path))
            samples[machine.name] = read_json(machine, path)
        samples["firewall_statistics"] = dict(
            nftables=json.loads(fw.succeed("nft --json list ruleset")),
            conntrack_statistics=fw.succeed("conntrack -S"),
            conntrack_count=fw.succeed("sysctl -n net.netfilter.nf_conntrack_count").strip(),
            conntrack_max=fw.succeed("sysctl -n net.netfilter.nf_conntrack_max").strip())
        preserve("runtime-" + name + ".json", samples)
        return samples

    try:
        start_all()
        fw.wait_for_unit("nftables.service")
        client.wait_for_unit("qa-capacity-client.service")
        backend.wait_for_unit("qa-capacity-peer.service")
        client.wait_until_succeeds("test -S /run/qa-nat-capacity.sock", timeout=30)
        backend.wait_until_succeeds("ss -Hln sport = :9000 | grep -q 9000", timeout=30)
        for interface, address in (("eth1", "198.18.10.100/24"), ("eth2", "198.18.20.1/24")):
            fw.wait_until_succeeds("ip -4 address show " + interface + " | grep -q " + address, timeout=30)
        assert fw.succeed("sysctl -n net.ipv4.ip_forward").strip() == "1"
        fw.fail("systemctl is-active velstra.service")
        receipt["cohort"] = dict(kernel=fw.succeed("uname -r").strip(),
            nftables=fw.succeed("nft --version").strip(),
            compared_agent_not_running=fw.succeed("cat /etc/qa-compared-agent").strip())
        rules_before = fw.succeed("nft --stateless list ruleset")
        receipt["rules_sha256"] = hashlib.sha256(rules_before.encode()).hexdigest()
        (artifacts / "rules-before.nft").write_text(rules_before)
        previous = None
        for count in counts:
            with subtest("same pressure workload " + str(count)):
                runtime_before_open = runtime_sample("before-open-" + str(count))
                manifest = control("open", "flows-" + str(count), count)
                time.sleep(0.1)
                runtime_before_probe = runtime_sample("before-probe-" + str(count))
                probes = control("probe", "echo-" + str(count))
                runtime_after_probe = runtime_sample("after-probe-" + str(count))
                phase = oracle.analyse(manifest, probes, count, shared.PROBE_REVISION, previous)
                previous = manifest
                phase["runtime_observations"] = dict(before_open=runtime_before_open,
                    before_probe=runtime_before_probe, after_probe=runtime_after_probe)
                phase["client_established_sockets"] = int(client.succeed("ss -Hnt state established '( dport = :9000 )' | wc -l"))
                phase["backend_established_sockets"] = int(backend.succeed("ss -Hnt state established '( sport = :9000 )' | wc -l"))
                receipt["phases"].append(phase)
                preserve("phase-" + str(count) + "-analysis.json", phase)
                preserve("nat-pressure-reference.json", receipt)
                print("NAT-PRESSURE-REFERENCE " + json.dumps({key: phase[key] for key in (
                    "requested", "initial_nonce_echoes", "verified_held_echoes", "passed")}))
        receipt["pressure_complete"] = len(receipt["phases"]) == len(counts) and receipt["phases"][-1]["requested"] == 20000
        rules_after = fw.succeed("nft --stateless list ruleset")
        (artifacts / "rules-after.nft").write_text(rules_after)
        receipt["configuration_unchanged"] = rules_before == rules_after
        receipt["passed"] = (receipt["pressure_complete"] and receipt["configuration_unchanged"]
                             and all(phase["passed"] for phase in receipt["phases"]))
        assert receipt["passed"], "nftables endpoint pressure control failed; inspect per-flow receipts"
    except Exception as error:
        receipt["error"] = str(error)
        raise
    finally:
        preserve("nat-pressure-reference.json", receipt)
  '';
}
