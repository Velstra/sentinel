# Separate diagnostic: defaults to1/64 real connections, NOT20k qualification.
# Pressure invocation explicitly passes counts=[1 64 12000 16000 20000].
# lanStateful=false is a separate disposable diagnostic, never a product fix.
{ pkgs, self, counts ? [ 1 64 ], lanStateful ? true }:
let
  lib = pkgs.lib;
  probe = ./nat-capacity-pressure-probe.py;
  command = "${pkgs.python3}/bin/python3 -B ${probe}";
in pkgs.testers.runNixOSTest {
  name = "sentinel-nat-capacity-${if lanStateful then "stateful" else "lan-stateless-diagnostic"}-${toString (lib.last counts)}";
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
      imports = [ self.nixosModules.sentinel ];
      boot.kernelPackages = self.nixosConfigurations.appliance.config.boot.kernelPackages;
      virtualisation = { vlans = [ 1 2 ]; memorySize = 1536; cores = 2; };
      networking.firewall.enable = lib.mkForce false;
      services.timesyncd.enable = lib.mkForce false;
      services.velstra = {
        interface = lib.mkForce "eth1";
        appliance = lib.mkForce ((pkgs.formats.toml {}).generate "nat-capacity-diagnostic.toml" {
          system.hostname = "nat-capacity-fixture";
          zone.lan = { default_action = "accept"; stateful = lanStateful; };
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

    spec = importlib.util.spec_from_file_location("nat_capacity_diagnostic", "${probe}")
    assert spec is not None and spec.loader is not None
    diagnostic = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(diagnostic)
    counts = diagnostic.validate_counts(${builtins.toJSON counts})
    artifacts = Path(os.environ["out"])
    receipt: dict[str, Any] = dict(scope="disposable live TCP/raw-map correlation; no universal entries-per-flow or eviction-count claim",
                   probe_sha256=hashlib.sha256(Path("${probe}").read_bytes()).hexdigest(),
                   requested_counts=counts, lan_stateful=${if lanStateful then "True" else "False"},
                   pressure_requested=max(counts) == 20000, pressure_complete=False,
                   pressure_complete_means="requested20000 phase executed, not necessarily passed",
                   phases=[], passed=False)

    def read_json(machine, path):
        # Large map dumps must not travel through the command-output channel.
        # Keep the exact guest bytes and check them before parsing/analysis.
        expected = machine.succeed("sha256sum " + shlex.quote(path)).split()[0]
        target = "guest-files/" + machine.name
        machine.copy_from_machine(path, target)
        raw = (artifacts / target / Path(path).name).read_bytes()
        actual = hashlib.sha256(raw).hexdigest()
        assert actual == expected, (path, "guest artifact transport hash mismatch", expected, actual)
        return json.loads(raw)

    def preserve(name, value):
        (artifacts / name).write_text(json.dumps(value, separators=(",", ":")) + "\n")

    def map_ids(value):
        return {name: row["metadata"]["id"] for name, row in value["maps"].items()}

    def sample(name):
        path = "/run/qa-capacity-" + name + ".json"
        status, output = fw.execute("${command} snapshot --output " + shlex.quote(path))
        value = read_json(fw, path)
        preserve(name + "-raw-maps.json", value)
        assert status == 0 and value["complete"], (name, output, value.get("complete"))
        return value

    def control(action, name, count=None):
        path = "/run/qa-capacity-" + name + ".json"
        option = " --count " + str(count) if count is not None else ""
        client.succeed("${command} control --action " + action + option + " --budget 45 --output " + shlex.quote(path))
        value = read_json(client, path)
        preserve(name + ".json", value)
        return value

    def drop_counters():
        # Diagnostics only: packet drops outside the datapath's own counters
        # (softirq backlog, NIC/veth rings, qdiscs) on every host.
        result = {}
        for machine in (client, backend, fw):
            softnet = machine.succeed("cat /proc/net/softnet_stat").split("\n")
            dropped = sum(int(line.split()[1], 16) for line in softnet if line.strip())
            squeezed = sum(int(line.split()[2], 16) for line in softnet if line.strip())
            links = json.loads(machine.succeed("ip -s -j link show"))
            link = {item["ifname"]: [item["stats64"]["rx"]["dropped"], item["stats64"]["tx"]["dropped"],
                                     item["stats64"]["rx"].get("missed", 0)] for item in links if item["ifname"] != "lo"}
            qdisc = json.loads(machine.succeed("tc -s -j qdisc show"))
            qdrops = sum(int(item.get("drops", 0)) for item in qdisc)
            result[machine.name] = dict(softnet_dropped=dropped, softnet_squeezed=squeezed, link=link, qdisc_drops=qdrops)
        return result

    def drop_delta(before, after):
        out = {}
        for host, b in before.items():
            a = after[host]
            out[host] = dict(softnet_dropped=a["softnet_dropped"] - b["softnet_dropped"],
                             softnet_squeezed=a["softnet_squeezed"] - b["softnet_squeezed"],
                             qdisc_drops=a["qdisc_drops"] - b["qdisc_drops"],
                             link={k: [x - y for x, y in zip(a["link"][k], b["link"].get(k, [0, 0, 0]))]
                                   for k in a["link"]})
        return out

    def runtime_sample(name):
        # Keep workload/scheduler and kernel TCP evidence next to packet/map
        # results. A timeout with owned map state is not allocator attribution.
        samples = {}
        for machine in (client, backend, fw):
            path = "/run/qa-capacity-runtime-" + name + ".json"
            machine.succeed("${command} runtime --output " + shlex.quote(path))
            samples[machine.name] = read_json(machine, path)
        samples["firewall_statistics"] = fw.succeed("sentinel show firewall statistics")
        preserve("runtime-" + name + ".json", samples)
        return samples

    try:
        start_all()
        for unit in ("sentinel-boot.service", "velstra.service", "wren.service"):
            fw.wait_for_unit(unit)
        backend.wait_for_unit("qa-capacity-peer.service")
        client.wait_for_unit("qa-capacity-client.service")
        client.wait_until_succeeds("test -S /run/qa-nat-capacity.sock", timeout=30)
        fw.succeed("sentinel config check /var/lib/sentinel/appliance.toml")
        fw.wait_until_succeeds("ip -4 address show eth1 | grep -q 198.18.10.100/24", timeout=30)
        fw.wait_until_succeeds("ip -4 address show eth2 | grep -q 198.18.20.1/24", timeout=30)
        receipt["cohort"] = dict(sentinel="${self.packages.x86_64-linux.sentinel}",
                                 agent="${self.packages.x86_64-linux.velstra}",
                                 object="${self.packages.x86_64-linux.velstra-ebpf}",
                                 kernel=fw.succeed("uname -r").strip(),
                                 config_hash=fw.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0])
        # The first snapshot supplies old IDs only. A real agent restart must
        # create new maps, so no earlier load-test bindings contaminate this run.
        # The appliance's agent persists its state across restarts (DP-27), so
        # release what it pinned while it is stopped to get fresh maps.
        fw.wait_until_succeeds("${command} snapshot --output /run/qa-capacity-initial.json", timeout=30)
        initial = read_json(fw, "/run/qa-capacity-initial.json")
        preserve("initial-raw-maps.json", initial)
        fw.succeed("systemctl stop velstra.service")
        fw.succeed("${self.packages.x86_64-linux.velstra}/bin/velstra release-datapath")
        fw.succeed("systemctl start velstra.service")
        fw.wait_until_succeeds("${command} snapshot --output /run/qa-capacity-baseline.json", timeout=30)
        baseline = read_json(fw, "/run/qa-capacity-baseline.json")
        preserve("baseline-raw-maps.json", baseline)
        receipt["initial_map_ids"], receipt["baseline_map_ids"] = map_ids(initial), map_ids(baseline)
        assert all(map_ids(initial)[name] != map_ids(baseline)[name] for name in diagnostic.MAP_LAYOUTS), "agent restart reused old map identity"
        assert all(baseline["maps"][name]["raw_count"] == 0 for name in ("CONNTRACK", "FW_FLOWS", "SYN_FLOWS")), "refusing a contaminated state-map baseline"
        fw.wait_until_succeeds("ip -details link show eth1 | grep -q prog/xdp", timeout=30)
        fw.wait_until_succeeds("ip -details link show eth2 | grep -q prog/xdp", timeout=30)
        template = None
        lan_index = int(fw.succeed("cat /sys/class/net/eth2/ifindex"))
        wan_index = int(fw.succeed("cat /sys/class/net/eth1/ifindex"))
        for count in counts:
            with subtest("nonce-verified held TCP flows " + str(count)):
                runtime_before_open = runtime_sample("before-open-" + str(count))
                manifest = control("open", "flows-" + str(count), count)
                time.sleep(0.1)  # Let final handshake/ACK work quiesce before the batch walks.
                before = sample("before-" + str(count))
                runtime_before_probe = runtime_sample("before-probe-" + str(count))
                drops_before = drop_counters()
                probes = control("probe", "echo-" + str(count))
                drops_after = drop_counters()
                runtime_after_probe = runtime_sample("after-probe-" + str(count))
                after = sample("after-" + str(count))
                analysis = diagnostic.analyse(before, manifest, probes, template,
                                              lan_index=lan_index, wan_index=wan_index)
                template = analysis["observed_ownership_template"]
                analysis["map_ids_unchanged"] = map_ids(before) == map_ids(after) == map_ids(baseline)
                analysis["runtime_observations"] = dict(before_open=runtime_before_open,
                    before_probe=runtime_before_probe, after_probe=runtime_after_probe)
                analysis["client_established_sockets"] = int(client.succeed("ss -Hnt state established '( dport = :9000 )' | wc -l"))
                analysis["backend_established_sockets"] = int(backend.succeed("ss -Hnt state established '( sport = :9000 )' | wc -l"))
                analysis["passed"] = analysis["passed"] and analysis["map_ids_unchanged"]
                receipt["phases"].append(analysis)
                preserve("phase-" + str(count) + "-analysis.json", analysis)
                preserve("nat-capacity-pressure.json", receipt)
                # Diagnostics only (no pass criterion): what kind of failure each
                # unverified held echo was, and the TCP/softirq counters that
                # separate a probe-side bottleneck from a datapath drop.
                kinds = {}
                for row in probes["rows"]:
                    if row.get("verified") is not True:
                        failure = row.get("failure") or {}
                        tag = str(failure.get("stage")) + "/" + str(failure.get("kind"))
                        kinds[tag] = kinds.get(tag, 0) + 1
                def tcp_delta(name):
                    out = {}
                    for host in ("client", "backend", "fw"):
                        a = runtime_before_probe.get(host, {}).get("netstat", {})
                        b = runtime_after_probe.get(host, {}).get("netstat", {})
                        sa, sb = runtime_before_probe.get(host, {}).get("snmp", {}), runtime_after_probe.get(host, {}).get("snmp", {})
                        row = {}
                        for group, key, x, y in (("TcpExt", k, a, b) for k in ("ListenOverflows", "ListenDrops", "TCPBacklogDrop", "TCPTimeouts", "TCPAbortOnTimeout", "TCPLossProbes", "TCPRcvQDrop", "PAWSEstab")):
                            try:
                                row[key] = int(y[group][key]) - int(x[group][key])
                            except (KeyError, TypeError, ValueError):
                                pass
                        for key in ("RetransSegs", "InErrs", "OutRsts", "EstabResets", "InCsumErrors"):
                            try:
                                row[key] = int(sb["Tcp"][key]) - int(sa["Tcp"][key])
                            except (KeyError, TypeError, ValueError):
                                pass
                        out[host] = row
                    return out
                print("NAT-CAPACITY-DIAG " + json.dumps({"requested": count, "failure_kinds": kinds,
                    "probe_keys": sorted(k for k in probes if k != "rows"),
                    "tcp_delta_during_probe": tcp_delta(count),
                    "drops_during_probe": drop_delta(drops_before, drops_after)}, sort_keys=True, default=str))
                print("NAT-CAPACITY-PHASE " + json.dumps({key: analysis[key] for key in (
                    "requested", "initial_nonce_echoes", "verified_held_echoes", "raw_maps", "passed")}, sort_keys=True))
        receipt["pressure_complete"] = counts[-1] == 20000 and receipt["phases"][-1]["requested"] == 20000
        receipt["configuration_unchanged"] = fw.succeed("sha256sum /var/lib/sentinel/appliance.toml").split()[0] == receipt["cohort"]["config_hash"]
        receipt["passed"] = receipt["configuration_unchanged"] and all(phase["passed"] for phase in receipt["phases"])
        preserve("nat-capacity-pressure.json", receipt)
        assert receipt["passed"], "held connection/admission/map-ownership failure; inspect preserved per-flow receipts (an expected bug is not a pass)"
    except Exception as error:
        receipt["error"] = str(error)
        raise
    finally:
        preserve("nat-capacity-pressure.json", receipt)
  '';
}
