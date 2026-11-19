{ pkgs, self, probeSource ? "${self.inputs.fabric}/tests/conformance/icmp-related-probe.py" }:
let
  inherit (pkgs) lib;
  kernelPackages = self.nixosConfigurations.appliance.config.boot.kernelPackages;
  probeFile = probeSource;
  probe = pkgs.writeShellScriptBin "icmp-related-probe" ''
    exec ${pkgs.python3}/bin/python3 -B ${probeFile} "$@"
  '';
  appliance = pkgs.writeText "icmp-related-appliance.toml" ''
    [system]
    hostname="dut"
    [zone.lan]
    default_action="drop"
    [zone.wan]
    default_action="drop"
    [[interface]]
    name="eth0"
    address="dhcp"
    [[interface]]
    name="eth1"
    address="198.18.10.100/24"
    zone="wan"
    [[interface]]
    name="eth2"
    address="198.18.20.1/24"
    zone="lan"
    [[rule]]
    name="outbound-probe"
    from="lan"
    proto="udp"
    port="18199"
    action="accept"
    [[nat.source]]
    name="outbound"
    zone="wan"
    [[nat.destination]]
    name="probe"
    zone="wan"
    proto="udp"
    port=18199
    to="198.18.20.51:18199"
    hairpin=true
  '';
  namespaceSetup = pkgs.writeShellScript "icmp-related-namespaces" ''
    set -eu
    for link in eth1 eth2 eth3 eth4; do
      ${pkgs.iproute2}/bin/ip link set dev "$link" up
    done
    ${lib.concatMapStringsSep "\n" (lane: let
      wan = if lane == "dut" then "eth1" else "eth3";
      lan = if lane == "dut" then "eth2" else "eth4";
    in ''
      ip netns add ${lane}-wan
      ip link set ${wan} netns ${lane}-wan
      ip -n ${lane}-wan link set ${wan} name net0
      ip -n ${lane}-wan address add 198.18.10.254/24 dev net0
      ip -n ${lane}-wan link set lo up
      ip -n ${lane}-wan link set net0 up
      ip -n ${lane}-wan route add default via 198.18.10.100
      ${lib.concatMapStringsSep "\n" (role: let
        address = if role == "client" then "50" else "51";
        # Namespace names may be long, link names must fit Linux IFNAMSIZ.
        link = "${if lane == "dut" then "d" else "r"}-${role}";
      in ''
        ip netns add ${lane}-${role}
        ip link add ${link} link ${lan} type macvlan mode bridge
        ip link set ${link} netns ${lane}-${role}
        ip -n ${lane}-${role} link set ${link} name net0
        ip -n ${lane}-${role} address add 198.18.20.${address}/24 dev net0
        ip -n ${lane}-${role} link set lo up
        ip -n ${lane}-${role} link set net0 up
        ip -n ${lane}-${role} route add default via 198.18.20.1
      '') [ "client" "backend" ]}
    '') [ "dut" "reference" ]}
  '';
in
pkgs.testers.runNixOSTest {
  name = "sentinel-related-icmp-netfilter";
  globalTimeout = 600;
  nodes = {
    dut = {
      imports = [ self.nixosModules.sentinel ];
      networking.hostName = lib.mkForce "dut";
      networking.firewall.enable = lib.mkForce false;
      boot = { inherit kernelPackages; };
      virtualisation = { vlans = [ 1 2 ]; memorySize = 2048; cores = 4; };
      services.velstra = {
        interface = lib.mkForce "eth1";
        appliance = lib.mkForce appliance;
      };
      environment.systemPackages = [ pkgs.bpftools pkgs.tcpdump ];
    };
    reference = {
      boot = {
        inherit kernelPackages;
        kernel.sysctl = {
          "net.ipv4.ip_forward" = 1;
          "net.ipv4.conf.all.accept_local" = 0;
        };
      };
      virtualisation = { vlans = [ 3 4 ]; memorySize = 768; cores = 2; };
      networking = {
        useNetworkd = true;
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1.ipv4.addresses = [{ address = "198.18.10.100"; prefixLength = 24; }];
        interfaces.eth2.ipv4.addresses = [{ address = "198.18.20.1"; prefixLength = 24; }];
        nftables.enable = true;
      };
      environment.systemPackages = [ pkgs.nftables pkgs.conntrack-tools pkgs.tcpdump ];
    };
    endpoints = {
      boot = { inherit kernelPackages; kernelModules = [ "macvlan" ]; };
      virtualisation = { vlans = [ 1 2 3 4 ]; memorySize = 1024; cores = 2; };
      networking = {
        useNetworkd = true;
        useDHCP = false;
        firewall.enable = false;
      };
      environment.systemPackages = [ probe pkgs.iproute2 pkgs.tcpdump pkgs.python3 ];
      systemd.services.icmp-related-namespaces = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        path = [ pkgs.iproute2 ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = namespaceSetup;
        };
      };
    };
  };
  testScript = ''
    import json, os, shlex, socket, struct, time
    from pathlib import Path
    from typing import Any

    reports: list[dict[str, Any]] = []
    failures = []
    artifact = Path(os.environ["out"], "icmp-related-differential.json")
    source_port = 41000

    def oracle(mode="related", nat=True):
        # An explicit deny rule is before the RELATED rule, just as it is before
        # the exception in Sentinel. block-icmp is not: it refuses NEW ICMP, so
        # an error about a tracked flow is still delivered (audit DP-10/DP-C07).
        # UDP probe admission is independent.
        forbid = 'ip protocol icmp counter drop' if mode == "explicit-deny" else ""
        after = 'ip protocol icmp counter drop' if mode == "block-icmp" else ""
        allow = 'ip protocol icmp counter accept' if mode in ("explicit-allow", "stateful-off-allow") else ""
        tracked = 'ct state established,related counter accept' if mode not in ("stateful-off", "stateful-off-allow") else ""
        rules = """
          flush ruleset
          table inet related_filter {
            chain input {
              type filter hook input priority filter; policy drop;
              iifname "lo" accept
              iifname "eth0" accept
              %s
              %s
              %s
              %s
            }
            chain forward {
              type filter hook forward priority filter; policy drop;
              %s
              %s
              %s
              %s
              iifname "eth2" udp dport 18199 counter accept
              # Do not accidentally admit an error by inherited NAT status
              # in the negative stateful-off/explicit-deny controls.
              ct status dnat ip protocol udp counter accept
            }
          }
        """ % (forbid, allow, tracked, after, forbid, allow, tracked, after)
        if nat:
            rules += """
              table ip related_nat {
                chain prerouting {
                  type nat hook prerouting priority dstnat; policy accept;
                  ip daddr 198.18.10.100 udp dport 18199 counter dnat to 198.18.20.51:18199
                }
                chain postrouting {
                  type nat hook postrouting priority srcnat; policy accept;
                  oifname "eth1" ip saddr 198.18.20.0/24 counter masquerade
                  oifname "eth2" ip saddr 198.18.20.0/24 ip daddr 198.18.20.51 udp dport 18199 counter snat to 198.18.20.1
                }
              }
            """
        reference.succeed("printf %s " + shlex.quote(rules) + " | nft -f -")
        reference.succeed("conntrack -F")

    def case_matches(case: Any, name: str, delivery: bool) -> bool:
        if not isinstance(case, dict):
            return False
        record: dict[str, Any] = case
        return record.get("passed") is True and record.get("case") == name and record.get("expected_delivery") is delivery

    def collect_report(lane, kind, mode, code, output):
        report: dict[str, Any]
        try:
            parsed = json.loads(output)
            if not isinstance(parsed, dict):
                raise ValueError("probe report must be an object")
            report = parsed
        except (json.JSONDecodeError, ValueError):
            report = {"results": [], "invalid_output": output}
        row = {"lane": lane, "path": kind, "mode": mode, "exit_code": code, "report": report}
        reports.append(row)
        expected: list[tuple[str, bool]] = (
            [(case, True) for case in ["port-min", "time-min", "parameter", "pmtu", "full", "options", "zero-udp", "odd-quote",
                "bad-quote-checksum", "bad-code", "unassigned-unreachable-code", "unassigned-parameter-code", "unassigned-time-code"]]
            + [(case, False) for case in ["bad-outer-checksum", "bad-icmp-checksum", "bad-envelope-match", "unmatched-port", "unmatched-destination", "truncated", "nonfirst-fragment", "error-about-error"]]
            + [("port-min", True)]
            if mode == "related" else
            [("unrelated-non-nat", True)] if mode in ("explicit-allow", "stateful-off-allow") else
            [("port-min", True)] if mode == "block-icmp" else
            [(mode, False)] if mode in ("missing-physical-state", "wrong-ingress", "expired-state") else
            [("port-min", False)]
        )
        cases = report.get("results")
        valid_cases = type(report.get("schema")) is int and report.get("schema") == 1 and report.get("profile") == mode and isinstance(cases, list) and len(cases) == len(expected) and all(
            case_matches(case, name, delivery)
            for case, (name, delivery) in zip(cases, expected)
        )
        if code != 0 or not valid_cases:
            failures.append(lane + "/" + kind + "/" + mode)
        return row

    def run(lane, kind, mode="related", port=41000):
        namespace = lane + ("-wan" if kind == "dnat" else "-client")
        source = "198.18.10.254" if kind == "dnat" else "198.18.20.50"
        target = "198.18.10.254" if kind == "snat" else "198.18.10.100"
        error_source = "198.18.10.254" if kind == "snat" else "198.18.10.100"
        command = ("ip netns exec " + namespace + " icmp-related-probe client --interface net0 --bind "
                   + source + " --target " + target + " --expected-error-source " + error_source
                   + " --source-port " + str(port) + " --profile " + mode + " --timeout 1.5")
        code, output = endpoints.execute(command, timeout=60)
        # An oracle failure is a broken fixture, not permission for the subject
        # to agree with the same failure. Retain both receipts before rejection.
        return collect_report(lane, kind, mode, code, output)

    def compare(reference_row, subject_row):
        oracle_cases = reference_row["report"].get("results", [])
        subject_cases = subject_row["report"].get("results", [])
        if oracle_cases != subject_cases:
            failures.append("differential/" + subject_row["path"] + "/" + subject_row["mode"])

    def map_entries(name):
        maps = json.loads(dut.succeed("bpftool -j map show"))
        identifier = next(item["id"] for item in maps if item["name"] == name)
        entries = json.loads(dut.succeed("bpftool -j map dump id " + str(identifier)))
        return identifier, {bytes(int(part, 16) for part in item["key"]): item["value"] for item in entries}

    def flow_key(policy, source, destination, sport, dport):
        return struct.pack("<I4s4sHHB3x", policy, socket.inet_aton(source), socket.inet_aton(destination), sport, dport, 17)

    def firewall_key(policy, source, destination, sport, dport):
        return (struct.pack("<I", policy) + socket.inet_aton(source) + bytes(12)
            + socket.inet_aton(destination) + bytes(12) + struct.pack("<HHBB2x", sport, dport, 17, 4))

    def release_peer(directory, action):
        # Publish only a complete command: a partially written "send" must
        # never become a flaky timeout or an injection in a later phase.
        endpoints.succeed("printf %s " + action + " > " + directory + "/release.tmp")
        endpoints.succeed("mv " + directory + "/release.tmp " + directory + "/release")

    def guarded_hairpin(mode, port):
        # These are Sentinel physical-policy safety checks, not a claim that
        # Linux's globally scoped conntrack enforces the same interface guard.
        unit = "icmp-held-" + mode
        directory = "/run/icmp-peer-dut-backend/" + mode
        result_path = "/tmp/" + unit + ".json"
        endpoints.succeed("systemd-run --unit=" + unit + " --property=Type=exec --property=StandardOutput=file:" + result_path
            + " ${pkgs.iproute2}/bin/ip netns exec dut-client ${probe}/bin/icmp-related-probe client"
            + " --interface net0 --bind 198.18.20.50 --target 198.18.10.100 --source-port " + str(port)
            + " --profile " + mode + " --timeout 12")
        endpoints.wait_until_succeeds("test -f " + directory + "/ready", timeout=5)
        request = json.loads(endpoints.succeed("cat " + directory + "/ready"))
        assert request["source"] == "198.18.20.1" and request["destination"] == "198.18.20.51", request
        assert request["source_port"] == port and request["destination_port"] == 18199, request
        _, nat_before = map_entries("CONNTRACK")
        nat_keys = [flow_key(0, "198.18.20.50", "198.18.10.100", port, 18199),
            flow_key(0, "198.18.20.51", "198.18.20.1", 18199, port)]
        # With one-second UDP idle limits the mapping can already have expired
        # by the time the peer reports ready, and the agent's reclaimer
        # (DP-07) deletes expired state instead of leaving it to LRU
        # eviction. Then the guard is checked against an absent mapping: the
        # ICMP error must not recreate it.
        if mode != "expired-state":
            assert all(key in nat_before for key in nat_keys), "both existing hairpin NAT directions required"
        endpoints.succeed("systemctl is-active --quiet " + unit)
        removed_keys = []
        if mode == "missing-physical-state":
            _, policy_entries = map_entries("IFACE_POLICY")
            ifindex = int(dut.succeed("cat /sys/class/net/eth2/ifindex"))
            policy = int.from_bytes(bytes(int(part, 16) for part in policy_entries[ifindex.to_bytes(4, "little")]), "little")
            identifier, entries = map_entries("FW_FLOWS")
            physical_keys = [firewall_key(policy, "198.18.20.50", "198.18.20.51", port, 18199),
                firewall_key(policy, "198.18.20.51", "198.18.20.50", 18199, port)]
            assert all(key in entries for key in physical_keys), "exact pre-SNAT physical pair must exist"
            # A later loader may also seed the post-SNAT physical wire pair.
            # Remove only this flow's physical pairs, never canonical NAT state.
            physical_keys += [firewall_key(policy, "198.18.20.1", "198.18.20.51", port, 18199),
                firewall_key(policy, "198.18.20.51", "198.18.20.1", 18199, port)]
            for key in physical_keys:
                if key in entries:
                    dut.succeed("bpftool map delete id " + str(identifier) + " key hex " + key.hex(" "))
                    removed_keys.append(key.hex())
            _, remaining = map_entries("FW_FLOWS")
            assert all(key not in remaining for key in physical_keys), "physical pair deletion failed"
        elif mode == "wrong-ingress":
            # Linux reverse-path filtering must not mask a missing eBPF
            # physical-policy guard in this adversarial injection.
            for interface in ["all", "default", "eth1", "eth2"]:
                dut.succeed("sysctl -w net.ipv4.conf." + interface + ".rp_filter=0")
                assert dut.succeed("cat /proc/sys/net/ipv4/conf/" + interface + "/rp_filter").strip() == "0"
            destination_mac = dut.succeed("cat /sys/class/net/eth1/address").strip()
            script = ("import socket; from pathlib import Path; "
                + "s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x800)); s.bind(('net0',0)); "
                + "frame=bytes.fromhex(" + repr(destination_mac.replace(":", "")) + ")+s.getsockname()[4]+bytes.fromhex('0800')+Path("
                + repr(directory + "/response.ip") + ").read_bytes(); assert s.send(frame)==len(frame)")
            endpoints.succeed("ip netns exec dut-wan ${pkgs.python3}/bin/python3 -c " + shlex.quote(script))
        elif mode == "expired-state":
            # The driver has configured both UDP idle limits to one second.
            time.sleep(2.2)
        else:
            raise AssertionError(mode)
        action = "suppress" if mode == "wrong-ingress" else "send"
        endpoints.succeed("systemctl is-active --quiet " + unit)
        release_peer(directory, action)
        endpoints.wait_until_succeeds("test -f " + directory + ("/suppressed" if action == "suppress" else "/sent"), timeout=3)
        endpoints.wait_until_fails("systemctl is-active --quiet " + unit, timeout=16)
        status = int(endpoints.succeed("systemctl show -p ExecMainStatus --value " + unit))
        output = endpoints.succeed("cat " + result_path)
        row = collect_report("dut", "hairpin", mode, status, output)
        _, nat_after = map_entries("CONNTRACK")
        # An ICMP error must never refresh counters/age, create a replacement or
        # make an expired mapping live. Background expiry may remove old state.
        unchanged = all(key not in nat_after or nat_after[key] == nat_before.get(key) for key in nat_keys)
        row["guard_evidence"] = {"physical_policy_guard": mode, "wire_request": request,
            "packet_injected": True, "peer_release": action,
            "injection_method": "wan-raw" if mode == "wrong-ingress" else "backend-raw",
            "injection_interface": "eth1" if mode == "wrong-ingress" else "eth2",
            "removed_physical_keys": removed_keys,
            "nat_keys": [key.hex() for key in nat_keys], "nat_state_unchanged_or_expired": unchanged}
        if not unchanged:
            failures.append("dut/hairpin/" + mode + "/icmp-mutated-nat-state")

    start_all()
    dut.wait_for_unit("sentinel-boot.service")
    dut.wait_for_unit("velstra.service")
    reference.wait_for_unit("nftables.service")
    endpoints.wait_for_unit("icmp-related-namespaces.service")
    dut.wait_until_succeeds("ip -4 address show eth1 | grep -q 198.18.10.100/24", timeout=30)
    dut.wait_until_succeeds("ip -4 address show eth2 | grep -q 198.18.20.1/24", timeout=30)
    for interface in ["eth1", "eth2"]:
        dut.succeed("ip -details link show " + interface + " | grep -q prog/xdp")
    for machine in [dut, reference]:
        assert machine.succeed("cat /proc/sys/net/ipv4/conf/all/accept_local").strip() == "0"
        machine.succeed("systemd-run --unit=icmp-related-capture tcpdump -U -n -i any -w /tmp/icmp-related.pcap")
    endpoints.succeed("icmp-related-probe selftest")
    for lane in ["dut", "reference"]:
        for role, address in [("wan", "198.18.10.254"), ("backend", "198.18.20.51")]:
            namespace = lane + "-" + role
            endpoints.succeed("systemd-run --unit=icmp-peer-" + namespace + " --property=Type=exec "
                + "${pkgs.iproute2}/bin/ip netns exec " + namespace
                + " ${probe}/bin/icmp-related-probe peer --interface net0 --bind " + address
                + " --control-directory /run/icmp-peer-" + namespace)
            endpoints.wait_until_succeeds("ip netns exec " + namespace + " ss -Hlun | grep -q ':18199'", timeout=15)
    oracle()
    try:
        for kind in ["snat", "dnat", "hairpin"]:
            with subtest("independent nftables and Sentinel " + kind + " ICMP errors/adversarial matrix"):
                reference_row = run("reference", kind, port=source_port)
                subject_row = run("dut", kind, port=source_port)
                compare(reference_row, subject_row)
                source_port += 200

        for mode in ["missing-physical-state", "wrong-ingress", "expired-state"]:
            with subtest("real hairpin physical-state and expiry guard: " + mode):
                if mode == "expired-state":
                    dut.succeed("printf %s 'set firewall global conntrack udp 1\nset firewall global conntrack udp-stream 1\ncommit\nsave\n' | sentinel configure")
                try:
                    guarded_hairpin(mode, source_port)
                except Exception as error:
                    failures.append("dut/hairpin/" + mode + "/guard-precondition")
                    reports.append({"lane": "dut", "path": "hairpin", "mode": mode,
                        "guard_error": str(error), "report": {"results": []}})
                    # Never inject a delayed packet into a later configuration.
                    endpoints.execute("printf %s suppress > /run/icmp-peer-dut-backend/" + mode + "/release")
                    endpoints.execute("systemctl stop icmp-peer-dut-backend")
                source_port += 200
        dut.succeed("printf %s 'delete firewall global conntrack udp\ndelete firewall global conntrack udp-stream\ncommit\nsave\n' | sentinel configure")

        # Configuration changes use the real installed CLI. Both physical
        # policies remain default-drop; disabling tracking cannot admit errors.
        for mode, commands in [
            ("stateful-off", ["set firewall zone wan stateful false"]),
            ("explicit-deny", ["set firewall zone wan stateful true",
                "set firewall rule reject-errors from wan", "set firewall rule reject-errors proto icmp",
                "set firewall rule reject-errors action drop"]),
            ("block-icmp", ["delete firewall rule reject-errors", "set firewall zone wan block-icmp true"]),
        ]:
            # block-icmp refuses new ICMP only; the error about the tracked flow
            # is delivered on both paths (see the oracle above).
            title = "RELATED passes " if mode == "block-icmp" else "RELATED does not bypass "
            with subtest(title + mode):
                script = "\n".join(commands + ["commit", "save"]) + "\n"
                dut.succeed("printf %s " + shlex.quote(script) + " | sentinel configure")
                oracle(mode)
                reference_row = run("reference", "snat", mode, source_port)
                subject_row = run("dut", "snat", mode, source_port)
                compare(reference_row, subject_row)
                source_port += 200

        # No NAT: an explicit operator allow still admits an ordinary error
        # whose quoted port is unmatched, including when tracking is disabled.
        for mode in ["explicit-allow", "stateful-off-allow"]:
            with subtest("explicit non-NAT error admission remains valid: " + mode):
                commands = ["set firewall zone wan block-icmp false",
                    "set firewall zone wan stateful " + ("false" if mode == "stateful-off-allow" else "true"),
                    "set firewall rule allow-errors from wan", "set firewall rule allow-errors proto icmp",
                    "set firewall rule allow-errors action accept"]
                if mode == "explicit-allow":
                    commands += ["delete nat source outbound", "delete nat destination probe"]
                script = "\n".join(commands + ["commit", "save"]) + "\n"
                dut.succeed("printf %s " + shlex.quote(script) + " | sentinel configure")
                oracle(mode, nat=False)
                reference_row = run("reference", "snat", mode, source_port)
                subject_row = run("dut", "snat", mode, source_port)
                compare(reference_row, subject_row)
                source_port += 200
    finally:
        evidence = {
            "schema": 1, "reports": reports, "failures": failures,
            "dut_kernel": dut.execute("uname -r")[1].strip(),
            "reference_kernel": reference.execute("uname -r")[1].strip(),
            "object_sha256": dut.execute("sha256sum ${self.packages.x86_64-linux.velstra-ebpf}")[1].split()[0],
            "probe_source": "${probeFile}",
            "probe_sha256": endpoints.execute("sha256sum ${probeFile}")[1].split()[0],
            "fixture_sha256": "${builtins.hashFile "sha256" ./icmp-related-test.nix}",
            "config_sha256": dut.execute("sha256sum /var/lib/sentinel/appliance.toml")[1].split()[0],
            "nft_version": reference.execute("nft --version")[1].strip(),
            "programs": dut.execute("bpftool -j prog show")[1],
            "scope": "IPv4 UDP quotes, SNAT/DNAT/hairpin, outer checksums/options/MTU and Linux opaque-code/quoted-checksum parity, native error queue (unassigned unreachable code raw-only), physical-state deletion/wrong ingress/expiry guards, explicit policy and non-stateful controls; no fragment or TCP-error wire certification",
        }
        artifact.write_text(json.dumps(evidence, indent=2) + "\n")
        print(json.dumps(evidence, sort_keys=True))
        for machine in [dut, reference]:
            machine.execute("systemctl stop icmp-related-capture")
            machine.copy_from_machine("/tmp/icmp-related.pcap", "captures/" + machine.name)
    assert not failures, failures
  '';
}
