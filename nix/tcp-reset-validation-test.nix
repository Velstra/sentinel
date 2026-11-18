{ pkgs, self, probeSource ? "${self.inputs.fabric}/tests/conformance/tcp-reset-probe.py" }:
let
  inherit (pkgs) lib;
  kernelPackages = self.nixosConfigurations.appliance.config.boot.kernelPackages;
  probe = pkgs.writeShellScriptBin "tcp-reset-probe" ''
    exec ${pkgs.python3}/bin/python3 -B ${probeSource} "$@"
  '';
  appliance = pkgs.writeText "tcp-reset-appliance.toml" ''
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
    address="198.19.10.1/24"
    zone="wan"
    [[interface]]
    name="eth2"
    address="198.19.20.1/24"
    zone="lan"
    [[rule]]
    name="native-tcp-echo"
    from="lan"
    proto="tcp"
    port="18198"
    action="accept"
  '';
  namespaces = pkgs.writeShellScript "tcp-reset-namespaces" ''
    set -eu
    ${lib.concatMapStringsSep "\n" (entry: ''
      ip netns add ${entry.name}
      ip link set ${entry.iface} netns ${entry.name}
      ip -n ${entry.name} link set ${entry.iface} name net0
      ip -n ${entry.name} address add ${entry.address}/24 dev net0
      ip -n ${entry.name} link set lo up
      ip -n ${entry.name} link set net0 up
      ip -n ${entry.name} route add default via ${entry.gateway}
    '') [
      { name = "dut-server"; iface = "eth1"; address = "198.19.10.254"; gateway = "198.19.10.1"; }
      { name = "dut-client"; iface = "eth2"; address = "198.19.20.50"; gateway = "198.19.20.1"; }
      { name = "reference-server"; iface = "eth3"; address = "198.19.10.254"; gateway = "198.19.10.1"; }
      { name = "reference-client"; iface = "eth4"; address = "198.19.20.50"; gateway = "198.19.20.1"; }
    ]}
  '';
in pkgs.testers.runNixOSTest {
  name = "sentinel-tcp-reset-sequence-differential";
  globalTimeout = 180;
  nodes = {
    dut = {
      imports = [ self.nixosModules.sentinel ];
      networking.hostName = lib.mkForce "dut";
      networking.firewall.enable = lib.mkForce false;
      boot = { inherit kernelPackages; kernel.sysctl."net.ipv4.ip_forward" = 1; };
      virtualisation = {
        vlans = [ 1 2 ]; memorySize = 1024; cores = 2;
        qemu.options = [ "-object filter-dump,id=reset-wire,netdev=vlan1,file=wan-before-guest.pcap" ];
      };
      services.velstra = { interface = lib.mkForce "eth1"; appliance = lib.mkForce appliance; };
      environment.systemPackages = [ pkgs.bpftools pkgs.tcpdump ];
    };
    reference = {
      boot = {
        inherit kernelPackages;
        kernelModules = [ "nf_conntrack" ];
        kernel.sysctl = {
          "net.ipv4.ip_forward" = 1;
          "net.netfilter.nf_conntrack_tcp_be_liberal" = 0;
          "net.netfilter.nf_conntrack_tcp_ignore_invalid_rst" = 0;
          "net.netfilter.nf_conntrack_checksum" = 1;
        };
      };
      virtualisation = {
        vlans = [ 3 4 ]; memorySize = 384; cores = 1;
        qemu.options = [ "-object filter-dump,id=reset-wire,netdev=vlan1,file=wan-before-guest.pcap" ];
      };
      networking = {
        useNetworkd = true;
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1.ipv4.addresses = [{ address = "198.19.10.1"; prefixLength = 24; }];
        interfaces.eth2.ipv4.addresses = [{ address = "198.19.20.1"; prefixLength = 24; }];
        nftables = {
          enable = true;
          ruleset = ''
            table inet reset_test {
              chain forward {
                type filter hook forward priority filter; policy drop;
                ct state invalid counter drop comment "invalid-reset"
                ct state established,related counter accept comment "established"
                iifname "eth2" tcp dport 18198 counter accept comment "native-tcp-echo"
              }
            }
          '';
        };
      };
      environment.systemPackages = [ pkgs.nftables pkgs.conntrack-tools pkgs.tcpdump ];
    };
    endpoints = {
      boot = { inherit kernelPackages; };
      virtualisation = { vlans = [ 1 2 3 4 ]; memorySize = 384; cores = 1; };
      networking = { useNetworkd = true; useDHCP = false; firewall.enable = false; };
      environment.systemPackages = [ probe pkgs.iproute2 pkgs.tcpdump pkgs.python3 ];
      systemd.services.tcp-reset-namespaces = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        path = [ pkgs.iproute2 ];
        serviceConfig = { Type = "oneshot"; RemainAfterExit = true; ExecStart = namespaces; };
      };
    };
  };
  testScript = ''
    import hashlib, json, os, re, shlex, shutil, socket, struct, time
    from pathlib import Path

    reports = []
    failures = []
    capture_paths = []

    def wire_contains(machine, digest):
        # Independent QEMU NIC capture, BEFORE guest XDP/kernel processing.
        # Match the entire Ethernet frame hash, not a potentially unrelated
        # counter increase or the absence of a packet after XDP_DROP.
        data = (machine.state_dir / "wan-before-guest.pcap").read_bytes()
        assert len(data) <= 4 * 1024 * 1024, "unexpected capture flood"
        if len(data) < 24:
            return False
        byteorder = "<" if data[:4] == bytes.fromhex("d4c3b2a1") else ">" if data[:4] == bytes.fromhex("a1b2c3d4") else None
        assert byteorder is not None, "not a native QEMU PCAP"
        assert struct.unpack_from(byteorder + "HH", data, 4) == (2, 4)
        assert struct.unpack_from(byteorder + "I", data, 20)[0] == 1, "not Ethernet"
        offset = 24
        while offset + 16 <= len(data):
            _, _, captured, original = struct.unpack_from(byteorder + "IIII", data, offset)
            assert captured == original and captured <= 65536, "truncated wire capture"
            offset += 16
            if offset + captured > len(data):
                break  # A concurrent QEMU write has not published this record.
            if hashlib.sha256(data[offset:offset + captured]).hexdigest() == digest:
                return True
            offset += captured
        return False

    def states(port):
        maps = json.loads(dut.succeed("bpftool -j map show"))
        identifier = next(item["id"] for item in maps if item["name"] == "FW_FLOWS")
        result = []
        for item in json.loads(dut.succeed("bpftool -j map dump id " + str(identifier))):
            raw_key = bytes(int(part, 16) for part in item["key"])
            policy, source, target, sport, dport, proto, family = struct.unpack("<I16s16sHHBB2x", raw_key)
            if proto != 6 or family != 4:
                continue
            identity = (socket.inet_ntoa(source[:4]), socket.inet_ntoa(target[:4]), sport, dport)
            if identity not in [("198.19.20.50", "198.19.10.254", port, 18198),
                                ("198.19.10.254", "198.19.20.50", 18198, port)]:
                continue
            value = bytes(int(part, 16) for part in item["value"])
            _, _, phase, reply = struct.unpack("<QQII", value)
            result.append({"key_hex": raw_key.hex(), "policy": policy, "tuple": identity,
                "phase": phase, "reply": reply})
        return sorted(result, key=lambda row: row["key_hex"])

    def stats():
        text = dut.succeed("sentinel show firewall statistics")
        return {name: int(value) for name, value in re.findall(r"^\s*([a-z_]+)\s+(\d+)\s*$", text, re.M)}

    def reference_state(port):
        return reference.execute("conntrack -L -p tcp --orig-src 198.19.20.50 --orig-dst 198.19.10.254 --sport "
            + str(port) + " --dport 18198 2>/dev/null")[1].strip()

    def nft_counters():
        rules = json.loads(reference.succeed("nft -j list chain inet reset_test forward"))
        return {item["rule"]["comment"]: next(part["counter"]["packets"] for part in item["rule"]["expr"]
                if "counter" in part) for item in rules["nftables"] if "rule" in item}

    def run_case(lane, case, port, ident):
        machine = dut if lane == "dut" else reference
        namespace = lane + "-client"
        directory = "/run/tcp-reset-" + lane + "-" + case
        unit = "tcp-reset-" + lane + "-" + case
        command = ("${pkgs.iproute2}/bin/ip netns exec " + namespace
            + " ${probe}/bin/tcp-reset-probe session --interface net0 --bind 198.19.20.50"
            + " --target 198.19.10.254 --source-port " + str(port) + " --ident " + str(ident)
            + " --case " + case + " --directory " + directory)
        endpoints.succeed("systemd-run --unit=" + unit + " --property=Type=exec " + command)
        endpoints.wait_until_succeeds("test -f " + directory + "/ready.json", timeout=10)
        before = states(port) if lane == "dut" else reference_state(port)
        if lane == "dut":
            assert len(before) == 4 and all(row["phase"] == 3 for row in before), before
        else:
            assert "ESTABLISHED" in before, before
        counters_before = stats() if lane == "dut" else nft_counters()
        capture = "/tmp/" + unit + ".pcap"
        capture_paths.append((machine, capture, lane + "-" + case + ".pcap"))
        machine.succeed("systemd-run --unit=" + unit + "-capture tcpdump --immediate-mode -U -n -i eth1 -w " + capture)
        machine.wait_until_succeeds("test -s " + capture, timeout=5)
        destination_mac = machine.succeed("cat /sys/class/net/eth1/address").strip()
        injection = json.loads(endpoints.succeed("ip netns exec " + lane + "-server ${probe}/bin/tcp-reset-probe inject"
            + " --interface net0 --ready " + directory + "/ready.json --case " + case
            + " --destination-mac " + destination_mac))
        packet = injection["packet"]
        assert packet["ip_checksum_valid"] is True, injection
        assert packet["tcp_checksum_valid"] is (case != "bad-checksum"), injection
        assert packet["id"] == ident and packet["flags"] == 20, injection
        wire_filter = "ip[4:2] = " + str(ident) + " and tcp[tcpflags] & tcp-rst != 0"
        deadline = time.monotonic() + 3
        while not wire_contains(machine, injection["frame_sha256"]):
            assert time.monotonic() < deadline, "exact injected frame never reached router NIC"
            time.sleep(0.01)
        after_injection = states(port) if lane == "dut" else reference_state(port)
        counters_after = stats() if lane == "dut" else nft_counters()
        endpoints.succeed("printf 'observe\\n' > " + directory + "/release")
        endpoints.wait_until_succeeds("test -f " + directory + "/report.json", timeout=7)
        endpoints.wait_until_fails("systemctl is-active --quiet " + unit, timeout=5)
        status = int(endpoints.succeed("systemctl show -p ExecMainStatus --value " + unit))
        endpoint = json.loads(endpoints.succeed("cat " + directory + "/report.json"))
        # Immediate capture disables libpcap's input batching; -U alone only
        # flushes packets already delivered to tcpdump. Finish the endpoint
        # observation before stopping, then require a readable capture. Lack
        # of a post-XDP record is never substituted for pre-guest wire proof.
        machine.succeed("systemctl stop " + unit + "-capture")
        post_xdp_capture = "Flags" in machine.succeed(
            "tcpdump -n -r " + capture + " " + shlex.quote(wire_filter) + " 2>/dev/null")
        if lane == "reference" or case == "valid-reset":
            assert post_xdp_capture, "post-XDP capture positive control failed"
        if lane == "dut":
            state_ok = not after_injection if case == "valid-reset" else after_injection == before
            assert counters_after["rx_packets"] > counters_before["rx_packets"], (counters_before, counters_after)
        else:
            state_ok = ("ESTABLISHED" not in after_injection if case == "valid-reset" else "ESTABLISHED" in after_injection)
            if case in ["foreign-tuple", "wrong-sequence", "bad-checksum"]:
                state_ok = state_ok and counters_after["invalid-reset"] > counters_before["invalid-reset"]
            elif case == "in-window-nonexact":
                state_ok = state_ok and counters_after["invalid-reset"] == counters_before["invalid-reset"]
        row = {"lane": lane, "case": case, "port": port, "ident": ident, "injection": injection,
            "wire_at_router": True, "post_xdp_capture": post_xdp_capture,
            "state_before": before, "state_after_injection": after_injection,
            "counters_before": counters_before, "counters_after": counters_after,
            "endpoint": endpoint, "exit_code": status, "state_ok": state_ok}
        reports.append(row)
        if status != 0 or endpoint.get("passed") is not True or not state_ok:
            failures.append(lane + "/" + case)

    start_all()
    dut.wait_for_unit("sentinel-boot.service")
    dut.wait_for_unit("velstra.service")
    reference.wait_for_unit("nftables.service")
    endpoints.wait_for_unit("tcp-reset-namespaces.service")
    endpoints.succeed("tcp-reset-probe selftest")
    for name in ["nf_conntrack_tcp_be_liberal", "nf_conntrack_tcp_ignore_invalid_rst"]:
        assert reference.succeed("cat /proc/sys/net/netfilter/" + name).strip() == "0"
    assert reference.succeed("cat /proc/sys/net/netfilter/nf_conntrack_checksum").strip() == "1"
    for lane in ["dut", "reference"]:
        endpoints.succeed("systemd-run --unit=tcp-echo-" + lane + " --property=Type=exec "
            + "${pkgs.iproute2}/bin/ip netns exec " + lane + "-server ${probe}/bin/tcp-reset-probe server --bind 198.19.10.254")
        endpoints.wait_until_succeeds("ip netns exec " + lane + "-server ss -Hlt | grep -q ':18198'", timeout=10)
    kernel_receipts = {machine.name: machine.execute("uname -r")[1].strip() for machine in [dut, reference, endpoints]}
    object_sha256 = dut.execute("sha256sum ${self.packages.x86_64-linux.velstra-ebpf}")[1].split()[0]
    try:
        for number, case in enumerate(["foreign-tuple", "wrong-sequence", "valid-reset", "in-window-nonexact", "bad-checksum"]):
            for lane in ["reference", "dut"]:
                with subtest(lane + ": actual " + case + " and same-socket continuity"):
                    run_case(lane, case, 42000 + number * 20, 0x7200 + number)
        dut.succeed("systemctl is-active --quiet velstra.service sentinel-boot.service")
    except Exception as error:
        failures.append("fixture-precondition/" + type(error).__name__)
        raise
    finally:
        captures = Path(os.environ["out"], "captures")
        captures.mkdir(exist_ok=True)
        for machine, capture, label in capture_paths:
            machine.execute("systemctl stop tcp-reset-" + label[:-5] + "-capture")
            machine.copy_from_machine(capture, "captures/post-xdp/" + machine.name)
        wire_hashes = {}
        for machine in [dut, reference]:
            machine.shutdown()
            source = machine.state_dir / "wan-before-guest.pcap"
            target = captures / (machine.name + "-before-guest.pcap")
            shutil.copyfile(source, target)
            wire_hashes[machine.name] = hashlib.sha256(target.read_bytes()).hexdigest()
        receipt = {"schema": 1, "reports": reports, "failures": failures,
            "kernels": kernel_receipts, "wire_capture_sha256": wire_hashes,
            "object_sha256": object_sha256,
            "probe_sha256": "${builtins.hashFile "sha256" probeSource}",
            "fixture_sha256": "${builtins.hashFile "sha256" ./tcp-reset-validation-test.nix}",
            "scope": "Routed IPv4 TCP resets, actual native echo and five injected controls including native challenge ACK and corrupt-checksum proof; no NAT/IPv6/HA/capacity or final-image qualification"}
        Path(os.environ["out"], "tcp-reset-differential.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print("TCP_RESET_RECEIPT " + json.dumps(receipt, sort_keys=True))
    assert not failures, failures
  '';
}
