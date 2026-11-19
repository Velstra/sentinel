{ pkgs, self }:
# DP-04 / DP-08 / DP-37 regression: nothing leaves a masquerade uplink with an
# inside source. Raw packets from a LAN host (portless protocols, IPv4 options,
# non-echo ICMP, TCP segments that cannot open a connection) are captured on
# the WAN segment; any capture with a 198.18.20.0/24 source fails the test.
# Positive controls prove the datapath is live and enforcing: an ordinary UDP
# datagram and TCP SYN, and the same carrying IPv4 options, must arrive
# TRANSLATED to the uplink address (ICMP with options is refused, not
# translated), and the refusal counters must move.
let
  inherit (pkgs) lib;
  kernelPackages = self.nixosConfigurations.appliance.config.boot.kernelPackages;
  sender = pkgs.writeText "leak-sender.py" ''
    import json, socket, struct, sys

    def checksum(data):
        if len(data) % 2:
            data += b"\0"
        total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        while total >> 16:
            total = (total & 0xffff) + (total >> 16)
        return ~total & 0xffff

    SRC, DST = "198.18.20.50", "198.18.10.254"
    src, dst = socket.inet_aton(SRC), socket.inet_aton(DST)

    def ip(proto, payload, ident, options=b""):
        ihl = 5 + len(options) // 4
        header = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, 4 * ihl + len(payload),
                             ident, 0, 64, proto, 0, src, dst) + options
        header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
        return header + payload

    def l4_checksum(proto, segment):
        return checksum(src + dst + struct.pack("!BBH", 0, proto, len(segment)) + segment)

    def tcp(sport, flags):
        segment = struct.pack("!HHIIBBHHH", sport, 18080, 1000, 0, 0x50, flags, 1024, 0, 0)
        return segment[:16] + struct.pack("!H", l4_checksum(6, segment)) + segment[18:]

    def udp(sport):
        segment = struct.pack("!HHHH", sport, 18081, 12, 0) + b"leak"
        return segment[:6] + struct.pack("!H", l4_checksum(17, segment)) + segment[8:]

    def icmp(kind, ident):
        message = struct.pack("!BBHHH", kind, 0, 0, ident, 1) + b"\0" * 12
        return message[:2] + struct.pack("!H", checksum(message)) + message[4:]

    NOP4 = b"\x01\x01\x01\x01"
    # (name, packet, expectation): "translated" must arrive from the uplink
    # address; "refused" must not arrive at all. Nothing may arrive untranslated.
    cases = [
        ("udp-control", ip(17, udp(41001), 0x5101), "translated"),
        ("tcp-syn-control", ip(6, tcp(41002, 0x02), 0x5102), "translated"),
        ("udp-ip-options", ip(17, udp(41003), 0x5103, NOP4), "translated"),
        ("tcp-syn-ip-options", ip(6, tcp(41004, 0x02), 0x5104, NOP4), "translated"),
        ("icmp-echo-ip-options", ip(1, icmp(8, 0x5105), 0x5105, NOP4), "refused"),
        ("gre", ip(47, b"\0\0\x08\0" + b"x" * 28, 0x5201), "refused"),
        ("esp", ip(50, b"\0\0\x10\0" + b"\0" * 28, 0x5202), "refused"),
        ("sctp", ip(132, b"\x9c\x40\x46\x50" + b"\0" * 28, 0x5203), "refused"),
        ("6in4", ip(41, b"\x60" + b"\0" * 39, 0x5204), "refused"),
        ("icmp-timestamp", ip(1, icmp(13, 0x5205), 0x5205), "refused"),
        ("tcp-bare-ack", ip(6, tcp(41006, 0x10), 0x5301), "refused"),
        ("tcp-xmas", ip(6, tcp(41007, 0x29), 0x5302), "refused"),
        ("tcp-null", ip(6, tcp(41008, 0x00), 0x5303), "refused"),
        ("tcp-syn-fin", ip(6, tcp(41009, 0x03), 0x5304), "refused"),
    ]
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as raw:
        for _, packet, _ in cases:
            for _ in range(3):
                raw.sendto(packet, (DST, 0))
    print(json.dumps([{"case": name, "id": struct.unpack("!H", packet[4:6])[0],
                       "expect": expect} for name, packet, expect in cases]))
  '';
  appliance = pkgs.writeText "leak-appliance.toml" ''
    [system]
    hostname="dut"
    [zone.lan]
    default_action="accept"
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
    [[nat.source]]
    name="outbound"
    zone="wan"
  '';
in pkgs.testers.runNixOSTest {
  name = "sentinel-masquerade-no-private-leak";
  globalTimeout = 600;
  nodes = {
    lan = {
      boot = { inherit kernelPackages; };
      virtualisation = { interfaces.eth1.vlan = 2; memorySize = 512; };
      networking = {
        useNetworkd = true;
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1.ipv4.addresses = [{ address = "198.18.20.50"; prefixLength = 24; }];
        defaultGateway = { interface = "eth1"; address = "198.18.20.1"; };
      };
      environment.systemPackages = [ pkgs.python3 ];
    };
    wan = {
      boot = { inherit kernelPackages; };
      virtualisation = { interfaces.eth1.vlan = 1; memorySize = 512; };
      networking = {
        useNetworkd = true;
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1.ipv4.addresses = [{ address = "198.18.10.254"; prefixLength = 24; }];
      };
      environment.systemPackages = [ pkgs.tcpdump ];
    };
    dut = {
      imports = [ self.nixosModules.sentinel ];
      networking.hostName = lib.mkForce "dut";
      networking.firewall.enable = lib.mkForce false;
      boot = { inherit kernelPackages; };
      virtualisation = {
        interfaces = { eth1.vlan = 1; eth2.vlan = 2; };
        memorySize = 1536; cores = 2;
      };
      services.velstra = { interface = lib.mkForce "eth1"; appliance = lib.mkForce appliance; };
      environment.systemPackages = [ pkgs.bpftools ];
    };
  };
  testScript = ''
    import json, re

    def stats():
        text = dut.succeed("sentinel show firewall statistics")
        return {n: int(v) for n, v in re.findall(r"^\s*([a-z_0-9]+)\s+(\d+)\s*$", text, re.M)}

    start_all()
    dut.wait_for_unit("sentinel-boot.service")
    dut.wait_for_unit("velstra.service")
    for interface in ["eth1", "eth2"]:
        dut.wait_until_succeeds("ip -details link show " + interface + " | grep -q prog/xdp", timeout=60)
    lan.wait_for_unit("systemd-networkd.service")
    wan.wait_for_unit("systemd-networkd.service")
    lan.wait_until_succeeds("ping -c1 -W1 198.18.20.1", timeout=60)
    wan.succeed("systemd-run --unit=leak-capture tcpdump -U -n -i eth1 -w /tmp/wan.pcap ip")
    wan.wait_until_succeeds("test -s /tmp/wan.pcap", timeout=10)
    before = stats()
    cases = json.loads(lan.succeed("python3 ${sender}"))
    lan.sleep(3)
    after = stats()
    wan.succeed("systemctl stop leak-capture.service")
    lines = wan.succeed("tcpdump -n -v -r /tmp/wan.pcap ip 2>/dev/null").splitlines()
    # tcpdump -v prints "(tos ..., id N, ...)" then "SRC > DST" on the next line.
    seen = []
    for index, line in enumerate(lines):
        match = re.search(r"\bid (\d+),", line)
        if match and index + 1 < len(lines):
            tokens = lines[index + 1].strip().split(" ")
            # Only what travelled toward the WAN host: its own replies differ.
            if len(tokens) > 2 and tokens[2].startswith("198.18.10.254"):
                seen.append((int(match.group(1)), tokens[0]))
    leaked = [entry for entry in seen if entry[1].startswith("198.18.20.")]
    report = []
    failures = []
    for case in cases:
        sources = sorted({source for ident, source in seen if ident == case["id"]})
        report.append({"case": case["case"], "expect": case["expect"], "sources": sources})
        if case["expect"] == "translated":
            ok = bool(sources) and all(s.startswith("198.18.10.100") for s in sources)
        else:
            ok = not sources
        if not ok:
            failures.append(case["case"])
    delta = {name: after.get(name, 0) - before.get(name, 0) for name in after}
    print("LEAK_RECEIPT " + json.dumps({"report": report, "leaked": leaked, "counters": delta,
        "object_sha256": dut.succeed("sha256sum ${self.packages.x86_64-linux.velstra-ebpf}").split()[0]}))
    assert not leaked, "private source left the masquerade uplink: " + repr(leaked)
    assert not failures, "unexpected delivery: " + repr(failures)
    # The refusals are the datapath's, not an absent program: counters move.
    assert delta.get("egress_nat_unsupported_dropped", 0) >= 18, delta
    assert delta.get("nat_opener_required", 0) + delta.get("tcp_invalid_flags", 0) >= 12, delta
    assert delta.get("egress_masqueraded", 0) >= 12, delta
  '';
}
