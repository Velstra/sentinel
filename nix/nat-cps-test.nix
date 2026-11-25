{ pkgs, self }:
# PERF-02 / DP-06 (live, 2026-11-20): masqueraded new-connection setup collapsed
# to ~300-500 conn/s once any non-allocator NAT write (an ICMP echo through the
# masquerade, a port-forward publication) had marked the standalone NAPT
# search bound "unbounded": every new flow then scanned the whole 32768-port
# domain in softirq. This check reproduces that history first (one ping, one
# port-forwarded connection), then offers new connections at a fixed rate,
# twice, with long-lived connections echoing throughout.
#
# Floor: 2000 new connections/s, offered open-loop for 10 s per phase, every
# one of them completed, the firewall refusing nothing but repeated server RSTs
# for flows a first RST already closed (each refusal logged and attributed),
# and at most
# 10 % needing a SYN retransmission (the links between test VMs drop packets
# on their own; the receipt measures every hop). That is
# 4x the live collapse and well under what the routed path did on the same
# hardware (14k/s). A cleanly closed binding holds its port for 120 s, so the
# second phase meets the first phase's bindings still in place: about 25,000
# of one remote endpoint's 32768 ports in use (measured), below the 80 % fill
# at which the 128-probe window refuses nothing. A failure here is the
# allocator or a binding's lifetime, not port exhaustion. The client's own lag is
# asserted too, so a client that cannot offer the rate fails as invalid
# rather than passing or failing for the wrong reason.
let
  lib = pkgs.lib;
  sentinel = self;
  python = "${pkgs.python3}/bin/python3";
  rate = 2000;
  seconds = 10;
  held = 128;
in
pkgs.testers.runNixOSTest {
  name = "sentinel-nat-cps";
  globalTimeout = 900;
  nodes = {
    client = {
      virtualisation = { vlans = [ 2 ]; cores = 4; memorySize = 2048; };
      networking = {
        useNetworkd = true;
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1.ipv4.addresses = [ { address = "198.18.20.50"; prefixLength = 24; } ];
        defaultGateway = { address = "198.18.20.1"; interface = "eth1"; };
      };
      boot.kernel.sysctl."net.ipv4.ip_local_port_range" = "1024 65000";
      # The port-forward target: one inbound connection is enough to make
      # the datapath publish a destination-NAT entry.
      systemd.services.pf-target = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        script = ''
          mkdir -p /srv/pf && echo pf-target > /srv/pf/index.html
          exec ${python} -m http.server 8080 --bind 198.18.20.50 --directory /srv/pf
        '';
      };
    };
    backend = {
      virtualisation = { vlans = [ 1 ]; cores = 4; memorySize = 2048; };
      networking = {
        useNetworkd = true;
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1.ipv4.addresses = [ { address = "198.18.10.254"; prefixLength = 24; } ];
      };
      boot.kernel.sysctl = {
        "net.core.somaxconn" = 8192;
        "net.ipv4.tcp_max_syn_backlog" = 16384;
      };
      environment.systemPackages = [ pkgs.curl pkgs.tcpdump ];
      systemd.services.cps-peer = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig = {
          ExecStart = "${python} -u ${./nat-cps-backend.py} 4";
          LimitNOFILE = 65536;
        };
      };
    };
    fw = {
      imports = [ sentinel.nixosModules.sentinel ];
      networking.hostName = lib.mkForce "fw";
      networking.firewall.enable = lib.mkForce false;
      boot.kernelPackages = sentinel.nixosConfigurations.appliance.config.boot.kernelPackages;
      virtualisation = { vlans = [ 1 2 ]; cores = 2; memorySize = 2048; };
      services.velstra = {
        interface = lib.mkForce "eth1";
        appliance = lib.mkForce (pkgs.writeText "nat-cps.toml" ''
          [system]
          hostname="fw"
          # Logs the packets the data plane refuses, and only those (a pass
          # is logged by a rule's own `log` alone): each refusal below is named
          # by its WAN port. Under this load it is also the regression guard
          # for the log flood, where `log` logged every reverse-NAT packet.
          [zone.wan]
          log=true
          [zone.lan]
          default_action="accept"
          [[interface]]
          name="eth0"
          address="dhcp"
          zone="management"
          [[interface]]
          name="eth1"
          address="198.18.10.100/24"
          zone="wan"
          [[interface]]
          name="eth2"
          address="198.18.20.1/24"
          zone="lan"
          [[nat.source]]
          name="wan-masq"
          zone="wan"
          [[nat.destination]]
          name="pf"
          zone="wan"
          proto="tcp"
          port=8080
          to="198.18.20.50:8080"
        '');
      };
      environment.systemPackages = [ pkgs.iproute2 pkgs.bpftools ];
    };
  };
  testScript = ''
    ${import ./uplink-ready.nix { inherit pkgs; }}
    import json
    import os
    import re
    import time
    from pathlib import Path
    from typing import Any

    receipt: dict[str, Any] = {"rate": ${toString rate}, "seconds": ${toString seconds}, "held": ${toString held}, "phases": []}

    def preserve():
        Path(os.environ["out"], "nat-cps.json").write_text(json.dumps(receipt, indent=2))

    def stats():
        text = fw.succeed("sentinel show firewall statistics")
        return {n: int(v) for n, v in re.findall(r"^\s*([a-z_0-9]+)\s+(\d+)\s*$", text, re.M)}

    def delta(before, after):
        return {k: after.get(k, 0) - before.get(k, 0) for k in after if after.get(k, 0) != before.get(k, 0)}

    def egress_runtime():
        # bpf_stats attribute a tail-call chain to the program the hook ran.
        programs = json.loads(fw.succeed("bpftool -j prog show"))
        rows = [p for p in programs if p.get("name") == "velstra_egress"]
        assert rows, "velstra_egress is not loaded"
        return (sum(p.get("run_time_ns", 0) for p in rows), sum(p.get("run_cnt", 0) for p in rows))

    # Where a retransmitted SYN was lost, per phase: the server's listen
    # queues, the client's own retransmissions, every NIC and qdisc on the
    # path, and (in `counters`) every data-plane drop and NAT counter.
    SERVER_TCP = ["TcpExtListenOverflows", "TcpExtListenDrops", "TcpExtTCPReqQFullDrop",
                  "TcpExtTCPReqQFullDoCookies", "TcpExtSyncookiesSent", "TcpExtTCPBacklogDrop"]
    CLIENT_TCP = ["TcpRetransSegs", "TcpExtTCPSynRetrans", "TcpExtTCPTimeouts"]

    def nstat(machine, names):
        text = machine.succeed("nstat -saz " + " ".join(names))
        return {n: int(v) for n, v in re.findall(r"^([A-Za-z0-9]+)\s+(\d+)", text, re.M) if n in names}

    def link_drops(machine):
        drops = {}
        for link in json.loads(machine.succeed("ip -s -j link show")):
            stats64 = link.get("stats64", {})
            for way in ("rx", "tx"):
                drops[link["ifname"] + "_" + way + "_dropped"] = stats64.get(way, {}).get("dropped", 0)
                # Packet counts per hop: what one end sent and the next end
                # received tells which link of the test network lost it.
                drops[link["ifname"] + "_" + way + "_packets"] = stats64.get(way, {}).get("packets", 0)
        return drops

    def qdisc_drops(machine):
        return {q["dev"] + "_" + q["kind"] + "_" + q.get("handle", "") + "_drops": q.get("drops", 0)
                for q in json.loads(machine.succeed("tc -s -j qdisc show"))}

    def path_counters():
        return {"server_tcp": nstat(backend, SERVER_TCP), "client_tcp": nstat(client, CLIENT_TCP),
                "server_links": link_drops(backend), "client_links": link_drops(client),
                "fw_links": link_drops(fw), "fw_qdiscs": qdisc_drops(fw)}

    def path_delta(before, after):
        return {k: delta(before[k], after[k]) for k in after}

    # Each hop of the test network: what one end sent minus what the next
    # end received. "fw" rows are the firewall itself (received on one NIC,
    # not sent on the other); the rest are the links between VMs.
    HOPS = [
        ("client>fw", "client_links", "eth1_tx_packets", "fw_links", "eth2_rx_packets"),
        ("fw lan>wan", "fw_links", "eth2_rx_packets", "fw_links", "eth1_tx_packets"),
        ("fw>server", "fw_links", "eth1_tx_packets", "server_links", "eth1_rx_packets"),
        ("server>fw", "server_links", "eth1_tx_packets", "fw_links", "eth1_rx_packets"),
        ("fw wan>lan", "fw_links", "eth1_rx_packets", "fw_links", "eth2_tx_packets"),
        ("fw>client", "fw_links", "eth2_tx_packets", "client_links", "eth1_rx_packets"),
    ]

    def hop_loss(path):
        return {name: path[a].get(ak, 0) - path[b].get(bk, 0) for name, a, ak, b, bk in HOPS}

    # Every data-plane counter that means a packet was refused, by reason.
    DATAPLANE_DROPS = ["dropped_default", "dropped_blocklist", "dropped_rule", "dropped_icmp",
                       "malformed", "egress_dropped", "rejected", "dropped_rate_limit",
                       "dropped_spoofed", "dropped_not_yours", "dropped_port_rate", "dropped_portal",
                       "tcp_invalid_reset", "tcp_invalid_flags", "firewall_state_write_failed",
                       "synproxy_rejected", "forward_ttl_exceeded", "lb_no_backend"]
    NAT_DROPS = ["egress_nat_no_candidate", "egress_nat_claim_failed", "nat_claim_collision",
                 "egress_nat_fragment_dropped", "egress_nat_unsupported_dropped"]

    def journal_cursor():
        return fw.succeed("journalctl -u velstra -n0 --show-cursor").strip().split("cursor: ")[-1]

    def refusals(cursor):
        # The data plane's DROP lines since `cursor`: (source, proto, port, reason).
        text = fw.succeed("journalctl -u velstra --no-pager -o cat --after-cursor='" + cursor + "' | grep -E 'DROP[0-9]* ' || true")
        return [(m.group(1), int(m.group(2)), int(m.group(3)), m.group(4)) for m in
                re.finditer(r"DROP (\S+) proto=(\d+) dport=(\d+) reason=(\w+)", text)]

    def server_resets(capture):
        # RSTs the server sent, per WAN port it sent them to.
        text = backend.succeed("tcpdump -r " + capture + " -nn 2>/dev/null || true")
        resets: dict[int, int] = {}
        for m in re.finditer(r" > 198\.18\.10\.100\.(\d+): Flags \[R", text):
            port = int(m.group(1))
            resets[port] = resets.get(port, 0) + 1
        return resets

    def napt_search_bound():
        out = fw.execute("bpftool -j map dump name NAPT_SEARCH")
        if out[0] != 0:
            return None
        rows = json.loads(out[1])
        return [r.get("value") or r.get("formatted", {}).get("value") for r in rows]

    start_all()
    # The NixOS test VMs boot with clocksource=acpi_pm. Under nested
    # virtualisation every read of it is an I/O-port exit costing tens of
    # microseconds, and the datapath reads the clock (bpf_ktime_get_ns)
    # several times per packet. A rate check on that clock measures the
    # emulated timer, not the datapath. No appliance runs on acpi_pm.
    for machine in [fw, client, backend]:
        machine.succeed("echo kvm-clock > /sys/devices/system/clocksource/clocksource0/current_clocksource")
    receipt["clocksource"] = fw.succeed("cat /sys/devices/system/clocksource/clocksource0/current_clocksource").strip()
    assert receipt["clocksource"] == "kvm-clock", receipt["clocksource"]
    fw.wait_for_unit("sentinel-boot.service")
    fw.wait_for_unit("velstra.service")
    backend.wait_for_unit("cps-peer.service")
    client.wait_for_unit("pf-target.service")
    fw.wait_until_succeeds("ip -4 address show eth1 | grep -q 198.18.10.100/24", timeout=30)
    fw.wait_until_succeeds("ip -4 address show eth2 | grep -q 198.18.20.1/24", timeout=30)
    for interface in ["eth1", "eth2"]:
        fw.wait_until_succeeds("ip -details link show " + interface + " | grep -q prog/xdp", timeout=60)
    uplink_ready.wait_uplink_addressed(fw, "eth1", "198.18.10.100")
    wan_index = int(fw.succeed("cat /sys/class/net/eth1/ifindex"))
    links = json.loads(fw.succeed("bpftool -j link show"))
    assert any(l.get("type") == "tcx" and l.get("ifindex") == wan_index
               and l.get("attach_type") == "tcx_egress" for l in links), links
    fw.succeed("sysctl -w kernel.bpf_stats_enabled=1")

    # The history the live box had: one ICMP echo through the masquerade and
    # one port-forwarded connection, each a NAT write outside the TCP/UDP
    # port allocator.
    client.wait_until_succeeds("ping -c1 -W1 198.18.10.254", timeout=60)
    backend.wait_until_succeeds("curl -sf --max-time 5 http://198.18.10.100:8080/ | grep -q pf-target", timeout=60)
    receipt["napt_search_after_history"] = napt_search_bound()
    preserve()

    client.succeed(
        "systemd-run --unit=cps-held -p LimitNOFILE=65536 ${python} ${./nat-cps-probe.py} hold"
        " --count ${toString held} --ready /tmp/held.ready --release /tmp/held.release --out /tmp/held.json"
    )
    client.wait_until_succeeds("test -s /tmp/held.ready", timeout=60)

    # A client socket the probe has closed retransmits its FIN at most this
    # many times (0 means the kernel's built-in 8).
    orphan_retries = int(client.succeed("sysctl -n net.ipv4.tcp_orphan_retries").strip()) or 8
    receipt["client_orphan_retries"] = orphan_retries
    receipt["server_listen"] = {
        "sysctl": backend.succeed("sysctl net.core.somaxconn net.ipv4.tcp_max_syn_backlog net.ipv4.tcp_syncookies").strip(),
        "sockets": backend.succeed("ss -ltn 'sport = :9200'").strip(),
    }
    for phase in ["first", "after-expiry"]:
        if phase == "after-expiry":
            # Past the 30 s firewall closing timeout and inside the server's
            # 60 s TIME_WAIT: the second phase meets the table the first one
            # left behind, with its reset bindings already expired and its
            # clean ones still held (120 s). Reused client tuples and
            # reissued public ports both happen here.
            fw.sleep(45)
        capture = "/tmp/server-resets-" + phase + ".pcap"
        backend.succeed("systemd-run --unit=server-resets-" + phase + " ${pkgs.tcpdump}/bin/tcpdump -p -U -i eth1 -w " + capture + " 'tcp src port 9200 and tcp[13] & 4 != 0'")
        backend.wait_until_succeeds("test -s " + capture, timeout=10)
        cursor = journal_cursor()
        counters = stats()
        path = path_counters()
        runtime = egress_runtime()
        result = json.loads(client.succeed(
            "prlimit --nofile=65536 ${python} ${./nat-cps-probe.py} open"
            " --count ${toString (rate * seconds)} --rate ${toString rate} --processes 4 --timeout 5"
        ))
        after = egress_runtime()
        result["phase"] = phase
        result["path"] = path_delta(path, path_counters())
        result["hop_loss"] = hop_loss(result["path"])
        # Late repeated server RSTs are still refused after the probe returns,
        # and the drop log trails the counters. Read both until the refusals
        # the counters hold match the ones logged, so the two describe the
        # same packets; then stop the RST capture, which then holds every
        # RST behind a counted refusal.
        for _ in range(40):
            refused = refusals(cursor)
            result["counters"] = delta(counters, stats())
            if len(refused) == result["counters"].get("dropped_default", 0):
                break
            time.sleep(0.5)
        result["refusals"] = refused
        result["dataplane_drops"] = {k: result["counters"][k] for k in DATAPLANE_DROPS if result["counters"].get(k)}
        result["nat_drops"] = {k: result["counters"][k] for k in NAT_DROPS if result["counters"].get(k)}
        backend.succeed("systemctl stop server-resets-" + phase)
        result["server_resets"] = server_resets(capture)
        runs = after[1] - runtime[1]
        result["egress_runs"] = runs
        result["egress_mean_ns"] = (after[0] - runtime[0]) // runs if runs else None
        result["napt_search"] = napt_search_bound()
        receipt["phases"].append(result)
        preserve()

    client.succeed("touch /tmp/held.release")
    client.wait_until_succeeds("test -s /tmp/held.json", timeout=120)
    receipt["held_result"] = json.loads(client.succeed("cat /tmp/held.json"))
    preserve()
    print(json.dumps(receipt, indent=2))
    print("packets lost per hop (sent minus received) and refusals per phase:")
    for result in receipt["phases"]:
        print(result["phase"].ljust(13), "  ".join(f"{k}={v}" for k, v in result["hop_loss"].items()),
              " slow-connects=" + str(result["retransmit_shaped_connects"]),
              " dataplane-drops=" + json.dumps(result["dataplane_drops"]))
        for source, proto, port, reason in result["refusals"]:
            print("  refused", source, "proto", proto, "WAN port", port, reason,
                  "- server RSTs to that port:", result["server_resets"].get(port, 0))

    # A dead datapath under default-accept would pass a rate check for the
    # wrong reason: every completion must have been masqueraded.
    held_result = receipt["held_result"]
    assert held_result["held"] == ${toString held} and held_result["rounds"] >= 3, held_result
    assert not held_result["echo_failures"], held_result["echo_failures"][:5]
    for result in receipt["phases"]:
        name = result["phase"]
        assert result["client_lag_p99_ms"] < 250, (name, "client could not offer the rate; the check is invalid", result)
        assert result["counters"].get("egress_masqueraded", 0) >= result["offered"], (name, result["counters"])
        assert result["failures"] == {}, (name, result["failures"], result)
        assert result["completed"] == result["offered"], (name, result)
        assert result["wan_ports_shared_by_client_ports"] == 0, (name, result)
        # What the firewall owns. It forwards what it receives: received on
        # one NIC minus sent on the other is the few packets of sampling skew
        # between the two counter reads (and the odd ARP), not a loss, once
        # the refusals below are taken off their direction.
        egress = result["counters"].get("egress_dropped", 0)
        dropped = sum(result["dataplane_drops"].values()) - egress
        assert abs(result["hop_loss"]["fw lan>wan"] - egress) <= 4, (name, result["hop_loss"], egress)
        assert abs(result["hop_loss"]["fw wan>lan"] - dropped) <= 4, (name, result["hop_loss"], dropped)
        # The one refusal this load legitimately causes: when a client
        # retransmission reaches a server that has already closed, the server
        # answers with several RSTs in quick succession. The first closes the
        # flow in the firewall, and the repeats find no state and fall to the
        # WAN default drop. Every refusal must be exactly that: logged, from
        # the server, TCP, dropped_default, to a WAN port that received more
        # server RSTs than refusals. Anything else is a real drop.
        assert set(result["dataplane_drops"]) <= {"dropped_default", "egress_dropped"}, (name, result["dataplane_drops"])
        assert len(result["refusals"]) == dropped, (name, "a refusal was not logged", result["refusals"], dropped)
        per_port: dict[int, int] = {}
        for source, proto, port, reason in result["refusals"]:
            assert (source, proto, reason) == ("198.18.10.254", 6, "dropped_default"), (name, source, proto, port, reason)
            per_port[port] = per_port.get(port, 0) + 1
        for port, count in per_port.items():
            assert count < result["server_resets"].get(port, 0), (name, "not a repeated RST", port, count, result["server_resets"].get(port, 0))
        # The same closure seen from the LAN: the server's first RST ended the
        # binding, and when that RST is then lost on its way to the client,
        # the client retransmits its FIN into a binding that is gone. DP-08
        # refuses that rather than letting a non-opener allocate. Every egress
        # drop must be exactly that refusal, and only a flow a server RST
        # closed whose RST never reached the client can cause one, at most
        # once per FIN retransmission the client's kernel makes for a closed
        # socket. Such RSTs are among the flows the capture saw reset and
        # among the packets lost on the fw>client link. The egress drop is
        # not logged per flow, so it is bounded by those, not attributed.
        assert egress == result["counters"].get("nat_opener_required", 0), (name, "an egress drop that is not a NAT opener refusal", result["counters"])
        lost_resets = min(len(result["server_resets"]), max(result["hop_loss"]["fw>client"], 0))
        assert egress <= orphan_retries * lost_resets, (name, "more opener refusals than lost server RSTs explain", egress, orphan_retries, lost_resets, result["server_resets"])
        assert result["nat_drops"] == {}, (name, result["nat_drops"])
        # A tripwire for the PERF-02 collapse, which left most new connections
        # retransmitting their SYN: 99.5 % of them never completed. The test
        # network's links between VMs lose packets on their own under this
        # open loop, and how many depends on the host: up to 276 connections
        # per phase needed a retransmission on an idle builder (up to 652
        # packets lost per hop), none on a quiet GitHub runner, and 758 on a
        # loaded one (2014 lost on one hop), each time with the firewall
        # forwarding everything it received. 10 % of the offered connections
        # (2000) is 2.6 times the worst of those and still five times below
        # "most"; the collapse itself also fails the completion asserts above.
        assert result["retransmit_shaped_connects"] <= result["offered"] // 10, (name, result["hop_loss"], result)
        assert result["completed_rate"] >= 0.95 * ${toString rate}, (name, result)
    fw.succeed("systemctl is-active sentinel-boot.service velstra.service")
  '';
}
