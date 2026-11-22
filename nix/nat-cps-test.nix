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
# one of them completed, at most 1 % needing a SYN retransmission. That is
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
      environment.systemPackages = [ pkgs.curl ];
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
    import json
    import os
    import re
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
        counters = stats()
        path = path_counters()
        runtime = egress_runtime()
        result = json.loads(client.succeed(
            "prlimit --nofile=65536 ${python} ${./nat-cps-probe.py} open"
            " --count ${toString (rate * seconds)} --rate ${toString rate} --processes 4 --timeout 5"
        ))
        after = egress_runtime()
        result["phase"] = phase
        result["counters"] = delta(counters, stats())
        result["path"] = path_delta(path, path_counters())
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
        # The test network itself loses the odd SYN under a 2000/s open
        # loop (one retransmission, ~1 s); the collapse loses nearly all.
        assert result["retransmit_shaped_connects"] <= result["offered"] // 100, (name, result)
        assert result["completed_rate"] >= 0.95 * ${toString rate}, (name, result)
        assert result["wan_ports_shared_by_client_ports"] == 0, (name, result)
        assert result["counters"].get("egress_nat_no_candidate", 0) == 0, (name, result["counters"])
        assert result["counters"].get("egress_nat_claim_failed", 0) == 0, (name, result["counters"])
    fw.succeed("systemctl is-active sentinel-boot.service velstra.service")
  '';
}
