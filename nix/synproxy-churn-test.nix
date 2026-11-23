# C15 SYN proxy splice lifetime: an IDLE proxied connection must survive many
# short ones, and no off-path forgery may end it. The proxy's per-connection
# record (`SYN_FLOWS`, an LRU) used to be removed by nothing, so every
# connection that ever completed kept its
# slot; once as many had come and gone as the map holds, each new admission
# evicted the least recently used record — an idle live connection — and it
# died silently: its client's segments read as a forged handshake ACK, its
# server's went out untranslated.
#
# The agent's state tables are shrunk to their minimum (`[state] connections =
# 1024`, so SYN_FLOWS holds 1024) to make "as many as the map holds" a minute's
# work. Short connections close both ways real clients do — normally (FIN) and
# with a reset — paced so that the firewall's own tables never fill: what is
# under test is the proxy's record, not capacity. Idle connections run routed
# and through a port-forward that changes the port (public 8025 -> inside
# 2525), whose server side carries a different tuple than the client opened.
#
# Then blind forgeries a sender who knows only who is talking to whom can send
# with an idle connection's tuple — a SYN on the live tuple, a SYN from the
# same client port to another server, a FIN and a reset with made-up sequence
# numbers — none of which may end its splice or stop the connection.
#
# Every scenario runs; failures are reported together.
{ pkgs, self }:
let
  banner = ./synproxy-banner.py;
  attack = ./synproxy-attack.py;
  churn = 1100;
in
pkgs.testers.runNixOSTest {
  name = "sentinel-synproxy-churn";
  globalTimeout = 1500;
  nodes = {
    client =
      { pkgs, ... }:
      {
        virtualisation.vlans = [ 1 ];
        networking = {
          useNetworkd = true;
          useDHCP = false;
          firewall.enable = false;
          interfaces.eth1.ipv4.addresses = [
            {
              address = "10.1.0.9";
              prefixLength = 24;
            }
          ];
          interfaces.eth1.ipv4.routes = [
            {
              address = "10.2.0.0";
              prefixLength = 24;
              via = "10.1.0.1";
            }
          ];
        };
        environment.systemPackages = [ pkgs.python3 ];
      };
    server =
      { pkgs, ... }:
      {
        virtualisation.vlans = [ 2 ];
        networking = {
          useNetworkd = true;
          useDHCP = false;
          firewall.enable = false;
          interfaces.eth1.ipv4.addresses = [
            {
              address = "10.2.0.2";
              prefixLength = 24;
            }
          ];
          defaultGateway = {
            address = "10.2.0.1";
            interface = "eth1";
          };
        };
        systemd.services.banner = {
          wantedBy = [ "multi-user.target" ];
          after = [ "network-online.target" ];
          script = "exec ${pkgs.python3}/bin/python3 ${banner} serve 2525";
        };
      };
    fw =
      { lib, pkgs, ... }:
      {
        imports = [ self.nixosModules.sentinel ./test-network-seed.nix ];
        networking.hostName = lib.mkForce "fw";
        networking.firewall.enable = lib.mkForce false;
        networking.interfaces.eth1.ipv4.addresses = [
          {
            address = "10.1.0.1";
            prefixLength = 24;
          }
        ];
        networking.interfaces.eth2.ipv4.addresses = [
          {
            address = "10.2.0.1";
            prefixLength = 24;
          }
        ];
        virtualisation.vlans = [
          1
          2
        ];
        virtualisation.memorySize = 2048;
        environment.systemPackages = [ pkgs.bpftools ];
        boot.kernel.sysctl = {
          "net.ipv4.ip_forward" = 1;
          "net.ipv4.conf.all.rp_filter" = 0;
          "net.ipv4.conf.default.rp_filter" = 0;
        };
        services.velstra.interface = lib.mkForce "eth1";
      };
  };
  testScript = ''
    import re

    failures = []

    def scenario(name, body):
        try:
            with subtest(name):
                body()
        except Exception as error:
            failures.append(f"{name}: {error}")
            print(f"SCENARIO FAILED: {name}: {error}")

    def counter(name):
        text = fw.succeed("sentinel show firewall statistics")
        m = re.search(rf"^\s*{name}\s+(\d+)", text, re.M)
        return int(m.group(1)) if m else 0

    def entries(table):
        return int(fw.succeed(f"bpftool -j map dump name {table} | grep -o '\"key\"' | wc -l").strip())

    def hold(marker, host, port):
        # One idle connection, proxied: its handshake was challenged and admitted.
        for _ in range(15):
            base = counter("synproxy_admitted")
            client.succeed(f"rm -f {marker}.*")
            client.succeed(
                f"setsid -f ${pkgs.python3}/bin/python3 ${banner} hold {host} {port} {marker} "
                f"> {marker}.log 2>&1 < /dev/null"
            )
            client.wait_until_succeeds(f"test -e {marker}.ready", timeout=30)
            if counter("synproxy_admitted") > base:
                return int(client.succeed(f"cat {marker}.port").strip())
            client.succeed(f"touch {marker}.go; sleep 1")
            fw.sleep(2)
        raise AssertionError(f"the idle connection to {host}:{port} was never proxied")

    def speaks(marker):
        client.succeed(f"touch {marker}.go")
        client.wait_until_succeeds(f"test -e {marker}.ok -o -e {marker}.fail", timeout=30)
        failure = client.succeed(f"cat {marker}.fail 2>/dev/null || true").strip()
        assert not failure, (
            f"the idle proxied connection {marker} died: {failure}\n"
            + fw.succeed("sentinel show firewall statistics")
        )

    start_all()
    fw.wait_for_unit("velstra.service")
    server.wait_for_unit("banner.service")
    client.wait_for_unit("multi-user.target")
    fw.wait_until_succeeds("ip addr show eth2 | grep -q 10.2.0.1", timeout=30)

    fw.succeed(
        "su admin -c \"printf '%s\\n' "
        "'set interface eth1 zone wan' "
        "'set interface eth2 zone lan' "
        "'set firewall zone wan default-action drop' "
        "'set firewall zone lan default-action accept' "
        "'set firewall rule banner-in from wan' "
        "'set firewall rule banner-in to lan' "
        "'set firewall rule banner-in proto tcp' "
        "'set firewall rule banner-in port 2525' "
        "'set firewall rule banner-in action accept' "
        "'set nat destination fwd zone wan' "
        "'set nat destination fwd proto tcp' "
        "'set nat destination fwd port 8025' "
        "'set nat destination fwd to 10.2.0.2:2525' "
        "'set firewall global conntrack tcp-closing 3' "
        "'set firewall syn-protect 2525' "
        "'set firewall syn-protect 8025' "
        "commit exit "
        "| sentinel configure\" 2>&1"
    )
    fw.wait_until_succeeds("grep -q '^\\[\\[synproxy\\]\\]' /run/sentinel/velstra.toml", timeout=30)

    # The smallest state tables the agent accepts. A load-time property: the
    # agent restarts with fresh maps of the new size.
    fw.succeed("grep -q '^\\[state\\]' /run/sentinel/velstra.toml")
    fw.succeed("sed -i 's/^\\[state\\]$/[state]\\nconnections = 1024/' /run/sentinel/velstra.toml")
    fw.succeed("systemctl restart velstra.service")
    fw.wait_for_unit("velstra.service")
    fw.wait_until_succeeds(
        "bpftool -j map show name SYN_FLOWS | grep -q '\"max_entries\":1024'", timeout=60
    )
    fw.fail("journalctl -u velstra.service | grep -q 'Error: loading'")

    routed = hold("/tmp/routed", "10.2.0.2", 2525)
    forwarded = hold("/tmp/forwarded", "10.1.0.1", 8025)
    target = hold("/tmp/target", "10.2.0.2", 2525)
    forge = "python3 ${attack}"

    def splice_of_target():
        # The SYN_FLOWS record of the target connection, by its exact key:
        # FlowKey { policy 0, client 10.1.0.9, server address zeroed, client
        # port, the port the server uses, TCP } (velstra_common::splice_key).
        ports = " ".join(
            f"{b:02x}" for b in target.to_bytes(2, "little") + (2525).to_bytes(2, "little")
        )
        key = f"00 00 00 00 0a 01 00 09 00 00 00 00 {ports} 06 00 00 00"
        status, out = fw.execute(f"bpftool -j map lookup name SYN_FLOWS key hex {key}")
        return out.strip() if status == 0 else None

    def attacks():
        # Blind forgeries carrying the live target connection's tuple: none
        # may end its splice, and none may stop the connection.
        recorded = splice_of_target()
        assert recorded, "the target connection has no splice to attack"
        client.succeed(f"{forge} syn 10.1.0.9 {target} 10.2.0.2 2525")
        client.succeed(f"{forge} syn 10.1.0.9 {target} 10.2.0.3 2525")
        client.succeed(f"{forge} fin 10.1.0.9 {target} 10.2.0.2 2525")
        client.succeed(f"{forge} rst 10.1.0.9 {target} 10.2.0.2 2525 0x2468ace0")
        # Two sweep rounds, then the splice must be there, unchanged, and the
        # connection must still carry traffic.
        fw.sleep(8)
        survived = splice_of_target()
        assert survived == recorded, f"the target's splice changed or went: {recorded} -> {survived}"
        speaks("/tmp/target")
    scenario("off-path forgeries do not end a live splice", attacks)

    def churn():
        before = counter("synproxy_admitted")
        # Distinct source ports for the two services: a splice is keyed by the
        # port the server uses (2525 for both), so one client port reused
        # across them inside the sweep window is the documented limitation,
        # not what this measures.
        client.succeed("python3 ${banner} churn 10.2.0.2 2525 ${toString churn} 40 20000", timeout=600)
        client.succeed("python3 ${banner} churn 10.1.0.1 8025 150 40 30000", timeout=600)
        admitted = counter("synproxy_admitted") - before
        assert admitted >= ${toString churn} + 150, f"only {admitted} churn connections were proxied"
        print(f"SYN_FLOWS holds {entries('SYN_FLOWS')} records after {admitted} short connections")
        fw.sleep(8)
        print(f"SYN_FLOWS holds {entries('SYN_FLOWS')} records before the idle connections speak")
    scenario("more short proxied connections than SYN_FLOWS holds", churn)
    scenario("an idle routed connection survives the churn", lambda: speaks("/tmp/routed"))
    scenario("an idle port-changing forward survives the churn", lambda: speaks("/tmp/forwarded"))

    def drained():
        # Connections that ended (FIN and RST alike, routed and forwarded)
        # leave no record behind: removed, not merely evicted.
        fw.sleep(8)
        left = entries("SYN_FLOWS")
        if left >= 16:
            print(fw.succeed("bpftool -j map dump name SYN_FLOWS | head -c 4000; echo; bpftool -j map dump name FW_FLOWS | head -c 6000"))
        assert left < 16, f"{left} SYN_FLOWS records outlive their connections"
    scenario("ended connections leave no splice", drained)

    def stateless_refused():
        # A proxied connection lives as long as its connection state; a
        # stateless zone keeps none, so the agent's validator refuses it and
        # the commit with it, leaving the running configuration as it was.
        status, out = fw.execute(
            "su admin -c \"printf '%s\\n' 'set firewall global stateful false' commit exit "
            "| sentinel configure\" 2>&1"
        )
        assert status != 0 and "not stateful" in out, f"stateless syn-protect accepted ({status}):\n{out}"
        fw.fail("grep -q '^stateful = false' /run/sentinel/velstra.toml")
    scenario("syn-protect on a stateless zone is refused", stateless_refused)

    print(fw.succeed("sentinel show firewall statistics"))
    assert not failures, "SYN-proxy splice lifetime scenarios failed:\n  " + "\n  ".join(failures)
  '';
}
