{ pkgs, self }:
# Authenticated conntrack sync as it ships (VCS2 over TCP, config-sync secret,
# explicit state peers on every member). A LAN client holds a masqueraded TCP
# connection through `fw`; `fw` replicates it to two peers (`bk1`, `bk2`), which
# proves the N-way mesh. State is only accepted between members whose shared
# policy digest agrees, so all three carry the same zones, NAT and rules and
# differ only in their own addresses. The backups are not on the flow's path:
# a flow they show was replicated, not seen.
let
  # Disposable, VM-only, and random: a config-sync secret that reads like
  # words is refused at check and commit, the shape `sentinel ha secret
  # generate` prints is what members carry.
  secret = "3068fa053fabbb486b885db58711df27d387fd3b631a5c3c5c8aae6102578a3f";
  member = number: lan: { lib, ... }: {
    imports = [ self.nixosModules.sentinel ./test-network-seed.nix ];
    networking.hostName = lib.mkForce "member${toString number}";
    networking.firewall.enable = lib.mkForce false;
    networking.interfaces.eth1.ipv4.addresses = [{ address = "10.1.0.${toString number}"; prefixLength = 24; }];
    networking.interfaces.eth2.ipv4.addresses = [{ address = "10.2.0.${toString lan}"; prefixLength = 24; }];
    virtualisation.vlans = [ 1 2 ];
    virtualisation.memorySize = 2048;
    boot.kernel.sysctl = {
      "net.ipv4.ip_forward" = 1;
      "net.ipv4.conf.all.rp_filter" = 0;
      "net.ipv4.conf.default.rp_filter" = 0;
    };
    services.velstra.interface = lib.mkForce "eth1";
  };
in pkgs.testers.runNixOSTest {
  name = "sentinel-conntracksync";
  nodes = {
    client = { pkgs, ... }: {
      virtualisation.vlans = [ 2 ];
      networking = {
        useNetworkd = true;
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1.ipv4.addresses = [{ address = "10.2.0.10"; prefixLength = 24; }];
        defaultGateway = { address = "10.2.0.1"; interface = "eth1"; };
      };
      environment.systemPackages = [ pkgs.curl pkgs.python3 ];
    };
    server = { pkgs, ... }: {
      virtualisation.vlans = [ 1 ];
      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4.addresses = [{ address = "10.1.0.10"; prefixLength = 24; }];
      systemd.services.web = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        script = ''
          mkdir -p /srv/web && echo hello-from-server > /srv/web/index.html
          exec ${pkgs.python3}/bin/python3 -m http.server 80 --directory /srv/web
        '';
      };
    };
    fw = member 1 1;
    bk1 = member 2 2;
    bk2 = member 3 3;
  };
  testScript = ''
    ${import ./uplink-ready.nix { inherit pkgs; }}
    members = {fw: 1, bk1: 2, bk2: 3}
    start_all()
    for n in members:
        n.wait_for_unit("multi-user.target")
        n.wait_for_unit("velstra.service")
        n.wait_until_succeeds("ip addr show eth1 | grep -q 10.1.0." + str(members[n]), timeout=20)
    server.wait_for_unit("web.service")

    # The same shared policy on every member; only the state endpoints differ.
    for n, number in members.items():
        peers = "".join(f"'set system conntrack-sync peer 10.1.0.{p}' " for p in (1, 2, 3) if p != number)
        n.succeed(
            "su admin -c \"printf '%s\\n' "
            "'set interface eth1 zone wan' "
            "'set interface eth2 zone lan' "
            "'set firewall zone lan default-action accept' "
            "'set nat source wan-masq zone wan' "
            "'set firewall rule state-sync from wan' "
            "'set firewall rule state-sync proto tcp' "
            "'set firewall rule state-sync port 5429' "
            "'set firewall rule state-sync action accept' "
            "'set system config-sync secret ${secret}' "
            f"'set system conntrack-sync listen 10.1.0.{number}:5429' "
            + peers +
            "commit save exit "
            "| sentinel configure\""
        )
    for n, number in members.items():
        n.wait_for_unit("velstra.service")
        n.succeed(f"grep -q '10.1.0.{number}:5429' /run/sentinel/velstra.toml")
        n.wait_until_succeeds(
            "journalctl -u velstra.service | grep -q 'conntrack-sync: authenticated TCP listening'",
            timeout=30,
        )

    # The flow: a masqueraded connection the client keeps open through fw.
    for n, number in members.items():
        uplink_ready.wait_uplink_addressed(n, "eth1", "10.1.0." + str(number))
    client.wait_until_succeeds("curl -s --max-time 5 http://10.1.0.10:80/ | grep -q hello-from-server", timeout=60)
    client.succeed(
        "systemd-run --unit=hold ${pkgs.python3}/bin/python3 -c "
        "'import socket,time; s=socket.create_connection((\"10.1.0.10\",80),5); time.sleep(600)'"
    )
    fw.wait_until_succeeds("sentinel show firewall flows | grep -q 10.2.0.10", timeout=30)

    # Both peers hold the flow they never forwarded: replicated, N-way.
    for n in (bk1, bk2):
        try:
            n.wait_until_succeeds("sentinel show firewall flows | grep -q 10.2.0.10", timeout=30)
        except Exception:
            print(n.execute("sentinel show firewall flows; journalctl -u velstra.service --no-pager -n 60")[1])
            raise
        # The digests agreed: no session was refused for a policy mismatch.
        n.fail("journalctl -u velstra.service | grep -q 'refusing state'")
  '';
}
