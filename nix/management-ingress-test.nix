# Explicit destination ACL acceptance, not automatic listen-address isolation.
# A real LAN packet is routed to the appliance's other, unzoned management NIC.
# Separate management access and forwarded same-port traffic are positive controls.
{ pkgs, self }:
let
  backend = pkgs.writeText "management-ingress-backend.py" ''
    import http.server, socket, ssl

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            assert self.path == "/backend"
            answer = b"forwarded-management-port-control\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(answer)))
            self.end_headers()
            self.wfile.write(answer)

        def log_message(self, *args):
            pass

    class DualStack(http.server.ThreadingHTTPServer):
        address_family = socket.AF_INET6

        def server_bind(self):
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            super().server_bind()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/run/management-backend/cert.pem", "/run/management-backend/key.pem")
    server = DualStack(("::", 8080), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
  '';
in
pkgs.testers.runNixOSTest {
  name = "sentinel-explicit-management-ingress-acl";
  globalTimeout = 360;
  nodes = {
    fw = { lib, ... }: {
      imports = [ self.nixosModules.sentinel ];
      virtualisation.vlans = [ 1 2 ];
      virtualisation.memorySize = 2048;
      networking.firewall.enable = lib.mkForce false;
      services.velstra.interface = lib.mkForce "eth2";
      services.velstra.appliance = lib.mkForce ((pkgs.formats.toml {}).generate "management-ingress.toml" {
        system.hostname = "management-ingress";
        interface = [
          { name = "eth0"; address = "dhcp"; }
          { name = "eth1"; address = "10.72.1.1/24"; address6 = "2001:db8:72:1::1/64"; }
          { name = "eth2"; zone = "lan"; address = "10.72.2.1/24"; address6 = "2001:db8:72:2::1/64"; }
        ];
        firewall.default_action = "accept";
        services.ssh = { enable = true; listen-address = "10.72.1.1"; };
        services.web = { enable = true; listen-address = "10.72.1.1"; tls = true; };
      });
      environment.systemPackages = [ pkgs.curl pkgs.tcpdump pkgs.python3 ];
    };
    management = {
      virtualisation.vlans = [ 1 ];
      networking = {
        useNetworkd = true;
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1 = {
          ipv4.addresses = [{ address = "10.72.1.2"; prefixLength = 24; }];
          ipv4.routes = [{ address = "10.72.2.0"; prefixLength = 24; via = "10.72.1.1"; }];
          ipv6.addresses = [{ address = "2001:db8:72:1::2"; prefixLength = 64; }];
          ipv6.routes = [{ address = "2001:db8:72:2::"; prefixLength = 64; via = "2001:db8:72:1::1"; }];
        };
      };
      services.openssh = { enable = true; settings.PermitRootLogin = "prohibit-password"; };
      environment.systemPackages = [ pkgs.curl pkgs.openssh ];
      systemd.services.management-backend = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig = {
          RuntimeDirectory = "management-backend";
          RuntimeDirectoryMode = "0700";
          ExecStart = "${pkgs.python3}/bin/python3 ${backend}";
        };
        preStart = ''
          ${pkgs.openssl}/bin/openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
            -subj /CN=disposable-management-backend \
            -keyout /run/management-backend/key.pem -out /run/management-backend/cert.pem 2>/dev/null
        '';
      };
    };
    lan = {
      virtualisation.vlans = [ 2 ];
      networking = {
        useNetworkd = true;
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1 = {
          ipv4.addresses = [{ address = "10.72.2.2"; prefixLength = 24; }];
          ipv4.routes = [{ address = "10.72.1.0"; prefixLength = 24; via = "10.72.2.1"; }];
          ipv6.addresses = [{ address = "2001:db8:72:2::2"; prefixLength = 64; }];
          ipv6.routes = [{ address = "2001:db8:72:1::"; prefixLength = 64; via = "2001:db8:72:2::1"; }];
        };
      };
      environment.systemPackages = [ pkgs.curl pkgs.openssh ];
    };
  };
  testScript = ''
    import json, os, shlex
    from pathlib import Path

    start_all()
    for node in (fw, management, lan):
        node.wait_for_unit("multi-user.target")
    fw.wait_for_unit("sentinel-boot.service")
    fw.wait_for_unit("velstra.service")
    management.wait_for_unit("management-backend.service")

    def configure(lines):
        commands = lines + ["commit", "save", "exit"]
        script = "printf '%s\\n' " + " ".join(shlex.quote(line) for line in commands)
        result = fw.succeed(script + " | sentinel configure 2>&1")
        assert "error:" not in result.lower(), result
        fw.wait_until_succeeds("ip link show eth2 | grep -q xdp", timeout=30)
        # The out-of-band management NIC deliberately stays unzoned/unfiltered.
        fw.fail("ip link show eth1 | grep -q xdp")
        return result

    keys = []
    for node in (management, lan):
        node.succeed("mkdir -p /root/.ssh && chmod 700 /root/.ssh && ssh-keygen -q -t ed25519 -N ''' -f /root/.ssh/id_ed25519")
        keys.append(node.succeed("cat /root/.ssh/id_ed25519.pub").strip())
    management.succeed("printf '%s\\n' " + shlex.quote(keys[1]) + " > /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys")
    configure(["set system login admin ssh-key " + key for key in keys])

    def ssh(target, user="admin"):
        return ("${pkgs.openssh}/bin/ssh -n -o BatchMode=yes -o StrictHostKeyChecking=no "
            "-o UserKnownHostsFile=/dev/null -o ConnectTimeout=2 -o ConnectionAttempts=1 "
            "-i /root/.ssh/id_ed25519 " + shlex.quote(user + "@" + target)
            + " " + shlex.quote("id -un"))

    def https(target, path="/api/v1/health"):
        host = "[" + target + "]" if ":" in target else target
        return ("${pkgs.curl}/bin/curl --noproxy '*' -g -ksSf --connect-timeout 2 --max-time 3 "
            + shlex.quote("https://" + host + ":8080" + path))

    def services_ready(target):
        fw.wait_for_unit("sshd.service")
        fw.wait_for_unit("sentinel-api.service")
        management.wait_until_succeeds(https(target), timeout=30)
        management.wait_until_succeeds(ssh(target), timeout=15)

    def positive_controls(target, backend_target):
        assert management.succeed(ssh(target)).strip() == "admin"
        health = json.loads(management.succeed(https(target)))
        assert health.get("status") == "ok", health
        assert lan.succeed(ssh(backend_target, "root")).strip() == "root"
        assert lan.succeed(https(backend_target, "/backend")).strip() == "forwarded-management-port-control"

    def assert_lan_allowed(target):
        assert lan.succeed(ssh(target)).strip() == "admin"
        assert json.loads(lan.succeed(https(target))).get("status") == "ok"

    def assert_lan_denied(target):
        code, output = lan.execute(ssh(target) + " 2>&1")
        assert code == 255 and "timed out" in output.lower(), (code, output)
        code, output = lan.execute(https(target))
        assert code == 28, (code, output)

    def capture_baseline(family, target):
        unit = "management-ingress-wire-" + family
        path = "/run/management-ingress-" + family + ".pcap"
        fw.succeed("systemd-run --unit=" + unit + " --property=RuntimeMaxSec=30 "
            "${pkgs.tcpdump}/bin/tcpdump --immediate-mode -U -ni eth2 -w " + path
            + " " + shlex.quote("tcp and dst host " + target + " and (dst port 22 or dst port 8080)"))
        fw.wait_until_succeeds("journalctl -u " + unit + " --no-pager | grep -q 'listening on eth2'", timeout=5)
        assert_lan_allowed(target)
        fw.succeed("systemctl kill --signal=SIGUSR2 " + unit + ".service")
        fw.succeed("systemctl stop " + unit + ".service")
        wire = fw.succeed("${pkgs.tcpdump}/bin/tcpdump -nn -r " + path + " 2>/dev/null")
        for port in (22, 8080):
            assert target + "." + str(port) + ": Flags [S]" in wire, (family, port, wire)
        return {"physical_ingress": "eth2", "management_address_owned_by": "eth1",
                "SSH_and_HTTPS_SYN_observed": True}

    observations = []
    for family, target, backend_target, prefix in (
        ("ipv4", "10.72.1.1", "10.72.1.2", "32"),
        ("ipv6", "2001:db8:72:1::1", "2001:db8:72:1::2", "128"),
    ):
        with subtest(family + " weak-host reproduction and explicit destination ACL"):
            configure(["set services ssh listen-address " + target,
                       "set services web listen-address " + target])
            services_ready(target)
            route = lan.succeed("ip " + ("-6" if family == "ipv6" else "-4") + " route get " + target)
            assert "via " + ("2001:db8:72:2::1" if family == "ipv6" else "10.72.2.1") in route, route
            # Genuine authenticated SSH and HTTPS reach a management destination
            # through the other ingress NIC before any explicit ACL exists.
            wire = capture_baseline(family, target)
            positive_controls(target, backend_target)
            name = "deny-lan-management-" + family
            configure([
                "set firewall rule " + name + " from lan",
                "set firewall rule " + name + " proto tcp",
                "set firewall rule " + name + " port 22,8080",
                "set firewall rule " + name + " destination " + target + "/" + prefix,
                "set firewall rule " + name + " family " + family,
                "set firewall rule " + name + " action drop",
                "set firewall rule " + name + " log true",
            ])
            services_ready(target)
            assert_lan_denied(target)
            positive_controls(target, backend_target)
            # Fresh SYNs must hit the actual eBPF drop, not a stopped listener or
            # a failed return route. The unfiltered management positives remain.
            events = fw.succeed("sentinel show firewall events")
            assert name in events, events
            before = fw.succeed("sha256sum /var/lib/sentinel/appliance.toml")
            fw.shutdown()
            fw.start()
            fw.wait_for_unit("multi-user.target")
            fw.wait_for_unit("sentinel-boot.service")
            fw.wait_for_unit("velstra.service")
            fw.wait_until_succeeds("ip link show eth2 | grep -q xdp", timeout=30)
            services_ready(target)
            assert fw.succeed("sha256sum /var/lib/sentinel/appliance.toml") == before
            assert_lan_denied(target)
            positive_controls(target, backend_target)
            configure(["delete firewall rule " + name])
            services_ready(target)
            assert_lan_allowed(target)
            positive_controls(target, backend_target)
            observations.append({"family": family, "baseline": wire,
                "explicit_destination_acl_blocks_LAN_SSH_and_HTTPS": True,
                "management_SSH_and_HTTPS_retained": True,
                "forwarded_same_port_SSH_and_HTTPS_retained": True,
                "saved_ACL_survives_reboot": True, "removal_restores_LAN_access": True})

    for node in (fw, management, lan):
        failed = node.succeed("systemctl --failed --no-legend --no-pager").strip()
        assert not failed, (node.name, failed)
    Path(os.environ["out"], "management-ingress.json").write_text(json.dumps({
        "contract": "opt-in explicit destination ACL, NOT automatic listen-address ingress isolation",
        "observations": observations}, indent=2))
  '';
}
