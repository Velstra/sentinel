# A config-sync credential activates the same API, never a wider listener.
# Explicit destination binding is NOT ingress-interface isolation: that separate
# opt-in ACL contract is covered by management-ingress-test.nix.
{ pkgs, self }:
let
  lib = pkgs.lib;
  token = "api-management-bind-disposable-vm-credential";
in
pkgs.testers.runNixOSTest {
  name = "sentinel-api-explicit-management-bind";
  globalTimeout = 300;
  nodes = {
    fw = {
      imports = [ self.nixosModules.sentinel ];
      virtualisation = { vlans = [ 1 2 ]; memorySize = 1536; };
      networking.firewall.enable = lib.mkForce false;
      services.velstra.interface = lib.mkForce "eth2";
      services.velstra.appliance = lib.mkForce ((pkgs.formats.toml { }).generate "api-management-bind.toml" {
        system.hostname = "api-management-bind";
        interface = [
          { name = "eth0"; address = "dhcp"; }
          { name = "eth1"; address = "10.82.0.1/24"; }
          { name = "eth2"; address = "10.83.0.1/24"; zone = "lan"; }
        ];
        firewall.default_action = "accept";
      });
      environment.systemPackages = [ pkgs.curl pkgs.openssl ];
    };
    client = {
      virtualisation = { vlans = [ 1 2 ]; memorySize = 768; };
      networking = {
        useNetworkd = true;
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1.ipv4.addresses = [{ address = "10.82.0.2"; prefixLength = 24; }];
        interfaces.eth2.ipv4.addresses = [{ address = "10.83.0.2"; prefixLength = 24; }];
      };
      environment.systemPackages = [ pkgs.curl ];
    };
  };
  testScript = ''
    import json, os, shlex
    from pathlib import Path

    start_all()
    for node in (fw, client):
        node.wait_for_unit("multi-user.target")
    fw.wait_for_unit("sentinel-boot.service")
    fw.wait_for_unit("velstra.service")
    client.wait_until_succeeds("ping -c1 -W1 10.82.0.1 && ping -c1 -W1 10.83.0.1", timeout=30)
    results = {}

    def configure(lines):
        script = "\n".join(lines + ["commit", "save", "exit"]) + "\n"
        output = fw.succeed("printf %s " + shlex.quote(script) + " | sentinel configure 2>&1")
        assert "error:" not in output.lower(), output
        fw.wait_for_unit("sentinel-api.service")

    def listeners(port):
        return fw.succeed("ss -H -ltn 'sport = :" + str(port) + "'").splitlines()

    def exact_listener(address, port):
        def assertion():
            rows = listeners(port)
            assert len(rows) == 1 and rows[0].split()[3] == address + ":" + str(port), rows
        fw.wait_until_succeeds("test $(ss -H -ltn 'sport = :" + str(port) + "' | wc -l) = 1", timeout=20)
        assertion()

    def request(node, address, port, route="health", authenticated=False, pinned=False):
        url = "https://" + address + ":" + str(port) + "/api/v1/" + route
        command = "curl --noproxy '*' -sSk --connect-timeout 2 --max-time 5 "
        if authenticated:
            command += "-H 'Authorization: Bearer ${token}' "
        if pinned:
            command += "--pinnedpubkey /tmp/api-bind-public.pem "
        output = node.succeed(command + "-w '\n%{http_code}' " + shlex.quote(url))
        body, status = output.rsplit("\n", 1)
        return int(status), json.loads(body)

    def refused(node, address, port):
        # A listener refusal is meaningful only while both real ingress links
        # still work; never accept a routing/firewall outage as bind isolation.
        node.succeed("ping -c1 -W1 " + shlex.quote(address))
        status, output = node.execute("curl --noproxy '*' -sSk --connect-timeout 2 --max-time 5 "
            + shlex.quote("https://" + address + ":" + str(port) + "/api/v1/health") + " 2>&1")
        assert status == 7, (address, port, status, output)

    with subtest("secret alone retains the default loopback listener"):
        configure(["set system config-sync secret ${token}"])
        exact_listener("127.0.0.1", 8080)
        assert request(fw, "127.0.0.1", 8080)[0] == 200
        assert request(fw, "127.0.0.1", 8080, "config")[0] == 401
        for address in ("10.82.0.1", "10.83.0.1"):
            refused(client, address, 8080)
        # Rebinding to a new IP legitimately renews the certificate SAN. Its
        # persisted public key, not the whole certificate, is the pinned identity.
        public_key = fw.succeed("openssl x509 -in /var/lib/sentinel/web-tls/cert.pem -pubkey -noout")
        for node in (fw, client):
            node.succeed("printf %s " + shlex.quote(public_key) + " >/tmp/api-bind-public.pem")
        results["secret_only_default"] = dict(listener="127.0.0.1:8080", local_health=200,
            unauthenticated_config=401, both_remote_addresses_refused=True)

    with subtest("secret-only explicit management address and custom port serve pinned TLS"):
        # These field setters intentionally enable web; explicitly disable it
        # last so the shared secret alone must keep the API alive in this case.
        configure(["set services web listen-address 10.82.0.1", "set services web port 8443",
                   "set services web enable false"])
        exact_listener("10.82.0.1", 8443)
        assert listeners(8080) == []
        assert fw.succeed("openssl x509 -in /var/lib/sentinel/web-tls/cert.pem -pubkey -noout") == public_key
        assert request(client, "10.82.0.1", 8443, pinned=True)[0] == 200
        assert request(client, "10.82.0.1", 8443, "config", authenticated=True, pinned=True)[0] == 200
        refused(client, "10.83.0.1", 8443)
        refused(fw, "127.0.0.1", 8443)
        status, _ = client.execute("curl --noproxy '*' -sSk --connect-timeout 2 --max-time 5 "
            "--pinnedpubkey 'sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' "
            "https://10.82.0.1:8443/api/v1/health 2>&1")
        assert status == 90, "mismatched TLS public key was not rejected"
        assert fw.succeed("openssl x509 -in /var/lib/sentinel/web-tls/cert.pem -pubkey -noout") == public_key
        saved = json.loads(fw.succeed("sentinel config convert /var/lib/sentinel/appliance.toml --to json"))
        assert saved["services"]["web"]["enable"] is False
        results["secret_only_explicit"] = dict(listener="10.82.0.1:8443", health=200,
            authenticated_config=200, tls_pin_verified=True, wrong_pin_exit=90,
            other_address_refused=True, web_enabled=False, public_key_unchanged=True)

    with subtest("web and sync together honor explicit IPv4 and IPv6 loopback"):
        configure(["set services web enable true", "set services web listen-address 127.0.0.1"])
        exact_listener("127.0.0.1", 8443)
        assert request(fw, "127.0.0.1", 8443, "config", authenticated=True, pinned=True)[0] == 200
        assert fw.succeed("openssl x509 -in /var/lib/sentinel/web-tls/cert.pem -pubkey -noout") == public_key
        for address in ("10.82.0.1", "10.83.0.1"):
            refused(client, address, 8443)
        configure(["set services web listen-address ::1"])
        exact_listener("[::1]", 8443)
        assert request(fw, "[::1]", 8443, "config", authenticated=True, pinned=True)[0] == 200
        assert fw.succeed("openssl x509 -in /var/lib/sentinel/web-tls/cert.pem -pubkey -noout") == public_key
        for address in ("10.82.0.1", "10.83.0.1"):
            refused(client, address, 8443)
        results["web_and_sync_loopback"] = dict(ipv4="127.0.0.1:8443", ipv6="[::1]:8443",
            authenticated_config=200, both_remote_addresses_refused=True, public_key_unchanged=True)

    with subtest("saved explicit bind survives reboot without failed units"):
        cert_hash = fw.succeed("sha256sum /var/lib/sentinel/web-tls/cert.pem").split()[0]
        fw.shutdown()
        fw.start()
        fw.wait_for_unit("multi-user.target")
        fw.wait_for_unit("sentinel-boot.service")
        fw.wait_for_unit("sentinel-api.service")
        client.wait_until_succeeds("ping -c1 -W1 10.82.0.1 && ping -c1 -W1 10.83.0.1", timeout=30)
        exact_listener("[::1]", 8443)
        fw.succeed("printf %s " + shlex.quote(public_key) + " >/tmp/api-bind-public.pem")
        assert request(fw, "[::1]", 8443, "config", authenticated=True, pinned=True)[0] == 200
        assert fw.succeed("openssl x509 -in /var/lib/sentinel/web-tls/cert.pem -pubkey -noout") == public_key
        for address in ("10.82.0.1", "10.83.0.1"):
            refused(client, address, 8443)
        assert fw.succeed("systemctl --failed --no-legend --plain").strip() == ""
        assert fw.succeed("sha256sum /var/lib/sentinel/web-tls/cert.pem").split()[0] == cert_hash
        results["reboot"] = dict(listener="[::1]:8443", authenticated_config=200,
            remote_refused=True, no_failed_units=True, certificate_unchanged=True)

    Path(os.environ["out"], "api-management-bind.json").write_text(json.dumps(results, indent=2))
  '';
}
