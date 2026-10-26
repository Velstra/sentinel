{ pkgs, self }:
let
  python = pkgs.python3.withPackages (p: [ p.cryptography ]);
  # Disposable TEST identities only. Production identities must never enter the Nix store.
  pki = pkgs.runCommand "sentinel-fleet-test-pki" { nativeBuildInputs = [ pkgs.openssl pkgs.coreutils ]; } ''
    mkdir -p "$out"
    cd "$out"
    openssl req -x509 -newkey ed25519 -nodes -subj /CN=FleetTestCA -days 36500 -keyout ca.key -out ca.pem
    openssl req -x509 -newkey ed25519 -nodes -subj /CN=UntrustedCA -days 36500 -keyout wrong-ca.key -out wrong-ca.pem
    openssl req -new -newkey ed25519 -nodes -subj /CN=fleet-controller -keyout server.key -out server.csr
    printf '%s\n' 'subjectAltName=IP:10.55.0.2' 'extendedKeyUsage=serverAuth' > server.ext
    openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 36500 -extfile server.ext -out server.pem
    openssl req -new -newkey ed25519 -nodes -subj /CN=edge-a -keyout client.key -out client.csr
    printf '%s\n' 'extendedKeyUsage=clientAuth' > client.ext
    openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 36500 -extfile client.ext -out client.pem
    openssl genpkey -algorithm ed25519 -out signing.key
    openssl pkey -in signing.key -pubout -outform DER | tail -c 32 | base64 -w0 > signing.pub
  '';
in pkgs.testers.runNixOSTest {
  name = "sentinel-fleet";
  nodes = {
    fw = { lib, ... }: {
      imports = [ self.nixosModules.sentinel ];
      networking.hostName = lib.mkForce "fw";
      networking.firewall.enable = lib.mkForce false;
      virtualisation.vlans = [ 1 ];
      virtualisation.memorySize = 2048;
      virtualisation.cores = 2;
      services.velstra.interface = lib.mkForce "eth1";
      environment.systemPackages = [ pkgs.curl pkgs.python3 ];
    };
    controller = {
      virtualisation.vlans = [ 1 ];
      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4.addresses = [{ address = "10.55.0.2"; prefixLength = 24; }];
      systemd.services.fleet-controller = {
        wantedBy = [ "multi-user.target" ];
        preStart = ''
          install -d -m700 /var/lib/fleet-test
          install -m600 ${pki}/* /var/lib/fleet-test/
        '';
        serviceConfig.ExecStart = "${python}/bin/python3 ${../tests/fleet/controller.py}";
      };
      environment.systemPackages = [ pkgs.curl pkgs.python3 ];
    };
  };
  testScript = ''
    import json, shlex, time
    start_all()
    for node in (fw, controller):
        node.wait_for_unit("multi-user.target")
    fw.wait_for_unit("velstra.service")
    controller.wait_for_open_port(9443)
    config = "/var/lib/sentinel/appliance.toml"
    state = "/var/lib/sentinel/.appliance.toml.fleet.json"
    pending = "/var/lib/sentinel/.appliance.toml.pending.json"
    def configure(lines):
        out = fw.succeed("printf '%s\\n' " + " ".join(shlex.quote(line) for line in lines + ["commit", "save", "exit"]) + " | sentinel configure 2>&1")
        assert "error:" not in out.lower(), out
    def queue(sequence, operation, mode=""):
        controller.succeed("printf %s " + shlex.quote(json.dumps(dict(sequence=sequence, operation=operation, mode=mode))) + " > /var/lib/fleet-test/command.json")
    def poll(ok=True):
        command = "sentinel fleet-poll --config " + config
        return fw.succeed(command) if ok else fw.fail(command)
    def last_request():
        return json.loads(controller.succeed("tail -1 /var/lib/fleet-test/requests.jsonl"))
    def candidate(hostname):
        text = fw.succeed("cat " + config)
        current = json.loads(fw.succeed("sentinel config convert " + config + " --to json"))["system"]["hostname"]
        text = text.replace('hostname = "' + current + '"', 'hostname = "' + hostname + '"')
        controller.succeed("printf %s " + shlex.quote(text) + " > /var/lib/fleet-test/candidate.toml")
    def stop_timer():
        fw.succeed("systemctl stop sentinel-fleet.timer sentinel-fleet.service")
    def wait_ready():
        fw.wait_until_succeeds("${pkgs.python3}/bin/python3 -c " + shlex.quote("import json;assert json.load(open('" + pending + "'))['ready']"), timeout=60)
    def sequence():
        return json.loads(fw.succeed("cat " + state))["sequence"]

    with subtest("standalone boot and forwarding do not require fleet"):
        fw.fail("systemctl is-active sentinel-fleet.timer")
        poll()
        controller.succeed("test ! -e /var/lib/fleet-test/requests.jsonl")
        configure(["set system hostname fleet-fw", "set interface eth1 zone lan", "set interface eth1 address 10.55.0.1/24",
            "set firewall global default-action accept", "set firewall rule ping from lan", "set firewall rule ping proto icmp", "set firewall rule ping log true", "set firewall rule ping action accept",
            "set services web enable true", "set services web tls false", "set services web confirm-timeout 8"])
        fw.succeed("ping -c 1 -W 2 10.55.0.2")

    with subtest("configured mTLS enrollment activates and removing trust fails closed"):
        fw.succeed("install -d -m700 /var/lib/sentinel/fleet; install -m600 ${pki}/client.key /var/lib/sentinel/fleet/client.key; install -m644 ${pki}/client.pem ${pki}/ca.pem /var/lib/sentinel/fleet/")
        fw.succeed("printf %s fleet-test-enrollment-credential > /var/lib/sentinel/fleet/token; chmod 600 /var/lib/sentinel/fleet/token")
        public_key = fw.succeed("cat ${pki}/signing.pub").strip()
        configure(["set fleet controller-url https://10.55.0.2:9443", "set fleet node-id edge-a",
            "set fleet enrollment-token file:/var/lib/sentinel/fleet/token", "set fleet signing-key " + public_key,
            "set fleet ca-certificate /var/lib/sentinel/fleet/ca.pem", "set fleet client-certificate /var/lib/sentinel/fleet/client.pem",
            "set fleet client-key /var/lib/sentinel/fleet/client.key", "set fleet poll-interval 1"])
        fw.wait_for_unit("sentinel-fleet.timer")
        try:
            controller.wait_until_succeeds("test -s /var/lib/fleet-test/requests.jsonl", timeout=20)
        except Exception:
            print(fw.execute("systemctl status sentinel-fleet.service sentinel-fleet.timer; systemctl list-timers --all; journalctl -u sentinel-fleet.service --no-pager -n 30")[1])
            print(controller.execute("journalctl -u fleet-controller --no-pager -n 30")[1])
            raise
        stop_timer()
        fw.fail("curl -fsS --max-time 3 --cacert /var/lib/sentinel/fleet/ca.pem -X POST https://10.55.0.2:9443/api/v1/sentinel/check-in")
        fw.succeed("cp ${pki}/wrong-ca.pem /var/lib/sentinel/fleet/ca.pem")
        poll(False)
        fw.succeed("cp ${pki}/ca.pem /var/lib/sentinel/fleet/ca.pem")
        fw.succeed("printf %s incorrect-enrollment-credential > /var/lib/sentinel/fleet/token")
        poll(False)
        fw.succeed("printf %s fleet-test-enrollment-credential > /var/lib/sentinel/fleet/token")
        fw.succeed("chmod 644 /var/lib/sentinel/fleet/client.key")
        poll(False)
        fw.succeed("chmod 600 /var/lib/sentinel/fleet/client.key")
        poll()
        assert last_request()["node"] == "edge-a"
        assert last_request()["telemetry"] is None

    with subtest("signed telemetry requests do not steal the local packet ring"):
        controller.succeed("ping -c 2 -W 2 10.55.0.1")
        queue(1, dict(action="telemetry"))
        poll(); poll()
        telemetry = last_request()["telemetry"]
        assert telemetry["interfaces"] and "routes" in telemetry["routing"], telemetry
        assert not telemetry["events"], telemetry
        # Counters only by default: no connection sample, NAT flow or top
        # talker — nothing naming a client — leaves the box.
        assert telemetry["flow_detail"] is False and "top_talkers" not in telemetry, telemetry
        assert "total" in telemetry["conntrack"] and "states" not in telemetry["conntrack"], telemetry
        assert "nat_flows" not in telemetry["conntrack"], telemetry
        events = fw.succeed("sentinel agent-query 'packet-events 256'")
        assert '"rule":"ping"' in events or '"rule": "ping"' in events, events
        fw.succeed("test $(stat -c %a " + state + ") = 600")

    with subtest("invalid signatures target bindings and replay never mutate configuration"):
        for mode in ("wrong-signature", "wrong-node", "wrong-challenge"):
            queue(2, dict(action="telemetry"), mode)
            poll(False)
            assert sequence() == 1
        queue(1, dict(action="telemetry"))
        # Exactly the same already accepted payload is an idempotent retry.
        poll()
        queue(1, dict(action="revert", id="stale"))
        poll(False)
        assert sequence() == 1

    with subtest("signed configuration converges live and needs a separate signed confirmation"):
        candidate("fleet-confirmed")
        queue(2, dict(action="apply-hostname"))
        poll(); wait_ready()
        fw.succeed("hostname | grep -x fleet-confirmed")
        fw.succeed("grep -q fleet-confirmed " + config)
        fw.succeed("test -f " + pending)
        queue(3, dict(action="confirm-current"))
        fw.succeed("systemctl start sentinel-fleet.timer")
        fw.wait_until_succeeds("test ! -e " + pending, timeout=30)
        stop_timer()
        assert sequence() == 3
        time.sleep(9)
        fw.succeed("hostname | grep -x fleet-confirmed")
        fw.succeed("grep -q fleet-confirmed " + config)

    with subtest("a signed revision cannot touch local trust anchors"):
        text = fw.succeed("cat " + config) + '\n[[system.login]]\nusername = "mallory"\nssh-key = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc mallory@controller"]\n'
        controller.succeed("printf %s " + shlex.quote(text) + " > /var/lib/fleet-test/candidate.toml")
        queue(4, dict(action="apply-hostname"))
        poll(False)
        assert sequence() == 4
        assert json.loads(fw.succeed("cat " + state))["result"]["state"] == "refused"
        fw.succeed("test ! -e " + pending)
        fw.fail("grep -q mallory " + config)
        fw.fail("id mallory")

    with subtest("controller outage cannot prevent automatic rollback local edits or reboot"):
        candidate("fleet-must-revert")
        queue(5, dict(action="apply-hostname"))
        poll(); wait_ready()
        controller.succeed("systemctl stop fleet-controller.service")
        fw.wait_until_succeeds("test ! -e " + pending, timeout=30)
        fw.succeed("hostname | grep -x fleet-confirmed")
        configure(["set interface eth1 mtu 1400"])
        fw.succeed("test $(cat /sys/class/net/eth1/mtu) = 1400; ping -c 1 -W 2 10.55.0.2")
        assert sequence() == 5
        fw.shutdown()
        fw.start()
        fw.wait_for_unit("multi-user.target")
        fw.wait_for_unit("sentinel-fleet.timer")
        fw.succeed("hostname | grep -x fleet-confirmed; ping -c 1 -W 2 10.55.0.2")
        assert sequence() == 5
        controller.succeed("systemctl start fleet-controller.service")
        controller.wait_for_open_port(9443)
        stop_timer()
        queue(3, dict(action="telemetry"))
        poll(False)
        assert sequence() == 5

    with subtest("flow-level telemetry is sent only after a local opt-in"):
        configure(["set fleet flow-telemetry true"])
        stop_timer()
        queue(6, dict(action="telemetry"))
        poll(); poll()
        telemetry = last_request()["telemetry"]
        assert "flow_detail" not in telemetry and "top_talkers" in telemetry, telemetry
        assert "states" in telemetry["conntrack"] and "nat_flows" in telemetry["conntrack"], telemetry

    with subtest("deleting fleet returns the appliance to standalone without a reboot"):
        configure(["delete fleet"])
        fw.fail("systemctl is-active sentinel-fleet.timer")
        poll()
        fw.succeed("ping -c 1 -W 2 10.55.0.2")
  '';
}
