{ pkgs, self }:
pkgs.testers.runNixOSTest {
  name = "sentinel-management-safety";
  nodes = {
    fw = { lib, ... }: {
      imports = [ self.nixosModules.sentinel ];
      networking.hostName = lib.mkForce "fw";
      networking.firewall.enable = lib.mkForce false;
      virtualisation.vlans = [ 1 ];
      virtualisation.memorySize = 2048;
      virtualisation.cores = 2;
      services.velstra.interface = lib.mkForce "eth1";
      environment.systemPackages = [ pkgs.curl ];
    };
    client = {
      virtualisation.vlans = [ 1 ];
      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4.addresses = [{ address = "10.44.1.2"; prefixLength = 24; }];
      environment.systemPackages = [ pkgs.curl pkgs.netcat-openbsd ];
    };
  };
  testScript = ''
    import json, shlex, time
    start_all()
    for node in (fw, client):
        node.wait_for_unit("multi-user.target")
    fw.wait_for_unit("velstra.service")
    config = "/var/lib/sentinel/appliance.toml"
    pending = "/var/lib/sentinel/.appliance.toml.pending.json"
    commands = [
        "set system hostname fw",
        "set interface eth1 zone lan", "set interface eth1 address 10.44.1.1/24",
        "set services web enable true", "set services web tls false",
        "set services web listen-address 0.0.0.0", "set services web confirm-timeout 12",
        "set firewall global stateful true",
        "set firewall rule management from lan", "set firewall rule management proto tcp",
        "set firewall rule management port 8080", "set firewall rule management action accept",
        "set firewall rule management-tls from lan", "set firewall rule management-tls proto tcp",
        "set firewall rule management-tls port 8443", "set firewall rule management-tls action accept",
        "set firewall rule ping from lan", "set firewall rule ping proto icmp",
        "set firewall rule ping action accept", "set firewall rule ping log true",
        "set firewall rule denied from lan", "set firewall rule denied proto udp",
        "set firewall rule denied port 9099", "set firewall rule denied action drop",
        "set firewall rule denied log true", "commit", "save", "exit",
    ]
    out = fw.succeed("printf '%s\\n' " + " ".join(shlex.quote(x) for x in commands) + " | sentinel configure")
    assert "error:" not in out.lower(), out
    fw.wait_for_unit("sentinel-api.service")
    fw.wait_for_open_port(8080)
    token = fw.succeed("cat /var/lib/sentinel/api-token").strip()
    base = "http://127.0.0.1:8080/api/v1/"
    auth = " -H " + shlex.quote("Authorization: Bearer " + token)

    def request(path, body=None, method=None, wait=True):
        command = "curl -fsSk --max-time 30" + auth
        if body is not None:
            command += " -H 'Content-Type: application/json' --data-binary " + shlex.quote(json.dumps(body))
        if method:
            command += " -X " + method
        result = json.loads(fw.succeed(command + " " + shlex.quote(base + path)))
        if wait and result.get("pending") and not result["pending"]["ready"]:
            until = time.monotonic() + 90
            while time.monotonic() < until:
                state = request("config/transaction")["pending"]
                assert state is not None, "provisional application was reverted"
                if state["ready"]:
                    result["pending"] = state
                    break
                time.sleep(0.2)
            else:
                raise AssertionError("independent apply did not complete")
        return result

    def configure(lines):
        command = "printf '%s\\n' " + " ".join(shlex.quote(line) for line in lines) + " | sentinel configure 2>&1"
        return fw.execute(command)

    def candidate(hostname, move=False):
        document = request("config/document")
        text = document["toml"].replace('hostname = "fw"', 'hostname = "' + hostname + '"')
        if move:
            text = text.replace("10.44.1.1/24", "10.44.1.9/24")
        return dict(toml=text, expected_revision=document["revision"])

    client.succeed("curl -fsS --max-time 5 http://10.44.1.1:8080/api/v1/health")
    baseline = fw.succeed("cat " + config)

    with subtest("a management lockout expires and reconciles without a reboot"):
        result = request("config/document", candidate("locked-out", True))
        identity = result["pending"]["id"]
        fw.succeed("hostname | grep -x locked-out")
        fw.succeed("test $(stat -c %a " + pending + ") = 600")
        client.fail("curl -fsS --max-time 2 http://10.44.1.1:8080/api/v1/health")
        code, output = configure(["set system hostname unsafe-save", "commit", "save", "exit"])
        assert code != 0 and "confirmation pending" in output, output
        fw.wait_until_succeeds("test ! -f " + pending, timeout=40)
        assert fw.succeed("cat " + config) == baseline
        fw.succeed("hostname | grep -x fw")
        client.succeed("curl -fsS --max-time 5 http://10.44.1.1:8080/api/v1/health")
        code = fw.succeed("curl -s -o /dev/null -w '%{http_code}'" + auth + " -H 'Content-Type: application/json' -d " + shlex.quote(json.dumps(dict(id=identity))) + " " + base + "config/confirm").strip()
        assert code == "409", code

    with subtest("port and TLS changes complete after their API process restarts"):
        document = request("config/document")
        proposed = document["toml"].replace("[services.web]", "[services.web]\nport = 8443").replace("tls = false", "tls = true")
        request("config/document", dict(toml=proposed, expected_revision=document["revision"]), wait=False)
        base = "https://127.0.0.1:8443/api/v1/"
        fw.wait_for_open_port(8443)
        # This listener has the proposed TLS settings, not the old saved file.
        fw.wait_until_succeeds("curl -fsSk --max-time 2 " + base + "health", timeout=30)
        until = time.monotonic() + 60
        while time.monotonic() < until:
            state = json.loads(fw.succeed("curl -fsSk" + auth + " " + base + "config/transaction"))["pending"]
            assert state is not None
            if state["ready"]:
                break
            time.sleep(0.2)
        else:
            raise AssertionError("TLS-change worker did not finish")
        fw.succeed("curl -fsSk" + auth + " -H 'Content-Type: application/json' --data-binary " + shlex.quote(json.dumps(dict(id=state["id"]))) + " " + base + "config/confirm")
        document = json.loads(fw.succeed("curl -fsSk" + auth + " " + base + "config/document"))
        fw.succeed("curl -fsSk" + auth + " -H 'Content-Type: application/json' --data-binary " + shlex.quote(json.dumps(dict(toml=baseline,expected_revision=document["revision"]))) + " " + base + "config/document")
        base = "http://127.0.0.1:8080/api/v1/"
        fw.wait_for_open_port(8080)
        fw.wait_until_succeeds("curl -fsS --max-time 2 " + base + "health", timeout=30)
        until = time.monotonic() + 60
        while time.monotonic() < until:
            state = request("config/transaction")["pending"]
            assert state is not None
            if state["ready"]:
                request("config/confirm", dict(id=state["id"]))
                break
            time.sleep(0.2)
        else:
            raise AssertionError("return to plaintext baseline did not finish")

    with subtest("recovery survives a killed management server"):
        request("config/document", candidate("api-dies"))
        fw.succeed("systemctl kill --signal=KILL sentinel-api.service")
        fw.wait_until_succeeds("test ! -f " + pending, timeout=40)
        fw.wait_for_unit("sentinel-api.service")
        assert fw.succeed("cat " + config) == baseline
        fw.succeed("hostname | grep -x fw")

    with subtest("confirmation is explicit and survives the expiry window"):
        result = request("config/document", candidate("confirmed"))
        request("config/confirm", dict(id=result["pending"]["id"]))
        time.sleep(14)
        fw.succeed("hostname | grep -x confirmed")
        fw.succeed("test ! -f " + pending)
        # Restore the named baseline for the boot-recovery assertion.
        document = request("config/document")
        result = request("config/document", dict(toml=baseline, expected_revision=document["revision"]))
        request("config/confirm", dict(id=result["pending"]["id"]))

    with subtest("real eBPF accept/drop events fan out to two concurrent streams"):
        for number in (1, 2):
            fw.succeed("(curl -sN --max-time 8" + auth + " " + base + "telemetry > /tmp/stream" + str(number) + ") >/tmp/curl" + str(number) + ".log 2>&1 &")
        time.sleep(2)
        client.succeed("ping -c 2 -W 2 10.44.1.1")
        client.succeed("printf probe | nc -u -w 1 10.44.1.1 9099 || true")
        time.sleep(7)
        common = []
        for number in (1, 2):
            frames = [json.loads(line[5:]) for line in fw.succeed("cat /tmp/stream" + str(number)).splitlines() if line.startswith("data:")]
            frames = [frame for frame in frames if "sequence" in frame]
            assert frames, "no telemetry snapshots"
            events = {event["id"]: event for frame in frames for event in frame["events"]}
            assert any(event["src"] == "10.44.1.2" and event["rule"] == "ping" and event["action"] == "accept" for event in events.values()), events
            assert any(event["rule"] == "denied" and event["action"] == "drop" and event["dst_port"] == 9099 for event in events.values()), events
            assert any(interface["name"] == "eth1" and interface["rates"] is not None for frame in frames for interface in frame["interfaces"])
            assert frames[-1]["ha"]["role"] == "standalone", frames[-1]
            assert frames[-1]["conntrack"]["total"] >= 1, frames[-1]
            assert len(frames[-1]["conntrack"]["states"]) <= 200, frames[-1]
            assert any(rule["rule"] == "denied" and rule["dropped"] > 0 for rule in frames[-1]["rule_counters"]["rules"]), frames[-1]
            # The route table is sent once per change per stream, then marked
            # unchanged; the first frame of each stream carries it in full.
            assert "routes" in frames[0]["routing"], frames[0]
            assert "bgp" in frames[-1]["routing"] and ("routes" in frames[-1]["routing"] or frames[-1]["routing"].get("routes_unchanged")), frames[-1]
            common.append(set(events))
        assert common[0] & common[1], "streams stole each other's ring events"
        # Readers page the agent's event log with their own cursors: the CLI
        # still sees what both streams already showed.
        shown = fw.succeed("sentinel show firewall events")
        assert '"rule":"ping"' in shown or '"rule": "ping"' in shown, shown

    with subtest("an unconfirmed persisted document is restored before boot rendering"):
        # A long window ensures this tests reboot recovery, not expiry.
        code, out = configure(["set services web confirm-timeout 300", "commit", "save", "exit"])
        assert code == 0 and "error:" not in out.lower(), out
        saved = fw.succeed("cat " + config)
        request("config/document", candidate("must-not-boot"))
        fw.succeed("grep -q must-not-boot " + config)
        fw.crash()
        fw.start()
        fw.wait_for_unit("multi-user.target")
        fw.wait_for_unit("sentinel-boot.service")
        fw.succeed("hostname | grep -x fw")
        fw.succeed("test ! -f " + pending)
        assert fw.succeed("cat " + config) == saved
        client.wait_until_succeeds("curl -fsS --max-time 3 http://10.44.1.1:8080/api/v1/health", timeout=40)
  '';
}
