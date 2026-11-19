# Product SSH identities, six exact sudo capabilities and real daemon data.
# This is not general CLI/UI qualification or a replacement for HA tests.
{ pkgs, self }:
let
  inherit (pkgs) lib;
  sentinel = self.packages.x86_64-linux.sentinel;
  core = sentinel.unwrapped or sentinel;
  wren = self.packages.x86_64-linux.wren;
  backend = pkgs.writeText "observe-udp-backend.py" ''
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("10.11.0.2", 19000))
        print("OBSERVE_BACKEND_READY", flush=True)
        while True:
            data, peer = server.recvfrom(65535)
            server.sendto(data, peer)
  '';
  traffic = pkgs.writeText "observe-real-traffic.py" ''
    import json, socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind(("10.10.0.2", 45111))
        client.settimeout(2)
        client.connect(("10.10.0.1", 19099))
        verified = 0
        for number in range(32):
            payload = ("observe-readonly-real-dnat:%04d:" % number).encode() + bytes(range(256))
            client.send(payload)
            assert client.recv(65535) == payload
            verified += len(payload)
        print(json.dumps({"verified_datagrams": 32, "verified_bytes": verified}))
  '';
  node = address: management: { ... }: {
    imports = [ self.nixosModules.sentinel (self.outPath + "/nix/test-network-seed.nix") ];
    virtualisation = { vlans = [ 1 2 3 ]; memorySize = 1536; cores = 2; };
    networking.firewall.enable = lib.mkForce false;
    networking.interfaces.eth1.ipv4.addresses = [{ inherit address; prefixLength = 24; }];
    # The product deliberately lowers zoned links when its agent stops. Keep
    # diagnostic transport independent so unavailable assertions reach the
    # actual helper rather than failing because SSH itself disappeared.
    networking.interfaces.eth3.ipv4.addresses = [{ address = management; prefixLength = 24; }];
    services.velstra.interface = lib.mkForce "eth1";
    services.getty.autologinUser = lib.mkForce null;
    environment.systemPackages = [ pkgs.curl pkgs.openssh pkgs.python3 pkgs.util-linux ];
  };
in pkgs.testers.runNixOSTest {
  name = "sentinel-six-local-readonly-capabilities";
  globalTimeout = 300;
  nodes = {
    fw = { ... }: {
      imports = [ (node "10.10.0.1" "10.12.0.1") ];
      networking.interfaces.eth2.ipv4.addresses = [{ address = "10.11.0.1"; prefixLength = 24; }];
    };
    peer = node "10.10.0.2" "10.12.0.2";
  };
  testScript = ''
    import json
    import os
    from pathlib import Path
    import re
    import shlex

    start_all()
    for machine in (fw, peer):
        for unit in ("multi-user.target", "sentinel-boot.service", "velstra.service"):
            machine.wait_for_unit(unit)

    secret = "f39ad37b578d1a4377ebee286e3a3ed3650b383aff12b751f893f342b0a43257"
    config = "/var/lib/sentinel/appliance.toml"
    running = "/run/sentinel/running.toml"
    registry = "/var/lib/sentinel/login-accounts.json"
    helper = "${core}/bin/sentinel"
    wren = "${wren}/bin/wren"
    rows = []
    hidden = [secret, "OBSERVE_MALFORMED_SOURCE_MARKER", "OBSERVE_MALFORMED_REGISTRY_MARKER"]

    def configure(machine, commands, save=True):
        ending = ["commit"] + (["save"] if save else []) + ["exit"]
        script = "printf '%s\\n' " + " ".join(shlex.quote(word) for word in commands + ending)
        output = machine.succeed(script + " | sentinel configure 2>&1")
        assert "error:" not in output.lower() and "commit failed" not in output.lower(), output
        assert "commit ok" in output.lower(), output

    def ssh(command, user="viewer", succeeds=True):
        invocation = ("ssh -n -i /root/.ssh/id_ed25519 -o BatchMode=yes "
            "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            "-o ConnectTimeout=3 -o LogLevel=ERROR " + user + "@10.12.0.1 " + shlex.quote(command) + " 2>&1")
        return peer.succeed(invocation) if succeeds else peer.fail(invocation)

    def capability(operation, succeeds=True, prefix=""):
        return ssh(prefix + "/run/wrappers/bin/sudo -n -- " + helper + " observe " + operation, succeeds=succeeds)

    def opaque(text):
        for value in hidden:
            assert value not in text, text
        return text

    def stats(text):
        values = dict((name, int(value)) for name, value in re.findall(r"^\s*([a-z_]+)\s+(\d+)\s*$", text, re.M))
        assert "rx_packets" in values, text
        return values

    def capacity(text):
        value = json.loads(text)
        assert value["version"] == 1 and value["stale"] is False, value
        maps = {row["name"]: row for row in value["maps"]}
        assert set(maps) == {"CONNTRACK", "FW_FLOWS", "SYN_FLOWS"}, value
        for row in maps.values():
            assert row["sample_complete"] and row["error"] is None, row
            assert row["map_id"] > 0 and row["max_entries"] == 65536, row
        return value, maps

    def request(path, body=None, token=None, method=None):
        command = "curl -ksS --connect-timeout 2 --max-time 10 -o /tmp/observe-api-reply -w '%{http_code}'"
        if token:
            command += " -H " + shlex.quote("Authorization: Bearer " + token)
        if body is not None:
            media = "text/plain" if isinstance(body, str) else "application/json"
            encoded = body if isinstance(body, str) else json.dumps(body)
            command += " -H " + shlex.quote("Content-Type: " + media) + " --data " + shlex.quote(encoded)
        if method:
            command += " -X " + method
        status = int(peer.succeed(command + " https://10.12.0.1:8080/api/v1/" + path).strip())
        return status, peer.succeed("cat /tmp/observe-api-reply")

    with subtest("pre-provisioning wheel admin retains ordinary show behavior"):
        fw.succeed("su admin -c 'sentinel show configuration'")
        fw.succeed("su admin -c 'sudo -n true'")

    public = peer.succeed("mkdir -p /root/.ssh && ssh-keygen -q -t ed25519 -N ''' -f /root/.ssh/id_ed25519 && cat /root/.ssh/id_ed25519.pub").strip()
    configure(fw, [
        "set system hostname observe-fw",
        "set interface eth1 zone wan", "set interface eth2 zone lan",
        "set firewall global default-action accept", "set firewall global stateful true",
        "set system group viewers permission read-only",
        "set system login admin ssh-key " + public,
        "set system login viewer group viewers",
        "set system login viewer password observe-public-test-password",
        "set system login viewer ssh-key " + public,
        "set system config-sync secret " + secret,
        "set services ssh listen-address 10.12.0.1",
        "set services web enable true", "set services web listen-address 10.12.0.1",
        "set protocols router-id 10.10.0.1", "set protocols bgp local-as 65001",
        "set protocols bgp neighbor 10.10.0.2 remote-as 65002",
        "set nat destination observe zone wan", "set nat destination observe proto udp",
        "set nat destination observe port 19099", "set nat destination observe to 10.11.0.2:19000",
    ])
    configure(peer, [
        "set system hostname observe-peer", "set interface eth1 zone wan",
        "set firewall global default-action accept",
        "set protocols router-id 10.10.0.2", "set protocols bgp local-as 65002",
        "set protocols bgp neighbor 10.10.0.1 remote-as 65001",
    ])
    # Check actual persisted random password hashes as well as the known plain
    # machine credential: seeing one redaction marker is not sufficient.
    hashes = json.loads(fw.succeed("${pkgs.python3}/bin/python3 -c " + shlex.quote(
        "import json,tomllib; body=tomllib.load(open('" + config + "','rb')); "
        "print(json.dumps([entry['hashed-password'] for entry in body['system']['login'] if entry.get('hashed-password')]))")))
    assert len(hashes) == 1 and hashes[0].startswith("$y$"), hashes
    hidden.extend(hashes)
    fw.wait_for_unit("sshd.service")
    fw.wait_for_unit("sentinel-api.service")
    fw.wait_until_succeeds("wren show bgp neighbors | grep -qi Established", timeout=60)
    peer.wait_until_succeeds("wren show bgp neighbors | grep -qi Established", timeout=30)
    peer.wait_until_succeeds("ssh -n -i /root/.ssh/id_ed25519 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 viewer@10.12.0.1 true", timeout=20)
    viewer_uid = int(fw.succeed("id -u viewer"))
    assert "wheel" not in fw.succeed("id -nG viewer").split()
    assert ssh("id -un").strip() == "viewer"

    with subtest("root-only storage and sockets stay protected; bootstrap admin still works"):
        for path in (config, running, registry):
            ssh("cat " + path, succeeds=False)
        ssh("sudo -n true", succeeds=False)
        assert secret in ssh("sentinel show configuration commands", user="admin")
        assert "Established" in ssh("sentinel show ip bgp summary", user="admin")
        for path in ("/run/velstra/query.sock", "/run/wren/wren.sock"):
            assert fw.succeed("stat -c %a " + path).strip() == "600"

    # A real DNAT connection is required: the flows view reports the NAT map,
    # not ordinary no-NAT firewall state. The backend has an independent route
    # domain, so its replies cannot shortcut through the peer's local stack.
    peer.succeed("ip netns add observe-backend && ip link set eth2 netns observe-backend && ip -n observe-backend address add 10.11.0.2/24 dev eth2 && ip -n observe-backend link set lo up && ip -n observe-backend link set eth2 up && ip -n observe-backend route add default via 10.11.0.1")
    peer.succeed("systemd-run --unit=observe-backend --service-type=exec -- ip netns exec observe-backend ${pkgs.python3}/bin/python3 -u ${backend}")
    peer.wait_until_succeeds("journalctl -u observe-backend --no-pager -o cat | grep -q OBSERVE_BACKEND_READY", timeout=10)
    baseline = stats(ssh("sentinel show firewall statistics"))
    delivered = json.loads(peer.succeed("${pkgs.python3}/bin/python3 ${traffic}"))
    assert delivered["verified_datagrams"] == 32 and delivered["verified_bytes"] > 8192, delivered

    with subtest("all six literal capabilities and normal show routing expose real redacted data"):
        forms = [
            ("configuration", "configuration"),
            ("configuration-commands", "configuration commands"),
            ("bgp-summary", "ip bgp summary"),
            ("flows", "flows"),
            ("firewall-statistics", "firewall statistics"),
            ("firewall-capacity", "firewall capacity"),
        ]
        answers = {}
        for operation, words in forms:
            direct = opaque(capability(operation))
            routed = opaque(ssh("sentinel show " + words))
            assert direct.strip() and routed.strip(), (operation, direct, routed)
            if operation in ("configuration", "configuration-commands"):
                assert "observe-fw" in direct and "__redacted__" in direct, direct
                assert direct == routed, operation
            if operation == "bgp-summary":
                assert "10.10.0.2" in direct and "Established" in direct, direct
                assert "Established" in routed, routed
            if operation == "flows":
                assert "10.11.0.2:19000" in direct and "45111" in direct, direct
                assert "10.11.0.2:19000" in routed, routed
            if operation == "firewall-statistics":
                assert stats(direct)["rx_packets"] >= baseline["rx_packets"] + 64, (baseline, direct)
                stats(routed)
            if operation == "firewall-capacity":
                value, maps = capacity(direct)
                assert maps["CONNTRACK"]["observed_entries"] >= 2, value
                capacity(routed)
            answers[operation] = direct
        rows.append({"six_capabilities": answers, "real_traffic": delivered})

    with subtest("read-only API parity uses the same active configuration and live map IDs"):
        status, text = request("login", {"username": "viewer", "password": "observe-public-test-password"})
        signed = json.loads(text)
        assert status == 200 and signed["permission"] == "read-only", (status, signed)
        token = signed["token"]
        status, text = request("config", token=token)
        assert status == 200 and json.loads(text)["system"]["hostname"] == "observe-fw", (status, text)
        opaque(text)
        for operation, words in forms:
            status, text = request("show/" + words.replace(" ", "/"), token=token)
            assert status == 200 and text.strip(), (words, status, text)
            opaque(text)
            if operation.startswith("configuration"):
                assert text == answers[operation], operation
            elif operation == "bgp-summary":
                assert "Established" in text and "10.10.0.2" in text, text
            elif operation == "flows":
                assert "10.11.0.2:19000" in text, text
            elif operation == "firewall-statistics":
                assert stats(text)["rx_packets"] >= baseline["rx_packets"] + 64, text
            elif operation == "firewall-capacity":
                _, api_maps = capacity(text)
                _, cli_maps = capacity(answers[operation])
                assert {name: row["map_id"] for name, row in api_maps.items()} == {
                    name: row["map_id"] for name, row in cli_maps.items()}
        status, text = request("configure", body="set system hostname viewer-must-not-write\ncommit\nsave", token=token)
        assert status == 403, (status, text)
        assert fw.succeed("hostname").strip() == "observe-fw"
        rows.append({"readonly_api_parity": True})

    with subtest("literal sudo rules reject generic tools, mutable paths, mutations and extra arguments"):
        before = fw.succeed("sha256sum " + config + " " + running)
        for command in (
            "sudo -n true", "sudo -n sh -c id", "sudo -n cat /etc/shadow",
            "sudo -n " + helper + " show configuration",
            "sudo -n " + helper + " agent-query --socket /run/velstra/query.sock reload",
            "sudo -n " + wren + " show bgp neighbors",
            "sudo -n " + helper + " observe reload",
            "sudo -n " + helper + " observe flows --socket /run/velstra/query.sock",
            "sudo -n " + helper + " observe configuration --config /etc/shadow",
            "sudo -n SENTINEL_CONFIG=/etc/shadow " + helper + " observe configuration",
            "sudo -n " + helper + " observe configuration extra",
            helper + " observe configuration",
            helper + " agent-query --socket /run/velstra/query.sock reload",
        ):
            opaque(ssh(command, succeeds=False))
        assert fw.succeed("sha256sum " + config + " " + running) == before
        rows.append({"generic_privilege_denials": 13})

    with subtest("forged caller, tool, config and redaction environment cannot change the capability"):
        fw.succeed("printf '%s\\n' '#!/bin/sh' 'touch /tmp/observe-injected-command-ran' > /tmp/observe-injected-tool && chmod 755 /tmp/observe-injected-tool")
        forged = ("env USER=admin LOGNAME=admin SUDO_USER=admin SUDO_UID=0 "
            "SENTINEL_CONFIG=/etc/shadow SENTINEL_REDACT=full "
            "SENTINEL_WREN_BIN=/tmp/observe-injected-tool SENTINEL_SELF_BIN=/tmp/observe-injected-tool ")
        answer = opaque(capability("configuration-commands", prefix=forged))
        assert "observe-fw" in answer and "__redacted__" in answer, answer
        assert "Established" in capability("bgp-summary", prefix=forged)
        # A normal custom-file show is never escalated into reading that file.
        opaque(ssh("env USER=admin LOGNAME=admin SENTINEL_CONFIG=/etc/shadow sentinel show configuration", succeeds=False))
        fw.fail("test -e /tmp/observe-injected-command-ran")
        rows.append({"forged_environment_denied_or_sanitized": True})

    with subtest("unsaved live intent is observed without substituting the older boot file"):
        saved = fw.succeed("sha256sum " + config)
        configure(fw, ["set system hostname observe-live"], save=False)
        assert fw.succeed("sha256sum " + config) == saved
        assert "set system hostname observe-live" in opaque(ssh("sentinel show configuration commands"))
        status, text = request("config", token=token)
        assert status == 200 and json.loads(text)["system"]["hostname"] == "observe-live", (status, text)
        configure(fw, ["set system hostname observe-fw"])
        rows.append({"active_not_saved_identity": True})

    with subtest("current account grant and durable numeric ownership are required on every call"):
        configure(fw, ["delete system login viewer group"])
        refused = opaque(capability("configuration", succeeds=False))
        assert "denied" in refused or "authorization" in refused, refused
        configure(fw, ["set system login viewer group viewers"])
        assert "observe-fw" in capability("configuration")
        fw.succeed("cp -p " + registry + " /run/observe-registry-good")
        for mutation in ("record['active'] = False", "record['uid'] = 65532"):
            script = ("import json,pathlib; p=pathlib.Path('" + registry + "'); "
                "body=json.loads(p.read_text()); record=body['accounts']['viewer']; " + mutation + "; p.write_text(json.dumps(body))")
            fw.succeed("${pkgs.python3}/bin/python3 -c " + shlex.quote(script))
            opaque(capability("configuration", succeeds=False))
            fw.succeed("cp -p /run/observe-registry-good " + registry)
            assert "observe-fw" in capability("configuration")
        assert int(fw.succeed("id -u viewer")) == viewer_uid
        rows.append({"live_grant_and_registry_revocation": True})

    with subtest("malformed protected configuration or registry cannot disclose parser excerpts"):
        fw.succeed("cp -p " + running + " /run/observe-running-good")
        fw.succeed("printf '%s\\n' '[system]' 'hostname = \"OBSERVE_MALFORMED_SOURCE_MARKER' > " + running)
        for operation, _ in forms:
            opaque(capability(operation, succeeds=False))
        fw.succeed("cp -p /run/observe-running-good " + running)
        fw.succeed("printf '%s\\n' '{\"OBSERVE_MALFORMED_REGISTRY_MARKER\":' > " + registry)
        opaque(capability("configuration", succeeds=False))
        fw.succeed("cp -p /run/observe-registry-good " + registry)
        assert "observe-fw" in capability("configuration")
        rows.append({"protected_parser_errors_opaque": True})

    with subtest("absent daemons report failure, not stale journal data or invented counters"):
        fw.succeed("systemctl stop velstra.service")
        fw.succeed("test $(cat /sys/class/net/eth3/operstate) = up")
        assert ssh("id -un").strip() == "viewer"
        for operation in ("flows", "firewall-statistics", "firewall-capacity"):
            text = opaque(capability(operation, succeeds=False))
            assert "unavailable" in text, text
            assert "rx_packets" not in text and "observed-below-threshold" not in text, text
        fw.succeed("systemctl start velstra.service")
        fw.wait_until_succeeds("sentinel show firewall capacity | ${pkgs.python3}/bin/python3 -c " + shlex.quote("import json,sys; assert json.load(sys.stdin)['version']==1"), timeout=30)
        capacity(capability("firewall-capacity"))
        fw.succeed("systemctl stop wren.service")
        text = opaque(capability("bgp-summary", succeeds=False))
        assert "unavailable" in text and "Established" not in text, text
        fw.succeed("systemctl start wren.service")
        fw.wait_until_succeeds("wren show bgp neighbors | grep -qi Established", timeout=60)
        assert "Established" in capability("bgp-summary")
        rows.append({"missing_daemon_honest_failure_and_recovery": True})

    fw.succeed("test $(systemctl --failed --no-legend | wc -l) -eq 0")
    Path(os.environ["out"], "observe-readonly.json").write_text(json.dumps({
        "scope": "six finite SSH observation capabilities and read-only API parity; not full UI or HA certification",
        "management": "unzoned eth3/VLAN3 10.12.0.1/24; separate from BGP/DNAT eth1 and backend eth2",
        "installed_core": helper, "wren": wren, "viewer_uid": viewer_uid,
        "kernel": fw.succeed("uname -r").strip(), "results": rows,
    }, indent=2) + "\n")
  '';
}
