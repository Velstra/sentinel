# Real source-bound HTTPS clients exercise the running product, not an Axum
# in-process router with synthetic ConnectInfo. All passwords are disposable.
{ pkgs, self }:
let
  initial = pkgs.writeText "auth-bounds-initial.cli" ''
    set interface eth1 zone lan
    set firewall global default-action accept
    set services web enable true
    set services web listen-address ::
    set system group viewers permission read-only
    set system login admin password disposable-auth-bounds-password
    set system login viewer group viewers
    set system login viewer password disposable-auth-bounds-password
    set system login budget-victim group viewers
    set system login budget-victim password disposable-auth-bounds-password
    commit
    save
    exit
  '';
  snapshot = pkgs.writeText "auth-bounds-snapshot.py" ''
    import json, os, tomllib
    with open("/var/lib/sentinel/appliance.toml", "rb") as source:
        appliance = tomllib.load(source)
    descriptor = os.open("/tmp/shared/auth-bounds-original.json",
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as target:
        json.dump(appliance, target)
  '';
  client = pkgs.writeText "auth-bounds-client.py" ''
    import concurrent.futures, copy, http.client, ipaddress, json, os, ssl, sys, time
    from pathlib import Path

    PASSWORD = "disposable-auth-bounds-password"
    CONTEXT = ssl._create_unverified_context()  # disposable self-signed lab only
    REPORT = Path("/tmp/auth-bounds-report.json")
    mode = sys.argv[1]
    records = json.loads(REPORT.read_text()) if REPORT.exists() else {}

    def normalized(address):
        address = ipaddress.ip_address(address)
        return address.ipv4_mapped or address if address.version == 6 else address

    def request(source, method, path, body=None, token=None, raw=None,
                content_type="application/json", headers=None, target=None):
        target = target or ("2001:db8:41::1" if ":" in source else "10.1.0.1")
        connection = http.client.HTTPSConnection(target, 8080, timeout=15,
            source_address=(source, 0), context=CONTEXT)
        connection.connect()
        # Prove the real socket was bound as requested, not a forwarding header.
        assert normalized(connection.sock.getsockname()[0]) == normalized(source)
        outgoing = {"Content-Type": content_type, "Connection": "close"}
        outgoing.update(headers or {})
        if token:
            outgoing["Authorization"] = "Bearer " + token
        payload = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        connection.request(method, path, payload, outgoing)
        response = connection.getresponse()
        text = response.read(3 * 1024 * 1024)
        status = response.status
        connection.close()
        try:
            answer = json.loads(text)
        except (json.JSONDecodeError, UnicodeDecodeError):
            answer = {"transport_error": text.decode(errors="replace")[:300]}
        return status, answer

    def login(source, username="admin", password=PASSWORD, **kwargs):
        return request(source, "POST", "/api/v1/login",
            {"username": username, "password": password}, **kwargs)

    def refused(result, status, message=None):
        actual, answer = result
        assert actual == status and "token" not in answer, (actual, answer.get("error"), status)
        if message:
            assert message in answer.get("error", ""), answer

    def accepted(result, permission="read-write"):
        status, answer = result
        assert status == 200 and isinstance(answer.get("token"), str), (status, answer.get("error"))
        assert answer.get("permission") == permission, answer.get("permission")
        return answer["token"]

    def parallel(attempts):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            return list(pool.map(lambda entry: login(**entry), attempts))

    def checkpoint(name):
        Path("/tmp/shared/auth-bounds-" + name).touch()
        acknowledged = Path("/tmp/shared/auth-bounds-" + name + "-checked")
        deadline = time.monotonic() + 30
        while not acknowledged.exists():
            assert time.monotonic() < deadline, "driver did not inspect actual " + name
            time.sleep(0.05)

    if mode == "bounds":
        cases = [
            ({}, None, "application/json", 400),
            ({"username": "x" * 33, "password": PASSWORD}, None, "application/json", 400),
            ({"username": "../admin", "password": PASSWORD}, None, "application/json", 400),
            ({"username": 42, "password": PASSWORD}, None, "application/json", 400),
            ({"username": "admin", "password": 42}, None, "application/json", 400),
            ({"username": "admin", "password": ""}, None, "application/json", 400),
            ({"username": "admin", "password": "x" * 4097}, None, "application/json", 400),
            ({"username": "admin", "password": "é" * 2049}, None, "application/json", 400),
            ({"username": "admin", "password": PASSWORD, "code": "0" * 65}, None, "application/json", 400),
            (None, b'{"username":', "application/json", 400),
            (None, b'{}', "text/plain", 415),
            # The pre-authentication body bound (CTRL-05: 64 KiB for sign-in,
            # api_listener SIGN_IN_BODY); one small chunk beyond it, so the
            # client has finished sending when the 413 arrives. The old 2 MiB
            # body was the JSON extractor's limit, which sign-in no longer
            # reaches: the server answers at 64 KiB and closes while such a
            # client is still writing.
            (None, b' ' * (64 * 1024 + 1024), "application/json", 413),
        ]
        for index, (body, raw, content_type, status) in enumerate(cases):
            refused(request("10.1.0." + str(20 + index), "POST", "/api/v1/login",
                body, raw=raw, content_type=content_type), status)
        # Valid boundary syntax does not grant an unknown account or a huge password.
        refused(login("10.1.0.35", username="a" * 32), 401)
        refused(login("10.1.0.36", password="x" * 4096), 401)
        # The documented schema permits extra fields and ignores codes for an
        # account without TOTP. They never replace the actual credential check.
        accepted(request("10.1.0.37", "POST", "/api/v1/login", {
            "username": "admin", "password": PASSWORD, "code": "0" * 64, "extra": True}))
        refused(request("10.1.0.38", "POST", "/api/v1/login", {
            "username": "admin", "password": "wrong-password", "extra": True}), 401)
        records[mode] = {"invalid_requests": len(cases), "boundary_and_extra_field_controls": 4}

    elif mode == "origin":
        guesses = [{"source": "10.1.0.40", "username": "spray" + str(index),
            "password": "wrong-password"} for index in range(12)]
        results = parallel(guesses)
        assert sorted(status for status, _ in results) == [401] * 10 + [429] * 2
        assert all("token" not in answer for _, answer in results)
        refused(login("10.1.0.40"), 429, "from your address")
        refused(login("10.1.0.40", headers={
            "X-Forwarded-For": "10.1.0.41", "Forwarded": "for=10.1.0.41"}), 429, "from your address")
        # A second transport spelling does not bypass the same real v4 source.
        refused(login("::ffff:10.1.0.40", target="::ffff:10.1.0.1"), 429, "from your address")
        accepted(login("10.1.0.41"))
        # Four cycles cross the account's30-attempt total without crossing10
        # per origin between successes. Both reset paths must therefore work.
        for _ in range(4):
            for _ in range(8):
                refused(login("10.1.0.42", password="wrong-password"), 401)
            accepted(login("10.1.0.42"))
        records[mode] = {"parallel_credential_refusals": 10, "parallel_locked_refusals": 2,
            "forwarding_header_bypass": False, "mapped_transport_bypass": False,
            "success_resets_origin_and_account_budgets_four_times": True}

    elif mode == "account":
        accepted(login("10.1.0.43", username="budget-victim"), "read-only")
        guesses = [{"source": "10.1.0." + str(43 + index % 4),
            "username": "budget-victim", "password": "wrong-password"} for index in range(30)]
        results = parallel(guesses)
        for result in results:
            refused(result, 401)
        refused(login("10.1.0.47", username="budget-victim"), 429, "for this account")
        accepted(login("10.1.0.47"))
        records[mode] = {"initial_correct_password_works": True, "distributed_failures": 30,
            "fresh_origin_correct_password_refused": True,
            "different_account_same_origin_works": True}

    elif mode == "ipv6":
        for index in range(10):
            refused(login("2001:db8:41:1::20", username="ipv6spray" + str(index)), 401)
        refused(login("2001:db8:41:1::21"), 429, "from your address")
        accepted(login("2001:db8:41:2::20"))
        records[mode] = {"same_prefix_failures": 10, "rotated_same_64_refused": True,
            "different_64_works": True}

    elif mode == "privilege":
        source = "10.1.0.48"
        viewer = accepted(login(source, username="viewer"), "read-only")
        admin = accepted(login(source))
        with open("/tmp/shared/auth-bounds-original.json") as config:
            original = json.load(config)
        candidate = copy.deepcopy(original)
        candidate["system"]["hostname"] = "auth-admin-confirmed"
        # The exact same valid document is subsequently accepted for admin.
        refused(request(source, "PUT", "/api/v1/config", candidate, viewer), 403, "read-only")
        refused(request(source, "POST", "/api/v1/configure", token=viewer,
            raw=b"set system hostname forbidden-viewer-write\ncommit\nsave\n"), 403, "read-only")
        status, transaction = request(source, "GET", "/api/v1/config/transaction", token=admin)
        assert status == 200 and transaction.get("pending") is None, transaction
        checkpoint("viewer-refused")
        status, result = request(source, "PUT", "/api/v1/config", candidate, admin)
        assert status == 200 and result.get("pending", {}).get("id"), (status, result.get("error"))
        status, result = request(source, "POST", "/api/v1/config/confirm",
            {"id": result["pending"]["id"]}, admin)
        assert status == 200, (status, result.get("error"))
        status, observed = request(source, "GET", "/api/v1/config", token=viewer)
        assert status == 200 and observed["system"]["hostname"] == "auth-admin-confirmed"
        checkpoint("admin-applied")
        # Restore through the same authenticated product transaction, not a file edit.
        status, result = request(source, "PUT", "/api/v1/config", original, admin)
        assert status == 200 and result.get("pending", {}).get("id"), (status, result.get("error"))
        status, result = request(source, "POST", "/api/v1/config/confirm",
            {"id": result["pending"]["id"]}, admin)
        assert status == 200, (status, result.get("error"))
        status, observed = request(source, "GET", "/api/v1/config", token=viewer)
        assert status == 200 and observed["system"]["hostname"] == original["system"]["hostname"]
        status, _ = request(source, "POST", "/api/v1/sign-out", token=viewer)
        assert status == 200
        refused(request(source, "GET", "/api/v1/config", token=viewer), 401)
        records[mode] = {"viewer_put_and_post_refused": True, "admin_put_confirm_and_restore": True,
            "viewer_signout_revokes_bearer": True}

    elif mode == "restart-recovery":
        # Runtime throttles intentionally reset on service restart; this is not
        # a claim that their 15-minute monotonic deadline has elapsed.
        accepted(login("10.1.0.40"))
        accepted(login("10.1.0.47", username="budget-victim"), "read-only")
        records[mode] = {"origin_restored_after_restart": True, "account_window_cleared_after_restart": True}
    else:
        raise AssertionError("unknown fixture mode")
    REPORT.write_text(json.dumps(records, indent=2))
    os.chmod(REPORT, 0o600)
    print(json.dumps({"phase": mode, "passed": records[mode]}))
  '';
in pkgs.testers.runNixOSTest {
  name = "sentinel-https-auth-bounds-and-authority";
  nodes = {
    fw = { lib, ... }: {
      imports = [ self.nixosModules.sentinel ./test-network-seed.nix ];
      virtualisation.memorySize = 2048;
      virtualisation.vlans = [ 1 ];
      networking.firewall.enable = lib.mkForce false;
      networking.interfaces.eth1 = {
        ipv4.addresses = [{ address = "10.1.0.1"; prefixLength = 24; }];
        ipv6.addresses = [{ address = "2001:db8:41::1"; prefixLength = 48; }];
      };
      services.velstra.interface = lib.mkForce "eth1";
      services.getty.autologinUser = lib.mkForce null;
      environment.systemPackages = [ pkgs.curl pkgs.python3 ];
    };
    client = { ... }: {
      virtualisation.vlans = [ 1 ];
      networking = {
        useNetworkd = true;
        useDHCP = false;
        firewall.enable = false;
        interfaces.eth1 = {
          ipv4.addresses = map (last: { address = "10.1.0.${toString last}"; prefixLength = 24; })
            (pkgs.lib.range 20 48);
          ipv6.addresses = map (address: { inherit address; prefixLength = 48; })
            [ "2001:db8:41:1::20" "2001:db8:41:1::21" "2001:db8:41:2::20" ];
        };
      };
      environment.systemPackages = [ pkgs.python3 ];
    };
  };
  testScript = ''
    import json, os
    from pathlib import Path
    start_all()
    for machine in (fw, client):
        machine.wait_for_unit("multi-user.target")
    fw.wait_for_unit("sentinel-boot.service")
    fw.wait_for_unit("velstra.service")
    fw.succeed("sentinel configure < ${initial} 2>&1")
    fw.wait_for_unit("sentinel-api.service")
    fw.wait_until_succeeds("curl -k -g -sSf --max-time 3 https://[::1]:8080/api/v1/health", timeout=30)
    fw.succeed("${pkgs.python3}/bin/python3 ${snapshot}")
    original = fw.succeed("sha256sum /var/lib/sentinel/appliance.toml")
    hostname = fw.succeed("hostname")
    invocation = fw.succeed("systemctl show sentinel-api.service -p InvocationID --value")
    for phase in ("bounds", "origin", "account", "ipv6", "privilege"):
        with subtest("actual source-bound HTTPS " + phase):
            if phase == "privilege":
                # Detach the WHOLE subshell from the driver's base64 pipe. A
                # Python-only redirect leaves the parent's stdout open until
                # the checkpoint expires, preventing the driver from replying.
                client.succeed("(set +e; ${pkgs.python3}/bin/python3 ${client} privilege; echo $? >/tmp/auth-privilege.exit) </dev/null >/tmp/auth-privilege.log 2>&1 &")
                fw.wait_until_succeeds("test -e /tmp/shared/auth-bounds-viewer-refused", timeout=30)
                assert fw.succeed("sha256sum /var/lib/sentinel/appliance.toml") == original
                assert fw.succeed("hostname") == hostname
                fw.succeed("touch /tmp/shared/auth-bounds-viewer-refused-checked")
                fw.wait_until_succeeds("test -e /tmp/shared/auth-bounds-admin-applied", timeout=30)
                assert fw.succeed("hostname").strip() == "auth-admin-confirmed"
                assert fw.succeed("sha256sum /var/lib/sentinel/appliance.toml") != original
                fw.succeed("touch /tmp/shared/auth-bounds-admin-applied-checked")
                client.wait_until_succeeds("test -e /tmp/auth-privilege.exit", timeout=30)
                code = client.succeed("cat /tmp/auth-privilege.exit").strip()
                output = client.succeed("cat /tmp/auth-privilege.log")
                assert code == "0", output
            else:
                client.succeed("${pkgs.python3}/bin/python3 ${client} " + phase)
            fw.succeed("systemctl is-active --quiet sentinel-api.service")
            # Rejected inputs and both refused writes cannot mutate state; the
            # privilege phase then performs and confirms its own real restore.
            assert fw.succeed("sha256sum /var/lib/sentinel/appliance.toml") == original
            assert fw.succeed("hostname") == hostname
            assert fw.succeed("systemctl show sentinel-api.service -p InvocationID --value") == invocation
    with subtest("documented in-memory throttle lifecycle and healthy recovery"):
        fw.succeed("systemctl restart sentinel-api.service")
        fw.wait_for_unit("sentinel-api.service")
        fw.wait_until_succeeds("curl -k -g -sSf --max-time 3 https://[::1]:8080/api/v1/health", timeout=30)
        client.succeed("${pkgs.python3}/bin/python3 ${client} restart-recovery")
    for machine in (fw, client):
        machine.fail("systemctl --failed --no-legend | grep .")
    receipt = json.loads(client.succeed("cat /tmp/auth-bounds-report.json"))
    with Path(os.environ["out"], "auth-bounds.json").open("w") as destination:
        json.dump(receipt, destination, indent=2)
  '';
}
