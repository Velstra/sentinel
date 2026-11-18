# Actual PID-1 timer + killed CLI after a real live hostname mutation. The
# product binary is unchanged; this fixture replaces two pinned tool wrappers
# only, shortening the test timer and injecting the caller's SIGKILL.
{ pkgs, self }:
let
  lib = pkgs.lib;
  timer = pkgs.writeShellScript "qa-confirm-systemd-run" ''
    set -euo pipefail
    if test -e /run/qa-confirm-refuse-arm; then
      echo 'deliberate test-only timer arm refusal' >&2
      exit 1
    fi
    args=()
    for arg in "$@"; do
      if test "$arg" = --on-active=1min; then
        args+=(--on-active=40s)
      else
        args+=("$arg")
      fi
    done
    exec ${pkgs.systemd}/bin/systemd-run "''${args[@]}"
  '';
  hostname = pkgs.writeShellScript "qa-confirm-hostname" ''
    set -euo pipefail
    ${pkgs.nettools}/bin/hostname "$@"
    if test "''${1:-}" = crash-after-mutation; then
      ${pkgs.systemd}/bin/systemctl is-active --quiet sentinel-confirm.timer
      ${pkgs.nettools}/bin/hostname > /run/qa-confirm-mutated-hostname
      kill -KILL "$PPID"
    fi
  '';
  cli = self.packages.x86_64-linux.sentinel.overrideAttrs (old:
    assert lib.hasInfix "${builtins.unsafeDiscardStringContext pkgs.nettools}/bin/hostname" old.buildCommand;
    assert lib.hasInfix "${builtins.unsafeDiscardStringContext pkgs.systemd}/bin/systemd-run" old.buildCommand;
    { buildCommand = builtins.replaceStrings
        [ "${pkgs.nettools}/bin/hostname" "${pkgs.systemd}/bin/systemd-run" ]
        [ "${hostname}" "${timer}" ] old.buildCommand; });
  conflicts = pkgs.writeText "qa-confirm-api-conflicts.py" ''
    import json, pathlib, ssl, urllib.error, urllib.request

    base = "https://192.0.2.1:8443/api/v1/"
    token = pathlib.Path("/var/lib/sentinel/api-token").read_text().strip()
    context = ssl._create_unverified_context()  # Disposable isolated guest TLS fixture only.
    def request(method, path, payload=None):
        headers = {"Authorization": "Bearer " + token}
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode()
        req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, context=context, timeout=5) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, json.load(error)

    paths = [pathlib.Path(p) for p in (
        "/var/lib/sentinel/appliance.toml", "/run/sentinel/running.toml",
        "/var/lib/sentinel/.appliance.toml.commit-confirm.toml")]
    before = [p.read_bytes() for p in paths]
    status, candidate = request("GET", "config")
    assert status == 200, status
    candidate["system"]["hostname"] = "api-must-not-apply"
    status, document = request("GET", "config/document")
    assert status == 200, status
    payload = dict(toml=document["toml"].replace("confirmed-live-only", "api-must-not-apply"),
                   expected_revision=document["revision"])
    review = dict(payload, validate_only=True)
    assert request("POST", "config/document", review)[0] == 200, "read-only review remains available"
    for method, path, body in (
        ("PUT", "config", candidate),
        ("POST", "config/document", payload),
        ("PUT", "config-sync", candidate),
    ):
        status, response = request(method, path, body)
        assert status == 409, (method, path, status)
        assert "confirm" in str(response), (path, response)
        assert [p.read_bytes() for p in paths] == before, path + " mutated protected intent"
    assert not pathlib.Path("/var/lib/sentinel/appliance.configsync-received").exists(), "sync admission wrote a participation fence"
    print("CLI timer retained: config, document and authenticated TLS config-sync writes refused before mutation")
  '';
  pairing = pkgs.writeText "qa-pair-admission.py" ''
    import json, pathlib, socket, ssl, subprocess, sys, threading, time, urllib.request

    # Disposable fixture credential, never a production pairing identity.
    credential = "qa-only-pairing-credential-32-bytes"
    plan = pathlib.Path("/var/lib/sentinel/ha-pair.json")
    paths = [pathlib.Path(p) for p in (
        "/var/lib/sentinel/appliance.toml", "/run/sentinel/running.toml",
        "/var/lib/sentinel/web-tls/cert.pem", "/var/lib/sentinel/web-tls/key.pem")]
    paths.append(plan)
    def snapshot(extra=()):
        return {p: p.read_bytes() if p.exists() else None for p in paths + list(extra)}

    seen = []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 9444))
    listener.listen()
    listener.settimeout(0.1)
    def peer():
        while True:
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            seen.append(True)
            connection.close()
    threading.Thread(target=peer, daemon=True).start()

    def refused(expected, config=None, extra=()):
        before = snapshot(extra)
        command = ["sentinel", "ha", "pair", "127.0.0.1:9444", "--mode", "two-node", "--secret-stdin"]
        if config is not None:
            command += ["--config", str(config)]
        result = subprocess.run(command, input=credential, text=True, capture_output=True, timeout=10)
        assert result.returncode != 0, "pairing was unexpectedly accepted"
        assert expected in result.stderr, result.stderr
        assert snapshot(extra) == before, "refusal changed configuration, TLS identity or retained plan"
        assert not seen, "pairing connected to peer before admission"

    before = snapshot()
    assert before[plan] is None, "fixture starts without a retained pairing plan"
    mode = sys.argv[1]
    if mode == "pending":
        refused("explicitly confirm or revert")
        # Even a retained/corrupt plan must remain untouched when admission
        # already forbids pairing; it must not trigger peer/TLS side effects.
        try:
            plan.write_bytes(b"retained disposable test plan")
            plan.chmod(0o600)
            refused("explicitly confirm or revert")
        finally:
            plan.unlink(missing_ok=True)
    elif mode == "unsaved":
        refused("running configuration has unsaved changes")
    elif mode == "custom":
        root = pathlib.Path("/run/qa-custom-transaction")
        root.mkdir(mode=0o700)
        config = root / "original.toml"
        # Pairing's independent transport preflight must be valid so these
        # tests actually reach the pending-journal admission being asserted.
        original = b"[system]\nhostname='custom-original'\n[services.web]\ntls=true\nlisten-address='192.0.2.1'\nport=8787\n"
        config.write_bytes(original)
        token = root / "token"
        service = subprocess.Popen(["sentinel", "api", "--no-apply", "--config", str(config),
                                    "--listen", "192.0.2.1:8787", "--token-file", str(token)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        context = ssl._create_unverified_context()  # Disposable guest certificate only.
        try:
            for _ in range(100):
                try:
                    with urllib.request.urlopen("https://192.0.2.1:8787/api/v1/health", timeout=0.1, context=context):
                        break
                except OSError:
                    assert service.poll() is None, "custom fixture API exited"
                    time.sleep(0.1)
            else:
                raise AssertionError("custom fixture API did not start")
            def request(method, path, payload=None):
                headers = {"Authorization": "Bearer " + token.read_text().strip()}
                data = None
                if payload is not None:
                    headers["Content-Type"] = "application/json"
                    data = json.dumps(payload).encode()
                req = urllib.request.Request("https://192.0.2.1:8787/api/v1/" + path,
                                             data=data, headers=headers, method=method)
                with urllib.request.urlopen(req, timeout=5, context=context) as response:
                    return json.load(response)
            document = request("GET", "config/document")
            result = request("POST", "config/document", dict(
                toml=document["toml"].replace("custom-original", "custom-provisional"),
                expected_revision=document["revision"]))
            journal = root / ".original.toml.pending.json"
            assert journal.exists() and result["pending"]["ready"], result
            refused("configuration confirmation pending", config, (config, journal))
            selected_before = snapshot((config, journal))
            compiled = root / "compiled.toml"
            result_apply = subprocess.run(["sentinel", "apply", str(config), "--out", str(compiled)],
                                          text=True, capture_output=True, timeout=10)
            assert result_apply.returncode != 0 and "confirmation pending" in result_apply.stderr
            assert not compiled.exists(), "selected-journal refusal wrote compiled policy"
            assert snapshot((config, journal)) == selected_before, "direct apply changed selected transaction"
            identity = result["pending"]["id"]
            assert request("POST", "config/revert", dict(id=identity))["reverted"]
            assert config.read_bytes() == original and not journal.exists(), "custom recovery did not restore exact bytes"
        finally:
            service.terminate()
            service.wait(timeout=5)
    else:
        raise AssertionError("unknown test mode")
    assert snapshot() == before, "admission check changed product intent or credentials"
    assert not seen, "unexpected peer connection"
    listener.close()
    print("HA admission " + mode + ": no peer connection, plan/TLS/config bytes unchanged")
  '';
in pkgs.testers.runNixOSTest {
  name = "sentinel-confirm-crash-protection";
  globalTimeout = 600;
  nodes.fw = { ... }: {
    imports = [ self.nixosModules.sentinel ./test-network-seed.nix ];
    virtualisation = { vlans = [ 1 ]; memorySize = 1536; };
    networking.firewall.enable = lib.mkForce false;
    networking.interfaces.eth1.ipv4.addresses = [{ address = "192.0.2.1"; prefixLength = 24; }];
    services.velstra.interface = lib.mkForce "eth1";
    environment.systemPackages = [ pkgs.python3 ];
  };
  testScript = ''
    import shlex, time
    fw.wait_for_unit("multi-user.target")
    for unit in ("sentinel-boot.service", "velstra.service", "wren.service"):
        fw.wait_for_unit(unit)
    saved = "/var/lib/sentinel/appliance.toml"
    snapshot = "/var/lib/sentinel/.appliance.toml.commit-confirm.toml"
    running = "/run/sentinel/running.toml"

    def configure(lines, succeeds=True, fault=False, no_apply=False):
        binary = "${cli}/bin/sentinel" if fault else "sentinel"
        script = "\n".join(lines + ["exit"]) + "\n"
        command = "printf %s " + shlex.quote(script) + " | " + binary + " configure" + (" --no-apply" if no_apply else "") + " 2>&1"
        return fw.succeed(command) if succeeds else fw.fail(command)

    configure(["set system hostname boot-saved", "set services web enable true",
               "set services web tls true", "set services web port 8443",
               "set services web listen-address 192.0.2.1", "commit", "save"])
    fw.wait_for_unit("sentinel-api.service")
    fw.wait_until_succeeds("curl -ksf https://192.0.2.1:8443/api/v1/health", timeout=30)
    boot_bytes = fw.succeed("cat " + saved)
    configure(["set system hostname unsaved-active", "commit"])
    fw.succeed("test $(hostname) = unsaved-active")
    assert fw.succeed("cat " + saved) == boot_bytes

    with subtest("timer arm refusal causes no candidate network mutation"):
        fw.succeed("touch /run/qa-confirm-refuse-arm")
        refused = configure(["set system hostname must-not-apply", "commit-confirm 1"], succeeds=False, fault=True)
        assert "candidate not applied" in refused, refused
        fw.succeed("test $(hostname) = unsaved-active")
        assert fw.succeed("cat " + saved) == boot_bytes
        fw.fail("systemctl is-active --quiet sentinel-confirm.timer")
        fw.succeed("rm /run/qa-confirm-refuse-arm")

    with subtest("SIGKILL after mutation cannot lose independent timer protection"):
        configure(["set system hostname crash-after-mutation", "commit-confirm 1"], succeeds=False, fault=True)
        fw.succeed("grep -x crash-after-mutation /run/qa-confirm-mutated-hostname")
        fw.succeed("test $(stat -c %a " + snapshot + ") = 600")
        fw.succeed("grep 'unsaved-active' " + snapshot)
        assert fw.succeed("cat " + saved) == boot_bytes
        fw.wait_until_succeeds("test $(hostname) = unsaved-active", timeout=90)
        fw.wait_until_succeeds("grep 'unsaved-active' " + running, timeout=30)
        fw.wait_until_succeeds("journalctl -b -u sentinel-confirm.service --no-pager --grep='reverted the running system to the rollback baseline' | grep -q baseline", timeout=30)
        assert fw.succeed("cat " + saved) == boot_bytes

    with subtest("pending protection cannot be replaced and successful confirm really cancels it"):
        configure(["set system hostname confirmed-live-only", "commit-confirm 1"], fault=True)
        refused = configure(["set system hostname cannot-rearm", "commit-confirm 1"], succeeds=False, fault=True)
        assert "already pending" in refused, refused
        intent = fw.succeed("cat " + running)
        private = fw.succeed("cat " + snapshot)
        for lines, no_apply in [
            (["set system hostname cannot-commit", "commit"], False),
            (["save"], False),
            (["save /tmp/qa-confirm-export.toml"], False),
            (["save"], True),
            (["set system hostname cannot-offline-commit", "commit"], True),
            (["rollback 0"], False),
            (["rollback 0"], True),
        ]:
            refused = configure(lines, succeeds=False, no_apply=no_apply)
            assert "explicitly confirm or revert" in refused, refused
            assert fw.succeed("cat " + saved) == boot_bytes
            assert fw.succeed("cat " + running) == intent
            assert fw.succeed("cat " + snapshot) == private
        fw.fail("test -e /tmp/qa-confirm-export.toml")
        refused = fw.fail("sentinel apply " + saved + " --out /tmp/qa-confirm-compiled.toml 2>&1")
        assert "explicitly confirm or revert" in refused, refused
        fw.fail("test -e /tmp/qa-confirm-compiled.toml")
        refused = fw.fail("sentinel confirm-rollback --commit-confirm --config " + snapshot + " --original-config /var/lib/sentinel/wrong.toml 2>&1")
        assert "invalid commit-confirm original configuration metadata" in refused, refused
        fw.succeed("${pkgs.python3}/bin/python3 ${conflicts}")
        fw.succeed("${pkgs.python3}/bin/python3 ${pairing} pending")
        fw.succeed("systemctl is-active --quiet sentinel-confirm.timer")
        fw.succeed("test $(hostname) = confirmed-live-only")
        configure(["confirm"], fault=True)
        fw.fail("systemctl is-active --quiet sentinel-confirm.timer")
        configure(["save /tmp/qa-confirm-accepted.toml"])
        fw.succeed("grep 'confirmed-live-only' /tmp/qa-confirm-accepted.toml")
        time.sleep(41)
        fw.succeed("test $(hostname) = confirmed-live-only")
        assert fw.succeed("cat " + saved) == boot_bytes
        fw.succeed("${pkgs.python3}/bin/python3 ${pairing} unsaved")

    with subtest("selected custom management journals block pairing and direct apply"):
        fw.succeed("${pkgs.python3}/bin/python3 ${pairing} custom")

    # Transient units do not survive reboot. The unchanged saved boot intent,
    # not the unsaved snapshot/candidate, must then seed the appliance.
    with subtest("reboot during an unconfirmed trial uses saved boot intent"):
        configure(["set system hostname unconfirmed-before-reboot", "commit-confirm 1"])
        fw.succeed("systemctl is-active --quiet sentinel-confirm.timer")
        fw.shutdown()
        fw.start()
        fw.wait_for_unit("multi-user.target")
        fw.wait_for_unit("sentinel-boot.service")
        fw.succeed("test $(hostname) = boot-saved")
        fw.fail("systemctl is-active --quiet sentinel-confirm.timer")
        assert fw.succeed("cat " + saved) == boot_bytes
  '';
}
