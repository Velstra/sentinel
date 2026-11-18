# Actual failed rollback + transient-unit garbage collection regression.
# The unchanged product core is wrapped only at hostname/systemd-run boundaries.
{ pkgs, self, expectFailureRetained ? true, reproduceArmed ? false }:
let
  lib = pkgs.lib;
  timer = pkgs.writeShellScript "qa-failed-confirm-systemd-run" ''
    set -euo pipefail
    args=()
    for arg in "$@"; do
      if test "$arg" = --on-active=1min; then
        args+=(--on-active=3s)
      else
        args+=("$arg")
      fi
    done
    exec ${pkgs.systemd}/bin/systemd-run "''${args[@]}"
  '';
  hostname = pkgs.writeShellScript "qa-failed-confirm-hostname" ''
    set -euo pipefail
    if test -e /run/qa-fail-restore && test "''${1:-}" = before-trial; then
      ${pkgs.nettools}/bin/hostname partial-restore
      ${pkgs.coreutils}/bin/touch /run/qa-partial-restore
      echo 'disposable fixture: restore failed after real hostname mutation' >&2
      exit 1
    fi
    if test -e /run/qa-delay-restore && test "''${1:-}" = before-trial; then
      ${pkgs.coreutils}/bin/touch /run/qa-restore-waiting
      for attempt in {1..200}; do
        if test -e /run/qa-release-restore; then
          exec ${pkgs.nettools}/bin/hostname "$@"
        fi
        ${pkgs.coreutils}/bin/sleep 0.1
      done
      echo 'disposable fixture: restore barrier timed out' >&2
      exit 1
    fi
    exec ${pkgs.nettools}/bin/hostname "$@"
  '';
  cli = self.packages.x86_64-linux.sentinel.overrideAttrs (old:
    assert lib.hasInfix "${builtins.unsafeDiscardStringContext pkgs.nettools}/bin/hostname" old.buildCommand;
    assert lib.hasInfix "${builtins.unsafeDiscardStringContext pkgs.systemd}/bin/systemd-run" old.buildCommand;
    { buildCommand = builtins.replaceStrings
        [ "${pkgs.nettools}/bin/hostname" "${pkgs.systemd}/bin/systemd-run" ]
        [ "${hostname}" "${timer}" ] old.buildCommand; });
  writer = pkgs.writeText "qa-confirm-serialized-save.py" ''
    import pathlib, subprocess
    root = pathlib.Path("/run")
    (root / "qa-save-started").touch(mode=0o600)
    result = subprocess.run(["${self.packages.x86_64-linux.sentinel}/bin/sentinel", "configure", "--config", "/var/lib/sentinel/qa-custom.toml"],
                            input="save\nexit\n", text=True, capture_output=True, timeout=30)
    (root / "qa-save-observed-running").write_bytes(pathlib.Path("/run/sentinel/running.toml").read_bytes())
    (root / "qa-save-observed-hostname").write_text(pathlib.Path("/proc/sys/kernel/hostname").read_text())
    (root / "qa-save-status").write_text(str(result.returncode))
  '';
  conflicts = pkgs.writeText "qa-failed-confirm-api-conflicts.py" ''
    import json, pathlib, re, ssl, urllib.error, urllib.request

    token = pathlib.Path("/var/lib/sentinel/api-token").read_text().strip()
    context = ssl._create_unverified_context()  # Disposable loopback fixture only.
    def request(method, path, payload=None):
        headers = {"Authorization": "Bearer " + token}
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode()
        req = urllib.request.Request("https://127.0.0.1:8443/api/v1/" + path,
                                     data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, context=context, timeout=5) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, json.load(error)

    protected = [pathlib.Path(p) for p in (
        "/var/lib/sentinel/appliance.toml", "/var/lib/sentinel/qa-custom.toml",
        "/run/sentinel/running.toml",
        "/var/lib/sentinel/.appliance.toml.commit-confirm.toml",
        "/var/lib/sentinel/.qa-custom.toml.commit-confirm.toml")]
    before = [p.read_bytes() for p in protected]
    status, candidate = request("GET", "config")
    assert status == 200, status
    candidate["system"]["hostname"] = "failed-api-must-not-apply"
    status, document = request("GET", "config/document")
    assert status == 200, status
    toml = re.sub(r'(?m)^hostname\s*=.*$', 'hostname = "failed-api-must-not-apply"',
                  document["toml"], count=1)
    assert toml != document["toml"], "fixture must attempt an actual hostname change"
    payload = dict(toml=toml, expected_revision=document["revision"])
    assert request("POST", "config/document", dict(payload, validate_only=True))[0] == 200
    for method, path, body in (
        ("PUT", "config", candidate),
        ("POST", "config/document", payload),
        ("PUT", "config-sync", candidate),
    ):
        status, response = request(method, path, body)
        assert status == 409 and "recovery failed" in str(response), (path, status, response)
        assert [p.read_bytes() for p in protected] == before, path + " changed protected intent"
    assert not pathlib.Path("/var/lib/sentinel/appliance.configsync-received").exists()
    assert pathlib.Path("/proc/sys/kernel/hostname").read_text().strip() == "partial-restore"
    print("Failed recovery: actual TLS config/document/config-sync writes return409, read-only review200, protected intent unchanged")
  '';
in pkgs.testers.runNixOSTest {
  name = "sentinel-confirm-failed-recovery";
  globalTimeout = 300;
  nodes.fw = { ... }: {
    imports = [ self.nixosModules.sentinel ./test-network-seed.nix ];
    virtualisation = { vlans = [ 1 ]; memorySize = 1536; };
    networking.firewall.enable = lib.mkForce false;
    networking.interfaces.eth1.ipv4.addresses = [{ address = "192.0.2.1"; prefixLength = 24; }];
    services.velstra.interface = lib.mkForce "eth1";
  };
  testScript = ''
    import json, shlex
    fw.wait_for_unit("multi-user.target")
    fw.wait_for_unit("sentinel-boot.service")
    fw.wait_for_unit("velstra.service")
    saved = "/var/lib/sentinel/appliance.toml"
    custom = "/var/lib/sentinel/qa-custom.toml"
    running = "/run/sentinel/running.toml"

    def configure(lines, fault=False, config=None, no_apply=False):
        binary = "${cli}/bin/sentinel" if fault else "sentinel"
        script = "\n".join(lines + ["exit"]) + "\n"
        option = " --config " + shlex.quote(config) if config else ""
        option += " --no-apply" if no_apply else ""
        return fw.execute("printf %s " + shlex.quote(script) + " | " + binary + " configure" + option + " 2>&1")

    def serialized_save():
        fw.wait_until_succeeds("test -e /run/qa-restore-waiting", timeout=10)
        fw.succeed("systemd-run --unit=qa-confirm-serialized-save --property=Type=exec ${pkgs.python3}/bin/python3 ${writer}")
        fw.wait_until_succeeds("test -e /run/qa-save-started", timeout=10)
        fw.succeed("systemctl is-active --quiet qa-confirm-serialized-save.service")
        fw.fail("test -e /run/qa-save-status")
        assert fw.succeed("cat " + custom) == custom_original
        fw.succeed("touch /run/qa-release-restore")
        fw.wait_until_succeeds("test -e /run/qa-save-status", timeout=30)
        assert fw.succeed("cat /run/qa-save-status").strip() == "0"
        assert fw.succeed("cat /run/qa-save-observed-running") == original_active
        assert fw.succeed("cat /run/qa-save-observed-hostname").strip() == "before-trial"
        fw.wait_until_succeeds("test $(systemctl show --property=LoadState --value sentinel-confirm.service) = not-found", timeout=30)
        fw.wait_until_succeeds("test $(systemctl show --property=LoadState --value qa-confirm-serialized-save.service) = not-found", timeout=30)
        fw.succeed("rm /run/qa-save-started /run/qa-save-status /run/qa-save-observed-running /run/qa-save-observed-hostname /run/qa-restore-waiting /run/qa-release-restore")

    status, output = configure(["set system hostname stale-before-confirm",
                                "set services web enable true", "set services web tls true",
                                "set services web port 8443", "set services web listen-address 127.0.0.1",
                                "commit", "save"])
    assert status == 0, output
    fw.wait_for_unit("sentinel-api.service")
    fw.wait_for_open_port(8443)
    # Leave a real, already-confirmed default-path snapshot behind. Failed
    # custom-path recovery must use its retained ExecStart, never this file.
    status, output = configure(["set system hostname boot-saved", "commit-confirm 1", "confirm", "save"])
    assert status == 0, output
    original = fw.succeed("cat " + saved)
    fw.succeed("cp " + saved + " " + custom)
    status, output = configure(["set system hostname before-trial", "commit", "save"], config=custom)
    assert status == 0, output
    custom_original = fw.succeed("cat " + custom)
    original_active = fw.succeed("cat " + running)
    if ${if reproduceArmed then "True" else "False"}:
        status, output = configure(["set system hostname armed-custom", "commit-confirm 1"], config=custom)
        assert status == 0, output
        output = fw.succeed("sentinel confirm-rollback 2>&1")
        after = dict(actual_hostname=fw.succeed("hostname").strip(),
                     running=fw.succeed("cat " + running),
                     saved_unchanged=fw.succeed("cat " + saved) == original,
                     custom_saved_unchanged=fw.succeed("cat " + custom) == custom_original)
        print("ARMED-CUSTOM-ROLLBACK " + json.dumps(after, sort_keys=True))
        assert after["actual_hostname"] == "before-trial", "bare rollback selected a stale default snapshot instead of the armed custom trial"
        assert after["running"] == original_active and after["saved_unchanged"] and after["custom_saved_unchanged"], after
    else:
        with subtest("armed custom trial uses its bound service rather than a confirmed stale default snapshot"):
            fw.succeed("touch /run/qa-delay-restore")
            # This case triggers recovery manually. Do not use the fixture's
            # accelerated one-minute timer: it can acquire apply.lock before
            # the driver requests rollback, then wait at the barrier that the
            # blocked driver cannot release. Automatic failure below retains
            # the short timer and independently exercises expiry.
            status, output = configure(["set system hostname armed-custom", "commit-confirm 10"], config=custom, fault=True)
            assert status == 0, output
            output = fw.succeed("sentinel confirm-rollback 2>&1")
            assert "rollback scheduled" in output and "reverted the running" not in output, output
            assert fw.succeed("hostname").strip() == "armed-custom", "queue acknowledgement is not a completed restore"
            serialized_save()
            assert fw.succeed("cat " + running) == original_active
            assert fw.succeed("cat " + saved) == original
            assert fw.succeed("cat " + custom) == custom_original
            fw.succeed("rm /run/qa-delay-restore")
    fw.succeed("touch /run/qa-fail-restore")
    status, output = configure(["set system hostname trial-active", "commit-confirm 1"], fault=True, config=custom)
    assert status == 0, output
    fw.wait_until_succeeds("test -e /run/qa-partial-restore", timeout=30)
    retained = ${if expectFailureRetained then "True" else "False"}
    if retained:
        fw.wait_until_succeeds("test $(systemctl show --property=ActiveState --value sentinel-confirm.service) = failed", timeout=30)
        assert fw.succeed("systemctl show --property=LoadState --value sentinel-confirm.service").strip() == "loaded"
        assert fw.succeed("systemctl show --property=Type --value sentinel-confirm.service").strip() == "exec"
    else:
        # Original negative mode: --collect erased both unit-state records.
        for unit in ("sentinel-confirm.timer", "sentinel-confirm.service"):
            fw.wait_until_succeeds("test $(systemctl show --property=LoadState --value " + unit + ") = not-found", timeout=30)
    states = {unit: fw.succeed("systemctl show --property=ActiveState --value " + unit).strip()
              for unit in ("sentinel-confirm.timer", "sentinel-confirm.service")}
    before = dict(saved_unchanged=fw.succeed("cat " + saved) == original,
                  custom_saved_unchanged=fw.succeed("cat " + custom) == custom_original,
                  running_trial="trial-active" in fw.succeed("cat " + running),
                  actual_hostname=fw.succeed("hostname").strip(), states=states)
    assert before["saved_unchanged"] and before["running_trial"] and before["actual_hostname"] == "partial-restore", before

    commit_status, commit_output = configure(["set system hostname after-failed-recovery", "commit"], config=custom)
    save_status, save_output = configure(["save"], config=custom)
    after = dict(commit_status=commit_status, save_status=save_status,
                 actual_hostname=fw.succeed("hostname").strip(),
                 saved_unchanged=fw.succeed("cat " + saved) == original,
                 custom_saved_unchanged=fw.succeed("cat " + custom) == custom_original,
                 running_trial="trial-active" in fw.succeed("cat " + running))
    print("FAILED-RECOVERY-ADMISSION " + json.dumps(dict(before=before, after=after), sort_keys=True))
    assert commit_status != 0 and save_status != 0, "ordinary writes were admitted after failed rollback evidence was garbage-collected"
    assert after["saved_unchanged"] and after["running_trial"] and after["actual_hostname"] == "partial-restore", after
    assert fw.succeed("cat " + custom) == custom_original
    for lines in (["confirm"], ["set system hostname cannot-rearm", "commit-confirm 1"]):
        status, output = configure(lines, config=custom)
        assert status != 0 and "recovery failed" in output, output
    status, output = configure(["confirm"], config=custom, no_apply=True)
    assert status != 0 and "recovery failed" in output, output
    with subtest("failed recovery refuses actual TLS API mutations without hiding read-only review"):
        fw.succeed("${pkgs.python3}/bin/python3 ${conflicts}")

    with subtest("failed retry is scheduled using retained custom ExecStart and remains blocked on failure"):
        output = fw.succeed("sentinel confirm-rollback 2>&1")
        assert "retry scheduled" in output and "reverted the running" not in output, output
        fw.wait_until_succeeds("test $(systemctl show --property=ActiveState --value sentinel-confirm.service) = failed", timeout=30)
        assert fw.succeed("hostname").strip() == "partial-restore"
        status, output = configure(["save"], config=custom)
        assert status != 0 and "recovery failed" in output, output
        assert fw.succeed("cat " + custom) == custom_original

    with subtest("successful exact-unit retry releases protection only after restore and publication"):
        fw.succeed("rm /run/qa-fail-restore")
        fw.succeed("touch /run/qa-delay-restore")
        output = fw.succeed("sentinel confirm-rollback 2>&1")
        assert "retry scheduled" in output and "reverted the running" not in output, output
        assert fw.succeed("systemctl show --property=ActiveState --value sentinel-confirm.service").strip() == "active"
        assert fw.succeed("hostname").strip() == "partial-restore", "scheduling was incorrectly treated as completed restore"
        serialized_save()
        assert fw.succeed("cat " + running) == original_active
        assert fw.succeed("cat " + custom) == custom_original
        assert fw.succeed("cat " + saved) == original
        status, output = configure(["set system hostname healthy-after-recovery", "commit", "save"], config=custom)
        assert status == 0, output
        fw.succeed("test $(hostname) = healthy-after-recovery")
  '';
}
