# Real PID-1 state with an unchanged Sentinel core. Only the pinned systemctl
# boundary is instrumented; the fault refuses one timer stop, never state reads.
{ pkgs, self }:
let
  lib = pkgs.lib;
  systemctl = pkgs.writeShellScript "qa-confirm-diagnostics-systemctl" ''
    set -euo pipefail
    if test "''${1:-}" = reset-failed; then
      printf '%s\n' "$*" >> /run/qa-confirm-reset-failed
    fi
    if test "''${1:-}" = stop && test "''${2:-}" = sentinel-confirm.timer; then
      if test -e /run/qa-confirm-refuse-stop; then
        printf '%s\n' refused:4 >> /run/qa-confirm-stop-results
        echo 'disposable fixture: commit-confirm stop denied' >&2
        exit 4
      fi
      if ${pkgs.systemd}/bin/systemctl "$@"; then
        result=0
      else
        result=$?
      fi
      printf '%s\n' "$result" >> /run/qa-confirm-stop-results
      exit "$result"
    fi
    exec ${pkgs.systemd}/bin/systemctl "$@"
  '';
  cli = self.packages.x86_64-linux.sentinel.overrideAttrs (old:
    let
      original = "--set SENTINEL_SYSTEMCTL_BIN  ${pkgs.systemd}/bin/systemctl";
    in
    assert lib.hasInfix (builtins.unsafeDiscardStringContext original) old.buildCommand;
    { buildCommand = builtins.replaceStrings
        [ original ]
        [ "--set SENTINEL_SYSTEMCTL_BIN  ${systemctl}" ] old.buildCommand; });
in pkgs.testers.runNixOSTest {
  name = "sentinel-confirm-diagnostics";
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
    for unit in ("sentinel-boot.service", "velstra.service", "wren.service"):
        fw.wait_for_unit(unit)
    saved = "/var/lib/sentinel/appliance.toml"
    running = "/run/sentinel/running.toml"
    snapshot = "/var/lib/sentinel/.appliance.toml.commit-confirm.toml"
    trace = "/run/qa-confirm-stop-results"
    marker = "/run/qa-confirm-refuse-stop"
    results = {}

    def configure(lines):
        script = "\n".join(lines + ["exit"]) + "\n"
        return fw.execute("printf %s " + shlex.quote(script) + " | ${cli}/bin/sentinel configure 2>&1")

    def clean_diagnostics(output):
        for forbidden in ("Failed to stop sentinel-confirm.timer",
                          "Failed to reset failed state", "warning: could not disarm"):
            assert forbidden not in output, output

    def property_value(unit, name):
        return fw.succeed("systemctl show --property=" + name + " --value " + unit).strip()

    def protection():
        return dict(timer_state=property_value("sentinel-confirm.timer", "ActiveState"),
                    deadline=property_value("sentinel-confirm.timer", "NextElapseUSecMonotonic"),
                    service_state=property_value("sentinel-confirm.service", "ActiveState"),
                    bound_restore=property_value("sentinel-confirm.service", "ExecStart"))

    def absent_units():
        for unit in ("sentinel-confirm.timer", "sentinel-confirm.service"):
            fw.wait_until_succeeds("test $(systemctl show --property=LoadState --value " + unit + ") = not-found", timeout=10)

    def intent(paths):
        # Compare hashes instead of putting configuration/credentials in receipts.
        return dict(files={path: fw.succeed("sha256sum -- " + shlex.quote(path)).split()[0]
                           for path in paths}, hostname=fw.succeed("hostname").strip())

    def stop_results():
        status, output = fw.execute("cat " + trace)
        return [] if status else output.splitlines()

    status, output = configure(["set system hostname diagnostics-saved", "commit", "save"])
    assert status == 0, output
    clean_diagnostics(output)
    saved_hash = intent([saved])["files"][saved]
    absent_units()

    with subtest("an actually absent timer is silent without hiding stop errors"):
        before = intent([saved, running])
        output = fw.succeed("${cli}/bin/sentinel confirm-rollback 2>&1")
        clean_diagnostics(output)
        assert "reverted the running system" in output, output
        assert intent([saved, running]) == before, "idle restore changed an already saved baseline"
        assert stop_results() == ["5"], "missing timer was not verified after exactly one real stop"
        absent_units()
        results["absent_timer"] = dict(real_stop_status=5, state="not-found", intent_unchanged=True)

    with subtest("normal arm and confirm have no obsolete cleanup diagnostics"):
        fw.succeed("rm " + trace)
        status, output = configure(["set system hostname diagnostics-normal", "commit-confirm 1"])
        assert status == 0 and "applied live" in output, output
        clean_diagnostics(output)
        assert stop_results() == [], "arming unexpectedly stopped a timer"
        fw.succeed("systemctl is-active --quiet sentinel-confirm.timer")
        assert fw.succeed("hostname").strip() == "diagnostics-normal"
        before = intent([saved, running, snapshot])
        assert before["files"][saved] == saved_hash, "trial persisted the candidate"
        status, output = configure(["confirm"])
        assert status == 0 and "confirmed — change kept" in output, output
        clean_diagnostics(output)
        assert stop_results() == ["0"], "normal confirmation did not stop the real timer once"
        assert intent([saved, running, snapshot]) == before, "confirmation changed active or saved intent"
        absent_units()
        results["normal_confirm"] = dict(real_stop_status=0, timer_removed=True, intent_unchanged=True)

    with subtest("a genuine stop refusal remains visible and cannot confirm the trial"):
        fw.succeed("rm " + trace)
        status, output = configure(["set system hostname diagnostics-protected", "commit-confirm 1"])
        assert status == 0 and "applied live" in output, output
        clean_diagnostics(output)
        fw.succeed("systemctl is-active --quiet sentinel-confirm.timer")
        before = intent([saved, running, snapshot])
        assert before["files"][saved] == saved_hash
        protection_before = protection()
        assert protection_before["timer_state"] == "active"
        assert protection_before["service_state"] == "inactive"
        assert protection_before["deadline"] not in ("", "0")
        assert "confirm-rollback" in protection_before["bound_restore"]
        fw.succeed("touch " + marker)
        status, output = configure(["confirm"])
        assert status != 0, "failed cancellation returned a successful CLI status"
        assert "disposable fixture: commit-confirm stop denied" in output, output
        assert "warning: could not disarm commit-confirm timer" in output, output
        assert "change was not confirmed" in output, output
        assert "confirmed — change kept" not in output, output
        assert stop_results() == ["refused:4"], "a root stop failure was retried or hidden"
        fw.succeed("systemctl is-active --quiet sentinel-confirm.timer")
        assert protection() == protection_before, "failed confirmation changed protection or its bound restore"
        assert intent([saved, running, snapshot]) == before, "failed confirmation changed protected intent"
        assert before["hostname"] == "diagnostics-protected"
        results["refused_stop"] = dict(cli_status=status, injected_stop_status=4,
                                       real_timer_state="active", intent_unchanged=True,
                                       false_confirmation=False)
        # Remove the fault and use the same real cancellation path to clean up.
        fw.succeed("rm " + marker)
        status, output = configure(["confirm"])
        assert status == 0 and "confirmed — change kept" in output, output
        clean_diagnostics(output)
        assert stop_results() == ["refused:4", "0"]
        assert intent([saved, running, snapshot]) == before
        absent_units()

    fw.fail("test -e /run/qa-confirm-reset-failed")
    fw.succeed("systemctl is-active --quiet velstra.service")
    fw.succeed("test -z \"$(systemctl --failed --no-legend --plain)\"")
    print("CONFIRM-DIAGNOSTICS " + json.dumps(dict(scope="disposable PID1/CLI regression; not reboot-durable journal qualification", results=results), sort_keys=True))
  '';
}
