# Diagnostic correction of the frozen cohort's stale commitconfirm fixture.
# No product sources or systemd responses are replaced. The fault wrapper
# reaches the actual final atomic rename only AFTER admission and live apply.
{ pkgs, self }:
let
  lib = pkgs.lib;
  publicationMv = pkgs.writeShellScript "qa-confirm-publication-mv" ''
    set -euo pipefail
    if test -e /run/qa-confirm-publication-arm && test "$#" -eq 4 &&
       test "$1" = -fT && test "$2" = -- &&
       test "$4" = /run/sentinel/running.toml; then
      ${pkgs.systemd}/bin/systemctl is-active --quiet sentinel-confirm.timer
      test "$(${pkgs.nettools}/bin/hostname)" = fw-unrecorded
      test -f /run/sentinel/running.toml
      test ! -e /run/sentinel/running-before-publication.toml
      ${pkgs.coreutils}/bin/mv -T /run/sentinel/running.toml /run/sentinel/running-before-publication.toml
      ${pkgs.coreutils}/bin/mkdir -m 0700 /run/sentinel/running.toml
      ${pkgs.coreutils}/bin/rm /run/qa-confirm-publication-arm
      ${pkgs.coreutils}/bin/touch /run/qa-confirm-publication-injected
    fi
    # coreutils itself must reject file-over-directory replacement, rather
    # than this fixture merely returning a synthetic failure status.
    exec ${pkgs.coreutils}/bin/mv "$@"
  '';
  cli = self.packages.x86_64-linux.sentinel.overrideAttrs (old:
    assert lib.hasInfix "${builtins.unsafeDiscardStringContext pkgs.coreutils}/bin/mv" old.buildCommand;
    { buildCommand = builtins.replaceStrings
        [ "${pkgs.coreutils}/bin/mv" ] [ "${publicationMv}" ] old.buildCommand; });
in pkgs.testers.runNixOSTest {
  name = "sentinel-commitconfirm-current-contract";
  globalTimeout = 300;
  nodes.machine = {
    imports = [ self.nixosModules.sentinel (self.outPath + "/nix/test-network-seed.nix") ];
    virtualisation.memorySize = 2048;
  };
  testScript = ''
    import shlex
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("sentinel-boot.service")
    machine.wait_for_unit("velstra.service")
    saved = "/var/lib/sentinel/appliance.toml"
    running = "/run/sentinel/running.toml"
    snapshot = "/var/lib/sentinel/.appliance.toml.commit-confirm.toml"
    def configure(lines, fault=False, succeeds=True):
        binary = "${cli}/bin/sentinel" if fault else "sentinel"
        script = "printf %s " + shlex.quote("\n".join(lines + ["exit", ""])) + " | " + binary + " configure 2>&1"
        command = "su admin -c " + shlex.quote(script)
        return machine.succeed(command) if succeeds else machine.fail(command)
    def digest(path):
        return machine.succeed("sha256sum " + path).split()[0]
    def restored(host):
        machine.wait_until_succeeds("test $(hostname) = " + host + " && grep -q " + host + " " + running, timeout=30)
        machine.wait_until_fails("systemctl is-active --quiet sentinel-confirm.timer", timeout=20)
        machine.wait_until_succeeds("test $(systemctl show --property=LoadState --value sentinel-confirm.service) = not-found", timeout=30)

    configure(["set firewall global default-action accept", "set interface eth0 zone wan",
               "set interface eth0 address dhcp", "set system hostname fw-base", "commit", "save"])
    machine.succeed("hostname | grep -x fw-base")
    machine.succeed("grep -q fw-base " + saved)
    saved_hash, active_hash = digest(saved), digest(running)

    with subtest("actual publication rename failure retains the independently armed rollback"):
        machine.succeed("touch /run/qa-confirm-publication-arm")
        refused = configure(["set system hostname fw-unrecorded", "commit-confirm 10"], fault=True, succeeds=False)
        assert "candidate applied and rollback armed, but recording active intent failed" in refused, refused
        machine.succeed("test -e /run/qa-confirm-publication-injected && test -d " + running)
        assert digest("/run/sentinel/running-before-publication.toml") == active_hash
        machine.succeed("hostname | grep -x fw-unrecorded")
        machine.succeed("systemctl is-active sentinel-confirm.timer")
        assert digest(saved) == saved_hash
        machine.succeed("grep -q fw-base " + snapshot)
        machine.succeed("rmdir " + running + " && mv -T /run/sentinel/running-before-publication.toml " + running)
        requested = machine.succeed("sentinel confirm-rollback 2>&1")
        assert "rollback scheduled" in requested, requested
        restored("fw-base")
        assert digest(running) == active_hash
        assert digest(saved) == saved_hash

    with subtest("confirm keeps live intent without overwriting the saved boot baseline"):
        configure(["set system hostname fw-c1", "commit-confirm 10"])
        machine.succeed("hostname | grep -x fw-c1")
        machine.succeed("grep -q fw-c1 " + running)
        machine.succeed("test $(stat -c %a " + running + ") = 640")
        machine.succeed("test $(stat -c %U " + running + ") = root")
        machine.succeed("systemctl is-active sentinel-confirm.timer")
        configure(["confirm"])
        machine.wait_until_fails("systemctl is-active sentinel-confirm.timer", timeout=20)
        machine.succeed("hostname | grep -x fw-c1")
        machine.succeed("grep -q fw-c1 " + running)
        assert digest(saved) == saved_hash
        confirmed_hash = digest(running)

    with subtest("manual rollback restores previous active intent, including unsaved confirmed changes"):
        configure(["set system hostname fw-c2", "commit-confirm 10"])
        machine.succeed("hostname | grep -x fw-c2")
        machine.succeed("grep -q fw-c2 " + running)
        machine.succeed("systemctl is-active sentinel-confirm.timer")
        machine.succeed("grep -q fw-c1 " + snapshot)
        requested = machine.succeed("sentinel confirm-rollback 2>&1")
        assert "rollback scheduled" in requested, requested
        restored("fw-c1")
        assert digest(running) == confirmed_hash
        assert digest(saved) == saved_hash

    with subtest("real one-minute PID1 timer restores exactly the previous active snapshot"):
        configure(["set system hostname fw-c3", "commit-confirm 1"])
        machine.succeed("hostname | grep -x fw-c3")
        machine.succeed("grep -q fw-c3 " + running)
        machine.succeed("systemctl is-active sentinel-confirm.timer")
        machine.wait_until_succeeds("hostname | grep -x fw-c1", timeout=120)
        restored("fw-c1")
        assert digest(running) == confirmed_hash
        assert digest(saved) == saved_hash
        machine.succeed("systemctl is-active velstra.service")
    print("COMMITCONFIRM_CURRENT_CONTRACT_PASS", flush=True)
  '';
}
