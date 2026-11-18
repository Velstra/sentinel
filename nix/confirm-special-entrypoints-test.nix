# Admission regression against genuine cold boot + retained CLI failure.
# No product source or systemd unit state is replaced; only hostname failure and
# the disposable trial's timer deadline are injected through pinned tool wrappers.
{ pkgs, self }:
let
  lib = pkgs.lib;
  timer = pkgs.writeShellScript "qa-special-confirm-systemd-run" ''
    set -euo pipefail
    args=()
    for arg in "$@"; do
      if test "$arg" = --on-active=1min; then
        args+=(--on-active=5s)
      else
        args+=("$arg")
      fi
    done
    exec ${pkgs.systemd}/bin/systemd-run "''${args[@]}"
  '';
  hostname = pkgs.writeShellScript "qa-special-confirm-hostname" ''
    set -euo pipefail
    if test -e /run/qa-special-fail-restore && test "''${1:-}" = before-trial; then
      ${pkgs.nettools}/bin/hostname partial-restore
      ${pkgs.coreutils}/bin/touch /run/qa-special-partial-restore
      echo 'disposable fixture: rollback failed after real hostname mutation' >&2
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
in pkgs.testers.runNixOSTest {
  name = "sentinel-confirm-special-entrypoint-admission";
  globalTimeout = 240;
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
    for unit in ("sentinel-boot.service", "sentinel-console.service", "velstra.service", "wren.service"):
        fw.wait_for_unit(unit)
    fw.succeed("test $(systemctl --failed --no-legend --plain | wc -l) -eq 0")
    saved = "/var/lib/sentinel/appliance.toml"
    running = "/run/sentinel/running.toml"
    snapshot = "/var/lib/sentinel/.appliance.toml.commit-confirm.toml"

    def configure(lines, fault=False):
        binary = "${cli}/bin/sentinel" if fault else "sentinel"
        script = "\n".join(lines + ["exit"]) + "\n"
        status, output = fw.execute("printf %s " + shlex.quote(script) + " | " + binary + " configure 2>&1")
        assert status == 0, output

    def timezone():
        return fw.succeed("timedatectl show --property=Timezone --value").strip()

    def failed():
        return fw.succeed("systemctl show --property=ActiveState --value sentinel-confirm.service").strip()

    configure(["set system hostname boot-saved", "set system timezone UTC", "commit", "save"])
    boot_bytes = fw.succeed("cat " + saved)
    assert timezone() == "UTC", "genuine boot/live baseline must support real timezone application"
    configure(["set system hostname before-trial", "set system timezone Europe/Berlin", "commit"])
    assert timezone() == "Europe/Berlin"
    assert fw.succeed("cat " + saved) == boot_bytes
    fw.succeed("touch /run/qa-special-fail-restore")
    configure(["set system hostname trial-active", "commit-confirm 1"], fault=True)
    fw.wait_until_succeeds("test -e /run/qa-special-partial-restore", timeout=20)
    fw.wait_until_succeeds("test $(systemctl show --property=ActiveState --value sentinel-confirm.service) = failed", timeout=20)
    assert fw.succeed("systemctl show --property=LoadState --value sentinel-confirm.service").strip() == "loaded"
    trial_bytes = fw.succeed("cat " + running)
    private_bytes = fw.succeed("cat " + snapshot)
    assert "trial-active" in trial_bytes and "Europe/Berlin" in trial_bytes
    assert timezone() == "Europe/Berlin" and failed() == "failed"
    assert fw.succeed("hostname").strip() == "partial-restore"

    with subtest("normal vconsole restart cannot replay saved timezone over protected active intent"):
        before = timezone()
        invocation = fw.succeed("systemctl show --property=InvocationID --value sentinel-console.service").strip()
        status, output = fw.execute("systemctl restart systemd-vconsole-setup.service 2>&1")
        assert status == 0, output
        fw.wait_until_succeeds("systemctl is-active --quiet sentinel-console.service && test $(systemctl show --property=InvocationID --value sentinel-console.service) != " + shlex.quote(invocation), timeout=20)
        console = dict(before_timezone=before, after_timezone=timezone(),
                       retained_failed=failed() == "failed",
                       saved_unchanged=fw.succeed("cat " + saved) == boot_bytes,
                       running_unchanged=fw.succeed("cat " + running) == trial_bytes,
                       snapshot_unchanged=fw.succeed("cat " + snapshot) == private_bytes)

    assert timezone() == "Europe/Berlin" and failed() == "failed"
    with subtest("public boot apply cannot mutate runtime while retained recovery failed"):
        before = fw.succeed("hostname").strip()
        status, output = fw.execute("sentinel apply-boot 2>&1")
        assert status != 0 and "recovery failed" in output, output
        explicit = fw.fail("sentinel apply-console --config " + saved + " 2>&1")
        assert "recovery failed" in explicit, explicit
        boot = dict(exit=status, before_hostname=before,
                    after_hostname=fw.succeed("hostname").strip(),
                    after_timezone=timezone(), retained_failed=failed() == "failed",
                    saved_unchanged=fw.succeed("cat " + saved) == boot_bytes,
                    running_unchanged=fw.succeed("cat " + running) == trial_bytes,
                    snapshot_unchanged=fw.succeed("cat " + snapshot) == private_bytes)

    proof = dict(genuine_cold_boot_passed=True, console=console, boot_apply=boot)
    print("SPECIAL-ENTRYPOINT-ADMISSION " + json.dumps(proof, sort_keys=True), flush=True)
    assert all(console[key] and boot[key] for key in (
        "retained_failed", "saved_unchanged", "running_unchanged", "snapshot_unchanged")), proof
    assert console["after_timezone"] == console["before_timezone"] and boot["after_hostname"] == boot["before_hostname"], "special entry points mutated live state despite retained Failed protection"

    with subtest("explicit recovery then ordinary console refresh preserves unsaved current intent"):
        fw.succeed("rm /run/qa-special-fail-restore")
        fw.succeed("sentinel confirm-rollback")
        fw.wait_until_succeeds("test $(hostname) = before-trial && grep -q before-trial " + running, timeout=30)
        fw.wait_until_succeeds("test $(systemctl show --property=LoadState --value sentinel-confirm.service) = not-found", timeout=30)
        assert timezone() == "Europe/Berlin"
        assert fw.succeed("cat " + saved) == boot_bytes
        active = fw.succeed("cat " + running)
        fw.succeed("systemctl restart systemd-vconsole-setup.service")
        fw.wait_for_unit("sentinel-console.service")
        assert timezone() == "Europe/Berlin", "automatic refresh replayed stale saved UTC over active timezone"
        refused = fw.fail("sentinel apply-boot 2>&1")
        assert "unsaved changes" in refused, refused
        assert fw.succeed("hostname").strip() == "before-trial"
        assert fw.succeed("cat " + running) == active
        assert fw.succeed("cat " + saved) == boot_bytes
        configure(["save"])
        fw.succeed("sentinel apply-boot")
        assert fw.succeed("hostname").strip() == "before-trial"

    with subtest("corrupt active state is an explicit error rather than a successful stale refresh"):
        active = fw.succeed("cat " + running)
        fw.succeed("printf invalid-toml > " + running)
        fw.fail("sentinel apply-console")
        fw.fail("sentinel apply-boot")
        assert timezone() == "Europe/Berlin"
        assert fw.succeed("hostname").strip() == "before-trial"
        fw.succeed("printf %s " + shlex.quote(active) + " > " + running)
        fw.succeed("test $(systemctl --failed --no-legend --plain | wc -l) -eq 0")
  '';
}
