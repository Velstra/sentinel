# Real kernel CAKE evidence: a specialized late boot entry point must not
# replay stale saved shaping while an independent CLI restore is Failed.
{ pkgs, self }:
let
  lib = pkgs.lib;
  timer = pkgs.writeShellScript "qa-late-confirm-systemd-run" ''
    set -euo pipefail
    args=()
    for arg in "$@"; do
      if test "$arg" = --on-active=1min; then args+=(--on-active=5s)
      else args+=("$arg"); fi
    done
    exec ${pkgs.systemd}/bin/systemd-run "''${args[@]}"
  '';
  hostname = pkgs.writeShellScript "qa-late-confirm-hostname" ''
    set -euo pipefail
    if test -e /run/qa-late-fail-restore && test "''${1:-}" = before-trial; then
      ${pkgs.nettools}/bin/hostname partial-restore
      echo 'disposable fixture: real restore failed after hostname mutation' >&2
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
  name = "sentinel-confirm-boot-late-admission";
  globalTimeout = 240;
  nodes.fw = { ... }: {
    imports = [ self.nixosModules.sentinel ./test-network-seed.nix ];
    virtualisation = { vlans = [ 1 ]; memorySize = 1536; };
    networking.firewall.enable = lib.mkForce false;
    networking.interfaces.eth1.ipv4.addresses = [{ address = "192.0.2.1"; prefixLength = 24; }];
    services.velstra.interface = lib.mkForce "eth1";
    environment.systemPackages = [ pkgs.iproute2 ];
  };
  testScript = ''
    import json, shlex
    fw.wait_for_unit("multi-user.target")
    for unit in ("sentinel-boot.service", "velstra.service", "wren.service"):
        fw.wait_for_unit(unit)
    fw.succeed("test -d /sys/module/sch_cake")
    saved = "/var/lib/sentinel/appliance.toml"
    running = "/run/sentinel/running.toml"
    snapshot = "/var/lib/sentinel/.appliance.toml.commit-confirm.toml"
    stamp = "/run/sentinel/qos/eth1"

    def configure(lines, fault=False):
        binary = "${cli}/bin/sentinel" if fault else "sentinel"
        script = "\n".join(lines + ["exit", ""])
        fw.succeed("printf %s " + shlex.quote(script) + " | " + binary + " configure")

    def qdisc():
        return fw.succeed("tc qdisc show dev eth1 root").strip()

    configure(["set system hostname boot-saved", "set interface eth1 qos discipline cake",
               "set interface eth1 qos bandwidth 10mbit", "commit", "save"])
    assert "cake" in qdisc() and "10Mbit" in qdisc(), qdisc()
    saved_bytes = fw.succeed("cat " + saved)
    configure(["set system hostname before-trial", "set interface eth1 qos bandwidth 20mbit", "commit"])
    assert "20Mbit" in qdisc(), qdisc()
    fw.succeed("touch /run/qa-late-fail-restore")
    configure(["set system hostname trial-active", "set interface eth1 qos bandwidth 30mbit", "commit-confirm 1"], fault=True)
    assert "30Mbit" in qdisc(), qdisc()
    fw.wait_until_succeeds("test $(systemctl show --property=ActiveState --value sentinel-confirm.service) = failed", timeout=20)
    assert "30Mbit" in qdisc(), "real failed restore must leave the current kernel shaper available as the admission oracle"
    before = {p: fw.succeed("cat " + p) for p in (saved, running, snapshot, stamp)}
    generation = fw.succeed("cat /run/sentinel/mutation.json")
    assert before[saved] == saved_bytes
    kernel = qdisc()
    status, output = fw.execute("sentinel apply-boot-late --config " + saved + " 2>&1")
    proof = dict(exit=status, before_qdisc=kernel, after_qdisc=qdisc(),
                 retained_failed=fw.succeed("systemctl show --property=ActiveState --value sentinel-confirm.service").strip() == "failed",
                 saved_unchanged=fw.succeed("cat " + saved) == before[saved],
                 running_unchanged=fw.succeed("cat " + running) == before[running],
                 snapshot_unchanged=fw.succeed("cat " + snapshot) == before[snapshot],
                 stamp_unchanged=fw.succeed("cat " + stamp) == before[stamp])
    print("BOOT-LATE-ADMISSION " + json.dumps(proof, sort_keys=True), flush=True)
    assert proof["retained_failed"] and all(proof[k] for k in ("saved_unchanged", "running_unchanged", "snapshot_unchanged")), proof
    assert status != 0 and proof["after_qdisc"] == kernel and proof["stamp_unchanged"], "late boot replay mutated the actual kernel shaper despite retained Failed recovery"

    def unchanged():
        assert qdisc() == kernel
        assert {p: fw.succeed("cat " + p) for p in before} == before
        assert fw.succeed("cat /run/sentinel/mutation.json") == generation
        assert fw.succeed("systemctl show --property=ActiveState --value sentinel-confirm.service").strip() == "failed"

    assert "recovery failed" in output, output
    unchanged()
    with subtest("automatic late refresh explicitly defers all real Failed protection without effects"):
        message = fw.succeed("sentinel apply-boot-late 2>&1")
        assert "deferred" in message and "no settings were applied" in message, message
        unchanged()

    with subtest("a corrupt management journal cannot be hidden by the other engine's recognized protection"):
        journal = "/var/lib/sentinel/.appliance.toml.pending.json"
        fw.fail("test -e " + journal)
        fw.succeed("printf invalid-json > " + journal + " && chmod 600 " + journal)
        for command in ("sentinel apply-boot-late", "sentinel apply-console"):
            refused = fw.fail(command + " 2>&1")
            assert "reading pending configuration transaction" in refused, refused
            unchanged()
        fw.succeed("rm " + journal)

    with subtest("real retained retry restores prior active20 and ordinary automatic refresh preserves it"):
        fw.succeed("rm /run/qa-late-fail-restore")
        fw.succeed("sentinel confirm-rollback")
        fw.wait_until_succeeds("test $(hostname) = before-trial && grep -q before-trial " + running, timeout=30)
        fw.wait_until_succeeds("test $(systemctl show --property=LoadState --value sentinel-confirm.service) = not-found", timeout=30)
        assert "20Mbit" in qdisc(), qdisc()
        assert fw.succeed("cat " + saved) == saved_bytes
        active = fw.succeed("cat " + running)
        fw.succeed("sentinel apply-boot-late")
        assert "20Mbit" in qdisc(), "automatic reapply chose stale saved10 instead of active20"
        assert fw.succeed("cat " + running) == active
        assert fw.succeed("cat " + saved) == saved_bytes

    with subtest("malformed and nonregular RUNNING never select the older saved shaper"):
        previous_generation = fw.succeed("cat /run/sentinel/mutation.json")
        fw.succeed("printf 'invalid = [' > " + running)
        fw.fail("sentinel apply-boot-late")
        assert "20Mbit" in qdisc()
        assert fw.succeed("cat /run/sentinel/mutation.json") == previous_generation
        fw.succeed("rm " + running + " && ln -s /var/lib/sentinel/appliance.toml " + running)
        refused = fw.fail("sentinel apply-boot-late 2>&1")
        assert "not a regular file" in refused, refused
        assert "20Mbit" in qdisc()
        assert fw.succeed("cat /run/sentinel/mutation.json") == previous_generation
        fw.succeed("rm " + running + " && printf %s " + shlex.quote(active) + " > " + running)

    with subtest("genuine cold boot still installs saved QoS after networkd"):
        configure(["save"])
        persisted = fw.succeed("cat " + saved)
        boot = fw.succeed("cat /proc/sys/kernel/random/boot_id")
        fw.shutdown()
        fw.start()
        fw.wait_for_unit("multi-user.target")
        for unit in ("sentinel-boot.service", "sentinel-boot-late.service", "velstra.service", "wren.service"):
            fw.wait_for_unit(unit)
        assert fw.succeed("cat /proc/sys/kernel/random/boot_id") != boot
        assert fw.succeed("cat " + saved) == persisted
        assert "20Mbit" in qdisc(), "cold boot failed to restore the saved kernel shaper"
        assert fw.succeed("hostname").strip() == "before-trial"
        fw.succeed("test $(systemctl --failed --no-legend --plain | wc -l) -eq 0")
  '';
}
