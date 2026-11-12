# Actual product boot renderer and SSH wire behavior. No replacement sshd,
# direct marker edits, daemon-stop workaround or saved/running-state repair.
{ pkgs, self }:
let
  node = setting: { lib, ... }: {
    imports = [ self.nixosModules.sentinel ];
    virtualisation.memorySize = 1024;
    services.velstra.appliance = lib.mkForce (pkgs.writeText "ssh-policy.toml" ''
      [system]
      hostname = "ssh-policy-${if setting == null then "default" else if setting then "enabled" else "disabled"}"
      ${lib.optionalString (setting != null) ''
        [services.ssh]
        enable = ${if setting then "true" else "false"}
      ''}
    '');
  };
in pkgs.testers.runNixOSTest {
  name = "sentinel-ssh-declarative-boot-and-live-policy";
  nodes.defaulted = node null;
  nodes.enabled = node true;
  nodes.disabled = node false;
  testScript = ''
    import json
    import os
    from pathlib import Path
    import shlex

    nodes = ((defaulted, True), (enabled, True), (disabled, False))
    observations = []
    identities = {}

    def boot_all():
        start_all()
        for machine, _ in nodes:
            machine.wait_for_unit("multi-user.target")
            machine.wait_for_unit("sentinel-boot.service")

    def observe(machine, wanted, phase):
        # Boot/start conditions and actual offered SSH identity must agree.
        if wanted:
            machine.wait_for_unit("sshd.service")
        else:
            # An ordinary start request must not override disabled intent.
            machine.succeed("systemctl start sshd.service")
        active, state = machine.execute("systemctl is-active sshd.service")
        marker, _ = machine.execute("test -f /run/sentinel-ssh/enabled")
        scanned, keys = machine.execute(
            "${pkgs.openssh}/bin/ssh-keyscan -T 3 -t ed25519 127.0.0.1 2>/dev/null")
        offered = {fields[2] for line in keys.splitlines()
                   if len(fields := line.split()) == 3 and fields[1] == "ssh-ed25519"}
        assert (active == 0) == wanted, (phase, machine.name, state)
        assert (marker == 0) == wanted, (phase, machine.name, marker)
        assert (scanned == 0) == wanted, (phase, machine.name, keys)
        assert len(offered) == int(wanted), (phase, machine.name, keys)
        machine.fail("systemctl is-failed --quiet sshd.service")
        public = machine.succeed("cut -d' ' -f2 /var/lib/sentinel/ssh/ssh_host_ed25519_key.pub").strip()
        identities.setdefault(machine.name, public)
        assert public == identities[machine.name], "SSH host identity changed"
        if wanted:
            assert offered == {public}
        observations.append({"node": machine.name, "phase": phase,
                             "enabled": wanted, "wire_key_offered": bool(offered),
                             "unit_state": state.strip()})

    def configure(machine, wanted, save):
        commands = ["set services ssh enable " + str(wanted).lower(), "commit"]
        if save:
            commands.append("save")
        commands.append("exit")
        pipeline = "printf '%s\\n' " + " ".join(shlex.quote(command) for command in commands)
        machine.succeed("su admin -c " + shlex.quote(pipeline + " | sentinel configure"))

    boot_all()
    for machine, wanted in nodes:
        observe(machine, wanted, "initial-saved-boot")

    with subtest("live commit uses effective intent even before save"):
        for machine, original in nodes:
            saved = machine.succeed("sha256sum /var/lib/sentinel/appliance.toml")
            configure(machine, not original, False)
            observe(machine, not original, "unsaved-live-commit")
            assert machine.succeed("sha256sum /var/lib/sentinel/appliance.toml") == saved
        for machine, _ in nodes:
            machine.shutdown()
        boot_all()
        for machine, wanted in nodes:
            observe(machine, wanted, "unsaved-change-discarded-by-cold-boot")

    with subtest("saved opposite policy survives a cold boot"):
        for machine, original in nodes:
            configure(machine, not original, True)
            observe(machine, not original, "saved-live-change")
            machine.shutdown()
        boot_all()
        for machine, original in nodes:
            observe(machine, not original, "saved-change-cold-boot")

    with subtest("normal CLI restores policy and preserves identity after reboot"):
        for machine, original in nodes:
            configure(machine, original, True)
            observe(machine, original, "restored-live-change")
            machine.shutdown()
        boot_all()
        for machine, original in nodes:
            observe(machine, original, "restored-policy-cold-boot")

    with Path(os.environ["out"], "ssh-policy.json").open("w") as output:
        json.dump({"actual_boot_and_live_observations": observations,
                   "host_identities_preserved": True}, output, indent=2)
  '';
}
