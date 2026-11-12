# Exercise the shipped NixOS sshd/keygen units, not an imitation key generator.
# Deliberately delay a nofail persistent mount past sysinit on every cold boot.
{ pkgs, self }:
pkgs.testers.runNixOSTest {
  name = "sentinel-ssh-persistence";
  nodes.machine = { lib, ... }: {
    imports = [ self.nixosModules.sentinel ];
    virtualisation.memorySize = 768;
    virtualisation.emptyDiskImages = [ 128 ];
    virtualisation.fileSystems."/var/lib/sentinel" = {
      device = "/dev/vdb";
      fsType = "ext4";
      autoFormat = true;
      options = [ "nofail" "x-systemd.requires=lab-state-delay.service" ];
    };
    systemd.services.lab-state-delay = {
      # nofail must permit sysinit/keygen to race this barrier without the fix.
      after = [ "sysinit.target" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        sleep 6
        touch /run/lab-state-ready
      '';
    };
    # A missing-key boot must actually reach keygen after the delayed mount.
    # This assertion fails without the product dependency, rather than allowing
    # a key generated on the underlying root to disappear unnoticed.
    systemd.services.sshd-keygen.preStart = ''
      ${pkgs.util-linux}/bin/mountpoint -q /var/lib/sentinel
      test -e /run/lab-state-ready
      touch /run/lab-keygen-after-mount
    '';
    boot.loader.systemd-boot.enable = lib.mkForce false;
    boot.loader.efi.canTouchEfiVariables = lib.mkForce false;
  };
  testScript = ''
    def fingerprints():
        return {kind: machine.succeed(
            f"ssh-keygen -lf /var/lib/sentinel/ssh/ssh_host_{kind}_key.pub").split()[1]
            for kind in ("ed25519", "rsa")}

    def offered_key():
        # Compare the actual SSH wire identity, not just files on disk.
        scan = machine.succeed("ssh-keyscan -T 5 -t ed25519 127.0.0.1 2>/dev/null")
        keys = {fields[2] for line in scan.splitlines()
            if len(fields := line.split()) == 3 and fields[1] == "ssh-ed25519"}
        assert len(keys) == 1, scan
        return keys.pop()

    with subtest("first key generation waits for a delayed nofail data mount"):
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("sshd.service")
        machine.succeed("test -e /run/lab-keygen-after-mount")
        machine.succeed("findmnt -n -o SOURCE /var/lib/sentinel | grep -x /dev/vdb")
        for unit in ("sshd", "sshd-keygen"):
            for property in ("After", "Requires"):
                dependencies = machine.succeed(f"systemctl show {unit}.service -p {property} --value").split()
                assert "var-lib-sentinel.mount" in dependencies, (unit, property, dependencies)
        original = fingerprints()
        offered = offered_key()
        public = machine.succeed("cut -d' ' -f2 /var/lib/sentinel/ssh/ssh_host_ed25519_key.pub").strip()
        assert offered == public, (offered, public)
        machine.succeed("printf persisted > /var/lib/sentinel/lab-marker")

    with subtest("cold boots preserve both keys and the actual offered identity"):
        for attempt in range(2):
            machine.shutdown()
            machine.start()
            machine.wait_for_unit("multi-user.target")
            machine.wait_for_unit("sshd.service")
            assert fingerprints() == original, (attempt, original, fingerprints())
            assert offered_key() == offered, attempt
            machine.succeed("grep -qx persisted /var/lib/sentinel/lab-marker")
            # Existing keys cause the real keygen condition to skip its script.
            machine.fail("test -e /run/lab-keygen-after-mount")
  '';
}
