# Local grants must converge in both directions, without rebooting sshd or
# deleting account IDs/homes. Every authentication below reaches real sshd/PAM.
{ pkgs, sentinelModule }:
pkgs.testers.runNixOSTest {
  name = "sentinel-login-reconcile";
  nodes.machine = {
    imports = [ sentinelModule ];
    virtualisation.memorySize = 2048;
    environment.systemPackages = [ pkgs.sshpass pkgs.openssh pkgs.openssl pkgs.python3 pkgs.strace pkgs.shadow ];
  };
  testScript = ''
    import json
    import shlex

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("sentinel-boot.service")
    machine.wait_for_unit("sshd.service")
    public = machine.succeed('mkdir -m 700 /var/lib/login-reconcile; ssh-keygen -t ed25519 -N "" -f /var/lib/login-reconcile/key -q; cat /var/lib/login-reconcile/key.pub').strip()
    password = "lifecycle-fixture-passphrase"
    rotated = "lifecycle-rotated-fixture-passphrase"
    state = "/var/lib/sentinel/managed-logins.json"
    options = (
        "-n -o LogLevel=ERROR -o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 "
    )

    def configure(commands, apply=True, expected_error=False):
        if expected_error:
            previous = machine.succeed("sha256sum /var/lib/sentinel/appliance.toml")
        script = "printf '%s\\n' " + " ".join(
            shlex.quote(command) for command in [*commands, "commit", "save", "exit"]
        )
        script += " | su admin -c " + shlex.quote("sentinel configure" + ("" if apply else " --no-apply"))
        script += " 2>&1"
        status, output = machine.execute(script)
        if expected_error:
            assert status != 0 and "error:" in output.lower(), (status, output)
            assert machine.succeed("sha256sum /var/lib/sentinel/appliance.toml") == previous
        else:
            assert status == 0 and "error:" not in output.lower(), (status, output)

    def passwd_auth(user, secret, allowed):
        command = (
            "timeout 15 sshpass -p " + shlex.quote(secret) + " ssh " + options +
            "-o PreferredAuthentications=password -o PubkeyAuthentication=no "
            "-o KbdInteractiveAuthentication=no -o NumberOfPasswordPrompts=1 " +
            shlex.quote(user + "@127.0.0.1") + " whoami 2>&1"
        )
        status, output = machine.execute(command, timeout=20)
        if allowed:
            assert status == 0 and output.strip() == user, (status, output)
        else:
            # A timeout or a dead server must never count as revocation.
            assert status in (5, 255) and f"{user}@127.0.0.1: Permission denied" in output, (status, output)

    def key_auth(user, allowed=True):
        command = (
            "timeout 15 ssh " + options +
            "-i /var/lib/login-reconcile/key -o IdentitiesOnly=yes -o BatchMode=yes "
            "-o PasswordAuthentication=no " + shlex.quote(user + "@127.0.0.1") + " whoami 2>&1"
        )
        status, output = machine.execute(command, timeout=20)
        if allowed:
            assert status == 0 and output.strip() == user, (status, output)
        else:
            assert status == 255 and f"{user}@127.0.0.1: Permission denied" in output, (status, output)

    def owners():
        return json.loads(machine.succeed("cat " + state))

    def grant(user, secret=None, key=True):
        commands = [f"set system login {user} ssh-key {public}"] if key else []
        if secret is not None:
            commands.append(f"set system login {user} password {secret}")
        configure(commands)

    with subtest("managed credentials work and unrelated accounts are preserved"):
        machine.succeed("useradd -m -s /run/current-system/sw/bin/bash unrelated")
        unrelated = machine.succeed("openssl passwd -6 unrelated-fixture-password").strip()
        machine.succeed("usermod -p " + shlex.quote(unrelated) + " unrelated")
        configure(["set services ssh password-authentication true"])
        grant("lifecycle", password)
        uid = machine.succeed("id -u lifecycle").strip()
        passwd_auth("lifecycle", password, True)
        key_auth("lifecycle")
        assert "lifecycle" in owners() and "unrelated" not in owners()
        assert machine.succeed("stat -c %a " + state).strip() == "640"

    with subtest("password hashes never appear in child process arguments"):
        machine.succeed(
            "printf '%s\\n' " + shlex.quote(f"set system login lifecycle password {password}") +
            " commit save exit | strace -f -s 16384 -e trace=execve "
            "-o /var/lib/login-reconcile/password.trace sentinel configure"
        )
        password_hash = machine.succeed("getent shadow lifecycle | cut -d: -f2").strip()
        trace = machine.succeed("cat /var/lib/login-reconcile/password.trace")
        assert password_hash not in trace, "a password hash was exposed in process arguments"
        assert "chpasswd" in trace and '"--encrypted"' in trace, trace
        passwd_auth("lifecycle", password, True)

    with subtest("a no-op reconcile preserves the password-aging date"):
        machine.succeed("chage -d 20000 lifecycle")
        configure([])
        assert machine.succeed("getent shadow lifecycle | cut -d: -f3").strip() == "20000"
        passwd_auth("lifecycle", password, True)

    with subtest("removing a password immediately revokes it while the key stays usable"):
        sshd = machine.succeed("systemctl show sshd -p MainPID --value").strip()
        configure(["delete system login lifecycle hashed-password"])
        passwd_auth("lifecycle", password, False)
        assert machine.succeed("getent shadow lifecycle | cut -d: -f2").strip() == "!"
        key_auth("lifecycle")
        before = machine.succeed("cat " + state)
        configure([])
        assert machine.succeed("cat " + state) == before
        assert machine.succeed("id -u lifecycle").strip() == uid
        assert machine.succeed("systemctl show sshd -p MainPID --value").strip() == sshd

    with subtest("password rotation and whole-login removal revoke old credentials"):
        configure([f"set system login lifecycle password {rotated}"])
        passwd_auth("lifecycle", password, False)
        passwd_auth("lifecycle", rotated, True)
        key_auth("lifecycle")
        configure(["delete system login lifecycle"])
        passwd_auth("lifecycle", rotated, False)
        key_auth("lifecycle", False)
        assert machine.succeed("id -u lifecycle").strip() == uid
        assert "lifecycle" not in owners()

    with subtest("password-only grants are tracked and removed without a key file"):
        grant("passwordonly", password, key=False)
        passwd_auth("passwordonly", password, True)
        machine.fail("test -e /run/sentinel-ssh/authorized_keys.passwordonly")
        assert "passwordonly" in owners()
        configure(["delete system login passwordonly"])
        passwd_auth("passwordonly", password, False)
        assert "passwordonly" not in owners()

    with subtest("already absent managed accounts converge without recreation"):
        grant("passwordonly", password, key=False)
        # The preceding real SSH login may leave systemd --user alive for its
        # configured stop delay. Delete only after that observed process exits;
        # a busy account is not the absent-account fixture this subtest needs.
        machine.succeed("command -v pgrep")
        machine.wait_until_succeeds("! pgrep -u passwordonly", timeout=30)
        machine.succeed("userdel passwordonly")
        configure(["delete system login passwordonly"])
        machine.fail("id -u passwordonly")
        assert "passwordonly" not in owners()

    with subtest("legacy generated keys establish ownership before a login is removed"):
        grant("legacy", password)
        machine.succeed("rm " + state)
        configure(["delete system login legacy"])
        passwd_auth("legacy", password, False)
        key_auth("legacy", False)
        assert "legacy" not in owners()

    with subtest("a failed ownership write cannot create an untracked credential"):
        machine.succeed(f"mount --bind {state} {state}")
        configure([f"set system login retryuser password {password}"], expected_error=True)
        machine.fail("id -u retryuser")
        assert "retryuser" not in owners()
        machine.succeed("umount " + state)
        grant("retryuser", password)
        passwd_auth("retryuser", password, True)

    with subtest("atomic configuration publication synchronizes its directory"):
        probe = "/var/lib/login-reconcile/probe.toml"
        machine.succeed("cp /var/lib/sentinel/appliance.toml " + probe)
        machine.succeed(
            "printf '%s\\n' 'set system hostname durable-probe' commit save exit "
            "| strace -yy -e trace=fsync,fdatasync,rename,renameat,renameat2 "
            "-o /var/lib/login-reconcile/sync.trace sentinel configure --no-apply --config " + probe
        )
        lines = machine.succeed("cat /var/lib/login-reconcile/sync.trace").splitlines()
        published = next(index for index, line in enumerate(lines) if
                         "rename" in line and '"' + probe + '"' in line and "= 0" in line)
        assert any("fsync(" in line and "</var/lib/login-reconcile>" in line and "= 0" in line
                   for line in lines[published + 1:]), "configuration rename was not followed by directory synchronization"
    with subtest("a failed revocation retains ownership and can be retried"):
        target = "/run/sentinel-ssh/authorized_keys.retryuser"
        machine.succeed(f"mount --bind {target} {target}")
        configure(["delete system login retryuser"], expected_error=True)
        assert "retryuser" in owners()
        machine.succeed("umount " + target)
        configure(["delete system login retryuser"])
        passwd_auth("retryuser", password, False)
        key_auth("retryuser", False)
        assert "retryuser" not in owners()

    with subtest("saved key-only grants are restored across a real reboot"):
        grant("lifecycle")
        key_auth("lifecycle")
        machine.shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("sentinel-boot.service")
        machine.wait_for_unit("sshd.service")
        key_auth("lifecycle")
        passwd_auth("lifecycle", rotated, False)

    with subtest("an offline desired-state removal is enforced at the next boot"):
        configure([f"set system login lifecycle password {password}"])
        passwd_auth("lifecycle", password, True)
        configure(["delete system login lifecycle"], apply=False)
        passwd_auth("lifecycle", password, True)
        machine.shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("sentinel-boot.service")
        machine.wait_for_unit("sshd.service")
        passwd_auth("lifecycle", password, False)
        key_auth("lifecycle", False)
        assert owners() == []
        assert machine.succeed("getent shadow unrelated | cut -d: -f2").strip() == unrelated

    with subtest("saved credential revocation survives an immediate power failure"):
        grant("crashuser", password)
        passwd_auth("crashuser", password, True)
        configure(["delete system login crashuser"])
        machine.crash()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("sentinel-boot.service")
        machine.wait_for_unit("sshd.service")
        passwd_auth("crashuser", password, False)
        key_auth("crashuser", False)

    with subtest("a refused SSH stop reports failure and preserves the saved configuration"):
        machine.succeed("mkdir -p /run/systemd/system/sshd.service.d; printf '[Unit]\\nRefuseManualStop=yes\\n' > /run/systemd/system/sshd.service.d/90-refuse-stop.conf; systemctl daemon-reload")
        configure(["set services ssh enable false"], expected_error=True)
        machine.succeed("systemctl is-active sshd.service")
        machine.succeed("rm /run/systemd/system/sshd.service.d/90-refuse-stop.conf; systemctl daemon-reload")

    with subtest("disabled SSH stays closed across reboot and can be enabled live"):
        configure(["set services ssh enable false"])
        machine.fail("systemctl is-active sshd.service")
        machine.shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("sentinel-boot.service")
        machine.fail("systemctl is-active sshd.service")
        machine.fail("ss -tlnH 'sport = :22' | grep -q LISTEN")
        configure(["set services ssh enable true"])
        machine.wait_for_unit("sshd.service")
        assert machine.succeed("getent shadow unrelated | cut -d: -f2").strip() == unrelated
  '';
}
