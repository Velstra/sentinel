# Appended to the real WireGuard fixture after its interface has been created.
import shlex

private_unit = "/run/systemd/network/10-sentinel-wg0.netdev"


def unchanged_commit():
    body = "printf '%s\\n' commit save exit | sentinel configure 2>&1"
    output = machine.succeed("su admin -c " + shlex.quote(body))
    assert "commit ok: applied live" in output and "saved" in output, output


with subtest("unchanged private network files keep their identity and daemon state"):
    machine.fail("su admin -c " + shlex.quote("cat " + private_unit))
    identity = machine.succeed("stat -c '%i:%y' " + private_unit)
    ifindex = machine.succeed("cat /sys/class/net/wg0/ifindex")
    pids = machine.succeed("systemctl show -p MainPID --value velstra.service wren.service")
    for _ in range(3):
        unchanged_commit()
        assert machine.succeed("stat -c '%i:%y' " + private_unit) == identity
        assert machine.succeed("cat /sys/class/net/wg0/ifindex") == ifindex
        assert machine.succeed("systemctl show -p MainPID --value velstra.service wren.service") == pids
        machine.fail("su admin -c " + shlex.quote("cat " + private_unit))
        machine.succeed("test ! -e /run/sentinel/networkd-reload.pending")

with subtest("non-UTF-8 private network drift is repaired without exposing the key"):
    digest = machine.succeed("sha256sum " + private_unit).split()[0]
    machine.succeed("printf '\\377' > " + private_unit)
    unchanged_commit()
    assert machine.succeed("sha256sum " + private_unit).split()[0] == digest
    assert machine.succeed("stat -c '%U:%G:%a' " + private_unit).strip() == "root:systemd-network:640"
    machine.fail("su admin -c " + shlex.quote("cat " + private_unit))
    machine.succeed("test ! -e /run/sentinel/networkd-reload.pending")

with subtest("private file permissions converge without rewriting equal contents"):
    identity = machine.succeed("stat -c '%i:%y' " + private_unit)
    machine.succeed("chmod 000 " + private_unit)
    unchanged_commit()
    assert machine.succeed("stat -c '%i:%y' " + private_unit) == identity
    assert machine.succeed("stat -c %a " + private_unit).strip() == "640"
    machine.fail("su admin -c " + shlex.quote("cat " + private_unit))
