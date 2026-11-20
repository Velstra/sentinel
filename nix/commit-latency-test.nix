{ pkgs, self }:
# How long a `commit` takes for the admin account, and where the time goes.
#
# An operator account is in `wheel`, which already has passwordless sudo, so a
# session it opens on the appliance may run as root. Escalating every
# privileged step separately cost one sudo round trip each: an unchanged commit
# of this two-zone box with NAT and three rules made 76 of them and took ~27 s
# as admin against ~4.4 s as root. The session now escalates once. Measured
# here: the admin pays the root cost plus that one escalation, no more.
pkgs.testers.runNixOSTest {
  name = "sentinel-commit-latency";
  nodes.fw = { lib, ... }: {
    imports = [ self.nixosModules.sentinel ];
    networking.hostName = lib.mkForce "fw";
    virtualisation.vlans = [ 1 2 ];
    virtualisation.memorySize = 2048;
    virtualisation.cores = 2;
    networking.firewall.enable = lib.mkForce false;
    services.velstra.interface = lib.mkForce "eth1";
    environment.systemPackages = [ pkgs.strace ];
    # An account outside wheel: its session keeps the per-step path and must
    # not gain anything from the single escalation.
    users.users.viewer.isNormalUser = true;
  };
  testScript = ''
    import shlex, time, statistics, re
    fw.wait_for_unit("multi-user.target")
    fw.wait_for_unit("velstra.service")

    lines = [
        "set interface eth1 zone lan", "set interface eth1 address 10.1.1.1/24",
        "set interface eth1 address6 2001:db8:101::1/64",
        "set interface eth2 zone wan", "set interface eth2 address 10.2.2.1/24",
        "set interface eth2 address6 2001:db8:102::1/64",
        "set firewall global stateful true", "set firewall global fail-closed true",
        "set nat source static zone wan", "set nat source static to 203.0.113.10",
    ]
    for name, proto, port in [("allow-tcp", "tcp", 9090), ("allow-udp", "udp", 9091), ("allow-dns", "udp", 53)]:
        lines += [f"set firewall rule {name} from lan", f"set firewall rule {name} proto {proto}",
                  f"set firewall rule {name} port {port}", f"set firewall rule {name} action accept"]

    def session(commands, user):
        script = "printf '%s\\n' " + " ".join(shlex.quote(c) for c in commands) + " | sentinel configure"
        return script if user == "root" else f"su {user} -c " + shlex.quote(script)

    def commit(user, extra=()):
        t0 = time.monotonic()
        out = fw.succeed(session(list(extra) + ["commit", "exit"], user) + " 2>&1")
        elapsed = time.monotonic() - t0
        assert "error:" not in out.lower(), out
        return elapsed

    def stamp(t):
        h, m, sec = t.split(":")
        return int(h) * 3600 + int(m) * 60 + float(sec)

    def sudo_steps(user):
        """Every sudo one unchanged commit by `user` starts, with its duration.

        strace runs as root, so sudo keeps its setuid bit under the tracer."""
        fw.succeed("rm -f /tmp/trace; strace -f -tt -qq -e trace=execve,exit_group -e signal=none -o /tmp/trace "
                   + session(["commit", "exit"], user) + " >/dev/null 2>&1")
        started, ended, argvs = {}, {}, {}
        for l in fw.succeed("cat /tmp/trace").splitlines():
            m = re.match(r'(\d+) +([\d:.]+) (execve|exit_group)\((.*)', l)
            if not m:
                continue
            pid, t, call, rest = m.group(1), stamp(m.group(2)), m.group(3), m.group(4)
            if call == "execve" and pid not in started:
                started[pid] = t
                argvs[pid] = re.findall(r'"((?:[^"\\]|\\.)*)"', rest)[1:]
            elif call == "exit_group":
                ended[pid] = t
        def short(argv):
            return " ".join((a.rsplit("/", 1)[-1] if a.startswith("/nix/store/") else a) for a in argv[:7])
        return [f"{ended.get(p, started[p]) - started[p]:6.2f}s  {short(argvs[p])}"
                for p in argvs if argvs[p] and argvs[p][0].rsplit("/", 1)[-1] == "sudo"]

    with subtest("the admin's configuration is in place"):
        fw.succeed(session(lines + ["commit", "save", "exit"], "admin"))
        fw.wait_until_succeeds("grep -q snat_address /run/sentinel/velstra.toml")

    report = {}
    for user in ("root", "admin"):
        report[f"unchanged commit as {user}"] = [commit(user) for _ in range(3)]
    report["one-rule commit as admin"] = [
        commit("admin", [f"set firewall rule allow-tcp port {9100 + i}"]) for i in range(3)
    ]
    steps = {user: sudo_steps(user) for user in ("root", "admin")}
    print("=== commit latency (seconds) ===")
    for name, runs in report.items():
        print(f"{name}: median {statistics.median(runs):.2f} runs {[round(r, 2) for r in runs]}")
    for user, calls in steps.items():
        print(f"sudo invocations in one unchanged {user} commit: {len(calls)}")
        for c in calls:
            print("  " + c)

    root = statistics.median(report["unchanged commit as root"])
    admin = statistics.median(report["unchanged commit as admin"])
    changed = statistics.median(report["one-rule commit as admin"])

    with subtest("an admin session escalates once, not once per step"):
        # The policy check and the escalation itself; everything after runs
        # as root. Counted, not timed: the count does not depend on the host.
        assert len(steps["admin"]) <= len(steps["root"]) + 2, (
            f"admin commit ran {len(steps['admin'])} sudo steps, root {len(steps['root'])}")

    with subtest("an admin commit costs what a root commit costs"):
        # One escalation measured 0.3-0.9 s on this VM (under strace); 3 s is
        # that twice over plus scheduling noise, and an order of magnitude
        # below the per-step cost this replaced (~22 s).
        assert admin <= root + 3.0, f"admin {admin:.2f} s vs root {root:.2f} s"
        assert changed <= root + 3.0, f"one-rule admin commit {changed:.2f} s vs root {root:.2f} s"

    with subtest("the sudo log names the operator who opened the session"):
        sudo_log = fw.succeed("journalctl -b -o cat _COMM=sudo | grep 'COMMAND=.*configure' || true")
        assert "admin :" in sudo_log, sudo_log

    with subtest("an account outside wheel gains nothing"):
        status, out = fw.execute(session(["set system hostname nope", "commit", "exit"], "viewer") + " 2>&1")
        print(out)
        fw.fail("hostname | grep -x nope")
        assert '"nope"' not in fw.succeed("cat /run/sentinel/running.toml"), out
  '';
}
