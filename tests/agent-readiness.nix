# A successful systemd start job is not a readiness acknowledgement.
{ pkgs, sentinelModule, sentinel }:
pkgs.testers.runNixOSTest {
  name = "sentinel-agent-readiness";
  nodes.machine = {
    imports = [ sentinelModule ];
    virtualisation.memorySize = 2048;
    environment.systemPackages = [ pkgs.bpftools pkgs.curl ];
  };
  testScript = ''
    import contextlib
    import json
    import shlex
    import tomllib

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("velstra.service")
    query = "${sentinel}/bin/sentinel agent-query status"
    machine.wait_until_succeeds(query + " | grep '^Ready$'", timeout=20)
    programs = "/sys/fs/bpf/sentinel/programs"

    def document(path):
        return tomllib.loads(machine.succeed("cat " + path))

    def pid():
        return machine.succeed("systemctl show -p MainPID --value velstra.service").strip()

    def command(*lines):
        script = "\n".join([*lines, "commit", "save", "exit", ""])
        return "su admin -c " + shlex.quote("printf %s " + shlex.quote(script) + " | ${sentinel}/bin/sentinel configure 2>&1")

    def apply(*lines):
        output = machine.succeed(command(*lines))
        assert "commit ok: applied live" in output and "saved /" in output, output

    @contextlib.contextmanager
    def incompatible_program_table():
        # Keep the last-good graph alive while the public pin has a real ABI fault.
        original = json.loads(machine.succeed("bpftool -j map show pinned " + programs))["id"]
        shadow = "/sys/fs/bpf/readiness-saved-programs"
        machine.succeed("bpftool map pin id " + str(original) + " " + shadow)
        machine.succeed("rm " + programs)
        machine.succeed("bpftool map create " + programs + " type array key 4 value 4 entries 3 name bad_programs")
        try:
            yield
        finally:
            machine.succeed("mv -f " + shadow + " " + programs)
            machine.succeed("systemctl restart velstra.service")
            machine.wait_until_succeeds(query + " | grep '^Ready$'", timeout=20)

    with subtest("real startup failure cannot be committed or saved as success"):
        saved = document("/var/lib/sentinel/appliance.toml")
        running = document("/run/sentinel/running.toml")
        hostname = machine.succeed("hostname").strip()
        with incompatible_program_table():
            output = machine.fail(command("set system hostname readiness-must-fail"))
            assert "to become Ready failed" in output, output
            assert "commit ok: applied live" not in output and "saved /" not in output, output
            machine.succeed("journalctl -u velstra.service --no-pager -o cat | grep 'incompatible persistent control map programs'")
            assert document("/var/lib/sentinel/appliance.toml") == saved
            assert document("/run/sentinel/running.toml") == running
            assert machine.succeed("hostname").strip() == hostname

    with subtest("retry after startup recovery converges"):
        apply("set system hostname readiness-recovered")
        assert machine.succeed("hostname").strip() == "readiness-recovered"
        assert document("/var/lib/sentinel/appliance.toml")["system"]["hostname"] == "readiness-recovered"
        machine.succeed(query + " | grep '^Ready$'")

    def integer(data):
        return int.from_bytes(bytes(int(part, 16) for part in data), "little")

    def config_map_id():
        entries = json.loads(machine.succeed("bpftool -j map dump pinned " + programs))
        main = [integer(entry["value"]) for entry in entries if integer(entry["key"]) == 1]
        assert len(main) == 1, entries
        info = json.loads(machine.succeed("bpftool -j prog show id " + str(main[0])))
        configs = []
        for index in info["map_ids"]:
            info = json.loads(machine.succeed("bpftool -j map show id " + str(index)))
            if info.get("name") == "CONFIG":
                configs.append(index)
        assert len(configs) == 1, configs
        return configs[0]

    with subtest("repeated apply repairs an active daemon with an unusable configuration map"):
        old_pid = pid()
        old_config = config_map_id()
        machine.succeed("bpftool map freeze id " + str(old_config))
        # A real blocked gate and frozen CONFIG require fresh process-owned maps.
        machine.succeed("bpftool map update pinned /sys/fs/bpf/sentinel/apply-state key 0 0 0 0 value 2 0 0 0")
        machine.succeed("systemctl is-active --quiet velstra.service")
        machine.succeed(query + " | grep '^Failed'")
        apply()
        machine.succeed(query + " | grep '^Ready$'")
        assert pid() != old_pid and int(pid()) > 0
        assert config_map_id() != old_config

    with subtest("unchanged healthy services preserve PID and compiled files"):
        healthy_pid = pid()
        files = machine.succeed("stat -c '%i:%y' /run/sentinel/velstra.toml /run/sentinel/wren.toml")
        apply()
        assert pid() == healthy_pid
        assert machine.succeed("stat -c '%i:%y' /run/sentinel/velstra.toml /run/sentinel/wren.toml") == files

    with subtest("authenticated API reports actual startup failure and preserves state"):
        machine.succeed("systemctl start sentinel-api.service")
        machine.wait_for_open_port(8080)
        machine.succeed("install -m 0600 /dev/null /run/readiness-auth.headers; sed 's/^/Authorization: Bearer /' /var/lib/sentinel/api-token > /run/readiness-auth.headers")

        def api_apply():
            script = "set system hostname readiness-api\ncommit\nsave\n"
            machine.succeed("printf %s " + shlex.quote(script) + " > /run/readiness-script")
            code = machine.succeed(
                "curl -sS --max-time 60 --cacert /var/lib/sentinel/web-tls/cert.pem "
                "-H @/run/readiness-auth.headers --data-binary @/run/readiness-script "
                "-o /run/readiness-response -w '%{http_code}' https://127.0.0.1:8080/api/v1/configure"
            ).strip()
            return code, json.loads(machine.succeed("cat /run/readiness-response"))

        saved = document("/var/lib/sentinel/appliance.toml")
        running = document("/run/sentinel/running.toml")
        with incompatible_program_table():
            code, response = api_apply()
            assert code == "200" and response.get("ok") is False, response
            assert "to become Ready failed" in response.get("output", ""), response
            assert document("/var/lib/sentinel/appliance.toml") == saved
            assert document("/run/sentinel/running.toml") == running
            assert machine.succeed("hostname").strip() == saved["system"]["hostname"]

    with subtest("API success requires an actually Ready recovered service"):
        code, response = api_apply()
        assert code == "200" and response.get("ok") is True, response
        assert document("/var/lib/sentinel/appliance.toml")["system"]["hostname"] == "readiness-api"
        assert machine.succeed("hostname").strip() == "readiness-api"
        machine.succeed(query + " | grep '^Ready$'")

    with subtest("removing the last zoned interface restores the actual fallback and stays idempotent"):
        def uplink():
            process = pid()
            assert process.isdigit() and int(process) > 0, process
            args = shlex.split(machine.succeed("ps -ww -p " + process + " -o args="))
            return args[args.index("--iface") + 1]

        fallback = uplink()
        machine.succeed("ip link add name lab-uplink type dummy; ip link set dev lab-uplink up")
        apply("set interface lab-uplink zone lab")
        assert uplink() == "lab-uplink"
        acknowledgement = json.loads(machine.succeed("${sentinel}/bin/sentinel agent-query 'interface lab-uplink'"))
        assert acknowledgement["ready"] is True, acknowledgement

        apply("delete interface lab-uplink zone")
        assert uplink() == fallback, (uplink(), fallback)
        machine.fail("grep '^VELSTRA_IFACE=' /run/sentinel/velstra.env")
        assert not json.loads(machine.succeed("ip -j link show lab-uplink"))[0].get("xdp")
        machine.succeed(query + " | grep '^Ready$'")
        healthy_pid = pid()
        env_identity = machine.succeed("stat -c '%i:%y' /run/sentinel/velstra.env")
        apply()
        assert pid() == healthy_pid
        assert machine.succeed("stat -c '%i:%y' /run/sentinel/velstra.env") == env_identity

        apply("delete interface lab-uplink")
        assert uplink() == fallback
        machine.succeed("ip link show lab-uplink")
  '';
}
