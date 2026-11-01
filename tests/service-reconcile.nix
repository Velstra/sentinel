# Real service lifecycle and transaction failures, without substituting systemctl.
{ pkgs, sentinelModule, sentinel }:
pkgs.testers.runNixOSTest {
  name = "sentinel-service-reconcile";
  nodes.machine = {
    imports = [ sentinelModule ];
    virtualisation.memorySize = 2048;
    environment.systemPackages = [ pkgs.curl ];
  };
  testScript = ''
    import json
    import shlex
    import tomllib

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("sentinel-boot.service")
    conf = "/run/sentinel/lldpd.d/sentinel.conf"
    dropin = "/run/systemd/system/lldpd.service.d/reconcile-fault.conf"

    def command(enabled):
        script = "\n".join([
            "set services lldp enable " + str(enabled).lower(),
            "commit", "save", "exit", "",
        ])
        body = "printf %s " + shlex.quote(script) + " | ${sentinel}/bin/sentinel configure 2>&1"
        return "su admin -c " + shlex.quote(body)

    def apply(enabled):
        machine.succeed(command(enabled))

    def persisted_enabled():
        document = tomllib.loads(machine.succeed("cat /var/lib/sentinel/appliance.toml"))
        return document.get("services", {}).get("lldp", {}).get("enable", False)

    def pid():
        return machine.succeed("systemctl show -p MainPID --value lldpd.service").strip()

    def fault(setting):
        machine.succeed("mkdir -p /run/systemd/system/lldpd.service.d")
        body = "[Unit]\n" + setting + "=yes\n"
        machine.succeed("printf %s " + shlex.quote(body) + " > " + dropin)
        machine.succeed("systemctl daemon-reload")

    def clear_fault():
        machine.succeed("rm -f " + dropin)
        machine.succeed("systemctl daemon-reload")

    with subtest("the internal private reader is root-only and distinguishes absence"):
        machine.succeed("install -d -m 0700 /run/private-reader-test")
        machine.succeed("printf protected-test-marker > /run/private-reader-test/secret; chmod 0600 /run/private-reader-test/secret")
        denied = "${sentinel}/bin/sentinel private-read /run/private-reader-test/secret > /tmp/private-reader-output 2> /tmp/private-reader-error"
        machine.fail("su admin -c " + shlex.quote(denied))
        machine.succeed("test ! -s /tmp/private-reader-output")
        machine.succeed("grep -q 'requires root' /tmp/private-reader-error")
        missing = machine.succeed("${sentinel}/bin/sentinel private-read /run/private-reader-test/missing | od -An -tu1").strip()
        assert missing == "0", missing

    with subtest("enable starts the actual service"):
        apply(True)
        machine.wait_for_unit("lldpd.service")
        machine.succeed("test -s " + conf)
        assert persisted_enabled()
        active_pid = pid()
        assert int(active_pid) > 0

    with subtest("an unchanged active service is not restarted"):
        apply(True)
        assert pid() == active_pid

    with subtest("private service configuration is compared without widening access"):
        script = "\n".join([
            "set services snmp community reconcile-test",
            "set services snmp allow 127.0.0.0/8",
            "commit", "save", "exit", "",
        ])
        private_command = "su admin -c " + shlex.quote(
            "printf %s " + shlex.quote(script) + " | ${sentinel}/bin/sentinel configure 2>&1"
        )
        machine.succeed(private_command)
        machine.wait_for_unit("sentinel-snmpd.service")
        private_pid = machine.succeed("systemctl show -p MainPID --value sentinel-snmpd.service").strip()
        machine.fail("su admin -c 'cat /run/sentinel/snmpd.conf'")
        machine.succeed(private_command)
        assert machine.succeed("systemctl show -p MainPID --value sentinel-snmpd.service").strip() == private_pid
        machine.fail("su admin -c 'cat /run/sentinel/snmpd.conf'")
        assert machine.succeed("stat -c '%U:%a' /run/sentinel/snmpd.conf").strip() == "root:640"

    with subtest("an unchanged enabled service recovers without a manual restart"):
        machine.succeed("systemctl stop lldpd.service")
        machine.fail("systemctl is-active --quiet lldpd.service")
        apply(True)
        machine.wait_for_unit("lldpd.service")
        assert int(pid()) > 0 and pid() != active_pid

    with subtest("disabled state stops a live daemon even when its file is missing"):
        machine.succeed("rm " + conf)
        apply(False)
        machine.fail("systemctl is-active --quiet lldpd.service")
        machine.succeed("test ! -e " + conf)
        assert not persisted_enabled()

    with subtest("a refused initial start cannot be saved as success"):
        fault("RefuseManualStart")
        try:
            output = machine.fail(command(True))
            assert "restarting configured service lldpd.service" in output, output
            assert not persisted_enabled()
            machine.fail("systemctl is-active --quiet lldpd.service")
            machine.succeed("test ! -e " + conf)
        finally:
            clear_fault()

    with subtest("retry after a start failure converges"):
        apply(True)
        machine.wait_for_unit("lldpd.service")
        assert persisted_enabled()

    with subtest("a refused unchanged start remains an honest failure"):
        machine.succeed("systemctl stop lldpd.service")
        fault("RefuseManualStart")
        try:
            output = machine.fail(command(True))
            assert "starting configured service lldpd.service" in output, output
            machine.fail("systemctl is-active --quiet lldpd.service")
            assert persisted_enabled()
        finally:
            clear_fault()

    with subtest("the unchanged configuration recovers after the fault clears"):
        apply(True)
        machine.wait_for_unit("lldpd.service")
        active_pid = pid()

    with subtest("a refused stop retains the working configuration and daemon"):
        fault("RefuseManualStop")
        try:
            output = machine.fail(command(False))
            assert "stopping unconfigured service lldpd.service" in output, output
            assert persisted_enabled()
            assert pid() == active_pid
            machine.succeed("test -s " + conf)
            machine.succeed("systemctl is-active --quiet lldpd.service")
        finally:
            clear_fault()

    with subtest("disable succeeds after a stop failure"):
        apply(False)
        machine.fail("systemctl is-active --quiet lldpd.service")
        machine.succeed("test ! -e " + conf)
        assert not persisted_enabled()

    with subtest("an unchanged disabled service remains stopped"):
        apply(False)
        machine.fail("systemctl is-active --quiet lldpd.service")
        assert not persisted_enabled()

    with subtest("the authenticated API starts the real service"):
        machine.succeed("systemctl start sentinel-api.service")
        machine.wait_for_open_port(8080)
        # Keep the minted token out of the command line and test output.
        machine.succeed(
            "install -m 0600 /dev/null /run/service-auth.headers; "
            "sed 's/^/Authorization: Bearer /' /var/lib/sentinel/api-token > /run/service-auth.headers"
        )

        def api_apply():
            script = "set services lldp enable true\ncommit\nsave\n"
            machine.succeed("printf %s " + shlex.quote(script) + " > /run/service-script")
            code = machine.succeed(
                "curl -sS --cacert /var/lib/sentinel/web-tls/cert.pem "
                "-H @/run/service-auth.headers --data-binary @/run/service-script "
                "-o /run/service-response -w '%{http_code}' "
                "https://127.0.0.1:8080/api/v1/configure"
            ).strip()
            response = json.loads(machine.succeed("cat /run/service-response"))
            return code, response

        code, response = api_apply()
        assert code == "200" and response.get("ok") is True, response
        machine.wait_for_unit("lldpd.service")
        assert persisted_enabled()

    with subtest("the API reports a failed apply and preserves actual disabled state"):
        apply(False)
        fault("RefuseManualStart")
        try:
            code, response = api_apply()
            # Inspect the command result, not just the HTTP envelope.
            assert response.get("ok") is False, response
            assert "restarting configured service lldpd.service" in response.get("output", ""), response
            assert not persisted_enabled()
            machine.fail("systemctl is-active --quiet lldpd.service")
            machine.succeed("test ! -e " + conf)
        finally:
            clear_fault()

    with subtest("operational API paths cannot invoke the internal file reader"):
        code = machine.succeed(
            "curl -sS --cacert /var/lib/sentinel/web-tls/cert.pem "
            "-H @/run/service-auth.headers -o /run/private-reader-api-response "
            "-w '%{http_code}' "
            "https://127.0.0.1:8080/api/v1/show/private-read/run/private-reader-test/secret"
        ).strip()
        assert code == "400", code
        response = machine.succeed("cat /run/private-reader-api-response")
        assert "protected-test-marker" not in response, response
  '';
}
