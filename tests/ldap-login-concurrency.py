#!/usr/bin/env python3
"""Real LDAP login isolation regression. Run only in a disposable VM/namespace.

Usage: python3 ldap-login-concurrency.py --isolated-runtime SENTINEL OPENLDAP
The flag acknowledges that the appliance runtime directory is disposable.
"""

import concurrent.futures
import contextlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


def port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_for(predicate, description):
    until = time.monotonic() + 20
    while time.monotonic() < until:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("timed out: " + description)


def stop(process):
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def main():
    assert len(sys.argv) == 4 and sys.argv[1] == "--isolated-runtime", __doc__
    binary, ldap = Path(sys.argv[2]).resolve(), Path(sys.argv[3]).resolve()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with tempfile.TemporaryDirectory(prefix="sentinel-ldap-") as temporary, contextlib.ExitStack() as cleanup:
        root = Path(temporary)
        database = root / "database"
        database.mkdir()
        ldap_port, api_port = port(), port()
        while api_port == ldap_port:
            api_port = port()
        uri = f"ldap://127.0.0.1:{ldap_port}"
        slapd_config = root / "slapd.conf"
        slapd_config.write_text(
            f"include {ldap}/etc/schema/core.schema\n"
            f"pidfile {root}/slapd.pid\nargsfile {root}/slapd.args\n"
            f"database mdb\nmaxsize 10485760\ndirectory {database}\n"
            'suffix "dc=example,dc=test"\nrootdn "cn=ldapuser,dc=example,dc=test"\n'
            'rootpw "correct-fixture-password"\n'
        )
        slapd_log = cleanup.enter_context((root / "slapd.log").open("w"))
        slapd = subprocess.Popen([str(ldap / "libexec/slapd"), "-d", "256", "-f", str(slapd_config),
                                  "-h", uri], stdout=slapd_log, stderr=subprocess.STDOUT)
        cleanup.callback(stop, slapd)

        def listening():
            try:
                with socket.create_connection(("127.0.0.1", ldap_port), timeout=0.2):
                    return True
            except OSError:
                assert slapd.poll() is None, (root / "slapd.log").read_text()
                return False

        wait_for(listening, "real LDAP server")
        # Establish independent controls against the actual directory first.
        for password, expected in [("correct-fixture-password", 0), ("wrong-fixture-password", 49)]:
            secret = root / "control-password"
            secret.touch(mode=0o600)
            secret.write_text(password)
            answer = subprocess.run([str(ldap / "bin/ldapwhoami"), "-x", "-H", uri,
                                     "-D", "cn=ldapuser,dc=example,dc=test", "-y", str(secret)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            assert answer.returncode == expected, "LDAP control did not give the expected verdict"
        secret.unlink()

        # A transparent launcher freezes both requests at the credential-file
        # boundary. Each copies the bytes the real LDAP client would read, then
        # invokes that actual client. No authentication response is simulated.
        launcher = root / "ldapwhoami-probe"
        launcher.write_text(f"#!{sys.executable}\n" + '''
import os, pathlib, subprocess, sys, time
root = pathlib.Path(os.environ["LDAP_TEST_ROOT"])
args = sys.argv[1:]
at = args.index("-y") + 1
secret = pathlib.Path(args[at])
kind = "good" if secret.read_text() == "correct-fixture-password" else "bad"
assert secret.stat().st_mode & 0o777 == 0o600
(root / ("ready." + kind)).touch()
deadline = time.monotonic() + 15
while not (root / "release").exists():
    assert time.monotonic() < deadline, "credential staging barrier timed out"
    time.sleep(0.01)
copy = root / ("client-secret." + kind)
copy.touch(mode=0o600)
copy.write_bytes(secret.read_bytes())
(root / ("copied." + kind)).touch()
while len(list(root.glob("copied.*"))) != 2:
    assert time.monotonic() < deadline, "credential read barrier timed out"
    time.sleep(0.01)
args[at] = str(copy)
try:
    sys.exit(subprocess.run([os.environ["LDAP_TEST_CLIENT"], *args], check=False).returncode)
finally:
    copy.unlink(missing_ok=True)
''')
        launcher.chmod(0o700)
        config = root / "appliance.toml"
        config.write_text(
            '[system]\nhostname = "ldap-test"\n'
            '[[system.group]]\nname = "viewers"\npermission = "read-only"\n'
            '[system.aaa]\ndefault-group = "viewers"\n'
            '[[system.aaa.ldap]]\nserver = "127.0.0.1"\n'
            f'port = {ldap_port}\ntls = "none"\nbase-dn = "dc=example,dc=test"\nuser-attribute = "cn"\n'
            '[services.web]\nenable = true\ntls = false\n'
        )
        token = root / "token"
        token.write_text("ldap-fixture-machine-token")
        token.chmod(0o600)
        api_log = cleanup.enter_context((root / "api.log").open("w"))
        environment = dict(os.environ, SENTINEL_LDAPWHOAMI_BIN=str(launcher), LDAP_TEST_ROOT=str(root),
                           LDAP_TEST_CLIENT=str(ldap / "bin/ldapwhoami"))
        environment.pop("SENTINEL_API_TOKEN", None)
        api = subprocess.Popen([str(binary), "api", "--listen", f"127.0.0.1:{api_port}",
                                "--config", str(config), "--token-file", str(token), "--no-apply"],
                               env=environment, stdout=api_log, stderr=subprocess.STDOUT)
        cleanup.callback(stop, api)
        base = f"http://127.0.0.1:{api_port}/api/v1/"

        def healthy():
            try:
                with opener.open(base + "health", timeout=1) as response:
                    return response.status == 200
            except OSError:
                assert api.poll() is None, (root / "api.log").read_text()
                return False

        wait_for(healthy, "actual management API")

        authenticated = {}

        def login(password):
            request = urllib.request.Request(base + "login", method="POST",
                                             data=json.dumps({"username": "ldapuser", "password": password}).encode(),
                                             headers={"Content-Type": "application/json"})
            try:
                with opener.open(request, timeout=25) as response:
                    authenticated["token"] = json.load(response)["token"]
                    return response.status
            except urllib.error.HTTPError as error:
                with error:
                    return error.code

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            bad = pool.submit(login, "wrong-fixture-password")
            wait_for(lambda: (root / "ready.bad").exists(), "invalid request staged")
            good = pool.submit(login, "correct-fixture-password")
            wait_for(lambda: (root / "ready.good").exists(), "valid request staged")
            (root / "release").touch()
            result = {"valid": good.result(timeout=25), "invalid": bad.result(timeout=25)}
        print(json.dumps(result), flush=True)
        assert result == {"valid": 200, "invalid": 401}, "concurrent LDAP requests shared credentials"
        assert not list(Path("/run/sentinel").glob(f"ldap-bind.{api.pid}*")), "bind secrets were left behind"

        def api_request(method, resource, credential, document=None):
            headers = {"Authorization": "Bearer " + credential}
            data = None
            if document is not None:
                data = json.dumps(document).encode()
                headers["Content-Type"] = "application/json"
            request = urllib.request.Request(base + resource, method=method, data=data, headers=headers)
            try:
                with opener.open(request, timeout=10) as response:
                    return response.status, json.load(response)
            except urllib.error.HTTPError as error:
                with error:
                    return error.code, json.load(error)

        credential = authenticated["token"]
        assert api_request("GET", "config", credential)[0] == 200, "directory login returned an unusable token"
        assert api_request("PUT", "config", credential, {"system": {"hostname": "forbidden"}})[0] == 403
        status, document = api_request("GET", "config", "ldap-fixture-machine-token")
        assert status == 200
        document["system"]["hostname"] = "directory-session-retained"
        update = api_request("PUT", "config", "ldap-fixture-machine-token", document)
        assert update[0] == 200, update
        assert api_request("GET", "config", credential)[0] == 200, "unrelated commit revoked a directory session"
        del document["system"]["aaa"]["default-group"]
        update = api_request("PUT", "config", "ldap-fixture-machine-token", document)
        assert update[0] == 200, update
        assert api_request("GET", "config", credential)[0] == 401, "withdrawn directory access still authenticated"


if __name__ == "__main__":
    main()
