#!/usr/bin/env python3
"""Exercise read permissions against two real, isolated management processes.

Usage: python3 tests/api-read-permissions.py /path/to/sentinel
No live apply, root privileges, network namespaces or external services required.
"""

import base64
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import unittest
import urllib.error
import urllib.request


BINARY = str(Path(sys.argv.pop(1)).resolve())
SECRET = "integration-machine-secret"
WIREGUARD_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
SECRETS = [SECRET, WIREGUARD_KEY, "112233445566778899aabbccddeeff00",
           "ospf-test-key", "bfd-test-secret", "snmp-test-secret"]
OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=ssl._create_unverified_context()),
)


def request(base, path, token=None):
    headers = {"Authorization": "Bearer " + token} if token else {}
    req = urllib.request.Request(base + "/api/v1/" + path, headers=headers)
    try:
        with OPENER.open(req, timeout=10) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        with error:
            return error.code, error.read().decode()


class ReadPermissions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="sentinel-read-permissions-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.processes = []
        cls.addClassCleanup(cls.stop)
        cls.peer, peer_root = cls.start("peer", tls=True)
        openssl = os.environ.get("SENTINEL_OPENSSL_BIN", "openssl")
        public = subprocess.check_output(
            [openssl, "x509", "-in", str(peer_root / "web-tls/cert.pem"),
             "-pubkey", "-noout"]
        )
        der = subprocess.run(
            [openssl, "pkey", "-pubin", "-outform", "DER"],
            input=public, stdout=subprocess.PIPE, check=True,
        ).stdout
        pin = base64.b64encode(hashlib.sha256(der).digest()).decode()
        authority = cls.peer.removeprefix("https://")
        cls.base, root = cls.start("primary", peer=authority, fingerprint=pin)
        cls.viewer = (root / "api-tokens/viewer").read_text().strip()
        cls.authority = authority
        cls.config = root / "appliance.toml"

    @classmethod
    def start(cls, name, tls=False, peer=None, fingerprint=None, environment=None, config_mode=0o600,
              password_hash=None, binary=None):
        binary = binary or BINARY
        root = cls.root / name
        root.mkdir(mode=0o700)
        config = (
            '[system]\nhostname = "' + name + '"\n'
            '[[system.group]]\nname = "viewers"\npermission = "read-only"\n'
            '[[system.login]]\nusername = "viewer"\ngroup = "viewers"\n'
            + ('hashed-password = ' + json.dumps(password_hash) + '\n' if password_hash else '') +
            '[system.config-sync]\nsecret = "' + SECRET + '"\n'
        )
        if peer:
            config += 'peer = [' + json.dumps(peer) + ']\n'
            config += 'peer-fingerprint = ' + json.dumps(fingerprint) + '\n'
        config += '[services.web]\nenable = true\ntls = ' + str(tls).lower() + '\n'
        config += '''
[services.snmp]
community = "snmp-test-secret"
[[interface]]
name = "eth0"
mac = "02:00:00:00:00:01"
[[interface]]
name = "sec0"
type = "macsec"
parent = "eth0"
macsec-key = "112233445566778899aabbccddeeff00"
macsec-peer = "02:00:00:00:00:02"
[[interface]]
name = "wg0"
type = "wireguard"
[[vpn.wireguard]]
name = "wg0"
private-key = "''' + WIREGUARD_KEY + '''"
[protocols.ospf]
auth-type = "md5"
auth-key = "ospf-test-key"
auth-key-id = 7
[protocols.bgp]
local-as = 65001
[[protocols.bgp.neighbor]]
address = "192.0.2.2"
remote-as = 65002
bfd = true
bfd-auth-type = "meticulous-sha1"
bfd-auth-key = "bfd-test-secret"
bfd-auth-key-id = 9
'''
        path = root / "appliance.toml"
        path.write_text(config)
        path.chmod(config_mode)
        valid = subprocess.run(
            [binary, "config", "check", str(path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        if valid.returncode:
            raise RuntimeError("test configuration was refused: " + valid.stderr)
        archive = root / "archive"
        archive.mkdir(mode=0o700)
        revision = archive / "config-00000000000000000001.toml"
        revision.write_text(config)
        revision.chmod(0o600)
        token = root / "api-token"
        token.write_text(SECRET)
        token.chmod(0o600)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        log = (root / "api.log").open("w+")
        cls.addClassCleanup(log.close)
        env = dict(os.environ)
        env.pop("SENTINEL_API_TOKEN", None)
        env.update(environment or {})
        proc = subprocess.Popen(
            [binary, "api", "--listen", f"127.0.0.1:{port}",
             "--config", str(path), "--token-file", str(token), "--no-apply"],
            stdout=log, stderr=subprocess.STDOUT, env=env,
        )
        cls.processes.append(proc)
        base = f"{'https' if tls else 'http'}://127.0.0.1:{port}"
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                if request(base, "health")[0] == 200:
                    return base, root
            except (OSError, urllib.error.URLError):
                pass
            if proc.poll() is not None:
                break
            time.sleep(0.05)
        log.seek(0)
        raise RuntimeError("management API did not start: " + log.read())

    @classmethod
    def stop(cls):
        for proc in reversed(cls.processes):
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    def test_readonly_configuration_paths_and_archive_hide_credentials(self):
        before = self.config.read_bytes()
        for path in ["config", "show/configuration", "show/configuration/commands",
                     "show/configuration/extra", "show/system/commit/0",
                     "config/revisions/0"]:
            with self.subTest(path=path):
                status, body = request(self.base, path, self.viewer)
                self.assertEqual(status, 200, body)
                self.assertIn("primary", body)
                for secret in SECRETS:
                    self.assertNotIn(secret, body)
        self.assertEqual(before, self.config.read_bytes())

    def test_invalid_revisions_are_refused_without_disclosing_configuration(self):
        for path in ["config/revisions/-1", "config/revisions/not-a-number",
                     "config/revisions/9999", "show/system/commit/not-a-number",
                     "stack/" + self.authority + "/show/system/commit/not-a-number"]:
            with self.subTest(path=path):
                status, body = request(self.base, path, self.viewer)
                self.assertEqual(status, 400, body)
                for secret in SECRETS:
                    self.assertNotIn(secret, body)

    def test_peer_proxy_does_not_elevate_the_viewer(self):
        for path in ["configuration", "configuration/commands", "system/commit/0"]:
            with self.subTest(path=path):
                status, body = request(
                    self.base, "stack/" + self.authority + "/show/" + path, self.viewer
                )
                self.assertEqual(status, 200, body)
                self.assertIn("peer", body)
                for secret in SECRETS:
                    self.assertNotIn(secret, body)

    def test_administrator_can_still_export_replayable_configuration(self):
        for prefix in ["show/", "stack/" + self.authority + "/show/"]:
            status, body = request(self.base, prefix + "configuration/commands", SECRET)
            self.assertEqual(status, 200, body)
            for secret in SECRETS:
                self.assertIn(secret, body)

    def test_concurrent_configuration_writes_publish_complete_documents(self):
        base, root = self.start("concurrent")
        barrier = threading.Barrier(12, timeout=15)

        def write(index):
            document = {
                "system": {"hostname": f"writer-{index}"},
                "interface": [
                    {"name": f"dummy{n}", "description": str(index % 10) * 240}
                    for n in range(1000)
                ],
            }
            req = urllib.request.Request(
                base + "/api/v1/config", method="PUT",
                data=json.dumps(document).encode(),
                headers={"Authorization": "Bearer " + SECRET,
                         "Content-Type": "application/json"},
            )
            barrier.wait()
            try:
                with OPENER.open(req, timeout=30) as response:
                    return response.status, response.read().decode()
            except urllib.error.HTTPError as error:
                with error:
                    return error.code, error.read().decode()

        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            responses = list(pool.map(write, range(12)))
        self.assertEqual([status for status, _ in responses], [200] * 12, responses)
        saved = root / "appliance.toml"
        result = tomllib.loads(saved.read_text())
        index = int(result["system"]["hostname"].removeprefix("writer-"))
        self.assertEqual(len(result["interface"]), 1000)
        self.assertTrue(all(row["description"] == str(index % 10) * 240
                            for row in result["interface"]))
        self.assertEqual(saved.stat().st_mode & 0o777, 0o640)
        self.assertFalse(list(root.glob("*.tmp")), "a writer left configuration staging files")

    def test_anonymous_requests_are_refused(self):
        status, body = request(self.base, "show/configuration")
        self.assertEqual(status, 401)
        self.assertNotIn(SECRET, body)

    def test_saved_revisions_are_not_world_readable(self):
        base, root = self.start("private-archive")
        document = {"system": {"hostname": "private-archive",
                               "config-sync": {"secret": SECRET}}}
        req = urllib.request.Request(
            base + "/api/v1/config", method="PUT", data=json.dumps(document).encode(),
            headers={"Authorization": "Bearer " + SECRET,
                     "Content-Type": "application/json"},
        )
        with OPENER.open(req, timeout=10) as response:
            self.assertEqual(response.status, 200)
        revisions = list((root / "archive").glob("config-*.toml"))
        self.assertGreaterEqual(len(revisions), 2)
        for revision in revisions:
            self.assertEqual(revision.stat().st_mode & 0o007, 0,
                             f"credentials are readable by everyone: {revision.name}")
        self.assertTrue(any(SECRET in revision.read_text() for revision in revisions))

    def test_ipv6_egress_rule_upload_and_preview_preserve_scope(self):
        base, root = self.start("ipv6-egress-validation")
        before = (root / "appliance.toml").read_bytes()
        source = ("set interface eth0 zone wan\n"
                  "set firewall rule outbound from wan\n"
                  "set firewall rule outbound proto tcp\n"
                  "set firewall rule outbound port 18090\n"
                  "set firewall rule outbound action drop\n"
                  "set firewall rule outbound family ipv6\n"
                  "set firewall rule outbound direction out\n")
        req = urllib.request.Request(base + "/api/v1/configure/validate", method="POST",
                                     data=source.encode(), headers={
                                         "Authorization": "Bearer " + SECRET,
                                         "Content-Type": "text/plain",
                                     })
        with OPENER.open(req, timeout=10) as response:
            self.assertEqual(response.status, 200)
            self.assertTrue(json.load(response)["ok"])
        self.assertEqual(before, (root / "appliance.toml").read_bytes())
        document = {"system": {"hostname": "ipv6-egress-validation", "config-sync": {"secret": SECRET}},
                    "interface": [{"name": "eth0", "zone": "wan"}],
                    "rule": [{"name": "outbound", "from": "wan", "proto": "tcp", "port": 18090,
                              "action": "drop", "family": "ipv6", "direction": "out"}]}
        req = urllib.request.Request(base + "/api/v1/config", method="PUT",
                                     data=json.dumps(document).encode(), headers={
                                         "Authorization": "Bearer " + SECRET,
                                         "Content-Type": "application/json",
                                     })
        with OPENER.open(req, timeout=10) as response:
            self.assertEqual(response.status, 200)
        rule = tomllib.loads((root / "appliance.toml").read_text())["rule"][0]
        self.assertEqual(rule["family"], "ipv6")
        self.assertEqual(rule["direction"], "out")

    def test_invalid_clone_macs_are_refused_without_publishing_or_archiving(self):
        base, root = self.start("clone-validation")
        path = root / "appliance.toml"
        before = path.read_bytes()
        archive = sorted((root / "archive").glob("config-*.toml"))
        for mac in ["00:00:00:00:00:00", "01:66:77:88:99:aa", "FF:FF:FF:FF:FF:FF"]:
            document = {"system": {"hostname": "clone-validation"},
                        "interface": [{"name": "eth0", "mac": mac}]}
            cases = [
                ("config", "PUT", json.dumps(document).encode(), "application/json", 400),
                ("configure/validate", "POST", f"set interface eth0 mac {mac}\n".encode(), "text/plain", 400),
                ("configure", "POST", f"set interface eth0 mac {mac}\ncommit\nsave\nexit\n".encode(), "text/plain", 200),
            ]
            for endpoint, method, data, content_type, expected in cases:
                with self.subTest(mac=mac, endpoint=endpoint):
                    req = urllib.request.Request(base + "/api/v1/" + endpoint,
                                                 method=method, data=data, headers={
                                                     "Authorization": "Bearer " + SECRET,
                                                     "Content-Type": content_type,
                                                 })
                    try:
                        with OPENER.open(req, timeout=10) as response:
                            status, result = response.status, json.load(response)
                    except urllib.error.HTTPError as error:
                        with error:
                            status, result = error.code, json.load(error)
                    self.assertEqual(status, expected, result)
                    message = result.get("error", result.get("output", ""))
                    self.assertIn("non-zero unicast", message, result)
                    if endpoint == "configure":
                        self.assertFalse(result["ok"], result)
                        self.assertNotIn("commit ok", message)
                    self.assertEqual(before, path.read_bytes())
                    self.assertEqual(archive, sorted((root / "archive").glob("config-*.toml")))
                    self.assertNotIn(SECRET, json.dumps(result))

    def test_large_configuration_scripts_do_not_deadlock_the_child_pipes(self):
        before = self.config.read_bytes()
        req = urllib.request.Request(
            self.base + "/api/v1/configure", method="POST",
            data=b"unknown-configuration-verb\n" * 7000,
            headers={"Authorization": "Bearer " + SECRET, "Content-Type": "text/plain"},
        )
        with OPENER.open(req, timeout=10) as response:
            result = json.load(response)
            self.assertEqual(response.status, 200)
        self.assertFalse(result["ok"], "invalid commands were reported as successful")
        self.assertIn("unknown-configuration-verb", result["output"])
        self.assertEqual(before, self.config.read_bytes())

    def test_large_script_exit_does_not_run_later_mutations(self):
        before = self.config.read_bytes()
        script = b"exit\n" + b"set system hostname must-not-save\n" * 5000 + b"commit\nsave\n"
        req = urllib.request.Request(
            self.base + "/api/v1/configure", method="POST", data=script,
            headers={"Authorization": "Bearer " + SECRET, "Content-Type": "text/plain"},
        )
        with OPENER.open(req, timeout=10) as response:
            result = json.load(response)
            self.assertEqual(response.status, 200)
        self.assertTrue(result["ok"], result)
        self.assertEqual(before, self.config.read_bytes())

    def test_peer_adjustment_is_validated_before_persistence(self):
        base, root = self.start("peer-validation")
        before = (root / "appliance.toml").read_bytes()
        document = {
            "system": {"hostname": "source"},
            "interface": [{"name": "source0", "address": "192.0.2.1/24"}],
            "services": {"dns": {"serve-on": ["source0"]}},
        }
        req = urllib.request.Request(
            base + "/api/v1/config-sync", method="PUT", data=json.dumps(document).encode(),
            headers={"Authorization": "Bearer " + SECRET,
                     "Content-Type": "application/json"},
        )
        try:
            with OPENER.open(req, timeout=10) as response:
                status, body = response.status, response.read().decode()
        except urllib.error.HTTPError as error:
            with error:
                status, body = error.code, error.read().decode()
        self.assertEqual(status, 400, body)
        self.assertIn("source0", body)
        self.assertEqual(before, (root / "appliance.toml").read_bytes())

    def test_operational_vpn_queries_never_prompt_for_privilege(self):
        tools = self.root / "noninteractive-tools"
        tools.mkdir(mode=0o700)
        arguments = tools / "arguments"
        swanctl = tools / "swanctl"
        swanctl.write_text("#!/bin/sh\nexit 1\n")
        swanctl.chmod(0o700)
        sudo = tools / "sudo"
        sudo.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$PROBE_ARGUMENTS"\nexit 1\n')
        sudo.chmod(0o700)
        base, _ = self.start("noninteractive-vpn", environment={
            "PATH": str(tools) + os.pathsep + os.environ.get("PATH", ""),
            "SENTINEL_SWANCTL_BIN": str(swanctl),
            "PROBE_ARGUMENTS": str(arguments),
        })
        status, body = request(base, "show/vpn", SECRET)
        self.assertEqual(status, 200, body)
        # The native-root VM run needs no sudo. Workstation diagnostics must
        # refuse an unavailable escalation immediately rather than prompt.
        if os.geteuid() != 0:
            self.assertEqual(arguments.read_text().splitlines()[0], "-n")
        else:
            self.assertFalse(arguments.exists(), "root diagnostics unexpectedly escalated")

    def test_legacy_active_configuration_is_protected_at_startup(self):
        _, root = self.start("legacy-config", config_mode=0o644)
        path = root / "appliance.toml"
        self.assertEqual(path.stat().st_mode & 0o777, 0o640)
        self.assertIn(SECRET, path.read_text())

    def test_environment_machine_token_never_escalates_account_permissions(self):
        machine = "isolated-environment-machine-token"
        openssl = os.environ.get("SENTINEL_OPENSSL_BIN", "openssl")
        password_hash = subprocess.run(
            [openssl, "passwd", "-6", "-stdin"], input="fixture-login-password",
            text=True, stdout=subprocess.PIPE, check=True,
        ).stdout.strip()
        base, root = self.start("environment-account", password_hash=password_hash,
                                environment={"SENTINEL_API_TOKEN": machine})
        account_token = root / "api-tokens/viewer"
        startup_token = account_token.read_text().strip()
        self.assertNotEqual(startup_token, machine)
        login = urllib.request.Request(
            base + "/api/v1/login", method="POST",
            data=json.dumps({"username": "viewer", "password": "fixture-login-password"}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with OPENER.open(login, timeout=10) as response:
            session = json.load(response)
        self.assertEqual(session["permission"], "read-only")
        self.assertEqual(session["token"], startup_token)
        before = (root / "appliance.toml").read_bytes()
        mutation = urllib.request.Request(
            base + "/api/v1/config", method="PUT",
            data=b'{"system":{"hostname":"unauthorized-write"}}',
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + session["token"]},
        )
        try:
            with OPENER.open(mutation, timeout=10) as response:
                status = response.status
        except urllib.error.HTTPError as error:
            with error:
                status = error.code
        self.assertEqual(status, 403, "a read-only sign-in returned a globally privileged credential")
        self.assertNotEqual(session["token"], machine)
        self.assertEqual((root / "appliance.toml").read_bytes(), before)
        self.assertEqual(account_token.read_text().strip(), session["token"])
        self.assertEqual(request(base, "config", machine)[0], 200)

        # Directory-authenticated accounts are minted on first login. Exercise
        # that same boundary with real concurrent HTTP handlers, not only the
        # in-process file helper, after withdrawing the pre-minted fixture token.
        account_token.unlink()
        barrier = threading.Barrier(8)

        def first_login(_):
            barrier.wait(timeout=10)
            with OPENER.open(login, timeout=20) as response:
                return json.load(response)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            sessions = list(pool.map(first_login, range(8)))
        persisted = account_token.read_text().strip()
        self.assertEqual(len(persisted), 43)
        self.assertEqual({s["token"] for s in sessions}, {persisted})
        self.assertTrue(all(s["permission"] == "read-only" for s in sessions))
        self.assertEqual(account_token.stat().st_mode & 0o777, 0o600)
        self.assertEqual(request(base, "config", persisted)[0], 200)
        self.assertEqual(sorted(p.name for p in account_token.parent.iterdir()), ["viewer"])

    def test_unauthenticated_login_never_exposes_invalid_configuration(self):
        base, root = self.start("invalid-login-config")
        path = root / "appliance.toml"
        damaged = path.read_text().replace('secret = "' + SECRET + '"', 'secret = ["' + SECRET + '"]')
        path.write_text(damaged)
        login = urllib.request.Request(
            base + "/api/v1/login", method="POST",
            data=b'{"username":"unknown","password":"fixture-password"}',
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as raised:
            OPENER.open(login, timeout=10)
        with raised.exception as error:
            status, body = error.code, error.read().decode()
        self.assertNotIn(SECRET, body, "public login leaked a configured secret through a parse error")
        self.assertEqual(status, 500)
        self.assertIn("configuration", json.loads(body)["error"])
        self.assertEqual(path.read_text(), damaged)

    def test_every_documented_route_enforces_its_authentication_boundary(self):
        status, body = request(self.base, "openapi.json")
        self.assertEqual(status, 200)
        schema = json.loads(body)
        before = self.config.read_bytes()
        public = {("GET", "/api/v1/health"), ("GET", "/api/v1/openapi.json"),
                  ("POST", "/api/v1/login")}
        substitutions = {"kind": "interfaces", "path": "flows", "revision": "0",
                         "member": "primary", "resolution": "hour", "series": "cpu",
                         "value": "192.0.2.1"}
        tested = set()
        for template, operations in schema["paths"].items():
            path = template
            for name, value in substitutions.items():
                path = path.replace("{" + name + "}", value)
            self.assertNotIn("{", path, "route needs a concrete test parameter")
            for method, operation in operations.items():
                method = method.upper()
                if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                    continue
                tested.add((method, template))
                is_public = (method, template) in public
                self.assertEqual(operation.get("security") == [], is_public,
                                 "documented authentication policy differs from the expected boundary")
                anonymous_status = (400 if method == "POST" else 200) if is_public else 401
                cases = [(None, anonymous_status), ("invalid-fixture-token", anonymous_status)]
                if not is_public and method != "GET":
                    cases.append((self.viewer, 403))
                for credential, expected in cases:
                    with self.subTest(method=method, route=template, expected=expected):
                        headers = {"Content-Type": "application/json"}
                        if credential:
                            headers["Authorization"] = "Bearer " + credential
                        req = urllib.request.Request(self.base + path, method=method,
                                                     data=None if method == "GET" else b"{}",
                                                     headers=headers)
                        try:
                            with OPENER.open(req, timeout=10) as response:
                                code, content = response.status, response.read().decode()
                        except urllib.error.HTTPError as error:
                            with error:
                                code, content = error.code, error.read().decode()
                        self.assertEqual(code, expected)
                        self.assertNotIn(SECRET, content)
        self.assertTrue(public.issubset(tested))
        self.assertGreaterEqual(len(tested), 22)
        self.assertEqual(self.config.read_bytes(), before)

    def test_candidate_validation_is_complete_authorized_and_side_effect_free(self):
        before = self.config.read_bytes()
        archive = sorted((self.config.parent / "archive").iterdir())
        cases = [
            ("set system hostname preview\n", SECRET, 200),
            ("set protocols static not-a-network via 192.0.2.1\n", SECRET, 400),
            ("set services dns serve-on missing0\n", SECRET, 400),
            ("set interface cyclea parent cyclea\nset interface cyclea vlan 42\n", SECRET, 400),
            ("set interface cyclea parent cycleb\nset interface cyclea vlan 42\n"
             "set interface cycleb parent cyclea\nset interface cycleb vlan 43\n", SECRET, 400),
            ("set interface carrier description Carrier\nset interface taga parent carrier\n"
             "set interface taga vlan 42\nset interface tagb parent carrier\n"
             "set interface tagb vlan 42\n", SECRET, 400),
            ("set interface carrier description Carrier\nset interface taga parent carrier\n"
             "set interface taga vlan 42\nset interface tagb parent carrier\n"
             "set interface tagb vlan 42\nset interface tagb vlan-protocol 802.1ad\n", SECRET, 200),
            ("set system hostname preview\nsave\n", SECRET, 400),
            ("commit\n", SECRET, 400),
            ("run clear ids blocks\n", SECRET, 400),
            ("rollback 0\n", SECRET, 400),
            ("set system hostname preview\n", self.viewer, 403),
            ("set system hostname preview\n", None, 401),
        ]
        for source, token, expected in cases:
            with self.subTest(source=source, role="viewer" if token == self.viewer else "other"):
                headers = {"Content-Type": "text/plain"}
                if token:
                    headers["Authorization"] = "Bearer " + token
                req = urllib.request.Request(self.base + "/api/v1/configure/validate",
                                             data=source.encode(), method="POST", headers=headers)
                try:
                    with OPENER.open(req, timeout=10) as response:
                        status, result = response.status, json.load(response)
                except urllib.error.HTTPError as error:
                    with error:
                        status, result = error.code, json.load(error)
                self.assertEqual(status, expected, result)
                if expected == 200:
                    self.assertTrue(result["ok"])
                else:
                    self.assertTrue(result["error"])
                self.assertEqual(before, self.config.read_bytes())
                self.assertEqual(archive, sorted((self.config.parent / "archive").iterdir()))

    def test_validation_attributes_only_edit_refusals_without_saving(self):
        before = self.config.read_bytes()
        for script, line in [
            ("set system hostname preview\nset firewall nonsense true\n", 2),
            ("set protocols static not-a-network via 192.0.2.1\n", None),
        ]:
            with self.subTest(line=line):
                req = urllib.request.Request(self.base + "/api/v1/configure/validate",
                                             data=script.encode(), method="POST", headers={
                                                 "Authorization": "Bearer " + SECRET,
                                                 "Content-Type": "text/plain",
                                             })
                with self.assertRaises(urllib.error.HTTPError) as failure:
                    OPENER.open(req, timeout=10)
                with failure.exception as response:
                    self.assertEqual(response.code, 400)
                    result = json.load(response)
                self.assertEqual(result["edit_line"], line)
                self.assertEqual(before, self.config.read_bytes())

    def test_candidate_rejects_expanded_rate_limit_overflow_without_saving(self):
        before = self.config.read_bytes()
        source = "set interface capacity0 zone capacity\n"
        for index in range(64):
            prefix = f"set firewall rule capacity-{index} "
            source += "".join(prefix + setting + "\n" for setting in [
                "from capacity", "action accept", "proto tcp_udp",
                f"port {10000 + index}", "limit 100",
            ])
        req = urllib.request.Request(self.base + "/api/v1/configure/validate",
                                     data=source.encode(), method="POST", headers={
                                         "Authorization": "Bearer " + SECRET,
                                         "Content-Type": "text/plain",
                                     })
        with self.assertRaises(urllib.error.HTTPError) as failure:
            OPENER.open(req, timeout=10)
        with failure.exception as response:
            result = json.load(response)
            self.assertEqual(response.code, 400, result)
        self.assertIn("128 rate-limited rules", result["error"])
        self.assertEqual(before, self.config.read_bytes())

    def test_corrupt_revision_errors_do_not_disclose_credential_source_lines(self):
        revision = self.config.parent / "archive/config-00000000000000000001.toml"
        original = revision.read_bytes()
        try:
            revision.write_text('[system.config-sync]\nsecret = "' + SECRET)
            for path in ["config/revisions/0", "show/system/commit/0"]:
                with self.subTest(path=path):
                    status, body = request(self.base, path, self.viewer)
                    self.assertNotIn(SECRET, body)
                    self.assertEqual(status, 400, body)
        finally:
            revision.write_bytes(original)


    def test_refused_configuration_script_does_not_execute_later_commit_and_save(self):
        base, root = self.start("refused-script")
        config = root / "appliance.toml"
        before = config.read_bytes()
        script = "set system hostname must-not-save\nset nonsense value\ncommit\nsave\nexit\n"
        req = urllib.request.Request(
            base + "/api/v1/configure", data=script.encode(), method="POST",
            headers={"Authorization": "Bearer " + SECRET, "Content-Type": "text/plain"},
        )
        with OPENER.open(req, timeout=10) as response:
            result = json.load(response)
        self.assertFalse(result["ok"], result)
        self.assertIn("error:", result["output"].lower())
        self.assertEqual(config.read_bytes(), before,
                         "a refused script still executed its trailing commit/save")

    def capture_process_probe(self, name):
        """Observe the process boundary without capturing workstation traffic.

        The appliance VM test separately exercises tcpdump with real packets.
        These requests check what may reach that boundary, not packet capture.
        """
        tools = self.root / name
        tools.mkdir(mode=0o700)
        arguments = tools / "arguments.json"
        timeout = tools / "timeout"
        timeout.write_text(
            "#!" + sys.executable + "\n"
            "import json, os, pathlib, sys\n"
            "pathlib.Path(os.environ['CAPTURE_ARGUMENTS']).write_text(json.dumps(sys.argv[1:]))\n"
            "print('capture process boundary reached')\n"
        )
        timeout.chmod(0o700)
        # The packaged launcher deliberately pins tool paths. Only these
        # process-boundary probes invoke its underlying compiled binary, so
        # the fixture cannot accidentally run a real capture instead. Other
        # tests, including real VM traffic, retain the normal launcher.
        binary = Path(BINARY)
        with binary.open("rb") as program:
            is_elf = program.read(4) == b"\x7fELF"
        if not is_elf:
            binary = binary.with_name("." + binary.name + "-wrapped")
            with binary.open("rb") as program:
                if program.read(4) != b"\x7fELF":
                    raise RuntimeError("capture process probe needs the compiled appliance binary")
        base, _ = self.start(name + "-api", environment={
            "SENTINEL_TIMEOUT_BIN": str(timeout),
            "CAPTURE_ARGUMENTS": str(arguments),
        }, binary=str(binary))
        return base, arguments

    def test_capture_rejects_wrong_field_types_before_starting_a_process(self):
        base, arguments = self.capture_process_probe("capture-types")
        for field, value in [
            ("interface", 1), ("interface", None),
            ("filter", False), ("filter", []), ("filter", {}), ("filter", None),
            ("packets", "3"), ("packets", -1), ("packets", 1.5),
            ("packets", True), ("packets", None),
            ("seconds", "2"), ("seconds", -1), ("seconds", 1.5),
            ("seconds", False), ("seconds", None),
        ]:
            with self.subTest(field=field, value=value):
                arguments.unlink(missing_ok=True)
                body = {"interface": "lo", "packets": 3, "seconds": 2, field: value}
                req = urllib.request.Request(
                    base + "/api/v1/capture", data=json.dumps(body).encode(), method="POST",
                    headers={"Authorization": "Bearer " + SECRET,
                             "Content-Type": "application/json"},
                )
                with self.assertRaises(urllib.error.HTTPError) as failure:
                    OPENER.open(req, timeout=10)
                with failure.exception as response:
                    self.assertEqual(response.code, 400)
                    error = json.load(response)["error"]
                    self.assertIn(field, error)
                self.assertFalse(arguments.exists(), "invalid capture input reached a process")

    def test_capture_limits_do_not_wrap_large_unsigned_integers(self):
        base, arguments = self.capture_process_probe("capture-limits")
        for packets, seconds, expected_packets, expected_seconds in [
            (None, None, 50, 10), (0, 0, 1, 1), (3, 2, 3, 2),
            (501, 61, 500, 60), (2**32 + 1, 2**32 + 1, 500, 60),
            (2**64 - 1, 2**64 - 1, 500, 60),
        ]:
            with self.subTest(packets=packets, seconds=seconds):
                body = {"interface": "lo"}
                if packets is not None:
                    body["packets"] = packets
                if seconds is not None:
                    body["seconds"] = seconds
                req = urllib.request.Request(
                    base + "/api/v1/capture", data=json.dumps(body).encode(), method="POST",
                    headers={"Authorization": "Bearer " + SECRET,
                             "Content-Type": "application/json"},
                )
                with OPENER.open(req, timeout=10) as response:
                    self.assertEqual(response.status, 200)
                    response.read()
                actual = json.loads(arguments.read_text())
                self.assertEqual(actual[0], str(expected_seconds), actual)
                self.assertEqual(actual[actual.index("-c") + 1], str(expected_packets), actual)


if __name__ == "__main__":
    unittest.main()
