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
    def start(cls, name, tls=False, peer=None, fingerprint=None, environment=None, config_mode=0o600):
        root = cls.root / name
        root.mkdir(mode=0o700)
        config = (
            '[system]\nhostname = "' + name + '"\n'
            '[[system.group]]\nname = "viewers"\npermission = "read-only"\n'
            '[[system.login]]\nusername = "viewer"\ngroup = "viewers"\n'
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
            [BINARY, "config", "check", str(path)],
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
            [BINARY, "api", "--listen", f"127.0.0.1:{port}",
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


if __name__ == "__main__":
    unittest.main()
