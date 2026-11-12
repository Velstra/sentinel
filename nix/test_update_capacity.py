"""Offline reference/fixture boundaries, never a VM/default-capacity proof."""
import base64
from contextlib import contextmanager
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import ssl
import subprocess
import tempfile
import textwrap
import threading
import time
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("capacity_fixture", HERE / "update_capacity.py")
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


class SnapshotMountTests(unittest.TestCase):
    def test_esp_is_held_before_hashing_and_released_afterward(self):
        with patch.object(C.os, "open", return_value=19) as opened, \
                patch.object(C.os, "close") as closed:
            def inspect():
                opened.assert_called_once_with(
                    "/boot/EFI/Linux", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                closed.assert_not_called()
            with patch.object(C, "_snapshot_mounted", side_effect=inspect) as observed:
                C.snapshot()
            observed.assert_called_once_with()
            closed.assert_called_once_with(19)

    def test_failed_snapshot_still_releases_esp(self):
        with patch.object(C.os, "open", return_value=19), \
                patch.object(C.os, "close") as closed, \
                patch.object(C, "_snapshot_mounted", side_effect=ValueError("observation failed")):
            with self.assertRaisesRegex(ValueError, "observation failed"):
                C.snapshot()
            closed.assert_called_once_with(19)


class CapacityFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.key, cls.cert = cls.root / "key.pem", cls.root / "cert.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ed25519", "-nodes",
                        "-days", "1", "-subj", "/CN=disposable-capacity-test",
                        "-addext", "subjectAltName=IP:127.0.0.1",
                        "-keyout", str(cls.key), "-out", str(cls.cert)],
                       check=True, capture_output=True)
        cls.image = cls.root / "image.raw"
        cls.bytes = (b"\0\x01\xfe\xff" * (9 * C.CHUNK // 4)) + b"\0tail"
        cls.image.write_bytes(cls.bytes)
        cls.manifest = json.dumps({"version": "9.0.0", "image": "candidate.raw",
                                  "sha256": hashlib.sha256(cls.bytes).hexdigest(),
                                  "product": "velstra-sentinel"}).encode()
        (cls.root / "manifest").write_bytes(cls.manifest)
        subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(cls.key),
                        "-in", str(cls.root / "manifest"), "-out", str(cls.root / "signature")],
                       check=True, capture_output=True)
        cls.signature = (cls.root / "signature").read_bytes()
        cls.public = cls.root / "public.pem"
        subprocess.run(["openssl", "pkey", "-in", str(cls.key), "-pubout", "-out", str(cls.public)],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                        "-inkey", str(cls.public), "-in", str(cls.root / "manifest"),
                        "-sigfile", str(cls.root / "signature")], check=True, capture_output=True)
        cls.envelope = cls.root / "release.json"
        cls.envelope.write_text(json.dumps({"schema": 1,
            "manifest": base64.b64encode(cls.manifest).decode(),
            "signature": base64.b64encode(cls.signature).decode()}))
        cls.server = C.ReleaseServer(cls.image, cls.envelope, cls.cert, cls.key, port=0).start()
        cls.url = "https://127.0.0.1:" + str(cls.server.server.server_address[1])
        cls.context = ssl.create_default_context(cafile=str(cls.cert))

    @classmethod
    def tearDownClass(cls):
        cls.server.close()
        cls.temporary.cleanup()

    def get(self, path):
        with urllib.request.urlopen(self.url + path, context=self.context, timeout=10) as response:
            return response.read()

    def event(self, index, path):
        end = time.monotonic() + 5
        while time.monotonic() < end:
            events = [e for e in self.server.observed(index) if e["path"] == path]
            if events:
                return events[-1]
            time.sleep(0.01)
        self.fail("Reference event did not complete")

    def test_good_real_tls_returns_exact_binary_and_signed_metadata(self):
        index = self.server.select("good")
        self.assertEqual(self.get("/current/candidate.raw"), self.bytes)
        event = self.event(index, "/current/candidate.raw")
        self.assertTrue(event["complete"])
        self.assertEqual(event["wire_SHA256"], hashlib.sha256(self.bytes).hexdigest())
        self.assertIn(event["TLS"], ("TLSv1.2", "TLSv1.3"))
        envelope = json.loads(self.get("/current/release.json"))
        self.assertEqual(base64.b64decode(envelope["manifest"]), self.manifest)
        self.assertEqual(base64.b64decode(envelope["signature"]), self.signature)

    def test_untrusted_tls_does_not_become_a_success(self):
        self.server.select("good")
        with self.assertRaises(urllib.error.URLError):
            urllib.request.urlopen(self.url + "/current/release.json", timeout=10)

    def test_signature_fault_changes_only_signature_not_manifest(self):
        self.server.select("bad-signature")
        envelope = json.loads(self.get("/current/release.json"))
        self.assertEqual(base64.b64decode(envelope["manifest"]), self.manifest)
        modified = base64.b64decode(envelope["signature"])
        self.assertEqual(len(modified), 64)
        self.assertNotEqual(modified, self.signature)
        self.assertEqual(modified[:-1], self.signature[:-1])
        bad = self.root / "bad-signature"
        bad.write_bytes(modified)
        refused = subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                                  "-inkey", str(self.public), "-in", str(self.root / "manifest"),
                                  "-sigfile", str(bad)], capture_output=True)
        self.assertNotEqual(refused.returncode, 0)

    def test_image_fault_changes_one_byte_and_preserves_full_length(self):
        index = self.server.select("tamper")
        received = self.get("/current/candidate.raw")
        self.assertEqual(len(received), len(self.bytes))
        self.assertEqual(sum(a != b for a, b in zip(received, self.bytes)), 1)
        self.assertNotEqual(hashlib.sha256(received).hexdigest(), hashlib.sha256(self.bytes).hexdigest())
        self.assertTrue(self.event(index, "/current/candidate.raw")["complete"])

    def test_client_cancellation_is_observed_as_incomplete_real_tls_transfer(self):
        index = self.server.select("cancel")
        with urllib.request.urlopen(self.url + "/current/candidate.raw",
                                    context=self.context, timeout=10) as response:
            self.assertEqual(response.read(32), self.bytes[:32])
        self.assertFalse(self.event(index, "/current/candidate.raw")["complete"])

    def test_unlisted_or_traversal_paths_are_not_served(self):
        self.server.select("good")
        for path in ("/current/../key.pem", "/key.pem", "/current/candidate.raw?x=1"):
            with self.subTest(path=path), self.assertRaises(urllib.error.HTTPError) as error:
                self.get(path)
            self.assertEqual(error.exception.code, 404)
            error.exception.close()
        with self.assertRaises(RuntimeError):
            self.server.select("unknown")

    def test_environment_removes_all_temporary_directory_overrides(self):
        with patch.dict(C.os.environ, {"TMPDIR": "/foreign", "TMP": "/foreign2", "TEMP": "/foreign3"}):
            self.assertFalse({"TMPDIR", "TMP", "TEMP"} & C.clean_environment().keys())

    def test_capacity_fixture_refuses_absent_or_same_namespace_before_any_command(self):
        for namespace in (None, "", "foreign", "mnt:[123]"):
            with self.subTest(namespace=namespace), patch.object(C.os, "readlink", return_value="mnt:[123]"), \
                 patch.object(C, "command") as command:
                with self.assertRaises(RuntimeError):
                    C.low_space(namespace)
                command.assert_not_called()

    def test_cancellation_unknown_pid_identity_cannot_send_a_signal(self):
        proof = {"pid": 123, "start_ticks": "456", "label": "cancel",
                 "actual_anonymous_stage_seen": True}
        with patch.object(C.Path, "read_text", return_value=json.dumps(proof)), \
             patch.object(C, "process_start", return_value="foreign"), patch.object(C.os, "kill") as kill:
            with self.assertRaises(RuntimeError):
                C.cancel()
            kill.assert_not_called()

    def test_visible_ext4_mount_uses_explicit_unique_kernel_query_and_owned_device(self):
        row = {"target": str(C.STATE), "fstype": "ext4", "source": "/dev/loop0", "maj:min": "7:0", "id": 100}
        output = subprocess.CompletedProcess([], 0, json.dumps({"filesystems": [row]}).encode(), b"")
        with patch.object(C, "command", return_value=output) as command, patch("builtins.print"):
            self.assertEqual(C.visible_ext4_mount(C.STATE, C.os.makedev(7, 0)), row)
        self.assertEqual(command.call_args.args,
            ("findmnt", "--kernel=mountinfo", "--json", "--uniq", "--target", str(C.STATE), "--output", "TARGET,FSTYPE,SOURCE,MAJ:MIN,ID"))

    def test_hidden_original_or_ambiguous_mounts_are_never_selected(self):
        row = {"target": str(C.STATE), "fstype": "ext4", "source": "/dev/loop0", "maj:min": "7:0", "id": 100}
        for rows in ([], [row, row | {"source": "/dev/vda6"}],
                     [row | {"target": "/"}], [row | {"fstype": "tmpfs"}],
                     [row | {"source": ""}], [row | {"children": [row]}], None):
            output = subprocess.CompletedProcess([], 0, json.dumps({"filesystems": rows}).encode(), b"")
            with self.subTest(rows=rows), patch.object(C, "command", return_value=output), \
                 patch("builtins.print"), self.assertRaises(RuntimeError):
                C.visible_ext4_mount(C.STATE, C.os.makedev(7, 0))

    def test_foreign_device_or_invalid_kernel_mount_identity_refused(self):
        row = {"target": str(C.STATE), "fstype": "ext4", "source": "/dev/loop0", "maj:min": "7:0", "id": 100}
        for change in ({"maj:min": "254:6"}, {"maj:min": "7:1"}, {"maj:min": None},
                       {"id": 0}, {"id": True}, {"id": "100"}):
            output = subprocess.CompletedProcess([], 0, json.dumps({"filesystems": [row | change]}).encode(), b"")
            with self.subTest(change=change), patch.object(C, "command", return_value=output), \
                 patch("builtins.print"), self.assertRaises(RuntimeError):
                C.visible_ext4_mount(C.STATE, C.os.makedev(7, 0))

    def test_unknown_owned_device_is_refused_before_findmnt(self):
        for device in (None, True, 0, -1, "7:0"):
            with self.subTest(device=device), patch.object(C, "command") as query, self.assertRaises(RuntimeError):
                C.visible_ext4_mount(C.STATE, device)
            query.assert_not_called()

    def test_visible_mount_diagnostic_precedes_an_invalid_observation_refusal(self):
        raw = b"not-json"
        output = subprocess.CompletedProcess([], 0, raw, b"")
        with patch.object(C, "command", return_value=output), patch("builtins.print") as emitted, \
             self.assertRaises(ValueError):
            C.visible_ext4_mount(C.STATE, C.os.makedev(7, 0))
        self.assertIn(repr(raw), emitted.call_args.args[0])
        self.assertIs(emitted.call_args.kwargs["file"], C.sys.stderr)

    def test_visible_mount_observation_is_bounded(self):
        output = subprocess.CompletedProcess([], 0, b"x" * 4097, b"")
        with patch.object(C, "command", return_value=output), patch("builtins.print") as emitted, \
             self.assertRaisesRegex(RuntimeError, "bound"):
            C.visible_ext4_mount(C.STATE, C.os.makedev(7, 0))
        self.assertLess(len(emitted.call_args.args[0]), 4200)

    def test_nix_embedded_driver_and_publisher_python_are_syntax_valid(self):
        source = (HERE / "update-capacity-test.nix").read_text()
        driver = source.split("  in ''\n", 1)[1].rsplit("\n  '';", 1)[0]
        import re
        driver = re.sub(r"\$\{([^}]*)\}", lambda match:
                        "28483" if match[1] == "toString port" else "/nix/store/fixture", driver)
        compile(textwrap.dedent(driver), "<capacity-vm-driver>", "exec")
        publish = source.split("<<'PY'\n", 1)[1].split("\n      PY", 1)[0]
        compile(textwrap.dedent(publish), "<capacity-release-publisher>", "exec")
        self.assertIn('mountHostNixStore = false', source)
        self.assertIn('memorySize = 4096', source)
        self.assertIn('-uuid 75b6fb89-0399-4b6e-865d-543702a6e25b', source)
        self.assertIn('cat /sys/class/dmi/id/product_uuid', driver)
        self.assertIn('def healthy(trial=False):', driver)
        self.assertIn('for name in reference.UNITS[:4]:', driver)
        self.assertIn('if trial:', driver)
        self.assertIn('healthy(trial=True)', driver)
        self.assertIn('machine.wait_until_succeeds(shlex.quote(checker)', driver)
        self.assertIn('"resize",str(overlay),"10G"', source)
        self.assertNotIn("TMPDIR=", driver)
        self.assertNotIn("systemd-bless-boot good", driver)
        self.assertNotIn("bootctl set-default", driver)
        self.assertIn('sentinel = self.packages.${pkgs.stdenv.hostPlatform.system}.sentinel;', source)
        self.assertIn('--sentinel /nix/store/fixture/bin/sentinel', driver)
        self.assertIn('--systemctl /nix/store/fixture/bin/systemctl', driver)
        self.assertIn('--journalctl /nix/store/fixture/bin/journalctl', driver)
        self.assertIn('helper + " wait-start cancel", timeout=110', driver)
        self.assertNotIn('test -f /run/qa-capacity-cancel/started.json', driver)


class StartupObservationTests(unittest.TestCase):
    """Mocked guest boundaries and real owned host children, not a VM verdict."""
    sentinel = "/nix/store/00000000000000000000000000000000-sentinel/bin/sentinel"
    systemctl = "/nix/store/00000000000000000000000000000000-systemd/bin/systemctl"
    journalctl = "/nix/store/00000000000000000000000000000000-systemd/bin/journalctl"

    @staticmethod
    def properties(**changes):
        values = {"LoadState": "loaded", "ActiveState": "active", "Result": "success",
                  "ExecMainCode": "0", "ExecMainStatus": "0", "MainPID": "123",
                  "InvocationID": "a" * 32}
        values.update(changes)
        return {"exit": 0, "error": None, "stdout": "".join(
            key + "=" + value + "\n" for key, value in values.items()).encode(), "stderr": b""}

    def test_exact_wrapped_executable_ignores_empty_and_hostile_path(self):
        for path in ("", "/hostile/basename/search"):
            with self.subTest(PATH=path), patch.dict(os.environ, {"PATH": path}), \
                 patch.object(C.subprocess, "Popen") as spawn:
                environment = C.clean_environment()
                C.spawn_update(self.sentinel, environment)
            self.assertEqual(spawn.call_args.args[0], [self.sentinel, "update", "install", "--commit"])
            self.assertEqual(spawn.call_args.kwargs["env"]["PATH"], path)
            self.assertIs(spawn.call_args.kwargs["stdin"], subprocess.DEVNULL)
            self.assertIs(spawn.call_args.kwargs["stderr"], subprocess.STDOUT)

    def test_relative_hidden_and_foreign_executables_refused_before_spawn(self):
        for executable in (None, "sentinel", "/run/current-system/sw/bin/sentinel",
                           self.sentinel.replace("/sentinel", "/.sentinel-wrapped"),
                           self.sentinel + " --allow-unsigned", self.sentinel.replace("0000", "eeee", 1)):
            with self.subTest(executable=executable), patch.object(C.subprocess, "Popen") as spawn, \
                 self.assertRaises(RuntimeError):
                C.spawn_update(executable, {})
            spawn.assert_not_called()

    def test_launch_failure_is_not_converted_to_an_updater_completion(self):
        with patch.object(C.subprocess, "Popen", side_effect=FileNotFoundError("fixture missing")), \
             self.assertRaises(FileNotFoundError):
            C.spawn_update(self.sentinel, {})

    def test_lowspace_and_transfer_share_exact_wrapped_argv(self):
        source = (HERE / "update_capacity.py").read_text()
        self.assertIn("proc = spawn_update(sentinel, environment)", source)
        self.assertIn("subprocess.run(update_argv(sentinel), stdin=subprocess.DEVNULL", source)
        self.assertNotIn('["sentinel", "update", "install"', source)

    def test_active_properties_require_exact_identity(self):
        actual = C.unit_properties(self.properties())
        self.assertEqual(actual["MainPID"], "123")
        self.assertEqual(actual["InvocationID"], "a" * 32)

    def test_activating_without_pid_is_pending_not_stage_success(self):
        actual = C.unit_properties(self.properties(ActiveState="activating", MainPID="0", InvocationID=""))
        self.assertEqual(actual["ActiveState"], "activating")

    def test_terminal_and_missing_units_refuse_immediately(self):
        for changes in ({"ActiveState": "failed", "Result": "exit-code"},
                        {"ActiveState": "inactive"}, {"ActiveState": "deactivating"},
                        {"LoadState": "not-found"}, {"LoadState": "error"},
                        {"Result": "signal"}, {"Result": "timeout"}):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                C.unit_properties(self.properties(**changes))

    def test_transport_failure_unknown_even_with_success_shaped_stdout(self):
        for status in (1, 4, 127, -15, None):
            with self.subTest(status=status), self.assertRaises(RuntimeError):
                C.unit_properties(self.properties() | {"exit": status})
        for error in ("spawn-FileNotFoundError", "timeout", "output-limit"):
            with self.subTest(error=error), self.assertRaises(RuntimeError):
                C.unit_properties(self.properties() | {"error": error})

    def test_incomplete_duplicate_foreign_and_malformed_properties_refused(self):
        raw = self.properties()["stdout"]
        for body in (raw + b"MainPID=123\n", raw + b"Foreign=yes\n",
                     raw.replace(b"MainPID=123\n", b""), b"not-a-property\n", b"\xff"):
            with self.subTest(body=body), self.assertRaises((RuntimeError, UnicodeDecodeError)):
                C.unit_properties(self.properties() | {"stdout": body})
        for changes in ({"MainPID": "0"}, {"MainPID": "1"}, {"MainPID": "-1"},
                        {"MainPID": "123 "}, {"MainPID": "1" * 17}, {"InvocationID": ""},
                        {"InvocationID": "A" * 32}, {"ExecMainCode": "foreign"},
                        {"ExecMainStatus": "-1"}):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                C.unit_properties(self.properties(**changes))

    def test_wait_success_requires_actual_started_proof(self):
        proof = {"label": "cancel", "actual_anonymous_stage_seen": True}
        with patch.object(C, "bounded_command", return_value=self.properties()) as query, \
             patch.object(C, "started_record", return_value=proof) as started, \
             patch.object(C.time, "sleep") as sleep:
            self.assertEqual(C.wait_started("cancel", self.systemctl, self.journalctl), proof)
        self.assertEqual(query.call_count, 1)
        self.assertEqual(query.call_args.args[0][-1], "qa-capacity-cancel.service")
        started.assert_called_once()
        sleep.assert_not_called()

    def test_activating_then_active_requires_proof_not_only_active_unit(self):
        pending = self.properties(ActiveState="activating", MainPID="0", InvocationID="")
        proof = {"label": "cancel", "actual_anonymous_stage_seen": True}
        with patch.object(C, "bounded_command", side_effect=[pending, self.properties(), self.properties()]) as query, \
             patch.object(C, "started_record", side_effect=[None, proof]) as started, \
             patch.object(C.time, "sleep"):
            self.assertEqual(C.wait_started("cancel", self.systemctl, self.journalctl), proof)
        self.assertEqual(query.call_count, 3)
        self.assertEqual(started.call_count, 2)

    def test_launch_failure_diagnostic_precedes_failclosed_no_retry(self):
        failed = self.properties(ActiveState="failed", Result="exit-code", MainPID="0", ExecMainStatus="1")
        journal = {"exit": 0, "error": None, "stdout": b"FileNotFoundError: sentinel\n", "stderr": b""}
        output = io.StringIO()
        with patch.object(C, "bounded_command", side_effect=[failed, journal]) as query, \
             patch.object(C, "result_diagnostic", return_value={"present": False}), \
             patch.object(C, "started_record") as started, patch.object(C.time, "sleep") as sleep, \
             patch.object(C.sys, "stderr", output), self.assertRaisesRegex(RuntimeError, "startup refused"):
            C.wait_started("cancel", self.systemctl, self.journalctl)
        self.assertEqual(query.call_count, 2)
        self.assertEqual(query.call_args.args[0], [self.journalctl, "--unit=qa-capacity-cancel.service",
            "--no-pager", "--output=short-precise", "--lines=20"])
        started.assert_not_called()
        sleep.assert_not_called()
        diagnostic = json.loads(output.getvalue().split("QA_CAPACITY_STARTUP_REFUSED ", 1)[1])
        self.assertIn("FileNotFoundError", diagnostic["journal"]["stdout_prefix"])
        self.assertTrue(diagnostic["started_proof_not_fabricated"])
        self.assertEqual(diagnostic["show"]["exit"], 0)

    def test_query_unknown_is_not_missing_and_diagnostic_preserves_both_pipes(self):
        unknown = {"exit": 127, "error": None, "stdout": b"query-output", "stderr": b"query-error"}
        journal = {"exit": None, "error": "timeout", "stdout": b"", "stderr": b""}
        output = io.StringIO()
        with patch.object(C, "bounded_command", side_effect=[unknown, journal]), \
             patch.object(C, "result_diagnostic", side_effect=PermissionError), \
             patch.object(C, "started_record") as started, patch.object(C.sys, "stderr", output), \
             self.assertRaises(RuntimeError):
            C.wait_started("cancel", self.systemctl, self.journalctl)
        started.assert_not_called()
        diagnostic = json.loads(output.getvalue().split("QA_CAPACITY_STARTUP_REFUSED ", 1)[1])
        self.assertEqual(diagnostic["show"]["exit"], 127)
        self.assertIn("query-output", diagnostic["show"]["stdout_prefix"])
        self.assertIn("query-error", diagnostic["show"]["stderr_prefix"])
        self.assertEqual(diagnostic["result"]["error"], "PermissionError")

    def test_elapsed_deadline_without_proof_is_never_success(self):
        output = io.StringIO()
        with patch.object(C, "bounded_command", return_value=self.properties()) as query, \
             patch.object(C, "result_diagnostic", return_value={"present": False}), \
             patch.object(C, "started_record") as started, patch.object(C.sys, "stderr", output), \
             self.assertRaises(RuntimeError):
            C.wait_started("cancel", self.systemctl, self.journalctl, timeout=0)
        self.assertEqual(query.call_count, 1)  # Diagnostic journal only, no state query.
        started.assert_not_called()
        self.assertIn("fixed startup deadline", output.getvalue())

    def test_unscoped_labels_or_tools_refuse_before_any_query(self):
        for arguments in (("foreign", self.systemctl, self.journalctl),
                          ("cancel", "systemctl", self.journalctl),
                          ("cancel", self.systemctl, "/tmp/journalctl")):
            with self.subTest(arguments=arguments), patch.object(C, "bounded_command") as query, \
                 self.assertRaises(RuntimeError):
                C.wait_started(*arguments)
            query.assert_not_called()

    def test_real_owned_child_completed_nonzero_and_streams_authoritative(self):
        result = C.bounded_command([os.path.realpath(os.sys.executable), "-c",
            "import os; os.write(1,b'public-out'); os.write(2,b'public-err'); raise SystemExit(127)"])
        self.assertEqual(result, {"exit": 127, "stdout": b"public-out", "stderr": b"public-err", "error": None})

    def test_real_owned_child_timeout_kills_and_reaps_only_child(self):
        owned = []
        real_spawn = subprocess.Popen

        def spawn(*args, **kwargs):
            child = real_spawn(*args, **kwargs)
            owned.append(child)
            return child

        with patch.object(C.subprocess, "Popen", side_effect=spawn):
            result = C.bounded_command([os.path.realpath(os.sys.executable), "-c", "import time; time.sleep(30)"], timeout=0.05)
        self.assertEqual(result["error"], "timeout")
        self.assertIsNone(result["exit"])
        self.assertEqual(len(owned), 1)
        self.assertIsNotNone(owned[0].poll())
        self.assertTrue(owned[0].stdout.closed and owned[0].stderr.closed)

    def test_real_owned_child_output_is_combined_bounded(self):
        result = C.bounded_command([os.path.realpath(os.sys.executable), "-c",
            "import os; os.write(1,b'x'*32768); os.write(2,b'y'*32768)"], maximum=1024)
        self.assertEqual(result["error"], "output-limit")
        self.assertLessEqual(len(result["stdout"]) + len(result["stderr"]), 1024)
        shown = C.display_observation(result)
        self.assertLessEqual(shown["captured_stdout_bytes"] + shown["captured_stderr_bytes"], 1024)

    def test_real_spawn_error_is_unknown_not_absence(self):
        result = C.bounded_command(["/nonexistent-qa-capacity-tool"])
        self.assertEqual(result["error"], "spawn-FileNotFoundError")
        self.assertIsNone(result["exit"])

    def test_started_proof_absence_is_pending_without_touching_process(self):
        with patch.object(C.os, "open", side_effect=FileNotFoundError), patch.object(C, "process_start") as identity:
            self.assertIsNone(C.started_record("cancel", {"MainPID": "123"}))
        identity.assert_not_called()

    @staticmethod
    def metadata(size, **changes):
        from types import SimpleNamespace
        return SimpleNamespace(**({"st_mode": stat.S_IFREG | 0o600, "st_uid": 0,
                                   "st_nlink": 1, "st_size": size} | changes))

    def read_record(self, name, value, function, metadata=None):
        """Host-owned file; only mocked fstat UID exercises guest root-only policy."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "qa-capacity-cancel"
            directory.mkdir()
            path = directory / name
            path.write_text(json.dumps(value))
            with patch.object(C, "START_ROOT", root), \
                 patch.object(C.os, "fstat", return_value=metadata or self.metadata(path.stat().st_size)):
                return function()

    def test_started_proof_requires_live_child_identity_and_anonymous_stage(self):
        proof = {"label": "cancel", "actual_anonymous_stage_seen": True, "pid": 456,
                 "parent": 123, "start_ticks": "789", "cmdline_hex": b"wrapped-sentinel".hex()}
        with patch.object(C, "process_start", return_value="789"), \
             patch.object(C.Path, "read_bytes", return_value=b"wrapped-sentinel"), \
             patch.object(C, "stage_samples", return_value=[{"inode": 42}]) as stage, \
             patch.object(C.Path, "stat", return_value=self.metadata(100, st_dev=7)):
            self.assertEqual(self.read_record("started.json", proof,
                lambda: C.started_record("cancel", {"MainPID": "123"})), proof)
        stage.assert_called_once_with(456, 7)

    def test_started_proof_foreign_parent_label_pid_or_missing_stage_refused(self):
        proof = {"label": "cancel", "actual_anonymous_stage_seen": True, "pid": 456,
                 "parent": 123, "start_ticks": "789", "cmdline_hex": b"wrapped-sentinel".hex()}
        for change in ({"label": "tamper"}, {"parent": 124}, {"pid": True},
                       {"actual_anonymous_stage_seen": False}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.read_record("started.json", proof | change,
                    lambda: C.started_record("cancel", {"MainPID": "123"}))
        with patch.object(C, "process_start", return_value="foreign"), self.assertRaises(RuntimeError):
            self.read_record("started.json", proof, lambda: C.started_record("cancel", {"MainPID": "123"}))
        with patch.object(C, "process_start", return_value="789"), \
             patch.object(C.Path, "read_bytes", return_value=b"wrapped-sentinel"), \
             patch.object(C.Path, "stat", return_value=self.metadata(100, st_dev=7)), \
             patch.object(C, "stage_samples", return_value=[]), self.assertRaises(RuntimeError):
            self.read_record("started.json", proof, lambda: C.started_record("cancel", {"MainPID": "123"}))

    def test_result_diagnostic_is_bounded_and_honest_about_merged_output(self):
        result = self.read_record("result.json", {"exit": 1, "output": "x" * 5000},
                                  lambda: C.result_diagnostic("cancel"))
        self.assertTrue(result["present"])
        self.assertEqual(result["exit"], 1)
        self.assertEqual(len(result["product_stdout_stderr_merged_prefix"]), 4096)
        self.assertEqual(result["output_characters"], 5000)

    def test_unprotected_or_oversized_records_are_never_read_as_proof(self):
        for changes in ({"st_uid": os.getuid() or 1}, {"st_nlink": 2},
                        {"st_mode": stat.S_IFREG | 0o644}, {"st_size": 4 * C.OUTPUT_LIMIT + 1},
                        {"st_mode": stat.S_IFDIR | 0o600}):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                self.read_record("result.json", {"output": "public-fixture"}, lambda: C.result_diagnostic("cancel"),
                                 metadata=self.metadata(100, **changes))


class AtomicPublicationTests(unittest.TestCase):
    """Owned host files/rename only; explicitly mocked guest root ownership.

    No chown, privilege elevation, mount, updater, systemd or guest is used.
    Existing40 cases remain; these tests exercise the real Linux rename syscall
    against only TemporaryDirectory files owned by this host test process.
    """

    @contextmanager
    def owned_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "qa-capacity-cancel"
            root.mkdir(mode=0o700)
            real_fstat, real_stat = os.fstat, os.stat

            class RootMetadata:
                def __init__(self, value):
                    self.value = value

                @property
                def st_uid(self):
                    return 0  # Guest root policy only, not actual host ownership.

                def __getattr__(self, name):
                    return getattr(self.value, name)

            with patch.object(C, "START_ROOT", base), \
                    patch.object(C.os, "fstat", side_effect=lambda *a, **kw: RootMetadata(real_fstat(*a, **kw))), \
                    patch.object(C.os, "stat", side_effect=lambda *a, **kw: RootMetadata(real_stat(*a, **kw))):
                yield root

    def test_final_absent_until_complete_atomic_publish_for_both_record_formats(self):
        for name, value in (("started.json", {"label": "cancel", "actual_anonymous_stage_seen": True}),
                            ("result.json", {"exit": -9, "samples": [{"inode": 42}], "output": "public fixture"})):
            with self.subTest(name=name), self.owned_directory() as root:
                path = root / name
                ready, release = threading.Event(), threading.Event()
                real_rename = C.rename_noreplace
                errors = []

                def hold(directory, source, destination):
                    ready.set()
                    if not release.wait(3):
                        raise RuntimeError("held test publication not released")
                    real_rename(directory, source, destination)

                def publish():
                    try:
                        C.private_json(path, value)
                    except Exception as error:
                        errors.append(error)

                with patch.object(C, "rename_noreplace", side_effect=hold):
                    worker = threading.Thread(target=publish)
                    worker.start()
                    try:
                        self.assertTrue(ready.wait(3))
                        self.assertFalse(path.exists())
                        hidden = list(root.iterdir())
                        self.assertEqual(len(hidden), 1)
                        self.assertEqual(json.loads(hidden[0].read_text()), value)
                        self.assertEqual(hidden[0].stat().st_nlink, 1)
                        self.assertEqual(stat.S_IMODE(hidden[0].stat().st_mode), 0o600)
                        if name == "started.json":
                            with patch.object(C, "process_start") as process:
                                self.assertIsNone(C.started_record("cancel", {"MainPID": "123"}))
                                process.assert_not_called()
                        else:
                            self.assertEqual(C.result_diagnostic("cancel"), {"present": False})
                    finally:
                        release.set()
                        worker.join(timeout=4)
                    self.assertFalse(worker.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(json.loads(path.read_text()), value)
                self.assertEqual(path.stat().st_nlink, 1)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(list(root.iterdir()), [path])

    def test_slow_partial_hidden_write_is_never_a_partial_final_record(self):
        with self.owned_directory() as root:
            path = root / "started.json"
            ready, release = threading.Event(), threading.Event()
            errors = []
            real_write = os.write
            calls = []

            def slow_write(fd, payload):
                calls.append(len(payload))
                if len(calls) == 1:
                    count = real_write(fd, payload[:3])
                    ready.set()
                    if not release.wait(3):
                        raise RuntimeError("held write not released")
                    return count
                return real_write(fd, payload)

            def publish():
                try:
                    C.private_json(path, {"label": "cancel", "actual_anonymous_stage_seen": True})
                except Exception as error:
                    errors.append(error)

            with patch.object(C.os, "write", side_effect=slow_write):
                worker = threading.Thread(target=publish)
                worker.start()
                try:
                    self.assertTrue(ready.wait(3))
                    self.assertFalse(path.exists())
                    self.assertIsNone(C.started_record("cancel", {"MainPID": "123"}))
                    self.assertEqual(next(root.iterdir()).stat().st_size, 3)
                finally:
                    release.set()
                    worker.join(timeout=4)
                self.assertFalse(worker.is_alive())
            self.assertEqual(errors, [])
            self.assertGreater(len(calls), 1)
            self.assertEqual(json.loads(path.read_text())["label"], "cancel")

    def test_existing_regular_corrupt_symlink_hardlink_or_directory_never_overwritten(self):
        for kind in ("empty", "corrupt", "valid", "symlink", "hardlink", "directory"):
            with self.subTest(kind=kind), self.owned_directory() as root:
                path = root / "started.json"
                other = root / "owned-existing"
                if kind == "directory":
                    path.mkdir()
                elif kind == "symlink":
                    other.write_text("retained target")
                    path.symlink_to(other)
                elif kind == "hardlink":
                    other.write_text("retained linked record")
                    os.link(other, path)
                else:
                    path.write_text({"empty": "", "corrupt": "{bad", "valid": '{"old":true}'}[kind])
                before = path.lstat()
                data = path.read_bytes() if kind != "directory" else None
                with self.assertRaises(OSError), patch.object(C.os, "rename") as replace:
                    C.private_json(path, {"new": True})
                replace.assert_not_called()
                self.assertEqual((path.lstat().st_dev, path.lstat().st_ino), (before.st_dev, before.st_ino))
                self.assertEqual(path.read_bytes() if kind != "directory" else None, data)
                hidden = list(root.glob(".publish-*"))
                self.assertEqual(len(hidden), 1)
                self.assertEqual(json.loads(hidden[0].read_text()), {"new": True})
                self.assertEqual(hidden[0].stat().st_nlink, 1)

    def test_existing_record_created_exactly_at_publish_barrier_is_not_replaced(self):
        with self.owned_directory() as root:
            path = root / "result.json"
            real_rename = C.rename_noreplace

            def race(directory, source, destination):
                path.write_text("retained late unknown")
                return real_rename(directory, source, destination)

            with patch.object(C, "rename_noreplace", side_effect=race), self.assertRaises(FileExistsError):
                C.private_json(path, {"exit": 0})
            self.assertEqual(path.read_text(), "retained late unknown")

    def test_unsupported_publication_has_no_replace_fallback_and_retains_complete_private_file(self):
        with self.owned_directory() as root:
            with patch.object(C, "rename_noreplace", side_effect=OSError(errno.ENOSYS, "unsupported")), \
                    patch.object(C.os, "rename") as replace, self.assertRaises(OSError):
                C.private_json(root / "started.json", {"label": "cancel"})
            replace.assert_not_called()
            self.assertFalse((root / "started.json").exists())
            hidden = list(root.glob(".publish-*"))
            self.assertEqual(len(hidden), 1)
            self.assertEqual(json.loads(hidden[0].read_text()), {"label": "cancel"})

    def test_serialization_failure_creates_no_visible_or_hidden_record(self):
        with self.owned_directory() as root, patch.object(C.os, "open") as opened, self.assertRaises(TypeError):
            C.private_json(root / "started.json", {"not_json": object()})
        opened.assert_not_called()

    def test_unscoped_path_refuses_before_any_open(self):
        for path in (Path("/tmp/started.json"), Path("/run/qa-capacity-cancel/foreign.json"),
                     Path("/run/qa-capacity-foreign/started.json")):
            with self.subTest(path=path), patch.object(C.os, "open") as opened, self.assertRaises(RuntimeError):
                C.private_json(path, {"label": "cancel"})
            opened.assert_not_called()

    def test_parent_symlink_refused_without_touching_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            other = base / "untouched"
            other.mkdir(mode=0o700)
            (base / "qa-capacity-cancel").symlink_to(other, target_is_directory=True)
            with patch.object(C, "START_ROOT", base), self.assertRaises(OSError):
                C.private_json(base / "qa-capacity-cancel/started.json", {})
            self.assertEqual(list(other.iterdir()), [])

    def test_parent_not_root0700_refuses_before_creating_proof(self):
        for owner, mode in ((1000, stat.S_IFDIR | 0o700), (0, stat.S_IFDIR | 0o755)):
            from types import SimpleNamespace
            with tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root = base / "qa-capacity-cancel"
                root.mkdir(mode=0o700)
                metadata = SimpleNamespace(st_uid=owner, st_mode=mode)
                with patch.object(C, "START_ROOT", base), patch.object(C.os, "fstat", return_value=metadata), \
                        self.assertRaises(RuntimeError):
                    C.private_json(root / "started.json", {})
                self.assertEqual(list(root.iterdir()), [])

    def test_write_failure_is_not_retried_or_published(self):
        with self.owned_directory() as root, patch.object(C.os, "write", side_effect=OSError(errno.ENOSPC, "full")) as write:
            with self.assertRaises(OSError):
                C.private_json(root / "started.json", {"label": "cancel"})
            write.assert_called_once()
            self.assertFalse((root / "started.json").exists())
            self.assertEqual(len(list(root.glob(".publish-*"))), 1)

    def test_unsafe_temporary_inode_refused_before_write_or_publication(self):
        from types import SimpleNamespace
        for change in ({"st_uid": 1000}, {"st_nlink": 2}, {"st_mode": stat.S_IFREG | 0o644},
                       {"st_mode": stat.S_IFIFO | 0o600}, {"st_dev": -1}):
            with self.subTest(change=change), self.owned_directory() as root:
                parent = root.stat()
                unsafe = SimpleNamespace(**({"st_mode": stat.S_IFREG | 0o600, "st_uid": 0,
                    "st_nlink": 1, "st_dev": parent.st_dev, "st_ino": 123, "st_size": 0} | change))
                with patch.object(C.os, "fstat", side_effect=[parent, unsafe]), \
                        patch.object(C.os, "write") as write, patch.object(C, "rename_noreplace") as publish, \
                        self.assertRaises(RuntimeError):
                    C.private_json(root / "started.json", {"label": "cancel"})
                write.assert_not_called()
                publish.assert_not_called()
                self.assertFalse((root / "started.json").exists())

    def test_present_partial_record_still_refuses_without_process_retry(self):
        with self.owned_directory() as root:
            path = root / "started.json"
            path.write_text("{")
            path.chmod(0o600)
            with patch.object(C, "process_start") as process, self.assertRaises(json.JSONDecodeError):
                C.started_record("cancel", {"MainPID": "123"})
            process.assert_not_called()
            self.assertEqual(path.read_text(), "{")


if __name__ == "__main__":
    unittest.main(verbosity=2)
