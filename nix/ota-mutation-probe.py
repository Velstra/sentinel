"""Real Check workers, signed trusted HTTPS and normal non-root CLI writers.

No image or Stage is requested: this qualifies the common mutation checkpoint,
not the separate native write handoff or production release.
"""
import argparse
import base64
import fcntl
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shlex
import ssl
import subprocess
import threading
import tempfile
import time
import urllib.error
import urllib.request
import uuid


def until(callback, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = callback()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("mutation checkpoint state did not converge")


def run(arguments, **kwargs):
    value = subprocess.run(arguments, text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=10, **kwargs)
    assert value.returncode == 0, value.stdout
    return value.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sentinel", required=True)
    sentinel = parser.parse_args().sentinel
    keys = Path("/etc/qa-mutation-keys")
    token = Path("/var/lib/sentinel/api-token").read_text().strip()
    epoch = Path("/run/sentinel/mutation.json")
    saved = Path("/var/lib/sentinel/appliance.toml")
    saved_hash = hashlib.sha256(saved.read_bytes()).hexdigest()
    initial_epoch = json.loads(epoch.read_bytes())
    assert initial_epoch["boot"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    assert epoch.stat().st_uid == 0 and epoch.stat().st_mode & 0o777 == 0o640
    run(["su", "admin", "-c", "test -r /run/sentinel/mutation.json"])
    api_tls = ssl._create_unverified_context()  # Disposable management TLS only.

    def request(path, body=None):
        headers = {"Authorization": "Bearer " + token}
        if body is not None:
            headers.update({"Content-Type": "application/json", "Origin": "https://127.0.0.1:8080"})
        value = urllib.request.Request("https://127.0.0.1:8080/api/v1" + path,
            data=None if body is None else json.dumps(body).encode(), headers=headers)
        try:
            response = urllib.request.urlopen(value, context=api_tls, timeout=4)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, json.load(response)

    def available():
        code, value = request("/system/updates")
        assert code == 200, value
        return value if value.get("observation", {}).get("state") == "fresh" and value["can_check"] else None

    def payload(state):
        return {"request_id": uuid.uuid4().hex + uuid.uuid4().hex,
                "expected_generation": state["generation"], "expected": state["mutation_context"]}

    def terminal(job_id):
        code, value = request("/system/updates/jobs/" + job_id)
        # An invalidated/cold observation explicitly returns retryable 503,
        # never a false missing-job verdict. Keep the accepted job ID.
        if code == 503:
            return None
        assert code == 200, value
        return value if value["phase"] in ("checked", "failed", "interrupted", "write-outcome-unknown") else None

    manifest = json.dumps({"version": "3.0.0", "image": "sentinel_3.0.0.raw",
                           "sha256": "0" * 64, "product": "velstra-sentinel"}, separators=(",", ":")).encode()
    scratch = Path("/run/qa-mutation-fixture")
    scratch.mkdir(mode=0o700)
    (scratch / "manifest").write_bytes(manifest)
    run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(keys / "release.key"),
         "-in", str(scratch / "manifest"), "-out", str(scratch / "signature")])
    envelope = json.dumps({"schema": 1, "manifest": base64.b64encode(manifest).decode(),
                           "signature": base64.b64encode((scratch / "signature").read_bytes()).decode()}).encode()
    entered, release, pause = threading.Event(), threading.Event(), threading.Event()
    release.set()
    paths, errors = [], []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            paths.append(self.path)
            if self.path != "/current/release.json":
                self.send_error(404)
                return
            if pause.is_set():
                entered.set()
                if not release.wait(15):
                    errors.append("owned metadata delay timed out")
                    self.send_error(504)
                    return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(envelope)))
            self.end_headers()
            self.wfile.write(envelope)

    server = ThreadingHTTPServer(("127.0.0.1", 29484), Handler)
    server.daemon_threads = True
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(keys / "tls.crt", keys / "tls.key")
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    phases = []
    try:
        state = until(available)
        assert state["mutation_context"]["mutation_epoch"] == initial_epoch["nonce"]
        assert state["current"]["permanent"] is True
        assert not state["can_stage"]
        # The real API admission must not wait behind a long-running apply.
        with Path("/run/sentinel/apply.lock").open("r+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            started = time.monotonic()
            code, value = request("/system/updates/check", payload(state))
            duration = time.monotonic() - started
            assert code == 409 and "busy" in value["error"].lower(), (code, value)
            assert duration < 1.5, duration
            assert not Path("/var/lib/sentinel/update-jobs").exists()
            fcntl.flock(lock, fcntl.LOCK_UN)
        phases.append({"name": "real-busy-admission-is-nonblocking", "seconds": duration})

        # Control: an actual independent worker must verify real TLS + signature.
        state = until(available)
        code, job = request("/system/updates/check", payload(state))
        assert code == 202, (code, job)
        checked = until(lambda: terminal(job["id"]))
        assert checked["phase"] == "checked" and checked["error"] is None, checked
        state = until(available)
        assert state["can_stage"] and state["offer"]["verified"]["manifest"]["version"] == "3.0.0", state
        phases.append({"name": "real-trusted-https-signed-check-control", "job": checked})

        pause.set()
        entered.clear()
        release.clear()
        before_nonce = state["mutation_context"]["mutation_epoch"]
        before_config_revision = state["mutation_context"]["config_revision"]
        code, job = request("/system/updates/check", payload(state))
        assert code == 202, (code, job)
        assert entered.wait(5), "real independent worker did not request metadata"
        started = time.monotonic()
        output = run(["su", "admin", "-c", shlex.join([sentinel, "configure"])],
                     input="set system hostname mutation-temporary\ncommit\nset system hostname mutation-fw\ncommit\nexit\n")
        duration = time.monotonic() - started
        assert output.count("commit ok") == 2 and "error:" not in output.lower(), output
        assert duration < 5 and not release.is_set(), duration
        assert hashlib.sha256(saved.read_bytes()).hexdigest() == saved_hash
        assert Path("/proc/sys/kernel/hostname").read_text().strip() == "mutation-fw"
        after_nonce = json.loads(epoch.read_bytes())["nonce"]
        assert before_nonce != after_nonce
        release.set()
        failed = until(lambda: terminal(job["id"]))
        assert failed["phase"] == "failed" and failed["error"] == "conflict", failed
        state = until(available)
        assert state["offer"] is None and not state["can_stage"], state
        assert state["mutation_context"]["config_revision"] == before_config_revision
        phases.append({"name": "real-nonroot-live-only-aba-during-network-observation",
                       "cli_seconds": duration, "before_nonce": before_nonce, "after_nonce": after_nonce,
                       "saved_bytes_unchanged": True, "job": failed})

        # Healthy post-ABA control: refusal must not permanently poison Check.
        pause.clear()
        code, job = request("/system/updates/check", payload(state))
        assert code == 202, (code, job)
        checked = until(lambda: terminal(job["id"]))
        assert checked["phase"] == "checked", checked
        state = until(available)
        assert state["can_stage"]
        phases.append({"name": "post-aba-signed-check-recovers", "job": checked})
        assert paths == ["/current/release.json"] * 3 and not errors, (paths, errors)
        assert hashlib.sha256(saved.read_bytes()).hexdigest() == saved_hash
        def blocked_fifo():
            code, value = request("/system/updates")
            return value if code == 200 and value.get("observation", {}).get("state") == "fresh" and not value["can_check"] and value["unavailable"] == "conflict" else None

        # Real special-file corruption must fail closed WITHOUT opening it.
        for name, path in (("journal", Path("/var/lib/sentinel/.appliance.toml.pending.json")),
                           ("outbox", Path("/var/lib/sentinel/configsync/pending.json"))):
            path.parent.mkdir(mode=0o750, exist_ok=True)
            assert not path.exists() and not path.is_symlink()
            previous = until(available)
            os.mkfifo(path, 0o600)
            try:
                until(blocked_fifo)
                started = time.monotonic()
                code, value = request("/system/updates/check", payload(previous))
                duration = time.monotonic() - started
                assert code == 409 and duration < 1.5, (code, value, duration)
                assert len(paths) == 3
                phases.append({"name": "real-" + name + "-fifo-refused-without-content-read",
                               "seconds": duration, "passed": True})
            finally:
                path.unlink()
            until(available)

        def natural_gc():
            for name in ("sentinel-confirm.timer", "sentinel-confirm.service"):
                value = dict(line.split("=", 1) for line in run(
                    ["systemctl", "show", "--property=LoadState,ActiveState,SubState", name]).splitlines())
                if value != {"LoadState": "not-found", "ActiveState": "inactive", "SubState": "dead"}:
                    return None
            return True

        def blocked():
            code, value = request("/system/updates")
            return value if code == 200 and value.get("observation", {}).get("state") == "fresh" and not value["can_check"] and value["unavailable"] == "conflict" else None

        def cli(commands):
            output = run(["su", "admin", "-c", shlex.join([sentinel, "configure"])], input=commands + "\nexit\n")
            assert "error:" not in output.lower(), output
            return output

        before = json.loads(epoch.read_bytes())["nonce"]
        cli("set system hostname mutation-confirm\ncommit-confirm 10")
        until(blocked)
        applied = json.loads(epoch.read_bytes())["nonce"]
        assert applied != before
        cli("confirm")
        until(natural_gc)
        state = until(available)
        confirmed = json.loads(epoch.read_bytes())["nonce"]
        assert confirmed != applied and state["offer"] is None
        assert hashlib.sha256(saved.read_bytes()).hexdigest() == saved_hash
        phases.append({"name": "real-admin-confirm-advances-epoch-and-naturally-collects", "passed": True})

        # Save belongs to this candidate session, not a newly opened session
        # whose candidate is deliberately loaded from the saved baseline.
        with tempfile.TemporaryFile(mode="w+t") as output:
            process = subprocess.Popen(["su", "admin", "-c", shlex.join([sentinel, "configure"])],
                stdin=subprocess.PIPE, stdout=output, stderr=subprocess.STDOUT, text=True)
            try:
                process.stdin.write("set system hostname mutation-save\ncommit-confirm 10\n")
                process.stdin.flush()
                until(lambda: Path("/proc/sys/kernel/hostname").read_text().strip() == "mutation-save")
                until(blocked)
                applied = json.loads(epoch.read_bytes())["nonce"]
                process.communicate("save\nexit\n", timeout=10)
                output.seek(0)
                transcript = output.read()
                assert process.returncode == 0 and "error:" not in transcript.lower(), transcript
                assert "commit-confirm:" in transcript and "saved" in transcript, transcript
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
        until(natural_gc)
        state = until(available)
        assert json.loads(epoch.read_bytes())["nonce"] != applied
        assert 'mutation-save' in saved.read_text()
        assert state["offer"] is None
        phases.append({"name": "real-admin-save-cancels-confirm-under-one-mutation-lock", "passed": True})
        cli("set system hostname mutation-fw\ncommit\nsave")
        assert Path("/proc/sys/kernel/hostname").read_text().strip() == "mutation-fw"
        # A real REST transaction writes a root-private journal. Normal admin
        # confirm must use the bounded, noninteractive privileged reader.
        code, document = request("/config/document")
        assert code == 200, document
        candidate = document["toml"].replace('hostname = "mutation-fw"', 'hostname = "mutation-management"')
        assert candidate != document["toml"]
        code, transaction = request("/config/document", {"toml": candidate,
            "expected_revision": document["revision"], "validate_only": False})
        assert code == 200 and transaction["pending"]["id"], (code, transaction)
        identifier = transaction["pending"]["id"]

        def ready():
            code, value = request("/config/transaction")
            assert code == 200, value
            return value if value.get("pending", {}) and value["pending"].get("ready") else None

        until(ready)
        journal = Path("/var/lib/sentinel/.appliance.toml.pending.json")
        assert journal.stat().st_uid == 0 and journal.stat().st_mode & 0o777 == 0o600
        run(["su", "admin", "-c", "test ! -r /var/lib/sentinel/.appliance.toml.pending.json"])
        cli("confirm " + identifier)
        assert not journal.exists()
        assert Path("/proc/sys/kernel/hostname").read_text().strip() == "mutation-management"
        assert "mutation-management" in saved.read_text()
        phases.append({"name": "real-admin-confirms-root-private-rest-journal-through-bounded-reader", "passed": True})
        cli("set system hostname mutation-fw\ncommit\nsave")
        print(json.dumps({"schema": "velstra-real-ota-mutation-checkpoint/v1", "real_efi_verity": True,
            "phases": phases, "channel_requests": paths, "all_selected_checks_passed": True,
            "stage_or_image_download_called": False, "native_or_production_release_certified": False}))
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    main()
