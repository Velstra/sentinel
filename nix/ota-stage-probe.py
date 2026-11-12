"""Real HTTP job Stage against a read-only attached donor, never a host disk."""
import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid


def run(args, *, timeout=15):
    value = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    if value.returncode:
        raise AssertionError(value.stdout)
    return value.stdout


def until(callback, seconds=30):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        last = callback()
        if last:
            return last
        time.sleep(0.1)
    raise AssertionError("real Stage state did not converge: " + repr(last))


def request(path, body=None):
    headers = {"Authorization": "Bearer " + Path("/var/lib/sentinel/api-token").read_text().strip()}
    if body is not None:
        headers.update({"Content-Type": "application/json", "Origin": "https://127.0.0.1:8080"})
    value = urllib.request.Request("https://127.0.0.1:8080/api/v1" + path, headers=headers,
        data=None if body is None else json.dumps(body).encode())
    try:
        response = urllib.request.urlopen(value, context=ssl._create_unverified_context(), timeout=4)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, json.load(response)


def available():
    code, value = request("/system/updates")
    if code == 503:
        return None
    assert code == 200, (code, value)
    return value if value.get("observation", {}).get("state") == "fresh" and value["can_check"] else None


def payload(state, stage=False):
    value = {"request_id": uuid.uuid4().hex + uuid.uuid4().hex,
             "expected_generation": state["generation"], "expected": state["mutation_context"]}
    if stage:
        value["offer_id"] = state["offer"]["id"]
    return value


def terminal(identifier):
    code, value = request("/system/updates/jobs/" + identifier)
    if code == 503:
        return None
    assert code == 200, (code, value)
    return value if value["phase"] in ("checked", "staged", "failed", "interrupted") else None


def digest(path):
    with Path(path).open("rb", buffering=0) as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def inactive_identity():
    return {str(number): {"sha256": digest(f"/dev/vda{number}"),
                         "guid": run(["lsblk", "-nro", "PARTUUID", f"/dev/vda{number}"]).strip()}
            for number in (4, 5)}


def main(sentinel):
    proof = json.loads(Path("/etc/qa-stage-proof/info.json").read_bytes())
    assert Path("/dev/sda").is_block_device()
    assert run(["findmnt", "-n", "-o", "SOURCE", "/var/lib/sentinel"]).strip() == "/dev/vda6"
    assert digest("/dev/sda") == proof["sha256"], "attached donor differs from signed build input"
    before = inactive_identity()
    initial = until(available)
    assert initial["current"]["permanent"] and initial["current"]["slot"] == "sentinel-a"
    saved = digest("/var/lib/sentinel/appliance.toml")
    Path("/var/lib/sentinel/qa-http-stage-persistence").write_text("persistent HTTP Stage proof\n")
    keys = Path("/etc/qa-stage-keys")
    scratch = Path("/run/qa-real-stage")
    scratch.mkdir(mode=0o700)

    def envelope(body, corrupt=False):
        (scratch / "manifest").write_bytes(body)
        run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(keys / "release.key"),
             "-in", str(scratch / "manifest"), "-out", str(scratch / "signature")])
        signature = bytearray((scratch / "signature").read_bytes())
        if corrupt:
            signature[0] ^= 1
        return json.dumps({"schema": 1, "manifest": base64.b64encode(body).decode(),
                           "signature": base64.b64encode(signature).decode()}).encode()

    body = {"version": "3.0.0", "image": "sentinel_3.0.0.raw", "sha256": proof["sha256"],
            "product": "velstra-sentinel"}
    normal = json.dumps(body, separators=(",", ":")).encode()
    envelopes = {"valid": envelope(normal), "invalid-signature": envelope(normal, corrupt=True),
                 "changed": envelope(json.dumps(body, indent=2).encode()),
                 "wrong-digest": envelope(json.dumps({**body, "sha256": "0" * 64}).encode())}
    mode = {"value": "valid", "download_complete": False, "pause": False}
    entered, release = threading.Event(), threading.Event()
    release.set()
    paths, errors, results = [], [], []

    def record(value):
        results.append(value)
        Path("/run/qa-real-stage-progress.json").write_text(json.dumps(results))

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            paths.append(self.path)
            if self.path == "/current/release.json":
                selected = "changed" if mode["value"] == "metadata-change" and mode["download_complete"] else mode["value"]
                data = envelopes.get(selected, envelopes["valid"])
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            elif self.path == "/current/sentinel_3.0.0.raw":
                self.send_response(200)
                self.send_header("Content-Length", str(proof["size"]))
                self.end_headers()
                if mode["pause"]:
                    entered.set()
                    if not release.wait(30):
                        errors.append("owned download gate timed out")
                        return
                try:
                    with Path("/dev/sda").open("rb", buffering=0) as source:
                        remaining = proof["size"]
                        while remaining:
                            block = source.read(min(1024**2, remaining))
                            assert block, "short donor"
                            self.wfile.write(block)
                            remaining -= len(block)
                    mode["download_complete"] = True
                except Exception as error:
                    errors.append(str(error))
            else:
                self.send_error(404)

    server = ThreadingHTTPServer(("127.0.0.1", 29485), Handler)
    server.daemon_threads = True
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(keys / "tls.crt", keys / "tls.key")
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    read_only_busy_jobs = []

    def check():
        # The independent periodic recovery writer may legitimately win the
        # nonblocking CAS after admission. Check is read-only: only a completed
        # typed Busy may be retried, with a NEW request and fresh context.
        # Never retry Stage or an ambiguous/unknown worker outcome here.
        for attempt in range(5):
            state = until(available)
            code, job = request("/system/updates/check", payload(state))
            assert code == 202, (code, job)
            completed = until(lambda: terminal(job["id"]))
            if completed["phase"] == "failed" and completed["error"] == "busy":
                read_only_busy_jobs.append(completed)
                assert inactive_identity() == before
                continue
            return completed
        raise AssertionError("five completed read-only checks remained Busy")

    def stage():
        state = until(available)
        assert state["can_stage"], state
        code, job = request("/system/updates/stage", payload(state, stage=True))
        assert code == 202, (code, job)
        return job

    try:
        mode["value"] = "invalid-signature"
        failed = check()
        assert failed["phase"] == "failed" and failed["error"] == "metadata-refused", failed
        assert inactive_identity() == before
        record({"case": "invalid-signature-refused-before-write", "job": failed})

        for selected, expected in (("wrong-digest", "download-refused"), ("metadata-change", "conflict")):
            mode.update(value=selected, download_complete=False)
            checked = check()
            assert checked["phase"] == "checked", checked
            accepted = stage()
            failed = until(lambda: terminal(accepted["id"]), seconds=180)
            assert failed["phase"] == "failed" and failed["error"] == expected, failed
            assert inactive_identity() == before, "refused Stage changed inactive partition bytes or GUIDs"
            assert until(available)["current"] == initial["current"]
            record({"case": selected + "-refused-before-write", "job": failed})

        mode.update(value="valid", download_complete=False, pause=True)
        release.clear()
        checked = check()
        assert checked["phase"] == "checked", checked
        accepted = stage()
        assert entered.wait(15), "real worker did not request the image"
        name = "sentinel-update-" + accepted["id"] + ".service"
        worker = run(["systemctl", "show", "-p", "MainPID", "--value", name]).strip()
        assert worker.isdigit() and int(worker) > 1, worker
        competing = subprocess.run([sentinel, "update", "install", "--commit"], text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
        assert competing.returncode != 0 and "another update is in progress" in competing.stdout, competing.stdout
        run(["systemctl", "restart", "sentinel-api.service"])
        until(lambda: run(["systemctl", "is-active", "sentinel-api.service"]).strip() == "active")
        def observed_active():
            try:
                code, value = request("/system/updates")
            except urllib.error.URLError as error:
                # The test itself just restarted the API. ActiveState=active
                # precedes bind/listen; only that bounded connection-refused
                # startup interval is retryable, not TLS/auth/other failures.
                if isinstance(error.reason, ConnectionRefusedError):
                    return None
                raise
            if code == 503:
                return None
            assert code == 200, (code, value)
            if value.get("observation", {}).get("state") != "fresh":
                return None
            assert not value["can_check"] and not value["can_stage"], value
            assert any(job["id"] == accepted["id"] and job["phase"] == "downloading"
                       for job in value["jobs"]), value
            return value
        until(observed_active)
        assert run(["systemctl", "show", "-p", "MainPID", "--value", name]).strip() == worker
        assert inactive_identity() == before, "paused download changed a target"
        release.set()
        staged = until(lambda: terminal(accepted["id"]), seconds=180)
        assert staged["phase"] == "staged" and staged["error"] is None, staged
        identity = staged["staged"]
        assert identity["active_slot"] == "sentinel-a" and identity["staged_slot"] == "sentinel-b", identity
        assert identity["boot_entry"] == "sentinel-b+3.efi", identity
        assert digest("/boot/EFI/Linux/" + identity["boot_entry"]) == identity["uki_sha256"]
        for target, source, field in ((4, 2, "verity_guid"), (5, 3, "store_guid")):
            guid = run(["lsblk", "-nro", "PARTUUID", f"/dev/vda{target}"]).strip().lower()
            donor_guid = run(["lsblk", "-nro", "PARTUUID", f"/dev/sda{source}"]).strip().lower()
            assert guid == identity[field].lower() == donor_guid, (guid, identity[field], donor_guid)
            assert digest(f"/dev/vda{target}") == digest(f"/dev/sda{source}"), "target partition differs from verified donor"
        assert digest("/var/lib/sentinel/appliance.toml") == saved
        assert not errors, errors
        record({"case": "real-stage-survives-api-restart-and-refuses-competing-cli-writer", "job": staged})
        Path("/var/lib/sentinel/qa-http-stage.json").write_text(json.dumps({"saved_sha256": saved,
            "boot_id": initial["current"]["boot_id"], "staged": identity}))
        print(json.dumps({"all_selected_checks_passed": True, "cases": results, "staged": identity,
            "requests": paths, "read_only_busy_jobs": read_only_busy_jobs,
            "donor_sha256": proof["sha256"], "real_efi_verity": True,
            "native_or_production_certified": False}))
    finally:
        release.set()
        server.shutdown()
        server.server_close()


def after_boot():
    previous = json.loads(Path("/var/lib/sentinel/qa-http-stage.json").read_text())
    assert Path("/etc/qa-stage-donor").is_file()
    assert not Path("/dev/sda").exists(), "donor remained attached during boot"
    state = until(available)
    current = state["current"]
    assert current["slot"] == "sentinel-b" and current["release"] == "3.0.0", current
    assert current["permanent"] and current["selected_entry"] == current["next_entry"] == "sentinel-b.efi", current
    assert current["boot_id"] != previous["boot_id"]
    assert current["uki_sha256"] == previous["staged"]["uki_sha256"]
    assert digest("/var/lib/sentinel/appliance.toml") == previous["saved_sha256"]
    assert Path("/var/lib/sentinel/qa-http-stage-persistence").read_text() == "persistent HTTP Stage proof\n"
    assert "ro" in run(["findmnt", "-n", "-o", "OPTIONS", "/nix/store"]).strip().split(",")
    print(json.dumps({"booted_new_slot": True, "preserved_state": True, "current": current,
                      "native_or_production_certified": False}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sentinel")
    parser.add_argument("--after-boot", action="store_true")
    args = parser.parse_args()
    if args.after_boot:
        after_boot()
    else:
        assert args.sentinel
        main(args.sentinel)
