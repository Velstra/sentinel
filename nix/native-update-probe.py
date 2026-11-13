"""Actual local HTTPS -> Rust job -> private native helper -> GPT/UKI -> B boot."""
import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid

STATE = Path("/var/lib/sentinel")
TOKEN = "qa_lab_only_" + "a" * 52


def run(args, timeout=30):
    result = subprocess.run(args, capture_output=True, timeout=timeout, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip()


def digest(path):
    with Path(path).open("rb", buffering=0) as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def request(path, body=None):
    headers = {"Authorization": "Bearer " + (STATE / "api-token").read_text().strip()}
    if body is not None:
        headers.update({"Content-Type": "application/json", "Origin": "https://127.0.0.1:8080"})
    req = urllib.request.Request("https://127.0.0.1:8080/api/v1" + path, headers=headers,
        data=None if body is None else json.dumps(body).encode())
    # Disposable loopback management identity only. The release channel below
    # uses actual system CA/IP/time validation in both curl and Python.
    try:
        response = urllib.request.urlopen(req, context=ssl._create_unverified_context(), timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, json.load(response)


def until(callback, seconds=45):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        last = callback()
        if last:
            return last
        time.sleep(0.1)
    raise AssertionError("native state did not converge: " + repr(last))


def available():
    code, state = request("/system/updates")
    if code == 503:
        return None
    assert code == 200, (code, state)
    return state if state.get("observation", {}).get("state") == "fresh" and state["can_check"] else None


def payload(state, stage=False):
    value = {"request_id": uuid.uuid4().hex + uuid.uuid4().hex,
        "expected_generation": state["generation"], "expected": state["mutation_context"]}
    if stage:
        value["offer_id"] = state["offer"]["id"]
    return value


def terminal(identifier):
    code, result = request("/system/updates/jobs/" + identifier)
    if code == 503:
        return None
    assert code == 200, (code, result)
    return result if result["phase"] in ("checked", "staged", "failed", "interrupted") else None


def restarted_api_has_job(identifier):
    # Type=exec may be active before bind/listen. Retry only this read-only
    # startup observation, never a mutation or a TLS/authentication failure.
    try:
        code, result = request("/system/updates/jobs/" + identifier)
    except urllib.error.URLError as error:
        if isinstance(error.reason, ConnectionRefusedError):
            return False
        raise
    assert code in (200, 503), (code, result)
    return code == 200


def disk_rows():
    return json.loads(run(["sfdisk", "--json", "/dev/vda"]))["partitiontable"]


def inactive():
    return {str(n): digest("/dev/vda" + str(n)) for n in (4, 5)}


def after_boot():
    proof = json.loads((STATE / "qa-native-proof.json").read_bytes())
    current = until(available)["current"]
    assert current["slot"] == "sentinel-b" and current["release"] == "v1.0.0-lts", current
    assert current["selected_entry"] == current["next_entry"] == "sentinel_v1.0.0-lts.efi", current
    assert current["permanent"]
    assert digest(STATE / "appliance.toml") == proof["config_sha256"]
    assert (STATE / "qa-native-data").read_text() == "persistent native OTA proof"
    assert {str(n): digest("/dev/vda" + str(n)) for n in (2, 3)} == proof["active_sha256"]
    print(json.dumps({"passed": True, "booted_new_native_slot": True, "current": current,
        "persistent_config_and_original_slot_preserved": True}))


def main(sentinel):
    # The factory's initial boot has been assessed. Exercise the native helper's
    # read-only ESP restoration explicitly; do not change the boot target/bless.
    run(["mount", "-o", "remount,ro", "/boot"])
    assert "ro" in run(["findmnt", "-nro", "OPTIONS", "--types", "vfat", "--target", "/boot"]).split(",")
    initial = until(available)
    assert initial["current"]["slot"] == "sentinel-a"
    assert initial["current"]["release"] == "v0.9.0-lts" and initial["current"]["permanent"]
    original_table = disk_rows()
    original_bytes = inactive()
    active = {str(n): digest("/dev/vda" + str(n)) for n in (2, 3)}
    config_hash = digest(STATE / "appliance.toml")
    (STATE / "qa-native-data").write_text("persistent native OTA proof")
    keys = Path("/etc/qa-native-keys")
    resources = Path("/etc/qa-native-resources")
    descriptor = json.loads((resources / "resources.json").read_bytes())
    image = json.loads((resources / "image.json").read_bytes())
    manifest = {"version": descriptor["version"], "image": "sentinel_v1.0.0-lts.raw",
        "sha256": image["sha256"], "product": "velstra-sentinel",
        "sysupdate": {"schema": 1, "resources": descriptor["resources"]}}
    scratch = Path("/run/qa-native-signing")
    scratch.mkdir(mode=0o700)

    def envelope(body, invalid=False):
        (scratch / "manifest").write_bytes(body)
        run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(keys / "release.key"),
            "-in", str(scratch / "manifest"), "-out", str(scratch / "signature")])
        signature = bytearray((scratch / "signature").read_bytes())
        if invalid:
            signature[0] ^= 1
        return json.dumps({"schema": 1, "manifest": base64.b64encode(body).decode(),
            "signature": base64.b64encode(signature).decode()}).encode()

    body = json.dumps(manifest, separators=(",", ":")).encode()
    envelopes = {"valid": envelope(body), "bad-signature": envelope(body, True),
        "swapped": envelope(json.dumps(manifest, indent=2).encode())}
    mode = {"kind": "valid", "swapped": False, "pause": False}
    entered, release = threading.Event(), threading.Event()
    release.set()
    paths, errors, results = [], [], []
    def record(name, result):
        results.append({"case": name, "job": result})
        (STATE / "qa-native-progress.json").write_text(json.dumps(results))

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            assert self.headers.get("Authorization") == "Bearer " + TOKEN
            assert re.fullmatch("[0-9a-f]{32}", self.headers.get("X-Velstra-Machine-ID", ""))
            paths.append(self.path)
            if self.path == "/current/release.json":
                selected = "swapped" if mode["swapped"] else mode["kind"]
                data = envelopes.get(selected, envelopes["valid"])
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            prefix = "/current/v1.0.0-lts/"
            if self.path.startswith(prefix):
                name = self.path[len(prefix):]
                if "/" not in name and name in {item["name"] for item in descriptor["resources"].values()}:
                    path = resources / name
                    self.send_response(200)
                    self.send_header("Content-Length", str(path.stat().st_size))
                    self.end_headers()
                    if mode["pause"]:
                        entered.set()
                        assert release.wait(40), "owned resource pause expired"
                    try:
                        with path.open("rb") as source:
                            while block := source.read(1024**2):
                                if mode["kind"] == "bad-resource" and source.tell() == path.stat().st_size:
                                    block = block[:-1] + bytes([block[-1] ^ 1])
                                self.wfile.write(block)
                        if mode["kind"] == "metadata-change":
                            mode["swapped"] = True
                    except (BrokenPipeError, ConnectionResetError):
                        pass  # A refused/cancelled read is not transfer success.
                    return
            self.send_error(404)

    server = ThreadingHTTPServer(("127.0.0.1", 29485), Handler)
    server.daemon_threads = True
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(keys / "tls.crt", keys / "tls.key")
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def check():
        for _ in range(5):
            state = until(available)
            code, job = request("/system/updates/check", payload(state))
            assert code == 202, (code, job)
            done = until(lambda: terminal(job["id"]), 90)
            if done["phase"] == "failed" and done["error"] == "busy":
                assert disk_rows() == original_table and inactive() == original_bytes
                record("completed-read-only-check-busy", done)
                continue
            return done
        raise AssertionError("read-only native checks remained Busy")

    def stage():
        state = until(available)
        assert state["can_stage"], state
        code, job = request("/system/updates/stage", payload(state, True))
        assert code == 202, (code, job)
        return job

    try:
        mode["kind"] = "bad-signature"
        done = check()
        assert done["phase"] == "failed" and done["error"] == "metadata-refused", done
        assert disk_rows() == original_table and inactive() == original_bytes
        record("signature-refused-before-write", done)
        for kind, error in [("bad-resource", "download-refused"), ("metadata-change", "conflict")]:
            mode.update(kind=kind, swapped=False)
            assert check()["phase"] == "checked"
            accepted = stage()
            done = until(lambda: terminal(accepted["id"]), 240)
            assert done["phase"] == "failed" and done["error"] == error, done
            assert disk_rows() == original_table and inactive() == original_bytes
            record(kind + "-refused-before-go", done)
        mode.update(kind="valid", swapped=False, pause=True)
        assert check()["phase"] == "checked"
        release.clear()
        accepted = stage()
        assert entered.wait(30), "native worker did not request an actual versioned resource"
        run(["systemctl", "restart", "sentinel-api.service"])
        until(lambda: restarted_api_has_job(accepted["id"]))
        contender = subprocess.run([sentinel, "update", "/dev/vda", "--allow-unsigned", "--commit"],
            capture_output=True, text=True, timeout=15)
        assert contender.returncode != 0 and "another update" in contender.stderr, contender.stderr
        release.set()
        done = until(lambda: terminal(accepted["id"]), 300)
        assert done["phase"] == "staged" and done["error"] is None, done
        assert done["staged"]["boot_entry"] == "sentinel_v1.0.0-lts+3-0.efi", done
        assert done["staged"]["active_slot"] == "sentinel-a" and done["staged"]["staged_slot"] == "sentinel-b"
        assert {str(n): digest("/dev/vda" + str(n)) for n in (2, 3)} == active
        assert digest(STATE / "appliance.toml") == config_hash
        assert "ro" in run(["findmnt", "-nro", "OPTIONS", "--types", "vfat", "--target", "/boot"]).split(",")
        record("real-native-stage-after-api-restart-and-competing-writer-refusal", done)
        assert not errors
        assert not any(path.endswith(".raw") for path in paths), "native path fell through to RAW download"
        proof = {"passed": True, "actual_native_writes": True, "cases": results,
            "config_sha256": config_hash, "active_sha256": active, "paths": paths}
        (STATE / "qa-native-proof.json").write_text(json.dumps(proof))
        print(json.dumps(proof))
    finally:
        release.set()
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sentinel")
    parser.add_argument("--after-boot", action="store_true")
    args = parser.parse_args()
    after_boot() if args.after_boot else main(args.sentinel)
