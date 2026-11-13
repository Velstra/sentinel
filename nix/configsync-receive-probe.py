"""Actual guest API/filesystem fault probes; never run on an operator host."""
import copy
import errno
import hashlib
import json
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

CONFIG = Path("/var/lib/sentinel/appliance.toml")
MARKER = CONFIG.with_suffix(".configsync-received")
RECORD = Path("/tmp/configsync-receive-proof.json")
TOKEN = "shared-token-123"  # Disposable fixture credential, never production.
RESULTS = Path("/tmp/configsync-receive-results.json")


def passed(case, **facts):
    results = json.loads(RESULTS.read_text()) if RESULTS.exists() else []
    assert all(item["case"] != case for item in results), "do not overwrite an executed case"
    results.append({"case": case, "passed": True, **facts})
    RESULTS.write_text(json.dumps(results, indent=2))


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def document(path=CONFIG):
    return json.loads(run("sentinel", "config", "convert", str(path), "--to", "json"))


def mtu():
    return json.loads(run("ip", "-j", "link", "show", "eth1"))[0]["mtu"]


def request(payload=None, port=8080):
    # The default VM API is already tested for real cross-node SPKI pinning.
    # This local fixture accepts ONLY its disposable self-signed TLS endpoint.
    route = "/api/v1/config-sync" if payload is not None else "/api/v1/health"
    req = urllib.request.Request(
        f"https://127.0.0.1:{port}{route}",
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"},
        method="PUT" if payload is not None else "GET",
    )
    try:
        with urllib.request.urlopen(req, context=ssl._create_unverified_context(), timeout=30) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


def changed(local):
    desired = copy.deepcopy(local)
    desired["system"]["hostname"] = "sender-identity-must-not-be-adopted"
    interface = next(link for link in desired["interface"] if link["name"] == "eth1")
    interface["mtu"] = 1400
    interface["address"] = "10.9.0.99/24"
    return desired


def disk_full():
    assert not MARKER.exists(), "fault probe must precede first synchronization"
    before, original_mtu = CONFIG.read_bytes(), mtu()
    with tempfile.TemporaryDirectory(prefix="configsync-enospc-") as directory:
        root = Path(directory)
        storage = root / "storage"
        storage.mkdir()
        subprocess.run(["mount", "-t", "tmpfs", "-o", "size=64k", "tmpfs", str(storage)], check=True)
        process = None
        try:
            path = storage / "appliance.toml"
            path.write_bytes(before)
            # Ensure the document lock already exists, so ENOSPC is injected
            # into the actual receive-journal publisher, not lock creation.
            path.with_suffix(".transaction.lock").touch(mode=0o660)
            token = root / "token"
            token.write_text(TOKEN)
            token.chmod(0o600)
            with (root / "api.log").open("wb") as log:
                process = subprocess.Popen([
                    "sentinel", "api", "--listen", "127.0.0.1:18080",
                    "--config", str(path), "--token-file", str(token)
                ], stdout=log, stderr=log)
                deadline = time.monotonic() + 30
                while True:
                    assert process.poll() is None, "real API exited during setup"
                    try:
                        assert request(port=18080)[0] == 200
                        break
                    except urllib.error.URLError:
                        assert time.monotonic() < deadline, "real API did not start"
                        time.sleep(0.1)
                with (storage / "filler").open("wb", buffering=0) as filler:
                    try:
                        while True:
                            filler.write(bytes(4096))
                    except OSError as error:
                        assert error.errno == errno.ENOSPC
                status, result = request(changed(document()), port=18080)
                assert status == 500, (status, result)
                assert "no policy was applied" in str(result), result
                assert "No space left on device" in str(result), result
                assert not path.with_suffix(".configsync-received").exists()
                assert path.read_bytes() == before
                assert CONFIG.read_bytes() == before and mtu() == original_mtu
        finally:
            if process is not None:
                process.terminate()
                process.wait(timeout=10)
            subprocess.run(["umount", str(storage)], check=True)
    passed("actual-enospc-before-apply", errno=errno.ENOSPC,
        response=500, saved_config_unchanged=True, live_mtu_unchanged=True)


def save_failure():
    assert not MARKER.exists(), "first-sync fault must precede participation"
    local = document()
    desired = changed(local)
    before = CONFIG.read_bytes()
    RECORD.write_text(json.dumps({"local": local, "desired": desired,
        "saved_sha256": hashlib.sha256(before).hexdigest()}))
    # Reading remains possible, while atomic rename onto a mountpoint returns
    # EBUSY AFTER the real live apply. The sibling receive journal stays writable.
    subprocess.run(["mount", "--bind", str(CONFIG), str(CONFIG)], check=True)
    try:
        status, result = request(desired)
        assert status == 500 and "APPLIED" in str(result) and "could NOT be saved" in str(result), (status, result)
        assert CONFIG.read_bytes() == before
        assert mtu() == 1400, "a real live network change must precede the save fault"
        fence = json.loads(MARKER.read_text())
        assert fence["version"] == 1
        assert len(fence["baseline"]) == len(fence["desired"]) == 64
        assert MARKER.stat().st_mode & 0o777 == 0o600
        stale = copy.deepcopy(desired)
        next(link for link in stale["interface"] if link["name"] == "eth1")["mtu"] = 1300
        assert request(stale)[0] == 409
        assert CONFIG.read_bytes() == before and mtu() == 1400
    finally:
        subprocess.run(["umount", str(CONFIG)], check=True)
    passed("actual-post-apply-save-failure", response=500, live_mtu=1400,
        saved_config_unchanged=True, durable_private_fence=True, different_stale_push=409)


def retry_after_restart():
    record = json.loads(RECORD.read_text())
    assert hashlib.sha256(CONFIG.read_bytes()).hexdigest() == record["saved_sha256"]
    stale = copy.deepcopy(record["desired"])
    next(link for link in stale["interface"] if link["name"] == "eth1")["mtu"] = 1300
    assert request(stale)[0] == 409, "API restart must not reopen first sync"
    status, result = request(record["desired"])
    assert status == 200 and result["saved"] is True, (status, result)
    saved = document()
    assert saved["system"]["hostname"] == record["local"]["system"]["hostname"]
    assert next(link for link in saved["interface"] if link["name"] == "eth1")["address"] == "10.9.0.2/24"
    assert mtu() == 1400
    assert request(record["desired"])[0] == 200, "identical delivery is idempotent"
    assert request(stale)[0] == 409
    receipt = MARKER.read_text().strip()
    assert len(receipt) == 64 and all(c in "0123456789abcdef" for c in receipt)
    assert not Path("/var/lib/sentinel/configsync/pending.json").exists(), "received policy must never echo"
    passed("actual-restart-exact-retry", different_stale_push=409, exact_retry=200,
        repeated_delivery=200, member_identity_preserved=True, completed_receipt=True, no_echo_outbox=True)


def rollback_after_completion():
    record = json.loads(RECORD.read_text())
    subprocess.run(["su", "admin", "-c", "sentinel configure"],
        input="delete interface eth1 mtu\ncommit\nsave\nexit\n", text=True, check=True)
    assert document() == record["local"], "real CLI rollback must restore the full prior baseline"
    assert request(record["desired"])[0] == 409, "a completed first-sync grant must stay consumed after rollback"
    assert document() == record["local"]
    subprocess.run(["su", "admin", "-c", "sentinel configure"],
        input="set interface eth1 mtu 1400\ncommit\nsave\nexit\n", text=True, check=True)
    assert mtu() == 1400
    passed("actual-cli-rollback", full_original_baseline_restored=True,
        completed_grant_stays_consumed=409, live_baseline_reestablished=True)


{"disk-full": disk_full, "save-failure": save_failure,
 "retry-after-restart": retry_after_restart,
 "rollback-after-completion": rollback_after_completion}[sys.argv[1]]()
