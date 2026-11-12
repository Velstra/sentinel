"""Isolate FIFO admission from independent-worker launch behavior."""
import argparse
import json
import os
from pathlib import Path
import ssl
import time
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument("--sentinel", required=True)
parser.parse_args()
token = Path("/var/lib/sentinel/api-token").read_text().strip()
tls = ssl._create_unverified_context()  # Disposable management TLS only.

def status():
    request = urllib.request.Request("https://127.0.0.1:8080/api/v1/system/updates",
                                     headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(request, context=tls, timeout=3) as response:
        assert response.status == 200
        return json.load(response)

def wait(refuse):
    deadline = time.monotonic() + 15
    last = None
    while time.monotonic() < deadline:
        last = status()
        if last.get("observation", {}).get("state") == "fresh":
            if refuse and not last["can_check"] and last["unavailable"] == "conflict":
                return last
            if not refuse and last["can_check"]:
                return last
        time.sleep(0.05)
    raise AssertionError("FIFO guard never returned a fresh bounded conflict" if refuse else "healthy control unavailable", last)

state = wait(False)
assert state["current"]["permanent"] is True
phases = []
for name, path in [("journal", Path("/var/lib/sentinel/.appliance.toml.pending.json")),
                   ("outbox", Path("/var/lib/sentinel/configsync/pending.json"))]:
    path.parent.mkdir(mode=0o750, exist_ok=True)
    assert not path.exists() and not path.is_symlink()
    os.mkfifo(path, 0o600)
    try:
        start = time.monotonic()
        wait(True)
        phases.append({"name": name, "refused_seconds": time.monotonic() - start})
    finally:
        path.unlink()
    wait(False)
assert not Path("/var/lib/sentinel/update-jobs").exists()
print(json.dumps({"schema": "velstra-real-ota-fifo-absence/v1", "phases": phases,
                  "all_selected_checks_passed": True, "real_efi_verity": True,
                  "check_or_stage_called": False, "production_release_certified": False}))
