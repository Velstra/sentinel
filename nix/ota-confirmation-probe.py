"""Guest-local CLI timer/rollback/API guard proof with refused Check admission.

One deliberate timer-only stop while the actual auto-rollback process waits on
the real common lock proves service-only refusal. No test-only reset-failed or
fake healthy state is used. Normal CLI paths must collect their real units.
An injected real rollback failure must block Check before durable job creation
or any upstream metadata request; no Stage offer is synthesized.
"""
import argparse
import fcntl
import hashlib
import json
from pathlib import Path
import shlex
import socket
import ssl
import subprocess
import threading
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
    raise AssertionError("real confirmation state did not converge")


def run(arguments, **kwargs):
    result = subprocess.run(arguments, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=20, **kwargs)
    assert result.returncode == 0, result.stdout
    return result.stdout


def units():
    result = {}
    for name in ("sentinel-confirm.timer", "sentinel-confirm.service"):
        output = run(["systemctl", "show", "--property=LoadState,ActiveState,SubState", name])
        result[name] = dict(line.split("=", 1) for line in output.splitlines())
    return result


def collected():
    state = units()
    if all(value == {"LoadState": "not-found", "ActiveState": "inactive", "SubState": "dead"}
           for value in state.values()):
        return state
    return None


class ChannelTripwire:
    def __enter__(self):
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 29484))
        self.socket.listen(8)
        self.socket.settimeout(0.1)
        self.stopped = threading.Event()
        self.attempts = 0
        self.errors = []
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()
        return self

    def serve(self):
        while not self.stopped.is_set():
            try:
                connection, _ = self.socket.accept()
            except TimeoutError:
                continue
            except OSError as error:
                if not self.stopped.is_set():
                    self.errors.append(str(error))
                return
            self.attempts += 1
            connection.close()

    def __exit__(self, *_):
        self.stopped.set()
        self.socket.close()
        self.thread.join(timeout=2)
        assert not self.thread.is_alive() and not self.errors, self.errors


def exercise(sentinel, fault_sentinel, channel):
    assert Path("/sys/firmware/efi/efivars").is_dir()
    assert Path("/dev/mapper/usr").is_block_device()
    token = Path("/var/lib/sentinel/api-token").read_text().strip()
    tls = ssl._create_unverified_context()  # Disposable guest factory TLS only.
    saved = Path("/var/lib/sentinel/appliance.toml")
    saved_hash = hashlib.sha256(saved.read_bytes()).hexdigest()

    def status():
        request = urllib.request.Request("https://127.0.0.1:8080/api/v1/system/updates",
                                         headers={"Authorization": "Bearer " + token})
        with urllib.request.urlopen(request, context=tls, timeout=3) as response:
            assert response.status == 200 and response.headers["Cache-Control"] == "no-store"
            value = json.load(response)
        if value.get("observation", {}).get("state") != "fresh":
            if not value["can_check"] and not value["can_stage"] and value["unavailable"] == "busy":
                return value
            return None
        # A held real writer now produces typed Busy without queueing behind it.
        if value["current"] is None and value["unavailable"] == "busy":
            assert not value["can_check"] and not value["can_stage"]
            return value
        assert value["current"]["permanent"] is True, value
        assert value["can_stage"] is False and value["jobs"] == [], value
        return value

    def available():
        value = status()
        return value if value and value["can_check"] and value["unavailable"] is None else None

    def blocked():
        value = status()
        return value if value and not value["can_check"] and value["unavailable"] in ("conflict", "busy") else None

    def failed_recovery():
        value = units()
        return value if value["sentinel-confirm.service"]["ActiveState"] == "failed" else None

    def failed_context():
        value = status()
        return value if value and not value["can_check"] and value["unavailable"] == "conflict" and value["mutation_context"] is not None else None

    def commit_confirm(hostname, minutes, *, binary=sentinel):
        output = run(["su", "admin", "-c", shlex.join([binary, "configure"])],
                     input=f"set system hostname {hostname}\ncommit-confirm {minutes}\nexit\n")
        assert "commit-confirm:" in output and "error:" not in output.lower(), output
        assert Path("/proc/sys/kernel/hostname").read_text().strip() == hostname
        assert hostname in Path("/run/sentinel/running.toml").read_text()
        assert hashlib.sha256(saved.read_bytes()).hexdigest() == saved_hash
        assert units()["sentinel-confirm.timer"]["ActiveState"] == "active"

    until(collected)
    until(available)
    phases = []
    commit_confirm("guard-keep", 10)
    until(blocked)
    confirmed = run(["su", "admin", "-c", shlex.join([sentinel, "configure"])], input="confirm\nexit\n")
    assert "error:" not in confirmed.lower() and "nothing to confirm" not in confirmed.lower(), confirmed
    after = until(collected)
    until(available)
    assert Path("/proc/sys/kernel/hostname").read_text().strip() == "guard-keep"
    phases.append({"name": "normal-cli-confirm", "guard_refused": True, "natural_gc": after})

    running = Path("/run/sentinel/running.toml")
    baseline = running.read_bytes()
    baseline_hostname = Path("/proc/sys/kernel/hostname").read_text().strip()
    commit_confirm("guard-revert", 10)
    until(blocked)
    run([sentinel, "confirm-rollback"])
    after = until(collected)
    until(available)
    assert Path("/proc/sys/kernel/hostname").read_text().strip() == baseline_hostname
    assert running.read_bytes() == baseline
    phases.append({"name": "normal-cli-manual-rollback", "guard_refused": True, "natural_gc": after})

    baseline = running.read_bytes()
    baseline_hostname = Path("/proc/sys/kernel/hostname").read_text().strip()
    commit_confirm("guard-auto", 1)
    until(blocked)
    # Hold only our real common-lock inode so the actual timer-spawned Sentinel
    # remains running before rollback. No unrelated PID is signalled.
    with Path("/run/sentinel/apply.lock").open("r+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        until(lambda: units()["sentinel-confirm.service"]["ActiveState"] == "active", seconds=100)
        # An operator stopping the elapsed timer must NOT authorize OTA while
        # its genuine rollback process still exists and may change live state.
        run(["systemctl", "stop", "sentinel-confirm.timer"])
        def timer_collected():
            value = units()
            return value if value["sentinel-confirm.timer"]["LoadState"] == "not-found" else None

        state = until(timer_collected)
        assert state["sentinel-confirm.service"]["ActiveState"] == "active", state
        until(blocked)
        assert Path("/proc/sys/kernel/hostname").read_text().strip() == "guard-auto"
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    until(lambda: Path("/proc/sys/kernel/hostname").read_text().strip() == baseline_hostname)
    after = until(collected)
    until(available)
    assert running.read_bytes() == baseline
    phases.append({"name": "actual-timer-service-with-timer-only-stop", "guard_refused": True,
                   "observed_service_only": state, "natural_gc_after_actual_rollback": after})

    # The wrapper only changes the real external hostname tool/timer deadline.
    # The production core, API, EFI identity, verity and systemctl are unchanged.
    baseline = running.read_bytes()
    baseline_hostname = Path("/proc/sys/kernel/hostname").read_text().strip()
    Path("/run/qa-ota-restore-hostname").write_text(baseline_hostname)
    Path("/run/qa-ota-fail-restore").touch(mode=0o600)
    commit_confirm("guard-failed-trial", 1, binary=fault_sentinel)
    until(lambda: Path("/run/qa-ota-partial-restore").exists())
    failed = until(failed_recovery)
    assert failed["sentinel-confirm.service"]["LoadState"] == "loaded", failed
    assert Path("/proc/sys/kernel/hostname").read_text().strip() == "guard-partial-restore"
    assert "guard-failed-trial" in running.read_text()
    refused = until(failed_context)
    assert refused["unavailable"] == "conflict" and refused["current"]["permanent"], refused
    assert refused["mutation_context"] is not None, "refusal must be an otherwise valid immutable context"
    jobs = Path("/var/lib/sentinel/update-jobs")
    assert not jobs.exists(), "fixture starts without durable update jobs"
    cli = subprocess.run([sentinel, "system", "update", "check", "--wait"], text=True,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
    assert cli.returncode == 1 and "check and review again" in cli.stdout, cli.stdout
    payload = dict(request_id=uuid.uuid4().hex + uuid.uuid4().hex,
                   expected_generation=refused["generation"], expected=refused["mutation_context"])
    request = urllib.request.Request("https://127.0.0.1:8080/api/v1/system/updates/check",
        data=json.dumps(payload).encode(), headers={"Authorization": "Bearer " + token,
        "Content-Type": "application/json", "Origin": "https://127.0.0.1:8080"}, method="POST")
    try:
        response = urllib.request.urlopen(request, context=tls, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        assert response.status == 409, response.status
        assert "check and review again" in str(json.load(response))
    assert not jobs.exists(), "refused Check created durable update state"
    assert channel.attempts == 0 and not channel.errors, "refused Check reached metadata upstream"
    assert hashlib.sha256(saved.read_bytes()).hexdigest() == saved_hash
    Path("/run/qa-ota-fail-restore").unlink()
    retried = run([sentinel, "confirm-rollback"])
    assert "retry scheduled" in retried and "reverted the running" not in retried, retried
    after = until(collected)
    until(available)
    assert running.read_bytes() == baseline
    assert Path("/proc/sys/kernel/hostname").read_text().strip() == baseline_hostname
    phases.append({"name": "actual-failed-restore-refuses-unified-check-before-job-or-network",
                   "guard_refused": True, "retained_failed": failed,
                   "api_http": 409, "cli_exit": cli.returncode, "natural_gc_after_retry": after})
    assert hashlib.sha256(saved.read_bytes()).hexdigest() == saved_hash
    assert not Path("/var/lib/sentinel/update-jobs").exists()
    assert channel.attempts == 0 and not channel.errors, channel.errors
    return {"schema": "velstra-real-ota-confirmation-unit-guard/v2", "real_efi_verity": True,
            "phases": phases, "channel_requests": channel.attempts,
            "check_or_stage_called": True, "check_admitted": False, "stage_called": False,
            "refused_check_requests": {"api_http": 409, "cli_exit": cli.returncode},
            "all_selected_checks_passed": True,
            "short_cas_or_native_stage_certified": False, "production_release_certified": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sentinel", required=True)
    parser.add_argument("--fault-sentinel", required=True)
    arguments = parser.parse_args()
    with ChannelTripwire() as channel:
        proof = exercise(arguments.sentinel, arguments.fault_sentinel, channel)
    print(json.dumps(proof))


if __name__ == "__main__":
    main()
