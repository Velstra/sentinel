"""Real capacity-gate fixtures. Importing never starts a server or mutates a guest.

The host-only HTTPS reference streams an existing immutable RAW; it never makes
a dense host copy. Guest subcommands run only inside the disposable Nix VM.
No helper substitutes for the product updater, signature gate or boot assessment.
"""
import argparse
import ctypes
import errno
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time

STATE = Path("/var/lib/sentinel")
CHUNK = 1024 * 1024
OUTPUT_LIMIT = 1024 * 1024
MODES = ("good", "bad-signature", "tamper", "cancel")
START_ROOT = Path("/run")
UNITS = ("sentinel-boot", "sentinel-api", "velstra", "wren",
         "velstra-boot-verify", "systemd-bless-boot")


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha_file(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as source:
        while block := source.read(4 * CHUNK):
            result.update(block)
    return result.hexdigest()


def rename_noreplace(directory, source, destination):
    """Linux-only atomic publication; never fall back to replacing rename/link."""
    need(all(isinstance(name, str) and name and "/" not in name and name not in (".", "..")
             for name in (source, destination)), "Relative publication basenames required")
    library = ctypes.CDLL(None, use_errno=True)
    rename = getattr(library, "renameat2", None)
    need(rename is not None, "Atomic no-replace publication is unsupported")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    ctypes.set_errno(0)
    if rename(directory, os.fsencode(source), directory, os.fsencode(destination), 1) != 0:
        code = ctypes.get_errno() or errno.EIO
        raise OSError(code, "Atomic no-replace publication refused", destination)


def private_json(path, value):
    """Publish complete fixture STARTED/result records, never an empty final inode.

    An uncertain failure retains the owned hidden file. Existing final records
    of any type are never replaced, cleaned up, reinterpreted or retried.
    """
    path = Path(path)
    need(path.name in ("started.json", "result.json")
         and path.parent in [START_ROOT / ("qa-capacity-" + label) for label in ("cancel", "tamper", "good")],
         "Unscoped fixture proof publication")
    payload = json.dumps(value, indent=2).encode("utf-8")
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    fd = None
    try:
        parent = os.fstat(directory)
        need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0
             and stat.S_IMODE(parent.st_mode) == 0o700, "Publication parent is not the root0700 fixture directory")
        temporary = ".publish-" + path.name + "-" + secrets.token_hex(16)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | os.O_NONBLOCK | os.O_CLOEXEC, 0o600, dir_fd=directory)

        def identity(metadata):
            need(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and metadata.st_nlink == 1
                 and stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_dev == parent.st_dev,
                 "Publication file is not the owned root0600 single-link regular inode")
            return metadata.st_dev, metadata.st_ino

        original = identity(os.fstat(fd))
        offset = 0
        while offset < len(payload):
            count = os.write(fd, payload[offset:])
            need(0 < count <= len(payload) - offset, "Incomplete private proof write")
            offset += count
        os.fsync(fd)
        complete = os.fstat(fd)
        need(identity(complete) == original and complete.st_size == len(payload),
             "Private proof inode or size changed during write")
        named = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
        need(identity(named) == original and named.st_size == len(payload),
             "Private proof temporary name changed before publication")
        rename_noreplace(directory, temporary, path.name)
        published = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        need(identity(published) == original and published.st_size == len(payload),
             "Published proof identity changed")
        os.fsync(directory)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


class ReleaseServer:
    """Loopback-only TLS reference with immutable paths and explicit modes."""
    def __init__(self, image, envelope, certificate, key, port=28483):
        self.image = Path(image)
        self.envelope = Path(envelope).read_bytes()
        self.mode = "good"
        self.events = []
        self.mutex = threading.Lock()
        self.stopping = threading.Event()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def do_GET(self):
                self.connection.settimeout(15)
                with owner.mutex:
                    mode = owner.mode
                event = {"path": self.path, "mode": mode, "bytes": 0,
                         "complete": False, "TLS": self.connection.version()}
                try:
                    if self.path == "/current/release.json":
                        body = owner.envelope
                        if mode == "bad-signature":
                            import base64
                            data = json.loads(body)
                            signature = bytearray(base64.b64decode(data["signature"], validate=True))
                            signature[-1] ^= 1
                            data["signature"] = base64.b64encode(signature).decode()
                            body = json.dumps(data).encode()
                        self.send_response(200)
                        self.send_header("Content-Length", str(len(body)))
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(body)
                        event.update(bytes=len(body), complete=True)
                    elif self.path == "/current/candidate.raw":
                        length = owner.image.stat().st_size
                        self.send_response(200)
                        self.send_header("Content-Length", str(length))
                        self.send_header("Content-Type", "application/octet-stream")
                        self.end_headers()
                        hasher = hashlib.sha256()
                        with owner.image.open("rb") as source:
                            while not owner.stopping.is_set():
                                block = source.read(CHUNK)
                                if not block:
                                    break
                                if mode == "tamper" and event["bytes"] <= 8 * CHUNK < event["bytes"] + len(block):
                                    changed = bytearray(block)
                                    changed[8 * CHUNK - event["bytes"]] ^= 1
                                    block = bytes(changed)
                                self.wfile.write(block)
                                hasher.update(block)
                                event["bytes"] += len(block)
                                # Give a separate guest observer time to inspect
                                # the REAL anonymous stage, not a mock hook.
                                owner.stopping.wait(0.10 if mode == "cancel" else 0.003)
                        event.update(complete=event["bytes"] == length,
                                     wire_SHA256=hasher.hexdigest())
                    else:
                        self.send_error(404)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLError, TimeoutError):
                    event["disconnected"] = True
                finally:
                    with owner.mutex:
                        owner.events.append(event)
                    self.close_connection = True

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certificate, key)

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def get_request(self):
                connection, address = super().get_request()
                connection.settimeout(15)
                try:
                    return context.wrap_socket(connection, server_side=True), address
                except Exception:
                    connection.close()
                    raise

        self.server = Server(("127.0.0.1", port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def select(self, mode):
        need(mode in MODES, "Unknown reference mode")
        with self.mutex:
            self.mode = mode
            return len(self.events)

    def observed(self, since=0):
        with self.mutex:
            return list(self.events[since:])

    def close(self):
        self.stopping.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=10)
        need(not self.thread.is_alive(), "TLS reference did not shut down")


def command(*args, check=True, timeout=120):
    result = subprocess.run(args, capture_output=True, timeout=timeout)
    if check:
        need(result.returncode == 0, "Fixture command failed: " + args[0])
    return result


def clean_environment():
    environment = dict(os.environ)
    for name in ("TMPDIR", "TMP", "TEMP"):
        environment.pop(name, None)
    return environment


def process_start(pid):
    # comm may contain spaces/parentheses; fields after its final ')' start at3.
    text = Path(f"/proc/{pid}/stat").read_text()
    return text[text.rfind(")") + 2:].split()[19]


def stage_samples(pid, expected_device):
    samples = []
    for descriptor in Path(f"/proc/{pid}/fd").iterdir():
        try:
            value = descriptor.stat()
            if stat.S_ISREG(value.st_mode) and value.st_nlink == 0 and value.st_dev == expected_device:
                need(value.st_uid == 0 and stat.S_IMODE(value.st_mode) == 0o600,
                     "Actual anonymous stage is not root0600")
                samples.append({"fd": descriptor.name, "logical": value.st_size,
                                "allocated": value.st_blocks * 512,
                                "device": value.st_dev, "inode": value.st_ino})
        except FileNotFoundError:
            continue
    need(len(samples) <= 1, "More than one anonymous image stage")
    return samples


def memory_value(name):
    values = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
    return int(values[name].split()[0]) * 1024


def oom_count():
    return int(dict(line.split() for line in Path("/proc/vmstat").read_text().splitlines())["oom_kill"])


def update_argv(sentinel):
    need(isinstance(sentinel, str) and re.fullmatch(r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/\s]+/bin/sentinel", sentinel),
         "Exact immutable WRAPPED Sentinel executable required")
    return [sentinel, "update", "install", "--commit"]


def spawn_update(sentinel, environment):
    return subprocess.Popen(update_argv(sentinel), stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=environment)


def transfer(label, sentinel):
    """Run/observe the installed CLI; no size/signature/write code is replaced."""
    need(label in ("tamper", "cancel", "good"), "Unscoped transfer label")
    root = Path("/run/qa-capacity-" + label)
    root.mkdir(mode=0o700)  # Exclusive: never repeat an uncertain write.
    environment = clean_environment()
    proc = spawn_update(sentinel, environment)
    output = bytearray()
    failure = []

    def drain():
        try:
            while block := proc.stdout.read(65536):
                need(len(output) + len(block) <= OUTPUT_LIMIT, "Updater output exceeded fixture bound")
                output.extend(block)
        except Exception as error:
            failure.append(type(error).__name__)
            proc.kill()

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    device = STATE.stat().st_dev
    samples = []
    maximum_rss = 0
    initial_shmem = maximum_shmem = memory_value("Shmem")
    initial_oom = oom_count()
    minimum_available = os.statvfs(STATE).f_bavail * os.statvfs(STATE).f_frsize
    started = time.monotonic()
    try:
        while proc.poll() is None:
            need(time.monotonic() - started < 900, "Actual update exceeded gate deadline")
            try:
                maximum_shmem = max(maximum_shmem, memory_value("Shmem"))
                available = os.statvfs(STATE)
                minimum_available = min(minimum_available, available.f_bavail * available.f_frsize)
                live = stage_samples(proc.pid, device)
                if live:
                    samples.extend(live)
                    if not (root / "started.json").exists():
                        private_json(root / "started.json", {
                            "pid": proc.pid, "start_ticks": process_start(proc.pid),
                            "cmdline_hex": Path(f"/proc/{proc.pid}/cmdline").read_bytes().hex(),
                            "parent": os.getpid(), "label": label,
                            "actual_anonymous_stage_seen": True})
                for line in Path(f"/proc/{proc.pid}/status").read_text().splitlines():
                    if line.startswith("VmRSS:"):
                        maximum_rss = max(maximum_rss, int(line.split()[1]) * 1024)
            except FileNotFoundError:
                pass
            time.sleep(0.10)
        reader.join(timeout=15)
        need(not reader.is_alive() and not failure, "Bounded updater output did not drain")
        status = proc.wait(timeout=5)
        private_json(root / "result.json", {
            "exit": status, "samples": samples, "max_RSS": maximum_rss,
            "initial_Shmem": initial_shmem, "maximum_Shmem": maximum_shmem,
            "minimum_state_available": minimum_available,
            "oom_kill_before": initial_oom, "oom_kill_after": oom_count(),
            "seconds": time.monotonic() - started, "output": output.decode(errors="replace"),
            "TMPDIR_TMP_TEMP_unset": all(key not in environment for key in ("TMPDIR", "TMP", "TEMP"))})
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=15)
        reader.join(timeout=15)


def cancel():
    path = Path("/run/qa-capacity-cancel/started.json")
    proof = json.loads(path.read_text())
    need(proof["label"] == "cancel" and proof["actual_anonymous_stage_seen"], "No active cancellation fixture")
    pid = proof["pid"]
    need(isinstance(pid, int) and pid > 1 and process_start(pid) == proof["start_ticks"],
         "Updater PID was reused or finished; do not signal")
    need(Path(f"/proc/{pid}/cmdline").read_bytes().hex() == proof["cmdline_hex"],
         "Updater command changed; do not signal")
    arguments = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    need(b"update" in arguments and b"install" in arguments and b"--commit" in arguments,
         "Cancellation target is not installed update CLI")
    need(stage_samples(pid, STATE.stat().st_dev), "Updater no longer owns its stage; stop")
    os.kill(pid, signal.SIGKILL)  # Owner death exercises actual curl PDEATHSIG.


def pending_curl():
    result = []
    for path in Path("/proc").glob("[0-9]*"):
        try:
            if ((path / "comm").read_text().strip() == "curl" and
                    b"10.0.2.2:28483/current/candidate.raw" in (path / "cmdline").read_bytes()):
                result.append(int(path.name))
        except FileNotFoundError:
            continue
    return result


def snapshot():
    """Hashes only: no private key/config plaintext in the test output."""
    # Reading UKIs used to activate the ESP *after* hashing its raw partition.
    # That mixed an unmounted FAT image with mounted-file observations after
    # idle expiration. Resolve the normal automount first and keep it busy for
    # the complete read-only observation; never manually mount/remount it.
    boot = os.open("/boot/EFI/Linux", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        _snapshot_mounted()
    finally:
        os.close(boot)


def _snapshot_mounted():
    parts = {str(number): sha_file(f"/dev/vda{number}") for number in range(1, 6)}
    private = {}
    for relative in ("appliance.toml", "ssh", "web-tls", "archive"):
        path = STATE / relative
        if path.is_file():
            private[relative] = sha_file(path)
        elif path.is_dir():
            for item in sorted(path.rglob("*")):
                if item.is_file() and not item.is_symlink():
                    private[str(item.relative_to(STATE))] = sha_file(item)
    table = json.loads(command("sfdisk", "--json", "/dev/vda").stdout)
    ukis = {item.name: sha_file(item) for item in sorted(Path("/boot/EFI/Linux").glob("sentinel-*.efi"))}
    size = int(command("blockdev", "--getsize64", "/dev/vda").stdout)
    headers = []
    with Path("/dev/vda").open("rb") as source:
        for start, length in ((0, 34 * 512), (size - 33 * 512, 33 * 512)):
            source.seek(start)
            headers.append(hashlib.sha256(source.read(length)).hexdigest())
    print(json.dumps({"parts": parts, "private": private, "GPT": table, "UKIs": ukis,
                      "GPT_headers": headers, "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                      "machine_id_SHA256": sha_file("/etc/machine-id")}))


def visible_ext4_mount(path, expected_device):
    # Pinned2.42.3 actually returns BOTH stacked mounts for --target alone.
    # Explicit kernel+uniq removes hidden targets; independently bind the row
    # to the owned loop device instead of trusting result order or source text.
    need(type(expected_device) is int and expected_device > 0, "Actual owned fixture device required")
    raw = command("findmnt", "--kernel=mountinfo", "--json", "--uniq", "--target", str(path),
                  "--output", "TARGET,FSTYPE,SOURCE,MAJ:MIN,ID").stdout
    print("QA_CAPACITY_VISIBLE_MOUNT " + repr(raw[:4096]), file=sys.stderr, flush=True)
    need(len(raw) <= 4096, "Visible-mount observation exceeded its bound")
    rows = json.loads(raw).get("filesystems")
    need(isinstance(rows, list) and len(rows) == 1, "Expected exactly one visible filesystem")
    row = rows[0]
    need(isinstance(row, dict) and row.get("target") == str(path)
         and row.get("fstype") == "ext4" and isinstance(row.get("source"), str)
         and row["source"] and not row.get("children")
         and row.get("maj:min") == f"{os.major(expected_device)}:{os.minor(expected_device)}"
         and type(row.get("id")) is int and row["id"] > 0,
         "Fixture is not the exact visible ext4 mount")
    return row


def bounded_command(argv, timeout=5, maximum=16384):
    """Only fixture-owned observations. Bound BOTH pipes and reap only our child."""
    result = {"exit": None, "stdout": b"", "stderr": b"", "error": None}
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env={"LC_ALL": "C", "SYSTEMD_COLORS": "0"})
    except OSError as error:
        result["error"] = "spawn-" + type(error).__name__
        return result
    began = time.monotonic()
    total = 0
    try:
        with selectors.DefaultSelector() as selector:
            for name in ("stdout", "stderr"):
                stream = getattr(child, name)
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = timeout - (time.monotonic() - began)
                if remaining <= 0:
                    result["error"] = "timeout"
                    break
                for key, _event in selector.select(min(remaining, 0.05)):
                    try:
                        block = os.read(key.fd, 4096)
                    except BlockingIOError:
                        continue
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    kept = block[:max(0, maximum - total)]
                    result[key.data] += kept
                    total += len(kept)
                    if len(kept) != len(block):
                        result["error"] = "output-limit"
                        break
                if result["error"]:
                    break
        if result["error"] is None:
            try:
                result["exit"] = child.wait(timeout=max(0.001, timeout - (time.monotonic() - began)))
            except subprocess.TimeoutExpired:
                result["error"] = "timeout"
    except Exception as error:
        result["error"] = "observation-" + type(error).__name__
    finally:
        if child.poll() is None:
            try:
                child.kill()
            except ProcessLookupError:
                pass  # The exact owned child exited between poll and kill.
            except OSError as error:
                result["error"] = "owned-observer-kill-" + type(error).__name__
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            result["error"] = "owned-observer-teardown-unknown"
        for stream in (child.stdout, child.stderr):
            stream.close()
    return result


def display_observation(result):
    return {"exit": result["exit"], "error": result["error"],
            "stdout_prefix": repr(result["stdout"][:4096]),
            "stderr_prefix": repr(result["stderr"][:4096]),
            "captured_stdout_bytes": len(result["stdout"]), "captured_stderr_bytes": len(result["stderr"])}


def unit_properties(result):
    need(result["error"] is None and result["exit"] == 0,
         "Unit transport/query failed; completion is unknown")
    values = {}
    for line in result["stdout"].decode("utf-8", errors="strict").splitlines():
        key, separator, value = line.partition("=")
        need(separator and key not in values, "Malformed/duplicate unit properties")
        values[key] = value
    need(set(values) == {"LoadState", "ActiveState", "Result", "ExecMainCode", "ExecMainStatus", "MainPID", "InvocationID"},
         "Incomplete/foreign unit properties")
    need(values["LoadState"] == "loaded" and values["ActiveState"] in ("active", "activating"),
         "Transfer service is terminal or unavailable before stage observation")
    need(all(re.fullmatch(r"[0-9]{1,16}", values[key])
             for key in ("MainPID", "ExecMainCode", "ExecMainStatus"))
         and (values["InvocationID"] == "" or re.fullmatch(r"[a-f0-9]{32}", values["InvocationID"])),
         "Transfer service has malformed process identity")
    need(values["Result"] == "success", "Transfer service has already reported an error")
    if values["ActiveState"] == "active":
        need(int(values["MainPID"]) > 1 and values["InvocationID"],
             "Active transfer has no exact running process identity")
    return values


def started_record(label, unit):
    path = START_ROOT / ("qa-capacity-" + label) / "started.json"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as source:
        metadata = os.fstat(source.fileno())
        need(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and metadata.st_nlink == 1
             and stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_size <= 8192,
             "Started proof is not the protected bounded fixture record")
        proof = json.loads(source.read(8193))
    need(proof["label"] == label and proof["actual_anonymous_stage_seen"] is True
         and type(proof["pid"]) is int and proof["pid"] > 1
         and proof["parent"] == int(unit["MainPID"]), "Started proof is not owned by this transfer service")
    need(process_start(proof["pid"]) == proof["start_ticks"]
         and Path(f"/proc/{proof['pid']}/cmdline").read_bytes().hex() == proof["cmdline_hex"]
         and stage_samples(proof["pid"], STATE.stat().st_dev),
         "Started updater identity or actual anonymous stage changed")
    return proof


def result_diagnostic(label):
    path = START_ROOT / ("qa-capacity-" + label) / "result.json"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return {"present": False}
    with os.fdopen(fd, "rb") as source:
        metadata = os.fstat(source.fileno())
        need(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
             and stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_nlink == 1,
             "Unsafe transfer result diagnostic")
        need(metadata.st_size <= 4 * OUTPUT_LIMIT, "Transfer result exceeds diagnostic read bound")
        result = json.loads(source.read(4 * OUTPUT_LIMIT + 1))
    output = result.get("output", "")
    need(isinstance(output, str), "Transfer result output is not text")
    return {"present": True, "exit": result.get("exit"),
            "product_stdout_stderr_merged_prefix": output[:4096], "output_characters": len(output)}


def wait_started(label, systemctl, journalctl, timeout=90):
    need(label in ("cancel", "tamper", "good"), "Unscoped startup observation")
    for executable, name in ((systemctl, "systemctl"), (journalctl, "journalctl")):
        need(re.fullmatch(r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/\s]+/bin/" + name, executable),
             "Pinned immutable observation tool required")
    unit = "qa-capacity-" + label + ".service"
    last = {"exit": None, "error": "not-observed", "stdout": b"", "stderr": b""}
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            last = bounded_command([systemctl, "show", "--property=LoadState,ActiveState,Result,ExecMainCode,ExecMainStatus,MainPID,InvocationID", unit])
            properties = unit_properties(last)
            proof = started_record(label, properties) if int(properties["MainPID"]) > 1 else None
            if proof is not None:
                return proof
            time.sleep(0.1)
        raise RuntimeError("No actual anonymous stage observed before the fixed startup deadline")
    except Exception as error:
        journal = bounded_command([journalctl, "--unit=" + unit, "--no-pager", "--output=short-precise", "--lines=20"])
        try:
            result = result_diagnostic(label)
        except Exception as diagnostic_error:
            result = {"error": type(diagnostic_error).__name__}
        diagnostic = {"reason": str(error), "unit": unit, "show": display_observation(last),
                      "journal": display_observation(journal), "result": result,
                      "started_proof_not_fabricated": True}
        print("QA_CAPACITY_STARTUP_REFUSED " + json.dumps(diagnostic), file=sys.stderr, flush=True)
        raise RuntimeError("Actual transfer startup refused; see bounded observation diagnostics") from error


def low_space(original_namespace, sentinel=None):
    """A bounded128MiB ext4 fixture in a PRIVATE mount namespace, never the DUT's
    real state filesystem or a full-volume-fill experiment. The real product
    sees the same saved channel but genuine insufficient persistent capacity.
    """
    need(isinstance(original_namespace, str) and re.fullmatch(r"mnt:\[\d+\]", original_namespace),
         "Explicit original mount namespace required")
    need(os.readlink(f"/proc/{os.getppid()}/ns/mnt") == original_namespace and
         os.readlink("/proc/self/ns/mnt") != original_namespace,
         "Private child mount namespace required")
    need(command("findmnt", "-n", "-o", "SOURCE", str(STATE)).stdout.strip() == b"/dev/vda6",
         "Unexpected original state; do not overlay it")
    command("mount", "--make-rprivate", "/")
    configuration = (STATE / "appliance.toml").read_bytes()
    original_state_device = STATE.stat().st_dev
    root = Path(tempfile.mkdtemp(prefix="qa-capacity-low-", dir="/run"))
    os.chmod(root, 0o700)
    image = root / "state.ext4"
    mounted = bound = False
    image_identity = None
    try:
        fd = os.open(image, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.truncate(128 * 1024 * 1024)
        image_identity = image.stat().st_ino
        need(stat.S_ISREG(image.stat().st_mode) and image.stat().st_nlink == 1,
             "Owned bounded fixture file required")
        command("mkfs.ext4", "-q", "-F", str(image))
        mount = root / "mounted"
        mount.mkdir(mode=0o700)
        command("mount", "-t", "ext4", "-o", "loop,nodev,nosuid,noexec", str(image), str(mount))
        mounted = True
        (mount / "appliance.toml").write_bytes(configuration)
        os.chmod(mount / "appliance.toml", 0o600)
        command("mount", "--bind", str(mount), str(STATE))
        bound = True
        need((STATE / "appliance.toml").read_bytes() == configuration, "Capacity fixture changed saved config")
        actual_mount = visible_ext4_mount(STATE, mount.stat().st_dev)
        need(STATE.stat().st_dev == mount.stat().st_dev
             and STATE.stat().st_dev != original_state_device,
             "Private overlay does not serve the actual bounded fixture filesystem")
        result = subprocess.run(update_argv(sentinel), stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=120, env=clean_environment())
        text = (result.stdout + result.stderr).decode(errors="replace")
        need(result.returncode != 0 and "insufficient persistent update staging capacity" in text,
             "Actual product did not refuse the real bounded ext4 capacity")
        need("image SHA-256 verified" not in text, "Low-capacity case reached image verification unexpectedly")
        print(json.dumps({"exit": result.returncode, "output": text,
                          "bounded_fixture_bytes": 128 * 1024 * 1024,
                          "private_mount_namespace": True, "original_state_filled": False,
                          "visible_fixture_mount": actual_mount,
                          "actual_bounded_device_differs_from_original": True}))
    finally:
        # Never delete a mounted tree. Failure retains the bounded fixture for
        # VM inspection instead of force-unmounting or recursively deleting it.
        if bound:
            command("umount", str(STATE))
        if mounted:
            command("umount", str(root / "mounted"))
        if image.exists():
            need(image.stat().st_ino == image_identity and image.stat().st_nlink == 1,
                 "Fixture inode changed; do not remove")
            image.unlink()
        if (root / "mounted").exists():
            (root / "mounted").rmdir()
        root.rmdir()


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sentinel", required=True)
    parser.add_argument("--systemctl", required=True)
    parser.add_argument("--journalctl", required=True)
    parser.add_argument("action", choices=("transfer", "cancel", "snapshot", "low-space", "no-curl", "wait-start"))
    parser.add_argument("value", nargs="?")
    args = parser.parse_args()
    if args.action == "transfer":
        transfer(args.value, args.sentinel)
    elif args.action == "cancel":
        cancel()
    elif args.action == "snapshot":
        snapshot()
    elif args.action == "no-curl":
        need(not pending_curl(), "Cancelled updater left a live curl")
    elif args.action == "wait-start":
        print(json.dumps(wait_started(args.value, args.systemctl, args.journalctl)))
    else:
        low_space(args.value, args.sentinel)
