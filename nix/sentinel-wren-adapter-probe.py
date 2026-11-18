"""Installed Sentinel static-only adapter: acknowledged success and real failure.

No daemon/RPC mock or injected errno. A syntactically valid route through an
off-link gateway reaches Wren's real kernel backend, remains pending, and must
fail the Sentinel operation. Prior daemon restart is deliberately retained for
rollback; a timed-out routing generation is not cancellation. Packets here are
locally originated ICMP, not a substitute for transit/HA qualification.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
import tomllib
from typing import Any
import urllib.request

ROOT = Path("/run/qa-wren-adapter")
FILES = tuple(Path(path) for path in (
    "/run/sentinel/wren.toml", "/run/sentinel/velstra.toml",
    "/run/sentinel/running.toml", "/var/lib/sentinel/appliance.toml"))
SOCKET = "/run/wren/wren.sock"
PREFIXES = ("198.19.244.1/32", "198.19.244.129/32", "198.19.244.200/32")
BAD = PREFIXES[2]
GATEWAY = "10.10.0.2"
OFFLINK = "192.0.2.254"


def run(*args, timeout=10, check=True):
    return subprocess.run(args, text=True, capture_output=True, timeout=timeout, check=check)


def status(text=None):
    if text is None:
        text = run("wren", "--socket", SOCKET, "show", "reload").stdout
    fields = {}
    for line in text.splitlines():
        key, sep, value = line.partition(" ")
        assert sep and key not in fields and key in {
            "scope", "generation", "state", "pending-prefixes", "detail"}, text
        fields[key] = value
    assert {"scope", "generation", "state", "pending-prefixes"} <= fields.keys(), text
    assert fields["scope"] == "routing" and fields["state"] in {
        "pending", "converged", "rejected", "superseded"}, text
    for key in ("generation", "pending-prefixes"):
        assert fields[key].isascii() and fields[key].isdecimal(), text
        fields[key] = int(fields[key])
    assert fields["state"] != "converged" or fields["pending-prefixes"] == 0, text
    return fields


def pid():
    value = int(run("systemctl", "show", "--property=MainPID", "--value", "wren.service").stdout)
    assert value > 0, "Wren is not running"
    return value


def monitor():
    deadline = time.monotonic() + 5
    payload = bytearray()
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(5)
        connection.connect(SOCKET)
        connection.sendall(b"monitor routes\n")
        while b"% end-of-dump\n" not in payload:
            remaining = deadline - time.monotonic()
            assert remaining > 0, "monitor deadline"
            connection.settimeout(remaining)
            chunk = connection.recv(4096)
            assert chunk, "monitor closed without complete observed snapshot"
            payload.extend(chunk)
            assert len(payload) <= 65536, "monitor output cap"
    lines = payload.decode().splitlines()
    assert lines[-1] == "% end-of-dump", lines
    return lines[:-1]


def inventory():
    return {prefix: json.loads(run("ip", "-details", "-j", "-4", "route", "show",
                                  "table", "main", "exact", prefix).stdout)
            for prefix in PREFIXES}


def validate_routes(observed, foreign, active):
    assert set(observed) == set(PREFIXES) and set(foreign) == set(PREFIXES)
    assert active is None or active in PREFIXES[:2], active
    for prefix in PREFIXES:
        routes = observed[prefix]
        assert [item for item in routes if item.get("protocol") != "static"] == foreign[prefix], (
            "foreign route identity changed", prefix, routes)
        owned = [item for item in routes if item.get("protocol") == "static"]
        if prefix != active:
            assert not owned, ("unexpected owned route", prefix, owned)
        else:
            assert len(owned) == 1, (prefix, owned)
            route = owned[0]
            assert (ipaddress.ip_network(route.get("dst", "0.0.0.0/0")) == ipaddress.ip_network(prefix)
                    and route.get("gateway") == GATEWAY
                    and route.get("dev") == "eth1" and route.get("metric") == 10
                    and route.get("type", "unicast") == "unicast"), route


def observe(foreign, active):
    # No wait-for-success after an acknowledgement. Reads immediately following
    # the receipt must already agree; this is not a cross-system atomic snapshot.
    routes = inventory()
    validate_routes(routes, foreign, active)
    snapshot = monitor()
    expected = [] if active is None else [f"+ {active} table 254 via {GATEWAY} dev eth1 proto static metric 10"]
    assert snapshot == expected, ("monitor disagrees with exact FIB", snapshot, expected)
    packets = {}
    for prefix in PREFIXES:
        result = run("ping", "-c", "1", "-W", "1", prefix.split("/")[0], timeout=3, check=False)
        assert (result.returncode == 0) == (prefix == active), (prefix, result.stdout, result.stderr)
        packets[prefix] = {"returncode": result.returncode, "stdout": result.stdout}
    return {"routes": routes, "monitor": snapshot, "packets": packets}


def bytes_snapshot():
    return {str(path): path.read_bytes() for path in FILES}


def hashes(snapshot):
    return {path: hashlib.sha256(data).hexdigest() for path, data in snapshot.items()}


def command(actor):
    assert actor in {"root", "admin"}, actor
    return (["sudo", "-u", "admin", "--"] if actor == "admin" else []) + ["sentinel", "configure"]


def configure(lines, actor="root"):
    result = subprocess.run(command(actor), input="\n".join([*lines, "exit", ""]),
                            capture_output=True, text=True, timeout=90)
    output = result.stdout + result.stderr
    assert result.returncode == 0 and "commit failed" not in output.lower(), output
    return output


def request(path, *, script=None, body=None):
    assert script is None or body is None
    token = Path("/var/lib/sentinel/api-token").read_text().strip()
    assert token, "missing machine token"
    data = script.encode() if script is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request("http://127.0.0.1:8080/api/v1/" + path, data=data,
        headers={"Authorization": "Bearer " + token,
                 "Content-Type": "text/plain" if script is not None else "application/json"})
    with urllib.request.urlopen(req, timeout=10) as response:
        encoded = response.read(65537)
        assert len(encoded) <= 65536, "HTTP output cap"
        return json.loads(encoded)


def lines_for(active, previous):
    lines = [] if previous is None else [f"delete protocols static {previous}"]
    return [*lines, f"set protocols static {active} via {GATEWAY}",
            f"set protocols static {active} dev eth1", f"set protocols static {active} metric 10", "commit"]


def validate_static_document(document, active, *, compiled):
    routes = (document if compiled else document.get("protocols", {})).get("static", [])
    assert len(routes) == 1, ("configuration lost or duplicated static intent", routes)
    expected = {"prefix": active, "via": GATEWAY, "dev": "eth1", "metric": 10}
    assert all(routes[0].get(key) == value for key, value in expected.items()), routes
    assert not routes[0].get("blackhole", False) and routes[0].get("vrf") is None, routes


def success_case(actor, active, previous, foreign):
    before_pid, before_status = pid(), status()
    assert before_status["state"] == "converged", before_status
    lines = lines_for(active, previous)
    if actor == "API":
        admitted = request("configure", script="\n".join(lines) + "\n")
        identity = admitted["pending"]["id"]
        deadline = time.monotonic() + 60
        while True:
            receipt = request("config/transaction")
            pending = receipt["pending"]
            assert pending is not None and pending["id"] == identity, receipt
            if pending["ready"]:
                break
            assert time.monotonic() < deadline, receipt
            time.sleep(0.1)
    else:
        receipt = {"output": configure([*lines, "save"], actor)}
    current = status()
    assert current["state"] == "converged" and current["generation"] == before_status["generation"] + 1, current
    assert pid() == before_pid, "static-only success restarted the daemon"
    proof = observe(foreign, active)
    if actor == "API":
        confirmed = request("config/confirm", body={"id": identity})
        assert confirmed["confirmed"] is True, confirmed
        assert confirmed["revision"] == admitted["pending"]["revision"], confirmed
        assert request("config/transaction")["pending"] is None
        receipt["confirmation"] = confirmed
    for path in (FILES[0], FILES[2], FILES[3]):
        validate_static_document(tomllib.loads(path.read_text()), active, compiled=path == FILES[0])
    return {"actor": actor, "operation": "static-success", "passed": True,
            "pid": before_pid, "generation": current, "receipt": receipt,
            "confirmed_file_hashes": hashes(bytes_snapshot()), **proof}


def pending_evidence(baseline, baseline_pid, generation):
    current = status()
    if current["generation"] == generation and current["state"] == "converged":
        return None
    assert current["generation"] == generation + 1 and current["state"] == "pending", current
    assert current["pending-prefixes"] > 0 and pid() == baseline_pid, current
    old = tomllib.loads(baseline[str(FILES[0])].decode())
    candidate = tomllib.loads(FILES[0].read_text())
    old_static, new_static = old.pop("static", []), candidate.pop("static", [])
    assert old == candidate, "candidate unexpectedly widened beyond static-only reload"
    added = [item for item in new_static if item not in old_static]
    assert len(added) == 1 and added[0]["prefix"] == BAD and added[0]["via"] == OFFLINK, added
    assert added[0]["dev"] == "eth1" and added[0]["metric"] == 10, added
    assert all(item in new_static for item in old_static), "prior static routes removed by setup"
    checked = run("wren", "--config", str(FILES[0]), "check")
    return {"generation": current, "pid": baseline_pid, "candidate_sha256": hashes(bytes_snapshot())[str(FILES[0])],
            "candidate_static": new_static, "check_returncode": checked.returncode}


def failure_case(actor, active, foreign):
    baseline, before_pid, before_status = bytes_snapshot(), pid(), status()
    assert before_status["state"] == "converged", before_status
    lines = [f"set protocols static {BAD} via {OFFLINK}", f"set protocols static {BAD} dev eth1",
             f"set protocols static {BAD} metric 10", "commit"]
    process = None
    evidence = None
    output_path = ROOT / (actor.lower() + "-failed-configure.log")
    deadline = time.monotonic() + 90
    try:
        if actor == "API":
            admitted = request("configure", script="\n".join(lines) + "\n")
            identity = admitted["pending"]["id"]
        else:
            with output_path.open("wb") as output:
                process = subprocess.Popen(command(actor), stdin=subprocess.PIPE,
                    stdout=output, stderr=output, text=True, start_new_session=True)
            assert process.stdin is not None
            process.stdin.write("\n".join([*lines, "exit", ""]))
            process.stdin.close()
        while True:
            if actor == "API":
                receipt = request("config/transaction")
                outcome = receipt.get("last_result") or {}
                if receipt["pending"] is None and outcome.get("id") == identity:
                    assert outcome["outcome"] == "apply-failed", receipt
                    break
            else:
                assert process is not None
                if process.poll() is not None:
                    assert process.returncode != 0, "uninstallable route was acknowledged successfully"
                    assert output_path.stat().st_size <= 262144, "CLI output cap"
                    output = output_path.read_text()
                    assert "rolled back to the previous running config" in output, output
                    assert "ROLLBACK INCOMPLETE" not in output, output
                    receipt = {"returncode": process.returncode, "output": output}
                    break
            if evidence is None:
                evidence = pending_evidence(baseline, before_pid, before_status["generation"])
            assert time.monotonic() < deadline, "candidate outcome deadline"
            time.sleep(0.1)
        assert evidence is not None, "no actual pending off-link generation was observed"
        assert bytes_snapshot() == baseline, "automatic rollback did not restore exact prior files"
        restored_pid = pid()
        assert restored_pid != before_pid, "timed-out generation not terminated by rollback restart"
        restored_status = status()
        assert restored_status == {"scope": "routing", "generation": 0,
                                   "state": "converged", "pending-prefixes": 0}, restored_status
        assert run("sentinel", "service-readiness", "wren.service").stdout.strip() == "ready"
        assert run("sentinel", "service-readiness", "velstra.service").stdout.strip() == "ready"
        proof = observe(foreign, active)
        return {"actor": actor, "operation": "real-offlink-failure", "passed": True,
                "before_pid": before_pid, "restored_pid": restored_pid,
                "baseline_hashes": hashes(baseline), "pending_evidence": evidence,
                "receipt": receipt, "restored_generation": restored_status, **proof}
    finally:
        # Only the owned CLI process group; no daemon or unrelated process kill.
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def validate_adapter(unit):
    reloads = [line.removeprefix("ExecReload=") for line in unit.splitlines() if line.startswith("ExecReload=")]
    assert len(reloads) == 2, ("unexpected ExecReload chain", reloads)
    executable, *check_args = reloads[0].split()
    other, *reload_args = reloads[1].split()
    assert executable.startswith("/nix/store/") and executable.endswith("/bin/wren"), executable
    assert other == executable and check_args == ["--config", "/run/sentinel/wren.toml", "check"], reloads
    assert reload_args == ["--socket", SOCKET, "reload"], reloads
    return reloads


def validate_topology(addresses):
    assert len(addresses) == 1 and addresses[0]["ifname"] == "eth1", addresses
    ipv4 = [ipaddress.ip_interface(f"{item['local']}/{item['prefixlen']}")
            for item in addresses[0]["addr_info"] if item["family"] == "inet"]
    assert ipaddress.ip_interface("10.10.0.1/24") in ipv4, ipv4
    assert not any(ipaddress.ip_address(OFFLINK) in item.network for item in ipv4), (
        "fault gateway is on-link; invalid negative setup", ipv4)


def main():
    ROOT.mkdir(mode=0o700, exist_ok=True)
    report: dict[str, Any] = {"passed": False, "cases": [], "scope": "paired static-only Sentinel/Wren adapter"}
    try:
        report["adapter"] = validate_adapter(run("systemctl", "cat", "wren.service").stdout)
        configure([
            "set firewall global default-action accept", "set interface eth1 zone wan",
            "set interface eth1 address 10.10.0.1/24", "set system hostname fw-adapter",
            "set protocols router-id 192.0.2.1", "set services web enable true",
            "set services web tls false", "set services web listen-address 127.0.0.1",
            "commit", "save"])
        validate_topology(json.loads(run("ip", "-j", "address", "show", "dev", "eth1").stdout))
        for prefix in PREFIXES:
            run("ip", "-4", "route", "add", "unreachable", prefix, "proto", "boot", "metric", "32000")
        foreign = inventory()
        assert all(len(value) == 1 and value[0].get("protocol") == "boot"
                   and value[0].get("type") == "unreachable" for value in foreign.values()), foreign
        report["initial_negative"] = observe(foreign, None)
        previous = None
        for actor, active in (("root", PREFIXES[0]), ("admin", PREFIXES[1]), ("API", PREFIXES[0])):
            report["active_case"] = actor + "/success"
            report["cases"].append(success_case(actor, active, previous, foreign))
            report["active_case"] = actor + "/failure"
            report["cases"].append(failure_case(actor, active, foreign))
            previous = active
        report["passed"] = True
    except Exception as error:
        report["error"] = str(error)
        if isinstance(error, subprocess.CalledProcessError):
            report["command_error"] = {"returncode": error.returncode, "stdout": error.stdout, "stderr": error.stderr}
        raise
    finally:
        (ROOT / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        journal = run("journalctl", "-u", "wren.service", "--no-pager", "-n", "300", check=False)
        (ROOT / "wren-journal.txt").write_text(journal.stdout)


if __name__ == "__main__":
    main()
