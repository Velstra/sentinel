"""Read-only product readiness gate for an immutable Sentinel boot trial."""
from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
import tomllib

BOOT_COUNT = Path("/sys/firmware/efi/efivars/LoaderBootCountPath-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f")


def trial_boot(path: Path = BOOT_COUNT) -> bool:
    """Never reboot a permanent install solely because a later config is bad."""
    try:
        # efivarfs prefixes the UTF-16 value with four attribute bytes.
        value = path.read_bytes()[4:].decode("utf-16-le").rstrip("\0")
        return re.fullmatch(r"[\\/]EFI[\\/]Linux[\\/][^\\/]+\+\d+-\d+\.efi", value) is not None
    except (OSError, UnicodeError):
        return False


def dataplane_enabled(path: Path) -> bool:
    interfaces = tomllib.loads(path.read_text())["interface"]
    if not isinstance(interfaces, list) or any(
            not isinstance(interface, dict) or not interface.get("name")
            or type(interface.get("policy")) is not int for interface in interfaces):
        raise ValueError("invalid compiled interface bindings")
    return bool(interfaces)


def query(path: str, request: bytes | None = None) -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(1)
        connection.connect(path)
        if request is None:
            return b""
        connection.sendall(request + b"\n")
        response = bytearray()
        while len(response) < 65536:
            chunk = connection.recv(min(4096, 65536 - len(response)))
            if not chunk:
                return bytes(response)
            response.extend(chunk)
        raise ValueError("oversized readiness response")


def link_failures(desired: dict, compiled: dict, links: list[dict]) -> list[str]:
    actual = {link["ifname"]: link for link in links}
    failures = []
    for interface in desired.get("interface", []):
        if interface.get("disabled", False):
            continue
        name = interface["name"]
        if name not in actual:
            failures.append(f"{name}: configured interface is missing")
            continue
        addresses = actual[name].get("addr_info", [])
        for field in ("address", "address6"):
            value = interface.get(field)
            # No carrier/DHCP server is required to bless an offline appliance.
            if not value or value in ("dhcp", "auto", "dhcp6"):
                continue
            expected = ipaddress.ip_interface(value)
            if not any(ipaddress.ip_address(address["local"]) == expected.ip
                       and address["prefixlen"] == expected.network.prefixlen
                       and not address.get("tentative", False)
                       and not address.get("dadfailed", False) for address in addresses):
                failures.append(f"{name}: configured {field} is not reconciled")
    for interface in compiled.get("interface", []):
        name = interface["name"]
        link = actual.get(name, {})
        xdp = link.get("xdp", {})
        # Pinned iproute2 uses numeric mode (1=driver, 2=generic, 3=offload),
        # with an attached array, NOT the textual mode printed by `ip link`.
        program = xdp.get("prog", {}).get("id", 0)
        if xdp.get("mode") not in (1, 2, 3) or type(program) is not int or program <= 0:
            failures.append(f"{name}: XDP attachment is missing")
        if interface.get("activate", False) and "UP" not in link.get("flags", []):
            failures.append(f"{name}: link is still held down")
    return failures


def pending(desired: dict, compiled: dict, systemctl: str, ip: str,
            runtime: Path) -> list[str]:
    units = ["sentinel-boot.service", "wren.service"]
    web = desired.get("services", {}).get("web", {})
    sync = desired.get("system", {}).get("config-sync", {})
    if web.get("enable", False) or sync.get("secret"):
        units.append("sentinel-api.service")
    dataplane = bool(compiled.get("interface", []))
    if dataplane:
        units.append("velstra.service")
    failures = []
    for unit in units:
        result = subprocess.run([systemctl, "is-active", "--quiet", unit],
                                capture_output=True, timeout=2, check=False)
        if result.returncode:
            failures.append(f"{unit}: not active")
    try:
        # Exercise the central router task and consume the reply. A bare
        # connect/close emits an avoidable server warning and cannot detect a
        # live listener whose router task is stuck.
        status = query("/run/wren/wren.sock", b"show vrf").strip()
        if status != b"no vrfs configured" and (not status or status.splitlines()[0].split() != [b"vrf", b"table", b"rd", b"routes"]):
            failures.append("routing control response is not ready")
    except (OSError, ValueError):
        failures.append("routing control socket is unavailable")
    if dataplane:
        try:
            if query("/run/velstra/query.sock", b"status").strip() != b"Ready":
                failures.append("dataplane configuration is not Ready")
        except (OSError, ValueError):
            failures.append("dataplane readiness is unavailable")
    if tomllib.loads(runtime.read_text()) != compiled:
        failures.append("compiled runtime differs from the saved configuration")
    result = subprocess.run([ip, "-j", "-d", "address", "show"],
                            capture_output=True, timeout=3, check=True)
    failures.extend(link_failures(desired, compiled, json.loads(result.stdout)))
    return failures


def verify(config: Path, runtime: Path, sentinel: str, systemctl: str,
           ip: str, timeout: float) -> bool:
    original = config.read_bytes()
    result = subprocess.run([sentinel, "config", "check", str(config)],
                            capture_output=True, timeout=15, check=False)
    if result.returncode:
        print("boot health: saved configuration failed validation", file=sys.stderr)
        return False
    result = subprocess.run([sentinel, "compile", str(config)],
                            capture_output=True, timeout=15, check=True)
    desired = tomllib.loads(original.decode())
    compiled = tomllib.loads(result.stdout.decode())
    deadline = time.monotonic() + timeout
    while True:
        if config.read_bytes() != original:
            print("boot health: configuration changed during assessment", file=sys.stderr)
            return False
        try:
            failures = pending(desired, compiled, systemctl, ip, runtime)
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            # Never echo raw tool output: it may contain configuration secrets.
            failures = ["runtime readiness probe unavailable"]
        if not failures and config.read_bytes() == original:
            print("boot health: saved config, services, links and XDP are ready", flush=True)
            return True
        if time.monotonic() >= deadline:
            print("boot health: " + "; ".join(failures), file=sys.stderr, flush=True)
            return False
        time.sleep(min(0.5, max(0, deadline - time.monotonic())))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["verify", "trial", "dataplane-enabled"])
    parser.add_argument("--config", type=Path, default=Path("/var/lib/sentinel/appliance.toml"))
    parser.add_argument("--runtime", type=Path, default=Path("/run/sentinel/velstra.toml"))
    parser.add_argument("--sentinel", default="sentinel")
    parser.add_argument("--systemctl", default="systemctl")
    parser.add_argument("--ip", default="ip")
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    if not 0 < args.timeout <= 60:
        parser.error("timeout must be greater than zero and at most 60 seconds")
    if args.mode == "trial":
        return 0 if trial_boot() else 1
    try:
        if args.mode == "dataplane-enabled":
            return 0 if dataplane_enabled(args.runtime) else 1
        return 0 if verify(args.config, args.runtime, args.sentinel,
                           args.systemctl, args.ip, args.timeout) else 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("boot health: configuration assessment unavailable", file=sys.stderr)
        # ExecCondition must fail, not skip, on malformed or unreadable state.
        return 255


if __name__ == "__main__":
    raise SystemExit(main())
