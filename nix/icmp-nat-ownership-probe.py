"""Disposable ICMP NAT ownership diagnostic; never run against live appliances.

Seeds at most eight exact keys after a verified, disjoint positive-control flow.
It does not remove entries, change map capacities, or provide expiry cleanup.
The fixture restarts the real agent between cases and verifies new map IDs.
"""

import argparse
import ctypes
import errno
import ipaddress
import json
import os
from pathlib import Path
import platform
import socket
import struct
import subprocess
import time


SOURCE = "198.18.20.50"
PUBLIC = "198.18.10.100"
REMOTE = "198.18.10.254"
IDENTIFIER = 43000
CONTROL_IDENTIFIER = 43111
KEY = struct.Struct("<I4s4sHHB3x")
VALUE = struct.Struct("<4s4sHHHHQQQQ")
CASES = ("clean", "own-later", "foreign-live", "foreign-expired", "wrong-flags", "secondary")
MARKER = Path("/run/qa-icmp-disposable")


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def address(value):
    return ipaddress.IPv4Address(value).packed


def seed(source=SOURCE, remote=REMOTE, identifier=IDENTIFIER):
    src, dst = int(ipaddress.IPv4Address(source)), int(ipaddress.IPv4Address(remote))
    value = src ^ (((dst << 16) | (dst >> 16)) & 0xffffffff) ^ (identifier << 16)
    value ^= value >> 16
    value = value * 0x7feb352d & 0xffffffff
    value ^= value >> 15
    value = value * 0x846ca68b & 0xffffffff
    return value ^ (value >> 16)


def candidates(identifier=IDENTIFIER):
    hashed = seed(identifier=identifier)
    return [32768 + (((hashed + probe) & 0xffffffff) % 32768) for probe in range(8)]


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    value = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while value >> 16:
        value = (value & 0xffff) + (value >> 16)
    return (~value) & 0xffff


def echo(identifier, nonce):
    need(type(identifier) is int and 0 <= identifier <= 65535, "invalid ICMP identifier")
    need(isinstance(nonce, str) and len(nonce) >= 16 and nonce.isascii(), "explicit ASCII nonce required")
    body = struct.pack("!BBHHH", 8, 0, 0, identifier, 1) + nonce.encode("ascii")
    return body[:2] + struct.pack("!H", checksum(body)) + body[4:]


def packet(raw, nonce):
    if len(raw) < 28 or raw[0] >> 4 != 4 or raw[9] != 1:
        return None
    offset = (raw[0] & 15) * 4
    total = struct.unpack_from("!H", raw, 2)[0]
    if offset < 20 or total > len(raw) or total < offset + 8:
        return None
    icmp = raw[offset:total]
    if icmp[8:] != nonce.encode("ascii"):
        return None
    kind, code, _, identifier, sequence = struct.unpack("!BBHHH", icmp[:8])
    return dict(source=str(ipaddress.IPv4Address(raw[12:16])),
                target=str(ipaddress.IPv4Address(raw[16:20])), kind=kind, code=code,
                identifier=identifier, sequence=sequence, checksum_valid=checksum(icmp) == 0)


class Element(ctypes.Structure):
    _fields_ = [("map_fd", ctypes.c_uint32), ("pad", ctypes.c_uint32),
                ("key", ctypes.c_uint64), ("value", ctypes.c_uint64),
                ("flags", ctypes.c_uint64)]


class Kernel:
    def __init__(self, map_id):
        need(platform.machine() == "x86_64" and os.geteuid() == 0, "disposable x86_64 root VM required")
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.syscall.restype = ctypes.c_long
        attr = ctypes.create_string_buffer(struct.pack("<III", map_id, 0, 0))
        self.fd = self.call(14, attr)  # BPF_MAP_GET_FD_BY_ID.

    def call(self, command, attr, missing=False):
        result = self.libc.syscall(321, command, ctypes.byref(attr), ctypes.sizeof(attr))
        if result < 0:
            error = ctypes.get_errno()
            if missing and error == errno.ENOENT:
                return None
            raise OSError(error, os.strerror(error))
        return result

    def lookup(self, key, size=VALUE.size):
        key_buffer, value_buffer = ctypes.create_string_buffer(key), ctypes.create_string_buffer(size)
        attr = Element(map_fd=self.fd, key=ctypes.addressof(key_buffer), value=ctypes.addressof(value_buffer))
        return None if self.call(1, attr, missing=True) is None else value_buffer.raw

    def insert(self, key, value):
        need(len(key) == KEY.size and len(value) == VALUE.size, "invalid fixture key/value ABI")
        key_buffer, value_buffer = ctypes.create_string_buffer(key), ctypes.create_string_buffer(value)
        attr = Element(map_fd=self.fd, key=ctypes.addressof(key_buffer), value=ctypes.addressof(value_buffer), flags=1)
        self.call(2, attr)  # BPF_MAP_UPDATE_ELEM + BPF_NOEXIST, never ANY.

    def close(self):
        os.close(self.fd)


def maps():
    return json.loads(subprocess.run(["bpftool", "-j", "map", "show"], check=True,
                                    capture_output=True, text=True, timeout=10).stdout)


def selected(name):
    found = [info for info in maps() if info.get("name") == name]
    need(len(found) == 1, "actual map identity is missing or ambiguous")
    return found[0]


def validate_metadata(info):
    need(info.get("name") == "CONNTRACK" and info.get("type") == "lru_hash"
         and info.get("bytes_key") == KEY.size and info.get("bytes_value") == VALUE.size
         and info.get("max_entries") == 65536 and type(info.get("id")) is int and info["id"] > 0,
         "actual NAT map differs from the reviewed disposable fixture")


def policy_id():
    info = selected("IFACE_POLICY")
    need(info.get("type") == "hash" and info.get("bytes_key") == info.get("bytes_value") == 4,
         "unexpected actual interface-policy ABI")
    kernel = Kernel(info["id"])
    try:
        value = kernel.lookup(struct.pack("<I", socket.if_nametoindex("eth1")), 4)
        need(value is not None, "WAN has no applied policy")
        policy = struct.unpack("<I", value)[0]
        need(policy != 0, "WAN policy is not explicitly zoned")
        return policy
    finally:
        kernel.close()


def raw_keys(policy, identifier=IDENTIFIER):
    return [KEY.pack(policy, address(REMOTE), address(PUBLIC), 0, port, 1) for port in candidates(identifier)]


def initial_values(case):
    need(case in CASES, "unknown diagnostic case")
    own = address(SOURCE)
    foreign = address("198.18.20.99")
    now = time.monotonic_ns()
    def value(owner, identifier=IDENTIFIER, flags=2, secondary=bytes(4), age=0):
        return VALUE.pack(owner, secondary, identifier, 0, flags, 0, 0, 0, now, age)
    if case == "clean":
        return {}
    if case == "own-later":
        return {7: value(own)}
    if case == "foreign-expired":
        return {index: value(foreign, identifier=IDENTIFIER + 1, age=604_800_000_000_000) for index in range(8)}
    if case == "foreign-live":
        return {index: value(foreign, identifier=IDENTIFIER + 1) for index in range(8)}
    if case == "wrong-flags":
        return {index: value(own, flags=0) for index in range(8)}
    return {index: value(own, secondary=foreign) for index in range(8)}


def seed_map(case):
    need(MARKER.is_file(), "missing disposable-VM mutation permission marker")
    info = selected("CONNTRACK")
    validate_metadata(info)
    existing = json.loads(subprocess.run(["bpftool", "-j", "map", "dump", "id", str(info["id"])],
                                        check=True, capture_output=True, text=True, timeout=10).stdout)
    need(len(existing) == 1, "expected only the verified disjoint positive-control binding")
    policy = policy_id()
    keys, values = raw_keys(policy), initial_values(case)
    kernel = Kernel(info["id"])
    try:
        control_key = raw_keys(policy, CONTROL_IDENTIFIER)[0]
        control = kernel.lookup(control_key)
        need(control is not None and not set(candidates()) & set(candidates(CONTROL_IDENTIFIER)),
             "missing or overlapping positive-control allocation")
        owner = VALUE.unpack(control)
        need(owner[0] == address(SOURCE) and owner[1] == bytes(4)
             and owner[2:6] == (CONTROL_IDENTIFIER, 0, 2, 0), "positive-control owner is not exact")
        need(all(kernel.lookup(key) is None for key in keys), "target candidate window is not empty")
        for index, value in values.items():
            kernel.insert(keys[index], value)
        observed = [kernel.lookup(key) for key in keys]
        need(all(observed[index] == values.get(index) for index in range(8)), "seed ownership mismatch")
        return dict(schema=1, case=case, metadata=info, policy=policy, candidates=candidates(),
                    keys=[key.hex() for key in keys], before=[None if value is None else value.hex() for value in observed],
                    control_key=control_key.hex(), control_value=control.hex())
    finally:
        kernel.close()


def inspect(state):
    info = selected("CONNTRACK")
    validate_metadata(info)
    need(info["id"] == state["metadata"]["id"] and state["candidates"] == candidates()
         and state["keys"] == [key.hex() for key in raw_keys(state["policy"])], "fixture/map identity changed")
    kernel = Kernel(info["id"])
    try:
        observed = [kernel.lookup(bytes.fromhex(key)) for key in state["keys"]]
        control = kernel.lookup(bytes.fromhex(state["control_key"]))
        return dict(metadata=info, after=[None if value is None else value.hex() for value in observed],
                    control_value=None if control is None else control.hex())
    finally:
        kernel.close()


def capture_pending(role, stop, deadline):
    return time.monotonic() < deadline and (role == "client" or not Path(stop).exists())


def traffic(role, nonce, ready, identifier=IDENTIFIER, stop=None):
    need(os.geteuid() == 0, "raw ICMP diagnostic needs disposable VM root")
    need(role == "client" or stop is not None, "listener requires explicit capture completion")
    need(stop is None or not Path(stop).exists(), "stale capture completion marker")
    received = []
    family = socket.AF_PACKET if role == "ingress" else socket.AF_INET
    protocol = socket.htons(0x0800) if role == "ingress" else socket.IPPROTO_ICMP
    with socket.socket(family, socket.SOCK_RAW, protocol) as sock:
        sock.bind(("eth2", 0) if role == "ingress" else (SOURCE if role == "client" else REMOTE, 0))
        if ready:
            Path(ready).write_text("ready\n")
        if role == "client":
            sock.sendto(echo(identifier, nonce), (REMOTE, 0))
        # Listener startup precedes other remote setup commands. Do not let a
        # short independent timer end capture before the client is invoked.
        # The driver closes both captures after the client's unchanged 1s
        # response window; 30s is a hard failure bound, never a success waiver.
        deadline = time.monotonic() + (1.0 if role == "client" else 30.0)
        while capture_pending(role, stop, deadline):
            sock.settimeout(max(.001, min(.05, deadline - time.monotonic())))
            try:
                raw, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue
            item = packet(raw[14:] if role == "ingress" else raw, nonce)
            expected = item is not None and item["kind"] == (0 if role == "client" else 8)
            if expected:
                received.append(item)
        complete = role == "client" or (
            time.monotonic() < deadline and stop is not None and Path(stop).exists())
    return dict(schema=1, role=role, nonce=nonce, packets=received,
                capture_complete=complete)


def echo_delivery(client, backend, ingress, identifier, wire_identifier):
    need(client["nonce"] == backend["nonce"] == ingress["nonce"], "inconsistent traffic receipt")
    replies, requests, entering = client["packets"], backend["packets"], ingress["packets"]
    arrived = len(entering) == 1 and entering[0] == dict(
        source=SOURCE, target=REMOTE, kind=8, code=0, identifier=identifier, sequence=1, checksum_valid=True)
    delivery = len(replies) == 1 and len(requests) == 1 and replies[0] == dict(
        source=REMOTE, target=SOURCE, kind=0, code=0, identifier=identifier, sequence=1, checksum_valid=True)
    translated = len(requests) == 1 and requests[0] == dict(
        source=PUBLIC, target=REMOTE, kind=8, code=0, identifier=wire_identifier, sequence=1, checksum_valid=True)
    return dict(arrived=arrived, delivery=delivery, translated=translated,
                passed=bool(arrived and delivery and translated))


def analyse(state, after, client, backend, ingress):
    case = state["case"]
    need(case in CASES and client["nonce"] == backend["nonce"], "inconsistent traffic receipt")
    need(after["metadata"]["id"] == state["metadata"]["id"], "map replaced within diagnostic")
    wanted = case in ("clean", "own-later")
    port = candidates()[7 if case == "own-later" else 0]
    traffic = echo_delivery(client, backend, ingress, IDENTIFIER, port)
    delivery, translated = traffic["delivery"], traffic["translated"]
    replies, requests = client["packets"], backend["packets"]
    preserved = state["before"] == after["after"]
    control_preserved = state["control_value"] == after["control_value"]
    passed = traffic["passed"] if wanted else (traffic["arrived"] and not replies and not requests and preserved)
    passed = passed and control_preserved
    return dict(case=case, expected_delivery=wanted, passed=bool(passed), exact_echo=delivery,
                expected_wire_identifier=port if wanted else None, wire_translation=translated,
                seeded_raw_values_unchanged=preserved, positive_control_preserved=control_preserved,
                ingress_witness=traffic["arrived"], before=state, after=after,
                client=client, backend=backend, ingress=ingress)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("seed", "inspect", "client", "backend", "ingress"))
    parser.add_argument("--case", choices=CASES)
    parser.add_argument("--state")
    parser.add_argument("--nonce")
    parser.add_argument("--ready")
    parser.add_argument("--stop")
    parser.add_argument("--identifier", type=int, default=IDENTIFIER)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.command == "seed":
        result = seed_map(args.case)
    elif args.command == "inspect":
        result = inspect(json.loads(Path(args.state).read_text()))
    else:
        need(args.nonce is not None and len(args.nonce) >= 16, "explicit nonce required")
        result = traffic(args.command, args.nonce, args.ready, args.identifier, args.stop)
    Path(args.output).write_text(json.dumps(result, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
