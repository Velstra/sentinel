"""Disposable VM regression for read-only firewall expiry classification.

Injects independent directional ages, not a deterministic multicore race.
Only absent, case-specific keys are seeded; never run on a live appliance.
"""

import argparse
import ctypes
import importlib.util
import json
from pathlib import Path
import socket
import struct
import time


KEY = struct.Struct("<I16s16sHHBB2x")
# FirewallState: four replicated fields, then 16 bytes of node-local TCP
# tracking (zero = sequence unknown).
VALUE = struct.Struct("<QQII16x")
SOURCE = "198.18.10.254"
TARGET = "198.18.10.100"
CASES = {"live": 45001, "expired": 45002, "absent": 45003}
MARKER = Path("/run/qa-firewall-expiry-disposable")


def keys(policy, identifier):
    src, dst = socket.inet_aton(SOURCE) + bytes(12), socket.inet_aton(TARGET) + bytes(12)
    return (KEY.pack(policy, src, dst, identifier, 0, 1, 4),
            KEY.pack(policy, dst, src, identifier, 8, 1, 4))


def values(case, now):
    age = 60_000_000_000 if case == "expired" else 0
    return VALUE.pack(now, age, 1, 1), VALUE.pack(now, 0, 1, 0)


def metadata(support):
    info = support.selected("FW_FLOWS")
    support.need(info.get("type") == "lru_hash" and info.get("bytes_key") == KEY.size
                 and info.get("bytes_value") == VALUE.size and info.get("max_entries") == 65536,
                 "unexpected firewall map ABI")
    return info


def state(support, case, seed):
    support.need(MARKER.is_file(), "missing disposable-VM mutation permission marker")
    info = metadata(support)
    kernel = support.Kernel(info["id"])
    pair = keys(support.policy_id(), CASES[case])
    try:
        if seed and case != "absent":
            for key, value in zip(pair, values(case, time.monotonic_ns()), strict=True):
                key_buf, val_buf = ctypes.create_string_buffer(key), ctypes.create_string_buffer(value)
                attr = support.Element(map_fd=kernel.fd, key=ctypes.addressof(key_buf),
                                       value=ctypes.addressof(val_buf), flags=1)
                kernel.call(2, attr)  # BPF_NOEXIST; never overwrite another entry.
        observed = [kernel.lookup(key, VALUE.size) for key in pair]
        return dict(map_id=info["id"], sampled_ns=time.monotonic_ns(), keys=[key.hex() for key in pair],
                    values=[item.hex() if item is not None else None for item in observed])
    finally:
        kernel.close()


def reply(support, identifier, nonce):
    body = struct.pack("!BBHHH", 0, 0, 0, identifier, 1) + nonce.encode("ascii")
    return body[:2] + struct.pack("!H", support.checksum(body)) + body[4:]


def listen(support, nonce, ready, stop):
    support.need(ready and stop and not Path(ready).exists() and not Path(stop).exists(),
                 "fresh explicit capture controls required")
    packets = []
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        sock.bind((TARGET, 0))
        Path(ready).touch()
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not Path(stop).exists():
            sock.settimeout(.05)
            try:
                raw, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue
            item = support.packet(raw, nonce)
            if item is not None:
                packets.append(item)
        return dict(complete=time.monotonic() < deadline and Path(stop).exists(), packets=packets)


def verdict(case, before, after, capture):
    identity = before["map_id"] == after["map_id"] and before["keys"] == after["keys"]
    wanted = dict(source=SOURCE, target=TARGET, kind=0, code=0,
                  identifier=CASES[case], sequence=1, checksum_valid=True)
    delivery = capture["packets"] == ([wanted] if case == "live" else [])
    unchanged = before["values"] == after["values"]
    premise = (before["values"] == [None, None] if case == "absent"
               else all(item is not None for item in before["values"]))
    if case == "expired" and premise:
        _, age, _, _ = VALUE.unpack(bytes.fromhex(before["values"][0]))
        last, reverse_age, _, _ = VALUE.unpack(bytes.fromhex(before["values"][1]))
        premise = (age >= 10_000_000_000 and reverse_age == 0
                   and 0 <= after["sampled_ns"] - last < 10_000_000_000)
    return bool(identity and premise and capture["complete"] and delivery
                and (case == "live" or unchanged))


def counter(text, name="dropped_default"):
    rows = [line.split() for line in text.splitlines()
            if line.split() and line.split()[0] == name]
    if (len(rows) != 1 or len(rows[0]) != 2 or not rows[0][1].isascii()
            or not rows[0][1].isdigit() or int(rows[0][1]) >= 2**64):
        raise ValueError("missing or malformed live firewall counter")
    return int(rows[0][1])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("seed", "inspect", "send", "listen"))
    parser.add_argument("--support", required=True)
    parser.add_argument("--case", choices=CASES, required=True)
    parser.add_argument("--nonce")
    parser.add_argument("--ready")
    parser.add_argument("--stop")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("icmp_support", args.support)
    assert spec is not None and spec.loader is not None
    support = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(support)
    if args.command in ("seed", "inspect"):
        result = state(support, args.case, args.command == "seed")
    else:
        support.need(args.nonce and args.nonce.isascii() and len(args.nonce) >= 16, "explicit nonce required")
        if args.command == "send":
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
                sock.bind((SOURCE, 0))
                count = sock.sendto(reply(support, CASES[args.case], args.nonce), (TARGET, 0))
            result = dict(bytes_sent=count)
        else:
            result = listen(support, args.nonce, args.ready, args.stop)
    Path(args.output).write_text(json.dumps(result, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
