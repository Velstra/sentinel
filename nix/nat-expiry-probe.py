"""Real-packet NAT expiry regression, only for marked disposable VMs.

Seeds exact, absent keys. This tests deletion on observation, not a concurrent
refresh race, garbage collection, allocation capacity or general NAT admission.
"""

import argparse
import ctypes
import importlib.util
import json
from pathlib import Path
import socket
import struct
import time


REMOTE = "198.18.10.254"
PUBLIC = "198.18.10.100"
CLIENT = "198.18.20.50"
PROTOCOLS = {"tcp": 6, "udp": 17, "icmp": 1}
CASES = ("live", "expired", "absent")
REUSE = "dnat-reuse"
SHADOW = "expired-tenant-shadow"
KEY = struct.Struct("<I4s4sHHB3x")
VALUE = struct.Struct("<4s4sHHHHQQQQ")
MARKER = Path("/run/qa-nat-expiry-disposable")
EXPIRED_AGE = 604_800_000_000_000


def ports(case):
    index = 3 if case == REUSE else 4 if case == SHADOW else CASES.index(case)
    return 44000 + index, 45000 + index, 46000 + index


def keys(policy, proto, case):
    remote, public, _ = ports(case)
    source = 0 if proto == 1 else remote
    pair = [KEY.pack(0 if case == REUSE else policy, socket.inet_aton(REMOTE), socket.inet_aton(PUBLIC),
                     source, public + offset, proto) for offset in (0, 100)]
    if case == SHADOW:
        pair.append(KEY.pack(0, socket.inet_aton(REMOTE), socket.inet_aton(PUBLIC), source, public, proto))
    return pair


def values(case, now):
    _, _, translated = ports(case)
    def value(age, flags=0 if case == REUSE else 2):
        return VALUE.pack(socket.inet_aton(CLIENT), bytes(4), translated, 0, flags, 0, 7, 777, now, age)
    pair = [None if case == "absent" else value(EXPIRED_AGE if case in ("expired", REUSE, SHADOW) else 0), value(0)]
    return pair + [value(0, 0)] if case == SHADOW else pair


def firewall_shadow(support, seed):
    key_format, value_format = struct.Struct("<I16s16sHHBB2x"), struct.Struct("<QQII16x")
    info = support.selected("FW_FLOWS")
    support.need(info.get("type") == "lru_hash" and info.get("bytes_key") == key_format.size
                 and info.get("bytes_value") == value_format.size and info.get("max_entries") == 65536,
                 "unexpected firewall map ABI")
    source, public, _ = ports(SHADOW)
    remote, wan = socket.inet_aton(REMOTE) + bytes(12), socket.inet_aton(PUBLIC) + bytes(12)
    pair = [key_format.pack(0, remote, wan, source, public, 17, 4),
            key_format.pack(0, wan, remote, public, source, 17, 4)]
    kernel = support.Kernel(info["id"])
    try:
        if seed:
            now = time.monotonic_ns()
            for reply, key in enumerate(pair):
                key_buffer = ctypes.create_string_buffer(key)
                value_buffer = ctypes.create_string_buffer(value_format.pack(now, 0, 3, reply))
                kernel.call(2, support.Element(map_fd=kernel.fd, key=ctypes.addressof(key_buffer),
                                              value=ctypes.addressof(value_buffer), flags=1))
        observed = [kernel.lookup(key, value_format.size) for key in pair]
        support.need(all(value is not None for value in observed), "missing canonical firewall permission")
        return dict(map_id=info["id"], keys=[key.hex() for key in pair], values=[value.hex() for value in observed])
    finally:
        kernel.close()


def state(support, proto, case, seed):
    support.need(MARKER.is_file(), "missing disposable-VM mutation permission marker")
    info = support.selected("CONNTRACK")
    support.validate_metadata(info)
    pair = keys(support.policy_id(), proto, case)
    kernel = support.Kernel(info["id"])
    try:
        if seed:
            support.need(all(kernel.lookup(key) is None for key in pair), "fixture keys already present")
            for key, value in zip(pair, values(case, time.monotonic_ns()), strict=True):
                if value is not None:
                    kernel.insert(key, value)  # NOEXIST only, never overwrite.
        found = [kernel.lookup(key) for key in pair]
        result = dict(map_id=info["id"], keys=[key.hex() for key in pair], sampled_ns=time.monotonic_ns(),
                      values=[value.hex() if value is not None else None for value in found])
        if case == SHADOW:
            result["firewall"] = firewall_shadow(support, seed)
        return result
    finally:
        kernel.close()


def datagram(support, proto, case, nonce, translated=False):
    source, public, target_port = ports(case)
    target = CLIENT if translated else PUBLIC
    destination = target_port if translated else public
    payload = nonce.encode("ascii")
    if proto == 1:
        segment = struct.pack("!BBHHH", 0, 0, 0, destination, 1) + payload
        check_offset = 2
        pseudo = b""
    else:
        if proto == 6:
            segment = struct.pack("!HHIIBBHHH", source, destination, 1001, 2001, 0x50, 0x10, 4096, 0, 0) + payload
            check_offset = 16
        else:
            segment = struct.pack("!HHHH", source, destination, 8 + len(payload), 0) + payload
            check_offset = 6
        pseudo = struct.pack("!4s4sBBH", socket.inet_aton(REMOTE), socket.inet_aton(target), 0, proto, len(segment))
    checksum = support.checksum(pseudo + segment)
    if proto == 17 and checksum == 0:
        checksum = 65535
    segment = segment[:check_offset] + struct.pack("!H", checksum) + segment[check_offset + 2:]
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 1234, 0, 64, proto, 0,
                         socket.inet_aton(REMOTE), socket.inet_aton(target))
    header = header[:10] + struct.pack("!H", support.checksum(header)) + header[12:]
    return header + segment


def packet(support, raw, proto, nonce):
    if len(raw) < 28 or raw[0] != 0x45 or raw[9] != proto:
        return None
    total = struct.unpack_from("!H", raw, 2)[0]
    if total > len(raw) or total < 28 or struct.unpack_from("!H", raw, 6)[0] & 0x3fff:
        return None
    segment = raw[20:total]
    offset = 20 if proto == 6 else 8
    if len(segment) < offset or segment[offset:] != nonce.encode("ascii"):
        return None
    if proto == 6 and (segment[12] != 0x50 or segment[13] != 0x10):
        return None
    if proto == 17 and struct.unpack_from("!H", segment, 4)[0] != len(segment):
        return None
    if proto == 1 and (segment[:2] != b"\0\0" or segment[6:8] != b"\0\1"):
        return None
    pseudo = b"" if proto == 1 else raw[12:20] + struct.pack("!BBH", 0, proto, len(segment))
    source, target = (0, struct.unpack_from("!H", segment, 4)[0]) if proto == 1 else struct.unpack_from("!HH", segment)
    return dict(source=socket.inet_ntoa(raw[12:16]), target=socket.inet_ntoa(raw[16:20]),
                source_port=source, target_port=target, proto=proto,
                checksum_valid=support.checksum(raw[:20]) == 0 and support.checksum(pseudo + segment) == 0)


def expected(proto, case, translated):
    source, public, target = ports(case)
    return dict(source=REMOTE, target=CLIENT if translated else PUBLIC, proto=proto,
                source_port=0 if proto == 1 else source, target_port=target if translated else public,
                checksum_valid=True)


def verdict(proto, case, before, after, captures, sent):
    identity = before["map_id"] == after["map_id"] and before["keys"] == after["keys"]
    neighbour = before["values"][1]
    present = neighbour is not None and after["values"][1] == neighbour
    if case == REUSE:
        # Compatibility guard: the historical path needs one retransmission
        # after deleting the expired forward key. Do not require that loss:
        # a repair that immediately admits both datagrams must also pass.
        translated = captures["client"]["packets"]
        local = captures["fw"]["packets"]
        first, last = before["values"][0], after["values"][0]
        if first is None or last is None:
            return False
        old, new = VALUE.unpack(bytes.fromhex(first)), VALUE.unpack(bytes.fromhex(last))
        return bool(proto == 17 and identity and present and sent.get("packets_sent") == 2
                    and all(capture["complete"] for capture in captures.values())
                    and 1 <= len(translated) <= 2 and len(local) + len(translated) == 2
                    and translated == [expected(proto, case, True)] * len(translated)
                    and local == [expected(proto, case, False)] * len(local)
                    and old[9] == EXPIRED_AGE and old[:6] == new[:6] and new[4] == 0
                    and new[6] == len(translated) and new[7] == len(translated) * (sent["bytes_sent"] + 14)
                    and before["sampled_ns"] <= new[8] <= after["sampled_ns"] and new[9] == 0)
    translated = case in ("live", SHADOW)
    delivery = (all(capture["complete"] for capture in captures.values())
                and captures["client"]["packets"] == ([expected(proto, case, True)] if translated else [])
                and captures["fw"]["packets"] == ([] if translated else [expected(proto, case, False)]))
    index = 2 if case == SHADOW else 0
    first, last = before["values"][index], after["values"][index]
    if case == SHADOW:
        identity = (identity and proto == 17 and before["values"][0] == after["values"][0]
                    and before["values"][0] is not None
                    and VALUE.unpack(bytes.fromhex(before["values"][0]))[9] == EXPIRED_AGE
                    and before["firewall"]["map_id"] == after["firewall"]["map_id"]
                    and before["firewall"]["keys"] == after["firewall"]["keys"])
    if translated:
        intact = False
        if first is not None and last is not None:
            old, new = VALUE.unpack(bytes.fromhex(first)), VALUE.unpack(bytes.fromhex(last))
            intact = (old[:6] == new[:6] and new[6] == old[6] + 1
                      and new[7] == old[7] + sent["bytes_sent"] + 14
                      and old[8] <= new[8] <= after["sampled_ns"] and new[9] == 0)
    elif case == "expired":
        intact = first is not None and first == last and VALUE.unpack(bytes.fromhex(first))[9] == EXPIRED_AGE
    else:
        intact = first is None and last is None
    return bool(identity and present and delivery and intact)


def listen(support, proto, nonce, role, ready, stop):
    support.need(ready and stop and not Path(ready).exists() and not Path(stop).exists(),
                 "fresh explicit capture controls required")
    packets = []
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, proto) as sock:
        sock.bind((CLIENT if role == "client" else PUBLIC, 0))
        Path(ready).touch()
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not Path(stop).exists():
            sock.settimeout(.05)
            try:
                raw, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue
            observed = packet(support, raw, proto, nonce)
            if observed is not None:
                packets.append(observed)
        return dict(complete=time.monotonic() < deadline and Path(stop).exists(), packets=packets)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("seed", "inspect", "send", "listen"))
    parser.add_argument("--support", required=True)
    parser.add_argument("--protocol", choices=PROTOCOLS, required=True)
    parser.add_argument("--case", choices=(*CASES, REUSE, SHADOW), required=True)
    parser.add_argument("--role", choices=("client", "fw"))
    parser.add_argument("--nonce")
    parser.add_argument("--ready")
    parser.add_argument("--stop")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("nat_support", args.support)
    assert spec is not None and spec.loader is not None
    support = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(support)
    proto = PROTOCOLS[args.protocol]
    support.need(args.case not in (REUSE, SHADOW) or proto == 17, "DNAT lifecycle fixtures are UDP only")
    if args.command in ("seed", "inspect"):
        result = state(support, proto, args.case, args.command == "seed")
    else:
        support.need(args.nonce and args.nonce.isascii() and 16 <= len(args.nonce) <= 64, "explicit short nonce required")
        if args.command == "send":
            raw = datagram(support, proto, args.case, args.nonce)
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.bind((REMOTE, 0))
                attempts = 2 if args.case == REUSE else 1
                for attempt in range(attempts):
                    if attempt:
                        time.sleep(.2)
                    count = sock.sendto(raw, (PUBLIC, 0))
                    support.need(count == len(raw), "partial packet send")
            result = dict(bytes_sent=len(raw), packets_sent=attempts)
        else:
            support.need(args.role is not None, "capture role required")
            result = listen(support, proto, args.nonce, args.role, args.ready, args.stop)
    Path(args.output).write_text(json.dumps(result, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
