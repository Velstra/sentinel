"""One exact reverse-key deletion in an explicitly marked disposable VM.

This is deliberate fixture injection, NOT a production collector, atomic
compare/delete primitive, concurrent-writer test or permission to sweep maps.
The ninth original TCP socket must retain its later public port afterwards.
"""

import argparse
import asyncio
import ctypes
import errno
import importlib.util
import json
import time
from pathlib import Path

MARKER = Path("/etc/sentinel-qa-nat-domain-hole")
PERMISSION = "disposable-nat-domain-hole-fixture-v1\n"
PUBLIC = "198.18.10.100"
SELECTED = 8


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("missing explicit fixture module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_manifest(premise, manifest):
    attempts = manifest.get("attempts")
    if (manifest.get("requested") != 9 or manifest.get("held") != 9
            or not isinstance(attempts, list) or len(attempts) != 9
            or not isinstance(manifest.get("nonce"), str) or len(manifest["nonce"]) != 32
            or any(c not in "0123456789abcdef" for c in manifest["nonce"])):
        raise ValueError("incomplete original-socket hole evidence")
    first = premise["reviewed_old_candidate_window"][0]
    for index, row in enumerate(attempts):
        if (type(row.get("id")) is not int or row["id"] != index
                or row.get("source") != [premise["source"], premise["source_ports"][index]]
                or row.get("target") != premise["target"]
                or row.get("wire_peer") != [PUBLIC, first + index]
                or row.get("initial_echo") is not True or "failure" in row):
            raise ValueError("socket identity, nonce admission or collision premise failed")


def transport(premise, manifest, echoes, expected_round, previous=None):
    validate_manifest(premise, manifest)
    rows = echoes.get("rows")
    if (rows != [{"id": SELECTED, "verified": True}]
            or rows[0].get("verified") is not True or type(rows[0].get("id")) is not int
            or type(echoes.get("round")) is not int or echoes["round"] != expected_round):
        raise ValueError("missing original selected-socket nonce/round echo")
    attempts = manifest["attempts"]
    if previous is not None and (manifest["nonce"] != previous["nonce"]
                                 or attempts != previous["attempts"]):
        raise ValueError("original socket manifest changed or reconnected")
    return {"selected": SELECTED, "round": expected_round,
                "original_public_tuple": attempts[SELECTED]["wire_peer"], "passed": True}


def bindings(shared, premise, manifest, sample, missing=()):
    """Select exact raw keys by complete reverse tuples, then validate owners."""
    _, nat = shared.indices(sample)
    entries = sample["maps"]["CONNTRACK"]["entries"]
    if len(nat) != 9 - len(missing) or len(entries) != len(nat):
        raise ValueError("unexpected NAT occupancy in isolated fixture")
    decoded = {shared.decode_key("CONNTRACK", bytes.fromhex(key)): (key, value)
               for key, value in entries}
    result = {}
    policies = set()
    for index, row in enumerate(manifest["attempts"]):
        reverse = (premise["target"][0], PUBLIC, premise["target"][1], row["wire_peer"][1], 6)
        found = [(key, value) for key, value in nat.items() if key[1:] == reverse]
        if index in missing:
            if found:
                raise ValueError("earlier candidate is no longer vacant")
            continue
        if len(found) != 1:
            raise ValueError("missing or ambiguous original reverse binding")
        key, value = found[0]
        owner, second, port, second_port, flags, padding, _, _, _, age = shared.NAT_VALUE.unpack(value)
        if (str(shared.ipaddress.IPv4Address(owner)) != premise["source"]
                or port != premise["source_ports"][index] or second != bytes(4)
                or second_port != 0 or flags != 2 or padding != 0 or age != 0):
            raise ValueError("foreign or malformed reverse owner")
        policies.add(key[0])
        raw_key, raw_value = decoded[key]
        result[index] = {"key": raw_key, "value": raw_value}
    if len(policies) != 1:
        raise ValueError("ambiguous NAT policy scope")
    return result


def delete_exact(kernel, key, expected):
    """A test-only check/delete sequence, deliberately not advertised as CAS."""
    if kernel.lookup(key) != expected:
        raise RuntimeError("refusing mutation: exact owner/value changed since snapshot")
    kernel.delete(key)
    if kernel.lookup(key) is not None:
        raise RuntimeError("deleted fixture key still exists")


class Element(ctypes.Structure):
    _fields_ = [("map_fd", ctypes.c_uint32), ("pad", ctypes.c_uint32),
                ("key", ctypes.c_uint64), ("value", ctypes.c_uint64),
                ("flags", ctypes.c_uint64)]


class FixtureKernel:
    def __init__(self, reader):
        self.reader = reader

    def call(self, command, key, value=None):
        key_buffer = ctypes.create_string_buffer(key)
        attribute = Element(map_fd=self.reader.fd, key=ctypes.addressof(key_buffer),
                            value=ctypes.addressof(value) if value is not None else 0)
        result = self.reader.libc.syscall(321, command, ctypes.byref(attribute), ctypes.sizeof(attribute))
        if result < 0:
            error = ctypes.get_errno()
            if command == 1 and error == errno.ENOENT:
                return False
            raise OSError(error, "disposable NAT fixture BPF operation")
        return True

    def lookup(self, key):
        value = ctypes.create_string_buffer(48)
        return value.raw if self.call(1, key, value) else None

    def delete(self, key):
        self.call(3, key)


def mutate(shared, premise, manifest, snapshot):
    if not MARKER.is_file() or MARKER.read_text() != PERMISSION:
        raise RuntimeError("missing exact disposable-VM mutation permission marker")
    validate_manifest(premise, manifest)
    owned = bindings(shared, premise, manifest, snapshot)
    victim, survivor = owned[0], owned[SELECTED]
    if victim["key"] == survivor["key"]:
        raise RuntimeError("cannot remove selected connection")
    info = snapshot["maps"]["CONNTRACK"]["metadata"]
    reader = shared.KernelReader(info)
    try:
        kernel = FixtureKernel(reader)
        if kernel.lookup(bytes.fromhex(survivor["key"])) != bytes.fromhex(survivor["value"]):
            raise RuntimeError("selected binding changed before injection")
        delete_exact(kernel, bytes.fromhex(victim["key"]), bytes.fromhex(victim["value"]))
    finally:
        reader.close()
    after = shared.snapshot()
    remaining = bindings(shared, premise, manifest, after, missing=(0,))
    if after["maps"]["CONNTRACK"]["metadata"]["id"] != info["id"]:
        raise RuntimeError("active NAT map changed during fixture injection")
    if {row["key"] for row in remaining.values()} != {row["key"] for row in owned.values()} - {victim["key"]}:
        raise RuntimeError("unexpected key change during fixture injection")
    return {"version": 1, "scope": "test-only exact unrelated-key deletion, not concurrent CAS or production GC",
                "map_id": info["id"], "removed": victim, "selected_before": survivor, "after": after}


def client_class(shared, collision):
    class HoleClient(collision.client_class(shared)):
        async def probe(self, budget):
            shared.need(len(self.attempts) == 9 and len(self.streams) == 9,
                        "all nine original sockets must have nonce-verified admission")
            self.round += 1
            shared.need(1 <= self.round <= 2, "exactly two selected-socket rounds are supported")
            started = time.monotonic()
            result = await self.probe_one(SELECTED)
            return {"version": 1, "round": self.round, "rows": [result],
                        "seconds": time.monotonic() - started}
    return HoleClient


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shared-probe", required=True)
    parser.add_argument("--collision-probe", required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("client")
    mutation = sub.add_parser("delete-earlier")
    mutation.add_argument("--manifest", required=True)
    mutation.add_argument("--snapshot", required=True)
    mutation.add_argument("--output", required=True)
    args = parser.parse_args()
    shared = load("nat_hole_shared", args.shared_probe)
    collision = load("nat_hole_collision", args.collision_probe)
    premise = collision.proof()
    if args.command == "client":
        client = client_class(shared, collision)(collision.SOURCE, [collision.TARGET], collision.PORT,
                                                PUBLIC, 2, collision.SOURCE_PORTS)
        asyncio.run(client.run())
    else:
        result = mutate(shared, premise, json.loads(Path(args.manifest).read_text()),
                        json.loads(Path(args.snapshot).read_text()))
        shared.output(result, args.output)


if __name__ == "__main__":
    main()
