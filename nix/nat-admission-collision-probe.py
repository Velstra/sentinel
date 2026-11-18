"""Nine real sockets with colliding legacy candidate windows, not map injection.

The candidate calculation describes the tested old allocator. Desired behavior
is nine admitted nonce-verified flows: this diagnostic must fail, not turn
green, when that allocator exhausts its eight-port window.
"""

import argparse
import asyncio
import importlib.util
import ipaddress
import resource
import time


SOURCE = "198.18.20.50"
TARGET = "198.18.10.254"
PORT = 9000
SOURCE_PORTS = [8350, 24283, 31677, 38489, 43020, 50625, 55442, 61181, 63149]


def seed(source, target, sport, dport):
    src, dst = int(ipaddress.IPv4Address(source)), int(ipaddress.IPv4Address(target))
    value = src ^ (((dst << 16) | (dst >> 16)) & 0xffffffff) ^ (sport << 16) ^ dport
    value ^= value >> 16
    value = value * 0x7feb352d & 0xffffffff
    value ^= value >> 15
    value = value * 0x846ca68b & 0xffffffff
    return value ^ (value >> 16)


def candidates(source_port):
    hashed = seed(SOURCE, TARGET, source_port, PORT)
    return [32768 + (((hashed + index) & 0xffffffff) % 32768) for index in range(8)]


def proof():
    windows = [candidates(port) for port in SOURCE_PORTS]
    if len(set(SOURCE_PORTS)) != 9 or any(window != windows[0] for window in windows):
        raise RuntimeError("diagnostic source ports no longer form the reviewed nine/eight collision")
    return dict(source=SOURCE, target=[TARGET, PORT], source_ports=SOURCE_PORTS,
                reviewed_old_candidate_window=windows[0], desired_nonce_verified_connections=9,
                scope="collision premise only; real packet/map receipts decide behavior")


def transport_result(manifest, echoes, count, previous=None):
    """Strict endpoint oracle shared by reference tests; not a map-ownership proof.

    The common client checks the exact nonce/flow/round payload on its original
    open socket. Also require complete identities, unique public tuples and
    stable admission records across phases; counts alone can hide duplicates.
    """
    if type(count) is not int or count not in (1, 8, 9):
        raise ValueError("unexpected collision phase")
    attempts, rows = manifest.get("attempts"), echoes.get("rows")
    if (manifest.get("candidate_premise") != proof()
            or manifest.get("admission_order") != "sequential, previous successful sockets held open"
            or manifest.get("requested") != count or manifest.get("held") != count
            or not isinstance(attempts, list) or len(attempts) != count
            or not isinstance(rows, list) or len(rows) != count
            or type(echoes.get("round")) is not int or echoes["round"] != (1, 8, 9).index(count) + 1
            or not isinstance(manifest.get("nonce"), str) or len(manifest["nonce"]) != 32):
        raise ValueError("incomplete collision transport evidence")
    ports = []
    for index, (attempt, row) in enumerate(zip(attempts, rows, strict=True)):
        wire = attempt.get("wire_peer")
        if (type(attempt.get("id")) is not int or attempt["id"] != index
                or type(row.get("id")) is not int or row["id"] != index
                or attempt.get("source") != [SOURCE, SOURCE_PORTS[index]]
                or attempt.get("target") != [TARGET, PORT]
                or attempt.get("initial_echo") is not True or row.get("verified") is not True
                or "failure" in attempt or "failure" in row
                or not isinstance(wire, list) or len(wire) != 2
                or wire[0] != "198.18.10.100" or type(wire[1]) is not int
                or not 1 <= wire[1] <= 65535):
            raise ValueError("failed, duplicate or misattributed collision flow")
        ports.append(wire[1])
    if len(set(ports)) != count:
        raise ValueError("public tuple alias")
    if previous is not None and (
            previous["nonce"] != manifest["nonce"]
            or attempts[:len(previous["attempts"])] != previous["attempts"]):
        raise ValueError("held connection identity changed between phases")
    return dict(requested=count, initial_nonce_echoes=count, verified_held_echoes=count,
                wire_ports_observed=ports, passed=True)


def load(path):
    spec = importlib.util.spec_from_file_location("nat_pressure_shared", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("missing explicit diagnostic shared probe")
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def client_class(shared):
    class SequentialClient(shared.Client):
        async def open_to(self, count, budget):
            shared.need(type(count) is int and len(self.attempts) < count <= len(SOURCE_PORTS),
                        "collision diagnostic supports up to nine sequential attempts")
            started = time.monotonic()
            for index in range(len(self.attempts), count):
                shared.need(time.monotonic() - started < budget, "collision admission budget exhausted")
                self.attempts.append(await self.open_one(index))
            return self.manifest(open_seconds=time.monotonic() - started, candidate_premise=proof(),
                                 admission_order="sequential, previous successful sockets held open")
    return SequentialClient


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shared-probe", required=True)
    args = parser.parse_args()
    proof()
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard < 65536:
        raise RuntimeError("fixture requires LimitNOFILE>=65536")
    resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, 65536), hard))
    shared = load(args.shared_probe)
    client = client_class(shared)(SOURCE, [TARGET], PORT, "198.18.10.100", 2, SOURCE_PORTS)
    asyncio.run(client.run())


if __name__ == "__main__":
    main()
