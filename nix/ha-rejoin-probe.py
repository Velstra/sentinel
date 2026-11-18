"""Disposable HA rejoin observation. No product map writes or role injection.

All endpoint traffic is ordinary TCP with exact nonce echoes. NAT sampling uses
the existing bounded batch-only reader, never individual LRU lookups. Samples
are non-atomic observations, not proof of ownership at an earlier packet time.
"""

import argparse
import asyncio
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time


ROOT = Path("/run/qa-ha-rejoin")
MARKER = Path("/run/qa-ha-rejoin-disposable")
SOURCE, TARGET, PUBLIC, PORT = "10.2.0.10", "10.1.0.10", "10.1.0.100", 8443
MAX_SECONDS, MAX_ROWS, FRAME_LIMIT = 240, 20_000, 1024
PHASES = {"baseline", "failover", "incumbent", "rejoin", "after"}
NAT = struct.Struct("<4s4sHHHHQQQQ")


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def phase():
    value = (ROOT / "phase").read_text().strip()
    need(value in PHASES, "unknown fixture phase")
    return value


def publish_phase(path, value):
    need(value in PHASES, "unknown fixture phase")
    temporary = path.with_suffix(".next")
    temporary.write_text(value + "\n")
    temporary.replace(path)


def append(file, row):
    row = dict(row, monotonic_ns=time.monotonic_ns(), phase=phase())
    text = json.dumps(row, separators=(",", ":"))
    need(len(text) <= 8 * 1024 * 1024, "oversized observation")
    file.write(text + "\n")
    file.flush()


def publish(path, value):
    temporary = path.with_suffix(".next")
    temporary.write_text(json.dumps(value, separators=(",", ":")) + "\n")
    temporary.replace(path)


def candidates(source_port):
    need(type(source_port) is int and 1 <= source_port <= 65535, "invalid source port")
    src, dst = int(ipaddress.IPv4Address(SOURCE)), int(ipaddress.IPv4Address(TARGET))
    hashed = src ^ (((dst << 16) | (dst >> 16)) & 0xffffffff) ^ (source_port << 16) ^ PORT
    hashed ^= hashed >> 16
    hashed = hashed * 0x7feb352d & 0xffffffff
    hashed ^= hashed >> 15
    hashed = hashed * 0x846ca68b & 0xffffffff
    hashed ^= hashed >> 16
    return dict(seed=hashed, ports=[32768 + (((hashed + i) & 0xffffffff) % 32768) for i in range(8)])


def payload(nonce, kind, index):
    need(len(nonce) == 32 and all(c in "0123456789abcdef" for c in nonce), "invalid nonce")
    need(kind in ("tick", "fresh") and type(index) is int and 0 <= index < MAX_ROWS,
         "invalid traffic identity")
    return f"{nonce} {kind} {index}\n".encode()


def failure(error):
    return dict(type=type(error).__name__, errno=getattr(error, "errno", None), detail=str(error)[:160])


async def close(writer):
    if writer is not None:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), .2)
        except (OSError, TimeoutError):
            pass


async def echo_peer(reader, writer, log):
    try:
        peer = writer.get_extra_info("peername")[:2]
        writer.write(json.dumps(dict(peer=peer, target=writer.get_extra_info("sockname")[:2])).encode() + b"\n")
        await writer.drain()
        while frame := await reader.readline():
            need(len(frame) <= FRAME_LIMIT and frame.endswith(b"\n"), "invalid echo frame")
            append(log, dict(kind="server", peer=peer, payload=frame.decode("ascii").strip()))
            writer.write(frame)
            await writer.drain()
    except (OSError, RuntimeError, ValueError, UnicodeError):
        # The client records failure; the server must continue accepting peers.
        pass
    finally:
        await close(writer)


async def serve():
    with (ROOT / "server.jsonl").open("w") as log:
        async def peer(reader, writer):
            await echo_peer(reader, writer, log)
        server = await asyncio.start_server(peer, TARGET, PORT, backlog=256, limit=FRAME_LIMIT)
        async with server:
            await server.serve_forever()


async def connect(source_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    try:
        sock.bind((SOURCE, source_port))
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        await asyncio.get_running_loop().sock_connect(sock, (TARGET, PORT))
        reader, writer = await asyncio.open_connection(sock=sock, limit=FRAME_LIMIT)
    except BaseException:
        sock.close()
        raise
    try:
        greeting = json.loads(await reader.readline())
        need(greeting.get("target") == [TARGET, PORT] and greeting.get("peer", [None])[0] == PUBLIC,
             "backend did not observe the intended SNAT path")
        need(type(greeting["peer"][1]) is int and 32768 <= greeting["peer"][1] <= 65535,
             "backend observed an invalid translated port")
        return reader, writer, greeting["peer"]
    except BaseException:
        await close(writer)
        raise


async def exchange(reader, writer, frame):
    writer.write(frame)
    await writer.drain()
    need(await reader.readline() == frame, "echo nonce/sequence mismatch")


async def client(nonce, seconds):
    stop = time.monotonic() + seconds
    with (ROOT / "client.jsonl").open("w") as log:
        async def ticks():
            writer = None
            try:
                reader, writer, peer = await asyncio.wait_for(connect(41000), 2)
                publish(ROOT / "stream.json", dict(connected=True, peer=peer, source=[SOURCE, 41000]))
                for index in range(MAX_ROWS):
                    if time.monotonic() >= stop or (ROOT / "stop").exists():
                        break
                    started = time.monotonic_ns()
                    started_phase = phase()
                    await asyncio.wait_for(exchange(reader, writer, payload(nonce, "tick", index)), 2)
                    append(log, dict(kind="tick", id=index, started_ns=started,
                                     started_phase=started_phase, ok=True, wire_peer=peer))
                    await asyncio.sleep(.05)
            except BaseException as error:
                if isinstance(error, asyncio.CancelledError):
                    raise
                append(log, dict(kind="tick", ok=False, failure=failure(error)))
            finally:
                await close(writer)

        async def fresh():
            for index in range(4000):
                if time.monotonic() >= stop or (ROOT / "stop").exists():
                    return
                port, writer = 42000 + index, None
                row = dict(kind="fresh", id=index, source=[SOURCE, port], target=[TARGET, PORT],
                           started_ns=time.monotonic_ns(), started_phase=phase(), candidates=candidates(port), ok=False)
                try:
                    async def attempt():
                        nonlocal writer
                        reader, writer, peer = await connect(port)
                        row["wire_peer"] = peer
                        await exchange(reader, writer, payload(nonce, "fresh", index))
                    await asyncio.wait_for(attempt(), .5)
                    row["ok"] = True
                except (OSError, RuntimeError, ValueError, TimeoutError, json.JSONDecodeError) as error:
                    row["failure"] = failure(error)
                finally:
                    await close(writer)
                append(log, row)
                await asyncio.sleep(.1)
        await asyncio.gather(ticks(), fresh())
    publish(ROOT / "client-finished.json", dict(completed=True, nonce=nonce))


def command(arguments):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=2, check=True)
    need(len(result.stdout) <= 8 * 1024 * 1024, "command observation exceeded limit")
    return result.stdout


def agent_query(request):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(.5)
        connection.connect("/run/velstra/query.sock")
        connection.sendall(request.encode() + b"\n")
        data = bytearray()
        while len(data) <= 65536:
            chunk = connection.recv(4096)
            if not chunk:
                return data.decode()
            data.extend(chunk)
        raise RuntimeError("oversized agent response")


def stats(text):
    result = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] in {"egress_dropped", "egress_masqueraded", "dropped_default"}:
            need(parts[0] not in result, "duplicate admission counter")
            result[parts[0]] = int(parts[1])
    need(set(result) == {"egress_dropped", "egress_masqueraded", "dropped_default"}, "missing admission counters")
    return result


def load_reader(path):
    spec = importlib.util.spec_from_file_location("ha_rejoin_batch_reader", path)
    need(spec is not None and spec.loader is not None, "batch reader unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def raw_nat(module):
    maps = json.loads(command(["bpftool", "-j", "map", "show"]))
    selected = [row for row in maps if row.get("name") == "CONNTRACK"]
    need(len(selected) == 1, "ambiguous NAT map")
    metadata = module.validate_metadata(selected[0])
    reader = module.KernelReader(metadata)
    try:
        rows = module.walk(reader, metadata["max_entries"], time.monotonic() + .5)
    finally:
        reader.close()
    return dict(metadata=metadata, complete=True, atomic_snapshot=False,
                rows=[[key.hex(), value.hex()] for key, value in sorted(rows.items())])


def collect_maps(module):
    nat = raw_nat(module)
    deadline = json.loads(command(["bpftool", "-j", "map", "dump", "pinned",
                                   "/sys/fs/bpf/velstra-ha/deadline"]))
    deadline_observed_boottime_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    return dict(nat=nat,
                deadline=deadline, deadline_observed_boottime_ns=deadline_observed_boottime_ns,
                counters=stats(agent_query("stats")), status=agent_query("status").strip(),
                addresses=json.loads(command(["ip", "-j", "address", "show"])),
                routes=json.loads(command(["ip", "-j", "route", "show"])),
                neighbours=json.loads(command(["ip", "-j", "neigh", "show"])),
                services=command(["systemctl", "show", "velstra.service", "wren.service",
                                  "--property=Id,MainPID,InvocationID,ActiveState"]))


async def observe(reader_path, seconds):
    module = load_reader(reader_path)
    stop = time.monotonic() + seconds
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    with (ROOT / "observer.jsonl").open("w") as log:
        async def roles():
            for _ in range(MAX_ROWS):
                if time.monotonic() >= stop or (ROOT / "stop").exists():
                    return
                try:
                    append(log, dict(kind="role", boot_id=boot,
                           boottime_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME),
                           role=json.loads(Path("/run/velstra/ha/role.json").read_text()),
                           agent=json.loads(Path("/run/velstra/ha/agent.json").read_text())))
                except (OSError, ValueError, RuntimeError) as error:
                    append(log, dict(kind="collection-error", stage="role", failure=failure(error)))
                await asyncio.sleep(.05)

        async def maps():
            for _ in range(MAX_ROWS):
                if time.monotonic() >= stop or (ROOT / "stop").exists():
                    return
                started = time.monotonic_ns()
                try:
                    value = await asyncio.to_thread(collect_maps, module)
                    value["deadline_value_ns"] = deadline_value(value["deadline"])
                    append(log, dict(kind="maps", started_ns=started,
                                     boottime_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME), **value))
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                    append(log, dict(kind="collection-error", stage="maps", failure=failure(error)))
                await asyncio.sleep(.25)
        await asyncio.gather(roles(), maps())
    publish(ROOT / "observer-finished.json", dict(completed=True, boot_id=boot))


def read_rows(path):
    raw = Path(path).read_bytes()
    need(len(raw) <= 128 * 1024 * 1024 and raw.endswith(b"\n"), "invalid/truncated observation log")
    rows = [json.loads(line) for line in raw.splitlines()]
    need(rows and len(rows) <= MAX_ROWS, "empty/oversized observation log")
    need(all(isinstance(row, dict) and row.get("phase") in PHASES
             and type(row.get("monotonic_ns")) is int for row in rows), "invalid observation identity")
    need(all("started_phase" not in row or row["started_phase"] in PHASES for row in rows), "invalid phase at attempt start")
    need(all(a["monotonic_ns"] <= b["monotonic_ns"] for a, b in zip(rows, rows[1:])), "log clock moved backwards")
    return rows, hashlib.sha256(raw).hexdigest()


def deadline_value(value):
    need(isinstance(value, list) and len(value) == 1, "invalid pinned deadline row")
    row = value[0]
    def raw_bytes(items, size):
        need(isinstance(items, list) and len(items) == size, "invalid pinned deadline width")
        result = []
        for item in items:
            need(type(item) is int or isinstance(item, str) and len(item) == 4 and item.startswith("0x"),
                 "invalid pinned deadline byte")
            number = int(item, 16) if isinstance(item, str) else item
            need(0 <= number <= 255, "invalid pinned deadline byte range")
            result.append(number)
        return bytes(result)
    need(isinstance(row, dict) and raw_bytes(row.get("key"), 4) == bytes(4), "invalid pinned deadline key")
    return int.from_bytes(raw_bytes(row.get("value"), 8), "little")


def analyse(client_rows, owner_rows):
    failures = []
    errors = [row for row in owner_rows if row["kind"] == "collection-error"]
    if errors:
        failures.append(dict(kind="collection-errors", count=len(errors)))
    phases = {}
    seen_ports = set()
    for row in client_rows:
        if row["kind"] == "fresh":
            port = row["source"][1]
            need(port not in seen_ports and row["candidates"] == candidates(port), "duplicate port or wrong candidate evidence")
            if row.get("ok"):
                need(row.get("wire_peer", [None])[0] == PUBLIC
                     and row["wire_peer"][1] in row["candidates"]["ports"], "successful flow has the wrong wire allocation")
            seen_ports.add(port)
    ticks = [row for row in client_rows if row["kind"] == "tick" and row.get("ok")]
    need([row["id"] for row in ticks] == list(range(len(ticks))), "established ticker reconnected or skipped identity")
    critical = {"incumbent", "rejoin", "after"}
    for first, second in zip(ticks, ticks[1:]):
        if first["phase"] in critical and second["phase"] in critical and second["monotonic_ns"] - first["monotonic_ns"] >= 500_000_000:
            failures.append(dict(kind="established-boundary-gap", timestamp=second["monotonic_ns"]))
        if "failover" in {first["phase"], second["phase"]} and second["monotonic_ns"] - first["monotonic_ns"] >= 1_500_000_000:
            failures.append(dict(kind="separate-failover-stream-gap", timestamp=second["monotonic_ns"]))
    for name in ("baseline", "incumbent", "rejoin", "after"):
        fresh = [row for row in client_rows if row["kind"] == "fresh" and row["phase"] == name]
        ticks = [row for row in client_rows if row["kind"] == "tick" and row["phase"] == name]
        tick_times = [row["monotonic_ns"] for row in ticks if row.get("ok")]
        maximum_gap = max((b - a for a, b in zip(tick_times, tick_times[1:])), default=0) / 1e9
        failed = [row for row in fresh + ticks if row.get("ok") is not True]
        phases[name] = dict(fresh=len(fresh), ticks=len(ticks), failures=failed, maximum_tick_gap_s=maximum_gap)
        if len(fresh) < 10 or len(ticks) < 20 or maximum_gap >= .5 or failed:
            failures.append(dict(kind="traffic", phase=name))
    roles = [row for row in owner_rows if row["kind"] == "role" and row["phase"] in {"incumbent", "rejoin", "after"}]
    need(roles, "owner role timeline absent")
    authority = roles[0]["role"]["authority"]
    owner_boots = {row["boot_id"] for row in roles}
    if len(owner_boots) != 1 or not all(owner_boots):
        failures.append(dict(kind="incumbent-boot-changed-or-unknown"))
    for row in roles:
        role, agent = row["role"], row["agent"]
        if (role["authority"] != authority or authority["owner"] != 2
                or role["deadline_ns"] <= row["boottime_ns"] or not role["vips_ready"]
                or agent["forwarding_term"] != authority["term"] or agent["policy"] != authority["policy"]):
            failures.append(dict(kind="incumbent-authority", timestamp=row["monotonic_ns"]))
    for name in ("incumbent", "rejoin", "after"):
        times = [row["monotonic_ns"] for row in roles if row["phase"] == name]
        if len(times) < 20 or times[-1] - times[0] < 1_000_000_000 or any(b - a > 250_000_000 for a, b in zip(times, times[1:])):
            failures.append(dict(kind="role-coverage", phase=name))
    maps = [row for row in owner_rows if row["kind"] == "maps"]
    need(maps and all(row["nat"]["complete"] is True for row in maps), "NAT observations absent/incomplete")
    for row in maps:
        nat_index(row["nat"])
    for name in critical:
        observations = [row for row in maps if row["phase"] == name]
        times = [row["monotonic_ns"] for row in observations]
        if len(observations) < 2 or times[-1] - times[0] < 1_000_000_000 or any(b - a > 2_000_000_000 for a, b in zip(times, times[1:])):
            failures.append(dict(kind="map-coverage", phase=name))
        for row in observations:
            if (row["deadline_value_ns"] <= row["deadline_observed_boottime_ns"] or row["status"] != "Ready"
                    or row["monotonic_ns"] - row["started_ns"] > 2_000_000_000):
                failures.append(dict(kind="map-authority-or-budget", timestamp=row["monotonic_ns"]))
            links = {link["ifname"]: {addr["local"] for addr in link.get("addr_info", [])
                                     if addr.get("family") == "inet"} for link in row["addresses"]}
            if "10.1.0.100" not in links.get("eth1", set()) or "10.2.0.100" not in links.get("eth2", set()):
                failures.append(dict(kind="incumbent-real-vip-missing", timestamp=row["monotonic_ns"]))
    identities = {row["nat"]["metadata"]["id"] for row in maps}
    if len(identities) != 1:
        failures.append(dict(kind="incumbent-map-replaced"))
    services = {row["services"] for row in maps}
    if len(services) != 1:
        failures.append(dict(kind="incumbent-service-replaced"))
    counter_delta = {name: maps[-1]["counters"][name] - maps[0]["counters"][name]
                     for name in ("egress_dropped", "egress_masqueraded", "dropped_default")}
    if any(value < 0 for value in counter_delta.values()):
        failures.append(dict(kind="counter-reset"))
    # Clock domains differ between guests. Retain all ownership samples but
    # never silently label a nearest different-guest time as packet-time proof.
    fresh_failures = [row for row in client_rows if row["kind"] == "fresh" and not row.get("ok")]
    return dict(version=1, passed=not failures, phases=phases, failures=failures,
                authority=authority, map_ids=sorted(identities), owner_boots=sorted(owner_boots),
                fresh_failure_evidence=fresh_failures,
                admission_counter_delta=counter_delta,
                ownership_scope="non-atomic same-owner samples; cross-guest packet-time attribution unknown",
                failover=[row for row in client_rows if row["phase"] == "failover"],
                candidate_owner_evidence=[candidate_owners(row, sample) for row in fresh_failures
                                          for sample in maps if sample["phase"] == row["phase"]])


def nat_index(sample):
    meta = sample["metadata"]
    need(sample.get("complete") is True and sample.get("atomic_snapshot") is False
         and meta.get("name") == "CONNTRACK" and meta.get("type") == "lru_hash"
         and meta.get("bytes_key") == 20 and meta.get("bytes_value") == NAT.size
         and type(meta.get("id")) is int and meta["id"] > 0, "invalid NAT sample ABI or identity")
    need(type(meta.get("max_entries")) is int and 1 <= meta["max_entries"] <= 65536
         and len(sample["rows"]) <= meta["max_entries"], "NAT sample exceeds capacity")
    result = {}
    for raw_key, raw_value in sample["rows"]:
        key, value = bytes.fromhex(raw_key), bytes.fromhex(raw_value)
        need(len(key) == 20 and key[-3:] == bytes(3) and len(value) == NAT.size, "invalid raw NAT record")
        need(key not in result, "duplicate raw NAT key")
        result[key] = value
    return result


def candidate_owners(attempt, sample):
    target, public = ipaddress.IPv4Address(TARGET).packed, ipaddress.IPv4Address(PUBLIC).packed
    ports = attempt["candidates"]["ports"]
    entries = {port: [] for port in ports}
    for key, value in nat_index(sample["nat"]).items():
        policy, source, destination, source_port, destination_port, protocol = struct.unpack("<I4s4sHHB3x", key)
        if (source, destination, source_port, protocol) != (target, public, PORT, 6) or destination_port not in entries:
            continue
        owner, secondary, port, second_port, flags, pad, packets, size, seen, age = NAT.unpack(value)
        entries[destination_port].append(dict(policy=policy, owner=str(ipaddress.IPv4Address(owner)),
             port=port, flags=flags, secondary=str(ipaddress.IPv4Address(secondary)), second_port=second_port,
             pad=pad, packets=packets, bytes=size, last_seen_ns=seen, age_ns=age,
             tuple_matches_attempt=owner == ipaddress.IPv4Address(SOURCE).packed and port == attempt["source"][1]
             and flags == 2 and secondary == bytes(4) and second_port == 0 and pad == 0))
    return dict(attempt=attempt["id"], phase=attempt["phase"], sample_ns=sample["monotonic_ns"],
                map_id=sample["nat"]["metadata"]["id"], atomic_snapshot=False,
                scope="tuple-only ownership at this sample; all policies retained, actual WAN policy and packet-time attribution unknown",
                candidates=[dict(port=port, observed=entries[port]) for port in ports])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve")
    client_parser = sub.add_parser("client")
    client_parser.add_argument("--nonce", required=True)
    client_parser.add_argument("--seconds", type=int, default=180)
    observer = sub.add_parser("observe")
    observer.add_argument("--reader", required=True)
    observer.add_argument("--seconds", type=int, default=180)
    phase_parser = sub.add_parser("phase")
    phase_parser.add_argument("--value", choices=sorted(PHASES), required=True)
    args = parser.parse_args()
    need(MARKER.is_file() and ROOT.is_dir(), "explicit disposable VM marker required")
    if hasattr(args, "seconds"):
        need(1 <= args.seconds <= MAX_SECONDS, "invalid observation duration")
    if args.command == "serve":
        asyncio.run(serve())
    elif args.command == "client":
        asyncio.run(client(args.nonce, args.seconds))
    elif args.command == "observe":
        asyncio.run(observe(args.reader, args.seconds))
    else:
        publish_phase(ROOT / "phase", args.value)


if __name__ == "__main__":
    main()
