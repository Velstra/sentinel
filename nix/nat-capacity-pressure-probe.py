"""Disposable-VM NAT pressure diagnostic; never writes a product BPF map.

TCP client/server roles exchange exact per-flow/per-round nonces. Kernel reads
use LOOKUP_BATCH only (no individual LRU lookups). Analysis is pure and records
correlations, not a claimed eviction counter or an atomic kernel snapshot.
"""

import argparse
import asyncio
from collections import Counter
import ctypes
import errno
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import resource
import secrets
import socket
import struct
import subprocess
import time


FLOW_KEY = struct.Struct("<I4s4sHHB3x")
FIREWALL_KEY = struct.Struct("<I16s16sHHBB2x")
FIREWALL_VALUE = struct.Struct("<QQII")
NAT_VALUE = struct.Struct("<4s4sHHHHQQQQ")
MAP_LAYOUTS = {"CONNTRACK": (20, 48, "lru_hash"),
               "FW_FLOWS": (44, 24, "lru_hash"),
               "SYN_FLOWS": (20, 16, "lru_hash"),
               "IFACE_POLICY": (4, 4, "hash")}
SOCKET = "/run/qa-nat-capacity.sock"
FRAME_LIMIT = 4096
REPLY_LIMIT = 64 * 1024 * 1024
MAX_FLOWS = 20_000
PROBE_REVISION = "prebound-endpoints-runtime-v3-echo-evidence"
SERVER_METRICS = "/run/qa-nat-server-metrics.json"


class LoopHealth:
    """Bounded aggregate, not a claim of lossless scheduler profiling."""
    def __init__(self):
        self.samples, self.max_lag_ms, self.last = 0, 0.0, None
        self.task = None

    def start(self):
        need(self.task is None, "loop monitor already started")
        self.task = asyncio.create_task(self.run())

    async def run(self):
        while True:
            before = time.monotonic()
            await asyncio.sleep(0.05)
            self.last = time.monotonic()
            self.max_lag_ms = max(self.max_lag_ms, max(0, self.last - before - 0.05) * 1000)
            self.samples += 1

    def sample(self):
        return dict(running=self.task is not None and not self.task.done(), samples=self.samples,
                    max_lag_ms=self.max_lag_ms,
                    heartbeat_age_ms=None if self.last is None else (time.monotonic() - self.last) * 1000)

    async def stop(self):
        if self.task is not None:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass


def proc_counters(text):
    """Parse paired Linux /proc/net/{snmp,netstat} lines, refusing truncation."""
    lines, result = text.splitlines(), {}
    need(len(lines) % 2 == 0, "truncated kernel counter pairs")
    for index in range(0, len(lines), 2):
        names, values = lines[index].split(), lines[index + 1].split()
        need(names and values and names[0] == values[0] and len(names) == len(values),
             "invalid kernel counter pair")
        need(names[0].rstrip(":") not in result and len(set(names[1:])) == len(names[1:]), "duplicate kernel counters")
        result[names[0].rstrip(":")] = dict(zip(names[1:], map(int, values[1:])))
    return result


def runtime():
    result = dict(version=1, probe_revision=PROBE_REVISION, monotonic_ns=time.monotonic_ns(),
                  scope="read-only host counters; deltas/lag are confounder evidence, not allocator attribution")
    for label, path in (("netstat", "/proc/net/netstat"), ("snmp", "/proc/net/snmp")):
        try:
            result[label] = proc_counters(Path(path).read_text())
        except (OSError, ValueError, RuntimeError) as error:
            result[label] = dict(error=failure("runtime-counters", error))
    for name in ("cpu", "memory", "io"):
        try:
            result["pressure_" + name] = Path("/proc/pressure/" + name).read_text()[:4096]
        except OSError as error:
            result["pressure_" + name] = dict(error=failure("runtime-pressure", error))
    try:
        backend = json.loads(Path(SERVER_METRICS).read_text())
        result["backend"] = dict(value=backend,
                                 age_ms=(time.monotonic_ns() - backend["monotonic_ns"]) / 1_000_000)
    except (OSError, ValueError, KeyError, TypeError) as error:
        result["backend"] = dict(error=failure("backend-metrics", error))
    return result


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def validate_counts(counts):
    need(isinstance(counts, list) and counts and counts[0] == 1,
         "counts must start with the one-flow ownership sample")
    need(all(type(n) is int and 1 <= n <= MAX_FLOWS for n in counts)
         and counts == sorted(set(counts)), "counts must be increasing distinct integers up to20000")
    return counts


def payload(nonce, flow, round_id):
    need(isinstance(nonce, str) and len(nonce) == 32
         and all(c in "0123456789abcdef" for c in nonce), "invalid test nonce")
    need(type(flow) is int and 0 <= flow < MAX_FLOWS
         and type(round_id) is int and 0 <= round_id <= 100, "invalid frame identity")
    return json.dumps(dict(nonce=nonce, flow=flow, round=round_id), sort_keys=True).encode() + b"\n"


def frame_evidence(frame):
    """Bounded diagnostics only; never make a malformed/delayed echo pass."""
    value = dict(length=len(frame), sha256=hashlib.sha256(frame).hexdigest())
    if len(frame) > FRAME_LIMIT or not frame.endswith(b"\n"):
        return value
    try:
        identity = json.loads(frame)
        if not isinstance(identity, dict) or set(identity) != {"nonce", "flow", "round"}:
            return value
        canonical = payload(identity["nonce"], identity["flow"], identity["round"])
    except (ValueError, RuntimeError, UnicodeError):
        return value
    value["identity"] = identity
    value["canonical_encoding"] = frame == canonical
    return value


class EchoMismatch(RuntimeError):
    def __init__(self, expected, actual):
        super().__init__("nonce/flow/round echo mismatch")
        self.evidence = dict(expected=frame_evidence(expected), received=frame_evidence(actual))


def verify_echo(expected, actual):
    if actual != expected:
        raise EchoMismatch(expected, actual)


def endpoint(value):
    need(isinstance(value, (list, tuple)) and len(value) == 2
         and isinstance(value[0], str) and type(value[1]) is int
         and 1 <= value[1] <= 65535, "invalid endpoint")
    return str(ipaddress.IPv4Address(value[0])), value[1]


def hello(frame, target, public):
    need(len(frame) <= FRAME_LIMIT and frame.endswith(b"\n"), "invalid peer greeting frame")
    value = json.loads(frame)
    need(isinstance(value, dict) and set(value) == {"peer", "target"}, "invalid peer greeting")
    peer, actual_target = endpoint(value["peer"]), endpoint(value["target"])
    need(actual_target == endpoint(target), "backend greeting has the wrong target")
    need(peer[0] == public and 32768 <= peer[1] <= 65535, "backend did not observe expected WAN SNAT")
    return peer


def failure(stage, error):
    if isinstance(error, (TimeoutError, asyncio.TimeoutError)):
        kind = "timeout"
    elif isinstance(error, OSError):
        kind = errno.errorcode.get(error.errno, type(error).__name__)
    else:
        kind = type(error).__name__
    result = dict(stage=stage, kind=kind, detail=str(error)[:160])
    if isinstance(error, EchoMismatch):
        # Keep the first offending frame. Do not drain, retry, skip old rounds,
        # close/reopen the socket, or otherwise change the transport verdict.
        result["echo_evidence"] = error.evidence
    return result


async def close_writer(writer):
    if writer is not None:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 0.25)
        except (OSError, TimeoutError):
            pass


async def echo_peer(reader, writer, metrics=None):
    if metrics is not None:
        metrics["accepted"] += 1
        metrics["active"] += 1
    try:
        writer.write(json.dumps(dict(peer=writer.get_extra_info("peername")[:2],
                                    target=writer.get_extra_info("sockname")[:2])).encode() + b"\n")
        await writer.drain()
        while True:
            frame = await reader.readline()
            if not frame:
                break
            need(len(frame) <= FRAME_LIMIT and frame.endswith(b"\n"), "oversized echo frame")
            writer.write(frame)
            await writer.drain()
            if metrics is not None:
                metrics["echo_frames"] += 1
    except (OSError, RuntimeError, ValueError):
        pass
    finally:
        if metrics is not None:
            metrics["active"] -= 1
        await close_writer(writer)


async def serve(addresses, port):
    health, metrics = LoopHealth(), dict(accepted=0, active=0, echo_frames=0)
    health.start()
    async def peer(reader, writer):
        await echo_peer(reader, writer, metrics)
    async def publish():
        while True:
            value = dict(version=1, probe_revision=PROBE_REVISION, monotonic_ns=time.monotonic_ns(),
                         counters=metrics, event_loop=health.sample(), configured_backlog=4096)
            temporary = Path(SERVER_METRICS + ".tmp")
            temporary.write_text(json.dumps(value, separators=(",", ":")) + "\n")
            temporary.replace(SERVER_METRICS)
            await asyncio.sleep(0.2)
    servers = [await asyncio.start_server(peer, address, port, limit=FRAME_LIMIT, backlog=4096)
               for address in addresses]
    publisher = asyncio.create_task(publish())
    try:
        await asyncio.Future()
    finally:
        publisher.cancel()
        try:
            await publisher
        except asyncio.CancelledError:
            pass
        await health.stop()
        for server in servers:
            server.close()
            await server.wait_closed()


class Client:
    def __init__(self, source, targets, port, public, timeout, source_ports=None):
        self.source = str(ipaddress.IPv4Address(source))
        self.targets = [str(ipaddress.IPv4Address(t)) for t in targets]
        self.port, self.public, self.timeout = port, str(ipaddress.IPv4Address(public)), timeout
        need(self.targets and 1 <= port <= 65535 and 0 < timeout <= 10, "invalid connection target/timeout")
        need(source_ports is None or (isinstance(source_ports, list) and source_ports
             and all(type(p) is int and 1024 <= p <= 65535 for p in source_ports)
             and len(source_ports) == len(set(source_ports))), "invalid explicit source ports")
        self.source_ports = source_ports
        self.nonce = secrets.token_hex(16)
        self.attempts, self.streams = [], {}
        self.round = 0
        self.lock = asyncio.Lock()
        self.health = LoopHealth()

    async def open_one(self, index):
        target = (self.targets[index % len(self.targets)], self.port)
        row = dict(id=index, target=list(target), initial_echo=False, started_monotonic_ns=time.monotonic_ns())
        writer, raw = None, None
        stage = "bind"
        started = time.monotonic()
        try:
            need(self.source_ports is None or index < len(self.source_ports), "explicit source-port list exhausted")
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.setblocking(False)
            raw.bind((self.source, 0 if self.source_ports is None else self.source_ports[index]))
            # Preserve source identity even when connect never completes. The
            # previous diagnostic could not correlate failed SYNs to NAT keys.
            row["source"] = list(raw.getsockname()[:2])
            stage = "connect"
            await asyncio.wait_for(asyncio.get_running_loop().sock_connect(raw, target), self.timeout)
            row["connect_ms"] = (time.monotonic() - started) * 1000
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(sock=raw, limit=FRAME_LIMIT), self.timeout)
            raw = None  # Ownership transfers to StreamWriter.
            stage = "greeting"
            row["wire_peer"] = list(hello(await asyncio.wait_for(reader.readline(), self.timeout), target, self.public))
            stage = "initial-echo"
            frame = payload(self.nonce, index, 0)
            writer.write(frame)
            await asyncio.wait_for(writer.drain(), self.timeout)
            verify_echo(frame, await asyncio.wait_for(reader.readline(), self.timeout))
            row["initial_echo"] = True
            self.streams[index] = (reader, writer)
            writer = None
        except (OSError, RuntimeError, ValueError, TimeoutError) as error:
            row["failure"] = failure(stage, error)
        finally:
            if raw is not None:
                raw.close()
            await close_writer(writer)
            row["elapsed_ms"] = (time.monotonic() - started) * 1000
        return row

    async def open_to(self, count, budget):
        need(type(count) is int and len(self.attempts) < count <= MAX_FLOWS, "invalid next flow count")
        started = time.monotonic()
        for first in range(len(self.attempts), count, 256):
            last = min(count, first + 256)
            if time.monotonic() - started >= budget:
                self.attempts.extend(dict(id=i, target=[self.targets[i % len(self.targets)], self.port],
                                          initial_echo=False,
                                          failure=dict(stage="open-budget", kind="not-attempted", detail="phase budget exhausted"))
                                     for i in range(first, count))
                break
            self.attempts.extend(await asyncio.gather(*(self.open_one(i) for i in range(first, last))))
        return self.manifest(open_seconds=time.monotonic() - started)

    def manifest(self, **extra):
        return dict(version=1, probe_revision=PROBE_REVISION, event_loop=self.health.sample(),
                    nonce=self.nonce, attempts=self.attempts, held=len(self.streams),
                    requested=len(self.attempts), **extra)

    async def probe_one(self, index):
        reader, writer = self.streams[index]
        try:
            frame = payload(self.nonce, index, self.round)
            writer.write(frame)
            await asyncio.wait_for(writer.drain(), self.timeout)
            verify_echo(frame, await asyncio.wait_for(reader.readline(), self.timeout))
            return dict(id=index, verified=True)
        except (OSError, RuntimeError, ValueError, TimeoutError) as error:
            return dict(id=index, verified=False, failure=failure("held-echo", error))

    async def probe(self, budget):
        self.round += 1
        need(self.round <= 100, "too many probe rounds")
        started = time.monotonic()
        indices = sorted(self.streams)
        rows = []
        for first in range(0, len(indices), 1024):
            if time.monotonic() - started >= budget:
                rows.extend(dict(id=i, verified=False, failure=dict(stage="probe-budget", kind="not-probed",
                                                                    detail="phase budget exhausted"))
                            for i in indices[first:])
                break
            rows.extend(await asyncio.gather(*(self.probe_one(i) for i in indices[first:first + 1024])))
        return dict(version=1, probe_revision=PROBE_REVISION, event_loop=self.health.sample(),
                    round=self.round, rows=rows, seconds=time.monotonic() - started)

    async def control(self, reader, writer):
        try:
            request = json.loads(await asyncio.wait_for(reader.readline(), 5))
            need(isinstance(request, dict) and set(request) <= {"action", "count", "budget"}, "invalid control request")
            budget = request.get("budget", 45)
            need(type(budget) in (int, float) and 1 <= budget <= 60, "invalid phase budget")
            async with self.lock:
                if request.get("action") == "open":
                    result = await self.open_to(request["count"], budget)
                elif request.get("action") == "probe":
                    result = await self.probe(budget)
                elif request.get("action") == "manifest":
                    result = self.manifest()
                else:
                    raise RuntimeError("unknown control action")
            writer.write(json.dumps(result, separators=(",", ":")).encode() + b"\n")
        except Exception as error:
            writer.write(json.dumps(dict(error=failure("control", error))).encode() + b"\n")
        try:
            await writer.drain()
        finally:
            await close_writer(writer)

    async def run(self):
        # Disposable root-only control; never network-accessible.
        need(not Path(SOCKET).exists(), "refusing to replace an existing client control socket")
        server = await asyncio.start_unix_server(self.control, SOCKET, limit=FRAME_LIMIT, start_serving=False)
        os.chmod(SOCKET, 0o600)
        await server.start_serving()
        self.health.start()
        try:
            await server.serve_forever()
        finally:
            await self.health.stop()
            server.close()
            for _, writer in self.streams.values():
                writer.close()


async def control_request(action, count, budget):
    reader, writer = await asyncio.open_unix_connection(SOCKET, limit=REPLY_LIMIT)
    try:
        writer.write(json.dumps(dict(action=action, count=count, budget=budget)).encode() + b"\n")
        await writer.drain()
        result = json.loads(await asyncio.wait_for(reader.readline(), 130))
        need("error" not in result, str(result.get("error")))
        return result
    finally:
        await close_writer(writer)


class Batch(ctypes.Structure):
    _fields_ = [(name, kind) for name, kind in (
        ("in_batch", ctypes.c_uint64), ("out_batch", ctypes.c_uint64),
        ("keys", ctypes.c_uint64), ("values", ctypes.c_uint64),
        ("count", ctypes.c_uint32), ("map_fd", ctypes.c_uint32),
        ("elem_flags", ctypes.c_uint64), ("flags", ctypes.c_uint64))]


def validate_metadata(info):
    name = info.get("name")
    need(name in MAP_LAYOUTS, "unreviewed map name")
    key_size, value_size, kind = MAP_LAYOUTS[name]
    need(type(info.get("id")) is int and info["id"] > 0 and info.get("type") == kind,
         "unexpected kernel map identity/type")
    need(info.get("bytes_key") == key_size and info.get("bytes_value") == value_size
         # The agent sizes the state maps at load (DP-06): up to 6 x 4,194,304.
         and type(info.get("max_entries")) is int and 1 <= info["max_entries"] <= 1 << 25,
         "unexpected kernel map ABI/capacity")
    return info


class KernelReader:
    def __init__(self, info):
        self.info = validate_metadata(info)
        need(platform.machine() == "x86_64" and os.geteuid() == 0, "disposable x86_64 root reader required")
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.syscall.restype = ctypes.c_long
        attr = ctypes.create_string_buffer(struct.pack("<III", info["id"], 0, 0))
        self.fd = self.libc.syscall(321, 14, ctypes.byref(attr), ctypes.sizeof(attr))
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "BPF_MAP_GET_FD_BY_ID")

    def batch(self, size, cursor):
        keys = ctypes.create_string_buffer(self.info["bytes_key"] * size)
        values = ctypes.create_string_buffer(self.info["bytes_value"] * size)
        input_cursor, output_cursor = ctypes.c_uint32(cursor or 0), ctypes.c_uint32(0)
        attr = Batch(in_batch=ctypes.addressof(input_cursor) if cursor is not None else 0,
                     out_batch=ctypes.addressof(output_cursor), keys=ctypes.addressof(keys),
                     values=ctypes.addressof(values), count=size, map_fd=self.fd)
        # This is the ONLY entry-reading command. No LOOKUP_ELEM/GET_NEXT_KEY,
        # writes, deletes, clearing, policy changes, or LRU-reference refresh.
        result = self.libc.syscall(321, 24, ctypes.byref(attr), ctypes.sizeof(attr))
        error = ctypes.get_errno() if result < 0 else 0
        if error == errno.ENOSPC:
            need(attr.count == 0, "partial ENOSPC batch cannot be retried safely")
            return None
        if error not in (0, errno.ENOENT):
            raise OSError(error, "BPF_MAP_LOOKUP_BATCH")
        need(attr.count <= size, "oversized kernel batch")
        key_size, value_size = self.info["bytes_key"], self.info["bytes_value"]
        rows = [(keys.raw[i * key_size:(i + 1) * key_size],
                 values.raw[i * value_size:(i + 1) * value_size]) for i in range(attr.count)]
        return output_cursor.value, rows, error == errno.ENOENT

    def close(self):
        os.close(self.fd)


def walk(reader, max_entries, deadline):
    rows, cursor, size = {}, None, min(1024, max_entries)
    for _ in range(4096):
        need(time.monotonic() < deadline, "raw snapshot time budget exhausted")
        batch = reader.batch(size, cursor)
        if batch is None:
            need(size < max_entries, "map bucket exceeds reviewed snapshot bound")
            size = min(size * 2, max_entries)
            continue
        next_cursor, items, end = batch
        need(len(rows) + len(items) <= max_entries, "map grew beyond capacity during snapshot")
        for key, value in items:
            need(key not in rows, "duplicate map key during snapshot")
            rows[key] = value
        if end:
            return rows
        need(items and next_cursor != cursor, "non-progressing map snapshot")
        cursor = next_cursor
    raise RuntimeError("raw snapshot syscall budget exhausted")


def snapshot():
    started = time.monotonic_ns()
    result = dict(version=1, atomic_snapshot=False, entry_reads="BPF_MAP_LOOKUP_BATCH only",
                  started_ns=started, maps={}, complete=False)
    maps = json.loads(subprocess.run(["bpftool", "-j", "map", "show"], check=True,
                                    capture_output=True, text=True, timeout=10).stdout)
    deadline = time.monotonic() + 8
    for name in MAP_LAYOUTS:
        row = dict(complete=False)
        result["maps"][name] = row
        reader = None
        try:
            choices = [m for m in maps if m.get("name") == name]
            need(len(choices) == 1, "map identity is missing/ambiguous")
            info = validate_metadata(choices[0])
            row["metadata"] = {field: info[field] for field in
                               ("name", "id", "type", "bytes_key", "bytes_value", "max_entries")}
            reader = KernelReader(info)
            first = walk(reader, info["max_entries"], deadline)
            second = walk(reader, info["max_entries"], deadline)
            need(first.keys() == second.keys(), "keys changed between complete batch walks")
            row.update(complete=True, raw_count=len(second),
                       entries=[[k.hex(), v.hex()] for k, v in sorted(second.items())])
        except Exception as error:
            row["error"] = failure("raw-snapshot", error)
        finally:
            if reader is not None:
                reader.close()
    result["finished_ns"] = time.monotonic_ns()
    result["complete"] = all(row["complete"] for row in result["maps"].values())
    return result


def decode_key(name, raw):
    if name == "FW_FLOWS":
        need(len(raw) == FIREWALL_KEY.size and raw[-2:] == b"\0\0", "invalid firewall key width/padding")
        policy, src, dst, sport, dport, proto, family = FIREWALL_KEY.unpack(raw)
        need(family in (4, 6), "invalid firewall key family")
        if family != 4:
            return None
        need(src[4:] == bytes(12) and dst[4:] == bytes(12), "invalid IPv4 firewall key")
        src, dst = src[:4], dst[:4]
    else:
        need(len(raw) == FLOW_KEY.size and raw[-3:] == bytes(3), "invalid NAT key width/padding")
        policy, src, dst, sport, dport, proto = FLOW_KEY.unpack(raw)
    return policy, str(ipaddress.IPv4Address(src)), str(ipaddress.IPv4Address(dst)), sport, dport, proto


def tuple_roles(row):
    source, target, public = endpoint(row["source"]), endpoint(row["target"]), endpoint(row["wire_peer"])
    return dict(private_forward=(source[0], target[0], source[1], target[1], 6),
                private_reverse=(target[0], source[0], target[1], source[1], 6),
                public_forward=(public[0], target[0], public[1], target[1], 6),
                public_reverse=(target[0], public[0], target[1], public[1], 6))


def indices(sample):
    need(sample.get("version") == 1 and sample.get("complete") is True
         and sample.get("atomic_snapshot") is False, "incomplete/invalid map sample")
    need(set(sample["maps"]) == set(MAP_LAYOUTS), "missing or unexpected state-map sample")
    for name, row in sample["maps"].items():
        validate_metadata(row["metadata"])
        need(row.get("complete") is True and row["metadata"]["name"] == name
             and type(row["raw_count"]) is int
             and row["raw_count"] == len(row["entries"]) <= row["metadata"]["max_entries"],
             "invalid/incomplete raw map entries or count")
    fw, nat = {}, {}
    for name, target in (("FW_FLOWS", fw), ("CONNTRACK", nat)):
        row = sample["maps"][name]
        need(row.get("complete") is True, "incomplete required map")
        validate_metadata(row["metadata"])
        for key_hex, value_hex in row["entries"]:
            raw, value = bytes.fromhex(key_hex), bytes.fromhex(value_hex)
            need(len(value) == row["metadata"]["bytes_value"], "invalid map value width")
            decoded = decode_key(name, raw)
            if decoded is not None:
                need(decoded not in target, "duplicate decoded map key")
                target[decoded] = value
    return fw, nat


def observed_roles(row, firewall):
    roles = tuple_roles(row)
    # Build once in analyse(), never scan the full map separately per flow.
    return [(role, policy, value) for role, key in roles.items()
            for policy, value in firewall.get(key, [])]


def analyse(sample, manifest, probes, template=None, *, lan_index, wan_index):
    fw, nat = indices(sample)
    policies = {}
    for key_hex, value_hex in sample["maps"]["IFACE_POLICY"]["entries"]:
        key, value = bytes.fromhex(key_hex), bytes.fromhex(value_hex)
        need(len(key) == 4 and len(value) == 4, "invalid interface policy width")
        index, policy = struct.unpack("<I", key)[0], struct.unpack("<I", value)[0]
        need(index not in policies, "duplicate interface policy")
        policies[index] = policy
    need(lan_index in policies and wan_index in policies and policies[lan_index] != policies[wan_index],
         "missing or indistinguishable LAN/WAN policy bindings")
    lookup, nat_lookup = {}, {}
    for (policy, *key), value in fw.items():
        lookup.setdefault(tuple(key), []).append((policy, value))
    for (policy, *key), value in nat.items():
        nat_lookup.setdefault(tuple(key), []).append((policy, value))
    attempts = manifest["attempts"]
    need(len(attempts) == manifest["requested"] and len({r["id"] for r in attempts}) == len(attempts),
         "invalid client manifest identity")
    successful = [row for row in attempts if row.get("initial_echo") is True]
    probe_rows = {row["id"]: row for row in probes["rows"]}
    need(len(probe_rows) == len(probes["rows"])
         and set(probe_rows) == {row["id"] for row in successful}, "probe does not cover every held flow exactly once")
    need(manifest["held"] == len(successful), "held connection count is inconsistent")
    if template is None:
        need(len(successful) == 1 and len(attempts) == 1, "ownership template requires exactly one real flow")
        template = sorted({(role, policy) for role, policy, _ in observed_roles(successful[0], lookup)})
        need(len(template) >= 2, "one-flow sample cannot establish firewall key ownership")
    else:
        template = [tuple(item) for item in template]
        need(len(template) >= 2 and len(set(template)) == len(template), "invalid observed ownership template")
    rows, external = [], set()
    alias_count = 0
    phase_counts, age_counts = Counter(), Counter()
    now = sample["finished_ns"]
    for key, value in fw.items():
        last, age, phase, reply = FIREWALL_VALUE.unpack(value)
        need(phase in (1, 2, 3, 4, 5) and reply in (0, 1), "invalid firewall state")
        if key[-1] != 6:
            continue
        phase_counts[str(phase)] += 1
        idle = max(0, now - last) + age
        lifetime = 86400 if phase == 3 else 30
        age_counts["expired" if idle >= lifetime * 1_000_000_000 else "unexpired"] += 1
    for row in successful:
        roles = tuple_roles(row)
        actual = {(role, policy) for role, policy, _ in observed_roles(row, lookup)}
        missing = sorted(set(template) - actual)
        bindings = nat_lookup.get(roles["public_reverse"], [])
        rows.append(dict(id=row["id"], missing_roles=missing, observed_roles=sorted(actual),
                         bindings=bindings, probe=probe_rows[row["id"]]))
        identity = (endpoint(row["target"]), endpoint(row["wire_peer"]))
        if identity in external:
            alias_count += 1
        external.add(identity)
    return _finish_analysis(sample, manifest, probes, template, rows, successful,
                            alias_count, phase_counts, age_counts, policies, lan_index, wan_index)


def _finish_analysis(sample, manifest, probes, template, rows, successful, aliases, phases, ages,
                     policies, lan_index, wan_index):
    failures = []
    for row, flow in zip(rows, successful):
        binding_kind = "nat-binding-missing"
        if len(row["bindings"]) > 1:
            binding_kind = "nat-binding-ambiguous"
        elif row["bindings"]:
            policy, raw = row["bindings"][0]
            target, secondary, port, secondary_port, flags, pad, _, _, _, _ = NAT_VALUE.unpack(raw)
            source = endpoint(flow["source"])
            valid = (str(ipaddress.IPv4Address(target)) == source[0] and port == source[1]
                     and secondary == bytes(4) and secondary_port == 0 and flags == 2 and pad == 0
                     and policy == policies[wan_index])
            binding_kind = "owned" if valid else "nat-binding-foreign"
        if binding_kind != "owned" or row["missing_roles"] or row["probe"].get("verified") is not True:
            failures.append(dict(id=row["id"], nat=binding_kind, missing_firewall_roles=row["missing_roles"],
                                 echo_failure=row["probe"].get("failure"),
                                 correlation="map-state-missing-or-foreign" if binding_kind != "owned" or row["missing_roles"]
                                 else "echo-failed-with-owned-map-state"))
    opening = [dict(id=row["id"], failure=row.get("failure")) for row in manifest["attempts"]
               if row.get("initial_echo") is not True]
    return dict(version=1, atomic_snapshot=False, requested=manifest["requested"],
                initial_nonce_echoes=len(successful), verified_held_echoes=sum(r.get("verified") is True for r in probes["rows"]),
                observed_ownership_template=template, opening_failures=opening, owned_flow_failures=failures,
                external_tuple_aliases=aliases, firewall_tcp_phases=dict(phases),
                firewall_tcp_age_classes_assuming_default_timeouts=dict(ages),
                assumed_age_timeouts_seconds=dict(tcp_syn=30, tcp_established=86400, tcp_closing=30),
                actual_policy_bindings=dict(lan=dict(ifindex=lan_index, policy=policies[lan_index]),
                                            wan=dict(ifindex=wan_index, policy=policies[wan_index])),
                raw_maps={name: dict(map_id=value["metadata"]["id"], raw_count=value["raw_count"],
                                    max_entries=value["metadata"]["max_entries"])
                          for name, value in sample["maps"].items()},
                passed=not failures and not opening and aliases == 0,
                scope="observed nonce-verified live TCP/map correlation, not atomic snapshot or eviction-count proof")


def output(value, path):
    text = json.dumps(value, separators=(",", ":")) + "\n"
    if path:
        Path(path).write_text(text)
    else:
        print(text, end="")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    server = sub.add_parser("serve")
    server.add_argument("--address", action="append", required=True)
    server.add_argument("--port", type=int, default=9000)
    client = sub.add_parser("client")
    client.add_argument("--source", required=True)
    client.add_argument("--target", action="append", required=True)
    client.add_argument("--public", required=True)
    client.add_argument("--port", type=int, default=9000)
    client.add_argument("--timeout", type=float, default=2)
    client.add_argument("--source-port", type=int, action="append")
    control = sub.add_parser("control")
    control.add_argument("--action", choices=("open", "probe", "manifest"), required=True)
    control.add_argument("--count", type=int)
    control.add_argument("--budget", type=int, default=45)
    control.add_argument("--output")
    dump = sub.add_parser("snapshot")
    dump.add_argument("--output")
    counters = sub.add_parser("runtime")
    counters.add_argument("--output")
    args = parser.parse_args()
    if args.command in ("serve", "client"):
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        need(hard >= 65536, "fixture requires LimitNOFILE>=65536")
        resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, 65536), hard))
    if args.command == "serve":
        asyncio.run(serve(args.address, args.port))
    elif args.command == "client":
        asyncio.run(Client(args.source, args.target, args.port, args.public, args.timeout, args.source_port).run())
    elif args.command == "control":
        output(asyncio.run(control_request(args.action, args.count, args.budget)), args.output)
    elif args.command == "runtime":
        output(runtime(), args.output)
    else:
        value = snapshot()
        output(value, args.output)
        raise SystemExit(0 if value["complete"] else 1)


if __name__ == "__main__":
    main()
