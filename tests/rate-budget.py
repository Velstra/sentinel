import json
import shlex
import struct

machine.wait_for_unit("multi-user.target")
machine.wait_for_unit("sentinel-boot-late.service")
peer.wait_for_unit("multi-user.target")
python = "/run/current-system/sw/bin/python3"

def run(source):
    return machine.succeed(python + " -u -c " + shlex.quote(source))

def apply(*lines):
    source = "\n".join([*lines, "commit", "save", "exit", ""])
    result = machine.succeed("su admin -c " + shlex.quote("printf %s " + shlex.quote(source) + " | sentinel configure 2>&1"))
    assert "commit ok: applied live" in result and "saved /" in result, result

apply("set interface eth1 address 198.18.90.1/24", "set interface eth1 zone wan", "set firewall global default-action accept", "set firewall global stateful false", "set firewall rule atomic from wan", "set firewall rule atomic direction in", "set firewall rule atomic proto udp", "set firewall rule atomic port 18091", "set firewall rule atomic action accept", "set firewall rule atomic limit 1", "set firewall rule atomic burst 7")
programs = json.loads(machine.succeed("bpftool -j prog show"))
entry = [p for p in programs if p["name"] == "velstra"]
assert len(entry) == 1, entry
program = str(entry[0]["id"])
ifindex = int(machine.succeed("cat /sys/class/net/eth1/ifindex"))

def hexes(data):
    return " ".join(f"{v:02x}" for v in data)

def current_maps():
    # Map names are global and need not be unique across pinned generations.
    # Follow the actual entry's jump table to its rule-processing program.
    def program_maps(program_id):
        info = json.loads(machine.succeed("bpftool -j prog show id " + str(program_id)))
        maps = {}
        for map_id in info["map_ids"]:
            detail = json.loads(machine.succeed("bpftool -j map show id " + str(map_id)))
            assert detail["name"] not in maps, detail
            maps[detail["name"]] = map_id
        return maps
    root = program_maps(program)
    main = json.loads(machine.succeed("bpftool -j map lookup id " + str(root["VELSTRA_PROGS"]) + " key hex 01 00 00 00"))
    main_id = int.from_bytes(bytes(int(part, 16) for part in main["value"]), "little")
    stage = program_maps(main_id)
    assert stage["STATS"] == root["STATS"], (stage, root)
    return {"RULE_LIMITS": stage["RULE_LIMITS"], "PORT_LIMITS": root["PORT_LIMITS"], "STATS": root["STATS"]}

owned_maps = current_maps()

def bucket(map_name, key, *, busy=0, rate=1, burst=7, units=None):
    if units is None:
        units = burst
    # Pin a future refill clock so the SMP proof measures exactly the programmed
    # initial credit, irrespective of scheduling delays or emulator speed.
    value = struct.pack("<IIIIQQ", busy, 0, rate, burst, units * 1_000_000_000, 2**64 - 1)
    machine.succeed("bpftool map update id " + str(owned_maps[map_name]) + " key hex " + hexes(key) + " value hex " + hexes(value))

def read_bucket(map_name, key):
    result = json.loads(machine.succeed("bpftool -j map lookup id " + str(owned_maps[map_name]) + " key hex " + hexes(key)))
    return struct.unpack("<IIIIQQ", bytes(int(b, 16) for b in result["value"]))

def counters(slot):
    result = json.loads(machine.succeed("bpftool -j map lookup id " + str(owned_maps["STATS"]) + " key hex " + hexes(struct.pack("<I", slot))))
    return {row["cpu"]: int.from_bytes(bytes(int(b, 16) for b in row["value"]), "little") for row in result["values"]}

def delta(before, slot):
    after = counters(slot)
    return {cpu: after[cpu] - before[cpu] for cpu in before}

run("""
import socket, struct, pathlib
eth = bytes.fromhex('0200000000010200000000020800')
def checksum(data):
    n = sum(int.from_bytes(data[i:i+2], 'big') for i in range(0, len(data), 2))
    n = (n & 65535) + (n >> 16)
    n = (n & 65535) + (n >> 16)
    return (~n) & 65535
ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 28, 77, 0, 64, 17, 0, socket.inet_aton('198.18.90.2'), socket.inet_aton('198.18.90.1'))
ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
packet = eth + ip + struct.pack('!HHHH', 45100, 18091, 8, 0)
pathlib.Path('/run/atomic-packet').write_bytes(packet)
ctx = bytearray(24)
struct.pack_into('<I', ctx, 4, len(packet))
struct.pack_into('<I', ctx, 12, IFINDEX)
pathlib.Path('/run/atomic-ctx').write_bytes(ctx)
""".replace("IFINDEX", str(ifindex)))

def race(repeat=500):
    result = run("""
import concurrent.futures, threading, subprocess, json
gate = threading.Barrier(4)
def worker(cpu):
    gate.wait(timeout=20)
    result = subprocess.run(['taskset', '-c', str(cpu), 'bpftool', '-j', 'prog', 'run', 'id', PROGRAM, 'data_in', '/run/atomic-packet', 'ctx_in', '/run/atomic-ctx', 'repeat', REPEAT], text=True, capture_output=True)
    assert result.returncode == 0, (cpu, result.returncode, result.stdout, result.stderr)
    return json.loads(result.stdout)['retval']
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    results = list(pool.map(worker, range(4)))
print(json.dumps(results))
""".replace("PROGRAM", repr(program)).replace("REPEAT", repr(str(repeat))))
    return json.loads(result)

with subtest("one rule budget across all four packet-processing CPUs"):
    key = struct.pack("<I", 1)
    bucket("RULE_LIMITS", key)
    before = {slot: counters(slot) for slot in [0, 3, 34, 45]}
    results = race()
    passed = delta(before[3], 3)
    dropped = delta(before[34], 34)
    rx = delta(before[0], 0)
    contention = delta(before[45], 45)
    assert all(rx[cpu] >= 500 for cpu in range(4)), rx
    assert sum(passed.values()) == 7, (passed, dropped, results)
    assert sum(dropped.values()) == 1993, (passed, dropped, results)
    assert sum(contention.values()) <= 1993, contention
    assert read_bucket("RULE_LIMITS", key) == (0, 0, 1, 7, 0, 2**64-1)
    print("ACTUAL_SHARED_RULE_CPUS", json.dumps({"passed": passed, "dropped": dropped, "contention": contention}), flush=True)

with subtest("contended rule budget fails closed without stealing the owner's lock"):
    key = struct.pack("<I", 1)
    bucket("RULE_LIMITS", key, busy=1)
    before = {slot: counters(slot) for slot in [3, 34, 45]}
    results = race(50)
    assert results == [1] * 4, results
    assert sum(delta(before[3], 3).values()) == 0
    assert sum(delta(before[34], 34).values()) == 200
    assert sum(delta(before[45], 45).values()) == 200
    assert read_bucket("RULE_LIMITS", key) == (1, 0, 1, 7, 7_000_000_000, 2**64-1)
    bucket("RULE_LIMITS", key)

apply("delete firewall rule atomic")
programs = json.loads(machine.succeed("bpftool -j prog show"))
entry = [p for p in programs if p["name"] == "velstra"]
assert len(entry) == 1, entry
program = str(entry[0]["id"])
owned_maps = current_maps()
with subtest("one byte budget across all four packet-processing CPUs"):
    key = struct.pack("<I", ifindex)
    bucket("PORT_LIMITS", key, burst=42*7)
    before = {slot: counters(slot) for slot in [0, 43, 45]}
    results = race()
    dropped = delta(before[43], 43)
    rx = delta(before[0], 0)
    contention = delta(before[45], 45)
    assert sum(rx.values()) == 7, (rx, dropped, results)
    assert sum(dropped.values()) == 1993, (rx, dropped, results)
    assert all(rx[cpu] + dropped[cpu] >= 500 for cpu in range(4)), (rx, dropped)
    assert sum(contention.values()) <= 1993, contention
    assert read_bucket("PORT_LIMITS", key) == (0, 0, 1, 294, 0, 2**64-1)
    print("ACTUAL_SHARED_PORT_CPUS", json.dumps({"rx": rx, "dropped": dropped, "contention": contention}), flush=True)

with subtest("contended port budget fails closed and exposes contention"):
    key = struct.pack("<I", ifindex)
    bucket("PORT_LIMITS", key, busy=1, burst=42*7)
    before = {slot: counters(slot) for slot in [0, 43, 45]}
    results = race(50)
    assert results == [1] * 4, results
    assert sum(delta(before[0], 0).values()) == 0
    assert sum(delta(before[43], 43).values()) == 200
    assert sum(delta(before[45], 45).values()) == 200
    assert read_bucket("PORT_LIMITS", key) == (1, 0, 1, 294, 294_000_000_000, 2**64-1)
    # Remove test-injected state before verifying traffic recovery.
    machine.succeed("bpftool map delete id " + str(owned_maps["PORT_LIMITS"]) + " key hex " + hexes(key))

with subtest("ordinary packet traffic recovers after contention"):
    peer.succeed("ping -c 3 -W 1 198.18.90.1")
    machine.succeed("ping -c 3 -W 1 198.18.90.2")
    stats = machine.succeed("sentinel agent-query stats")
    assert "rate_limit_contention" in stats, stats
    print("ACTUAL_SHARED_BUCKET_STATS", stats, flush=True)
