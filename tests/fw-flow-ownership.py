"""Kernel assertions for the FlowSpec + HA map-ownership regression."""
import argparse
import ipaddress
import json
import socket
import struct
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("mode", choices=["seed", "present", "absent"])
args = parser.parse_args()

def bpftool(*arguments):
    return json.loads(subprocess.check_output(["bpftool", "-j", *arguments], text=True))

def interface_program_ids(value):
    if isinstance(value, list):
        return [item for part in value for item in interface_program_ids(part)]
    if isinstance(value, dict):
        if "xdp" in value:
            return interface_program_ids(value["xdp"])
        if value.get("devname") == "eth1" and "id" in value:
            return [value["id"]]
        return [item for part in value.values() for item in interface_program_ids(part)]
    return []

if args.mode == "seed":
    key = struct.pack("<I4s4sHHB3x", 1, ipaddress.ip_address("203.0.113.55").packed,
                      ipaddress.ip_address("10.7.0.2").packed, 0, 8, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.bind(("127.0.0.1", 5430))
        peer.sendto(b"VCS1" + struct.pack("<HH", 1, 1) + key, ("127.0.0.1", 5429))
    raise SystemExit(0)

ids = interface_program_ids(bpftool("net", "show", "dev", "eth1"))
assert len(ids) == 1, ids
# The attached dispatcher tail-calls the protocol programs. Follow the actual
# program-array graph; the dispatcher's own map_ids need not include FW_FLOWS.
map_info = {item["id"]: item for item in bpftool("map", "show")}
pending = list(ids)
visited = set()
flow_ids = set()
while pending:
    program_id = pending.pop()
    if program_id in visited:
        continue
    visited.add(program_id)
    program = bpftool("prog", "show", "id", str(program_id))
    if isinstance(program, list):
        assert len(program) == 1, program
        program = program[0]
    assert program["type"] == "xdp", program
    for map_id in program["map_ids"]:
        info = map_info[map_id]
        if info["name"] == "FW_FLOWS":
            flow_ids.add(map_id)
        if info["type"] == "prog_array":
            for row in bpftool("map", "dump", "id", str(map_id)) or []:
                target = row["value"]
                if isinstance(target, list):
                    target = int.from_bytes(bytes(int(value, 16) for value in target), "little")
                elif isinstance(target, dict):
                    target = target["id"]
                assert isinstance(target, int) and target > 0, row
                pending.append(target)
assert len(flow_ids) == 1, (ids, visited, flow_ids)
flow_maps = [map_info[flow_ids.pop()]]
rows = bpftool("map", "dump", "id", str(flow_maps[0]["id"])) or []
matching = []
marker = False
for row in rows:
    key = bytes(int(value, 16) for value in row["key"])
    assert len(key) == 20, key.hex()
    if key[8:12] == ipaddress.ip_address("10.7.0.2").packed and key[16] == 1:
        matching.append(key.hex())
        marker |= key[4:8] == ipaddress.ip_address("203.0.113.55").packed
print(json.dumps(dict(mapId=flow_maps[0]["id"], matching=matching, importedMarker=marker)))
if args.mode == "present":
    assert matching and marker, "HA import must reach the actual packet program's map"
else:
    assert not matching, "FlowSpec must purge matching grants while HA owns its shared handle"
