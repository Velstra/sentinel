"""Real kernel TC reassembly primitive; not a Sentinel NAT acceptance test."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import time
import traceback


PIN = "/sys/fs/bpf/fragment_primitive"
CLIENT = "198.18.1.2"
SERVER = "198.18.2.2"
PORT = 49200


def run(*args, check=True):
    result = subprocess.run(args, check=False, capture_output=True, text=True, timeout=15)
    if check and result.returncode:
        raise RuntimeError(f"command {args!r} exited {result.returncode}:\n{result.stdout}\n{result.stderr}")
    return result


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def body(size, ident):
    # Wire bytes resembling the private receipt must not authorize admission.
    prefix = struct.pack("!IIIII", 0x46524147, 0x10203040, 1, 3, 0)
    return (prefix + bytes((i + ident) % 251 for i in range(size)))[:size]


def send_packets(args):
    payload = body(args.size, args.ident)
    source, target = socket.inet_aton(CLIENT), socket.inet_aton(SERVER)
    udp = struct.pack("!HHHH", 49300, PORT, len(payload) + 8, 0) + payload
    pseudo = source + target + struct.pack("!BBH", 0, 17, len(udp))
    value = checksum(pseudo + udp) or 65535
    udp = udp[:6] + struct.pack("!H", value) + udp[8:]
    mtu = 1480
    pieces = list(range(0, len(udp), mtu))
    if args.partial:
        pieces = pieces[:-1]
    if args.reverse:
        pieces.reverse()
    dest = bytes.fromhex(args.mac.replace(":", ""))
    own = bytes.fromhex(Path("/sys/class/net/c0/address").read_text().strip().replace(":", ""))
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as raw:
        raw.bind(("c0", 0))
        for offset in pieces:
            piece = udp[offset : offset + mtu]
            flags = offset // 8 | (0x2000 if offset + len(piece) < len(udp) else 0)
            ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(piece), args.ident,
                             flags, 64, 17, 0, source, target)
            ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
            raw.send(dest + own + b"\x08\x00" + ip + piece)
            time.sleep(0.0002)


def receive(args):
    frames, received = [], []
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    raw.bind(("s0", 0))
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
    udp.bind((SERVER, PORT))
    Path(args.ready).touch()
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        readable, _, _ = select.select([raw, udp], [], [], min(0.1, max(0, deadline - time.monotonic())))
        for sock in readable:
            if sock is udp:
                data, peer = udp.recvfrom(65535)
                received.append({"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "peer": peer})
                deadline = min(deadline, time.monotonic() + 0.2)
            else:
                data = raw.recv(65535)
                if len(data) < 34 or data[12:14] != b"\x08\x00":
                    continue
                ip = data[14:34]
                if struct.unpack_from("!H", ip, 4)[0] != args.ident:
                    continue
                total, frag = struct.unpack_from("!HH", ip, 2)[0], struct.unpack_from("!H", ip, 6)[0]
                frames.append({"total": total, "offset": (frag & 0x1fff) * 8,
                               "more": bool(frag & 0x2000), "ttl": ip[8],
                               "ip_checksum_valid": checksum(ip) == 0,
                               "payload_hex": data[34 : 14 + total].hex()})
    raw.close()
    udp.close()
    Path(args.output).write_text(json.dumps({"frames": frames, "received": received}))


def map_set(key, value):
    key_bytes, value_bytes = struct.pack("<I", key), struct.pack("<I", value)
    run("bpftool", "map", "update", "pinned", PIN + "/maps/settings", "key", "hex",
        *[f"{b:02x}" for b in key_bytes], "value", "hex", *[f"{b:02x}" for b in value_bytes])


def counter(key):
    result = json.loads(run("bpftool", "-j", "map", "lookup", "pinned", PIN + "/maps/counters",
                            "key", "hex", *[f"{b:02x}" for b in struct.pack("<I", key)]).stdout)
    value = result["value"]
    if isinstance(value, list):
        return int.from_bytes(bytes(int(v, 0) if isinstance(v, str) else v for v in value), "little")
    return int(value)


def configure():
    for ns in ("frag-client", "frag-server"):
        run("ip", "netns", "add", ns)
        run("ip", "-n", ns, "link", "set", "lo", "up")
    for root, peer, ns, address, peer_address in (
        ("r-lan", "c0", "frag-client", "198.18.1.1/24", CLIENT + "/24"),
        ("r-wan", "s0", "frag-server", "198.18.2.1/24", SERVER + "/24"),
    ):
        run("ip", "link", "add", root, "type", "veth", "peer", "name", peer)
        run("ip", "link", "set", peer, "netns", ns)
        run("ip", "address", "add", address, "dev", root)
        run("ip", "link", "set", root, "up")
        run("ip", "-n", ns, "address", "add", peer_address, "dev", peer)
        run("ip", "-n", ns, "link", "set", peer, "up")
        run("ip", "-n", ns, "route", "add", "default", "via", address.split("/")[0])
    run("ip", "link", "add", "frag-stage", "type", "dummy")
    run("ip", "link", "set", "frag-stage", "up")
    run("sysctl", "-w", "net.ipv4.ip_forward=1", "net.ipv4.ipfrag_time=2")
    for iface in ("all", "default", "r-lan", "r-wan"):
        run("sysctl", "-w", f"net.ipv4.conf.{iface}.rp_filter=0")
    server_links = json.loads(run("ip", "-n", "frag-server", "-j", "link", "show", "s0").stdout)
    run("ip", "neighbor", "replace", SERVER, "lladdr", server_links[0]["address"], "nud", "permanent", "dev", "r-wan")
    run("tc", "qdisc", "replace", "dev", "r-wan", "root", "handle", "1:", "fq_codel")
    for iface in ("r-wan", "frag-stage"):
        run("tc", "qdisc", "add", "dev", iface, "clsact")
    Path(PIN + "/maps").mkdir(parents=True)


def setup_filters(obj):
    run("bpftool", "prog", "loadall", obj, PIN, "type", "classifier", "pinmaps", PIN + "/maps")
    indices = [socket.if_nametoindex(name) for name in ("frag-stage", "r-lan", "r-wan")]
    for key, value in enumerate(indices + [0, 0x10203040, 1]):
        map_set(key, value)
    run("tc", "filter", "add", "dev", "r-wan", "egress", "protocol", "ip", "pref", "1",
        "bpf", "direct-action", "pinned", PIN + "/release")
    run("tc", "filter", "add", "dev", "r-wan", "egress", "protocol", "ip", "pref", "2",
        "matchall", "action", "mirred", "egress", "redirect", "dev", "frag-stage")
    run("tc", "filter", "add", "dev", "frag-stage", "egress", "protocol", "ip", "pref", "1",
        "matchall", "action", "ct", "zone", "54321", "pipe", "action", "goto", "chain", "1")
    # Same tc_run: chain jump retains MRU. The observer and terminal drop share chain 1.
    run("tc", "filter", "add", "dev", "frag-stage", "egress", "chain", "1", "protocol", "ip", "pref", "2",
        "bpf", "pinned", PIN + "/observe", "action", "ct", "clear", "pipe",
        "action", "mirred", "egress", "redirect", "dev", "r-wan")
    run("tc", "filter", "add", "dev", "frag-stage", "egress", "chain", "1", "protocol", "ip", "pref", "99",
        "matchall", "action", "drop")
    return indices


def flow_ct():
    result = run("conntrack", "-L", "-f", "ipv4", "-s", CLIENT, "-d", SERVER, check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr)
    return [line for line in result.stdout.splitlines() if "src=" in line]


def main(args):
    report = {"schema": 1, "scope": "isolated kernel primitive, no Sentinel NAT qualification",
              "kernel": os.uname().release, "label": args.label,
              "fixture_sha256": hashlib.sha256(Path(args.object).read_bytes()).hexdigest(), "cases": []}
    try:
        configure()
        report["interface_indices"] = setup_filters(args.object)
        report["kernel_conntrack_before"] = flow_ct()
        assert not report["kernel_conntrack_before"]
        router_mac = Path("/sys/class/net/r-lan/address").read_text().strip()
        cases = [("in-order", 6000, False, False, 0, True),
                 ("out-of-order", 6000, True, False, 0, True),
                 ("maximum-ipv4-out-of-order", 65507, True, False, 0, True),
                 ("nonfragmented-control", 128, False, False, 0, True),
                 ("missing-receipt", 6000, True, False, 1, False),
                 ("stale-epoch", 6000, True, False, 2, False),
                 ("wrong-output", 6000, True, False, 3, False),
                 ("wrong-header-binding", 6000, True, False, 4, False),
                 ("incomplete-queue", 6000, True, True, 0, False),
                 ("wire-receipt-without-observer", 6000, True, False, 5, False)]
        for num, (name, size, reverse, partial, mode, allowed) in enumerate(cases):
            ident = 21000 + num
            ready, out = f"/tmp/frag-ready-{num}", f"/tmp/frag-wire-{num}.json"
            map_set(3, mode)
            if mode == 5:
                run("tc", "filter", "del", "dev", "frag-stage", "egress", "chain", "1",
                    "protocol", "ip", "pref", "2")
            before = [counter(i) for i in range(12)]
            receiver = subprocess.Popen(["ip", "netns", "exec", "frag-server", sys.executable,
                                         __file__, "receive", "--ident", str(ident), "--ready", ready,
                                         "--output", out, "--timeout", "1.6"])
            try:
                deadline = time.monotonic() + 3
                while not Path(ready).exists():
                    assert receiver.poll() is None, "receiver exited before ready"
                    assert time.monotonic() < deadline, "receiver readiness timeout"
                    time.sleep(0.01)
                command = ["ip", "netns", "exec", "frag-client", sys.executable, __file__, "send",
                           "--size", str(size), "--ident", str(ident), "--mac", router_mac]
                if reverse:
                    command.append("--reverse")
                if partial:
                    command.append("--partial")
                run(*command)
                assert receiver.wait(timeout=4) == 0
            finally:
                if receiver.poll() is None:
                    receiver.kill()
                    receiver.wait()
            wire = json.loads(Path(out).read_text())
            after = [counter(i) for i in range(12)]
            delta = [end - start for start, end in zip(before, after)]
            item = {"name": name, "payload_bytes": size, "counter_delta": delta, "wire": wire,
                    "kernel_conntrack": flow_ct(), "passed": False}
            report["cases"].append(item)
            if allowed:
                assert len(wire["received"]) == 1, item
                assert wire["received"][0]["sha256"] == hashlib.sha256(body(size, ident)).hexdigest(), item
                frames = sorted(wire["frames"], key=lambda frame: frame["offset"])
                assert frames and all(frame["ttl"] == 63 and frame["ip_checksum_valid"] and frame["total"] <= 1500 for frame in frames), item
                packet = bytes.fromhex("".join(frame["payload_hex"] for frame in frames))
                assert len(packet) == size + 8, item
                pseudo = socket.inet_aton(CLIENT) + socket.inet_aton(SERVER) + struct.pack("!BBH", 0, 17, len(packet))
                assert checksum(pseudo + packet) == 0, item
                assert delta[0] == 1 and delta[1] == size + 28 and delta[2] == len(frames) and delta[3] == 0, item
            else:
                assert not wire["received"] and not wire["frames"], item
                assert delta[2] == 0, item
                assert delta[0] == (0 if partial or mode == 5 else 1), item
                if not partial and mode != 5:
                    assert delta[3] > 0, item
            assert not item["kernel_conntrack"], item
            item["passed"] = True
            print("PASSED " + name, flush=True)
        time.sleep(2.5)
        report["kernel_conntrack_after"] = flow_ct()
        report["qdisc"] = json.loads(run("tc", "-s", "-j", "qdisc", "show", "dev", "r-wan").stdout)
        report["filters"] = {
            iface: run("tc", "-s", "filter", "show", "dev", iface, "egress").stdout
            for iface in ("r-wan", "frag-stage")
        }
        report["passed"] = True
    except Exception:
        report["error"] = traceback.format_exc()
        report["passed"] = False
        print(report["error"], file=sys.stderr)
    finally:
        Path(args.output).write_text(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", nargs="?", default="test", choices=("test", "send", "receive"))
    parser.add_argument("--object")
    parser.add_argument("--label")
    parser.add_argument("--output", default="/tmp/fragment-primitive.json")
    parser.add_argument("--size", type=int, default=6000)
    parser.add_argument("--ident", type=int, default=21000)
    parser.add_argument("--mac")
    parser.add_argument("--reverse", action="store_true")
    parser.add_argument("--partial", action="store_true")
    parser.add_argument("--ready")
    parser.add_argument("--timeout", type=float, default=2)
    options = parser.parse_args()
    if options.operation == "send":
        send_packets(options)
    elif options.operation == "receive":
        receive(options)
    else:
        raise SystemExit(main(options))
