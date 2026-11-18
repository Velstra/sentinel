"""Combined kernel primitive only: no Sentinel policy, NAT or HA claims."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time
import traceback


def load_base(path):
    spec = importlib.util.spec_from_file_location("fragment_base", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def send(base, args):
    payload = base.body(args.size, args.ident)
    source, target = socket.inet_aton(base.CLIENT), socket.inet_aton(base.SERVER)
    udp = struct.pack("!HHHH", 49300, base.PORT, len(payload) + 8, 0) + payload
    pseudo = source + target + struct.pack("!BBH", 0, 17, len(udp))
    udp = udp[:6] + struct.pack("!H", base.checksum(pseudo + udp) or 65535) + udp[8:]
    offsets = list(range(0, len(udp), 1480))[args.start : args.end]
    if args.reverse:
        offsets.reverse()
    mac = bytes.fromhex(args.mac.replace(":", ""))
    own = bytes.fromhex(Path("/sys/class/net/c0/address").read_text().strip().replace(":", ""))
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as raw:
        raw.bind(("c0", 0))
        for offset in offsets:
            piece = udp[offset : offset + 1480]
            flags = offset // 8 | (0x2000 if offset + len(piece) < len(udp) else 0)
            ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(piece), args.ident,
                             flags, 64, 17, 0, source, target)
            ip = ip[:10] + struct.pack("!H", base.checksum(ip)) + ip[12:]
            raw.send(mac + own + b"\x08\x00" + ip + piece)
            time.sleep(0.0002)


def install(base, obj):
    run = base.run
    base.configure()
    run("sysctl", "-w", "net.ipv4.ipfrag_time=20")
    run("ip", "netns", "add", "frag-other")
    run("ip", "-n", "frag-other", "link", "set", "lo", "up")
    run("ip", "link", "add", "r-other", "type", "veth", "peer", "name", "c-other")
    run("ip", "link", "set", "c-other", "netns", "frag-other")
    run("ip", "-n", "frag-other", "link", "set", "c-other", "name", "c0")
    run("ip", "-n", "frag-other", "address", "add", base.CLIENT + "/24", "dev", "c0")
    run("ip", "-n", "frag-other", "link", "set", "c0", "up")
    run("ip", "address", "add", "198.18.1.1/24", "dev", "r-other")
    run("ip", "link", "set", "r-other", "up")
    run("sysctl", "-w", "net.ipv4.conf.r-other.rp_filter=0")
    run("ip", "link", "add", "frag-stage2", "type", "dummy")
    run("ip", "link", "set", "frag-stage2", "up")
    run("tc", "qdisc", "add", "dev", "frag-stage2", "clsact")
    run("bpftool", "prog", "loadall", obj, base.PIN, "type", "classifier", "pinmaps", base.PIN + "/maps")
    names = ("frag-stage", "r-lan", "r-wan", "r-other", "frag-stage2")
    indices = {name: socket.if_nametoindex(name) for name in names}
    values = [indices["frag-stage"], indices["r-lan"], indices["r-wan"], 0,
              0x10203040, 1, indices["r-other"], 0, indices["frag-stage2"]]
    for key, value in enumerate(values):
        base.map_set(key, value)
    for iface, zone in (("r-lan", "12341"), ("r-other", "12342")):
        run("tc", "qdisc", "add", "dev", iface, "clsact")
        run("tc", "filter", "add", "dev", iface, "ingress", "protocol", "ip", "pref", "1",
            "matchall", "action", "ct", "zone", zone, "pipe", "action", "goto", "chain", "1")
        run("tc", "filter", "add", "dev", iface, "ingress", "chain", "1", "protocol", "ip", "pref", "2",
            "bpf", "pinned", base.PIN + "/ingress", "action", "ct", "clear", "pipe",
            "action", "goto", "chain", "2")
        run("tc", "filter", "add", "dev", iface, "ingress", "chain", "1", "protocol", "ip", "pref", "99",
            "matchall", "action", "drop")
        run("tc", "filter", "add", "dev", iface, "ingress", "chain", "2", "protocol", "ip", "pref", "2",
            "bpf", "pinned", base.PIN + "/handoff", "action", "pass")
        run("tc", "filter", "add", "dev", iface, "ingress", "chain", "2", "protocol", "ip", "pref", "99",
            "matchall", "action", "drop")
    run("tc", "filter", "add", "dev", "r-wan", "egress", "protocol", "ip", "pref", "10",
        "bpf", "direct-action", "pinned", base.PIN + "/release")
    for pref, incoming, stage in ((20, "r-lan", "frag-stage"), (30, "r-other", "frag-stage2")):
        run("tc", "filter", "add", "dev", "r-wan", "egress", "protocol", "ip", "pref", str(pref),
            "flower", "indev", incoming, "action", "mirred", "egress", "redirect", "dev", stage)
    run("tc", "filter", "add", "dev", "r-wan", "egress", "protocol", "ip", "pref", "99",
        "matchall", "action", "drop")
    for stage, zone in (("frag-stage", "54321"), ("frag-stage2", "54322")):
        run("tc", "filter", "add", "dev", stage, "egress", "protocol", "ip", "pref", "1",
            "matchall", "action", "ct", "zone", zone, "pipe", "action", "goto", "chain", "1")
        run("tc", "filter", "add", "dev", stage, "egress", "chain", "1", "protocol", "ip", "pref", "2",
            "bpf", "pinned", base.PIN + "/observe", "action", "ct", "clear", "pipe",
            "action", "mirred", "egress", "redirect", "dev", "r-wan")
        run("tc", "filter", "add", "dev", stage, "egress", "chain", "1", "protocol", "ip", "pref", "99",
            "matchall", "action", "drop")
    return indices


def sample(base):
    return [base.counter(i) for i in range(20)]


def capture(base, args, ident, commands, timeout=1.6):
    suffix = f"{ident}-{time.monotonic_ns()}"
    ready, output = f"/tmp/combined-ready-{suffix}", f"/tmp/combined-wire-{suffix}.json"
    receiver = subprocess.Popen(["ip", "netns", "exec", "frag-server", sys.executable,
                                 args.base_probe, "receive", "--ident", str(ident), "--ready", ready,
                                 "--output", output, "--timeout", str(timeout)])
    try:
        deadline = time.monotonic() + 3
        while not Path(ready).exists():
            assert receiver.poll() is None, "receiver exited before ready"
            assert time.monotonic() < deadline, "receiver readiness timeout"
            time.sleep(0.01)
        for ns, size, reverse, start, end in commands:
            iface = "r-other" if ns == "frag-other" else "r-lan"
            mac = Path(f"/sys/class/net/{iface}/address").read_text().strip()
            command = ["ip", "netns", "exec", ns, sys.executable, __file__, "send",
                       "--base-probe", args.base_probe, "--size", str(size), "--ident", str(ident),
                       "--start", str(start), "--mac", mac]
            if end is not None:
                command.extend(["--end", str(end)])
            if reverse:
                command.append("--reverse")
            base.run(*command)
        assert receiver.wait(timeout=5) == 0
    finally:
        if receiver.poll() is None:
            receiver.kill()
            receiver.wait()
    return json.loads(Path(output).read_text())


def assert_delivery(base, wire, size, ident, count=1):
    assert len(wire["received"]) == count, wire
    expected = hashlib.sha256(base.body(size, ident)).hexdigest()
    assert all(entry["sha256"] == expected and entry["bytes"] == size for entry in wire["received"]), wire
    assert wire["frames"] and all(frame["ttl"] == 63 and frame["total"] <= 1500 and frame["ip_checksum_valid"]
                                  for frame in wire["frames"]), wire


def main(base, args):
    report = {"schema": 1, "scope": "isolated combined kernel primitive, no product NAT/policy/HA",
              "kernel": os.uname().release, "label": args.label,
              "fixture_sha256": hashlib.sha256(Path(args.object).read_bytes()).hexdigest(), "cases": []}
    try:
        report["interface_indices"] = install(base, args.object)
        report["kernel_conntrack_before"] = base.flow_ct()
        assert not report["kernel_conntrack_before"]
        cases = [("ingress-route-egress", 6000, "frag-client", 0, 0, True),
                 ("maximum-ipv4-combined", 65507, "frag-client", 0, 0, True),
                 ("second-dedicated-domain", 6000, "frag-other", 0, 0, True),
                 ("missing-ingress-receipt", 6000, "frag-client", 1, 0, False),
                 ("stale-ingress-epoch", 6000, "frag-client", 2, 0, False),
                 ("missing-egress-receipt", 6000, "frag-client", 0, 1, False),
                 ("stale-egress-epoch", 6000, "frag-client", 0, 2, False)]
        for num, (name, size, ns, in_mode, out_mode, allowed) in enumerate(cases):
            ident = 23000 + num
            base.map_set(7, in_mode)
            base.map_set(3, out_mode)
            before = sample(base)
            wire = capture(base, args, ident, [(ns, size, True, 0, None)])
            delta = [end - start for start, end in zip(before, sample(base))]
            item = {"name": name, "payload_bytes": size, "counter_delta": delta, "wire": wire, "passed": False}
            report["cases"].append(item)
            try:
                assert delta[9] == 1, item
                if allowed:
                    assert_delivery(base, wire, size, ident)
                    assert delta[15] == 1 and delta[0] == 1 and delta[1] == size + 28, item
                    assert delta[4] == (size + 8 + 1479) // 1480, item
                    assert delta[2] == len(wire["frames"]) and delta[3] == 0, item
                else:
                    assert not wire["received"] and not wire["frames"] and delta[2] == 0, item
                    if in_mode:
                        assert delta[18] == 1 and delta[15] == 0 and delta[0] == 0, item
                    else:
                        assert delta[15] == 1 and delta[0] == 1 and delta[3] > 0, item
                item["kernel_conntrack"] = base.flow_ct()
                assert not item["kernel_conntrack"], item
                item["passed"] = True
            except AssertionError:
                item["error"] = traceback.format_exc()
            print(("PASSED " if item["passed"] else "FAILED ") + name, flush=True)

        base.map_set(7, 0)
        base.map_set(3, 0)
        # A direct second ct, with no mirred reset, must expose the inherited
        # untracked-fragment pitfall; this classifier always drops safely.
        for command in (
            ("tc", "filter", "add", "dev", "r-wan", "egress", "protocol", "ip", "pref", "1",
             "matchall", "action", "ct", "zone", "54321", "pipe", "action", "goto", "chain", "2"),
            ("tc", "filter", "add", "dev", "r-wan", "egress", "chain", "2", "protocol", "ip", "pref", "2",
             "bpf", "pinned", base.PIN + "/pitfall", "action", "drop"),
            ("tc", "filter", "add", "dev", "r-wan", "egress", "chain", "2", "protocol", "ip", "pref", "99",
             "matchall", "action", "drop"),
        ):
            base.run(*command)
        before = sample(base)
        wire = capture(base, args, 23100, [("frag-client", 6000, True, 0, None)])
        delta = [end - start for start, end in zip(before, sample(base))]
        item = {"name": "untracked-without-mirred-negative", "counter_delta": delta, "wire": wire,
                # Dropping the first output callback aborts Linux's remaining
                # fragment emissions. One observed fragment proves ct skipped
                # reassembly; requiring five would incorrectly test emission
                # after an intentional fatal output error.
                "passed": delta[9] == 1 and delta[15] == 1 and delta[16] == 1 and delta[17] == 0
                and delta[0] == 0 and not wire["frames"] and not wire["received"]}
        report["cases"].append(item)
        print(("PASSED " if item["passed"] else "FAILED ") + item["name"], flush=True)
        base.run("tc", "filter", "del", "dev", "r-wan", "egress", "protocol", "ip", "pref", "1")

        # Identical IP tuple/ID/bytes, complementary halves on separate physical
        # bindings. Shared queues would incorrectly complete a datagram here.
        before = sample(base)
        wire = capture(base, args, 23200, [("frag-client", 6000, False, 0, 3),
                                          ("frag-other", 6000, False, 3, None)], timeout=0.5)
        delta = [end - start for start, end in zip(before, sample(base))]
        item = {"name": "cross-domain-partials-cannot-combine", "counter_delta": delta, "wire": wire,
                "passed": delta[9] == 0 and delta[0] == 0 and not wire["frames"] and not wire["received"]}
        report["cases"].append(item)
        print(("PASSED " if item["passed"] else "FAILED ") + item["name"], flush=True)
        before = sample(base)
        wire = capture(base, args, 23200, [("frag-client", 6000, False, 3, None),
                                          ("frag-other", 6000, False, 0, 3)])
        delta = [end - start for start, end in zip(before, sample(base))]
        item = {"name": "both-domains-complete-independently", "counter_delta": delta, "wire": wire, "passed": False}
        report["cases"].append(item)
        try:
            assert_delivery(base, wire, 6000, 23200, count=2)
            assert delta[9] == 2 and delta[15] == 2 and delta[0] == 2 and delta[2] == 10, item
            item["passed"] = True
        except AssertionError:
            item["error"] = traceback.format_exc()
        print(("PASSED " if item["passed"] else "FAILED ") + item["name"], flush=True)
        report["kernel_conntrack_after"] = base.flow_ct()
        report["qdisc"] = json.loads(base.run("tc", "-s", "-j", "qdisc", "show", "dev", "r-wan").stdout)
        report["filters"] = {
            name: base.run("tc", "-s", "filter", "show", "dev", name, direction).stdout
            for name, direction in (("r-lan", "ingress"), ("r-other", "ingress"),
                                    ("r-wan", "egress"), ("frag-stage", "egress"), ("frag-stage2", "egress"))
        }
        report["passed"] = all(case["passed"] for case in report["cases"]) and not report["kernel_conntrack_after"]
        assert any(q["kind"] == "fq_codel" and q.get("handle") == "1:" and q.get("packets", 0) >= base.counter(2)
                   for q in report["qdisc"]), report["qdisc"]
    except Exception:
        report["passed"] = False
        report["error"] = traceback.format_exc()
        print(report["error"], file=sys.stderr)
    finally:
        Path(args.output).write_text(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", nargs="?", default="test", choices=("test", "send"))
    parser.add_argument("--base-probe", required=True)
    parser.add_argument("--object")
    parser.add_argument("--label")
    parser.add_argument("--output", default="/tmp/fragment-combined.json")
    parser.add_argument("--size", type=int, default=6000)
    parser.add_argument("--ident", type=int, default=23000)
    parser.add_argument("--mac")
    parser.add_argument("--reverse", action="store_true")
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--end", type=int)
    options = parser.parse_args()
    base_module = load_base(options.base_probe)
    if options.operation == "send":
        send(base_module, options)
    else:
        raise SystemExit(main(base_module, options))
