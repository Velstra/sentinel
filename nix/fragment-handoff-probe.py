"""Reserved-flow ingress reinjection mechanics; no Sentinel policy/NAT claims."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import traceback


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def map_value(base, name, key, value=None):
    command = ["bpftool", "-j", "map", "lookup" if value is None else "update", "pinned",
               base.PIN + "/maps/" + name, "key", "hex",
               *[f"{v:02x}" for v in struct.pack("<I", key)]]
    if value is not None:
        base.run(*command, "value", "hex", *[f"{v:02x}" for v in struct.pack("<I", value)])
        return None
    result = json.loads(base.run(*command).stdout)["value"]
    if isinstance(result, list):
        return int.from_bytes(bytes(int(v, 0) if isinstance(v, str) else v for v in result), "little")
    return int(result)


def install_filters(base, duplicate=False):
    base.run("tc", "filter", "add", "dev", "frag-stage", "egress", "protocol", "ip", "pref", "1",
             "matchall", "action", "ct", "zone", "12431", "pipe", "action", "goto", "chain", "1")
    install_authorizer(base, duplicate)


def install_authorizer(base, duplicate=False):
    command = ["tc", "filter", "add", "dev", "frag-stage", "egress", "chain", "1",
               "protocol", "ip", "pref", "2", "bpf", "pinned", base.PIN + "/authorize",
               "action", "ct", "clear", "pipe"]
    if duplicate:
        command += ["action", "mirred", "ingress", "mirror", "dev", "r-lan", "pipe"]
    base.run(*command, "action", "mirred", "ingress", "redirect", "dev", "r-lan")


def counters(base):
    return [map_value(base, "handoff_counts", key) for key in range(14)]


def clear_tickets(base):
    records = json.loads(base.run("bpftool", "-j", "map", "dump", "pinned", base.PIN + "/maps/tickets").stdout)
    for record in records:
        key = record["key"]
        raw = (struct.pack("<Q", key) if isinstance(key, int)
               else bytes(int(v, 0) if isinstance(v, str) else v for v in key))
        assert len(raw) == 8, record
        base.run("bpftool", "map", "delete", "pinned", base.PIN + "/maps/tickets",
                 "key", "hex", *[f"{v:02x}" for v in raw])
    assert not json.loads(base.run("bpftool", "-j", "map", "dump", "pinned", base.PIN + "/maps/tickets").stdout)


def main(args):
    base = module(args.base_probe, "handoff_base")
    combined = module(args.combined_probe, "handoff_combined")
    capture_args = argparse.Namespace(base_probe=args.base_probe)
    report = {"schema": 1, "scope": "reserved-flow ingress dummy/mirred handoff only; no product policy/NAT/HA",
              "kernel": os.uname().release, "label": args.label, "cases": [],
              "fixture_sha256": hashlib.sha256(Path(args.object).read_bytes()).hexdigest(),
              "probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "attach_helper_sha256": hashlib.sha256(Path(args.attach).read_bytes()).hexdigest()}
    try:
        base.configure()
        base.run("sysctl", "-w", "net.ipv4.ipfrag_time=20")
        report["interface_indices"] = {name: socket.if_nametoindex(name)
                                       for name in ("r-lan", "r-wan", "frag-stage")}
        base.run("bpftool", "prog", "loadall", args.object, base.PIN, "pinmaps", base.PIN + "/maps")
        values = [report["interface_indices"]["frag-stage"], report["interface_indices"]["r-lan"],
                  0x6374A920, 7, 0]
        for key, value in enumerate(values):
            map_value(base, "handoff_cfg", key, value)
        base.run("tc", "qdisc", "add", "dev", "r-lan", "clsact")
        base.run(args.attach, base.PIN + "/phys_gate", "r-lan", "ingress", base.PIN + "/link_ingress")
        base.run("bpftool", "net", "attach", "xdpgeneric", "pinned", base.PIN + "/wire_xdp", "dev", "r-lan")
        links = json.loads(base.run("bpftool", "-j", "-f", "link", "show").stdout)
        report["kernel_link"] = [link for link in links if base.PIN + "/link_ingress" in link.get("pinned", [])]
        assert len(report["kernel_link"]) == 1 and report["kernel_link"][0]["type"] == "tcx", links
        assert report["kernel_link"][0]["ifindex"] == values[1], report["kernel_link"]
        report["xdp_link"] = json.loads(base.run("ip", "-details", "-j", "link", "show", "dev", "r-lan").stdout)
        install_filters(base)
        # Only the ORIGINAL physical iif selects the usable output route. A
        # staging iif or accidental local-origin route hits the prohibit route.
        base.run("ip", "route", "add", "prohibit", base.SERVER + "/32")
        base.run("ip", "route", "add", "table", "124", "198.18.2.0/24", "dev", "r-wan")
        base.run("ip", "rule", "add", "pref", "124", "iif", "r-lan", "to", base.SERVER + "/32", "table", "124")
        good = base.run("ip", "route", "get", base.SERVER, "from", base.CLIENT, "iif", "r-lan")
        bad = base.run("ip", "route", "get", base.SERVER, "from", base.CLIENT, "iif", "frag-stage", check=False)
        report["route_controls"] = {"physical": good.stdout, "staging_status": bad.returncode,
                                    "staging_stderr": bad.stderr}
        assert "dev r-wan" in good.stdout and "table 124" in good.stdout and bad.returncode != 0
        report["kernel_conntrack_before"] = base.flow_ct()
        assert not report["kernel_conntrack_before"]

        def exercise(name, ident, size=6000, mode=0, delivered=False, partial=False,
                     auth=1, bad_receipt=0, duplicate=False, wire_complete=False,
                     reentries=None, insertion_failed=0):
            map_value(base, "handoff_cfg", 4, mode)
            before = counters(base)
            wire = combined.capture(base, capture_args, ident,
                                    [("frag-client", size, True, 0, 4 if partial else None)])
            delta = [end - start for start, end in zip(before, counters(base))]
            item = {"name": name, "counter_delta": delta, "wire": wire,
                    "kernel_conntrack": base.flow_ct(), "passed": False}
            report["cases"].append(item)
            try:
                fragments = 1 if wire_complete else (4 if partial else (size + 8 + 1479) // 1480)
                # Initial bpf_redirect sets redirected; mirred's mirror clone
                # retains that marker too. The pinned generic-XDP hook skips
                # BOTH reinjections, so the duplicate control still sees only
                # the original wire fragments, not an extra generic-XDP call.
                assert delta[0] == fragments, item
                expected_reentries = auth * (2 if duplicate else 1) if reentries is None else reentries
                assert delta[1] == fragments + expected_reentries, item
                assert delta[2] == (0 if wire_complete else fragments), item
                assert delta[6] == auth and delta[4] == bad_receipt, item
                assert delta[8] == 0 and delta[9] == insertion_failed and not item["kernel_conntrack"], item
                if delivered:
                    combined.assert_delivery(base, wire, size, ident)
                    assert delta[3] == 1 and delta[7] == 1, item
                else:
                    assert not wire["received"] and not wire["frames"] and delta[3] == 0, item
                item["passed"] = True
            except AssertionError:
                item["error"] = traceback.format_exc()
            print(("PASSED " if item["passed"] else "FAILED ") + name, flush=True)

        exercise("original-iif-generic-xdp-single-pass", 26000, delivered=True)
        exercise("maximum-ipv4-original-iif", 26001, size=65507, delivered=True)
        exercise("consumed-ticket-replay", 26001, size=65507, mode=5, bad_receipt=1)
        exercise("complete-wire-packet-cannot-claim-reinjection", 26003, size=128,
                 auth=0, bad_receipt=1, wire_complete=True)
        exercise("incomplete-queue-no-authorization", 26004, partial=True, auth=0)
        for num, (name, mode) in enumerate((("missing-receipt", 1), ("stale-epoch", 2),
                                            ("wrong-physical-binding", 3), ("wrong-header-binding", 4),
                                            ("expired-ticket", 6), ("wrong-stage-binding", 7))):
            exercise(name, 26010 + num, mode=mode, bad_receipt=1)

        base.run("tc", "filter", "del", "dev", "frag-stage", "egress", "chain", "1",
                 "protocol", "ip", "pref", "2")
        install_authorizer(base, duplicate=True)
        exercise("mirrored-ticket-consumed-once", 26030, delivered=True, bad_receipt=1, duplicate=True)
        base.run("tc", "filter", "del", "dev", "frag-stage", "egress", "chain", "1",
                 "protocol", "ip", "pref", "2")
        exercise("deleted-authorizer-filter-drops-by-default", 26031, auth=0)
        install_authorizer(base)
        base.run("tc", "filter", "del", "dev", "frag-stage", "egress", "protocol", "ip", "pref", "1")
        exercise("deleted-ct-dispatch-filter-drops-by-default", 26032, auth=0)
        base.run("tc", "qdisc", "del", "dev", "frag-stage", "clsact")
        exercise("deleted-staging-clsact-drops-by-default", 26033, auth=0)
        base.run("tc", "qdisc", "add", "dev", "frag-stage", "clsact")
        install_filters(base)
        exercise("explicit-reinstall-recovers", 26034, delivered=True)

        # No eviction of permission: exhaust the actual bounded HASH with
        # inert, expired fixture entries. Unique BPF_NOEXIST creation must fail
        # closed, then explicitly clearing ONLY our test map restores service.
        clear_tickets(base)
        for index in range(128):
            key = struct.pack("<Q", 0x7FFF000000000000 + index)
            value = struct.pack("<QQIIII", 0, 0, 0, 0, 0, 0)
            base.run("bpftool", "map", "update", "pinned", base.PIN + "/maps/tickets",
                     "key", "hex", *[f"{v:02x}" for v in key], "value", "hex",
                     *[f"{v:02x}" for v in value])
        filled = json.loads(base.run("bpftool", "-j", "map", "dump", "pinned", base.PIN + "/maps/tickets").stdout)
        assert len(filled) == 128
        report["ticket_capacity_control"] = {"entries": len(filled), "kind": "bounded HASH, no eviction"}
        exercise("full-ticket-hash-fails-closed", 26040, reentries=0, insertion_failed=1)
        assert len(json.loads(base.run("bpftool", "-j", "map", "dump", "pinned", base.PIN + "/maps/tickets").stdout)) == 128
        clear_tickets(base)
        exercise("ticket-capacity-clear-recovers", 26041, delivered=True)
        report["kernel_conntrack_after"] = base.flow_ct()
        report["qdisc"] = json.loads(base.run("tc", "-s", "-j", "qdisc", "show", "dev", "r-wan").stdout)
        assert any(q["kind"] == "fq_codel" and q.get("packets", 0) > 0 for q in report["qdisc"])
        report["passed"] = all(item["passed"] for item in report["cases"]) and not report["kernel_conntrack_after"]
    except Exception:
        report["error"] = traceback.format_exc()
        report["passed"] = False
        print(report["error"])
    finally:
        Path(args.output).write_text(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-probe", required=True)
    parser.add_argument("--combined-probe", required=True)
    parser.add_argument("--attach", required=True)
    parser.add_argument("--object", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--output", default="/tmp/fragment-handoff.json")
    raise SystemExit(main(parser.parse_args()))
