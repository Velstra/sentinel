"""Actual pinned-Aya TCX ordering, including explicit unsafe design controls."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import traceback


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def map_value(base, name, key, value=None):
    args = ["bpftool", "-j", "map", "lookup" if value is None else "update", "pinned",
            base.PIN + "/maps/" + name, "key", "hex", *[f"{b:02x}" for b in struct.pack("<I", key)]]
    if value is not None:
        args += ["value", "hex", *[f"{b:02x}" for b in struct.pack("<I", value)]]
        base.run(*args)
        return None
    result = json.loads(base.run(*args).stdout)["value"]
    if isinstance(result, list):
        return int.from_bytes(bytes(int(v, 0) if isinstance(v, str) else v for v in result), "little")
    return int(result)


def main(args):
    base = module(args.base_probe, "fragment_base")
    combined = module(args.combined_probe, "fragment_combined")
    # Combined.capture launches its own sender; it also expects base_probe.
    combined_args = argparse.Namespace(base_probe=args.base_probe)
    report = {"schema": 1, "scope": "isolated TCX order/dispatch, no product NAT/policy/HA",
              "kernel": os.uname().release, "label": args.label,
              "fixture_sha256": hashlib.sha256(Path(args.object).read_bytes()).hexdigest(),
              "attach_helper_sha256": hashlib.sha256(Path(args.attach).read_bytes()).hexdigest(),
              "probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "base_probe_sha256": hashlib.sha256(Path(args.base_probe).read_bytes()).hexdigest(),
              "combined_probe_sha256": hashlib.sha256(Path(args.combined_probe).read_bytes()).hexdigest(),
              "aya_revision": "6f6859fbc0857b792f78fe4a128c6808267cbfcf", "cases": [], "links": []}
    try:
        report["interface_indices"] = combined.install(base, args.object)
        for name, direction, program in (("r-lan", "ingress", "gate_in"),
                                         ("r-other", "ingress", "gate_in"),
                                         ("r-wan", "egress", "gate_out")):
            pin = base.PIN + "/link_" + name.replace("-", "_")
            output = base.run(args.attach, base.PIN + "/" + program, name, direction, pin).stdout
            # The pinned bpftool's single-link branch returns a stale errno even
            # after a successful query. Enumeration independently succeeds at
            # ENOENT and reports the actual kernel links plus pinned paths.
            # Keep strict command success; never accept plausible failed stdout.
            info = json.loads(base.run("bpftool", "-j", "-f", "link", "show").stdout)
            entries = [entry for entry in info if pin in entry.get("pinned", [])]
            program_info = json.loads(base.run("bpftool", "-j", "prog", "show", "pinned",
                                               base.PIN + "/" + program).stdout)
            if isinstance(program_info, list):
                assert len(program_info) == 1, program_info
                program_info = program_info[0]
            assert len(entries) == 1 and entries[0]["type"] == "tcx", entries
            assert entries[0]["ifindex"] == report["interface_indices"][name], entries
            assert entries[0]["devname"] == name, entries
            assert entries[0]["attach_type"] == "tcx_" + direction, entries
            assert entries[0]["prog_id"] == program_info["id"], (entries, program_info)
            report["links"].append({"interface": name, "direction": direction,
                                    "attachment_output": output, "kernel_link": entries[0]})
        report["kernel_conntrack_before"] = base.flow_ct()
        assert not report["kernel_conntrack_before"]
        # in/out modes: 0 NEXT, 1 PASS, 2 DROP, 3 readiness-fenced NEXT.
        cases = [("next-dispatches-both-legacy-stages", 6000, "frag-client", 0, 0, 1, 1, True, False),
                 ("next-maximum-ipv4", 65507, "frag-client", 0, 0, 1, 1, True, False),
                 ("next-second-dedicated-domain", 6000, "frag-other", 0, 0, 1, 1, True, False),
                 ("unsafe-pass-bypasses-legacy-ingress", 6000, "frag-client", 1, 0, 0, 1, True, True),
                 ("unsafe-pass-bypasses-legacy-egress", 6000, "frag-client", 0, 1, 1, 0, True, True),
                 ("tcx-drop-stops-before-ingress-stage", 6000, "frag-client", 2, 0, 0, 0, False, False),
                 ("tcx-drop-stops-before-egress-stage", 6000, "frag-client", 0, 2, 1, 0, False, False),
                 ("ready-fenced-next-dispatch", 6000, "frag-client", 3, 3, 1, 1, True, False)]
        map_value(base, "gate_settings", 2, 3)
        for num, (name, size, ns, in_mode, out_mode, ingress, egress, delivered, hazard) in enumerate(cases):
            ident = 24000 + num
            map_value(base, "gate_settings", 0, in_mode)
            map_value(base, "gate_settings", 1, out_mode)
            before = combined.sample(base)
            gates_before = [map_value(base, "gate_counters", i) for i in range(2)]
            wire = combined.capture(base, combined_args, ident, [(ns, size, True, 0, None)])
            delta = [end - start for start, end in zip(before, combined.sample(base))]
            gates = [map_value(base, "gate_counters", i) - gates_before[i] for i in range(2)]
            item = {"name": name, "design_hazard_control": hazard, "counter_delta": delta,
                    "tcx_counter_delta": gates, "wire": wire, "passed": False}
            report["cases"].append(item)
            try:
                assert delta[9] == ingress and delta[0] == egress and gates[0] > 0, item
                assert delta[15] == ingress, item
                if delivered:
                    combined.assert_delivery(base, wire, size, ident)
                    assert gates[1] > 0, item
                    if egress:
                        assert delta[2] == len(wire["frames"]), item
                    else:
                        assert delta[2] == 0, item
                else:
                    assert not wire["frames"] and not wire["received"] and delta[2] == 0, item
                assert not base.flow_ct(), item
                item["passed"] = True
            except AssertionError:
                item["error"] = traceback.format_exc()
            print(("PASSED " if item["passed"] else "FAILED ") + name, flush=True)

        # A TCX NEXT decision must not turn an incomplete datagram into policy
        # admission or an outbound packet. Send four of five fragments only.
        map_value(base, "gate_settings", 0, 0)
        map_value(base, "gate_settings", 1, 0)
        before = combined.sample(base)
        gates_before = [map_value(base, "gate_counters", i) for i in range(2)]
        wire = combined.capture(base, combined_args, 24090, [("frag-client", 6000, True, 0, 4)])
        delta = [end - start for start, end in zip(before, combined.sample(base))]
        gates = [map_value(base, "gate_counters", i) - gates_before[i] for i in range(2)]
        item = {"name": "next-incomplete-queue-not-admitted", "counter_delta": delta,
                "tcx_counter_delta": gates, "wire": wire,
                "passed": gates == [4, 0] and delta[9] == 0 and delta[0] == 0
                and delta[2] == 0 and not wire["frames"] and not wire["received"]
                and not base.flow_ct()}
        report["cases"].append(item)
        print(("PASSED " if item["passed"] else "FAILED ") + item["name"], flush=True)

        # Unsafe design control: an uncoordinated chain deletion while readiness
        # stays set is NOT detected by NEXT or by the manually managed flag.
        map_value(base, "gate_settings", 0, 3)
        map_value(base, "gate_settings", 1, 3)
        map_value(base, "gate_settings", 2, 3)
        base.run("tc", "filter", "del", "dev", "r-lan", "ingress", "protocol", "ip", "pref", "1")
        before = combined.sample(base)
        gates_before = [map_value(base, "gate_counters", i) for i in range(2)]
        wire = combined.capture(base, combined_args, 24095, [("frag-client", 6000, True, 0, None)])
        delta = [end - start for start, end in zip(before, combined.sample(base))]
        gates = [map_value(base, "gate_counters", i) - gates_before[i] for i in range(2)]
        item = {"name": "unsafe-stale-ready-missing-ingress-chain", "design_hazard_control": True,
                "counter_delta": delta, "tcx_counter_delta": gates, "wire": wire, "passed": False}
        report["cases"].append(item)
        try:
            combined.assert_delivery(base, wire, 6000, 24095)
            assert delta[9] == 0 and delta[15] == 0 and delta[0] == 1, item
            assert delta[2] == len(wire["frames"]) and gates[0] > 0 and gates[1] > 0, item
            assert not base.flow_ct(), item
            item["passed"] = True
        except AssertionError:
            item["error"] = traceback.format_exc()
        print(("PASSED " if item["passed"] else "FAILED ") + item["name"], flush=True)

        # Only explicitly closing readiness fences the now-missing chain. This
        # is not proof of automatic loss detection or production loader safety.
        map_value(base, "gate_settings", 2, 2)
        before = combined.sample(base)
        wire = combined.capture(base, combined_args, 24100, [("frag-client", 6000, True, 0, None)])
        delta = [end - start for start, end in zip(before, combined.sample(base))]
        item = {"name": "missing-chain-fenced-closed", "counter_delta": delta, "wire": wire,
                "passed": delta[9] == 0 and delta[0] == 0 and not wire["frames"] and not wire["received"]}
        report["cases"].append(item)
        print(("PASSED " if item["passed"] else "FAILED ") + item["name"], flush=True)
        report["kernel_conntrack_after"] = base.flow_ct()
        report["qdisc"] = json.loads(base.run("tc", "-s", "-j", "qdisc", "show", "dev", "r-wan").stdout)
        assert any(qdisc["kind"] == "fq_codel" and qdisc.get("packets", 0) > 0
                   for qdisc in report["qdisc"]), report["qdisc"]
        report["passed"] = all(case["passed"] for case in report["cases"]) and not report["kernel_conntrack_after"]
        report["qualification"] = ("TCX mechanics only; PASS and stale-ready chain-loss bypass hazards "
                                   "reproduced, not production cleared")
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
    parser.add_argument("--output", default="/tmp/fragment-tcx.json")
    raise SystemExit(main(parser.parse_args()))
