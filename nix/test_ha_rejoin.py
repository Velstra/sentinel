"""Pure HA-rejoin probe/receipt contracts. These are NOT packet/VM evidence."""

import copy
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("rejoin", Path(__file__).with_name("ha-rejoin-probe.py"))
assert SPEC is not None and SPEC.loader is not None
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


def nat_sample():
    return dict(metadata=dict(name="CONNTRACK", id=123, type="lru_hash", bytes_key=20,
                              bytes_value=48, max_entries=65536),
                complete=True, atomic_snapshot=False, rows=[])


def happy_rows():
    client, owner = [], []
    authority = dict(term=2, owner=2, policy=[17] * 32, boot=[18] * 16)
    tick_id, fresh_id = 0, 0
    for phase_index, name in enumerate(("baseline", "incumbent", "rejoin", "after")):
        start = 1_000_000_000 + phase_index * 2_000_000_000
        for index in range(40):
            timestamp = start + index * 50_000_000
            client.append(dict(kind="tick", id=tick_id, phase=name, monotonic_ns=timestamp, ok=True))
            tick_id += 1
            if index % 2 == 0:
                port = 42000 + fresh_id
                candidate = P.candidates(port)
                client.append(dict(kind="fresh", id=fresh_id, phase=name, monotonic_ns=timestamp,
                                   started_ns=timestamp-1_000_000, source=[P.SOURCE, port],
                                   target=[P.TARGET, P.PORT], candidates=candidate,
                                   wire_peer=[P.PUBLIC, candidate["ports"][0]], ok=True))
                fresh_id += 1
            owner.append(dict(kind="role", phase=name, monotonic_ns=timestamp,
                              boottime_ns=timestamp, boot_id="unchanged-owner-boot",
                              role=dict(authority=copy.deepcopy(authority), deadline_ns=timestamp+200_000_000,
                                        vips_ready=True),
                              agent=dict(forwarding_term=2, policy=[17] * 32)))
            if index % 5 == 0:
                owner.append(dict(kind="maps", phase=name, monotonic_ns=timestamp,
                                  started_ns=timestamp-1_000_000, boottime_ns=timestamp,
                                  deadline_value_ns=timestamp+200_000_000, status="Ready",
                                  deadline_observed_boottime_ns=timestamp,
                                  counters=dict(egress_dropped=0, egress_masqueraded=index+phase_index*40,
                                                dropped_default=0), services="same exact PIDs and invocations",
                                  addresses=[dict(ifname="eth1",addr_info=[dict(family="inet",local="10.1.0.100")]),
                                             dict(ifname="eth2",addr_info=[dict(family="inet",local="10.2.0.100")])],
                                  nat=nat_sample()))
    return client, owner


class RejoinContracts(unittest.TestCase):
    def test_phase_publication_is_atomic_and_invalid_phases_remain_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root/"phase"
            path.write_text("baseline\n")
            original = Path.replace
            observed = []
            def replace(temporary, destination):
                observed.append(path.read_text().strip())
                self.assertEqual(temporary.read_text().strip(), "rejoin")
                return original(temporary, destination)
            with mock.patch.object(Path, "replace", autospec=True, side_effect=replace):
                P.publish_phase(path, "rejoin")
            self.assertEqual(observed, ["baseline"])
            with mock.patch.object(P, "ROOT", root):
                self.assertEqual(P.phase(), "rejoin")
                for invalid in ("", "rej", "rejoin\nafter"):
                    path.write_text(invalid)
                    with self.assertRaises(RuntimeError):
                        P.phase()

    def test_fixed_wire_candidates_and_payload_identity(self):
        # Independently computed with integer/BigInt 32-bit operations, not
        # copied from the probe's returned value.
        self.assertEqual(P.candidates(42000), dict(seed=1864877357, ports=list(range(50477, 50485))))
        self.assertEqual(P.payload("a"*32, "fresh", 7), b"a"*32+b" fresh 7\n")
        for bad in (0, -1, 65536, True, "42000"):
            with self.subTest(bad=bad), self.assertRaises(RuntimeError):
                P.candidates(bad)
        for nonce in ("short", "z"*32):
            with self.assertRaises(RuntimeError):
                P.payload(nonce, "tick", 0)

    def test_clean_complete_receipt_is_accepted(self):
        client, owner = happy_rows()
        receipt = P.analyse(client, owner)
        self.assertTrue(receipt["passed"], receipt)
        self.assertEqual(receipt["map_ids"], [123])
        self.assertEqual(receipt["phases"]["rejoin"]["fresh"], 20)
        self.assertIn("unknown", receipt["ownership_scope"])

    def test_each_fresh_failure_stays_red_even_with_a_collision_hypothesis(self):
        client, owner = happy_rows()
        failed = next(row for row in client if row["kind"] == "fresh" and row["phase"] == "rejoin")
        failed["ok"] = False
        failed["failure"] = dict(type="TimeoutError")
        raw_key = struct.pack("<I4s4sHHB3x", 19, P.ipaddress.IPv4Address(P.TARGET).packed,
                              P.ipaddress.IPv4Address(P.PUBLIC).packed, P.PORT,
                              failed["candidates"]["ports"][0], 6)
        value = P.NAT.pack(P.ipaddress.IPv4Address("10.2.0.99").packed, bytes(4), 44000, 0,
                           2, 0, 1, 90, 1234, 0)
        sample = next(row for row in owner if row["kind"] == "maps" and row["phase"] == "rejoin")
        sample["nat"]["rows"] = [[raw_key.hex(), value.hex()]]
        receipt = P.analyse(client, owner)
        self.assertFalse(receipt["passed"])
        evidence = receipt["candidate_owner_evidence"][0]
        self.assertEqual(len(evidence["candidates"]), 8)
        actual = evidence["candidates"][0]["observed"][0]
        self.assertEqual(actual["owner"], "10.2.0.99")
        self.assertFalse(actual["tuple_matches_attempt"])
        self.assertIn("unknown", evidence["scope"])

    def test_lease_owner_policy_and_map_replacement_are_not_healthy_rejoin(self):
        for change in ("deadline", "owner", "policy", "map", "service", "status", "vip", "boot"):
            client, owner = happy_rows()
            role = next(row for row in owner if row["kind"] == "role" and row["phase"] == "rejoin")
            maps = next(row for row in owner if row["kind"] == "maps" and row["phase"] == "rejoin")
            if change == "deadline":
                role["role"]["deadline_ns"] = role["boottime_ns"]
            elif change == "owner":
                role["role"]["authority"]["owner"] = 1
            elif change == "policy":
                role["agent"]["policy"] = [99] * 32
            elif change == "map":
                maps["nat"]["metadata"]["id"] = 124
            elif change == "service":
                maps["services"] = "new incarnation"
            elif change == "vip":
                maps["addresses"] = []
            elif change == "boot":
                role["boot_id"] = "different-owner-boot"
            else:
                maps["status"] = "Failed"
            with self.subTest(change=change):
                self.assertFalse(P.analyse(client, owner)["passed"])

    def test_collection_error_and_missing_role_or_map_coverage_are_red(self):
        for kind in ("collection-error", "role-gap", "missing-maps", "slow-maps"):
            client, owner = happy_rows()
            if kind == "collection-error":
                owner.append(dict(kind=kind, phase="rejoin", monotonic_ns=99_000_000_000))
            elif kind == "role-gap":
                owner = [row for row in owner if not (row["kind"] == "role" and row["phase"] == "rejoin")]
            elif kind == "missing-maps":
                owner = [row for row in owner if not (row["kind"] == "maps" and row["phase"] == "after")]
            else:
                next(row for row in owner if row["kind"] == "maps" and row["phase"] == "rejoin")["started_ns"] = 0
            with self.subTest(kind=kind):
                self.assertFalse(P.analyse(client, owner)["passed"])

    def test_missing_collector_executable_never_becomes_empty_clean_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = str(Path(directory)/"missing-bpftool")
            with self.assertRaises(FileNotFoundError):
                P.command([missing, "-j", "map", "show"])
        with mock.patch.object(P.subprocess, "run", side_effect=FileNotFoundError(2, "missing bpftool")):
            with self.assertRaises(FileNotFoundError):
                P.collect_maps(object())
        client, owner = happy_rows()
        owner = [row for row in owner if row["kind"] != "maps"]
        owner.append(dict(kind="collection-error", phase="rejoin", monotonic_ns=99_000_000_000,
                          stage="maps", failure=dict(type="FileNotFoundError", detail="missing bpftool")))
        with self.assertRaisesRegex(RuntimeError, "NAT observations absent/incomplete"):
            P.analyse(client, owner)

    def test_no_reconnect_skipped_tick_or_boundary_gap_is_hidden(self):
        for kind in ("restart", "boundary", "duplicate-port", "wrong-candidate", "wrong-wire"):
            client, owner = happy_rows()
            tick = next(row for row in client if row["kind"] == "tick" and row["phase"] == "rejoin")
            fresh = next(row for row in client if row["kind"] == "fresh" and row["phase"] == "rejoin")
            if kind == "restart":
                tick["id"] = 0
            elif kind == "boundary":
                for row in client:
                    if row["phase"] in {"rejoin", "after"}:
                        row["monotonic_ns"] += 600_000_000
            elif kind == "duplicate-port":
                fresh["source"][1] = 42000
            elif kind == "wrong-candidate":
                fresh["candidates"]["ports"][0] = 1
            else:
                fresh["wire_peer"][0] = "10.1.0.2"
            with self.subTest(kind=kind):
                if kind == "boundary":
                    self.assertFalse(P.analyse(client, owner)["passed"])
                else:
                    with self.assertRaises(RuntimeError):
                        P.analyse(client, owner)

    def test_counter_and_deadline_parsers_fail_closed(self):
        self.assertEqual(P.stats(" egresS ignored\n egresS ignored\n egress_dropped 2\n egress_masqueraded 3\n dropped_default 4\n"),
                         dict(egress_dropped=2, egress_masqueraded=3, dropped_default=4))
        with self.assertRaises(RuntimeError):
            P.stats("egress_dropped 2\n")
        with self.assertRaises(RuntimeError):
            P.stats("egress_dropped 2\negress_dropped 3\n")
        value = [{"key":["0x00"]*4,"value":list((12345).to_bytes(8,"little"))}]
        self.assertEqual(P.deadline_value(value), 12345)
        for bad in ([], [{"key":[0]*4,"value":[True]*8}], [{"key":[1]*4,"value":[0]*8}],
                    [{"key":[0]*4,"value":[0]*7}]):
            with self.assertRaises(RuntimeError):
                P.deadline_value(bad)

    def test_raw_map_identity_duplicates_and_abi_are_not_ignored(self):
        key = struct.pack("<I4s4sHHB3x", 19, bytes(4), bytes(4), 1, 2, 6).hex()
        for kind in ("missing", "atomic", "width", "duplicate", "short-value"):
            sample = nat_sample()
            if kind == "missing":
                sample["complete"] = False
            elif kind == "atomic":
                sample["atomic_snapshot"] = True
            elif kind == "width":
                sample["metadata"]["bytes_value"] = 24
            elif kind == "duplicate":
                sample["rows"] = [[key, bytes(48).hex()]] * 2
            else:
                sample["rows"] = [[key, bytes(47).hex()]]
            with self.subTest(kind=kind), self.assertRaises(RuntimeError):
                P.nat_index(sample)

    def test_raw_log_requires_framing_monotonic_order_and_phase(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"log"
            rows = [dict(kind="tick",phase="rejoin",monotonic_ns=1)]
            path.write_text(json.dumps(rows[0])+"\n")
            self.assertEqual(P.read_rows(path)[0], rows)
            for text in ("", json.dumps(rows[0]), json.dumps(dict(rows[0],phase="unknown"))+"\n",
                         json.dumps(dict(rows[0],monotonic_ns=2))+"\n"+json.dumps(rows[0])+"\n"):
                path.write_text(text)
                with self.assertRaises(RuntimeError):
                    P.read_rows(path)


if __name__ == "__main__":
    unittest.main()
