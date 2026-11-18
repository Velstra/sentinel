"""Pure diagnostic contracts; these do not qualify live NAT or20k capacity."""

import copy
import asyncio
import ctypes
import errno
import importlib.util
import json
from pathlib import Path
import struct
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("nat_pressure", Path(__file__).with_name("nat-capacity-pressure-probe.py"))
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


def fixture():
    rows = dict(version=1, nonce="a" * 32, requested=1, held=1,
                attempts=[dict(id=0, source=["198.18.20.50", 43000],
                               target=["198.18.10.254", 9000], wire_peer=["198.18.10.100", 50000],
                               initial_echo=True)])
    now = 100_000_000_000
    sample = dict(version=1, complete=True, atomic_snapshot=False, finished_ns=now, maps={})
    for number, (name, (key_size, value_size, kind)) in enumerate(P.MAP_LAYOUTS.items(), 1):
        sample["maps"][name] = dict(complete=True, raw_count=0, entries=[], metadata=dict(
            name=name, id=number, type=kind, bytes_key=key_size, bytes_value=value_size, max_entries=65536))
    for role, addresses in P.tuple_roles(rows["attempts"][0]).items():
        src, dst, sport, dport, proto = addresses
        policy = 1 if role.startswith("private") else 2
        key = P.FIREWALL_KEY.pack(policy, P.ipaddress.IPv4Address(src).packed + bytes(12),
                                  P.ipaddress.IPv4Address(dst).packed + bytes(12), sport, dport, proto, 4)
        value = P.FIREWALL_VALUE.pack(now, 0, 3, int(role.endswith("reverse")))
        sample["maps"]["FW_FLOWS"]["entries"].append([key.hex(), value.hex()])
    key = P.FLOW_KEY.pack(2, bytes([198, 18, 10, 254]), bytes([198, 18, 10, 100]), 9000, 50000, 6)
    value = P.NAT_VALUE.pack(bytes([198, 18, 20, 50]), bytes(4), 43000, 0, 2, 0, 7, 1234, now, 0)
    sample["maps"]["CONNTRACK"]["entries"] = [[key.hex(), value.hex()]]
    sample["maps"]["IFACE_POLICY"]["entries"] = [
        [struct.pack("<I", 2).hex(), struct.pack("<I", 2).hex()],
        [struct.pack("<I", 3).hex(), struct.pack("<I", 1).hex()]]
    for row in sample["maps"].values():
        row["raw_count"] = len(row["entries"])
    probes = dict(version=1, round=1, rows=[dict(id=0, verified=True)])
    return sample, rows, probes


def analyse(sample, rows, probes, template=None):
    return P.analyse(sample, rows, probes, template, lan_index=3, wan_index=2)


class Contracts(unittest.TestCase):
    def test_runtime_missing_sources_are_errors_not_zero_counters(self):
        with mock.patch.object(P.Path, "read_text", side_effect=FileNotFoundError("unavailable")):
            result = P.runtime()
        for name in ("netstat", "snmp", "pressure_cpu", "pressure_memory", "pressure_io", "backend"):
            self.assertIn("error", result[name])
        self.assertNotIn("value", result["backend"])

    def test_runtime_retains_measured_values_and_backend_sample_age(self):
        backend = dict(monotonic_ns=2_000_000_000, counters=dict(active=12000, echo_frames=24000),
                       event_loop=dict(running=True, samples=10, max_lag_ms=35))
        def read(path):
            if str(path) == P.SERVER_METRICS:
                return json.dumps(backend)
            if str(path).startswith("/proc/pressure/"):
                return "some avg10=0.00 avg60=0.00 avg300=0.00 total=7\n"
            return "Tcp: RetransSegs\nTcp: 17\n"
        with mock.patch.object(P.Path, "read_text", read), \
                mock.patch.object(P.time, "monotonic_ns", return_value=2_200_000_000):
            result = P.runtime()
        self.assertEqual(result["snmp"]["Tcp"]["RetransSegs"], 17)
        self.assertEqual(result["backend"], dict(value=backend, age_ms=200))

    def test_runtime_malformed_measurements_remain_explicit_errors(self):
        def read(path):
            return "not-json" if str(path) == P.SERVER_METRICS else "Tcp: truncated\n"
        with mock.patch.object(P.Path, "read_text", read):
            result = P.runtime()
        for name in ("netstat", "snmp", "backend"):
            self.assertIn("error", result[name])

    def test_kernel_counters_are_paired_and_never_silently_truncated(self):
        self.assertEqual(P.proc_counters("TcpExt: ListenOverflows ListenDrops\nTcpExt: 2 3\n"),
                         {"TcpExt": {"ListenOverflows": 2, "ListenDrops": 3}})
        for text in ("TcpExt: A\n", "TcpExt: A B\nTcpExt: 1\n", "TcpExt: A\nTcp: 1\n",
                     "Tcp: A A\nTcp: 1 2\n", "Tcp: A\nTcp: 1\nTcp: A\nTcp: 2\n"):
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                P.proc_counters(text)

    def test_explicit_source_ports_cannot_repeat_or_include_implicit_zero(self):
        for ports in ([0], [True], [80], [65536], [40000, 40000], []):
            with self.subTest(ports=ports), self.assertRaises(RuntimeError):
                P.Client("127.0.0.1", ["127.0.0.1"], 9000, "127.0.0.1", 2, ports)

    def test_counts_are_explicit_bounded_and_start_with_observed_one_flow(self):
        for values in ([1, 64], [1, 64, 12000, 16000, 20000]):
            self.assertEqual(P.validate_counts(values), values)
        for values in ([], [64], [1, 1], [1, 0], [1, True], [1, 20001], [1, 64, 2]):
            with self.subTest(values=values), self.assertRaises(RuntimeError):
                P.validate_counts(values)

    def test_nonce_payload_does_not_accept_another_flow_round_or_session(self):
        frame = P.payload("a" * 32, 7, 2)
        P.verify_echo(frame, frame)
        for other in (P.payload("b" * 32, 7, 2), P.payload("a" * 32, 8, 2),
                      P.payload("a" * 32, 7, 3), b"x", frame[:-1]):
            with self.assertRaises(RuntimeError):
                P.verify_echo(frame, other)
        for nonce in ("a" * 31, "g" * 32, "A" * 32):
            with self.assertRaises(RuntimeError):
                P.payload(nonce, 0, 0)

    def test_greeting_binds_actual_wire_peer_and_destination(self):
        value = dict(peer=["198.18.10.100", 50000], target=["198.18.10.254", 9000])
        def encoded(data):
            return json.dumps(data).encode() + b"\n"
        self.assertEqual(P.hello(encoded(value), ("198.18.10.254", 9000), "198.18.10.100"), ("198.18.10.100", 50000))
        for field, replacement in (("peer", ["198.18.20.50", 50000]),
                                   ("peer", ["198.18.10.100", 0]),
                                   ("target", ["198.18.10.253", 9000])):
            altered = dict(value, **{field: replacement})
            with self.assertRaises(RuntimeError):
                P.hello(encoded(altered), ("198.18.10.254", 9000), "198.18.10.100")

    def test_batch_abi_and_layout_are_explicit_not_assumed_flow_counts(self):
        self.assertEqual(ctypes.sizeof(P.Batch), 56)
        self.assertEqual((P.FLOW_KEY.size, P.NAT_VALUE.size, P.FIREWALL_KEY.size, P.FIREWALL_VALUE.size), (20, 48, 44, 24))
        metadata = fixture()[0]["maps"]["FW_FLOWS"]["metadata"]
        P.validate_metadata(metadata)
        for field, value in (("id", True), ("type", "hash"), ("bytes_key", 20),
                             ("bytes_value", 32), ("max_entries", 65537), ("name", "foreign")):
            with self.assertRaises(RuntimeError):
                P.validate_metadata(dict(metadata, **{field: value}))

    def test_paired_observed_ownership_passes_without_hardcoded_four(self):
        sample, rows, probes = fixture()
        actual = analyse(sample, rows, probes)
        self.assertTrue(actual["passed"])
        self.assertEqual(len(actual["observed_ownership_template"]), 4)
        self.assertEqual(actual["firewall_tcp_phases"], {"3": 4})
        smaller = copy.deepcopy(sample)
        smaller["maps"]["FW_FLOWS"]["entries"] = smaller["maps"]["FW_FLOWS"]["entries"][2:]
        smaller["maps"]["FW_FLOWS"]["raw_count"] = 2
        other = analyse(smaller, rows, probes)
        self.assertTrue(other["passed"])
        self.assertEqual(len(other["observed_ownership_template"]), 2)

    def test_lost_owned_firewall_key_is_failure_even_if_this_echo_passed(self):
        sample, rows, probes = fixture()
        template = analyse(sample, rows, probes)["observed_ownership_template"]
        sample["maps"]["FW_FLOWS"]["entries"].pop()
        sample["maps"]["FW_FLOWS"]["raw_count"] -= 1
        value = analyse(sample, rows, probes, template)
        self.assertFalse(value["passed"])
        self.assertEqual(len(value["owned_flow_failures"][0]["missing_firewall_roles"]), 1)

    def test_missing_foreign_and_wrong_policy_nat_never_pass(self):
        for mode in ("missing", "foreign", "policy"):
            with self.subTest(mode=mode):
                sample, rows, probes = fixture()
                row = sample["maps"]["CONNTRACK"]
                if mode == "missing":
                    row["entries"], row["raw_count"] = [], 0
                elif mode == "foreign":
                    value = list(P.NAT_VALUE.unpack(bytes.fromhex(row["entries"][0][1])))
                    value[2] = 43001
                    row["entries"][0][1] = P.NAT_VALUE.pack(*value).hex()
                else:
                    key = list(P.FLOW_KEY.unpack(bytes.fromhex(row["entries"][0][0])))
                    key[0] = 99
                    row["entries"][0][0] = P.FLOW_KEY.pack(*key).hex()
                value = analyse(sample, rows, probes)
                self.assertFalse(value["passed"])
                self.assertNotEqual(value["owned_flow_failures"][0]["nat"], "owned")

    def test_data_loss_with_complete_owned_maps_is_not_a_green_expected_bug(self):
        sample, rows, probes = fixture()
        probes["rows"][0] = dict(id=0, verified=False, failure=dict(stage="held-echo", kind="timeout"))
        actual = analyse(sample, rows, probes)
        self.assertFalse(actual["passed"])
        self.assertEqual(actual["owned_flow_failures"][0]["correlation"], "echo-failed-with-owned-map-state")

    def test_incomplete_duplicate_or_truncated_observation_refuses_analysis(self):
        sample, rows, probes = fixture()
        for mode in ("incomplete", "duplicate", "count", "probe", "capacity", "value", "othermap"):
            altered, checked = copy.deepcopy(sample), copy.deepcopy(probes)
            if mode == "incomplete":
                altered["complete"] = False
            elif mode == "duplicate":
                altered["maps"]["FW_FLOWS"]["entries"].append(altered["maps"]["FW_FLOWS"]["entries"][0])
                altered["maps"]["FW_FLOWS"]["raw_count"] += 1
            elif mode == "count":
                altered["maps"]["FW_FLOWS"]["raw_count"] = 10
            elif mode == "capacity":
                altered["maps"]["FW_FLOWS"]["metadata"]["max_entries"] = 3
            elif mode == "value":
                altered["maps"]["CONNTRACK"]["entries"][0][1] = "00"
            elif mode == "othermap":
                altered["maps"]["SYN_FLOWS"]["complete"] = False
            else:
                checked["rows"] = []
            with self.subTest(mode=mode), self.assertRaises(RuntimeError):
                analyse(altered, rows, checked)

    def test_bounded_batch_walk_rejects_churn_and_grows_only_within_capacity(self):
        class Reader:
            def __init__(self, values):
                self.values = iter(values)
            def batch(self, size, cursor):
                return next(self.values)
        deadline = P.time.monotonic() + 5
        self.assertEqual(P.walk(Reader([(1, [(b"a", b"b")], True)]), 1, deadline), {b"a": b"b"})
        for values in ([(1, [], False)], [(1, [(b"a", b"b")], False), (1, [(b"a", b"b")], True)], [None]):
            with self.assertRaises(RuntimeError):
                P.walk(Reader(values), 1, deadline)

    def test_raw_batch_reader_never_uses_individual_lru_lookup(self):
        commands = []
        class Libc:
            def syscall(self, number, command, pointer, size):
                commands.append((number, command, size))
                attr = ctypes.cast(pointer, ctypes.POINTER(P.Batch)).contents
                attr.count = 0
                ctypes.set_errno(errno.ENOENT)
                return -1
        reader = object.__new__(P.KernelReader)
        reader.info = fixture()[0]["maps"]["FW_FLOWS"]["metadata"]
        reader.fd, reader.libc = 7, Libc()
        self.assertEqual(reader.batch(4, None), (0, [], True))
        self.assertEqual(commands, [(321, 24, 56)])

    def test_raw_batch_errors_cannot_be_treated_as_an_empty_healthy_map(self):
        class Libc:
            def __init__(self, error, count):
                self.error, self.count = error, count
            def syscall(self, number, command, pointer, size):
                ctypes.cast(pointer, ctypes.POINTER(P.Batch)).contents.count = self.count
                ctypes.set_errno(self.error)
                return -1
        for error, count in ((errno.EFAULT, 0), (errno.ENOSPC, 1), (errno.EPERM, 0)):
            reader = object.__new__(P.KernelReader)
            reader.info = fixture()[0]["maps"]["FW_FLOWS"]["metadata"]
            reader.fd, reader.libc = 7, Libc(error, count)
            with self.subTest(error=error), self.assertRaises((RuntimeError, OSError)):
                reader.batch(4, None)


class AsyncContracts(unittest.IsolatedAsyncioTestCase):
    async def test_failed_connect_keeps_prebound_endpoint_and_closes_raw_socket(self):
        created = []
        factory = P.socket.socket
        def tracked(*args, **kwargs):
            value = factory(*args, **kwargs)
            created.append(value)
            return value
        loop = asyncio.get_running_loop()
        client = P.Client("127.0.0.1", ["127.0.0.1"], 9000, "127.0.0.1", 2)
        async def reject(raw, target):
            self.assertEqual(raw.getblocking(), False)
            self.assertEqual(raw.getsockname()[0], "127.0.0.1")
            raise TimeoutError("deliberate connect failure")
        with mock.patch.object(P.socket, "socket", side_effect=tracked), \
                mock.patch.object(loop, "sock_connect", side_effect=reject):
            result = await client.open_one(0)
        self.assertEqual(result["failure"]["stage"], "connect")
        self.assertEqual(result["failure"]["kind"], "timeout")
        self.assertEqual(result["source"][0], "127.0.0.1")
        self.assertGreater(result["source"][1], 0)
        self.assertEqual([raw.fileno() for raw in created], [-1])
        self.assertFalse(result["initial_echo"])
        self.assertEqual(client.streams, {})

    async def test_monitor_distinguishes_not_started_from_measured_zero_lag(self):
        health = P.LoopHealth()
        self.assertFalse(health.sample()["running"])
        self.assertIsNone(health.sample()["heartbeat_age_ms"])
        health.start()
        try:
            await asyncio.sleep(0.07)
            self.assertTrue(health.sample()["running"])
            self.assertGreater(health.sample()["samples"], 0)
        finally:
            await health.stop()
        self.assertFalse(health.sample()["running"])


if __name__ == "__main__":
    unittest.main()
