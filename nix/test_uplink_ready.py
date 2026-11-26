"""Unit tests for nix/uplink-ready.py, the masquerade readiness wait."""

import importlib.util
import json
import pathlib
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("uplink_ready", HERE / "uplink-ready.py")
uplink = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uplink)


class FakeMachine:
    """Answers `cat .../ifindex` and successive MASQUERADE dumps."""

    def __init__(self, ifindex, dumps):
        self.ifindex = ifindex
        self.dumps = list(dumps)
        self.reads = 0

    def succeed(self, command):
        if command.startswith("cat /sys/class/net/"):
            return str(self.ifindex) + "\n"
        assert "map dump name MASQUERADE" in command, command
        self.reads += 1
        dump = self.dumps[0] if len(self.dumps) == 1 else self.dumps.pop(0)
        return json.dumps(dump)


def entry(ifindex, value, formatted=False):
    key = ["0x%02x" % b for b in ifindex.to_bytes(4, "little")]
    raw = ["0x%02x" % b for b in value]
    row = {"key": key, "value": raw}
    if formatted:
        row["formatted"] = {"key": ifindex, "value": value}
    return row


class UplinkReady(unittest.TestCase):
    def test_reads_raw_hex_keys_and_values(self):
        machine = FakeMachine(3, [[entry(3, [198, 18, 10, 100], formatted=True), entry(7, [0, 0, 0, 0])]])
        self.assertEqual(uplink.masquerade_entries(machine), {3: [198, 18, 10, 100], 7: [0, 0, 0, 0]})

    def test_returns_once_the_uplink_holds_its_address(self):
        machine = FakeMachine(3, [[entry(3, [0, 0, 0, 0])], [entry(3, [0, 0, 0, 0])],
                                  [entry(3, [198, 18, 10, 100])]])
        with mock.patch.object(uplink.time, "sleep"):
            uplink.wait_uplink_addressed(machine, "eth1", "198.18.10.100", timeout=30)
        self.assertEqual(machine.reads, 3)

    def test_another_interface_holding_the_address_is_not_enough(self):
        machine = FakeMachine(3, [[entry(4, [198, 18, 10, 100]), entry(3, [0, 0, 0, 0])]])
        with mock.patch.object(uplink.time, "sleep"), self.assertRaises(AssertionError) as raised:
            uplink.wait_uplink_addressed(machine, "eth1", "198.18.10.100", timeout=0)
        self.assertIn("not masqueraded from 198.18.10.100", str(raised.exception))

    def test_an_unaddressed_uplink_times_out_with_the_table(self):
        machine = FakeMachine(3, [[entry(3, [0, 0, 0, 0])]])
        with mock.patch.object(uplink.time, "sleep"), self.assertRaises(AssertionError) as raised:
            uplink.wait_uplink_addressed(machine, "eth1", "198.18.10.100", timeout=0)
        self.assertIn("{3: [0, 0, 0, 0]}", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
