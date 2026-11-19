"""Unit tests for legacy-velstra-filter.py (the mixed-version HA fixture)."""

import importlib.util
import pathlib
import tomllib
import unittest

SPEC = importlib.util.spec_from_file_location(
    "legacy_filter", pathlib.Path(__file__).with_name("legacy-velstra-filter.py")
)
legacy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(legacy)

CONFIG = """default_action = "drop"

[state]
persist = true

[[policy]]
id = 7
name = "lan"
default_action = "drop"

[[policy.port_rule]]
name = "ssh-in"
proto = "tcp"
port = 22
action = "pass"
dst-local = true

[[policy.port_rule]]
name = "dns-in"
proto = "udp"
port = 53
action = "pass"
family = "ipv6"
dst-local = true

[[policy.port_rule]]
name = "web"
proto = "tcp"
port = 443
action = "pass"
dst = "10.2.0.0/24"
"""

IP = [
    {"ifname": "lo", "addr_info": [{"local": "127.0.0.1"}, {"local": "::1"}]},
    {"ifname": "eth1", "addr_info": [{"local": "10.1.0.1"}, {"local": "fe80::1"}]},
    {"ifname": "eth2", "addr_info": [{"local": "10.2.0.1"}]},
]


class LegacyFilter(unittest.TestCase):
    def rules(self, text):
        return tomllib.loads(text)["policy"][0]["port_rule"]

    def test_named_tables_are_dropped_and_others_kept(self):
        out, stripped, _ = legacy.rewrite(CONFIG, {"state"}, [])
        self.assertEqual(stripped, ["[state]"])
        self.assertNotIn("state", tomllib.loads(out))
        self.assertEqual(tomllib.loads(out)["default_action"], "drop")

    def test_a_local_rule_becomes_one_host_route_per_address(self):
        out, _, expanded = legacy.rewrite(CONFIG, {"state"}, legacy.host_addresses(IP))
        self.assertEqual(expanded, 2)
        ssh = [r["dst"] for r in self.rules(out) if r["name"] == "ssh-in"]
        self.assertEqual(ssh, ["10.1.0.1/32", "10.2.0.1/32", "fe80::1/128"])
        dns = [r["dst"] for r in self.rules(out) if r["name"] == "dns-in"]
        self.assertEqual(dns, ["fe80::1/128"])
        web = [r for r in self.rules(out) if r["name"] == "web"]
        self.assertEqual(web[0]["dst"], "10.2.0.0/24")
        self.assertFalse(any("dst-local" in r for r in self.rules(out)))

    def test_no_address_means_no_rule_never_any_destination(self):
        out, _, _ = legacy.rewrite(CONFIG, {"state"}, [])
        names = [r["name"] for r in self.rules(out)]
        self.assertEqual(names, ["web"])


if __name__ == "__main__":
    unittest.main()
