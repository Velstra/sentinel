import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("boot_health", Path(__file__).with_name("boot-health.py"))
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)


class BootHealthTests(unittest.TestCase):
    def setUp(self):
        self.desired = {"interface": [{"name": "wan0", "zone": "wan", "address": "192.0.2.1/24"}]}
        self.compiled = {"interface": [{"name": "wan0", "policy": 1, "activate": True}]}
        self.link = {"ifname": "wan0", "flags": ["UP"],
                     "xdp": {"mode": 2, "prog": {"id": 42},
                             "attached": [{"mode": 2, "prog": {"id": 42}}]},
                     "addr_info": [{"local": "192.0.2.1", "prefixlen": 24}]}

    def test_healthy_native_and_generic_hooks(self):
        for mode in (1, 2, 3):
            self.link["xdp"]["mode"] = mode
            self.assertEqual(health.link_failures(self.desired, self.compiled, [self.link]), [])

    def test_missing_or_invalid_kernel_program_identity_is_not_an_attachment(self):
        for mode, program in ((0, 42), (2, 0), (2, -1), (2, True), (2, "42")):
            self.link["xdp"] = {"mode": mode, "prog": {"id": program}}
            self.assertTrue(health.link_failures(self.desired, self.compiled, [self.link]))

    def test_active_process_without_hook_or_reconciled_address_is_not_healthy(self):
        for field in ("xdp", "addr_info", "flags"):
            broken = dict(self.link)
            broken.pop(field)
            self.assertTrue(health.link_failures(self.desired, self.compiled, [broken]), field)
        self.assertTrue(health.link_failures(self.desired, self.compiled, []))

    def test_disabled_links_and_offline_dhcp_do_not_require_a_lease_or_carrier(self):
        self.assertEqual(health.link_failures({"interface": [{"name": "absent", "disabled": True}]}, {}, []), [])
        self.desired["interface"][0]["address"] = "dhcp"
        self.link["addr_info"] = []
        self.assertEqual(health.link_failures(self.desired, self.compiled, [self.link]), [])

    def test_factory_skip_is_not_an_error_or_a_malformed_config_bypass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.toml"
            path.write_text("interface=[]\n")
            self.assertFalse(health.dataplane_enabled(path))
            path.write_text('[[interface]]\nname="wan0"\npolicy=1\n')
            self.assertTrue(health.dataplane_enabled(path))
            for malformed in ('', 'interface="wrong"', '[[interface]]\nname="wan0"\n',
                              '[[interface]]\nname="wan0"\npolicy=true\n'):
                path.write_text(malformed)
                with self.assertRaises((KeyError, ValueError)):
                    health.dataplane_enabled(path)

    def test_ipv6_address_identity_and_dad_failure(self):
        self.desired["interface"][0].pop("address")
        self.desired["interface"][0]["address6"] = "2001:db8::1/64"
        address = {"local": "2001:0db8:0:0:0:0:0:1", "prefixlen": 64}
        self.link["addr_info"] = [address]
        self.assertEqual(health.link_failures(self.desired, self.compiled, [self.link]), [])
        for state in ("tentative", "dadfailed"):
            address[state] = True
            self.assertTrue(health.link_failures(self.desired, self.compiled, [self.link]))
            address.pop(state)

    def test_efi_trial_is_bounded_to_an_actual_counted_uki_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "efivar"
            for value, expected in (("\\EFI\\Linux\\sentinel-a+2-1.efi", True),
                                    ("/EFI/Linux/sentinel-b+0-3.efi", True),
                                    ("/EFI/Linux/sentinel-a.efi", False),
                                    ("/EFI/Linux/../../anything+3-0.efi", False),
                                    ("/other/sentinel-a+3-0.efi", False)):
                path.write_bytes(b"\x07\x00\x00\x00" + (value + "\0").encode("utf-16-le"))
                self.assertEqual(health.trial_boot(path), expected, value)
            path.write_bytes(b"invalid")
            self.assertFalse(health.trial_boot(path))
            self.assertFalse(health.trial_boot(Path(directory) / "absent"))

    def test_schema_failure_and_concurrent_change_withhold_blessing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "appliance.toml"
            path.write_text('[system]\nhostname="boot-test"\n')
            with patch.object(health.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)), \
                    patch.object(health, "pending") as pending:
                self.assertFalse(health.verify(path, path, "sentinel", "systemctl", "ip", 0.01))
                pending.assert_not_called()
            def changed(*args, **kwargs):
                path.write_text('[system]\nhostname="changed"\n')
                return subprocess.CompletedProcess([], 0, b"", b"")
            with patch.object(health.subprocess, "run", side_effect=changed), \
                    patch.object(health, "pending") as pending:
                self.assertFalse(health.verify(path, path, "sentinel", "systemctl", "ip", 0.01))
                pending.assert_not_called()

    def test_api_and_dataplane_are_required_only_when_configured(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.toml"
            path.write_text("")
            called = []
            def run(command, **kwargs):
                called.append(command)
                return subprocess.CompletedProcess(command, 0, b"[]", b"")
            with patch.object(health.subprocess, "run", side_effect=run), patch.object(health, "query", return_value=b"no vrfs configured\n"):
                self.assertEqual(health.pending({}, {}, "systemctl", "ip", path), [])
                self.assertFalse(any("sentinel-api.service" in command or "velstra.service" in command for command in called))
                called.clear()
                health.pending({"system": {"config-sync": {"secret": "test-only"}}}, {}, "systemctl", "ip", path)
                self.assertTrue(any("sentinel-api.service" in command for command in called))

    def test_configuration_not_ready_and_runtime_drift_are_not_waived(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.toml"
            path.write_text("different=true\n")
            with patch.object(health.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"[]", b"")), \
                    patch.object(health, "query", side_effect=lambda path, request: b"no vrfs configured\n" if "wren" in path else b"Failed (traffic blocked)\n"):
                failures = health.pending({}, self.compiled, "systemctl", "ip", path)
                self.assertIn("dataplane configuration is not Ready", failures)
                self.assertIn("compiled runtime differs from the saved configuration", failures)

    def test_router_readiness_requires_a_real_bounded_command_response(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.toml"
            path.write_text("")
            with patch.object(health.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"[]", b"")):
                for reply in (b"", b"error: router unavailable\n", b"unexpected\n"):
                    with patch.object(health, "query", return_value=reply):
                        self.assertIn("routing control response is not ready", health.pending({}, {}, "systemctl", "ip", path))
                with patch.object(health, "query", return_value=b"vrf table rd routes\ntenant 100 - 5\n"):
                    self.assertEqual(health.pending({}, {}, "systemctl", "ip", path), [])


if __name__ == "__main__":
    unittest.main()
