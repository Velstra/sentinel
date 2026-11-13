"""Offline synthetic oracle tests only; no VM, socket, Nix or cloud execution."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("fixture_observer", SOURCE / "nix/update-test-observer.py")
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


def network():
    desired = {"interface": [{"name": "eth1", "zone": "wan", "address": "192.0.2.2/24",
                              "address6": "2001:db8:1::2/64"}]}
    compiled = {"interface": [{"name": "eth1", "policy": 1, "activate": True}]}
    links = [{"ifname": "eth1", "flags": ["UP"], "xdp": {"mode": 2, "prog": {"id": 42}},
              "addr_info": [{"local": "192.0.2.2", "prefixlen": 24},
                            {"local": "2001:db8:1::2", "prefixlen": 64}]}]
    return [desired, compiled, copy.deepcopy(compiled), links,
            {"ipv4": ["192.0.2.2/24"], "ipv6": ["2001:db8:1::2/64"]}, b"Ready\n"]


def unit(start, end):
    return {"ActiveState": "active", "Result": "success", "ExecMainStatus": "0",
            "ExecMainStartTimestampMonotonic": str(start),
            "ExecMainExitTimestampMonotonic": str(end)}


def assessment():
    return {"velstra": unit(10, 0), "verify": unit(20, 30), "bless": unit(40, 50)}


def snapshot():
    return {"phase": "initial", "disk": "/dev/vda", "boot_id": "initial",
            "persistent": {"config_sha256": "a" * 64, "ssh_keys": {name: "b" * 64 for name in observer.KEYS},
                           "machine_id_raw_sha256": "c" * 64},
            "fallback_a": {"2": {"sha256": "d" * 64}, "3": {"sha256": "e" * 64}, "uki_sha256": "f" * 64},
            "partitions": {str(n): {"uuid": f"partition-{n}", "type": f"type-{n}", "size": n} for n in range(1, 7)},
            "dataplane": {"addresses": ["192.0.2.2/24"], "xdp_program_id": 42}}


def gpt(phase="initial"):
    kinds = {"2": observer.USR_VERITY, "3": observer.USR}
    if phase != "initial":
        kinds |= {"4": observer.USR_VERITY, "5": observer.USR}
    return "\n".join(f"vda{n} part 268435456 00000000-0000-0000-0000-00000000000{n} "
                     + kinds.get(str(n), "11111111-1111-1111-1111-111111111111") for n in range(1, 7))


class FixtureOracleTests(unittest.TestCase):
    def test_healthy_synthetic_native_generic_and_offload_bindings(self):
        for mode in (1, 2, 3):
            args = network()
            args[3][0]["xdp"]["mode"] = mode
            self.assertEqual(observer.validate_dataplane(*args)["xdp_mode"], mode)

    def test_address_only_unconfigured_factory_is_not_this_fixture(self):
        args = network()
        args[0]["interface"][0].pop("zone")
        args[1]["interface"] = []
        args[2] = copy.deepcopy(args[1])
        with self.assertRaises(ValueError):
            observer.validate_dataplane(*args)

    def test_wrong_nic_zone_disabled_or_extra_interface_refused(self):
        for field, value in (("name", "eth0"), ("zone", "wrong"), ("disabled", True)):
            args = network()
            args[0]["interface"][0][field] = value
            with self.assertRaises(ValueError):
                observer.validate_dataplane(*args)
        args = network()
        args[0]["interface"].append({"name": "another"})
        with self.assertRaises(ValueError):
            observer.validate_dataplane(*args)

    def test_runtime_drift_or_missing_policy_binding_refused(self):
        for value in ([], [{"name": "eth0", "policy": 1}], [{"name": "eth1", "policy": True}],
                      [{"name": "eth1", "policy": -1}]):
            args = network()
            args[1]["interface"] = value
            with self.assertRaises(ValueError):
                observer.validate_dataplane(*args)
        args = network()
        args[2]["different"] = True
        with self.assertRaises(ValueError):
            observer.validate_dataplane(*args)

    def test_active_agent_without_ready_is_refused(self):
        for ready in (b"", b"Failed (traffic blocked)", b"Readying"):
            args = network()
            args[-1] = ready
            with self.assertRaises(ValueError):
                observer.validate_dataplane(*args)

    def test_bad_or_missing_actual_xdp_identity_refused(self):
        for mode, program in ((0, 42), (True, 42), (2, 0), (2, True), (2, "42"), (2, -1)):
            args = network()
            args[3][0]["xdp"] = {"mode": mode, "prog": {"id": program}}
            with self.assertRaises(ValueError):
                observer.validate_dataplane(*args)
        args = network()
        args[3][0].pop("xdp")
        with self.assertRaises(ValueError):
            observer.validate_dataplane(*args)

    def test_address_mismatch_missing_link_or_down_link_refused(self):
        for kind in ("expected", "actual", "down", "missing", "dadfailed"):
            args = network()
            if kind == "expected":
                args[4]["ipv4"] = ["192.0.2.3/24"]
            elif kind == "actual":
                args[3][0]["addr_info"] = []
            elif kind == "down":
                args[3][0]["flags"] = []
            elif kind == "missing":
                args[3] = []
            else:
                args[3][0]["addr_info"][0]["dadfailed"] = True
            with self.assertRaises(ValueError):
                observer.validate_dataplane(*args)

    def test_empty_duplicate_or_wrong_family_expected_addresses_refused(self):
        for expected in ({"ipv4": [], "ipv6": []},
                         {"ipv4": ["192.0.2.2/24"] * 2, "ipv6": []},
                         {"ipv4": ["2001:db8::2/64"], "ipv6": []}):
            args = network()
            args[4] = expected
            with self.assertRaises(ValueError):
                observer.validate_dataplane(*args)

    def test_normal_completed_assessment_is_required(self):
        observer.validate_assessment(assessment(), "Marked boot as 'good'. (Boot attempt counter is at 1.)")

    def test_bless_before_assessment_or_agent_start_refused(self):
        for label, field, value in (("verify", "ExecMainStartTimestampMonotonic", "1"),
                                    ("bless", "ExecMainStartTimestampMonotonic", "29"),
                                    ("velstra", "ExecMainStartTimestampMonotonic", "0"),
                                    ("bless", "ExecMainExitTimestampMonotonic", "0")):
            units = assessment()
            units[label][field] = value
            with self.assertRaises(ValueError):
                observer.validate_assessment(units, "Marked boot as 'good'.")

    def test_unrun_failed_or_inactive_assessment_refused(self):
        for label in ("velstra", "verify", "bless"):
            for field, value in (("ActiveState", "inactive"), ("Result", "exit-code"), ("ExecMainStatus", "1")):
                units = assessment()
                units[label][field] = value
                with self.assertRaises(ValueError):
                    observer.validate_assessment(units, "Marked boot as 'good'.")
        with self.assertRaises(ValueError):
            observer.validate_assessment(assessment(), "ordinary unit completed; no actual bless result")

    def test_unit_property_parser_rejects_duplicate_missing_and_malformed(self):
        raw = "\n".join(f"{key}={value}" for key, value in unit(1, 2).items())
        self.assertEqual(observer.parse_properties(raw), unit(1, 2))
        for broken in (raw + "\nResult=success", raw.replace("Result=success\n", ""), "nonsense", raw + "\nUnexpected=x"):
            with self.assertRaises(ValueError):
                observer.parse_properties(broken)

    def test_correct_verity_backing_deduplicates_same_disk_ancestors(self):
        observer.validate_backing("usr crypt\nvda3 part\nvda disk\nvda2 part\nvda disk", "/dev/vda", "initial")
        observer.validate_backing("usr crypt\nvda5 part\nvda disk\nvda4 part\nvda disk", "/dev/vda", "booted")

    def test_foreign_ambiguous_wrong_slot_or_malformed_backing_refused(self):
        for raw in ("usr crypt\nvda5 part\nvda disk", "vda3 part\nsda disk", "vda3 part\nvda disk\nsda disk",
                    "vda3 part\nvda disk\nsda3 part", "not parseable too many fields", ""):
            with self.assertRaises(ValueError):
                observer.validate_backing(raw, "/dev/vda", "initial")
        with self.assertRaises(ValueError):
            observer.validate_backing("vda3 part\nvda disk", "/dev/sda", "initial")

    def test_actual_permanent_and_pending_entries_and_broad_fallback(self):
        for phase, entries, slot in (("initial", ["sentinel-a.efi"], "a"),
                                     ("staged", ["sentinel-a.efi", "sentinel-b+3.efi"], "b"),
                                     ("booted", ["sentinel-a.efi", "sentinel-b.efi"], "b")):
            observer.validate_entries(entries, f"preferred sentinel-{slot}*\ndefault sentinel-*\n", phase)

    def test_exact_pinned_verity_valid_status_and_corruption_refusals(self):
        observer.validate_verity_status("0 5242880 verity V\n")
        for raw in ("0 5242880 verity C", "0 5242880 linear V", "0 0 verity V", "1 5242880 verity V",
                    "0 5242880 verity", "0 5242880 verity V unexpected", "", "junk junk verity V"):
            with self.assertRaises(ValueError):
                observer.validate_verity_status(raw)

    def test_missing_fallback_still_counted_or_extra_entry_refused(self):
        for entries in (["sentinel-b.efi"], ["sentinel-a.efi", "sentinel-b+2-1.efi"],
                        ["sentinel-a.efi", "sentinel-b.efi", "foreign.efi"]):
            with self.assertRaises(ValueError):
                observer.validate_entries(entries, "preferred sentinel-b*\ndefault sentinel-*\n", "booted")

    def test_hard_default_wrong_preference_or_duplicate_default_refused(self):
        for loader in ("preferred sentinel-b*\ndefault sentinel-b*", "preferred sentinel-a*\ndefault sentinel-*",
                       "preferred sentinel-b*\ndefault sentinel-*\ndefault sentinel-*"):
            with self.assertRaises(ValueError):
                observer.validate_entries(["sentinel-a.efi", "sentinel-b+3.efi"], loader, "staged")

    def test_six_target_gpt_identities_and_verity_types(self):
        self.assertEqual(set(observer.validate_partitions(gpt(), "/dev/vda", "initial")), set("123456"))
        observer.validate_partitions(gpt("booted"), "/dev/vda", "booted")

    def test_missing_duplicate_foreign_or_wrong_type_gpt_refused(self):
        raw = gpt("staged")
        for broken in ("\n".join(raw.splitlines()[:-1]), raw + "\n" + raw.splitlines()[0],
                       raw.replace("vda4", "sda4"), raw.replace(observer.USR_VERITY, observer.USR),
                       raw.replace("000000000006", "000000000005")):
            with self.assertRaises(ValueError):
                observer.validate_partitions(broken, "/dev/vda", "staged")

    def test_staging_and_reboot_preserve_identity_but_program_id_may_change(self):
        first = snapshot()
        for phase in ("staged", "booted"):
            current = copy.deepcopy(first)
            current["phase"] = phase
            current["dataplane"]["xdp_program_id"] = 100
            if phase == "booted":
                current["boot_id"] = "new-boot"
            observer.compare(first, current, phase)

    def test_changed_config_private_key_machine_or_fallback_bytes_refused(self):
        for kind in ("config", "key", "machine", "sealed", "uki", "gpt", "address", "disk"):
            first = snapshot()
            current = copy.deepcopy(first)
            current["phase"] = "staged"
            if kind == "config":
                current["persistent"]["config_sha256"] = "0" * 64
            elif kind == "key":
                current["persistent"]["ssh_keys"]["ssh_host_rsa_key"] = "0" * 64
            elif kind == "machine":
                current["persistent"]["machine_id_raw_sha256"] = "0" * 64
            elif kind == "sealed":
                current["fallback_a"]["3"]["sha256"] = "0" * 64
            elif kind == "uki":
                current["fallback_a"]["uki_sha256"] = "0" * 64
            elif kind == "gpt":
                current["partitions"]["6"]["uuid"] = "wrong"
            elif kind == "address":
                current["dataplane"]["addresses"] = []
            else:
                current["disk"] = "/dev/vdb"
            with self.assertRaises(ValueError):
                observer.compare(first, current, "staged")

    def test_wrong_boot_transition_or_comparison_phase_refused(self):
        first = snapshot()
        current = copy.deepcopy(first)
        current["phase"] = "booted"
        with self.assertRaises(ValueError):
            observer.compare(first, current, "booted")
        current["phase"] = "staged"
        current["boot_id"] = "new-boot"
        with self.assertRaises(ValueError):
            observer.compare(first, current, "staged")
        with self.assertRaises(ValueError):
            observer.compare(first, current, "initial")

    def test_private_key_hash_never_returns_secret_bytes(self):
        metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_dev=1,
                                   st_ino=2, st_size=6, st_mtime_ns=3)
        with patch.object(observer.os, "open", return_value=9) as opened, \
                patch.object(observer.os, "fstat", return_value=metadata), \
                patch.object(observer.os, "read", side_effect=[b"secret", b""]), \
                patch.object(observer.os, "close") as closed:
            digest = observer.file_sha(Path("/synthetic/key"), 100, private=True)
            self.assertEqual(digest, hashlib.sha256(b"secret").hexdigest())
            self.assertNotIn("secret", digest)
            self.assertTrue(opened.call_args.args[1] & observer.os.O_NOFOLLOW)
            self.assertTrue(opened.call_args.args[1] & observer.os.O_NONBLOCK)
            closed.assert_called_once_with(9)

    def test_nonroot_nonregular_or_world_readable_key_refused_before_read(self):
        for mode, owner in ((stat.S_IFIFO | 0o600, 0), (stat.S_IFREG | 0o644, 0), (stat.S_IFREG | 0o600, 1000)):
            metadata = SimpleNamespace(st_mode=mode, st_uid=owner, st_dev=1, st_ino=2, st_size=6, st_mtime_ns=3)
            with patch.object(observer.os, "open", return_value=9), \
                    patch.object(observer.os, "fstat", return_value=metadata), \
                    patch.object(observer.os, "read") as read, patch.object(observer.os, "close"):
                with self.assertRaises(ValueError):
                    observer.file_sha(Path("/synthetic/key"), 100, private=True)
                read.assert_not_called()


class NativeProbeStartupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        module = importlib.util.spec_from_file_location("native_probe", SOURCE / "nix/native-update-probe.py")
        cls.probe = importlib.util.module_from_spec(module)
        module.loader.exec_module(cls.probe)

    def test_only_read_only_connection_refused_is_retryable(self):
        error = self.probe.urllib.error.URLError(ConnectionRefusedError(111, "refused"))
        with patch.object(self.probe, "request", side_effect=error) as request:
            self.assertFalse(self.probe.restarted_api_has_job("reviewed-job"))
        request.assert_called_once_with("/system/updates/jobs/reviewed-job")

    def test_success_and_observation_unavailable_remain_distinct(self):
        for status, expected in ((200, True), (503, False)):
            with self.subTest(status=status), patch.object(self.probe, "request", return_value=(status, {})):
                self.assertEqual(self.probe.restarted_api_has_job("job"), expected)

    def test_auth_missing_job_and_server_errors_are_not_startup_retries(self):
        for status in (401, 403, 404, 409, 500):
            with self.subTest(status=status), patch.object(self.probe, "request", return_value=(status, {})):
                with self.assertRaises(AssertionError):
                    self.probe.restarted_api_has_job("job")

    def test_tls_dns_reset_and_unexpected_failures_are_not_hidden(self):
        for reason in (self.probe.ssl.SSLCertVerificationError("bad certificate"),
                       OSError("DNS unavailable"), ConnectionResetError(104, "reset")):
            error = self.probe.urllib.error.URLError(reason)
            with self.subTest(reason=type(reason).__name__), patch.object(self.probe, "request", side_effect=error):
                with self.assertRaises(self.probe.urllib.error.URLError) as caught:
                    self.probe.restarted_api_has_job("job")
                self.assertIs(caught.exception, error)

    def test_restart_observation_converges_without_resubmitting_any_mutation(self):
        error = self.probe.urllib.error.URLError(ConnectionRefusedError(111, "refused"))
        with patch.object(self.probe, "request", side_effect=[error, (503, {}), (200, {})]) as request, \
                patch.object(self.probe.time, "sleep"):
            self.assertTrue(self.probe.until(lambda: self.probe.restarted_api_has_job("job"), seconds=1))
        self.assertEqual(request.call_count, 3)
        self.assertTrue(all(call.args == ("/system/updates/jobs/job",) and not call.kwargs
                            for call in request.call_args_list))

    def test_missing_api_remains_bounded_and_cannot_pass(self):
        error = self.probe.urllib.error.URLError(ConnectionRefusedError(111, "refused"))
        with patch.object(self.probe, "request", side_effect=error) as request, \
                patch.object(self.probe.time, "sleep"), \
                patch.object(self.probe.time, "monotonic", side_effect=[0, 0, 1, 2]):
            with self.assertRaisesRegex(AssertionError, "did not converge"):
                self.probe.until(lambda: self.probe.restarted_api_has_job("job"), seconds=1.5)
        self.assertEqual(request.call_count, 2)


if __name__ == "__main__":
    unittest.main()
