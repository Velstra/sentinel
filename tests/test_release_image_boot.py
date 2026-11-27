"""Host-side boot-gate contracts; these tests do not boot or certify an image."""
import ast
import hashlib
from pathlib import Path
import re
import tempfile
import textwrap
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "nix/release-image-boot.nix"
NIX = SOURCE.read_text()
SCRIPT = textwrap.dedent(NIX.split("  testScript = { nodes, ... }: ''\n", 1)[1].rsplit("\n  '';", 1)[0])
# Nix interpolation is confined to Python string constants. Parsing the whole
# rendered shape catches syntax errors while tests execute the exact helpers.
TREE = ast.parse(re.sub(r"\$\{[^}]+\}", "NIX_VALUE", SCRIPT))
HELPERS = {"hash_file", "require_digest", "entry_names", "require_entry", "record_marker", "require_markers"}
FUNCTIONS = ast.Module(body=[node for node in TREE.body if isinstance(node, ast.FunctionDef) and node.name in HELPERS], type_ignores=[])
ENV = {"Path": Path, "hashlib": hashlib, "re": re}
exec(compile(FUNCTIONS, str(SOURCE), "exec"), ENV)


class ReleaseImageBootContracts(unittest.TestCase):
    def test_all_selected_helpers_are_the_real_fixture_definitions(self):
        self.assertEqual({node.name for node in FUNCTIONS.body}, HELPERS)

    def test_source_digest_accepts_only_exact_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "candidate.raw")
            path.write_bytes(b"exact-release-image")
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(ENV["require_digest"](path, expected), expected)
            path.write_bytes(b"different-release-image")
            with self.assertRaisesRegex(AssertionError, "hash mismatch"):
                ENV["require_digest"](path, expected)

    def test_digest_rejects_invalid_expected_values(self):
        for expected in ("", "0" * 63, "0" * 65, "G" * 64, "A" * 64):
            with self.subTest(expected=expected), self.assertRaisesRegex(AssertionError, "invalid expected"):
                ENV["require_digest"](Path("must-not-be-opened"), expected)

    def test_initial_entry_requires_a_counted_trial(self):
        names = ENV["entry_names"]("::/EFI/Linux/sentinel-a+3.efi\n")
        self.assertEqual(ENV["require_entry"](names, False), ["sentinel-a+3.efi"])
        for entries in ({"sentinel-a.efi"}, set(), {"sentinel-a+2-1.efi"}):
            with self.subTest(entries=entries), self.assertRaises(AssertionError):
                ENV["require_entry"](entries, False)

    def test_permanent_entry_cannot_hide_trial_or_unknown_payloads(self):
        self.assertEqual(ENV["require_entry"]({"sentinel-a.efi"}, True), ["sentinel-a.efi"])
        for entries in ({"sentinel-a+3.efi"}, {"sentinel-a.efi", "sentinel-a+2-1.efi"},
                        {"sentinel-a.efi", "unknown.efi"}, {"sentinel-b.efi"}, set()):
            with self.subTest(entries=entries), self.assertRaises(AssertionError):
                ENV["require_entry"](entries, True)

    def milestones(self, blessed=True):
        lines = ["EFI stub: UEFI Secure Boot is enabled", "sentinel-fw login:",
                 "Reached target Multi-User System",
                 "boot health: saved config, services, links and XDP are ready"]
        if blessed:
            lines.append("Finished Mark the Current Boot Loader Entry as Good")
        observed = {}
        for number, line in enumerate(lines, 1):
            ENV["record_marker"](line, observed, number)
        return observed

    def test_first_boot_requires_health_and_bless_not_just_login(self):
        observed = self.milestones()
        self.assertEqual(len(ENV["require_markers"](observed, True)), 5)
        for missing in observed:
            reduced = {name: value for name, value in observed.items() if name != missing}
            with self.subTest(missing=missing), self.assertRaisesRegex(AssertionError, "missing boot"):
                ENV["require_markers"](reduced, True)

    def test_permanent_second_boot_does_not_schedule_another_assessment(self):
        observed = self.milestones(False)
        del observed["product-health"]
        self.assertEqual(len(ENV["require_markers"](observed, False)), 3)
        del observed["multi-user"]
        with self.assertRaisesRegex(AssertionError, "missing boot"):
            ENV["require_markers"](observed, False)

    def test_observed_unit_and_health_failures_are_rejected_on_either_boot(self):
        for line in ("[FAILED] Failed to start a service", "[DEPEND] Dependency failed",
                     "Failed to start required service", "boot health: configuration assessment unavailable"):
            with self.subTest(line=line), self.assertRaises(AssertionError):
                ENV["record_marker"](line, {}, 1)

    def test_bless_before_product_health_is_not_accepted(self):
        observed = self.milestones()
        observed["boot-blessed"] = 2
        with self.assertRaises(AssertionError):
            ENV["require_markers"](observed, True)

    def test_secure_boot_must_precede_health(self):
        observed = self.milestones()
        observed["secure-boot"] = 9
        with self.assertRaises(AssertionError):
            ENV["require_markers"](observed, True)

    def test_unexpected_reboot_is_not_combined_into_one_success(self):
        observed = self.milestones()
        with self.assertRaisesRegex(AssertionError, "unexpected reboot"):
            ENV["record_marker"]("EFI stub: UEFI Secure Boot is enabled", observed, 5)

    def test_ansi_and_repeated_getty_prompts_are_handled(self):
        observed = {}
        ENV["record_marker"]("\x1b[32msentinel-fw login:\x1b[0m", observed, 1)
        ENV["record_marker"]("sentinel-fw login:", observed, 2)
        self.assertEqual(observed, {"login-prompt": 1})

    # Boot 1 of release run 45868284650 (attempt 2) as its job log shows it,
    # from Secure Boot to the getty, with the lines in between that carry no
    # marker left out. agetty ends with "sentinel-fw login: " and no newline:
    # the driver reads the serial line by line, so that prompt only reached
    # the queue when the VM was killed 220 s later.
    RUN_45868284650_BOOT_1 = (
        b"EFI stub: UEFI Secure Boot is enabled.\r\n"
        b"[  OK  ] Reached target Multi-User System.\r\n"
        b"         Starting Verify the appliance before blessing the current UKI...\r\n"
        b"[   11.237886] velstra-boot-verify-start[676]: boot health: saved config, services, links and XDP are ready\r\n"
        b"[  OK  ] Finished Verify the appliance before blessing the current UKI.\r\n"
        b"         Starting Mark the Current Boot Loader Entry as Good...\r\n"
        b"[  OK  ] Finished Mark the Current Boot Loader Entry as Good.\r\n"
        b"7878+q6E616D65\r\n"
        b"\r\n"
        b"<<< Welcome to Velstra Sentinel 26.05.20261116.f684076 (x86_64) - ttyS0 >>>\r\n"
        b"\r\n"
        b"\r\n"
        b"sentinel-fw login: ")

    @staticmethod
    def delivered_while_running(serial):
        """What the test driver queues while the VM runs: whole lines only,
        decoded the way its serial reader decodes them."""
        return [raw.decode(errors="ignore").replace("\r", "").rstrip() for raw in serial.split(b"\n")[:-1]]

    def test_getty_on_the_serial_console_without_a_newline_after_its_prompt(self):
        lines = self.delivered_while_running(self.RUN_45868284650_BOOT_1)
        self.assertNotIn("sentinel-fw login:", lines)
        for require_bless in (True, False):
            with self.subTest(require_bless=require_bless):
                observed = {}
                for number, line in enumerate(lines, 1):
                    ENV["record_marker"](line, observed, number)
                self.assertEqual(len(ENV["require_markers"](observed, require_bless)), 5 if require_bless else 3)
                self.assertLess(observed["multi-user"], observed["login-prompt"])

    def test_issue_line_counts_only_when_agetty_expanded_it_for_ttyS0(self):
        for line in ("<<< Welcome to Velstra Sentinel 26.05.20261116.f684076 (x86_64) - \\l >>>",
                     "<<< Welcome to Velstra Sentinel 26.05.20261116.f684076 (x86_64) - tty1 >>>",
                     "<<< Welcome to Velstra Sentinel 26.05.20261116.f684076 (x86_64) - ttyS01 >>>",
                     "<<< Welcome to NixOS 26.05.20261116.f684076 (x86_64) - ttyS0 >>>",
                     "Welcome to Velstra Sentinel!"):
            observed = {}
            with self.subTest(line=line):
                ENV["record_marker"](line, observed, 1)
                self.assertNotIn("login-prompt", observed)

    def test_login_prompt_must_follow_secure_boot(self):
        observed = self.milestones()
        observed["login-prompt"] = 0
        with self.assertRaises(AssertionError):
            ENV["require_markers"](observed, True)

    def test_other_hostname_and_failure_logs_are_not_health_success(self):
        observed = {}
        for line in ("another-node login:", "EFI stub: UEFI Secure Boot is disabled"):
            ENV["record_marker"](line, observed, 1)
        self.assertEqual(observed, {})

    def test_exact_artifact_and_no_guest_agent_contract(self):
        self.assertIn("directBoot.enable = false;", NIX)
        self.assertIn("mountHostNixStore = false;", NIX)
        self.assertIn("useSecureBoot = true;", NIX)
        self.assertIn('lib.hasInfix "PRIVATE KEY"', NIX)
        self.assertIn('for number in (1, 2):', SCRIPT)
        self.assertIn('report["source_sha256_before"] = require_digest(source, expected)', SCRIPT)
        self.assertIn('report["source_sha256_after"] = require_digest(source, expected)', SCRIPT)
        self.assertIn('os.environ["NIX_EFI_VARS"]', SCRIPT)
        for forbidden in ("machine.succeed", "machine.execute", "machine.send_chars", "peer.send", "machine.shutdown"):
            self.assertNotIn(forbidden, SCRIPT)


if __name__ == "__main__":
    unittest.main()
