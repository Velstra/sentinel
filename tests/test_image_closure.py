"""Regression tests for the shipped-closure build-tool check (IMG-06)."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_image_closure.py"


def load():
    spec = importlib.util.spec_from_file_location("check_image_closure", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


closure = load()
H = "/nix/store/" + "a" * 32 + "-"


class ParseStoreName(unittest.TestCase):
    def test_plain_package(self):
        self.assertEqual(closure.parse_store_name(H + "glibc-2.42-100"), ("glibc", "2.42-100", "out"))

    def test_split_output(self):
        self.assertEqual(closure.parse_store_name(H + "curl-8.23.0-bin"), ("curl", "8.23.0", "bin"))
        self.assertEqual(closure.parse_store_name(H + "glibc-2.42-100-dev"), ("glibc", "2.42-100", "dev"))
        self.assertEqual(closure.parse_store_name(H + "gcc-15.3.0-libgcc"), ("gcc", "15.3.0", "libgcc"))

    def test_hyphenated_pname(self):
        self.assertEqual(closure.parse_store_name(H + "gcc-wrapper-15.3.0"), ("gcc-wrapper", "15.3.0", "out"))
        self.assertEqual(closure.parse_store_name(H + "util-linux-minimal-2.42.3-lib"),
                         ("util-linux-minimal", "2.42.3", "lib"))
        self.assertEqual(closure.parse_store_name(H + "perl5.42.3-JSON-4.10"), ("perl5.42.3-JSON", "4.10", "out"))

    def test_patch_version_suffix(self):
        self.assertEqual(closure.parse_store_name(H + "openssh-10.5p1"), ("openssh", "10.5p1", "out"))

    def test_unversioned(self):
        self.assertEqual(closure.parse_store_name(H + "unit-script-sentinel-boot-start"),
                         ("unit-script-sentinel-boot-start", "", "out"))

    def test_rejects_non_store_path(self):
        with self.assertRaises(ValueError):
            closure.parse_store_name("/usr/bin/gcc")


class ForbiddenOutputs(unittest.TestCase):
    def offenders(self, *names):
        return [entry["path"] for entry in closure.forbidden([H + name for name in names])]

    def test_compiler_is_forbidden(self):
        self.assertEqual(self.offenders("gcc-15.3.0"), [H + "gcc-15.3.0"])
        self.assertTrue(self.offenders("gcc-wrapper-15.3.0"))
        self.assertTrue(self.offenders("xgcc-15.3.0"))
        self.assertTrue(self.offenders("clang-21.1.8"))
        self.assertTrue(self.offenders("clang-wrapper-21.1.8"))
        self.assertTrue(self.offenders("llvm-21.1.8"))

    def test_binutils_is_forbidden(self):
        self.assertTrue(self.offenders("binutils-2.46"))
        self.assertTrue(self.offenders("binutils-wrapper-2.46"))

    def test_dev_outputs_and_headers_are_forbidden(self):
        self.assertTrue(self.offenders("glibc-2.42-100-dev"))
        self.assertTrue(self.offenders("openssl-3.6.5-dev"))
        self.assertTrue(self.offenders("linux-headers-6.18.7"))
        self.assertTrue(self.offenders("linux-headers-static-6.18.7"))

    def test_runtime_libraries_are_allowed(self):
        self.assertEqual(self.offenders(
            "gcc-15.3.0-lib", "gcc-15.3.0-libgcc", "xgcc-15.3.0-libgcc", "glibc-2.42-100",
            "glibc-2.42-100-bin", "llvm-21.1.8-lib", "openssl-3.6.5", "curl-8.23.0-bin",
            "linux-6.12.117-modules", "systemd-260.5", "libdevmapper-1.02", "udev-rules"), [])

    def test_reasons_name_the_rule(self):
        entries = closure.forbidden([H + "glibc-2.42-100-dev", H + "gcc-15.3.0"])
        self.assertEqual({entry["reason"] for entry in entries}, {"development output", "compiler toolchain"})


class CommandLine(unittest.TestCase):
    def run_check(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            listing = Path(tmp) / "closure.txt"
            listing.write_text(text)
            return subprocess.run([sys.executable, "-B", str(SCRIPT), str(listing)],
                                  capture_output=True, text=True, check=False)

    def test_old_closure_fails(self):
        result = self.run_check(f"{H}glibc-2.42-100\n{H}gcc-15.3.0\n{H}glibc-2.42-100-dev\n")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("gcc-15.3.0", result.stdout)
        self.assertIn("glibc-2.42-100-dev", result.stdout)

    def test_clean_closure_passes(self):
        result = self.run_check(f"{H}glibc-2.42-100\n{H}gcc-15.3.0-lib\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_empty_closure_is_refused(self):
        # An empty list proves nothing about the image; never report it clean.
        result = self.run_check("\n")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_garbage_line_is_refused(self):
        result = self.run_check(f"{H}glibc-2.42-100\nnot a store path\n")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)



class Exceptions(unittest.TestCase):
    HEADERS = "/nix/store/" + "a" * 32 + "-linux-headers-static-6.18.7"

    def test_a_reviewed_exception_lets_only_that_package_through(self):
        gcc = "/nix/store/" + "b" * 32 + "-gcc-15.3.0"
        found = closure.forbidden([self.HEADERS, gcc], allowed=["linux-headers-static"])
        self.assertEqual([entry["path"] for entry in found], [gcc])

    def test_a_stale_exception_fails(self):
        found = closure.forbidden(["/nix/store/" + "c" * 32 + "-glibc-2.42-100"],
                                  allowed=["linux-headers-static"])
        self.assertEqual(found[0]["reason"], "stale exception (matches nothing)")

    def test_an_exception_needs_a_reason(self):
        self.assertEqual(closure.main(["--allow", "linux-headers-static", "-"]), 2)

if __name__ == "__main__":
    unittest.main()
