"""Unit tests for the shipped-closure security floor check."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_security_floor.py"
MANIFEST = ROOT / "nix" / "security-floor.json"


def load():
    spec = importlib.util.spec_from_file_location("check_security_floor", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


floor = load()
A = "/nix/store/" + "a" * 32 + "-"
B = "/nix/store/" + "b" * 32 + "-"
KERNEL = [{"package": "linux", "minimum": "6.12.118", "fixes": "6.12.y stable"}]


class Versions(unittest.TestCase):
    def test_numeric_components(self):
        self.assertLess(floor.version_key("6.12.117"), floor.version_key("6.12.118"))
        self.assertLess(floor.version_key("6.12.99"), floor.version_key("6.12.118"))
        self.assertEqual(floor.version_key("2.42-103"), (2, 42, 103))
        self.assertLess(floor.version_key("1.9.17p1"), floor.version_key("1.9.17p2"))

    def test_rejects_versionless(self):
        with self.assertRaises(ValueError):
            floor.version_key("unstable")


class Floors(unittest.TestCase):
    def test_old_kernel_fails(self):
        failures = floor.floor_failures([A + "linux-6.12.117", A + "linux-6.12.117-modules"], KERNEL)
        self.assertEqual(len(failures), 2)
        self.assertIn("linux-6.12.117", failures[0])

    def test_fixed_kernel_passes(self):
        self.assertEqual(floor.floor_failures([A + "linux-6.12.118", A + "linux-6.12.118-modules"], KERNEL), [])

    def test_one_stale_copy_fails(self):
        failures = floor.floor_failures([A + "linux-6.12.118", B + "linux-6.12.117-modules"], KERNEL)
        self.assertEqual(len(failures), 1)

    def test_absent_package_fails(self):
        failures = floor.floor_failures([A + "glibc-2.42-103"], KERNEL)
        self.assertIn("not in the closure", failures[0])

    def test_other_pnames_do_not_match(self):
        paths = [A + "linux-6.12.118", A + "linux-firmware-20261101", A + "linux-headers-static-6.12"]
        self.assertEqual(floor.floor_failures(paths, KERNEL), [])

    def test_manifest_validation(self):
        with self.assertRaises(ValueError):
            floor.load_floors({"schema": "wrong", "floors": KERNEL})
        with self.assertRaises(ValueError):
            floor.load_floors({"schema": floor.SCHEMA, "floors": [{"package": "linux", "minimum": "6"}]})
        with self.assertRaises(ValueError):
            floor.load_floors({"schema": floor.SCHEMA, "floors": KERNEL + KERNEL})

    def test_shipped_manifest_is_valid(self):
        floors = floor.load_floors(json.loads(MANIFEST.read_text()))
        self.assertIn("linux", {f["package"] for f in floors})


class Replacements(unittest.TestCase):
    def test_taken(self):
        self.assertEqual(floor.replacement_failures([B + "sudo-1.9.17p2"], [
            {"old": A + "sudo-1.9.17p2", "new": B + "sudo-1.9.17p2"}]), [])

    def test_not_taken(self):
        failures = floor.replacement_failures([A + "sudo-1.9.17p2"], [
            {"old": A + "sudo-1.9.17p2", "new": B + "sudo-1.9.17p2"}])
        self.assertEqual(len(failures), 2)

    def test_unused_output_absent_on_both_sides(self):
        self.assertEqual(floor.replacement_failures([B + "libcap-2.78-lib"], [
            {"old": A + "libcap-2.77-lib", "new": B + "libcap-2.78-lib"},
            {"old": A + "libcap-2.77-man", "new": B + "libcap-2.78-man"}]), [])

    def test_rewritten_copy_of_the_replacement_counts(self):
        C = "/nix/store/" + "c" * 32 + "-"
        self.assertEqual(floor.replacement_failures([C + "suricata-8.0.7"], [
            {"old": A + "suricata-8.0.3", "new": B + "suricata-8.0.7"}]), [])

    def test_inert_backport(self):
        failures = floor.replacement_failures([A + "glibc-2.42-103"], [
            {"old": A + "lego-4.35.2", "new": B + "lego-4.35.2"}])
        self.assertEqual(failures, ["replacement inert: no output of the backported lego is in the closure"])


class Programs(unittest.TestCase):
    def test_forbidden_program_found(self):
        shipped = {A + "sqlite-3.54.1-bin/bin/sqlite3"}
        failures = floor.program_failures([A + "sqlite-3.54.1-bin"], ["sqlite3"], shipped.__contains__)
        self.assertEqual(failures, ["program must not ship: " + A + "sqlite-3.54.1-bin/bin/sqlite3"])

    def test_library_only_passes(self):
        self.assertEqual(floor.program_failures([A + "sqlite-3.54.1"], ["sqlite3", "ocspcheck"],
                                                lambda _path: False), [])


class Main(unittest.TestCase):
    def run_main(self, paths, floors, replacements=None):
        with tempfile.TemporaryDirectory() as tmp:
            closure = Path(tmp, "paths")
            closure.write_text("\n".join(paths) + "\n")
            manifest = Path(tmp, "floors.json")
            manifest.write_text(json.dumps({"schema": floor.SCHEMA, "floors": floors}))
            argv = [str(closure), "--floors", str(manifest)]
            if replacements is not None:
                Path(tmp, "repl.json").write_text(json.dumps(replacements))
                argv += ["--replacements", str(Path(tmp, "repl.json"))]
            return floor.main(argv)

    def test_exit_codes(self):
        self.assertEqual(self.run_main([A + "linux-6.12.118"], KERNEL), 0)
        self.assertEqual(self.run_main([A + "linux-6.12.117"], KERNEL), 1)
        self.assertEqual(self.run_main([], KERNEL), 2)
        self.assertEqual(self.run_main([A + "linux-6.12.118"], KERNEL, replacements=[]), 2)


if __name__ == "__main__":
    unittest.main()
