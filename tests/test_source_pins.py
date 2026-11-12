import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("check_source_pins", ROOT / "scripts/check_source_pins.py")
pins = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pins)


class SourcePinTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="sentinel-pin-test-")
        self.addCleanup(temporary.cleanup)
        self.source = Path(temporary.name)
        self.document = json.loads((ROOT / "flake.lock").read_text())
        self.definition = (ROOT / "flake.nix").read_text()

    def check(self, document=None, definition=None):
        (self.source / "flake.lock").write_text(json.dumps(document or self.document))
        (self.source / "flake.nix").write_text(self.definition if definition is None else definition)
        return pins.validate(self.source)

    def test_real_cohort_has_official_pins_and_a_distinct_fixed_legacy_fixture(self):
        result = self.check()
        self.assertEqual(result["fabric-legacy-napt"], pins.LEGACY_NAPT)
        self.assertNotEqual(result["fabric"], result["fabric-legacy-napt"])

    def test_missing_mutable_foreign_or_mismatched_pin_is_rejected(self):
        for name in pins.INPUTS:
            for section in ("locked", "original"):
                for key, value in (("owner", "untrusted"), ("repo", "other"),
                                   ("type", "git"), ("rev", "main"), ("rev", "a" * 40)):
                    with self.subTest(name=name, section=section, key=key, value=value):
                        document = copy.deepcopy(self.document)
                        document["nodes"][name][section][key] = value
                        with self.assertRaises(ValueError):
                            self.check(document)
            document = copy.deepcopy(self.document)
            document["nodes"][name]["locked"].pop("narHash")
            with self.assertRaises(ValueError):
                self.check(document)

    def test_url_drift_and_duplicate_declarations_are_rejected(self):
        for definition in (self.definition.replace("github:Velstra/wren/", "github:other/wren/"),
                           self.definition + '\n wren = { url = "github:Velstra/wren/main"; };\n'):
            with self.assertRaises(ValueError):
                self.check(definition=definition)

    def test_both_sides_of_mixed_version_test_cannot_silently_advance(self):
        document = copy.deepcopy(self.document)
        current = document["nodes"]["fabric"]["locked"]["rev"]
        for section in ("locked", "original"):
            document["nodes"]["fabric-legacy-napt"][section]["rev"] = current
        with self.assertRaisesRegex(ValueError, "fixture must not advance"):
            self.check(document, self.definition.replace(pins.LEGACY_NAPT, current))

    def test_production_cannot_silently_revert_to_the_old_fixture(self):
        document = copy.deepcopy(self.document)
        current = document["nodes"]["fabric"]["locked"]["rev"]
        for section in ("locked", "original"):
            document["nodes"]["fabric"][section]["rev"] = pins.LEGACY_NAPT
        with self.assertRaisesRegex(ValueError, "current dataplane twice"):
            self.check(document, self.definition.replace(current, pins.LEGACY_NAPT))


if __name__ == "__main__":
    unittest.main()
