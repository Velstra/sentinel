"""STATIC-10: an aged or floating Nix input fails CI."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("freshness", ROOT / "scripts" / "check_input_freshness.py")
freshness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(freshness)
DAY = 86400


def lock(modified, rev="a" * 40, nar="sha256-x"):
    return {"root": "root", "nodes": {
        "root": {"inputs": {"nixpkgs": "nixpkgs"}},
        "nixpkgs": {"locked": {"lastModified": modified, "rev": rev, "narHash": nar}}}}


class Freshness(unittest.TestCase):
    def test_a_recent_immutable_pin_passes(self):
        self.assertEqual(freshness.problems(lock(1000 * DAY), 1010 * DAY, 21), [])

    def test_an_aged_pin_fails(self):
        found = freshness.problems(lock(1000 * DAY), 1024 * DAY, 21)
        self.assertEqual(len(found), 1)
        self.assertIn("24 days old", found[0])

    def test_an_unlocked_input_fails(self):
        self.assertTrue(freshness.problems(lock(1000 * DAY, nar=""), 1000 * DAY, 21))

    def test_the_repository_lock_parses(self):
        document = json.loads((ROOT / "flake.lock").read_text())
        self.assertIsInstance(freshness.problems(document, 0, 10**6), list)


if __name__ == "__main__":
    unittest.main()
