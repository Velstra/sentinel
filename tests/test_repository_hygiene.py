import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("hygiene", Path(__file__).resolve().parents[1] /
                                             "scripts/check_repository_hygiene.py")
hygiene = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hygiene)


class RepositoryHygieneTests(unittest.TestCase):
    def test_disk_names_and_renamed_qcow2_are_rejected_without_reading_secrets(self):
        for name in ("disk.qcow2", "disk.RAW", "installer.iso", "partition.raw.zst", "update.efi"):
            self.assertTrue(hygiene.image_artifact(name))
        self.assertTrue(hygiene.image_artifact("innocent.bin", b"QFI\xfb"))
        self.assertFalse(hygiene.image_artifact("docs/network.png", b"\x89PNG"))

    def test_only_tracked_files_are_examined_and_symlinks_are_not_followed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "--quiet", str(root)], check=True)
            (root / "source.rs").write_text("fn main() {}")
            (root / "renamed.bin").write_bytes(b"QFI\xfbprivate-disk-data")
            (root / "untracked.raw").write_bytes(b"private-untracked-disk")
            (root / "symlink").symlink_to("untracked.raw")
            subprocess.run(["git", "-C", str(root), "add", "source.rs", "renamed.bin", "symlink"], check=True)
            self.assertEqual(hygiene.check(root), ["renamed.bin"])


if __name__ == "__main__":
    unittest.main()
