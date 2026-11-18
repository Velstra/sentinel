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

    def test_compressed_image_names_are_rejected(self):
        for suffix in hygiene.IMAGE_SUFFIXES:
            for compression in ("", ".xz", ".gz", ".zst"):
                self.assertTrue(hygiene.image_artifact("disk" + suffix + compression))

    def test_deleted_historical_images_remain_blocked_without_reading_their_contents(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def git(*args):
                return subprocess.check_output(["git", "-C", str(root), *args])
            git("init", "--quiet")
            git("config", "user.name", "Fixture")
            git("config", "user.email", "fixture@example.invalid")
            git("config", "commit.gpgsign", "false")
            git("config", "core.hooksPath", "/dev/null")
            names = ("old image.qcow2", "nested/new\nline.RAW.zst")
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("DISPOSABLE FIXTURE, NOT A DISK")
            git("add", "--", *names)
            git("commit", "--quiet", "-m", "historical fixture")
            git("rm", "--", *names)
            git("commit", "--quiet", "-m", "deletion is not removal from history")
            self.assertEqual(hygiene.check(root), [])
            self.assertEqual(set(hygiene.check_history(root)), set(names))
            with self.assertRaises(subprocess.CalledProcessError):
                hygiene.check_history(root, "--all")

    def test_shallow_history_is_refused(self):
        from unittest.mock import patch
        with patch.object(hygiene.subprocess, "check_output", return_value="true\n"):
            with self.assertRaisesRegex(ValueError, "complete Git checkout"):
                hygiene.check_history(Path("/unused"))


if __name__ == "__main__":
    unittest.main()
