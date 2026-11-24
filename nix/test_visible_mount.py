"""Visible-mount regression, including the real util-linux parser."""
import importlib.util
import os
from pathlib import Path
import subprocess
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "observer", Path(__file__).parent / "update-test-observer.py")
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


class VisibleMountTests(unittest.TestCase):
    def test_partition_probe_options_are_accepted_by_real_lsblk(self):
        probe = subprocess.run(["lsblk", "-nbro", "NAME,TYPE,SIZE,PARTUUID,PARTTYPE", "/dev/null"],
                               capture_output=True, text=True, env=dict(os.environ, LC_ALL="C"))
        # The harmless non-block device is refused after successful option parsing.
        self.assertNotEqual(probe.returncode, 0)
        self.assertIn("not a block device", probe.stderr)
        self.assertNotIn("cannot be combined", probe.stderr)

    def test_actual_findmnt_reproduces_ambiguous_stacked_source_output(self):
        # Synthetic kernel table; no mount or host filesystem change occurs.
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "esp"
            target.mkdir()
            table = Path(directory) / "mountinfo"
            table.write_text(
                f"10 1 0:42 / {target} rw - autofs systemd-1 rw\n"
                f"11 10 8:1 / {target} rw - vfat /dev/vda1 rw\n")
            base = ["findmnt", "--tab-file", str(table), "-nr"]
            old = subprocess.check_output(base + ["-o", "SOURCE", str(target)], text=True)
            self.assertEqual(old.split(), ["systemd-1", "/dev/vda1"])

    def test_visible_kernel_device_matches_expected_block_device(self):
        with patch.object(observer.os, "stat", side_effect=[
                SimpleNamespace(st_mode=stat.S_IFDIR, st_dev=2049),
                SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=2049)]) as probe, \
                patch.object(observer.os.path, "ismount", return_value=True), \
                patch.object(observer.os, "listdir", return_value=[]):
            observer.require_visible_mount("/boot", "/dev/vda1")
        self.assertEqual([call.args for call in probe.call_args_list], [("/boot",), ("/dev/vda1",)])

    def test_an_idle_unmounted_automount_is_mounted_before_it_is_compared(self):
        # /boot is a systemd automount with an idle timeout. Once it has
        # expired, a bare stat sees the autofs (st_dev 42); only an access
        # below the mountpoint mounts the ESP again (st_dev 2049).
        state = {"mounted": False}

        def listdir(path):
            self.assertEqual(path, "/boot")
            state["mounted"] = True
            return []

        def fake_stat(path):
            if path == "/boot":
                return SimpleNamespace(st_mode=stat.S_IFDIR, st_dev=2049 if state["mounted"] else 42)
            return SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=2049)

        with patch.object(observer.os, "listdir", side_effect=listdir), \
                patch.object(observer.os, "stat", side_effect=fake_stat), \
                patch.object(observer.os.path, "ismount", return_value=True):
            observer.require_visible_mount("/boot", "/dev/vda1")
        self.assertTrue(state["mounted"])

    def test_foreign_autofs_unmounted_and_nonblock_sources_refused(self):
        for dev, target_mode, source_mode, mounted in (
                (2050, stat.S_IFDIR, stat.S_IFBLK, True),
                (42, stat.S_IFDIR, stat.S_IFBLK, True),
                (2049, stat.S_IFDIR, stat.S_IFBLK, False),
                (2049, stat.S_IFDIR, stat.S_IFREG, True),
                (2049, stat.S_IFREG, stat.S_IFBLK, True)):
            with self.subTest(dev=dev, mounted=mounted), \
                    patch.object(observer.os, "stat", side_effect=[
                        SimpleNamespace(st_mode=target_mode, st_dev=dev),
                        SimpleNamespace(st_mode=source_mode, st_rdev=2049)]), \
                    patch.object(observer.os.path, "ismount", return_value=mounted), \
                    patch.object(observer.os, "listdir", return_value=[]):
                with self.assertRaises(ValueError):
                    observer.require_visible_mount("/boot", "/dev/vda1")


if __name__ == "__main__":
    unittest.main()
