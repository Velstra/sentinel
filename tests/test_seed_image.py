"""Seeding tool contracts (PROV-01). The end-to-end case runs real e2fsprogs.

Set SEED_E2E=1 (the Nix check does) to require the end-to-end case: it builds a
six-partition GPT image whose data partition is an ext4 made like the image
build's, seeds it with the real tool and reads the result back. Without the
variable it is reported as skipped, never as passed.
"""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("seed_image", ROOT / "scripts" / "seed-image.py")
seed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seed)

REACHABLE = """
[system]
hostname = "seeded"
[[system.group]]
name = "admins"
permission = "read-write"
[[system.login]]
username = "admin"
group = "admins"
ssh-key = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExam test"]
[[interface]]
name = "enp3s0"
zone = "mgmt"
address = "dhcp"
[services.ssh]
enable = true
"""


def table(names, sector=512):
    parts, start = [], 2048
    for name in names:
        parts.append({"node": f"x{len(parts)+1}", "start": start, "size": 1024, "name": name})
        start += 1024
    return {"label": "gpt", "sectorsize": sector, "partitions": parts}


class Partition(unittest.TestCase):
    def test_finds_the_last_partition_named_data(self):
        t = table(["esp", "store-verity", "store", "store-verity-b", "store-b", "data"])
        self.assertEqual(seed.data_partition(t), (7168 * 512, 1024 * 512))

    def test_refuses_foreign_layouts(self):
        for bad in (table(["esp", "data", "store"]), table(["esp", "store"]),
                    table(["data", "data"]), table(["esp", "data"], sector=4096),
                    {"label": "dos", "sectorsize": 512, "partitions": []}):
            with self.subTest(bad=bad), self.assertRaises(seed.SeedError):
                seed.data_partition(bad)


class Reachability(unittest.TestCase):
    def load(self, text):
        return seed.tomllib.loads(text)

    def test_a_key_login_in_a_read_write_group_with_ssh_is_reachable(self):
        problems, bare = seed.reachability_problems(self.load(REACHABLE))
        self.assertEqual(problems, [])
        self.assertEqual(bare, ["enp3s0"])

    def test_each_missing_way_in_is_named(self):
        cases = {
            "read-only group": REACHABLE.replace('"read-write"', '"read-only"'),
            "no ssh service": REACHABLE.replace("enable = true", "enable = false"),
            "no interface": REACHABLE.split("[[interface]]")[0] + "[services.ssh]\nenable = true\n",
            "no credential": REACHABLE.replace('ssh-key = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExam test"]', ""),
        }
        for label, text in cases.items():
            with self.subTest(label):
                problems, _ = seed.reachability_problems(self.load(text))
                self.assertEqual(len(problems), 1, problems)

    def test_hw_id_bound_interface_is_not_reported_as_bare(self):
        text = REACHABLE.replace('name = "enp3s0"', 'name = "enp3s0"\nhw-id = "52:54:00:00:00:01"')
        self.assertEqual(seed.reachability_problems(self.load(text))[1], [])


class Script(unittest.TestCase):
    def test_writes_root_owned_files_with_private_modes(self):
        text = seed.debugfs_script(Path("/tmp/stage"), True)
        self.assertIn("mkdir ssh", text)
        self.assertIn("write /tmp/stage/appliance.toml appliance.toml", text)
        for name, mode in (("appliance.toml", "0100600"), ("ssh/ssh_host_ed25519_key", "0100600"),
                           ("ssh", "040700"), ("ssh/ssh_host_ed25519_key.pub", "0100644")):
            self.assertIn(f"set_inode_field {name} mode {mode}", text)
            self.assertIn(f"set_inode_field {name} uid 0", text)
            self.assertIn(f"set_inode_field {name} gid 0", text)

    def test_existing_ssh_directory_is_not_recreated(self):
        self.assertNotIn("mkdir", seed.debugfs_script(Path("/tmp/stage"), False))

    def test_unquotable_staging_path_refused(self):
        with self.assertRaises(seed.SeedError):
            seed.debugfs_script(Path("/tmp/a stage"), True)

    def test_stat_parsing(self):
        sample = ("Inode: 12   Type: regular    Mode:  0600   Flags: 0x80000\n"
                  "Generation: 0    Version: 0x00000000\nUser:     0   Group:     0   Size: 10\n")
        self.assertEqual(seed.parse_stat(sample), ("regular", 0o600, 0, 0))
        with self.assertRaises(seed.SeedError):
            seed.parse_stat("stat: File not found by ext2_lookup")


class Copy(unittest.TestCase):
    def test_writing_over_existing_data_never_keeps_old_bytes(self):
        with tempfile.TemporaryDirectory() as scratch:
            new, old = Path(scratch) / "new", Path(scratch) / "old"
            new.write_bytes(b"\0" * seed.CHUNK + b"N" * 16)
            old.write_bytes(b"O" * (seed.CHUNK + 16))
            seed.copy_range(new, old, 0, seed.CHUNK + 16)
            self.assertEqual(old.read_bytes(), new.read_bytes())


class Refusals(unittest.TestCase):
    def test_unreachable_config_refused_before_touching_the_image(self):
        with tempfile.TemporaryDirectory() as scratch:
            config = Path(scratch) / "appliance.toml"
            config.write_text(REACHABLE.replace("enable = true", "enable = false"))
            with mock.patch.object(seed, "run") as run:
                code = seed.main(["--image", str(config), "--config", str(config),
                                  "--output", str(Path(scratch) / "out.raw")])
            self.assertEqual(code, 1)
            run.assert_not_called()
            self.assertFalse((Path(scratch) / "out.raw").exists())

    def test_existing_output_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as scratch:
            out = Path(scratch) / "out.raw"
            out.write_text("keep")
            code = seed.main(["--image", str(Path(scratch) / "in.raw"), "--config", str(out),
                              "--output", str(out)])
            self.assertEqual(code, 1)
            self.assertEqual(out.read_text(), "keep")


TOOLS = ("SFDISK", "DEBUGFS", "E2FSCK", "SSH_KEYGEN", "MKFS_EXT4")


@unittest.skipUnless(os.environ.get("SEED_E2E") == "1", "set SEED_E2E=1 to run against real e2fsprogs")
class EndToEnd(unittest.TestCase):
    def setUp(self):
        missing = [name for name in TOOLS if not os.environ.get("SEED_" + name)]
        self.assertEqual(missing, [], "SEED_E2E=1 needs every SEED_<TOOL> path")
        self.scratch = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.scratch)
        image = self.scratch / "factory.raw"
        sector_data = 8 * 2048
        with open(image, "wb") as handle:
            handle.truncate((2048 + 5 * 2048 + sector_data + 2048) * 512)
        layout = "label: gpt\n" + "".join(
            f"start={2048 + i * 2048}, size=2048, name={name}\n"
            for i, name in enumerate(["esp", "store-verity", "store", "store-verity-b", "store-b"])
        ) + f"start={2048 + 5 * 2048}, size={sector_data}, name=data\n"
        subprocess.run([os.environ["SEED_SFDISK"], "--quiet", str(image)], input=layout,
                       text=True, check=True)
        fs = self.scratch / "data.ext4"
        # As the image build does it: an empty, labelled ext4 of the partition size.
        subprocess.run([os.environ["SEED_MKFS_EXT4"], "-q", "-L", "data", "-T", "default",
                        str(fs), f"{sector_data // 2}k"], check=True)
        seed.copy_range(fs, image, 0, fs.stat().st_size, target_offset=(2048 + 5 * 2048) * 512)
        self.image = image
        self.config = self.scratch / "appliance.toml"
        self.config.write_text(REACHABLE)
        os.environ["SEED_SENTINEL"] = os.environ.get("SEED_SENTINEL") or "true"

    def test_seeded_image_has_the_files_owned_and_moded_as_the_boot_reads_them(self):
        out = self.scratch / "seeded.raw"
        before = self.image.read_bytes()
        self.assertEqual(seed.main(["--image", str(self.image), "--config", str(self.config),
                                    "--output", str(out)]), 0)
        self.assertEqual(self.image.read_bytes(), before, "the input image was modified")
        offset, length = seed.data_partition(json.loads(subprocess.run(
            [os.environ["SEED_SFDISK"], "--json", str(out)], capture_output=True, text=True,
            check=True).stdout)["partitiontable"])
        fs = self.scratch / "check.ext4"
        with open(fs, "wb") as handle:
            handle.truncate(length)
        seed.copy_range(out, fs, offset, length)
        subprocess.run([os.environ["SEED_E2FSCK"], "-fn", str(fs)], check=True, capture_output=True)
        dumped = self.scratch / "dumped.toml"
        subprocess.run([os.environ["SEED_DEBUGFS"], "-R", f"dump /appliance.toml {dumped}", str(fs)],
                       check=True, capture_output=True)
        self.assertEqual(dumped.read_text(), REACHABLE)
        stat = subprocess.run([os.environ["SEED_DEBUGFS"], "-R", "stat /ssh/ssh_host_ed25519_key",
                               str(fs)], check=True, capture_output=True, text=True).stdout
        self.assertEqual(seed.parse_stat(stat), ("regular", 0o600, 0, 0))
        # Everything outside the data partition is byte-identical.
        seeded = out.read_bytes()
        self.assertEqual(seeded[:offset], before[:offset])
        self.assertEqual(seeded[offset + length:], before[offset + length:])

    def test_an_already_seeded_image_is_refused(self):
        first, second = self.scratch / "one.raw", self.scratch / "two.raw"
        self.assertEqual(seed.main(["--image", str(self.image), "--config", str(self.config),
                                    "--output", str(first)]), 0)
        self.assertEqual(seed.main(["--image", str(first), "--config", str(self.config),
                                    "--output", str(second)]), 1)
        self.assertFalse(second.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
