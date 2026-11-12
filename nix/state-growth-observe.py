"""Read-only witnesses around the REAL growth unit in the disposable image test.

No target argument is accepted. The test observes the active factory disk;
it never mounts, resizes, repairs, blesses or changes the selected boot entry.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

spec = importlib.util.spec_from_file_location("grow", sys.argv[1])
grow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(grow)
stage, sfdisk = sys.argv[2:]
assert stage in ("before", "after") and os.geteuid() == 0
disk, size, _ = grow.boot_disk()
table = json.loads(subprocess.check_output([sfdisk, "--json", disk], text=True))["partitiontable"]
layout = grow.validate_table(table, disk, size)
assert not grow.mounted_device(grow.partition_path(disk, 6))
directory = Path("/run/state-growth-proof")
directory.mkdir(mode=0o700, exist_ok=True)
before = json.loads((directory/"before.json").read_text()) if stage == "after" else None
regions = before["layout"]["parts"] if before else layout["parts"]
hashes = []
for index, part in enumerate(regions, 1):
    digest = hashlib.sha256()
    remaining = part["size"] * 512
    with open(grow.partition_path(disk, index), "rb", buffering=0) as source:
        while remaining:
            block = source.read(min(remaining, 8 * 1024**2))
            assert block, "unexpected partition EOF"
            digest.update(block)
            remaining -= len(block)
    hashes.append(digest.hexdigest())
report = {"layout": layout, "original_region_sha256": hashes,
          "state_not_mounted": True, "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}
if before:
    assert hashes == before["original_region_sha256"], "growth changed existing partition payload"
    expected = before["layout"]
    grow.validate_after(expected, table, layout["parts"][5]["size"]*512)
    report["all_six_original_regions_unchanged"] = True
(directory/(stage+".json")).write_text(json.dumps(report, indent=2))
