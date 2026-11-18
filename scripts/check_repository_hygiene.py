#!/usr/bin/env python3
"""Reject bootable disk artifacts in tracked source; never print their contents."""
from pathlib import Path
import subprocess
import sys

IMAGE_SUFFIXES = (".qcow2", ".raw", ".img", ".iso", ".vmdk", ".vhd", ".vhdx",
                  ".raw.zst", ".qcow2.zst", ".efi")


def image_artifact(name: str, header: bytes = b"") -> bool:
    return name.lower().endswith(IMAGE_SUFFIXES) or header.startswith(b"QFI\xfb")


def check(root: Path) -> list[str]:
    tracked = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"])
    rejected = []
    for raw in tracked.split(b"\0"):
        if not raw:
            continue
        name = raw.decode("utf-8", errors="surrogateescape")
        path = root / name
        header = b""
        if path.is_file() and not path.is_symlink():
            with path.open("rb") as stream:
                header = stream.read(4)
        if image_artifact(name, header):
            rejected.append(name)
    return rejected


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    rejected = check(root)
    if rejected:
        for name in rejected:
            print(f"Refusing tracked appliance artifact: {name!r}", file=sys.stderr)
        raise SystemExit(1)
    print("Tracked source contains no bootable disk artifacts (not a historical secret audit).")
