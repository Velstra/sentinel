#!/usr/bin/env python3
"""Reject bootable disk artifacts in tracked source; never print their contents."""
import argparse
from pathlib import Path
import subprocess
import sys

IMAGE_SUFFIXES = (".qcow", ".qcow2", ".raw", ".img", ".iso", ".vmdk", ".vdi", ".vhd", ".vhdx", ".efi")


def image_artifact(name: str, header: bytes = b"") -> bool:
    normalized = name.lower()
    for compression in (".zst", ".xz", ".gz"):
        if normalized.endswith(compression):
            normalized = normalized[:-len(compression)]
            break
    return normalized.endswith(IMAGE_SUFFIXES) or header.startswith(b"QFI\xfb")


def check_history(root: Path, reference: str = "HEAD") -> list[str]:
    """Reject historical image paths; this is not a general secret scanner.

    Complete ancestry is mandatory. A shallow checkout can otherwise hide the
    very commit a later deletion tries to remove from the reviewer's view.
    NUL-delimited paths retain spaces and embedded newlines without Git quoting.
    No historical file contents are opened or logged.
    """
    if subprocess.check_output([
        "git", "-C", str(root), "rev-parse", "--is-shallow-repository"
    ], text=True).strip() != "false":
        raise ValueError("historical artifact check requires a complete Git checkout")
    commit = subprocess.check_output([
        "git", "-C", str(root), "rev-parse", "--verify", "--end-of-options",
        reference + "^{commit}",
    ], text=True).strip()
    paths = subprocess.check_output([
        "git", "-C", str(root), "log", "--format=", "--name-only", "-z",
        "--no-renames", commit, "--",
    ])
    names = {raw.lstrip(b"\n").decode("utf-8", errors="surrogateescape")
             for raw in paths.split(b"\0") if raw.lstrip(b"\n")}
    return sorted(name for name in names if image_artifact(name))


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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history", action="store_true", help="also inspect complete HEAD ancestry")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    rejected = check(root)
    if args.history:
        try:
            rejected = sorted(set(rejected) | set(check_history(root)))
        except (ValueError, subprocess.CalledProcessError) as error:
            print(f"Historical artifact check failed: {error}", file=sys.stderr)
            raise SystemExit(1)
    if rejected:
        for name in rejected:
            print(f"Refusing tracked appliance artifact: {name!r}", file=sys.stderr)
        raise SystemExit(1)
    print("No bootable artifact paths found in " +
          ("tracked source or HEAD history" if args.history else "tracked source") +
          " (not a general secret audit).")
