#!/usr/bin/env python3
"""Download one same-run immutable artifact; digest mismatch is fatal."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
import zipfile


def unpack(archive, output, budget):
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        seen = set()
        total = 0
        for entry in entries:
            path = PurePosixPath(entry.filename)
            mode = entry.external_attr >> 16
            if (path.is_absolute() or ".." in path.parts or "\\" in entry.filename
                    or entry.filename in seen or not path.parts or stat.S_ISLNK(mode)
                    or stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)
                    or path.as_posix() != entry.filename.rstrip("/") or entry.flag_bits & 1):
                raise ValueError("unsafe artifact archive entry")
            seen.add(entry.filename)
            total += entry.file_size
        if not 0 < total <= budget:
            raise ValueError("artifact expanded size exceeds approved byte budget")
        output.mkdir(parents=True, exist_ok=False)
        bundle.extractall(output)


def download(identifier, expected, output):
    if not re.fullmatch(r"[1-9][0-9]*", identifier) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("immutable artifact ID and exact SHA256 required")
    root = f"repos/{os.environ['GITHUB_REPOSITORY']}/actions/artifacts/{identifier}"
    info = json.loads(subprocess.check_output(["gh", "api", root], text=True, timeout=30))
    workflow = info.get("workflow_run", {})
    budget = int(os.environ.get("RELEASE_ARTIFACT_BYTE_BUDGET", "0"))
    if (info.get("expired") is not False or workflow.get("id") != int(os.environ["GITHUB_RUN_ID"])
            or workflow.get("head_sha") != os.environ["GITHUB_SHA"]
            or info.get("digest") != f"sha256:{expected}"
            or not 0 < info.get("size_in_bytes", 0) <= budget):
        raise ValueError("artifact is expired, oversized or belongs to another run/source/digest")
    with tempfile.TemporaryDirectory(prefix="sentinel-transfer-") as temp:
        archive = Path(temp) / "artifact.zip"
        with archive.open("wb") as stream:
            subprocess.run(["gh", "api", root + "/zip"], stdout=stream, check=True, timeout=1800)
        with archive.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != expected:
                raise ValueError("artifact download digest mismatch")
        unpack(archive, output, budget)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--id", required=True)
    parser.add_argument("--digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    download(args.id, args.digest, args.output)
