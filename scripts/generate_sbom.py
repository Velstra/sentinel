#!/usr/bin/env python3
"""Generate a source-lockfile CycloneDX SBOM, never an OS/image certificate."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib

INPUTS = ("Cargo.toml", "Cargo.lock", "ui/package.json", "ui/package-lock.json")
SCOPE = "source-lockfiles"
SYFT_CONFIG = "javascript:\n  include-dev-dependencies: true\n"


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def snapshot(source: Path) -> dict[str, bytes]:
    source = source.resolve(strict=True)
    result = {}
    for name in INPUTS:
        path = source / name
        if path.resolve(strict=True) != path or not path.is_file():
            raise ValueError(f"SBOM input must be a regular, non-symlink source file: {name}")
        if path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError(f"SBOM input exceeds 8 MiB: {name}")
        result[name] = path.read_bytes()
    return result


def revision(source: Path) -> str:
    value = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True, timeout=30
    ).strip()
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value):
        raise ValueError("a full source commit is required")
    # A developer may add this script without committing it yet, but the four
    # declared source inputs must belong to HEAD. Do not label dirty locks with
    # the clean commit's identity.
    for name in INPUTS:
        if subprocess.check_output(
            ["git", "-C", str(source), "show", f"{value}:{name}"], timeout=30
        ) != (source / name).read_bytes():
            raise ValueError(f"SBOM input differs from source commit: {name}")
    return value


def validate_bom(bom: dict) -> dict[str, int]:
    if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.6":
        raise ValueError("Syft must produce supported CycloneDX JSON")
    components = bom.get("components")
    if not isinstance(components, list) or not components:
        raise ValueError("empty or malformed SBOM package catalog")
    counts = {"cargo": 0, "npm": 0}
    for component in components:
        if (not isinstance(component, dict) or not isinstance(component.get("name"), str)
                or not component["name"] or component.get("type") not in {
                    "application", "framework", "library", "container", "platform",
                    "operating-system", "device", "device-driver", "firmware", "file",
                    "machine-learning-model", "data", "cryptographic-asset"}):
            raise ValueError("malformed CycloneDX component")
        # PURLs are optional in CycloneDX. For example a private, unversioned
        # npm project is valid without one; retain it without counting it as
        # proof that versioned ecosystem dependencies were inventoried.
        purl = component.get("purl", "")
        if not isinstance(purl, str):
            raise ValueError("invalid component package URL")
        for ecosystem in counts:
            if purl.startswith(f"pkg:{ecosystem}/"):
                counts[ecosystem] += 1
    if not all(counts.values()):
        raise ValueError("both Cargo and npm dependency catalogs are required")
    return counts


def generate(source: Path, output: Path, syft: str) -> dict:
    source = source.resolve(strict=True)
    before = snapshot(source)
    commit = revision(source)
    version = tomllib.loads(before["Cargo.toml"].decode())["package"]["version"]
    if not isinstance(version, str) or not version:
        raise ValueError("Cargo package version is required")
    # An exclusive directory prevents accidental replacement of older evidence.
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="sentinel-sbom-") as temporary:
        scratch = Path(temporary)
        catalog = scratch / "catalog"
        catalog.mkdir()
        for name, contents in before.items():
            destination = catalog / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(contents)
        # Never scan the checkout: target/, node_modules/, work/, private keys
        # and arbitrary untracked files are not SBOM inputs. An explicit config
        # and sanitized Syft environment prevent ambient catalog exclusions.
        config = scratch / "syft.yaml"
        config.write_text(SYFT_CONFIG)
        env = {key: value for key, value in os.environ.items() if not key.startswith("SYFT_")}
        env["SYFT_CHECK_FOR_APP_UPDATE"] = "false"
        raw = scratch / "sbom.cdx.json"
        subprocess.run(
            [syft, f"dir:{catalog}", "--config", str(config), "--source-name", "velstra-sentinel",
             "--source-version", version, "-o", f"cyclonedx-json@1.6={raw}"],
            cwd=scratch, env=env, check=True, timeout=180,
        )
        if raw.stat().st_size > 32 * 1024 * 1024:
            raise ValueError("SBOM exceeds 32 MiB")
        bom = json.loads(raw.read_bytes())
        counts = validate_bom(bom)
        if snapshot(source) != before or revision(source) != commit:
            raise ValueError("source inputs changed during SBOM generation")
        properties = bom.setdefault("metadata", {}).setdefault("properties", [])
        properties.extend([
            {"name": "velstra:scope", "value": SCOPE},
            {"name": "velstra:source:commit", "value": commit},
            {"name": "velstra:coverage", "value": "Cargo and npm declared dependencies, including development dependencies; excludes the NixOS runtime image"},
        ])
        body = (json.dumps(bom, sort_keys=True, indent=2) + "\n").encode()
        provenance = {
            "schema": 1, "scope": SCOPE, "source_commit": commit, "version": version,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "inputs_sha256": {name: digest(contents) for name, contents in before.items()},
            "component_count": len(bom["components"]), "ecosystems": counts,
            "sbom_sha256": digest(body), "image_certification": False,
        }
        (output / "sbom.cdx.json").write_bytes(body)
        evidence = (json.dumps(provenance, sort_keys=True, indent=2) + "\n").encode()
        (output / "sbom.provenance.json").write_bytes(evidence)
        (output / "SHA256SUMS").write_text(
            f"{digest(body)}  sbom.cdx.json\n{digest(evidence)}  sbom.provenance.json\n"
        )
    return provenance


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--syft", default="syft")
    args = parser.parse_args()
    print(json.dumps(generate(args.source, args.output_dir.resolve(), args.syft), sort_keys=True))


if __name__ == "__main__":
    main()
