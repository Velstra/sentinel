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
from urllib.parse import unquote

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
                identity = purl.split("?", 1)[0].split("#", 1)[0].removeprefix(f"pkg:{ecosystem}/")
                name, separator, version = identity.rpartition("@")
                if (not separator or not name or not version
                        or re.search(r"%(?![0-9a-fA-F]{2})", identity)
                        or unquote(name) != component["name"]
                        or unquote(version) != component.get("version")):
                    raise ValueError("component package URL does not match its name/version")
                counts[ecosystem] += 1
    if not all(counts.values()):
        raise ValueError("both Cargo and npm dependency catalogs are required")
    return counts


def validate_lock_coverage(bom: dict, inputs: dict[str, bytes]) -> dict[str, int]:
    """A nonempty ecosystem catalog is not evidence of a complete lock scan."""
    validate_bom(bom)
    cargo = tomllib.loads(inputs["Cargo.lock"].decode()).get("package")
    npm = json.loads(inputs["ui/package-lock.json"])
    packages = npm.get("packages")
    if not isinstance(cargo, list) or not cargo:
        raise ValueError("nonempty Cargo package lock required")
    if npm.get("lockfileVersion") not in (2, 3) or not isinstance(packages, dict) or not packages:
        raise ValueError("npm v2/v3 package lock required")
    expected = {"cargo": set(), "npm": set()}
    local_cargo = set()
    for package in cargo:
        if not isinstance(package, dict):
            raise ValueError("invalid Cargo lock package")
        expected["cargo"].add((package.get("name"), package.get("version")))
        if not package.get("source"):
            local_cargo.add((package.get("name"), package.get("version")))
    for location, package in packages.items():
        if not isinstance(package, dict) or package.get("link"):
            raise ValueError("invalid or externally linked npm lock package")
        # The private top-level application can legitimately omit its version.
        if not location and not package.get("version"):
            continue
        name = package.get("name") or location.rsplit("node_modules/", 1)[-1]
        expected["npm"].add((name, package.get("version")))
    for ecosystem, identities in expected.items():
        if not identities or any(not all(isinstance(v, str) and v for v in pair) for pair in identities):
            raise ValueError(f"invalid {ecosystem} lock package identity")
        actual = {(c.get("name"), c.get("version")) for c in bom["components"]
                  if c.get("purl", "").startswith(f"pkg:{ecosystem}/")}
        if ecosystem == "cargo":
            # Syft deliberately omits a registry PURL for local/workspace
            # packages. Require its exact Cargo.lock catalog attribution;
            # an unrelated npm component with the same name cannot cover it.
            for component in bom["components"]:
                identity = (component.get("name"), component.get("version"))
                properties = component.get("properties", [])
                if (identity in local_cargo
                        and {"name": "syft:package:foundBy", "value": "rust-cargo-lock-cataloger"} in properties
                        and {"name": "syft:location:0:path", "value": "/Cargo.lock"} in properties):
                    actual.add(identity)
        missing = identities - actual
        if missing:
            raise ValueError(f"incomplete {ecosystem} lock coverage: " +
                             ", ".join(name + "@" + version for name, version in sorted(missing)[:20]))
    return {ecosystem: len(identities) for ecosystem, identities in expected.items()}


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
        lock_counts = validate_lock_coverage(bom, before)
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
            "lock_package_identities": lock_counts,
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
