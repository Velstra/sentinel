#!/usr/bin/env python3
"""Check official immutable inputs and the separate historical HA fixture."""

import json
from pathlib import Path
import re
import sys

LEGACY_NAPT = "f72cf32c001293ee1a1d9873f4e145cdc1a7287d"
INPUTS = {"fabric": "fabric", "fabric-legacy-napt": "fabric", "wren": "wren"}


def validate(source: Path) -> dict[str, str]:
    document = json.loads((source / "flake.lock").read_text())
    nodes = document["nodes"]
    root = nodes[document["root"]]["inputs"]
    definition = (source / "flake.nix").read_text()
    revisions = {}
    for name, repository in INPUTS.items():
        node = nodes[root[name]]
        locked, original = node["locked"], node["original"]
        revision = locked.get("rev", "")
        expected = {"owner": "Velstra", "repo": repository, "type": "github", "rev": revision}
        if (node.get("flake") is not False or not re.fullmatch(r"[a-f0-9]{40}", revision)
                or not locked.get("narHash") or original != expected
                or any(locked.get(key) != value for key, value in expected.items())):
            raise ValueError(f"{name} must pin one immutable official GitHub revision")
        declarations = re.findall(
            r"^\s*" + re.escape(name) + r'\s*=\s*\{\s*url\s*=\s*"([^"]+)";',
            definition, re.MULTILINE,
        )
        if declarations != [f"github:Velstra/{repository}/{revision}"]:
            raise ValueError(f"{name} URL does not match its locked source")
        revisions[name] = revision
    if revisions["fabric-legacy-napt"] != LEGACY_NAPT:
        raise ValueError("the deployed mixed-version NAPT fixture must not advance")
    if revisions["fabric"] == revisions["fabric-legacy-napt"]:
        raise ValueError("mixed-version HA must not test the current dataplane twice")
    return revisions


if __name__ == "__main__":
    print(json.dumps(validate(Path(sys.argv[1])), sort_keys=True))
