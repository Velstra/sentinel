#!/usr/bin/env python3
"""Prove that the shipped closure carries the security fixes it claims to.

A backport in `nix/security-backports.nix` or a version bump in `flake.nix`
is only a fix if the image that ships contains the fixed build. This check
reads the store paths of the image's system closure and fails when

* a package named in the floor manifest (`security-floor.json`) is present
  below its minimum version, or is absent altogether (a floor that matches
  nothing proves nothing and must be removed, not silently kept);
* a replacement made by `system.replaceDependencies` did not take: a
  replaced store path still ships, or no output of the backported package
  does (an inert backport);
* a `--forbid-program` executable is in some path's bin/ or sbin/.

Exit 0 when every floor and replacement holds, 1 when one does not, 2 when
the input is unusable. Stdlib only.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_image_closure import parse_store_name, read_paths  # noqa: E402

SCHEMA = "velstra-security-floor/1"
NUMBER = re.compile(r"\d+")


def version_key(version):
    """Numeric components only: 6.12.118, 2.42-103 and 1.9.17p2 all compare."""
    numbers = [int(n) for n in NUMBER.findall(version)]
    if not numbers:
        raise ValueError(f"no numeric version in {version!r}")
    return tuple(numbers)


def load_floors(document):
    if document.get("schema") != SCHEMA:
        raise ValueError(f"floor manifest schema is not {SCHEMA}")
    floors = document.get("floors")
    if not isinstance(floors, list) or not floors:
        raise ValueError("floor manifest needs a non-empty floors list")
    seen = set()
    for floor in floors:
        if not isinstance(floor, dict):
            raise ValueError("every floor must be an object")
        for key in ("package", "minimum", "fixes"):
            if not floor.get(key):
                raise ValueError(f"floor {floor!r} lacks {key}")
        if floor["package"] in seen:
            raise ValueError(f"duplicate floor for {floor['package']!r}")
        seen.add(floor["package"])
        version_key(floor["minimum"])
    return floors


def floor_failures(paths, floors):
    """Every floor that the closure violates, with the offending path."""
    by_name = {}
    for path in paths:
        pname, version, _output = parse_store_name(path)
        by_name.setdefault(pname, []).append((path, version))
    failures = []
    for floor in floors:
        found = by_name.get(floor["package"], [])
        if not found:
            failures.append(f"floor {floor['package']} >= {floor['minimum']}: package not in the closure")
            continue
        minimum = version_key(floor["minimum"])
        for path, version in found:
            if not version or version_key(version) < minimum:
                failures.append(f"floor {floor['package']} >= {floor['minimum']} ({floor['fixes']}): ships {path}")
    return failures


def store_name(path):
    """The part of a store path after the hash: what a rewrite preserves."""
    return path.rsplit("/", 1)[-1].split("-", 1)[1]


def replacement_failures(paths, replacements):
    """A replacement took if no replaced path ships and, per package, at
    least one output by the replacement's name does.

    `system.replaceDependencies` also rewrites a replacement that itself
    refers to another replaced path (a backported suricata linking the
    replaced libcap), so what ships may be a rewritten copy: same store name,
    other hash. The replaced path itself must be gone in every case. Outputs
    the closure never used, such as a man page, may be absent on both sides.
    """
    present = set(paths)
    replaced = {entry.get("old") for entry in replacements}
    names = {store_name(path) for path in paths if path not in replaced}
    failures, shipped = [], {}
    for entry in replacements:
        old, new = entry.get("old"), entry.get("new")
        if not old or not new:
            raise ValueError(f"replacement {entry!r} needs old and new")
        pname = parse_store_name(new)[0]
        shipped[pname] = shipped.get(pname, False) or new in present or store_name(new) in names
        if old in present:
            failures.append(f"replacement did not take: {old} still ships")
    for pname, found in sorted(shipped.items()):
        if not found:
            failures.append(f"replacement inert: no output of the backported {pname} is in the closure")
    return failures


def program_failures(paths, programs, exists=os.path.lexists):
    """Executables that must not ship: their CVEs live in the program, not in
    the library the image does need (the sqlite3 shell, libressl ocspcheck)."""
    failures = []
    for path in paths:
        for directory in ("bin", "sbin"):
            for program in programs:
                candidate = f"{path}/{directory}/{program}"
                if exists(candidate):
                    failures.append(f"program must not ship: {candidate}")
    return failures


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("closure", help="file with one store path per line")
    parser.add_argument("--floors", required=True, help="security-floor.json")
    parser.add_argument("--replacements", help="JSON list of {old, new} store paths")
    parser.add_argument("--forbid-program", action="append", default=[], metavar="NAME",
                        help="an executable no closure path may carry in bin/ or sbin/")
    args = parser.parse_args(argv)
    try:
        with open(args.closure, encoding="utf-8") as stream:
            paths = read_paths(stream)
        floors = load_floors(json.loads(Path(args.floors).read_text()))
        replacements = []
        if args.replacements:
            replacements = json.loads(Path(args.replacements).read_text())
            if not isinstance(replacements, list) or not replacements:
                raise ValueError("replacements must be a non-empty list")
        failures = (floor_failures(paths, floors) + replacement_failures(paths, replacements)
                    + program_failures(paths, args.forbid_program))
    except (OSError, ValueError) as error:
        print(f"security floor check refused its input: {error}", file=sys.stderr)
        return 2
    for failure in failures:
        print(f"FAIL {failure}")
    if failures:
        print(f"{len(failures)} security floor violations in {len(paths)} store paths")
        return 1
    print(f"security floor holds: {len(floors)} floors, {len(replacements)} replacements, "
          f"{len(paths)} store paths")
    return 0


if __name__ == "__main__":
    sys.exit(main())
