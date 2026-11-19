#!/usr/bin/env python3
"""Fail when the locked nixpkgs is older than the security-update window (STATIC-10).

The image's userspace CVE fixes arrive through the nixpkgs pin, so a pin that
quietly ages is a release that quietly accumulates known vulnerabilities: the
1.0.0 candidate shipped a 24-day-old pin carrying fixed curl, OpenSSH and zlib
CVEs. This is time-dependent by design, so it runs in CI, not inside a Nix
build. It also checks that every locked input is immutable (rev + narHash).

    python3 scripts/check_input_freshness.py [--max-age-days 21] [--now EPOCH]
"""

import argparse
import json
from pathlib import Path
import sys
import time

DEFAULT_MAX_AGE_DAYS = 21
DAY = 86400


def problems(lock, now, max_age_days):
    nodes = lock["nodes"]
    root = nodes[lock["root"]]["inputs"]
    found = []
    for name, node in nodes.items():
        if name == lock["root"]:
            continue
        locked = node.get("locked", {})
        if not locked.get("narHash") or not locked.get("rev"):
            found.append(f"input {name} is not locked to an immutable revision")
    nixpkgs = nodes[root["nixpkgs"]]["locked"]
    age = (now - int(nixpkgs.get("lastModified", 0))) / DAY
    if age > max_age_days:
        found.append(f"nixpkgs {nixpkgs.get('rev', '?')[:12]} is {age:.0f} days old "
                     f"(limit {max_age_days}); run `nix flake update nixpkgs` and requalify")
    return found


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--lock", type=Path, default=Path(__file__).resolve().parents[1] / "flake.lock")
    parser.add_argument("--max-age-days", type=int, default=DEFAULT_MAX_AGE_DAYS)
    parser.add_argument("--now", type=int, default=None, help="epoch seconds (tests)")
    args = parser.parse_args(argv)
    found = problems(json.loads(args.lock.read_text()), args.now or int(time.time()), args.max_age_days)
    for problem in found:
        print(f"input freshness: {problem}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
