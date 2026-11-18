#!/usr/bin/env python3
"""Enforce a named build/package-manager tool policy on the image closure.

This is not proof that arbitrary renamed programs cannot compile code.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat


FORBIDDEN = frozenset({
    "nix", "nix-env", "nix-store", "nix-daemon", "nix-build", "nix-shell",
    "nixos-rebuild", "strace", "rustc", "cargo", "gcc", "g++", "clang",
    "clang++", "cc", "c++", "apt", "apt-get", "dpkg", "mkosi", "make",
})
TOOL_FAMILIES = re.compile(
    r"^(?:nix(?:-[a-z][a-z0-9-]*)?|cargo(?:-[a-z][a-z0-9-]*)?|rustc|rustup|"
    r"(?:[a-z0-9_]+-)*(?:gcc|g\+\+|clang|clang\+\+|cc|c\+\+)"
    r"(?:-(?:\d+(?:\.\d+)*|ar|nm|ranlib))?)$"
)
STORE_OUTPUT_NAME = re.compile(r"^[0123456789abcdfghijklmnpqrsvwxyz]{32}-(.+)$")


def forbidden_name(name: str) -> bool:
    return name in FORBIDDEN or TOOL_FAMILIES.fullmatch(name) is not None


def gcc_completion_data_link(candidate: Path, package: Path) -> bool:
    """Recognize GCC's non-executable Bash completion aliases, not tools.

    No directory is exempted from inspection. Only direct links to the same
    completion directory's bounded, regular, non-executable GCC completion
    text qualify. Executable, dangling, escaping and binary targets fail closed.
    """
    completion = package / "share/bash-completion/completions"
    if candidate.parent != completion or not candidate.is_symlink():
        return False
    try:
        target = candidate.resolve(strict=True)
        if target.parent != completion.resolve(strict=True) or target.name != "gcc":
            return False
        attributes = target.stat()
        if (not stat.S_ISREG(attributes.st_mode) or attributes.st_mode & 0o111
                or not 0 < attributes.st_size <= 65536):
            return False
        with target.open("rb") as stream:
            data = stream.read(65537)
        if len(data) > 65536 or b"\x00" in data:
            return False
        text = data.decode("utf-8", errors="strict")
        return (text.startswith("# gcc(1) completion")
                and "\n_comp_cmd_gcc()\n" in text
                and "complete -F _comp_cmd_gcc " in text)
    except (OSError, RuntimeError, UnicodeError):
        return False


def inspect(paths: list[Path]) -> list[str]:
    if not paths:
        raise ValueError("empty image closure is not evidence")
    failures = set()

    def fail_walk(error: OSError) -> None:
        raise error

    for path in paths:
        try:
            info = path.lstat()
        except FileNotFoundError:
            raise ValueError(f"missing closure path: {path}")
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
                or stat.S_ISLNK(info.st_mode)):
            raise ValueError(f"unsupported closure output type: {path}")
        if not stat.S_ISDIR(info.st_mode):
            match = STORE_OUTPUT_NAME.fullmatch(path.name)
            name = match.group(1) if match else path.name
            if forbidden_name(name) and (stat.S_ISLNK(info.st_mode) or info.st_mode & 0o111):
                failures.add(str(path))
            # Store aliases are not traversal roots. Their real targets must
            # be included in the supplied Nix closure and visited independently.
            continue
        # Do not follow directory links: their real targets are themselves
        # included in the closure. Inspect libexec and nested toolchain trees,
        # not just the system profile or top-level bin directory.
        for directory, subdirectories, files in os.walk(
                path, followlinks=False, onerror=fail_walk):
            for name in subdirectories + files:
                candidate = Path(directory) / name
                attributes = candidate.lstat()
                if stat.S_ISDIR(attributes.st_mode):
                    continue
                if forbidden_name(name) and not gcc_completion_data_link(candidate, path) and (
                    attributes.st_mode & 0o111
                    or stat.S_ISLNK(attributes.st_mode)
                    or any(part in {"bin", "sbin", "libexec"} for part in candidate.relative_to(path).parts[:-1])
                ):
                    failures.add(str(candidate))
    return sorted(failures)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store-paths", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    paths = [Path(line) for line in args.store_paths.read_text().splitlines() if line]
    failures = inspect(paths)
    receipt = {"schema": "sentinel-image-runtime/v1", "paths": sorted(map(str, paths)),
               "forbidden_names": sorted(FORBIDDEN), "forbidden_families": TOOL_FAMILIES.pattern,
               "violations": failures}
    args.receipt.write_text(json.dumps(receipt, indent=2) + "\n")
    if failures:
        raise SystemExit("Forbidden image runtime tools:\n" + "\n".join(failures))


if __name__ == "__main__":
    main()
