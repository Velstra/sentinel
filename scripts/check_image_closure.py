#!/usr/bin/env python3
"""Refuse a shipped closure that carries a build toolchain (audit IMG-06).

Input: a file of store paths, one per line (`nix path-info -r <toplevel>`), or
`-` for stdin. Exit 0 when clean, 1 when forbidden outputs are present, 2 when
the input itself is unusable (empty, or a line that is not a store path): an
empty list proves nothing about the image and must never read as clean.

The 1.0.0 image shipped gcc, binutils, glibc-dev and linux-headers because
rsyslog's MongoDB output pulled mongoc → gcc-wrapper. Runtime libraries of the
compiler (`gcc-*-lib`, `-libgcc`) and LLVM's shared library output stay
allowed: dynamically linked programs need them.
"""
import argparse
import re
import sys

STORE_PATH = re.compile(r"^/nix/store/[0-9a-df-np-sv-z]{32}-(?P<name>[^/\s]+)$")
# Outputs a Nix package can be split into. Only these are peeled off the end
# of a store name; anything else stays part of the version.
OUTPUTS = {
    "bin", "dev", "lib", "libgcc", "out", "man", "doc", "devdoc", "info", "static", "debug",
    "headers", "modules", "getent", "man1", "py", "python", "scripts", "terminfo", "udev",
    "dist", "data", "lib32", "devman", "sbin",
}
VERSION_START = re.compile(r"^[0-9]")
COMPILERS = {"gcc", "gcc-wrapper", "xgcc", "gcc-unwrapped", "clang", "clang-wrapper",
             "clang-unwrapped", "llvm", "binutils", "binutils-wrapper", "binutils-unwrapped"}
RUNTIME_OUTPUTS = {"lib", "libgcc"}
HEADERS = {"linux-headers", "linux-headers-static", "glibc-headers"}


def parse_store_name(path):
    """Return (pname, version, output) for a store path."""
    match = STORE_PATH.match(path.strip())
    if match is None:
        raise ValueError(f"not a store path: {path!r}")
    tokens = match.group("name").split("-")
    for index, token in enumerate(tokens[1:], 1):
        if VERSION_START.match(token):
            pname, rest = "-".join(tokens[:index]), tokens[index:]
            break
    else:
        return match.group("name"), "", "out"
    output = "out"
    if len(rest) > 1 and rest[-1] in OUTPUTS:
        output = rest.pop()
    return pname, "-".join(rest), output


def classify(path):
    """Return the reason a store path must not ship, or None."""
    pname, _version, output = parse_store_name(path)
    if output == "dev":
        return "development output"
    if pname in HEADERS:
        return "kernel/libc headers"
    if pname in COMPILERS and output not in RUNTIME_OUTPUTS:
        return "compiler toolchain"
    return None


def forbidden(paths):
    """Pure check: the offending entries, each with its path and reason."""
    result = []
    for path in paths:
        reason = classify(path)
        if reason is not None:
            result.append({"path": path, "reason": reason})
    return result


def read_paths(stream):
    paths = [line.strip() for line in stream if line.strip()]
    if not paths:
        raise ValueError("empty closure listing")
    for path in paths:
        parse_store_name(path)
    return paths


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("closure", help="file with one store path per line, or - for stdin")
    args = parser.parse_args(argv)
    try:
        if args.closure == "-":
            paths = read_paths(sys.stdin)
        else:
            with open(args.closure, encoding="utf-8") as stream:
                paths = read_paths(stream)
    except (OSError, ValueError) as error:
        print(f"closure check refused its input: {error}", file=sys.stderr)
        return 2
    offenders = forbidden(paths)
    for entry in offenders:
        print(f"FORBIDDEN {entry['reason']}: {entry['path']}")
    if offenders:
        print(f"{len(offenders)} of {len(paths)} store paths are build tools; the appliance must not ship them")
        return 1
    print(f"closure clean: {len(paths)} store paths, no compiler, binutils, headers or -dev outputs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
