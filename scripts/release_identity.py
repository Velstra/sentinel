#!/usr/bin/env python3
"""Materialize an explicit release identity in an ephemeral, private directory."""
import argparse
import base64
import os
from pathlib import Path
import tempfile


def materialize(parent, kind):
    parent = Path(parent).resolve(strict=True)
    repo = Path(__file__).resolve().parents[1]
    if parent.is_relative_to(repo) or parent.is_relative_to("/nix/store"):
        raise ValueError("identity directory must be outside the checkout/store")
    directory = Path(tempfile.mkdtemp(prefix="sentinel-identity-", dir=parent))
    if kind == "firmware":
        inputs = {f"{name}.crt": (f"VELSTRA_{name.upper()}_CERT", False)
                  for name in ("PK", "KEK", "db")}
        inputs |= {f"{name}.auth": (f"VELSTRA_{name.upper()}_AUTH_BASE64", True)
                   for name in ("PK", "KEK", "db")}
        inputs["db.key"] = ("VELSTRA_DB_KEY_PEM", False)
    else:
        inputs = {"release.asc": ("VELSTRA_GPG_PRIVATE_KEY", False)}
    for filename, (variable, encoded) in inputs.items():
        value = os.environ.pop(variable, "")
        if not value or len(value) > 256 * 1024:
            raise ValueError(f"missing or oversized {variable}")
        body = base64.b64decode(value, validate=True) if encoded else value.encode()
        fd = os.open(directory / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(body)
    return directory


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=["firmware", "gpg"])
    args = parser.parse_args()
    directory = materialize(os.environ["RUNNER_TEMP"], args.kind)
    with open(os.environ["GITHUB_ENV"], "a") as stream:
        stream.write(f"RELEASE_IDENTITY={directory}\n")
        if args.kind == "firmware":
            stream.write(f"VELSTRA_DB_KEY={directory / 'db.key'}\n")
        else:
            stream.write(f"GNUPGHOME={directory}\n")
