#!/usr/bin/env python3
"""Seed a Sentinel raw image's data partition with a first-boot configuration.

A raw or QCOW2 import of the factory image has no account, no address and no
cloud-init: the only way in is the persistent data partition (GPT name and ext4
label `data`), which the first boot reads `appliance.toml` and the SSH host key
from. This tool writes exactly those files into a COPY of the image:

  * it refuses a configuration the image's own `sentinel config check` refuses,
    and one that leaves no way to log in unless --allow-unreachable is given;
  * it adds the files to the factory ext4 that the image build created, with
    libext2fs (debugfs), instead of formatting a new filesystem: the layout is
    the one the image boots and grows on every unseeded first boot;
  * files are root-owned, the config and private host key mode 0600;
  * the result is verified (e2fsck, mode/owner, byte-for-byte content) before
    the partition is written back, and the input image is never modified.

Run it through the flake so every tool is the pinned one:

    nix run .#seed-image -- --image velstra-sentinel_1.raw \\
        --config appliance.toml --output seeded.raw [--qcow2 seeded.qcow2]
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib

SECTOR = 512
CHUNK = 1024 * 1024
DATA_LABEL = "data"
CONFIG = "appliance.toml"
HOST_KEY = "ssh/ssh_host_ed25519_key"
MAX_CONFIG_BYTES = 4 * 1024 * 1024
# Owner, group and mode of every file the first boot reads from the partition.
LAYOUT = (
    ("ssh", 0o040700),
    (CONFIG, 0o100600),
    (HOST_KEY, 0o100600),
    (HOST_KEY + ".pub", 0o100644),
)


class SeedError(Exception):
    """A refusal with an operator-facing reason."""


def require(condition, message):
    if not condition:
        raise SeedError(message)


def tool(name, default):
    return os.environ.get("SEED_" + name, default)


def run(command, *, ok=(0,), capture=True):
    result = subprocess.run([str(part) for part in command], check=False, text=True,
                            capture_output=capture, timeout=600)
    if result.returncode not in ok:
        detail = (result.stderr or result.stdout or "").strip()[-2000:]
        raise SeedError(f"{Path(str(command[0])).name} failed ({result.returncode}): {detail}")
    return result.stdout or ""


def data_partition(table):
    """Return (start_bytes, size_bytes) of the one partition named `data`."""
    require(isinstance(table, dict) and table.get("label") == "gpt", "the image has no GPT")
    require(table.get("sectorsize") == SECTOR, "the image does not use 512-byte sectors")
    parts = table.get("partitions")
    require(isinstance(parts, list) and parts, "the image has no partitions")
    named = [p for p in parts if isinstance(p, dict) and p.get("name") == DATA_LABEL]
    require(len(named) == 1, "the image must have exactly one partition named 'data'")
    require(named[0] is parts[-1], "the 'data' partition is not the last partition")
    start, size = named[0].get("start"), named[0].get("size")
    require(type(start) is int and type(size) is int and start > 0 and size > 0,
            "the 'data' partition has no usable geometry")
    return start * SECTOR, size * SECTOR


def reachability_problems(config):
    """Why a box booted from this config could not be entered, if it could not."""
    problems = []
    system = config.get("system", {}) if isinstance(config.get("system"), dict) else {}
    groups = {g.get("name"): g.get("permission") for g in system.get("group", [])
              if isinstance(g, dict)}
    logins = [l for l in system.get("login", []) if isinstance(l, dict)]
    usable = [l for l in logins
              if groups.get(l.get("group")) == "read-write"
              and (l.get("ssh-key") or l.get("hashed-password"))]
    if not usable:
        problems.append("no [[system.login]] in a read-write group has an ssh-key or hashed-password")
    ssh = config.get("services", {}).get("ssh", {}) if isinstance(config.get("services"), dict) else {}
    if not (isinstance(ssh, dict) and ssh.get("enable") is True):
        problems.append("[services.ssh] enable is not true")
    interfaces = [i for i in config.get("interface", []) if isinstance(i, dict)]
    if not interfaces:
        problems.append("no [[interface]] is configured")
    bare = sorted(i["name"] for i in interfaces
                  if isinstance(i.get("name"), str) and not i.get("hw-id")
                  and re.fullmatch(r"(enp|ens|eno|eth)\w+", i["name"]))
    return problems, bare


def debugfs_script(stage, create_ssh_dir):
    """debugfs commands that add the staged files and fix owner and mode."""
    lines = ["cd /"]
    if create_ssh_dir:
        lines.append("mkdir ssh")
    for name in (CONFIG, HOST_KEY, HOST_KEY + ".pub"):
        source = stage / name
        require(re.fullmatch(r"[A-Za-z0-9_./+-]+", str(source)) is not None,
                "the staging path contains characters debugfs cannot quote")
        lines.append(f"write {source} {name}")
    for name, mode in LAYOUT:
        lines += [f"set_inode_field {name} mode 0{mode:o}",
                  f"set_inode_field {name} uid 0", f"set_inode_field {name} gid 0"]
    return "\n".join(lines) + "\n"


def parse_stat(text):
    """Mode, uid and gid from `debugfs -R 'stat <path>'` output."""
    mode = re.search(r"Mode:\s+(?:\\)?0?([0-7]{3,4})", text)
    user = re.search(r"User:\s+(\d+)", text)
    group = re.search(r"Group:\s+(\d+)", text)
    kind = re.search(r"Type:\s+(\w+)", text)
    require(mode and user and group and kind, "debugfs did not report the inode")
    return kind.group(1), int(mode.group(1), 8), int(user.group(1)), int(group.group(1))


def copy_range(source, target, offset, length, target_offset=0, *, skip_zero=False):
    """Copy bytes. `skip_zero` leaves all-zero chunks unwritten, which keeps a
    copy into a FRESH sparse file sparse; it must never be used to write over
    existing data, where a skipped chunk keeps the old bytes underneath (the
    audit's `dd conv=sparse` seed recipe corrupted ext4 exactly that way)."""
    with open(source, "rb") as reader, open(target, "r+b") as writer:
        reader.seek(offset)
        position = 0
        while position < length:
            block = reader.read(min(CHUNK, length - position))
            require(block, "the image is shorter than its partition table says")
            if not skip_zero or block.count(0) != len(block):
                writer.seek(target_offset + position)
                writer.write(block)
            position += len(block)


def sparse_copy(source, target):
    size = source.stat().st_size
    with open(target, "xb") as writer:
        writer.truncate(size)
    copy_range(source, target, 0, size, skip_zero=True)


def stage_files(stage, config_path, host_key):
    (stage / "ssh").mkdir(mode=0o700)
    shutil.copyfile(config_path, stage / CONFIG)
    key = stage / HOST_KEY
    if host_key:
        shutil.copyfile(host_key, key)
        public = Path(str(host_key) + ".pub")
        if public.exists():
            shutil.copyfile(public, Path(str(key) + ".pub"))
        else:
            (Path(str(key) + ".pub")).write_text(
                run([tool("SSH_KEYGEN", "ssh-keygen"), "-y", "-f", key]))
    else:
        run([tool("SSH_KEYGEN", "ssh-keygen"), "-q", "-t", "ed25519", "-N", "",
             "-C", "sentinel-seeded-host", "-f", key])
    os.chmod(key, 0o600)
    return run([tool("SSH_KEYGEN", "ssh-keygen"), "-l", "-f", Path(str(key) + ".pub")]).strip()


def verify_filesystem(fs, stage):
    debugfs = tool("DEBUGFS", "debugfs")
    run([tool("E2FSCK", "e2fsck"), "-f", "-n", fs])
    for name, mode in LAYOUT:
        kind, found, uid, gid = parse_stat(run([debugfs, "-R", f"stat /{name}", fs]))
        require((found, uid, gid) == (mode & 0o7777, 0, 0),
                f"/{name} was written as {found:o} {uid}:{gid}, not {mode & 0o7777:o} 0:0")
        require(kind == ("directory" if mode & 0o040000 else "regular"), f"/{name} has the wrong type")
    with tempfile.TemporaryDirectory(prefix="sentinel-seed-verify-") as scratch:
        for name in (CONFIG, HOST_KEY, HOST_KEY + ".pub"):
            dumped = Path(scratch) / Path(name).name
            run([debugfs, "-R", f"dump /{name} {dumped}", fs])
            require(dumped.read_bytes() == (stage / name).read_bytes(),
                    f"/{name} differs from the staged file after writing")


def seed(args):
    config_bytes = args.config.read_bytes()
    require(len(config_bytes) <= MAX_CONFIG_BYTES, "the configuration exceeds 4 MiB")
    try:
        config = tomllib.loads(config_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise SeedError(f"the configuration is not valid TOML: {error}") from error
    problems, bare = reachability_problems(config)
    if problems and not args.allow_unreachable:
        raise SeedError("this configuration leaves no way into the box: " + "; ".join(problems)
                        + " (pass --allow-unreachable to seed it anyway)")
    run([tool("SENTINEL", "sentinel"), "config", "check", args.config])
    table = json.loads(run([tool("SFDISK", "sfdisk"), "--json", args.image]))["partitiontable"]
    offset, length = data_partition(table)
    require(offset + length <= args.image.stat().st_size, "the data partition exceeds the image")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sentinel-seed-") as scratch:
        scratch = Path(scratch)
        fs = scratch / "data.ext4"
        with open(fs, "xb") as handle:
            handle.truncate(length)
        copy_range(args.image, fs, offset, length, skip_zero=True)
        run([tool("E2FSCK", "e2fsck"), "-f", "-n", fs])
        debugfs = tool("DEBUGFS", "debugfs")
        if "Type: regular" in run([debugfs, "-R", f"stat /{CONFIG}", fs], ok=(0, 1)):
            raise SeedError("the image's data partition is already seeded; start from a factory image")
        has_ssh = "Type: directory" in run([debugfs, "-R", "stat /ssh", fs], ok=(0, 1))
        stage = scratch / "stage"
        stage.mkdir(mode=0o700)
        fingerprint = stage_files(stage, args.config, args.host_key)
        commands = scratch / "debugfs.cmd"
        commands.write_text(debugfs_script(stage, not has_ssh))
        run([debugfs, "-w", "-f", commands, fs])
        verify_filesystem(fs, stage)
        public_key = (stage / (HOST_KEY + ".pub")).read_text().strip()
        try:
            sparse_copy(args.image, args.output)
            copy_range(fs, args.output, 0, length, target_offset=offset)
            if args.qcow2:
                run([tool("QEMU_IMG", "qemu-img"), "convert", "-c", "-f", "raw", "-O", "qcow2",
                     args.output, args.qcow2])
        except BaseException:
            # Never leave a half-written image that looks like a seeded one.
            args.output.unlink(missing_ok=True)
            if args.qcow2:
                args.qcow2.unlink(missing_ok=True)
            raise
    return {"output": str(args.output), "qcow2": str(args.qcow2) if args.qcow2 else None,
            "data_partition": {"offset": offset, "bytes": length},
            "host_key": public_key, "host_key_fingerprint": fingerprint,
            "warnings": (["unreachable: " + p for p in problems]
                         + [f"interface {name!r} is bound by kernel name only; a removed or "
                            "re-ordered NIC moves it to another port. Bind it with "
                            "hw-id = \"<mac>\"" for name in bare])}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--image", type=Path, required=True, help="factory raw image (read only)")
    parser.add_argument("--config", type=Path, required=True, help="appliance.toml to seed")
    parser.add_argument("--output", type=Path, required=True, help="seeded raw image to create")
    parser.add_argument("--host-key", type=Path,
                        help="existing ed25519 host private key (default: generate one)")
    parser.add_argument("--qcow2", type=Path, help="also write a compressed qcow2 copy")
    parser.add_argument("--allow-unreachable", action="store_true",
                        help="seed a configuration that has no usable SSH login")
    args = parser.parse_args(argv)
    try:
        require(args.image.resolve() != args.output.resolve(), "--output must differ from --image")
        require(not args.output.exists(), f"{args.output} already exists")
        report = seed(args)
    except (SeedError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"seed-image: {error}", file=sys.stderr)
        return 1
    for warning in report["warnings"]:
        print(f"seed-image: warning: {warning}", file=sys.stderr)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
