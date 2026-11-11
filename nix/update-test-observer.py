"""Read-only, root-only oracle for the dedicated immutable update VM fixture.

Importing this module performs no probes. This is test code, not a product
health replacement or an endpoint. It never changes configuration, boot state,
devices, units or keys. Private file contents are never included in its result.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import tomllib

USR = "8484680c-9521-48c6-9c11-b0720656f69e"
USR_VERITY = "77ff5f63-e7b6-4633-acf4-1565b864c0e6"
KEYS = tuple(f"ssh_host_{kind}_key{suffix}"
             for kind in ("ed25519", "rsa") for suffix in ("", ".pub"))
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
PROPERTIES = ("ActiveState", "Result", "ExecMainStatus",
              "ExecMainStartTimestampMonotonic", "ExecMainExitTimestampMonotonic")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def command(argv: list[str], timeout: int = 20) -> str:
    result = subprocess.run(argv, check=True, capture_output=True, timeout=timeout,
                            env=dict(os.environ, LC_ALL="C"))
    require(len(result.stdout) <= 1024 * 1024, "oversized observer response")
    return result.stdout.decode("utf-8", errors="strict")


def file_sha(path: Path, limit: int, *, private: bool = False,
             block: bool = False) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISBLK(before.st_mode) if block else stat.S_ISREG(before.st_mode),
                "unexpected file/device type")
        require(before.st_uid == 0, "observer input is not root-owned")
        if private:
            require(stat.S_IMODE(before.st_mode) == 0o600, "private key mode is not 0600")
        if not block:
            require(0 < before.st_size <= limit, "unexpected observer file size")
        digest = hashlib.sha256()
        total = 0
        while data := os.read(descriptor, 1024 * 1024):
            total += len(data)
            require(total <= limit, "oversized observer input")
            digest.update(data)
        require(total > 0, "empty observer input")
        after = os.fstat(descriptor)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
                "observer input changed while read")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def parse_properties(raw: str) -> dict[str, str]:
    pairs = [line.split("=", 1) for line in raw.splitlines()]
    require(all(len(pair) == 2 for pair in pairs), "malformed unit properties")
    result = dict(pairs)
    require(len(pairs) == len(result) and set(result) == set(PROPERTIES),
            "missing, duplicate or unexpected unit property")
    return result


def numeric(value: str) -> int:
    require(isinstance(value, str) and value.isdecimal(), "invalid monotonic unit timestamp")
    return int(value)


def validate_assessment(units: dict, journal: str) -> None:
    require(set(units) == {"velstra", "verify", "bless"}, "incomplete assessment units")
    for name, unit in units.items():
        require(set(unit) == set(PROPERTIES), "incomplete unit properties")
        require(unit["Result"] == "success" and unit["ExecMainStatus"] == "0",
                f"unsuccessful {name} unit")
        require(unit["ActiveState"] == "active",
                f"inactive required {name} unit")
    started = numeric(units["velstra"]["ExecMainStartTimestampMonotonic"])
    verify_start = numeric(units["verify"]["ExecMainStartTimestampMonotonic"])
    verified = numeric(units["verify"]["ExecMainExitTimestampMonotonic"])
    blessed = numeric(units["bless"]["ExecMainStartTimestampMonotonic"])
    bless_exit = numeric(units["bless"]["ExecMainExitTimestampMonotonic"])
    require(0 < started <= verify_start <= verified <= blessed <= bless_exit,
            "normal product assessment did not precede blessing")
    require("Marked boot as 'good'." in journal, "normal blessing result absent from current-boot journal")


def canonical_addresses(values: list[str], version: int) -> set[str]:
    require(isinstance(values, list), "invalid expected address list")
    result = set()
    for value in values:
        address = ipaddress.ip_interface(value)
        require(address.version == version, "wrong expected address family")
        result.add(str(address))
    require(len(result) == len(values), "duplicate expected address")
    return result


def validate_dataplane(desired: dict, compiled: dict, runtime: dict,
                       links: list[dict], expected: dict, ready: bytes) -> dict:
    require(set(expected) == {"ipv4", "ipv6"}, "unexpected fixture address schema")
    address4 = canonical_addresses(expected["ipv4"], 4)
    address6 = canonical_addresses(expected["ipv6"], 6)
    require(bool(address4 or address6) and len(address4) <= 1 and len(address6) <= 1,
            "fixture NIC has no unique declared address")
    interfaces = desired.get("interface", [])
    require(isinstance(interfaces, list) and len(interfaces) == 1,
            "fixture must declare exactly one interface")
    interface = interfaces[0]
    require(interface.get("name") == "eth1" and interface.get("zone") == "wan"
            and interface.get("disabled", False) is False, "fixture eth1 is not enabled and zoned")
    for field, addresses in (("address", address4), ("address6", address6)):
        actual = {str(ipaddress.ip_interface(interface[field]))} if field in interface else set()
        require(actual == addresses, f"saved {field} differs from Nix test declaration")
    bindings = compiled.get("interface", [])
    require(isinstance(bindings, list) and len(bindings) == 1
            and bindings[0].get("name") == "eth1"
            and type(bindings[0].get("policy")) is int and bindings[0]["policy"] >= 0,
            "real eth1 dataplane binding is absent")
    require(runtime == compiled, "compiled runtime differs from saved configuration")
    require(ready.strip() == b"Ready", "actual dataplane did not report Ready")
    require(isinstance(links, list) and len(links) == 1 and links[0].get("ifname") == "eth1",
            "wrong or missing actual dataplane NIC")
    link = links[0]
    program = link.get("xdp", {}).get("prog", {}).get("id")
    require(type(link.get("xdp", {}).get("mode")) is int and link["xdp"]["mode"] in (1, 2, 3)
            and type(program) is int and program > 0, "actual XDP program is absent")
    require("UP" in link.get("flags", []), "real fixture link is not UP")
    actual_addresses = {str(ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}"))
                        for a in link.get("addr_info", [])
                        if not a.get("tentative", False) and not a.get("dadfailed", False)}
    require(address4 | address6 <= actual_addresses, "declared link addresses are not reconciled")
    return {"interface": "eth1", "zone": "wan", "xdp_mode": link["xdp"]["mode"],
            "xdp_program_id": program, "addresses": sorted(address4 | address6)}


def validate_backing(raw: str, disk: str, phase: str) -> None:
    require(re.fullmatch(r"/dev/vd[a-z]+", disk) is not None, "unexpected fixture disk")
    require(phase in ("initial", "staged", "booted"), "unknown observation phase")
    rows = [line.split() for line in raw.splitlines()]
    require(rows and all(len(row) == 2 for row in rows), "malformed mapper ancestry")
    require({name for name, kind in rows if kind == "disk"} == {disk[5:]},
            "foreign or ambiguous mapper root disk")
    parts = {name for name, kind in rows if kind == "part"}
    allowed = {disk[5:] + n for n in (("4", "5") if phase == "booted" else ("2", "3"))}
    require(parts <= allowed and disk[5:] + ("5" if phase == "booted" else "3") in parts,
            "wrong active slot backs the verity mapper")


def validate_verity_status(raw: str) -> None:
    # The exact 6.12.113 fixture kernel emits only V/C for STATUSTYPE_INFO.
    # Do not silently reinterpret new-kernel extensions or corruption as ready.
    fields = raw.split()
    require(len(fields) == 4 and fields[0] == "0" and fields[1].isascii()
            and fields[1].isdecimal() and int(fields[1]) > 0
            and fields[2:] == ["verity", "V"], "real dm-verity target is not healthy")


def validate_entries(entries: list[str], loader: str, phase: str) -> None:
    expected = {"initial": {"sentinel-a.efi"},
                "staged": {"sentinel-a.efi", "sentinel-b+3.efi"},
                "booted": {"sentinel-a.efi", "sentinel-b.efi"}}[phase]
    require(len(entries) == len(set(entries)) and set(entries) == expected,
            "unexpected permanent/counted/fallback UKI entries")
    lines = [line.split() for line in loader.splitlines()]
    preferences = [line for line in lines if line and line[0] == "preferred"]
    defaults = [line for line in lines if line and line[0] == "default"]
    slot = "a" if phase == "initial" else "b"
    require(preferences == [["preferred", f"sentinel-{slot}*"]]
            and defaults == [["default", "sentinel-*"]], "loader lost preference or eligible fallback")


def validate_partitions(raw: str, disk: str, phase: str) -> dict:
    parts = {}
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[1] != "part":
            continue
        require(len(fields) == 5, "malformed GPT partition observation")
        name, _, size, uuid, kind = fields
        require(name.startswith(disk[5:]) and name[len(disk[5:]):] in set("123456"),
                "foreign partition in target GPT")
        number = name[len(disk[5:]):]
        require(number not in parts and size.isdecimal() and int(size) > 0
                and UUID.fullmatch(uuid.lower()) is not None
                and UUID.fullmatch(kind.lower()) is not None, "invalid or duplicate GPT identity")
        parts[number] = {"size": int(size), "uuid": uuid.lower(), "type": kind.lower()}
    require(set(parts) == set("123456") and len({p["uuid"] for p in parts.values()}) == 6,
            "target does not have six uniquely identified appliance partitions")
    require(parts["2"]["type"] == USR_VERITY and parts["3"]["type"] == USR,
            "fallback A lost its verity partition types")
    if phase != "initial":
        require(parts["4"]["type"] == USR_VERITY and parts["5"]["type"] == USR,
                "staged B lacks verity partition types")
    return parts


def query_ready() -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect("/run/velstra/query.sock")
        connection.sendall(b"status\n")
        result = bytearray()
        while data := connection.recv(1024):
            result.extend(data)
            require(len(result) < 65536, "oversized dataplane status")
        return bytes(result)


def persistent_identity() -> dict:
    config = Path("/var/lib/sentinel/appliance.toml")
    machine = Path("/etc/machine-id").read_bytes()
    require(re.fullmatch(rb"[0-9a-f]{32}\n?", machine) is not None,
            "invalid actual machine identity")
    keys = {name: file_sha(Path("/var/lib/sentinel/ssh") / name, 16384,
                           private=not name.endswith(".pub")) for name in KEYS}
    return {"config_sha256": file_sha(config, 1024 * 1024),
            "machine_id_raw_sha256": hashlib.sha256(machine).hexdigest(), "ssh_keys": keys}


def compare(initial: dict, current: dict, phase: str) -> None:
    require(initial.get("phase") == "initial" and current.get("phase") == phase
            and phase in ("staged", "booted"), "wrong comparison phase")
    require(current["disk"] == initial["disk"], "target disk identity changed")
    require(current["persistent"] == initial["persistent"], "persistent config/key/machine identity changed")
    require(current["fallback_a"] == initial["fallback_a"], "active/fallback A bytes or identity changed")
    for number in ("1", "2", "3", "6"):
        require(current["partitions"][number] == initial["partitions"][number],
                "protected GPT partition changed")
    require(current["dataplane"]["addresses"] == initial["dataplane"]["addresses"],
            "configured dataplane address changed")
    same_boot = current["boot_id"] == initial["boot_id"]
    require(same_boot if phase == "staged" else not same_boot, "wrong boot transition")


def require_visible_mount(target: str, source: str) -> None:
    # A systemd autofs mount and the actual filesystem can share a target.
    # stat resolves the filesystem actually serving this path. Compare kernel
    # device numbers, not presentation names or all stacked mount-table rows.
    mounted = os.stat(target)
    device = os.stat(source)
    require(stat.S_ISDIR(mounted.st_mode) and os.path.ismount(target),
            f"expected an actual mountpoint at {target}")
    require(stat.S_ISBLK(device.st_mode) and mounted.st_dev == device.st_rdev,
            f"visible filesystem at {target} does not belong to {source}")


def observe(disk: str, phase: str, expected: dict) -> dict:
    require(os.geteuid() == 0, "root read-only observer required")
    validate_backing(command(["lsblk", "-nsro", "NAME,TYPE", "/dev/mapper/usr"]), disk, phase)
    require_visible_mount("/var/lib/sentinel", disk + "6")
    require_visible_mount("/boot", disk + "1")
    require_visible_mount("/usr", "/dev/mapper/usr")
    validate_verity_status(command(["dmsetup", "status", "usr"]))
    identity = persistent_identity()
    desired = tomllib.loads(Path("/var/lib/sentinel/appliance.toml").read_text())
    compiled = tomllib.loads(command(["sentinel", "compile", "/var/lib/sentinel/appliance.toml"]))
    runtime = tomllib.loads(Path("/run/sentinel/velstra.toml").read_text())
    dataplane = validate_dataplane(desired, compiled, runtime,
                                  json.loads(command(["ip", "-j", "-d", "address", "show", "eth1"])),
                                  expected, query_ready())
    partitions = validate_partitions(command(["lsblk", "-nbro", "NAME,TYPE,SIZE,PARTUUID,PARTTYPE", disk]),
                                     disk, phase)
    entries = sorted(path.name for path in Path("/boot/EFI/Linux").glob("*.efi"))
    loader = Path("/boot/loader/loader.conf").read_text()
    validate_entries(entries, loader, phase)
    units = {}
    for label, unit in (("velstra", "velstra.service"), ("verify", "velstra-boot-verify.service"),
                        ("bless", "systemd-bless-boot.service")):
        units[label] = parse_properties(command(["systemctl", "show", unit]
                                        + [f"--property={name}" for name in PROPERTIES]))
    journal = command(["journalctl", "--boot=0", "--unit=systemd-bless-boot.service", "--output=cat", "--no-pager"])
    validate_assessment(units, journal)
    fallback = {number: dict(partitions[number], sha256=file_sha(Path(disk + number), 4 * 1024**3, block=True))
                for number in ("2", "3")}
    fallback["uki_sha256"] = file_sha(Path("/boot/EFI/Linux/sentinel-a.efi"), 256 * 1024**2)
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    require(UUID.fullmatch(boot) is not None, "invalid current boot identity")
    firmware_uuid = Path("/sys/class/dmi/id/product_uuid").read_text().strip().lower()
    require(firmware_uuid == "49cbd410-429c-4cdb-bc48-49c74f12e3db",
            "fixture virtual hardware identity changed")
    require(persistent_identity() == identity, "persistent identity changed during observation")
    if phase != "initial":
        require(Path("/var/lib/sentinel/update-data-proof").read_bytes() == b"persistent-target-data",
                "persistent update proof changed")
    return {"phase": phase, "disk": disk, "boot_id": boot, "firmware_uuid": firmware_uuid, "persistent": identity,
            "dataplane": dataplane, "partitions": partitions, "fallback_a": fallback,
            "entries": entries, "loader": loader, "assessment": units,
            "normal_bless_journal_good": True}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disk", required=True)
    parser.add_argument("--phase", choices=("initial", "staged", "booted"), required=True)
    parser.add_argument("--expected-json", required=True)
    args = parser.parse_args()
    print(json.dumps(observe(args.disk, args.phase, json.loads(args.expected_json)), sort_keys=True))


if __name__ == "__main__":
    main()
