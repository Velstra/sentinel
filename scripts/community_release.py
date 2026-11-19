#!/usr/bin/env python3
"""Build, externally sign and verify immutable Community release artifacts.

Private keys are file inputs outside both the checkout and Nix store. This is
not the Enterprise sysupdate layout converter or an OS vulnerability scanner.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]
LAYOUT = ["esp", "store-verity", "store", "store-verity-b", "store-b", "data"]
EFI = ["/EFI/BOOT/BOOTX64.EFI", "/EFI/systemd/systemd-bootx64.efi",
       "/EFI/Linux/sentinel-a+3.efi"]
EXCLUSIONS = {"SHA256SUMS", "SHA256SUMS.gpg"}
ASSET_LIMIT = 2 * 1024**3
# Export discovery must not silently shrink away the known release blockers.
# This is a floor, not the whole catalog: every other exported check still runs.
REQUIRED_SAFETY_CHECKS = frozenset({
    "dataplane-conformance", "nat-capacity-pressure", "tcp-reset-validation",
    "ebpf-verifier-6-6", "ebpf-verifier-6-12", "ebpf-verifier-6-18",
    "login-lifecycle", "auth-bounds", "observe-readonly", "wren-static-reload", "apply-ordering",
    "nat", "hairpin", "reject", "commit", "ntp", "bootfallback", "boothealth",
    "ipsec", "vti",
    "ha-pair", "ha-two-node", "ha-two-node-flow", "ha-napt-mixed-version",
})


def run(*args, capture=False, env=None):
    result = subprocess.run([str(a) for a in args], cwd=ROOT, env=env, check=True,
                            stdout=subprocess.PIPE if capture else None, text=True)
    return result.stdout.strip() if capture else None


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def document(path, data):
    with Path(path).open("x") as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write("\n")


def version(value):
    if not re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.[1-9][0-9]*)?", value):
        raise ValueError("expected vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-rc.N")
    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
    if value[1:].split("-rc.")[0] != cargo:
        raise ValueError("release version must match Cargo.toml")
    return value


def source():
    sha = run("git", "rev-parse", "HEAD", capture=True)
    if not re.fullmatch("[0-9a-f]{40}", sha):
        raise ValueError("full source commit required")
    if run("git", "status", "--porcelain", capture=True):
        raise ValueError("release requires a clean checkout; put outputs outside it")
    return sha


def regular(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"regular non-symlink file required: {path}")
    return path.resolve(strict=True)


def secret(name):
    path = regular(os.environ[name])
    stat = path.stat()
    if stat.st_uid != os.geteuid() or stat.st_mode & 0o077:
        raise ValueError(f"{name} must be owned by the signer, mode 0600 or stricter")
    if path.is_relative_to(ROOT) or path.is_relative_to("/nix/store"):
        raise ValueError(f"{name} must be outside the checkout and Nix store")
    return path


def certs(directory):
    """Fingerprints are protected environment variables, not artifact claims."""
    directory = Path(directory)
    for name in ("PK", "KEK", "db"):
        path = regular(directory / f"{name}.crt")
        expected = os.environ[f"VELSTRA_{name.upper()}_CERT_SHA256"]
        if not re.fullmatch("[0-9a-f]{64}", expected) or digest(path) != expected:
            raise ValueError(f"untrusted {name} certificate bytes")
        subject = run("openssl", "x509", "-in", path, "-noout", "-subject", capture=True)
        if re.search(r"demo|test|example", subject, re.I):
            raise ValueError("test/demo Secure Boot identity cannot be released")
        run("openssl", "x509", "-in", path, "-checkend", "2592000", "-noout")
    return directory


def partition_table(image):
    table = json.loads(run("sfdisk", "--json", image, capture=True))["partitiontable"]
    rows = table.get("partitions", [])
    if (table.get("label") != "gpt" or table.get("sectorsize") != 512
            or [p.get("name") for p in rows] != LAYOUT):
        raise ValueError("unreviewed Community disk layout")
    return rows


def esp(image):
    return f"{image}@@{partition_table(image)[0]['start'] * 512}"


def build(expression, **variables):
    env = os.environ | {"SENTINEL_RELEASE_SOURCE": str(ROOT)} | variables
    result = run("nix", "build", "--impure", "--no-link", "--no-write-lock-file",
                 "--max-jobs", "1", "--cores", "4", "--print-out-paths", "-L",
                 "--expr", expression, env=env, capture=True)
    paths = result.splitlines()
    if len(paths) != 1 or not paths[0].startswith("/nix/store/"):
        raise ValueError("expected one Nix output")
    return Path(paths[0])


SELF = 'let self = builtins.getFlake (builtins.getEnv "SENTINEL_RELEASE_SOURCE"); '


def build_image(args):
    sha = source()
    release = version(args.version)
    args.output.mkdir(parents=True, exist_ok=False)
    output = build(SELF + '''cfg = self.nixosConfigurations.sentinel-image.extendModules {
      modules = [ ({ lib, ... }: { velstra.appliance.imageVersion = lib.mkForce
        (builtins.getEnv "SENTINEL_RELEASE_VERSION"); }) ];
      }; in cfg.config.system.build.finalImageSigned''', SENTINEL_RELEASE_VERSION=release[1:])
    images = list(output.rglob("*.raw"))
    if len(images) != 1:
        raise ValueError("expected one factory image")
    partition_table(images[0])
    run("zstd", "-T4", "-6", images[0], "-o", args.output / "factory.raw.zst")
    document(args.output / "build.json", {"schema": 1, "source": sha, "version": release,
             "raw_sha256": digest(images[0]), "compressed_sha256": digest(args.output / "factory.raw.zst"),
             "trust": "factory-test-keys-not-for-publication"})


def decompress(path, target):
    # Output never overwrites a prior candidate; corruption is fatal.
    if target.exists():
        raise ValueError("refusing to overwrite raw image")
    run("zstd", "-d", regular(path), "-o", target)


def verify_image(image, certificate_dir, release):
    certificate_dir = certs(certificate_dir)
    with tempfile.TemporaryDirectory(prefix="sentinel-pe-verify-") as temp:
        temp = Path(temp)
        for index, item in enumerate(EFI):
            pe = temp / f"{index}.efi"
            run("mcopy", "-i", esp(image), f"::{item}", pe)
            run("sbverify", "--cert", certificate_dir / "db.crt", pe)
        osrel = temp / "os-release"
        run("objcopy", "--dump-section", f".osrel={osrel}", temp / "2.efi")
        fields = dict(line.split("=", 1) for line in osrel.read_text().rstrip("\0").splitlines()
                      if "=" in line and not line.startswith("#"))
        if fields.get("IMAGE_VERSION", "").strip('"') != release[1:]:
            raise ValueError("UKI IMAGE_VERSION does not match the release")
        for name in ("PK", "KEK", "db"):
            copied = temp / f"{name}.auth"
            run("mcopy", "-i", esp(image), f"::/loader/keys/sentinel/{name}.auth", copied)
            if digest(copied) != digest(certificate_dir / f"{name}.auth"):
                raise ValueError("image enrollment differs from signing inputs")


def sign_image(args):
    sha = source()
    release = version(args.version)
    identity = certs(args.identity)
    key = secret("VELSTRA_DB_KEY")
    receipt = json.loads((args.input / "build.json").read_text())
    compressed = args.input / "factory.raw.zst"
    if (receipt.get("source") != sha or receipt.get("version") != release
            or receipt.get("compressed_sha256") != digest(compressed)):
        raise ValueError("factory artifact source/version/hash mismatch")
    args.output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="sentinel-external-sign-", dir=os.environ.get("RUNNER_TEMP")) as temp:
        temp = Path(temp)
        image = temp / "signed.raw"
        decompress(compressed, image)
        if digest(image) != receipt["raw_sha256"]:
            raise ValueError("factory raw digest mismatch")
        before = partition_table(image)
        for index, item in enumerate(EFI):
            pe, signed = temp / f"{index}.efi", temp / f"{index}.signed.efi"
            run("mcopy", "-i", esp(image), f"::{item}", pe)
            run("sbattach", "--remove", pe)
            run("sbsign", "--key", key, "--cert", identity / "db.crt", "--output", signed, pe)
            run("sbverify", "--cert", identity / "db.crt", signed)
            run("mcopy", "-o", "-i", esp(image), signed, f"::{item}")
        for name in ("PK", "KEK", "db"):
            run("mcopy", "-o", "-i", esp(image), regular(identity / f"{name}.auth"),
                f"::/loader/keys/sentinel/{name}.auth")
        if partition_table(image) != before:
            raise ValueError("signing must not convert Community partition layout")
        verify_image(image, identity, release)
        run("zstd", "-T4", "-6", image, "-o", args.output / "signed.raw.zst")
        document(args.output / "signed.json", {"schema": 1, "source": sha, "version": release,
                 "raw_sha256": digest(image), "compressed_sha256": digest(args.output / "signed.raw.zst")})
    public = args.output / "identity"
    public.mkdir()
    for name in ("PK", "KEK", "db"):
        for ext in ("crt", "auth"):
            shutil.copyfile(regular(identity / f"{name}.{ext}"), public / f"{name}.{ext}")


def convert_qcow(image, target):
    run("qemu-img", "convert", "-f", "raw", "-O", "qcow2", image, target)
    run("qemu-img", "check", "-f", "qcow2", target)
    run("qemu-img", "compare", "-f", "raw", "-F", "qcow2", image, target)


def verify_iso(iso, store_name, expected_sha256, scratch):
    # Read actual ISO bytes, not just the derivation's configured input path.
    squash, embedded = scratch / "store.squashfs", scratch / "embedded"
    run("xorriso", "-osirrox", "on", "-indev", iso, "-extract", "/nix-store.squashfs", squash)
    run("unsquashfs", "-processors", "4", "-d", embedded, squash, store_name)
    if digest(embedded / store_name) != expected_sha256:
        raise ValueError("installer does not carry the exact signed disk")


def package(args):
    sha, release = source(), version(args.version)
    receipt = json.loads((args.input / "signed.json").read_text())
    if (receipt.get("source") != sha or receipt.get("version") != release
            or receipt.get("compressed_sha256") != digest(args.input / "signed.raw.zst")):
        raise ValueError("signed artifact source/version/hash mismatch")
    identity = certs(args.input / "identity")
    args.output.mkdir(parents=True, exist_ok=False)
    prefix = f"velstra-sentinel_{release}_x86_64"
    with tempfile.TemporaryDirectory(prefix="sentinel-package-", dir=os.environ.get("RUNNER_TEMP")) as temp:
        image = Path(temp) / "signed.raw"
        decompress(args.input / "signed.raw.zst", image)
        if digest(image) != receipt["raw_sha256"]:
            raise ValueError("signed raw digest mismatch")
        verify_image(image, identity, release)
        run("mcopy", "-i", esp(image), "::/EFI/Linux/sentinel-a+3.efi", args.output / f"{prefix}.efi")
        qcow = args.output / f"{prefix}.qcow2"
        convert_qcow(image, qcow)
        store = run("nix", "store", "add-path", image, capture=True)
        output = build(SELF + '''cfg = self.nixosConfigurations.sentinel-iso.extendModules {
          modules = [ ({ lib, ... }: { velstra.iso.imageSource = lib.mkForce (toString
            (builtins.storePath (builtins.getEnv "SENTINEL_SIGNED_IMAGE")));
            velstra.iso.label = lib.mkForce (builtins.getEnv "SENTINEL_RELEASE_VERSION"); }) ];
          }; in cfg.config.system.build.isoImage''', SENTINEL_SIGNED_IMAGE=store,
          SENTINEL_RELEASE_VERSION=release[1:])
        iso = list(output.rglob("*.iso"))
        if len(iso) != 1:
            raise ValueError("expected one installer ISO")
        shutil.copyfile(iso[0], args.output / f"{prefix}.iso")
        verify_iso(iso[0], Path(store).name, receipt["raw_sha256"], Path(temp))
        gate = build(SELF + '''pkgs = self.nixosConfigurations.appliance.pkgs;
          test = import (self.outPath + "/nix/release-image-boot.nix") {
            inherit self pkgs; signedImage = builtins.storePath (builtins.getEnv "SENTINEL_SIGNED_IMAGE");
            expectedSha256 = builtins.getEnv "SENTINEL_RAW_SHA256";
            pkCert = builtins.toPath (builtins.getEnv "SENTINEL_PK_CERT");
            kekCert = builtins.toPath (builtins.getEnv "SENTINEL_KEK_CERT");
            dbCert = builtins.toPath (builtins.getEnv "SENTINEL_DB_CERT");
          }; in test.overrideTestDerivation (_: { SENTINEL_RELEASE_RUN =
            builtins.getEnv "SENTINEL_RELEASE_RUN"; })''',
          SENTINEL_RELEASE_RUN=os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"],
          SENTINEL_SIGNED_IMAGE=store, SENTINEL_RAW_SHA256=receipt["raw_sha256"],
          SENTINEL_PK_CERT=str(identity / "PK.crt"), SENTINEL_KEK_CERT=str(identity / "KEK.crt"),
          SENTINEL_DB_CERT=str(identity / "db.crt"))
        if digest(image) != receipt["raw_sha256"]:
            raise ValueError("qualification mutated the original disk")
        boot = json.loads((gate / "release-image-boot.json").read_text())
        if (boot.get("complete") is not True or len(boot.get("boots", [])) != 2
                or any(boot.get(k) != receipt["raw_sha256"] for k in
                       ("expected_sha256", "source_sha256_before", "source_sha256_after"))):
            raise ValueError("exact-disk boot evidence is incomplete or mismatched")
        shutil.copyfile(gate / "release-image-boot.json", args.output / "release-image-boot.json")
    shutil.copyfile(args.input / "signed.raw.zst", args.output / f"{prefix}.raw.zst")
    for name in ("PK", "KEK", "db"):
        shutil.copyfile(identity / f"{name}.crt", args.output / f"{name}.crt")
    document(args.output / "image-evidence.json", receipt | {
        "boot_test_output": str(gate), "tested_at": int(time.time()),
        "disk_secure_boot": True, "installer_secure_boot": False,
        "qcow2_byte_equivalent": True, "iso_embedded_raw_verified": True,
        "scope": "exact-disk-secure-boot-and-blessing; source-regressions-are-separate"})
    (args.output / "INSTALL.txt").write_text(
        "Verify SHA256SUMS.gpg with the independently obtained release key, then SHA256SUMS.\n"
        "The ISO installer currently requires Secure Boot disabled. The installed disk has production-signed UKIs.\n"
        "Enroll the published firmware certificates only after verifying their independent fingerprints.\n"
        "The QCOW2 is a standalone disk; the compressed RAW decompresses with zstd -d.\n"
        "The source SBOM is not an OS vulnerability or hardware qualification certificate.\n")


def files(directory):
    paths = sorted(Path(directory).iterdir())
    for path in paths:
        regular(path)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", path.name):
            raise ValueError("unsafe artifact basename")
        if path.stat().st_size >= ASSET_LIMIT:
            raise ValueError(f"GitHub release asset exceeds 2 GiB: {path.name}")
    return [p for p in paths if p.name not in EXCLUSIONS]


def verify_bundle(directory):
    paths = files(directory)
    expected = "".join(f"{digest(p)}  {p.name}\n" for p in paths)
    if (directory / "SHA256SUMS").read_text() != expected:
        raise ValueError("bundle inventory/hash mismatch (including added or missing files)")
    fingerprint = os.environ["VELSTRA_GPG_FINGERPRINT"]
    if not re.fullmatch(r"[0-9A-F]{40}|[0-9A-F]{64}", fingerprint):
        raise ValueError("full trusted signing fingerprint required")
    status = run("gpg", "--batch", "--status-fd", "1", "--verify",
                 directory / "SHA256SUMS.gpg", directory / "SHA256SUMS", capture=True)
    valid = [line.split() for line in status.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
    if len(valid) != 1 or fingerprint not in (valid[0][2], valid[0][-1]):
        raise ValueError("checksum signature is not from the trusted release identity")
    validate_bundle(directory)


def validate_bundle(directory):
    """Check unsigned content/evidence before the attestation key is loaded."""
    paths = files(directory)
    evidence = json.loads((directory / "image-evidence.json").read_text())
    if (evidence.get("source") != source() or evidence.get("version") != os.environ["RELEASE_VERSION"]
            or type(evidence.get("tested_at")) is not int
            or not 0 <= time.time() - evidence["tested_at"] <= 86400):
        raise ValueError("stale or mismatched image qualification")
    prefix = f"velstra-sentinel_{version(evidence['version'])}_x86_64"
    required = {f"{prefix}.iso", f"{prefix}.qcow2", f"{prefix}.raw.zst", f"{prefix}.efi", "PK.crt", "KEK.crt", "db.crt",
                "INSTALL.txt", "image-evidence.json", "release-image-boot.json", "source-checks.json",
                "source-sbom.cdx.json", "source-sbom.provenance.json"}
    if {p.name for p in paths} != required:
        raise ValueError("release inventory is incomplete or has unexpected files")
    if (evidence.get("disk_secure_boot") is not True or evidence.get("installer_secure_boot") is not False
            or evidence.get("qcow2_byte_equivalent") is not True or evidence.get("iso_embedded_raw_verified") is not True
            or digest(directory / f"{prefix}.raw.zst") != evidence.get("compressed_sha256")):
        raise ValueError("incomplete image/format verification")
    boot = json.loads((directory / "release-image-boot.json").read_text())
    if (boot.get("complete") is not True or len(boot.get("boots", [])) != 2
            or [r.get("number") for r in boot["boots"]] != [1, 2]
            or any(boot.get(k) != evidence.get("raw_sha256") for k in
                   ("expected_sha256", "source_sha256_before", "source_sha256_after"))
            or boot.get("certificate_sha256") != {n: digest(directory / f"{n}.crt") for n in ("PK", "KEK", "db")}):
        raise ValueError("boot evidence mismatch")
    checks = json.loads((directory / "source-checks.json").read_text())
    nonce = os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    if checks.get("source") != evidence["source"] or checks.get("run") != nonce:
        raise ValueError("source checks do not belong to this workflow run")
    # The immutable plan job supplies the catalog independently of the bundle.
    names = json.loads(os.environ["RELEASE_CHECK_CATALOG"])["check"]
    validate_checks(checks.get("checks"), names, evidence["source"], nonce)
    provenance = json.loads((directory / "source-sbom.provenance.json").read_text())
    if (provenance.get("source_commit") != evidence["source"] or provenance.get("scope") != "source-lockfiles"
            or provenance.get("sbom_sha256") != digest(directory / "source-sbom.cdx.json")):
        raise ValueError("source SBOM does not match the qualified source")


def checks(args):
    sha = source()
    names = json.loads(run("nix", "eval", "--json", "--no-write-lock-file",
                           ".#checks.x86_64-linux", "--apply", "builtins.attrNames", capture=True))
    validate_catalog(names)
    if args.check:
        if args.check not in names:
            raise ValueError("unknown check")
        nonce = os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
        output = build(SELF + '''name = builtins.getEnv "SENTINEL_CHECK";
          test = self.checks.x86_64-linux.${name}; nonce = _: {
            SENTINEL_RELEASE_RUN = builtins.getEnv "SENTINEL_RELEASE_RUN"; };
          in if test ? overrideTestDerivation then test.overrideTestDerivation nonce
          else test.overrideAttrs nonce''', SENTINEL_CHECK=args.check, SENTINEL_RELEASE_RUN=nonce)
        document(args.output, {"source": sha, "check": args.check, "output": str(output),
                              "run": nonce, "completed_at": int(time.time())})
    else:
        print(json.dumps({"check": names}, separators=(",", ":")))


def validate_catalog(names):
    if (not isinstance(names, list) or not 1 <= len(names) <= 256
            or any(not isinstance(n, str) or not re.fullmatch(r"[a-zA-Z0-9_-]+", n) for n in names)
            or len(set(names)) != len(names)):
        raise ValueError("invalid or oversized check catalog; review workflow sharding")
    missing = REQUIRED_SAFETY_CHECKS - set(names)
    if missing:
        raise ValueError("release catalog omits mandatory safety checks: " + ", ".join(sorted(missing)))


def validate_checks(receipts, names, sha, nonce):
    validate_catalog(names)
    if (not isinstance(receipts, list) or len(receipts) != len(names)
            or any(not isinstance(r, dict) for r in receipts)
            or sorted(r.get("check", "") for r in receipts) != sorted(names)
            or any(r.get("source") != sha or r.get("run") != nonce
                   or type(r.get("completed_at")) is not int
                   or not 0 <= time.time() - r["completed_at"] <= 86400 for r in receipts)):
        raise ValueError("missing, duplicate, stale or wrong-source check receipts")


def aggregate(args):
    sha = source()
    names = json.loads(run("nix", "eval", "--json", ".#checks.x86_64-linux", "--apply",
                          "builtins.attrNames", capture=True))
    receipts = [json.loads(p.read_text()) for p in args.input.glob("*.json")]
    expected_run = os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
    validate_checks(receipts, names, sha, expected_run)
    document(args.output, {"source": sha, "run": expected_run, "checks": receipts,
                          "scope": "source-regressions-not-exact-final-disk-tests"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["build", "sign", "package", "checks", "aggregate", "validate", "seal", "verify", "budget"])
    parser.add_argument("--version")
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--check")
    args = parser.parse_args()
    if args.command == "build": build_image(args)
    elif args.command == "sign": sign_image(args)
    elif args.command == "package": package(args)
    elif args.command == "checks": checks(args)
    elif args.command == "aggregate": aggregate(args)
    elif args.command == "validate": validate_bundle(args.input)
    elif args.command == "budget":
        limit = int(os.environ.get("RELEASE_ARTIFACT_BYTE_BUDGET", "0"))
        size = sum(regular(p).stat().st_size for p in args.input.rglob("*") if not p.is_dir())
        if size <= 0 or size > limit:
            raise ValueError(f"artifact bytes {size} exceed explicitly approved budget {limit}")
    elif args.command == "seal":
        paths = files(args.input)
        (args.input / "SHA256SUMS").write_text("".join(f"{digest(p)}  {p.name}\n" for p in paths))
        run("gpg", "--batch", "--no-tty", "--local-user", os.environ["VELSTRA_GPG_FINGERPRINT"],
            "--detach-sign", "--output", args.input / "SHA256SUMS.gpg", args.input / "SHA256SUMS")
        verify_bundle(args.input)
    else: verify_bundle(args.input)


if __name__ == "__main__":
    main()
