#!/usr/bin/env python3
"""Real PE/GPT signing controls on a synthetic, non-bootable TEST disk.

This is not an appliance qualification. Keys and disk exist only in a private
temporary directory; no production signing identity or block device is used.
Run with bash scripts/release-tools.sh python3 tests/release_signing_smoke.py.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib
from types import SimpleNamespace
import uuid

ROOT = Path(__file__).resolve().parents[1]
VERSION = "v" + tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
spec = importlib.util.spec_from_file_location("community_release", ROOT / "scripts/community_release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def smoke():
    with tempfile.TemporaryDirectory(prefix="sentinel-signing-control-") as temp:
        temp = Path(temp)
        identity, incoming, outgoing = temp / "identity", temp / "incoming", temp / "outgoing"
        identity.mkdir(mode=0o700)
        incoming.mkdir()
        owner = str(uuid.uuid4())
        for name in ("PK", "KEK", "db"):
            run("openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "90",
                "-subj", f"/CN=Ephemeral QA {name}/", "-keyout", identity / f"{name}.key", "-out", identity / f"{name}.crt",
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            (identity / f"{name}.key").chmod(0o600)
            run("cert-to-efi-sig-list", "-g", owner, identity / f"{name}.crt", identity / f"{name}.esl")
            signer = "KEK" if name == "db" else "PK"
            run("sign-efi-sig-list", "-g", owner, "-k", identity / f"{signer}.key", "-c", identity / f"{signer}.crt",
                name, identity / f"{name}.esl", identity / f"{name}.auth")
            os.environ[f"VELSTRA_{name.upper()}_CERT_SHA256"] = release.digest(identity / f"{name}.crt")
        os.environ["VELSTRA_DB_KEY"] = str(identity / "db.key")
        disk, fat = temp / "fixture.raw", temp / "esp.fat"
        with disk.open("wb") as stream: stream.truncate(80 * 1024**2)
        with fat.open("wb") as stream: stream.truncate(64 * 1024**2)
        layout = "label: gpt\nunit: sectors\n\nstart=2048,size=131072,type=U,name=esp\n"
        layout += "".join(f"size=2048,type=L,name={name}\n" for name in release.LAYOUT[1:])
        run("sfdisk", disk, input=layout, text=True)
        run("mformat", "-F", "-i", fat, "::")
        for name in ("/EFI", "/EFI/BOOT", "/EFI/systemd", "/EFI/Linux", "/loader", "/loader/keys", "/loader/keys/sentinel"):
            run("mmd", "-i", fat, "::" + name)
        boot = Path(os.environ["SENTINEL_TEST_BOOT_EFI"])
        pe, signed = temp / "payload.efi", temp / "factory.efi"
        shutil.copyfile(boot, pe)
        (temp / "os-release").write_text(f"IMAGE_ID=sentinel\nIMAGE_VERSION={VERSION[1:]}\n")
        run("objcopy", "--remove-section", ".osrel", pe)
        headers = run("objdump", "-p", pe, capture_output=True, text=True).stdout
        base = int(next(line.split()[1] for line in headers.splitlines() if line.startswith("ImageBase")), 16)
        run("objcopy", "--add-section", f".osrel={temp / 'os-release'}", "--change-section-vma", f".osrel={base + 0x2000000:#x}", pe)
        run("openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "90",
            "-subj", "/CN=Factory test only/", "-keyout", temp / "factory.key", "-out", temp / "factory.crt",
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        run("sbsign", "--key", temp / "factory.key", "--cert", temp / "factory.crt", "--output", signed, pe)
        for name in release.EFI: run("mcopy", "-i", fat, signed, "::" + name)
        for name in ("PK", "KEK", "db"):
            run("mcopy", "-i", fat, identity / f"{name}.auth", f"::/loader/keys/sentinel/{name}.auth")
        # Copy only into this newly created regular test file, never a device.
        with disk.open("r+b") as target, fat.open("rb") as source:
            target.seek(2048 * 512)
            shutil.copyfileobj(source, target)
        table_before = release.partition_table(disk)
        run("zstd", "-T2", disk, "-o", incoming / "factory.raw.zst")
        release.source = lambda: "a" * 40  # Synthetic fixture, not a source-candidate receipt.
        release.document(incoming / "build.json", {"source": "a" * 40, "version": VERSION,
                         "raw_sha256": release.digest(disk), "compressed_sha256": release.digest(incoming / "factory.raw.zst")})
        release.sign_image(SimpleNamespace(version=VERSION, identity=identity, input=incoming, output=outgoing))
        verify = temp / "verify.raw"
        release.decompress(outgoing / "signed.raw.zst", verify)
        # sfdisk's node paths differ because the test file name changed.
        normalized = lambda rows: [{k: v for k, v in row.items() if k != "node"} for row in rows]
        assert normalized(release.partition_table(verify)) == normalized(table_before)
        release.verify_image(verify, outgoing / "identity", VERSION)
        try:
            release.verify_image(verify, outgoing / "identity", VERSION + "-wrong")
        except ValueError as error:
            assert "IMAGE_VERSION" in str(error)
        else: raise AssertionError("wrong UKI version accepted")
        os.environ["VELSTRA_DB_CERT_SHA256"] = "0" * 64
        try:
            release.verify_image(verify, outgoing / "identity", VERSION)
        except ValueError as error:
            assert "untrusted" in str(error)
        else: raise AssertionError("wrong trust identity accepted")
        release.convert_qcow(verify, temp / "fixture.qcow2")
        store, iso_root = temp / "store", temp / "iso-root"
        store.mkdir()
        iso_root.mkdir()
        shutil.copyfile(verify, store / "synthetic-signed.raw")
        run("mksquashfs", store, iso_root / "nix-store.squashfs", "-noappend", "-processors", "2", "-quiet")
        run("xorriso", "-as", "mkisofs", "-quiet", "-o", temp / "fixture.iso", iso_root)
        for expected, name in ((release.digest(verify), "positive"), ("0" * 64, "wrong-hash")):
            scratch = temp / name
            scratch.mkdir()
            try:
                release.verify_iso(temp / "fixture.iso", "synthetic-signed.raw", expected, scratch)
            except ValueError as error:
                assert name == "wrong-hash" and "exact signed disk" in str(error)
            else:
                assert name == "positive", "ISO readback accepted the wrong disk digest"
        print(json.dumps({"scope": "synthetic non-bootable signing controls only", "production_keys": False,
                          "three_pe_signatures": "passed", "gpt_preserved": "passed",
                          "enrollment_readback": "passed", "wrong_version": "rejected", "wrong_identity": "rejected",
                          "qcow2_byte_comparison": "passed", "iso_payload_readback": "passed", "wrong_iso_hash": "rejected"}))


if __name__ == "__main__": smoke()
