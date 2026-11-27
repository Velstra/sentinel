# Boot the exact externally signed Community disk, without modifying its guest
# closure. The first counted boot must pass product health before blessing;
# the second checks Secure Boot and persistence of that permanent selection.
# A permanent entry does not schedule boot-count assessment again. This is not
# a second runtime-health assessment, dataplane test or installer test.
{ pkgs, self, signedImage, expectedSha256, pkCert, kekCert, dbCert }:
let
  lib = pkgs.lib;
  publicCertificate = name: path:
    let contents = builtins.readFile path;
    in assert lib.hasInfix "-----BEGIN CERTIFICATE-----" contents;
       assert !(lib.hasInfix "PRIVATE KEY" contents);
       pkgs.writeText "release-${name}.crt" contents;
  publicPk = publicCertificate "PK" pkCert;
  publicKek = publicCertificate "KEK" kekCert;
  publicDb = publicCertificate "db" dbCert;
  guid = "a5a5a5a5-1234-5678-9abc-def012345678";
  vars = pkgs.runCommand "release-ovmf-vars.fd"
    { nativeBuildInputs = [ pkgs.python3Packages.virt-firmware ]; } ''
    virt-fw-vars \
      --input ${(pkgs.OVMF.override { secureBoot = true; }).fd}/FV/OVMF_VARS.fd \
      --output $out \
      --set-pk ${guid} ${publicPk} \
      --add-kek ${guid} ${publicKek} \
      --add-db ${guid} ${publicDb} \
      --secure-boot
  '';
in assert builtins.match "[0-9a-f]{64}" expectedSha256 != null;
pkgs.testers.runNixOSTest {
  name = "sentinel-exact-release-image-boot";
  globalTimeout = 720;
  nodes.machine = { ... }: {
    imports = [ self.nixosModules.sentinel (self.outPath + "/nix/image.nix") ];
    virtualisation = {
      directBoot.enable = false;
      mountHostNixStore = false;
      useEFIBoot = true;
      useSecureBoot = true;
      efi.variables = vars;
      memorySize = 2048;
      fileSystems = lib.mkVMOverride { };
    };
  };
  testScript = { nodes, ... }: ''
    import concurrent.futures
    import hashlib
    import json
    import os
    from pathlib import Path
    import queue
    import re
    import socket
    import subprocess
    import tempfile
    import time

    def hash_file(path):
        with Path(path).open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()

    def require_digest(path, expected):
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise AssertionError("invalid expected image SHA-256")
        actual = hash_file(path)
        assert actual == expected, ("release image hash mismatch", actual, expected)
        return actual

    def entry_names(listing):
        return {line.strip().rsplit("/", 1)[-1] for line in listing.splitlines() if line.strip()}

    def require_entry(names, permanent):
        expected = {"sentinel-a.efi" if permanent else "sentinel-a+3.efi"}
        assert names == expected, ("unexpected release boot entries", sorted(names), sorted(expected))
        return sorted(names)

    def record_marker(line, observed, number):
        line = re.sub(r"\x1b\[[0-9;]*m", "", line)
        assert not any(failure in line for failure in
                       ("[FAILED]", "[DEPEND]", "Failed to start ")), ("failed boot unit", line)
        if "boot health:" in line:
            assert "boot health: saved config, services, links and XDP are ready" in line, ("failed product assessment", line)
        markers = {
            "secure-boot": re.escape("EFI stub: UEFI Secure Boot is enabled"),
            "product-health": re.escape("boot health: saved config, services, links and XDP are ready"),
            "boot-blessed": re.escape("Finished Mark the Current Boot Loader Entry as Good"),
            # agetty prints its issue line, then "sentinel-fw login: " with no
            # newline, which the driver's line-based serial reader only hands
            # over once the VM has ended. Only agetty expands the issue's \l
            # to the terminal it runs on, so this line proves the serial getty.
            "login-prompt": r"sentinel-fw login:|<<< Welcome to Velstra Sentinel \S+ \(\S+\) - ttyS0 >>>",
            "multi-user": re.escape("Reached target Multi-User System"),
        }
        for name, marker in markers.items():
            if re.search(marker, line):
                if name == "secure-boot":
                    assert name not in observed, ("unexpected reboot during assessment", name)
                observed.setdefault(name, number)

    def require_markers(observed, require_bless):
        required = {"secure-boot", "multi-user", "login-prompt"}
        if require_bless:
            required.update({"product-health", "boot-blessed"})
        assert required <= observed.keys(), ("missing boot milestones", sorted(required - observed.keys()))
        assert observed["secure-boot"] < observed["multi-user"], observed
        assert observed["secure-boot"] < observed["login-prompt"], observed
        if "product-health" in observed:
            assert observed["secure-boot"] < observed["product-health"], observed
        if "boot-blessed" in observed:
            assert observed["product-health"] < observed["boot-blessed"], observed
        return sorted(required)

    def boot_once(machine, require_bless, log):
        # Only a host-side test-driver handshake. There is no guest agent in
        # the shipped image and no command is sent to this socket.
        machine.shell_path.unlink(missing_ok=True)
        starter = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        future = starter.submit(machine.start)
        lines = []
        try:
            deadline = time.monotonic() + 30
            while True:
                try:
                    peer.connect(str(machine.shell_path))
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    if future.done():
                        future.result()
                    assert time.monotonic() < deadline, "test-driver handshake timed out"
                    time.sleep(0.05)
            future.result(timeout=30)
            observed = {}
            required = {"secure-boot", "multi-user", "login-prompt"}
            if require_bless:
                required.update({"product-health", "boot-blessed"})
            deadline = time.monotonic() + 240
            while not required <= observed.keys() and time.monotonic() < deadline:
                try:
                    line = machine.last_lines.get(timeout=0.2)
                except queue.Empty:
                    assert machine.process.poll() is None, "release VM exited before boot assessment"
                    continue
                lines.append(line)
                record_marker(line, observed, len(lines))
            log.write_text("\n".join(lines) + "\n")
            require_markers(observed, require_bless)
            return observed
        finally:
            log.write_text("\n".join(lines) + "\n")
            if machine.booted:
                machine.crash()
            elif machine.process is not None and machine.process.poll() is None:
                machine.process.terminate()
                machine.process.wait(timeout=10)
            peer.close()
            starter.shutdown(wait=False, cancel_futures=True)

    source = Path("${signedImage}")
    expected = "${expectedSha256}"
    output = Path(os.environ["out"])
    output.mkdir(parents=True, exist_ok=True)
    qemu_img = "${nodes.machine.virtualisation.qemu.package}/bin/qemu-img"
    sfdisk = "${pkgs.util-linux}/bin/sfdisk"
    mdir = "${pkgs.mtools}/bin/mdir"
    boot_records: list[dict[str, object]] = []
    report: dict[str, object] = {
        "scope": "exact signed Community disk: first-boot health assessment and second-boot permanent-selection persistence",
        "expected_sha256": expected, "complete": False, "boots": boot_records}

    def entries(raw):
        table = json.loads(subprocess.check_output([sfdisk, "--json", str(raw)]))["partitiontable"]
        assert table["label"] == "gpt", table
        esp = [part for part in table["partitions"]
               if part.get("name") == "esp" and part.get("type", "").lower() == "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"]
        assert len(esp) == 1, esp
        offset = esp[0]["start"] * table.get("sectorsize", 512)
        return entry_names(subprocess.check_output(
            [mdir, "-b", "-i", f"{raw}@@{offset}", "::/EFI/Linux/"], text=True))

    try:
        report["source_sha256_before"] = require_digest(source, expected)
        report["initial_entries"] = require_entry(entries(source), permanent=False)
        report["certificate_sha256"] = {
            "PK": hash_file("${publicPk}"), "KEK": hash_file("${publicKek}"), "db": hash_file("${publicDb}")}
        # Overlay conversions can be several GiB: use the build work directory,
        # not a session's potentially memory-backed default temporary directory.
        with tempfile.TemporaryDirectory(prefix="release-image-boot-", dir=os.getcwd()) as scratch:
            overlay = Path(scratch, "boot.qcow2")
            inspection = Path(scratch, "inspection.raw")
            subprocess.run([qemu_img, "create", "-f", "qcow2", "-b", str(source), "-F", "raw", str(overlay)], check=True)
            os.environ["NIX_DISK_IMAGE"] = str(overlay)
            # This file is created from the public-certificate vars template
            # once and deliberately retained across both cold boots.
            os.environ["NIX_EFI_VARS"] = str(Path(scratch, "firmware-vars.fd"))
            for number in (1, 2):
                serial_log = output / f"boot-{number}.serial.log"
                milestones = boot_once(machine, require_bless=number == 1, log=serial_log)
                subprocess.run([qemu_img, "convert", "-O", "raw", str(overlay), str(inspection)], check=True)
                permanent = require_entry(entries(inspection), permanent=True)
                boot_records.append({"number": number, "milestones": milestones,
                                     "health_assessment_expected": number == 1,
                                     "permanent_entries": permanent, "serial_sha256": hash_file(serial_log)})
                inspection.unlink()
        report["source_sha256_after"] = require_digest(source, expected)
        report["complete"] = True
    finally:
        (output / "release-image-boot.json").write_text(json.dumps(report, indent=2) + "\n")
  '';
}
